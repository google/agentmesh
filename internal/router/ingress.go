// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package router

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	gostream "github.com/libp2p/go-libp2p-gostream"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/protobuf/proto"
)

const (
	ingressModeMetadata = "metadata"
	ingressModeUnknown  = "unknown"

	ingressOutcomeAllow           = "allow"
	ingressOutcomeDeny            = "deny"
	ingressOutcomeUnauthenticated = "unauthenticated"
	ingressOutcomeNotFound        = "not_found"
	ingressOutcomeRateLimited     = "rate_limited"
	ingressOutcomeBadGateway      = "bad_gateway"
	ingressOutcomeInvalid         = "invalid"
	ingressOutcomeUnavailable     = "unavailable"

	maxIngressBodyBytes     = 32 << 20
	maxIngressCardBodyBytes = 1 << 20
	a2aAgentCardSubpath     = ".well-known/agent-card.json"
	ingressDialTimeout      = 10 * time.Second
)

var routerIngressRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_router_ingress_requests_total",
		Help: "External HTTP ingress requests handled by this router, by mode and outcome",
	},
	[]string{"mode", "outcome"},
)

func init() {
	for _, mode := range []string{api.IngressAuthModeStringEdge, api.IngressAuthModeStringPassthrough, ingressModeMetadata, ingressModeUnknown} {
		for _, outcome := range []string{
			ingressOutcomeAllow,
			ingressOutcomeDeny,
			ingressOutcomeUnauthenticated,
			ingressOutcomeNotFound,
			ingressOutcomeRateLimited,
			ingressOutcomeBadGateway,
			ingressOutcomeInvalid,
			ingressOutcomeUnavailable,
		} {
			routerIngressRequestsTotal.WithLabelValues(mode, outcome)
		}
	}
}

// IngressAddr returns the bound TCP address of the standalone HTTP ingress
// listener when IngressAddr was configured, or nil when off or mounted on a
// shared port via IngressHandler.
func (r *Router) IngressAddr() net.Addr {
	if r == nil {
		return nil
	}
	return r.ingressAddr
}

func (r *Router) serveIngress(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	r.ingressServer = &http.Server{
		Handler:           r.IngressHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	r.ingressAddr = listener.Addr()
	if r.config.IngressTLSCertPath != "" {
		go func() {
			if err := r.ingressServer.ServeTLS(listener, r.config.IngressTLSCertPath, r.config.IngressTLSKeyPath); err != nil && err != http.ErrServerClosed {
				logger.Errorf("[Ingress] HTTPS server error: %v", err)
			}
		}()
		logger.Infof("Router HTTPS ingress listening on https://%s/ingress", r.ingressAddr)
		return nil
	}
	go func() {
		if err := r.ingressServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Errorf("[Ingress] HTTP server error: %v", err)
		}
	}()
	logger.Infof("Router HTTP ingress listening on http://%s/ingress", r.ingressAddr)
	return nil
}

// IngressHandler returns the HTTP handler for /ingress/ and
// /ingress/.well-known/oauth-protected-resource, suitable either for a
// dedicated listener (--ingress-addr) or for single-port mounting in
// agentmesh-one.
func (r *Router) IngressHandler() http.Handler {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			peerStr := addr
			if h, _, err := net.SplitHostPort(addr); err == nil {
				peerStr = h
			}
			pid, err := peer.Decode(peerStr)
			if err != nil {
				return nil, fmt.Errorf("invalid target peer %q: %w", peerStr, err)
			}
			if r.gated == nil {
				return nil, errors.New("router host is not initialized")
			}
			// The inbound request carries no deadline, so an unresponsive
			// provider or a hung stream negotiation would hold this
			// goroutine for as long as the client waits. The stream, once
			// open, outlives dialCtx.
			dialCtx, cancel := context.WithTimeout(ctx, ingressDialTimeout)
			defer cancel()
			return gostream.Dial(network.WithAllowLimitedConn(dialCtx, "ingress"), r.gated, pid, api.IngressProtocolID)
		},
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /ingress/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /ingress/.well-known/oauth-protected-resource", r.handleIngressProtectedResourceMetadata)
	mux.HandleFunc("/ingress/", func(w http.ResponseWriter, req *http.Request) {
		r.handleIngressRequest(w, req, transport)
	})
	return mux
}

func isUnspecifiedBindHost(host string) bool {
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if h == "" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsUnspecified()
}

func (r *Router) singlePortWSPort() string {
	if r.Host == nil || r.Host.Network() == nil {
		return ""
	}
	for _, a := range r.Host.Network().ListenAddresses() {
		if _, err := a.ValueForProtocol(multiaddr.P_WS); err != nil {
			continue
		}
		if port, err := a.ValueForProtocol(multiaddr.P_TCP); err == nil {
			return port
		}
	}
	return ""
}

func (r *Router) leasedIngressURL() string {
	if configured := strings.TrimSuffix(strings.TrimSpace(r.config.IngressURL), "/"); configured != "" {
		return configured
	}
	if r.ingressAddr != nil {
		addrStr := r.ingressAddr.String()
		host, _, err := net.SplitHostPort(addrStr)
		if err == nil && !isUnspecifiedBindHost(host) {
			scheme := "http"
			if r.config.IngressTLSCertPath != "" {
				scheme = "https"
			}
			return scheme + "://" + addrStr + "/ingress"
		}
		return ""
	}
	if r.config.AdvertiseSinglePortIngress {
		host := strings.TrimSpace(r.config.SinglePortBindHost)
		if !isUnspecifiedBindHost(host) {
			if port := r.singlePortWSPort(); port != "" {
				return "http://" + net.JoinHostPort(host, port) + "/ingress"
			}
		}
	}
	return ""
}

// effectiveIngressBaseURL resolves the canonical external /ingress base URL
// from operator configuration or a non-unspecified bound listener, never from
// the untrusted HTTP Host header.
func (r *Router) effectiveIngressBaseURL() string {
	if leased := r.leasedIngressURL(); leased != "" {
		return leased
	}
	if pub := strings.TrimSuffix(strings.TrimSpace(r.config.PublicControlPlaneURL), "/"); pub != "" {
		return pub + "/ingress"
	}
	if r.config.AdvertiseSinglePortIngress {
		if port := r.singlePortWSPort(); port != "" {
			return "http://" + net.JoinHostPort("127.0.0.1", port) + "/ingress"
		}
	}
	return strings.TrimSuffix(strings.TrimSpace(r.config.ControlPlaneURL), "/") + "/ingress"
}

func (r *Router) effectivePublicControlPlaneURL() string {
	if pub := strings.TrimSuffix(strings.TrimSpace(r.config.PublicControlPlaneURL), "/"); pub != "" {
		return pub
	}
	if r.config.AdvertiseSinglePortIngress || (r.config.IngressURL != "" && r.config.AllowInsecureControlPlane) {
		return strings.TrimSuffix(r.effectiveIngressBaseURL(), "/ingress")
	}
	return strings.TrimSuffix(strings.TrimSpace(r.config.ControlPlaneURL), "/")
}

func (r *Router) handleIngressProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	base := r.effectiveIngressBaseURL()
	var servers []string
	if cp := r.effectivePublicControlPlaneURL(); cp != "" {
		servers = append(servers, cp)
	}
	doc := api.OAuthProtectedResourceMetadata{
		Resource:               base,
		AuthorizationServers:   servers,
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"openid", "email", "profile"},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(ingressModeMetadata, ingressOutcomeBadGateway).Inc()
		logger.Errorf("[Ingress] Failed to marshal protected resource metadata: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	routerIngressRequestsTotal.WithLabelValues(ingressModeMetadata, ingressOutcomeAllow).Inc()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(out)
}

func (r *Router) writeIngressUnauthorized(w http.ResponseWriter, modeMetric, message string) {
	routerIngressRequestsTotal.WithLabelValues(modeMetric, ingressOutcomeUnauthenticated).Inc()
	metaURL := r.effectiveIngressBaseURL() + "/.well-known/oauth-protected-resource"
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, metaURL))
	http.Error(w, message, http.StatusUnauthorized)
}

func biscuitRateLimitKey(b *biscuit.Biscuit, raw []byte) string {
	if b != nil {
		if ids := b.RevocationIds(); len(ids) > 0 && len(ids[0]) > 0 {
			return "biscuit:" + base64.RawURLEncoding.EncodeToString(ids[0])
		}
	}
	sum := sha256.Sum256(raw)
	return "biscuit:" + hex.EncodeToString(sum[:16])
}

func (r *Router) handleIngressRequest(w http.ResponseWriter, req *http.Request, transport http.RoundTripper) {
	if !r.isReady.Load() || r.shutdown.Load() {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeUnavailable).Inc()
		logger.Warn("[Ingress] Router is not ready or is shutting down")
		http.Error(w, "Router is not ready", http.StatusServiceUnavailable)
		return
	}

	clientIP := clientIPFromRemoteAddr(req.RemoteAddr)
	req.Body = http.MaxBytesReader(w, req.Body, maxIngressBodyBytes)

	if api.HasDotSegment(req.URL.Path) {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeInvalid).Inc()
		logger.Debugf("[Ingress] Rejecting dot-segment path from %s", clientIP)
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	trimmed := strings.TrimPrefix(req.URL.Path, "/ingress/")
	parts := strings.SplitN(trimmed, "/", 4)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeInvalid).Inc()
		logger.Debugf("[Ingress] Rejecting malformed ingress path from %s", clientIP)
		http.Error(w, "Invalid ingress path: expected /ingress/<peer_id>/<service_type>/<service_name>", http.StatusBadRequest)
		return
	}
	peerIDStr := parts[0]
	serviceTypeStr := strings.ToLower(parts[1])
	serviceName := parts[2]
	subpath := ""
	hasTrailingOrSubpath := len(parts) == 4
	if hasTrailingOrSubpath {
		subpath = parts[3]
	}

	targetPeer, err := peer.Decode(peerIDStr)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeInvalid).Inc()
		logger.Debugf("[Ingress] Rejecting invalid peer ID from %s: %v", clientIP, err)
		http.Error(w, "Invalid peer ID", http.StatusBadRequest)
		return
	}
	svcType, err := api.ParseServiceType(serviceTypeStr)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeInvalid).Inc()
		logger.Debugf("[Ingress] Rejecting invalid service type %q from %s", serviceTypeStr, clientIP)
		http.Error(w, "Invalid service type", http.StatusBadRequest)
		return
	}
	if !api.IsInboundServiceType(svcType) {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeNotFound).Inc()
		logger.Debugf("[Ingress] Rejecting non-inbound service type %q from %s", serviceTypeStr, clientIP)
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}
	if err := api.ValidateServiceFormat(serviceTypeStr + "://" + serviceName); err != nil {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeInvalid).Inc()
		logger.Debugf("[Ingress] Rejecting invalid service name from %s: %v", clientIP, err)
		http.Error(w, "Invalid service name", http.StatusBadRequest)
		return
	}
	if _, banned := r.bannedPeers.Load(targetPeer); banned {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeNotFound).Inc()
		logger.Warnf("[Ingress] Refusing ingress request to banned peer %s", targetPeer)
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	key, err := api.ServiceKey(svcType, serviceName)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeInvalid).Inc()
		logger.Debugf("[Ingress] Invalid service key for %s://%s: %v", serviceTypeStr, serviceName, err)
		http.Error(w, "Invalid service key", http.StatusBadRequest)
		return
	}
	providers, err := r.lookupProviders(req.Context(), "", key, directoryMaxLimit)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeBadGateway).Inc()
		logger.Warnf("[Ingress] Directory lookup failed for %s://%s: %v", serviceTypeStr, serviceName, err)
		http.Error(w, "Service lookup failed", http.StatusBadGateway)
		return
	}
	var providerRec *api.PeerRecord
	for _, rec := range providers {
		recPID, decErr := peer.Decode(rec.GetPeerId())
		if decErr != nil {
			logger.Warnf("[Ingress] Ignoring provider record with invalid peer ID %q: %v", rec.GetPeerId(), decErr)
			continue
		}
		if recPID == targetPeer {
			providerRec = rec
			break
		}
	}
	if providerRec == nil || providerRec.GetIngress() == nil {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeNotFound).Inc()
		logger.Debugf("[Ingress] No ingress record found for %s (%s://%s)", targetPeer, serviceTypeStr, serviceName)
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	ing := providerRec.GetIngress()
	effectiveMode := api.EffectiveIngressAuthMode(ing)
	modeStr, err := api.IngressAuthModeToString(effectiveMode)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(ingressModeUnknown, ingressOutcomeDeny).Inc()
		logger.Warnf("[Ingress] Unsupported ingress auth mode %v for %s", effectiveMode, targetPeer)
		http.Error(w, "Unsupported ingress auth mode", http.StatusForbidden)
		return
	}

	r.keysMu.RLock()
	routerBiscuit := r.credential.biscuit
	r.keysMu.RUnlock()
	if len(routerBiscuit) == 0 {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeUnavailable).Inc()
		logger.Warn("[Ingress] Router credential unavailable")
		http.Error(w, "Router credential unavailable", http.StatusServiceUnavailable)
		return
	}
	routerBiscuitHeader := base64.StdEncoding.EncodeToString(routerBiscuit)

	targetURI := serviceTypeStr + "://" + serviceName
	backendPath := "/" + subpath
	isAgentCardGet := svcType == api.ServiceType_SERVICE_TYPE_A2A &&
		req.Method == http.MethodGet &&
		(subpath == "" || subpath == a2aAgentCardSubpath)

	var (
		verifiedCaller   *identity.VerifiedBiscuitClaims
		callerBiscuitHdr string
		evalParams       identity.IngressEvalParams
	)

	// On EDGE ingress (except unauthenticated A2A AgentCard GET), verify the
	// caller's Biscuit, revocation state, actor bans, rate limit, TAR rules, and
	// ServiceIngress.allow locally BEFORE dialing or authenticating the provider.
	if effectiveMode == api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE && !isAgentCardGet {
		bearerToken, ok := extractBearerToken(req.Header.Get("Authorization"))
		if !ok {
			if r.ingressLimiter != nil && !r.ingressLimiter.Allow("unauth:"+clientIP) {
				routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeRateLimited).Inc()
				logger.Warnf("[Ingress] Rate limit exceeded for unauthenticated client %s", clientIP)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			r.writeIngressUnauthorized(w, modeStr, "Missing or invalid Authorization: Bearer header")
			return
		}
		if isCompactJWT(bearerToken) {
			if r.ingressLimiter != nil && !r.ingressLimiter.Allow("unauth:"+clientIP) {
				routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeRateLimited).Inc()
				logger.Warnf("[Ingress] Rate limit exceeded for JWT client %s", clientIP)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			logger.Debugf("[Ingress] Rejecting raw JWT on edge ingress from %s for %s; exchange at /oauth/token required", clientIP, targetURI)
			r.writeIngressUnauthorized(w, modeStr, "Mesh Biscuit required; exchange platform JWT at /oauth/token")
			return
		}
		rawCaller, err := identity.DecodeBase64Biscuit(bearerToken)
		if err != nil {
			if r.ingressLimiter != nil && !r.ingressLimiter.Allow("unauth:"+clientIP) {
				routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeRateLimited).Inc()
				logger.Warnf("[Ingress] Rate limit exceeded for invalid token encoding from %s", clientIP)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			r.writeIngressUnauthorized(w, modeStr, "Invalid Bearer token encoding")
			return
		}
		verified, err := identity.InspectVerifiedBiscuit(rawCaller, r.getTrustedPublicKeys(), r.config.BiscuitTimeout)
		if err != nil {
			if r.ingressLimiter != nil && !r.ingressLimiter.Allow("unauth:"+clientIP) {
				routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeRateLimited).Inc()
				logger.Warnf("[Ingress] Rate limit exceeded for failed biscuit verification from %s", clientIP)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			logger.Warnf("[Ingress] Biscuit verification failed from %s for %s: %v", clientIP, targetURI, err)
			r.writeIngressUnauthorized(w, modeStr, "Invalid Bearer token")
			return
		}
		if r.ingressLimiter != nil && !r.ingressLimiter.Allow(biscuitRateLimitKey(verified.Biscuit, rawCaller)) {
			routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeRateLimited).Inc()
			logger.Warnf("[Ingress] Rate limit exceeded for caller %s from %s", verified.Principal(), clientIP)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		if r.isBiscuitRevoked(verified.Biscuit) {
			logger.Warnf("[Ingress] Refusing revoked Biscuit from %s for %s", clientIP, targetURI)
			r.writeIngressUnauthorized(w, modeStr, "Token has been revoked")
			return
		}
		for _, pidStr := range []string{verified.NodePeerID, verified.ActorNodePeerID, verified.ClientPeerID} {
			if pidStr == "" {
				continue
			}
			if actorPID, decErr := peer.Decode(pidStr); decErr == nil {
				if _, banned := r.bannedPeers.Load(actorPID); banned {
					routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeDeny).Inc()
					logger.Warnf("[Ingress] Refusing Biscuit from banned peer %s", actorPID)
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		evalParams = identity.IngressEvalParams{
			ServiceType:     serviceTypeStr,
			ServiceName:     serviceName,
			Method:          req.Method,
			Path:            backendPath,
			MeshPolicyRules: r.meshPolicyRules(),
			Allow:           ing.GetAllow(),
			Timeout:         r.config.BiscuitTimeout,
		}
		if svcType == api.ServiceType_SERVICE_TYPE_MCP {
			mcpTool, allowInit, bodyErr := api.InspectMCPHTTPRequestBody(req, api.DefaultMaxMCPBodyInspectBytes)
			if bodyErr != nil {
				routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeInvalid).Inc()
				logger.Warnf("[Ingress] Oversized or unreadable MCP body from %s for %s: %v", clientIP, targetURI, bodyErr)
				http.Error(w, bodyErr.Error(), http.StatusRequestEntityTooLarge)
				return
			}
			evalParams.MCPTool = mcpTool
			evalParams.AllowMCPStreamInit = allowInit
		}
		if _, err := identity.ValidateIngressCallerPreDial(verified, evalParams); err != nil {
			routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeDeny).Inc()
			logger.Warnf("[Ingress] Pre-dial AuthZ denied caller (%s) from %s for %s: %v", verified.Principal(), clientIP, targetURI, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		verifiedCaller = verified
		callerBiscuitHdr = base64.StdEncoding.EncodeToString(rawCaller)
	} else if r.ingressLimiter != nil {
		anonKey := "anon:" + clientIP + ":" + targetPeer.String()
		if !r.ingressLimiter.Allow(anonKey) {
			routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeRateLimited).Inc()
			logger.Warnf("[Ingress] Rate limit exceeded for client %s to target %s", clientIP, targetPeer)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	cred, err := r.ensureProviderAuthenticated(req.Context(), targetPeer, providerRec.GetAddrs())
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
		logger.Warnf("[Ingress] Could not reach or authenticate provider %s for %s://%s: %v", targetPeer, serviceTypeStr, serviceName, err)
		http.Error(w, "Bad Gateway: provider unreachable", http.StatusBadGateway)
		return
	}

	// Re-check the provider's role ceiling against current mesh policy so a
	// revoked role grant takes effect at the next sync without waiting for TTL.
	if err := r.requireIngress(targetPeer, svcType, serviceName, effectiveMode); err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeDeny).Inc()
		logger.Warnf("[Ingress] Provider %s no longer authorized to expose %s://%s (%s): %v", targetPeer, serviceTypeStr, serviceName, modeStr, err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Unauthenticated GET discovery of A2A AgentCard (both well-known path and
	// bare service root GET for resolvers such as a2a-go).
	if isAgentCardGet {
		r.serveIngressAgentCard(w, req, transport, targetPeer, serviceName, effectiveMode, modeStr, routerBiscuitHeader)
		return
	}

	if effectiveMode == api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeAllow).Inc()
		logger.Infow("Border Crossing",
			"direction", "inbound",
			"protocol", string(api.IngressProtocolID),
			"mode", api.IngressAuthModeStringPassthrough,
			"client_ip", clientIP,
			"target_peer_id", targetPeer.String(),
			"target", targetURI,
			"method", req.Method,
			"path", backendPath,
		)
		r.forwardIngressHTTP(w, req, transport, targetPeer, serviceTypeStr, serviceName, subpath, hasTrailingOrSubpath, routerBiscuitHeader, api.IngressAuthModeStringPassthrough, "")
		return
	}

	targetFacts, err := identity.TargetFactsFromBiscuit(cred.biscuit, r.getTrustedPublicKeys(), r.config.BiscuitTimeout)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
		logger.Warnf("[Ingress] Failed to extract target facts for %s: %v", targetPeer, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	evalParams.TargetFacts = targetFacts

	callerRes, err := identity.AuthorizeIngressDelegatedBiscuit(verifiedCaller, evalParams)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeDeny).Inc()
		logger.Warnf("[Ingress] Edge AuthZ denied Biscuit caller (%s) from %s for %s: %v", verifiedCaller.Principal(), clientIP, targetURI, err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeAllow).Inc()
	logger.Infow("Border Crossing",
		"direction", "inbound",
		"protocol", string(api.IngressProtocolID),
		"mode", api.IngressAuthModeStringEdge,
		"client_ip", clientIP,
		"principal", callerRes.Principal,
		"roles", callerRes.Roles,
		"task", callerRes.TaskName,
		"target_peer_id", targetPeer.String(),
		"target", targetURI,
		"method", req.Method,
		"path", backendPath,
	)

	r.forwardIngressHTTP(w, req, transport, targetPeer, serviceTypeStr, serviceName, subpath, hasTrailingOrSubpath, routerBiscuitHeader, api.IngressAuthModeStringEdge, callerBiscuitHdr)
}

func (r *Router) forwardIngressHTTP(
	w http.ResponseWriter,
	req *http.Request,
	transport http.RoundTripper,
	targetPeer peer.ID,
	serviceTypeStr, serviceName, subpath string,
	hasTrailingOrSubpath bool,
	routerBiscuitHeader, modeStr, callerBiscuitHdr string,
) {
	upstreamPath := "/" + serviceTypeStr + "/" + serviceName
	if hasTrailingOrSubpath {
		upstreamPath += "/" + subpath
	}
	stripAuth := modeStr == api.IngressAuthModeStringEdge

	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = targetPeer.String()
			pr.Out.URL.Path = upstreamPath
			pr.Out.URL.RawPath = ""
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Host = targetPeer.String()

			api.SanitizeExternalIngressHeaders(pr.Out.Header, stripAuth)
			pr.Out.Header.Set(api.HeaderMeshBiscuit, routerBiscuitHeader)
			pr.Out.Header.Set(api.HeaderMeshIngress, modeStr)
			if callerBiscuitHdr != "" {
				pr.Out.Header.Set(api.HeaderMeshIngressCallerBiscuit, callerBiscuitHdr)
			}
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeInvalid).Inc()
				logger.Warnf("[Ingress] Request body to %s (%s://%s) exceeded size limit", targetPeer, serviceTypeStr, serviceName)
				http.Error(rw, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}
			routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
			logger.Warnf("[Ingress] Upstream stream to %s (%s://%s) failed: %v", targetPeer, serviceTypeStr, serviceName, err)
			http.Error(rw, "Bad Gateway", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, req)
}

func (r *Router) serveIngressAgentCard(
	w http.ResponseWriter,
	req *http.Request,
	transport http.RoundTripper,
	targetPeer peer.ID,
	serviceName string,
	effectiveMode api.IngressAuthMode,
	modeStr string,
	routerBiscuitHeader string,
) {
	cardURL := fmt.Sprintf("http://%s/%s/%s/%s", targetPeer.String(), api.ServiceTypeStringA2A, serviceName, a2aAgentCardSubpath)
	outReq, err := http.NewRequestWithContext(req.Context(), http.MethodGet, cardURL, nil)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
		logger.Errorf("[Ingress] Failed to build A2A agent card request for %s/%s: %v", targetPeer, serviceName, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	outReq.Header.Set(api.HeaderMeshBiscuit, routerBiscuitHeader)
	outReq.Header.Set(api.HeaderMeshIngress, modeStr)
	if effectiveMode == api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH {
		if authHdr := req.Header.Get("Authorization"); authHdr != "" {
			outReq.Header.Set("Authorization", authHdr)
		}
	}

	resp, err := (&http.Client{Transport: transport, Timeout: 15 * time.Second}).Do(outReq)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
		logger.Warnf("[Ingress] Failed to fetch A2A agent card from %s/%s: %v", targetPeer, serviceName, err)
		http.Error(w, "Bad Gateway: agent card fetch failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body := io.LimitReader(resp.Body, maxIngressCardBodyBytes)
	if resp.StatusCode != http.StatusOK {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
		logger.Warnf("[Ingress] Backend returned status %d for A2A agent card %s/%s", resp.StatusCode, targetPeer, serviceName)
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, body)
		return
	}

	var card a2a.AgentCard
	if err := json.NewDecoder(body).Decode(&card); err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
		logger.Warnf("[Ingress] Invalid A2A agent card JSON from %s/%s: %v", targetPeer, serviceName, err)
		http.Error(w, "Bad Gateway: invalid agent card JSON", http.StatusBadGateway)
		return
	}

	serviceBase := fmt.Sprintf("%s/%s/%s/%s", r.effectiveIngressBaseURL(), targetPeer.String(), api.ServiceTypeStringA2A, serviceName)
	if err := r.rewriteAgentCardForIngress(&card, serviceBase, r.effectivePublicControlPlaneURL(), effectiveMode); err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
		logger.Warnf("[Ingress] A2A agent card from %s/%s unusable on ingress: %v", targetPeer, serviceName, err)
		http.Error(w, fmt.Sprintf("Bad Gateway: %v", err), http.StatusBadGateway)
		return
	}

	out, err := json.Marshal(&card)
	if err != nil {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeBadGateway).Inc()
		logger.Errorf("[Ingress] Failed to marshal AgentCard for %s/%s: %v", targetPeer, serviceName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	for _, h := range []string{"Cache-Control", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	sum := sha256.Sum256(out)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	if ingressETagMatches(req.Header.Get("If-None-Match"), etag) {
		routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeAllow).Inc()
		w.WriteHeader(http.StatusNotModified)
		return
	}
	routerIngressRequestsTotal.WithLabelValues(modeStr, ingressOutcomeAllow).Inc()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	_, _ = w.Write(out)
}

func (r *Router) rewriteAgentCardForIngress(card *a2a.AgentCard, serviceBase, publicControlPlaneURL string, effectiveMode api.IngressAuthMode) error {
	kept := make([]*a2a.AgentInterface, 0, len(card.SupportedInterfaces))
	for _, iface := range card.SupportedInterfaces {
		if iface == nil || !isHTTPTransportBinding(iface.ProtocolBinding) {
			continue
		}
		iface.URL = resolveIngressInterfaceURL(serviceBase, iface.URL)
		kept = append(kept, iface)
	}
	if len(kept) == 0 {
		return fmt.Errorf("agent card advertises no HTTP interface (JSONRPC or HTTP+JSON)")
	}
	card.SupportedInterfaces = kept
	card.Signatures = nil
	if card.Skills == nil {
		card.Skills = []a2a.AgentSkill{}
	}
	if card.DefaultInputModes == nil {
		card.DefaultInputModes = []string{}
	}
	if card.DefaultOutputModes == nil {
		card.DefaultOutputModes = []string{}
	}

	if effectiveMode == api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE {
		cpBase := strings.TrimSuffix(strings.TrimSpace(publicControlPlaneURL), "/")
		schemes := a2a.NamedSecuritySchemes{
			"bearer": a2a.HTTPAuthSecurityScheme{
				Scheme:       "bearer",
				BearerFormat: "Biscuit",
				Description:  "Agent Mesh delegated session or task Biscuit",
			},
		}
		reqs := a2a.SecurityRequirementsOptions{
			{"bearer": {}},
		}
		if cpBase != "" {
			schemes["agentmesh_oauth2"] = a2a.OAuth2SecurityScheme{
				Description:       "Agent Mesh OAuth 2.1 Authorization Server",
				Oauth2MetadataURL: cpBase + "/.well-known/oauth-authorization-server",
				Flows: a2a.AuthorizationCodeOAuthFlow{
					AuthorizationURL: cpBase + "/oauth/authorize",
					TokenURL:         cpBase + "/oauth/token",
					Scopes: map[string]string{
						"openid":  "OpenID Connect identity",
						"email":   "Email claim",
						"profile": "Profile claim",
					},
					PKCERequired: true,
				},
			}
			reqs = append(reqs, a2a.SecurityRequirements{"agentmesh_oauth2": {}})
		}
		card.SecuritySchemes = schemes
		card.SecurityRequirements = reqs
	}
	return nil
}

func (r *Router) ensureProviderAuthenticated(ctx context.Context, targetPeer peer.ID, rawAddrs []string) (memberCredential, error) {
	if r.Host == nil {
		return memberCredential{}, errors.New("router host is not initialized")
	}
	if r.isPeerAuthenticated(targetPeer) && r.Host.Network().Connectedness(targetPeer) == network.Connected {
		if v, ok := r.credentials.Load(targetPeer); ok {
			return v.(memberCredential), nil
		}
	}

	dialCtx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "ingress"), ingressDialTimeout)
	defer cancel()

	transportAddrs, relayPeers := splitProviderAddrs(targetPeer, rawAddrs)
	for _, relayID := range relayPeers {
		if relayID != r.Host.ID() && !r.isPeerAuthenticated(relayID) {
			r.ensureFederated(dialCtx)
			break
		}
	}
	if len(transportAddrs) > 0 {
		r.Host.Peerstore().AddAddrs(targetPeer, transportAddrs, 2*time.Minute)
	}
	if r.Host.Network().Connectedness(targetPeer) != network.Connected {
		if err := r.Host.Connect(dialCtx, peer.AddrInfo{ID: targetPeer, Addrs: transportAddrs}); err != nil {
			return memberCredential{}, fmt.Errorf("connect to provider %s: %w", targetPeer, err)
		}
	}
	if v, ok := r.credentials.Load(targetPeer); ok && r.isPeerAuthenticated(targetPeer) {
		return v.(memberCredential), nil
	}
	return r.authenticateIngressMember(dialCtx, targetPeer)
}

func (r *Router) authenticateIngressMember(ctx context.Context, targetPeer peer.ID) (memberCredential, error) {
	if _, banned := r.bannedPeers.Load(targetPeer); banned {
		return memberCredential{}, fmt.Errorf("peer %s is banned", targetPeer)
	}
	r.keysMu.RLock()
	ourBiscuit := r.credential.biscuit
	r.keysMu.RUnlock()
	if len(ourBiscuit) == 0 {
		return memberCredential{}, errors.New("router has no credential")
	}

	s, err := r.Host.NewStream(ctx, targetPeer, api.AuthProtocolID)
	if err != nil {
		return memberCredential{}, fmt.Errorf("open auth stream: %w", err)
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(ingressDialTimeout))

	frameBytes, err := proto.Marshal(&api.AuthFrame{Biscuit: ourBiscuit})
	if err != nil {
		return memberCredential{}, err
	}
	if err := msgio.NewVarintWriter(s).WriteMsg(frameBytes); err != nil {
		_ = s.Reset()
		return memberCredential{}, fmt.Errorf("write auth frame: %w", err)
	}

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		_ = s.Reset()
		return memberCredential{}, fmt.Errorf("read auth response: %w", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		return memberCredential{}, fmt.Errorf("unmarshal auth response: %w", err)
	}
	if !resp.Success {
		return memberCredential{}, fmt.Errorf("provider rejected auth handshake: %s", resp.Error)
	}

	b, verifyingKey, expiry, err := identity.VerifyBiscuitAdmission(resp.Biscuit, targetPeer, r.getTrustedPublicKeys(), r.config.BiscuitTimeout)
	if err != nil {
		return memberCredential{}, fmt.Errorf("verify provider biscuit: %w", err)
	}
	if r.isBiscuitRevoked(b) {
		return memberCredential{}, fmt.Errorf("provider %s biscuit is revoked", targetPeer)
	}
	cred := memberCredential{biscuit: b, key: verifyingKey}
	r.admitPeer(targetPeer, expiry)
	r.credentials.Store(targetPeer, cred)
	return cred, nil
}

func splitProviderAddrs(targetPeer peer.ID, rawAddrs []string) ([]multiaddr.Multiaddr, []peer.ID) {
	var transport []multiaddr.Multiaddr
	var relays []peer.ID
	for _, s := range rawAddrs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			logger.Debugf("[Ingress] Ignoring invalid provider multiaddr %q for %s: %v", s, targetPeer, err)
			continue
		}
		tAddr, pid := peer.SplitAddr(ma)
		if pid != "" && pid != targetPeer {
			logger.Debugf("[Ingress] Ignoring provider multiaddr %q naming %s instead of %s", s, pid, targetPeer)
			continue
		}
		if tAddr == nil {
			continue
		}
		transport = append(transport, tAddr)
		if _, err := tAddr.ValueForProtocol(multiaddr.P_CIRCUIT); err == nil {
			if relayStr, err := tAddr.ValueForProtocol(multiaddr.P_P2P); err == nil {
				if rpid, err := peer.Decode(relayStr); err == nil {
					relays = append(relays, rpid)
				}
			}
		}
	}
	return transport, relays
}

func extractBearerToken(header string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	return tok, tok != ""
}

func isCompactJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

func clientIPFromRemoteAddr(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host != "" {
		return host
	}
	if remoteAddr != "" {
		return remoteAddr
	}
	return "unknown"
}

func isHTTPTransportBinding(binding a2a.TransportProtocol) bool {
	switch strings.ToUpper(string(binding)) {
	case string(a2a.TransportProtocolJSONRPC), string(a2a.TransportProtocolHTTPJSON):
		return true
	}
	return false
}

func resolveIngressInterfaceURL(base, raw string) string {
	ref, err := url.Parse(raw)
	if err != nil || ref.Scheme != "" || ref.Host != "" || ref.User != nil || ref.Opaque != "" ||
		strings.HasPrefix(ref.Path, "/") || api.HasDotSegment(ref.Path) {
		return base
	}
	out := base
	if ref.Path != "" {
		out += "/" + ref.EscapedPath()
	}
	if ref.RawQuery != "" {
		out += "?" + ref.RawQuery
	}
	return out
}

func ingressETagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}
