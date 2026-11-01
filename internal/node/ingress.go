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

package node

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	gostream "github.com/libp2p/go-libp2p-gostream"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	externalIngressOutcomeAllow           = "allow"
	externalIngressOutcomeDeny            = "deny"
	externalIngressOutcomeUnauthenticated = "unauthenticated"
	externalIngressOutcomeNotFound        = "not_found"
	externalIngressOutcomeRateLimited     = "rate_limited"
	externalIngressOutcomeInvalid         = "invalid"
)

var externalIngressRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_node_external_ingress_requests_total",
		Help: "External HTTP ingress requests received from enrolled routers over /mesh/ingress/1.0.0, by auth mode and outcome",
	},
	[]string{"mode", "outcome"},
)

func init() {
	for _, mode := range []string{api.IngressAuthModeStringEdge, api.IngressAuthModeStringPassthrough, "unknown"} {
		for _, outcome := range []string{
			externalIngressOutcomeAllow,
			externalIngressOutcomeDeny,
			externalIngressOutcomeUnauthenticated,
			externalIngressOutcomeNotFound,
			externalIngressOutcomeRateLimited,
			externalIngressOutcomeInvalid,
		} {
			externalIngressRequestsTotal.WithLabelValues(mode, outcome)
		}
	}
}

// routerIngressURLs returns the sorted, deduplicated public ingress base URLs
// advertised by routers in this node's catalog.
func (n *AgentMeshNode) routerIngressURLs() []string {
	cands := n.routerCandidates()
	seen := make(map[string]bool, len(cands))
	var out []string
	for _, c := range cands {
		u := strings.TrimSuffix(strings.TrimSpace(c.IngressURL), "/")
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// RouterIngressURLs returns the sorted, deduplicated public ingress base URLs
// advertised by routers in this node's catalog.
func (n *AgentMeshNode) RouterIngressURLs() []string {
	return n.routerIngressURLs()
}

// PreferredRouterIngressURL returns the preferred public ingress base URL for
// this node, preferring a router the node is currently attached to before
// falling back to any router in the catalog that advertises an ingress_url.
func (n *AgentMeshNode) PreferredRouterIngressURL() string {
	var attachedURLs []string
	for _, c := range n.routerCandidates() {
		u := strings.TrimSuffix(strings.TrimSpace(c.IngressURL), "/")
		if u == "" || !n.isAttached(c.ID) {
			continue
		}
		if !slices.Contains(attachedURLs, u) {
			attachedURLs = append(attachedURLs, u)
		}
	}
	if len(attachedURLs) > 0 {
		sort.Strings(attachedURLs)
		return attachedURLs[0]
	}
	if urls := n.routerIngressURLs(); len(urls) > 0 {
		return urls[0]
	}
	return ""
}

// ExternalIngressHandler returns the HTTP handler mounted on
// api.IngressProtocolID (/mesh/ingress/1.0.0).
func (n *AgentMeshNode) ExternalIngressHandler() http.Handler {
	return n.externalIngressHandler()
}

// logIngressURLs logs the public HTTP ingress URLs for a registered service
// whenever routers in the catalog advertise an ingress_url.
func (n *AgentMeshNode) logIngressURLs(info *api.ServiceInfo) {
	if info == nil || info.GetIngress() == nil {
		return
	}
	typeStr, err := api.ServiceTypeToString(info.GetType())
	if err != nil {
		return
	}
	modeStr, err := api.IngressAuthModeToString(api.EffectiveIngressAuthMode(info.GetIngress()))
	if err != nil {
		modeStr = api.IngressAuthModeStringEdge
	}
	pid, err := n.localPeerID()
	if err != nil || pid == "" {
		return
	}
	urls := n.routerIngressURLs()
	if len(urls) == 0 {
		logger.Infof("[Ingress] Service %s/%s configured for %s ingress; no router currently advertises an ingress_url", typeStr, info.GetName(), modeStr)
		return
	}
	for _, base := range urls {
		logger.Infof("[Ingress] Public %s ingress URL for %s/%s: %s/%s/%s/%s", modeStr, typeStr, info.GetName(), base, pid.String(), typeStr, info.GetName())
	}
}

// StartExternalIngressServer starts the HTTP-over-libp2p server on
// api.IngressProtocolID (/mesh/ingress/1.0.0) that receives external HTTP
// requests forwarded by enrolled routers. The listener is built on routerHost,
// so a stream from any peer that did not authenticate as a router is reset at
// the gate before the HTTP server reads it; the handler's X-Mesh-Biscuit check
// below is the second, independent layer.
func (n *AgentMeshNode) StartExternalIngressServer(ctx context.Context) error {
	gated := &routerHost{meshHost{Host: n.Host, n: n}}
	listener, err := gostream.Listen(gated, api.IngressProtocolID)
	if err != nil {
		return err
	}

	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler:           n.externalIngressHandler(),
	}

	go func() {
		logger.Infof("[Ingress] Starting external ingress HTTP server on protocol %s", api.IngressProtocolID)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Errorf("[Ingress] External ingress server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := server.Close(); err != nil {
			logger.Errorf("[Ingress] Failed to close external ingress server: %v", err)
		}
		if err := listener.Close(); err != nil {
			logger.Errorf("[Ingress] Failed to close external ingress listener: %v", err)
		}
	}()

	return nil
}

func (n *AgentMeshNode) externalIngressHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := &readCloserWithCount{ReadCloser: r.Body}
		r.Body = rc
		wc := &responseWriterWithCount{ResponseWriter: w, statusCode: http.StatusOK}
		w = wc

		var remotePeer peer.ID
		var target string
		modeMetric := "unknown"

		defer func() {
			peerIDStr := ""
			if remotePeer != "" {
				peerIDStr = remotePeer.String()
			}
			finalTarget := target
			if finalTarget == "" {
				finalTarget = "unauthenticated_or_failed"
			}
			logger.Infow("Stream Accounting",
				"peer_id", peerIDStr,
				"target", finalTarget,
				"protocol", string(api.IngressProtocolID),
				"bytes_read", rc.bytesRead.Load(),
				"bytes_written", wc.bytesWritten.Load(),
			)
		}()

		path := r.URL.Path
		if api.HasDotSegment(path) {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeInvalid)
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeInvalid)
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		serviceTypeStr := strings.ToLower(parts[0])
		serviceName := parts[1]
		upstreamPath := ""
		if len(parts) > 2 {
			upstreamPath = parts[2]
		}

		serviceType, err := api.ParseServiceType(serviceTypeStr)
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeInvalid)
			http.Error(w, "Invalid service type", http.StatusBadRequest)
			return
		}
		if !api.IsInboundServiceType(serviceType) {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeNotFound)
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}

		remotePeer, err = peer.Decode(r.RemoteAddr)
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeInvalid)
			http.Error(w, "Invalid remote peer", http.StatusBadRequest)
			return
		}
		if n.revokedPeers != nil && n.revokedPeers.Contains(remotePeer.String()) {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			logger.Warnf("[ExternalIngress] Refusing banned peer %s", remotePeer)
			refuse(w, http.StatusForbidden, "Peer is revoked", proxyStatusDenied)
			return
		}
		if n.externalIngressLimiter != nil && !n.externalIngressLimiter.Allow(remotePeer.String()) {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeRateLimited)
			logger.Warnf("[ExternalIngress] Rate limit exceeded for router %s", remotePeer)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Verify the forwarding peer is an enrolled, non-revoked router holding
		// role("mesh:role:router") bound to remotePeer in Block 0.
		routerBiscuitHeader := r.Header.Get(api.HeaderMeshBiscuit)
		if routerBiscuitHeader == "" {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeUnauthenticated)
			http.Error(w, "Missing X-Mesh-Biscuit header", http.StatusUnauthorized)
			return
		}
		routerBiscuitBytes, err := identity.DecodeBase64Biscuit(routerBiscuitHeader)
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeInvalid)
			http.Error(w, "Invalid X-Mesh-Biscuit encoding", http.StatusBadRequest)
			return
		}
		routerClaims, err := n.VerifyLocalBiscuit(routerBiscuitBytes)
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			logger.Warnf("[ExternalIngress] Router biscuit verification failed for %s: %v", remotePeer, err)
			refuse(w, http.StatusForbidden, "Router authentication failed", proxyStatusDenied)
			return
		}
		if err := identity.RequireAuthorityBinding(routerClaims.Biscuit, remotePeer); err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			logger.Warnf("[ExternalIngress] Router biscuit binding mismatch for %s: %v", remotePeer, err)
			refuse(w, http.StatusForbidden, "Router authentication failed", proxyStatusDenied)
			return
		}
		if !slices.Contains(routerClaims.Roles, api.RoleRouter) {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			logger.Warnf("[ExternalIngress] Peer %s lacks %s role on %s", remotePeer, api.RoleRouter, api.IngressProtocolID)
			refuse(w, http.StatusForbidden, "Forbidden: only enrolled routers may forward external ingress", proxyStatusDenied)
			return
		}

		if n.services == nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeInvalid)
			logger.Error("[ExternalIngress] Service registry not initialized")
			http.Error(w, "Service registry not initialized", http.StatusServiceUnavailable)
			return
		}
		svc, ok := n.services.GetTyped(serviceType, serviceName)
		if !ok || svc.Handler() == nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeNotFound)
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		ing := svc.Info().GetIngress()
		if ing == nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeNotFound)
			logger.Warnf("[ExternalIngress] Refusing external ingress to internal-only service %s://%s from router %s", serviceTypeStr, truncateForLog(serviceName), remotePeer)
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		if gate, ok := svc.(ExternalIngressGate); ok && !gate.ExternalIngressAllowed() {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeNotFound)
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}

		effectiveMode := api.EffectiveIngressAuthMode(ing)
		modeStr, err := api.IngressAuthModeToString(effectiveMode)
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			refuse(w, http.StatusForbidden, "Unsupported service ingress auth mode", proxyStatusConfigurationError)
			return
		}
		modeMetric = modeStr

		if wireMode := strings.TrimSpace(r.Header.Get(api.HeaderMeshIngress)); wireMode != "" && wireMode != modeStr {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			logger.Warnf("[ExternalIngress] Router %s sent mode %q for %s://%s configured as %q", remotePeer, truncateForLog(wireMode), serviceTypeStr, serviceName, modeStr)
			refuse(w, http.StatusForbidden, "Ingress auth mode mismatch", proxyStatusDenied)
			return
		}

		target = serviceTypeStr + "://" + serviceName
		backendPath := "/" + upstreamPath

		if effectiveMode == api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH {
			api.SanitizeExternalIngressHeaders(r.Header, false)
			r.Header.Set(api.HeaderPeerID, remotePeer.String())
			r.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringPassthrough)

			n.recordExternalIngress(modeMetric, externalIngressOutcomeAllow)
			logger.Infow("Border Crossing",
				"direction", "inbound",
				"protocol", string(api.IngressProtocolID),
				"mode", api.IngressAuthModeStringPassthrough,
				"router_peer_id", remotePeer.String(),
				"target", target,
				"method", r.Method,
				"path", backendPath,
			)
			rewriteExternalIngressRequestPath(r, parts, upstreamPath)
			svc.Handler().ServeHTTP(w, r)
			return
		}

		// INGRESS_AUTH_MODE_EDGE: an enrolled router may fetch the public A2A
		// AgentCard without caller credentials so external A2A clients can
		// discover SecuritySchemes before authenticating.
		callerBiscuitHeader := strings.TrimSpace(r.Header.Get(api.HeaderMeshIngressCallerBiscuit))
		if serviceType == api.ServiceType_SERVICE_TYPE_A2A &&
			r.Method == http.MethodGet &&
			upstreamPath == a2aAgentCardPath &&
			callerBiscuitHeader == "" {
			api.SanitizeExternalIngressHeaders(r.Header, true)
			r.Header.Set(api.HeaderPeerID, remotePeer.String())
			r.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringEdge)

			n.recordExternalIngress(modeMetric, externalIngressOutcomeAllow)
			logger.Infow("Border Crossing",
				"direction", "inbound",
				"protocol", string(api.IngressProtocolID),
				"mode", api.IngressAuthModeStringEdge,
				"router_peer_id", remotePeer.String(),
				"principal", "anonymous:agent-card",
				"target", target,
				"method", r.Method,
				"path", backendPath,
			)
			rewriteExternalIngressRequestPath(r, parts, upstreamPath)
			svc.Handler().ServeHTTP(w, r)
			return
		}

		if callerBiscuitHeader == "" {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeUnauthenticated)
			logger.Warnf("[ExternalIngress] Missing caller biscuit on edge ingress request from router %s for %s", remotePeer, target)
			http.Error(w, "Missing caller credentials on edge ingress request", http.StatusUnauthorized)
			return
		}

		callerBiscuitBytes, err := identity.DecodeBase64Biscuit(callerBiscuitHeader)
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeInvalid)
			logger.Warnf("[ExternalIngress] Invalid caller biscuit encoding via router %s for %s: %v", remotePeer, target, err)
			http.Error(w, "Invalid caller biscuit encoding", http.StatusBadRequest)
			return
		}
		verifiedCaller, err := n.VerifyLocalBiscuit(callerBiscuitBytes)
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			logger.Warnf("[ExternalIngress] Caller biscuit verification failed via router %s for %s: %v", remotePeer, target, err)
			refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusDenied)
			return
		}

		evalParams, err := n.buildExternalIngressEvalParams(serviceTypeStr, serviceName, r.Method, backendPath, ing.GetAllow())
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			logger.Warnf("[ExternalIngress] Failed to build evaluation context for %s: %v", target, err)
			refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusConfigurationError)
			return
		}

		if serviceType == api.ServiceType_SERVICE_TYPE_MCP {
			preParams := evalParams
			preParams.AllowMCPStreamInit = true
			if _, authErr := identity.AuthorizeIngressDelegatedBiscuit(verifiedCaller, preParams); authErr != nil {
				n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
				logger.Warnf("[ExternalIngress] Pre-body MCP AuthZ failed via router %s for %s: %v", remotePeer, target, authErr)
				refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusDenied)
				return
			}
			mcpTool, allowInit, bodyErr := api.InspectMCPHTTPRequestBody(r, api.DefaultMaxMCPBodyInspectBytes)
			if bodyErr != nil {
				n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
				logger.Warnf("[ExternalIngress] MCP body inspection failed via router %s for %s: %v", remotePeer, target, bodyErr)
				refuse(w, http.StatusRequestEntityTooLarge, bodyErr.Error(), proxyStatusDenied)
				return
			}
			evalParams.MCPTool = mcpTool
			evalParams.AllowMCPStreamInit = allowInit
		}

		callerRes, err := identity.AuthorizeIngressDelegatedBiscuit(verifiedCaller, evalParams)
		if err != nil {
			n.recordExternalIngress(modeMetric, externalIngressOutcomeDeny)
			logger.Warnf("[ExternalIngress] AuthZ denied via router %s for %s: %v", remotePeer, target, err)
			refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusDenied)
			return
		}

		api.SanitizeExternalIngressHeaders(r.Header, true)
		r.Header.Set(api.HeaderPeerID, remotePeer.String())
		r.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringEdge)
		if callerRes.Principal != "" {
			r.Header.Set(api.HeaderMeshPrincipal, callerRes.Principal)
		}
		if len(callerRes.Roles) > 0 {
			r.Header.Set(api.HeaderMeshRoles, strings.Join(callerRes.Roles, ","))
		}
		if callerRes.TaskName != "" {
			r.Header.Set(api.HeaderMeshTask, callerRes.TaskName)
		}

		n.recordExternalIngress(modeMetric, externalIngressOutcomeAllow)
		logger.Infow("Border Crossing",
			"direction", "inbound",
			"protocol", string(api.IngressProtocolID),
			"mode", api.IngressAuthModeStringEdge,
			"router_peer_id", remotePeer.String(),
			"principal", callerRes.Principal,
			"roles", callerRes.Roles,
			"task", callerRes.TaskName,
			"target", target,
			"method", r.Method,
			"path", backendPath,
		)

		rewriteExternalIngressRequestPath(r, parts, upstreamPath)
		ctx := r.Context()
		if len(callerBiscuitBytes) > 0 {
			ctx = WithCallerBiscuit(ctx, callerBiscuitBytes)
		}
		svc.Handler().ServeHTTP(w, r.WithContext(ctx))
	})
}

func (n *AgentMeshNode) buildExternalIngressEvalParams(serviceType, serviceName, method, path string, allow []string) (identity.IngressEvalParams, error) {
	pol, err := n.meshPolicy()
	if err != nil {
		return identity.IngressEvalParams{}, err
	}
	return identity.IngressEvalParams{
		ServiceType:     serviceType,
		ServiceName:     serviceName,
		Method:          method,
		Path:            path,
		TargetFacts:     pol.TargetFacts,
		MeshPolicyRules: pol.MeshRules,
		LocalPolicies:   pol.LocalPolicies,
		LocalChecks:     pol.LocalChecks,
		LocalRules:      pol.LocalRules,
		Allow:           allow,
		Timeout:         n.BiscuitTimeout,
	}, nil
}

func rewriteExternalIngressRequestPath(r *http.Request, parts []string, upstreamPath string) {
	if upstreamPath == "" {
		r.URL.Path = "/"
		if len(parts) == 2 {
			r.Header.Set(api.HeaderMeshNoTrailingSlash, "true")
		}
	} else {
		r.URL.Path = "/" + upstreamPath
	}
	r.URL.RawPath = ""
}

// CallerDetails describes the verified mesh caller behind an inbound HTTP
// request delivered to a registered Service.Handler() over /libp2p-http or
// /mesh/ingress/1.0.0.
type CallerDetails struct {
	PeerID          string
	Principal       string
	Roles           []string
	Labels          map[string]string
	Task            string
	ExternalIngress bool
}

// CallerDetailsFromRequest extracts the verified caller identity from an HTTP
// request already authenticated by StartIngressServer or StartExternalIngressServer.
func (n *AgentMeshNode) CallerDetailsFromRequest(r *http.Request) CallerDetails {
	ingressMode := strings.TrimSpace(r.Header.Get(api.HeaderMeshIngress))
	remotePeer := strings.TrimSpace(r.Header.Get(api.HeaderPeerID))

	if ingressMode == api.IngressAuthModeStringPassthrough {
		return CallerDetails{
			PeerID:          remotePeer,
			Principal:       "passthrough",
			ExternalIngress: true,
		}
	}

	callerBiscuit := CallerBiscuitFromContext(r.Context())
	if ingressMode == api.IngressAuthModeStringEdge && len(callerBiscuit) == 0 {
		return CallerDetails{
			PeerID:          remotePeer,
			Principal:       "anonymous:agent-card",
			ExternalIngress: true,
		}
	}

	out := CallerDetails{
		PeerID:          remotePeer,
		Principal:       r.Header.Get(api.HeaderMeshPrincipal),
		Task:            r.Header.Get(api.HeaderMeshTask),
		ExternalIngress: ingressMode != "",
	}
	if hdrRoles := strings.TrimSpace(r.Header.Get(api.HeaderMeshRoles)); hdrRoles != "" {
		out.Roles = strings.Split(hdrRoles, ",")
	}
	if len(callerBiscuit) > 0 && n != nil {
		if claims, err := n.VerifyLocalBiscuit(callerBiscuit); err == nil && claims != nil {
			if out.ExternalIngress && claims.ActorNodePeerID != "" {
				if id, pErr := peer.Decode(claims.ActorNodePeerID); pErr == nil {
					out.PeerID = id.String()
				} else {
					logger.Debugf("[ExternalIngress] Ignoring invalid actor_node %q in caller biscuit: %v", claims.ActorNodePeerID, pErr)
				}
			}
			if out.Principal == "" {
				out.Principal = claims.Principal()
			}
			if len(out.Roles) == 0 && len(claims.Roles) > 0 {
				out.Roles = slices.Clone(claims.Roles)
			}
			if len(claims.Labels) > 0 {
				out.Labels = maps.Clone(claims.Labels)
			}
			if out.Task == "" {
				out.Task = outermostTaskName(claims.TaskRules)
			}
		}
	}
	return out
}

func outermostTaskName(rules []*api.TaskAuthorizationRule) string {
	for i := len(rules) - 1; i >= 0; i-- {
		if name := rules[i].GetName(); name != "" {
			return name
		}
	}
	return ""
}
