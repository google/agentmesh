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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/credprovider"
	"github.com/google/agentmesh/internal/identity"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/peer"
)

// WithCallerBiscuit attaches a verified caller Biscuit (such as a narrowed
// Task Biscuit or an exchanged Delegated Session Biscuit) to ctx so outbound
// mesh and egress handlers use it instead of the node's standing identity.
func WithCallerBiscuit(ctx context.Context, biscuitBytes []byte) context.Context {
	return credprovider.WithCallerBiscuit(ctx, biscuitBytes)
}

// CallerBiscuitFromContext returns the caller Biscuit attached to ctx, or nil.
func CallerBiscuitFromContext(ctx context.Context) []byte {
	return credprovider.CallerBiscuitFromContext(ctx)
}

// GetRequestIdentity returns the caller Biscuit from ctx when present,
// falling back to the node's own enrolled Biscuit identity.
func (n *AgentMeshNode) GetRequestIdentity(ctx context.Context) []byte {
	if b := CallerBiscuitFromContext(ctx); len(b) > 0 {
		return b
	}
	return n.GetIdentity()
}

// trustedPublicKeys returns the Control Plane Ed25519 public keys currently
// trusted by this node, falling back to the stored mesh config key if needed.
func (n *AgentMeshNode) trustedPublicKeys() []ed25519.PublicKey {
	n.keysMu.RLock()
	keys := publicKeysOf(n.trustedKeys)
	n.keysMu.RUnlock()
	if len(keys) == 0 && n.Store != nil {
		if pubKeyBytes, _, err := n.Store.LoadMeshConfig(); err == nil && len(pubKeyBytes) == ed25519.PublicKeySize {
			keys = append(keys, ed25519.PublicKey(pubKeyBytes))
		}
	}
	return keys
}

// VerifyLocalBiscuit verifies a raw Biscuit against the node's revocation
// cache, banned peer cache, and trusted Control Plane keys, returning its
// extracted claims and TaskAuthorizationRule chain.
func (n *AgentMeshNode) VerifyLocalBiscuit(rawToken []byte) (*identity.VerifiedBiscuitClaims, error) {
	if len(rawToken) == 0 {
		return nil, errors.New("empty biscuit token")
	}
	b, _, err := identity.UnmarshalInbound(rawToken)
	if err != nil {
		return nil, fmt.Errorf("invalid biscuit: %w", err)
	}
	if n.IsBiscuitRevoked(b) {
		return nil, errors.New("biscuit is revoked")
	}
	keys := n.trustedPublicKeys()
	if len(keys) == 0 {
		return nil, errors.New("no trusted control plane keys available")
	}
	claims, err := identity.InspectVerifiedBiscuit(rawToken, keys, n.BiscuitTimeout)
	if err != nil {
		return nil, err
	}
	if n.revokedPeers != nil {
		for _, pidStr := range []string{claims.NodePeerID, claims.ActorNodePeerID, claims.ClientPeerID} {
			if pidStr == "" {
				continue
			}
			if pid, pErr := peer.Decode(pidStr); pErr == nil {
				if _, banned := n.revokedPeers.Get(pid.String()); banned {
					return nil, fmt.Errorf("peer %s is banned", pid.String())
				}
			}
		}
	}
	return claims, nil
}

// verifyLocalCallerBiscuit verifies a Biscuit presented to this node's local
// sidecar or OAuth token endpoint. Unattenuated standing node Biscuits
// (len(claims.TaskRules) == 0) must be bound to this node's localPeerID;
// task-attenuated Biscuits (len(claims.TaskRules) > 0) may be further
// attenuated or exchanged for an outbound border JWT at a PEP node.
func (n *AgentMeshNode) verifyLocalCallerBiscuit(rawToken []byte) (*identity.VerifiedBiscuitClaims, error) {
	claims, err := n.VerifyLocalBiscuit(rawToken)
	if err != nil {
		return nil, err
	}
	if len(claims.TaskRules) == 0 {
		if localPID, pErr := n.localPeerID(); pErr == nil && localPID != "" {
			if claims.ClientPeerID != "" && claims.ClientPeerID != localPID.String() {
				return nil, fmt.Errorf("standing biscuit client_peer_id %s is not bound to this node %s", claims.ClientPeerID, localPID.String())
			}
		}
	}
	return claims, nil
}

func (n *AgentMeshNode) localPeerID() (peer.ID, error) {
	if n.Host != nil && n.Host.ID() != "" {
		return n.Host.ID(), nil
	}
	if n.config.PrivKey != nil {
		return peer.IDFromPrivateKey(n.config.PrivKey)
	}
	return "", errors.New("node has no peer ID")
}

func (n *AgentMeshNode) controlPlaneURL() (string, error) {
	if n.Store != nil {
		if u, err := n.Store.LoadControlPlaneURL(); err == nil && u != "" {
			return u, nil
		}
	}
	return "", errors.New("control plane URL not configured in node store")
}

// ExchangeSubjectJWT calls POST /token/exchange on the Control Plane to verify
// an external JWT (OIDC, K8s SA, SPIFFE JWT-SVID) and mint a short-lived
// Delegated Session Biscuit bound to this node. Unattenuated, unsealed
// exchanges are cached in memory by SHA-256 of the subject JWT.
func (n *AgentMeshNode) ExchangeSubjectJWT(ctx context.Context, subjectToken, subjectTokenType string, taskRule *api.TaskAuthorizationRule, seal bool) (*api.TokenExchangeResponse, error) {
	if subjectToken == "" {
		return nil, errors.New("subject_token is required")
	}
	cacheable := taskRule == nil && !seal
	sum := sha256.Sum256([]byte(subjectTokenType + "|" + subjectToken))
	cacheKey := hex.EncodeToString(sum[:])

	if cacheable {
		n.mu.Lock()
		if n.delegatedBiscuitCache == nil {
			n.delegatedBiscuitCache, _ = lru.New[string, *api.TokenExchangeResponse](1024)
		}
		cache := n.delegatedBiscuitCache
		n.mu.Unlock()
		if cache != nil {
			if cached, ok := cache.Get(cacheKey); ok && cached != nil {
				if cached.GetExpireTime().IsValid() && cached.GetExpireTime().AsTime().After(time.Now().Add(10*time.Second)) {
					if b, _, err := identity.UnmarshalInbound(cached.GetBiscuitToken()); err == nil && !n.IsBiscuitRevoked(b) {
						return cached, nil
					}
				}
				cache.Remove(cacheKey)
			}
		}
	}

	cpURL, err := n.controlPlaneURL()
	if err != nil {
		return nil, err
	}
	nodeBiscuit := n.GetIdentity()
	if len(nodeBiscuit) == 0 {
		return nil, errors.New("node has no enrolled biscuit identity")
	}
	if n.config.PrivKey == nil {
		return nil, errors.New("node has no private key")
	}
	pid, err := n.localPeerID()
	if err != nil {
		return nil, err
	}
	challengeMs := time.Now().UnixMilli()
	challenge := api.TokenExchangeChallenge(pid.String(), challengeMs)
	sig, err := n.config.PrivKey.Sign([]byte(challenge))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token exchange challenge: %w", err)
	}
	req := &api.TokenExchangeRequest{
		SubjectToken:       subjectToken,
		TaskRule:           taskRule,
		Seal:               seal,
		ChallengeUnixMs:    challengeMs,
		ChallengeSignature: sig,
	}
	resp, err := n.controlPlane(cpURL).ExchangeToken(ctx, nodeBiscuit, req)
	if err != nil {
		return nil, err
	}
	if cacheable && n.delegatedBiscuitCache != nil {
		n.delegatedBiscuitCache.Add(cacheKey, resp)
	}
	return resp, nil
}

// MintBorderJWT calls POST /sts/token on the Control Plane to verify a caller
// Biscuit for an egress destination and mint a short-lived ES256 JWT for cloud
// STS federation. Minted JWTs are cached in memory until 10s before expiry.
func (n *AgentMeshNode) MintBorderJWT(ctx context.Context, callerBiscuit []byte, destination, audience string) (*api.STSTokenResponse, error) {
	if len(callerBiscuit) == 0 {
		callerBiscuit = n.GetIdentity()
	}
	if len(callerBiscuit) == 0 {
		return nil, errors.New("missing biscuit for STS token minting")
	}
	destination = api.NormalizeMeshHost(destination)
	if destination == "" {
		return nil, errors.New("destination is required")
	}
	h := sha256.New()
	h.Write(callerBiscuit)
	h.Write([]byte("|" + destination + "|" + audience))
	cacheKey := hex.EncodeToString(h.Sum(nil))

	n.mu.Lock()
	if n.stsTokenCache == nil {
		n.stsTokenCache, _ = lru.New[string, *api.STSTokenResponse](1024)
	}
	cache := n.stsTokenCache
	n.mu.Unlock()
	if cache != nil {
		if cached, ok := cache.Get(cacheKey); ok && cached != nil {
			if cached.GetExpireTime().IsValid() && cached.GetExpireTime().AsTime().After(time.Now().Add(10*time.Second)) {
				return cached, nil
			}
			cache.Remove(cacheKey)
		}
	}

	cpURL, err := n.controlPlaneURL()
	if err != nil {
		return nil, err
	}
	nodeBiscuit := n.GetIdentity()
	if len(nodeBiscuit) == 0 {
		return nil, errors.New("node has no enrolled biscuit identity")
	}
	if n.config.PrivKey == nil {
		return nil, errors.New("node has no private key")
	}
	pid, err := n.localPeerID()
	if err != nil {
		return nil, err
	}
	challengeMs := time.Now().UnixMilli()
	challenge := api.STSTokenChallenge(pid.String(), challengeMs)
	sig, err := n.config.PrivKey.Sign([]byte(challenge))
	if err != nil {
		return nil, fmt.Errorf("failed to sign STS token challenge: %w", err)
	}
	req := &api.STSTokenRequest{
		Biscuit:            callerBiscuit,
		Destination:        destination,
		Audience:           audience,
		ChallengeUnixMs:    challengeMs,
		ChallengeSignature: sig,
	}
	resp, err := n.controlPlane(cpURL).MintSTSToken(ctx, nodeBiscuit, req)
	if err != nil {
		return nil, err
	}
	if cache != nil {
		cache.Add(cacheKey, resp)
	}
	return resp, nil
}

// decodeBiscuitToken decodes a base64 or base64url Biscuit string and checks
// that it unmarshals as a syntactically valid Biscuit with valid tar_blocks.
func decodeBiscuitToken(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty token")
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
		base64.RawStdEncoding,
	} {
		raw, err := enc.DecodeString(s)
		if err != nil || len(raw) == 0 {
			continue
		}
		if _, _, err := identity.UnmarshalInbound(raw); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("not a valid Agent Mesh biscuit token")
}

// isLikelyJWT reports whether s has the 3-part base64url structure of a compact
// JWS/JWT with a JSON header containing an "alg" field.
func isLikelyJWT(s string) bool {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return false
	}
	_, ok := hdr["alg"].(string)
	return ok
}

// resolveCallerCredential inspects a bearer credential presented to agentmesh-node.
// It returns:
//   - (biscuitBytes, true, nil) when the credential is a valid Biscuit or an
//     external JWT successfully exchanged into a Delegated Session Biscuit;
//   - (nil, true, err) when the credential is recognizable as a Biscuit or JWT
//     but failed verification/exchange (so the caller must fail closed);
//   - (nil, false, nil) when the credential is neither a Biscuit nor a JWT.
func (n *AgentMeshNode) resolveCallerCredential(ctx context.Context, bearer string) ([]byte, bool, error) {
	if n == nil || bearer == "" {
		return nil, false, nil
	}
	if rawBiscuit, err := decodeBiscuitToken(bearer); err == nil {
		if _, verifyErr := n.verifyLocalCallerBiscuit(rawBiscuit); verifyErr != nil {
			return nil, true, verifyErr
		}
		return rawBiscuit, true, nil
	}
	// Check if it's a syntactically valid Biscuit whose tar_blocks failed validation.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawURLEncoding, base64.RawStdEncoding} {
		if raw, err := enc.DecodeString(bearer); err == nil && len(raw) > 0 {
			if _, _, uErr := identity.UnmarshalInbound(raw); uErr != nil && errors.Is(uErr, identity.ErrAppendedBlocks) {
				return nil, true, uErr
			}
		}
	}
	if isLikelyJWT(bearer) {
		resp, err := n.ExchangeSubjectJWT(ctx, bearer, api.TokenTypeJWT, nil, false)
		if err != nil {
			return nil, true, err
		}
		return resp.GetBiscuitToken(), true, nil
	}
	return nil, false, nil
}

// withCallerOrTokenAuth gates a sidecar handler behind either:
//  1. the Unix domain socket / mTLS,
//  2. the static sidecar API token (AGENTMESH_API_TOKEN),
//  3. a verified Agent Mesh Biscuit (including attenuated Task Biscuits), or
//  4. an external Workload/User JWT exchanged via the Control Plane STS.
//
// Whenever a caller Biscuit or JWT is presented, the verified Biscuit is
// attached to r.Context() via WithCallerBiscuit so outbound mesh/egress calls
// execute under the caller's narrowed authority.
func withCallerOrTokenAuth(node *AgentMeshNode, token string, allowAuthorizationFallback bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debugf("[SidecarAuth] Incoming request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Extract optional X-Mesh-Authentication, X-Mesh-Biscuit (injected by an
		// upstream Envoy ext_authz / ext_proc filter), or Authorization bearer value.
		headerName := api.HeaderMeshAuthentication
		authHeader := r.Header.Get(headerName)
		var bearer string
		var hasBearer bool
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				bearer = strings.TrimSpace(parts[1])
				hasBearer = true
			}
		} else if b64 := strings.TrimSpace(r.Header.Get(api.HeaderMeshBiscuit)); b64 != "" {
			headerName = api.HeaderMeshBiscuit
			authHeader = b64
			bearer = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(b64, "Bearer "), "bearer "))
			hasBearer = bearer != ""
		} else if allowAuthorizationFallback {
			headerName = "Authorization"
			authHeader = r.Header.Get(headerName)
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
					bearer = strings.TrimSpace(parts[1])
					hasBearer = true
				}
			}
		}

		// Local Unix socket or mTLS (token == ""): transport already authenticates
		// the local process, but if the caller also supplied a Task Biscuit or JWT,
		// bind it to the request context (and fail closed if that Biscuit/JWT is invalid/revoked).
		if fromLocalSocket(r) || token == "" {
			if hasBearer && (token == "" || headerName == api.HeaderMeshBiscuit || !constantTimeEqual(bearer, token)) {
				biscuitBytes, isMeshCred, err := node.resolveCallerCredential(r.Context(), bearer)
				if isMeshCred {
					if err != nil {
						http.Error(w, fmt.Sprintf("Forbidden: %v", err), http.StatusForbidden)
						return
					}
					r = r.WithContext(WithCallerBiscuit(r.Context(), biscuitBytes))
					r.Header.Del(headerName)
				} else if headerName == api.HeaderMeshAuthentication || headerName == api.HeaderMeshBiscuit {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
			r.Header.Del(api.HeaderMeshAuthentication)
			r.Header.Del(api.HeaderMeshBiscuit)
			stripSidecarTokenFromAuthorization(r, token)
			next.ServeHTTP(w, r)
			return
		}

		if authHeader == "" {
			accepted := fmt.Sprintf("%q", api.HeaderMeshAuthentication)
			if allowAuthorizationFallback {
				accepted += ` or "Authorization"`
			}
			logger.Warnf("[SidecarAuth] Request %s %s rejected: missing %s header", r.Method, r.URL.Path, accepted)
			http.Error(w, fmt.Sprintf("Unauthorized: missing %s header, e.g. %q: \"Bearer <api-token>\"", accepted, api.HeaderMeshAuthentication), http.StatusUnauthorized)
			return
		}
		if !hasBearer {
			http.Error(w, fmt.Sprintf("Invalid %q header format, expected \"Bearer <api-token>\"", headerName), http.StatusUnauthorized)
			return
		}

		if headerName != api.HeaderMeshBiscuit && constantTimeEqual(bearer, token) {
			r.Header.Del(headerName)
			stripSidecarTokenFromAuthorization(r, token)
			next.ServeHTTP(w, r)
			return
		}

		biscuitBytes, isMeshCred, err := node.resolveCallerCredential(r.Context(), bearer)
		if !isMeshCred || err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		r = r.WithContext(WithCallerBiscuit(r.Context(), biscuitBytes))
		r.Header.Del(headerName)
		stripSidecarTokenFromAuthorization(r, token)
		next.ServeHTTP(w, r)
	})
}

// handleNodeOAuthToken implements the token endpoint (POST /oauth/token) on
// agentmesh-node. It accepts three grant shapes, all of which end in a Biscuit:
//
//   - RFC 8693 token exchange: subject_token is a Biscuit to attenuate or an
//     external JWT to exchange at the control plane.
//   - RFC 6749 client_credentials with RFC 7523 section 2.2 client
//     authentication: client_assertion is a JWT (for example a SPIFFE JWT-SVID,
//     draft-ietf-oauth-spiffe-client-auth) that is exchanged at the control
//     plane. This is the shape OAuth clients such as NVIDIA OpenShell token
//     grants and Keycloak-style workload clients send.
//   - RFC 7523 section 2.1 jwt-bearer authorization grant: assertion is a JWT
//     authorization grant, as produced by draft-ietf-oauth-identity-chaining.
//
// A client_assertion on any grant also authenticates the caller, so a token
// exchange without a subject_token narrows the assertion's own identity.
func handleNodeOAuthToken(node *AgentMeshNode, sidecarToken string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeNodeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}
	if node == nil {
		writeNodeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Node not initialized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeNodeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form body")
		return
	}

	clientAssertion, hasClientAssertion, caErr := clientAssertionFromForm(r.Form)
	if caErr != nil {
		writeNodeOAuthError(w, http.StatusUnauthorized, "invalid_client", caErr.Error())
		return
	}

	subjectToken := strings.TrimSpace(r.FormValue("subject_token"))
	subjectTokenType := strings.TrimSpace(r.FormValue("subject_token_type"))
	// A rejected subject is invalid_grant, unless the subject is the client
	// assertion itself, which makes it a client authentication failure.
	subjectRejected := func(err error) {
		writeNodeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
	}
	switch grantType := r.FormValue("grant_type"); grantType {
	case api.GrantTypeTokenExchange:
	case api.GrantTypeClientCredentials:
		if !hasClientAssertion {
			writeNodeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client_credentials requires a JWT client_assertion (RFC 7523 section 2.2)")
			return
		}
		subjectToken = clientAssertion
		subjectTokenType = api.TokenTypeJWT
		subjectRejected = func(err error) {
			writeNodeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		}
	case api.GrantTypeJWTBearer:
		assertion := strings.TrimSpace(r.FormValue("assertion"))
		if !isLikelyJWT(assertion) {
			writeNodeOAuthError(w, http.StatusBadRequest, "invalid_grant", "assertion must be a JWT (RFC 7523 section 2.1)")
			return
		}
		subjectToken = assertion
		subjectTokenType = api.TokenTypeJWT
	default:
		writeNodeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Supported grant types: "+strings.Join(nodeOAuthGrantTypes, ", "))
		return
	}

	requestedTokenType := strings.TrimSpace(r.FormValue("requested_token_type"))
	resources := r.Form["resource"]
	scope := strings.TrimSpace(r.FormValue("scope"))
	options := strings.TrimSpace(r.FormValue("options"))
	sealParam := strings.TrimSpace(r.FormValue("seal"))
	audience := strings.TrimSpace(r.FormValue("audience"))
	seal := sealParam == "true" || sealParam == "1"

	tar, err := api.BuildTARFromOAuthParams("oauth-task", options, resources, scope, nil)
	if err != nil {
		writeNodeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	var baseBiscuit []byte
	var expiresAt time.Time

	if subjectToken != "" && subjectToken != "self" {
		if rawBiscuit, bErr := decodeBiscuitToken(subjectToken); bErr == nil {
			claims, vErr := node.verifyLocalCallerBiscuit(rawBiscuit)
			if vErr != nil {
				writeNodeOAuthError(w, http.StatusBadRequest, "invalid_grant", vErr.Error())
				return
			}
			baseBiscuit = rawBiscuit
			expiresAt = claims.Expiration
		} else if subjectTokenType == api.TokenTypeBiscuit {
			writeNodeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject_token is not a valid Biscuit")
			return
		} else {
			// External JWT: exchange at the Control Plane.
			if requestedTokenType != api.TokenTypeJWT {
				resp, exErr := node.ExchangeSubjectJWT(r.Context(), subjectToken, subjectTokenType, tar, seal)
				if exErr != nil {
					subjectRejected(exErr)
					return
				}
				expIn := int64(300)
				if resp.GetExpireTime().IsValid() {
					expIn = int64(time.Until(resp.GetExpireTime().AsTime()).Seconds())
					if expIn <= 0 {
						expIn = 1
					}
				}
				writeNodeOAuthTokenResponse(w, base64.StdEncoding.EncodeToString(resp.GetBiscuitToken()), api.TokenTypeBiscuit, expIn, scope)
				return
			}
			resp, exErr := node.ExchangeSubjectJWT(r.Context(), subjectToken, subjectTokenType, tar, false)
			if exErr != nil {
				subjectRejected(exErr)
				return
			}
			baseBiscuit = resp.GetBiscuitToken()
			if resp.GetExpireTime().IsValid() {
				expiresAt = resp.GetExpireTime().AsTime()
			}
		}
	} else {
		// No subject_token (or "self"): authenticate caller via a client
		// assertion or the sidecar gate, and use the caller's Biscuit if
		// provided, or the node's own Biscuit.
		var callerBiscuit []byte
		if hasClientAssertion {
			resp, exErr := node.ExchangeSubjectJWT(r.Context(), clientAssertion, api.TokenTypeJWT, nil, false)
			if exErr != nil {
				writeNodeOAuthError(w, http.StatusUnauthorized, "invalid_client", exErr.Error())
				return
			}
			callerBiscuit = resp.GetBiscuitToken()
		} else {
			var ok bool
			callerBiscuit, ok = authenticateSidecarCaller(node, sidecarToken, r)
			if !ok {
				writeNodeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Sidecar authentication, client_assertion, or subject_token required")
				return
			}
		}
		if len(callerBiscuit) > 0 {
			baseBiscuit = callerBiscuit
		} else {
			baseBiscuit = node.GetIdentity()
		}
		if len(baseBiscuit) == 0 {
			writeNodeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Node has no identity biscuit")
			return
		}
		if claims, vErr := node.VerifyLocalBiscuit(baseBiscuit); vErr == nil {
			expiresAt = claims.Expiration
		}
	}

	if tar != nil {
		if tar.GetExpireTime().IsValid() && (expiresAt.IsZero() || tar.GetExpireTime().AsTime().Before(expiresAt)) {
			expiresAt = tar.GetExpireTime().AsTime()
		}
		baseBiscuit, err = identity.AttenuateBiscuit(baseBiscuit, tar)
		if err != nil {
			writeNodeOAuthError(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf("Failed to attenuate biscuit: %v", err))
			return
		}
	}
	if seal {
		baseBiscuit, err = identity.SealBiscuit(baseBiscuit)
		if err != nil {
			writeNodeOAuthError(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("Failed to seal biscuit: %v", err))
			return
		}
	}

	// If the caller explicitly requested an outbound border JWT for an egress resource:
	if requestedTokenType == api.TokenTypeJWT {
		dest := ""
		for _, res := range resources {
			if after, ok := strings.CutPrefix(res, api.EgressServicePrefix); ok {
				dest = after
				break
			}
		}
		if dest == "" {
			writeNodeOAuthError(w, http.StatusBadRequest, "invalid_target", "requested_token_type=jwt requires an egress://<destination> resource")
			return
		}
		stsResp, stsErr := node.MintBorderJWT(r.Context(), baseBiscuit, dest, audience)
		if stsErr != nil {
			writeNodeOAuthError(w, http.StatusForbidden, "access_denied", stsErr.Error())
			return
		}
		expIn := int64(300)
		if stsResp.GetExpireTime().IsValid() {
			expIn = int64(time.Until(stsResp.GetExpireTime().AsTime()).Seconds())
			if expIn <= 0 {
				expIn = 1
			}
		}
		writeNodeOAuthTokenResponse(w, stsResp.GetJwt(), api.TokenTypeJWT, expIn, scope)
		return
	}

	expIn := int64(300)
	if !expiresAt.IsZero() {
		expIn = int64(time.Until(expiresAt).Seconds())
		if expIn <= 0 {
			expIn = 1
		}
	}
	writeNodeOAuthTokenResponse(w, base64.StdEncoding.EncodeToString(baseBiscuit), api.TokenTypeBiscuit, expIn, scope)
}

func authenticateSidecarCaller(node *AgentMeshNode, sidecarToken string, r *http.Request) ([]byte, bool) {
	for _, hdr := range []string{api.HeaderMeshAuthentication, "Authorization"} {
		val := r.Header.Get(hdr)
		if val == "" {
			continue
		}
		parts := strings.SplitN(val, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			continue
		}
		bearer := strings.TrimSpace(parts[1])
		if sidecarToken != "" && constantTimeEqual(bearer, sidecarToken) {
			return nil, true
		}
		if biscuitBytes, isMeshCred, err := node.resolveCallerCredential(r.Context(), bearer); isMeshCred && err == nil {
			return biscuitBytes, true
		}
	}
	if fromLocalSocket(r) || sidecarToken == "" {
		return nil, true
	}
	return nil, false
}

// handleNodeOAuthRevoke implements RFC 7009 Token Revocation (POST /oauth/revoke)
// on agentmesh-node, adding the Biscuit's root Block 0 revocation ID to the local
// revocation cache so any call carrying it (or any child attenuated from it)
// is immediately rejected.
func handleNodeOAuthRevoke(node *AgentMeshNode, sidecarToken string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeNodeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}
	if node == nil {
		writeNodeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Node not initialized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeNodeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form body")
		return
	}
	tokenStr := strings.TrimSpace(r.FormValue("token"))
	if tokenStr == "" {
		writeNodeOAuthError(w, http.StatusBadRequest, "invalid_request", "token parameter is required")
		return
	}

	rawBiscuit, err := decodeBiscuitToken(tokenStr)
	if err != nil {
		// Per RFC 7009 Section 2.2, invalid tokens still return 200 OK if the
		// client is authenticated, or 400 if unrecognizable and unauthenticated.
		if _, ok := authenticateSidecarCaller(node, sidecarToken, r); ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeNodeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid biscuit token")
		return
	}

	// Verify signature against trusted Control Plane keys before accepting an
	// unauthenticated revocation so arbitrary bytes cannot pollute the cache.
	expiry := time.Now().Add(24 * time.Hour)
	if claims, vErr := node.VerifyLocalBiscuit(rawBiscuit); vErr == nil {
		if !claims.Expiration.IsZero() {
			expiry = claims.Expiration
		}
	} else if _, ok := authenticateSidecarCaller(node, sidecarToken, r); !ok {
		// Allow revoking an already-revoked token idempotently if its signature is valid.
		b, _, uErr := identity.UnmarshalInbound(rawBiscuit)
		if uErr != nil || !node.IsBiscuitRevoked(b) {
			writeNodeOAuthError(w, http.StatusUnauthorized, "invalid_token", vErr.Error())
			return
		}
	}

	if _, err := node.RevokeBiscuitToken(rawBiscuit, expiry); err != nil {
		writeNodeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
}

// nodeOAuthGrantTypes and nodeOAuthClientAuthMethods are what the node's token
// endpoint accepts and advertises (RFC 8414 and draft-ietf-oauth-spiffe-client-auth
// section 4).
var (
	nodeOAuthGrantTypes = []string{
		api.GrantTypeTokenExchange,
		api.GrantTypeClientCredentials,
		api.GrantTypeJWTBearer,
	}
	nodeOAuthClientAuthMethods = []string{"none", "private_key_jwt", "spiffe_jwt"}
)

// clientAssertionFromForm reads an RFC 7523 section 2.2 client assertion from
// the token request. It returns (assertion, true, nil) for a well-formed JWT
// assertion, (_, false, nil) when the request carries none, and an error when
// the assertion or its type is unusable.
func clientAssertionFromForm(form url.Values) (string, bool, error) {
	assertion := strings.TrimSpace(form.Get("client_assertion"))
	assertionType := strings.TrimSpace(form.Get("client_assertion_type"))
	if assertion == "" && assertionType == "" {
		return "", false, nil
	}
	if assertion == "" {
		return "", false, errors.New("client_assertion is required with client_assertion_type")
	}
	if assertionType == "" {
		return "", false, errors.New("client_assertion_type is required with client_assertion")
	}
	switch assertionType {
	case api.ClientAssertionTypeJWTBearer, api.ClientAssertionTypeJWTSPIFFE:
	default:
		return "", false, fmt.Errorf("unsupported client_assertion_type %q; use %s or %s", assertionType, api.ClientAssertionTypeJWTBearer, api.ClientAssertionTypeJWTSPIFFE)
	}
	if !isLikelyJWT(assertion) {
		return "", false, errors.New("client_assertion must be a JWT")
	}
	return assertion, true, nil
}

// nodeBaseURL is the origin a caller reached this node on, for self-referencing
// metadata documents.
func nodeBaseURL(node *AgentMeshNode, r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" && node != nil && node.BoundHTTPAddr != "" {
		host = node.BoundHTTPAddr
	}
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host
}

// handleOAuthProtectedResource serves RFC 9728 OAuth 2.0 Protected Resource Metadata
// (GET /.well-known/oauth-protected-resource).
func handleOAuthProtectedResource(node *AgentMeshNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var authServers []string
	if node != nil {
		if cpURL, err := node.controlPlaneURL(); err == nil && cpURL != "" {
			authServers = append(authServers, cpURL)
		}
	}
	meta := api.OAuthProtectedResourceMetadata{
		Resource:               nodeBaseURL(node, r) + "/mcp",
		AuthorizationServers:   authServers,
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"mcp", "inference", "egress", "a2a"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

// handleOAuthAuthorizationServer serves RFC 8414 Authorization Server Metadata
// (GET /.well-known/oauth-authorization-server) for the node's own token
// endpoint. The node issues Biscuits only; interactive authorization lives on
// the control plane, which the protected resource metadata points at.
func handleOAuthAuthorizationServer(node *AgentMeshNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	issuer := nodeBaseURL(node, r)
	meta := api.OAuthAuthorizationServerMetadata{
		Issuer:                                 issuer,
		TokenEndpoint:                          issuer + "/oauth/token",
		RevocationEndpoint:                     issuer + "/oauth/revoke",
		ResponseTypesSupported:                 []string{},
		GrantTypesSupported:                    nodeOAuthGrantTypes,
		TokenEndpointAuthMethodsSupported:      nodeOAuthClientAuthMethods,
		RevocationEndpointAuthMethodsSupported: nodeOAuthClientAuthMethods,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

func writeNodeOAuthTokenResponse(w http.ResponseWriter, accessToken, issuedTokenType string, expiresIn int64, scope string) {
	resp := map[string]any{
		"access_token":      accessToken,
		"issued_token_type": issuedTokenType,
		"token_type":        "Bearer",
		"expires_in":        expiresIn,
	}
	if scope != "" {
		resp["scope"] = scope
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeNodeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
