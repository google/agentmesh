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
	"strings"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/peer"
)

type callerBiscuitContextKey struct{}

// WithCallerBiscuit attaches a verified caller Biscuit (such as a narrowed
// Task Biscuit or an exchanged Delegated Session Biscuit) to ctx so outbound
// mesh and egress handlers use it instead of the node's standing identity.
func WithCallerBiscuit(ctx context.Context, biscuitBytes []byte) context.Context {
	if len(biscuitBytes) == 0 {
		return ctx
	}
	cp := append([]byte(nil), biscuitBytes...)
	return context.WithValue(ctx, callerBiscuitContextKey{}, cp)
}

// CallerBiscuitFromContext returns the caller Biscuit attached to ctx, or nil.
func CallerBiscuitFromContext(ctx context.Context) []byte {
	if ctx == nil {
		return nil
	}
	b, _ := ctx.Value(callerBiscuitContextKey{}).([]byte)
	return b
}

// GetRequestIdentity returns the caller Biscuit from ctx when present,
// falling back to the node's own enrolled Biscuit identity.
func (n *SamNode) GetRequestIdentity(ctx context.Context) []byte {
	if b := CallerBiscuitFromContext(ctx); len(b) > 0 {
		return b
	}
	return n.GetIdentity()
}

// trustedPublicKeys returns the Control Plane Ed25519 public keys currently
// trusted by this node, falling back to the stored mesh config key if needed.
func (n *SamNode) trustedPublicKeys() []ed25519.PublicKey {
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
// cache and trusted Control Plane keys, returning its extracted claims and
// TaskAuthorizationRule chain.
func (n *SamNode) VerifyLocalBiscuit(rawToken []byte) (*identity.VerifiedBiscuitClaims, error) {
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
	return identity.InspectVerifiedBiscuit(rawToken, keys, n.BiscuitTimeout)
}

func (n *SamNode) localPeerID() (peer.ID, error) {
	if n.Host != nil && n.Host.ID() != "" {
		return n.Host.ID(), nil
	}
	if n.config.PrivKey != nil {
		return peer.IDFromPrivateKey(n.config.PrivKey)
	}
	return "", errors.New("node has no peer ID")
}

func (n *SamNode) controlPlaneURL() (string, error) {
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
func (n *SamNode) ExchangeSubjectJWT(ctx context.Context, subjectToken, subjectTokenType string, taskRule *api.TaskAuthorizationRule, seal bool) (*api.TokenExchangeResponse, error) {
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
	resp, err := controlPlaneClient(cpURL).ExchangeToken(ctx, nodeBiscuit, req)
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
func (n *SamNode) MintBorderJWT(ctx context.Context, callerBiscuit []byte, destination, audience string) (*api.STSTokenResponse, error) {
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
	resp, err := controlPlaneClient(cpURL).MintSTSToken(ctx, nodeBiscuit, req)
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
	return nil, errors.New("not a valid SAM biscuit token")
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

// resolveCallerCredential inspects a bearer credential presented to sam-node.
// It returns:
//   - (biscuitBytes, true, nil) when the credential is a valid Biscuit or an
//     external JWT successfully exchanged into a Delegated Session Biscuit;
//   - (nil, true, err) when the credential is recognizable as a Biscuit or JWT
//     but failed verification/exchange (so the caller must fail closed);
//   - (nil, false, nil) when the credential is neither a Biscuit nor a JWT.
func (n *SamNode) resolveCallerCredential(ctx context.Context, bearer string) ([]byte, bool, error) {
	if n == nil || bearer == "" {
		return nil, false, nil
	}
	if rawBiscuit, err := decodeBiscuitToken(bearer); err == nil {
		if _, verifyErr := n.VerifyLocalBiscuit(rawBiscuit); verifyErr != nil {
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
//  2. the static sidecar API token (SAM_API_TOKEN),
//  3. a verified SAM Biscuit (including attenuated Task Biscuits), or
//  4. an external Workload/User JWT exchanged via the Control Plane STS.
//
// Whenever a caller Biscuit or JWT is presented, the verified Biscuit is
// attached to r.Context() via WithCallerBiscuit so outbound mesh/egress calls
// execute under the caller's narrowed authority.
func withCallerOrTokenAuth(node *SamNode, token string, allowAuthorizationFallback bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debugf("[SidecarAuth] Incoming request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Extract optional X-Sam-Authentication or Authorization bearer value.
		headerName := api.HeaderSamAuthentication
		authHeader := r.Header.Get(headerName)
		if authHeader == "" && allowAuthorizationFallback {
			headerName = "Authorization"
			authHeader = r.Header.Get(headerName)
		}

		var bearer string
		var hasBearer bool
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				bearer = strings.TrimSpace(parts[1])
				hasBearer = true
			}
		}

		// Local Unix socket or mTLS (token == ""): transport already authenticates
		// the local process, but if the caller also supplied a Task Biscuit or JWT,
		// bind it to the request context (and fail closed if that Biscuit/JWT is invalid/revoked).
		if fromLocalSocket(r) || token == "" {
			if hasBearer && (token == "" || !constantTimeEqual(bearer, token)) {
				biscuitBytes, isMeshCred, err := node.resolveCallerCredential(r.Context(), bearer)
				if isMeshCred {
					if err != nil {
						http.Error(w, fmt.Sprintf("Forbidden: %v", err), http.StatusForbidden)
						return
					}
					r = r.WithContext(WithCallerBiscuit(r.Context(), biscuitBytes))
					r.Header.Del(headerName)
				} else if headerName == api.HeaderSamAuthentication {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
			r.Header.Del(api.HeaderSamAuthentication)
			stripSidecarTokenFromAuthorization(r, token)
			next.ServeHTTP(w, r)
			return
		}

		if authHeader == "" {
			accepted := fmt.Sprintf("%q", api.HeaderSamAuthentication)
			if allowAuthorizationFallback {
				accepted += ` or "Authorization"`
			}
			logger.Warnf("[SidecarAuth] Request %s %s rejected: missing %s header", r.Method, r.URL.Path, accepted)
			http.Error(w, fmt.Sprintf("Unauthorized: missing %s header, e.g. %q: \"Bearer <api-token>\"", accepted, api.HeaderSamAuthentication), http.StatusUnauthorized)
			return
		}
		if !hasBearer {
			http.Error(w, fmt.Sprintf("Invalid %q header format, expected \"Bearer <api-token>\"", headerName), http.StatusUnauthorized)
			return
		}

		if constantTimeEqual(bearer, token) {
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

// handleNodeOAuthToken implements RFC 8693 Token Exchange & Attenuation
// (POST /oauth/token) on sam-node.
func handleNodeOAuthToken(node *SamNode, sidecarToken string, w http.ResponseWriter, r *http.Request) {
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

	grantType := r.FormValue("grant_type")
	if grantType != api.GrantTypeTokenExchange {
		writeNodeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Only urn:ietf:params:oauth:grant-type:token-exchange is supported on sam-node")
		return
	}

	subjectToken := strings.TrimSpace(r.FormValue("subject_token"))
	subjectTokenType := strings.TrimSpace(r.FormValue("subject_token_type"))
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
			claims, vErr := node.VerifyLocalBiscuit(rawBiscuit)
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
					writeNodeOAuthError(w, http.StatusBadRequest, "invalid_grant", exErr.Error())
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
				writeNodeOAuthError(w, http.StatusBadRequest, "invalid_grant", exErr.Error())
				return
			}
			baseBiscuit = resp.GetBiscuitToken()
			if resp.GetExpireTime().IsValid() {
				expiresAt = resp.GetExpireTime().AsTime()
			}
		}
	} else {
		// No subject_token (or "self"): authenticate caller via sidecar gate and
		// use the caller's Biscuit if provided, or the node's own Biscuit.
		callerBiscuit, ok := authenticateSidecarCaller(node, sidecarToken, r)
		if !ok {
			writeNodeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Sidecar authentication or subject_token required")
			return
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

func authenticateSidecarCaller(node *SamNode, sidecarToken string, r *http.Request) ([]byte, bool) {
	for _, hdr := range []string{api.HeaderSamAuthentication, "Authorization"} {
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
// on sam-node, adding the Biscuit's root Block 0 revocation ID to the local
// revocation cache so any call carrying it (or any child attenuated from it)
// is immediately rejected.
func handleNodeOAuthRevoke(node *SamNode, sidecarToken string, w http.ResponseWriter, r *http.Request) {
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

// handleOAuthProtectedResource serves RFC 9728 OAuth 2.0 Protected Resource Metadata
// (GET /.well-known/oauth-protected-resource).
func handleOAuthProtectedResource(node *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	var authServers []string
	if node != nil {
		if cpURL, err := node.controlPlaneURL(); err == nil && cpURL != "" {
			authServers = append(authServers, cpURL)
		}
	}
	meta := map[string]any{
		"resource":                 fmt.Sprintf("%s://%s/mcp", scheme, host),
		"authorization_servers":    authServers,
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp", "inference", "egress", "a2a"},
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
