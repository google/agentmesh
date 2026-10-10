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

package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// maxSTSTokenTTL is the maximum lifetime of an outbound border JWT minted by POST /sts/token.
	maxSTSTokenTTL = 15 * time.Minute
	// oauthAuthCodeTTL is the lifetime of a single-use OAuth 2.1 authorization code.
	oauthAuthCodeTTL = 5 * time.Minute
	// maxPendingOAuthCodes caps the in-memory OAuth 2.1 authorization code table.
	maxPendingOAuthCodes = 4096
)

// JSONWebKey represents a single public key in an RFC 7517 JSON Web Key Set.
type JSONWebKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JSONWebKeySet represents an RFC 7517 JSON Web Key Set served at GET /jwks.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// OIDCSigner signs outbound ES256 border JWTs at POST /sts/token and publishes
// the corresponding public keys at GET /jwks.
type OIDCSigner interface {
	SignJWT(ctx context.Context, claims jwt.MapClaims) (string, error)
	JWKS(ctx context.Context) (*JSONWebKeySet, error)
}

type es256KeyEntry struct {
	kid       string
	priv      *ecdsa.PrivateKey
	jwk       JSONWebKey
	expiresAt time.Time // zero for the currently active signing key
}

const oidcKeyCacheTTL = time.Minute

// LocalES256Signer is the default OIDCSigner using P-256 (ES256) keys
// with overlap grace-period support and optional SQLStore persistence.
type LocalES256Signer struct {
	mu       sync.RWMutex
	store    storage.Store
	current  es256KeyEntry
	retired  []es256KeyEntry
	loadedAt time.Time
}

// NewLocalES256SignerWithStore creates a LocalES256Signer backed by store when non-nil.
func NewLocalES256SignerWithStore(store storage.Store) (*LocalES256Signer, error) {
	if store != nil {
		ctx := context.Background()
		if dbKeys, err := store.GetAllValidOIDCKeys(ctx); err == nil && len(dbKeys) > 0 {
			var current *es256KeyEntry
			var retired []es256KeyEntry
			for _, k := range dbKeys {
				entry, decErr := decodeOIDCKeyPair(k)
				if decErr != nil {
					continue
				}
				if k.Expiration.IsZero() && current == nil {
					e := entry
					current = &e
				} else {
					retired = append(retired, entry)
				}
			}
			if current != nil {
				return &LocalES256Signer{
					store:    store,
					current:  *current,
					retired:  retired,
					loadedAt: time.Now(),
				}, nil
			}
		}
	}

	entry, err := generateES256KeyEntry()
	if err != nil {
		return nil, err
	}
	if store != nil {
		ctx := context.Background()
		privBytes, mErr := x509.MarshalECPrivateKey(entry.priv)
		pubBytes, pErr := entry.priv.PublicKey.Bytes()
		if mErr == nil && pErr == nil {
			_ = store.SaveInitialOIDCKey(ctx, entry.kid, privBytes, pubBytes)
			if cur, gErr := store.GetCurrentOIDCKey(ctx); gErr == nil && cur != nil {
				if loaded, dErr := decodeOIDCKeyPair(*cur); dErr == nil {
					entry = loaded
				}
			}
		}
	}
	return &LocalES256Signer{store: store, current: entry, loadedAt: time.Now()}, nil
}

func decodeOIDCKeyPair(k storage.OIDCKeyPair) (es256KeyEntry, error) {
	priv, err := x509.ParseECPrivateKey(k.PrivateKey)
	if err != nil {
		return es256KeyEntry{}, err
	}
	uncompressed := k.PublicKey
	if len(uncompressed) != 65 {
		uncompressed, err = priv.PublicKey.Bytes()
		if err != nil || len(uncompressed) != 65 {
			return es256KeyEntry{}, fmt.Errorf("invalid P-256 public key bytes")
		}
	}
	xBytes := uncompressed[1:33]
	yBytes := uncompressed[33:65]
	return es256KeyEntry{
		kid:  k.Kid,
		priv: priv,
		jwk: JSONWebKey{
			Kty: "EC",
			Crv: "P-256",
			Use: "sig",
			Alg: "ES256",
			Kid: k.Kid,
			X:   base64.RawURLEncoding.EncodeToString(xBytes),
			Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		},
		expiresAt: k.Expiration,
	}, nil
}

func generateES256KeyEntry() (es256KeyEntry, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return es256KeyEntry{}, fmt.Errorf("generate P-256 key: %w", err)
	}
	uncompressed, err := priv.PublicKey.Bytes()
	if err != nil || len(uncompressed) != 65 {
		return es256KeyEntry{}, fmt.Errorf("encode P-256 public key: %w", err)
	}
	xBytes := uncompressed[1:33]
	yBytes := uncompressed[33:65]
	sum := sha256.Sum256(uncompressed)
	kid := hex.EncodeToString(sum[:8])
	return es256KeyEntry{
		kid:  kid,
		priv: priv,
		jwk: JSONWebKey{
			Kty: "EC",
			Crv: "P-256",
			Use: "sig",
			Alg: "ES256",
			Kid: kid,
			X:   base64.RawURLEncoding.EncodeToString(xBytes),
			Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		},
	}, nil
}

// Rotate generates a new active ES256 signing key and retains the previous key
// in JWKS for gracePeriod so in-flight border JWTs remain verifiable.
func (s *LocalES256Signer) Rotate(gracePeriod time.Duration) (string, error) {
	next, err := generateES256KeyEntry()
	if err != nil {
		return "", err
	}
	if s.store != nil {
		privBytes, mErr := x509.MarshalECPrivateKey(next.priv)
		pubBytes, pErr := next.priv.PublicKey.Bytes()
		if mErr != nil || pErr != nil {
			return "", fmt.Errorf("failed to marshal rotated ES256 key")
		}
		if err := s.store.RotateOIDCKeys(context.Background(), next.kid, privBytes, pubBytes, gracePeriod); err != nil {
			return "", err
		}
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.current
	prev.expiresAt = now.Add(gracePeriod)
	var kept []es256KeyEntry
	for _, r := range s.retired {
		if now.Before(r.expiresAt) {
			kept = append(kept, r)
		}
	}
	if gracePeriod > 0 {
		kept = append(kept, prev)
	}
	s.retired = kept
	s.current = next
	s.loadedAt = now
	return next.kid, nil
}

// SignJWT signs claims with the active ES256 key and sets the "kid" header.
func (s *LocalES256Signer) SignJWT(ctx context.Context, claims jwt.MapClaims) (string, error) {
	s.mu.RLock()
	active := s.current
	stale := s.store != nil && time.Since(s.loadedAt) >= oidcKeyCacheTTL
	s.mu.RUnlock()

	if stale {
		if cur, err := s.store.GetCurrentOIDCKey(ctx); err == nil && cur != nil {
			if loaded, dErr := decodeOIDCKeyPair(*cur); dErr == nil {
				s.mu.Lock()
				s.current = loaded
				s.loadedAt = time.Now()
				active = loaded
				s.mu.Unlock()
			}
		}
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = active.kid
	return tok.SignedString(active.priv)
}

// JWKS returns the active public key plus any retired keys still within their overlap grace window.
func (s *LocalES256Signer) JWKS(ctx context.Context) (*JSONWebKeySet, error) {
	if s.store != nil {
		if dbKeys, err := s.store.GetAllValidOIDCKeys(ctx); err == nil && len(dbKeys) > 0 {
			keys := make([]JSONWebKey, 0, len(dbKeys))
			for _, k := range dbKeys {
				if entry, dErr := decodeOIDCKeyPair(k); dErr == nil {
					keys = append(keys, entry.jwk)
				}
			}
			if len(keys) > 0 {
				return &JSONWebKeySet{Keys: keys}, nil
			}
		}
	}
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := []JSONWebKey{s.current.jwk}
	for _, r := range s.retired {
		if now.Before(r.expiresAt) {
			keys = append(keys, r.jwk)
		}
	}
	return &JSONWebKeySet{Keys: keys}, nil
}

// RotateOIDCKey rotates the control plane's ES256 OIDC signing key when backed by LocalES256Signer.
func (s *Server) RotateOIDCKey(gracePeriod time.Duration) (string, error) {
	local, ok := s.oidcSigner.(*LocalES256Signer)
	if !ok {
		return "", errors.New("configured OIDCSigner does not support local key rotation")
	}
	return local.Rotate(gracePeriod)
}

func isValidHostHeader(host string) bool {
	if host == "" || len(host) > 255 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '.' && c != '-' && c != ':' && c != '[' && c != ']' {
			return false
		}
	}
	return true
}

// oidcIssuerURL returns the canonical OIDC issuer URL for this control plane.
func (s *Server) oidcIssuerURL(r *http.Request) string {
	if iss := strings.TrimRight(strings.TrimSpace(s.config.STSIssuerURL), "/"); iss != "" {
		return iss
	}
	scheme := "http"
	if r != nil {
		if r.TLS != nil || (s.config.TrustForwardedHeaders && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")) {
			scheme = "https"
		}
		if host := strings.TrimSpace(r.Host); isValidHostHeader(host) {
			return scheme + "://" + host
		}
	}
	if s.listener != nil {
		return scheme + "://" + s.listener.Addr().String()
	}
	return scheme + "://" + s.config.ListenAddr
}

// HandleOpenIDConfiguration serves GET `/.well-known/openid-configuration`.
func (s *Server) HandleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	issuer := s.oidcIssuerURL(r)
	doc := map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/jwks",
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"grant_types_supported": []string{
			api.GrantTypeAuthorizationCode,
			api.GrantTypeTokenExchange,
		},
		"code_challenge_methods_supported": []string{"S256"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "jti", "act", "mesh_roles", "mesh_task",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// HandleOAuthAuthorizationServer serves GET `/.well-known/oauth-authorization-server` (RFC 8414).
func (s *Server) HandleOAuthAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	issuer := s.oidcIssuerURL(r)
	doc := api.OAuthAuthorizationServerMetadata{
		Issuer:                        issuer,
		AuthorizationEndpoint:         issuer + "/oauth/authorize",
		TokenEndpoint:                 issuer + "/oauth/token",
		JWKSURI:                       issuer + "/jwks",
		ResponseTypesSupported:        []string{"code"},
		GrantTypesSupported:           []string{api.GrantTypeAuthorizationCode, api.GrantTypeTokenExchange},
		CodeChallengeMethodsSupported: []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{
			"none",
			"client_secret_post",
			"private_key_jwt",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// HandleJWKS serves GET `/jwks`.
func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jwks, err := s.oidcSigner.JWKS(r.Context())
	if err != nil {
		logger.Errorf("Failed to build JWKS: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(jwks)
}

func (s *Server) allowNodeSTSRequest(peerID string) bool {
	if s.stsLimiter == nil {
		return true
	}
	return s.stsLimiter.Allow(peerID)
}

// revokedPruneMin is the smallest revocation set RevokeBiscuitID bothers to
// sweep for expired entries.
const revokedPruneMin = 64

// RevokeBiscuitID records a root Biscuit revocation ID (base64url-encoded) as
// revoked until expiry.
func (s *Server) RevokeBiscuitID(revocationID string, expiry time.Time) {
	if revocationID == "" {
		return
	}
	if expiry.IsZero() {
		expiry = time.Now().Add(s.config.BiscuitTTL)
	}
	now := time.Now()
	s.revokedBiscuitsMu.Lock()
	// Expired entries also go on read; dropping them here too keeps the map
	// bounded when nothing polls /revocations.
	if len(s.revokedBiscuits) >= s.revokedPruneAt {
		for id, exp := range s.revokedBiscuits {
			if !now.Before(exp) {
				delete(s.revokedBiscuits, id)
			}
		}
		s.revokedPruneAt = max(revokedPruneMin, 2*len(s.revokedBiscuits))
	}
	s.revokedBiscuits[revocationID] = expiry
	s.revokedBiscuitsMu.Unlock()
	if s.store != nil {
		_ = s.store.SaveRevokedBiscuit(context.Background(), revocationID, expiry)
	}
}

func extractRootRevocationID(rawToken []byte) (string, error) {
	b, err := biscuit.Unmarshal(rawToken)
	if err != nil {
		return "", err
	}
	ids := b.RevocationIds()
	if len(ids) == 0 {
		return "", errors.New("biscuit has no revocation IDs")
	}
	return base64.RawURLEncoding.EncodeToString(ids[0]), nil
}

// RevokeBiscuitToken extracts the root (block 0) RevocationId of rawToken and
// records it in the control plane's revocation set.
func (s *Server) RevokeBiscuitToken(rawToken []byte, expiry time.Time) (string, error) {
	revID, err := extractRootRevocationID(rawToken)
	if err != nil {
		return "", err
	}
	s.RevokeBiscuitID(revID, expiry)
	return revID, nil
}

func (s *Server) cacheBannedNodeRevocationID(peerID string, rawBiscuit []byte) {
	if peerID == "" || len(rawBiscuit) == 0 {
		return
	}
	revID, err := extractRootRevocationID(rawBiscuit)
	if err != nil || revID == "" {
		return
	}
	s.revokedBiscuitsMu.Lock()
	s.bannedNodeRevIDs[peerID] = revID
	s.revokedBiscuitsMu.Unlock()
}

func (s *Server) clearBannedNodeRevocationID(peerID string) {
	if peerID == "" {
		return
	}
	s.revokedBiscuitsMu.Lock()
	delete(s.bannedNodeRevIDs, peerID)
	s.revokedBiscuitsMu.Unlock()
}

func (s *Server) listRevokedBiscuitIDs(ctx context.Context, bannedPeers []string) ([]string, error) {
	now := time.Now()
	set := make(map[string]bool)

	if s.store != nil {
		if dbRev, err := s.store.ListRevokedBiscuits(ctx, now); err == nil {
			for id := range dbRev {
				set[id] = true
			}
		}
	}

	var missingPeers []string
	bannedPeerSet := make(map[string]bool, len(bannedPeers))
	for _, p := range bannedPeers {
		bannedPeerSet[p] = true
	}

	s.revokedBiscuitsMu.Lock()
	for id, exp := range s.revokedBiscuits {
		if now.Before(exp) {
			set[id] = true
		} else {
			delete(s.revokedBiscuits, id)
		}
	}
	for peerID := range s.bannedNodeRevIDs {
		if !bannedPeerSet[peerID] {
			delete(s.bannedNodeRevIDs, peerID)
		}
	}
	for _, peerID := range bannedPeers {
		if revID, ok := s.bannedNodeRevIDs[peerID]; ok {
			if revID != "" {
				set[revID] = true
			}
		} else {
			missingPeers = append(missingPeers, peerID)
		}
	}
	s.revokedBiscuitsMu.Unlock()

	for _, peerID := range missingPeers {
		n, err := s.store.GetNode(ctx, peerID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			return nil, err
		}
		var revID string
		if len(n.Biscuit) > 0 {
			revID, _ = extractRootRevocationID(n.Biscuit)
		}
		s.revokedBiscuitsMu.Lock()
		s.bannedNodeRevIDs[peerID] = revID
		s.revokedBiscuitsMu.Unlock()
		if revID != "" {
			set[revID] = true
		}
	}

	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Server) isBiscuitRevoked(ctx context.Context, revocationIDs [][]byte) bool {
	if len(revocationIDs) == 0 {
		return false
	}
	now := time.Now()
	s.revokedBiscuitsMu.RLock()
	for _, rawID := range revocationIDs {
		encoded := base64.RawURLEncoding.EncodeToString(rawID)
		if exp, ok := s.revokedBiscuits[encoded]; ok && now.Before(exp) {
			s.revokedBiscuitsMu.RUnlock()
			return true
		}
		for _, bannedRevID := range s.bannedNodeRevIDs {
			if bannedRevID != "" && bannedRevID == encoded {
				s.revokedBiscuitsMu.RUnlock()
				return true
			}
		}
	}
	s.revokedBiscuitsMu.RUnlock()

	if s.store != nil {
		for _, rawID := range revocationIDs {
			encoded := base64.RawURLEncoding.EncodeToString(rawID)
			if revoked, err := s.store.IsBiscuitRevoked(ctx, encoded, now); err == nil && revoked {
				return true
			}
		}
	}
	return false
}

func (s *Server) configuredIssuers() []string {
	seen := make(map[string]bool)
	var out []string
	add := func(iss string) {
		iss = strings.TrimSpace(iss)
		if iss != "" && !seen[iss] {
			seen[iss] = true
			out = append(out, iss)
		}
	}
	for _, iss := range strings.Split(s.config.OIDCIssuer, ",") {
		add(iss)
	}
	for iss := range s.workloadIssuers {
		add(iss)
	}
	for iss := range s.workloadEmailSuffixes {
		add(iss)
	}
	s.providersMu.RLock()
	for iss := range s.providers {
		add(iss)
	}
	s.providersMu.RUnlock()
	return out
}

func (s *Server) checkBiscuitRevocationAndBans(ctx context.Context, claims *identity.VerifiedBiscuitClaims) (int, error) {
	if s.isBiscuitRevoked(ctx, claims.RevocationIDs) {
		return http.StatusForbidden, errors.New("caller biscuit is revoked")
	}
	now := time.Now()
	for _, rawPeerID := range []string{claims.NodePeerID, claims.ActorNodePeerID, claims.ClientPeerID} {
		if rawPeerID == "" {
			continue
		}
		pID, err := peer.Decode(rawPeerID)
		if err != nil {
			return http.StatusForbidden, fmt.Errorf("invalid peer ID %q: %w", rawPeerID, err)
		}
		canonical := pID.String()
		banned, err := s.store.IsNodeBanned(ctx, canonical)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("failed to check node ban: %w", err)
		}
		if banned {
			return http.StatusForbidden, fmt.Errorf("peer %s is banned", canonical)
		}
		nodeRec, err := s.store.GetNode(ctx, canonical)
		if err != nil {
			if !errors.Is(err, storage.ErrNotFound) {
				return http.StatusInternalServerError, fmt.Errorf("failed to load node %s: %w", canonical, err)
			}
			continue
		}
		if err := nodeRec.CheckAdmission(now); err != nil {
			return http.StatusForbidden, fmt.Errorf("peer %s is not admitted: %w", canonical, err)
		}
		if nodeRec.OwnerID != "" {
			if owner, uErr := s.store.GetUser(ctx, nodeRec.OwnerID); uErr == nil && owner != nil && owner.Issuer != "" {
				if ownerBanned, bErr := s.store.IsIdentityBanned(ctx, owner.IdentityKey()); bErr != nil {
					return http.StatusInternalServerError, fmt.Errorf("failed to check owner ban: %w", bErr)
				} else if ownerBanned {
					return http.StatusForbidden, fmt.Errorf("owner of peer %s is banned", canonical)
				}
			}
		}
		if nodeRec.ClaimsJSON != "" {
			var storedClaims jwt.MapClaims
			if json.Unmarshal([]byte(nodeRec.ClaimsJSON), &storedClaims) == nil {
				if key := oidcIdentityKey(storedClaims); key != "" {
					if idBanned, bErr := s.store.IsIdentityBanned(ctx, key); bErr != nil {
						return http.StatusInternalServerError, fmt.Errorf("failed to check identity ban: %w", bErr)
					} else if idBanned {
						return http.StatusForbidden, fmt.Errorf("identity of peer %s is banned", canonical)
					}
				}
			}
		}
	}
	if claims.User != "" {
		if user, err := s.store.GetUser(ctx, claims.User); err == nil && user != nil && user.Issuer != "" {
			if banned, bErr := s.store.IsIdentityBanned(ctx, user.IdentityKey()); bErr != nil {
				return http.StatusInternalServerError, fmt.Errorf("failed to check user ban: %w", bErr)
			} else if banned {
				return http.StatusForbidden, fmt.Errorf("user %s is banned", claims.User)
			}
		}
		for _, iss := range s.configuredIssuers() {
			if banned, bErr := s.store.IsIdentityBanned(ctx, iss+"|"+claims.User); bErr != nil {
				return http.StatusInternalServerError, fmt.Errorf("failed to check identity ban: %w", bErr)
			} else if banned {
				return http.StatusForbidden, fmt.Errorf("user %s is banned", claims.User)
			}
		}
	}
	return http.StatusOK, nil
}

// HandleRevocations serves GET `/revocations` (mesh protocol, binary protobuf).
func (s *Server) HandleRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.admittedNodeWithChallenge(w, r, api.RevocationsChallenge) == nil {
		return
	}
	ctx := r.Context()
	bannedPeers, err := s.store.ListBannedPeerIDs(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve banned peers for /revocations: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	revocationIDs, err := s.listRevokedBiscuitIDs(ctx, bannedPeers)
	if err != nil {
		logger.Errorf("Failed to retrieve revoked biscuit IDs for /revocations: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	resp := &api.RevocationsResponse{
		RevocationIds: revocationIDs,
		BannedPeerIds: bannedPeers,
	}
	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

// HandleTokenExchange serves stateless HTTP POST `/token/exchange` (mesh protocol).
// It verifies the calling agentmesh-node's Biscuit + PoP challenge, verifies the
// inbound subject JWT, resolves subject roles from mesh policy, and mints a
// short-lived Delegated Session Biscuit with zero database writes.
func (s *Server) HandleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodeRecord := s.admittedNode(r)
	if nodeRecord == nil {
		writeChallengeError(w, "Unauthorized: node credential required")
		return
	}
	if nodeRecord.Role == api.RoleRouter {
		http.Error(w, "Forbidden: router credentials cannot exchange tokens", http.StatusForbidden)
		return
	}
	if !s.allowNodeSTSRequest(nodeRecord.PeerID) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req api.TokenExchangeRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.SubjectToken) == "" {
		http.Error(w, "subject_token is required", http.StatusBadRequest)
		return
	}

	nodePubKey, err := crypto.UnmarshalPublicKey(nodeRecord.PublicKey)
	if err != nil {
		logger.Errorf("Corrupted public key stored for node %s: %v", nodeRecord.PeerID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	challengePayload := api.TokenExchangeChallenge(nodeRecord.PeerID, req.ChallengeUnixMs)
	if err := verifyFreshChallenge(nodePubKey, challengePayload, req.ChallengeUnixMs, req.ChallengeSignature); err != nil {
		logger.Warnw("Token exchange challenge verification failed", "peer_id", nodeRecord.PeerID, "error", err)
		writeChallengeError(w, "Invalid token exchange challenge: "+err.Error())
		return
	}

	actorPeerID, err := peer.Decode(nodeRecord.PeerID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	biscuitData, biscuitExpiry, subjectID, resolvedRoles, status, err := s.mintDelegatedBiscuitFromJWT(
		r.Context(),
		req.SubjectToken,
		actorPeerID,
		req.TaskRule,
		req.Seal,
		0,
		true,
	)
	if err != nil {
		logger.Infow("Border Crossing",
			"direction", "inbound",
			"endpoint", "/token/exchange",
			"decision", "deny",
			"actor_node", nodeRecord.PeerID,
			"reason", err.Error(),
		)
		http.Error(w, err.Error(), status)
		return
	}

	logger.Infow("Border Crossing",
		"direction", "inbound",
		"endpoint", "/token/exchange",
		"decision", "allow",
		"actor_node", nodeRecord.PeerID,
		"subject", subjectID,
		"roles", resolvedRoles,
		"expire_time", biscuitExpiry.UTC().Format(time.RFC3339),
	)

	resp := &api.TokenExchangeResponse{
		BiscuitToken: biscuitData,
		ExpireTime:   timestamppb.New(biscuitExpiry),
		Roles:        resolvedRoles,
		Subject:      subjectID,
	}
	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

func (s *Server) mintDelegatedBiscuitFromJWT(
	ctx context.Context,
	subjectJWT string,
	actorPeerID peer.ID,
	taskRule *api.TaskAuthorizationRule,
	seal bool,
	requestedTTLSeconds int64,
	allowWorkload bool,
) ([]byte, time.Time, string, []string, int, error) {
	verifyCtx, cancel := context.WithTimeout(ctx, JWTVerificationTimeout)
	defer cancel()

	claims, token, err := identity.VerifyJWT(verifyCtx, subjectJWT, s.config.AllowedAudiences, s.getProviders())
	if err != nil {
		return nil, time.Time{}, "", nil, http.StatusUnauthorized, fmt.Errorf("JWT validation failed: %w", err)
	}
	if !allowWorkload && s.isWorkloadClaims(claims) {
		return nil, time.Time{}, "", nil, http.StatusForbidden, errWorkloadIdentity
	}
	if verifiedEmail(claims) == "" {
		delete(claims, "email")
	}

	subjectKey := oidcIdentityKey(claims)
	if subjectKey != "" {
		banned, err := s.store.IsIdentityBanned(ctx, subjectKey)
		if err != nil {
			logger.Errorf("Failed to check identity ban for %s: %v", subjectKey, err)
			return nil, time.Time{}, "", nil, http.StatusInternalServerError, errors.New("internal server error")
		}
		if banned {
			return nil, time.Time{}, "", nil, http.StatusForbidden, errors.New("identity is banned")
		}
	}

	subjectPrincipal := verifiedEmail(claims)
	if subjectPrincipal == "" {
		if sub, _ := claims["sub"].(string); sub != "" {
			subjectPrincipal = sub
		} else {
			subjectPrincipal = subjectKey
		}
	}

	privKey, _, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		logger.Errorf("Failed to retrieve current signing key: %v", err)
		return nil, time.Time{}, "", nil, http.StatusInternalServerError, errors.New("internal server error")
	}

	policyRoles, bindings, err := s.store.GetMeshPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		logger.Errorf("Failed to load mesh policy for token exchange: %v", err)
		return nil, time.Time{}, "", nil, http.StatusInternalServerError, errors.New("internal server error")
	}

	// Pass empty peerID so node:<peer> bindings on the origin node never leak to the delegated subject.
	rawRoles := resolveRoles("", claims, bindings)
	var resolvedRoles []string
	for _, r := range rawRoles {
		if r == api.RoleRouter {
			continue
		}
		resolvedRoles = append(resolvedRoles, r)
	}
	sort.Strings(resolvedRoles)

	now := time.Now()
	ttl := s.config.DelegatedBiscuitTTL
	if ttl <= 0 || ttl > s.config.BiscuitTTL {
		ttl = s.config.BiscuitTTL
	}
	if requestedTTLSeconds > 0 {
		reqDur := time.Duration(requestedTTLSeconds) * time.Second
		if reqDur < ttl {
			ttl = reqDur
		}
	}
	biscuitExpiry := now.Add(ttl)
	if !token.Expiry.IsZero() && token.Expiry.Before(biscuitExpiry) {
		biscuitExpiry = token.Expiry
	}

	biscuitData, err := identity.MintDelegatedBiscuitToken(privKey, claims, actorPeerID, biscuitExpiry, resolvedRoles, policyRoles, taskRule, seal)
	if err != nil {
		logger.Errorw("Delegated Biscuit minting failed", "actor_node", actorPeerID.String(), "error", err)
		return nil, time.Time{}, "", nil, http.StatusBadRequest, fmt.Errorf("failed to mint delegated biscuit: %w", err)
	}
	if taskRule != nil {
		biscuitExpiry = api.EffectiveTARExpiration(biscuitExpiry, []*api.TaskAuthorizationRule{taskRule})
	}
	return biscuitData, biscuitExpiry, subjectPrincipal, resolvedRoles, http.StatusOK, nil
}

// HandleSTSToken serves stateless HTTP POST `/sts/token` (mesh protocol).
// It authenticates the calling egress agentmesh-node via Biscuit + PoP challenge,
// verifies the caller's Biscuit + appended tar_block chain against standing
// mesh policy and egress://<destination>, and mints a short-lived ES256 JWT.
func (s *Server) HandleSTSToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodeRecord := s.admittedNode(r)
	if nodeRecord == nil {
		writeChallengeError(w, "Unauthorized: node credential required")
		return
	}
	if nodeRecord.Role == api.RoleRouter {
		http.Error(w, "Forbidden: router credentials cannot mint STS tokens", http.StatusForbidden)
		return
	}
	if !s.allowNodeSTSRequest(nodeRecord.PeerID) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req api.STSTokenRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}
	if len(req.Biscuit) == 0 {
		http.Error(w, "biscuit is required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Destination) == "" {
		http.Error(w, "destination is required", http.StatusBadRequest)
		return
	}

	nodePubKey, err := crypto.UnmarshalPublicKey(nodeRecord.PublicKey)
	if err != nil {
		logger.Errorf("Corrupted public key stored for node %s: %v", nodeRecord.PeerID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	challengePayload := api.STSTokenChallenge(nodeRecord.PeerID, req.ChallengeUnixMs)
	if err := verifyFreshChallenge(nodePubKey, challengePayload, req.ChallengeUnixMs, req.ChallengeSignature); err != nil {
		logger.Warnw("STS token challenge verification failed", "peer_id", nodeRecord.PeerID, "error", err)
		writeChallengeError(w, "Invalid STS token challenge: "+err.Error())
		return
	}

	// Verify that if the destination is configured in PolicyConfig.egress with
	// served_by constraints, the calling agentmesh-node is authorized to serve it.
	destHost := api.NormalizeMeshHost(strings.TrimPrefix(strings.TrimSpace(req.Destination), api.EgressServicePrefix))
	if egressList, err := s.store.GetEgressDestinations(r.Context()); err == nil {
		for _, d := range egressList {
			if d != nil && d.GetName() == destHost {
				if len(d.GetServedBy()) > 0 {
					callingRoles := s.nodeRoles(r.Context(), nodeRecord)
					if !api.EgressServedBy(d, callingRoles, nodeRecord.Labels) {
						http.Error(w, fmt.Sprintf("calling node %s is not in served_by for egress://%s", nodeRecord.PeerID, destHost), http.StatusForbidden)
						return
					}
				}
				break
			}
		}
	}

	audience, audErr := s.resolveEgressAudience(r.Context(), req.Destination, req.Audience)
	if audErr != nil {
		http.Error(w, audErr.Error(), http.StatusForbidden)
		return
	}

	claims, status, err := s.authorizeBiscuitForEgress(r.Context(), req.Biscuit, req.Destination)
	if err != nil {
		logger.Infow("Border Crossing",
			"direction", "outbound",
			"endpoint", "/sts/token",
			"decision", "deny",
			"actor_node", nodeRecord.PeerID,
			"audience", audience,
			"destination", req.Destination,
			"reason", err.Error(),
		)
		http.Error(w, err.Error(), status)
		return
	}

	now := time.Now()
	ttl := s.config.STSTokenTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if ttl > maxSTSTokenTTL {
		ttl = maxSTSTokenTTL
	}
	jwtExpiry := now.Add(ttl)
	if !claims.Expiration.IsZero() && claims.Expiration.Before(jwtExpiry) {
		jwtExpiry = claims.Expiration
	}
	if !now.Before(jwtExpiry) {
		http.Error(w, "Biscuit token is expired", http.StatusForbidden)
		return
	}

	jti := cryptoRandUUID()
	subject := claims.Principal()
	taskName := claims.InnermostTaskName()
	jwtClaims := jwt.MapClaims{
		"iss":        s.oidcIssuerURL(r),
		"sub":        subject,
		"aud":        audience,
		"act":        map[string]any{"sub": nodeRecord.PeerID},
		"mesh_roles": claims.Roles,
		"iat":        now.Unix(),
		"exp":        jwtExpiry.Unix(),
		"jti":        jti,
	}
	if taskName != "" {
		jwtClaims["mesh_task"] = taskName
	}

	signedJWT, err := s.oidcSigner.SignJWT(r.Context(), jwtClaims)
	if err != nil {
		logger.Errorf("Failed to sign outbound STS JWT: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logger.Infow("Border Crossing",
		"direction", "outbound",
		"endpoint", "/sts/token",
		"decision", "allow",
		"actor_node", nodeRecord.PeerID,
		"subject", subject,
		"audience", audience,
		"destination", req.Destination,
		"task", taskName,
		"jti", jti,
		"expire_time", jwtExpiry.UTC().Format(time.RFC3339),
	)

	resp := &api.STSTokenResponse{
		Jwt:        signedJWT,
		ExpireTime: timestamppb.New(jwtExpiry),
		Subject:    subject,
		Roles:      claims.Roles,
		TaskName:   taskName,
	}
	respData, err := proto.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

func (s *Server) resolveEgressAudience(ctx context.Context, destination, reqAudience string) (string, error) {
	destHost := api.NormalizeMeshHost(strings.TrimPrefix(strings.TrimSpace(destination), api.EgressServicePrefix))
	reqAud := strings.TrimSpace(reqAudience)
	if egressList, err := s.store.GetEgressDestinations(ctx); err == nil {
		for _, d := range egressList {
			if d != nil && d.GetName() == destHost {
				if fed := d.GetBroker().GetOidcFederation(); fed != nil && strings.TrimSpace(fed.GetAudience()) != "" {
					policyAud := strings.TrimSpace(fed.GetAudience())
					if reqAud != "" && reqAud != policyAud {
						return "", fmt.Errorf("requested audience %q does not match policy audience for egress://%s", reqAud, destHost)
					}
					return policyAud, nil
				}
				if aws := d.GetBroker().GetAwsAssumeRole(); aws != nil && strings.TrimSpace(aws.GetRoleArn()) != "" {
					if reqAud != "" && reqAud != "sts.amazonaws.com" {
						return "", fmt.Errorf("requested audience %q does not match AWS STS audience \"sts.amazonaws.com\" for egress://%s", reqAud, destHost)
					}
					return "sts.amazonaws.com", nil
				}
				break
			}
		}
	}
	if reqAud != "" {
		return reqAud, nil
	}
	return "https://" + destHost, nil
}

var stsDestinationRules = []biscuit.Rule{
	mustParseSTSRule(fmt.Sprintf(`%s($t, $k) <- %s($t, $k)`, api.FactHTTPMethodOK, api.FactService)),
	mustParseSTSRule(fmt.Sprintf(`%s($t, $k) <- %s($t, $k)`, api.FactHTTPPathOK, api.FactService)),
	mustParseSTSRule(fmt.Sprintf(`%s($t, "*") <- %s($t, $n)`, api.FactHTTPMethodOK, api.FactService)),
	mustParseSTSRule(fmt.Sprintf(`%s($t, "*") <- %s($t, $n)`, api.FactHTTPPathOK, api.FactService)),
	mustParseSTSRule(fmt.Sprintf(`%s("*", "*") <- %s($t, $n)`, api.FactHTTPMethodOK, api.FactService)),
	mustParseSTSRule(fmt.Sprintf(`%s("*", "*") <- %s($t, $n)`, api.FactHTTPPathOK, api.FactService)),
}

func mustParseSTSRule(s string) biscuit.Rule {
	r, err := parser.FromStringRule(s)
	if err != nil {
		panic(fmt.Sprintf("invalid static STS Datalog rule %q: %v", s, err))
	}
	return r
}

func (s *Server) authorizeBiscuitForEgress(ctx context.Context, rawBiscuit []byte, destination string) (*identity.VerifiedBiscuitClaims, int, error) {
	trustedKeys, err := s.store.GetAllValidPublicKeys(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to load signing keys: %w", err)
	}
	claims, err := identity.InspectVerifiedBiscuit(rawBiscuit, trustedKeys, s.config.BiscuitTimeout)
	if err != nil {
		return nil, http.StatusForbidden, fmt.Errorf("invalid caller biscuit: %w", err)
	}
	if status, revErr := s.checkBiscuitRevocationAndBans(ctx, claims); revErr != nil {
		return nil, status, revErr
	}
	if claims.ClientPeerID == "" {
		return nil, http.StatusForbidden, errors.New("caller biscuit lacks client_peer_id")
	}
	clientPeer, err := peer.Decode(claims.ClientPeerID)
	if err != nil {
		return nil, http.StatusForbidden, fmt.Errorf("invalid client_peer_id in biscuit: %w", err)
	}
	if err := identity.RequireAuthorityRequestBinding(claims.Biscuit, clientPeer); err != nil {
		return nil, http.StatusForbidden, err
	}

	authorizer, err := claims.Biscuit.Authorizer(claims.VerifyingKey, identity.AuthorizerOptions(s.config.BiscuitTimeout)...)
	if err != nil {
		return nil, http.StatusForbidden, err
	}
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactService,
			IDs:  []biscuit.Term{biscuit.String("egress"), biscuit.String(destination)},
		},
	})
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactConnectionPeerID,
			IDs:  []biscuit.Term{biscuit.String(clientPeer.String())},
		},
	})
	authorizer.AddCheck(api.BaselineReplayCheck)
	authorizer.AddFact(api.MarkerFact(api.FactTargetUnrestricted))
	authorizer.AddCheck(api.BaselineTargetCheck)
	identity.EnforceExpiration(authorizer)

	for _, p := range api.BaselinePolicies {
		authorizer.AddPolicy(p)
	}
	for _, r := range api.BaselineRules {
		authorizer.AddRule(r)
	}
	for _, r := range api.BaselineHTTPRules {
		authorizer.AddRule(r)
	}
	// Destination-level STS minting checks whether the role grants egress://<destination>
	// at all (plain or HTTP-narrowed); per-request method/path restrictions are
	// enforced by the egress agentmesh-node PEP on the wire HTTP request.
	for _, r := range stsDestinationRules {
		authorizer.AddRule(r)
	}

	roles, bindings, err := s.store.GetMeshPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to load mesh policy: %w", err)
	}
	egressDests, err := s.store.GetEgressDestinations(ctx)
	if err != nil && err != storage.ErrNotFound {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to load egress destinations: %w", err)
	}
	policyRules, _ := api.BuildPolicyRules(roles, bindings)
	policyRules = append(policyRules, api.BuildEgressServingRules(egressDests)...)
	for _, pr := range policyRules {
		authorizer.AddRule(pr.Rule)
	}

	if err := authorizer.Authorize(); err != nil {
		return nil, http.StatusForbidden, fmt.Errorf("standing policy denied egress://%s: %w", destination, err)
	}

	if err := api.EvaluateTaskRulesForDestination(claims.TaskRules, "egress", destination, time.Now()); err != nil {
		return nil, http.StatusForbidden, err
	}

	// Collect any roles derived via Datalog policy bindings so mesh_roles is complete.
	if facts, qErr := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_roles", IDs: []biscuit.Term{biscuit.Variable("r")}},
		Body: []biscuit.Predicate{{Name: api.FactRole, IDs: []biscuit.Term{biscuit.Variable("r")}}},
	}); qErr == nil {
		roleSet := make(map[string]bool, len(claims.Roles))
		for _, r := range claims.Roles {
			roleSet[r] = true
		}
		for _, f := range facts {
			if len(f.IDs) == 1 {
				if str, ok := f.IDs[0].(biscuit.String); ok {
					roleSet[string(str)] = true
				}
			}
		}
		merged := make([]string, 0, len(roleSet))
		for r := range roleSet {
			merged = append(merged, r)
		}
		sort.Strings(merged)
		claims.Roles = merged
	}

	return claims, http.StatusOK, nil
}

// oauthAuthCode represents a single-use OAuth 2.1 PKCE authorization code.
type oauthAuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	SubjectJWT    string
	ActorPeerID   peer.ID
	TAR           *api.TaskAuthorizationRule
	ExpiresAt     time.Time
}

var oauthConsentPageTmpl = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Authorize Agent Task</title></head>
<body>
  <h2>Authorize Agent Task</h2>
  <p>Client: <strong>{{.ClientID}}</strong></p>
  {{if .TaskName}}<p>Task: <strong>{{.TaskName}}</strong></p>{{end}}
  {{if .Services}}<p>Allowed Services: <code>{{.Services}}</code></p>{{end}}
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    <input type="hidden" name="scope" value="{{.Scope}}">
    {{range .Resources}}<input type="hidden" name="resource" value="{{.}}">{{end}}
    <input type="hidden" name="options" value="{{.Options}}">
    <input type="hidden" name="actor_peer_id" value="{{.ActorPeerID}}">
    <input type="hidden" name="id_token" value="{{.IDToken}}">
    <input type="hidden" name="approve" value="true">
    <button type="submit">Approve</button>
  </form>
</body>
</html>`))

func isValidOAuthRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Scheme, "https") {
		return true
	}
	if strings.EqualFold(u.Scheme, "http") {
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return true
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

func clientRateLimitKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return "oauth:" + r.RemoteAddr
	}
	return "oauth:" + host
}

// HandleOAuthAuthorize serves GET and POST `/oauth/authorize` (OAuth 2.1 Authorization Code + PKCE S256).
func (s *Server) HandleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allowNodeSTSRequest(clientRateLimitKey(r)) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form parameters", http.StatusBadRequest)
		return
	}

	responseType := r.Form.Get("response_type")
	if responseType != "" && responseType != "code" {
		http.Error(w, "Unsupported response_type (must be code)", http.StatusBadRequest)
		return
	}
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	redirectURI := strings.TrimSpace(r.Form.Get("redirect_uri"))
	if redirectURI != "" && !isValidOAuthRedirectURI(redirectURI) {
		http.Error(w, "Invalid redirect_uri: must be https or loopback http without fragment", http.StatusBadRequest)
		return
	}
	state := r.Form.Get("state")
	codeChallenge := strings.TrimSpace(r.Form.Get("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(r.Form.Get("code_challenge_method"))
	if codeChallenge == "" || (codeChallengeMethod != "" && codeChallengeMethod != "S256") {
		http.Error(w, "PKCE code_challenge with code_challenge_method=S256 is required", http.StatusBadRequest)
		return
	}

	subjectJWT := strings.TrimSpace(r.Form.Get("id_token"))
	if subjectJWT == "" {
		subjectJWT = strings.TrimSpace(r.Form.Get("id_token_hint"))
	}
	if subjectJWT == "" {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			subjectJWT = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if subjectJWT == "" {
		http.Error(w, "Bearer OIDC token or id_token parameter required", http.StatusUnauthorized)
		return
	}

	// Verify the user's OIDC JWT upfront before rendering consent or issuing a code.
	verifyCtx, cancel := context.WithTimeout(r.Context(), JWTVerificationTimeout)
	defer cancel()
	claims, _, err := identity.VerifyJWT(verifyCtx, subjectJWT, s.config.AllowedAudiences, s.getProviders())
	if err != nil {
		http.Error(w, "Invalid OIDC token: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if s.isWorkloadClaims(claims) {
		http.Error(w, errWorkloadIdentity.Error(), http.StatusForbidden)
		return
	}
	if subjectKey := oidcIdentityKey(claims); subjectKey != "" {
		if banned, bErr := s.store.IsIdentityBanned(r.Context(), subjectKey); bErr != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		} else if banned {
			http.Error(w, "Identity is banned", http.StatusForbidden)
			return
		}
	}

	actorPeerStr := strings.TrimSpace(r.Form.Get("actor_peer_id"))
	var actorPeerID peer.ID
	if actorPeerStr != "" {
		pID, err := peer.Decode(actorPeerStr)
		if err != nil {
			http.Error(w, "Invalid actor_peer_id", http.StatusBadRequest)
			return
		}
		nodeRec, err := s.store.GetNode(r.Context(), pID.String())
		if err != nil || nodeRec == nil || nodeRec.CheckAdmission(time.Now()) != nil {
			http.Error(w, "Invalid or un-admitted actor_peer_id", http.StatusForbidden)
			return
		}
		actorPeerID = pID
	}

	resources := r.Form["resource"]
	scope := r.Form.Get("scope")
	optionsParam := r.Form.Get("options")
	if optionsParam == "" {
		optionsParam = r.Form.Get("tar")
	}
	tarRule, err := api.BuildTARFromOAuthParams("consent-"+clientID, optionsParam, resources, scope, nil)
	if err != nil {
		http.Error(w, "Invalid task scope/options: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Browser HTML navigations (or any GET carrying an approve query param) must
	// always render the consent form and submit approval via POST.
	if r.Method == http.MethodGet && (strings.Contains(r.Header.Get("Accept"), "text/html") || r.Form.Get("approve") != "") {
		var svcList []string
		var taskName string
		if tarRule != nil {
			taskName = tarRule.GetName()
			for _, rule := range tarRule.GetRules() {
				svcList = append(svcList, rule.GetAllowedServices()...)
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = oauthConsentPageTmpl.Execute(w, map[string]any{
			"ClientID":            clientID,
			"RedirectURI":         redirectURI,
			"State":               state,
			"CodeChallenge":       codeChallenge,
			"CodeChallengeMethod": "S256",
			"Scope":               scope,
			"Resources":           resources,
			"Options":             optionsParam,
			"ActorPeerID":         actorPeerID.String(),
			"IDToken":             subjectJWT,
			"TaskName":            taskName,
			"Services":            strings.Join(svcList, ", "),
		})
		return
	}
	if r.Method == http.MethodPost && r.PostForm.Get("approve") != "true" {
		http.Error(w, "Consent approval required", http.StatusForbidden)
		return
	}

	rawCode := make([]byte, 24)
	if _, err := rand.Read(rawCode); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	code := base64.RawURLEncoding.EncodeToString(rawCode)

	now := time.Now()
	s.oauthCodesMu.Lock()
	for k, v := range s.oauthCodes {
		if now.After(v.ExpiresAt) {
			delete(s.oauthCodes, k)
		}
	}
	if len(s.oauthCodes) >= maxPendingOAuthCodes {
		s.oauthCodesMu.Unlock()
		http.Error(w, "Too many pending authorization requests", http.StatusTooManyRequests)
		return
	}
	s.oauthCodes[code] = &oauthAuthCode{
		Code:          code,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		SubjectJWT:    subjectJWT,
		ActorPeerID:   actorPeerID,
		TAR:           tarRule,
		ExpiresAt:     now.Add(oauthAuthCodeTTL),
	}
	s.oauthCodesMu.Unlock()

	if redirectURI != "" {
		u, err := url.Parse(redirectURI)
		if err != nil {
			http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
			return
		}
		q := u.Query()
		q.Set("code", code)
		if state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":  code,
		"state": state,
	})
}

// HandleOAuthToken serves POST `/oauth/token` supporting OAuth 2.1
// `authorization_code` (with PKCE S256) and RFC 8693 `token-exchange`.
func (s *Server) HandleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allowNodeSTSRequest(clientRateLimitKey(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "rate limit exceeded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form body")
		return
	}

	grantType := r.Form.Get("grant_type")
	switch grantType {
	case api.GrantTypeAuthorizationCode:
		s.handleOAuthAuthCodeGrant(w, r)
	case api.GrantTypeTokenExchange:
		s.handleOAuthTokenExchangeGrant(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant_type")
	}
}

func decodeBase64Biscuit(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(encoded)
}

func (s *Server) resolveDefaultActorPeer(ctx context.Context, r *http.Request) (peer.ID, error) {
	if nodeRecord := s.admittedNode(r); nodeRecord != nil {
		return peer.Decode(nodeRecord.PeerID)
	}
	_, pub, err := s.store.GetCurrentKey(ctx)
	if err != nil {
		return "", err
	}
	ck, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return "", err
	}
	return peer.IDFromPublicKey(ck)
}

func (s *Server) handleOAuthAuthCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.Form.Get("code"))
	codeVerifier := strings.TrimSpace(r.Form.Get("code_verifier"))
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	redirectURI := strings.TrimSpace(r.Form.Get("redirect_uri"))
	if code == "" || codeVerifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code and code_verifier are required")
		return
	}

	s.oauthCodesMu.Lock()
	entry, ok := s.oauthCodes[code]
	if ok {
		delete(s.oauthCodes, code)
	}
	s.oauthCodesMu.Unlock()

	if !ok || time.Now().After(entry.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid or expired")
		return
	}
	if entry.ClientID != "" && clientID != entry.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if entry.RedirectURI != "" && redirectURI != entry.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	verifierHash := sha256.Sum256([]byte(codeVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])
	if subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(entry.CodeChallenge)) != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE code_verifier verification failed")
		return
	}

	actorPeerID := entry.ActorPeerID
	if actorPeerID == "" {
		var err error
		actorPeerID, err = s.resolveDefaultActorPeer(r.Context(), r)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Could not resolve actor node peer_id: "+err.Error())
			return
		}
	}

	seal := r.Form.Get("seal") == "true"
	biscuitData, biscuitExpiry, _, _, status, err := s.mintDelegatedBiscuitFromJWT(r.Context(), entry.SubjectJWT, actorPeerID, entry.TAR, seal, 0, false)
	if err != nil {
		writeOAuthError(w, status, "invalid_grant", err.Error())
		return
	}

	expiresIn := int64(time.Until(biscuitExpiry).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      base64.StdEncoding.EncodeToString(biscuitData),
		"issued_token_type": api.TokenTypeBiscuit,
		"token_type":        "Bearer",
		"expires_in":        expiresIn,
	})
}

func (s *Server) handleOAuthTokenExchangeGrant(w http.ResponseWriter, r *http.Request) {
	subjectToken := strings.TrimSpace(r.Form.Get("subject_token"))
	subjectTokenType := strings.TrimSpace(r.Form.Get("subject_token_type"))
	if subjectToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}

	var reqTTL int64
	if ttlStr := strings.TrimSpace(r.Form.Get("expires_in")); ttlStr != "" {
		if parsed, err := strconv.ParseInt(ttlStr, 10, 64); err == nil && parsed > 0 {
			reqTTL = parsed
		}
	}

	var tarExpire *timestamppb.Timestamp
	if reqTTL > 0 {
		tarExpire = timestamppb.New(time.Now().Add(time.Duration(reqTTL) * time.Second))
	}
	tarRule, err := api.BuildTARFromOAuthParams(
		r.Form.Get("task_name"),
		r.Form.Get("options"),
		r.Form["resource"],
		r.Form.Get("scope"),
		tarExpire,
	)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	seal := r.Form.Get("seal") == "true"

	var biscuitData []byte
	var biscuitExpiry time.Time

	if subjectTokenType == api.TokenTypeBiscuit {
		rawBiscuit, err := decodeBase64Biscuit(subjectToken)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid biscuit subject_token")
			return
		}
		trustedKeys, err := s.store.GetAllValidPublicKeys(r.Context())
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to load signing keys")
			return
		}
		claims, err := identity.InspectVerifiedBiscuit(rawBiscuit, trustedKeys, s.config.BiscuitTimeout)
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_grant", "Invalid subject biscuit: "+err.Error())
			return
		}
		if status, revErr := s.checkBiscuitRevocationAndBans(r.Context(), claims); revErr != nil {
			writeOAuthError(w, status, "invalid_grant", revErr.Error())
			return
		}
		biscuitData = rawBiscuit
		biscuitExpiry = claims.Expiration
		if tarRule != nil {
			biscuitData, err = identity.AttenuateBiscuit(biscuitData, tarRule)
			if err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to attenuate biscuit: "+err.Error())
				return
			}
			biscuitExpiry = api.EffectiveTARExpiration(biscuitExpiry, []*api.TaskAuthorizationRule{tarRule})
		}
		if seal {
			biscuitData, err = identity.SealBiscuit(biscuitData)
			if err != nil {
				writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to seal biscuit")
				return
			}
		}
	} else {
		admitted := s.admittedNode(r)
		actorPeerID, err := s.resolveDefaultActorPeer(r.Context(), r)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Could not resolve actor peer_id: "+err.Error())
			return
		}
		var status int
		biscuitData, biscuitExpiry, _, _, status, err = s.mintDelegatedBiscuitFromJWT(r.Context(), subjectToken, actorPeerID, tarRule, seal, reqTTL, admitted != nil)
		if err != nil {
			writeOAuthError(w, status, "invalid_grant", err.Error())
			return
		}
	}

	expiresIn := int64(time.Until(biscuitExpiry).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      base64.StdEncoding.EncodeToString(biscuitData),
		"issued_token_type": api.TokenTypeBiscuit,
		"token_type":        "Bearer",
		"expires_in":        expiresIn,
	})
}

func writeOAuthError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
