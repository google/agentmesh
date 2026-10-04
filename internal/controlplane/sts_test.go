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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/node"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func enrollTestNodeForSTS(t *testing.T, baseURL string, mintOIDC func(map[string]interface{}) string) (crypto.PrivKey, peer.ID, []byte, ed25519.PublicKey) {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	peerID, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	ts := time.Now().UnixMilli()
	sig, err := priv.Sign(api.RegisterChallenge(peerID.String(), ts))
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	enrollReq := &api.EnrollRequest{
		Jwt:                mintOIDC(map[string]interface{}{"sub": "node-operator", "email": "ops@example.com", "email_verified": true}),
		PeerId:             peerID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	}
	reqBytes, _ := proto.Marshal(enrollReq)
	resp, err := http.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("register request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register returned %d: %s", resp.StatusCode, string(body))
	}
	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollResp); err != nil {
		t.Fatalf("unmarshal EnrollResponse: %v", err)
	}
	return priv, peerID, enrollResp.BiscuitToken, ed25519.PublicKey(enrollResp.ControlPlanePublicKey)
}

func TestTokenExchangeStatelessAndRoleIsolation(t *testing.T) {
	issuer, mintOIDC := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() { _ = srv.Close() }()

	// Seed initial policy allowing open node enrollment so we can enroll nodeA.
	ctx := context.Background()
	initialRoles := []*api.PolicyRole{
		{Name: api.RoleNode, AllowedServices: []string{"mcp://weather"}, AllowedTargets: []string{"*"}},
	}
	initialBindings := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
	}
	if err := store.SavePolicyDocument(ctx, initialRoles, initialBindings, nil); err != nil {
		t.Fatalf("SavePolicyDocument: %v", err)
	}

	nodePriv, nodePeerID, nodeBiscuit, cpPubKey := enrollTestNodeForSTS(t, baseURL, mintOIDC)

	// Now update policy so that:
	// - node:<nodePeerID> is bound to "node-admin-role" (granting mcp://internal-admin)
	// - user:alice-sub is bound to "analyst" (granting mcp://weather and egress://bigquery.googleapis.com)
	roles := []*api.PolicyRole{
		{Name: api.RoleNode, AllowedServices: []string{"mcp://weather"}, AllowedTargets: []string{"*"}},
		{Name: "node-admin-role", AllowedServices: []string{"mcp://internal-admin"}, AllowedTargets: []string{"*"}},
		{Name: "analyst", AllowedServices: []string{"mcp://weather", "egress://bigquery.googleapis.com"}, AllowedTargets: []string{"*"}},
	}
	bindings := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
		{Role: "node-admin-role", Members: []string{"node:" + nodePeerID.String()}},
		{Role: "analyst", Members: []string{"user:alice-sub"}},
	}
	if err := store.SavePolicyDocument(ctx, roles, bindings, nil); err != nil {
		t.Fatalf("SavePolicyDocument: %v", err)
	}

	nodesBefore, err := store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}

	aliceJWT := mintOIDC(map[string]interface{}{
		"sub":            "alice-sub",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	ts := time.Now().UnixMilli()
	sig, err := nodePriv.Sign(api.TokenExchangeChallenge(nodePeerID.String(), ts))
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	exReq := &api.TokenExchangeRequest{
		SubjectToken: aliceJWT,
		TaskRule: &api.TaskAuthorizationRule{
			Name: "weather-check",
			Rules: []*api.TaskRule{
				{
					AllowedServices: []string{"mcp://weather"},
					Operation:       &api.TaskOperation{AllowedTools: []string{"get_forecast"}},
				},
			},
		},
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	}
	exBytes, _ := proto.Marshal(exReq)
	httpReq, _ := http.NewRequest(http.MethodPost, baseURL+"/token/exchange", bytes.NewReader(exBytes))
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(nodeBiscuit))

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("POST /token/exchange failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token/exchange returned %d: %s", resp.StatusCode, string(respBody))
	}

	var exResp api.TokenExchangeResponse
	if err := proto.Unmarshal(respBody, &exResp); err != nil {
		t.Fatalf("unmarshal TokenExchangeResponse: %v", err)
	}
	if exResp.Subject != "alice@example.com" {
		t.Fatalf("Subject = %q, want alice@example.com", exResp.Subject)
	}
	if slices.Contains(exResp.Roles, "node-admin-role") {
		t.Fatalf("delegated token leaked node:<peer> role: %v", exResp.Roles)
	}
	if !slices.Contains(exResp.Roles, "analyst") {
		t.Fatalf("expected analyst role in %v", exResp.Roles)
	}

	// Verify zero DB writes occurred during /token/exchange.
	nodesAfter, err := store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes after exchange: %v", err)
	}
	if len(nodesAfter) != len(nodesBefore) {
		t.Fatalf("nodes count changed from %d to %d; /token/exchange must be stateless", len(nodesBefore), len(nodesAfter))
	}

	// Delegated Biscuit must NOT pass peer handshake verification (no node() fact).
	if _, err := identity.VerifyBiscuit(exResp.BiscuitToken, nodePeerID, []ed25519.PublicKey{cpPubKey}, time.Second); err == nil {
		t.Fatal("expected VerifyBiscuit (peer handshake) to reject delegated token lacking node() fact")
	}

	// Verify SamNode.Authorize accepts the delegated token for mcp://weather get_forecast,
	// denies mcp://weather drop_table (TAR), and denies mcp://internal-admin (standing policy).
	compiledRules, _ := api.BuildPolicyRules(roles, bindings)
	parsedRules, err := api.ParseDatalogRules(api.PolicyRuleTexts(compiledRules))
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}
	nStore, err := node.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = nStore.Close() }()
	verifierNode, err := node.NewSamNode(node.Options{
		PrivKey:            nodePriv,
		Store:              nStore,
		ControlPlanePubKey: cpPubKey,
		BiscuitTimeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("NewSamNode: %v", err)
	}
	verifierNode.MeshPolicyRules = parsedRules
	verifierNode.SetIdentityCache(nodeBiscuit)

	if err := verifierNode.Authorize(exResp.BiscuitToken, node.RequestContext{
		PeerID:   nodePeerID,
		Protocol: string(api.MCPProtocolID),
		Target:   "mcp://weather",
		MCPTool:  "get_forecast",
	}, cpPubKey); err != nil {
		t.Fatalf("expected Authorize to allow get_forecast on mcp://weather, got: %v", err)
	}

	if err := verifierNode.Authorize(exResp.BiscuitToken, node.RequestContext{
		PeerID:   nodePeerID,
		Protocol: string(api.MCPProtocolID),
		Target:   "mcp://weather",
		MCPTool:  "drop_table",
	}, cpPubKey); err == nil {
		t.Fatal("expected Authorize to deny drop_table on mcp://weather")
	}

	if err := verifierNode.Authorize(exResp.BiscuitToken, node.RequestContext{
		PeerID:   nodePeerID,
		Protocol: string(api.MCPProtocolID),
		Target:   "mcp://internal-admin",
		MCPTool:  "get_forecast",
	}, cpPubKey); err == nil {
		t.Fatal("expected Authorize to deny mcp://internal-admin")
	}
}

func jwkToECDSAPublicKey(t *testing.T, jwk JSONWebKey) *ecdsa.PublicKey {
	t.Helper()
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("decode jwk.X: %v", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("decode jwk.Y: %v", err)
	}
	uncompressed := make([]byte, 0, 1+len(xBytes)+len(yBytes))
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, xBytes...)
	uncompressed = append(uncompressed, yBytes...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		t.Fatalf("ParseUncompressedPublicKey: %v", err)
	}
	return pub
}

func TestOIDCIssuerJWKSAndSTSToken(t *testing.T) {
	issuer, mintOIDC := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer, func(o *Options) {
		o.STSIssuerURL = "https://cp.sam-mesh.example"
	})
	defer func() { _ = srv.Close() }()

	ctx := context.Background()
	roles := []*api.PolicyRole{
		{Name: api.RoleNode, AllowedServices: []string{"mcp://weather"}, AllowedTargets: []string{"*"}},
		{Name: "analyst", AllowedServices: []string{"egress://bigquery.googleapis.com", "mcp://weather"}, AllowedTargets: []string{"*"}},
	}
	bindings := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
		{Role: "analyst", Members: []string{"user:alice-sub"}},
	}
	if err := store.SavePolicyDocument(ctx, roles, bindings, nil); err != nil {
		t.Fatalf("SavePolicyDocument: %v", err)
	}

	nodePriv, nodePeerID, nodeBiscuit, _ := enrollTestNodeForSTS(t, baseURL, mintOIDC)

	// 1. Check /.well-known/openid-configuration
	discResp, err := http.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET openid-configuration: %v", err)
	}
	defer func() { _ = discResp.Body.Close() }()
	var discDoc map[string]any
	if err := json.NewDecoder(discResp.Body).Decode(&discDoc); err != nil {
		t.Fatalf("decode discovery doc: %v", err)
	}
	if discDoc["issuer"] != "https://cp.sam-mesh.example" {
		t.Fatalf("issuer = %v, want https://cp.sam-mesh.example", discDoc["issuer"])
	}
	if discDoc["jwks_uri"] != "https://cp.sam-mesh.example/jwks" {
		t.Fatalf("jwks_uri = %v", discDoc["jwks_uri"])
	}

	// 2. Mint a delegated Biscuit for Alice with a TAR allowing egress://bigquery.googleapis.com
	aliceJWT := mintOIDC(map[string]interface{}{
		"sub":            "alice-sub",
		"email":          "alice@example.com",
		"email_verified": true,
	})
	ts := time.Now().UnixMilli()
	sig, _ := nodePriv.Sign(api.TokenExchangeChallenge(nodePeerID.String(), ts))
	exReq := &api.TokenExchangeRequest{
		SubjectToken: aliceJWT,
		TaskRule: &api.TaskAuthorizationRule{
			Name: "bq-export",
			Rules: []*api.TaskRule{
				{
					AllowedServices: []string{"egress://bigquery.googleapis.com"},
					Operation:       &api.TaskOperation{AllowedMethods: []string{"POST"}, AllowedPaths: []string{"/bigquery/v2/*"}},
				},
			},
		},
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	}
	exBytes, _ := proto.Marshal(exReq)
	httpExReq, _ := http.NewRequest(http.MethodPost, baseURL+"/token/exchange", bytes.NewReader(exBytes))
	httpExReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(nodeBiscuit))
	exHTTPResp, err := http.DefaultClient.Do(httpExReq)
	if err != nil || exHTTPResp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange failed: %v", err)
	}
	exBody, _ := io.ReadAll(exHTTPResp.Body)
	_ = exHTTPResp.Body.Close()
	var exResp api.TokenExchangeResponse
	_ = proto.Unmarshal(exBody, &exResp)

	// 3. Call POST /sts/token for bigquery.googleapis.com
	stsTs := time.Now().UnixMilli()
	stsSig, _ := nodePriv.Sign(api.STSTokenChallenge(nodePeerID.String(), stsTs))
	stsReq := &api.STSTokenRequest{
		Biscuit:            exResp.BiscuitToken,
		Destination:        "bigquery.googleapis.com",
		Audience:           "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sam/providers/cp",
		ChallengeUnixMs:    stsTs,
		ChallengeSignature: stsSig,
	}
	stsReqBytes, _ := proto.Marshal(stsReq)
	httpSTSReq, _ := http.NewRequest(http.MethodPost, baseURL+"/sts/token", bytes.NewReader(stsReqBytes))
	httpSTSReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(nodeBiscuit))
	stsHTTPResp, err := http.DefaultClient.Do(httpSTSReq)
	if err != nil {
		t.Fatalf("POST /sts/token failed: %v", err)
	}
	defer func() { _ = stsHTTPResp.Body.Close() }()
	stsBody, _ := io.ReadAll(stsHTTPResp.Body)
	if stsHTTPResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /sts/token returned %d: %s", stsHTTPResp.StatusCode, string(stsBody))
	}
	var stsResp api.STSTokenResponse
	if err := proto.Unmarshal(stsBody, &stsResp); err != nil {
		t.Fatalf("unmarshal STSTokenResponse: %v", err)
	}
	if stsResp.Subject != "alice@example.com" || stsResp.TaskName != "bq-export" {
		t.Fatalf("unexpected STSTokenResponse metadata: subject=%q task=%q", stsResp.Subject, stsResp.TaskName)
	}

	// 4. Rotate OIDC key with overlap and verify both old and new keys appear in /jwks
	if _, err := srv.RotateOIDCKey(time.Minute); err != nil {
		t.Fatalf("RotateOIDCKey: %v", err)
	}
	jwksResp, err := http.Get(baseURL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer func() { _ = jwksResp.Body.Close() }()
	var jwks JSONWebKeySet
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys in JWKS after overlap rotation, got %d", len(jwks.Keys))
	}

	// Verify the JWT minted before rotation against the JWKS!
	parsedJWT, err := jwt.Parse(stsResp.Jwt, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		for _, k := range jwks.Keys {
			if k.Kid == kid {
				return jwkToECDSAPublicKey(t, k), nil
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	})
	if err != nil || !parsedJWT.Valid {
		t.Fatalf("failed to verify STS JWT against /jwks: %v", err)
	}
	claims := parsedJWT.Claims.(jwt.MapClaims)
	if claims["sub"] != "alice@example.com" {
		t.Fatalf("jwt sub = %v, want alice@example.com", claims["sub"])
	}
	if claims["sam_task"] != "bq-export" {
		t.Fatalf("jwt sam_task = %v, want bq-export", claims["sam_task"])
	}
	actMap, _ := claims["act"].(map[string]any)
	if actMap["sub"] != nodePeerID.String() {
		t.Fatalf("jwt act.sub = %v, want %s", actMap["sub"], nodePeerID.String())
	}

	// 5. Verify /sts/token denies destination not allowed by TAR (e.g. api.github.com)
	badSTSReq := &api.STSTokenRequest{
		Biscuit:            exResp.BiscuitToken,
		Destination:        "api.github.com",
		Audience:           "https://api.github.com",
		ChallengeUnixMs:    stsTs,
		ChallengeSignature: stsSig,
	}
	badBytes, _ := proto.Marshal(badSTSReq)
	httpBadReq, _ := http.NewRequest(http.MethodPost, baseURL+"/sts/token", bytes.NewReader(badBytes))
	httpBadReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(nodeBiscuit))
	badResp, err := http.DefaultClient.Do(httpBadReq)
	if err != nil {
		t.Fatalf("POST /sts/token failed: %v", err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthorized destination, got %d", badResp.StatusCode)
	}

	// 6. Revoke the Biscuit and verify /sts/token denies it and /revocations lists it
	revID, err := srv.RevokeBiscuitToken(exResp.BiscuitToken, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("RevokeBiscuitToken: %v", err)
	}
	httpRevokedSTS, _ := http.NewRequest(http.MethodPost, baseURL+"/sts/token", bytes.NewReader(stsReqBytes))
	httpRevokedSTS.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(nodeBiscuit))
	revSTSResp, err := http.DefaultClient.Do(httpRevokedSTS)
	if err != nil {
		t.Fatalf("POST /sts/token failed: %v", err)
	}
	_ = revSTSResp.Body.Close()
	if revSTSResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked Biscuit at /sts/token, got %d", revSTSResp.StatusCode)
	}

	httpRevList, _ := http.NewRequest(http.MethodGet, baseURL+"/revocations", nil)
	httpRevList.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(nodeBiscuit))
	revListResp, err := http.DefaultClient.Do(httpRevList)
	if err != nil {
		t.Fatalf("GET /revocations failed: %v", err)
	}
	defer func() { _ = revListResp.Body.Close() }()
	revListBody, _ := io.ReadAll(revListResp.Body)
	var revocations api.RevocationsResponse
	if err := proto.Unmarshal(revListBody, &revocations); err != nil {
		t.Fatalf("unmarshal RevocationsResponse: %v", err)
	}
	if !slices.Contains(revocations.RevocationIds, revID) {
		t.Fatalf("expected revocation ID %q in %v", revID, revocations.RevocationIds)
	}
}

func TestOAuth21AuthorizationCodePKCEAndTokenExchange(t *testing.T) {
	issuer, mintOIDC := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() { _ = srv.Close() }()

	ctx := context.Background()
	roles := []*api.PolicyRole{
		{Name: api.RoleNode, AllowedServices: []string{"mcp://weather"}, AllowedTargets: []string{"*"}},
		{Name: "analyst", AllowedServices: []string{"mcp://weather", "inference://gemini.pro"}, AllowedTargets: []string{"*"}},
	}
	bindings := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
		{Role: "analyst", Members: []string{"user:alice-sub"}},
	}
	if err := store.SavePolicyDocument(ctx, roles, bindings, nil); err != nil {
		t.Fatalf("SavePolicyDocument: %v", err)
	}

	nodePriv, nodePeerID, nodeBiscuit, cpPubKey := enrollTestNodeForSTS(t, baseURL, mintOIDC)
	aliceJWT := mintOIDC(map[string]interface{}{
		"sub":            "alice-sub",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	// 1. Perform OAuth 2.1 Authorization Code + PKCE S256
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	verifierHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])

	authForm := url.Values{
		"response_type":         {"code"},
		"client_id":             {"planner-ui"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"resource":              {"mcp://weather"},
		"scope":                 {"tool:get_forecast"},
		"actor_peer_id":         {nodePeerID.String()},
		"state":                 {"xyz-123"},
		"approve":               {"true"},
	}
	authReq, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/authorize", strings.NewReader(authForm.Encode()))
	authReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authReq.Header.Set("Authorization", "Bearer "+aliceJWT)

	authResp, err := http.DefaultClient.Do(authReq)
	if err != nil {
		t.Fatalf("POST /oauth/authorize: %v", err)
	}
	defer func() { _ = authResp.Body.Close() }()
	if authResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(authResp.Body)
		t.Fatalf("POST /oauth/authorize returned %d: %s", authResp.StatusCode, string(body))
	}
	var codePayload map[string]string
	if err := json.NewDecoder(authResp.Body).Decode(&codePayload); err != nil {
		t.Fatalf("decode code payload: %v", err)
	}
	authCode := codePayload["code"]
	if authCode == "" || codePayload["state"] != "xyz-123" {
		t.Fatalf("unexpected authorize response: %v", codePayload)
	}

	// Wrong PKCE verifier must fail (and consume the single-use code, so issue a second one after).
	badTokForm := url.Values{
		"grant_type":    {api.GrantTypeAuthorizationCode},
		"code":          {authCode},
		"client_id":     {"planner-ui"},
		"code_verifier": {"wrong-verifier"},
	}
	badTokResp, err := http.PostForm(baseURL+"/oauth/token", badTokForm)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	_ = badTokResp.Body.Close()
	if badTokResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad PKCE verifier, got %d", badTokResp.StatusCode)
	}

	// Issue a fresh code and redeem with the valid PKCE code_verifier.
	authReq2, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/authorize", strings.NewReader(authForm.Encode()))
	authReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authReq2.Header.Set("Authorization", "Bearer "+aliceJWT)
	authResp2, _ := http.DefaultClient.Do(authReq2)
	_ = json.NewDecoder(authResp2.Body).Decode(&codePayload)
	_ = authResp2.Body.Close()

	tokForm := url.Values{
		"grant_type":    {api.GrantTypeAuthorizationCode},
		"code":          {codePayload["code"]},
		"client_id":     {"planner-ui"},
		"code_verifier": {codeVerifier},
	}
	tokResp, err := http.PostForm(baseURL+"/oauth/token", tokForm)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer func() { _ = tokResp.Body.Close() }()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("POST /oauth/token returned %d: %s", tokResp.StatusCode, string(body))
	}
	var tokJSON map[string]any
	if err := json.NewDecoder(tokResp.Body).Decode(&tokJSON); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokJSON["issued_token_type"] != api.TokenTypeBiscuit {
		t.Fatalf("issued_token_type = %v, want %s", tokJSON["issued_token_type"], api.TokenTypeBiscuit)
	}
	biscuitB64, _ := tokJSON["access_token"].(string)
	biscuitBytes, err := base64.StdEncoding.DecodeString(biscuitB64)
	if err != nil {
		t.Fatalf("decode access_token biscuit: %v", err)
	}

	// Verify the returned Biscuit has 1 appended tar_block narrowing to mcp://weather get_forecast.
	_, taskRules, err := identity.UnmarshalInbound(biscuitBytes)
	if err != nil {
		t.Fatalf("UnmarshalInbound: %v", err)
	}
	if len(taskRules) != 1 {
		t.Fatalf("expected 1 tar_block on OAuth biscuit, got %d", len(taskRules))
	}

	// 2. Test RFC 8693 Token Exchange on /oauth/token to further attenuate and seal the Biscuit.
	subTAR := &api.TaskAuthorizationRule{
		Name:       "sealed-subtask",
		ExpireTime: timestamppb.New(time.Now().Add(5 * time.Minute)),
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"mcp://weather"},
				Operation:       &api.TaskOperation{AllowedTools: []string{"get_forecast"}},
			},
		},
	}
	subTARB64, err := api.EncodeTARBlockPayload(subTAR)
	if err != nil {
		t.Fatalf("EncodeTARBlockPayload: %v", err)
	}
	exForm := url.Values{
		"grant_type":         {api.GrantTypeTokenExchange},
		"subject_token":      {biscuitB64},
		"subject_token_type": {api.TokenTypeBiscuit},
		"options":            {subTARB64},
		"seal":               {"true"},
	}
	exTokResp, err := http.PostForm(baseURL+"/oauth/token", exForm)
	if err != nil {
		t.Fatalf("POST /oauth/token (exchange): %v", err)
	}
	defer func() { _ = exTokResp.Body.Close() }()
	if exTokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(exTokResp.Body)
		t.Fatalf("POST /oauth/token (exchange) returned %d: %s", exTokResp.StatusCode, string(body))
	}
	var exTokJSON map[string]any
	_ = json.NewDecoder(exTokResp.Body).Decode(&exTokJSON)
	sealedBytes, _ := base64.StdEncoding.DecodeString(exTokJSON["access_token"].(string))

	// Sealed Biscuit must have 2 tar_blocks and reject further attenuation!
	_, rules2, err := identity.UnmarshalInbound(sealedBytes)
	if err != nil {
		t.Fatalf("UnmarshalInbound sealed: %v", err)
	}
	if len(rules2) != 2 {
		t.Fatalf("expected 2 tar_blocks, got %d", len(rules2))
	}
	if _, err := identity.AttenuateBiscuit(sealedBytes, subTAR); err == nil {
		t.Fatal("expected AttenuateBiscuit on a sealed token to fail")
	}

	// And verify the 2-block sealed Biscuit authorizes mcp://weather get_forecast on SamNode.
	compiledRules, _ := api.BuildPolicyRules(roles, bindings)
	parsedRules, _ := api.ParseDatalogRules(api.PolicyRuleTexts(compiledRules))
	nStore, err := node.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = nStore.Close() }()
	verifierNode, err := node.NewSamNode(node.Options{
		PrivKey:            nodePriv,
		Store:              nStore,
		ControlPlanePubKey: cpPubKey,
		BiscuitTimeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("NewSamNode: %v", err)
	}
	verifierNode.MeshPolicyRules = parsedRules
	verifierNode.SetIdentityCache(nodeBiscuit)
	if err := verifierNode.Authorize(sealedBytes, node.RequestContext{
		PeerID:   nodePeerID,
		Protocol: string(api.MCPProtocolID),
		Target:   "mcp://weather",
		MCPTool:  "get_forecast",
	}, cpPubKey); err != nil {
		t.Fatalf("expected sealed 2-hop OAuth Biscuit to authorize get_forecast, got: %v", err)
	}
}
