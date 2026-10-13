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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/node"
	"github.com/google/agentmesh/internal/storage"
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

	nodesBefore, err := store.ListNodes(ctx, storage.NodeFilter{})
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
	nodesAfter, err := store.ListNodes(ctx, storage.NodeFilter{})
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

	// Verify AgentMeshNode.Authorize accepts the delegated token for mcp://weather get_forecast,
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
	verifierNode, err := node.NewAgentMeshNode(node.Options{
		PrivKey:            nodePriv,
		Store:              nStore,
		ControlPlanePubKey: cpPubKey,
		BiscuitTimeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode: %v", err)
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
		o.STSIssuerURL = "https://cp.agentmesh.example"
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
	if discDoc["issuer"] != "https://cp.agentmesh.example" {
		t.Fatalf("issuer = %v, want https://cp.agentmesh.example", discDoc["issuer"])
	}
	if discDoc["jwks_uri"] != "https://cp.agentmesh.example/jwks" {
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
		Audience:           "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/agentmesh/providers/cp",
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
	if claims["mesh_task"] != "bq-export" {
		t.Fatalf("jwt mesh_task = %v, want bq-export", claims["mesh_task"])
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
	revTS := time.Now().UnixMilli()
	revSig, err := nodePriv.Sign(api.RevocationsChallenge(nodePeerID.String(), revTS))
	if err != nil {
		t.Fatalf("sign RevocationsChallenge: %v", err)
	}
	httpRevList.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(revTS, 10))
	httpRevList.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(revSig))
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

	// And verify the 2-block sealed Biscuit authorizes mcp://weather get_forecast on AgentMeshNode.
	compiledRules, _ := api.BuildPolicyRules(roles, bindings)
	parsedRules, _ := api.ParseDatalogRules(api.PolicyRuleTexts(compiledRules))
	nStore, err := node.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = nStore.Close() }()
	verifierNode, err := node.NewAgentMeshNode(node.Options{
		PrivKey:            nodePriv,
		Store:              nStore,
		ControlPlanePubKey: cpPubKey,
		BiscuitTimeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode: %v", err)
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

	// Verify that a non-canonical (CIDv1 base32) peer ID in Biscuit claims is
	// canonicalized by InspectVerifiedBiscuit and caught by IsNodeBanned in authorizeBiscuitForEgress.
	if err := store.SetNodeBanned(ctx, nodePeerID.String(), true); err != nil {
		t.Fatalf("SetNodeBanned: %v", err)
	}
	cidV1Str := peer.ToCid(nodePeerID).String()
	if cidV1Str == nodePeerID.String() {
		t.Fatalf("expected CIDv1 string %q to differ from canonical base58 %q", cidV1Str, nodePeerID.String())
	}
	unbannedPriv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	unbannedPeerID, err := peer.IDFromPrivateKey(unbannedPriv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	cpPriv, _, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	bBuilder := biscuit.NewBuilder(cpPriv)
	_ = bBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
	}})
	_ = bBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(cidV1Str)},
	}})
	_ = bBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactActorNode,
		IDs:  []biscuit.Term{biscuit.String(unbannedPeerID.String())},
	}})
	_ = bBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactClientPeerID,
		IDs:  []biscuit.Term{biscuit.String(unbannedPeerID.String())},
	}})
	_ = bBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactUser,
		IDs:  []biscuit.Term{biscuit.String("alice-sub")},
	}})
	nonCanonicalB, err := bBuilder.Build()
	if err != nil {
		t.Fatalf("bBuilder.Build: %v", err)
	}
	nonCanonicalBiscuit, err := nonCanonicalB.Serialize()
	if err != nil {
		t.Fatalf("nonCanonicalB.Serialize: %v", err)
	}
	inspected, err := identity.InspectVerifiedBiscuit(nonCanonicalBiscuit, []ed25519.PublicKey{cpPubKey}, time.Second)
	if err != nil {
		t.Fatalf("InspectVerifiedBiscuit: %v", err)
	}
	if inspected.NodePeerID != nodePeerID.String() {
		t.Fatalf("expected InspectVerifiedBiscuit to canonicalize NodePeerID to %q, got %q", nodePeerID.String(), inspected.NodePeerID)
	}
	if _, status, err := srv.authorizeBiscuitForEgress(ctx, nonCanonicalBiscuit, "bigquery.googleapis.com"); err == nil || status != http.StatusForbidden || !strings.Contains(err.Error(), "is banned") {
		t.Fatalf("expected authorizeBiscuitForEgress to reject banned CIDv1 peer ID with 403 'is banned', got status=%d err=%v", status, err)
	}
}

func TestSTSSecurityHardening(t *testing.T) {
	issuer, mintOIDC := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() { _ = srv.Close() }()

	ctx := context.Background()
	initRoles := []*api.PolicyRole{
		{Name: api.RoleNode, AllowedServices: []string{"egress://s3.amazonaws.com"}, AllowedTargets: []string{"*"}},
	}
	initBindings := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
	}
	if err := store.SavePolicyDocument(ctx, initRoles, initBindings, nil); err != nil {
		t.Fatalf("SavePolicyDocument: %v", err)
	}

	nodePriv, nodePeerID, nodeBiscuit, _ := enrollTestNodeForSTS(t, baseURL, mintOIDC)
	otherPriv, otherPeerID, otherBiscuit, _ := enrollTestNodeForSTS(t, baseURL, mintOIDC)

	// 1. OIDC key persistence and rotation in SQL store
	initialKeys, err := store.GetAllValidOIDCKeys(ctx)
	if err != nil || len(initialKeys) != 1 {
		t.Fatalf("expected 1 persisted OIDC key, got %d (err=%v)", len(initialKeys), err)
	}
	if _, err := srv.RotateOIDCKey(time.Hour); err != nil {
		t.Fatalf("RotateOIDCKey: %v", err)
	}
	rotatedKeys, err := store.GetAllValidOIDCKeys(ctx)
	if err != nil || len(rotatedKeys) != 2 {
		t.Fatalf("expected 2 valid OIDC keys after rotation, got %d (err=%v)", len(rotatedKeys), err)
	}
	reloadedSigner, err := NewLocalES256SignerWithStore(store)
	if err != nil {
		t.Fatalf("NewLocalES256SignerWithStore: %v", err)
	}
	reloadedJWKS, err := reloadedSigner.JWKS(ctx)
	if err != nil || len(reloadedJWKS.Keys) != 2 {
		t.Fatalf("expected reloaded signer to have 2 keys, got %v (err=%v)", reloadedJWKS, err)
	}

	// 2. Configure AWS egress destination served ONLY by role "egress-gateway" (bound to nodePeerID)
	roles := []*api.PolicyRole{
		{Name: api.RoleNode, AllowedServices: []string{"egress://s3.amazonaws.com"}, AllowedTargets: []string{"*"}},
		{Name: "egress-gateway", AllowedServices: []string{"egress://s3.amazonaws.com"}, AllowedTargets: []string{"*"}},
	}
	bindings := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
		{Role: "egress-gateway", Members: []string{"node:" + nodePeerID.String()}},
	}
	egress := []*api.EgressDestination{
		{
			Name:     "s3.amazonaws.com",
			ServedBy: []string{"egress-gateway"},
			Broker: &api.CredentialBroker{
				Kind: &api.CredentialBroker_AwsAssumeRole{
					AwsAssumeRole: &api.AWSAssumeRole{
						RoleArn: "arn:aws:iam::123456789012:role/agentmesh-s3",
					},
				},
			},
		},
	}
	if err := store.SavePolicyDocument(ctx, roles, bindings, egress); err != nil {
		t.Fatalf("SavePolicyDocument: %v", err)
	}

	// Calling /sts/token from otherPeerID (not in ServedBy) must fail with 403
	callSTS := func(callerPriv crypto.PrivKey, callerID peer.ID, callerBiscuit []byte, aud string) *http.Response {
		t.Helper()
		ts := time.Now().UnixMilli()
		sig, _ := callerPriv.Sign(api.STSTokenChallenge(callerID.String(), ts))
		reqProto := &api.STSTokenRequest{
			Biscuit:            nodeBiscuit,
			Destination:        "s3.amazonaws.com",
			Audience:           aud,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		}
		reqBytes, _ := proto.Marshal(reqProto)
		httpReq, _ := http.NewRequest(http.MethodPost, baseURL+"/sts/token", bytes.NewReader(reqBytes))
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		httpReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(callerBiscuit))
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			t.Fatalf("POST /sts/token: %v", err)
		}
		return resp
	}

	unauthNodeResp := callSTS(otherPriv, otherPeerID, otherBiscuit, "")
	_ = unauthNodeResp.Body.Close()
	if unauthNodeResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when non-ServedBy node calls /sts/token, got %d", unauthNodeResp.StatusCode)
	}

	// Calling /sts/token from nodePeerID with a mismatched custom audience on aws_assume_role must fail with 403
	badAudResp := callSTS(nodePriv, nodePeerID, nodeBiscuit, "https://evil.example.com")
	_ = badAudResp.Body.Close()
	if badAudResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when custom audience mismatches aws_assume_role config, got %d", badAudResp.StatusCode)
	}

	// Calling /sts/token from nodePeerID with valid audience succeeds
	okResp := callSTS(nodePriv, nodePeerID, nodeBiscuit, "sts.amazonaws.com")
	_ = okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from authorized ServedBy node, got %d", okResp.StatusCode)
	}

	// 3. Router credentials (mesh:role:router) must be forbidden on /token/exchange and /sts/token
	routerPriv, routerPub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	routerPeerID, err := peer.IDFromPrivateKey(routerPriv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	routerPubBytes, _ := crypto.MarshalPublicKey(routerPub)
	cpPriv, _, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	routerBiscuit, err := identity.MintBootstrapBiscuitToken(cpPriv, routerPeerID, api.RoleRouter, time.Now().Add(time.Hour), roles, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}
	if err := store.EnrollNode(ctx, &storage.EnrolledNode{
		PeerID:         routerPeerID.String(),
		PublicKey:      routerPubBytes,
		Biscuit:        routerBiscuit,
		Role:           api.RoleRouter,
		EnrollmentType: "BOOTSTRAP",
		EnrolledAt:     time.Now(),
	}); err != nil {
		t.Fatalf("EnrollNode router: %v", err)
	}

	routerSTSResp := callSTS(routerPriv, routerPeerID, routerBiscuit, "sts.amazonaws.com")
	_ = routerSTSResp.Body.Close()
	if routerSTSResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when router calls /sts/token, got %d", routerSTSResp.StatusCode)
	}

	exTS := time.Now().UnixMilli()
	exSig, _ := routerPriv.Sign(api.TokenExchangeChallenge(routerPeerID.String(), exTS))
	exReqBytes, _ := proto.Marshal(&api.TokenExchangeRequest{
		SubjectToken:       mintOIDC(map[string]interface{}{"sub": "alice-sub"}),
		ChallengeUnixMs:    exTS,
		ChallengeSignature: exSig,
	})
	exReq, _ := http.NewRequest(http.MethodPost, baseURL+"/token/exchange", bytes.NewReader(exReqBytes))
	exReq.Header.Set("Content-Type", "application/x-protobuf")
	exReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(routerBiscuit))
	routerExResp, err := http.DefaultClient.Do(exReq)
	if err != nil {
		t.Fatalf("POST /token/exchange as router: %v", err)
	}
	_ = routerExResp.Body.Close()
	if routerExResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when router calls /token/exchange, got %d", routerExResp.StatusCode)
	}
}

func TestOAuthAndControlPlaneHardening(t *testing.T) {
	issuer, mintOIDC := startCustomMockOIDC(t)
	workloadIssuer, mintWorkload := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer, func(o *Options) {
		o.WorkloadIssuer = workloadIssuer
	})
	defer func() { _ = srv.Close() }()
	srv.config.AdminToken = "admin-secret"

	ctx := context.Background()
	roles := []*api.PolicyRole{
		{Name: api.RoleNode, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}},
	}
	bindings := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
	}
	if err := store.SavePolicyDocument(ctx, roles, bindings, nil); err != nil {
		t.Fatalf("SavePolicyDocument: %v", err)
	}

	// 1. Workload JWT on unauthenticated /oauth/token must be rejected with 403
	workloadJWT := mintWorkload(map[string]interface{}{"sub": "spiffe://cluster.local/ns/default/sa/agent"})
	exForm := url.Values{
		"grant_type":         {api.GrantTypeTokenExchange},
		"subject_token":      {workloadJWT},
		"subject_token_type": {api.TokenTypeIDToken},
	}
	wResp, err := http.PostForm(baseURL+"/oauth/token", exForm)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	_ = wResp.Body.Close()
	if wResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for workload JWT on unauthenticated /oauth/token, got %d", wResp.StatusCode)
	}

	// 2. GET /oauth/authorize?approve=true must NOT auto-approve on GET (renders consent form instead)
	aliceJWT := mintOIDC(map[string]interface{}{"sub": "alice-sub"})
	verifierHash := sha256.Sum256([]byte("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
	codeChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])
	getAuthReq, _ := http.NewRequest(http.MethodGet, baseURL+"/oauth/authorize?response_type=code&client_id=c1&code_challenge="+codeChallenge+"&code_challenge_method=S256&approve=true", nil)
	getAuthReq.Header.Set("Authorization", "Bearer "+aliceJWT)
	getAuthResp, err := http.DefaultClient.Do(getAuthReq)
	if err != nil {
		t.Fatalf("GET /oauth/authorize: %v", err)
	}
	getAuthBody, _ := io.ReadAll(getAuthResp.Body)
	_ = getAuthResp.Body.Close()
	if !strings.Contains(getAuthResp.Header.Get("Content-Type"), "text/html") || strings.Contains(string(getAuthBody), `"code":`) {
		t.Fatalf("expected GET /oauth/authorize?approve=true to render HTML form rather than issuing a code, got Content-Type=%s body=%s", getAuthResp.Header.Get("Content-Type"), string(getAuthBody))
	}

	// 3. POST /oauth/authorize with javascript: redirect_uri must be rejected with 400
	badRedirForm := url.Values{
		"response_type":         {"code"},
		"client_id":             {"c1"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"redirect_uri":          {"javascript:alert(1)"},
		"approve":               {"true"},
	}
	badRedirReq, _ := http.NewRequest(http.MethodPost, baseURL+"/oauth/authorize", strings.NewReader(badRedirForm.Encode()))
	badRedirReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRedirReq.Header.Set("Authorization", "Bearer "+aliceJWT)
	badRedirResp, err := http.DefaultClient.Do(badRedirReq)
	if err != nil {
		t.Fatalf("POST /oauth/authorize: %v", err)
	}
	_ = badRedirResp.Body.Close()
	if badRedirResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for javascript: redirect_uri, got %d", badRedirResp.StatusCode)
	}

	// 4. POST /policies with text/plain Content-Type must be rejected with 415
	polReq, _ := http.NewRequest(http.MethodPost, baseURL+"/policies", strings.NewReader(""))
	polReq.Header.Set("Content-Type", "text/plain")
	polReq.Header.Set("Authorization", "Bearer admin-secret")
	polResp, err := http.DefaultClient.Do(polReq)
	if err != nil {
		t.Fatalf("POST /policies: %v", err)
	}
	_ = polResp.Body.Close()
	if polResp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415 for text/plain POST /policies, got %d", polResp.StatusCode)
	}
}

// Expired revocations leave the in-memory set as writes accumulate, not only
// when /revocations is read, and the set stays bounded by its live entries.
func TestRevokeBiscuitIDPrunesExpiredEntries(t *testing.T) {
	srv, store, _ := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	for i := 0; i < 4*revokedPruneMin; i++ {
		srv.RevokeBiscuitID(fmt.Sprintf("expired-%d", i), time.Now().Add(-time.Minute))
	}
	srv.RevokeBiscuitID("live", time.Now().Add(time.Hour))

	srv.revokedBiscuitsMu.RLock()
	defer srv.revokedBiscuitsMu.RUnlock()
	if n := len(srv.revokedBiscuits); n > revokedPruneMin+1 {
		t.Errorf("revocation set holds %d entries after %d expired writes, want at most %d", n, 4*revokedPruneMin, revokedPruneMin+1)
	}
	if _, ok := srv.revokedBiscuits["live"]; !ok {
		t.Error("live revocation missing")
	}
}
