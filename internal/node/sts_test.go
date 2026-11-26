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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stsNodeHarness struct {
	node        *AgentMeshNode
	cpPub       ed25519.PublicKey
	cpPriv      ed25519.PrivateKey
	peerID      peer.ID
	nodeBiscuit []byte
	policyRoles []*api.PolicyRole
}

func newSTSNodeHarness(t *testing.T) *stsNodeHarness {
	t.Helper()
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pid, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.SaveMeshConfig(cpPub, nil); err != nil {
		t.Fatalf("SaveMeshConfig: %v", err)
	}

	policyRoles := []*api.PolicyRole{
		{
			Name:            "developer",
			AllowedServices: []string{"mcp://github", "inference://gemini-pro", "egress://api.github.com"},
			AllowedTargets:  []string{"*"},
		},
	}

	nodeBiscuit, _, err := identity.MintBiscuitToken(
		cpPriv,
		jwt.MapClaims{"sub": "alice", "email": "alice@example.com"},
		nil,
		pid,
		time.Now().Add(time.Hour),
		[]string{api.RoleNode, "developer"},
		policyRoles,
		nil,
	)
	if err != nil {
		t.Fatalf("MintBiscuitToken: %v", err)
	}
	if err := store.SaveIdentity(nodeBiscuit); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	n, err := NewAgentMeshNode(Options{
		PrivKey: privKey,
		Store:   store,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode: %v", err)
	}
	n.trustedKeys = []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}}
	n.SetIdentityCache(nodeBiscuit)
	n.MeshPolicyRules = []biscuit.Rule{}

	return &stsNodeHarness{
		node:        n,
		cpPub:       cpPub,
		cpPriv:      cpPriv,
		peerID:      pid,
		nodeBiscuit: nodeBiscuit,
		policyRoles: policyRoles,
	}
}

func TestNodeOAuthTokenAttenuationAndSeal(t *testing.T) {
	h := newSTSNodeHarness(t)
	sidecarToken := "secret-sidecar-token"

	// 1. Exchange subject_token Biscuit with RFC 8707 resource + scope narrowing.
	form := url.Values{}
	form.Set("grant_type", api.GrantTypeTokenExchange)
	form.Set("subject_token", base64.StdEncoding.EncodeToString(h.nodeBiscuit))
	form.Set("subject_token_type", api.TokenTypeBiscuit)
	form.Add("resource", "mcp://github")
	form.Set("scope", "tool:get_pr")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleNodeOAuthToken(h.node, sidecarToken, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if resp["issued_token_type"] != api.TokenTypeBiscuit {
		t.Fatalf("unexpected issued_token_type: %v", resp["issued_token_type"])
	}
	attenuatedB64, _ := resp["access_token"].(string)
	attenuatedBytes, err := base64.StdEncoding.DecodeString(attenuatedB64)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}

	// Verify narrowed Biscuit allows mcp://github get_pr, denies merge_pr and mcp://billing.
	allowCtx := RequestContext{
		PeerID:   h.peerID,
		Protocol: string(api.MCPProtocolID),
		Target:   "mcp://github",
		MCPTool:  "get_pr",
		Local:    true,
	}
	if err := h.node.VerifyBiscuitToken(attenuatedBytes, allowCtx); err != nil {
		t.Fatalf("expected get_pr to be allowed: %v", err)
	}
	denyToolCtx := allowCtx
	denyToolCtx.MCPTool = "merge_pr"
	if err := h.node.VerifyBiscuitToken(attenuatedBytes, denyToolCtx); err == nil {
		t.Fatalf("expected merge_pr to be denied by tar_block")
	}

	// 2. Attenuate node's own identity via sidecar token (subject_token omitted) and seal=true.
	tar := &api.TaskAuthorizationRule{
		Name: "sealed-task",
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"inference://gemini-pro"},
			},
		},
	}
	tarB64, err := api.EncodeTARBlockPayload(tar)
	if err != nil {
		t.Fatalf("EncodeTARBlockPayload: %v", err)
	}

	form2 := url.Values{}
	form2.Set("grant_type", api.GrantTypeTokenExchange)
	form2.Set("options", tarB64)
	form2.Set("seal", "true")

	req2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Bearer "+sidecarToken)
	rec2 := httptest.NewRecorder()
	handleNodeOAuthToken(h.node, sidecarToken, rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for sealed self-attenuation, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var resp2 map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	sealedBytes, _ := base64.StdEncoding.DecodeString(resp2["access_token"].(string))

	// Attempting to further attenuate a sealed Biscuit must fail.
	if _, err := identity.AttenuateBiscuit(sealedBytes, tar); err == nil {
		t.Fatalf("expected further attenuation of sealed biscuit to fail")
	}
}

func TestNodeOAuthRevokeAndSyncRevocations(t *testing.T) {
	h := newSTSNodeHarness(t)
	sidecarToken := "secret-sidecar-token"

	// Mint a separate task biscuit and attenuate a child from it.
	parentBiscuit, _, err := identity.MintBiscuitToken(
		h.cpPriv,
		jwt.MapClaims{"sub": "bob", "email": "bob@example.com"},
		nil,
		h.peerID,
		time.Now().Add(time.Hour),
		[]string{api.RoleNode, "developer"},
		h.policyRoles,
		nil,
	)
	if err != nil {
		t.Fatalf("MintBiscuitToken: %v", err)
	}
	childBiscuit, err := identity.AttenuateBiscuit(parentBiscuit, &api.TaskAuthorizationRule{
		Name: "child-task",
		Rules: []*api.TaskRule{
			{AllowedServices: []string{"mcp://github"}},
		},
	})
	if err != nil {
		t.Fatalf("AttenuateBiscuit: %v", err)
	}
	grandchildBiscuit, err := identity.AttenuateBiscuit(childBiscuit, &api.TaskAuthorizationRule{
		Name: "grandchild-task",
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"mcp://github"},
				Operation:       &api.TaskOperation{AllowedTools: []string{"get_pr"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("AttenuateBiscuit grandchild: %v", err)
	}

	// Revoke childBiscuit on POST /oauth/revoke: invalidates childBiscuit and
	// grandchildBiscuit while keeping parentBiscuit valid.
	form := url.Values{}
	form.Set("token", base64.StdEncoding.EncodeToString(childBiscuit))
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleNodeOAuthRevoke(h.node, sidecarToken, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /oauth/revoke, got %d: %s", rec.Code, rec.Body.String())
	}

	if _, err := h.node.VerifyLocalBiscuit(childBiscuit); err == nil {
		t.Fatalf("expected revoked child biscuit to fail VerifyLocalBiscuit")
	}
	if _, err := h.node.VerifyLocalBiscuit(grandchildBiscuit); err == nil {
		t.Fatalf("expected grandchild biscuit to also be revoked via child's RevocationId")
	}
	if _, err := h.node.VerifyLocalBiscuit(parentBiscuit); err != nil {
		t.Fatalf("expected parent biscuit to remain valid when only child task is revoked: %v", err)
	}

	// Revoking parentBiscuit invalidates parentBiscuit too.
	formParent := url.Values{}
	formParent.Set("token", base64.StdEncoding.EncodeToString(parentBiscuit))
	reqParent := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(formParent.Encode()))
	reqParent.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recParent := httptest.NewRecorder()
	handleNodeOAuthRevoke(h.node, sidecarToken, recParent, reqParent)
	if recParent.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /oauth/revoke for parent, got %d", recParent.Code)
	}
	if _, err := h.node.VerifyLocalBiscuit(parentBiscuit); err == nil {
		t.Fatalf("expected revoked parent biscuit to fail VerifyLocalBiscuit")
	}

	// Test syncRevocations pulling from Control Plane /revocations.
	thirdBiscuit, _, err := identity.MintBiscuitToken(
		h.cpPriv,
		jwt.MapClaims{"sub": "carol", "email": "carol@example.com"},
		nil,
		h.peerID,
		time.Now().Add(time.Hour),
		[]string{api.RoleNode, "developer"},
		h.policyRoles,
		nil,
	)
	if err != nil {
		t.Fatalf("MintBiscuitToken: %v", err)
	}
	parsedThird, _, err := identity.UnmarshalInbound(thirdBiscuit)
	if err != nil {
		t.Fatalf("UnmarshalInbound: %v", err)
	}
	revIDHex := hex.EncodeToString(parsedThird.RevocationIds()[0])

	// A plaintext loopback control plane passes ValidateControlPlaneTransport,
	// so the node's own client reaches cpServer without touching
	// http.DefaultTransport, which every other test's background request
	// also reads.
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/revocations" {
			http.NotFound(w, r)
			return
		}
		payload, _ := proto.Marshal(&api.RevocationsResponse{
			RevocationIds: []string{revIDHex},
		})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(payload)
	}))
	defer cpServer.Close()

	if err := h.node.syncRevocations(context.Background(), cpServer.URL); err != nil {
		t.Fatalf("syncRevocations: %v", err)
	}
	if _, err := h.node.VerifyLocalBiscuit(thirdBiscuit); err == nil {
		t.Fatalf("expected thirdBiscuit to be rejected after syncRevocations")
	}
}

func TestWithCallerOrTokenAuthAndJWTExchange(t *testing.T) {
	h := newSTSNodeHarness(t)
	sidecarToken := "secret-sidecar-token"

	delegatedBiscuit, err := identity.MintDelegatedBiscuitToken(
		h.cpPriv,
		jwt.MapClaims{"sub": "k8s-sa-payments", "email": "payments@cluster.local"},
		h.peerID,
		time.Now().Add(5*time.Minute),
		[]string{"developer"},
		h.policyRoles,
		nil,
		false,
	)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken: %v", err)
	}

	var exchangeCalls atomic.Int32
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token/exchange" {
			exchangeCalls.Add(1)
			payload, _ := proto.Marshal(&api.TokenExchangeResponse{
				BiscuitToken: delegatedBiscuit,
				ExpireTime:   timestamppb.New(time.Now().Add(5 * time.Minute)),
				Roles:        []string{"developer"},
				Subject:      "k8s-sa-payments",
			})
			w.Header().Set("Content-Type", "application/x-protobuf")
			_, _ = w.Write(payload)
			return
		}
		http.NotFound(w, r)
	}))
	defer cpServer.Close()

	if err := h.node.Store.SaveControlPlaneURL(cpServer.URL); err != nil {
		t.Fatalf("SaveControlPlaneURL: %v", err)
	}

	var capturedIdentity []byte
	handler := withCallerOrTokenAuth(h.node, sidecarToken, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIdentity = h.node.GetRequestIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Static sidecar token uses node's standing identity.
	req1 := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req1.Header.Set("Authorization", "Bearer "+sidecarToken)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK || !bytes.Equal(capturedIdentity, h.nodeBiscuit) {
		t.Fatalf("expected 200 OK with nodeBiscuit, got %d", rec1.Code)
	}

	// 2. Narrowed Task Biscuit in Authorization header overrides request identity.
	narrowed, err := identity.AttenuateBiscuit(h.nodeBiscuit, &api.TaskAuthorizationRule{
		Name:  "narrow-task",
		Rules: []*api.TaskRule{{AllowedServices: []string{"mcp://github"}}},
	})
	if err != nil {
		t.Fatalf("AttenuateBiscuit: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req2.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(narrowed))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || !bytes.Equal(capturedIdentity, narrowed) {
		t.Fatalf("expected 200 OK with narrowed task biscuit, got %d", rec2.Code)
	}

	// 3. External JWT in Authorization header triggers transparent /token/exchange and caches result.
	fakeJWTHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	fakeJWTPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"k8s-sa-payments"}`))
	fakeJWTSig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	fakeJWT := fakeJWTHeader + "." + fakeJWTPayload + "." + fakeJWTSig

	for i := range 2 {
		reqJWT := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		reqJWT.Header.Set("Authorization", "Bearer "+fakeJWT)
		recJWT := httptest.NewRecorder()
		handler.ServeHTTP(recJWT, reqJWT)
		if recJWT.Code != http.StatusOK || !bytes.Equal(capturedIdentity, delegatedBiscuit) {
			t.Fatalf("attempt %d: expected 200 OK with delegatedBiscuit, got %d", i+1, recJWT.Code)
		}
	}
	if got := exchangeCalls.Load(); got != 1 {
		t.Fatalf("expected second JWT call to hit LRU cache (1 control plane call), got %d", got)
	}
}

// startFakeExchangeControlPlane serves POST /token/exchange for h.node,
// answering every subject JWT with delegated, attenuated and sealed as the
// request asks, the way the real control plane does.
func startFakeExchangeControlPlane(t *testing.T, h *stsNodeHarness, delegated []byte) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	cpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token/exchange" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req api.TokenExchangeRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out := delegated
		if req.GetTaskRule() != nil {
			var err error
			if out, err = identity.AttenuateBiscuit(out, req.GetTaskRule()); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if req.GetSeal() {
			var err error
			if out, err = identity.SealBiscuit(out); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		payload, _ := proto.Marshal(&api.TokenExchangeResponse{
			BiscuitToken: out,
			ExpireTime:   timestamppb.New(time.Now().Add(5 * time.Minute)),
			Roles:        []string{"developer"},
			Subject:      "spiffe://openshell.example/sandbox/sbx-1",
		})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(payload)
	}))
	t.Cleanup(cpServer.Close)
	if err := h.node.Store.SaveControlPlaneURL(cpServer.URL); err != nil {
		t.Fatalf("SaveControlPlaneURL: %v", err)
	}
	return &calls
}

// postNodeOAuthToken posts form to the node token endpoint over TCP (no local
// socket, no sidecar header) and returns the status and decoded JSON body.
func postNodeOAuthToken(t *testing.T, h *stsNodeHarness, sidecarToken string, form url.Values) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleNodeOAuthToken(h.node, sidecarToken, rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return rec.Code, body
}

func decodeIssuedBiscuit(t *testing.T, body map[string]any) []byte {
	t.Helper()
	if body["issued_token_type"] != api.TokenTypeBiscuit {
		t.Fatalf("issued_token_type = %v, want biscuit", body["issued_token_type"])
	}
	raw, err := base64.StdEncoding.DecodeString(body["access_token"].(string))
	if err != nil {
		t.Fatalf("access_token is not base64: %v", err)
	}
	return raw
}

// TestNodeOAuthTokenClientAssertionGrants covers the RFC 7523 shapes an OAuth
// client such as an OpenShell token grant or an identity-chaining caller sends
// to /oauth/token, alongside the RFC 8693 exchange the node already served.
func TestNodeOAuthTokenClientAssertionGrants(t *testing.T) {
	h := newSTSNodeHarness(t)
	sidecarToken := "secret-sidecar-token"

	delegated, err := identity.MintDelegatedBiscuitToken(
		h.cpPriv,
		jwt.MapClaims{"sub": "spiffe://openshell.example/sandbox/sbx-1"},
		h.peerID,
		time.Now().Add(5*time.Minute),
		[]string{"developer"},
		h.policyRoles,
		nil,
		false,
	)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken: %v", err)
	}
	exchangeCalls := startFakeExchangeControlPlane(t, h, delegated)

	// A SPIFFE JWT-SVID as the Workload API would hand it out: the fake control
	// plane does not check the signature, the real one does.
	svid := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT","kid":"k1"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"spiffe://openshell.example/sandbox/sbx-1","aud":["agentmesh-audience"]}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte("sig"))

	getPR := RequestContext{PeerID: h.peerID, Protocol: string(api.MCPProtocolID), Target: "mcp://github", MCPTool: "get_pr", Local: true}
	mergePR := getPR
	mergePR.MCPTool = "merge_pr"
	gemini := RequestContext{PeerID: h.peerID, Target: "inference://gemini-pro", Local: true}

	t.Run("client_credentials with jwt-spiffe assertion issues the delegated biscuit", func(t *testing.T) {
		exchangeCalls.Store(0)
		form := url.Values{}
		form.Set("grant_type", api.GrantTypeClientCredentials)
		form.Set("client_assertion_type", api.ClientAssertionTypeJWTSPIFFE)
		form.Set("client_assertion", svid)
		for i := range 2 {
			code, body := postNodeOAuthToken(t, h, sidecarToken, form)
			if code != http.StatusOK {
				t.Fatalf("attempt %d: status %d: %v", i+1, code, body)
			}
			if !bytes.Equal(decodeIssuedBiscuit(t, body), delegated) {
				t.Fatalf("attempt %d: access_token is not the delegated biscuit", i+1)
			}
			if body["token_type"] != "Bearer" {
				t.Fatalf("token_type = %v", body["token_type"])
			}
		}
		if got := exchangeCalls.Load(); got != 1 {
			t.Fatalf("unattenuated assertion grants should share the exchange cache, got %d control plane calls", got)
		}
	})

	t.Run("client_credentials with jwt-bearer assertion honours scope, resource and seal", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", api.GrantTypeClientCredentials)
		form.Set("client_assertion_type", api.ClientAssertionTypeJWTBearer)
		form.Set("client_assertion", svid)
		form.Add("resource", "mcp://github")
		form.Set("scope", "tool:get_pr")
		form.Set("seal", "true")
		code, body := postNodeOAuthToken(t, h, sidecarToken, form)
		if code != http.StatusOK {
			t.Fatalf("status %d: %v", code, body)
		}
		issued := decodeIssuedBiscuit(t, body)
		if err := h.node.VerifyBiscuitToken(issued, getPR); err != nil {
			t.Fatalf("get_pr on mcp://github should be allowed: %v", err)
		}
		if err := h.node.VerifyBiscuitToken(issued, mergePR); err == nil {
			t.Fatalf("merge_pr should be denied by the scope")
		}
		if err := h.node.VerifyBiscuitToken(issued, gemini); err == nil {
			t.Fatalf("inference://gemini-pro should be denied by the resource")
		}
		if _, err := identity.AttenuateBiscuit(issued, &api.TaskAuthorizationRule{Name: "x"}); err == nil {
			t.Fatalf("sealed biscuit must not accept further blocks")
		}
	})

	t.Run("jwt-bearer authorization grant issues the delegated biscuit", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", api.GrantTypeJWTBearer)
		form.Set("assertion", svid)
		code, body := postNodeOAuthToken(t, h, sidecarToken, form)
		if code != http.StatusOK {
			t.Fatalf("status %d: %v", code, body)
		}
		if !bytes.Equal(decodeIssuedBiscuit(t, body), delegated) {
			t.Fatalf("access_token is not the delegated biscuit")
		}
	})

	t.Run("token exchange without subject_token narrows the client assertion's own identity", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", api.GrantTypeTokenExchange)
		form.Set("client_assertion_type", api.ClientAssertionTypeJWTSPIFFE)
		form.Set("client_assertion", svid)
		form.Add("resource", "inference://gemini-pro")
		code, body := postNodeOAuthToken(t, h, sidecarToken, form)
		if code != http.StatusOK {
			t.Fatalf("status %d: %v", code, body)
		}
		issued := decodeIssuedBiscuit(t, body)
		if err := h.node.VerifyBiscuitToken(issued, gemini); err != nil {
			t.Fatalf("inference://gemini-pro should be allowed: %v", err)
		}
		if err := h.node.VerifyBiscuitToken(issued, getPR); err == nil {
			t.Fatalf("mcp://github should be denied by the resource")
		}
	})

	rejected := []struct {
		name   string
		form   url.Values
		status int
		code   string
	}{
		{
			name:   "client_credentials without assertion",
			form:   url.Values{"grant_type": {api.GrantTypeClientCredentials}},
			status: http.StatusUnauthorized,
			code:   "invalid_client",
		},
		{
			name: "client_credentials with unsupported assertion type",
			form: url.Values{
				"grant_type":            {api.GrantTypeClientCredentials},
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:saml2-bearer"},
				"client_assertion":      {svid},
			},
			status: http.StatusUnauthorized,
			code:   "invalid_client",
		},
		{
			name: "client_credentials with assertion that is not a JWT",
			form: url.Values{
				"grant_type":            {api.GrantTypeClientCredentials},
				"client_assertion_type": {api.ClientAssertionTypeJWTSPIFFE},
				"client_assertion":      {sidecarToken},
			},
			status: http.StatusUnauthorized,
			code:   "invalid_client",
		},
		{
			name: "client_assertion without client_assertion_type",
			form: url.Values{
				"grant_type":       {api.GrantTypeClientCredentials},
				"client_assertion": {svid},
			},
			status: http.StatusUnauthorized,
			code:   "invalid_client",
		},
		{
			name: "client_assertion_type without client_assertion",
			form: url.Values{
				"grant_type":            {api.GrantTypeClientCredentials},
				"client_assertion_type": {api.ClientAssertionTypeJWTSPIFFE},
			},
			status: http.StatusUnauthorized,
			code:   "invalid_client",
		},
		{
			name:   "jwt-bearer without assertion",
			form:   url.Values{"grant_type": {api.GrantTypeJWTBearer}},
			status: http.StatusBadRequest,
			code:   "invalid_grant",
		},
		{
			name:   "unknown grant type",
			form:   url.Values{"grant_type": {"password"}},
			status: http.StatusBadRequest,
			code:   "unsupported_grant_type",
		},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			before := exchangeCalls.Load()
			code, body := postNodeOAuthToken(t, h, sidecarToken, tc.form)
			if code != tc.status || body["error"] != tc.code {
				t.Fatalf("status %d error %v, want %d %s (%v)", code, body["error"], tc.status, tc.code, body["error_description"])
			}
			if exchangeCalls.Load() != before {
				t.Fatalf("a rejected request must not reach the control plane")
			}
		})
	}

	t.Run("authorization server metadata advertises the grants and spiffe_jwt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		req.Host = "node.example:8080"
		rec := httptest.NewRecorder()
		handleOAuthAuthorizationServer(h.node, rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var meta api.OAuthAuthorizationServerMetadata
		if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
			t.Fatalf("json: %v", err)
		}
		if meta.Issuer != "http://node.example:8080" || meta.TokenEndpoint != "http://node.example:8080/oauth/token" {
			t.Fatalf("issuer/token_endpoint = %q / %q", meta.Issuer, meta.TokenEndpoint)
		}
		for _, want := range []string{api.GrantTypeTokenExchange, api.GrantTypeClientCredentials, api.GrantTypeJWTBearer} {
			if !slices.Contains(meta.GrantTypesSupported, want) {
				t.Fatalf("grant_types_supported %v lacks %s", meta.GrantTypesSupported, want)
			}
		}
		if !slices.Contains(meta.TokenEndpointAuthMethodsSupported, "spiffe_jwt") || !slices.Contains(meta.TokenEndpointAuthMethodsSupported, "private_key_jwt") {
			t.Fatalf("token_endpoint_auth_methods_supported = %v", meta.TokenEndpointAuthMethodsSupported)
		}
		if !strings.Contains(rec.Body.String(), `"response_types_supported":[]`) {
			t.Fatalf("response_types_supported must be an empty array, not null: %s", rec.Body.String())
		}
	})
}

func TestExtAuthzHTTPAndGRPC(t *testing.T) {
	h := newSTSNodeHarness(t)

	narrowed, err := identity.AttenuateBiscuit(h.nodeBiscuit, &api.TaskAuthorizationRule{
		Name: "pr-review-task",
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"mcp://github"},
				Operation: &api.TaskOperation{
					AllowedTools: []string{"get_pr"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("AttenuateBiscuit: %v", err)
	}
	narrowedB64 := base64.StdEncoding.EncodeToString(narrowed)

	// 1. HTTP ext_authz allow: mcp://github + tool get_pr
	reqAllow := httptest.NewRequest(http.MethodPost, "/ext_authz/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pr"}}`))
	reqAllow.Header.Set("Authorization", "Bearer "+narrowedB64)
	recAllow := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, recAllow, reqAllow)
	if recAllow.Code != http.StatusOK {
		t.Fatalf("expected HTTP ext_authz 200 OK, got %d: %s", recAllow.Code, recAllow.Body.String())
	}
	if recAllow.Header().Get(api.HeaderMeshPrincipal) != "alice@example.com" {
		t.Fatalf("unexpected X-Mesh-Principal: %q", recAllow.Header().Get(api.HeaderMeshPrincipal))
	}
	if !strings.Contains(recAllow.Header().Get(api.HeaderMeshTask), "pr-review-task") {
		t.Fatalf("expected X-Mesh-Task to contain pr-review-task, got %q", recAllow.Header().Get(api.HeaderMeshTask))
	}

	// 2. HTTP ext_authz deny: mcp://github + tool merge_pr
	reqDeny := httptest.NewRequest(http.MethodPost, "/ext_authz/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"merge_pr"}}`))
	reqDeny.Header.Set("Authorization", "Bearer "+narrowedB64)
	recDeny := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, recDeny, reqDeny)
	if recDeny.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP ext_authz 403 Forbidden for merge_pr, got %d", recDeny.Code)
	}

	// 2b. HTTP ext_authz deny when target service cannot be resolved (must not skip VerifyBiscuitToken).
	reqNoTarget := httptest.NewRequest(http.MethodPost, "/ext_authz/unknown/route", nil)
	reqNoTarget.Header.Set("Authorization", "Bearer "+narrowedB64)
	recNoTarget := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, recNoTarget, reqNoTarget)
	if recNoTarget.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP ext_authz 403 Forbidden when target cannot be resolved, got %d: %s", recNoTarget.Code, recNoTarget.Body.String())
	}

	// 2c. HTTP ext_authz deny when X-Mesh-Target-Service is malformed.
	reqBadTarget := httptest.NewRequest(http.MethodPost, "/ext_authz", nil)
	reqBadTarget.Header.Set("Authorization", "Bearer "+narrowedB64)
	reqBadTarget.Header.Set(api.HeaderMeshTargetService, "not-a-valid-scheme")
	recBadTarget := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, recBadTarget, reqBadTarget)
	if recBadTarget.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP ext_authz 403 Forbidden for malformed X-Mesh-Target-Service, got %d: %s", recBadTarget.Code, recBadTarget.Body.String())
	}

	// 3. gRPC ext_authz Check (/envoy.service.auth.v3.Authorization/Check). The tool is in the body,
	// so a check with no body for a POST cannot name it: a credential with allowed_tools is refused.
	// A GET opens a stream and carries no call, so it is decided for the service alone.
	for _, tc := range []struct {
		name, method, body string
		wantCode           codes.Code
	}{
		{name: "POST with the allowed tool in the body", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pr"}}`, wantCode: codes.OK},
		{name: "POST with no body", method: "POST", wantCode: codes.PermissionDenied},
		{name: "GET with no body", method: "GET", wantCode: codes.OK},
	} {
		grpcResp, err := newNodeEnvoyGateway(h.node).Check(context.Background(), &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: tc.method,
						Path:   "/mcp/github",
						Body:   tc.body,
						Headers: map[string]string{
							"authorization": "Bearer " + narrowedB64,
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("%s: Check: %v", tc.name, err)
		}
		if got := codes.Code(grpcResp.GetStatus().GetCode()); got != tc.wantCode {
			t.Fatalf("%s: gRPC CheckResponse status code %v, want %v", tc.name, got, tc.wantCode)
		}
	}
}

// An application on the same host can reach the ext_authz routes. Only a
// caller that the transport authenticates as the gateway gets the upstream
// credential of an egress destination (GHSA-2g97-3v45-p9f4).
func TestExtAuthzUpstreamCredentialNeedsTrustedTransport(t *testing.T) {
	const secret = "ghp_secret_of_the_node"
	secrets := t.TempDir()
	if err := os.WriteFile(filepath.Join(secrets, "github-ro"), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write the credential file: %v", err)
	}

	plainTCP := func(r *http.Request) *http.Request { return r }
	unixSocket := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), localSocketContextKey{}, true))
	}
	tlsWith := func(state tls.ConnectionState) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			r.TLS = &state
			return r
		}
	}
	tlsNoClientCert := tlsWith(tls.ConnectionState{})
	verifiedClientCert := tlsWith(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}})

	tests := []struct {
		name       string
		credential string
		target     string
		tool       string
		transport  func(*http.Request) *http.Request
		wantStatus int
		wantAuth   string
	}{
		{name: "plain TCP", credential: "github-ro", target: "egress://api.github.com", transport: plainTCP, wantStatus: http.StatusForbidden},
		{name: "TLS without a client certificate", credential: "github-ro", target: "egress://api.github.com", transport: tlsNoClientCert, wantStatus: http.StatusForbidden},
		{name: "Unix socket", credential: "github-ro", target: "egress://api.github.com", transport: unixSocket, wantStatus: http.StatusOK, wantAuth: "Bearer " + secret},
		{name: "verified client certificate", credential: "github-ro", target: "egress://api.github.com", transport: verifiedClientCert, wantStatus: http.StatusOK, wantAuth: "Bearer " + secret},
		{name: "plain TCP, destination without a credential", target: "egress://api.github.com", transport: plainTCP, wantStatus: http.StatusOK},
		{name: "plain TCP, MCP service", credential: "github-ro", target: "mcp://github", tool: "get_pr", transport: plainTCP, wantStatus: http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSTSNodeHarness(t)
			h.node.services = NewServiceRegistry(&fakeDHT{}, 0)
			svc, err := newEgressServiceForNode(h.node, &api.EgressDestination{
				Name:       "api.github.com",
				TargetUrl:  "https://api.github.com",
				Credential: tc.credential,
			}, secrets)
			if err != nil {
				t.Fatalf("newEgressServiceForNode: %v", err)
			}
			t.Cleanup(func() { _ = svc.Teardown() })
			if err := h.node.services.Register(context.Background(), svc); err != nil {
				t.Fatalf("Register egress: %v", err)
			}
			task, err := identity.AttenuateBiscuit(h.nodeBiscuit, &api.TaskAuthorizationRule{
				Name: "read-acme-repos",
				Rules: []*api.TaskRule{
					{
						AllowedServices: []string{"egress://api.github.com"},
						Operation:       &api.TaskOperation{AllowedMethods: []string{"GET"}, AllowedPaths: []string{"/repos/acme/*"}},
					},
					{
						AllowedServices: []string{"mcp://github"},
						Operation:       &api.TaskOperation{AllowedTools: []string{"get_pr"}},
					},
				},
			})
			if err != nil {
				t.Fatalf("AttenuateBiscuit: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/ext_authz/repos/acme/x", nil)
			if tc.tool != "" {
				// The body names the tool of an MCP call.
				body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tc.tool + `"}}`
				req = httptest.NewRequest(http.MethodPost, "/ext_authz/repos/acme/x", strings.NewReader(body))
			}
			req.Header.Set(api.HeaderMeshTargetService, tc.target)
			req.Header.Set(api.HeaderMeshBiscuit, base64.StdEncoding.EncodeToString(task))
			rec := httptest.NewRecorder()
			handleExtAuthzHTTP(h.node, rec, tc.transport(req))

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := rec.Header().Get("Authorization"); got != tc.wantAuth {
				t.Errorf("Authorization in the answer = %q, want %q", got, tc.wantAuth)
			}
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("body %q carries the upstream credential", rec.Body.String())
			}
			if tc.wantStatus == http.StatusForbidden && !strings.Contains(rec.Body.String(), "Unix socket") {
				t.Errorf("body = %q, want it to name the Unix socket and the client certificate", rec.Body.String())
			}
		})
	}
}

func TestInspectMCPHTTPRequestBody(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mcp://github/get_pr"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/github", strings.NewReader(body))
	tool, allowInit, err := inspectMCPHTTPRequestBody(req)
	if err != nil {
		t.Fatalf("inspectMCPHTTPRequestBody: %v", err)
	}
	if tool != "get_pr" || allowInit {
		t.Fatalf("got tool=%q allowInit=%v, want tool=\"get_pr\" allowInit=false", tool, allowInit)
	}
	restored, _ := io.ReadAll(req.Body)
	if string(restored) != body {
		t.Fatalf("body was not restored: got %q, want %q", string(restored), body)
	}

	initReq := httptest.NewRequest(http.MethodPost, "/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	tool, allowInit, err = inspectMCPHTTPRequestBody(initReq)
	if err != nil || tool != "" || !allowInit {
		t.Fatalf("initialize: got tool=%q allowInit=%v err=%v, want allowInit=true", tool, allowInit, err)
	}

	notifReq := httptest.NewRequest(http.MethodPost, "/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	tool, allowInit, err = inspectMCPHTTPRequestBody(notifReq)
	if err != nil || tool != "" || !allowInit {
		t.Fatalf("notifications/initialized: got tool=%q allowInit=%v err=%v, want allowInit=true", tool, allowInit, err)
	}

	discoverReq := httptest.NewRequest(http.MethodPost, "/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"server/discover"}`))
	tool, allowInit, err = inspectMCPHTTPRequestBody(discoverReq)
	if err != nil || tool != "" || !allowInit {
		t.Fatalf("server/discover: got tool=%q allowInit=%v err=%v, want allowInit=true", tool, allowInit, err)
	}

	sseReq := httptest.NewRequest(http.MethodGet, "/mcp/github", nil)
	tool, allowInit, err = inspectMCPHTTPRequestBody(sseReq)
	if err != nil || tool != "" || !allowInit {
		t.Fatalf("GET SSE stream: got tool=%q allowInit=%v err=%v, want allowInit=true", tool, allowInit, err)
	}

	unknownReq := httptest.NewRequest(http.MethodPost, "/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"resources/read"}`))
	tool, allowInit, err = inspectMCPHTTPRequestBody(unknownReq)
	if err != nil || tool != "" || allowInit {
		t.Fatalf("resources/read: got tool=%q allowInit=%v err=%v, want allowInit=false", tool, allowInit, err)
	}
}

func TestCrossNodeBiscuitAndBannedPeerRejection(t *testing.T) {
	h := newSTSNodeHarness(t)

	otherPriv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPID, err := peer.IDFromPrivateKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	foreignBiscuit, _, err := identity.MintBiscuitToken(
		h.cpPriv,
		jwt.MapClaims{"sub": "mallory", "email": "mallory@example.com"},
		nil,
		otherPID,
		time.Now().Add(time.Hour),
		[]string{api.RoleNode, "developer"},
		h.policyRoles,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	foreignB64 := base64.StdEncoding.EncodeToString(foreignBiscuit)

	// 1. Foreign node's Biscuit must be rejected as a subject_token on /oauth/token.
	form := url.Values{}
	form.Set("grant_type", api.GrantTypeTokenExchange)
	form.Set("subject_token", foreignB64)
	form.Set("subject_token_type", api.TokenTypeBiscuit)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer secret-sidecar-token")
	rec := httptest.NewRecorder()
	handleNodeOAuthToken(h.node, "secret-sidecar-token", rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("expected /oauth/token to reject foreign node Biscuit")
	}

	// 2. Foreign node's Biscuit must be rejected on ext_authz even if X-Mesh-Peer-Id is spoofed.
	authzReq := httptest.NewRequest(http.MethodGet, "/ext_authz/mesh/mcp/github", nil)
	authzReq.Header.Set("Authorization", "Bearer "+foreignB64)
	authzReq.Header.Set("X-Mesh-Peer-Id", otherPID.String())
	authzRec := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, authzRec, authzReq)
	if authzRec.Code != http.StatusForbidden {
		t.Fatalf("expected ext_authz to reject foreign Biscuit with spoofed X-Mesh-Peer-Id, got %d", authzRec.Code)
	}

	// 3. Banning the local peer in revokedPeers causes VerifyLocalBiscuit and ext_authz to reject.
	h.node.revokedPeers.Add(h.peerID.String(), time.Now().Unix())
	defer h.node.revokedPeers.Remove(h.peerID.String())

	if _, err := h.node.VerifyLocalBiscuit(h.nodeBiscuit); err == nil {
		t.Fatal("expected VerifyLocalBiscuit to reject banned peer")
	}
	localAuthzReq := httptest.NewRequest(http.MethodGet, "/ext_authz/mesh/mcp/github", nil)
	localAuthzReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(h.nodeBiscuit))
	localAuthzRec := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, localAuthzRec, localAuthzReq)
	if localAuthzRec.Code != http.StatusForbidden {
		t.Fatalf("expected ext_authz to reject banned peer, got %d", localAuthzRec.Code)
	}
}

// Datalog reads an expiration before 1970 as a far future date, so the Datalog
// expiration check passes. The enforcement point must also check the
// expiration in Go, or the Biscuit does not lapse (GHSA-qg99-6frq-2h5m).
func TestVerifyBiscuitTokenRefusesExpirationBeforeEpoch(t *testing.T) {
	h := newSTSNodeHarness(t)
	reqCtx := RequestContext{PeerID: h.peerID, Protocol: string(api.MCPProtocolID), Target: "mcp://github", MCPTool: "get_pr", Local: true}

	// A delegated Biscuit as the control plane mints it. The builder is used
	// directly because the mint refuses an expiration before 1970.
	build := func(t *testing.T, expiry time.Time) []byte {
		t.Helper()
		facts := []biscuit.Fact{
			{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(expiry)}}},
			{Predicate: biscuit.Predicate{Name: api.FactActorNode, IDs: []biscuit.Term{biscuit.String(h.peerID.String())}}},
			{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(h.peerID.String())}}},
			{Predicate: biscuit.Predicate{Name: api.FactUser, IDs: []biscuit.Term{biscuit.String("alice")}}},
		}
		facts = append(facts, api.BuildServiceDatalogFacts([]string{"mcp://github"})...)
		builder := biscuit.NewBuilder(h.cpPriv)
		for _, f := range facts {
			if err := builder.AddAuthorityFact(f); err != nil {
				t.Fatalf("AddAuthorityFact(%s): %v", f, err)
			}
		}
		token, err := builder.Build()
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		raw, err := token.Serialize()
		if err != nil {
			t.Fatalf("Serialize: %v", err)
		}
		return raw
	}

	for _, tc := range []struct {
		name      string
		expiry    time.Time
		wantAdmit bool
	}{
		{name: "valid for five minutes", expiry: time.Now().Add(5 * time.Minute), wantAdmit: true},
		{name: "before 1970", expiry: time.Date(1734, time.August, 16, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := h.node.VerifyBiscuitToken(build(t, tc.expiry), reqCtx)
			if (err == nil) != tc.wantAdmit {
				t.Errorf("VerifyBiscuitToken(expiration %s) error = %v, want admitted = %v", tc.expiry.UTC().Format(time.RFC3339), err, tc.wantAdmit)
			}
		})
	}
}

func TestExtAuthzMCPBodyInspection(t *testing.T) {
	h := newSTSNodeHarness(t)
	tar := &api.TaskAuthorizationRule{
		Name: "tasks/get-pr-only",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"mcp://github"},
			Operation:       &api.TaskOperation{AllowedTools: []string{"get_pr"}},
		}},
	}
	taskBiscuit, err := identity.AttenuateBiscuit(h.nodeBiscuit, tar)
	if err != nil {
		t.Fatal(err)
	}
	b64Biscuit := base64.StdEncoding.EncodeToString(taskBiscuit)

	// 1. HTTP ext_authz with tools/call for disallowed tool "merge_pr" in JSON-RPC body -> 403.
	disallowedBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"merge_pr"}}`
	httpReq := httptest.NewRequest(http.MethodPost, "/ext_authz/mesh/mcp/github", strings.NewReader(disallowedBody))
	httpReq.Header.Set("Authorization", "Bearer "+b64Biscuit)
	httpRec := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, httpRec, httpReq)
	if httpRec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP ext_authz to reject disallowed MCP tool in body, got %d", httpRec.Code)
	}

	// 2. HTTP ext_authz with tools/call for allowed tool "get_pr" in JSON-RPC body -> 200.
	allowedBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pr"}}`
	httpReqOK := httptest.NewRequest(http.MethodPost, "/ext_authz/mesh/mcp/github", strings.NewReader(allowedBody))
	httpReqOK.Header.Set("Authorization", "Bearer "+b64Biscuit)
	httpRecOK := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, httpRecOK, httpReqOK)
	if httpRecOK.Code != http.StatusOK {
		t.Fatalf("expected HTTP ext_authz to allow get_pr tool in body, got %d", httpRecOK.Code)
	}

	// 3. A client can set any request header. An X-Mesh-Mcp-Tool header that names the allowed tool
	// does not replace the tool that the body calls ("merge_pr") -> 403.
	httpReqHeader := httptest.NewRequest(http.MethodPost, "/ext_authz/mesh/mcp/github", strings.NewReader(disallowedBody))
	httpReqHeader.Header.Set("Authorization", "Bearer "+b64Biscuit)
	httpReqHeader.Header.Set("X-Mesh-Mcp-Tool", "get_pr")
	httpRecHeader := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, httpRecHeader, httpReqHeader)
	if httpRecHeader.Code != http.StatusForbidden {
		t.Fatalf("HTTP ext_authz with a body that calls merge_pr and a client header that names get_pr: got status %d, want 403", httpRecHeader.Code)
	}
}

// A border JWT is a bearer credential for an egress destination: its holder
// can exchange it at the cloud provider. The node returns it only on a
// transport that authenticates the caller as the gateway. On any other
// transport it does not ask the control plane for one.
func TestNodeOAuthTokenBorderJWTNeedsTrustedTransport(t *testing.T) {
	h := newSTSNodeHarness(t)
	const borderJWT = "header.payload.signature"

	var mints atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sts/token" {
			http.NotFound(w, r)
			return
		}
		mints.Add(1)
		payload, err := proto.Marshal(&api.STSTokenResponse{Jwt: borderJWT, ExpireTime: timestamppb.New(time.Now().Add(5 * time.Minute))})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(payload)
	}))
	t.Cleanup(controlPlane.Close)
	if err := h.node.Store.SaveControlPlaneURL(controlPlane.URL); err != nil {
		t.Fatalf("SaveControlPlaneURL: %v", err)
	}

	plainTCP := func(r *http.Request) *http.Request { return r }
	unixSocket := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), localSocketContextKey{}, true))
	}
	tlsWith := func(state tls.ConnectionState) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			r.TLS = &state
			return r
		}
	}

	tests := []struct {
		name               string
		transport          func(*http.Request) *http.Request
		requestedTokenType string
		wantStatus         int
		wantIssued         string
	}{
		{name: "plain TCP", transport: plainTCP, requestedTokenType: api.TokenTypeJWT, wantStatus: http.StatusForbidden},
		{name: "TLS without a client certificate", transport: tlsWith(tls.ConnectionState{}), requestedTokenType: api.TokenTypeJWT, wantStatus: http.StatusForbidden},
		{name: "Unix socket", transport: unixSocket, requestedTokenType: api.TokenTypeJWT, wantStatus: http.StatusOK, wantIssued: api.TokenTypeJWT},
		{name: "verified client certificate", transport: tlsWith(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}), requestedTokenType: api.TokenTypeJWT, wantStatus: http.StatusOK, wantIssued: api.TokenTypeJWT},
		{name: "plain TCP, the caller asks for a Biscuit", transport: plainTCP, wantStatus: http.StatusOK, wantIssued: api.TokenTypeBiscuit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mintsBefore := mints.Load()
			form := url.Values{}
			form.Set("grant_type", api.GrantTypeTokenExchange)
			form.Set("subject_token", base64.StdEncoding.EncodeToString(h.nodeBiscuit))
			form.Set("subject_token_type", api.TokenTypeBiscuit)
			form.Add("resource", "egress://api.github.com")
			if tc.requestedTokenType != "" {
				form.Set("requested_token_type", tc.requestedTokenType)
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			handleNodeOAuthToken(h.node, "secret-sidecar-token", rec, tc.transport(req))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not JSON: %s", rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				if body["error"] != "access_denied" {
					t.Errorf("error %v, want access_denied", body["error"])
				}
				if strings.Contains(rec.Body.String(), borderJWT) {
					t.Errorf("the refusal carries the border JWT: %s", rec.Body.String())
				}
				if got := mints.Load() - mintsBefore; got != 0 {
					t.Errorf("the node asked the control plane for %d border JWT(s), want 0", got)
				}
				return
			}
			if body["issued_token_type"] != tc.wantIssued {
				t.Errorf("issued_token_type %v, want %s", body["issued_token_type"], tc.wantIssued)
			}
			if tc.wantIssued == api.TokenTypeJWT && body["access_token"] != borderJWT {
				t.Errorf("access_token %v, want the border JWT of the control plane", body["access_token"])
			}
		})
	}
}
