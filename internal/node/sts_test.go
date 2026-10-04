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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stsNodeHarness struct {
	node        *SamNode
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

	n, err := NewSamNode(Options{
		PrivKey: privKey,
		Store:   store,
	})
	if err != nil {
		t.Fatalf("NewSamNode: %v", err)
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

	cpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// Point controlPlaneClient at cpServer by temporarily swapping http.DefaultTransport.
	origTransport := http.DefaultTransport
	http.DefaultTransport = cpServer.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = origTransport })

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
	cpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	origTransport := http.DefaultTransport
	http.DefaultTransport = cpServer.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = origTransport })
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
	reqAllow := httptest.NewRequest(http.MethodPost, "/ext_authz/mcp/github", nil)
	reqAllow.Header.Set("Authorization", "Bearer "+narrowedB64)
	reqAllow.Header.Set(HeaderSamMCPTool, "get_pr")
	recAllow := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, recAllow, reqAllow)
	if recAllow.Code != http.StatusOK {
		t.Fatalf("expected HTTP ext_authz 200 OK, got %d: %s", recAllow.Code, recAllow.Body.String())
	}
	if recAllow.Header().Get(api.HeaderSamPrincipal) != "alice@example.com" {
		t.Fatalf("unexpected X-Sam-Principal: %q", recAllow.Header().Get(api.HeaderSamPrincipal))
	}
	if !strings.Contains(recAllow.Header().Get(api.HeaderSamTask), "pr-review-task") {
		t.Fatalf("expected X-Sam-Task to contain pr-review-task, got %q", recAllow.Header().Get(api.HeaderSamTask))
	}

	// 2. HTTP ext_authz deny: mcp://github + tool merge_pr
	reqDeny := httptest.NewRequest(http.MethodPost, "/ext_authz/mcp/github", nil)
	reqDeny.Header.Set("Authorization", "Bearer "+narrowedB64)
	reqDeny.Header.Set(HeaderSamMCPTool, "merge_pr")
	recDeny := httptest.NewRecorder()
	handleExtAuthzHTTP(h.node, recDeny, reqDeny)
	if recDeny.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP ext_authz 403 Forbidden for merge_pr, got %d", recDeny.Code)
	}

	// 3. gRPC ext_authz Check (/envoy.service.auth.v3.Authorization/Check)
	grpcReqPayload := buildEnvoyCheckRequestPayload("POST", "/mcp/github", map[string]string{
		"authorization":                   "Bearer " + narrowedB64,
		strings.ToLower(HeaderSamMCPTool): "get_pr",
	})
	var grpcBody bytes.Buffer
	_ = writeGRPCFrame(&grpcBody, grpcReqPayload)

	grpcReq := httptest.NewRequest(http.MethodPost, "/envoy.service.auth.v3.Authorization/Check", &grpcBody)
	grpcReq.Header.Set("Content-Type", "application/grpc")
	grpcRec := httptest.NewRecorder()
	handleExtAuthzGRPC(h.node, grpcRec, grpcReq)
	if grpcRec.Code != http.StatusOK {
		t.Fatalf("expected gRPC HTTP 200, got %d", grpcRec.Code)
	}
	respFrame, err := readGRPCFrame(grpcRec.Body)
	if err != nil {
		t.Fatalf("readGRPCFrame: %v", err)
	}
	// First field is status {code: 0}; field 3 is ok_response.
	num, typ, n := protowire.ConsumeTag(respFrame)
	if n < 0 || num != 1 || typ != protowire.BytesType {
		t.Fatalf("unexpected CheckResponse tag: num=%d typ=%d", num, typ)
	}
	statusBytes, m := protowire.ConsumeBytes(respFrame[n:])
	if m < 0 || len(statusBytes) < 2 || statusBytes[1] != 0 {
		t.Fatalf("expected gRPC CheckResponse status.code == 0 (OK), got %x", statusBytes)
	}
}

func buildEnvoyCheckRequestPayload(method, path string, headers map[string]string) []byte {
	var httpBytes []byte
	httpBytes = protowire.AppendTag(httpBytes, 2, protowire.BytesType)
	httpBytes = protowire.AppendString(httpBytes, method)
	for k, v := range headers {
		var entry []byte
		entry = protowire.AppendTag(entry, 1, protowire.BytesType)
		entry = protowire.AppendString(entry, k)
		entry = protowire.AppendTag(entry, 2, protowire.BytesType)
		entry = protowire.AppendString(entry, v)
		httpBytes = protowire.AppendTag(httpBytes, 3, protowire.BytesType)
		httpBytes = protowire.AppendBytes(httpBytes, entry)
	}
	httpBytes = protowire.AppendTag(httpBytes, 4, protowire.BytesType)
	httpBytes = protowire.AppendString(httpBytes, path)

	var reqBytes []byte
	reqBytes = protowire.AppendTag(reqBytes, 2, protowire.BytesType)
	reqBytes = protowire.AppendBytes(reqBytes, httpBytes)

	var attrBytes []byte
	attrBytes = protowire.AppendTag(attrBytes, 4, protowire.BytesType)
	attrBytes = protowire.AppendBytes(attrBytes, reqBytes)

	var checkReq []byte
	checkReq = protowire.AppendTag(checkReq, 1, protowire.BytesType)
	checkReq = protowire.AppendBytes(checkReq, attrBytes)
	return checkReq
}
