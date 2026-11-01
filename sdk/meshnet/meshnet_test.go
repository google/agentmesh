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

package meshnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

func TestAttenuateToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	t.Run("rejects_before_up_and_nil_rule", func(t *testing.T) {
		var unstarted Server
		if _, _, err := unstarted.AttenuateToken(&api.TaskAuthorizationRule{Name: "t1"}, time.Minute, false); err == nil {
			t.Fatal("AttenuateToken succeeded before Up, want error")
		}
		env := newStartedTestServer(t, ctx)
		if _, _, err := env.server.AttenuateToken(nil, time.Minute, false); err == nil {
			t.Fatal("AttenuateToken(nil) succeeded, want error")
		}
	})

	t.Run("attenuates_caps_ttl_and_seals", func(t *testing.T) {
		env := newStartedTestServer(t, ctx)
		rule := &api.TaskAuthorizationRule{
			Name:        "review-pr-42",
			DisplayName: "Review PR 42",
			Rules: []*api.TaskRule{
				{
					AllowedServices: []string{"a2a://coder"},
					Operation:       &api.TaskOperation{AllowedMethods: []string{"POST"}},
				},
			},
		}

		unsealedB64, exp, err := env.server.AttenuateToken(rule, 5*time.Minute, false)
		if err != nil {
			t.Fatalf("AttenuateToken(seal=false): %v", err)
		}
		if d := time.Until(exp); d <= 0 || d > 5*time.Minute+time.Second {
			t.Errorf("attenuated expiry delta = %v, want (0, 5m]", d)
		}
		rawUnsealed, err := base64.RawURLEncoding.DecodeString(unsealedB64)
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}
		rules, err := identity.ExtractTaskRules(rawUnsealed)
		if err != nil || len(rules) != 1 || rules[0].GetName() != "review-pr-42" {
			t.Fatalf("ExtractTaskRules = %v, err=%v; want [review-pr-42]", rules, err)
		}

		// A second attenuation succeeds on an unsealed token.
		if _, err := identity.AttenuateBiscuit(rawUnsealed, &api.TaskAuthorizationRule{
			Name:       "narrower",
			ExpireTime: rules[0].GetExpireTime(),
			Rules:      rules[0].GetRules(),
		}); err != nil {
			t.Fatalf("expected unsealed token to allow further attenuation: %v", err)
		}

		// With seal=true, downstream holders cannot append another block.
		sealedB64, _, err := env.server.AttenuateToken(rule, 5*time.Minute, true)
		if err != nil {
			t.Fatalf("AttenuateToken(seal=true): %v", err)
		}
		rawSealed, err := base64.RawURLEncoding.DecodeString(sealedB64)
		if err != nil {
			t.Fatalf("DecodeString(sealed): %v", err)
		}
		if _, err := identity.AttenuateBiscuit(rawSealed, &api.TaskAuthorizationRule{
			Name:       "forged-append",
			ExpireTime: rules[0].GetExpireTime(),
			Rules:      rules[0].GetRules(),
		}); err == nil {
			t.Fatal("AttenuateBiscuit succeeded on a sealed token, want error")
		}
	})
}

func TestAgentCardRelativizeAndRegenerate(t *testing.T) {
	peerID := "12D3KooWExamplePeer"
	privRoot := "/mesh/" + peerID + "/a2a/coder"
	pubRoot := "/ingress/" + peerID + "/a2a/coder"
	roots := []string{pubRoot, privRoot, ""}

	orig := &a2a.AgentCard{
		Name:        "coder",
		Description: "Laptop coder",
		Version:     "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{
			{URL: "https://bananas.sam-mesh.dev" + pubRoot + "/invoke?mode=fast", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
			{URL: "http://agentmesh.local" + privRoot, ProtocolBinding: a2a.TransportProtocolHTTPJSON, ProtocolVersion: "1.0"},
			{URL: "http://127.0.0.1:9090/v1/rpc", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
			{URL: "127.0.0.1:50051", ProtocolBinding: a2a.TransportProtocolGRPC, ProtocolVersion: "1.0"},
		},
		Signatures: []a2a.AgentCardSignature{{Protected: "hdr", Signature: "sig"}},
	}
	rawOrig, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	relBytes, err := relativizeAgentCardMultiRoot(rawOrig, roots)
	if err != nil {
		t.Fatalf("relativizeAgentCardMultiRoot: %v", err)
	}
	var relCard a2a.AgentCard
	if err := json.Unmarshal(relBytes, &relCard); err != nil {
		t.Fatalf("Unmarshal relativized card: %v", err)
	}
	if got := relCard.SupportedInterfaces[0].URL; got != "invoke?mode=fast" {
		t.Errorf("interface[0].URL = %q, want %q", got, "invoke?mode=fast")
	}
	if got := relCard.SupportedInterfaces[1].URL; got != "" {
		t.Errorf("interface[1].URL = %q, want empty relative root", got)
	}
	if got := relCard.SupportedInterfaces[2].URL; got != "v1/rpc" {
		t.Errorf("interface[2].URL = %q, want %q", got, "v1/rpc")
	}

	base := "http://agentmesh.local" + privRoot
	if err := regenerateAgentCardForMesh(&relCard, base); err != nil {
		t.Fatalf("regenerateAgentCardForMesh: %v", err)
	}
	if len(relCard.SupportedInterfaces) != 3 {
		t.Fatalf("len(SupportedInterfaces) = %d, want 3 (gRPC dropped)", len(relCard.SupportedInterfaces))
	}
	if got := relCard.SupportedInterfaces[0].URL; got != base+"/invoke?mode=fast" {
		t.Errorf("regenerated[0] = %q, want %q", got, base+"/invoke?mode=fast")
	}
	if got := relCard.SupportedInterfaces[1].URL; got != base {
		t.Errorf("regenerated[1] = %q, want %q", got, base)
	}
	if got := relCard.SupportedInterfaces[2].URL; got != base+"/v1/rpc" {
		t.Errorf("regenerated[2] = %q, want %q", got, base+"/v1/rpc")
	}
	if len(relCard.Signatures) != 0 {
		t.Errorf("Signatures = %v, want stripped", relCard.Signatures)
	}

	// Dot-segments (including backslash-separated segments) are never preserved.
	for _, bad := range []string{"../admin", "..\\admin"} {
		if got := meshInterfaceURL(base, bad); got != base {
			t.Errorf("meshInterfaceURL(%q) = %q, want %q", bad, got, base)
		}
	}

	etag := agentCardETag(relBytes)
	if !etagMatches(etag, etag) || !etagMatches("W/"+etag, etag) || !etagMatches("*", etag) {
		t.Errorf("etagMatches failed for %s", etag)
	}
	if etagMatches(`"other"`, etag) {
		t.Errorf("etagMatches matched unrelated tag")
	}

	inHdr := http.Header{
		"Authorization":    {"Bearer app-token"},
		"Cookie":           {"sid=secret"},
		"X-Mesh-Principal": {"spoofed"},
		api.HeaderPeerID:   {"spoofed-peer"},
	}
	sanitized := sanitizeOutboundMeshHeaders(inHdr, []byte("biscuit-bytes"))
	if sanitized.Get("Cookie") != "" || sanitized.Get("X-Mesh-Principal") != "" || sanitized.Get(api.HeaderPeerID) != "" {
		t.Errorf("sanitizeOutboundMeshHeaders leaked restricted headers: %v", sanitized)
	}
	if sanitized.Get("Authorization") != "Bearer app-token" {
		t.Errorf("Authorization header was dropped: %v", sanitized)
	}
	if sanitized.Get(api.HeaderMeshBiscuit) == "" {
		t.Error("X-Mesh-Biscuit not injected")
	}
}

func TestParseRequiredLabels(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		want    map[string]string
		wantErr bool
	}{
		{name: "empty", header: "", want: nil},
		{name: "whitespace", header: "   ", want: nil},
		{name: "valid_pair", header: "env=prod, region = us-central1", want: map[string]string{"env": "prod", "region": "us-central1"}},
		{name: "trailing_comma_tolerated", header: "env=prod,", want: map[string]string{"env": "prod"}},
		{name: "lone_commas_rejected", header: ",,", wantErr: true},
		{name: "missing_equals", header: "env-prod", wantErr: true},
		{name: "duplicate_key", header: "env=prod,env=staging", wantErr: true},
		{name: "invalid_key", header: "BAD KEY!=val", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRequiredLabels(tc.header)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseRequiredLabels(%q) = %v, want error", tc.header, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRequiredLabels(%q) unexpected error: %v", tc.header, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseRequiredLabels(%q) = %v, want %v", tc.header, got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("got[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestListenA2AWhoIsDiscoverAndHTTPClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mesh := newInProcessMeshPair(t, ctx)
	provider := mesh.provider
	caller := mesh.caller

	ep, err := provider.ListenA2A(ctx, A2AOptions{
		Name:        "coder",
		Description: "In-process coding agent",
	})
	if err != nil {
		t.Fatalf("ListenA2A: %v", err)
	}
	if ep.PublicURL != nil {
		t.Fatalf("PublicURL = %v, want nil when Public=false", ep.PublicURL)
	}

	var seenCaller CallerInfo
	var seenRemoteAddr string
	var callerMu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		card := &a2a.AgentCard{
			Name:        "coder",
			Description: "In-process coding agent",
			Version:     "1.0.0",
			SupportedInterfaces: []*a2a.AgentInterface{
				{URL: ep.PrivateURL.String() + "/invoke", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	})
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		info, ok := provider.WhoIs(r.RemoteAddr)
		if !ok || info == nil {
			http.Error(w, "missing WhoIs", http.StatusInternalServerError)
			return
		}
		// Mutate returned copy to verify WhoIs returns a defensive copy.
		if len(info.Roles) > 0 {
			info.Roles[0] = "mutated"
		}
		info.Labels["env"] = "mutated"

		fresh, ok := provider.WhoIs(r.RemoteAddr)
		if !ok {
			http.Error(w, "missing second WhoIs", http.StatusInternalServerError)
			return
		}
		callerMu.Lock()
		seenCaller = *fresh
		seenRemoteAddr = r.RemoteAddr
		callerMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ep.PrivateListener) }()
	t.Cleanup(func() {
		_ = httpSrv.Close()
		_ = ep.Close()
	})

	// 1. Targeted discovery & type-wide catalog discovery.
	byName, err := caller.Discover(ctx, api.ServiceType_SERVICE_TYPE_A2A, "coder")
	if err != nil {
		t.Fatalf("Discover(by name): %v", err)
	}
	if len(byName) != 1 || byName[0].GetLocalProxyUrl() != ep.PrivateURL.String() {
		t.Fatalf("Discover(by name) = %v, want [%s]", byName, ep.PrivateURL.String())
	}

	byType, err := caller.Discover(ctx, api.ServiceType_SERVICE_TYPE_A2A, "")
	if err != nil {
		t.Fatalf("Discover(by type): %v", err)
	}
	if len(byType) != 1 || byType[0].GetSrvDescription() != "In-process coding agent" {
		t.Fatalf("Discover(by type) = %v, want description 'In-process coding agent'", byType)
	}

	// 2. AgentCard fetch via caller.HTTPClient() rewrites URL & supports ETag/304.
	hc := caller.HTTPClient()
	cardResp, err := hc.Get(ep.PrivateURL.String() + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatalf("GET agent-card.json: %v", err)
	}
	cardBody, err := io.ReadAll(cardResp.Body)
	_ = cardResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(agent-card.json): %v", err)
	}
	if cardResp.StatusCode != http.StatusOK {
		t.Fatalf("agent-card status = %d: %s", cardResp.StatusCode, cardBody)
	}
	var gotCard a2a.AgentCard
	if err := json.Unmarshal(cardBody, &gotCard); err != nil {
		t.Fatalf("unmarshal card: %v", err)
	}
	if len(gotCard.SupportedInterfaces) != 1 || gotCard.SupportedInterfaces[0].URL != ep.PrivateURL.String()+"/invoke" {
		t.Fatalf("SupportedInterfaces = %+v, want %s/invoke", gotCard.SupportedInterfaces, ep.PrivateURL.String())
	}
	etag := cardResp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag header on regenerated AgentCard")
	}

	req304, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.PrivateURL.String()+"/.well-known/agent-card.json", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext(304): %v", err)
	}
	req304.Header.Set("If-None-Match", etag)
	resp304, err := hc.Do(req304)
	if err != nil {
		t.Fatalf("GET agent-card with If-None-Match: %v", err)
	}
	_ = resp304.Body.Close()
	if resp304.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match status = %d, want 304", resp304.StatusCode)
	}

	// 3. POST /invoke verifies WhoIs caller identity, defensive copy, and post-close cleanup.
	invReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.PrivateURL.String()+"/invoke", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext(invoke): %v", err)
	}
	invReq.Header.Set(api.HeaderMeshRequiredLabels, "env=prod")
	invResp, err := hc.Do(invReq)
	if err != nil {
		t.Fatalf("POST /invoke: %v", err)
	}
	_, readErr := io.ReadAll(invResp.Body)
	_ = invResp.Body.Close()
	if readErr != nil {
		t.Fatalf("io.ReadAll(invoke): %v", readErr)
	}
	if invResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /invoke status = %d, want 200", invResp.StatusCode)
	}

	callerMu.Lock()
	gotCaller := seenCaller
	remoteAddr := seenRemoteAddr
	callerMu.Unlock()

	if gotCaller.PeerID != caller.Status().PeerID {
		t.Errorf("WhoIs PeerID = %q, want %q", gotCaller.PeerID, caller.Status().PeerID)
	}
	if gotCaller.Principal != "alice@example.com" {
		t.Errorf("WhoIs Principal = %q, want %q", gotCaller.Principal, "alice@example.com")
	}
	if len(gotCaller.Roles) != 1 || gotCaller.Roles[0] != api.RoleNode {
		t.Errorf("WhoIs Roles = %v, want [%s]", gotCaller.Roles, api.RoleNode)
	}
	if gotCaller.Labels["env"] != "prod" {
		t.Errorf("WhoIs Labels[env] = %q, want prod", gotCaller.Labels["env"])
	}

	// Wait briefly for trackedConn.Close() to evict remoteAddr from activeConns.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, still := provider.WhoIs(remoteAddr); !still {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, still := provider.WhoIs(remoteAddr); still {
		t.Errorf("WhoIs(%q) still present after connection closed", remoteAddr)
	}

	// 4. Required-label mismatch fails closed BEFORE sending request bytes.
	badLabelReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.PrivateURL.String()+"/invoke", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext(badLabel): %v", err)
	}
	badLabelReq.Header.Set(api.HeaderMeshRequiredLabels, "env=staging")
	badLabelResp, err := hc.Do(badLabelReq)
	if err != nil {
		t.Fatalf("POST with mismatched required label: %v", err)
	}
	_ = badLabelResp.Body.Close()
	if badLabelResp.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched required label status = %d, want 403", badLabelResp.StatusCode)
	}
}

func TestLocalMCPAndInferenceHandlers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mesh := newInProcessMeshPair(t, ctx)
	_, err := mesh.provider.ListenA2A(ctx, A2AOptions{Name: "helper", Description: "Helper agent"})
	if err != nil {
		t.Fatalf("ListenA2A: %v", err)
	}

	// 1. Local MCPServer + MCPHandler over StreamableHTTP.
	if mesh.caller.MCPServer() == nil {
		t.Fatal("MCPServer() returned nil")
	}
	mcpHTTP := httptest.NewServer(mesh.caller.MCPHandler())
	t.Cleanup(mcpHTTP.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-caller", Version: "1.0.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: mcpHTTP.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatalf("MCP Connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	toolsRes, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(toolsRes.Tools) != 6 {
		t.Fatalf("len(Tools) = %d, want 6 mesh tools", len(toolsRes.Tools))
	}

	infoRes, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "get_mesh_info"})
	if err != nil || infoRes.IsError {
		t.Fatalf("get_mesh_info failed: err=%v res=%+v", err, infoRes)
	}

	discRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_remote_services",
		Arguments: map[string]any{"type": "a2a"},
	})
	if err != nil || discRes.IsError {
		t.Fatalf("discover_remote_services failed: err=%v res=%+v", err, discRes)
	}
	discText := discRes.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(discText, "helper") {
		t.Errorf("discover_remote_services = %s, want helper", discText)
	}

	localRes, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "list_local_services"})
	if err != nil || localRes.IsError {
		t.Fatalf("list_local_services failed: err=%v res=%+v", err, localRes)
	}

	// CIDv1 representation of self PeerID is canonicalized and rejected by find_remote_tools.
	selfCIDv1 := peer.ToCid(mesh.caller.peerID).String()
	selfToolRes, selfToolErr := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "find_remote_tools",
		Arguments: map[string]any{"peer_id": selfCIDv1},
	})
	if selfToolErr == nil && (selfToolRes == nil || !selfToolRes.IsError) {
		t.Fatalf("find_remote_tools accepted CIDv1 self peer_id %q, want error", selfCIDv1)
	}

	// 2. Local InferenceHandler routes and validation.
	infHTTP := httptest.NewServer(mesh.caller.InferenceHandler())
	t.Cleanup(infHTTP.Close)

	modelsResp, err := http.Get(infHTTP.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	modelsBody, err := io.ReadAll(modelsResp.Body)
	_ = modelsResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(/v1/models): %v", err)
	}
	if modelsResp.StatusCode != http.StatusOK || !strings.Contains(string(modelsBody), `"object":"list"`) {
		t.Fatalf("GET /v1/models = %d: %s", modelsResp.StatusCode, modelsBody)
	}

	resp405, err := http.Post(infHTTP.URL+"/v1/models", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp405.Body.Close()
	if resp405.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /v1/models = %d, want 405", resp405.StatusCode)
	}

	resp404, err := http.Get(infHTTP.URL + "/v1/unknown")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("GET /v1/unknown = %d, want 404", resp404.StatusCode)
	}

	resp400, err := http.Post(infHTTP.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp400.Body.Close()
	if resp400.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /v1/chat/completions missing model = %d, want 400", resp400.StatusCode)
	}

	respUnknownModel, err := http.Post(infHTTP.URL+"/v1/chat/completions", "application/json", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	_ = respUnknownModel.Body.Close()
	if respUnknownModel.StatusCode != http.StatusNotFound {
		t.Errorf("POST /v1/chat/completions with unknown model = %d, want 404", respUnknownModel.StatusCode)
	}
}

func TestExternalIngressCanonicalizesActorNodePeerID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env := newStartedTestServer(t, ctx)
	s := env.server

	ep, err := s.ListenA2A(ctx, A2AOptions{
		Name:        "coder",
		Public:      true,
		IngressAuth: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
		NoAnnounce:  true,
	})
	if err != nil {
		t.Fatalf("ListenA2A: %v", err)
	}
	t.Cleanup(func() { _ = ep.Close() })

	var gotPeerID string
	var mu sync.Mutex
	pubSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if info, ok := s.WhoIs(r.RemoteAddr); ok && info != nil {
				mu.Lock()
				gotPeerID = info.PeerID
				mu.Unlock()
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() { _ = pubSrv.Serve(ep.PublicListener) }()
	t.Cleanup(func() { _ = pubSrv.Close() })

	actorHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = actorHost.Close() })
	cidv1Actor := peer.ToCid(actorHost.ID()).String()
	if cidv1Actor == actorHost.ID().String() {
		t.Fatalf("peer.ToCid(%s) produced identical string", actorHost.ID())
	}

	routerBiscuit := mintTestBiscuit(t, env.cpPriv, env.routerHost.ID().String(), api.RoleRouter, time.Now().Add(time.Hour))

	b := biscuit.NewBuilder(env.cpPriv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactActorNode, IDs: []biscuit.Term{biscuit.String(cidv1Actor)}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
		{Predicate: biscuit.Predicate{Name: api.FactEmail, IDs: []biscuit.Term{biscuit.String("carol@example.com")}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
		api.MarkerFact(api.FactTargetUnrestricted),
	} {
		if err := b.AddAuthorityFact(f); err != nil {
			t.Fatalf("AddAuthorityFact: %v", err)
		}
	}
	built, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	callerBytes, err := built.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/coder/invoke", strings.NewReader(`{}`))
	req.RemoteAddr = env.routerHost.ID().String()
	req.Header.Set(api.HeaderMeshBiscuit, base64.RawURLEncoding.EncodeToString(routerBiscuit))
	req.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringEdge)
	req.Header.Set(api.HeaderMeshIngressCallerBiscuit, base64.RawURLEncoding.EncodeToString(callerBytes))

	rec := httptest.NewRecorder()
	s.externalIngressHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("externalIngressHandler status = %d (%s), want 200", rec.Code, rec.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPeerID != actorHost.ID().String() {
		t.Fatalf("WhoIs PeerID = %q, want canonical %q (from CIDv1 %q)", gotPeerID, actorHost.ID().String(), cidv1Actor)
	}
}

type inProcessMeshPair struct {
	provider *Server
	caller   *Server
}

func newInProcessMeshPair(t *testing.T, ctx context.Context) *inProcessMeshPair {
	t.Helper()
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rh, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rh.Close() })

	var dirMu sync.Mutex
	providersByKey := map[string]map[peer.ID]*api.PeerRecord{}
	peersByID := map[peer.ID]*api.PeerRecord{}

	routerBiscuit := mintTestBiscuit(t, cpPriv, rh.ID().String(), api.RoleRouter, time.Now().Add(24*time.Hour))
	rh.SetStreamHandler(api.AuthProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: routerBiscuit})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})
	rh.SetStreamHandler(api.DirectoryProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		remote := st.Conn().RemotePeer()

		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		var req api.DirectoryRequest
		_ = proto.Unmarshal(msg, &req)
		reader.ReleaseMsg(msg)

		resp := &api.DirectoryResponse{}
		dirMu.Lock()
		entry := peersByID[remote]
		if entry == nil {
			var addrs []string
			for _, ma := range rh.Peerstore().Addrs(remote) {
				addrs = append(addrs, ma.String())
			}
			entry = &api.PeerRecord{PeerId: remote.String(), Addrs: addrs}
			peersByID[remote] = entry
		}
		switch op := req.GetRequest().(type) {
		case *api.DirectoryRequest_Provide:
			k := string(op.Provide.GetKey())
			if providersByKey[k] == nil {
				providersByKey[k] = map[peer.ID]*api.PeerRecord{}
			}
			providersByKey[k][remote] = entry
		case *api.DirectoryRequest_Withdraw:
			delete(providersByKey[string(op.Withdraw.GetKey())], remote)
		case *api.DirectoryRequest_FindProviders:
			for _, p := range providersByKey[string(op.FindProviders.GetKey())] {
				resp.Providers = append(resp.Providers, p)
			}
		case *api.DirectoryRequest_FindPeer:
			if pid, err := peer.Decode(op.FindPeer.GetPeerId()); err == nil {
				resp.Peer = peersByID[pid]
			}
		}
		dirMu.Unlock()

		reply, _ := proto.Marshal(resp)
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})

	var routerAddrs []string
	for _, a := range rh.Addrs() {
		routerAddrs = append(routerAddrs, a.String()+"/p2p/"+rh.ID().String())
	}
	cp := newFakeControlPlaneHTTPWithKeys(t, cpPub, cpPriv, routerAddrs)

	startOne := func() *Server {
		s := &Server{
			StateDir:        t.TempDir(),
			ControlPlaneURL: cp.srv.URL,
			BootstrapToken:  "boot-secret",
			ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
			AllowInsecure:   true,
		}
		if _, err := s.Up(ctx); err != nil {
			t.Fatalf("Server.Up: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}

	p := startOne()
	c := startOne()
	// Ensure router peerstore has listen multiaddrs of both peers for FindProviders/FindPeer.
	dirMu.Lock()
	for _, srv := range []*Server{p, c} {
		var maddrs []string
		for _, ma := range srv.host.Addrs() {
			maddrs = append(maddrs, ma.String())
		}
		peersByID[srv.host.ID()] = &api.PeerRecord{PeerId: srv.host.ID().String(), Addrs: maddrs}
	}
	dirMu.Unlock()

	return &inProcessMeshPair{provider: p, caller: c}
}
