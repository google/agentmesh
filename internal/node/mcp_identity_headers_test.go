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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func generateTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	return pid
}

func TestPopulateVerifiedIdentityHeaders(t *testing.T) {
	remotePeer := generateTestPeerID(t)

	t.Run("full claims", func(t *testing.T) {
		claims := &identity.VerifiedBiscuitClaims{
			User:            "alice@example.com",
			Email:           "alice@example.com",
			Roles:           []string{"developer", "operator"},
			Labels:          map[string]string{"env": "prod", "region": "us-central1"},
			Claims:          map[string][]string{"dept": {"platform"}, "tier": {"gold"}},
			ActorNodePeerID: generateTestPeerID(t).String(),
			TaskRules: []*api.TaskAuthorizationRule{
				{Name: "tasks/code-review"},
			},
		}

		h := make(http.Header)
		populateVerifiedIdentityHeaders(h, remotePeer, claims)

		if got := h.Get(api.HeaderPeerID); got != remotePeer.String() {
			t.Errorf("%s = %q, want %q", api.HeaderPeerID, got, remotePeer.String())
		}
		if got := h.Get(api.HeaderMeshOrigin); got != api.MeshOriginRemote {
			t.Errorf("%s = %q, want %q", api.HeaderMeshOrigin, got, api.MeshOriginRemote)
		}
		if got := h.Get(api.HeaderMeshPrincipal); got != "alice@example.com" {
			t.Errorf("%s = %q, want alice@example.com", api.HeaderMeshPrincipal, got)
		}
		if got := h.Get(api.HeaderMeshRoles); got != "developer,operator" {
			t.Errorf("%s = %q, want developer,operator", api.HeaderMeshRoles, got)
		}
		if got := h.Get(api.HeaderMeshActorNode); got != claims.ActorNodePeerID {
			t.Errorf("%s = %q, want %q", api.HeaderMeshActorNode, got, claims.ActorNodePeerID)
		}
		if got := h.Get(api.HeaderMeshTask); got != "tasks/code-review" {
			t.Errorf("%s = %q, want tasks/code-review", api.HeaderMeshTask, got)
		}
		if got := h.Get(api.HeaderMeshLabels); !strings.Contains(got, "env=prod") || !strings.Contains(got, "region=us-central1") {
			t.Errorf("%s = %q, want env=prod,region=us-central1", api.HeaderMeshLabels, got)
		}
		if got := h.Get(api.HeaderMeshClaims); !strings.Contains(got, "dept=platform") || !strings.Contains(got, "tier=gold") {
			t.Errorf("%s = %q, want dept=platform,tier=gold", api.HeaderMeshClaims, got)
		}
	})

	t.Run("nil claims handled safely", func(t *testing.T) {
		h := make(http.Header)
		populateVerifiedIdentityHeaders(h, remotePeer, nil)

		if got := h.Get(api.HeaderPeerID); got != remotePeer.String() {
			t.Errorf("%s = %q, want %q", api.HeaderPeerID, got, remotePeer.String())
		}
		if got := h.Get(api.HeaderMeshOrigin); got != api.MeshOriginRemote {
			t.Errorf("%s = %q, want %q", api.HeaderMeshOrigin, got, api.MeshOriginRemote)
		}
		if got := h.Get(api.HeaderMeshPrincipal); got != "" {
			t.Errorf("%s = %q, want empty", api.HeaderMeshPrincipal, got)
		}
		if got := h.Get(api.HeaderMeshActorNode); got != "" {
			t.Errorf("%s = %q, want empty", api.HeaderMeshActorNode, got)
		}
	})

	t.Run("actorNode fallback to NodePeerID then remotePeer", func(t *testing.T) {
		claims := &identity.VerifiedBiscuitClaims{
			NodePeerID: generateTestPeerID(t).String(),
		}
		h := make(http.Header)
		populateVerifiedIdentityHeaders(h, remotePeer, claims)
		if got := h.Get(api.HeaderMeshActorNode); got != claims.NodePeerID {
			t.Errorf("%s = %q, want %q", api.HeaderMeshActorNode, got, claims.NodePeerID)
		}

		claims.NodePeerID = ""
		h = make(http.Header)
		populateVerifiedIdentityHeaders(h, remotePeer, claims)
		if got := h.Get(api.HeaderMeshActorNode); got != remotePeer.String() {
			t.Errorf("%s = %q, want %q", api.HeaderMeshActorNode, got, remotePeer.String())
		}
	})
}

func TestStripMeshIdentityHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set("X-Mesh-Principal", "forged-principal")
	h.Set("x-mesh-roles", "forged-role")
	h.Set("X-MESH-CLAIMS", "forged-claim")
	h.Set("X-Mesh-Labels", "forged-label")
	h.Set("X-Mesh-Actor-Node", "forged-node")
	h.Set("X-Mesh-Task", "forged-task")
	h.Set("X-Peer-Id", "forged-peer")
	h.Set("x-peer-id", "forged-peer-2")
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "Bearer valid-token")

	stripMeshIdentityHeaders(h)

	for name := range h {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-mesh-") || strings.EqualFold(name, api.HeaderPeerID) {
			t.Errorf("header %q was not stripped by stripMeshIdentityHeaders", name)
		}
	}
	if got := h.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := h.Get("Authorization"); got != "Bearer valid-token" {
		t.Errorf("Authorization = %q, want Bearer valid-token", got)
	}
}

func TestReverseProxy_PrivacyBoundary(t *testing.T) {
	t.Run("loopback backend forwards identity headers by default", func(t *testing.T) {
		var receivedHeaders http.Header
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		proxy, err := newReverseProxyHandler(backend.URL)
		if err != nil {
			t.Fatalf("newReverseProxyHandler: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set(api.HeaderMeshPrincipal, "alice")
		req.Header.Set(api.HeaderMeshActorNode, "12D3KooWActor")
		req.Header.Set(api.HeaderPeerID, "12D3KooWPeer")

		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := receivedHeaders.Get(api.HeaderMeshPrincipal); got != "alice" {
			t.Errorf("%s = %q, want alice", api.HeaderMeshPrincipal, got)
		}
		if got := receivedHeaders.Get(api.HeaderMeshActorNode); got != "12D3KooWActor" {
			t.Errorf("%s = %q, want 12D3KooWActor", api.HeaderMeshActorNode, got)
		}
		if got := receivedHeaders.Get(api.HeaderPeerID); got != "12D3KooWPeer" {
			t.Errorf("%s = %q, want 12D3KooWPeer", api.HeaderPeerID, got)
		}
	})

	t.Run("external backend strips identity headers by default", func(t *testing.T) {
		var receivedHeaders http.Header
		// Custom RoundTripper simulating an external server (e.g. backend.example)
		mockTransport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			receivedHeaders = r.Header.Clone()
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			return rec.Result(), nil
		})

		proxy, err := newReverseProxy("http://external.example.com/mcp", false)
		if err != nil {
			t.Fatalf("newReverseProxy: %v", err)
		}
		proxy.Transport = mockTransport

		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set(api.HeaderMeshPrincipal, "alice")
		req.Header.Set(api.HeaderMeshActorNode, "12D3KooWActor")
		req.Header.Set(api.HeaderPeerID, "12D3KooWPeer")

		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := receivedHeaders.Get(api.HeaderMeshPrincipal); got != "" {
			t.Errorf("external backend saw %s: %q, want stripped", api.HeaderMeshPrincipal, got)
		}
		if got := receivedHeaders.Get(api.HeaderMeshActorNode); got != "" {
			t.Errorf("external backend saw %s: %q, want stripped", api.HeaderMeshActorNode, got)
		}
		if got := receivedHeaders.Get(api.HeaderPeerID); got != "" {
			t.Errorf("external backend saw %s: %q, want stripped", api.HeaderPeerID, got)
		}
	})

	t.Run("external backend with forward_context=true delivers identity headers", func(t *testing.T) {
		var receivedHeaders http.Header
		mockTransport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			receivedHeaders = r.Header.Clone()
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			return rec.Result(), nil
		})

		proxy, err := newReverseProxy("http://external.example.com/mcp", true)
		if err != nil {
			t.Fatalf("newReverseProxy: %v", err)
		}
		proxy.Transport = mockTransport

		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set(api.HeaderMeshPrincipal, "alice")
		req.Header.Set(api.HeaderMeshActorNode, "12D3KooWActor")
		req.Header.Set(api.HeaderPeerID, "12D3KooWPeer")

		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := receivedHeaders.Get(api.HeaderMeshPrincipal); got != "alice" {
			t.Errorf("%s = %q, want alice", api.HeaderMeshPrincipal, got)
		}
		if got := receivedHeaders.Get(api.HeaderMeshActorNode); got != "12D3KooWActor" {
			t.Errorf("%s = %q, want 12D3KooWActor", api.HeaderMeshActorNode, got)
		}
		if got := receivedHeaders.Get(api.HeaderPeerID); got != "12D3KooWPeer" {
			t.Errorf("%s = %q, want 12D3KooWPeer", api.HeaderPeerID, got)
		}
	})
}

func TestMCPService_BackendTransportForStream_PrivacyBoundary(t *testing.T) {
	remotePeer := generateTestPeerID(t)

	reqCtx := RequestContext{
		PeerID: remotePeer,
		CallerClaims: &identity.VerifiedBiscuitClaims{
			User:            "bob@example.com",
			Email:           "bob@example.com",
			Roles:           []string{"developer"},
			ActorNodePeerID: generateTestPeerID(t).String(),
			TaskRules: []*api.TaskAuthorizationRule{
				{Name: "tasks/execute-tool"},
			},
		},
	}

	t.Run("loopback backend attaches verified identity headers", func(t *testing.T) {
		var receivedHeaders http.Header
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		svc := &MCPService{baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "calc"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		}}

		transport, err := svc.backendTransportForStream(nil, reqCtx)
		if err != nil {
			t.Fatalf("backendTransportForStream: %v", err)
		}

		st, ok := transport.(*mcp.StreamableClientTransport)
		if !ok {
			t.Fatalf("got %T, want *mcp.StreamableClientTransport", transport)
		}

		// Make an HTTP call using the transport's HTTP client
		req, err := http.NewRequest(http.MethodPost, backend.URL, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		// Try to inject forged headers; they must be stripped
		req.Header.Set(api.HeaderMeshPrincipal, "forged-principal")
		req.Header.Set(api.HeaderPeerID, "forged-peer")

		resp, err := st.HTTPClient.Do(req)
		if err != nil {
			t.Fatalf("HTTPClient.Do: %v", err)
		}
		_ = resp.Body.Close()

		if got := receivedHeaders.Get(api.HeaderMeshPrincipal); got != "bob@example.com" {
			t.Errorf("%s = %q, want bob@example.com", api.HeaderMeshPrincipal, got)
		}
		if got := receivedHeaders.Get(api.HeaderMeshActorNode); got != reqCtx.CallerClaims.ActorNodePeerID {
			t.Errorf("%s = %q, want %q", api.HeaderMeshActorNode, got, reqCtx.CallerClaims.ActorNodePeerID)
		}
		if got := receivedHeaders.Get(api.HeaderPeerID); got != remotePeer.String() {
			t.Errorf("%s = %q, want %q", api.HeaderPeerID, got, remotePeer.String())
		}
		if got := receivedHeaders.Get(api.HeaderMeshOrigin); got != api.MeshOriginRemote {
			t.Errorf("%s = %q, want %q", api.HeaderMeshOrigin, got, api.MeshOriginRemote)
		}
		if got := receivedHeaders.Get(api.HeaderMeshTask); got != "tasks/execute-tool" {
			t.Errorf("%s = %q, want tasks/execute-tool", api.HeaderMeshTask, got)
		}
	})

	t.Run("external backend without forward_context does not attach identity headers", func(t *testing.T) {
		var receivedHeaders http.Header
		mockTransport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			receivedHeaders = r.Header.Clone()
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			return rec.Result(), nil
		})

		svc := &MCPService{baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "remote-calc", ForwardContext: false},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://external-mcp.example.com/mcp"},
		}}

		transport, err := svc.backendTransportForStream(nil, reqCtx)
		if err != nil {
			t.Fatalf("backendTransportForStream: %v", err)
		}
		st := transport.(*mcp.StreamableClientTransport)
		// Point transport to mock roundtripper
		client := &http.Client{Transport: mockTransport}
		if st.HTTPClient != nil && st.HTTPClient.Transport != nil {
			if ht, ok := st.HTTPClient.Transport.(mcpHeaderTransport); ok {
				ht.base = mockTransport
				client.Transport = ht
			}
		}

		req, err := http.NewRequest(http.MethodPost, "http://external-mcp.example.com/mcp", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do: %v", err)
		}
		_ = resp.Body.Close()

		if got := receivedHeaders.Get(api.HeaderMeshPrincipal); got != "" {
			t.Errorf("external backend saw %s: %q, want empty", api.HeaderMeshPrincipal, got)
		}
		if got := receivedHeaders.Get(api.HeaderMeshActorNode); got != "" {
			t.Errorf("external backend saw %s: %q, want empty", api.HeaderMeshActorNode, got)
		}
		if got := receivedHeaders.Get(api.HeaderPeerID); got != "" {
			t.Errorf("external backend saw %s: %q, want empty", api.HeaderPeerID, got)
		}
	})

	t.Run("external backend with forward_context=true attaches verified identity headers", func(t *testing.T) {
		var receivedHeaders http.Header
		mockTransport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			receivedHeaders = r.Header.Clone()
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			return rec.Result(), nil
		})

		svc := &MCPService{baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "remote-calc", ForwardContext: true},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://external-mcp.example.com/mcp"},
		}}

		transport, err := svc.backendTransportForStream(nil, reqCtx)
		if err != nil {
			t.Fatalf("backendTransportForStream: %v", err)
		}
		st := transport.(*mcp.StreamableClientTransport)
		client := &http.Client{Transport: mockTransport}
		if st.HTTPClient != nil && st.HTTPClient.Transport != nil {
			if ht, ok := st.HTTPClient.Transport.(mcpHeaderTransport); ok {
				ht.base = mockTransport
				client.Transport = ht
			}
		}

		req, err := http.NewRequest(http.MethodPost, "http://external-mcp.example.com/mcp", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do: %v", err)
		}
		_ = resp.Body.Close()

		if got := receivedHeaders.Get(api.HeaderMeshPrincipal); got != "bob@example.com" {
			t.Errorf("%s = %q, want bob@example.com", api.HeaderMeshPrincipal, got)
		}
		if got := receivedHeaders.Get(api.HeaderMeshActorNode); got != reqCtx.CallerClaims.ActorNodePeerID {
			t.Errorf("%s = %q, want %q", api.HeaderMeshActorNode, got, reqCtx.CallerClaims.ActorNodePeerID)
		}
		if got := receivedHeaders.Get(api.HeaderPeerID); got != remotePeer.String() {
			t.Errorf("%s = %q, want %q", api.HeaderPeerID, got, remotePeer.String())
		}
	})

	t.Run("discovery probe without caller context sends no identity headers", func(t *testing.T) {
		var receivedHeaders http.Header
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		svc := &MCPService{baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "calc"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		}}

		transport, err := svc.backendTransport()
		if err != nil {
			t.Fatalf("backendTransport: %v", err)
		}
		st := transport.(*mcp.StreamableClientTransport)

		req, err := http.NewRequest(http.MethodGet, backend.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := st.HTTPClient.Do(req)
		if err != nil {
			t.Fatalf("HTTPClient.Do: %v", err)
		}
		_ = resp.Body.Close()

		if got := receivedHeaders.Get(api.HeaderMeshPrincipal); got != "" {
			t.Errorf("probe saw %s: %q, want empty", api.HeaderMeshPrincipal, got)
		}
		if got := receivedHeaders.Get(api.HeaderPeerID); got != "" {
			t.Errorf("probe saw %s: %q, want empty", api.HeaderPeerID, got)
		}
	})
}

// TestMCPService_ParityBetweenLibp2pHTTPAndPassThrough verifies that both the
// /mesh/<peer>/mcp/<service> HTTP reverse proxy path and the call_remote_tool
// /mesh/mcp/1.0.0 stream pass-through path deliver equivalent verified identity headers
// to the backend target_url service.
func TestMCPService_ParityBetweenLibp2pHTTPAndPassThrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var mu sync.Mutex
	var lastHeaders http.Header

	backend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		mu.Lock()
		lastHeaders = r.Header.Clone()
		mu.Unlock()

		srv := mcp.NewServer(&mcp.Implementation{Name: "parity-backend", Version: "1.0.0"}, nil)
		srv.AddTool(&mcp.Tool{
			Name:        "ping",
			Description: "ping tool",
			InputSchema: map[string]any{"type": "object"},
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "pong"}}}, nil
		})
		return srv
	}, nil))
	defer backend.Close()

	remotePeer := generateTestPeerID(t)

	claims := &identity.VerifiedBiscuitClaims{
		User:            "charlie@example.com",
		Email:           "charlie@example.com",
		Roles:           []string{"agent", "tester"},
		Labels:          map[string]string{"env": "test"},
		Claims:          map[string][]string{"team": {"core"}},
		ActorNodePeerID: generateTestPeerID(t).String(),
		TaskRules: []*api.TaskAuthorizationRule{
			{Name: "tasks/ping"},
		},
	}

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "parity-service"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("svc.Init: %v", err)
	}
	defer func() { _ = svc.Teardown() }()

	// Path 1: /mesh/<peer>/mcp/<service> over /libp2p-http proxy path
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	// Caller supplies forged headers; ingress strips them and stamps verified headers
	req.Header.Set("X-Mesh-Principal", "forged-charlie")
	req.Header.Set("X-Peer-Id", "forged-peer")
	stripMeshIdentityHeaders(req.Header)
	populateVerifiedIdentityHeaders(req.Header, remotePeer, claims)

	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	mu.Lock()
	httpPathHeaders := lastHeaders.Clone()
	mu.Unlock()

	// Path 2: call_remote_tool stream pass-through over /mesh/mcp/1.0.0
	reqCtx := RequestContext{
		PeerID:       remotePeer,
		CallerClaims: claims,
	}

	streamTransport, err := svc.backendTransportForStream(nil, reqCtx)
	if err != nil {
		t.Fatalf("backendTransportForStream: %v", err)
	}
	st, ok := streamTransport.(*mcp.StreamableClientTransport)
	if !ok {
		t.Fatalf("got %T, want *mcp.StreamableClientTransport", streamTransport)
	}

	// Connect an MCP client to backend through streamTransport's client
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	mu.Lock()
	streamPathHeaders := lastHeaders.Clone()
	mu.Unlock()

	// Verify header parity between both paths
	headersToCheck := []string{
		api.HeaderPeerID,
		api.HeaderMeshOrigin,
		api.HeaderMeshPrincipal,
		api.HeaderMeshRoles,
		api.HeaderMeshClaims,
		api.HeaderMeshLabels,
		api.HeaderMeshActorNode,
		api.HeaderMeshTask,
	}

	for _, h := range headersToCheck {
		httpVal := httpPathHeaders.Get(h)
		streamVal := streamPathHeaders.Get(h)
		if httpVal == "" {
			t.Errorf("Path 1 (HTTP proxy) did not deliver %s", h)
		}
		if streamVal == "" {
			t.Errorf("Path 2 (Stream pass-through) did not deliver %s", h)
		}
		if httpVal != streamVal {
			t.Errorf("Header parity mismatch for %s: Path 1 got %q, Path 2 got %q", h, httpVal, streamVal)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
