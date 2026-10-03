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
	"testing"
	"time"

	"github.com/google/sam/api"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestConnectionGater(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Logf("failed to close store: %v", err)
		}
	}()

	cache, err := lru.New[string, int64](100)
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		Store:          store,
		revokedPeers:   cache,
		BiscuitTimeout: 500 * time.Millisecond,
	}
	gater := &nodeConnGate{node: node}

	// Generate test peer IDs
	priv1, _, _ := crypto.GenerateEd25519Key(nil)
	peer1, _ := peer.IDFromPrivateKey(priv1)

	priv2, _, _ := crypto.GenerateEd25519Key(nil)
	peer2, _ := peer.IDFromPrivateKey(priv2)

	priv3, _, _ := crypto.GenerateEd25519Key(nil)
	peer3, _ := peer.IDFromPrivateKey(priv3)

	// Case 1: Peer is not banned
	if !gater.InterceptPeerDial(peer1) {
		t.Errorf("expected InterceptPeerDial to allow peer1")
	}
	if !gater.InterceptSecured(network.DirInbound, peer1, nil) {
		t.Errorf("expected InterceptSecured to allow peer1")
	}

	// Case 2: Peer is in revoked cache
	node.revokedPeers.Add(peer2.String(), time.Now().Unix())
	if gater.InterceptPeerDial(peer2) {
		t.Errorf("expected InterceptPeerDial to deny peer2 (in revoked cache)")
	}

	if gater.InterceptSecured(network.DirInbound, peer2, nil) {
		t.Errorf("expected InterceptSecured to deny peer2 (in revoked cache)")
	}

	// Case 3: a peer the control plane does not ban stays reachable, even
	// after another peer has been banned.
	if !gater.InterceptPeerDial(peer3) {
		t.Errorf("expected InterceptPeerDial to allow peer3")
	}
	if !gater.InterceptSecured(network.DirInbound, peer3, nil) {
		t.Errorf("expected InterceptSecured to allow peer3")
	}
}

// The revocation cache is filled from the control plane's ban set by the
// pre-start pull (SyncControlPlane -> reconcileBannedPeers). Without that a
// restarted node would enforce no ban at all until the next MeshEvent_BANNED,
// which for a ban published while it was down never arrives.
func TestGaterEnforcesSeededBans(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Logf("failed to close store: %v", err)
		}
	}()

	bannedPriv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	banned, err := peer.IDFromPrivateKey(bannedPriv)
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := peer.IDFromPrivateKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}

	node, err := NewSamNode(Options{PrivKey: bannedPriv, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	// The wire form may be any encoding of the peer ID, and one bad entry
	// must not stop the rest from being enforced.
	node.reconcileBannedPeers([]string{peer.ToCid(banned).String(), "not-a-peer-id"}, time.Now())

	gater := &nodeConnGate{node: node}
	if gater.InterceptPeerDial(banned) {
		t.Error("a peer in the control plane's ban set must not be dialled")
	}
	if gater.InterceptSecured(network.DirInbound, banned, nil) {
		t.Error("a peer in the control plane's ban set must not be accepted")
	}
	if !gater.InterceptPeerDial(allowed) {
		t.Error("seeding a ban must not deny unrelated peers")
	}
}

// startBareNode brings up a SamNode without control plane/enrollment.
func startBareNode(t *testing.T, ctx context.Context) (*SamNode, func()) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewSamNode(Options{
		PrivKey:           priv,
		RouterAddrs:       nil,
		Store:             store,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	node.BiscuitTimeout = 500 * time.Millisecond
	if err := node.Start(ctx); err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = node.Teardown()
		_ = store.Close()
	}
	return node, cleanup
}

const testMCPProtocol = protocol.ID("/sam-test/mcp/1.0.0")

func TestHandleMCPStream_DumbPipeProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "review_pr", Description: "Run a code review", InputSchema: map[string]any{"type": "object"}},
	}
	upstream := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer upstream.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	// Init a real MCPService so session + aggregatedTools are populated; insert
	// directly to skip DHT advertisement.
	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("MCPService.Init: %v", err)
	}
	nodeA.services.insertService(svc)
	t.Cleanup(func() { _ = svc.Teardown() })

	// Bypass biscuit auth by exposing HandleMCPStream on a test-only protocol.
	nodeA.Host.SetStreamHandler(testMCPProtocol, func(s network.Stream) {
		nodeA.HandleMCPStream(s, RequestContext{Target: "mcp://code-reviewer"})
	})

	if err := nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProtocol)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	found := false
	for _, n := range names {
		if n == "review_pr" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tools/list to include %q; got %v", "review_pr", names)
	}

	// Dumb pipe: infra tools are NOT present.
	for _, n := range names {
		if n == "get_mesh_info" {
			t.Errorf("expected infra tool get_mesh_info to be absent in dumb pipe; got %v", names)
		}
	}
}

func TestHandleMCPStream_ForwarderRoutesCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "echo", Description: "echo", InputSchema: map[string]any{"type": "object"}},
	}
	upstream := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer upstream.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "svc"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("MCPService.Init: %v", err)
	}
	nodeA.services.insertService(svc)
	t.Cleanup(func() { _ = svc.Teardown() })

	nodeA.Host.SetStreamHandler(testMCPProtocol, func(s network.Stream) {
		nodeA.HandleMCPStream(s, RequestContext{Target: "mcp://svc"})
	})

	if err := nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProtocol)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"unused": true},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("expected non-empty Content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	// newFakeMCPHandler echoes "fake-result:<tool-name>" using the un-namespaced form.
	if tc.Text != "fake-result:echo" {
		t.Errorf("forwarder did not pass un-namespaced name; got %q", tc.Text)
	}
}

// startBareQUICNode is startBareNode over the QUIC transport instead of TCP.
//
// The distinction matters for TestHandleStreamPassThrough_BackendEOFDoesNotDropInFlightResponse
// below: go-libp2p's QUIC-backed network.Stream.Close cancels the read side
// over the wire (CancelRead sends a QUIC STOP_SENDING frame to the peer),
// while the yamux stream used over startBareNode's plain TCP transport does
// the equivalent locally only - its CloseRead doc says plainly "Remote is
// not notified." A stream backed by TCP+yamux structurally cannot exercise
// the wire-level race this test is after; only a real QUIC connection can.
func startBareQUICNode(t *testing.T, ctx context.Context) (*SamNode, func()) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewSamNode(Options{
		PrivKey:           priv,
		RouterAddrs:       nil,
		Store:             store,
		MeshID:            "test-mesh",
		DiscoveryInterval: "1s",
		ListenAddrs:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		EnableRelay:       false,
		NodeConfig:        &NodeConfigComplete{},
		KeyGracePeriod:    24 * time.Hour,
		AllowLoopback:     true,
		MonitorBootstrap:  2 * time.Minute,
		MonitorInterval:   1 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	node.BiscuitTimeout = 500 * time.Millisecond
	if err := node.Start(ctx); err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = node.Teardown()
		_ = store.Close()
	}
	return node, cleanup
}

// TestHandleStreamPassThrough_BackendEOFDoesNotDropInFlightResponse is a
// regression test for google/sam#375.
//
// A backend that answers a single request and then closes its side of the
// connection - a normal EOF for a one-shot HTTP-style backend, not a
// failure - used to make HandleStreamPassThrough tear the whole
// client-facing stream down immediately via network.Stream.Close. Close's
// own documented contract says it "does not guarantee receipt of the data";
// closing right behind a Write that had just reported success raced the
// response off the wire, and the caller in the original report sometimes
// saw EOF in its place. See the comment on the drain logic in
// HandleStreamPassThrough for the fix.
//
// The race is timing-dependent, so this repeats the call many times over a
// real QUIC connection (see startBareQUICNode) rather than asserting on a
// single attempt.
func TestHandleStreamPassThrough_BackendEOFDoesNotDropInFlightResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// A payload closer in size to the 834-byte response in the original
	// report than a trivial "ok" would be - small messages are far more
	// likely to always win the race regardless of the bug.
	wantText := strings.Repeat("x", 700)
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		srv := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0.0.1"}, nil)
		srv.AddTool(&mcp.Tool{Name: "echo", Description: "echo", InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: wantText}}}, nil
			})
		return srv
	}, nil))
	defer upstream.Close()

	nodeA, cleanupA := startBareQUICNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareQUICNode(t, ctx)
	defer cleanupB()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "svc"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("MCPService.Init: %v", err)
	}
	nodeA.services.insertService(svc)
	t.Cleanup(func() { _ = svc.Teardown() })

	nodeA.Host.SetStreamHandler(testMCPProtocol, func(s network.Stream) {
		nodeA.HandleMCPStream(s, RequestContext{Target: "mcp://svc"})
	})

	if err := nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	const iterations = 50
	for i := 0; i < iterations; i++ {
		func() {
			s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProtocol)
			if err != nil {
				t.Fatalf("iteration %d: NewStream: %v", i, err)
			}
			defer func() { _ = s.Close() }()

			client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
			session, err := client.Connect(ctx, NewStreamTransport(s), nil)
			if err != nil {
				t.Fatalf("iteration %d: client.Connect: %v", i, err)
			}
			defer func() { _ = session.Close() }()

			res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{}})
			if err != nil {
				t.Fatalf("iteration %d: CallTool: %v", i, err)
			}
			tc, ok := res.Content[0].(*mcp.TextContent)
			if !ok || tc.Text != wantText {
				t.Fatalf("iteration %d: got %v, want text of length %d", i, res.Content, len(wantText))
			}
		}()
	}
}

// TestHandleStreamPassThrough_SlowBackendDoesNotHitDrainTimeout is a
// regression test for review feedback from aojea on google/sam#379: the
// drain wait was timed from the start of the whole exchange, not from when
// the backend leg actually finished, so any session - healthy or not -
// that happened to run longer than passThroughDrainTimeout got killed
// mid-flight. Shrinks passThroughDrainTimeout for the test so proving this
// doesn't need a multi-second sleep; startBareNode's plain TCP transport is
// enough here, since this is about goroutine timing, not the QUIC-specific
// Close semantics TestHandleStreamPassThrough_BackendEOFDoesNotDropInFlightResponse
// covers.
func TestHandleStreamPassThrough_SlowBackendDoesNotHitDrainTimeout(t *testing.T) {
	oldTimeout := passThroughDrainTimeout
	passThroughDrainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { passThroughDrainTimeout = oldTimeout })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Several times passThroughDrainTimeout: under the bug, the stream was
	// torn down well before the backend ever answered.
	const backendDelay = 300 * time.Millisecond
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		srv := mcp.NewServer(&mcp.Implementation{Name: "slow", Version: "0.0.1"}, nil)
		srv.AddTool(&mcp.Tool{Name: "slow_echo", Description: "slow", InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				time.Sleep(backendDelay)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
			})
		return srv
	}, nil))
	defer upstream.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "slow-svc"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("MCPService.Init: %v", err)
	}
	nodeA.services.insertService(svc)
	t.Cleanup(func() { _ = svc.Teardown() })

	nodeA.Host.SetStreamHandler(testMCPProtocol, func(s network.Stream) {
		nodeA.HandleMCPStream(s, RequestContext{Target: "mcp://slow-svc"})
	})

	if err := nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProtocol)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "slow_echo", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("CallTool: %v (a healthy exchange slower than passThroughDrainTimeout must not be killed for that alone)", err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok || tc.Text != "ok" {
		t.Fatalf("got %v, want text %q", res.Content, "ok")
	}
}

func TestHandleMCPStream_TAREnforcesAllowedTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		srv := mcp.NewServer(&mcp.Implementation{Name: "weather-srv", Version: "0.0.1"}, nil)
		srv.AddTool(&mcp.Tool{Name: "get_weather", Description: "allowed tool", InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "sunny"}}}, nil
			})
		srv.AddTool(&mcp.Tool{Name: "drop_table", Description: "forbidden tool", InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "dropped"}}}, nil
			})
		return srv
	}, nil))
	defer upstream.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "weather"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("MCPService.Init: %v", err)
	}
	nodeA.services.insertService(svc)
	t.Cleanup(func() { _ = svc.Teardown() })

	tar := &api.TaskAuthorizationRule{
		Name: "only-get-weather",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"mcp://weather"},
			Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather"}},
		}},
	}
	nodeA.Host.SetStreamHandler(testMCPProtocol, func(s network.Stream) {
		nodeA.HandleMCPStream(s, RequestContext{
			PeerID:    s.Conn().RemotePeer(),
			Target:    "mcp://weather",
			TaskRules: []*api.TaskAuthorizationRule{tar},
		})
	})

	if err := nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProtocol)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Allowed tool call succeeds.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_weather", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("CallTool(get_weather) unexpected error: %v", err)
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); !ok || tc.Text != "sunny" {
		t.Fatalf("got %v, want text %q", res.Content, "sunny")
	}

	// Forbidden tool call is rejected by the PEP before reaching the upstream MCP server.
	if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "drop_table", Arguments: map[string]any{}}); err == nil {
		t.Fatal("expected CallTool(drop_table) to be denied by TAR")
	}
}
