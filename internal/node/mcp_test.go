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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/multiformats/go-multiaddr"
)

func TestMCPHandler_HTTP(t *testing.T) {
	// Setup a dummy node
	node := &AgentMeshNode{
		BiscuitTimeout: 500 * time.Millisecond,
	}
	handler := NewMCPHandler(node)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	client := &http.Client{}

	// Test GET on root (should be 404 now)
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status NotFound on root, got %d", resp.StatusCode)
	}

	// Test GET on /mcp
	req2, err := http.NewRequest("GET", ts.URL+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	// Stateless servers have no standalone SSE stream; the spec reserves 405 for that.
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status MethodNotAllowed on GET /mcp, got %d", resp2.StatusCode)
	}
}

func TestResolveRelayAddresses(t *testing.T) {
	ctx := context.Background()
	mn := mocknet.New()

	// Create local host
	localHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}

	// The directory is not asked: the addresses are in the peerstore.
	node := &AgentMeshNode{
		Host:           localHost,
		Directory:      &routerDirectory{host: localHost, routers: func() []peer.ID { return nil }, addrs: localHost.Addrs},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	// Create relay host
	relayHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	relayID := relayHost.ID()

	// Add relay direct IP to DHT peerstore
	relayDirectAddr, _ := multiaddr.NewMultiaddr("/ip4/10.0.0.1/tcp/4501")
	localHost.Peerstore().AddAddr(relayID, relayDirectAddr, peerstore.PermanentAddrTTL)
	relayHost.Peerstore().AddAddr(relayID, relayDirectAddr, peerstore.PermanentAddrTTL)

	_ = mn.LinkAll()
	_ = mn.ConnectAllButSelf()

	// Create a target node behind the relay
	targetHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	targetID := targetHost.ID()

	// Add a dns-based circuit address for the target node to the local host's peerstore
	circuitAddrStr := fmt.Sprintf("/dns4/router.com/tcp/4501/p2p/%s/p2p-circuit", relayID.String())
	circuitAddr, _ := multiaddr.NewMultiaddr(circuitAddrStr)
	localHost.Peerstore().AddAddr(targetID, circuitAddr, peerstore.PermanentAddrTTL)

	// Run the function
	node.preparePeerAddrs(ctx, targetID)

	// Verify that the direct IP circuit address was added to the target's peerstore
	addrs := localHost.Peerstore().Addrs(targetID)
	foundDirect := false
	expectedDirectAddrStr := fmt.Sprintf("/p2p/%s/p2p-circuit", relayID.String())

	for _, addr := range addrs {
		if addr.String() == expectedDirectAddrStr {
			foundDirect = true
			break
		}
	}

	if !foundDirect {
		t.Errorf("Expected generic circuit address %s not found in peerstore. Got: %v", expectedDirectAddrStr, addrs)
	}
}

// A peer named by ID alone, with no address anywhere (an SDK agent publishes
// no record), is given a circuit through every router that admitted this
// node, and through nothing else. A peer known by direct addresses only is
// given the same circuits besides them: those addresses may be on a network
// this node cannot reach. A peer that announced a circuit is not.
func TestPreparePeerAddrsFallsBackToAuthenticatedRouters(t *testing.T) {
	ctx := context.Background()
	mn := mocknet.New()
	localHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	stale, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	_ = mn.LinkAll()
	if _, err := mn.ConnectPeers(localHost.ID(), admitted.ID()); err != nil {
		t.Fatal(err)
	}
	unknown, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}

	node := &AgentMeshNode{
		Host:                 localHost,
		Directory:            &routerDirectory{host: localHost, routers: func() []peer.ID { return nil }, addrs: localHost.Addrs},
		BiscuitTimeout:       500 * time.Millisecond,
		authenticatedRouters: map[peer.ID]bool{admitted.ID(): true, stale.ID(): true},
	}
	circuit := fmt.Sprintf("/p2p/%s/p2p-circuit", admitted.ID())
	addrsOf := func(p peer.ID) []string {
		var got []string
		for _, a := range localHost.Peerstore().Addrs(p) {
			got = append(got, a.String())
		}
		sort.Strings(got)
		return got
	}

	node.preparePeerAddrs(ctx, unknown.ID())
	if got := addrsOf(unknown.ID()); len(got) != 1 || got[0] != circuit {
		t.Fatalf("addresses for an unknown peer: got %v, want only a circuit through the connected router %v", got, circuit)
	}

	directOnly, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	direct := multiaddr.StringCast("/ip4/172.18.0.6/tcp/5002")
	localHost.Peerstore().AddAddr(directOnly.ID(), direct, peerstore.PermanentAddrTTL)
	node.preparePeerAddrs(ctx, directOnly.ID())
	want := []string{direct.String(), circuit}
	sort.Strings(want)
	if got := addrsOf(directOnly.ID()); !slices.Equal(got, want) {
		t.Fatalf("addresses for a peer with direct addresses only: got %v, want %v", got, want)
	}

	announced, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	other, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	ownCircuit := multiaddr.StringCast(fmt.Sprintf("/ip4/10.0.0.2/tcp/4501/p2p/%s/p2p-circuit", other.ID()))
	localHost.Peerstore().AddAddr(announced.ID(), ownCircuit, peerstore.PermanentAddrTTL)
	node.preparePeerAddrs(ctx, announced.ID())
	if got := addrsOf(announced.ID()); slices.Contains(got, circuit) {
		t.Fatalf("a peer that announced a circuit was also given ours: %v", got)
	}
}

// scriptedDirectory answers FindPeer from a queue of outcomes and counts the
// calls; the other methods are not reached by preparePeerAddrs.
type scriptedDirectory struct {
	findPeer []func(peer.ID) (peer.AddrInfo, error)
	calls    int
}

func (d *scriptedDirectory) Provide(context.Context, []byte, string) error { return nil }
func (d *scriptedDirectory) Withdraw(context.Context, []byte) error        { return nil }
func (d *scriptedDirectory) FindProviders(context.Context, []byte, int) ([]peer.AddrInfo, error) {
	return nil, nil
}
func (d *scriptedDirectory) FindPeer(_ context.Context, p peer.ID) (peer.AddrInfo, error) {
	d.calls++
	if len(d.findPeer) == 0 {
		return peer.AddrInfo{ID: p}, errors.New("no scripted answer")
	}
	next := d.findPeer[0]
	d.findPeer = d.findPeer[1:]
	return next(p)
}

// A directory lookup that fails leaves the peer with circuits through this
// node's routers for the dial at hand, and nothing more: the next lookup asks
// the directory again instead of dialing the guess for TempAddrTTL. Once the
// directory answers, the peer's own addresses are dialed (our circuits stay
// as a second path) and the directory is not asked again while they last.
func TestPreparePeerAddrsAsksAgainAfterFailedLookup(t *testing.T) {
	ctx := context.Background()
	mn := mocknet.New()
	localHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	target, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	_ = mn.LinkAll()
	if _, err := mn.ConnectPeers(localHost.ID(), admitted.ID()); err != nil {
		t.Fatal(err)
	}
	// A node holds its router's addresses; mocknet does not fill them in.
	localHost.Peerstore().AddAddrs(admitted.ID(), admitted.Addrs(), peerstore.PermanentAddrTTL)
	ownCircuit := fmt.Sprintf("/p2p/%s/p2p-circuit", admitted.ID())
	announced := multiaddr.StringCast("/ip4/203.0.113.7/tcp/4501")

	dir := &scriptedDirectory{findPeer: []func(peer.ID) (peer.AddrInfo, error){
		func(p peer.ID) (peer.AddrInfo, error) {
			return peer.AddrInfo{ID: p}, errors.New("i/o deadline reached")
		},
		func(p peer.ID) (peer.AddrInfo, error) {
			return peer.AddrInfo{ID: p, Addrs: []multiaddr.Multiaddr{announced}}, nil
		},
	}}
	node := &AgentMeshNode{
		Host:                 localHost,
		Directory:            dir,
		BiscuitTimeout:       500 * time.Millisecond,
		authenticatedRouters: map[peer.ID]bool{admitted.ID(): true},
	}
	addrsOf := func() []string {
		var got []string
		for _, a := range localHost.Peerstore().Addrs(target.ID()) {
			got = append(got, a.String())
		}
		sort.Strings(got)
		return got
	}

	node.preparePeerAddrs(ctx, target.ID())
	if dir.calls != 1 {
		t.Fatalf("directory calls after a failed lookup = %d, want 1", dir.calls)
	}
	if got := addrsOf(); len(got) != 1 || got[0] != ownCircuit {
		t.Fatalf("addresses after a failed lookup = %v, want only the fallback circuit %s", got, ownCircuit)
	}

	node.preparePeerAddrs(ctx, target.ID())
	if dir.calls != 2 {
		t.Fatalf("directory calls after the fallback was cached = %d, want 2: the guess must not stand in for a record", dir.calls)
	}
	if got := addrsOf(); !slices.Contains(got, announced.String()) {
		t.Fatalf("addresses after the directory answered = %v, want %s among them", got, announced)
	}

	node.preparePeerAddrs(ctx, target.ID())
	if dir.calls != 2 {
		t.Fatalf("directory calls with a record in the peerstore = %d, want 2", dir.calls)
	}
}

func TestSplitToolName(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantService string
		wantTool    string
		wantErr     bool
	}{
		{
			name:    "Empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:        "Modern URI format",
			input:       "mcp://my-service/my-tool",
			wantService: "mcp://my-service",
			wantTool:    "my-tool",
			wantErr:     false,
		},
		{
			name:        "Modern URI format with path depth",
			input:       "mcp://my-service/my-tool/sub-tool",
			wantService: "mcp://my-service",
			wantTool:    "my-tool/sub-tool",
			wantErr:     false,
		},
		{
			name:    "Missing tool path",
			input:   "mcp://my-service",
			wantErr: true,
		},
		{
			name:    "No scheme path",
			input:   "mesh.catalog/some-tool",
			wantErr: true,
		},
		{
			name:    "Just tool name",
			input:   "some-tool",
			wantErr: true,
		},
		{
			name:        "Strict system catalog URI",
			input:       "system://mesh.catalog/some-tool",
			wantService: "system://mesh.catalog",
			wantTool:    "some-tool",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSvc, gotTool, err := api.SplitToolName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SplitToolName(%q) returned error: %v, wantErr: %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr {
				if gotSvc != tt.wantService || gotTool != tt.wantTool {
					t.Errorf("splitToolName(%q) = (%q, %q), want (%q, %q)",
						tt.input, gotSvc, gotTool, tt.wantService, tt.wantTool)
				}
			}
		})
	}
}

// The relay's own address is what a circuit address carries before its
// /p2p/<relay>/p2p-circuit tail; a bare circuit and a direct address carry
// none.
func TestRelayTransportAddr(t *testing.T) {
	relayHost, err := mocknet.New().GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	relay := relayHost.ID().String()
	for _, tc := range []struct {
		addr, want string
	}{
		{"/ip4/136.113.153.46/udp/4501/quic-v1/p2p/" + relay + "/p2p-circuit", "/ip4/136.113.153.46/udp/4501/quic-v1"},
		{"/dns4/bootstrap.example/tcp/4501/p2p/" + relay + "/p2p-circuit", "/dns4/bootstrap.example/tcp/4501"},
		{"/p2p/" + relay + "/p2p-circuit", ""},
		{"/ip4/10.0.0.1/tcp/5002", ""},
	} {
		got := relayTransportAddr(multiaddr.StringCast(tc.addr))
		if (got == nil) != (tc.want == "") || (got != nil && got.String() != tc.want) {
			t.Errorf("relayTransportAddr(%s) = %v, want %q", tc.addr, got, tc.want)
		}
	}
}
