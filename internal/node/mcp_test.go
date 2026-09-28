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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/sam/api"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/multiformats/go-multiaddr"
)

func TestMCPHandler_HTTP(t *testing.T) {
	// Setup a dummy node
	node := &SamNode{
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

	// Create a real DHT bound to the mock host
	kdht, err := dht.New(localHost, dht.Mode(dht.ModeServer))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kdht.Close() }()

	node := &SamNode{
		Host:           localHost,
		DHT:            kdht,
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

	// Create DHT for relay
	relayDHT, err := dht.New(relayHost, dht.Mode(dht.ModeServer))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relayDHT.Close() }()

	_ = mn.LinkAll()
	_ = mn.ConnectAllButSelf()

	// Wait for DHT
	_, _ = kdht.RoutingTable().TryAddPeer(relayID, true, true)
	_, _ = relayDHT.RoutingTable().TryAddPeer(localHost.ID(), true, true)

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
// node, and through nothing else.
func TestPreparePeerAddrsFallsBackToAuthenticatedRouters(t *testing.T) {
	ctx := context.Background()
	mn := mocknet.New()
	localHost, err := mn.GenPeer()
	if err != nil {
		t.Fatal(err)
	}
	kdht, err := dht.New(localHost, dht.Mode(dht.ModeClient))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kdht.Close() }()
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

	node := &SamNode{
		Host:                 localHost,
		DHT:                  kdht,
		BiscuitTimeout:       500 * time.Millisecond,
		authenticatedRouters: map[peer.ID]bool{admitted.ID(): true, stale.ID(): true},
	}
	node.preparePeerAddrs(ctx, unknown.ID())

	var got []string
	for _, a := range localHost.Peerstore().Addrs(unknown.ID()) {
		got = append(got, a.String())
	}
	want := []string{fmt.Sprintf("/p2p/%s/p2p-circuit", admitted.ID())}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("addresses for an unknown peer: got %v, want only a circuit through the connected router %v", got, want)
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
			input:   "sam.catalog/some-tool",
			wantErr: true,
		},
		{
			name:    "Just tool name",
			input:   "some-tool",
			wantErr: true,
		},
		{
			name:        "Strict system catalog URI",
			input:       "system://sam.catalog/some-tool",
			wantService: "system://sam.catalog",
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
