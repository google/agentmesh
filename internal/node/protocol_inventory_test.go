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
	"bufio"
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"

	"github.com/google/agentmesh/api"
)

// Every protocol a started node registers on its libp2p host belongs to
// exactly one of these sets. A protocol in none of them fails
// TestNodeProtocolInventoryIsClassified: whoever adds a stream handler has to
// say here how an unauthenticated peer is kept out of it, and the gated set
// is then checked live, not by reading the code.
var (
	// handshakeProtocols are the only protocols open to a peer that has not
	// authenticated: what the handshake itself needs (identify, the mesh
	// handshake) and libp2p's own reachability plumbing. Nothing here reads
	// mesh data.
	handshakeProtocols = []protocol.ID{
		api.AuthProtocolID,
		identify.ID,
		identify.IDPush,
		ping.ID,
		autonatv2.DialProtocol,
		autonatv2.DialBackProtocol,
		circuit.ProtoIDv2Stop,
	}

	// credentialProtocols authenticate inside the stream: the first frame or
	// request carries a Biscuit, and the handler refuses the stream itself
	// when it does not verify. Each has its own test of that refusal.
	credentialProtocols = []protocol.ID{
		api.MCPProtocolID,
		api.GoAwayProtocolID,
		"/libp2p-http",
	}

	// gatedProtocols are served through meshHost or routerHost: a stream from
	// a peer that has not completed the handshake is reset and counted before
	// the handler sees it. The test below opens each one from a stranger and
	// checks exactly that.
	gatedProtocols = []protocol.ID{
		api.IngressProtocolID,
		pubsub.FloodSubID,
		api.DHTProtocolID,
	}
)

func TestNodeProtocolInventoryIsClassified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	r := newFakeRouter(t, "/ip4/127.0.0.1/tcp/0")
	node := r.startNode(t, ctx, r.routerAddrs)

	registered := node.Host.Mux().Protocols()
	slices.Sort(registered)
	var unclassified []protocol.ID
	var gated []protocol.ID
	for _, p := range registered {
		switch {
		case slices.Contains(handshakeProtocols, p), slices.Contains(credentialProtocols, p):
		case slices.Contains(gatedProtocols, p):
			gated = append(gated, p)
		default:
			unclassified = append(unclassified, p)
		}
	}
	if len(unclassified) > 0 {
		t.Fatalf("node registers protocols that no set in protocol_inventory_test.go names: %v\n"+
			"Add each to handshakeProtocols (open before the handshake, nothing else may be), "+
			"credentialProtocols (the handler verifies a Biscuit in the stream) or "+
			"gatedProtocols (registered through meshHost/routerHost).", unclassified)
	}
	if !slices.Contains(gated, api.IngressProtocolID) {
		t.Fatalf("%s is not registered on a started node; registered: %v", api.IngressProtocolID, registered)
	}

	stranger, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stranger.Close() })
	if err := stranger.Connect(ctx, peer.AddrInfo{ID: node.Host.ID(), Addrs: node.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	for _, p := range gated {
		t.Run(string(p), func(t *testing.T) {
			before := counterValue(t, streamsRefusedTotal.WithLabelValues(streamScopeUnauthenticated, string(p)))

			s, err := stranger.NewStream(ctx, node.Host.ID(), p)
			if err != nil {
				t.Fatalf("open %s: %v", p, err)
			}
			defer func() { _ = s.Reset() }()
			if _, err := s.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
				t.Fatalf("write: %v", err)
			}
			// The gate holds the stream for the handshake; nothing may come
			// back meanwhile, whatever the handler behind it would answer.
			buf := make([]byte, 64)
			_ = s.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n, err := s.Read(buf); err == nil {
				t.Fatalf("%s answered %q to a peer that never authenticated", p, buf[:n])
			}

			// Dropping the connection ends the wait: the gate refuses the
			// stream and counts it under this protocol.
			if err := stranger.Network().ClosePeer(node.Host.ID()); err != nil {
				t.Fatal(err)
			}
			waitForCounter(t, func() float64 {
				return counterValue(t, streamsRefusedTotal.WithLabelValues(streamScopeUnauthenticated, string(p)))
			}, before+1, 5*time.Second)

			if err := stranger.Connect(ctx, peer.AddrInfo{ID: node.Host.ID(), Addrs: node.Host.Addrs()}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// /mesh/ingress/1.0.0 is served only to a router. A member that completed
// the handshake with the node is still refused at the gate, before the HTTP
// server behind it reads a byte, and counted; a peer admitted as a router
// reaches the handler.
func TestExternalIngressProtocolServesOnlyRouters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	r := newFakeRouter(t, "/ip4/127.0.0.1/tcp/0")
	node := r.startNode(t, ctx, r.routerAddrs)

	request := "GET /a2a/assistant/.well-known/agent-card.json HTTP/1.1\r\nHost: mesh\r\n\r\n"

	t.Run("member is refused at the gate", func(t *testing.T) {
		member := newAdmittedPeer(t, ctx, node, r, api.RoleNode)
		if !node.isAdmitted(member.ID()) || node.isAdmittedRouter(member.ID()) {
			t.Fatalf("member admitted=%v router=%v, want true/false", node.isAdmitted(member.ID()), node.isAdmittedRouter(member.ID()))
		}
		before := counterValue(t, streamsRefusedTotal.WithLabelValues(streamScopeNotRouter, string(api.IngressProtocolID)))

		s, err := member.NewStream(ctx, node.Host.ID(), api.IngressProtocolID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Reset() }()
		if _, err := s.Write([]byte(request)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := s.Read(buf); err == nil {
			t.Fatalf("ingress protocol answered a member %q; the gate must reset the stream", buf[:n])
		}
		waitForCounter(t, func() float64 {
			return counterValue(t, streamsRefusedTotal.WithLabelValues(streamScopeNotRouter, string(api.IngressProtocolID)))
		}, before+1, 5*time.Second)
	})

	t.Run("router reaches the handler", func(t *testing.T) {
		router := newAdmittedPeer(t, ctx, node, r, api.RoleRouter)
		if !node.isAdmittedRouter(router.ID()) {
			t.Fatal("peer admitted with the router role is not recorded as a router")
		}

		s, err := router.NewStream(ctx, node.Host.ID(), api.IngressProtocolID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		if _, err := s.Write([]byte(request)); err != nil {
			t.Fatal(err)
		}
		_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(s), nil)
		if err != nil {
			t.Fatalf("read HTTP response from ingress handler: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		// The handler ran: with no X-Mesh-Biscuit it refuses the request
		// itself, which is the second layer behind the gate.
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d from the handler's own credential check", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("ban withdraws router standing", func(t *testing.T) {
		router := newAdmittedPeer(t, ctx, node, r, api.RoleRouter)
		node.banPeer(router.ID(), time.Now().UnixMilli())
		if node.isAdmitted(router.ID()) || node.isAdmittedRouter(router.ID()) {
			t.Fatal("banned peer still admitted")
		}
	})
}

// newAdmittedPeer is a libp2p host that connects to node and completes the
// mesh handshake with a credential the fake router's control plane key signed
// for the given role.
func newAdmittedPeer(t *testing.T, ctx context.Context, node *AgentMeshNode, r *fakeRouter, role string) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.Connect(ctx, peer.AddrInfo{ID: node.Host.ID(), Addrs: node.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	s, err := h.NewStream(ctx, node.Host.ID(), api.AuthProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	frame, err := proto.Marshal(&api.AuthFrame{Biscuit: r.mint(h.ID().String(), role)})
	if err != nil {
		t.Fatal(err)
	}
	if err := msgio.NewVarintWriter(s).WriteMsg(frame); err != nil {
		t.Fatal(err)
	}
	reply, err := msgio.NewVarintReaderSize(s, 1024*64).ReadMsg()
	if err != nil {
		t.Fatalf("handshake reply: %v", err)
	}
	var resp api.AuthResponse
	if err := proto.Unmarshal(reply, &resp); err != nil || !resp.Success {
		t.Fatalf("handshake refused: %v %s", err, resp.GetError())
	}
	return h
}

// waitForCounter polls get until it reaches want, and reports the last value
// it saw if the deadline passes first.
func waitForCounter(t *testing.T, get func() float64, want float64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var got float64
	for time.Now().Before(deadline) {
		got = get()
		if got >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("counter = %v, want %v", got, want)
}
