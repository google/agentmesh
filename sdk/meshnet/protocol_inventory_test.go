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
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/autonatv2"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

// Every protocol a started meshnet.Server registers on its libp2p host belongs
// to exactly one of these three sets (mirroring internal/node/protocol_inventory_test.go).
var (
	handshakeProtocols = []protocol.ID{
		api.AuthProtocolID,
		identify.ID,
		identify.IDPush,
		ping.ID,
		autonatv2.DialProtocol,
		autonatv2.DialBackProtocol,
		circuit.ProtoIDv2Stop,
	}

	credentialProtocols = []protocol.ID{
		api.MCPProtocolID,
		api.GoAwayProtocolID,
		"/libp2p-http",
	}

	gatedProtocols = []protocol.ID{
		api.IngressProtocolID,
		pubsub.FloodSubID,
		api.DHTProtocolID,
	}
)

func TestServerProtocolInventoryIsClassified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env := newStartedTestServer(t, ctx)
	s := env.server
	h := s.node.Host

	registered := h.Mux().Protocols()
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
		t.Fatalf("meshnet.Server registers unclassified protocols: %v\n"+
			"Classify each into handshakeProtocols, credentialProtocols, or gatedProtocols.", unclassified)
	}
	if !slices.Contains(gated, api.IngressProtocolID) {
		t.Fatalf("%s is not registered on a started Server; registered: %v", api.IngressProtocolID, registered)
	}

	stranger, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stranger.Close() })
	if err := stranger.Connect(ctx, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()}); err != nil {
		t.Fatal(err)
	}

	for _, p := range gated {
		t.Run(string(p), func(t *testing.T) {
			before := s.node.RefusedStreamCount("unauthenticated", p)

			st, err := stranger.NewStream(ctx, h.ID(), p)
			if err != nil {
				t.Fatalf("open %s: %v", p, err)
			}
			defer func() { _ = st.Reset() }()
			if _, err := st.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 64)
			_ = st.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n, err := st.Read(buf); err == nil {
				t.Fatalf("%s answered %q to an unauthenticated peer", p, buf[:n])
			}

			if err := stranger.Network().ClosePeer(h.ID()); err != nil {
				t.Fatal(err)
			}
			waitForCount(t, func() uint64 {
				return s.node.RefusedStreamCount("unauthenticated", p)
			}, before+1, 5*time.Second)

			if err := stranger.Connect(ctx, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExternalIngressProtocolServesOnlyRouters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env := newStartedTestServer(t, ctx)
	s := env.server
	h := s.node.Host

	request := "GET /a2a/assistant/.well-known/agent-card.json HTTP/1.1\r\nHost: mesh\r\n\r\n"

	t.Run("member_is_refused_at_the_gate", func(t *testing.T) {
		member := newAdmittedTestPeer(t, ctx, s, env.cpPriv, api.RoleNode)
		if !s.node.IsAdmitted(member.ID()) || s.node.IsAdmittedRouter(member.ID()) {
			t.Fatalf("member admitted=%v router=%v, want true/false", s.node.IsAdmitted(member.ID()), s.node.IsAdmittedRouter(member.ID()))
		}
		before := s.node.RefusedStreamCount("not_router", api.IngressProtocolID)

		st, err := member.NewStream(ctx, h.ID(), api.IngressProtocolID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = st.Reset() }()
		if _, err := st.Write([]byte(request)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := st.Read(buf); err == nil {
			t.Fatalf("ingress protocol answered a non-router member %q; gate must reset stream", buf[:n])
		}
		waitForCount(t, func() uint64 {
			return s.node.RefusedStreamCount("not_router", api.IngressProtocolID)
		}, before+1, 5*time.Second)
	})

	t.Run("router_reaches_the_handler", func(t *testing.T) {
		router := newAdmittedTestPeer(t, ctx, s, env.cpPriv, api.RoleRouter)
		if !s.node.IsAdmittedRouter(router.ID()) {
			t.Fatal("peer admitted with RoleRouter is not recorded as a router")
		}

		st, err := router.NewStream(ctx, h.ID(), api.IngressProtocolID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = st.Close() }()
		if _, err := st.Write([]byte(request)); err != nil {
			t.Fatal(err)
		}
		_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(st), nil)
		if err != nil {
			t.Fatalf("read HTTP response from ingress handler: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d from handler's own credential check", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("ban_withdraws_router_standing", func(t *testing.T) {
		router := newAdmittedTestPeer(t, ctx, s, env.cpPriv, api.RoleRouter)
		s.node.BanPeer(router.ID(), time.Now().UnixMilli())
		if s.node.IsAdmitted(router.ID()) || s.node.IsAdmittedRouter(router.ID()) {
			t.Fatal("banned peer still admitted")
		}
	})
}

type startedTestEnv struct {
	cpPub      ed25519.PublicKey
	cpPriv     ed25519.PrivateKey
	routerHost host.Host
	cp         *fakeControlPlaneHTTP
	server     *Server
}

func newStartedTestServer(t *testing.T, ctx context.Context) *startedTestEnv {
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
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		var req api.DirectoryRequest
		_ = proto.Unmarshal(msg, &req)
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.DirectoryResponse{})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})

	var routerAddrs []string
	for _, a := range rh.Addrs() {
		routerAddrs = append(routerAddrs, a.String()+"/p2p/"+rh.ID().String())
	}

	cp := newFakeControlPlaneHTTPWithKeys(t, cpPub, cpPriv, routerAddrs)
	s := &Server{
		StateDir:        t.TempDir(),
		ControlPlaneURL: cp.srv.URL,
		BootstrapToken:  "boot-secret",
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
	}
	upSt, err := s.Up(ctx)
	if err != nil {
		t.Fatalf("Server.Up: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	st := s.Status()
	if upSt.PeerID == "" || st.PeerID == "" || len(st.AttachedRouters) < 1 {
		t.Fatalf("unexpected Status after Up: %+v", st)
	}

	return &startedTestEnv{
		cpPub:      cpPub,
		cpPriv:     cpPriv,
		routerHost: rh,
		cp:         cp,
		server:     s,
	}
}

func newAdmittedTestPeer(t *testing.T, ctx context.Context, s *Server, cpPriv ed25519.PrivateKey, role string) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.Connect(ctx, peer.AddrInfo{ID: s.node.Host.ID(), Addrs: s.node.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	st, err := h.NewStream(ctx, s.node.Host.ID(), api.AuthProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	frame, err := proto.Marshal(&api.AuthFrame{
		Biscuit: mintTestBiscuit(t, cpPriv, h.ID().String(), role, time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := msgio.NewVarintWriter(st).WriteMsg(frame); err != nil {
		t.Fatal(err)
	}
	reply, err := msgio.NewVarintReaderSize(st, 64*1024).ReadMsg()
	if err != nil {
		t.Fatalf("handshake reply: %v", err)
	}
	var resp api.AuthResponse
	if err := proto.Unmarshal(reply, &resp); err != nil || !resp.Success {
		t.Fatalf("handshake refused: %v %s", err, resp.GetError())
	}
	return h
}

func waitForCount(t *testing.T, get func() uint64, want uint64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var got uint64
	for time.Now().Before(deadline) {
		got = get()
		if got >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("counter = %d, want >= %d", got, want)
}
