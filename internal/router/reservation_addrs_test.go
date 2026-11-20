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

package router

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/multiformats/go-multiaddr"
)

// A member that reserved with a router is reached through it, and a DHT
// lookup for the member that reaches that router must say so: the member
// told its other routers through identify, but identify ran here before
// the reservation, and an SDK member listens on nothing else. The router
// records the circuit address through itself when it grants the
// reservation, and a peer that queries it finds the member there.
func TestRouterRecordsWhereAReservedMemberIsReached(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	relayHost := newLoopbackHost(t, libp2p.DisableRelay())
	r := &Router{Host: relayHost, config: Options{AllowLoopback: true}}
	if _, err := relay.New(relayHost, relay.WithACL(&relayACL{r: r})); err != nil {
		t.Fatal(err)
	}
	routerDHT, err := dht.New(relayHost, dht.Mode(dht.ModeServer), dht.ProtocolPrefix(api.DHTProtocolPrefix))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = routerDHT.Close() }()
	relayInfo := peer.AddrInfo{ID: relayHost.ID(), Addrs: relayHost.Addrs()}

	// Like an SDK member: dials out, listens on nothing.
	member, err := libp2p.New(libp2p.EnableRelay(), libp2p.NoListenAddrs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = member.Close() }()
	if err := member.Connect(ctx, relayInfo); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Reserve(ctx, member, relayInfo); err == nil {
		t.Fatal("a reservation was granted before the member authenticated")
	}
	if got := relayHost.Peerstore().Addrs(member.ID()); slices.ContainsFunc(got, hasCircuit) {
		t.Fatalf("a refused reservation left a circuit address: %v", got)
	}

	r.authenticatedPeers.Store(member.ID(), true)
	if _, err := client.Reserve(ctx, member, relayInfo); err != nil {
		t.Fatal(err)
	}
	want := relayHost.Addrs()[0].String() + "/p2p/" + relayHost.ID().String() + "/p2p-circuit"
	got := relayHost.Peerstore().Addrs(member.ID())
	if !slices.ContainsFunc(got, func(ma multiaddr.Multiaddr) bool { return ma.String() == want }) {
		t.Fatalf("router records %v for the member, want %s among them", got, want)
	}

	// A peer whose lookup reaches the router learns the address. kad-dht
	// answers FindPeer with "not found" for a peer it could not dial during
	// the lookup, which this caller cannot (it has no relay transport), but
	// the lookup leaves what it learned in the caller's peerstore, and the
	// node reads that; see preparePeerAddrs.
	caller := newLoopbackHost(t, libp2p.DisableRelay())
	callerDHT, err := dht.New(caller, dht.Mode(dht.ModeClient), dht.ProtocolPrefix(api.DHTProtocolPrefix))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = callerDHT.Close() }()
	if err := caller.Connect(ctx, relayInfo); err != nil {
		t.Fatal(err)
	}
	for callerDHT.RoutingTable().Size() == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("the router never entered the caller's routing table")
		case <-time.After(20 * time.Millisecond):
		}
	}
	_, _ = callerDHT.FindPeer(ctx, member.ID())
	learned := caller.Peerstore().Addrs(member.ID())
	if len(learned) != 1 || learned[0].String() != want {
		t.Errorf("the lookup left %v in the caller's peerstore, want [%s]", learned, want)
	}

	// The address leaves with the member.
	r.forgetPeer(member.ID())
	if got := relayHost.Peerstore().Addrs(member.ID()); slices.ContainsFunc(got, hasCircuit) {
		t.Errorf("a forgotten member still has a circuit address: %v", got)
	}
}

func hasCircuit(ma multiaddr.Multiaddr) bool {
	return strings.HasSuffix(ma.String(), "/p2p-circuit")
}

// The circuit addresses follow the lease: the --external-addr addresses plus
// the WebTransport address of the QUIC one. A malformed --external-addr fails
// at start instead of disappearing from the lease.
func TestRouterCircuitAddrsFollowTheExternalAddrs(t *testing.T) {
	h, webTransport := newWebTransportHost(t)
	r := &Router{Host: h, config: Options{ExternalAddrs: []string{"/dns4/router.example/tcp/4501", "/ip4/203.0.113.9/udp/4501/quic-v1"}}}
	var got []string
	for _, ma := range r.circuitAddrs() {
		got = append(got, ma.String())
	}
	suffix := "/p2p/" + h.ID().String() + "/p2p-circuit"
	want := []string{"/dns4/router.example/tcp/4501" + suffix, "/ip4/203.0.113.9/udp/4501/quic-v1" + suffix, "/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport + suffix}
	if !slices.Equal(got, want) {
		t.Errorf("circuitAddrs = %v, want %v", got, want)
	}

	o := Options{ControlPlaneURL: "http://127.0.0.1:8080", ExternalAddrs: []string{"203.0.113.9:4501"}}
	o.Default()
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "external address") {
		t.Fatalf("malformed external address: err = %v, want rejection", err)
	}
}
