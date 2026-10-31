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
	"slices"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/p2plimits"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/protocol"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
)

// memberProtocols are the protocols on which every member holds a stream
// open to its router for as long as it is connected (the DHT keeps one
// request stream per peer, gossip one per direction) or opens one when it
// joins. libp2p's default for a protocol it was not told about is a few
// hundred inbound streams in all, scaled from host memory: on the testnet it
// was 768, and the 769th member's DHT and gossip streams were refused, which
// kept the router out of that member's routing table and the member out of
// discovery (libp2p_rcmgr_blocked_resources{scope="protocol"} counted them,
// without saying which protocol).
var memberProtocols = slices.Concat(
	[]protocol.ID{identify.ID, identify.IDPush, api.AuthProtocolID, api.DHTProtocolID, api.DirectoryProtocolID},
	pubsub.GossipSubDefaultProtocols,
)

// connCapHeadroom is the resource manager's connection cap as a multiple of
// the high watermark.
const connCapHeadroom = 2

// hubLimits returns the libp2p resource limits for a router, sized from the
// connection budget rather than from host memory. libp2p's defaults are for
// a leaf peer that talks to a few dozen others and scale with the memory of
// the machine: a router on a 1 GB VM got 1024 inbound streams in all, 64 for
// identify and 64 relayed connections per peer, and refused the handshakes
// of a joining fleet (libp2p_rcmgr_blocked_resources counts them). A router
// is a hub: every member holds a connection and, on it, a few long-lived
// streams (gossip, its relay reservation) and a burst of short ones when it
// joins (identify, the auth handshake, DHT), and a service many members
// call holds one relayed connection per caller.
//
// highWaterMark is the member count the router sheds at and conns the
// inbound connection budget per source address, both from Options; circuits
// is the relayed connections one peer may hold. The connection caps sit
// above the watermark: the connection manager trims and the router sheds
// members between the watermark and the cap, and the manager refuses only
// what neither has handled yet. A cap at the watermark refused members
// while the router still counted itself below it.
func hubLimits(highWaterMark, conns, circuits int) rcmgr.ConcreteLimitConfig {
	limits := rcmgr.DefaultLimits
	libp2p.SetDefaultServiceLimits(&limits)
	scaled := limits.AutoScale()

	sysBase := max(conns, highWaterMark, DefaultHighWaterMark)
	connCap := connCapHeadroom * sysBase
	// Streams per member on the scopes that see every member.
	const streamsPerConn = 8
	streams := p2plimits.Streams
	system := streams(streamsPerConn * connCap)
	system.Conns = rcmgr.LimitVal(2 * connCap)
	system.ConnsInbound = rcmgr.LimitVal(connCap)
	system.FD = rcmgr.LimitVal(2 * connCap)
	transient := streams(sysBase)
	transient.Conns = rcmgr.LimitVal(sysBase)
	transient.ConnsInbound = rcmgr.LimitVal(sysBase)
	transient.FD = rcmgr.LimitVal(sysBase)

	// A relayed connection is one hop stream from the caller and one stop
	// stream to the destination, both held while it lasts; the memory the
	// relay reserves per connection is a few KiB on each, on top of the
	// streams' windows.
	relayStreams := streams(sysBase)
	perPeerCircuits := streams(circuits)

	protocols := map[protocol.ID]rcmgr.ResourceLimits{
		circuit.ProtoIDv2Hop:  relayStreams,
		circuit.ProtoIDv2Stop: relayStreams,
		api.IngressProtocolID: streams(connCap),
	}
	// Every connection, not every member: a member attached elsewhere holds
	// a connection here for its DHT queries, with a DHT stream and gossip
	// streams on it, and at 10,000 members the testnet's routers carried
	// 9,000 connections each for 3,600 members. The connection cap is what
	// bounds those streams.
	for _, p := range memberProtocols {
		protocols[p] = streams(connCap)
	}

	overrides := rcmgr.PartialLimitConfig{
		System:    system,
		Transient: transient,
		// The peer scope for a service many members call carries one stop
		// stream per relayed caller, up to the per-peer circuit budget.
		PeerDefault: perPeerCircuits,
		Service: map[string]rcmgr.ResourceLimits{
			identify.ServiceName: streams(connCap),
			relay.ServiceName:    relayStreams,
		},
		ServicePeer: map[string]rcmgr.ResourceLimits{
			relay.ServiceName: perPeerCircuits,
		},
		Protocol: protocols,
		ProtocolPeer: map[protocol.ID]rcmgr.ResourceLimits{
			circuit.ProtoIDv2Hop:  perPeerCircuits,
			circuit.ProtoIDv2Stop: perPeerCircuits,
			api.IngressProtocolID: perPeerCircuits,
		},
	}
	return overrides.Build(scaled)
}
