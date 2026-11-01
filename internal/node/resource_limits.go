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
	"slices"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/p2plimits"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The node's connection budget: the connection manager trims down to the
// low watermark once the high one is passed, and the resource manager
// refuses past the high one. A node that publishes a service is called by
// many members, each over a connection of its own, so the budget is sized
// for a provider rather than for a leaf that talks to a few peers.
const (
	ConnLowWaterMark  = 100
	ConnHighWaterMark = 400
)

// ConnsPerSourceIP is how many inbound connections one source address may
// hold at once. Members share addresses (pod SNAT, Cloud NAT, an office, a
// fleet on one host), and libp2p's default of 8 made a provider refuse the
// ninth caller behind any of them with nothing in its logs or metrics.
var ConnsPerSourceIP = p2plimits.DefaultConnsPerSourceIP(ConnHighWaterMark)

var inboundRefusedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_node_inbound_connections_refused_total",
		Help: "Inbound connections the resource manager refused before the handshake, by reason",
	},
	[]string{"reason"},
)

func init() {
	for _, v := range p2plimits.Reasons {
		inboundRefusedTotal.WithLabelValues(v)
	}
}

// connsPerSourceIPDesc exports the cap in force, so a dashboard can read the
// refusal counter against it.
var connsPerSourceIPDesc = prometheus.NewDesc(
	"agentmesh_node_conns_per_source_ip_limit",
	"Inbound connections allowed from one source IP",
	nil, nil)

// nodeLimits returns the libp2p resource limits for a node, sized from its
// connection budget rather than from host memory. libp2p's defaults scale
// with the memory the process sees: a provider in a small container got 126
// inbound connections and 47 in handshake at once, and refused a fleet
// calling it. Each connection carries a few long-lived streams and a burst
// of short ones when a caller arrives (identify, the auth handshake, the
// call itself).
func nodeLimits(conns int) rcmgr.ConcreteLimitConfig {
	limits := rcmgr.DefaultLimits
	libp2p.SetDefaultServiceLimits(&limits)
	scaled := limits.AutoScale()

	const streamsPerConn = 8
	system := p2plimits.Streams(streamsPerConn * conns)
	system.Conns = rcmgr.LimitVal(2 * conns)
	system.ConnsInbound = rcmgr.LimitVal(conns)
	system.FD = rcmgr.LimitVal(2 * conns)
	transient := p2plimits.Streams(conns)
	transient.Conns = rcmgr.LimitVal(conns)
	transient.ConnsInbound = rcmgr.LimitVal(conns)
	transient.FD = rcmgr.LimitVal(conns)

	overrides := rcmgr.PartialLimitConfig{
		System:    system,
		Transient: transient,
		// The peer scope for a router carries one relay stop stream per
		// caller it relays, as many as the connection budget admits.
		PeerDefault: p2plimits.Streams(conns),
		Service: map[string]rcmgr.ResourceLimits{
			identify.ServiceName: p2plimits.Streams(conns),
		},
		Protocol: map[protocol.ID]rcmgr.ResourceLimits{},
	}
	// One stream per caller for as long as it is connected (its DHT request
	// stream, gossip), or one when it arrives; libp2p's default for a
	// protocol it was not told about scales from host memory. A caller holds
	// one MCP stream per session, so that protocol gets the per-connection
	// share of the system budget.
	for _, p := range slices.Concat(
		[]protocol.ID{identify.ID, identify.IDPush, api.AuthProtocolID, api.DHTProtocolID},
		pubsub.GossipSubDefaultProtocols,
	) {
		overrides.Protocol[p] = p2plimits.Streams(conns)
	}
	overrides.Protocol[api.MCPProtocolID] = p2plimits.Streams(streamsPerConn * conns)
	overrides.Protocol[api.IngressProtocolID] = p2plimits.Streams(streamsPerConn * conns)

	// A caller that arrives through a router is one relay stop stream, and
	// every caller through the same router is a stream from that one peer.
	// libp2p's default is 128 per peer, which capped a provider at 128
	// callers through each of its routers, so the stop protocol gets the
	// whole connection budget, per peer and in all.
	stop := p2plimits.Streams(conns)
	stop.Memory = rcmgr.LimitVal64(int64(conns) * 64 << 10)
	overrides.Protocol[circuit.ProtoIDv2Stop] = stop
	overrides.ProtocolPeer = map[protocol.ID]rcmgr.ResourceLimits{
		circuit.ProtoIDv2Stop: stop,
		api.IngressProtocolID: p2plimits.Streams(conns),
	}
	return overrides.Build(scaled)
}

var streamsRefusedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_node_streams_refused_total",
		Help: "Streams the resource manager refused, by scope and protocol (or service)",
	},
	[]string{"scope", "protocol"},
)

// memoryRefusedTotal counts the memory reservations the resource manager
// refused: the muxer's window for a new stream, among others.
var memoryRefusedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "agentmesh_node_memory_reservations_refused_total",
	Help: "Memory reservations the resource manager refused; a new stream that needed one was refused with it",
})

// busiestConnStreams is the most streams any one connection carries. On a
// provider the connection to a router carries one stream per caller
// relayed through it; a QUIC connection admits
// p2plimits.QUICStreamsPerConnection and the next caller waits.
var busiestConnStreams = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "agentmesh_node_busiest_connection_streams",
		Help: "Streams on the connection that carries the most, by transport; QUIC admits 256 per connection and a further stream waits",
	},
	[]string{"transport"},
)

// streamPressureInterval is how often connections are sampled for it.
const streamPressureInterval = 15 * time.Second

// newResourceManager is the resource manager the node's host runs with:
// nodeLimits, the per-source cap on direct callers, and every refusal
// counted and logged. A caller that arrives through a router is not
// charged to the router's address; see p2plimits.Observed.
func newResourceManager() (network.ResourceManager, error) {
	return p2plimits.New(nodeLimits(ConnHighWaterMark), ConnsPerSourceIP, inboundRefusedTotal, logger.Warnf,
		rcmgr.WithMetrics(p2plimits.CountStreamRefusals(streamsRefusedTotal, memoryRefusedTotal, logger.Warnf)))
}
