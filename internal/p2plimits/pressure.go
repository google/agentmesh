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

package p2plimits

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
)

// QUICStreamsPerConnection is how many streams the far end may hold open on
// one QUIC connection, as go-libp2p configures quic-go; a stream opened
// past it waits for one to close, with no error at either end. yamux over
// TCP has no limit of its own; the resource manager's are the only ones.
// Every relayed connection to a peer is one stream on the relay's
// connection to it, so a service called through a router has at most this
// many relayed callers through it over QUIC.
const QUICStreamsPerConnection = 256

// StreamPressureWarnAt is the stream count at which a QUIC connection is
// reported: nine tenths of what it admits.
const StreamPressureWarnAt = QUICStreamsPerConnection * 9 / 10

// TransportQUIC is the transport name libp2p gives a QUIC connection;
// WebTransport runs over QUIC with the same stream limit.
const TransportQUIC = "quic-v1"

// quicTransports are the transports with QUIC's per-connection stream limit.
var quicTransports = map[string]bool{TransportQUIC: true, "quic": true, "webtransport": true}

// StreamPressure reports the connection of a host that carries the most
// streams, by transport, and warns once per peer per RefusalLogInterval when
// a QUIC connection is within reach of its stream limit: the next stream
// between the two waits, which a relay turns into a hop that hangs until
// its connect timeout and a caller into a dial that times out, neither of
// which says why.
type StreamPressure struct {
	conns     func() []network.Conn
	busiest   *prometheus.GaugeVec
	warnf     func(format string, args ...any)
	mu        sync.Mutex
	lastLogAt map[peer.ID]time.Time
	now       func() time.Time
	// reported are the transports busiest has a value for.
	reported map[string]bool
}

// connLoad is what the sampler reads off a connection.
type connLoad struct {
	peer      peer.ID
	transport string
	streams   int
}

// ObserveStreamPressure returns a sampler over conns. busiest carries the
// label transport; a nil warnf only samples.
func ObserveStreamPressure(conns func() []network.Conn, busiest *prometheus.GaugeVec, warnf func(format string, args ...any)) *StreamPressure {
	if warnf == nil {
		warnf = func(string, ...any) {}
	}
	return &StreamPressure{conns: conns, busiest: busiest, warnf: warnf, lastLogAt: map[peer.ID]time.Time{}, now: time.Now, reported: map[string]bool{}}
}

// SetClock replaces the clock the log limiter reads; for tests.
func (p *StreamPressure) SetClock(now func() time.Time) { p.now = now }

// Run samples every interval until ctx ends.
func (p *StreamPressure) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Sample()
		}
	}
}

// Sample reads every connection once.
func (p *StreamPressure) Sample() {
	conns := p.conns()
	loads := make([]connLoad, 0, len(conns))
	for _, c := range conns {
		loads = append(loads, connLoad{peer: c.RemotePeer(), transport: c.ConnState().Transport, streams: c.Stat().NumStreams})
	}
	p.observe(loads)
}

func (p *StreamPressure) observe(loads []connLoad) {
	// Relayed connections are streams on a transport connection already
	// counted; they carry one stream each and have no limit of their own.
	busiest := map[string]int{TransportQUIC: 0, "tcp": 0}
	p.mu.Lock()
	// A transport reported before falls back to 0 when its last connection
	// is gone, rather than keep the closed connection's count.
	for transport := range p.reported {
		busiest[transport] = 0
	}
	for _, l := range loads {
		if l.transport == "p2p-circuit" {
			continue
		}
		if l.streams > busiest[l.transport] {
			busiest[l.transport] = l.streams
		}
	}
	for transport, n := range busiest {
		p.reported[transport] = true
		p.busiest.WithLabelValues(transport).Set(float64(n))
	}

	threshold := StreamPressureWarnAt
	now := p.now()
	for k, t := range p.lastLogAt {
		if now.Sub(t) >= RefusalLogInterval {
			delete(p.lastLogAt, k)
		}
	}
	var report []connLoad
	for _, l := range loads {
		if !quicTransports[l.transport] || l.streams < threshold {
			continue
		}
		if _, recent := p.lastLogAt[l.peer]; recent {
			continue
		}
		p.lastLogAt[l.peer] = now
		report = append(report, l)
	}
	p.mu.Unlock()
	for _, l := range report {
		p.warnf("[Conn] Connection to %s over %s carries %d streams of the %d QUIC admits per connection; a further stream between the two waits for one to close, which a relayed connection shows as a dial that times out", l.peer, l.transport, l.streams, QUICStreamsPerConnection)
	}
}
