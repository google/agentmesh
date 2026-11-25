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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/test"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}

// The busiest connection per transport is a gauge, and a QUIC connection
// near its stream limit is named once per interval: a relay's connection
// to a service holds one stream per relayed caller, and the 257th caller
// over QUIC waits with no error at either end.
func TestStreamPressureNamesAQUICConnectionNearItsLimit(t *testing.T) {
	relay, other := test.RandPeerIDFatal(t), test.RandPeerIDFatal(t)
	loads := []connLoad{
		{peer: relay, transport: TransportQUIC, streams: 240},
		{peer: other, transport: TransportQUIC, streams: 3},
		{peer: test.RandPeerIDFatal(t), transport: "tcp", streams: 500},
	}
	busiest := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_busiest"}, []string{"transport"})
	var lines []string
	now := time.Unix(1_700_000_000, 0)
	p := ObserveStreamPressure(func() []network.Conn { return nil }, busiest, func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	p.SetClock(func() time.Time { return now })

	p.observe(loads)
	if got := gaugeValue(t, busiest.WithLabelValues(TransportQUIC)); got != 240 {
		t.Errorf("busiest quic = %v, want 240", got)
	}
	if got := gaugeValue(t, busiest.WithLabelValues("tcp")); got != 500 {
		t.Errorf("busiest tcp = %v, want 500: tcp has no stream limit, the gauge still shows the load", got)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], relay.String()) || !strings.Contains(lines[0], "240 streams of the 256") {
		t.Fatalf("warnings = %q, want one naming the relay's connection", lines)
	}

	// Still loaded a sample later: not repeated within the interval.
	p.observe(loads)
	if len(lines) != 1 {
		t.Errorf("warned again within the interval: %q", lines)
	}
	now = now.Add(RefusalLogInterval)
	p.observe(loads)
	if len(lines) != 2 {
		t.Errorf("not warned again after the interval: %q", lines)
	}

	// Below the threshold nothing is said, and a peer that is quiet for an
	// interval is forgotten.
	now = now.Add(RefusalLogInterval)
	p.observe([]connLoad{{peer: relay, transport: TransportQUIC, streams: 10}})
	if len(lines) != 2 {
		t.Errorf("warned for a connection under the threshold: %q", lines[len(lines)-1])
	}
	if got := gaugeValue(t, busiest.WithLabelValues(TransportQUIC)); got != 10 {
		t.Errorf("busiest quic after the load left = %v, want 10", got)
	}
	if n := len(p.lastLogAt); n != 0 {
		t.Errorf("peers remembered after an interval of quiet = %d, want 0", n)
	}
}

// A transport other than QUIC and TCP (the router listens on WebSocket,
// WebTransport and WebRTC) falls back to 0 once its last connection is
// gone, instead of keeping the closed connection's count.
func TestStreamPressureClearsATransportWithNoConnectionLeft(t *testing.T) {
	busiest := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_busiest"}, []string{"transport"})
	p := ObserveStreamPressure(func() []network.Conn { return nil }, busiest, nil)
	transports := []string{"websocket", "webtransport", "webrtc-direct"}

	var loads []connLoad
	for _, transport := range transports {
		loads = append(loads, connLoad{peer: test.RandPeerIDFatal(t), transport: transport, streams: 7})
	}
	p.observe(loads)
	for _, transport := range transports {
		if got := gaugeValue(t, busiest.WithLabelValues(transport)); got != 7 {
			t.Errorf("busiest %s with one connection of 7 streams = %v, want 7", transport, got)
		}
	}

	p.observe(nil)
	for _, transport := range transports {
		if got := gaugeValue(t, busiest.WithLabelValues(transport)); got != 0 {
			t.Errorf("busiest %s after its last connection closed = %v, want 0", transport, got)
		}
	}
}
