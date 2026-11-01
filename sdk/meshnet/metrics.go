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
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/prometheus/client_golang/prometheus"
)

type serverMetrics struct {
	reg              prometheus.Registerer
	stateCollector   *serverStateCollector
	streamsRefused   *prometheus.CounterVec
	credentialLapses prometheus.Counter
}

func newServerMetrics(s *Server, reg prometheus.Registerer) (*serverMetrics, error) {
	wrapped := prometheus.WrapRegistererWith(prometheus.Labels{"peer_id": s.peerID.String()}, reg)
	sc := newServerStateCollector(s)
	refused := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentmesh_meshnet_streams_refused_total",
		Help: "Inbound libp2p streams refused by the auth gate on this embedded Server, by scope and protocol.",
	}, []string{"scope", "protocol"})
	lapses := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "agentmesh_meshnet_credential_lapses_total",
		Help: "Failed background renewal attempts while this embedded Server's credential is expired.",
	})

	var registered []prometheus.Collector
	for _, c := range []prometheus.Collector{sc, refused, lapses} {
		if err := wrapped.Register(c); err != nil {
			for _, prev := range registered {
				wrapped.Unregister(prev)
			}
			return nil, err
		}
		registered = append(registered, c)
	}
	return &serverMetrics{
		reg:              wrapped,
		stateCollector:   sc,
		streamsRefused:   refused,
		credentialLapses: lapses,
	}, nil
}

func (m *serverMetrics) unregister() {
	if m == nil || m.reg == nil {
		return
	}
	m.reg.Unregister(m.stateCollector)
	m.reg.Unregister(m.streamsRefused)
	m.reg.Unregister(m.credentialLapses)
}

type serverStateCollector struct {
	s               *Server
	ready           *prometheus.Desc
	connectedPeers  *prometheus.Desc
	routers         *prometheus.Desc
	services        *prometheus.Desc
	biscuitExpiry   *prometheus.Desc
	credentialLapse *prometheus.Desc
}

func newServerStateCollector(s *Server) *serverStateCollector {
	return &serverStateCollector{
		s: s,
		ready: prometheus.NewDesc(
			"agentmesh_meshnet_ready",
			"1 when this embedded Server is connected to at least one router with an unexpired credential, 0 otherwise.",
			nil, nil,
		),
		connectedPeers: prometheus.NewDesc(
			"agentmesh_meshnet_connected_peers",
			"Libp2p peers with an open connection to this embedded Server.",
			nil, nil,
		),
		routers: prometheus.NewDesc(
			"agentmesh_meshnet_routers",
			"Routers tracked by this embedded Server, by state.",
			[]string{"state"}, nil,
		),
		services: prometheus.NewDesc(
			"agentmesh_meshnet_services_registered",
			"Local services registered on this embedded Server.",
			nil, nil,
		),
		biscuitExpiry: prometheus.NewDesc(
			"agentmesh_meshnet_biscuit_expiry_timestamp_seconds",
			"Unix timestamp when this embedded Server's current Biscuit credential expires.",
			nil, nil,
		),
		credentialLapse: prometheus.NewDesc(
			"agentmesh_meshnet_credential_lapsed",
			"1 when this embedded Server's credential has expired and renewal failed, 0 otherwise.",
			nil, nil,
		),
	}
}

func (c *serverStateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.ready
	ch <- c.connectedPeers
	ch <- c.routers
	ch <- c.services
	ch <- c.biscuitExpiry
	ch <- c.credentialLapse
}

func (c *serverStateCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.s
	var readyVal, peersVal, attachedVal, servicesVal, lapsedVal float64
	if s.credentialLapsed.Load() {
		lapsedVal = 1
	}
	if s.node != nil && s.node.Host != nil {
		peersVal = float64(len(s.node.Host.Network().Peers()))
		attachedVal = float64(len(s.node.AttachedRouterIDs()))
		if s.node.IsConnected() && lapsedVal == 0 {
			readyVal = 1
		}
		if s.node.Services() != nil {
			servicesVal = float64(len(s.node.ListLocalServices(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)))
		}
	}

	ch <- prometheus.MustNewConstMetric(c.ready, prometheus.GaugeValue, readyVal)
	ch <- prometheus.MustNewConstMetric(c.connectedPeers, prometheus.GaugeValue, peersVal)
	ch <- prometheus.MustNewConstMetric(c.routers, prometheus.GaugeValue, attachedVal, "attached")
	ch <- prometheus.MustNewConstMetric(c.services, prometheus.GaugeValue, servicesVal)
	ch <- prometheus.MustNewConstMetric(c.credentialLapse, prometheus.GaugeValue, lapsedVal)
	if exp := s.credentialExpireTime(); !exp.IsZero() {
		ch <- prometheus.MustNewConstMetric(c.biscuitExpiry, prometheus.GaugeValue, float64(exp.Unix()))
	}
}

func (s *Server) onStreamRefused(scope, proto string) {
	key := scope + "|" + proto
	s.refusedMu.Lock()
	if s.refusedStreams == nil {
		s.refusedStreams = make(map[string]uint64)
	}
	s.refusedStreams[key]++
	s.refusedMu.Unlock()
	if s.metrics != nil {
		s.metrics.streamsRefused.WithLabelValues(scope, proto).Inc()
	}
}

func (s *Server) refusedStreamCount(scope string, proto protocol.ID) uint64 {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	return s.refusedStreams[scope+"|"+string(proto)]
}
