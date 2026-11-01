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
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/google/agentmesh/api"
)

// Outcomes of an inbound /mesh/auth handshake.
const (
	handshakeOK           = "ok"
	handshakeBanned       = "banned"
	handshakeRateLimited  = "rate_limited"
	handshakeReadFailed   = "read_failed"
	handshakeInvalidFrame = "invalid_frame"
	handshakeUnauthorized = "unauthorized"
)

// Outcomes of a control-plane lease renewal attempt.
const (
	leaseOK           = "ok"
	leaseUnreachable  = "unreachable"
	leaseUnauthorized = "unauthorized"
	leaseRejected     = "rejected"
)

// Outcomes of a go-away sent to a member.
const (
	goAwayOK          = "ok"
	goAwayUnsupported = "unsupported"
	goAwayFailed      = "failed"
)

var (
	authHandshakesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_router_auth_handshakes_total",
			Help: "Inbound mesh authentication handshakes by outcome",
		},
		[]string{"result"},
	)

	leaseRenewalsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_router_lease_renewals_total",
			Help: "Control-plane lease renewal attempts by outcome",
		},
		[]string{"result"},
	)

	goAwaySentTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_router_goaway_sent_total",
			Help: "Members told to attach elsewhere, by reason (DRAINING, OVERLOADED) and outcome",
		},
		[]string{"reason", "result"},
	)

	unauthenticatedClosedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "agentmesh_router_unauthenticated_connections_closed_total",
			Help: "Inbound connections closed because the peer did not pass the handshake within --auth-deadline",
		},
	)
)

// Every outcome exists from the first scrape, so a rate() over one that has
// not happened yet reads 0 rather than no data.
func init() {
	for _, v := range []string{handshakeOK, handshakeBanned, handshakeRateLimited, handshakeReadFailed, handshakeInvalidFrame, handshakeUnauthorized} {
		authHandshakesTotal.WithLabelValues(v)
	}
	for _, v := range []string{leaseOK, leaseUnreachable, leaseUnauthorized, leaseRejected} {
		leaseRenewalsTotal.WithLabelValues(v)
	}
	for _, reason := range []api.RouterGoAway_Reason{api.RouterGoAway_DRAINING, api.RouterGoAway_OVERLOADED} {
		for _, v := range []string{goAwayOK, goAwayUnsupported, goAwayFailed} {
			goAwaySentTotal.WithLabelValues(reason.String(), v)
		}
	}
}

// routerStateCollector exports the live view only the router has: who has
// proven mesh membership on this hop, as opposed to who merely holds a
// transport connection. Nothing is emitted before Start has finished, since
// the host and DHT do not exist yet.
type routerStateCollector struct {
	r *Router

	infoDesc          *prometheus.Desc
	readyDesc         *prometheus.Desc
	drainingDesc      *prometheus.Desc
	authenticatedDesc *prometheus.Desc
	peerRoutersDesc   *prometheus.Desc
	connectedDesc     *prometheus.Desc
	connectionsDesc   *prometheus.Desc
	watermarkDesc     *prometheus.Desc
	relayLimitDesc    *prometheus.Desc
	bannedDesc        *prometheus.Desc
	revokedDesc       *prometheus.Desc
	dhtDesc           *prometheus.Desc
	recordsDesc       *prometheus.Desc
	biscuitExpiryDesc *prometheus.Desc
}

func newRouterStateCollector(r *Router) *routerStateCollector {
	return &routerStateCollector{
		r: r,
		infoDesc: prometheus.NewDesc(
			"agentmesh_router_info",
			"The router's mesh identity; always 1",
			[]string{"peer_id"}, nil),
		readyDesc: prometheus.NewDesc(
			"agentmesh_router_ready",
			"1 once the router is enrolled and its libp2p host is online",
			nil, nil),
		drainingDesc: prometheus.NewDesc(
			"agentmesh_router_draining",
			"1 once the router has withdrawn its lease and is shutting down",
			nil, nil),
		authenticatedDesc: prometheus.NewDesc(
			"agentmesh_router_authenticated_peers",
			"Connected peers that have completed the mesh authentication handshake",
			nil, nil),
		peerRoutersDesc: prometheus.NewDesc(
			"agentmesh_router_peer_routers",
			"Peer routers known, from the control plane's list or a handshake with the router role: all of them, and those currently authenticated",
			[]string{"state"}, nil),
		connectedDesc: prometheus.NewDesc(
			"agentmesh_router_connected_peers",
			"Peers with an open libp2p connection, authenticated or not",
			nil, nil),
		connectionsDesc: prometheus.NewDesc(
			"agentmesh_router_connections",
			"Open libp2p connections by direction; a peer may hold several",
			[]string{"direction"}, nil),
		watermarkDesc: prometheus.NewDesc(
			"agentmesh_router_connection_watermark",
			"Connection manager limits: above high, connections are trimmed down to low",
			[]string{"level"}, nil),
		relayLimitDesc: prometheus.NewDesc(
			"agentmesh_router_relay_limit",
			"Relay budgets in force, to read libp2p_relaysvc_* against",
			[]string{"limit"}, nil),
		bannedDesc: prometheus.NewDesc(
			"agentmesh_router_banned_peers",
			"Peers on the ban list synced from the control plane",
			nil, nil),
		revokedDesc: prometheus.NewDesc(
			"agentmesh_router_revoked_tokens",
			"Active revoked Biscuit tokens held in this router's deny list",
			nil, nil),
		dhtDesc: prometheus.NewDesc(
			"agentmesh_router_dht_routing_table_size",
			"Peers in the Kademlia routing table",
			nil, nil),
		recordsDesc: prometheus.NewDesc(
			"agentmesh_router_directory_records",
			"Directory records this router holds: its members' and the copies placed on it",
			nil, nil),
		biscuitExpiryDesc: prometheus.NewDesc(
			"agentmesh_router_biscuit_expiry_timestamp_seconds",
			"Unix time the router's own mesh credential expires",
			nil, nil),
	}
}

func (c *routerStateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.infoDesc, c.readyDesc, c.drainingDesc, c.authenticatedDesc, c.peerRoutersDesc, c.connectedDesc, c.connectionsDesc, c.watermarkDesc, c.relayLimitDesc,
		c.bannedDesc, c.revokedDesc, c.dhtDesc, c.recordsDesc, c.biscuitExpiryDesc, connsPerSourceIPDesc,
	} {
		ch <- d
	}
}

func (c *routerStateCollector) Collect(ch chan<- prometheus.Metric) {
	r := c.r
	ch <- prometheus.MustNewConstMetric(connsPerSourceIPDesc, prometheus.GaugeValue, float64(effectiveConnsPerSourceIP(r.config.ConnsPerSourceIP)))
	ch <- prometheus.MustNewConstMetric(c.watermarkDesc, prometheus.GaugeValue, float64(r.config.LowWaterMark), "low")
	ch <- prometheus.MustNewConstMetric(c.watermarkDesc, prometheus.GaugeValue, float64(r.config.HighWaterMark), "high")
	ch <- prometheus.MustNewConstMetric(c.relayLimitDesc, prometheus.GaugeValue, float64(r.config.RelayMaxReservations), "reservations")
	ch <- prometheus.MustNewConstMetric(c.relayLimitDesc, prometheus.GaugeValue, float64(r.config.ConnsPerSourceIP), "reservations_per_ip")
	ch <- prometheus.MustNewConstMetric(c.relayLimitDesc, prometheus.GaugeValue, float64(r.config.RelayMaxCircuits), "circuits_per_peer")
	draining := 0.0
	if r.shutdown.Load() {
		draining = 1
	}
	ch <- prometheus.MustNewConstMetric(c.drainingDesc, prometheus.GaugeValue, draining)
	// isReady is stored after Host and DHT are assigned, so observing it
	// true is what makes reading them from this goroutine safe.
	if !r.isReady.Load() {
		ch <- prometheus.MustNewConstMetric(c.readyDesc, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.readyDesc, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.infoDesc, prometheus.GaugeValue, 1, r.Host.ID().String())
	ch <- prometheus.MustNewConstMetric(c.authenticatedDesc, prometheus.GaugeValue, float64(syncMapLen(&r.authenticatedPeers)))
	listed, federated := r.peerRouterCounts()
	ch <- prometheus.MustNewConstMetric(c.peerRoutersDesc, prometheus.GaugeValue, float64(listed), "listed")
	ch <- prometheus.MustNewConstMetric(c.peerRoutersDesc, prometheus.GaugeValue, float64(federated), "authenticated")
	ch <- prometheus.MustNewConstMetric(c.connectedDesc, prometheus.GaugeValue, float64(len(r.Host.Network().Peers())))
	var inbound, outbound int
	for _, conn := range r.Host.Network().Conns() {
		if conn.Stat().Direction == network.DirInbound {
			inbound++
		} else {
			outbound++
		}
	}
	ch <- prometheus.MustNewConstMetric(c.connectionsDesc, prometheus.GaugeValue, float64(inbound), "inbound")
	ch <- prometheus.MustNewConstMetric(c.connectionsDesc, prometheus.GaugeValue, float64(outbound), "outbound")
	ch <- prometheus.MustNewConstMetric(c.bannedDesc, prometheus.GaugeValue, float64(syncMapLen(&r.bannedPeers)))
	ch <- prometheus.MustNewConstMetric(c.revokedDesc, prometheus.GaugeValue, float64(r.revokedTokens.activeCount(time.Now())))
	ch <- prometheus.MustNewConstMetric(c.dhtDesc, prometheus.GaugeValue, float64(r.DHT.RoutingTable().Size()))
	ch <- prometheus.MustNewConstMetric(c.recordsDesc, prometheus.GaugeValue, float64(r.records.size()))

	r.keysMu.RLock()
	expiry := r.credential.expiration
	r.keysMu.RUnlock()
	if !expiry.IsZero() {
		ch <- prometheus.MustNewConstMetric(c.biscuitExpiryDesc, prometheus.GaugeValue, float64(expiry.Unix()))
	}
}

func syncMapLen(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// serveMetrics opens the operator listener: /metrics, /healthz, /readyz and
// /debug/peer, the router's view of one peer.
// It is off unless an address is configured, and never shares a port with the
// libp2p listeners, so it can stay cluster-internal while the mesh port is
// public. libp2p's own metrics land in the default registry, so exposing it
// here is what makes relay reservations and connection churn visible.
func (r *Router) serveMetrics(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(newRouterStateCollector(r))

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(
		prometheus.Gatherers{prometheus.DefaultGatherer, reg},
		promhttp.HandlerOpts{},
	))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !r.isReady.Load() {
			http.Error(w, "router is not online yet", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /debug/peer", r.handleDebugPeer)

	r.metricsServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	r.metricsAddr = listener.Addr()
	go func() {
		_ = r.metricsServer.Serve(listener)
	}()
	logger.Infof("Router metrics listening on http://%s", r.metricsAddr)
	return nil
}
