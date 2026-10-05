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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Outcomes of an inbound /sam/auth handshake.
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

var (
	authHandshakesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sam_router_auth_handshakes_total",
			Help: "Inbound mesh authentication handshakes by outcome",
		},
		[]string{"result"},
	)

	leaseRenewalsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sam_router_lease_renewals_total",
			Help: "Control-plane lease renewal attempts by outcome",
		},
		[]string{"result"},
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
}

// routerStateCollector exports the live view only the router has: who has
// proven mesh membership on this hop, as opposed to who merely holds a
// transport connection. Nothing is emitted before Start has finished, since
// the host and DHT do not exist yet.
type routerStateCollector struct {
	r *Router

	infoDesc          *prometheus.Desc
	readyDesc         *prometheus.Desc
	authenticatedDesc *prometheus.Desc
	connectedDesc     *prometheus.Desc
	bannedDesc        *prometheus.Desc
	dhtDesc           *prometheus.Desc
	biscuitExpiryDesc *prometheus.Desc
}

func newRouterStateCollector(r *Router) *routerStateCollector {
	return &routerStateCollector{
		r: r,
		infoDesc: prometheus.NewDesc(
			"sam_router_info",
			"The router's mesh identity; always 1",
			[]string{"peer_id"}, nil),
		readyDesc: prometheus.NewDesc(
			"sam_router_ready",
			"1 once the router is enrolled and its libp2p host is online",
			nil, nil),
		authenticatedDesc: prometheus.NewDesc(
			"sam_router_authenticated_peers",
			"Connected peers that have completed the mesh authentication handshake",
			nil, nil),
		connectedDesc: prometheus.NewDesc(
			"sam_router_connected_peers",
			"Peers with an open libp2p connection, authenticated or not",
			nil, nil),
		bannedDesc: prometheus.NewDesc(
			"sam_router_banned_peers",
			"Peers on the ban list synced from the control plane",
			nil, nil),
		dhtDesc: prometheus.NewDesc(
			"sam_router_dht_routing_table_size",
			"Peers in the Kademlia routing table",
			nil, nil),
		biscuitExpiryDesc: prometheus.NewDesc(
			"sam_router_biscuit_expiry_timestamp_seconds",
			"Unix time the router's own mesh credential expires",
			nil, nil),
	}
}

func (c *routerStateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.infoDesc, c.readyDesc, c.authenticatedDesc, c.connectedDesc, c.bannedDesc, c.dhtDesc, c.biscuitExpiryDesc, connsPerSourceIPDesc,
	} {
		ch <- d
	}
}

func (c *routerStateCollector) Collect(ch chan<- prometheus.Metric) {
	r := c.r
	ch <- prometheus.MustNewConstMetric(connsPerSourceIPDesc, prometheus.GaugeValue, float64(effectiveConnsPerSourceIP(r.config.ConnsPerSourceIP)))
	// isReady is stored after Host and DHT are assigned, so observing it
	// true is what makes reading them from this goroutine safe.
	if !r.isReady.Load() {
		ch <- prometheus.MustNewConstMetric(c.readyDesc, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.readyDesc, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.infoDesc, prometheus.GaugeValue, 1, r.Host.ID().String())
	ch <- prometheus.MustNewConstMetric(c.authenticatedDesc, prometheus.GaugeValue, float64(syncMapLen(&r.authenticatedPeers)))
	ch <- prometheus.MustNewConstMetric(c.connectedDesc, prometheus.GaugeValue, float64(len(r.Host.Network().Peers())))
	ch <- prometheus.MustNewConstMetric(c.bannedDesc, prometheus.GaugeValue, float64(syncMapLen(&r.bannedPeers)))
	ch <- prometheus.MustNewConstMetric(c.dhtDesc, prometheus.GaugeValue, float64(r.DHT.RoutingTable().Size()))

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

// serveMetrics opens the operator listener: /metrics, /healthz and /readyz.
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
