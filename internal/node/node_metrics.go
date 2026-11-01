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
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// goAwayReceivedTotal counts the routers that sent this node away, by the
// reason they gave; process-wide, like the other counters.
var goAwayReceivedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_node_router_goaway_received_total",
		Help: "Times a router told this node to attach elsewhere, by reason (DRAINING, OVERLOADED)",
	},
	[]string{"reason"},
)

func init() {
	for _, reason := range []api.RouterGoAway_Reason{api.RouterGoAway_DRAINING, api.RouterGoAway_OVERLOADED} {
		goAwayReceivedTotal.WithLabelValues(reason.String())
	}
	for _, router := range []string{transitListed, transitUnlisted} {
		for _, result := range []string{"ok", "failed"} {
			transitHandshakesTotal.WithLabelValues(router, result)
		}
	}
	for _, result := range []string{lookupFound, lookupNotFound, lookupFailed} {
		peerLookupsTotal.WithLabelValues(result)
	}
	for _, result := range []string{reachOK, reachRelayRefused, reachDialTimeout, reachNoAddress, reachDialFailed, reachNoAnswer, reachAuthRejected, reachOtherFailure} {
		providerReachTotal.WithLabelValues(result)
	}
}

// providerReachTotal counts the attempts a call made to reach a provider
// for its credential, by outcome; every failure is one 502 at the caller.
var providerReachTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_node_provider_reach_total",
		Help: "Attempts to reach a provider for its credential before a call, by outcome: ok, relay_refused, dial_timeout, no_address, dial_failed, no_answer, auth_rejected, other",
	},
	[]string{"result"},
)

// The outcome of a DHT lookup for a peer's addresses: found, found
// nothing, or the lookup itself failed (an empty routing table, a timeout).
const (
	lookupFound    = "found"
	lookupNotFound = "not_found"
	lookupFailed   = "failed"
)

// peerLookupsTotal counts the DHT lookups a call ran for a peer it held no
// address for; not_found rising is a peer the DHT does not carry, failed
// rising is this node cut off from the DHT.
var peerLookupsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_node_peer_lookups_total",
		Help: "DHT lookups for a peer's addresses, by outcome: found, not_found, failed",
	},
	[]string{"result"},
)

// The router a transit handshake is with: one the control plane's catalog
// lists, or a relay found only in a peer's record.
const (
	transitListed   = "listed"
	transitUnlisted = "unlisted"
)

// transitHandshakesTotal counts the handshakes a call made with a router it
// did not hold, to reach a peer through it; the unlisted ones are routers
// the catalog missed, which a rising count during a rollout explains.
var transitHandshakesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_node_transit_handshakes_total",
		Help: "Handshakes with a router this node did not hold, run to reach a peer through it, by whether the control plane listed the router and by result",
	},
	[]string{"router", "result"},
)

// nodeStateCollector exports the node's own view of its mesh membership: the
// same figures GET /debug/mesh-info and /debug/token-info answer on demand,
// as gauges a scraper can keep. A node that runs unattended, such as a
// canary, becomes a continuous probe of the mesh this way.
type nodeStateCollector struct {
	n *AgentMeshNode

	readyDesc         *prometheus.Desc
	meshConnectedDesc *prometheus.Desc
	connectedDesc     *prometheus.Desc
	authenticatedDesc *prometheus.Desc
	biscuitExpiryDesc *prometheus.Desc
	servicesDesc      *prometheus.Desc
	routersDesc       *prometheus.Desc
	routerCandsDesc   *prometheus.Desc
}

func newNodeStateCollector(n *AgentMeshNode) *nodeStateCollector {
	return &nodeStateCollector{
		n: n,
		readyDesc: prometheus.NewDesc(
			"agentmesh_node_ready",
			"1 once the libp2p host, DHT and identity store exist",
			nil, nil),
		meshConnectedDesc: prometheus.NewDesc(
			"agentmesh_node_mesh_connected",
			"1 while the node holds an authenticated connection to a router",
			nil, nil),
		connectedDesc: prometheus.NewDesc(
			"agentmesh_node_connected_peers",
			"Peers with an open libp2p connection, authenticated or not",
			nil, nil),
		authenticatedDesc: prometheus.NewDesc(
			"agentmesh_node_authenticated_peers",
			"Peers that have completed the mesh authentication handshake with this node",
			nil, nil),
		biscuitExpiryDesc: prometheus.NewDesc(
			"agentmesh_node_biscuit_expiry_timestamp_seconds",
			"Unix time the node's mesh credential expires",
			nil, nil),
		servicesDesc: prometheus.NewDesc(
			"agentmesh_node_services_registered",
			"Local services this node offers to the mesh, by type",
			[]string{"type"}, nil),
		routersDesc: prometheus.NewDesc(
			"agentmesh_node_routers",
			"Routers this node keeps a session with: attached now, wanted (--routers, or every router listed when fewer), and directory (authenticated for DHT lookups and announcements without being attached)",
			[]string{"state"}, nil),
		routerCandsDesc: prometheus.NewDesc(
			"agentmesh_node_router_candidates",
			"Routers the control plane lists that this node may attach to: all of them, and those attesting --router-selector",
			[]string{"match"}, nil),
	}
}

func (c *nodeStateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.readyDesc, c.meshConnectedDesc, c.connectedDesc, c.authenticatedDesc,
		c.biscuitExpiryDesc, c.servicesDesc, c.routersDesc, c.routerCandsDesc, connsPerSourceIPDesc,
	} {
		ch <- d
	}
}

func (c *nodeStateCollector) Collect(ch chan<- prometheus.Metric) {
	n := c.n
	ch <- prometheus.MustNewConstMetric(connsPerSourceIPDesc, prometheus.GaugeValue, float64(ConnsPerSourceIP))
	if n.debugReady() != nil {
		ch <- prometheus.MustNewConstMetric(c.readyDesc, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.readyDesc, prometheus.GaugeValue, 1)

	connected := 0.0
	if n.IsConnected() {
		connected = 1
	}
	ch <- prometheus.MustNewConstMetric(c.meshConnectedDesc, prometheus.GaugeValue, connected)
	ch <- prometheus.MustNewConstMetric(c.connectedDesc, prometheus.GaugeValue, float64(len(n.Host.Network().Peers())))

	ch <- prometheus.MustNewConstMetric(c.routersDesc, prometheus.GaugeValue, float64(n.AttachedRouters()), "attached")
	ch <- prometheus.MustNewConstMetric(c.routersDesc, prometheus.GaugeValue, float64(n.wantRouters()), "wanted")
	cands := n.routerCandidates()
	_, matching := selectRouters(cands, 0, n.config.RouterSelector, nil, nil)
	ch <- prometheus.MustNewConstMetric(c.routerCandsDesc, prometheus.GaugeValue, float64(len(cands)), "any")
	ch <- prometheus.MustNewConstMetric(c.routerCandsDesc, prometheus.GaugeValue, float64(matching), "selector")

	authenticated := 0
	n.authPeers.Range(func(_, _ any) bool {
		authenticated++
		return true
	})
	ch <- prometheus.MustNewConstMetric(c.authenticatedDesc, prometheus.GaugeValue, float64(authenticated))

	if exp, err := n.Store.LoadIdentityExpiration(); err == nil && exp > 0 {
		ch <- prometheus.MustNewConstMetric(c.biscuitExpiryDesc, prometheus.GaugeValue, float64(exp))
	}

	if n.services != nil {
		byType := map[string]int{}
		for _, svc := range n.services.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED) {
			byType[serviceTypeLabel(svc.Type)]++
		}
		for t, count := range byType {
			ch <- prometheus.MustNewConstMetric(c.servicesDesc, prometheus.GaugeValue, float64(count), t)
		}
	}
}

// serviceTypeLabel turns SERVICE_TYPE_MCP into "mcp".
func serviceTypeLabel(t api.ServiceType) string {
	return strings.ToLower(strings.TrimPrefix(t.String(), "SERVICE_TYPE_"))
}

// metricsHandler serves the process-wide registry, which carries the request
// and inference counters and the Go runtime, alongside this node's own state.
// The state collector is per node so two nodes in one process (tests,
// agentmesh-one) never fight over a registration.
func (n *AgentMeshNode) metricsHandler() http.Handler {
	n.metricsOnce.Do(func() {
		n.metricsRegistry = prometheus.NewRegistry()
		n.metricsRegistry.MustRegister(newNodeStateCollector(n))
	})
	return promhttp.HandlerFor(
		prometheus.Gatherers{prometheus.DefaultGatherer, n.metricsRegistry},
		promhttp.HandlerOpts{},
	)
}

// StartMetricsServer serves /metrics, /healthz and /readyz on addr with no
// authentication, for a scraper and a kubelet that hold no sidecar token.
// The sidecar's own /metrics stays token-gated: this listener exists so a
// socket-only node, which has no TCP port at all, can still be observed. It
// is off unless an operator names the address, since nothing on it is gated.
func StartMetricsServer(node *AgentMeshNode, addr string) (*http.Server, error) {
	if addr == "" {
		return nil, errors.New("no metrics address configured")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", node.metricsHandler())
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if node.debugReady() != nil || !node.IsConnected() {
			http.Error(w, "not connected to the mesh", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		// Informational once Serve has the listener; lets callers find the port.
		Addr:              listener.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = server.Serve(listener)
	}()
	logger.Infof("Metrics listening on http://%s", listener.Addr())
	return server, nil
}
