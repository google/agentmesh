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

package controlplane

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/storage"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sam_control_plane_http_requests_total",
			Help: "Control-plane HTTP requests by registered route and status code",
		},
		[]string{"route", "code"},
	)

	httpRequestDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sam_control_plane_http_request_duration_seconds",
			Help:    "Time a control-plane request occupied its handler",
			Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"route"},
	)
)

// observeRoute counts and times requests to one registered mux pattern. The
// pattern, not the request path, is the label: paths carry peer ids and token
// ids chosen off-plane, so the raw path can never become a label.
func observeRoute(pattern string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusWriter{ResponseWriter: w}
		h(rec, r)
		httpRequestsTotal.WithLabelValues(pattern, strconv.Itoa(rec.status())).Inc()
		httpRequestDurationSeconds.WithLabelValues(pattern).Observe(time.Since(start).Seconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) status() int {
	if s.code == 0 {
		return http.StatusOK
	}
	return s.code
}

func (s *statusWriter) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

const (
	// meshStateTTL bounds how often a scrape may hit the store. Router leases
	// renew on the order of minutes, so anything fresher is noise.
	meshStateTTL = 30 * time.Second
	// meshStateTimeout caps one refresh so a slow store cannot hold a scrape
	// past the scraper's own deadline.
	meshStateTimeout = 5 * time.Second
)

// Node admission states as reported by meshStateCollector. "admitted" is
// what CheckAdmission says, not liveness: a node that enrolled once and went
// away stays admitted until its session expires. Liveness is
// sam_control_plane_mesh_connected_peers.
const (
	nodeStateAdmitted = "admitted"
	nodeStateExpired  = "expired"
	nodeStateBanned   = "banned"
)

// Bootstrap token states as reported by meshStateCollector.
const (
	tokenStateActive    = "active"
	tokenStateRevoked   = "revoked"
	tokenStateExpired   = "expired"
	tokenStateExhausted = "exhausted"
)

// meshSnapshot is what one refresh of the store reduces to. Only counts and
// per-router figures survive: a node's peer id is never a label.
type meshSnapshot struct {
	nodesByRoleState   map[[2]string]int
	users              int
	enrollmentRequests map[string]int
	tokensByState      map[string]int
	routers            []storage.RouterLease
	meshConnectedPeers int
	// signingKeys is how many keys verify a credential today: one, or two
	// during the grace period after a rotation. retiringKeyExpiry is when
	// the retiring one stops verifying; zero when there is none.
	signingKeys       int
	retiringKeyExpiry time.Time
}

// meshStateCollector exports the control plane's view of the mesh: who is
// enrolled, which routers hold a lease and what they report attached to them.
// The store is the source of truth shared by every replica, so each replica
// exports the same figures and a dashboard may take any one of them.
type meshStateCollector struct {
	store   storage.Store
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time

	mu        sync.Mutex
	fetchedAt time.Time
	snapshot  meshSnapshot
	ok        bool

	nodesDesc        *prometheus.Desc
	usersDesc        *prometheus.Desc
	requestsDesc     *prometheus.Desc
	tokensDesc       *prometheus.Desc
	routersDesc      *prometheus.Desc
	routerPeersDesc  *prometheus.Desc
	routerDHTDesc    *prometheus.Desc
	routerLeaseDesc  *prometheus.Desc
	meshPeersDesc    *prometheus.Desc
	signingKeysDesc  *prometheus.Desc
	retiringKeyDesc  *prometheus.Desc
	scrapeOKDesc     *prometheus.Desc
	scrapeSampleDesc *prometheus.Desc
}

func newMeshStateCollector(store storage.Store) *meshStateCollector {
	return &meshStateCollector{
		store:   store,
		ttl:     meshStateTTL,
		timeout: meshStateTimeout,
		now:     time.Now,
		nodesDesc: prometheus.NewDesc(
			"sam_control_plane_enrolled_nodes",
			"Enrolled identities by role and admission state",
			[]string{"role", "state"}, nil),
		usersDesc: prometheus.NewDesc(
			"sam_control_plane_users",
			"Human identities that have enrolled",
			nil, nil),
		requestsDesc: prometheus.NewDesc(
			"sam_control_plane_enrollment_requests",
			"Enrollment requests by status",
			[]string{"status"}, nil),
		tokensDesc: prometheus.NewDesc(
			"sam_control_plane_bootstrap_tokens",
			"Bootstrap tokens by state",
			[]string{"state"}, nil),
		routersDesc: prometheus.NewDesc(
			"sam_control_plane_routers_active",
			"Routers holding an unexpired lease",
			nil, nil),
		routerPeersDesc: prometheus.NewDesc(
			"sam_control_plane_router_connected_peers",
			"Peers a router reported connected on its last lease renewal",
			[]string{"router"}, nil),
		routerDHTDesc: prometheus.NewDesc(
			"sam_control_plane_router_dht_size",
			"DHT routing table size a router reported on its last lease renewal",
			[]string{"router"}, nil),
		routerLeaseDesc: prometheus.NewDesc(
			"sam_control_plane_router_lease_renewed_timestamp_seconds",
			"Unix time of a router's last lease renewal",
			[]string{"router"}, nil),
		meshPeersDesc: prometheus.NewDesc(
			"sam_control_plane_mesh_connected_peers",
			"Distinct non-router peers connected to at least one active router",
			nil, nil),
		signingKeysDesc: prometheus.NewDesc(
			"sam_control_plane_signing_keys",
			"Signing keys a credential verifies against: 1, or 2 during the grace period after a rotation",
			nil, nil),
		retiringKeyDesc: prometheus.NewDesc(
			"sam_control_plane_retiring_key_expiry_timestamp_seconds",
			"Unix time the retiring signing key stops verifying; absent when no rotation is in its grace period",
			nil, nil),
		scrapeOKDesc: prometheus.NewDesc(
			"sam_control_plane_mesh_state_scrape_success",
			"1 if the mesh state was read from the store, 0 if the last read failed",
			nil, nil),
		scrapeSampleDesc: prometheus.NewDesc(
			"sam_control_plane_mesh_state_timestamp_seconds",
			"Unix time the exported mesh state was read from the store",
			nil, nil),
	}
}

func (c *meshStateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.nodesDesc, c.usersDesc, c.requestsDesc, c.tokensDesc, c.routersDesc,
		c.routerPeersDesc, c.routerDHTDesc, c.routerLeaseDesc, c.meshPeersDesc,
		c.signingKeysDesc, c.retiringKeyDesc, c.scrapeOKDesc, c.scrapeSampleDesc,
	} {
		ch <- d
	}
}

func (c *meshStateCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if now.Sub(c.fetchedAt) >= c.ttl {
		c.refresh(now)
	}

	ok := 0.0
	if c.ok {
		ok = 1
	}
	ch <- prometheus.MustNewConstMetric(c.scrapeOKDesc, prometheus.GaugeValue, ok)
	if c.fetchedAt.IsZero() {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.scrapeSampleDesc, prometheus.GaugeValue, float64(c.fetchedAt.Unix()))

	s := c.snapshot
	for k, n := range s.nodesByRoleState {
		ch <- prometheus.MustNewConstMetric(c.nodesDesc, prometheus.GaugeValue, float64(n), k[0], k[1])
	}
	ch <- prometheus.MustNewConstMetric(c.usersDesc, prometheus.GaugeValue, float64(s.users))
	for status, n := range s.enrollmentRequests {
		ch <- prometheus.MustNewConstMetric(c.requestsDesc, prometheus.GaugeValue, float64(n), status)
	}
	for state, n := range s.tokensByState {
		ch <- prometheus.MustNewConstMetric(c.tokensDesc, prometheus.GaugeValue, float64(n), state)
	}
	ch <- prometheus.MustNewConstMetric(c.routersDesc, prometheus.GaugeValue, float64(len(s.routers)))
	for _, r := range s.routers {
		ch <- prometheus.MustNewConstMetric(c.routerPeersDesc, prometheus.GaugeValue, float64(len(r.ConnectedPeers)), r.PeerID)
		ch <- prometheus.MustNewConstMetric(c.routerDHTDesc, prometheus.GaugeValue, float64(r.DHTSize), r.PeerID)
		ch <- prometheus.MustNewConstMetric(c.routerLeaseDesc, prometheus.GaugeValue, float64(r.LastRenewal.Unix()), r.PeerID)
	}
	ch <- prometheus.MustNewConstMetric(c.meshPeersDesc, prometheus.GaugeValue, float64(s.meshConnectedPeers))
	ch <- prometheus.MustNewConstMetric(c.signingKeysDesc, prometheus.GaugeValue, float64(s.signingKeys))
	if !s.retiringKeyExpiry.IsZero() {
		ch <- prometheus.MustNewConstMetric(c.retiringKeyDesc, prometheus.GaugeValue, float64(s.retiringKeyExpiry.Unix()))
	}
}

// refresh replaces the snapshot from the store. A failed read keeps the last
// good snapshot and flips the success gauge, so a store outage is visible
// without the figures vanishing.
func (c *meshStateCollector) refresh(now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	snap, err := readMeshSnapshot(ctx, c.store, now)
	if err != nil {
		logger.Warnf("Mesh state metrics refresh failed: %v", err)
		c.ok = false
		return
	}
	c.snapshot = snap
	c.fetchedAt = now
	c.ok = true
}

func readMeshSnapshot(ctx context.Context, store storage.Store, now time.Time) (meshSnapshot, error) {
	snap := meshSnapshot{
		nodesByRoleState:   map[[2]string]int{},
		enrollmentRequests: map[string]int{},
		tokensByState:      map[string]int{},
	}

	nodes, err := store.ListNodes(ctx)
	if err != nil {
		return snap, err
	}
	for i := range nodes {
		snap.nodesByRoleState[[2]string{nodes[i].Role, nodeState(&nodes[i], now)}]++
	}

	users, err := store.ListUsers(ctx)
	if err != nil {
		return snap, err
	}
	snap.users = len(users)

	reqs, err := store.ListEnrollmentRequests(ctx)
	if err != nil {
		return snap, err
	}
	for _, r := range reqs {
		snap.enrollmentRequests[enrollmentStatusLabel(r.Status)]++
	}

	tokens, err := store.ListBootstrapTokens(ctx)
	if err != nil {
		return snap, err
	}
	for i := range tokens {
		snap.tokensByState[tokenState(&tokens[i], now)]++
	}

	routers, err := store.GetActiveRouters(ctx)
	if err != nil {
		return snap, err
	}
	snap.routers = routers
	snap.meshConnectedPeers = countMeshPeers(routers)

	keys, err := store.GetAllValidKeys(ctx)
	if err != nil {
		return snap, err
	}
	snap.signingKeys = len(keys)
	for _, k := range keys {
		// The current key has no expiration; a retiring one expires at the end of its grace period.
		if !k.Expiration.IsZero() && (snap.retiringKeyExpiry.IsZero() || k.Expiration.Before(snap.retiringKeyExpiry)) {
			snap.retiringKeyExpiry = k.Expiration
		}
	}

	return snap, nil
}

// enrollmentStatusLabel turns ENROLLMENT_STATUS_PENDING into "pending".
func enrollmentStatusLabel(s api.EnrollmentStatus) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "ENROLLMENT_STATUS_"))
}

func nodeState(n *storage.EnrolledNode, now time.Time) string {
	switch n.CheckAdmission(now) {
	case nil:
		return nodeStateAdmitted
	case storage.ErrNodeBanned:
		return nodeStateBanned
	default:
		return nodeStateExpired
	}
}

func tokenState(t *storage.BootstrapToken, now time.Time) string {
	switch {
	case t.IsRevoked():
		return tokenStateRevoked
	case !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt):
		return tokenStateExpired
	case t.UsagesCount >= t.MaxUsages:
		return tokenStateExhausted
	default:
		return tokenStateActive
	}
}

// countMeshPeers is the headline mesh size: every peer some active router has
// attached, counted once, with the routers themselves left out since they
// hold connections to each other.
func countMeshPeers(routers []storage.RouterLease) int {
	routerIDs := make(map[string]bool, len(routers))
	for _, r := range routers {
		routerIDs[r.PeerID] = true
	}
	seen := map[string]bool{}
	for _, r := range routers {
		for _, p := range r.ConnectedPeers {
			if !routerIDs[p] {
				seen[p] = true
			}
		}
	}
	return len(seen)
}

// metricsHandler serves the process-wide registry, which carries the request
// counters above and the Go runtime, alongside this server's own mesh state.
// The mesh collector is per server rather than global so two servers in one
// process (tests, sam-one) never fight over a registration.
func (s *Server) metricsHandler() http.Handler {
	return promhttp.HandlerFor(
		prometheus.Gatherers{prometheus.DefaultGatherer, s.metricsRegistry},
		promhttp.HandlerOpts{},
	)
}
