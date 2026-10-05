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
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/storage"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gathered indexes one Gather() by metric name and sorted label pairs so a
// test can ask for a sample by "name{k=v,...}".
type gathered map[string]float64

func gather(t *testing.T, c prometheus.Collector) gathered {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := gathered{}
	for _, f := range fams {
		for _, m := range f.GetMetric() {
			out[sampleKey(f.GetName(), m)] = m.GetGauge().GetValue()
		}
	}
	return out
}

func sampleKey(name string, m *dto.Metric) string {
	var parts []string
	for _, l := range m.GetLabel() {
		parts = append(parts, l.GetName()+"="+l.GetValue())
	}
	if len(parts) == 0 {
		return name
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

func (g gathered) want(t *testing.T, key string, v float64) {
	t.Helper()
	got, ok := g[key]
	if !ok {
		t.Fatalf("missing sample %s; have %v", key, g)
	}
	if got != v {
		t.Errorf("%s = %v, want %v", key, got, v)
	}
}

func newMetricsTestStore(t *testing.T) storage.Store {
	t.Helper()
	store, err := storage.NewSQLStore("sqlite", filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedMeshState(t *testing.T, store storage.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()

	nodes := []storage.EnrolledNode{
		{PeerID: "node-a", Role: api.RoleNode, EnrolledAt: now, ExpiresAt: now.Add(time.Hour)},
		{PeerID: "node-b", Role: api.RoleNode, EnrolledAt: now, ExpiresAt: now.Add(time.Hour)},
		{PeerID: "node-old", Role: api.RoleNode, EnrolledAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		{PeerID: "node-bad", Role: api.RoleNode, EnrolledAt: now, ExpiresAt: now.Add(time.Hour)},
		{PeerID: "router-1", Role: api.RoleRouter, EnrolledAt: now, ExpiresAt: now.Add(time.Hour)},
		{PeerID: "router-2", Role: api.RoleRouter, EnrolledAt: now, ExpiresAt: now.Add(time.Hour)},
	}
	for i := range nodes {
		nodes[i].PublicKey = []byte("pk-" + nodes[i].PeerID)
		nodes[i].Biscuit = []byte("biscuit")
		nodes[i].EnrollmentType = "test"
		if err := store.EnrollNode(ctx, &nodes[i]); err != nil {
			t.Fatalf("enroll %s: %v", nodes[i].PeerID, err)
		}
	}
	if err := store.SetNodeBanned(ctx, "node-bad", true); err != nil {
		t.Fatalf("ban: %v", err)
	}

	// Routers peer with each other and share node-a; node-c is attached to
	// router-2 without an enrollment row, as a peer mid-handshake would be.
	leases := []storage.RouterLease{
		{PeerID: "router-1", Addresses: []string{"/ip4/10.0.0.1/tcp/4501"}, LastRenewal: now, ExpiresAt: now.Add(time.Hour),
			ConnectedPeers: []string{"router-2", "node-a", "node-b"}, DHTSize: 5},
		{PeerID: "router-2", Addresses: []string{"/ip4/10.0.0.2/tcp/4501"}, LastRenewal: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
			ConnectedPeers: []string{"router-1", "node-a", "node-c"}, DHTSize: 4},
		{PeerID: "router-gone", Addresses: []string{"/ip4/10.0.0.3/tcp/4501"}, LastRenewal: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
			ConnectedPeers: []string{"node-z"}, DHTSize: 1},
	}
	for i := range leases {
		if err := store.UpsertRouterLease(ctx, &leases[i]); err != nil {
			t.Fatalf("lease %s: %v", leases[i].PeerID, err)
		}
	}

	if err := store.SaveUser(ctx, &storage.User{ID: "alice", Issuer: "https://issuer", Email: "alice@example.com", Role: "user", CreatedAt: now}); err != nil {
		t.Fatalf("user: %v", err)
	}

	tokens := []storage.BootstrapToken{
		{ID: "tok-active", TokenHash: "h1", Role: api.RoleNode, MaxUsages: 5, UsagesCount: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		{ID: "tok-exhausted", TokenHash: "h2", Role: api.RoleNode, MaxUsages: 1, UsagesCount: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		{ID: "tok-expired", TokenHash: "h3", Role: api.RoleNode, MaxUsages: 5, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		{ID: "tok-revoked", TokenHash: "h4", Role: api.RoleNode, MaxUsages: 5, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
	for i := range tokens {
		if err := store.SaveBootstrapToken(ctx, &tokens[i]); err != nil {
			t.Fatalf("token %s: %v", tokens[i].ID, err)
		}
	}
	if err := store.RevokeBootstrapToken(ctx, "tok-revoked"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	reqs := []storage.EnrollmentRequest{
		{ID: "req-1", PeerID: "pending-1", TokenID: "tok-active", Status: api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING, CreatedAt: now},
		{ID: "req-2", PeerID: "pending-2", TokenID: "tok-active", Status: api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING, CreatedAt: now},
		{ID: "req-3", PeerID: "node-a", TokenID: "tok-active", Status: api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, CreatedAt: now},
	}
	for i := range reqs {
		reqs[i].PublicKey = []byte("pk-" + reqs[i].PeerID)
		if err := store.CreateEnrollmentRequest(ctx, &reqs[i]); err != nil {
			t.Fatalf("request %s: %v", reqs[i].ID, err)
		}
	}

	// A rotation in its grace period: the first key retires in an hour, the
	// second signs now.
	for i, grace := range []time.Duration{0, time.Hour} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			err = store.SaveInitialKey(ctx, priv, pub)
		} else {
			err = store.RotateKeys(ctx, priv, pub, grace)
		}
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
	}
}

func TestMeshStateCollectorExportsStoreState(t *testing.T) {
	store := newMetricsTestStore(t)
	now := time.Now()
	seedMeshState(t, store, now)

	c := newMeshStateCollector(store)
	c.now = func() time.Time { return now }
	g := gather(t, c)

	g.want(t, "sam_control_plane_mesh_state_scrape_success", 1)
	g.want(t, "sam_control_plane_mesh_state_timestamp_seconds", float64(now.Unix()))

	g.want(t, "sam_control_plane_enrolled_nodes{role="+api.RoleNode+",state=admitted}", 2)
	g.want(t, "sam_control_plane_enrolled_nodes{role="+api.RoleNode+",state=expired}", 1)
	g.want(t, "sam_control_plane_enrolled_nodes{role="+api.RoleNode+",state=banned}", 1)
	g.want(t, "sam_control_plane_enrolled_nodes{role="+api.RoleRouter+",state=admitted}", 2)
	g.want(t, "sam_control_plane_users", 1)

	g.want(t, "sam_control_plane_enrollment_requests{status=pending}", 2)
	g.want(t, "sam_control_plane_enrollment_requests{status=approved}", 1)

	g.want(t, "sam_control_plane_bootstrap_tokens{state=active}", 1)
	g.want(t, "sam_control_plane_bootstrap_tokens{state=exhausted}", 1)
	g.want(t, "sam_control_plane_bootstrap_tokens{state=expired}", 1)
	g.want(t, "sam_control_plane_bootstrap_tokens{state=revoked}", 1)

	// The lapsed lease is neither counted nor labelled.
	g.want(t, "sam_control_plane_routers_active", 2)
	g.want(t, "sam_control_plane_router_connected_peers{router=router-1}", 3)
	g.want(t, "sam_control_plane_router_connected_peers{router=router-2}", 3)
	g.want(t, "sam_control_plane_router_dht_size{router=router-1}", 5)
	g.want(t, "sam_control_plane_router_dht_size{router=router-2}", 4)
	g.want(t, "sam_control_plane_router_lease_renewed_timestamp_seconds{router=router-2}", float64(now.Add(-time.Minute).Unix()))
	if _, ok := g["sam_control_plane_router_connected_peers{router=router-gone}"]; ok {
		t.Error("lapsed router lease was exported")
	}

	// node-a counted once, routers excluded, node-z behind a dead lease ignored.
	g.want(t, "sam_control_plane_mesh_connected_peers", 3)

	// Both keys verify during the grace period; the retiring one's expiry is exported.
	g.want(t, "sam_control_plane_signing_keys", 2)
	retiring, ok := g["sam_control_plane_retiring_key_expiry_timestamp_seconds"]
	if !ok {
		t.Fatal("retiring key expiry not exported during the grace period")
	}
	if until := time.Until(time.Unix(int64(retiring), 0)); until < 55*time.Minute || until > 65*time.Minute {
		t.Errorf("retiring key expires in %v, want about an hour", until)
	}
}

func TestMeshStateCollectorCachesWithinTTL(t *testing.T) {
	store := newMetricsTestStore(t)
	now := time.Now()
	seedMeshState(t, store, now)

	clock := now
	c := newMeshStateCollector(store)
	c.now = func() time.Time { return clock }

	gather(t, c).want(t, "sam_control_plane_routers_active", 2)

	extra := storage.RouterLease{PeerID: "router-3", Addresses: []string{"/ip4/10.0.0.4/tcp/4501"}, LastRenewal: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.UpsertRouterLease(context.Background(), &extra); err != nil {
		t.Fatal(err)
	}

	clock = now.Add(c.ttl / 2)
	gather(t, c).want(t, "sam_control_plane_routers_active", 2)

	clock = now.Add(c.ttl)
	gather(t, c).want(t, "sam_control_plane_routers_active", 3)
}

func TestMeshStateCollectorKeepsLastSnapshotWhenStoreFails(t *testing.T) {
	store := newMetricsTestStore(t)
	now := time.Now()
	seedMeshState(t, store, now)

	clock := now
	c := newMeshStateCollector(store)
	c.now = func() time.Time { return clock }

	g := gather(t, c)
	g.want(t, "sam_control_plane_mesh_state_scrape_success", 1)
	g.want(t, "sam_control_plane_routers_active", 2)

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(c.ttl)

	g = gather(t, c)
	g.want(t, "sam_control_plane_mesh_state_scrape_success", 0)
	g.want(t, "sam_control_plane_routers_active", 2)
	g.want(t, "sam_control_plane_mesh_state_timestamp_seconds", float64(now.Unix()))
}

func TestMeshStateCollectorBeforeFirstReadReportsOnlyFailure(t *testing.T) {
	store := newMetricsTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	g := gather(t, newMeshStateCollector(store))
	g.want(t, "sam_control_plane_mesh_state_scrape_success", 0)
	if len(g) != 1 {
		t.Errorf("expected only the success gauge before any snapshot, got %v", g)
	}
}

func TestObserveRouteLabelsByPatternAndCode(t *testing.T) {
	before := counterValue(t, httpRequestsTotal, "/admin/nodes/", "404")

	h := observeRoute("/admin/nodes/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such node", http.StatusNotFound)
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/nodes/12D3KooWsecret/unban", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}

	if got := counterValue(t, httpRequestsTotal, "/admin/nodes/", "404"); got != before+1 {
		t.Errorf("counter = %v, want %v", got, before+1)
	}

	// A handler that never calls WriteHeader is a 200.
	before = counterValue(t, httpRequestsTotal, "/info", "200")
	observeRoute("/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/info", nil))
	if got := counterValue(t, httpRequestsTotal, "/info", "200"); got != before+1 {
		t.Errorf("counter = %v, want %v", got, before+1)
	}
}

func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	var m dto.Metric
	if err := vec.WithLabelValues(labels...).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func TestMetricsEndpointServesMeshStateAndRuntime(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	for _, want := range []string{
		"sam_control_plane_mesh_state_scrape_success 1",
		"sam_control_plane_routers_active 0",
		"sam_control_plane_mesh_connected_peers 0",
		"go_goroutines",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}
