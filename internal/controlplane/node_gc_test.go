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
	"slices"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/storage"
)

func TestGCExpiredNodesAppliesRetention(t *testing.T) {
	store := newMetricsTestStore(t)
	ctx := context.Background()
	now := time.Now()

	enroll := func(id string, expiresAt time.Time) {
		t.Helper()
		if err := store.EnrollNode(ctx, &storage.EnrolledNode{
			PeerID: id, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode,
			EnrollmentType: "OIDC", EnrolledAt: now.Add(-90 * 24 * time.Hour), ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	// Retention is 7d: only a session that lapsed more than a week ago goes.
	enroll("lapsed-8d", now.Add(-8*24*time.Hour))
	enroll("lapsed-6d", now.Add(-6*24*time.Hour))
	enroll("admitted", now.Add(24*time.Hour))

	srv, err := NewServer(Options{
		DriverName: "sqlite", DataSourceName: "unused", OIDCIssuer: "https://issuer",
		NodeRetention: 7 * 24 * time.Hour,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	before := counterValue(t, nodesDeletedTotal, deletedReasonSession)

	srv.gcExpiredNodes(now)

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes after sweep, want 2: %+v", len(nodes), nodes)
	}
	for _, n := range nodes {
		if n.PeerID == "lapsed-8d" {
			t.Error("lapsed-8d survived a 7d retention")
		}
	}
	if got := counterValue(t, nodesDeletedTotal, deletedReasonSession) - before; got != 1 {
		t.Errorf("nodes_deleted_total{reason=session} advanced by %v, want 1", got)
	}
}

// A bootstrap enrollment has no session, so the sweep judges it by its last
// refresh: a member that did not refresh for the retention is forgotten, a
// member an ephemeral token enrolled after the ephemeral retention, and one
// that refreshed recently stays whichever token enrolled it. The ladder's
// ten thousand members per run left exactly these rows on the testnet.
func TestGCForgetsSilentBootstrapMembers(t *testing.T) {
	store := newMetricsTestStore(t)
	ctx := context.Background()
	now := time.Now()

	enroll := func(id string, lastRefresh time.Time, ephemeral bool) {
		t.Helper()
		if err := store.EnrollNode(ctx, &storage.EnrolledNode{
			PeerID: id, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode,
			EnrollmentType: "BOOTSTRAP", EnrolledAt: lastRefresh, Ephemeral: ephemeral,
		}); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	// Retention 7d, ephemeral retention 1h.
	enroll("regular-fresh", now.Add(-time.Hour), false)
	enroll("regular-6d", now.Add(-6*24*time.Hour), false)
	enroll("regular-8d", now.Add(-8*24*time.Hour), false)
	enroll("ephemeral-fresh", now.Add(-10*time.Minute), true)
	enroll("ephemeral-2h", now.Add(-2*time.Hour), true)
	enroll("banned-8d", now.Add(-8*24*time.Hour), false)
	if err := store.SetNodeBanned(ctx, "banned-8d", true); err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(Options{
		DriverName: "sqlite", DataSourceName: "unused", OIDCIssuer: "https://issuer",
		NodeRetention: 7 * 24 * time.Hour, EphemeralNodeRetention: time.Hour,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	silentBefore := counterValue(t, nodesDeletedTotal, deletedReasonSilent)
	ephemeralBefore := counterValue(t, nodesDeletedTotal, deletedReasonEphemeral)

	srv.gcExpiredNodes(now)

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, n := range nodes {
		left = append(left, n.PeerID)
	}
	slices.Sort(left)
	want := []string{"banned-8d", "ephemeral-fresh", "regular-6d", "regular-fresh"}
	if !slices.Equal(left, want) {
		t.Fatalf("after the sweep %v remain, want %v", left, want)
	}
	if got := counterValue(t, nodesDeletedTotal, deletedReasonSilent) - silentBefore; got != 1 {
		t.Errorf("nodes_deleted_total{reason=silent} advanced by %v, want 1", got)
	}
	if got := counterValue(t, nodesDeletedTotal, deletedReasonEphemeral) - ephemeralBefore; got != 1 {
		t.Errorf("nodes_deleted_total{reason=ephemeral} advanced by %v, want 1", got)
	}
}

// One sweep also bounds the records enrollment leaves behind: the requests,
// the tokens that made them, the router leases, and the in-memory service
// catalog. Every table the testnet audit found growing is covered here.
func TestGCStorageBoundsEnrollmentRecordsAndCatalog(t *testing.T) {
	store := newMetricsTestStore(t)
	ctx := context.Background()
	now := time.Now()
	day := 24 * time.Hour

	if err := store.SaveBootstrapToken(ctx, &storage.BootstrapToken{
		ID: "old", TokenHash: "hash-old", Role: api.RoleNode, MaxUsages: 10, CreatedAt: now.Add(-41 * day), ExpiresAt: now.Add(-40 * day),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveBootstrapToken(ctx, &storage.BootstrapToken{
		ID: "live", TokenHash: "hash-live", Role: api.RoleNode, MaxUsages: 10, CreatedAt: now, ExpiresAt: now.Add(day),
	}); err != nil {
		t.Fatal(err)
	}
	resolved := now.Add(-40 * day)
	if err := store.CreateEnrollmentRequest(ctx, &storage.EnrollmentRequest{
		ID: "old-request", PeerID: "old-peer", PublicKey: []byte("pub"), TokenID: "old",
		Status: api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, CreatedAt: now.Add(-41 * day), ResolvedAt: &resolved,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateEnrollmentRequest(ctx, &storage.EnrollmentRequest{
		ID: "live-request", PeerID: "live-peer", PublicKey: []byte("pub"), TokenID: "live",
		Status: api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	for _, lease := range []struct {
		id        string
		expiresAt time.Time
	}{{"router-live", now.Add(time.Minute)}, {"router-gone", now.Add(-40 * day)}} {
		if err := store.UpsertRouterLease(ctx, &storage.RouterLease{PeerID: lease.id, Addresses: []string{"/ip4/127.0.0.1/tcp/1"}, LastRenewal: now, ExpiresAt: lease.expiresAt}); err != nil {
			t.Fatal(err)
		}
	}
	// An admitted node that reported services, and a report left by a node
	// whose row the sweep already collected.
	admitted, gone := "admitted-peer", "gone-peer"
	if err := store.EnrollNode(ctx, &storage.EnrolledNode{
		PeerID: admitted, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode, EnrollmentType: "BOOTSTRAP", EnrolledAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(Options{
		DriverName: "sqlite", DataSourceName: "unused", OIDCIssuer: "https://issuer",
		NodeRetention: 30 * day, EphemeralNodeRetention: time.Hour,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	srv.catalog[admitted] = nodeCatalogEntry{ReportedAt: now}
	srv.catalog[gone] = nodeCatalogEntry{ReportedAt: now}

	before := map[string]float64{}
	for _, table := range []string{tableEnrollmentRequests, tableBootstrapTokens, tableRouters} {
		before[table] = counterValue(t, storageRowsDeletedTotal, table)
	}

	srv.gcStorage(now)

	for table, want := range map[string]float64{tableEnrollmentRequests: 1, tableBootstrapTokens: 1, tableRouters: 1} {
		if got := counterValue(t, storageRowsDeletedTotal, table) - before[table]; got != want {
			t.Errorf("storage_rows_deleted_total{table=%s} advanced by %v, want %v", table, got, want)
		}
	}
	counts, err := store.CountRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int64{"enrollment_requests": 1, "bootstrap_tokens": 1, "routers": 1, "nodes": 1} {
		if counts[table] != want {
			t.Errorf("%s has %d rows after the sweep, want %d", table, counts[table], want)
		}
	}
	if _, ok := srv.catalogSnapshot()[gone]; ok {
		t.Errorf("catalog still holds the report of a node that is no longer enrolled")
	}
	if _, ok := srv.catalogSnapshot()[admitted]; !ok {
		t.Errorf("catalog dropped the report of an admitted node")
	}
	var m dto.Metric
	if err := catalogEntries.Write(&m); err != nil {
		t.Fatal(err)
	}
	if got := m.GetGauge().GetValue(); got != 1 {
		t.Errorf("catalog_entries = %v, want 1", got)
	}
}

// A retention that is not positive is refused, not read as "keep forever":
// an unbounded nodes table is what this GC exists to prevent. Unset is the
// default (TestGCExpiredNodesDefaultsRetention).
func TestNodeRetentionMustBePositive(t *testing.T) {
	store := newMetricsTestStore(t)
	for _, retention := range []time.Duration{-1, -time.Hour} {
		_, err := NewServer(Options{DriverName: "sqlite", DataSourceName: "unused", OIDCIssuer: "https://issuer", NodeRetention: retention}, store)
		if err == nil || !strings.Contains(err.Error(), "NodeRetention must be positive") {
			t.Fatalf("NewServer with NodeRetention %s: err = %v, want a refusal naming NodeRetention", retention, err)
		}
	}
}

// The sweep runs at a tenth of the retention, no more often than every
// second and no less often than hourly: the default retention sweeps hourly,
// a test's retention of seconds sweeps every second.
func TestNodeGCIntervalFollowsRetention(t *testing.T) {
	for retention, want := range map[time.Duration]time.Duration{
		DefaultNodeRetention: time.Hour,
		24 * time.Hour:       time.Hour,
		5 * time.Hour:        30 * time.Minute,
		time.Second:          time.Second,
		3 * time.Second:      time.Second,
	} {
		if got := nodeGCInterval(retention); got != want {
			t.Errorf("nodeGCInterval(%s) = %s, want %s", retention, got, want)
		}
	}
}

// A caller that leaves NodeRetention unset, such as agentmesh-one, still
// reclaims rows whose session lapsed more than DefaultNodeRetention ago.
func TestGCExpiredNodesDefaultsRetention(t *testing.T) {
	store := newMetricsTestStore(t)
	ctx := context.Background()
	now := time.Now()
	for id, expiresAt := range map[string]time.Time{
		"stale":  now.Add(-DefaultNodeRetention - time.Hour),
		"recent": now.Add(-DefaultNodeRetention + time.Hour),
	} {
		if err := store.EnrollNode(ctx, &storage.EnrolledNode{
			PeerID: id, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode,
			EnrollmentType: "OIDC", EnrolledAt: now.Add(-90 * 24 * time.Hour), ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}

	srv, err := NewServer(Options{DriverName: "sqlite", DataSourceName: "unused", OIDCIssuer: "https://issuer"}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	srv.gcExpiredNodes(now)
	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].PeerID != "recent" {
		t.Fatalf("after a sweep with the default retention got %+v, want only recent", nodes)
	}
}

// listHookStore runs afterList once, after ListNodes has read the table and
// before its caller sees the result.
type listHookStore struct {
	storage.Store
	afterList func()
}

func (s *listHookStore) ListNodes(ctx context.Context, filter storage.NodeFilter) ([]storage.EnrolledNode, error) {
	nodes, err := s.Store.ListNodes(ctx, filter)
	if hook := s.afterList; hook != nil {
		s.afterList = nil
		hook()
	}
	return nodes, err
}

// A node whose session lapsed enrolls again and reports its services while
// the sweep is between listing the admitted nodes and pruning: its new
// report belongs to an admitted node and must survive the sweep, which only
// forgets the reports it saw before it listed.
func TestPruneCatalogKeepsAReportWrittenDuringTheSweep(t *testing.T) {
	base := newMetricsTestStore(t)
	store := &listHookStore{Store: base}
	ctx := context.Background()
	now := time.Now()
	enroll := func(id string, expiresAt time.Time) {
		t.Helper()
		if err := base.EnrollNode(ctx, &storage.EnrolledNode{
			PeerID: id, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode,
			EnrollmentType: "OIDC", EnrolledAt: now.Add(-time.Hour), ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	enroll("lapsed", now.Add(-time.Minute))

	srv, err := NewServer(Options{DriverName: "sqlite", DataSourceName: "unused", OIDCIssuer: "https://issuer"}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	srv.catalog["lapsed"] = nodeCatalogEntry{ReportedAt: now.Add(-time.Hour)}
	srv.catalog["gone"] = nodeCatalogEntry{ReportedAt: now.Add(-time.Hour)}

	fresh := now.Add(time.Second)
	store.afterList = func() {
		enroll("lapsed", now.Add(time.Hour))
		srv.catalogMu.Lock()
		srv.catalog["lapsed"] = nodeCatalogEntry{ReportedAt: fresh}
		srv.catalogMu.Unlock()
	}

	srv.pruneCatalog(now)

	snap := srv.catalogSnapshot()
	if entry, ok := snap["lapsed"]; !ok || !entry.ReportedAt.Equal(fresh) {
		t.Fatalf("report of the re-admitted node after the sweep: present=%v reported_at=%s, want the report written at %s", ok, entry.ReportedAt, fresh)
	}
	if _, ok := snap["gone"]; ok {
		t.Fatal("the sweep kept the report of a node that is not enrolled")
	}
}
