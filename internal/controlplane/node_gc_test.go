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
	"strings"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/storage"
	dto "github.com/prometheus/client_model/go"
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

	var before dto.Metric
	_ = nodesDeletedTotal.Write(&before)

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

	var after dto.Metric
	_ = nodesDeletedTotal.Write(&after)
	if got := after.GetCounter().GetValue() - before.GetCounter().GetValue(); got != 1 {
		t.Errorf("agentmesh_control_plane_nodes_deleted_total advanced by %v, want 1", got)
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
