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

func TestNodeGCLoopIsOffWithoutRetention(t *testing.T) {
	store := newMetricsTestStore(t)
	ctx := context.Background()
	now := time.Now()
	if err := store.EnrollNode(ctx, &storage.EnrolledNode{
		PeerID: "lapsed", PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode,
		EnrollmentType: "OIDC", EnrolledAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(Options{DriverName: "sqlite", DataSourceName: "unused", OIDCIssuer: "https://issuer", NodeRetention: -1}, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	// The loop returns immediately with a negative retention, and a direct
	// sweep is a no-op too: it means keep forever, not "expired as of now".
	srv.wg.Add(1)
	srv.runNodeGCLoop()
	srv.gcExpiredNodes(now)
	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("negative retention deleted rows: %d left", len(nodes))
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
