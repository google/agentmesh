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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/google/agentmesh/internal/storage"
)

const (
	// DefaultNodeRetention keeps a lapsed enrollment for a month past its
	// session, and a bootstrap enrollment for a month past its last refresh,
	// long enough to be looked up when investigating an incident, and is
	// what --node-retention defaults to.
	DefaultNodeRetention = 30 * 24 * time.Hour

	// DefaultEphemeralNodeRetention is how long a member an ephemeral token
	// enrolled is kept after its last refresh: an hour, long past the few
	// minutes a member of a fleet, a probe or a CI job stays, and what
	// --ephemeral-node-retention defaults to.
	DefaultEphemeralNodeRetention = time.Hour

	// maxNodeGCInterval bounds how often the sweep runs. Rows lapse on a
	// scale of days, so nothing is gained by sweeping more often than hourly;
	// a retention far shorter than that, as a test sets, sweeps at a tenth
	// of it so a lapsed row does not outlive the retention by much.
	maxNodeGCInterval = time.Hour
	minNodeGCInterval = time.Second
)

// nodeGCInterval is the sweep period for a retention: a tenth of it, within
// [minNodeGCInterval, maxNodeGCInterval].
func nodeGCInterval(retention time.Duration) time.Duration {
	return min(maxNodeGCInterval, max(minNodeGCInterval, retention/10))
}

var nodesDeletedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "agentmesh_control_plane_nodes_deleted_total",
	Help: "Enrolled node records removed by the node GC, by reason: session for a session that lapsed more than the retention ago, silent for a bootstrap member that did not refresh for the retention, ephemeral for one an ephemeral token enrolled that did not refresh for the ephemeral retention",
}, []string{"reason"})

const (
	deletedReasonSession   = "session"
	deletedReasonSilent    = "silent"
	deletedReasonEphemeral = "ephemeral"
)

var storageRowsDeletedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "agentmesh_control_plane_storage_rows_deleted_total",
	Help: "Rows the storage GC removed from a table other than nodes: enrollment requests older than the retention, bootstrap tokens expired for the retention that no request refers to, router leases expired for the retention",
}, []string{"table"})

var catalogEntries = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "agentmesh_control_plane_catalog_entries",
	Help: "Service reports the control plane holds in memory, one per node that reported since it was admitted",
})

const (
	tableEnrollmentRequests = "enrollment_requests"
	tableBootstrapTokens    = "bootstrap_tokens"
	tableRouters            = "routers"
)

func init() {
	for _, reason := range []string{deletedReasonSession, deletedReasonSilent, deletedReasonEphemeral} {
		nodesDeletedTotal.WithLabelValues(reason)
	}
	for _, table := range []string{tableEnrollmentRequests, tableBootstrapTokens, tableRouters} {
		storageRowsDeletedTotal.WithLabelValues(table)
	}
}

// runNodeGCLoop sweeps once at start and then hourly. Replicas each sweep
// against the shared database; the deletes are idempotent, so the race is
// harmless and not worth a claim.
func (s *Server) runNodeGCLoop() {
	defer s.wg.Done()
	s.gcStorage(time.Now())

	ticker := time.NewTicker(nodeGCInterval(s.config.NodeRetention))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.gcStorage(time.Now())
		case <-s.ctx.Done():
			return
		}
	}
}

// gcStorage is one sweep over everything that grows with mesh activity: the
// node records, the enrollment requests, the bootstrap tokens, the router
// leases, and the in-memory service catalog. Each step logs its own failure
// and the next one still runs, so one table's trouble does not let another
// grow.
func (s *Server) gcStorage(now time.Time) {
	s.gcExpiredNodes(now)
	if s.ctx.Err() != nil {
		return
	}
	s.gcEnrollmentRecords(now)
	if s.ctx.Err() != nil {
		return
	}
	s.pruneCatalog(now)
}

// gcEnrollmentRecords deletes the enrollment requests resolved, or left
// pending, more than NodeRetention ago (EphemeralNodeRetention when an
// ephemeral token made them), then the bootstrap tokens that expired more
// than NodeRetention ago and that no remaining request refers to, then the
// router leases expired for as long. Requests go before tokens because a
// request refers to its token.
func (s *Server) gcEnrollmentRecords(now time.Time) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	before := now.Add(-s.config.NodeRetention)
	requests, err := s.store.DeleteStaleEnrollmentRequests(ctx, before, now.Add(-s.config.EphemeralNodeRetention))
	if err != nil {
		logger.Errorf("Failed to delete stale enrollment requests: %v", err)
	} else if requests > 0 {
		storageRowsDeletedTotal.WithLabelValues(tableEnrollmentRequests).Add(float64(requests))
		logger.Infof("Deleted %d enrollment requests older than the retention", requests)
	}

	tokens, err := s.store.DeleteExpiredBootstrapTokens(ctx, before)
	if err != nil {
		logger.Errorf("Failed to delete expired bootstrap tokens: %v", err)
	} else if tokens > 0 {
		storageRowsDeletedTotal.WithLabelValues(tableBootstrapTokens).Add(float64(tokens))
		logger.Infof("Deleted %d bootstrap tokens expired more than %s ago", tokens, s.config.NodeRetention)
	}

	leases, err := s.store.DeleteExpiredRouterLeases(ctx, before)
	if err != nil {
		logger.Errorf("Failed to delete expired router leases: %v", err)
	} else if leases > 0 {
		storageRowsDeletedTotal.WithLabelValues(tableRouters).Add(float64(leases))
		logger.Infof("Deleted %d router leases expired more than %s ago", leases, s.config.NodeRetention)
	}
}

// pruneCatalog forgets the service report of every peer that is no longer
// an admitted node: its enrollment lapsed, was collected or was banned on
// another replica. The console already hides such reports; this keeps the
// cache from holding one entry per member that ever joined until the next
// restart.
func (s *Server) pruneCatalog(now time.Time) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	snap := s.catalogSnapshot()
	if len(snap) == 0 {
		catalogEntries.Set(0)
		return
	}
	admitted, err := s.store.ListNodes(ctx, storage.NodeFilter{States: []storage.NodeState{storage.NodeAdmitted}, Now: now})
	if err != nil {
		logger.Errorf("Failed to list admitted nodes to prune the service catalog: %v", err)
		return
	}
	keep := make(map[string]struct{}, len(admitted))
	for i := range admitted {
		keep[admitted[i].PeerID] = struct{}{}
	}
	dropped := 0
	s.catalogMu.Lock()
	for peerID, seen := range snap {
		if _, ok := keep[peerID]; ok {
			continue
		}
		// A report written since the snapshot came from a node admitted
		// when it reported, after the list was read: it is not this
		// sweep's to drop.
		if cur, ok := s.catalog[peerID]; ok && !cur.ReportedAt.Equal(seen.ReportedAt) {
			logger.Debugw("Kept service report written during the sweep", "peer_id", peerID)
			continue
		}
		delete(s.catalog, peerID)
		logger.Debugw("Dropped service report of a node no longer admitted", "peer_id", peerID)
		dropped++
	}
	remaining := len(s.catalog)
	s.catalogMu.Unlock()
	catalogEntries.Set(float64(remaining))
	if dropped > 0 {
		logger.Infof("Dropped %d service reports of nodes no longer admitted, %d remain", dropped, remaining)
	}
}

// gcExpiredNodes deletes every unbanned node whose session expired more than
// NodeRetention before now, and every unbanned bootstrap member, which has
// no session, that did not refresh for NodeRetention, or for
// EphemeralNodeRetention when an ephemeral token enrolled it. Options.Validate
// has refused a retention that is not positive, so there is no "keep
// forever": an unbounded nodes table is what slowed every console refresh
// and metrics scrape.
func (s *Server) gcExpiredNodes(now time.Time) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	deleted, err := s.store.DeleteExpiredNodes(ctx, now.Add(-s.config.NodeRetention))
	if err != nil {
		logger.Errorf("Failed to delete expired node records: %v", err)
		return
	}
	if deleted > 0 {
		nodesDeletedTotal.WithLabelValues(deletedReasonSession).Add(float64(deleted))
		logger.Infof("Deleted %d node records whose session expired more than %s ago", deleted, s.config.NodeRetention)
	}

	silent, ephemeral, err := s.store.DeleteSilentBootstrapNodes(ctx, now.Add(-s.config.NodeRetention), now.Add(-s.config.EphemeralNodeRetention))
	if err != nil {
		logger.Errorf("Failed to delete silent bootstrap node records: %v", err)
		return
	}
	if silent > 0 {
		nodesDeletedTotal.WithLabelValues(deletedReasonSilent).Add(float64(silent))
		logger.Infof("Deleted %d bootstrap node records that did not refresh for %s", silent, s.config.NodeRetention)
	}
	if ephemeral > 0 {
		nodesDeletedTotal.WithLabelValues(deletedReasonEphemeral).Add(float64(ephemeral))
		logger.Infof("Deleted %d ephemeral node records that did not refresh for %s", ephemeral, s.config.EphemeralNodeRetention)
	}
}
