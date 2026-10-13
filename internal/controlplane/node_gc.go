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
)

const (
	// DefaultNodeRetention keeps a lapsed enrollment for a month past its
	// session, long enough to be looked up when investigating an incident,
	// and is what --node-retention defaults to.
	DefaultNodeRetention = 30 * 24 * time.Hour

	// nodeGCInterval is how often the sweep runs. Rows lapse on a scale of
	// days, so nothing is gained by sweeping more often than hourly.
	nodeGCInterval = time.Hour
)

var nodesDeletedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "agentmesh_control_plane_nodes_deleted_total",
	Help: "Enrolled node records removed after outliving their session by the retention period",
})

// runNodeGCLoop sweeps once at start and then hourly. Replicas each sweep
// against the shared database; the delete is idempotent, so the race is
// harmless and not worth a claim.
func (s *Server) runNodeGCLoop() {
	defer s.wg.Done()
	if s.config.NodeRetention <= 0 {
		return
	}

	s.gcExpiredNodes(time.Now())

	ticker := time.NewTicker(nodeGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.gcExpiredNodes(time.Now())
		case <-s.ctx.Done():
			return
		}
	}
}

// gcExpiredNodes deletes every unbanned node whose session expired more than
// NodeRetention before now. A negative retention means keep forever, and that
// holds here too, not only in the loop that decides whether to tick.
func (s *Server) gcExpiredNodes(now time.Time) {
	if s.config.NodeRetention <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	deleted, err := s.store.DeleteExpiredNodes(ctx, now.Add(-s.config.NodeRetention))
	if err != nil {
		logger.Errorf("Failed to delete expired node records: %v", err)
		return
	}
	if deleted > 0 {
		nodesDeletedTotal.Add(float64(deleted))
		logger.Infof("Deleted %d node records whose session expired more than %s ago", deleted, s.config.NodeRetention)
	}
}
