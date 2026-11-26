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

package containment

import (
	golog "github.com/ipfs/go-log/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

var logger = golog.Logger("agentmesh-containment")

var (
	containmentQueuedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_containment_events_queued_total",
			Help: "Total security signals queued for containment webhook delivery.",
		},
		[]string{"signal_type"},
	)

	containmentDeliveredTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_containment_events_delivered_total",
			Help: "Total containment webhook events delivered, by signal type and HTTP status code.",
		},
		[]string{"signal_type", "status_code"},
	)

	containmentDroppedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_containment_events_dropped_total",
			Help: "Total containment webhook events dropped, by signal type and reason (buffer_full, client_timeout, transport_error, shutdown_timeout).",
		},
		[]string{"signal_type", "reason"},
	)

	containmentCoalescedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_containment_events_coalesced_total",
			Help: "Total rapid duplicate security signals coalesced within the deduplication window.",
		},
		[]string{"signal_type"},
	)

	containmentDeliveryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "agentmesh_containment_delivery_duration_seconds",
			Help:    "Webhook HTTP delivery duration in seconds.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		[]string{"signal_type"},
	)

	containmentQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "agentmesh_containment_queue_depth",
			Help: "Current depth of the containment webhook ring buffer queue.",
		},
	)

	containmentCoalescerEntries = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "agentmesh_containment_coalescer_entries",
			Help: "Current number of active deduplication entries held by the containment coalescer.",
		},
	)

	containmentCoalescerOverflowTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "agentmesh_containment_coalescer_overflow_total",
			Help: "Total containment signals that bypassed coalescing because the active entry cap was reached.",
		},
	)
)

// GetDroppedCount returns the sum of dropped events across all reasons and types.
func GetDroppedCount() int64 {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return 0
	}
	var total float64
	for _, mf := range mfs {
		if mf.GetName() == "agentmesh_containment_events_dropped_total" {
			for _, m := range mf.GetMetric() {
				if m.GetCounter() != nil {
					total += m.GetCounter().GetValue()
				}
			}
		}
	}
	return int64(total)
}

// GetDroppedCountFor returns the count of dropped events for a specific signal type and reason.
func GetDroppedCountFor(signalType, reason string) float64 {
	m := &dto.Metric{}
	if err := containmentDroppedTotal.WithLabelValues(signalType, reason).Write(m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// GetDeliveredCountFor returns the count of delivered events for a specific signal type and status code.
func GetDeliveredCountFor(signalType, statusCode string) float64 {
	m := &dto.Metric{}
	if err := containmentDeliveredTotal.WithLabelValues(signalType, statusCode).Write(m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}
