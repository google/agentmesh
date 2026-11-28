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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	inferenceRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_node_inference_requests_total",
			Help: "Total number of inference requests served by this node, by caller peer ID and service",
		},
		[]string{"peer_id", "service"},
	)

	inferenceTokensTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_node_inference_tokens_total",
			Help: "Total number of inference tokens tracked by agentmesh-node, by caller peer ID, service, model, and token type",
		},
		[]string{"peer_id", "service", "model", "token_type"},
	)

	inferenceRequestBytesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_node_inference_request_bytes_total",
			Help: "Total number of inference request bytes received by this node, by caller peer ID and service",
		},
		[]string{"peer_id", "service"},
	)

	inferenceResponseBytesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_node_inference_response_bytes_total",
			Help: "Total number of inference response bytes sent by this node, by caller peer ID and service",
		},
		[]string{"peer_id", "service"},
	)

	facadeRejectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agentmesh_node_facade_rejections_total",
			Help: "Providers excluded by the OpenAI facade scorer, by reason",
		},
		[]string{"reason"},
	)

	facadeRetriesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "agentmesh_node_facade_retries_total",
			Help: "Completion attempts retried on another provider after a retryable failure",
		},
	)
)

// recordFacadeRejection accounts one excluded provider by reason.
func recordFacadeRejection(reason string) {
	facadeRejectionsTotal.WithLabelValues(reason).Inc()
}

func recordFacadeRetry() {
	facadeRetriesTotal.Inc()
}

// recordInferenceRequest increments the inference request metric for the caller peer and service.
func recordInferenceRequest(peerID, service string) {
	if peerID == "" {
		peerID = "unknown"
	}
	if service == "" {
		service = "unknown"
	}
	inferenceRequestsTotal.WithLabelValues(peerID, service).Inc()
}

// recordInferenceBytes increments the inference request and response byte metrics.
func recordInferenceBytes(peerID, service string, reqBytes, respBytes int64) {
	if peerID == "" {
		peerID = "unknown"
	}
	if service == "" {
		service = "unknown"
	}
	if reqBytes > 0 {
		inferenceRequestBytesTotal.WithLabelValues(peerID, service).Add(float64(reqBytes))
	}
	if respBytes > 0 {
		inferenceResponseBytesTotal.WithLabelValues(peerID, service).Add(float64(respBytes))
	}
}

// recordTokens increments the prompt and completion token metrics attributed to caller peer, service, and model.
func recordTokens(peerID, service, model string, promptTokens, completionTokens int) {
	if peerID == "" {
		peerID = "unknown"
	}
	if service == "" {
		service = "unknown"
	}
	if model == "" {
		model = "unknown"
	}
	if promptTokens > 0 {
		inferenceTokensTotal.WithLabelValues(peerID, service, model, "prompt").Add(float64(promptTokens))
	}
	if completionTokens > 0 {
		inferenceTokensTotal.WithLabelValues(peerID, service, model, "completion").Add(float64(completionTokens))
	}
}
