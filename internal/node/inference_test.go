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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	dto "github.com/prometheus/client_model/go"
)

func newInferenceTestPeer(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("crypto.GenerateKeyPair: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("peer.IDFromPrivateKey: %v", err)
	}
	return id
}

func getCounterValue(peerID, service, model, tokenType string) float64 {
	metric, err := inferenceTokensTotal.GetMetricWithLabelValues(peerID, service, model, tokenType)
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := metric.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func getRequestCounterValue(peerID, service string) float64 {
	metric, err := inferenceRequestsTotal.GetMetricWithLabelValues(peerID, service)
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := metric.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func getRequestBytesValue(peerID, service string) float64 {
	metric, err := inferenceRequestBytesTotal.GetMetricWithLabelValues(peerID, service)
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := metric.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func getResponseBytesValue(peerID, service string) float64 {
	metric, err := inferenceResponseBytesTotal.GetMetricWithLabelValues(peerID, service)
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := metric.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// The backend sees no forwarding header a caller sent and no Go default
// User-Agent: ReverseProxy strips Forwarded and X-Forwarded-* before its
// Rewrite runs and blanks a missing User-Agent, the same in Rewrite mode
// as the Director used to do by hand.
func TestInferenceService_ForwardingHeadersDoNotReachTheBackend(t *testing.T) {
	var seen http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: "test-inference-headers"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: server.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	req := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", strings.NewReader(`{}`))
	req.RemoteAddr = "12D3KooWpeer"
	req.Header.Set("Forwarded", "for=spoofed;host=spoofed;proto=spoofed")
	req.Header.Set("X-Forwarded-For", "spoofed")
	req.Header.Set("X-Forwarded-Host", "spoofed")
	req.Header.Set("X-Forwarded-Proto", "spoofed")
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if got, ok := seen[name]; ok {
			t.Errorf("backend saw %s: %q", name, got)
		}
	}
	if got := seen.Get("User-Agent"); got != "" {
		t.Errorf("backend saw User-Agent %q, want none", got)
	}
}

func TestInferenceService_TokenAccountability_JSON(t *testing.T) {
	peerID := newInferenceTestPeer(t).String()
	modelName := "test-model-json"
	serviceName := "test-inference-json"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{
			"model": "%s",
			"usage": {
				"prompt_tokens": 42,
				"completion_tokens": 99
			}
		}`, modelName)
	}))
	defer server.Close()

	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: server.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	reqPayload := `{"test":true}`
	req := httptest.NewRequest("POST", "http://localhost/chat", bytes.NewReader([]byte(reqPayload)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Peer-Id", peerID)
	w := httptest.NewRecorder()

	initialPromptTokens := getCounterValue(peerID, serviceName, modelName, "prompt")
	initialCompletionTokens := getCounterValue(peerID, serviceName, modelName, "completion")
	initialRequests := getRequestCounterValue(peerID, serviceName)
	initialReqBytes := getRequestBytesValue(peerID, serviceName)
	initialRespBytes := getResponseBytesValue(peerID, serviceName)

	svc.Handler().ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d, body: %s", resp.StatusCode, string(body))
	}

	promptTokens := getCounterValue(peerID, serviceName, modelName, "prompt") - initialPromptTokens
	completionTokens := getCounterValue(peerID, serviceName, modelName, "completion") - initialCompletionTokens
	requests := getRequestCounterValue(peerID, serviceName) - initialRequests
	reqBytes := getRequestBytesValue(peerID, serviceName) - initialReqBytes
	respBytes := getResponseBytesValue(peerID, serviceName) - initialRespBytes

	if promptTokens != 42 {
		t.Errorf("Expected 42 prompt tokens, got %f", promptTokens)
	}
	if completionTokens != 99 {
		t.Errorf("Expected 99 completion tokens, got %f", completionTokens)
	}
	if requests != 1 {
		t.Errorf("Expected 1 request, got %f", requests)
	}
	if reqBytes != float64(len(reqPayload)) {
		t.Errorf("Expected %d request bytes, got %f", len(reqPayload), reqBytes)
	}
	if respBytes != float64(len(body)) {
		t.Errorf("Expected %d response bytes, got %f", len(body), respBytes)
	}
}

func TestInferenceService_TokenAccountability_SSE(t *testing.T) {
	peerID := newInferenceTestPeer(t).String()
	modelName := "test-model-sse"
	serviceName := "test-inference-sse"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)

		_, _ = fmt.Fprintf(w, "data: {\"model\":\"%s\"}\n\n", modelName)
		flusher.Flush()

		_, _ = fmt.Fprintf(w, "data: {\"model\":\"%s\",\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":150}}\n\n", modelName)
		flusher.Flush()

		_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer server.Close()

	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: server.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	reqPayload := `{"test":true}`
	req := httptest.NewRequest("POST", "http://localhost/chat", bytes.NewReader([]byte(reqPayload)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Peer-Id", peerID)
	w := httptest.NewRecorder()

	initialPromptTokens := getCounterValue(peerID, serviceName, modelName, "prompt")
	initialCompletionTokens := getCounterValue(peerID, serviceName, modelName, "completion")
	initialRequests := getRequestCounterValue(peerID, serviceName)
	initialReqBytes := getRequestBytesValue(peerID, serviceName)
	initialRespBytes := getResponseBytesValue(peerID, serviceName)

	svc.Handler().ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d, body: %s", resp.StatusCode, string(body))
	}

	// Let's assert that we actually got the SSE stream
	if !strings.Contains(string(body), "[DONE]") {
		t.Fatalf("Expected body to contain [DONE], got: %q", string(body))
	}

	promptTokens := getCounterValue(peerID, serviceName, modelName, "prompt") - initialPromptTokens
	completionTokens := getCounterValue(peerID, serviceName, modelName, "completion") - initialCompletionTokens
	requests := getRequestCounterValue(peerID, serviceName) - initialRequests
	reqBytes := getRequestBytesValue(peerID, serviceName) - initialReqBytes
	respBytes := getResponseBytesValue(peerID, serviceName) - initialRespBytes

	if promptTokens != 50 {
		t.Errorf("Expected 50 prompt tokens, got %f", promptTokens)
	}
	if completionTokens != 150 {
		t.Errorf("Expected 150 completion tokens, got %f", completionTokens)
	}
	if requests != 1 {
		t.Errorf("Expected 1 request, got %f", requests)
	}
	if reqBytes != float64(len(reqPayload)) {
		t.Errorf("Expected %d request bytes, got %f", len(reqPayload), reqBytes)
	}
	if respBytes != float64(len(body)) {
		t.Errorf("Expected %d response bytes, got %f", len(body), respBytes)
	}
}
