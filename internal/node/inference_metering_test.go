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
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestInferenceService_PerCallerAndServiceAttribution(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"model":"m1","usage":{"prompt_tokens":10,"completion_tokens":20}}`)
	}))
	defer backend.Close()

	svc1 := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: "service-alpha"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc1.Init(context.Background()); err != nil {
		t.Fatalf("svc1.Init failed: %v", err)
	}

	svc2 := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: "service-beta"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc2.Init(context.Background()); err != nil {
		t.Fatalf("svc2.Init failed: %v", err)
	}

	caller1 := newInferenceTestPeer(t).String()
	caller2 := newInferenceTestPeer(t).String()

	reqBody := `{"messages":[{"role":"user","content":"hello"}]}`

	// Baseline snapshot
	snap := func(peerID, service, model string) (reqs, reqB, respB, pTok, cTok float64) {
		return getRequestCounterValue(peerID, service),
			getRequestBytesValue(peerID, service),
			getResponseBytesValue(peerID, service),
			getCounterValue(peerID, service, model, "prompt"),
			getCounterValue(peerID, service, model, "completion")
	}

	c1s1Reqs, c1s1ReqB, c1s1RespB, c1s1PTok, c1s1CTok := snap(caller1, "service-alpha", "m1")
	c1s2Reqs, c1s2ReqB, c1s2RespB, c1s2PTok, c1s2CTok := snap(caller1, "service-beta", "m1")
	c2s1Reqs, c2s1ReqB, c2s1RespB, c2s1PTok, c2s1CTok := snap(caller2, "service-alpha", "m1")

	// Call 1: Caller 1 -> Service Alpha
	callService := func(svc *InferenceService, caller string) int {
		req := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", bytes.NewReader([]byte(reqBody)))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Peer-Id", caller)
		w := httptest.NewRecorder()
		svc.Handler().ServeHTTP(w, req)
		resp := w.Result()
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return len(b)
	}

	respLen1 := callService(svc1, caller1)
	// Call 2: Caller 1 -> Service Beta
	respLen2 := callService(svc2, caller1)
	// Call 3: Caller 2 -> Service Alpha
	respLen3 := callService(svc1, caller2)

	// Check Caller 1 on Service Alpha
	if diff := getRequestCounterValue(caller1, "service-alpha") - c1s1Reqs; diff != 1 {
		t.Errorf("caller1 svc1 requests: got %f, want 1", diff)
	}
	if diff := getRequestBytesValue(caller1, "service-alpha") - c1s1ReqB; diff != float64(len(reqBody)) {
		t.Errorf("caller1 svc1 req bytes: got %f, want %d", diff, len(reqBody))
	}
	if diff := getResponseBytesValue(caller1, "service-alpha") - c1s1RespB; diff != float64(respLen1) {
		t.Errorf("caller1 svc1 resp bytes: got %f, want %d", diff, respLen1)
	}
	if diff := getCounterValue(caller1, "service-alpha", "m1", "prompt") - c1s1PTok; diff != 10 {
		t.Errorf("caller1 svc1 prompt tokens: got %f, want 10", diff)
	}
	if diff := getCounterValue(caller1, "service-alpha", "m1", "completion") - c1s1CTok; diff != 20 {
		t.Errorf("caller1 svc1 completion tokens: got %f, want 20", diff)
	}

	// Check Caller 1 on Service Beta
	if diff := getRequestCounterValue(caller1, "service-beta") - c1s2Reqs; diff != 1 {
		t.Errorf("caller1 svc2 requests: got %f, want 1", diff)
	}
	if diff := getRequestBytesValue(caller1, "service-beta") - c1s2ReqB; diff != float64(len(reqBody)) {
		t.Errorf("caller1 svc2 req bytes: got %f, want %d", diff, len(reqBody))
	}
	if diff := getResponseBytesValue(caller1, "service-beta") - c1s2RespB; diff != float64(respLen2) {
		t.Errorf("caller1 svc2 resp bytes: got %f, want %d", diff, respLen2)
	}
	if diff := getCounterValue(caller1, "service-beta", "m1", "prompt") - c1s2PTok; diff != 10 {
		t.Errorf("caller1 svc2 prompt tokens: got %f, want 10", diff)
	}
	if diff := getCounterValue(caller1, "service-beta", "m1", "completion") - c1s2CTok; diff != 20 {
		t.Errorf("caller1 svc2 completion tokens: got %f, want 20", diff)
	}

	// Check Caller 2 on Service Alpha
	if diff := getRequestCounterValue(caller2, "service-alpha") - c2s1Reqs; diff != 1 {
		t.Errorf("caller2 svc1 requests: got %f, want 1", diff)
	}
	if diff := getRequestBytesValue(caller2, "service-alpha") - c2s1ReqB; diff != float64(len(reqBody)) {
		t.Errorf("caller2 svc1 req bytes: got %f, want %d", diff, len(reqBody))
	}
	if diff := getResponseBytesValue(caller2, "service-alpha") - c2s1RespB; diff != float64(respLen3) {
		t.Errorf("caller2 svc1 resp bytes: got %f, want %d", diff, respLen3)
	}
	if diff := getCounterValue(caller2, "service-alpha", "m1", "prompt") - c2s1PTok; diff != 10 {
		t.Errorf("caller2 svc1 prompt tokens: got %f, want 10", diff)
	}
	if diff := getCounterValue(caller2, "service-alpha", "m1", "completion") - c2s1CTok; diff != 20 {
		t.Errorf("caller2 svc1 completion tokens: got %f, want 20", diff)
	}
}

func TestInferenceService_MissingUsageMetadata(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Upstream does not report usage
		_, _ = fmt.Fprint(w, `{"id":"chatcmpl-123","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"pong"}}]}`)
	}))
	defer backend.Close()

	serviceName := "test-missing-usage"
	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("svc.Init failed: %v", err)
	}

	peerID := newInferenceTestPeer(t).String()
	reqPayload := `{"messages":[{"role":"user","content":"ping"}]}`

	initReqs := getRequestCounterValue(peerID, serviceName)
	initReqB := getRequestBytesValue(peerID, serviceName)
	initRespB := getResponseBytesValue(peerID, serviceName)
	initPTok := getCounterValue(peerID, serviceName, "gpt-4o", "prompt")
	initCTok := getCounterValue(peerID, serviceName, "gpt-4o", "completion")

	req := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", bytes.NewReader([]byte(reqPayload)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Peer-Id", peerID)
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if diff := getRequestCounterValue(peerID, serviceName) - initReqs; diff != 1 {
		t.Errorf("requests: got %f, want 1", diff)
	}
	if diff := getRequestBytesValue(peerID, serviceName) - initReqB; diff != float64(len(reqPayload)) {
		t.Errorf("req bytes: got %f, want %d", diff, len(reqPayload))
	}
	if diff := getResponseBytesValue(peerID, serviceName) - initRespB; diff != float64(len(body)) {
		t.Errorf("resp bytes: got %f, want %d", diff, len(body))
	}
	if diff := getCounterValue(peerID, serviceName, "gpt-4o", "prompt") - initPTok; diff != 0 {
		t.Errorf("prompt tokens: got %f, want 0", diff)
	}
	if diff := getCounterValue(peerID, serviceName, "gpt-4o", "completion") - initCTok; diff != 0 {
		t.Errorf("completion tokens: got %f, want 0", diff)
	}
}

func TestInferenceService_StreamingMissingUsage(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = fmt.Fprint(w, "data: {\"model\":\"stream-model\",\"choices\":[{\"delta\":{\"content\":\"chunk1\"}}]}\n\n")
		flusher.Flush()
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer backend.Close()

	serviceName := "test-stream-no-usage"
	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("svc.Init failed: %v", err)
	}

	peerID := newInferenceTestPeer(t).String()
	reqPayload := `{"stream":true}`

	initReqs := getRequestCounterValue(peerID, serviceName)
	initReqB := getRequestBytesValue(peerID, serviceName)
	initRespB := getResponseBytesValue(peerID, serviceName)
	initPTok := getCounterValue(peerID, serviceName, "stream-model", "prompt")
	initCTok := getCounterValue(peerID, serviceName, "stream-model", "completion")

	req := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", bytes.NewReader([]byte(reqPayload)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Peer-Id", peerID)
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if diff := getRequestCounterValue(peerID, serviceName) - initReqs; diff != 1 {
		t.Errorf("requests: got %f, want 1", diff)
	}
	if diff := getRequestBytesValue(peerID, serviceName) - initReqB; diff != float64(len(reqPayload)) {
		t.Errorf("req bytes: got %f, want %d", diff, len(reqPayload))
	}
	if diff := getResponseBytesValue(peerID, serviceName) - initRespB; diff != float64(len(body)) {
		t.Errorf("resp bytes: got %f, want %d", diff, len(body))
	}
	if diff := getCounterValue(peerID, serviceName, "stream-model", "prompt") - initPTok; diff != 0 {
		t.Errorf("prompt tokens: got %f, want 0", diff)
	}
	if diff := getCounterValue(peerID, serviceName, "stream-model", "completion") - initCTok; diff != 0 {
		t.Errorf("completion tokens: got %f, want 0", diff)
	}
}

func TestInferenceService_ErrorPaths(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"error":{"message":"internal error","type":"server_error"}}`)
	}))
	defer backend.Close()

	serviceName := "test-error-path"
	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("svc.Init failed: %v", err)
	}

	peerID := newInferenceTestPeer(t).String()
	reqPayload := `{"model":"fail-model"}`

	initReqs := getRequestCounterValue(peerID, serviceName)
	initReqB := getRequestBytesValue(peerID, serviceName)
	initRespB := getResponseBytesValue(peerID, serviceName)
	initPTok := getCounterValue(peerID, serviceName, "fail-model", "prompt")
	initCTok := getCounterValue(peerID, serviceName, "fail-model", "completion")

	req := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", bytes.NewReader([]byte(reqPayload)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Peer-Id", peerID)
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	if diff := getRequestCounterValue(peerID, serviceName) - initReqs; diff != 1 {
		t.Errorf("requests: got %f, want 1", diff)
	}
	if diff := getRequestBytesValue(peerID, serviceName) - initReqB; diff != float64(len(reqPayload)) {
		t.Errorf("req bytes: got %f, want %d", diff, len(reqPayload))
	}
	if diff := getResponseBytesValue(peerID, serviceName) - initRespB; diff != float64(len(body)) {
		t.Errorf("resp bytes: got %f, want %d", diff, len(body))
	}
	if diff := getCounterValue(peerID, serviceName, "fail-model", "prompt") - initPTok; diff != 0 {
		t.Errorf("prompt tokens: got %f, want 0", diff)
	}
	if diff := getCounterValue(peerID, serviceName, "fail-model", "completion") - initCTok; diff != 0 {
		t.Errorf("completion tokens: got %f, want 0", diff)
	}
}

func TestInferenceService_IdentitySecurity_UntrustedHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"model":"m","usage":{"prompt_tokens":1,"completion_tokens":2}}`)
	}))
	defer backend.Close()

	serviceName := "test-spoof-defense"
	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("svc.Init failed: %v", err)
	}

	spoofedPeer := newInferenceTestPeer(t).String()
	reqPayload := `{"prompt":"test"}`

	initVictimReqs := getRequestCounterValue(spoofedPeer, serviceName)
	initUnknownReqs := getRequestCounterValue("unknown", serviceName)

	// An external request arriving from non-loopback IP (e.g. 198.51.100.42:54321)
	req := httptest.NewRequest("POST", "http://localhost/v1/completions", bytes.NewReader([]byte(reqPayload)))
	req.RemoteAddr = "198.51.100.42:54321"
	req.Header.Set("X-Peer-Id", spoofedPeer)
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	// Victim must NOT be charged
	if diff := getRequestCounterValue(spoofedPeer, serviceName) - initVictimReqs; diff != 0 {
		t.Errorf("spoofed victim was billed: got %f, want 0", diff)
	}
	// Must fall back to "unknown"
	if diff := getRequestCounterValue("unknown", serviceName) - initUnknownReqs; diff != 1 {
		t.Errorf("unknown requests: got %f, want 1", diff)
	}
}

func TestInferenceService_DirectPeerIDRemoteAddr(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"model":"m","usage":{"prompt_tokens":5,"completion_tokens":5}}`)
	}))
	defer backend.Close()

	serviceName := "test-direct-peer"
	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("svc.Init failed: %v", err)
	}

	// Valid libp2p peer ID in RemoteAddr as provided by libp2p-http listener
	peerID := newInferenceTestPeer(t).String()
	initReqs := getRequestCounterValue(peerID, serviceName)

	req := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", strings.NewReader(`{}`))
	req.RemoteAddr = peerID
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if diff := getRequestCounterValue(peerID, serviceName) - initReqs; diff != 1 {
		t.Errorf("direct peer ID requests: got %f, want 1", diff)
	}
}

func TestInferenceService_PrometheusMetricsEndpoint(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	node := &AgentMeshNode{Store: store, services: NewServiceRegistry(&fakeDHT{}, 0)}
	srv, err := StartMetricsServer(node, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"model":"m","usage":{"prompt_tokens":11,"completion_tokens":22}}`)
	}))
	defer backend.Close()

	serviceName := "test-prom-scrape"
	peerID := newInferenceTestPeer(t).String()

	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("svc.Init failed: %v", err)
	}

	req := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", strings.NewReader(`{"sample":"data"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Peer-Id", peerID)
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	metricsURL := "http://" + srv.Addr + "/metrics"
	resp, err := http.Get(metricsURL)
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	metricsBody, _ := io.ReadAll(resp.Body)
	text := string(metricsBody)

	expectedMetrics := []string{
		fmt.Sprintf(`agentmesh_node_inference_requests_total{peer_id="%s",service="%s"}`, peerID, serviceName),
		fmt.Sprintf(`agentmesh_node_inference_request_bytes_total{peer_id="%s",service="%s"}`, peerID, serviceName),
		fmt.Sprintf(`agentmesh_node_inference_response_bytes_total{peer_id="%s",service="%s"}`, peerID, serviceName),
		fmt.Sprintf(`agentmesh_node_inference_tokens_total{model="m",peer_id="%s",service="%s",token_type="prompt"}`, peerID, serviceName),
		fmt.Sprintf(`agentmesh_node_inference_tokens_total{model="m",peer_id="%s",service="%s",token_type="completion"}`, peerID, serviceName),
	}

	for _, expected := range expectedMetrics {
		if !strings.Contains(text, expected) {
			t.Errorf("metrics output missing expected line: %s\nFull metrics output:\n%s", expected, text)
		}
	}
}

func TestInferenceService_PeerIDCanonicalization(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"model":"m"}`)
	}))
	defer backend.Close()

	serviceName := "test-canonicalization"
	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("svc.Init failed: %v", err)
	}

	pid := newInferenceTestPeer(t)
	canonicalID := pid.String()
	cidAlias := peer.ToCid(pid).String()
	if cidAlias == canonicalID {
		t.Fatalf("expected CID alias to differ from canonical string")
	}

	initCanonicalReqs := getRequestCounterValue(canonicalID, serviceName)
	initAliasReqs := getRequestCounterValue(cidAlias, serviceName)
	initUnknownReqs := getRequestCounterValue("unknown", serviceName)

	// Case 1: Send request with CID alias in X-Peer-Id from localhost.
	// It should be canonicalized to canonicalID, not recorded under cidAlias.
	req1 := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", strings.NewReader(`{}`))
	req1.RemoteAddr = "127.0.0.1:1234"
	req1.Header.Set("X-Peer-Id", cidAlias)
	w1 := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w1, req1)

	if diff := getRequestCounterValue(canonicalID, serviceName) - initCanonicalReqs; diff != 1 {
		t.Errorf("canonical peer ID requests: got %f, want 1", diff)
	}
	if diff := getRequestCounterValue(cidAlias, serviceName) - initAliasReqs; diff != 0 {
		t.Errorf("alias peer ID was directly recorded: got %f, want 0", diff)
	}

	// Case 2: Send request with CID alias directly in RemoteAddr.
	// It should also decode and canonicalize to canonicalID.
	req2 := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", strings.NewReader(`{}`))
	req2.RemoteAddr = cidAlias
	w2 := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w2, req2)

	if diff := getRequestCounterValue(canonicalID, serviceName) - initCanonicalReqs; diff != 2 {
		t.Errorf("canonical peer ID requests after RemoteAddr alias: got %f, want 2", diff)
	}

	// Case 3: Send request with an invalid non-peer string; must fall back to "unknown".
	reqInvalid := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", strings.NewReader(`{}`))
	reqInvalid.RemoteAddr = "127.0.0.1:1234"
	reqInvalid.Header.Set("X-Peer-Id", "not-a-valid-peer-id")
	wInvalid := httptest.NewRecorder()

	svc.Handler().ServeHTTP(wInvalid, reqInvalid)

	if diff := getRequestCounterValue("unknown", serviceName) - initUnknownReqs; diff != 1 {
		t.Errorf("unknown requests after invalid peer ID: got %f, want 1", diff)
	}
}

func TestInferenceService_ExcludeDiscoveryProbes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/v1/models" {
			_, _ = fmt.Fprint(w, `{"object":"list","data":[{"id":"m1"}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"model":"m1","usage":{"prompt_tokens":5,"completion_tokens":5}}`)
	}))
	defer backend.Close()

	serviceName := "test-probe-exclusion"
	svc := &InferenceService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: serviceName},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		},
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("svc.Init failed: %v", err)
	}

	peerID := newInferenceTestPeer(t).String()

	initReqs := getRequestCounterValue(peerID, serviceName)
	initReqB := getRequestBytesValue(peerID, serviceName)
	initRespB := getResponseBytesValue(peerID, serviceName)

	// 1. Send GET /v1/models (discovery probe)
	reqProbe := httptest.NewRequest("GET", "http://localhost/v1/models", nil)
	reqProbe.RemoteAddr = "127.0.0.1:1234"
	reqProbe.Header.Set("X-Peer-Id", peerID)
	wProbe := httptest.NewRecorder()
	svc.Handler().ServeHTTP(wProbe, reqProbe)

	if wProbe.Code != http.StatusOK {
		t.Fatalf("probe status = %d, want %d", wProbe.Code, http.StatusOK)
	}

	// Discovery probes must NOT increment any inference counters
	if diff := getRequestCounterValue(peerID, serviceName) - initReqs; diff != 0 {
		t.Errorf("discovery probe incremented requests: got %f, want 0", diff)
	}
	if diff := getRequestBytesValue(peerID, serviceName) - initReqB; diff != 0 {
		t.Errorf("discovery probe incremented req bytes: got %f, want 0", diff)
	}
	if diff := getResponseBytesValue(peerID, serviceName) - initRespB; diff != 0 {
		t.Errorf("discovery probe incremented resp bytes: got %f, want 0", diff)
	}

	// 2. Send actual inference call (POST /v1/chat/completions)
	reqInf := httptest.NewRequest("POST", "http://localhost/v1/chat/completions", strings.NewReader(`{"model":"m1"}`))
	reqInf.RemoteAddr = "127.0.0.1:1234"
	reqInf.Header.Set("X-Peer-Id", peerID)
	wInf := httptest.NewRecorder()
	svc.Handler().ServeHTTP(wInf, reqInf)

	if wInf.Code != http.StatusOK {
		t.Fatalf("inference status = %d, want %d", wInf.Code, http.StatusOK)
	}

	// Actual inference request MUST increment counters
	if diff := getRequestCounterValue(peerID, serviceName) - initReqs; diff != 1 {
		t.Errorf("inference requests: got %f, want 1", diff)
	}
}
