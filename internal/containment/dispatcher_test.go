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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDispatcher_TableDrivenSignals(t *testing.T) {
	now := timestamppb.New(time.Date(2026, 11, 10, 20, 0, 0, 0, time.UTC))

	cases := []struct {
		name         string
		signalType   string
		subject      string
		setPayload   func(ev *api.SecuritySignalEvent)
		wantFieldKey string
	}{
		{
			name:       "policy.denied",
			signalType: "agentmesh.policy.denied",
			subject:    "peer-alpha",
			setPayload: func(ev *api.SecuritySignalEvent) {
				ev.Data = &api.SecuritySignalEvent_PolicyDenied{
					PolicyDenied: &api.PolicyDeniedSignal{
						Direction:         api.SignalCallerDirection_LOCAL_WORKLOAD,
						Reason:            api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
						Detail:            "datalog block 0 denied egress",
						TargetService:     "bigquery",
						RequestedResource: "//bigquery.googleapis.com/projects/p1",
						EventTime:         now,
					},
				}
			},
			wantFieldKey: "policy_denied",
		},
		{
			name:       "transport.refused",
			signalType: "agentmesh.transport.refused",
			subject:    "peer-bravo",
			setPayload: func(ev *api.SecuritySignalEvent) {
				ev.Data = &api.SecuritySignalEvent_TransportRefused{
					TransportRefused: &api.TransportRefusedSignal{
						Reason:          api.TransportRefusalReason_PEER_UNAUTHENTICATED,
						Detail:          "handshake unauthenticated",
						PeerId:          "peer-bravo",
						RemoteMultiaddr: "/ip4/192.168.1.50/tcp/4001",
						CoalescedCount:  1,
						FirstSeenTime:   now,
						EventTime:       now,
					},
				}
			},
			wantFieldKey: "transport_refused",
		},
		{
			name:       "identity.revoked",
			signalType: "agentmesh.identity.revoked",
			subject:    "peer-charlie",
			setPayload: func(ev *api.SecuritySignalEvent) {
				ev.Data = &api.SecuritySignalEvent_IdentityRevoked{
					IdentityRevoked: &api.IdentityRevokedSignal{
						PeerId:    "peer-charlie",
						Source:    api.RevocationSource_LOCAL_CONTROL_PLANE_SYNC,
						Reason:    "compromised credential reported",
						EventTime: now,
					},
				}
			},
			wantFieldKey: "identity_revoked",
		},
		{
			name:       "enrollment.rejected",
			signalType: "agentmesh.enrollment.rejected",
			subject:    "peer-delta",
			setPayload: func(ev *api.SecuritySignalEvent) {
				ev.Data = &api.SecuritySignalEvent_EnrollmentRejected{
					EnrollmentRejected: &api.EnrollmentRejectedSignal{
						Reason:    api.EnrollmentRejectionReason_AUTONOMOUS_RECOVERY_DISABLED,
						Detail:    "proof-of-possession expired",
						PeerId:    "peer-delta",
						EventTime: now,
					},
				}
			},
			wantFieldKey: "enrollment_rejected",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan *api.SecuritySignalEvent, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("ce-specversion") != "1.0" {
					t.Errorf("got ce-specversion %q, want 1.0", r.Header.Get("ce-specversion"))
				}
				if r.Header.Get("ce-type") != tc.signalType {
					t.Errorf("got ce-type %q, want %q", r.Header.Get("ce-type"), tc.signalType)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("got Content-Type %q, want application/json", r.Header.Get("Content-Type"))
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("io.ReadAll: %v", err)
				}
				ev := &api.SecuritySignalEvent{}
				if err := protojson.Unmarshal(body, ev); err != nil {
					t.Errorf("protojson.Unmarshal failed: %v", err)
				}
				received <- ev
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)

			disp, err := NewDispatcher(Config{
				Endpoints: []EndpointConfig{{URL: srv.URL}},
			})
			if err != nil {
				t.Fatalf("NewDispatcher: %v", err)
			}
			t.Cleanup(func() { _ = disp.Close(context.Background()) })

			ev := &api.SecuritySignalEvent{
				Id:              "test-id-1234",
				Source:          "urn:agentmesh:node:test",
				SpecVersion:     "1.0",
				Type:            tc.signalType,
				EventTime:       now,
				DataContentType: "application/json",
				Subject:         tc.subject,
			}
			tc.setPayload(ev)

			disp.Dispatch(ev)

			select {
			case got := <-received:
				if got.Type != tc.signalType {
					t.Errorf("got event type %q, want %q", got.Type, tc.signalType)
				}
				if got.Subject != tc.subject {
					t.Errorf("got subject %q, want %q", got.Subject, tc.subject)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("timeout waiting for signal delivery")
			}
		})
	}
}

func TestDispatcher_NonBlockingEnqueueAndShedding(t *testing.T) {
	blockWorker := make(chan struct{})
	workerStarted := make(chan struct{})
	var workerStartedOnce sync.Once
	var deliveredCount atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workerStartedOnce.Do(func() { close(workerStarted) })
		<-blockWorker // Hold worker
		deliveredCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		select {
		case <-blockWorker:
		default:
			close(blockWorker)
		}
		srv.Close()
	})

	// Queue capacity of 2 with 1 worker
	disp, err := NewDispatcher(Config{
		QueueCapacity: 2,
		Workers:       1,
		Endpoints:     []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	now := timestamppb.Now()
	makeEvent := func(i int) *api.SecuritySignalEvent {
		return &api.SecuritySignalEvent{
			Id:          fmt.Sprintf("id-%d", i),
			Type:        "agentmesh.policy.denied",
			Source:      "urn:agentmesh:node:test",
			SpecVersion: "1.0",
			EventTime:   now,
			Data: &api.SecuritySignalEvent_PolicyDenied{
				PolicyDenied: &api.PolicyDeniedSignal{
					TargetService: fmt.Sprintf("service-%d", i),
					Detail:        "denied",
				},
			},
		}
	}

	// Dispatch 1 event to enter worker loop and block in HTTP handler
	disp.Dispatch(makeEvent(0))
	select {
	case <-workerStarted:
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for worker to reach blocked handler")
	}

	initialDropped := GetDroppedCount()

	// Dispatch 10 events rapidly. Must return immediately without blocking.
	start := time.Now()
	for i := 1; i <= 10; i++ {
		disp.Dispatch(makeEvent(i))
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Dispatch loop took %v, want <100ms (strictly non-blocking)", elapsed)
	}

	// Unblock worker and shut down
	close(blockWorker)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	finalDropped := GetDroppedCount()
	droppedDelta := finalDropped - initialDropped
	// 2 in queue = delivered; 8 dropped
	if droppedDelta != 8 {
		t.Errorf("dropped events = %d, want 8", droppedDelta)
	}
	if deliveredCount.Load() != 3 {
		t.Errorf("delivered count = %d, want 3", deliveredCount.Load())
	}
}

func TestDispatcher_CoalescingWindow(t *testing.T) {
	var receivedMu sync.Mutex
	var received []*api.SecuritySignalEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ev := &api.SecuritySignalEvent{}
		_ = protojson.Unmarshal(body, ev)
		receivedMu.Lock()
		received = append(received, ev)
		receivedMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		CoalescingWindow: 100 * time.Millisecond,
		Endpoints:        []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	now := timestamppb.Now()
	// Rapidly emit 30 duplicate transport refused events for peer-target
	for i := 0; i < 30; i++ {
		disp.Dispatch(&api.SecuritySignalEvent{
			Id:          fmt.Sprintf("ev-%d", i),
			Type:        "agentmesh.transport.refused",
			Source:      "urn:agentmesh:node:test",
			SpecVersion: "1.0",
			EventTime:   now,
			Subject:     "peer-target",
			Data: &api.SecuritySignalEvent_TransportRefused{
				TransportRefused: &api.TransportRefusedSignal{
					PeerId:     "peer-target",
					ProtocolId: "/agentmesh/auth",
					Reason:     api.TransportRefusalReason_PEER_UNAUTHENTICATED,
				},
			},
		})
	}

	// Close forces synchronous flush of active coalescing window
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	receivedMu.Lock()
	defer receivedMu.Unlock()

	// Should have coalesced 30 events into initial (count=0 or 1) + summary with total count 30
	var totalCount uint32
	for _, ev := range received {
		if tr := ev.GetTransportRefused(); tr != nil {
			if tr.CoalescedCount > 0 {
				totalCount += tr.CoalescedCount
			} else {
				totalCount++
			}
		}
	}
	if totalCount != 30 {
		t.Errorf("total coalesced count = %d, want 30 across %d delivered batches", totalCount, len(received))
	}
}

func TestDispatcher_MultiKeyCoalescing(t *testing.T) {
	var receivedMu sync.Mutex
	countsByPeer := make(map[string]uint32)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ev := &api.SecuritySignalEvent{}
		_ = protojson.Unmarshal(body, ev)
		if tr := ev.GetTransportRefused(); tr != nil {
			receivedMu.Lock()
			c := tr.CoalescedCount
			if c == 0 {
				c = 1
			}
			countsByPeer[tr.PeerId] += c
			receivedMu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		CoalescingWindow: 100 * time.Millisecond,
		Endpoints:        []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	now := timestamppb.Now()
	// Interleave 20 events for peer-A and 20 events for peer-B
	for i := 0; i < 20; i++ {
		disp.Dispatch(&api.SecuritySignalEvent{
			Id:          fmt.Sprintf("ev-a-%d", i),
			Type:        "agentmesh.transport.refused",
			Source:      "urn:agentmesh:node:test",
			SpecVersion: "1.0",
			EventTime:   now,
			Subject:     "peer-A",
			Data: &api.SecuritySignalEvent_TransportRefused{
				TransportRefused: &api.TransportRefusedSignal{
					PeerId:     "peer-A",
					ProtocolId: "/agentmesh/auth",
					Reason:     api.TransportRefusalReason_PEER_UNAUTHENTICATED,
				},
			},
		})
		disp.Dispatch(&api.SecuritySignalEvent{
			Id:          fmt.Sprintf("ev-b-%d", i),
			Type:        "agentmesh.transport.refused",
			Source:      "urn:agentmesh:node:test",
			SpecVersion: "1.0",
			EventTime:   now,
			Subject:     "peer-B",
			Data: &api.SecuritySignalEvent_TransportRefused{
				TransportRefused: &api.TransportRefusedSignal{
					PeerId:     "peer-B",
					ProtocolId: "/agentmesh/auth",
					Reason:     api.TransportRefusalReason_PEER_UNAUTHENTICATED,
				},
			},
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	receivedMu.Lock()
	defer receivedMu.Unlock()

	if countsByPeer["peer-A"] != 20 {
		t.Errorf("peer-A count = %d, want 20", countsByPeer["peer-A"])
	}
	if countsByPeer["peer-B"] != 20 {
		t.Errorf("peer-B count = %d, want 20", countsByPeer["peer-B"])
	}
}

func TestDispatcher_HMACSHA256SignatureAndSecretHygiene(t *testing.T) {
	secretKey := []byte("test-hmac-containment-secret-key-32b!")
	secretDir := t.TempDir()
	secretFile := filepath.Join(secretDir, "containment.hmac")
	if err := os.WriteFile(secretFile, secretKey, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var verified atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts := r.Header.Get("X-AgentMesh-Timestamp")
		sig := r.Header.Get("X-AgentMesh-Signature")
		if ts == "" || sig == "" {
			t.Errorf("missing HMAC headers: ts=%q sig=%q", ts, sig)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("io.ReadAll: %v", err)
			return
		}

		if VerifySignature(secretKey, ts, body, sig) {
			verified.Store(true)
			w.WriteHeader(http.StatusOK)
		} else {
			t.Errorf("signature verification failed: ts=%s sig=%s", ts, sig)
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		Endpoints: []EndpointConfig{{
			URL:            srv.URL,
			HMACSecretPath: secretFile,
		}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	disp.Dispatch(&api.SecuritySignalEvent{
		Id:          "test-hmac-id",
		Type:        "agentmesh.policy.denied",
		Source:      "urn:agentmesh:node:test",
		SpecVersion: "1.0",
		EventTime:   timestamppb.Now(),
		Data: &api.SecuritySignalEvent_PolicyDenied{
			PolicyDenied: &api.PolicyDeniedSignal{
				TargetService: "vault",
				Detail:        "access denied",
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	if !verified.Load() {
		t.Errorf("HMAC signature was not successfully verified by receiver")
	}

	// Verify tampering detection
	fakeBody := []byte(`{"tampered":true}`)
	if VerifySignature(secretKey, "12345678", fakeBody, "sha256=invalid") {
		t.Errorf("VerifySignature unexpectedly passed for tampered signature")
	}
}

func TestDispatcher_UnixDomainSocket(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "containment.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix): %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	received := make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- string(body)
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	disp, err := NewDispatcher(Config{
		Endpoints: []EndpointConfig{{URL: "unix:" + filepath.ToSlash(sockPath)}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	disp.Dispatch(&api.SecuritySignalEvent{
		Id:          "unix-test-id",
		Type:        "agentmesh.identity.revoked",
		Source:      "urn:agentmesh:node:local",
		SpecVersion: "1.0",
		EventTime:   timestamppb.Now(),
		Data: &api.SecuritySignalEvent_IdentityRevoked{
			IdentityRevoked: &api.IdentityRevokedSignal{
				PeerId: "peer-banned",
				Reason: "administrative eviction",
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	select {
	case body := <-received:
		if !strings.Contains(body, "agentmesh.identity.revoked") {
			t.Errorf("Unix socket body missing event type: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for Unix domain socket delivery")
	}
}

func TestDispatcher_GracefulShutdownAndDrain(t *testing.T) {
	var count atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		QueueCapacity: 50,
		Workers:       2,
		Endpoints:     []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	now := timestamppb.Now()
	for i := 0; i < 20; i++ {
		disp.Dispatch(&api.SecuritySignalEvent{
			Id:          fmt.Sprintf("id-%d", i),
			Type:        "agentmesh.policy.denied",
			Source:      "urn:agentmesh:node:test",
			SpecVersion: "1.0",
			EventTime:   now,
			Data: &api.SecuritySignalEvent_PolicyDenied{
				PolicyDenied: &api.PolicyDeniedSignal{
					TargetService: fmt.Sprintf("service-%d", i),
					Detail:        "drain test",
				},
			},
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	if got := count.Load(); got != 20 {
		t.Errorf("delivered during shutdown = %d, want 20", got)
	}
}

func TestDispatcher_UnresponsiveServerShutdownTimeout(t *testing.T) {
	releaseHandler := make(chan struct{})
	serverEntered := make(chan struct{})
	var serverEnteredOnce sync.Once

	hangServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverEnteredOnce.Do(func() { close(serverEntered) })
		select {
		case <-releaseHandler:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		select {
		case <-releaseHandler:
		default:
			close(releaseHandler)
		}
		hangServer.Close()
	})

	disp, err := NewDispatcher(Config{
		QueueCapacity: 10,
		Workers:       1,
		Endpoints: []EndpointConfig{{
			URL:     hangServer.URL,
			Timeout: 5 * time.Second,
		}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	disp.Dispatch(&api.SecuritySignalEvent{
		Id:          "hang-event",
		Type:        "agentmesh.policy.denied",
		Source:      "urn:agentmesh:node:test",
		SpecVersion: "1.0",
		EventTime:   timestamppb.Now(),
	})

	// Wait until the handler has actually been entered
	select {
	case <-serverEntered:
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for server handler entry")
	}

	// Close with very short 20ms deadline; worker is stuck in hangServer handler
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = disp.Close(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Errorf("expected Close timeout error; got nil")
	}
	if elapsed > 1*time.Second {
		t.Errorf("Close took %v, want <=1s", elapsed)
	}
}

func TestClient_InsecureHTTPRejection(t *testing.T) {
	// Non-loopback plain HTTP target must fail closed
	_, err := NewSingleClient(EndpointConfig{
		URL: "http://example.com/events",
	})
	if err == nil {
		t.Errorf("expected error for non-loopback http URL, got nil")
	}

	// Loopback plain HTTP must succeed
	c, err := NewSingleClient(EndpointConfig{
		URL: "http://127.0.0.1:8080/events",
	})
	if err != nil {
		t.Errorf("unexpected error for loopback http URL: %v", err)
	}
	_ = c.Close()
}

func TestConfig_FromProto(t *testing.T) {
	protoCfg := &api.SecuritySignalsConfig{
		Enabled:          true,
		QueueCapacity:    512,
		CoalescingWindow: durationpb.New(2 * time.Second),
		Endpoints: []*api.WebhookEndpointConfig{
			{
				Url:        "http://127.0.0.1:9090/events",
				Timeout:    durationpb.New(1 * time.Second),
				MaxRetries: 2,
				EventTypes: []string{"agentmesh.policy.denied"},
			},
		},
	}

	cfg, err := FromProto(protoCfg)
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if !cfg.Enabled {
		t.Errorf("got Enabled false, want true")
	}
	if cfg.QueueCapacity != 512 {
		t.Errorf("got QueueCapacity %d, want 512", cfg.QueueCapacity)
	}
	if cfg.CoalescingWindow != 2*time.Second {
		t.Errorf("got CoalescingWindow %v, want 2s", cfg.CoalescingWindow)
	}
	if len(cfg.Endpoints) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(cfg.Endpoints))
	}
	if cfg.Endpoints[0].URL != "http://127.0.0.1:9090/events" {
		t.Errorf("got endpoint URL %q, want http://127.0.0.1:9090/events", cfg.Endpoints[0].URL)
	}
}
