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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 1. Transport Resilience & Failure Handling
// Tests behaviour when target Unix domain socket or HTTP server is down, slow, or abruptly disconnected.

func TestAdversarial_UnixSocketNonExistent(t *testing.T) {
	// Target Unix domain socket does NOT exist
	nonExistentSock := filepath.Join(t.TempDir(), "nonexistent.sock")

	disp, err := NewDispatcher(Config{
		QueueCapacity: 10,
		Workers:       1,
		Endpoints: []EndpointConfig{{
			URL:        "unix:" + filepath.ToSlash(nonExistentSock),
			MaxRetries: 1,
			Timeout:    100 * time.Millisecond,
		}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher failed: %v", err)
	}

	initialDropped := GetDroppedCountFor("agentmesh.policy.denied", "transport_error")

	// Dispatch should be completely non-blocking
	start := time.Now()
	disp.Dispatch(&api.SecuritySignalEvent{
		Type:      "agentmesh.policy.denied",
		EventTime: timestamppb.Now(),
		Data: &api.SecuritySignalEvent_PolicyDenied{
			PolicyDenied: &api.PolicyDeniedSignal{
				TargetService: "test-service",
				Detail:        "unix non-existent test",
			},
		},
	})
	dispatchDuration := time.Since(start)
	if dispatchDuration > 50*time.Millisecond {
		t.Errorf("Dispatch blocked for %v, want <50ms", dispatchDuration)
	}

	// Close cleanly
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close failed: %v", err)
	}

	finalDropped := GetDroppedCountFor("agentmesh.policy.denied", "transport_error")
	if finalDropped-initialDropped < 1 {
		t.Errorf("expected transport_error drop increment, got initial=%f, final=%f", initialDropped, finalDropped)
	}
}

func TestAdversarial_UnixSocketAbruptDisconnect(t *testing.T) {
	// Use short path under TempDir to stay within AF_UNIX 108 byte limit on Windows
	sockDir, err := os.MkdirTemp("", "ud*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "d.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix): %v", err)
	}

	// Accept a connection and immediately close/reset it abruptly
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Abruptly close connection without sending HTTP response
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })

	disp, err := NewDispatcher(Config{
		QueueCapacity: 10,
		Workers:       1,
		Endpoints: []EndpointConfig{{
			URL:        "unix:" + filepath.ToSlash(sockPath),
			MaxRetries: 1,
			Timeout:    200 * time.Millisecond,
		}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher failed: %v", err)
	}

	start := time.Now()
	disp.Dispatch(&api.SecuritySignalEvent{
		Type:      "agentmesh.policy.denied",
		EventTime: timestamppb.Now(),
		Data: &api.SecuritySignalEvent_PolicyDenied{
			PolicyDenied: &api.PolicyDeniedSignal{
				TargetService: "disconnect-service",
				Detail:        "abrupt disconnect test",
			},
		},
	})
	if time.Since(start) > 50*time.Millisecond {
		t.Errorf("Dispatch took %v, want <50ms", time.Since(start))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close failed: %v", err)
	}
}

func TestAdversarial_HTTPServer500RetriesAndMetrics(t *testing.T) {
	var attempts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	initial500Delivered := GetDeliveredCountFor("agentmesh.transport.refused", "500")
	initialTransportErrors := GetDroppedCountFor("agentmesh.transport.refused", "transport_error")

	maxRetries := uint32(2)
	disp, err := NewDispatcher(Config{
		QueueCapacity: 10,
		Workers:       1,
		Endpoints: []EndpointConfig{{
			URL:        srv.URL,
			MaxRetries: maxRetries,
			Timeout:    500 * time.Millisecond,
		}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher failed: %v", err)
	}

	disp.Dispatch(&api.SecuritySignalEvent{
		Type:      "agentmesh.transport.refused",
		EventTime: timestamppb.Now(),
		Data: &api.SecuritySignalEvent_TransportRefused{
			TransportRefused: &api.TransportRefusedSignal{
				PeerId: "peer-500",
				Reason: api.TransportRefusalReason_PEER_UNAUTHENTICATED,
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close failed: %v", err)
	}

	// 1 initial attempt + 2 retries = 3 attempts
	expectedAttempts := int64(1 + maxRetries)
	if got := attempts.Load(); got != expectedAttempts {
		t.Errorf("got %d attempts, want %d", got, expectedAttempts)
	}

	final500Delivered := GetDeliveredCountFor("agentmesh.transport.refused", "500")
	if final500Delivered-initial500Delivered != float64(expectedAttempts) {
		t.Errorf("delivered 500 count delta = %f, want %f", final500Delivered-initial500Delivered, float64(expectedAttempts))
	}

	finalTransportErrors := GetDroppedCountFor("agentmesh.transport.refused", "transport_error")
	if finalTransportErrors-initialTransportErrors < 1 {
		t.Errorf("expected transport_error increment, got initial=%f, final=%f", initialTransportErrors, finalTransportErrors)
	}
}

func TestAdversarial_HTTPServer403NoRetry(t *testing.T) {
	var attempts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		QueueCapacity: 10,
		Workers:       1,
		Endpoints: []EndpointConfig{{
			URL:        srv.URL,
			MaxRetries: 3, // Should NOT retry on 4xx
			Timeout:    500 * time.Millisecond,
		}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher failed: %v", err)
	}

	disp.Dispatch(&api.SecuritySignalEvent{
		Type:      "agentmesh.identity.revoked",
		EventTime: timestamppb.Now(),
		Data: &api.SecuritySignalEvent_IdentityRevoked{
			IdentityRevoked: &api.IdentityRevokedSignal{
				PeerId: "peer-403",
				Reason: "forbidden endpoint test",
			},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close failed: %v", err)
	}

	// Should stop immediately after 1 attempt because 403 is a client error
	if got := attempts.Load(); got != 1 {
		t.Errorf("got %d attempts on HTTP 403, want exactly 1 (no retries for 4xx)", got)
	}
}

// 2. Shutdown Deadline Timeout & Graceful Drop Accounting
// Verifies remaining queue items are dropped gracefully, incrementing shutdown_timeout drops without hanging.

func TestAdversarial_ShutdownTimeoutWithBufferedEvents(t *testing.T) {
	blockServer := make(chan struct{})
	serverEntered := make(chan struct{})
	var once sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(serverEntered) })
		<-blockServer
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		select {
		case <-blockServer:
		default:
			close(blockServer)
		}
		srv.Close()
	})

	queueCap := 10
	disp, err := NewDispatcher(Config{
		QueueCapacity: queueCap,
		Workers:       1,
		Endpoints: []EndpointConfig{{
			URL:        srv.URL,
			Timeout:    5 * time.Second,
			MaxRetries: 1,
		}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher failed: %v", err)
	}

	now := timestamppb.Now()

	// 1. Dispatch 1st event that causes worker 1 to block in the HTTP server
	disp.Dispatch(&api.SecuritySignalEvent{
		Id:        "blocking-event",
		Type:      "agentmesh.policy.denied",
		EventTime: now,
		Data: &api.SecuritySignalEvent_PolicyDenied{
			PolicyDenied: &api.PolicyDeniedSignal{
				TargetService: "blocker",
			},
		},
	})

	// Wait until worker is firmly blocked in server
	select {
	case <-serverEntered:
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for worker to enter server")
	}

	initialShutdownTimeoutDrops := GetDroppedCountFor("all", "shutdown_timeout")

	// 2. Now dispatch 4 more events that will sit in d.queue (buffer size 10)
	for i := 1; i <= 4; i++ {
		disp.Dispatch(&api.SecuritySignalEvent{
			Id:        fmt.Sprintf("queued-%d", i),
			Type:      "agentmesh.policy.denied",
			EventTime: now,
			Data: &api.SecuritySignalEvent_PolicyDenied{
				PolicyDenied: &api.PolicyDeniedSignal{
					TargetService: fmt.Sprintf("queued-%d", i),
				},
			},
		})
	}

	// 3. Initiate Close with an extremely tight deadline (20ms)
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelClose()

	start := time.Now()
	err = disp.Close(closeCtx)
	elapsed := time.Since(start)

	if err == nil {
		t.Errorf("expected Close() to return deadline exceeded error, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Close() took %v to timeout, want <=500ms", elapsed)
	}

	// 4. Verify shutdown_timeout drop metric incremented by remaining count (4 items)
	finalShutdownTimeoutDrops := GetDroppedCountFor("all", "shutdown_timeout")
	delta := finalShutdownTimeoutDrops - initialShutdownTimeoutDrops
	if delta != 4 {
		t.Errorf("shutdown_timeout drops delta = %f, want 4", delta)
	}

	// Release blocked server
	close(blockServer)
}

// 3. Cryptographic Integrity & Anti-SSRF
// Verifies tampered HMAC signatures are rejected, and non-loopback HTTP targets fail closed.

func TestAdversarial_HMACValidationMatrix(t *testing.T) {
	secretKey := []byte("correct-secret-key-32-bytes-long!")
	wrongKey := []byte("wrong-secret-key-32-bytes-long-!")
	validBody := []byte(`{"id":"test-event-123","type":"agentmesh.policy.denied"}`)
	timestamp := "1731272400000"

	validSig := ComputeSignature(secretKey, timestamp, validBody)

	tests := []struct {
		name      string
		secret    []byte
		ts        string
		body      []byte
		signature string
		wantValid bool
	}{
		{
			name:      "Valid signature matches",
			secret:    secretKey,
			ts:        timestamp,
			body:      validBody,
			signature: validSig,
			wantValid: true,
		},
		{
			name:      "Tampered signature byte rejected",
			secret:    secretKey,
			ts:        timestamp,
			body:      validBody,
			signature: validSig[:len(validSig)-1] + "0",
			wantValid: false,
		},
		{
			name:      "Tampered body rejected",
			secret:    secretKey,
			ts:        timestamp,
			body:      []byte(`{"id":"test-event-123","type":"agentmesh.policy.denied","tampered":true}`),
			signature: validSig,
			wantValid: false,
		},
		{
			name:      "Tampered timestamp rejected",
			secret:    secretKey,
			ts:        "1731272400001",
			body:      validBody,
			signature: validSig,
			wantValid: false,
		},
		{
			name:      "Wrong secret rejected",
			secret:    wrongKey,
			ts:        timestamp,
			body:      validBody,
			signature: validSig,
			wantValid: false,
		},
		{
			name:      "Empty signature rejected",
			secret:    secretKey,
			ts:        timestamp,
			body:      validBody,
			signature: "",
			wantValid: false,
		},
		{
			name:      "Empty timestamp rejected",
			secret:    secretKey,
			ts:        "",
			body:      validBody,
			signature: validSig,
			wantValid: false,
		},
		{
			name:      "Empty secret rejected",
			secret:    nil,
			ts:        timestamp,
			body:      validBody,
			signature: validSig,
			wantValid: false,
		},
		{
			name:      "Prefix-only signature rejected",
			secret:    secretKey,
			ts:        timestamp,
			body:      validBody,
			signature: "sha256=",
			wantValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifySignature(tc.secret, tc.ts, tc.body, tc.signature)
			if got != tc.wantValid {
				t.Errorf("VerifySignature() = %v, want %v", got, tc.wantValid)
			}
		})
	}
}

func TestAdversarial_AntiSSRFValidationMatrix(t *testing.T) {
	tests := []struct {
		url        string
		shouldPass bool
		desc       string
	}{
		// Permitted targets
		{"http://127.0.0.1:8080/events", true, "Standard IPv4 loopback"},
		{"http://127.0.0.2:9000/events", true, "IPv4 loopback range 127.0.0.0/8"},
		{"http://127.255.255.254:80/events", true, "IPv4 loopback high boundary"},
		{"http://localhost:8080/events", true, "Named localhost"},
		{"http://[::1]:8080/events", true, "IPv6 loopback"},
		{"unix:/run/containment.sock", true, "Unix domain socket"},
		{"unix:///var/run/containment.sock", true, "Unix domain socket with triple slash"},
		{"https://remote.secure.corp/events", true, "HTTPS remote target"},
		{"unix:///run/agentmesh/containment.sock", true, "Documentation Unix domain socket (triple slash)"},
		{"http://127.0.0.1:8095/events", true, "Documentation IPv4 loopback endpoint"},
		{"https://containment-controller.agentmesh.svc:8443/events", true, "Documentation HTTPS kubernetes service"},
		{"https://containment-controller.agentmesh.svc.cluster.local:8443/events", true, "Documentation HTTPS kubernetes cluster.local"},
		{"https://siem.internal:8443/alerts", true, "Documentation HTTPS SIEM alert endpoint"},

		// Forbidden non-loopback HTTP targets (Anti-SSRF fail closed)
		{"http://containment-controller.agentmesh.svc:8095/events", false, "Old doc plain HTTP kubernetes service (anti-SSRF rejected)"},
		{"http://containment-controller.agentmesh.svc.cluster.local:8095/events", false, "Old doc plain HTTP cluster.local (anti-SSRF rejected)"},
		{"http://10.0.0.1:8080/events", false, "RFC1918 10.0.0.0/8"},
		{"http://172.16.0.1:8080/events", false, "RFC1918 172.16.0.0/12"},
		{"http://192.168.1.1:8080/events", false, "RFC1918 192.168.0.0/16"},
		{"http://169.254.169.254/latest/meta-data", false, "Link-local cloud metadata (AWS/GCP)"},
		{"http://evil.com:8080/events", false, "Arbitrary remote domain over plain HTTP"},
		{"http://0.0.0.0:8080/events", false, "Unspecified IPv4 (INADDR_ANY)"},
		{"http://100.64.0.1:8080/events", false, "CGNAT range 100.64.0.0/10"},
		{"http://[fe80::1]:8080/events", false, "IPv6 link-local"},
		{"http://[fc00::1]:8080/events", false, "IPv6 unique local"},
		{"http://[::ffff:10.0.0.1]:8080/events", false, "IPv4-mapped IPv6 non-loopback 10.0.0.1"},
		{"http://[::ffff:169.254.169.254]:8080/events", false, "IPv4-mapped IPv6 non-loopback 169.254.169.254"},
		{"http://localhost.evil.com:8080/events", false, "Subdomain evasion localhost.evil.com"},
		{"http://evil-localhost:8080/events", false, "Suffix evasion evil-localhost"},
		{"http://127.0.0.1.nip.io:8080/events", false, "DNS wildcard resolving to 127.0.0.1"},

		// Invalid schemes
		{"ftp://127.0.0.1:21/events", false, "FTP scheme forbidden"},
		{"file:///etc/passwd", false, "File scheme forbidden"},
		{"gopher://127.0.0.1:70", false, "Gopher scheme forbidden"},
		{"unix:", false, "Empty unix path forbidden"},
		{"", false, "Empty target URL forbidden"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			client, err := NewSingleClient(EndpointConfig{URL: tc.url})
			if tc.shouldPass {
				if err != nil {
					t.Errorf("expected URL %q to pass, but got error: %v", tc.url, err)
				}
				if client != nil {
					_ = client.Close()
				}
			} else {
				if err == nil {
					t.Errorf("expected URL %q to fail closed, but it was accepted!", tc.url)
					if client != nil {
						_ = client.Close()
					}
				}
			}
		})
	}
}

// 4. Concurrency & High Throughput Edge Cases

func TestAdversarial_ConcurrentDispatchAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		QueueCapacity:    100,
		Workers:          4,
		CoalescingWindow: 50 * time.Millisecond,
		Endpoints:        []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	var wg sync.WaitGroup
	goroutines := 10
	dispatchesPerRoutine := 100

	// Launch concurrent dispatchers
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < dispatchesPerRoutine; i++ {
				disp.Dispatch(&api.SecuritySignalEvent{
					Id:        fmt.Sprintf("concurrent-%d-%d", gid, i),
					Type:      "agentmesh.policy.denied",
					EventTime: timestamppb.Now(),
					Subject:   fmt.Sprintf("peer-%d", gid%3),
					Data: &api.SecuritySignalEvent_PolicyDenied{
						PolicyDenied: &api.PolicyDeniedSignal{
							TargetService: "db",
						},
					},
				})
			}
		}(g)
	}

	// Close asynchronously while workers are active
	time.Sleep(5 * time.Millisecond)
	closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_ = disp.Close(closeCtx)
	wg.Wait()

	// Calling Dispatch after Close must not panic or block
	disp.Dispatch(&api.SecuritySignalEvent{
		Id:        "post-close-event",
		Type:      "agentmesh.policy.denied",
		EventTime: timestamppb.Now(),
	})

	// Calling Close a second time must return nil without deadlocking
	if err := disp.Close(context.Background()); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
}

func TestAdversarial_NilAndEmptyEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		QueueCapacity: 10,
		Workers:       1,
		Endpoints:     []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	initialNilDrops := GetDroppedCountFor("unknown", "nil_event")

	// 1. Dispatch nil event
	disp.Dispatch(nil)

	// 2. Dispatch empty event
	disp.Dispatch(&api.SecuritySignalEvent{})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = disp.Close(ctx)

	finalNilDrops := GetDroppedCountFor("unknown", "nil_event")
	if finalNilDrops-initialNilDrops != 1 {
		t.Errorf("expected 1 nil_event drop, got delta %f", finalNilDrops-initialNilDrops)
	}
}
