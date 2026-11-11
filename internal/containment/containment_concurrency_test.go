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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestStress_QueueSaturationAndSheddingMetrics tests rapid bursts exceeding QueueCapacity,
// verifying exact drop counting in containmentDroppedTotal with label reason="buffer_full",
// strictly non-blocking returns, and per-signal-type metrics.
func TestStress_QueueSaturationAndSheddingMetrics(t *testing.T) {
	blockHandler := make(chan struct{})
	handlerEntered := make(chan struct{})
	var handlerEnteredOnce sync.Once
	var deliveredCount atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerEnteredOnce.Do(func() { close(handlerEntered) })
		<-blockHandler
		deliveredCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		select {
		case <-blockHandler:
		default:
			close(blockHandler)
		}
		srv.Close()
	})

	const queueCap = 20
	const numWorkers = 2
	disp, err := NewDispatcher(Config{
		QueueCapacity: queueCap,
		Workers:       numWorkers,
		Endpoints:     []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	signalType := "agentmesh.policy.denied"
	initialDropped := GetDroppedCountFor(signalType, "buffer_full")

	// Send 2 events to saturate the workers (2 workers blocked)
	for i := 0; i < numWorkers; i++ {
		disp.Dispatch(&api.SecuritySignalEvent{
			Id:          fmt.Sprintf("worker-block-%d", i),
			Type:        signalType,
			Source:      "urn:agentmesh:node:stress",
			SpecVersion: "1.0",
			EventTime:   timestamppb.Now(),
			Data: &api.SecuritySignalEvent_PolicyDenied{
				PolicyDenied: &api.PolicyDeniedSignal{
					TargetService: "vault",
					Detail:        "blocker",
				},
			},
		})
	}

	select {
	case <-handlerEntered:
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for worker to reach blocked handler")
	}

	// Now the queue can hold exactly queueCap (20) events.
	// We dispatch 100 events rapidly.
	// Expected: exactly 20 are queued, exactly 80 are dropped with buffer_full.
	const burstSize = 100
	start := time.Now()
	for i := 0; i < burstSize; i++ {
		disp.Dispatch(&api.SecuritySignalEvent{
			Id:          fmt.Sprintf("burst-%d", i),
			Type:        signalType,
			Source:      "urn:agentmesh:node:stress",
			SpecVersion: "1.0",
			EventTime:   timestamppb.Now(),
			Data: &api.SecuritySignalEvent_PolicyDenied{
				PolicyDenied: &api.PolicyDeniedSignal{
					TargetService: fmt.Sprintf("svc-%d", i),
					Detail:        "burst item",
				},
			},
		})
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Dispatch burst took %v, want <100ms (strictly non-blocking)", elapsed)
	}

	afterBurstDropped := GetDroppedCountFor(signalType, "buffer_full")
	droppedInBurst := int(afterBurstDropped - initialDropped)
	expectedDropped := burstSize - queueCap // 100 - 20 = 80
	if droppedInBurst != expectedDropped {
		t.Errorf("dropped in burst = %d, want %d (QueueCapacity=%d, burst=%d)",
			droppedInBurst, expectedDropped, queueCap, burstSize)
	}

	// Unblock workers and allow queue to drain
	close(blockHandler)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	// Total delivered should be numWorkers (2) + queueCap (20) = 22
	expectedDelivered := int64(numWorkers + queueCap)
	if deliveredCount.Load() != expectedDelivered {
		t.Errorf("delivered count = %d, want %d", deliveredCount.Load(), expectedDelivered)
	}
}

// TestStress_ConcurrentBurstQueueSaturation tests high concurrency across 20 goroutines
// sending 500 events each (10,000 events total) with zero deadlocks and consistent accounting.
func TestStress_ConcurrentBurstQueueSaturation(t *testing.T) {
	var deliveredCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveredCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	const queueCap = 100
	const workers = 4
	disp, err := NewDispatcher(Config{
		QueueCapacity: queueCap,
		Workers:       workers,
		Endpoints:     []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	signalTypes := []string{
		"agentmesh.policy.denied",
		"agentmesh.transport.refused",
		"agentmesh.identity.revoked",
		"agentmesh.enrollment.rejected",
	}

	initDropped := GetDroppedCount()
	const goroutines = 20
	const eventsPerGoroutine = 500
	const totalEvents = goroutines * eventsPerGoroutine // 10,000

	var wg sync.WaitGroup
	startSignal := make(chan struct{})

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			<-startSignal
			for i := 0; i < eventsPerGoroutine; i++ {
				st := signalTypes[(gid+i)%len(signalTypes)]
				disp.Dispatch(&api.SecuritySignalEvent{
					Id:          fmt.Sprintf("g%d-ev%d", gid, i),
					Type:        st,
					Source:      "urn:agentmesh:node:stress",
					SpecVersion: "1.0",
					EventTime:   timestamppb.Now(),
					Subject:     fmt.Sprintf("peer-%d", gid),
				})
			}
		}(g)
	}

	close(startSignal)
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	endDropped := GetDroppedCount()
	totalDropped := endDropped - initDropped
	delivered := deliveredCount.Load()

	t.Logf("10,000 event concurrent burst result: delivered=%d, dropped=%d, sum=%d",
		delivered, totalDropped, delivered+totalDropped)

	if delivered+totalDropped != int64(totalEvents) {
		t.Errorf("accounting discrepancy: delivered (%d) + dropped (%d) = %d, want total %d",
			delivered, totalDropped, delivered+totalDropped, totalEvents)
	}
}

// TestStress_CoalescingNaturalTimerAccuracy tests high-frequency bursts for identical
// (signal_type, peer_id, service) tuples, verifying:
// 1. Exactly 1 initial event and 1 summary event on window closure via natural timer.
// 2. CoalescedCount accuracy on initial and summary event.
// 3. A second burst after window closure starts a clean new coalescing cycle.
func TestStress_CoalescingNaturalTimerAccuracy(t *testing.T) {
	var receivedMu sync.Mutex
	var received []*api.SecuritySignalEvent

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
			return
		}
		ev := &api.SecuritySignalEvent{}
		if err := protojson.Unmarshal(body, ev); err != nil {
			t.Errorf("Unmarshal: %v", err)
			return
		}
		receivedMu.Lock()
		received = append(received, ev)
		receivedMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	coalescingWin := 80 * time.Millisecond
	disp, err := NewDispatcher(Config{
		QueueCapacity:    500,
		Workers:          2,
		CoalescingWindow: coalescingWin,
		Endpoints:        []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	makeRefusedEvent := func(id string, tStamp *timestamppb.Timestamp) *api.SecuritySignalEvent {
		return &api.SecuritySignalEvent{
			Id:          id,
			Type:        "agentmesh.transport.refused",
			Source:      "urn:agentmesh:node:test",
			SpecVersion: "1.0",
			EventTime:   tStamp,
			Subject:     "peer-coalesce-target",
			Data: &api.SecuritySignalEvent_TransportRefused{
				TransportRefused: &api.TransportRefusedSignal{
					PeerId:     "peer-coalesce-target",
					ProtocolId: "/agentmesh/auth",
					Reason:     api.TransportRefusalReason_PEER_UNAUTHENTICATED,
				},
			},
		}
	}

	// Burst 1: 50 identical events
	t0 := timestamppb.Now()
	for i := 0; i < 50; i++ {
		disp.Dispatch(makeRefusedEvent(fmt.Sprintf("b1-ev-%d", i), t0))
	}

	// Wait for the natural timer to expire (window + buffer)
	// Coalescing window is 80ms, wait 200ms
	time.Sleep(200 * time.Millisecond)

	receivedMu.Lock()
	countPhase1 := len(received)
	var phase1Events []*api.SecuritySignalEvent
	phase1Events = append(phase1Events, received...)
	receivedMu.Unlock()

	// Should have received exactly 2 events: 1 initial + 1 summary
	if countPhase1 != 2 {
		t.Fatalf("Phase 1: got %d received events, want exactly 2 (1 initial + 1 summary)", countPhase1)
	}

	evInitial := phase1Events[0]
	evSummary := phase1Events[1]

	trInit := evInitial.GetTransportRefused()
	if trInit == nil {
		t.Fatalf("Phase 1 initial event has nil TransportRefused")
	}
	if trInit.CoalescedCount != 1 {
		t.Errorf("Phase 1 initial CoalescedCount = %d, want 1", trInit.CoalescedCount)
	}

	trSum := evSummary.GetTransportRefused()
	if trSum == nil {
		t.Fatalf("Phase 1 summary event has nil TransportRefused")
	}
	// Initial event accounted for 1; 49 duplicates were coalesced into summary
	if trSum.CoalescedCount != 49 {
		t.Errorf("Phase 1 summary CoalescedCount = %d, want 49", trSum.CoalescedCount)
	}
	if evSummary.Id == evInitial.Id {
		t.Errorf("summary event reused initial event UUID: %s", evSummary.Id)
	}

	// Burst 2: After the window closed, send 20 more events for the same tuple.
	// This must start a fresh coalescing window.
	t1 := timestamppb.Now()
	for i := 0; i < 20; i++ {
		disp.Dispatch(makeRefusedEvent(fmt.Sprintf("b2-ev-%d", i), t1))
	}

	// Wait for second window to expire naturally
	time.Sleep(200 * time.Millisecond)

	receivedMu.Lock()
	countPhase2 := len(received)
	var phase2Events []*api.SecuritySignalEvent
	phase2Events = append(phase2Events, received...)
	receivedMu.Unlock()

	if countPhase2 != 4 {
		t.Fatalf("Phase 2: got total %d received events, want 4 (2 from Phase 1 + 2 from Phase 2)", countPhase2)
	}

	evInit2 := phase2Events[2]
	evSum2 := phase2Events[3]

	trInit2 := evInit2.GetTransportRefused()
	if trInit2.CoalescedCount != 1 {
		t.Errorf("Phase 2 initial CoalescedCount = %d, want 1", trInit2.CoalescedCount)
	}

	trSum2 := evSum2.GetTransportRefused()
	if trSum2.CoalescedCount != 19 {
		t.Errorf("Phase 2 summary CoalescedCount = %d, want 19", trSum2.CoalescedCount)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}
}

// TestStress_CoalescingSingleEventNoSummary tests that an isolated event produces
// exactly 1 delivery and NO trailing summary event when the timer expires.
func TestStress_CoalescingSingleEventNoSummary(t *testing.T) {
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
		CoalescingWindow: 60 * time.Millisecond,
		Endpoints:        []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	disp.Dispatch(&api.SecuritySignalEvent{
		Id:          "single-event-id",
		Type:        "agentmesh.transport.refused",
		Source:      "urn:agentmesh:node:test",
		SpecVersion: "1.0",
		EventTime:   timestamppb.Now(),
		Subject:     "peer-isolated",
		Data: &api.SecuritySignalEvent_TransportRefused{
			TransportRefused: &api.TransportRefusedSignal{
				PeerId:     "peer-isolated",
				ProtocolId: "/agentmesh/auth",
				Reason:     api.TransportRefusalReason_PEER_UNAUTHENTICATED,
			},
		},
	})

	// Wait well past the 60ms window
	time.Sleep(150 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	receivedMu.Lock()
	defer receivedMu.Unlock()

	// Should be strictly 1 event, 0 summary events
	if len(received) != 1 {
		t.Errorf("single event produced %d deliveries, want exactly 1 (no summary for single occurrence)", len(received))
	}
}

// TestStress_CoalescingMultiTupleIndependence verifies that multiple distinct
// (signal_type, peer_id, service) tuples coalesce independently.
func TestStress_CoalescingMultiTupleIndependence(t *testing.T) {
	var receivedMu sync.Mutex
	receivedEvents := make(map[string][]*api.SecuritySignalEvent)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ev := &api.SecuritySignalEvent{}
		_ = protojson.Unmarshal(body, ev)

		targetService := extractTargetService(ev)
		key := fmt.Sprintf("%s|%s|%s", ev.Type, ev.Subject, targetService)

		receivedMu.Lock()
		receivedEvents[key] = append(receivedEvents[key], ev)
		receivedMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		QueueCapacity:    500,
		Workers:          2,
		CoalescingWindow: 80 * time.Millisecond,
		Endpoints:        []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	// Define 4 tuples:
	// T1: (transport.refused, peer-1, /auth)
	// T2: (transport.refused, peer-2, /auth)  --> different peer
	// T3: (transport.refused, peer-1, /http)  --> different service
	// T4: (policy.denied,    peer-1, /auth)  --> different signal type
	type tupleDef struct {
		key        string
		signalType string
		peerID     string
		service    string
		createEv   func(id string) *api.SecuritySignalEvent
	}

	tuples := []tupleDef{
		{
			key:        "agentmesh.transport.refused|peer-1|/auth",
			signalType: "agentmesh.transport.refused",
			peerID:     "peer-1",
			service:    "/auth",
			createEv: func(id string) *api.SecuritySignalEvent {
				return &api.SecuritySignalEvent{
					Id:          id,
					Type:        "agentmesh.transport.refused",
					Subject:     "peer-1",
					SpecVersion: "1.0",
					EventTime:   timestamppb.Now(),
					Data: &api.SecuritySignalEvent_TransportRefused{
						TransportRefused: &api.TransportRefusedSignal{
							PeerId:     "peer-1",
							ProtocolId: "/auth",
							Reason:     api.TransportRefusalReason_PEER_UNAUTHENTICATED,
						},
					},
				}
			},
		},
		{
			key:        "agentmesh.transport.refused|peer-2|/auth",
			signalType: "agentmesh.transport.refused",
			peerID:     "peer-2",
			service:    "/auth",
			createEv: func(id string) *api.SecuritySignalEvent {
				return &api.SecuritySignalEvent{
					Id:          id,
					Type:        "agentmesh.transport.refused",
					Subject:     "peer-2",
					SpecVersion: "1.0",
					EventTime:   timestamppb.Now(),
					Data: &api.SecuritySignalEvent_TransportRefused{
						TransportRefused: &api.TransportRefusedSignal{
							PeerId:     "peer-2",
							ProtocolId: "/auth",
							Reason:     api.TransportRefusalReason_PEER_UNAUTHENTICATED,
						},
					},
				}
			},
		},
		{
			key:        "agentmesh.transport.refused|peer-1|/http",
			signalType: "agentmesh.transport.refused",
			peerID:     "peer-1",
			service:    "/http",
			createEv: func(id string) *api.SecuritySignalEvent {
				return &api.SecuritySignalEvent{
					Id:          id,
					Type:        "agentmesh.transport.refused",
					Subject:     "peer-1",
					SpecVersion: "1.0",
					EventTime:   timestamppb.Now(),
					Data: &api.SecuritySignalEvent_TransportRefused{
						TransportRefused: &api.TransportRefusedSignal{
							PeerId:     "peer-1",
							ProtocolId: "/http",
							Reason:     api.TransportRefusalReason_PEER_UNAUTHENTICATED,
						},
					},
				}
			},
		},
		{
			key:        "agentmesh.policy.denied|peer-1|/auth",
			signalType: "agentmesh.policy.denied",
			peerID:     "peer-1",
			service:    "/auth",
			createEv: func(id string) *api.SecuritySignalEvent {
				return &api.SecuritySignalEvent{
					Id:          id,
					Type:        "agentmesh.policy.denied",
					Subject:     "peer-1",
					SpecVersion: "1.0",
					EventTime:   timestamppb.Now(),
					Data: &api.SecuritySignalEvent_PolicyDenied{
						PolicyDenied: &api.PolicyDeniedSignal{
							CallerPeerId:  "peer-1",
							TargetService: "/auth",
							Detail:        "denied",
						},
					},
				}
			},
		},
	}

	const eventsPerTuple = 25
	// Interleave dispatch of all 4 tuples concurrently
	var wg sync.WaitGroup
	for _, td := range tuples {
		wg.Add(1)
		go func(tDef tupleDef) {
			defer wg.Done()
			for i := 0; i < eventsPerTuple; i++ {
				disp.Dispatch(tDef.createEv(fmt.Sprintf("%s-%d", tDef.peerID, i)))
			}
		}(td)
	}
	wg.Wait()

	// Wait for natural timer expiration
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	receivedMu.Lock()
	defer receivedMu.Unlock()

	// Each tuple must have exactly 2 deliveries: 1 initial + 1 summary
	for _, td := range tuples {
		evList := receivedEvents[td.key]
		if len(evList) != 2 {
			t.Errorf("tuple %q: got %d delivered events, want exactly 2 (1 initial + 1 summary)", td.key, len(evList))
			continue
		}

		if td.signalType == "agentmesh.transport.refused" {
			initTR := evList[0].GetTransportRefused()
			sumTR := evList[1].GetTransportRefused()
			if initTR == nil || sumTR == nil {
				t.Errorf("tuple %q: nil TransportRefused in events", td.key)
				continue
			}
			if initTR.CoalescedCount != 1 {
				t.Errorf("tuple %q initial CoalescedCount = %d, want 1", td.key, initTR.CoalescedCount)
			}
			if sumTR.CoalescedCount != eventsPerTuple-1 {
				t.Errorf("tuple %q summary CoalescedCount = %d, want %d",
					td.key, sumTR.CoalescedCount, eventsPerTuple-1)
			}
		} else if td.signalType == "agentmesh.policy.denied" {
			sumPD := evList[1].GetPolicyDenied()
			if sumPD == nil {
				t.Errorf("tuple %q summary has nil PolicyDenied", td.key)
				continue
			}
			expectedSubstr := fmt.Sprintf("(coalesced %d occurrences)", eventsPerTuple-1)
			if !strings.Contains(sumPD.Detail, expectedSubstr) {
				t.Errorf("tuple %q summary detail %q does not contain %q", td.key, sumPD.Detail, expectedSubstr)
			}
		}
	}
}

// TestStress_ConcurrentDispatchAndClose stresses the dispatcher under simultaneous
// continuous event injection and Close calls across multiple iterations to detect
// any panics (e.g., send on closed channel) or deadlocks.
func TestStress_ConcurrentDispatchAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	for iteration := 0; iteration < 5; iteration++ {
		disp, err := NewDispatcher(Config{
			QueueCapacity:    50,
			Workers:          2,
			CoalescingWindow: 10 * time.Millisecond,
			Endpoints:        []EndpointConfig{{URL: srv.URL}},
		})
		if err != nil {
			t.Fatalf("iteration %d NewDispatcher: %v", iteration, err)
		}

		stopWorkers := make(chan struct{})
		var dispatchWg sync.WaitGroup

		for g := 0; g < 6; g++ {
			dispatchWg.Add(1)
			go func(gid int) {
				defer dispatchWg.Done()
				counter := 0
				for {
					select {
					case <-stopWorkers:
						return
					default:
						counter++
						disp.Dispatch(&api.SecuritySignalEvent{
							Id:          fmt.Sprintf("iter%d-g%d-%d", iteration, gid, counter),
							Type:        "agentmesh.transport.refused",
							SpecVersion: "1.0",
							EventTime:   timestamppb.Now(),
							Subject:     fmt.Sprintf("peer-stress-%d", gid%3),
							Data: &api.SecuritySignalEvent_TransportRefused{
								TransportRefused: &api.TransportRefusedSignal{
									PeerId:     fmt.Sprintf("peer-stress-%d", gid%3),
									ProtocolId: "/auth",
								},
							},
						})
						time.Sleep(500 * time.Microsecond)
					}
				}
			}(g)
		}

		// Let dispatches run for 25ms, then initiate Close while dispatches are still actively calling Dispatch
		time.Sleep(25 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = disp.Close(ctx)
		cancel()

		if err != nil && err != context.DeadlineExceeded {
			t.Errorf("iteration %d: unexpected Close error: %v", iteration, err)
		}

		close(stopWorkers)
		dispatchWg.Wait()
	}
}

// TestStress_ZeroCoalescingWindow verifies that when CoalescingWindow is 0,
// all events are enqueued directly without deduplication.
func TestStress_ZeroCoalescingWindow(t *testing.T) {
	var deliveredCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveredCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	disp, err := NewDispatcher(Config{
		QueueCapacity:    100,
		Workers:          2,
		CoalescingWindow: 0, // Disabled coalescing
		Endpoints:        []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	const n = 30
	for i := 0; i < n; i++ {
		disp.Dispatch(&api.SecuritySignalEvent{
			Id:          fmt.Sprintf("zero-win-%d", i),
			Type:        "agentmesh.policy.denied",
			SpecVersion: "1.0",
			EventTime:   timestamppb.Now(),
			Subject:     "peer-zero",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := disp.Close(ctx); err != nil {
		t.Fatalf("disp.Close: %v", err)
	}

	if deliveredCount.Load() != n {
		t.Errorf("delivered count with zero window = %d, want %d", deliveredCount.Load(), n)
	}
}
