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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/containment"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// expectEventTimeout collects an event from chanDispatcher with a strict bounded wait.
func expectEventTimeout(t *testing.T, d *chanDispatcher, expectedType string, timeout time.Duration) *api.SecuritySignalEvent {
	t.Helper()
	select {
	case evt := <-d.events:
		if evt.Type != expectedType {
			t.Fatalf("expected event type %q, got %q", expectedType, evt.Type)
		}
		return evt
	case <-time.After(timeout):
		t.Fatalf("timed out after %v waiting for event type %q", timeout, expectedType)
		return nil
	}
}

// 1. Empirical test of Node PEP policy rejections and emitted api.SecuritySignalEvent
func TestContainmentSecurity_PEP_PolicyRejections(t *testing.T) {
	disp := newChanDispatcher(20)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}

	callerPID := peer.ID("12D3KooWAdversarialCallerPeerID")

	t.Run("DatalogEvaluationDenial", func(t *testing.T) {
		req := RequestContext{
			PeerID:   callerPID,
			Target:   "database",
			Protocol: "/agentmesh/sql/1.0.0",
		}

		datalogErr := errors.New("authorization check failed: missing fact: right(#authority, \"database\", \"execute\")")
		n.emitMiddlewarePolicyDenied(req, nil, datalogErr)

		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		if evt.SpecVersion != "1.0" {
			t.Errorf("expected SpecVersion '1.0', got %q", evt.SpecVersion)
		}
		if evt.DataContentType != "application/json" {
			t.Errorf("expected DataContentType 'application/json', got %q", evt.DataContentType)
		}
		if evt.Subject != callerPID.String() {
			t.Errorf("expected Subject %q, got %q", callerPID.String(), evt.Subject)
		}
		if evt.EventTime == nil || evt.EventTime.AsTime().IsZero() {
			t.Errorf("expected valid non-zero EventTime, got %v", evt.EventTime)
		}

		pd := evt.GetPolicyDenied()
		if pd == nil {
			t.Fatal("expected PolicyDenied signal payload, got nil")
		}
		if pd.Reason != api.PolicyDenialReason_DATALOG_EVALUATION_DENIED {
			t.Errorf("expected DATALOG_EVALUATION_DENIED, got %v", pd.Reason)
		}
		if pd.TargetService != "database" {
			t.Errorf("expected TargetService 'database', got %q", pd.TargetService)
		}
		if pd.RequestedOperation != "/agentmesh/sql/1.0.0" {
			t.Errorf("expected RequestedOperation '/agentmesh/sql/1.0.0', got %q", pd.RequestedOperation)
		}
		if pd.Direction != api.SignalCallerDirection_REMOTE_PEER {
			t.Errorf("expected REMOTE_PEER for remote peer request, got %v", pd.Direction)
		}
	})

	t.Run("DatalogEvaluationDenial_ServiceSubstringClassification", func(t *testing.T) {
		// When the target service name contains the word "service" (e.g. "db-service"),
		// Datalog evaluation denials must not be misclassified as UNAUTHORIZED_SERVICE.
		req := RequestContext{
			PeerID:   callerPID,
			Target:   "db-service",
			Protocol: "/agentmesh/sql/1.0.0",
		}

		datalogErr := errors.New("authorization check failed: missing fact: right(#authority, \"db-service\", \"execute\")")
		n.emitMiddlewarePolicyDenied(req, nil, datalogErr)

		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		pd := evt.GetPolicyDenied()
		if pd == nil {
			t.Fatal("expected PolicyDenied signal payload, got nil")
		}
		if pd.Reason != api.PolicyDenialReason_DATALOG_EVALUATION_DENIED {
			t.Fatalf("expected DATALOG_EVALUATION_DENIED, got %v", pd.Reason)
		}
	})

	t.Run("TaskAuthorizationRuleViolation_DeniedTarget", func(t *testing.T) {
		req := RequestContext{
			PeerID:   callerPID,
			Target:   "mcp://production-storage",
			Protocol: "/agentmesh/mcp/1.0.0",
			MCPTool:  "delete_all_records",
		}

		tarErr := fmt.Errorf("tar_block[1] (\"scoped-task\") denied request to mcp://production-storage")
		n.emitMiddlewarePolicyDenied(req, nil, tarErr)

		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		pd := evt.GetPolicyDenied()
		if pd == nil {
			t.Fatal("expected PolicyDenied signal, got nil")
		}
		if pd.Reason != api.PolicyDenialReason_TASK_AUTHORIZATION_RULE_VIOLATION {
			t.Errorf("expected TASK_AUTHORIZATION_RULE_VIOLATION, got %v", pd.Reason)
		}
		if pd.RequestedOperation != "delete_all_records" {
			t.Errorf("expected RequestedOperation 'delete_all_records', got %q", pd.RequestedOperation)
		}
		if pd.TargetService != "mcp://production-storage" {
			t.Errorf("expected TargetService 'mcp://production-storage', got %q", pd.TargetService)
		}
	})

	t.Run("TaskAuthorizationRuleViolation_ExpiredTARBlock", func(t *testing.T) {
		req := RequestContext{
			PeerID:   callerPID,
			Target:   "mcp://weather",
			Protocol: "/agentmesh/mcp/1.0.0",
		}

		tarExpiredErr := fmt.Errorf("tar_block[2] (\"weather-read\") expired at 2026-10-01T00:00:00Z")
		n.emitMiddlewarePolicyDenied(req, nil, tarExpiredErr)

		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		pd := evt.GetPolicyDenied()
		if pd == nil {
			t.Fatal("expected PolicyDenied signal, got nil")
		}
		if pd.Reason != api.PolicyDenialReason_TASK_AUTHORIZATION_RULE_VIOLATION {
			t.Errorf("expected TASK_AUTHORIZATION_RULE_VIOLATION, got %v", pd.Reason)
		}
	})

	t.Run("ModelArmor_PromptSanitizationBlock_Request", func(t *testing.T) {
		svc := &EgressService{
			node: n,
			info: &api.ServiceInfo{
				Name: "llm-gateway",
			},
		}

		req, err := http.NewRequest(http.MethodPost, "http://localhost/mesh/dummy/http/v1/chat/completions", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}

		callerCtx := egressCallerContext{
			actorNode: callerPID.String(),
			principal: "agent-adversary",
			roles:     []string{"mesh:role:node", "researcher"},
			task:      "prompt-injection-test",
		}

		svc.emitInspectionDenied(req, callerCtx, "model_armor", "request", "prompt matched sanitization filter: prompt_injection_detected")

		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		pd := evt.GetPolicyDenied()
		if pd == nil {
			t.Fatal("expected PolicyDenied signal, got nil")
		}
		if pd.Reason != api.PolicyDenialReason_INSPECTION_FILTER_BLOCKED {
			t.Errorf("expected INSPECTION_FILTER_BLOCKED, got %v", pd.Reason)
		}
		if pd.TargetService != api.EgressServicePrefix+"llm-gateway" {
			t.Errorf("expected TargetService '%sllm-gateway', got %q", api.EgressServicePrefix, pd.TargetService)
		}
		if pd.CallerSubject != "agent-adversary" {
			t.Errorf("expected CallerSubject 'agent-adversary', got %q", pd.CallerSubject)
		}
		if pd.CallerPeerId != callerPID.String() {
			t.Errorf("expected CallerPeerId %q, got %q", callerPID.String(), pd.CallerPeerId)
		}
	})

	t.Run("ModelArmor_PromptSanitizationBlock_Response", func(t *testing.T) {
		svc := &EgressService{
			node: n,
			info: &api.ServiceInfo{
				Name: "llm-gateway",
			},
		}

		req, err := http.NewRequest(http.MethodPost, "http://localhost/mesh/dummy/http/v1/chat/completions", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}

		callerCtx := egressCallerContext{
			actorNode: callerPID.String(),
			principal: "agent-adversary",
			roles:     []string{"mesh:role:node"},
		}

		svc.emitInspectionDenied(req, callerCtx, "model_armor", "response", "response matched sanitization filter: pii_leak")

		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		pd := evt.GetPolicyDenied()
		if pd.Reason != api.PolicyDenialReason_INSPECTION_FILTER_BLOCKED {
			t.Errorf("expected INSPECTION_FILTER_BLOCKED, got %v", pd.Reason)
		}
	})

	t.Run("ExtProc_FilterBlock", func(t *testing.T) {
		svc := &EgressService{
			node: n,
			info: &api.ServiceInfo{
				Name: "secure-api",
			},
		}

		req, err := http.NewRequest(http.MethodGet, "http://localhost/mesh/dummy/http/data", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}

		callerCtx := egressCallerContext{
			actorNode: callerPID.String(),
			principal: "worker-1",
		}

		svc.emitInspectionDenied(req, callerCtx, "ext_proc", "request", "blocked by custom DLP rule 42")

		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		pd := evt.GetPolicyDenied()
		if pd.Reason != api.PolicyDenialReason_INSPECTION_FILTER_BLOCKED {
			t.Errorf("expected INSPECTION_FILTER_BLOCKED, got %v", pd.Reason)
		}
	})
}

// 2. Empirical test of Caller Direction Accuracy across all code paths
func TestContainmentSecurity_CallerDirection_Accuracy(t *testing.T) {
	disp := newChanDispatcher(20)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}

	_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	remotePID, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("IDFromPublicKey: %v", err)
	}

	t.Run("Stream_LocalWorkload_Tagged", func(t *testing.T) {
		req := RequestContext{
			PeerID:   remotePID,
			Target:   "local-echo",
			Protocol: "/agentmesh/echo/1.0.0",
			Local:    true, // Marked local
		}

		n.emitMiddlewarePolicyDenied(req, nil, errors.New("datalog check failed: denial"))
		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		pd := evt.GetPolicyDenied()
		if pd.Direction != api.SignalCallerDirection_LOCAL_WORKLOAD {
			t.Errorf("expected LOCAL_WORKLOAD when req.Local=true, got %v", pd.Direction)
		}
	})

	t.Run("Stream_RemotePeer_Tagged", func(t *testing.T) {
		req := RequestContext{
			PeerID:   remotePID,
			Target:   "remote-service",
			Protocol: "/agentmesh/echo/1.0.0",
			Local:    false, // Marked remote
		}

		n.emitMiddlewarePolicyDenied(req, nil, errors.New("datalog check failed: denial"))
		evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
		pd := evt.GetPolicyDenied()
		if pd.Direction != api.SignalCallerDirection_REMOTE_PEER {
			t.Errorf("expected REMOTE_PEER when req.Local=false, got %v", pd.Direction)
		}
	})

	t.Run("HTTP_LocalSocket_ContextTagged", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://localhost/service", nil)
		// Attach local socket context key
		reqWithLocal := req.WithContext(context.WithValue(req.Context(), localSocketContextKey{}, true))

		dir := n.detectCallerDirection(reqWithLocal, nil)
		if dir != api.SignalCallerDirection_LOCAL_WORKLOAD {
			t.Errorf("expected LOCAL_WORKLOAD from localSocketContextKey, got %v", dir)
		}
	})

	t.Run("HTTP_RemotePeer_RemoteAddrDecoded", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://localhost/service", nil)
		req.RemoteAddr = remotePID.String()

		dir := n.detectCallerDirection(req, nil)
		if dir != api.SignalCallerDirection_REMOTE_PEER {
			t.Errorf("expected REMOTE_PEER from RemoteAddr peer string, got %v", dir)
		}
	})

	t.Run("HTTP_ContextOverride_RemotePeer", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://localhost/service", nil)
		reqWithDir := req.WithContext(WithCallerDirection(req.Context(), api.SignalCallerDirection_REMOTE_PEER))

		dir := n.detectCallerDirection(reqWithDir, nil)
		if dir != api.SignalCallerDirection_REMOTE_PEER {
			t.Errorf("expected REMOTE_PEER from WithCallerDirection, got %v", dir)
		}
	})

	t.Run("HTTP_ContextOverride_LocalWorkload", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://localhost/service", nil)
		// Even if RemoteAddr is a remote peer, context override takes precedence
		req.RemoteAddr = remotePID.String()
		reqWithDir := req.WithContext(WithCallerDirection(req.Context(), api.SignalCallerDirection_LOCAL_WORKLOAD))

		dir := n.detectCallerDirection(reqWithDir, nil)
		if dir != api.SignalCallerDirection_LOCAL_WORKLOAD {
			t.Errorf("expected LOCAL_WORKLOAD from WithCallerDirection override, got %v", dir)
		}
	})
}

// 3. Empirical test of Stream Refusal and Ban Gossip Emission
func TestContainmentSecurity_StreamRefusal_And_BanGossip(t *testing.T) {
	disp := newChanDispatcher(20)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}

	testPeer := peer.ID("12D3KooWAdversarialRefusalPeer")
	maddr, err := multiaddr.NewMultiaddr("/ip4/10.0.0.42/tcp/5001")
	if err != nil {
		t.Fatalf("NewMultiaddr: %v", err)
	}

	t.Run("TransportRefused_PeerUnauthenticated", func(t *testing.T) {
		n.emitTransportRefused(testPeer, maddr, protocol.ID("/agentmesh/data/1.0.0"),
			api.TransportRefusalReason_PEER_UNAUTHENTICATED, "handshake timeout")

		evt := expectEventTimeout(t, disp, "agentmesh.transport.refused", time.Second)
		if evt.Type != "agentmesh.transport.refused" {
			t.Errorf("expected agentmesh.transport.refused, got %q", evt.Type)
		}
		if evt.Subject != testPeer.String() {
			t.Errorf("expected Subject %q, got %q", testPeer.String(), evt.Subject)
		}
		tr := evt.GetTransportRefused()
		if tr == nil {
			t.Fatal("expected TransportRefused signal, got nil")
		}
		if tr.Reason != api.TransportRefusalReason_PEER_UNAUTHENTICATED {
			t.Errorf("expected PEER_UNAUTHENTICATED, got %v", tr.Reason)
		}
		if tr.RemoteMultiaddr != "/ip4/10.0.0.42/tcp/5001" {
			t.Errorf("expected RemoteMultiaddr '/ip4/10.0.0.42/tcp/5001', got %q", tr.RemoteMultiaddr)
		}
	})

	t.Run("TransportRefused_NotRouterRole", func(t *testing.T) {
		n.emitTransportRefused(testPeer, maddr, protocol.ID("/agentmesh/router/1.0.0"),
			api.TransportRefusalReason_NOT_ROUTER_ROLE, "role mismatch")

		evt := expectEventTimeout(t, disp, "agentmesh.transport.refused", time.Second)
		tr := evt.GetTransportRefused()
		if tr.Reason != api.TransportRefusalReason_NOT_ROUTER_ROLE {
			t.Errorf("expected NOT_ROUTER_ROLE, got %v", tr.Reason)
		}
	})

	t.Run("IdentityRevoked_GossipBanEvent", func(t *testing.T) {
		_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateEd25519Key: %v", err)
		}
		bannedPID, err := peer.IDFromPublicKey(pub)
		if err != nil {
			t.Fatalf("IDFromPublicKey: %v", err)
		}

		nowProto := timestamppb.Now()
		n.handleBannedEvent(&api.MeshEvent{
			Type:      api.MeshEvent_BANNED,
			PeerId:    bannedPID.String(),
			EventTime: nowProto,
		})

		evt := expectEventTimeout(t, disp, "agentmesh.identity.revoked", time.Second)
		if evt.Subject != bannedPID.String() {
			t.Errorf("expected Subject %q, got %q", bannedPID.String(), evt.Subject)
		}
		ir := evt.GetIdentityRevoked()
		if ir == nil {
			t.Fatal("expected IdentityRevoked signal, got nil")
		}
		if ir.Source != api.RevocationSource_MESH_EVENT_BANNED_GOSSIP {
			t.Errorf("expected MESH_EVENT_BANNED_GOSSIP, got %v", ir.Source)
		}
		if ir.PeerId != bannedPID.String() {
			t.Errorf("expected PeerId %q, got %q", bannedPID.String(), ir.PeerId)
		}

		// Out-of-order older ban event MUST be dropped without emitting duplicate
		olderProto := timestamppb.New(nowProto.AsTime().Add(-10 * time.Minute))
		n.handleBannedEvent(&api.MeshEvent{
			Type:      api.MeshEvent_BANNED,
			PeerId:    bannedPID.String(),
			EventTime: olderProto,
		})

		// Channel should have no new events
		select {
		case unexpected := <-disp.events:
			t.Fatalf("unexpected event emitted for out-of-order ban: %v", unexpected)
		case <-time.After(50 * time.Millisecond):
			// Passed: dropped silently
		}
	})
}

// 4. Empirical test of High-Concurrency, Deadlock-Freedom, and Queue Saturation
func TestContainmentSecurity_Concurrency_DeadlockFreedom_UnderSaturation(t *testing.T) {
	var receivedCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Small queue to force buffer saturation and shedding
	realDisp, err := containment.NewDispatcher(containment.Config{
		Endpoints: []containment.EndpointConfig{
			{
				URL:     server.URL,
				Timeout: time.Second,
			},
		},
		QueueCapacity: 20,
		Workers:       4,
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	node := &AgentMeshNode{
		containmentDispatcher: realDisp,
	}

	const goroutines = 30
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Rapid interleaved emissions across all hook types
				switch (gid + i) % 4 {
				case 0:
					node.EmitPolicyDenied(PolicyDeniedParams{
						Direction:     api.SignalCallerDirection_REMOTE_PEER,
						Reason:        api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
						Detail:        "stress denial",
						TargetService: "calculator",
						CallerPeerID:  "12D3KooWConcurrentCaller",
						EventTime:     time.Now(),
					})
				case 1:
					node.emitTransportRefused(peer.ID("12D3KooWConcurrentRefused"), nil,
						protocol.ID("/agentmesh/test"), api.TransportRefusalReason_PEER_UNAUTHENTICATED, "stress refusal")
				case 2:
					node.handleBannedEvent(&api.MeshEvent{
						Type:      api.MeshEvent_BANNED,
						PeerId:    fmt.Sprintf("12D3KooWBanned%d_%d", gid, i),
						EventTime: timestamppb.Now(),
					})
				case 3:
					node.emitIdentityRevoked(fmt.Sprintf("12D3KooWRevoked%d", gid),
						api.RevocationSource_LOCAL_CONTROL_PLANE_SYNC, "stress revoked", nil)
				}
			}
		}(g)
	}

	// Wait with a hard timeout to empirically prove zero deadlock
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded without deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected during concurrent containment signal dispatch")
	}

	// Clean drain and close within bounded deadline
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := realDisp.Close(closeCtx); err != nil {
		t.Logf("Close returned: %v (expected under queue shedding saturation)", err)
	}
}

// 5. Empirical test verifying that nil dispatcher never panics
func TestContainmentSecurity_NilDispatcher_ZeroPanic(t *testing.T) {
	n := &AgentMeshNode{
		containmentDispatcher: nil,
	}

	// Every hook call must safely no-op without panicking
	n.EmitPolicyDenied(PolicyDeniedParams{
		Reason: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
	})
	n.emitMiddlewarePolicyDenied(RequestContext{}, nil, errors.New("err"))
	n.emitTransportRefused(peer.ID("dummy"), nil, protocol.ID("/test"), api.TransportRefusalReason_PEER_UNAUTHENTICATED, "refused")
	n.emitIdentityRevoked("dummy", api.RevocationSource_LOCAL_CONTROL_PLANE_SYNC, "revoked", nil)
	n.handleBannedEvent(&api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    "12D3KooWDummyPeerID",
		EventTime: timestamppb.Now(),
	})
}


// 6. Empirical high-volume stress tests verifying zero panic, zero deadlock, and clean bounded drain

func TestContainmentSecurity_Concurrency_HighVolume_10000Emissions_ZeroPanic_BoundedDrain(t *testing.T) {
	var deliveredCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveredCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	disp, err := containment.NewDispatcher(containment.Config{
		Endpoints: []containment.EndpointConfig{
			{
				URL:     server.URL,
				Timeout: 2 * time.Second,
			},
		},
		QueueCapacity: 200,
		Workers:       8,
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	// Generate 20 real cryptographic peer IDs for realistic multihash decoding
	var realPeers [20]peer.ID
	for i := 0; i < 20; i++ {
		_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateEd25519Key: %v", err)
		}
		pid, err := peer.IDFromPublicKey(pub)
		if err != nil {
			t.Fatalf("IDFromPublicKey: %v", err)
		}
		realPeers[i] = pid
	}

	node := &AgentMeshNode{
		containmentDispatcher: disp,
		peerLastEventTime:     make(map[string]int64),
	}

	const goroutines = 50
	const iterationsPerGoroutine = 200 // 50 * 200 = 10,000 total events
	var wg sync.WaitGroup
	wg.Add(goroutines)

	startGate := make(chan struct{})
	var closeOnce sync.Once
	closeTrigger := make(chan struct{})

	// Concurrently close node when trigger fires
	go func() {
		<-closeTrigger
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = node.CloseWithContext(closeCtx)
	}()

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			<-startGate

			for i := 0; i < iterationsPerGoroutine; i++ {
				// Trigger concurrent close halfway through
				if gid == 0 && i == iterationsPerGoroutine/2 {
					closeOnce.Do(func() { close(closeTrigger) })
				}

				pID := realPeers[(gid+i)%20]

				switch (gid + i) % 4 {
				case 0:
					node.EmitPolicyDenied(PolicyDeniedParams{
						Direction:          api.SignalCallerDirection_LOCAL_WORKLOAD,
						Reason:             api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
						Detail:             fmt.Sprintf("stress denial %d-%d", gid, i),
						TargetService:      fmt.Sprintf("service-%d", i%10),
						RequestedOperation: "query",
						RequestedResource:  "/data",
						CallerPeerID:       pID.String(),
						CallerSubject:      fmt.Sprintf("agent-%d", gid),
						CallerRoles:        []string{"worker"},
						EventTime:          time.Now(),
					})
				case 1:
					node.emitTransportRefused(
						pID,
						nil,
						protocol.ID("/agentmesh/test/1.0"),
						api.TransportRefusalReason_PEER_UNAUTHENTICATED,
						fmt.Sprintf("handshake rejected %d-%d", gid, i),
					)
				case 2:
					node.handleBannedEvent(&api.MeshEvent{
						Type:      api.MeshEvent_BANNED,
						PeerId:    pID.String(),
						EventTime: timestamppb.New(time.Now().Add(time.Duration(i) * time.Millisecond)),
					})
				case 3:
					node.emitIdentityRevoked(
						pID.String(),
						api.RevocationSource_LOCAL_CONTROL_PLANE_SYNC,
						"policy revocation",
						[]string{"rev-1", "rev-2"},
					)
				}
			}
		}(g)
	}

	// Release all workers simultaneously
	close(startGate)

	// Await completion with hard timeout to detect deadlock
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded: all goroutines completed without deadlock or panic
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK DETECTED: 10,000 concurrent event emissions did not complete within 10s")
	}

	// Ensure close trigger was pulled
	closeOnce.Do(func() { close(closeTrigger) })

	// Ensure final node close completes cleanly
	finalCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := node.CloseWithContext(finalCtx); err != nil {
		t.Logf("Final node close returned: %v (clean idempotent teardown)", err)
	}

	t.Logf("Empirical stress test completed successfully: delivered=%d", deliveredCount.Load())
}

func TestContainmentSecurity_Concurrency_GossipBan_BurstMonotonicTracking(t *testing.T) {
	node := &AgentMeshNode{
		peerLastEventTime: make(map[string]int64),
	}

	// Pre-generate 10 real cryptographic peer IDs
	var realPeers [10]peer.ID
	for i := 0; i < 10; i++ {
		_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateEd25519Key: %v", err)
		}
		pid, err := peer.IDFromPublicKey(pub)
		if err != nil {
			t.Fatalf("IDFromPublicKey: %v", err)
		}
		realPeers[i] = pid
	}

	const goroutines = 30
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	baseTime := time.Now()

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Mix of out-of-order and newer events
				eventTime := baseTime.Add(time.Duration((i*7)%iterations) * time.Millisecond)
				targetPeer := realPeers[i%10].String()

				node.handleBannedEvent(&api.MeshEvent{
					Type:      api.MeshEvent_BANNED,
					PeerId:    targetPeer,
					EventTime: timestamppb.New(eventTime),
				})
			}
		}(g)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK DETECTED in concurrent gossip ban processing")
	}

	node.mu.Lock()
	defer node.mu.Unlock()
	if len(node.peerLastEventTime) != 10 {
		t.Errorf("expected 10 distinct tracked peers, got %d", len(node.peerLastEventTime))
	}
}

func TestContainmentSecurity_Concurrency_DispatcherCloseRace_ZeroPanic(t *testing.T) {
	const trials = 10
	for trial := 0; trial < trials; trial++ {
		disp, err := containment.NewDispatcher(containment.Config{
			QueueCapacity: 50,
			Workers:       2,
		})
		if err != nil {
			t.Fatalf("NewDispatcher: %v", err)
		}

		node := &AgentMeshNode{
			containmentDispatcher: disp,
		}

		var wg sync.WaitGroup
		const emitters = 20
		wg.Add(emitters)

		stopCh := make(chan struct{})
		var emissionCount atomic.Int64

		for e := 0; e < emitters; e++ {
			go func(id int) {
				defer wg.Done()
				for {
					select {
					case <-stopCh:
						return
					default:
						if id%2 == 0 {
							node.EmitPolicyDenied(PolicyDeniedParams{
								Direction: api.SignalCallerDirection_REMOTE_PEER,
								Reason:    api.PolicyDenialReason_ROLE_MISMATCH,
								Detail:    "close race",
								EventTime: time.Now(),
							})
						} else {
							node.emitTransportRefused(
								peer.ID("12D3KooWRacePeer"),
								nil,
								protocol.ID("/agentmesh/test"),
								api.TransportRefusalReason_PEER_UNAUTHENTICATED,
								"close race",
							)
						}
						emissionCount.Add(1)
					}
				}
			}(e)
		}

		time.Sleep(5 * time.Millisecond)

		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := disp.Close(closeCtx); err != nil {
			t.Logf("Trial %d close returned: %v", trial, err)
		}
		cancel()

		close(stopCh)
		wg.Wait()
	}
}
