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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type chanDispatcher struct {
	events chan *api.SecuritySignalEvent
}

func newChanDispatcher(buf int) *chanDispatcher {
	return &chanDispatcher{
		events: make(chan *api.SecuritySignalEvent, buf),
	}
}

func (d *chanDispatcher) Dispatch(event *api.SecuritySignalEvent) {
	select {
	case d.events <- event:
	default:
	}
}

func (d *chanDispatcher) Close(ctx context.Context) error {
	return nil
}

func expectEvent(t *testing.T, d *chanDispatcher, expectedType string) *api.SecuritySignalEvent {
	t.Helper()
	select {
	case evt := <-d.events:
		if evt.Type != expectedType {
			t.Fatalf("expected event type %q, got %q", expectedType, evt.Type)
		}
		return evt
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event type %q", expectedType)
		return nil
	}
}

func TestContainmentNode_PolicyDenied_EmitDirect(t *testing.T) {
	disp := newChanDispatcher(10)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}

	now := time.Now()
	n.EmitPolicyDenied(PolicyDeniedParams{
		Direction:          api.SignalCallerDirection_LOCAL_WORKLOAD,
		Reason:             api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		Detail:             "query authorization failed",
		TargetService:      "bigquery",
		RequestedOperation: "SELECT",
		RequestedResource:  "datasets/prod/*",
		CallerPeerID:       "12D3KooWDummyCallerPeerID",
		CallerSubject:      "service-account-1@gserviceaccount.com",
		CallerRoles:        []string{"mesh:role:node", "analytics-reader"},
		CallerLabels:       map[string]string{"env": "prod"},
		EventTime:          now,
	})

	evt := expectEvent(t, disp, "agentmesh.policy.denied")
	if evt.SpecVersion != "1.0" {
		t.Errorf("expected SpecVersion 1.0, got %q", evt.SpecVersion)
	}
	if evt.Subject != "12D3KooWDummyCallerPeerID" {
		t.Errorf("expected Subject '12D3KooWDummyCallerPeerID', got %q", evt.Subject)
	}
	pd := evt.GetPolicyDenied()
	if pd == nil {
		t.Fatal("expected PolicyDenied data, got nil")
	}
	if pd.Direction != api.SignalCallerDirection_LOCAL_WORKLOAD {
		t.Errorf("expected LOCAL_WORKLOAD, got %v", pd.Direction)
	}
	if pd.Reason != api.PolicyDenialReason_DATALOG_EVALUATION_DENIED {
		t.Errorf("expected DATALOG_EVALUATION_DENIED, got %v", pd.Reason)
	}
	if pd.TargetService != "bigquery" {
		t.Errorf("expected TargetService bigquery, got %q", pd.TargetService)
	}
	if pd.RequestedOperation != "SELECT" {
		t.Errorf("expected RequestedOperation SELECT, got %q", pd.RequestedOperation)
	}
	if pd.RequestedResource != "datasets/prod/*" {
		t.Errorf("expected RequestedResource datasets/prod/*, got %q", pd.RequestedResource)
	}
	if pd.CallerSubject != "service-account-1@gserviceaccount.com" {
		t.Errorf("expected CallerSubject service-account-1@gserviceaccount.com, got %q", pd.CallerSubject)
	}
	if len(pd.CallerRoles) != 2 || pd.CallerRoles[1] != "analytics-reader" {
		t.Errorf("unexpected CallerRoles: %v", pd.CallerRoles)
	}
	if pd.CallerLabels["env"] != "prod" {
		t.Errorf("unexpected CallerLabels: %v", pd.CallerLabels)
	}
}

func TestContainmentNode_PolicyDenied_MiddlewareClassification(t *testing.T) {
	disp := newChanDispatcher(10)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}

	req := RequestContext{
		PeerID:   peer.ID("12D3KooWTestPeerID"),
		User:     "bob",
		Group:    "eng",
		Target:   "calculator-mcp",
		Protocol: "/agentmesh/mcp/1.0.0",
	}

	// 1. Datalog denial
	datalogErr := errors.New("datalog check failed: authorize check: missing fact: right(#authority, \"calculator-mcp\", \"execute\")")
	n.emitMiddlewarePolicyDenied(req, nil, datalogErr)
	evt1 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd1 := evt1.GetPolicyDenied()
	if pd1.Reason != api.PolicyDenialReason_DATALOG_EVALUATION_DENIED {
		t.Errorf("expected DATALOG_EVALUATION_DENIED, got %v", pd1.Reason)
	}
	if pd1.TargetService != "calculator-mcp" {
		t.Errorf("expected TargetService calculator-mcp, got %q", pd1.TargetService)
	}

	// 2. TAR rule denial
	tarErr := errors.New("tar_block: task authorization rule failed: rule 1: operation denied for untrusted input")
	n.emitMiddlewarePolicyDenied(req, nil, tarErr)
	evt2 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd2 := evt2.GetPolicyDenied()
	if pd2.Reason != api.PolicyDenialReason_TASK_AUTHORIZATION_RULE_VIOLATION {
		t.Errorf("expected TASK_AUTHORIZATION_RULE_VIOLATION, got %v", pd2.Reason)
	}

	// 3. Biscuit revocation denial
	revokedErr := errors.New("biscuit token authority is revoked by control plane")
	n.emitMiddlewarePolicyDenied(req, nil, revokedErr)
	evt3 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd3 := evt3.GetPolicyDenied()
	if pd3.Reason != api.PolicyDenialReason_EXPIRED_CREDENTIAL {
		t.Errorf("expected EXPIRED_CREDENTIAL, got %v", pd3.Reason)
	}

	// 4. Role mismatch denial (anchored phrase)
	roleErr := errors.New("unauthorized role: caller requires admin role")
	n.emitMiddlewarePolicyDenied(req, nil, roleErr)
	evt4 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd4 := evt4.GetPolicyDenied()
	if pd4.Reason != api.PolicyDenialReason_ROLE_MISMATCH {
		t.Errorf("expected ROLE_MISMATCH, got %v", pd4.Reason)
	}

	// 5. Unauthorized service denial (anchored phrase and ErrProviderNotGranted)
	svcErr := fmt.Errorf("%w: calculator-mcp", ErrProviderNotGranted)
	n.emitMiddlewarePolicyDenied(req, nil, svcErr)
	evt5 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd5 := evt5.GetPolicyDenied()
	if pd5.Reason != api.PolicyDenialReason_UNAUTHORIZED_SERVICE {
		t.Errorf("expected UNAUTHORIZED_SERVICE, got %v", pd5.Reason)
	}

	// 6. Unauthorized path or method denial (anchored phrase)
	methodErr := errors.New("method not allowed: POST /admin/config")
	n.emitMiddlewarePolicyDenied(req, nil, methodErr)
	evt6 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd6 := evt6.GetPolicyDenied()
	if pd6.Reason != api.PolicyDenialReason_UNAUTHORIZED_PATH_OR_METHOD {
		t.Errorf("expected UNAUTHORIZED_PATH_OR_METHOD, got %v", pd6.Reason)
	}

	// 7. Biscuit sentinel ErrPolicyDenied
	sentinelErr := biscuit.ErrPolicyDenied
	n.emitMiddlewarePolicyDenied(req, nil, sentinelErr)
	evt7 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd7 := evt7.GetPolicyDenied()
	if pd7.Reason != api.PolicyDenialReason_DATALOG_EVALUATION_DENIED {
		t.Errorf("expected DATALOG_EVALUATION_DENIED, got %v", pd7.Reason)
	}
}

func TestContainmentNode_PolicyDenied_EgressInspection(t *testing.T) {
	disp := newChanDispatcher(10)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}
	svc := &EgressService{
		node: n,
		info: &api.ServiceInfo{
			Name: "api-partner",
		},
	}

	httpReq, err := http.NewRequest(http.MethodPost, "http://localhost/mesh/dummy/http/api/v1/query", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	callerCtx := egressCallerContext{
		actorNode: "12D3KooWInspectionCaller",
		principal: "remote-agent-42",
		roles:     []string{"mesh:role:node"},
		task:      "summarize-report",
	}

	// ModelArmor request block
	svc.emitInspectionDenied(httpReq, callerCtx, "model_armor", "request", "jailbreak attempt detected by ModelArmor filter")
	evt1 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd1 := evt1.GetPolicyDenied()
	if pd1.Reason != api.PolicyDenialReason_INSPECTION_FILTER_BLOCKED {
		t.Errorf("expected INSPECTION_FILTER_BLOCKED, got %v", pd1.Reason)
	}
	if pd1.CallerSubject != "remote-agent-42" {
		t.Errorf("expected remote-agent-42, got %q", pd1.CallerSubject)
	}
	if pd1.TargetService != api.EgressServicePrefix+"api-partner" {
		t.Errorf("expected %sapi-partner, got %q", api.EgressServicePrefix, pd1.TargetService)
	}

	// ExtProc response block
	svc.emitInspectionDenied(httpReq, callerCtx, "ext_proc", "response", "data exfiltration blocked by ExtProc filter")
	evt2 := expectEvent(t, disp, "agentmesh.policy.denied")
	pd2 := evt2.GetPolicyDenied()
	if pd2.Reason != api.PolicyDenialReason_INSPECTION_FILTER_BLOCKED {
		t.Errorf("expected INSPECTION_FILTER_BLOCKED, got %v", pd2.Reason)
	}
}

func TestContainmentNode_TransportRefused(t *testing.T) {
	disp := newChanDispatcher(10)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}

	testPeer := peer.ID("12D3KooWRefusedPeer")
	maddr, err := multiaddr.NewMultiaddr("/ip4/192.168.1.100/tcp/4001")
	if err != nil {
		t.Fatalf("multiaddr: %v", err)
	}

	// 1. Unauthenticated peer
	n.emitTransportRefused(testPeer, maddr, protocol.ID("/agentmesh/auth/1.0.0"), api.TransportRefusalReason_PEER_UNAUTHENTICATED, "peer not authenticated")
	evt1 := expectEvent(t, disp, "agentmesh.transport.refused")
	tr1 := evt1.GetTransportRefused()
	if tr1.Reason != api.TransportRefusalReason_PEER_UNAUTHENTICATED {
		t.Errorf("expected PEER_UNAUTHENTICATED, got %v", tr1.Reason)
	}
	if tr1.PeerId != testPeer.String() {
		t.Errorf("expected PeerId %q, got %q", testPeer.String(), tr1.PeerId)
	}
	if tr1.RemoteMultiaddr != "/ip4/192.168.1.100/tcp/4001" {
		t.Errorf("expected RemoteMultiaddr /ip4/192.168.1.100/tcp/4001, got %q", tr1.RemoteMultiaddr)
	}
	if tr1.CoalescedCount != 1 {
		t.Errorf("expected CoalescedCount 1, got %d", tr1.CoalescedCount)
	}

	// 2. Not router role
	n.emitTransportRefused(testPeer, maddr, protocol.ID("/agentmesh/router/1.0.0"), api.TransportRefusalReason_NOT_ROUTER_ROLE, "peer does not hold mesh:role:router")
	evt2 := expectEvent(t, disp, "agentmesh.transport.refused")
	tr2 := evt2.GetTransportRefused()
	if tr2.Reason != api.TransportRefusalReason_NOT_ROUTER_ROLE {
		t.Errorf("expected NOT_ROUTER_ROLE, got %v", tr2.Reason)
	}
}

func TestContainmentNode_IdentityRevoked_GossipBan(t *testing.T) {
	disp := newChanDispatcher(10)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}

	_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	bannedPID, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("IDFromPublicKey: %v", err)
	}

	n.handleBannedEvent(&api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    bannedPID.String(),
		EventTime: timestamppb.Now(),
	})

	evt := expectEvent(t, disp, "agentmesh.identity.revoked")
	if evt.Subject != bannedPID.String() {
		t.Errorf("expected Subject %q, got %q", bannedPID.String(), evt.Subject)
	}
	ir := evt.GetIdentityRevoked()
	if ir == nil {
		t.Fatal("expected IdentityRevoked data, got nil")
	}
	if ir.Source != api.RevocationSource_MESH_EVENT_BANNED_GOSSIP {
		t.Errorf("expected MESH_EVENT_BANNED_GOSSIP, got %v", ir.Source)
	}
	if ir.PeerId != bannedPID.String() {
		t.Errorf("expected PeerId %q, got %q", bannedPID.String(), ir.PeerId)
	}
}

func TestContainmentNode_IdentityRevoked_ControlPlaneSync(t *testing.T) {
	dir, err := os.MkdirTemp("", "node-containment-store-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	disp := newChanDispatcher(10)
	privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}

	cpPub, _, _ := ed25519.GenerateKey(nil)

	node, err := NewAgentMeshNode(Options{
		PrivKey:                  privKey,
		Store:                    store,
		ControlPlanePubKey:       cpPub,
		ContainmentDispatcher:    disp,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode: %v", err)
	}
	defer func() { _ = node.Teardown() }()

	_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	bannedPID, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("IDFromPublicKey: %v", err)
	}

	node.reconcileBannedPeers([]string{bannedPID.String()}, time.Now())

	evt := expectEvent(t, disp, "agentmesh.identity.revoked")
	if evt.Subject != bannedPID.String() {
		t.Errorf("expected Subject %q, got %q", bannedPID.String(), evt.Subject)
	}
	ir := evt.GetIdentityRevoked()
	if ir == nil {
		t.Fatal("expected IdentityRevoked data, got nil")
	}
	if ir.Source != api.RevocationSource_LOCAL_CONTROL_PLANE_SYNC {
		t.Errorf("expected LOCAL_CONTROL_PLANE_SYNC, got %v", ir.Source)
	}
}

func TestContainmentNode_CallerDirectionContext(t *testing.T) {
	ctx := context.Background()

	// Default when unset returns unspecified with false
	dir, ok := CallerDirectionFromContext(ctx)
	if ok || dir != api.SignalCallerDirection_SIGNAL_CALLER_DIRECTION_UNSPECIFIED {
		t.Errorf("expected unspecified false, got %v, %v", dir, ok)
	}

	// Explicit REMOTE_PEER
	remoteCtx := WithCallerDirection(ctx, api.SignalCallerDirection_REMOTE_PEER)
	dir, ok = CallerDirectionFromContext(remoteCtx)
	if !ok || dir != api.SignalCallerDirection_REMOTE_PEER {
		t.Errorf("expected REMOTE_PEER true, got %v, %v", dir, ok)
	}

	// Explicit LOCAL_WORKLOAD
	localCtx := WithCallerDirection(ctx, api.SignalCallerDirection_LOCAL_WORKLOAD)
	dir, ok = CallerDirectionFromContext(localCtx)
	if !ok || dir != api.SignalCallerDirection_LOCAL_WORKLOAD {
		t.Errorf("expected LOCAL_WORKLOAD true, got %v, %v", dir, ok)
	}
}
