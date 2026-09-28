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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildAndSaveBiscuit builds a biscuit signed with rootPriv that identifies
// node as caller, grants allow_mcp_server("*"), carries the node role as a
// real enrollment does, and saves it to node's store.
func buildAndSaveBiscuit(node *SamNode, rootPriv ed25519.PrivateKey) error {
	callerID := node.Host.ID().String()
	builder := biscuit.NewBuilder(rootPriv)
	_ = builder.AddAuthorityFact(api.MarkerFact(api.FactTargetUnrestricted))
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(callerID)},
	}}); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactRole,
		IDs:  []biscuit.Term{biscuit.String(api.RoleNode)},
	}}); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(callerID)},
	}}); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(api.MarkerFact(api.FactGrantedServiceAllTypes)); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
	}}); err != nil {
		return err
	}
	bisc, err := builder.Build()
	if err != nil {
		return err
	}
	biscBytes, err := bisc.Serialize()
	if err != nil {
		return err
	}
	return node.Store.SaveIdentity(biscBytes)
}

// enrollUnderRoot makes every node a member of the same mesh: each gets an
// identity biscuit signed by a fresh root and trusts that root, so both ends
// of any pair verify each other (the caller through WithBiscuitAuth, the
// provider through the label gate). Returns the root key pair for tests that
// need to mint extra tokens.
func enrollUnderRoot(t *testing.T, nodes ...*SamNode) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	for _, n := range nodes {
		if err := buildAndSaveBiscuit(n, rootPriv); err != nil {
			t.Fatalf("buildAndSaveBiscuit for %s: %v", n.Host.ID(), err)
		}
		n.keysMu.Lock()
		n.trustedKeys = append(n.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
		n.keysMu.Unlock()
	}
	return rootPub, rootPriv
}

func TestHandleFindRemoteTools_EmptyMesh_ReturnsEmptyArray(t *testing.T) {
	ctx, cancel := contextWithShortTimeout()
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	res, _, err := node.handleFindRemoteTools(ctx, &mcp.CallToolRequest{}, FindRemoteToolsParams{})
	if err != nil {
		t.Fatalf("handleFindRemoteTools: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("expected non-empty result content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &rows); err != nil {
		t.Fatalf("response not JSON array: %v (text: %q)", err, tc.Text)
	}
	if len(rows) != 0 {
		t.Errorf("expected empty results for empty mesh, got %d rows", len(rows))
	}
}

func TestHandleFindRemoteTools_SelfPeerRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleFindRemoteTools(ctx, &mcp.CallToolRequest{}, FindRemoteToolsParams{
		PeerID: node.Host.ID().String(),
	})
	if err == nil {
		t.Fatal("expected error when peer_id equals self peer ID")
	}
}

// contextWithShortTimeout returns a context with a small deadline so
// that tests fail fast if a libp2p dial hangs.
func contextWithShortTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func TestHandleFindRemoteTools_SinglePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "review_pr", Description: "Run a code review", InputSchema: map[string]any{"type": "object"}},
		{Name: "add_comment", Description: "Add a comment", InputSchema: map[string]any{"type": "object"}},
	}
	hostedSrv := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer hostedSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	enrollUnderRoot(t, nodeA, nodeB)

	// Register an MCP service on B with two tools.
	regReq := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}
	if err := nodeB.RegisterService(ctx, regReq); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	res, _, err := nodeA.handleFindRemoteTools(ctx, &mcp.CallToolRequest{}, FindRemoteToolsParams{
		PeerID: nodeB.Host.ID().String(),
	})
	if err != nil {
		t.Fatalf("handleFindRemoteTools: %v", err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	var rows []remoteToolRow
	if err := json.Unmarshal([]byte(tc.Text), &rows); err != nil {
		t.Fatalf("unmarshal: %v (text: %q)", err, tc.Text)
	}

	wantNames := map[string]bool{
		"mcp://code-reviewer/review_pr":   false,
		"mcp://code-reviewer/add_comment": false,
	}
	for _, row := range rows {
		if row.PeerID != nodeB.Host.ID().String() {
			t.Errorf("row has peer_id %q, want %q", row.PeerID, nodeB.Host.ID().String())
		}
		if _, ok := wantNames[row.ToolName]; ok {
			wantNames[row.ToolName] = true
		}
	}
	for name, found := range wantNames {
		if !found {
			t.Errorf("expected tool %q in response, not found; rows=%+v", name, rows)
		}
	}
}

// TestHandleFindRemoteTools_BackendPredatesDiscover is a regression test for
// a go-sdk v1.7.0 (SEP-2575) incompatibility: mcp.Client.Connect() sends a
// "server/discover" preflight before "initialize", falling back to the
// legacy handshake if it's rejected. HandleStreamPassThrough's dumb-pipe
// proxy used to forward that preflight straight to the backend, and a
// backend that doesn't understand it (like calc-mcp's Python server) would
// reject it, killing the whole libp2p stream before the "initialize"
// fallback could run. This exercises that path with a Go backend that
// mimics the same "discover unsupported" rejection, so it runs in
// milliseconds instead of the full docker-based e2e suite.
func TestHandleFindRemoteTools_BackendPredatesDiscover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tools := []*mcp.Tool{
		{Name: "add", Description: "Add two numbers", InputSchema: map[string]any{"type": "object"}},
	}
	hostedSrv := httptest.NewServer(newPreDiscoverMCPHandler(t, tools))
	defer hostedSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	enrollUnderRoot(t, nodeA, nodeB)

	regReq := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "calculator"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}
	if err := nodeB.RegisterService(ctx, regReq); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	res, _, err := nodeA.handleFindRemoteTools(ctx, &mcp.CallToolRequest{}, FindRemoteToolsParams{
		PeerID: nodeB.Host.ID().String(),
	})
	if err != nil {
		t.Fatalf("handleFindRemoteTools: %v", err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	var rows []remoteToolRow
	if err := json.Unmarshal([]byte(tc.Text), &rows); err != nil {
		t.Fatalf("unmarshal: %v (text: %q)", err, tc.Text)
	}

	var found bool
	for _, row := range rows {
		if row.Error != "" {
			t.Errorf("row for %q has unexpected error: %s", row.ToolName, row.Error)
		}
		if row.ToolName == "mcp://calculator/add" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected mcp://calculator/add in response, not found; rows=%+v", rows)
	}
}

func TestHandleFindRemoteTools_MeshWide(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// B hosts "code-reviewer", C hosts "mcp:summarizer", D hosts "plugin:linter".
	bTools := []*mcp.Tool{
		{Name: "review_pr", Description: "review", InputSchema: map[string]any{"type": "object"}},
	}
	cTools := []*mcp.Tool{
		{Name: "summarize", Description: "summarize", InputSchema: map[string]any{"type": "object"}},
	}
	dTools := []*mcp.Tool{
		{Name: "lint", Description: "lint", InputSchema: map[string]any{"type": "object"}},
	}
	bSrv := httptest.NewServer(newFakeMCPHandler(t, bTools))
	defer bSrv.Close()
	cSrv := httptest.NewServer(newFakeMCPHandler(t, cTools))
	defer cSrv.Close()
	dSrv := httptest.NewServer(newFakeMCPHandler(t, dTools))
	defer dSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()
	nodeC, cleanupC := startBareNode(t, ctx)
	defer cleanupC()
	nodeD, cleanupD := startBareNode(t, ctx)
	defer cleanupD()

	// Connect A to B, C, and D; every node is enrolled under one root so A's
	// stream passes WithBiscuitAuth and each target passes A's provider gate.
	enrollUnderRoot(t, nodeA, nodeB, nodeC, nodeD)
	for _, target := range []*SamNode{nodeB, nodeC, nodeD} {
		if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: target.Host.ID(), Addrs: target.Host.Addrs()}); err != nil {
			t.Fatalf("connect to %s: %v", target.Host.ID(), err)
		}
	}

	if err := nodeB.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: bSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService B: %v", err)
	}
	if err := nodeC.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "summarizer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: cSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService C: %v", err)
	}
	if err := nodeD.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "linter"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: dSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService D: %v", err)
	}
	// A name that carries its own scheme used to be accepted and reached via
	// a name-only fallback that ignored the type the policy was evaluated on.
	for _, legacy := range []string{"mcp://summarizer", "plugin://linter"} {
		if err := nodeD.RegisterService(ctx, &api.RegisterServiceRequest{
			Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: legacy},
			Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: dSrv.URL},
		}); err == nil {
			t.Errorf("service name %q was accepted", legacy)
		}
	}

	// Direct fan-out test: invoke fetchRemoteToolCatalogue for peers,
	// confirm they return their tools.
	rowsB, errB := nodeA.fetchRemoteToolCatalogue(ctx, nodeB.Host.ID(), "")
	if errB != nil {
		t.Fatalf("fetch from B: %v", errB)
	}
	rowsC, errC := nodeA.fetchRemoteToolCatalogue(ctx, nodeC.Host.ID(), "")
	if errC != nil {
		t.Fatalf("fetch from C: %v", errC)
	}
	rowsD, errD := nodeA.fetchRemoteToolCatalogue(ctx, nodeD.Host.ID(), "")
	if errD != nil {
		t.Fatalf("fetch from D: %v", errD)
	}

	gotNames := map[string]bool{}
	for _, tool := range append(append(rowsB, rowsC...), rowsD...) {
		gotNames[tool.ToolName] = true
	}

	for _, want := range []string{"mcp://code-reviewer/review_pr", "mcp://summarizer/summarize", "mcp://linter/lint"} {
		if !gotNames[want] {
			t.Errorf("missing %s; got %v", want, gotNames)
		}
	}
}

func TestHandleFindRemoteTools_PartialFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("network/dial: skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "summarize", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}))
	defer cSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeC, cleanupC := startBareNode(t, ctx)
	defer cleanupC()

	enrollUnderRoot(t, nodeA, nodeC)

	// A connects to C only; B is a fictional peer ID that won't resolve.
	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeC.Host.ID(), Addrs: nodeC.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	if err := nodeC.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "summarizer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: cSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	// Generate a fictitious peer ID from a fresh keypair we never connect to.
	_, fakePub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	fictitiousPID, err := peer.IDFromPublicKey(fakePub)
	if err != nil {
		t.Fatal(err)
	}

	rows := nodeA.fanOutFetch(ctx, []peer.ID{nodeC.Host.ID(), fictitiousPID}, "")

	gotSummarizer := false
	for _, r := range rows {
		if r.ToolName == "mcp://summarizer/summarize" {
			gotSummarizer = true
		}
	}
	if !gotSummarizer {
		t.Errorf("expected mcp://summarizer/summarize from C even with B unreachable; got %+v", rows)
	}
}

func buildAndSaveCustomBiscuit(node *SamNode, rootPriv ed25519.PrivateKey, allowedServices []string) error {
	callerID := node.Host.ID().String()
	builder := biscuit.NewBuilder(rootPriv)
	err := builder.AddAuthorityFact(api.MarkerFact(api.FactTargetUnrestricted))
	if err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(callerID)},
	}}); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactRole,
		IDs:  []biscuit.Term{biscuit.String(api.RoleNode)},
	}}); err != nil {
		return err
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(callerID)},
	}}); err != nil {
		return err
	}
	for _, svc := range allowedServices {
		opType, opName := api.ParseServiceTarget(svc)
		if opName == "" {
			opName = "*"
		}
		if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "granted_service_exact",
			IDs:  []biscuit.Term{biscuit.String(opType), biscuit.String(opName)},
		}}); err != nil {
			return err
		}
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
	}}); err != nil {
		return err
	}
	bisc, err := builder.Build()
	if err != nil {
		return err
	}
	biscBytes, err := bisc.Serialize()
	if err != nil {
		return err
	}
	return node.Store.SaveIdentity(biscBytes)
}

func TestFetchRemoteToolCatalogue_AuthRejectedHidden(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "summarize", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}))
	defer cSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeC, cleanupC := startBareNode(t, ctx)
	defer cleanupC()

	// Both enrolled under one root; A's identity is then narrowed to a
	// biscuit that DOES NOT allow "summarizer", only "some_other_service"
	// and "system://sam.catalog".
	_, rootPrivEd := enrollUnderRoot(t, nodeA, nodeC)
	if err := buildAndSaveCustomBiscuit(nodeA, rootPrivEd, []string{"mcp://some_other_service", "system://sam.catalog"}); err != nil {
		t.Fatalf("buildAndSaveCustomBiscuit: %v", err)
	}

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeC.Host.ID(), Addrs: nodeC.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	if err := nodeC.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "summarizer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: cSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}

	// Fetching tools from C should succeed for the catalog, but the unauthorized
	// "summarizer" service must be hidden entirely rather than leaked as an error
	// row (issue #176: discovery should only ever show what the caller can call).
	rows, err := nodeA.fetchRemoteToolCatalogue(ctx, nodeC.Host.ID(), "")
	if err != nil {
		t.Fatalf("fetchRemoteToolCatalogue returned unexpected overall error: %v", err)
	}

	if len(rows) != 0 {
		t.Fatalf("expected unauthorized service to be hidden (0 rows), got %d: %+v", len(rows), rows)
	}
}

func TestVerifyGossipToolRows_AuthenticatesEachServiceOnSamePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	allowedSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "review_pr", Description: "authorized review", InputSchema: map[string]any{"type": "object"}},
	}))
	defer allowedSrv.Close()
	deniedSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "review_pr", Description: "unauthorized review", InputSchema: map[string]any{"type": "object"}},
	}))
	defer deniedSrv.Close()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	_, rootPriv := enrollUnderRoot(t, nodeA, nodeB)
	if err := buildAndSaveCustomBiscuit(nodeA, rootPriv, []string{"mcp://allowed-reviewer"}); err != nil {
		t.Fatalf("buildAndSaveCustomBiscuit: %v", err)
	}
	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	for name, targetURL := range map[string]string{
		"allowed-reviewer": allowedSrv.URL,
		"denied-reviewer":  deniedSrv.URL,
	} {
		if err := nodeB.RegisterService(ctx, &api.RegisterServiceRequest{
			Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: name},
			Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: targetURL},
		}); err != nil {
			t.Fatalf("RegisterService %s: %v", name, err)
		}
	}

	peerID := nodeB.Host.ID().String()
	rows := nodeA.verifyGossipToolRows(ctx, []remoteToolRow{
		{PeerID: peerID, ToolName: "mcp://allowed-reviewer/review_pr", Labels: map[string]string{"region": "us"}},
		{PeerID: peerID, ToolName: "mcp://denied-reviewer/review_pr", Labels: map[string]string{"region": "us"}},
	})

	if len(rows) != 1 {
		t.Fatalf("expected one authorized row, got %d: %+v", len(rows), rows)
	}
	if rows[0].ToolName != "mcp://allowed-reviewer/review_pr" {
		t.Fatalf("unexpected verified tool: %+v", rows[0])
	}
	if rows[0].Description != "authorized review" {
		t.Errorf("Description = %q, want authorized review", rows[0].Description)
	}
	if rows[0].Labels["region"] != "us" {
		t.Errorf("gossip routing labels were not preserved: %+v", rows[0].Labels)
	}
}

func TestVerifyGossipToolRows_UsesIndependentRequestTimeouts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, publicKey, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	candidates := make([]remoteToolRow, 0, gossipVerificationMaxConcurrent+1)
	for i := range gossipVerificationMaxConcurrent {
		candidates = append(candidates, remoteToolRow{
			PeerID:   peerID.String(),
			ToolName: fmt.Sprintf("mcp://slow-%d/review_pr", i),
		})
	}
	candidates = append(candidates, remoteToolRow{
		PeerID:   peerID.String(),
		ToolName: "mcp://fast/review_pr",
	})

	allSlowRequestsStarted := make(chan struct{})
	releaseSlowRequests := make(chan struct{})
	var slowRequestsStarted atomic.Int32
	go func() {
		select {
		case <-allSlowRequestsStarted:
		case <-ctx.Done():
			return
		}
		select {
		case <-time.After(500 * time.Millisecond):
			close(releaseSlowRequests)
		case <-ctx.Done():
		}
	}()

	var fastRequestBudget time.Duration
	fetchDescription := func(ctx context.Context, pid peer.ID, toolName string) (*remoteToolDescription, error) {
		if toolName == "mcp://fast/review_pr" {
			deadline, ok := ctx.Deadline()
			if !ok {
				return nil, errors.New("fast request has no deadline")
			}
			fastRequestBudget = time.Until(deadline)
			return &remoteToolDescription{
				PeerID:      pid.String(),
				ToolName:    toolName,
				Description: "verified after delayed candidates",
			}, nil
		}

		if slowRequestsStarted.Add(1) == gossipVerificationMaxConcurrent {
			close(allSlowRequestsStarted)
		}
		select {
		case <-releaseSlowRequests:
			return nil, errors.New("delayed candidate rejected")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	rows := verifyGossipToolRowsWithFetcher(ctx, candidates, fetchDescription)
	if len(rows) != 1 || rows[0].ToolName != "mcp://fast/review_pr" {
		t.Fatalf("expected only the final candidate to verify, got %+v", rows)
	}
	if minimumBudget := gossipVerificationTimeout - 250*time.Millisecond; fastRequestBudget < minimumBudget {
		t.Fatalf("final candidate inherited an exhausted timeout: got %v, want at least %v", fastRequestBudget, minimumBudget)
	}
}

func TestCallMCPTool_LabelEnforcement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}

	// nodeA authenticates to nodeB as an unrestricted caller.
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	nodeB.keysMu.Lock()
	nodeB.trustedKeys = append(nodeB.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeB.keysMu.Unlock()

	// nodeB's own identity is control-plane-attested with region=eu-de; nodeA
	// must trust the same root to verify it.
	nodeBIdentity, err := identity.MintBootstrapBiscuitToken(rootPriv, nodeB.Host.ID(), api.RoleNode, time.Now().Add(time.Hour), nil, map[string]string{"region": "eu-de"})
	if err != nil {
		t.Fatalf("mint nodeB identity: %v", err)
	}
	nodeB.SetIdentityCache(nodeBIdentity)
	nodeA.keysMu.Lock()
	nodeA.trustedKeys = append(nodeA.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeA.keysMu.Unlock()

	hostedSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "review_pr", Description: "Run a code review", InputSchema: map[string]any{"type": "object"}},
	}))
	defer hostedSrv.Close()

	if err := nodeB.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}
	defer func() { _ = nodeB.UnregisterService(ctx, "code-reviewer") }()

	// A required label that nodeB's attestation satisfies (exact match).
	if _, err := nodeA.CallMCPTool(ctx, nodeB.Host.ID(), "mcp://code-reviewer/review_pr", map[string]any{}, map[string]string{"region": "eu-de"}); err != nil {
		t.Fatalf("CallMCPTool with satisfied label requirement should succeed: %v", err)
	}

	// A required label that nodeB's attestation does not satisfy: fail closed.
	if _, err := nodeA.CallMCPTool(ctx, nodeB.Host.ID(), "mcp://code-reviewer/review_pr", map[string]any{}, map[string]string{"region": "na-us"}); err == nil {
		t.Fatal("CallMCPTool with a non-matching label requirement must fail")
	}
}

// The operator's egress floor gates MCP egress even when the caller supplies no
// required_labels: silence must not waive the floor (see #385).
func TestCallMCPTool_EgressFloorEnforcement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}

	// nodeA authenticates to nodeB as an unrestricted caller.
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("buildAndSaveBiscuit: %v", err)
	}
	nodeB.keysMu.Lock()
	nodeB.trustedKeys = append(nodeB.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeB.keysMu.Unlock()

	// nodeB attests region=eu-de and nothing else.
	nodeBIdentity, err := identity.MintBootstrapBiscuitToken(rootPriv, nodeB.Host.ID(), api.RoleNode, time.Now().Add(time.Hour), nil, map[string]string{"region": "eu-de"})
	if err != nil {
		t.Fatalf("mint nodeB identity: %v", err)
	}
	nodeB.SetIdentityCache(nodeBIdentity)
	nodeA.keysMu.Lock()
	nodeA.trustedKeys = append(nodeA.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeA.keysMu.Unlock()

	hostedSrv := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "review_pr", Description: "Run a code review", InputSchema: map[string]any{"type": "object"}},
	}))
	defer hostedSrv.Close()

	if err := nodeB.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}
	defer func() { _ = nodeB.UnregisterService(ctx, "code-reviewer") }()

	// Floor satisfied by nodeB's attestation; the caller requires nothing.
	nodeA.nodeConfig = &NodeConfigComplete{EgressRequireLabels: map[string]string{"region": "eu-de"}}
	if _, err := nodeA.CallMCPTool(ctx, nodeB.Host.ID(), "mcp://code-reviewer/review_pr", map[string]any{}, nil); err != nil {
		t.Fatalf("CallMCPTool inside the floor should succeed: %v", err)
	}

	// Floor nodeB does not attest; the caller staying silent must not waive it.
	nodeA.nodeConfig = &NodeConfigComplete{EgressRequireLabels: map[string]string{"jurisdiction": "eu"}}
	if _, err := nodeA.CallMCPTool(ctx, nodeB.Host.ID(), "mcp://code-reviewer/review_pr", map[string]any{}, nil); err == nil {
		t.Fatal("CallMCPTool outside the floor with no caller requirement must fail")
	}
}

func TestNewMCPHandler_RegistersFindRemoteTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	srv := httptest.NewServer(NewMCPHandler(node))
	defer srv.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp"}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	found := false
	for _, tl := range res.Tools {
		if tl.Name == "find_remote_tools" {
			found = true
		}
	}
	if !found {
		var names []string
		for _, tl := range res.Tools {
			names = append(names, tl.Name)
		}
		t.Errorf("find_remote_tools missing from sidecar tools/list; got %v", names)
	}
}

// A legacy-version client that also sends the 2026-07-28 per-request _meta
// tag must be served, not refused as a new-protocol request; a stateful SDK
// handler answers it with -32022.
func TestNewMCPHandler_AcceptsLegacyRequestWithProtocolVersionMeta(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := httptest.NewServer(NewMCPHandler(&SamNode{BiscuitTimeout: 500 * time.Millisecond}))
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"tc","version":"0.0.1"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(out), `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("initialize with _meta protocol version tag: status %d body %s", resp.StatusCode, out)
	}
	if resp.Header.Get("Mcp-Session-Id") != "" {
		t.Errorf("stateless handler must not issue Mcp-Session-Id, got %q", resp.Header.Get("Mcp-Session-Id"))
	}
}

func TestHandleDescribeRemoteTool_EmptyPeerID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		ToolName: "code-reviewer/review_pr",
	})
	if err == nil {
		t.Fatal("expected error for empty peer_id")
	}
}

func TestHandleDescribeRemoteTool_EmptyToolName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID: "12D3KooWFakePeerID",
	})
	if err == nil {
		t.Fatal("expected error for empty tool_name")
	}
}

func TestHandleDescribeRemoteTool_NonNamespacedRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   node.Host.ID().String(),
		ToolName: "send_message", // no dot
	})
	if err == nil {
		t.Fatal("expected error for tool_name without '.'")
	}
	if !strings.Contains(err.Error(), "service/tool") {
		t.Errorf("error %q does not explain the namespacing requirement", err.Error())
	}
}

func TestHandleDescribeRemoteTool_SelfPeerRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   node.Host.ID().String(),
		ToolName: "mcp://code-reviewer/review_pr",
	})
	if err == nil {
		t.Fatal("expected error when peer_id equals self peer ID")
	}
}

func TestHandleDescribeRemoteTool_InvalidPeerID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	_, _, err := node.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   "not-a-valid-peer-id",
		ToolName: "mcp://code-reviewer/review_pr",
	})
	if err == nil {
		t.Fatal("expected error for malformed peer_id")
	}
}

func TestHandleDescribeRemoteTool_RoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	enrollUnderRoot(t, nodeA, nodeB)

	tools := []*mcp.Tool{
		{
			Name:        "review_pr",
			Description: "Run a code review",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []any{"pr_url"},
				"properties": map[string]any{
					"pr_url": map[string]any{"type": "string"},
				},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"summary": map[string]any{"type": "string"},
				},
			},
		},
	}
	hostedSrv := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer hostedSrv.Close()

	regReq := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}
	if err := nodeB.RegisterService(ctx, regReq); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}
	defer func() { _ = nodeB.UnregisterService(ctx, "code-reviewer") }()

	res, _, err := nodeA.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   nodeB.Host.ID().String(),
		ToolName: "mcp://code-reviewer/review_pr",
	})
	if err != nil {
		t.Fatalf("handleDescribeRemoteTool: %v", err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}

	var desc remoteToolDescription
	if err := json.Unmarshal([]byte(tc.Text), &desc); err != nil {
		t.Fatalf("unmarshal: %v (text: %q)", err, tc.Text)
	}
	if desc.PeerID != nodeB.Host.ID().String() {
		t.Errorf("PeerID = %q, want %q", desc.PeerID, nodeB.Host.ID().String())
	}
	if desc.ToolName != "mcp://code-reviewer/review_pr" {
		t.Errorf("ToolName = %q, want %q", desc.ToolName, "mcp://code-reviewer/review_pr")
	}
	if desc.Description != "Run a code review" {
		t.Errorf("Description = %q, want %q", desc.Description, "Run a code review")
	}
	inSchema, ok := desc.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("InputSchema type = %T, want map[string]any", desc.InputSchema)
	}
	if inSchema["type"] != "object" {
		t.Errorf("InputSchema.type = %v, want 'object'", inSchema["type"])
	}
	outSchema, ok := desc.OutputSchema.(map[string]any)
	if !ok {
		t.Fatalf("OutputSchema type = %T, want map[string]any", desc.OutputSchema)
	}
	if outSchema["type"] != "object" {
		t.Errorf("OutputSchema.type = %v, want 'object'", outSchema["type"])
	}
}

func TestHandleDescribeRemoteTool_RoundTrip_UnknownTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()
	nodeB, cleanupB := startBareNode(t, ctx)
	defer cleanupB()

	if err := nodeA.Host.Connect(ctx, peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	enrollUnderRoot(t, nodeA, nodeB)

	tools := []*mcp.Tool{
		{Name: "review_pr", Description: "x", InputSchema: map[string]any{"type": "object"}},
	}
	hostedSrv := httptest.NewServer(newFakeMCPHandler(t, tools))
	defer hostedSrv.Close()
	if err := nodeB.RegisterService(ctx, &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "code-reviewer"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: hostedSrv.URL},
	}); err != nil {
		t.Fatalf("RegisterService: %v", err)
	}
	defer func() { _ = nodeB.UnregisterService(ctx, "code-reviewer") }()

	_, _, err := nodeA.handleDescribeRemoteTool(ctx, &mcp.CallToolRequest{}, DescribeRemoteToolParams{
		PeerID:   nodeB.Host.ID().String(),
		ToolName: "mcp://code-reviewer/does-not-exist",
	})
	if err == nil {
		t.Fatal("expected error from peer when tool is not registered")
	}
	wantError := "tool not found on peer"
	if err.Error() != wantError {
		t.Errorf("error %q != %q", err.Error(), wantError)
	}
}

func TestNewMCPHandler_RegistersDescribeRemoteTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	srv := httptest.NewServer(NewMCPHandler(node))
	defer srv.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "tc", Version: "0.0.1"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp"}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	found := false
	for _, tl := range res.Tools {
		if tl.Name == "describe_remote_tool" {
			found = true
		}
	}
	if !found {
		var names []string
		for _, tl := range res.Tools {
			names = append(names, tl.Name)
		}
		t.Errorf("describe_remote_tool missing from sidecar tools/list; got %v", names)
	}
}

// newFakeMCPHandler returns an http.Handler serving a tiny MCP server over
// streamable-http with the given tools registered.
func newFakeMCPHandler(t *testing.T, tools []*mcp.Tool) http.Handler {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0.0.1"}, nil)
	for _, tool := range tools {
		toolCopy := tool
		srv.AddTool(toolCopy, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "fake-result:" + toolCopy.Name}},
			}, nil
		})
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
}

// newPreDiscoverMCPHandler wraps a real streamable-http MCP server but
// rejects the SEP-2575 "server/discover" preflight with a plain HTTP 400,
// the way a server built against an older SDK/spec version does (e.g. the
// Python `mcp` package used by development/examples/calc-mcp). This lets
// tests exercise HandleStreamPassThrough against a backend that predates
// "server/discover" without needing a real non-Go MCP server.
func newPreDiscoverMCPHandler(t *testing.T, tools []*mcp.Tool) http.Handler {
	t.Helper()
	real := newFakeMCPHandler(t, tools)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			var probe struct {
				Method string `json:"method"`
			}
			if json.Unmarshal(body, &probe) == nil && preflightMethodsUnsupportedByPassThrough[probe.Method] {
				http.Error(w, "Missing session ID", http.StatusBadRequest)
				return
			}
		}
		real.ServeHTTP(w, r)
	})
}
