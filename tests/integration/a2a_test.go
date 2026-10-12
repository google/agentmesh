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

package integration_test

import (
	"context"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/google/agentmesh/api"
)

// headerRoundTripper stamps fixed headers (mesh auth, labels) on every
// request so the stock A2A SDK client needs no Agent Mesh-specific code.
type headerRoundTripper struct {
	headers map[string]string
}

func (h headerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func meshHTTPClient(token string, extra map[string]string) *http.Client {
	headers := map[string]string{api.HeaderMeshAuthentication: "Bearer " + token}
	for k, v := range extra {
		headers[k] = v
	}
	return &http.Client{Transport: headerRoundTripper{headers: headers}}
}

// TestA2ACUJ covers the "A2A agent behind the mesh" CUJ with the official
// SDK on both ends: node A (attested region=eu) hosts a stock a2asrv agent;
// a stock a2aclient bootstraps from the regenerated card served by node B,
// holds a message exchange, and a region-mismatched request is refused
// fail-closed before any payload leaves node B.
func TestA2ACUJ(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/agentmesh-node")
	_, hubAddr := startMockRouter(t)

	homeA := t.TempDir()
	homeB := t.TempDir()
	apiToken := "test-token"

	// Stock-SDK A2A agent on node A's side: a2asrv serving its card and
	// echoing message/send. The card deliberately advertises a gRPC
	// interface and a stale signature, which the mesh must drop on
	// regeneration, and streaming, which it must keep and carry. The backend
	// exists before the node: services are declared in the node's
	// configuration, never registered at runtime.
	var sendCount atomic.Int32
	var sawLabelsHeader atomic.Bool
	echo := a2asrv.AgentExecutorFunc(func(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			sendCount.Add(1)
			yield(a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("echo from eu")), nil)
		}
	})
	agentCard := &a2a.AgentCard{
		Name:         "echo-agent",
		Description:  "test a2a agent",
		Version:      "1.0.0",
		Capabilities: a2a.AgentCapabilities{Streaming: true},
		SupportedInterfaces: []*a2a.AgentInterface{
			{URL: "http://localhost:9999", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
			{URL: "localhost:50051", ProtocolBinding: a2a.TransportProtocolGRPC, ProtocolVersion: "1.0"},
		},
		Signatures: []a2a.AgentCardSignature{{Protected: "eyJhbGciOiJFUzI1NiJ9", Signature: "c3RhbGU"}},
	}
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(agentCard))
	mux.Handle("/", a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(echo)))
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(api.HeaderMeshRequiredLabels) != "" {
			sawLabelsHeader.Store(true)
		}
		mux.ServeHTTP(w, r)
	}))
	defer agent.Close()

	t.Log("Starting Node A (provider, region=eu)...")
	nodeA := startBackgroundNode(t, nodeBin, hubAddr, homeA,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--config", writeNodeConfig(t, homeA, map[string]string{"region": "eu"}, svcDecl{Type: "a2a", Name: "echo-agent", TargetURL: agent.URL}),
	)
	t.Log("Starting Node B (consumer)...")
	nodeB := startBackgroundNode(t, nodeBin, hubAddr, homeB,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
	)

	apiAddrA := nodeA.waitForAPI(t)
	apiAddrB := nodeB.waitForAPI(t)

	addrA := nodeA.p2pAddr
	connectPeer(t, apiAddrB, addrA)
	waitForDHTPeers(t, apiAddrA)

	idx := strings.LastIndex(addrA, "/p2p/")
	if idx < 0 {
		t.Fatalf("no /p2p/ component in peer addr %q", addrA)
	}
	peerA := addrA[idx+len("/p2p/"):]

	meshBase := "http://" + apiAddrB + "/mesh/" + peerA + "/a2a/echo-agent"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// CUJ step 1: a stock SDK resolver bootstraps from the regenerated card.
	// Poll: the first fetch can race connectivity establishment.
	resolver := agentcard.NewResolver(meshHTTPClient(apiToken, nil))
	var card *a2a.AgentCard
	deadline := time.Now().Add(30 * time.Second)
	for {
		var err error
		card, err = resolver.Resolve(ctx, meshBase)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout resolving agent card through the mesh: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(card.SupportedInterfaces) != 1 || card.SupportedInterfaces[0].URL != meshBase {
		t.Errorf("interfaces not regenerated / gRPC not dropped: %+v", card.SupportedInterfaces)
	}
	if card.SupportedInterfaces[0].ProtocolBinding != a2a.TransportProtocolJSONRPC {
		t.Errorf("binding = %q, want JSONRPC", card.SupportedInterfaces[0].ProtocolBinding)
	}
	if !card.Capabilities.Streaming {
		t.Errorf("streaming = %v, want true as the agent declares it", card.Capabilities.Streaming)
	}
	if len(card.Signatures) != 0 {
		t.Error("stale signatures must be dropped from the regenerated card")
	}

	// CUJ step 2: a stock SDK client built from that card, constrained to
	// region=eu, is admitted and gets the echo back.
	euClient, err := a2aclient.NewFromCard(ctx, card,
		a2aclient.WithJSONRPCTransport(meshHTTPClient(apiToken, map[string]string{api.HeaderMeshRequiredLabels: "region=eu"})))
	if err != nil {
		t.Fatalf("stock client rejected the regenerated card: %v", err)
	}
	req := &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi"))}
	deadline = time.Now().Add(30 * time.Second)
	var result a2a.SendMessageResult
	for {
		result, err = euClient.SendMessage(ctx, req)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("labelled message/send failed: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	reply, ok := result.(*a2a.Message)
	if !ok {
		t.Fatalf("send result = %T, want *a2a.Message", result)
	}
	if len(reply.Parts) == 0 || reply.Parts[0].Text() != "echo from eu" {
		t.Fatalf("unexpected reply: %+v", reply)
	}

	// CUJ step 2b: the card keeps streaming, so the same client may stream
	// the exchange; the SSE response must cross the mesh as it is.
	var streamed []a2a.Event
	for event, err := range euClient.SendStreamingMessage(ctx, req) {
		if err != nil {
			t.Fatalf("streamed message/send failed: %v", err)
		}
		streamed = append(streamed, event)
	}
	if len(streamed) != 1 {
		t.Fatalf("streamed %d events, want the one echo: %+v", len(streamed), streamed)
	}
	if msg, ok := streamed[0].(*a2a.Message); !ok || len(msg.Parts) == 0 || msg.Parts[0].Text() != "echo from eu" {
		t.Fatalf("streamed event = %+v, want a message with text %q", streamed[0], "echo from eu")
	}

	// CUJ step 3: a mismatched label refuses fail-closed BEFORE egress —
	// the agent backend must never see the request.
	before := sendCount.Load()
	usClient, err := a2aclient.NewFromCard(ctx, card,
		a2aclient.WithJSONRPCTransport(meshHTTPClient(apiToken, map[string]string{api.HeaderMeshRequiredLabels: "region=us-east-1"})))
	if err != nil {
		t.Fatalf("client construction failed: %v", err)
	}
	if _, err := usClient.SendMessage(ctx, req); err == nil {
		t.Fatal("mismatched label must fail closed")
	}
	if sendCount.Load() != before {
		t.Fatal("payload reached the agent despite label refusal")
	}

	// Zero-trust invariant: the labels header never crosses the mesh.
	if sawLabelsHeader.Load() {
		t.Errorf("%s header leaked to the agent backend", api.HeaderMeshRequiredLabels)
	}

	t.Log("A2A CUJ test passed.")
}
