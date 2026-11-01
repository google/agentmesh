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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/node"
	"github.com/google/agentmesh/internal/standalone"
	"github.com/google/agentmesh/sdk/meshnet"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

// TestMeshnetStateDirInterop verifies byte-for-byte compatibility between
// agentmesh-node state export/import and sdk/meshnet's StateDir in both directions.
func TestMeshnetStateDirInterop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv, err := standalone.New(standalone.Options{
		BindAddress: "127.0.0.1:0",
		DataDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("standalone.New: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("standalone.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	// 1. Enroll with agentmesh-node -> export StateDir -> resume in meshnet.Server.
	nodeStoreDir := t.TempDir()
	nodeStore, err := node.NewStore(nodeStoreDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	priv := node.GetOrGenerateKey(nodeStore)
	wantPeerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	enrollNode, err := node.NewAgentMeshNode(node.Options{
		PrivKey:       priv,
		Store:         nodeStore,
		ListenAddrs:   []string{"/ip4/127.0.0.1/tcp/0"},
		AllowLoopback: true,
		RequiredRole:  api.RoleNode,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode: %v", err)
	}
	if err := enrollNode.Start(ctx); err != nil {
		t.Fatalf("enrollNode.Start: %v", err)
	}
	if err := enrollNode.EnrollBootstrap(ctx, srv.PublicURL(), srv.JoinToken()); err != nil {
		_ = enrollNode.Teardown()
		t.Fatalf("EnrollBootstrap: %v", err)
	}
	if err := nodeStore.SaveControlPlaneURL(srv.PublicURL()); err != nil {
		t.Fatalf("SaveControlPlaneURL: %v", err)
	}
	_ = enrollNode.Teardown()

	keyBytes, err := nodeStore.LoadKey()
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	exportedCred, err := nodeStore.Credential()
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	_ = nodeStore.Close()

	exportedDir := filepath.Join(t.TempDir(), "from-node")
	if err := node.WriteStateDir(exportedDir, keyBytes, exportedCred); err != nil {
		t.Fatalf("node.WriteStateDir: %v", err)
	}

	gotKey, gotCred, err := meshnet.ReadStateDir(exportedDir)
	if err != nil {
		t.Fatalf("meshnet.ReadStateDir: %v", err)
	}
	if !bytes.Equal(gotKey, keyBytes) || !proto.Equal(gotCred, exportedCred) {
		t.Fatalf("meshnet.ReadStateDir did not round-trip node.WriteStateDir")
	}

	resumed := &meshnet.Server{
		StateDir:      exportedDir,
		ListenAddrs:   []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure: true,
	}
	st, err := resumed.Up(ctx)
	if err != nil {
		t.Fatalf("resumed.Up: %v", err)
	}
	t.Cleanup(func() { _ = resumed.Close() })
	if st.PeerID != wantPeerID.String() {
		t.Fatalf("resumed PeerID = %q, want %q", st.PeerID, wantPeerID.String())
	}

	// 2. Enroll fresh meshnet.Server -> read its StateDir via node.ReadStateDir & import into node.Store.
	fromMeshnetDir := filepath.Join(t.TempDir(), "from-meshnet")
	fresh := &meshnet.Server{
		StateDir:        fromMeshnetDir,
		ControlPlaneURL: srv.PublicURL(),
		BootstrapToken:  srv.JoinToken(),
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
	}
	freshSt, err := fresh.Up(ctx)
	if err != nil {
		t.Fatalf("fresh.Up: %v", err)
	}
	_ = fresh.Close()

	impKey, impCred, err := node.ReadStateDir(fromMeshnetDir)
	if err != nil {
		t.Fatalf("node.ReadStateDir(fromMeshnetDir): %v", err)
	}
	impPriv, err := crypto.UnmarshalPrivateKey(impKey)
	if err != nil {
		t.Fatalf("UnmarshalPrivateKey: %v", err)
	}
	impPID, err := peer.IDFromPrivateKey(impPriv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	if impPID.String() != freshSt.PeerID {
		t.Fatalf("imported PeerID = %q, want %q", impPID.String(), freshSt.PeerID)
	}

	destStore, err := node.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore(dest): %v", err)
	}
	defer func() { _ = destStore.Close() }()
	if err := destStore.SaveKey(impKey); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}
	if err := destStore.SetCredential(impCred); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
}

// TestMeshnetEndToEndIntegration exercises the complete embedded Go SDK surface
// against a real standalone.Server + agentmesh-node:
//   - Private P2P A2A serving & calling (ListenA2A, Discover, HTTPClient, WhoIs, SSE)
//   - External HTTP Ingress in EDGE mode (anonymous card, OIDC /oauth/token, AttenuateToken TAR)
//     and PASSTHROUGH mode (app pair token + X-Mesh-* header sanitization)
//   - Policy-ceiling fallback when allowed_ingress denies public exposure
//   - Local MCPHandler progressive discovery (find_remote_tools -> describe_remote_tool -> call_remote_tool)
//   - Local InferenceHandler zero-secret OpenAI /v1/models + /v1/chat/completions + label floor
func TestMeshnetEndToEndIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	oidcURL, mintJWT := startCustomMockOIDC(t)

	srv, err := standalone.New(standalone.Options{
		BindAddress:      "127.0.0.1:0",
		DataDir:          t.TempDir(),
		OIDCIssuer:       oidcURL,
		AllowedAudiences: []string{"agentmesh-audience"},
	})
	if err != nil {
		t.Fatalf("standalone.New: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("standalone.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	// Policy grants public ingress ONLY for a2a://coder and a2a://paired so that
	// a2a://ceiling-blocked exercises the policy-ceiling fallback path.
	postOperatorPolicy(t, ctx, srv.PublicURL(), srv.AdminToken(), &api.PolicyConfig{
		Roles: []*api.PolicyRole{
			{
				Name:            api.RoleRouter,
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"*"},
			},
			{
				Name:            api.RoleNode,
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"*"},
				AllowedPublish:  []string{"*"},
				AllowedLabels:   []string{"env=*"},
				AllowedIngress: []*api.IngressGrant{
					{
						Services: []string{"a2a://coder"},
						AllowedAuthModes: []api.IngressAuthMode{
							api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
						},
					},
					{
						Services: []string{"a2a://paired"},
						AllowedAuthModes: []api.IngressAuthMode{
							api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
						},
					},
				},
			},
			{
				Name:            "external-caller",
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"a2a://coder"},
			},
		},
		Bindings: []*api.PolicyBinding{
			{
				Role:    "external-caller",
				Members: []string{"email:carol@example.com", "email:bob@example.com"},
			},
		},
	})

	// 1. Start an agentmesh-node hosting mcp://tools and inference://llm.
	type echoArgs struct {
		Message string `json:"message"`
	}
	mcpBackendSrv := mcp.NewServer(&mcp.Implementation{Name: "tools", Version: "1.0.0"}, nil)
	mcp.AddTool(mcpBackendSrv, &mcp.Tool{
		Name:        "echo_arg",
		Description: "Echoes a message back to the caller",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + args.Message}},
		}, nil, nil
	})
	mcpBackend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpBackendSrv }, nil))
	t.Cleanup(mcpBackend.Close)

	infMux := http.NewServeMux()
	infMux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"mesh-qwen","object":"model"}]}`))
	})
	infMux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			_, _ = fmt.Fprintf(w, "data: {\"id\":\"cmpl-1\",\"model\":%q,\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n", body.Model)
			if flusher != nil {
				flusher.Flush()
			}
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"cmpl-1","model":%q,"choices":[{"message":{"role":"assistant","content":"mesh-reply"}}]}`, body.Model)
	})
	infBackend := httptest.NewServer(infMux)
	t.Cleanup(infBackend.Close)

	providerNode := enrollAndStartRuntimeNode(
		t,
		ctx,
		srv.PublicURL(),
		srv.JoinToken(),
		"",
		nil,
		node.ReachabilityAuto,
		[]string{"/ip4/127.0.0.1/tcp/0"},
		[]api.ServiceConfig{
			{Type: "mcp", Name: "tools", Description: "Workspace tools", TargetURL: mcpBackend.URL},
			{Type: "inference", Name: "llm", Description: "Mesh Qwen LLM", TargetURL: infBackend.URL},
		},
	)
	providerPeerID := providerNode.Host.ID().String()

	// 2. Start two embedded meshnet.Server instances (srvA = A2A provider, srvB = consumer).
	srvA := &meshnet.Server{
		StateDir:        t.TempDir(),
		ControlPlaneURL: srv.PublicURL(),
		BootstrapToken:  srv.JoinToken(),
		Labels:          map[string]string{"env": "prod"},
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
	}
	stA, err := srvA.Up(ctx)
	if err != nil {
		t.Fatalf("srvA.Up: %v", err)
	}
	t.Cleanup(func() { _ = srvA.Close() })

	srvB := &meshnet.Server{
		StateDir:        t.TempDir(),
		ControlPlaneURL: srv.PublicURL(),
		BootstrapToken:  srv.JoinToken(),
		Labels:          map[string]string{"env": "dev"},
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
	}
	stB, err := srvB.Up(ctx)
	if err != nil {
		t.Fatalf("srvB.Up: %v", err)
	}
	t.Cleanup(func() { _ = srvB.Close() })

	// 3. Register A2A services on srvA:
	//    - coder (Public EDGE, allow carol + srvB node)
	//    - paired (Public PASSTHROUGH)
	//    - ceiling-blocked (Public EDGE requested, denied by allowed_ingress -> falls back to private-only)
	coderEP, err := srvA.ListenA2A(ctx, meshnet.A2AOptions{
		Name:         "coder",
		Description:  "Embedded Go SDK coding agent",
		Public:       true,
		IngressAuth:  api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
		IngressAllow: []string{"email:carol@example.com", "node:" + stB.PeerID},
	})
	if err != nil {
		t.Fatalf("ListenA2A(coder): %v", err)
	}
	t.Cleanup(func() { _ = coderEP.Close() })
	if coderEP.PublicURL == nil {
		t.Fatalf("coderEP.PublicURL is nil, want %s/%s/a2a/coder", srv.IngressURL(), stA.PeerID)
	}

	var coderWhoIsMu sync.Mutex
	var lastCoderWhoIs meshnet.CallerInfo

	coderExec := a2asrv.AgentExecutorFunc(func(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			if len(ec.Message.Parts) > 0 && ec.Message.Parts[0].Text() == "stream" {
				if !yield(a2a.NewSubmittedTask(ec, ec.Message), nil) {
					return
				}
				yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("stream-ok"))), nil)
				return
			}
			yield(a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("meshnet-hello")), nil)
		}
	})
	coderCard := &a2a.AgentCard{
		Name:         "coder",
		Description:  "Embedded Go SDK coding agent",
		Version:      "1.0.0",
		Capabilities: a2a.AgentCapabilities{Streaming: true},
		SupportedInterfaces: []*a2a.AgentInterface{
			{URL: coderEP.PrivateURL.String() + "/invoke", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
		},
	}
	coderMux := http.NewServeMux()
	coderMux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(coderCard))
	coderMux.Handle("/invoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if info, ok := srvA.WhoIs(r.RemoteAddr); ok && info != nil {
			coderWhoIsMu.Lock()
			lastCoderWhoIs = *info
			coderWhoIsMu.Unlock()
		}
		a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(coderExec)).ServeHTTP(w, r)
	}))
	coderPrivHTTP := &http.Server{Handler: coderMux}
	coderPubHTTP := &http.Server{Handler: coderMux}
	go func() { _ = coderPrivHTTP.Serve(coderEP.PrivateListener) }()
	go func() { _ = coderPubHTTP.Serve(coderEP.PublicListener) }()
	t.Cleanup(func() {
		_ = coderPrivHTTP.Close()
		_ = coderPubHTTP.Close()
	})

	// PASSTHROUGH service on srvA.
	pairedEP, err := srvA.ListenA2A(ctx, meshnet.A2AOptions{
		Name:        "paired",
		Description: "Pair-token A2A service",
		Public:      true,
		IngressAuth: api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
	})
	if err != nil {
		t.Fatalf("ListenA2A(paired): %v", err)
	}
	t.Cleanup(func() { _ = pairedEP.Close() })
	if pairedEP.PublicURL == nil {
		t.Fatal("pairedEP.PublicURL is nil, want public URL")
	}

	var passthroughClean atomic.Bool
	pairedExec := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			yield(a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("paired-ok")), nil)
		}
	})
	pairedCard := &a2a.AgentCard{
		Name:        "paired",
		Description: "Pair-token A2A service",
		Version:     "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{
			{URL: pairedEP.PublicURL.String() + "/invoke", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
		},
	}
	pairedMux := http.NewServeMux()
	pairedMux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(pairedCard))
	pairedMux.Handle("/invoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasWhoIs := srvA.WhoIs(r.RemoteAddr)
		if !hasWhoIs && r.Header.Get(api.HeaderMeshPrincipal) == "" && r.Header.Get(api.HeaderMeshIngress) == api.IngressAuthModeStringPassthrough {
			passthroughClean.Store(true)
		}
		if r.Header.Get("Authorization") != "Bearer pair-secret-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(pairedExec)).ServeHTTP(w, r)
	}))
	pairedPubHTTP := &http.Server{Handler: pairedMux}
	go func() { _ = pairedPubHTTP.Serve(pairedEP.PublicListener) }()
	t.Cleanup(func() { _ = pairedPubHTTP.Close() })

	// Policy-ceiling fallback service on srvA: Public=true requested, hub denies ingress,
	// so PublicURL is nil while PrivateListener continues serving internal mesh peers.
	blockedEP, err := srvA.ListenA2A(ctx, meshnet.A2AOptions{
		Name:        "ceiling-blocked",
		Description: "Policy ceiling fallback service",
		Public:      true,
		IngressAuth: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
	})
	if err != nil {
		t.Fatalf("ListenA2A(ceiling-blocked): %v", err)
	}
	t.Cleanup(func() { _ = blockedEP.Close() })
	if blockedEP.PublicURL != nil {
		t.Fatalf("blockedEP.PublicURL = %v, want nil when policy ceiling denies ingress", blockedEP.PublicURL)
	}
	blockedPrivHTTP := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("private-still-works"))
	})}
	go func() { _ = blockedPrivHTTP.Serve(blockedEP.PrivateListener) }()
	t.Cleanup(func() { _ = blockedPrivHTTP.Close() })

	// 4. Verify Private P2P A2A from srvB -> srvA (Discover + AgentCard + SendMessage + SSE + WhoIs).
	var foundCoder string
	deadline := time.Now().Add(5 * time.Second)
	for {
		providers, dErr := srvB.Discover(ctx, api.ServiceType_SERVICE_TYPE_A2A, "coder")
		if dErr == nil && len(providers) > 0 {
			foundCoder = providers[0].GetLocalProxyUrl()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("srvB.Discover(coder) timed out; last err=%v", dErr)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if foundCoder != coderEP.PrivateURL.String() {
		t.Fatalf("discovered URL = %q, want %q", foundCoder, coderEP.PrivateURL.String())
	}

	privCard, err := agentcard.NewResolver(srvB.HTTPClient()).Resolve(ctx, foundCoder)
	if err != nil {
		t.Fatalf("Resolve private coder card: %v", err)
	}
	privA2AClient, err := a2aclient.NewFromCard(ctx, privCard, a2aclient.WithJSONRPCTransport(srvB.HTTPClient()))
	if err != nil {
		t.Fatalf("a2aclient.NewFromCard(private): %v", err)
	}
	privRes, err := privA2AClient.SendMessage(ctx, &a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello")),
	})
	if err != nil {
		t.Fatalf("private SendMessage: %v", err)
	}
	if msg, ok := privRes.(*a2a.Message); !ok || len(msg.Parts) == 0 || msg.Parts[0].Text() != "meshnet-hello" {
		t.Fatalf("private SendMessage reply = %#v, want meshnet-hello", privRes)
	}
	coderWhoIsMu.Lock()
	gotPrivWhoIs := lastCoderWhoIs
	coderWhoIsMu.Unlock()
	if gotPrivWhoIs.PeerID != stB.PeerID || gotPrivWhoIs.Labels["env"] != "dev" {
		t.Fatalf("private WhoIs = %+v, want PeerID=%s env=dev", gotPrivWhoIs, stB.PeerID)
	}

	// Verify private fallback on ceiling-blocked service works while /ingress returns 404.
	privBlockedResp, err := srvB.HTTPClient().Get(blockedEP.PrivateURL.String() + "/ping")
	if err != nil {
		t.Fatalf("private GET ceiling-blocked: %v", err)
	}
	privBlockedBody, err := io.ReadAll(privBlockedResp.Body)
	_ = privBlockedResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(ceiling-blocked): %v", err)
	}
	if privBlockedResp.StatusCode != http.StatusOK || string(privBlockedBody) != "private-still-works" {
		t.Fatalf("private ceiling-blocked = %d %q, want 200 private-still-works", privBlockedResp.StatusCode, privBlockedBody)
	}

	extHTTP := &http.Client{Timeout: 5 * time.Second}
	pubBlockedResp, err := extHTTP.Get(fmt.Sprintf("%s/%s/a2a/ceiling-blocked/.well-known/agent-card.json", srv.IngressURL(), stA.PeerID))
	if err != nil {
		t.Fatalf("GET public ceiling-blocked: %v", err)
	}
	_ = pubBlockedResp.Body.Close()
	if pubBlockedResp.StatusCode != http.StatusNotFound {
		t.Fatalf("public ceiling-blocked = %d, want 404", pubBlockedResp.StatusCode)
	}

	// 5. Verify Public External Ingress (EDGE + OIDC /oauth/token + AttenuateToken TAR + PASSTHROUGH).
	pubCard, err := agentcard.NewResolver(extHTTP).Resolve(ctx, coderEP.PublicURL.String())
	if err != nil {
		t.Fatalf("Resolve public coder card: %v", err)
	}
	if len(pubCard.SupportedInterfaces) != 1 || pubCard.SupportedInterfaces[0].URL != coderEP.PublicURL.String()+"/invoke" {
		t.Fatalf("public SupportedInterfaces = %+v, want %s/invoke", pubCard.SupportedInterfaces, coderEP.PublicURL.String())
	}

	// 5a. External OIDC user allowed by IngressAllow (SendMessage + SSE SendStreamingMessage).
	carolJWT := mintJWT(map[string]any{"sub": "carol-sub", "email": "carol@example.com"})
	carolBiscuit := exchangeJWTForBiscuit(t, srv.PublicURL(), carolJWT, "", false)
	pubAllowed, err := a2aclient.NewFromCard(ctx, pubCard, a2aclient.WithJSONRPCTransport(bearerClient(carolBiscuit, nil)))
	if err != nil {
		t.Fatalf("NewFromCard(public carol): %v", err)
	}
	var gotSSE bool
	for ev, sErr := range pubAllowed.SendStreamingMessage(ctx, &a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("stream")),
	}) {
		if sErr != nil {
			t.Fatalf("SendStreamingMessage: %v", sErr)
		}
		if upd, ok := ev.(*a2a.TaskStatusUpdateEvent); ok && upd.Status.State == a2a.TaskStateCompleted {
			gotSSE = true
		}
	}
	if !gotSSE {
		t.Fatal("did not receive completed TaskStatusUpdateEvent over public SSE")
	}
	coderWhoIsMu.Lock()
	gotPubWhoIs := lastCoderWhoIs
	coderWhoIsMu.Unlock()
	if gotPubWhoIs.Principal != "carol@example.com" {
		t.Fatalf("public WhoIs Principal = %q, want carol@example.com", gotPubWhoIs.Principal)
	}
	if gotPubWhoIs.PeerID != "" {
		t.Fatalf("public OIDC user WhoIs PeerID = %q, want empty string", gotPubWhoIs.PeerID)
	}

	// 5b. External OIDC user excluded by IngressAllow gets denied.
	bobJWT := mintJWT(map[string]any{"sub": "bob-sub", "email": "bob@example.com"})
	bobBiscuit := exchangeJWTForBiscuit(t, srv.PublicURL(), bobJWT, "", false)
	pubDenied, err := a2aclient.NewFromCard(ctx, pubCard, a2aclient.WithJSONRPCTransport(bearerClient(bobBiscuit, nil)))
	if err != nil {
		t.Fatalf("NewFromCard(public bob): %v", err)
	}
	if _, err := pubDenied.SendMessage(ctx, &a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi")),
	}); err == nil {
		t.Fatal("excluded external user succeeded on coder, want error")
	}

	// 5c. Task-scoped Biscuit minted offline via srvB.AttenuateToken(..., seal=true) surfaces Task in WhoIs.
	tarToken, _, err := srvB.AttenuateToken(&api.TaskAuthorizationRule{
		Name: "audit-pr-99",
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"a2a://coder"},
				Operation:       &api.TaskOperation{AllowedMethods: []string{"POST"}},
			},
		},
	}, 2*time.Minute, true)
	if err != nil {
		t.Fatalf("srvB.AttenuateToken: %v", err)
	}
	pubTARClient, err := a2aclient.NewFromCard(ctx, pubCard, a2aclient.WithJSONRPCTransport(bearerClient(tarToken, nil)))
	if err != nil {
		t.Fatalf("NewFromCard(TAR): %v", err)
	}
	if _, err := pubTARClient.SendMessage(ctx, &a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi")),
	}); err != nil {
		t.Fatalf("SendMessage(TAR): %v", err)
	}
	coderWhoIsMu.Lock()
	gotTARWhoIs := lastCoderWhoIs
	coderWhoIsMu.Unlock()
	if gotTARWhoIs.Task != "audit-pr-99" {
		t.Fatalf("TAR WhoIs Task = %q, want audit-pr-99", gotTARWhoIs.Task)
	}
	if gotTARWhoIs.PeerID != stB.PeerID {
		t.Fatalf("TAR WhoIs PeerID = %q, want %q", gotTARWhoIs.PeerID, stB.PeerID)
	}

	// 5d. PASSTHROUGH service preserves upstream Bearer pair token and strips spoofed X-Mesh-*.
	pubPairedCard, err := agentcard.NewResolver(extHTTP).Resolve(ctx, pairedEP.PublicURL.String())
	if err != nil {
		t.Fatalf("Resolve public paired card: %v", err)
	}
	pairedClient, err := a2aclient.NewFromCard(ctx, pubPairedCard, a2aclient.WithJSONRPCTransport(
		bearerClient("pair-secret-123", map[string]string{api.HeaderMeshPrincipal: "spoofed-admin"}),
	))
	if err != nil {
		t.Fatalf("NewFromCard(paired): %v", err)
	}
	if _, err := pairedClient.SendMessage(ctx, &a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi")),
	}); err != nil {
		t.Fatalf("SendMessage(paired): %v", err)
	}
	if !passthroughClean.Load() {
		t.Fatal("PASSTHROUGH backend saw spoofed X-Mesh-Principal or missed X-Mesh-Ingress=passthrough")
	}

	// 6. Verify srvB.MCPHandler() 3-step progressive remote tool discovery & invocation against agentmesh-node.
	localMCP := httptest.NewServer(srvB.MCPHandler())
	t.Cleanup(localMCP.Close)

	mcpCli := mcp.NewClient(&mcp.Implementation{Name: "agent-caller", Version: "1.0.0"}, nil)
	mcpSess, err := mcpCli.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: localMCP.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatalf("Connect local MCPHandler: %v", err)
	}
	t.Cleanup(func() { _ = mcpSess.Close() })

	var foundToolsText string
	deadline = time.Now().Add(5 * time.Second)
	for {
		findRes, fErr := mcpSess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "find_remote_tools",
			Arguments: map[string]any{"tool_name": "echo_arg"},
		})
		if fErr == nil && len(findRes.Content) > 0 {
			txt := findRes.Content[0].(*mcp.TextContent).Text
			foundToolsText = txt
			if !findRes.IsError && strings.Contains(txt, "mcp://tools/echo_arg") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("find_remote_tools did not discover mcp://tools/echo_arg in time; last=%q err=%v", foundToolsText, fErr)
		}
		time.Sleep(50 * time.Millisecond)
	}

	descRes, err := mcpSess.CallTool(ctx, &mcp.CallToolParams{
		Name: "describe_remote_tool",
		Arguments: map[string]any{
			"peer_id":   providerPeerID,
			"tool_name": "mcp://tools/echo_arg",
		},
	})
	if err != nil || descRes.IsError {
		t.Fatalf("describe_remote_tool: err=%v res=%+v", err, descRes)
	}
	if !strings.Contains(descRes.Content[0].(*mcp.TextContent).Text, "message") {
		t.Fatalf("describe_remote_tool schema missing 'message': %s", descRes.Content[0].(*mcp.TextContent).Text)
	}

	callRes, err := mcpSess.CallTool(ctx, &mcp.CallToolParams{
		Name: "call_remote_tool",
		Arguments: map[string]any{
			"peer_id":   providerPeerID,
			"tool_name": "mcp://tools/echo_arg",
			"arguments": map[string]any{"message": "from-meshnet"},
		},
	})
	if err != nil || callRes.IsError {
		t.Fatalf("call_remote_tool: err=%v res=%+v", err, callRes)
	}
	if got := callRes.Content[0].(*mcp.TextContent).Text; !strings.Contains(got, "echo:from-meshnet") {
		t.Fatalf("call_remote_tool output = %q, want echo:from-meshnet", got)
	}

	// 7. Verify srvB.InferenceHandler() zero-secret OpenAI /v1/models + /v1/chat/completions + label check.
	localInf := httptest.NewServer(srvB.InferenceHandler())
	t.Cleanup(localInf.Close)

	modelsResp, err := extHTTP.Get(localInf.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	modelsBody, err := io.ReadAll(modelsResp.Body)
	_ = modelsResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(/v1/models): %v", err)
	}
	if modelsResp.StatusCode != http.StatusOK || !strings.Contains(string(modelsBody), "mesh-qwen") {
		t.Fatalf("GET /v1/models = %d %s, want mesh-qwen", modelsResp.StatusCode, modelsBody)
	}

	chatResp, err := extHTTP.Post(localInf.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"mesh-qwen","messages":[{"role":"user","content":"ping"}]}`))
	if err != nil {
		t.Fatalf("POST /v1/chat/completions: %v", err)
	}
	chatBody, err := io.ReadAll(chatResp.Body)
	_ = chatResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(/v1/chat/completions): %v", err)
	}
	if chatResp.StatusCode != http.StatusOK || !strings.Contains(string(chatBody), "mesh-reply") {
		t.Fatalf("POST /v1/chat/completions = %d %s, want mesh-reply", chatResp.StatusCode, chatBody)
	}

	streamChatResp, err := extHTTP.Post(localInf.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"mesh-qwen","stream":true,"messages":[{"role":"user","content":"ping"}]}`))
	if err != nil {
		t.Fatalf("POST streaming /v1/chat/completions: %v", err)
	}
	streamChatBody, err := io.ReadAll(streamChatResp.Body)
	_ = streamChatResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(streaming /v1/chat/completions): %v", err)
	}
	if streamChatResp.StatusCode != http.StatusOK || !strings.Contains(string(streamChatBody), "[DONE]") {
		t.Fatalf("POST streaming /v1/chat/completions = %d %s, want SSE [DONE]", streamChatResp.StatusCode, streamChatBody)
	}

	badInfReq, err := http.NewRequestWithContext(ctx, http.MethodPost, localInf.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"mesh-qwen","messages":[{"role":"user","content":"ping"}]}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext(badInf): %v", err)
	}
	badInfReq.Header.Set("Content-Type", "application/json")
	badInfReq.Header.Set(api.HeaderMeshRequiredLabels, "tier=missing")
	badInfResp, err := extHTTP.Do(badInfReq)
	if err != nil {
		t.Fatalf("POST /v1/chat/completions with unmet label: %v", err)
	}
	badInfBody, err := io.ReadAll(badInfResp.Body)
	_ = badInfResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(badInfResp): %v", err)
	}
	if badInfResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unmet required label on inference = %d %s, want 503", badInfResp.StatusCode, badInfBody)
	}
}
