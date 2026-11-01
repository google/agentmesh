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
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/controlplane"
	"github.com/google/agentmesh/internal/node"
	"github.com/google/agentmesh/internal/router"
	"github.com/google/agentmesh/internal/standalone"
	"github.com/google/agentmesh/internal/storage"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/encoding/protojson"
)

func bearerClient(token string, extra map[string]string) *http.Client {
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	for k, v := range extra {
		headers[k] = v
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: headerRoundTripper{headers: headers},
	}
}

func postOperatorPolicy(t *testing.T, ctx context.Context, baseURL, adminToken string, cfg *api.PolicyConfig) {
	t.Helper()
	payload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal PolicyConfig: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/policies", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new POST /policies request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST /policies: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /policies = %s: %s", resp.Status, body)
	}
}

func exchangeJWTForBiscuit(t *testing.T, cpURL, jwtStr, optionsJSON string, seal bool) string {
	t.Helper()
	form := url.Values{
		"grant_type":         {api.GrantTypeTokenExchange},
		"subject_token":      {jwtStr},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
	}
	if optionsJSON != "" {
		form.Set("options", optionsJSON)
	}
	if seal {
		form.Set("seal", "true")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).PostForm(cpURL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/token = %s: %s", resp.Status, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		t.Fatalf("decode /oauth/token response: %v (%s)", err, body)
	}
	return out.AccessToken
}

func enrollAndStartRuntimeNode(
	t *testing.T,
	ctx context.Context,
	cpURL string,
	bootstrapToken string,
	jwtStr string,
	selector map[string]string,
	reachability node.Reachability,
	listenAddrs []string,
	services []api.ServiceConfig,
) *node.AgentMeshNode {
	t.Helper()
	storeDir := t.TempDir()
	nodeStore, err := node.NewStore(storeDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = nodeStore.Close() })

	priv := node.GetOrGenerateKey(nodeStore)
	enrollNode, err := node.NewAgentMeshNode(node.Options{
		PrivKey:        priv,
		Store:          nodeStore,
		ListenAddrs:    []string{"/ip4/127.0.0.1/tcp/0"},
		AllowLoopback:  true,
		RequiredRole:   api.RoleNode,
		RouterSelector: selector,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode(enroll): %v", err)
	}
	enrollCtx, enrollCancel := context.WithCancel(ctx)
	if err := enrollNode.Start(enrollCtx); err != nil {
		enrollCancel()
		t.Fatalf("enrollNode.Start: %v", err)
	}
	if bootstrapToken != "" {
		err = enrollNode.EnrollBootstrap(enrollCtx, cpURL, bootstrapToken)
	} else {
		err = enrollNode.Enroll(enrollCtx, cpURL, jwtStr)
	}
	if err != nil {
		_ = enrollNode.Teardown()
		enrollCancel()
		t.Fatalf("enrollment failed: %v", err)
	}
	if err := nodeStore.SaveControlPlaneURL(cpURL); err != nil {
		t.Fatalf("SaveControlPlaneURL: %v", err)
	}
	_ = enrollNode.Teardown()
	enrollCancel()

	cpPub, storedAddrs, err := nodeStore.LoadMeshConfig()
	if err != nil {
		t.Fatalf("LoadMeshConfig: %v", err)
	}
	var rAddrs []multiaddr.Multiaddr
	for _, s := range storedAddrs {
		if ma, mErr := multiaddr.NewMultiaddr(s); mErr == nil {
			rAddrs = append(rAddrs, ma)
		}
	}

	runtimeNode, err := node.NewAgentMeshNode(node.Options{
		PrivKey:                  priv,
		ControlPlanePubKey:       cpPub,
		RouterAddrs:              rAddrs,
		Store:                    nodeStore,
		ListenAddrs:              listenAddrs,
		AllowLoopback:            true,
		RequiredRole:             api.RoleNode,
		RouterSelector:           selector,
		Reachability:             reachability,
		DiscoveryInterval:        "100ms",
		AutoRelayBootDelay:       50 * time.Millisecond,
		AutoRelayMinInterval:     50 * time.Millisecond,
		AutoRelayBackoff:         50 * time.Millisecond,
		ControlPlaneSyncInterval: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode(runtime): %v", err)
	}
	if err := runtimeNode.SyncControlPlane(ctx); err != nil {
		t.Fatalf("runtimeNode.SyncControlPlane: %v", err)
	}
	if err := runtimeNode.Start(ctx); err != nil {
		t.Fatalf("runtimeNode.Start: %v", err)
	}
	t.Cleanup(func() {
		_ = runtimeNode.Teardown()
	})
	if len(services) > 0 {
		if err := runtimeNode.RegisterStaticServices(ctx, services); err != nil {
			t.Fatalf("RegisterStaticServices: %v", err)
		}
	}
	return runtimeNode
}

// TestStandaloneExternalIngressCUJ verifies the end-to-end External HTTP
// Ingress journey on agentmesh-one's single port:
//   - RFC 9728 OAuth Protected Resource metadata at /ingress/.well-known/oauth-protected-resource
//   - Internal-only services remain 404 on /ingress/...
//   - Default EDGE mode: unauthenticated A2A AgentCard discovery with public URL & SecuritySchemes rewrite,
//     raw JWT rejection (401 + RFC 9728 WWW-Authenticate), RFC 8693 /oauth/token Delegated Session Biscuit
//   - ServiceIngress.allow ACL enforcement, stock A2A SendMessage & SSE SendStreamingMessage,
//     X-Mesh-Principal delivery to the backend, and TAR MCP tool attenuation
//   - Opt-in PASSTHROUGH mode: upstream Bearer pair token preserved end-to-end while spoofed X-Mesh-*
//     headers are stripped.
func TestStandaloneExternalIngressCUJ(t *testing.T) {
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
				AllowedIngress: []*api.IngressGrant{
					{
						Services: []string{"*"},
						AllowedAuthModes: []api.IngressAuthMode{
							api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
							api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
						},
					},
				},
			},
			{
				Name:            "external-caller",
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"a2a://coder", "mcp://tools"},
			},
		},
		Bindings: []*api.PolicyBinding{
			{
				Role:    "external-caller",
				Members: []string{"email:yaroslav@example.com", "email:other@example.com"},
			},
		},
	})

	// 1. Stock A2A backend for a2a://coder (EDGE mode).
	var lastPrincipal atomic.Value
	firstStreamSeen := make(chan struct{})
	coderExec := a2asrv.AgentExecutorFunc(func(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			if len(ec.Message.Parts) > 0 && ec.Message.Parts[0].Text() == "stream" {
				if !yield(a2a.NewSubmittedTask(ec, ec.Message), nil) {
					return
				}
				select {
				case <-firstStreamSeen:
				case <-ctx.Done():
					return
				}
				yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("streamed from laptop"))), nil)
				return
			}
			yield(a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("hello from laptop")), nil)
		}
	})
	coderCard := &a2a.AgentCard{
		Name:         "coder",
		Description:  "a2a-serve laptop coding agent",
		Version:      "1.0.0",
		Capabilities: a2a.AgentCapabilities{Streaming: true},
		SupportedInterfaces: []*a2a.AgentInterface{
			{URL: "http://127.0.0.1:9999/invoke", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
			{URL: "127.0.0.1:50051", ProtocolBinding: a2a.TransportProtocolGRPC, ProtocolVersion: "1.0"},
		},
		Signatures: []a2a.AgentCardSignature{{Protected: "eyJhbGciOiJFUzI1NiJ9", Signature: "c3RhbGU"}},
	}
	coderMux := http.NewServeMux()
	coderMux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(coderCard))
	coderMux.Handle("/invoke", a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(coderExec)))
	coderBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.Header.Get(api.HeaderMeshPrincipal); p != "" {
			lastPrincipal.Store(p)
		}
		coderMux.ServeHTTP(w, r)
	}))
	t.Cleanup(coderBackend.Close)

	// 2. Stock A2A backend for a2a://paired (PASSTHROUGH mode with app-level pair token).
	var passthroughSpoofStripped atomic.Bool
	pairedExec := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			yield(a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("paired ok")), nil)
		}
	})
	pairedCard := &a2a.AgentCard{
		Name:        "paired",
		Description: "a2a-serve pair-token agent",
		Version:     "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{
			{URL: "http://127.0.0.1:9998/invoke", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
		},
		SecuritySchemes: a2a.NamedSecuritySchemes{
			"pair_bearer": a2a.HTTPAuthSecurityScheme{Scheme: "bearer", Description: "a2a-serve pair token"},
		},
	}
	pairedMux := http.NewServeMux()
	pairedMux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(pairedCard))
	pairedMux.Handle("/invoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(api.HeaderMeshPrincipal) == "" && r.Header.Get(api.HeaderMeshRoles) == "" && r.Header.Get(api.HeaderMeshIngress) == api.IngressAuthModeStringPassthrough {
			passthroughSpoofStripped.Store(true)
		}
		if r.Header.Get("Authorization") != "Bearer a2p_pair_123" {
			http.Error(w, "invalid pair token", http.StatusUnauthorized)
			return
		}
		a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(pairedExec)).ServeHTTP(w, r)
	}))
	pairedBackend := httptest.NewServer(pairedMux)
	t.Cleanup(pairedBackend.Close)

	// 3. Stock MCP Streamable HTTP backend for mcp://tools (EDGE mode + TAR tool check).
	type emptyArgs struct{}
	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "tools", Version: "1.0.0"}, nil)
	mcp.AddTool(mcpSrv, &mcp.Tool{Name: "read_file", Description: "Read file"}, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "file-data"}}}, nil, nil
	})
	mcp.AddTool(mcpSrv, &mcp.Tool{Name: "exec_shell", Description: "Exec shell"}, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "shell-ran"}}}, nil, nil
	})
	mcpBackend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpSrv }, nil))
	t.Cleanup(mcpBackend.Close)

	provider := enrollAndStartRuntimeNode(
		t,
		ctx,
		srv.PublicURL(),
		srv.JoinToken(),
		"",
		nil,
		node.ReachabilityAuto,
		[]string{"/ip4/127.0.0.1/tcp/0"},
		[]api.ServiceConfig{
			{
				Type:      "a2a",
				Name:      "coder",
				TargetURL: coderBackend.URL,
				Ingress:   &api.IngressConfig{AuthMode: "edge", Allow: []string{"email:yaroslav@example.com"}},
			},
			{
				Type:      "a2a",
				Name:      "paired",
				TargetURL: pairedBackend.URL,
				Ingress:   &api.IngressConfig{AuthMode: "passthrough"},
			},
			{
				Type:      "mcp",
				Name:      "tools",
				TargetURL: mcpBackend.URL,
				Ingress:   &api.IngressConfig{AuthMode: "edge"},
			},
			{
				Type:      "a2a",
				Name:      "internal",
				TargetURL: coderBackend.URL,
			},
		},
	)
	peerID := provider.Host.ID().String()
	httpClient := &http.Client{Timeout: 5 * time.Second}

	// RFC 9728 Protected Resource Metadata is served on the public ingress root.
	metaResp, err := httpClient.Get(srv.IngressURL() + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET oauth-protected-resource: %v", err)
	}
	metaBody, _ := io.ReadAll(metaResp.Body)
	_ = metaResp.Body.Close()
	if metaResp.StatusCode != http.StatusOK {
		t.Fatalf("oauth-protected-resource = %s: %s", metaResp.Status, metaBody)
	}
	var prm api.OAuthProtectedResourceMetadata
	if err := json.Unmarshal(metaBody, &prm); err != nil {
		t.Fatalf("unmarshal PRM: %v", err)
	}
	if prm.Resource != srv.IngressURL() {
		t.Errorf("PRM resource = %q, want %q", prm.Resource, srv.IngressURL())
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != srv.PublicURL() {
		t.Errorf("PRM authorization_servers = %v, want [%s]", prm.AuthorizationServers, srv.PublicURL())
	}

	// Internal-only service (ingress == nil) is never exposed on /ingress/...
	coderPublicBase := fmt.Sprintf("%s/%s/a2a/coder", srv.IngressURL(), peerID)
	resolver := agentcard.NewResolver(httpClient)
	var publicCoderCard *a2a.AgentCard
	deadline := time.Now().Add(5 * time.Second)
	for {
		publicCoderCard, err = resolver.Resolve(ctx, coderPublicBase)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resolve public coder AgentCard failed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	internalResp, err := httpClient.Get(fmt.Sprintf("%s/%s/a2a/internal/.well-known/agent-card.json", srv.IngressURL(), peerID))
	if err != nil {
		t.Fatalf("GET internal service over /ingress: %v", err)
	}
	_ = internalResp.Body.Close()
	if internalResp.StatusCode != http.StatusNotFound {
		t.Fatalf("internal service over /ingress = %d, want 404", internalResp.StatusCode)
	}

	// Verify public AgentCard URL, protocol filtering, signature stripping, and SecuritySchemes.
	wantInvokeURL := coderPublicBase + "/invoke"
	if len(publicCoderCard.SupportedInterfaces) != 1 || publicCoderCard.SupportedInterfaces[0].URL != wantInvokeURL {
		t.Fatalf("SupportedInterfaces = %+v, want [%s]", publicCoderCard.SupportedInterfaces, wantInvokeURL)
	}
	if !publicCoderCard.Capabilities.Streaming {
		t.Errorf("Capabilities.Streaming = false, want true")
	}
	if len(publicCoderCard.Signatures) != 0 {
		t.Errorf("Signatures = %+v, want empty", publicCoderCard.Signatures)
	}
	if _, ok := publicCoderCard.SecuritySchemes["agentmesh_oauth2"]; !ok {
		t.Errorf("SecuritySchemes missing agentmesh_oauth2: %+v", publicCoderCard.SecuritySchemes)
	}

	// Unauthenticated invocation receives 401 with RFC 9728 WWW-Authenticate challenge.
	unauthResp, err := httpClient.Post(wantInvokeURL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"message/send"}`))
	if err != nil {
		t.Fatalf("unauthenticated POST: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized || !strings.Contains(unauthResp.Header.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource") {
		t.Fatalf("unauthenticated POST = %d WWW-Authenticate=%q, want 401 with resource_metadata", unauthResp.StatusCode, unauthResp.Header.Get("WWW-Authenticate"))
	}

	// Raw OIDC JWT presented directly to /ingress/ is rejected with 401 + RFC 9728 WWW-Authenticate
	// (external callers exchange JWTs at POST /oauth/token into Delegated Session Biscuits).
	yaroslavJWT := mintJWT(map[string]any{"sub": "yaroslav-sub", "email": "yaroslav@example.com"})
	rawJWTReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, wantInvokeURL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"message/send"}`))
	rawJWTReq.Header.Set("Content-Type", "application/json")
	rawJWTReq.Header.Set("Authorization", "Bearer "+yaroslavJWT)
	rawJWTResp, err := httpClient.Do(rawJWTReq)
	if err != nil {
		t.Fatalf("raw JWT POST: %v", err)
	}
	_ = rawJWTResp.Body.Close()
	if rawJWTResp.StatusCode != http.StatusUnauthorized || !strings.Contains(rawJWTResp.Header.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource") {
		t.Fatalf("raw JWT POST = %d WWW-Authenticate=%q, want 401 with resource_metadata", rawJWTResp.StatusCode, rawJWTResp.Header.Get("WWW-Authenticate"))
	}

	// Delegated Session Biscuit permitted by mesh role ("external-caller") but excluded by ServiceIngress.allow gets 403.
	otherJWT := mintJWT(map[string]any{"sub": "other-sub", "email": "other@example.com"})
	otherBiscuit := exchangeJWTForBiscuit(t, srv.PublicURL(), otherJWT, "", false)
	deniedClient, err := a2aclient.NewFromCard(ctx, publicCoderCard, a2aclient.WithJSONRPCTransport(bearerClient(otherBiscuit, nil)))
	if err != nil {
		t.Fatalf("NewFromCard(other): %v", err)
	}
	if _, err := deniedClient.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi"))}); err == nil {
		t.Fatal("SendMessage with caller excluded by ServiceIngress.allow succeeded, want error")
	}

	// Authorized Delegated Session Biscuit succeeds on both SendMessage and SSE SendStreamingMessage.
	yaroslavBiscuit := exchangeJWTForBiscuit(t, srv.PublicURL(), yaroslavJWT, "", false)
	allowedClient, err := a2aclient.NewFromCard(ctx, publicCoderCard, a2aclient.WithJSONRPCTransport(bearerClient(yaroslavBiscuit, nil)))
	if err != nil {
		t.Fatalf("NewFromCard(yaroslav): %v", err)
	}
	sendRes, err := allowedClient.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi"))})
	if err != nil {
		t.Fatalf("SendMessage(yaroslav): %v", err)
	}
	replyMsg, ok := sendRes.(*a2a.Message)
	if !ok || len(replyMsg.Parts) == 0 || replyMsg.Parts[0].Text() != "hello from laptop" {
		t.Fatalf("SendMessage reply = %#v, want 'hello from laptop'", sendRes)
	}
	evPrincipal, _ := lastPrincipal.Load().(string)
	if !strings.Contains(evPrincipal, "yaroslav") {
		t.Fatalf("backend X-Mesh-Principal = %q, want yaroslav identity", evPrincipal)
	}

	var streamed []a2a.Event
	for ev, sErr := range allowedClient.SendStreamingMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("stream"))}) {
		if sErr != nil {
			t.Fatalf("SendStreamingMessage: %v", sErr)
		}
		streamed = append(streamed, ev)
		if len(streamed) == 1 {
			close(firstStreamSeen)
		}
	}
	if len(streamed) != 2 {
		t.Fatalf("streamed %d events, want 2", len(streamed))
	}

	// Exchange OIDC JWT at POST /oauth/token into a TAR-attenuated, sealed Session Biscuit
	// scoped exclusively to mcp://tools tool "read_file".
	tarJSON := `{"name":"read-only","rules":[{"allowed_services":["mcp://tools"],"operation":{"allowed_tools":["read_file"]}}]}`
	tarBiscuit := exchangeJWTForBiscuit(t, srv.PublicURL(), yaroslavJWT, tarJSON, true)

	mcpURL := fmt.Sprintf("%s/%s/mcp/tools", srv.IngressURL(), peerID)
	mcpCli := mcp.NewClient(&mcp.Implementation{Name: "external-mcp-caller", Version: "1.0.0"}, nil)
	var mcpSess *mcp.ClientSession
	deadline = time.Now().Add(5 * time.Second)
	for {
		mcpSess, err = mcpCli.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   mcpURL,
			HTTPClient: bearerClient(tarBiscuit, nil),
		}, nil)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("MCP Connect over /ingress failed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Cleanup(func() { _ = mcpSess.Close() })

	if _, err := mcpSess.CallTool(ctx, &mcp.CallToolParams{Name: "read_file"}); err != nil {
		t.Fatalf("TAR-permitted MCP tool read_file failed: %v", err)
	}
	if _, err := mcpSess.CallTool(ctx, &mcp.CallToolParams{Name: "exec_shell"}); err == nil {
		t.Fatal("TAR-excluded MCP tool exec_shell succeeded, want 403 rejection")
	}

	// Opt-in PASSTHROUGH mode preserves upstream pair token and strips spoofed X-AgentMesh-* headers.
	pairedPublicBase := fmt.Sprintf("%s/%s/a2a/paired", srv.IngressURL(), peerID)
	pairedPublicCard, err := resolver.Resolve(ctx, pairedPublicBase)
	if err != nil {
		t.Fatalf("resolve paired AgentCard: %v", err)
	}
	if _, hasOAuth := pairedPublicCard.SecuritySchemes["agentmesh_oauth2"]; hasOAuth {
		t.Errorf("PASSTHROUGH card unexpectedly injected agentmesh_oauth2: %+v", pairedPublicCard.SecuritySchemes)
	}
	if _, hasPair := pairedPublicCard.SecuritySchemes["pair_bearer"]; !hasPair {
		t.Errorf("PASSTHROUGH card lost upstream pair_bearer scheme: %+v", pairedPublicCard.SecuritySchemes)
	}

	badPairClient, err := a2aclient.NewFromCard(ctx, pairedPublicCard, a2aclient.WithJSONRPCTransport(bearerClient("wrong-token", map[string]string{
		api.HeaderMeshPrincipal: "spoofed-admin",
		api.HeaderMeshRoles:     "admin",
		api.HeaderMeshIngress:   "edge",
	})))
	if err != nil {
		t.Fatalf("NewFromCard(badPair): %v", err)
	}
	if _, err := badPairClient.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi"))}); err == nil {
		t.Fatal("PASSTHROUGH SendMessage with wrong pair token succeeded, want error")
	}

	goodPairClient, err := a2aclient.NewFromCard(ctx, pairedPublicCard, a2aclient.WithJSONRPCTransport(bearerClient("a2p_pair_123", map[string]string{
		api.HeaderMeshPrincipal: "spoofed-admin",
		api.HeaderMeshRoles:     "admin",
		api.HeaderMeshIngress:   "edge",
	})))
	if err != nil {
		t.Fatalf("NewFromCard(goodPair): %v", err)
	}
	pairRes, err := goodPairClient.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hi"))})
	if err != nil {
		t.Fatalf("PASSTHROUGH SendMessage with valid pair token: %v", err)
	}
	pairReply, ok := pairRes.(*a2a.Message)
	if !ok || len(pairReply.Parts) == 0 || pairReply.Parts[0].Text() != "paired ok" {
		t.Fatalf("PASSTHROUGH reply = %#v, want 'paired ok'", pairRes)
	}
	if !passthroughSpoofStripped.Load() {
		t.Fatal("PASSTHROUGH backend saw spoofed X-AgentMesh-* headers")
	}
}

// TestFederatedMultiRouterIngressRoleCeilingAndBan verifies:
//   - A NAT-ed laptop node with zero open listen ports (ReachabilityPrivate), attached ONLY to
//     Router A (tier=relay), is reachable through Router B's standalone --ingress-addr HTTP gateway
//     over Router A's circuit relay (/p2p/<routerA>/p2p-circuit/p2p/<node>).
//   - PolicyRole.allowed_ingress ceiling: when mesh:role:node grants EDGE only on a2a://coder,
//     attempting to expose a2a://ungranted (PASSTHROUGH) is refused on external ingress (404 on Router B)
//     while automatically falling back to plain internal directory announcement so mesh peers can still
//     discover a2a://ungranted internally.
//   - Banning the provider node via POST /admin/revoke immediately causes Router B to return 404.
func TestFederatedMultiRouterIngressRoleCeilingAndBan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	oidcURL, mintJWT := startCustomMockOIDC(t)
	tmpDir := t.TempDir()

	store, err := storage.NewSQLStore("sqlite", filepath.Join(tmpDir, "cp.db"))
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	const adminToken = "mesh_adm_integration_test"
	cp, err := controlplane.NewServer(controlplane.Options{
		ListenAddr:            "127.0.0.1:0",
		OIDCIssuer:            oidcURL,
		AllowedAudiences:      []string{"agentmesh-audience"},
		BiscuitTimeout:        10 * time.Second,
		AdminToken:            adminToken,
		AutoApproveEnrollment: true,
	}, store)
	if err != nil {
		t.Fatalf("controlplane.NewServer: %v", err)
	}
	if err := cp.Start(); err != nil {
		t.Fatalf("cp.Start: %v", err)
	}
	t.Cleanup(func() { _ = cp.Close() })
	cpURL := "http://" + cp.Addr()

	postOperatorPolicy(t, ctx, cpURL, adminToken, &api.PolicyConfig{
		Roles: []*api.PolicyRole{
			{
				Name:            api.RoleRouter,
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"*"},
				AllowedLabels:   []string{"tier=*"},
			},
			{
				Name:            api.RoleNode,
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"*"},
				AllowedPublish:  []string{"*"},
				// Empty allowed_auth_modes grants EDGE only on a2a://coder.
				AllowedIngress: []*api.IngressGrant{
					{Services: []string{"a2a://coder"}},
				},
			},
			{
				Name:            "external-caller",
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"a2a://coder"},
			},
		},
		Bindings: []*api.PolicyBinding{
			{Role: api.RoleRouter, Members: []string{"group:routers"}},
			{Role: api.RoleNode, Members: []string{"email:node-owner@example.com"}},
			{Role: "external-caller", Members: []string{"email:alan@example.com"}},
		},
	})

	routerJWT := mintJWT(map[string]any{
		"sub":    "router-svc",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	rtrA, err := router.NewRouter(ctx, router.Options{
		ControlPlaneURL:          cpURL,
		ListenAddrs:              []string{"/ip4/127.0.0.1/tcp/0"},
		AllowLoopback:            true,
		KeysDBPath:               filepath.Join(tmpDir, "routerA.key"),
		OIDCToken:                routerJWT,
		Labels:                   map[string]string{"tier": "relay"},
		ControlPlaneSyncInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRouter(A): %v", err)
	}
	if err := rtrA.Start(); err != nil {
		t.Fatalf("rtrA.Start: %v", err)
	}
	t.Cleanup(func() { _ = rtrA.Close() })

	meshAdapter, err := controlplane.NewP2PMeshAdapter(rtrA.Host, rtrA.EventTopic, store)
	if err != nil {
		t.Fatalf("NewP2PMeshAdapter: %v", err)
	}
	t.Cleanup(func() { _ = meshAdapter.Close() })
	cp.SetMeshAdapter(meshAdapter)

	rtrB, err := router.NewRouter(ctx, router.Options{
		ControlPlaneURL:          cpURL,
		PublicControlPlaneURL:    cpURL,
		ListenAddrs:              []string{"/ip4/127.0.0.1/tcp/0"},
		AllowLoopback:            true,
		KeysDBPath:               filepath.Join(tmpDir, "routerB.key"),
		OIDCToken:                routerJWT,
		Labels:                   map[string]string{"tier": "edge"},
		IngressAddr:              "127.0.0.1:0",
		AllowInsecureIngressHTTP: true,
		ControlPlaneSyncInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRouter(B): %v", err)
	}
	if err := rtrB.Start(); err != nil {
		t.Fatalf("rtrB.Start: %v", err)
	}
	t.Cleanup(func() { _ = rtrB.Close() })

	if rtrB.IngressAddr() == nil {
		t.Fatal("rtrB.IngressAddr() is nil")
	}
	ingressBaseB := "http://" + rtrB.IngressAddr().String() + "/ingress"

	// Wait until both routers have leased and authenticated with each other.
	deadline := time.Now().Add(5 * time.Second)
	for len(rtrB.Host.Network().ConnsToPeer(rtrA.Host.ID())) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Router B did not federate with Router A within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}

	execFn := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			yield(a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("relayed via router A")), nil)
		}
	})
	card := &a2a.AgentCard{
		Name:    "coder",
		Version: "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{
			{URL: "http://127.0.0.1:9997/invoke", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
		},
	}
	backendMux := http.NewServeMux()
	backendMux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
	backendMux.Handle("/invoke", a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(execFn)))
	backend := httptest.NewServer(backendMux)
	t.Cleanup(backend.Close)

	// Enroll a private node (zero listen addresses!) attached strictly to Router A (tier=relay).
	nodeJWT := mintJWT(map[string]any{"sub": "node-owner", "email": "node-owner@example.com"})
	provider := enrollAndStartRuntimeNode(
		t,
		ctx,
		cpURL,
		"",
		nodeJWT,
		map[string]string{"tier": "relay"},
		node.ReachabilityPrivate,
		[]string{},
		[]api.ServiceConfig{
			{
				Type:      "a2a",
				Name:      "coder",
				TargetURL: backend.URL,
				Ingress:   &api.IngressConfig{AuthMode: "edge"},
			},
			{
				Type:      "a2a",
				Name:      "ungranted",
				TargetURL: backend.URL,
				Ingress:   &api.IngressConfig{AuthMode: "passthrough"},
			},
		},
	)
	peerID := provider.Host.ID()

	// Wait until the private node announces a /p2p-circuit address via Router A and
	// Router B can resolve the public AgentCard across Router B -> Router A relay -> node.
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resolver := agentcard.NewResolver(httpClient)
	coderURL := fmt.Sprintf("%s/%s/a2a/coder", ingressBaseB, peerID)
	var resolvedCard *a2a.AgentCard
	deadline = time.Now().Add(8 * time.Second)
	for {
		var rErr error
		resolvedCard, rErr = resolver.Resolve(ctx, coderURL)
		if rErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Router B failed to resolve relayed AgentCard on %s: %v", coderURL, rErr)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Ungranted PASSTHROUGH service was rejected on external ingress -> 404 on Router B,
	// while announceServiceKeys fell back to plain Provide so internal mesh discovery still finds it.
	ungrantedResp, err := httpClient.Get(fmt.Sprintf("%s/%s/a2a/ungranted/.well-known/agent-card.json", ingressBaseB, peerID))
	if err != nil {
		t.Fatalf("GET ungranted passthrough service: %v", err)
	}
	_ = ungrantedResp.Body.Close()
	if ungrantedResp.StatusCode != http.StatusNotFound {
		t.Fatalf("ungranted passthrough service status = %d, want 404", ungrantedResp.StatusCode)
	}
	ungrantedKey, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, "ungranted")
	if err != nil {
		t.Fatalf("ServiceKey(a2a, ungranted): %v", err)
	}
	internalProviders, err := provider.Directory.FindProviders(ctx, ungrantedKey, 10)
	if err != nil {
		t.Fatalf("FindProviders(a2a://ungranted): %v", err)
	}
	foundInternal := false
	for _, pi := range internalProviders {
		if pi.ID == peerID {
			foundInternal = true
			break
		}
	}
	if !foundInternal {
		t.Fatalf("a2a://ungranted missing from internal directory after ingress ceiling refusal; got providers %v", internalProviders)
	}

	// External caller exchanges OIDC JWT at POST /oauth/token and invokes a2a://coder through Router B -> Router A circuit relay -> private node.
	alanJWT := mintJWT(map[string]any{"sub": "alan-sub", "email": "alan@example.com"})
	alanBiscuit := exchangeJWTForBiscuit(t, cpURL, alanJWT, "", false)
	a2aCli, err := a2aclient.NewFromCard(ctx, resolvedCard, a2aclient.WithJSONRPCTransport(bearerClient(alanBiscuit, nil)))
	if err != nil {
		t.Fatalf("NewFromCard(alan): %v", err)
	}
	res, err := a2aCli.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("ping"))})
	if err != nil {
		t.Fatalf("relayed SendMessage failed: %v", err)
	}
	msg, ok := res.(*a2a.Message)
	if !ok || len(msg.Parts) == 0 || msg.Parts[0].Text() != "relayed via router A" {
		t.Fatalf("relayed SendMessage reply = %#v, want 'relayed via router A'", res)
	}

	// Admin bans the provider node -> BANNED gossip propagates from CP -> Router A -> Router B -> 404 immediately.
	revokePayload, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(&api.TokenRevokeRequest{PeerId: peerID.String()})
	if err != nil {
		t.Fatalf("marshal TokenRevokeRequest: %v", err)
	}
	revokeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cpURL+"/admin/revoke", bytes.NewReader(revokePayload))
	if err != nil {
		t.Fatalf("new POST /admin/revoke: %v", err)
	}
	revokeReq.Header.Set("Authorization", "Bearer "+adminToken)
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeResp, err := httpClient.Do(revokeReq)
	if err != nil {
		t.Fatalf("POST /admin/revoke: %v", err)
	}
	_ = revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /admin/revoke = %s, want 200", revokeResp.Status)
	}

	deadline = time.Now().Add(5 * time.Second)
	for {
		resp, gErr := httpClient.Get(coderURL + "/.well-known/agent-card.json")
		if gErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("banned provider node did not become 404 on Router B within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
