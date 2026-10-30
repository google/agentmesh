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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/node"
	"github.com/google/agentmesh/internal/standalone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestNativeSDKMCPStdio drives the built entrypoint with a stock MCP
// client, over stdio, against agentmesh-one and a real Go provider. Both
// services exist and the provider may publish both; the caller may use only
// calc. The second process must resume its saved identity without a token.
func TestNativeSDKMCPStdio(t *testing.T) {
	root := repoRoot(t)
	entry := filepath.Join(root, "sdk", "js", "dist", "cli.js")
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	if _, err := os.Stat(entry); err != nil {
		t.Skip("SDK executable not built: cd sdk/js && npm ci && npm run build")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policy := `{"roles":[
		{"name":"mesh:role:router","allowed_services":["*"],"allowed_targets":["*"]},
		{"name":"mesh:role:node","allowed_services":["system://*","mcp://calc"],"allowed_publish":["*"],"allowed_targets":["*"]}
	]}`
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startStandalone(t, ctx, standalone.Options{BindAddress: "127.0.0.1:0", DataDir: t.TempDir(), PolicyFile: policyPath})
	provider := newStandaloneTestNode(t, ctx)
	if err := provider.EnrollBootstrap(ctx, srv.PublicURL(), srv.JoinToken()); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	backend := mcp.NewServer(&mcp.Implementation{Name: "calc", Version: "1"}, nil)
	backend.AddTool(&mcp.Tool{Name: "add", Description: "add numbers", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "3"}}}, nil
	})
	httpBackend := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return backend }, nil))
	t.Cleanup(httpBackend.Close)
	for _, name := range []string{"calc", "denied"} {
		if err := provider.RegisterService(ctx, &api.RegisterServiceRequest{
			Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: name},
			Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: httpBackend.URL},
		}); err != nil {
			t.Fatal(err)
		}
	}
	tokenPath := filepath.Join(t.TempDir(), "join-token")
	if err := os.WriteFile(tokenPath, []byte(srv.JoinToken()), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	// Compare the executable's caller parameter contracts with the Go node,
	// using the node's real MCP registration rather than a copied schema fixture.
	nodeServer := node.NewMCPServer(provider)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	nodeSession, err := nodeServer.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodeSession.Close() })
	nodeClient, err := mcp.NewClient(&mcp.Implementation{Name: "schema-check", Version: "1"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nodeClient.Close() })
	nodeTools, err := nodeClient.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Descriptions and generator-specific JSON Schema keywords may differ;
	// field names, JSON types and required parameters must match.
	contract := func(schema any) any {
		data, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Properties map[string]struct {
				Type any `json:"type"`
			} `json:"properties"`
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Properties) == 0 {
			parsed.Properties = nil
		}
		if len(parsed.Required) == 0 {
			parsed.Required = nil
		}
		sort.Strings(parsed.Required)
		return parsed
	}
	contracts := map[string]any{}
	for _, tool := range nodeTools.Tools {
		contracts[tool.Name] = contract(tool.InputSchema)
	}
	var firstPeer string
	for launch := range 2 {
		cmd := exec.CommandContext(ctx, "node", entry)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "AGENTMESH_") {
				cmd.Env = append(cmd.Env, value)
			}
		}
		cmd.Env = append(cmd.Env, "AGENTMESH_CONTROL_PLANE_URL="+srv.PublicURL(), "AGENTMESH_STATE_DIR="+stateDir)
		if launch == 0 {
			cmd.Env = append(cmd.Env, "AGENTMESH_BOOTSTRAP_TOKEN_PATH="+tokenPath)
		}
		cmd.Stderr = os.Stderr
		client := mcp.NewClient(&mcp.Implementation{Name: "stdio-integration", Version: "1"}, nil)
		session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			t.Fatalf("launch %d: %v", launch, err)
		}
		t.Cleanup(func() { _ = session.Close() })
		invoke := func(name string, args map[string]any, wantError bool) *mcp.CallToolResult {
			t.Helper()
			result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if result.IsError != wantError {
				content, _ := json.Marshal(result.Content)
				t.Fatalf("%s: isError=%v, want %v; content=%s", name, result.IsError, wantError, content)
			}
			return result
		}
		info := invoke("get_mesh_info", map[string]any{}, false)
		var details struct {
			PeerID string `json:"peer_id"`
		}
		if err := json.Unmarshal([]byte(info.Content[0].(*mcp.TextContent).Text), &details); err != nil || details.PeerID == "" {
			t.Fatalf("invalid mesh info: %v", err)
		}
		if launch == 0 {
			firstPeer = details.PeerID
		} else if details.PeerID != firstPeer {
			t.Fatalf("restart changed identity: %s -> %s", firstPeer, details.PeerID)
		}
		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("tools/list: %v", err)
		}
		if got, want := len(tools.Tools), 5; got != want {
			t.Fatalf("tools/list: got %d tools, want %d", got, want)
		}
		for _, tool := range tools.Tools {
			if got, want := contract(tool.InputSchema), contracts[tool.Name]; !reflect.DeepEqual(got, want) {
				t.Fatalf("%s parameter contract differs: got %+v, want %+v", tool.Name, got, want)
			}
		}
		peer := provider.Host.ID().String()
		invoke("describe_remote_tool", map[string]any{"peer_id": peer, "tool_name": "mcp://calc/add"}, false)
		result := invoke("call_remote_tool", map[string]any{"peer_id": peer, "tool_name": "mcp://calc/add", "arguments": map[string]any{"a": 1, "b": 2}}, false)
		if text, ok := result.Content[0].(*mcp.TextContent); !ok || text.Text != "3" {
			t.Fatalf("unexpected tool result: got %v, want text content %q", result.Content, "3")
		}
		before := calls.Load()
		invoke("call_remote_tool", map[string]any{"peer_id": peer, "tool_name": "mcp://denied/add"}, true)
		invoke("call_remote_tool", map[string]any{"peer_id": peer, "tool_name": "mcp://calc/add", "required_labels": "region=unattested"}, true)
		if got, want := calls.Load(), before; got != want {
			t.Fatalf("a refused call reached the backend: got %d backend calls, want %d", got, want)
		}
		found := invoke("find_remote_tools", map[string]any{}, false)
		var rows []struct {
			ToolName string `json:"tool_name"`
		}
		if err := json.Unmarshal([]byte(found.Content[0].(*mcp.TextContent).Text), &rows); err != nil || len(rows) != 1 || rows[0].ToolName != "mcp://calc/add" {
			t.Fatalf("find_remote_tools must expose only calc/add: %v, %v", rows, err)
		}
		discovered := invoke("discover_remote_services", map[string]any{"type": "mcp", "name": "calc"}, false)
		var services []struct {
			PeerID   string `json:"peer_id"`
			Name     string `json:"srv_name"`
			ProxyURL string `json:"local_proxy_url"`
		}
		if err := json.Unmarshal([]byte(discovered.Content[0].(*mcp.TextContent).Text), &services); err != nil || len(services) != 1 || services[0].PeerID != peer || services[0].Name != "mcp://calc" || services[0].ProxyURL != "" {
			t.Fatalf("discovery must return the real provider without an HTTP proxy: %+v, %v", services, err)
		}
		if err := session.Close(); err != nil {
			t.Fatalf("stdin close did not stop the executable: %v", err)
		}
		if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
			t.Fatalf("executable did not exit cleanly: %v", cmd.ProcessState)
		}
	}
}
