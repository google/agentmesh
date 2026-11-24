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
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The params of a tools/call go to the backend as the same bytes. When they
// state the tool name twice, the task check must refuse the call: the name it
// would check is not the name every backend reads.
func TestMCPService_TaskCheckRefusesAToolNamedTwice(t *testing.T) {
	svc := &MCPService{baseService: baseService{
		info: &api.ServiceInfo{Name: "weather", Type: api.ServiceType_SERVICE_TYPE_MCP},
	}}
	reqCtx := RequestContext{TaskRules: []*api.TaskAuthorizationRule{{
		Name: "only-get-weather",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"mcp://weather"},
			Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather"}},
		}},
	}}}
	id, err := jsonrpc.MakeID(float64(1))
	if err != nil {
		t.Fatalf("MakeID: %v", err)
	}

	for _, tc := range []struct {
		name       string
		params     string
		wantDenied bool
	}{
		{name: "allowed tool", params: `{"name":"get_weather"}`},
		{name: "allowed name after another name in upper case", params: `{"name":"drop_table","NAME":"get_weather"}`, wantDenied: true},
		{name: "allowed name after another name", params: `{"name":"drop_table","name":"get_weather"}`, wantDenied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := svc.authorizeMCPRequest(&jsonrpc.Request{ID: id, Method: "tools/call", Params: []byte(tc.params)}, reqCtx)
			if !tc.wantDenied {
				if resp != nil {
					t.Fatalf("tools/call with params %s was refused: %v, want it allowed", tc.params, resp.Error)
				}
				return
			}
			if resp == nil {
				t.Fatalf("tools/call with params %s was allowed, want it refused", tc.params)
			}
			var rpcErr *jsonrpc.Error
			if !errors.As(resp.Error, &rpcErr) || rpcErr.Code != jsonrpc.CodeInvalidParams {
				t.Fatalf("tools/call with params %s got error %v, want code %d (invalid params)", tc.params, resp.Error, jsonrpc.CodeInvalidParams)
			}
		})
	}
}

// A message with no id gets no answer, and a server must not run a request
// that comes as one. A backend on a generic JSON-RPC library can run it.
// Under a task-scoped credential, a message with no id goes to the backend
// only when its method is a notification.
func TestMCPService_TaskCheckAllowsOnlyANotificationWithNoID(t *testing.T) {
	svc := &MCPService{baseService: baseService{
		info: &api.ServiceInfo{Name: "weather", Type: api.ServiceType_SERVICE_TYPE_MCP},
	}}
	reqCtx := RequestContext{TaskRules: []*api.TaskAuthorizationRule{{
		Name: "only-get-weather",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"mcp://weather"},
			Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather"}},
		}},
	}}}

	for _, tc := range []struct {
		name        string
		method      string
		params      string
		wantAllowed bool
	}{
		{name: "initialized notification", method: "notifications/initialized", wantAllowed: true},
		{name: "cancelled notification", method: "notifications/cancelled", params: `{"requestId":1}`, wantAllowed: true},
		{name: "call of a forbidden tool", method: "tools/call", params: `{"name":"drop_table"}`},
		{name: "call of an allowed tool", method: "tools/call", params: `{"name":"get_weather"}`},
		{name: "method that the task denies with an id", method: "resources/read", params: `{"uri":"file:///etc/passwd"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := svc.authorizeMCPRequest(&jsonrpc.Request{Method: tc.method, Params: []byte(tc.params)}, reqCtx)
			if allowed := resp == nil; allowed != tc.wantAllowed {
				t.Fatalf("%s with no id: allowed = %v, want %v", tc.method, allowed, tc.wantAllowed)
			}
		})
	}
}

// A task rule with allowed_tools decides a request in the same way on a
// /mesh/mcp stream and on HTTP: the two enforcement points take the session
// methods from api.MCPSessionMethod. allowed_tools grants tools, so a list of
// the resources or of the prompts is denied on both.
func TestMCPService_TaskCheckDecidesARequestAsTheHTTPInspection(t *testing.T) {
	svc := &MCPService{baseService: baseService{
		info: &api.ServiceInfo{Name: "weather", Type: api.ServiceType_SERVICE_TYPE_MCP},
	}}
	rules := []*api.TaskAuthorizationRule{{
		Name: "only-get-weather",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"mcp://weather"},
			Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather"}},
		}},
	}}
	id, err := jsonrpc.MakeID(float64(1))
	if err != nil {
		t.Fatalf("MakeID: %v", err)
	}

	for _, tc := range []struct {
		name        string
		method      string
		params      string
		wantAllowed bool
	}{
		{name: "initialize", method: "initialize", wantAllowed: true},
		{name: "server/discover", method: "server/discover", wantAllowed: true},
		{name: "ping", method: "ping", wantAllowed: true},
		{name: "tools/list", method: "tools/list", wantAllowed: true},
		{name: "call of an allowed tool", method: "tools/call", params: `{"name":"get_weather"}`, wantAllowed: true},
		{name: "call of a forbidden tool", method: "tools/call", params: `{"name":"drop_table"}`},
		{name: "resources/list", method: "resources/list"},
		{name: "prompts/list", method: "prompts/list"},
		{name: "resources/read", method: "resources/read", params: `{"uri":"file:///etc/passwd"}`},
		{name: "prompt with the name of an allowed tool", method: "prompts/get", params: `{"name":"get_weather"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			onStream := svc.authorizeMCPRequest(&jsonrpc.Request{ID: id, Method: tc.method, Params: []byte(tc.params)}, RequestContext{TaskRules: rules}) == nil

			body := `{"jsonrpc":"2.0","id":1,"method":"` + tc.method + `"`
			if tc.params != "" {
				body += `,"params":` + tc.params
			}
			body += "}"
			tool, allowInit := api.InspectJSONRPCMCPBody([]byte(body))
			onHTTP := api.EvaluateTaskRules(rules, api.TaskRequestContext{
				ServiceType:        "mcp",
				ServiceName:        "weather",
				MCPTool:            tool,
				AllowMCPStreamInit: allowInit,
			}, time.Now()) == nil

			if onStream != tc.wantAllowed || onHTTP != tc.wantAllowed {
				t.Fatalf("%s: allowed on a stream = %v, allowed on HTTP = %v, want %v on both", tc.method, onStream, onHTTP, tc.wantAllowed)
			}
		})
	}
}

// newProbeBackend serves a real MCP server that exposes no tools at all.
func newProbeBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "probe-backend", Version: "0.0.1"}, nil)
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	t.Cleanup(ts.Close)
	return ts
}

func newProbeService(url string) *MCPService {
	return &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Name: "probe-me", Type: api.ServiceType_SERVICE_TYPE_MCP},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: url},
	}}
}

// Serving no tools is not a fault: a backend may serve only resources or
// prompts and is still an MCP server, so it must stay advertisable.
func TestMCPService_ProbeAcceptsToollessBackend(t *testing.T) {
	svc := newProbeService(newProbeBackend(t).URL)
	if err := svc.Probe(context.Background()); err != nil {
		t.Errorf("Probe on a tool-less MCP backend: %v", err)
	}
}

// The canary case: answers HTTP, is not an MCP server.
func TestMCPService_ProbeRejectsNonMCPBackend(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(ts.Close)

	svc := newProbeService(ts.URL)
	if err := svc.Probe(context.Background()); err == nil {
		t.Fatal("Probe accepted a backend that is not an MCP server")
	}
}

// Backends routinely start after the node does, so a failed probe must not be
// sticky: the next one has to see the backend as it is now, not as it was.
func TestMCPService_ProbeRecoversWhenBackendComesUp(t *testing.T) {
	var up atomic.Bool
	real := mcp.NewServer(&mcp.Implementation{Name: "late", Version: "0.0.1"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return real }, nil)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "still starting", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	svc := newProbeService(ts.URL)
	if err := svc.Probe(context.Background()); err == nil {
		t.Fatal("Probe accepted a backend that was not serving yet")
	}

	up.Store(true)
	if err := svc.Probe(context.Background()); err != nil {
		t.Errorf("Probe still failing after the backend came up: %v", err)
	}
}

// A cancelled context is a fact about the caller, not the backend.
func TestMCPService_ProbeFailsOnCancelledContext(t *testing.T) {
	svc := newProbeService(newProbeBackend(t).URL)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := svc.Probe(cancelled); err == nil {
		t.Fatal("Probe returned nil for a cancelled context")
	}

	if err := svc.Probe(context.Background()); err != nil {
		t.Errorf("Probe after a cancelled one: %v", err)
	}
}

func TestMCPServiceToolsListsEveryPage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pageSize int
		want     []string
	}{
		{name: "single page", pageSize: 3, want: []string{"alpha", "middle", "zulu"}},
		{name: "one tool per page", pageSize: 1, want: []string{"alpha", "middle", "zulu"}},
		{name: "short final page", pageSize: 2, want: []string{"alpha", "middle", "zulu"}},
		{name: "no tools", pageSize: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := mcp.NewServer(&mcp.Implementation{Name: "backend", Version: "0.0.1"}, &mcp.ServerOptions{PageSize: tc.pageSize})
			for i := len(tc.want) - 1; i >= 0; i-- {
				mcp.AddTool(backend, &mcp.Tool{Name: tc.want[i]}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
					return &mcp.CallToolResult{}, nil, nil
				})
			}
			server := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return backend }, nil))
			t.Cleanup(server.Close)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			service := newProbeService(server.URL)
			got, err := service.Tools(ctx)
			if err != nil {
				t.Fatalf("Tools: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("Tools = %v, want %v", got, tc.want)
			}
			cached, err := service.Tools(ctx)
			if err != nil || !slices.Equal(cached, tc.want) {
				t.Fatalf("cached Tools = %v, %v, want %v, nil", cached, err, tc.want)
			}
		})
	}
}
