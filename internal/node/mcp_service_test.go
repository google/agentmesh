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
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
