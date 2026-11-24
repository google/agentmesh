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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestFindRemoteToolsOnlyQueriesSelectedService(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	caller, closeCaller := startBareNode(t, ctx)
	t.Cleanup(closeCaller)
	provider, closeProvider := startBareNode(t, ctx)
	t.Cleanup(closeProvider)
	if err := caller.Host.Connect(ctx, peer.AddrInfo{ID: provider.Host.ID(), Addrs: provider.Host.Addrs()}); err != nil {
		t.Fatalf("connect to provider: %v", err)
	}
	enrollUnderRoot(t, caller, provider)

	backend := newFakeMCPHandler(t, []*mcp.Tool{{Name: "read", InputSchema: map[string]any{"type": "object"}}})
	var otherRequests atomic.Int64
	selected := httptest.NewServer(backend)
	t.Cleanup(selected.Close)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req struct{ Method string }
			if json.Unmarshal(body, &req) == nil && req.Method == "tools/list" {
				otherRequests.Add(1)
			}
		}
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(other.Close)
	for _, svc := range []struct{ name, url string }{
		{"inventory", selected.URL},
		{"inventory-archive", other.URL},
	} {
		if err := provider.RegisterService(ctx, &api.RegisterServiceRequest{
			Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: svc.name},
			Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: svc.url},
		}); err != nil {
			t.Fatalf("register %q: %v", svc.name, err)
		}
	}

	for _, tc := range []struct {
		name, filter string
		wantCount    int
		wantOther    bool
	}{
		{"unfiltered", "", 2, true},
		{"bare", "mcp://inventory", 1, false},
		{"missing", "mcp://missing", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := otherRequests.Load()
			rows, err := caller.fetchRemoteToolCatalogue(ctx, provider.Host.ID(), tc.filter)
			if err != nil {
				t.Fatalf("fetch catalog: %v", err)
			}
			if len(rows) != tc.wantCount {
				t.Fatalf("rows = %v, want %d", rows, tc.wantCount)
			}
			for _, row := range rows {
				if row.Error != "" {
					t.Fatalf("unexpected tool error: %s", row.Error)
				}
			}
			if got := otherRequests.Load() - before; (got > 0) != tc.wantOther {
				t.Fatalf("unrelated backend requests = %d, want any: %t", got, tc.wantOther)
			}
		})
	}
}
