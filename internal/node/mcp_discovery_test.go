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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/sam/api"
	samdiscovery "github.com/google/sam/internal/node/discovery"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPService_Tools(t *testing.T) {
	backend := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "zeta", Description: "z", InputSchema: map[string]any{"type": "object"}},
		{Name: "alpha", Description: "a", InputSchema: map[string]any{"type": "object"}},
	}))
	defer backend.Close()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "tools-svc"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
	}}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	got, err := svc.Tools(context.Background())
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if want := []string{"alpha", "zeta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Tools: got %v, want %v (sorted)", got, want)
	}

	// Cached: survives the backend going away.
	backend.Close()
	got, err = svc.Tools(context.Background())
	if err != nil || len(got) != 2 {
		t.Errorf("cached Tools: got %v, err %v", got, err)
	}
}

func TestMCPService_Tools_Pagination(t *testing.T) {
	backend := httptest.NewServer(newFakeMCPHandlerWithOptions(t, []*mcp.Tool{
		{Name: "zeta", Description: "z", InputSchema: map[string]any{"type": "object"}},
		{Name: "alpha", Description: "a", InputSchema: map[string]any{"type": "object"}},
		{Name: "beta", Description: "b", InputSchema: map[string]any{"type": "object"}},
	}, &mcp.ServerOptions{PageSize: 1}))
	defer backend.Close()

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "tools-svc"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
	}}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	got, err := svc.Tools(context.Background())
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if want := []string{"alpha", "beta", "zeta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Tools: got %v, want %v (sorted across pages)", got, want)
	}
}

func TestListAllTools_BoundedAgainstEndlessCursor(t *testing.T) {
	var pages atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		if req.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		} // notification
		var result any = map[string]any{}
		switch req.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2026-07-28",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "hostile", "version": "0"},
			}
		case "tools/list":
			pages.Add(1)
			result = map[string]any{
				"tools":      []any{map[string]any{"name": "x", "inputSchema": map[string]any{"type": "object"}}},
				"nextCursor": "again",
				"ttlMs":      60000, "cacheScope": "public", // makes the SDK serve repeats from cache
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
		Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	tools, err := listAllTools(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != maxToolsPerService {
		t.Fatalf("got %d tools, want cap %d", len(tools), maxToolsPerService)
	}
}

// fakeToolService is a local MCP Service reporting served tool names.
type fakeToolService struct {
	testService
	tools []string
	err   error
}

func (f *fakeToolService) Tools(_ context.Context) ([]string, error) {
	return f.tools, f.err
}

func TestDiscoverySource(t *testing.T) {
	node := &SamNode{
		services:   NewServiceRegistry(&fakeDHT{}, 0),
		nodeConfig: &NodeConfigComplete{Labels: map[string]string{"region": "EU"}},
	}
	ctx := context.Background()

	llm := newFakeModelService("llm", nil, "model-b", "model-a")
	tools := &fakeToolService{
		testService: testService{info: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "reviewer"}},
		tools:       []string{"review_pr", "lint"},
	}
	broken := &fakeToolService{
		testService: testService{info: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "broken"}},
		err:         fmt.Errorf("backend down"),
	}
	for _, svc := range []Service{llm, tools, broken} {
		if err := node.services.Register(ctx, svc); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	anns := node.discoverySource()
	if len(anns) != 2 {
		t.Fatalf("announcements: got %d (%+v), want 2", len(anns), anns)
	}
	byName := map[string]samdiscovery.Announcement{}
	for _, a := range anns {
		byName[a.Name] = a
	}
	if a := byName["llm"]; a.Type != api.ServiceType_SERVICE_TYPE_INFERENCE || len(a.Keys) != 2 {
		t.Errorf("llm announcement: %+v", a)
	}
	if a := byName["reviewer"]; a.Type != api.ServiceType_SERVICE_TYPE_MCP || len(a.Keys) != 2 {
		t.Errorf("reviewer announcement: %+v", a)
	}
	for name, a := range byName {
		if a.Labels["region"] != "EU" {
			t.Errorf("%s labels: got %v, want region=EU", name, a.Labels)
		}
	}
}

func TestCapKeys(t *testing.T) {
	keys := make([]string, api.MaxAnnounceKeys+5)
	for i := range keys {
		keys[i] = fmt.Sprintf("k%03d", i)
	}
	sort.Strings(keys)
	if got := capKeys(keys); len(got) != api.MaxAnnounceKeys {
		t.Errorf("capKeys: got %d, want %d", len(got), api.MaxAnnounceKeys)
	}
	if got := capKeys(keys[:3]); len(got) != 3 {
		t.Errorf("capKeys under cap: got %d, want 3", len(got))
	}
}

func TestGossipToolRows(t *testing.T) {
	provs := []samdiscovery.Provider{
		{PeerID: "peerA", Service: "reviewer", Labels: map[string]string{"region": "eu"}},
		{PeerID: "peerB", Service: "other"},
	}
	rows := gossipToolRows(provs, "review_pr", "")
	if len(rows) != 2 {
		t.Fatalf("rows: got %+v, want 2", rows)
	}
	if rows[0].ToolName != "mcp://reviewer/review_pr" || rows[0].Labels["region"] != "eu" {
		t.Errorf("row 0: %+v", rows[0])
	}
	if len(rows[1].Labels) != 0 {
		t.Errorf("row 1 should have no labels: %+v", rows[1])
	}

	filtered := gossipToolRows(provs, "review_pr", "mcp://reviewer")
	if len(filtered) != 1 || filtered[0].PeerID != "peerA" {
		t.Errorf("service filter: got %+v", filtered)
	}
}

// The tool schema documents service_name as a bare name ("code-reviewer") while
// tool names carry the mcp:// prefix. Matching the two literally made the
// documented spelling return nothing, which is indistinguishable from a mesh
// that has no such service.
func TestNormalizeServiceFilter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty is no filter", in: "", want: ""},
		{name: "bare name gains the scheme", in: "everything", want: "mcp://everything"},
		{name: "namespaced name is already canonical", in: "mcp://everything", want: "mcp://everything"},
		{name: "a non-MCP scheme is an error, not an empty result", in: "inference://vllm-tpu", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeServiceFilter(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeServiceFilter(%q): want error, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeServiceFilter(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeServiceFilter(%q): got %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Providers announce a service either bare or namespaced; both denote the same
// service and must match one canonical filter.
func TestGossipToolRows_MatchesEitherAnnouncedForm(t *testing.T) {
	provs := []samdiscovery.Provider{
		{PeerID: "peerA", Service: "everything"},
		{PeerID: "peerB", Service: "mcp://everything"},
		{PeerID: "peerC", Service: "other"},
	}
	rows := gossipToolRows(provs, "get-sum", "mcp://everything")
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}
	for _, row := range rows {
		if row.ToolName != "mcp://everything/get-sum" {
			t.Errorf("got %q", row.ToolName)
		}
	}
}

func TestFilterRowsByToolName(t *testing.T) {
	rows := []remoteToolRow{
		{PeerID: "p1", ToolName: "mcp://svc/review_pr"},
		{PeerID: "p2", ToolName: "mcp://svc/lint"},
		{PeerID: "p3", Error: "unreachable"},
	}
	got := filterRowsByToolName(rows, "review_pr")
	if len(got) != 1 || got[0].PeerID != "p1" {
		t.Errorf("filter: got %+v", got)
	}
}
