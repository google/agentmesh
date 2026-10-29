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
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHandleFindRemoteTools_Intent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	backend := httptest.NewServer(newFakeMCPHandler(t, []*mcp.Tool{
		{Name: "add_comment", Description: "Add a comment", InputSchema: map[string]any{"type": "object"}},
		{Name: "review_pr", Description: "Review a pull request", InputSchema: map[string]any{"type": "object"}},
	}))
	defer backend.Close()
	caller, cleanupCaller := startBareNode(t, ctx)
	defer cleanupCaller()
	provider, cleanupProvider := startBareNode(t, ctx)
	defer cleanupProvider()
	_, root := enrollUnderRoot(t, caller, provider)
	if err := buildAndSaveCustomBiscuit(caller, root, []string{"mcp://code-reviewer", "system://mesh.catalog"}); err != nil {
		t.Fatal(err)
	}
	if err := caller.Host.Connect(ctx, peer.AddrInfo{ID: provider.Host.ID(), Addrs: provider.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"code-reviewer", "private-review"} {
		if err := provider.RegisterService(ctx, &api.RegisterServiceRequest{
			Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: name},
			Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: backend.URL},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, service, exact, intent, wantFirst string
		wantCount                               int
	}{
		{"intent with peer", "", "", "review pull request", "review_pr", 2},
		{"bare service", "code-reviewer", "", "review pull request", "review_pr", 2},
		{"namespaced service", "mcp://code-reviewer", "", "review pull request", "review_pr", 2},
		{"exact name wins", "", "add_comment", "review pull request", "add_comment", 1},
		{"denied service stays hidden", "private-review", "", "review pull request", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, _, err := caller.handleFindRemoteTools(ctx, nil, FindRemoteToolsParams{
				PeerID: provider.Host.ID().String(), ServiceName: tc.service, ToolName: tc.exact, Intent: tc.intent,
			})
			if err != nil {
				t.Fatal(err)
			}
			var rows []remoteToolRow
			if err := json.Unmarshal([]byte(result.Content[0].(*mcp.TextContent).Text), &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != tc.wantCount {
				t.Fatalf("got %d rows, want %d: %+v", len(rows), tc.wantCount, rows)
			}
			for _, row := range rows {
				if row.PeerID != provider.Host.ID().String() || !strings.HasPrefix(row.ToolName, "mcp://code-reviewer/") || row.Error != "" {
					t.Errorf("unexpected or unauthorized row: %+v", row)
				}
			}
			if len(rows) > 0 && rows[0].ToolName != "mcp://code-reviewer/"+tc.wantFirst {
				t.Errorf("first tool = %q, want %q", rows[0].ToolName, tc.wantFirst)
			}
		})
	}
}

func TestRankRowsByIntent(t *testing.T) {
	tests := []struct {
		name, intent string
		rows         []remoteToolRow
		want         []string
	}{
		{"coverage before name matches", "review pull request", []remoteToolRow{
			{PeerID: "partial", ToolName: "mcp://review/review"},
			{PeerID: "full", ToolName: "mcp://tools/check", Description: "Review a pull request"},
		}, []string{"full", "partial"}},
		{"name breaks coverage tie", "review", []remoteToolRow{
			{PeerID: "description", ToolName: "mcp://a/check", Description: "review"},
			{PeerID: "name", ToolName: "mcp://z/review"},
		}, []string{"name", "description"}},
		{"case punctuation and distinct terms", "THE REVIEW_review, pull-request!", []remoteToolRow{
			{PeerID: "repetition", ToolName: "mcp://a/review", Description: "review review review review"},
			{PeerID: "coverage", ToolName: "mcp://z/review_pr", Description: "Review a pull request"},
		}, []string{"coverage", "repetition"}},
		{"Unicode words", "문서 요약", []remoteToolRow{
			{PeerID: "other", ToolName: "mcp://tools/edit", Description: "문서 편집"},
			{PeerID: "match", ToolName: "mcp://tools/summarize", Description: "문서 요약"},
		}, []string{"match", "other"}},
		{"retain unmatched tools and errors", "review", []remoteToolRow{
			{PeerID: "error", ToolName: "mcp://review", Error: "review unavailable"},
			{PeerID: "unmatched", ToolName: "mcp://a/list"},
			{PeerID: "match", ToolName: "mcp://z/review"},
		}, []string{"match", "unmatched", "error"}},
		{"sort ties by tool then peer", "missing", []remoteToolRow{
			{PeerID: "z", ToolName: "mcp://b/tool"},
			{PeerID: "b", ToolName: "mcp://a/tool"},
			{PeerID: "a", ToolName: "mcp://a/tool"},
		}, []string{"a", "b", "z"}},
		{"empty preserves order", "", []remoteToolRow{{PeerID: "z"}, {PeerID: "a"}}, []string{"z", "a"}},
		{"whitespace preserves order", " \t\n", []remoteToolRow{{PeerID: "z"}, {PeerID: "a"}}, []string{"z", "a"}},
		{"function words preserve order", "the and of to", []remoteToolRow{{PeerID: "z"}, {PeerID: "a"}}, []string{"z", "a"}},
		{"empty catalogue", "review", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows := rankRowsByIntent(slices.Clone(tc.rows), tc.intent)
			var got []string
			for _, row := range rows {
				got = append(got, row.PeerID)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("order = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRankRowsByIntent_PreservesRows(t *testing.T) {
	rows := []remoteToolRow{
		{PeerID: "one", ToolName: "mcp://tools/list", Description: "List branches", Labels: map[string]string{"region": "west"}},
		{PeerID: "two", ToolName: "mcp://tools/review", Description: "Review code", Labels: map[string]string{"region": "east"}},
		{PeerID: "three", ToolName: "mcp://unavailable", Error: "failed to connect"},
	}
	want := []remoteToolRow{rows[1], rows[0], rows[2]}
	got := rankRowsByIntent(rows, "review")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ranked rows = %+v, want %+v", got, want)
	}
	slices.Reverse(got)
	if again := rankRowsByIntent(got, "review"); !reflect.DeepEqual(again, want) {
		t.Errorf("rank depends on input order: %+v, want %+v", again, want)
	}
}

func BenchmarkRankRowsByIntent(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			catalogue := make([]remoteToolRow, size)
			for i := range catalogue {
				catalogue[i] = remoteToolRow{
					PeerID:      fmt.Sprintf("peer-%d", i),
					ToolName:    fmt.Sprintf("mcp://code-reviewer/tool_%d", i),
					Description: "Review a pull request and report code quality issues",
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				rankRowsByIntent(slices.Clone(catalogue), "review pull request")
			}
		})
	}
}
