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
	"fmt"
	"reflect"
	"slices"
	"testing"
)

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

// BenchmarkRankRowsByIntent measures local ranking of synthetic catalogue rows,
// including the input-slice copy needed because ranking reorders it in place.
// It excludes mesh discovery and MCP calls and does not measure search relevance.
func BenchmarkRankRowsByIntent(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("rows=%d", size), func(b *testing.B) {
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
