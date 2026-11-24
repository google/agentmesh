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

import "testing"

func TestFilterRowsByFullToolName(t *testing.T) {
	rows := []remoteToolRow{
		{ToolName: "mcp://catalog/read"},
		{ToolName: "mcp://catalog/reports/read"},
		{ToolName: "mcp://catalog/reports/read", Error: "backend unavailable"},
	}
	for _, tc := range []struct {
		query string
		want  string
	}{
		{"read", "mcp://catalog/read"},
		{"reports/read", "mcp://catalog/reports/read"},
		{"missing/read", ""},
	} {
		t.Run(tc.query, func(t *testing.T) {
			got := filterRowsByToolName(rows, tc.query)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("matches for %q = %v, want none", tc.query, got)
				}
				return
			}
			if len(got) != 1 || got[0].ToolName != tc.want {
				t.Fatalf("matches for %q = %v, want only %q", tc.query, got, tc.want)
			}
		})
	}
}
