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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestFormatOutput(t *testing.T) {
	compactMeshInfo := `{"peer_id":"12D3KooWTest","connected_peers":["12D3KooWA","12D3KooWB"],"attached_routers":["12D3KooWR"],"router_peer_id":"12D3KooWR","local_api_socket":"/tmp/agentmesh.sock"}`
	prettyMeshInfo := "{\n" +
		"  \"peer_id\": \"12D3KooWTest\",\n" +
		"  \"connected_peers\": [\n" +
		"    \"12D3KooWA\",\n" +
		"    \"12D3KooWB\"\n" +
		"  ],\n" +
		"  \"attached_routers\": [\n" +
		"    \"12D3KooWR\"\n" +
		"  ],\n" +
		"  \"router_peer_id\": \"12D3KooWR\",\n" +
		"  \"local_api_socket\": \"/tmp/agentmesh.sock\"\n" +
		"}"

	cases := []struct {
		name   string
		input  string
		pretty bool
		want   string
	}{
		{
			name:   "json_object_pretty_enabled",
			input:  compactMeshInfo,
			pretty: true,
			want:   prettyMeshInfo,
		},
		{
			name:   "json_object_pretty_disabled",
			input:  compactMeshInfo,
			pretty: false,
			want:   compactMeshInfo,
		},
		{
			name:   "json_array_pretty_enabled",
			input:  `[{"peer_id":"12D3KooWA","srv_name":"erp-db"}]`,
			pretty: true,
			want:   "[\n  {\n    \"peer_id\": \"12D3KooWA\",\n    \"srv_name\": \"erp-db\"\n  }\n]",
		},
		{
			name:   "empty_json_collections",
			input:  `[]`,
			pretty: true,
			want:   `[]`,
		},
		{
			name:   "surrounding_whitespace_trimmed_when_valid_json",
			input:  "  {\"peer_id\":\"12D3KooWTest\"} \n",
			pretty: true,
			want:   "{\n  \"peer_id\": \"12D3KooWTest\"\n}",
		},
		{
			name:   "plain_text_untouched",
			input:  "To call an inference service, send a normal HTTP request.",
			pretty: true,
			want:   "To call an inference service, send a normal HTTP request.",
		},
		{
			name:   "bracket_prefixed_non_json_untouched",
			input:  "[A2A Auditor] APPROVED",
			pretty: true,
			want:   "[A2A Auditor] APPROVED",
		},
		{
			name:   "empty_string_untouched",
			input:  "",
			pretty: true,
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatOutput(tc.input, tc.pretty)
			if got != tc.want {
				t.Errorf("formatOutput(%q, %v) =\n%s\nwant:\n%s", tc.input, tc.pretty, got, tc.want)
			}
		})
	}
}

func TestIsTerminalNonTTY(t *testing.T) {
	t.Run("nil_file", func(t *testing.T) {
		if isTerminal(nil) {
			t.Fatalf("isTerminal(nil) = true, want false")
		}
	})

	t.Run("pipe_is_not_terminal", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() failed: %v", err)
		}
		t.Cleanup(func() {
			_ = r.Close()
			_ = w.Close()
		})
		if isTerminal(r) || isTerminal(w) {
			t.Fatalf("isTerminal on os.Pipe() = true, want false")
		}
	})

	t.Run("regular_file_is_not_terminal", func(t *testing.T) {
		f, err := os.Create(filepath.Join(t.TempDir(), "out.json"))
		if err != nil {
			t.Fatalf("os.Create failed: %v", err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if isTerminal(f) {
			t.Fatalf("isTerminal on regular file = true, want false")
		}
	})
}

func TestMCPClientCLIGetMeshInfoPrettyAndPiped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	compact := `{"peer_id":"12D3KooWNode1","connected_peers":["12D3KooWRouter"],"attached_routers":["12D3KooWRouter"],"router_peer_id":"12D3KooWRouter","local_api_socket":"/tmp/node1.sock"}`

	srv := mcp.NewServer(&mcp.Implementation{Name: "test-node", Version: "0.0.1"}, nil)
	type emptyArgs struct{}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_mesh_info",
		Description: "Get information about the mesh network",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: compact},
				&mcp.TextContent{Text: "Hint: plain text stays as-is"},
			},
		}, nil, nil
	})

	httpSrv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return srv
	}, nil))
	t.Cleanup(httpSrv.Close)

	binPath := filepath.Join(t.TempDir(), "mcp-client")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(out))
	}

	t.Run("piped_stdout_defaults_to_compact_single_line", func(t *testing.T) {
		out, err := exec.Command(binPath, "-url", httpSrv.URL, "-tool", "get_mesh_info").Output()
		if err != nil {
			t.Fatalf("mcp-client failed: %v", err)
		}
		got := string(out)
		want := compact + "\nHint: plain text stays as-is\n"
		if got != want {
			t.Errorf("piped stdout =\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("pretty_flag_indents_json_and_preserves_plain_text", func(t *testing.T) {
		out, err := exec.Command(binPath, "-url", httpSrv.URL, "-tool", "get_mesh_info", "-pretty").Output()
		if err != nil {
			t.Fatalf("mcp-client -pretty failed: %v", err)
		}
		got := string(out)
		if !strings.Contains(got, "  \"peer_id\": \"12D3KooWNode1\",\n") {
			t.Errorf("expected 2-space indented peer_id in output, got:\n%s", got)
		}
		if !strings.HasSuffix(got, "\nHint: plain text stays as-is\n") {
			t.Errorf("expected trailing plain-text content untouched, got:\n%s", got)
		}
	})
}
