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

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectJSONRPCMCPBody(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantTool  string
		wantAllow bool
	}{
		{
			name:      "tools/call bare tool",
			body:      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`,
			wantTool:  "read_file",
			wantAllow: false,
		},
		{
			name:      "tools/call namespaced tool",
			body:      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mcp://github/get_pr"}}`,
			wantTool:  "get_pr",
			wantAllow: false,
		},
		{
			name:      "initialize",
			body:      `{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
			wantTool:  "",
			wantAllow: true,
		},
		{
			name:      "notifications/initialized",
			body:      `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			wantTool:  "",
			wantAllow: true,
		},
		{
			name:      "server/discover",
			body:      `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`,
			wantTool:  "",
			wantAllow: true,
		},
		{
			name:      "tools/list",
			body:      `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			wantTool:  "",
			wantAllow: true,
		},
		{
			name:      "resources/read is not auth-free",
			body:      `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///secret"}}`,
			wantTool:  "",
			wantAllow: false,
		},
		{
			name:      "empty body",
			body:      "   ",
			wantTool:  "",
			wantAllow: false,
		},
		{
			name:      "invalid json",
			body:      "{not-json",
			wantTool:  "",
			wantAllow: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTool, gotAllow := InspectJSONRPCMCPBody([]byte(tc.body))
			if gotTool != tc.wantTool || gotAllow != tc.wantAllow {
				t.Fatalf("InspectJSONRPCMCPBody(%q) = (%q, %v), want (%q, %v)", tc.body, gotTool, gotAllow, tc.wantTool, tc.wantAllow)
			}
		})
	}
}

func TestInspectMCPHTTPRequestBody(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mcp://git/status"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/git", strings.NewReader(body))
	tool, allowInit, err := InspectMCPHTTPRequestBody(req, 1024)
	if err != nil {
		t.Fatalf("InspectMCPHTTPRequestBody: %v", err)
	}
	if tool != "status" || allowInit {
		t.Fatalf("got (%q, %v), want (\"status\", false)", tool, allowInit)
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil || string(restored) != body {
		t.Fatalf("restored body = %q (err=%v), want %q", string(restored), err, body)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/mcp/git", nil)
	if tool, allowInit, err := InspectMCPHTTPRequestBody(getReq, 1024); err != nil || tool != "" || !allowInit {
		t.Fatalf("GET SSE stream: got (%q, %v, %v), want (\"\", true, nil)", tool, allowInit, err)
	}

	oversized := httptest.NewRequest(http.MethodPost, "/mcp/git", strings.NewReader(strings.Repeat("a", 65)))
	if _, _, err := InspectMCPHTTPRequestBody(oversized, 64); err == nil {
		t.Fatal("oversized MCP body succeeded, want error")
	}
}

func TestSanitizeExternalIngressHeaders(t *testing.T) {
	edgeHdr := http.Header{
		"Authorization":    {"Bearer caller-token"},
		"Cookie":           {"sid=123"},
		"X-Mesh-Principal": {"spoofed@evil.example"},
		"X-Mesh-Custom":    {"evil"},
		"X-Peer-Id":        {"spoofed-peer"},
		"Content-Type":     {"application/json"},
		"X-Hub-Signature":  {"sha256=ok"},
	}
	SanitizeExternalIngressHeaders(edgeHdr, true)
	for _, mustDrop := range []string{"Authorization", "Cookie", "X-Mesh-Principal", "X-Mesh-Custom", "X-Peer-Id"} {
		if got := edgeHdr.Get(mustDrop); got != "" {
			t.Errorf("stripAuth=true kept %s=%q", mustDrop, got)
		}
	}
	if edgeHdr.Get("Content-Type") != "application/json" || edgeHdr.Get("X-Hub-Signature") != "sha256=ok" {
		t.Errorf("stripAuth=true dropped benign headers: %v", edgeHdr)
	}

	passHdr := http.Header{
		"Authorization":    {"Bearer pair-token"},
		"Cookie":           {"sid=123"},
		"X-Mesh-Principal": {"spoofed@evil.example"},
		"X-Peer-Id":        {"spoofed-peer"},
	}
	SanitizeExternalIngressHeaders(passHdr, false)
	if got := passHdr.Get("Authorization"); got != "Bearer pair-token" {
		t.Errorf("stripAuth=false Authorization = %q, want Bearer pair-token", got)
	}
	for _, mustDrop := range []string{"Cookie", "X-Mesh-Principal", "X-Peer-Id"} {
		if got := passHdr.Get(mustDrop); got != "" {
			t.Errorf("stripAuth=false kept %s=%q", mustDrop, got)
		}
	}
}
