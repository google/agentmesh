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

// Command github-mcp-live is a minimal Cloud Run backend used to qualify
// Google Cloud Agent Gateway + agentmesh-node Service Extensions with real
// GitHub traffic:
//   - POST /mcp (and POST /): handles JSON-RPC 2.0 MCP tools/call for read-only
//     GitHub issue tools (list_issues, issue_read, search_issues) by querying
//     live https://api.github.com and echoing the verified X-Mesh-* headers
//     stamped by agentmesh-node ext_proc. Mutating tools are never executed and
//     return a clear sentinel error if an authorization bypass ever occurred.
//   - GET/POST /<org>/<repo>.git/...: reverse-proxies Git Smart HTTP traffic
//     to real https://github.com for Edge ALB qualification.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	maxJSONRPCBytes = 1 << 20
	githubAPIBase   = "https://api.github.com"
	githubGitBase   = "https://github.com"
)

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	gitUpstream, err := url.Parse(githubGitBase)
	if err != nil {
		log.Fatalf("parse github url: %v", err)
	}
	gitProxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(gitUpstream)
			pr.Out.Host = gitUpstream.Host
			// Strip internal mesh headers before forwarding to public github.com.
			for k := range pr.Out.Header {
				lk := strings.ToLower(k)
				if strings.HasPrefix(lk, "x-mesh-") || lk == "x-peer-id" {
					pr.Out.Header.Del(k)
				}
			}
		},
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		handleMCP(w, r, httpClient)
	})
	mux.HandleFunc("/mcp/", func(w http.ResponseWriter, r *http.Request) {
		handleMCP(w, r, httpClient)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".git/") || strings.HasSuffix(r.URL.Path, ".git") {
			gitProxy.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodPost {
			handleMCP(w, r, httpClient)
			return
		}
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("github-mcp-live listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func handleMCP(w http.ResponseWriter, r *http.Request, client *http.Client) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONRPCBytes))
	if err != nil {
		log.Printf("handleMCP 400: read body failed: %v", err)
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	var rpc jsonRPCRequest
	if err := json.Unmarshal(body, &rpc); err != nil {
		log.Printf("handleMCP 400: invalid json-rpc body (len=%d): %v", len(body), err)
		http.Error(w, "invalid json-rpc body", http.StatusBadRequest)
		return
	}

	verifiedHeaders := make(map[string]string)
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-mesh-") || lk == "x-peer-id" {
			verifiedHeaders[k] = strings.Join(vals, ",")
		}
	}
	if r.Header.Get("Authorization") != "" {
		verifiedHeaders["Authorization"] = "<present-redacted>"
	}

	var result any
	switch rpc.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]any{"name": "github-mcp-live", "version": "1.0.0"},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "tools/list":
		result = map[string]any{
			"tools": []map[string]any{
				{"name": "list_issues", "description": "List live issues from a GitHub repository"},
				{"name": "issue_read", "description": "Read a live GitHub issue by number"},
				{"name": "search_issues", "description": "Search live GitHub issues"},
				{"name": "issue_write", "description": "Create or edit an issue (must be blocked by TAR)"},
				{"name": "create_pull_request", "description": "Open a pull request (must be blocked by TAR)"},
				{"name": "push_files", "description": "Push files to a repository (must be blocked by TAR)"},
				{"name": "delete_repository", "description": "Delete a repository (must be blocked by TAR)"},
			},
		}
	case "tools/call":
		toolRes, callErr := executeReadOnlyTool(r.Context(), client, r.Header.Get("Authorization"), rpc.Params.Name, rpc.Params.Arguments)
		if callErr != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"error": map[string]any{
					"code":    -32000,
					"message": callErr.Error(),
				},
			})
			return
		}
		result = map[string]any{
			"tool":                     rpc.Params.Name,
			"live_github_data":         toolRes,
			"backend_verified_headers": verifiedHeaders,
		}
	default:
		http.Error(w, "unsupported json-rpc method", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      rpc.ID,
		"result":  result,
	})
}

func executeReadOnlyTool(ctx context.Context, client *http.Client, authHeader, tool string, args map[string]any) (any, error) {
	owner := stringArg(args, "owner", "google")
	repo := stringArg(args, "repo", "agentmesh")
	if !isSafeSlug(owner) || !isSafeSlug(repo) {
		return nil, fmt.Errorf("invalid owner or repo")
	}

	var target string
	switch tool {
	case "list_issues":
		target = fmt.Sprintf("%s/repos/%s/%s/issues?per_page=3&state=all", githubAPIBase, owner, repo)
	case "issue_read":
		num := 1
		if raw, ok := args["issue_number"].(float64); ok && raw > 0 {
			num = int(raw)
		}
		target = fmt.Sprintf("%s/repos/%s/%s/issues/%d", githubAPIBase, owner, repo, num)
	case "search_issues":
		q := stringArg(args, "query", fmt.Sprintf("repo:%s/%s", owner, repo))
		target = fmt.Sprintf("%s/search/issues?per_page=3&q=%s", githubAPIBase, url.QueryEscape(q))
	default:
		return nil, fmt.Errorf("MUTATING_TOOL_REACHED_BACKEND: %s (ext_proc should have blocked this)", tool)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "agentmesh-gcp-agw-demo")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONRPCBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github api returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawBody)))
	}
	var parsed any
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		return nil, err
	}
	return summarizeGitHubResponse(tool, parsed), nil
}

func summarizeGitHubResponse(tool string, parsed any) any {
	switch tool {
	case "list_issues":
		items, ok := parsed.([]any)
		if !ok {
			return parsed
		}
		out := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if m, ok := item.(map[string]any); ok {
				out = append(out, map[string]any{
					"number": m["number"],
					"state":  m["state"],
					"title":  m["title"],
					"url":    m["html_url"],
				})
			}
		}
		return out
	case "issue_read":
		if m, ok := parsed.(map[string]any); ok {
			return map[string]any{
				"number": m["number"],
				"state":  m["state"],
				"title":  m["title"],
				"url":    m["html_url"],
			}
		}
	}
	return parsed
}

func stringArg(args map[string]any, key, fallback string) string {
	if args == nil {
		return fallback
	}
	if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func isSafeSlug(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
