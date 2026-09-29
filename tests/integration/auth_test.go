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

package integration_test

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/sam/api"
)

func TestNodeAuthEnforcementIntegration(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	_, mockRouterAddr := startMockRouter(t)

	home := t.TempDir()
	logFile, err := os.Create(filepath.Join(home, "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = logFile.Close()
	}()

	// getFreePort is already defined in minimal_helpers_test.go
	port := getFreePort(t)
	nodeURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	apiToken := "secret-integration-token"

	cmd := exec.Command(nodeBin, "run",
		"--control-plane", mockRouterAddr,
		"--data-dir", home,
		"--api-token-path", tokenPath(t, apiToken),
		"--jwt", "fake-jwt",
		"--bind-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start node: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	// Wait for node to be ready
	client := &http.Client{Timeout: 2 * time.Second}
	ready := false
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := client.Get(nodeURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
	}

	if !ready {
		b, _ := os.ReadFile(filepath.Join(home, "node.log"))
		t.Fatalf("Node did not become ready in time. Log:\n%s", string(b))
	}

	// Verify authentication on endpoints
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		needsToken     bool
	}{
		{"healthz is public", "GET", "/healthz", http.StatusOK, false},
		{"readyz is public", "GET", "/readyz", http.StatusOK, false},
		// Services are declared in configuration only: the former runtime
		// registration endpoints are gone, so /sam/service/register is just
		// another egress-proxy path behind auth like any /sam/ path.
		{"discover is protected", "GET", "/sam/service/discover?type=mcp&name=test", http.StatusUnauthorized, false},
		{"egress proxy is protected", "GET", "/sam/", http.StatusUnauthorized, false},
		{"register path is protected like any egress path", "POST", "/sam/service/register", http.StatusUnauthorized, false},
		{"mcp root is protected", "GET", "/mcp", http.StatusUnauthorized, false},

		// /sam/service/discover expects node to be connected.
		{"discover with token", "GET", "/sam/service/discover?type=mcp&name=test", http.StatusOK, true},
		// The sessionless MCP server has no standalone stream: GET is 405.
		{"mcp root with token", "GET", "/mcp", http.StatusMethodNotAllowed, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, nodeURL+tt.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			if tt.needsToken {
				req.Header.Set(api.HeaderSamAuthentication, "Bearer "+apiToken)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer func() {
				_ = resp.Body.Close()
			}()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d for %s, got %d", tt.expectedStatus, tt.path, resp.StatusCode)
			}
		})
	}
}
