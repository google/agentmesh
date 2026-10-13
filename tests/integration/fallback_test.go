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
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/google/agentmesh/internal/node"
)

// init forces the biscuit-go parser to build its underlying participle
// lexer and reflection caches synchronously at startup. This prevents
// a known data race when multiple goroutines parse facts concurrently.
func init() {
	_, _ = parser.FromStringFact(`warmup("cache")`)
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestSelfHealingHTTPFallback: the routers a node stored can be gone by its
// next start (a redeploy moves every router's address); the node must ask
// the control plane for the current ones, reach one, and remember it.
func TestSelfHealingHTTPFallback(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/agentmesh-node")
	tmpDir := t.TempDir()
	oidcURL, mintToken := startCustomMockOIDC(t)

	// Leases are short so the control plane forgets the old router soon
	// after it is gone, the way a redeploy replaces the router set.
	meshDir := filepath.Join(tmpDir, "mesh")
	cpPort, _ := startControlPlane(t, meshDir, oidcURL, meshPolicyFile(t, meshDir), "--lease-duration", "2s")
	cpURL := fmt.Sprintf("http://127.0.0.1:%d", cpPort)
	oldRouter, stopOldRouter := startRouter(t, meshDir, cpPort, mintToken, "old-router")

	home := filepath.Join(tmpDir, "home")
	env, dataDir := nodeHome(home)
	token := tokenPath(t, "node-token")

	// Enroll while the old router is the only one, so it is the one stored.
	first := launchNode(t, nodeBin, env, home, "run", "--control-plane", cpURL,
		"--jwt", mintToken(map[string]interface{}{"sub": jwtUser}), "--allow-loopback", "--api-token-path", token)
	first.waitForAPI(t)
	waitForPeerOnRouter(t, cpPort, testAdminToken, first.peerID.String(), 10*time.Second)
	first.kill()
	if addrs := storedRouters(t, dataDir); !slices.Contains(addrs, oldRouter) {
		t.Fatalf("stored routers %v do not include the router the node enrolled through, %s", addrs, oldRouter)
	}

	// The redeploy: the stored router is gone, a new one is up, and only the
	// control plane knows about it.
	stopOldRouter()
	newRouter, _ := startRouter(t, meshDir, cpPort, mintToken, "new-router")
	waitForRouterSet(t, cpPort, []string{newRouter}, 10*time.Second)

	// The node comes back on its stored config and no --control-plane: what
	// it stored is a dead address, so reaching the new router at all means
	// it asked the control plane. /healthz answers only once Start succeeded,
	// and Start fails unless a router authenticated the node.
	again := launchNode(t, nodeBin, env, home, "run", "--allow-loopback", "--api-token-path", token)
	again.waitForAPI(t)
	lease := waitForPeerOnRouter(t, cpPort, testAdminToken, again.peerID.String(), 10*time.Second)
	if !slices.Contains(lease.Addresses, newRouter) {
		t.Fatalf("the node is connected to %v, not to the new router %s", lease.Addresses, newRouter)
	}

	// Healed for good: the next start does not need the control plane to
	// find a router either.
	again.kill()
	addrs := storedRouters(t, dataDir)
	if !slices.Contains(addrs, newRouter) || slices.Contains(addrs, oldRouter) {
		t.Fatalf("stored routers %v: want %s and not %s", addrs, newRouter, oldRouter)
	}
}

// storedRouters is the router set the node would dial on its next start.
func storedRouters(t *testing.T, dataDir string) []string {
	t.Helper()
	store, err := node.NewStore(dataDir)
	if err != nil {
		t.Fatalf("open node store: %v", err)
	}
	defer func() { _ = store.Close() }()
	_, addrs, err := store.LoadMeshConfig()
	if err != nil {
		t.Fatalf("load mesh config: %v", err)
	}
	return addrs
}

// waitForRouterSet waits until the control plane's active routers listen on
// exactly want.
func waitForRouterSet(t *testing.T, cpPort int, want []string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var got []string
		for _, lease := range fetchAdminStatus(t, cpPort, testAdminToken).ActiveRouters {
			got = append(got, lease.Addresses...)
		}
		slices.Sort(got)
		if slices.Equal(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("control plane :%d routers = %v, want %v", cpPort, got, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
