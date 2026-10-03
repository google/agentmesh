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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func TestMain(m *testing.M) {
	code := m.Run()
	builtBinaries.Range(func(_, entry any) bool {
		if b := entry.(*binaryBuild); b.path != "" {
			_ = os.RemoveAll(filepath.Dir(b.path))
		}
		return true
	})
	os.Exit(code)
}

// builtBinaries holds one build per package for the whole test process:
// Go caches compilation, but every `go build -o` links again, and fifty
// tests each linking three binaries is a minute of nothing.
var builtBinaries sync.Map // pkgPath -> *binaryBuild

type binaryBuild struct {
	once sync.Once
	path string
	err  error
}

func buildBinary(t *testing.T, pkgPath string) string {
	t.Helper()
	entry, _ := builtBinaries.LoadOrStore(pkgPath, &binaryBuild{})
	b := entry.(*binaryBuild)
	b.once.Do(func() {
		root := repoRoot(t)
		dir, err := os.MkdirTemp("", "sam-integration-bin-")
		if err != nil {
			b.err = err
			return
		}
		b.path = filepath.Join(dir, filepath.Base(pkgPath))
		cmd := exec.Command("go", "build", "-o", b.path, ".")
		cmd.Dir = filepath.Join(root, pkgPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			b.err = fmt.Errorf("%v\n%s", err, output)
		}
	})
	if b.err != nil {
		t.Fatalf("building %s failed: %v", pkgPath, b.err)
	}
	return b.path
}

func runCommand(
	t *testing.T,
	cwd string,
	timeout time.Duration,
	env []string,
	stdin string,
	name string,
	args ...string,
) (string, string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cwd
	tmpBin := filepath.Join(t.TempDir(), "bin")
	_ = os.MkdirAll(tmpBin, 0755)
	_ = os.WriteFile(filepath.Join(tmpBin, "xdg-open"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	_ = os.WriteFile(filepath.Join(tmpBin, "open"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	var finalEnv []string
	finalEnv = append(finalEnv, "BROWSER=echo")
	for _, e := range append(os.Environ(), env...) {
		if !strings.HasPrefix(e, "SSH_CLIENT=") && !strings.HasPrefix(e, "SSH_TTY=") {
			finalEnv = append(finalEnv, e)
		}
	}
	for i, e := range finalEnv {
		if strings.HasPrefix(e, "PATH=") {
			finalEnv[i] = "PATH=" + tmpBin + string(os.PathListSeparator) + e[5:]
		}
	}
	cmd.Env = finalEnv
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stdout.String(), stderr.String(), context.DeadlineExceeded
	}
	return stdout.String(), stderr.String(), err
}

type interceptorWriter struct {
	w       io.Writer
	buf     *bytes.Buffer
	handled bool
}

func (iw *interceptorWriter) Write(p []byte) (n int, err error) {
	n, err = iw.w.Write(p)
	iw.buf.Write(p)
	if !iw.handled {
		s := iw.buf.String()
		if strings.Contains(s, "redirect_uri=") && strings.Contains(s, "state=") {
			iw.handled = true
			go func() {
				// Play the user: open the authorization URL the CLI printed. The
				// provider signs the user in and redirects to the CLI's loopback
				// callback, which the client follows.
				for _, line := range strings.Split(s, "\n") {
					if !strings.Contains(line, "redirect_uri=") {
						continue
					}
					for _, p := range strings.Split(strings.TrimSpace(line), " ") {
						if strings.HasPrefix(p, "http") {
							time.Sleep(100 * time.Millisecond)
							if resp, err := http.Get(p); err == nil {
								_ = resp.Body.Close()
							}
						}
					}
				}
			}()
		}
	}
	return n, err
}

func runCommandWithCallback(
	t *testing.T,
	cwd string,
	timeout time.Duration,
	env []string,
	stdin string,
	name string,
	args ...string,
) (string, string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cwd
	tmpBin := filepath.Join(t.TempDir(), "bin")
	_ = os.MkdirAll(tmpBin, 0755)
	_ = os.WriteFile(filepath.Join(tmpBin, "xdg-open"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	_ = os.WriteFile(filepath.Join(tmpBin, "open"), []byte("#!/bin/sh\nexit 0\n"), 0755)

	var finalEnv []string
	finalEnv = append(finalEnv, "BROWSER=echo")
	for _, e := range append(os.Environ(), env...) {
		if !strings.HasPrefix(e, "SSH_CLIENT=") && !strings.HasPrefix(e, "SSH_TTY=") {
			finalEnv = append(finalEnv, e)
		}
	}
	for i, e := range finalEnv {
		if strings.HasPrefix(e, "PATH=") {
			finalEnv[i] = "PATH=" + tmpBin + string(os.PathListSeparator) + e[5:]
		}
	}
	cmd.Env = finalEnv
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &interceptorWriter{w: &stdout, buf: &bytes.Buffer{}}
	cmd.Stderr = &stderr

	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stdout.String(), stderr.String(), context.DeadlineExceeded
	}
	return stdout.String(), stderr.String(), err
}

func startMockRouter(t *testing.T) (peer.ID, string) {
	routerID, controlPlaneURL, _ := startMockRouterWithControlPlaneKey(t)
	return routerID, controlPlaneURL
}

func startMockRouterWithControlPlaneKey(t *testing.T) (peer.ID, string, ed25519.PublicKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate control plane key: %v", err)
	}

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create mock libp2p host: %v", err)
	}

	h.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		reader := msgio.NewVarintReaderSize(s, 1024*64)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		defer reader.ReleaseMsg(msg)

		writer := msgio.NewVarintWriter(s)
		resp := &api.AuthResponse{
			Success: true,
			Biscuit: createMockBiscuitToken(t, h.ID().String(), priv, api.RoleRouter, nil),
		}
		respBytes, _ := proto.Marshal(resp)
		_ = writer.WriteMsg(respBytes)
	})

	kdht, err := dht.New(h, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/sam"))
	if err != nil {
		t.Fatalf("failed to create DHT on mock router: %v", err)
	}

	// Start HTTP server for enrollment

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		var req api.EnrollRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		resp := &api.EnrollResponse{
			BiscuitToken:          createMockBiscuitToken(t, req.PeerId, priv, api.RoleNode, req.Labels),
			ControlPlanePublicKey: pub,
			RouterAddresses:       []string{h.Addrs()[0].String() + "/p2p/" + h.ID().String()},
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	httpServer := httptest.NewServer(mux)

	t.Cleanup(func() {
		httpServer.Close()
		_ = kdht.Close()
		_ = h.Close()
	})

	return h.ID(), httpServer.URL, pub
}

func createMockBiscuitToken(t *testing.T, peerID string, priv ed25519.PrivateKey, role string, labels map[string]string) []byte {
	builder := biscuit.NewBuilder(priv)
	err := builder.AddAuthorityFact(api.MarkerFact(api.FactTargetUnrestricted))
	if err != nil {
		t.Fatalf("failed to add target_unrestricted: %v", err)
	}

	for _, fact := range api.LabelFacts(labels) {
		if err := builder.AddAuthorityFact(fact); err != nil {
			t.Fatalf("failed to add label fact: %v", err)
		}
	}

	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(1 * time.Hour))},
	}})
	if err != nil {
		t.Fatalf("failed to add FactExpiration fact: %v", err)
	}

	if role == "" {
		role = api.RoleRouter
	}
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactRole,
		IDs:  []biscuit.Term{biscuit.String(role)},
	}})
	if err != nil {
		t.Fatalf("failed to add role fact: %v", err)
	}

	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(peerID)},
	}})
	if err != nil {
		t.Fatalf("failed to add node fact: %v", err)
	}

	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(peerID)},
	}})
	if err != nil {
		t.Fatalf("failed to add client_peer_id fact: %v", err)
	}

	err = builder.AddAuthorityFact(api.MarkerFact(api.FactGrantedServiceAllTypes))
	if err != nil {
		t.Fatalf("failed to add granted_service_all_types fact: %v", err)
	}

	b, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build biscuit: %v", err)
	}
	serialized, err := b.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize biscuit: %v", err)
	}
	return serialized
}

func startControlPlaneAndRouter(t *testing.T, tmpDir string, oidcURL string, mintToken func(map[string]interface{}) string, policyFile string) (int, func()) {
	cpPort, stopCP := startControlPlane(t, tmpDir, oidcURL, policyFile)
	_, stopRouter := startRouter(t, tmpDir, cpPort, mintToken, "router")

	// Wait for router lease to be active and registered
	fetchPeerID(t, cpPort)

	cleanup := func() {
		stopRouter()
		stopCP()
	}

	return cpPort, cleanup
}

// startControlPlane starts a sam-control-plane under tmpDir, trusting oidcURL
// and holding the policy in policyFile with the router role added, plus any
// extra flags. It returns the port and a stop function.
func startControlPlane(t *testing.T, tmpDir string, oidcURL string, policyFile string, extra ...string) (int, func()) {
	t.Helper()
	cpBin := buildBinary(t, "./cmd/sam-control-plane")
	cpPort := getFreePort(t)

	// Automatically adjust the policy file to grant the "router" role to group "routers"
	originalPolicy, err := os.ReadFile(policyFile)
	if err == nil {
		writePolicyWithRouter(t, policyFile, string(originalPolicy))
	}

	cpCmd := exec.Command(cpBin, append([]string{
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", cpPort),
		"--db-dsn", filepath.Join(tmpDir, "cp-keys.db"),
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
		"--admin-token-path", tokenPath(t, "test-admin-token"),
	}, extra...)...)
	cpCmd.Stdout = os.Stdout
	cpCmd.Stderr = os.Stderr
	if err := cpCmd.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}
	stop := func() {
		_ = cpCmd.Process.Kill()
		_ = cpCmd.Wait()
	}
	t.Cleanup(stop)

	waitForControlPlane(t, cpPort)
	injectPolicyYAML(t, cpPort, "test-admin-token", policyFile)
	return cpPort, stop
}

// startRouter starts a sam-router named name against the control plane on
// cpPort, renewing its lease every second so the control plane's view of the
// router's peers is current. It returns the router's p2p address and a stop
// function.
func startRouter(t *testing.T, tmpDir string, cpPort int, mintToken func(map[string]interface{}) string, name string) (string, func()) {
	t.Helper()
	routerBin := buildBinary(t, "./cmd/sam-router")
	routerPort := getFreePort(t)

	routerJWT := mintToken(map[string]interface{}{
		"sub":    name,
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	routerCmd := exec.Command(routerBin,
		"--control-plane", fmt.Sprintf("http://127.0.0.1:%d", cpPort),
		"--listen", fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", routerPort),
		"--keys-path", filepath.Join(tmpDir, name+"-keys.db"),
		"--allow-loopback",
		"--oidc-token", routerJWT,
		// Each renewal carries the router's connected peers, which is how
		// tests see a node reach the mesh through the control plane.
		"--lease-renew-interval", "1s",
	)
	routerCmd.Stdout = os.Stdout
	routerCmd.Stderr = os.Stderr
	if err := routerCmd.Start(); err != nil {
		t.Fatalf("failed to start router: %v", err)
	}
	stop := func() {
		_ = routerCmd.Process.Kill()
		_ = routerCmd.Wait()
	}
	t.Cleanup(stop)

	// The router's peer ID is its own; the control plane learns it from the
	// first lease, which is also when the router is ready for nodes.
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, lease := range fetchAdminStatus(t, cpPort, "test-admin-token").ActiveRouters {
			for _, addr := range lease.Addresses {
				if strings.HasPrefix(addr, fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/", routerPort)) {
					return addr, stop
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("router %s never leased with control plane :%d", name, cpPort)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Test ports come from below the kernel's ephemeral range. A bind-and-close
// probe on 127.0.0.1:0 returns an ephemeral port that is free for anyone the
// moment it is released, including the process under test: a node enrolls
// over HTTP first and binds its sidecar port last, so one of its own
// connections could take the reserved port as its source port in between.
// The kernel never assigns a source port below ephemeralPortLow on its own,
// so a port from [reservedPortBase, ephemeralPortLow) is only ever contended
// by another explicit listener, which the probe still detects.
const reservedPortBase = 10000

var ephemeralPortLow = func() int {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err == nil {
		var low, high int
		if _, err := fmt.Sscan(string(data), &low, &high); err == nil && low > reservedPortBase {
			return low
		}
	}
	return 32768
}()

// portCursor starts at a pid-derived offset so concurrent test processes
// walk different parts of the range instead of racing for the same ports.
var portCursor atomic.Int64

func init() {
	portCursor.Store(int64(os.Getpid()))
}

func getFreePort(t *testing.T) int {
	t.Helper()
	span := int64(ephemeralPortLow - reservedPortBase)
	for range span {
		port := reservedPortBase + int(portCursor.Add(1)%span)
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = l.Close()
		return port
	}
	t.Fatalf("no free TCP port on 127.0.0.1 between %d and %d", reservedPortBase, ephemeralPortLow-1)
	return 0
}

// adminStatus is the control plane's view of the mesh, in the types it
// serializes on /admin/status.
type adminStatus struct {
	EnrolledNodes []storage.EnrolledNode `json:"enrolled_nodes"`
	ActiveRouters []storage.RouterLease  `json:"active_routers"`
}

func fetchAdminStatus(t *testing.T, cpPort int, adminToken string) adminStatus {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/admin/status", cpPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/status: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/status: %s", resp.Status)
	}
	var status adminStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode /admin/status: %v", err)
	}
	return status
}

// enrolledNode is the control plane's record of peerID, or nil.
func (s adminStatus) enrolledNode(peerID string) *storage.EnrolledNode {
	for i := range s.EnrolledNodes {
		if s.EnrolledNodes[i].PeerID == peerID {
			return &s.EnrolledNodes[i]
		}
	}
	return nil
}

// routerWith is the lease of a router that reports peerID connected, or nil.
func (s adminStatus) routerWith(peerID string) *storage.RouterLease {
	for i := range s.ActiveRouters {
		for _, p := range s.ActiveRouters[i].ConnectedPeers {
			if p == peerID {
				return &s.ActiveRouters[i]
			}
		}
	}
	return nil
}

// waitForPeerOnRouter returns the lease of the router peerID is connected
// to, as the control plane learns it from the router's lease renewals.
func waitForPeerOnRouter(t *testing.T, cpPort int, adminToken string, peerID string, timeout time.Duration) *storage.RouterLease {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if lease := fetchAdminStatus(t, cpPort, adminToken).routerWith(peerID); lease != nil {
			return lease
		}
		if time.Now().After(deadline) {
			t.Fatalf("no router on control plane :%d reported %s connected within %v", cpPort, peerID, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func fetchPeerID(t *testing.T, port int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		var peerID string
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/info", port))
		if err == nil {
			bodyBytes, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err == nil {
				var info api.ControlPlaneInfoResponse
				if err := proto.Unmarshal(bodyBytes, &info); err == nil {
					if len(info.RouterAddresses) > 0 {
						peerID = extractPeerID(info.RouterAddresses[0])
					}
				}
			}
		}

		if peerID != "" {
			return peerID
		}

		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for router lease registration on /info: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func extractPeerID(maddrStr string) string {
	parts := strings.Split(maddrStr, "/")
	for i, part := range parts {
		if part == "p2p" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func waitForDHTReady(t *testing.T, clientBin string, apiPort int, token string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	cmdArgs := []string{
		"-url", fmt.Sprintf("http://127.0.0.1:%d/mcp", apiPort),
		"-token", token,
		"-tool", "get_mesh_info",
		"-args", `{}`,
	}

	for time.Now().Before(deadline) {
		cmd := exec.Command(clientBin, cmdArgs...)
		out, err := cmd.Output()
		if err == nil {
			if strings.Contains(string(out), `"dht_size":`) && !strings.Contains(string(out), `"dht_size":0`) {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("DHT not ready on port %d", apiPort)
}

func waitForControlPlane(t *testing.T, port int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var lastErr error
	var lastStatus int
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/info", port))
		if err == nil {
			lastStatus = resp.StatusCode
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = nil
		} else {
			lastErr = err
			lastStatus = 0
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				t.Fatalf("timed out waiting for control plane /info: last error: %v", lastErr)
			}
			t.Fatalf("timed out waiting for control plane /info: last HTTP status %d", lastStatus)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func writePolicyWithRouter(t *testing.T, path string, yamlContent string) {
	t.Helper()
	content := yamlContent

	// Replace empty markers first
	content = strings.ReplaceAll(content, "bindings: []", "bindings:")
	content = strings.ReplaceAll(content, "roles: []", "roles:")

	routerRole := fmt.Sprintf(`  - name: %s
    allowed_services: []
    allowed_targets: ["*"]
  - name: %s
    allowed_services: []
    allowed_targets: []`, api.RoleRouter, api.RoleNode)
	routerBinding := fmt.Sprintf(`  - role: %s
    members: ["group:routers"]`, api.RoleRouter)

	if strings.Contains(content, "roles:") {
		content = strings.Replace(content, "roles:", "roles:\n"+routerRole, 1)
	} else {
		content += "\nroles:\n" + routerRole
	}

	if strings.Contains(content, "bindings:") {
		content = strings.Replace(content, "bindings:", "bindings:\n"+routerBinding, 1)
	} else {
		content += "\nbindings:\n" + routerBinding
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// injectPolicyYAML posts a policy fixture through the same conversion the console
// performs: YAML for readability, protojson on the wire. Going through JSON keeps
// this helper free of any field list, so a new PolicyRole field needs no change
// here and cannot be silently dropped.
func injectPolicyYAML(t *testing.T, port int, adminToken string, policyFile string) {
	t.Helper()

	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("failed to read policy file %s: %v", policyFile, err)
	}

	var doc interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal policy file %s: %v", policyFile, err)
	}

	jsonData, err := json.Marshal(yamlToJSON(doc))
	if err != nil {
		t.Fatalf("failed to convert policy file %s to JSON: %v", policyFile, err)
	}

	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/policies", port), bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to POST policy to control plane: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected POST /policies status: %s (body: %s)", resp.Status, string(body))
	}
}

// yamlToJSON rewrites the map[interface{}]interface{} that yaml.v2 produces into
// the map[string]interface{} encoding/json requires.
func yamlToJSON(v interface{}) interface{} {
	switch typed := v.(type) {
	case map[interface{}]interface{}:
		converted := make(map[string]interface{}, len(typed))
		for key, value := range typed {
			converted[fmt.Sprintf("%v", key)] = yamlToJSON(value)
		}
		return converted
	case []interface{}:
		for i, value := range typed {
			typed[i] = yamlToJSON(value)
		}
		return typed
	default:
		return v
	}
}

func waitForDiscoverableService(t *testing.T, apiAddr, token, svcType, svcName string) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet,
			"http://"+apiAddr+"/sam/service/discover?type="+svcType+"&name="+svcName, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set(api.HeaderSamAuthentication, "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var providers []*api.DiscoveredProvider
			decodeErr := json.NewDecoder(resp.Body).Decode(&providers)
			_ = resp.Body.Close()
			if decodeErr == nil && len(providers) > 0 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s://%s to be discoverable", svcType, svcName)
}

func newBoundaryMCPHandler(t *testing.T) http.Handler {
	t.Helper()

	srv := mcp.NewServer(&mcp.Implementation{Name: "calc", Version: "0.0.1"}, nil)
	srv.AddTool(&mcp.Tool{
		Name:        "add",
		Description: "add two numbers",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "fake-result:add"}},
		}, nil
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
}
