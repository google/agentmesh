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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/controlplane"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// sdkConformanceReport is what sdk/js/src/conformance.ts and
// sdk/python/src/agent_mesh/conformance.py print after enrolling, reloading
// from disk and refreshing against the control plane this test runs.
type sdkConformanceReport struct {
	SDK                 string   `json:"sdk"`
	PeerID              string   `json:"peer_id"`
	PublicKey           string   `json:"public_key"`
	Biscuit             string   `json:"biscuit"`
	Expiration          int64    `json:"expiration"`
	ControlPlaneKeys    []string `json:"control_plane_keys"`
	RouterAddresses     []string `json:"router_addresses"`
	ReloadedPeerID      string   `json:"reloaded_peer_id"`
	RefreshedBiscuit    string   `json:"refreshed_biscuit"`
	RefreshedExpiration int64    `json:"refreshed_expiration"`
	AuthFrame           string   `json:"auth_frame"`
}

// sdkRunner is how to start one SDK's conformance runner, or why it cannot
// run here. The SDKs are not Go and are not built by `go test`, so a
// missing toolchain skips rather than fails; CI installs both.
type sdkRunner struct {
	name string
	cmd  func(root string) (*exec.Cmd, string)
}

var sdkRunners = []sdkRunner{
	{
		name: "js",
		cmd: func(root string) (*exec.Cmd, string) {
			entry := filepath.Join(root, "sdk", "js", "dist", "conformance.js")
			if _, err := exec.LookPath("node"); err != nil {
				return nil, "node is not installed"
			}
			if _, err := os.Stat(entry); err != nil {
				return nil, "sdk/js is not built (cd sdk/js && npm ci && npm run build)"
			}
			return exec.Command("node", entry), ""
		},
	},
	{
		name: "python",
		cmd: func(root string) (*exec.Cmd, string) {
			python := filepath.Join(root, "sdk", "python", ".venv", "bin", "python")
			if _, err := os.Stat(python); err != nil {
				var lookErr error
				if python, lookErr = exec.LookPath("python3"); lookErr != nil {
					return nil, "python3 is not installed"
				}
			}
			if err := exec.Command(python, "-c", "import agent_mesh").Run(); err != nil {
				return nil, "agent_mesh is not importable (pip install -e sdk/python)"
			}
			return exec.Command(python, "-m", "agent_mesh.conformance"), ""
		},
	},
}

// TestNativeSDKs is the interoperability check for the native SDKs: each one
// enrolls a fresh identity over the mesh protocol (protobuf over HTTP,
// signed proof-of-possession challenges) with a real control plane in
// manual-approval mode, polls /enroll/status until this test approves it,
// reloads its state from disk, refreshes its biscuit and reports what it
// holds. The control plane's own verification of every request is the
// judge; this test then checks that what the SDK holds is what the control
// plane issued and bound to the peer ID the SDK derived.
func TestNativeSDKs(t *testing.T) {
	root := repoRoot(t)
	oidcURL, _ := startCustomMockOIDC(t)

	store, err := storage.NewSQLStore("sqlite", filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	const adminToken = "test-admin-token"
	srv, err := controlplane.NewServer(controlplane.Options{
		ListenAddr:            "127.0.0.1:0",
		AdminToken:            adminToken,
		OIDCIssuer:            oidcURL,
		AllowedAudiences:      []string{"sam-mesh-audience"},
		AutoApproveEnrollment: false,
	}, store)
	if err != nil {
		t.Fatalf("failed to create control plane: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	baseURL := "http://" + srv.Addr()

	ctx := context.Background()
	_, cpPub, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("failed to load control plane signing key: %v", err)
	}

	// A router lease is what puts router addresses in an approved enrollment.
	routerAddr := "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWP8iKhDf3iCMo2H3butNVfdTUtYwYWYQ75jTGnynXPFMp"
	if err := store.UpsertRouterLease(ctx, &storage.RouterLease{
		PeerID:      "12D3KooWP8iKhDf3iCMo2H3butNVfdTUtYwYWYQ75jTGnynXPFMp",
		Addresses:   []string{routerAddr},
		LastRenewal: time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("failed to register router lease: %v", err)
	}

	for _, runner := range sdkRunners {
		t.Run(runner.name, func(t *testing.T) {
			cmd, skip := runner.cmd(root)
			if skip != "" {
				t.Skipf("%s SDK: %s", runner.name, skip)
			}

			tokenPath := filepath.Join(t.TempDir(), "bootstrap.token")
			if err := os.WriteFile(tokenPath, []byte(mintBootstrapToken(t, baseURL, adminToken)+"\n"), 0o600); err != nil {
				t.Fatalf("failed to write bootstrap token: %v", err)
			}
			stateDir := filepath.Join(t.TempDir(), "state")

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			cmd.Dir = root
			cmd.Env = append(os.Environ(),
				"SAM_CONTROL_PLANE_URL="+baseURL,
				"SAM_BOOTSTRAP_TOKEN_PATH="+tokenPath,
				"SAM_SDK_STATE_DIR="+stateDir,
			)
			if err := cmd.Start(); err != nil {
				t.Fatalf("failed to start %s runner: %v", runner.name, err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()

			// The runner is now polling /enroll/status with signed challenges.
			// Approve it the way an operator would.
			peerID := approvePendingEnrollment(t, baseURL, adminToken, done)

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("%s runner failed: %v\nstdout:\n%s\nstderr:\n%s", runner.name, err, stdout.String(), stderr.String())
				}
			case <-time.After(8 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("%s runner did not finish after approval\nstdout:\n%s\nstderr:\n%s", runner.name, stdout.String(), stderr.String())
			}

			var report sdkConformanceReport
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("%s runner printed no report: %v\nstdout:\n%s\nstderr:\n%s", runner.name, err, stdout.String(), stderr.String())
			}
			verifySDKReport(t, ctx, store, cpPub, peerID, routerAddr, &report)

			// The state directory holds the identity in the encoding sam-node
			// uses and nothing world-readable.
			keyBytes, err := os.ReadFile(filepath.Join(stateDir, "identity.key"))
			if err != nil {
				t.Fatalf("identity.key not written: %v", err)
			}
			priv, err := crypto.UnmarshalPrivateKey(keyBytes)
			if err != nil {
				t.Fatalf("identity.key is not a libp2p private key: %v", err)
			}
			if fromKey, _ := peer.IDFromPrivateKey(priv); fromKey != peerID {
				t.Fatalf("identity.key belongs to %s, report says %s", fromKey, peerID)
			}
			for _, name := range []string{"identity.key", "credential.json"} {
				info, err := os.Stat(filepath.Join(stateDir, name))
				if err != nil {
					t.Fatalf("%s not written: %v", name, err)
				}
				if mode := info.Mode().Perm(); mode != 0o600 {
					t.Errorf("%s has mode %o, want 0600", name, mode)
				}
			}
		})
	}
}

// verifySDKReport checks a runner's report against the control plane's
// records: the peer ID is the one the control plane bound, both biscuits
// verify under the control plane key for that peer with the node role, the
// refresh was persisted server-side, and the AuthFrame the SDK would open a
// stream with carries the refreshed biscuit.
func verifySDKReport(t *testing.T, ctx context.Context, store storage.Store, cpPub ed25519.PublicKey, peerID peer.ID, routerAddr string, report *sdkConformanceReport) {
	t.Helper()
	if report.PeerID != peerID.String() {
		t.Fatalf("report peer_id %s, control plane enrolled %s", report.PeerID, peerID)
	}
	if report.ReloadedPeerID != report.PeerID {
		t.Errorf("identity did not survive reload: %s vs %s", report.ReloadedPeerID, report.PeerID)
	}

	// The SDK's peer ID derivation, checked from the raw key with go-libp2p.
	rawPub, err := hex.DecodeString(report.PublicKey)
	if err != nil || len(rawPub) != ed25519.PublicKeySize {
		t.Fatalf("report public_key is not a raw ed25519 key: %q", report.PublicKey)
	}
	pub, err := crypto.UnmarshalEd25519PublicKey(rawPub)
	if err != nil {
		t.Fatalf("report public_key does not unmarshal: %v", err)
	}
	if derived, _ := peer.IDFromPublicKey(pub); derived != peerID {
		t.Errorf("peer ID %s does not derive from the reported public key (got %s)", peerID, derived)
	}

	node, err := store.GetNode(ctx, peerID.String())
	if err != nil {
		t.Fatalf("control plane has no node record for %s: %v", peerID, err)
	}
	if libp2pPub, _ := crypto.MarshalPublicKey(pub); !bytes.Equal(node.PublicKey, libp2pPub) {
		t.Errorf("control plane stored public key %x, SDK holds %x", node.PublicKey, libp2pPub)
	}
	if node.Role != api.RoleNode {
		t.Errorf("node enrolled with role %q, want %q", node.Role, api.RoleNode)
	}

	const biscuitTimeout = 5 * time.Second
	biscuit := decodeB64(t, "biscuit", report.Biscuit)
	refreshed := decodeB64(t, "refreshed_biscuit", report.RefreshedBiscuit)
	for name, b := range map[string][]byte{"biscuit": biscuit, "refreshed_biscuit": refreshed} {
		if _, err := identity.VerifyBiscuitAndGetExpiry(b, peerID, []ed25519.PublicKey{cpPub}, biscuitTimeout); err != nil {
			t.Errorf("%s does not verify for %s under the control plane key: %v", name, peerID, err)
		}
		if err := identity.VerifyBiscuitRole(b, cpPub, api.RoleNode, biscuitTimeout); err != nil {
			t.Errorf("%s lacks role %s: %v", name, api.RoleNode, err)
		}
	}
	if bytes.Equal(biscuit, refreshed) {
		t.Error("refresh returned the same biscuit")
	}
	// Only the last issued biscuit is redeemable, so the control plane must
	// hold the refreshed one, and that is what the SDK must present next.
	if !bytes.Equal(node.Biscuit, refreshed) {
		t.Error("control plane's current biscuit for the node is not the refreshed one the SDK holds")
	}
	if report.RefreshedExpiration <= time.Now().Unix() || report.Expiration <= time.Now().Unix() {
		t.Errorf("expirations are not in the future: %d, %d", report.Expiration, report.RefreshedExpiration)
	}

	if len(report.ControlPlaneKeys) == 0 || !containsHex(report.ControlPlaneKeys, cpPub) {
		t.Errorf("control_plane_keys %v does not include the signing key %x", report.ControlPlaneKeys, cpPub)
	}
	if len(report.RouterAddresses) != 1 || report.RouterAddresses[0] != routerAddr {
		t.Errorf("router_addresses %v, want [%s]", report.RouterAddresses, routerAddr)
	}

	var frame api.AuthFrame
	if err := proto.Unmarshal(decodeB64(t, "auth_frame", report.AuthFrame), &frame); err != nil {
		t.Fatalf("auth_frame is not an AuthFrame: %v", err)
	}
	if !bytes.Equal(frame.Biscuit, refreshed) {
		t.Error("auth_frame does not carry the refreshed biscuit")
	}
	if frame.TargetService != "mcp://echo" {
		t.Errorf("auth_frame target = %q", frame.TargetService)
	}
}

func mintBootstrapToken(t *testing.T, baseURL, adminToken string) string {
	t.Helper()
	body, err := json.Marshal(api.BootstrapTokenRequest{
		Role:        api.RoleNode,
		TTLHours:    1,
		MaxUsages:   1,
		Description: "native sdk conformance",
	})
	if err != nil {
		t.Fatalf("failed to encode bootstrap token request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/admin/bootstrap-tokens", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build bootstrap token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("failed to create bootstrap token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status creating token: %s body %s", resp.Status, msg)
	}
	var token struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil || token.Token == "" {
		t.Fatalf("failed to decode bootstrap token: %v", err)
	}
	return token.Token
}

// approvePendingEnrollment waits for the runner's enrollment request to
// appear, approves it and returns the peer ID the control plane bound. done
// reports a runner that gave up before that.
func approvePendingEnrollment(t *testing.T, baseURL, adminToken string, done <-chan error) peer.ID {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("runner exited before its enrollment was approved: %v", err)
		default:
		}
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/admin/enrollments", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var pending []storage.EnrollmentRequest
		decodeErr := json.NewDecoder(resp.Body).Decode(&pending)
		_ = resp.Body.Close()
		if decodeErr != nil || resp.StatusCode != http.StatusOK {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		for _, e := range pending {
			if e.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
				continue
			}
			approve, _ := http.NewRequest(http.MethodPost, baseURL+"/admin/enrollments/"+e.ID+"/approve", nil)
			approve.Header.Set("Authorization", "Bearer "+adminToken)
			approveResp, err := client.Do(approve)
			if err != nil {
				t.Fatalf("failed to approve enrollment: %v", err)
			}
			msg, _ := io.ReadAll(approveResp.Body)
			_ = approveResp.Body.Close()
			if approveResp.StatusCode != http.StatusOK {
				t.Fatalf("failed to approve enrollment: %s body %s", approveResp.Status, msg)
			}
			pid, err := peer.Decode(e.PeerID)
			if err != nil {
				t.Fatalf("control plane recorded an undecodable peer ID %q: %v", e.PeerID, err)
			}
			return pid
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("runner's enrollment request never appeared")
	return ""
}

func decodeB64(t *testing.T, field, value string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(b) == 0 {
		t.Fatalf("report %s is not base64 or is empty: %q", field, value)
	}
	return b
}

func containsHex(values []string, want []byte) bool {
	for _, v := range values {
		if strings.EqualFold(v, hex.EncodeToString(want)) {
			return true
		}
	}
	return false
}
