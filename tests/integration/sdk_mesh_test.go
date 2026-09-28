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
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/controlplane"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// sdkMesh is the real mesh the SDK tests run against: a control plane
// publishing gossip events, a sam-router, and a sam-node serving the MCP
// service "calc" from a backend the test runs.
type sdkMesh struct {
	root       string
	store      *storage.SQLStore
	publisher  *controlplane.P2PMeshAdapter
	baseURL    string
	adminToken string
	cpPort     int
	cpPriv     ed25519.PrivateKey
	cpPub      ed25519.PublicKey
	routerAddr string
	routerPeer string
	// routerAddrs lists every router; routerAddr is one of them, for tests
	// that need a router. The control plane hands them out in a random order
	// per response, so members spread across them.
	routerAddrs []string
	samNode     *backgroundNode
	nodeAPI     string
	// egressSeen records what sdkMeshEgressHost received: the node presents
	// sdkMeshEgressCredential to it and nothing of the caller.
	egressSeen func() []*http.Request
	// mintToken mints an OIDC token the control plane accepts, as a platform's
	// workload identity token would be.
	mintToken func(map[string]interface{}) string
}

// sdkMeshLabels is what every provider in the mesh attests, the node and the
// SDK members alike: the inputs of the "any-of requirement matches one key"
// case of internal/node/labels_gate_test.go, so the caller-side check can be
// run against a real credential from every implementation.
var sdkMeshLabels = map[string]string{"region": "na-us", "team": "platform"}

// The egress destination the sam-node serves, assigned to it by label, and
// the credential the platform delivered to the node's host for it.
const (
	sdkMeshEgressHost       = "api.example.test"
	sdkMeshEgressCredential = "ghp_node_secret"
)

// sdkMeshLabelRequirements are the caller requirements the matrix runs against
// sdkMeshLabels: one pair of two matches, so a requirement is met by any of its
// pairs (api.LabelCheck joins them with `or`); none of the pairs matches, so
// it is refused; one pair that matches; the coarser value of a finer claim, so
// there is no hierarchy.
var sdkMeshLabelRequirements = []struct {
	name     string
	required map[string]string
	allowed  bool
}{
	{"any-of requirement matches one key", map[string]string{"region": "eu", "team": "platform"}, true},
	{"disjoint labels fail", map[string]string{"region": "eu", "team": "sre"}, false},
	{"exact match", map[string]string{"team": "platform"}, true},
	{"no built-in hierarchy", map[string]string{"region": "na"}, false},
}

const sdkMeshAdminToken = "test-admin-token"

func startSDKMesh(t *testing.T) *sdkMesh {
	t.Helper()
	root := repoRoot(t)
	oidcURL, mintToken := startCustomMockOIDC(t)
	var egressMu sync.Mutex
	var egressSeen []*http.Request

	store, err := storage.NewSQLStore("sqlite", filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv, err := controlplane.NewServer(controlplane.Options{
		ListenAddr:            "127.0.0.1:0",
		AdminToken:            sdkMeshAdminToken,
		OIDCIssuer:            oidcURL,
		AllowedAudiences:      []string{"sam-mesh-audience"},
		AutoApproveEnrollment: true,
	}, store)
	if err != nil {
		t.Fatalf("failed to create control plane: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	baseURL := "http://" + srv.Addr()
	_, portStr, _ := net.SplitHostPort(srv.Addr())
	cpPort, _ := strconv.Atoi(portStr)

	// Bans and rotations reach the mesh as gossip events through the routers,
	// as the sam-control-plane binary publishes them.
	publisher, err := controlplane.NewMeshPublisher(context.Background(), store, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to start mesh event publisher: %v", err)
	}
	t.Cleanup(func() { _ = publisher.Close() })
	srv.SetMeshAdapter(publisher)

	// The router enrolls through OIDC with group "routers" and the node with
	// user mock-user. Every member holds the node role, which may reach any
	// service on any target and declare the two labels the matrix uses; the
	// SDK members get it from their bootstrap token and the node from its
	// binding. The node alone carries team=platform, which is what selects it
	// to serve the egress destination.
	egress := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		egressMu.Lock()
		egressSeen = append(egressSeen, r.Clone(context.Background()))
		egressMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(egress.Close)
	policyFile := filepath.Join(t.TempDir(), "policy.yaml")
	policy := fmt.Sprintf(`roles:
  - name: %s
    allowed_services: []
    allowed_targets: ["*"]
  - name: %s
    allowed_services: ["*"]
    allowed_targets: ["*"]
    allowed_labels: ["region=*", "team=*"]
bindings:
  - role: %s
    members: ["group:routers"]
  - role: %s
    members: ["user:mock-user"]
egress:
  - name: %s
    target_url: %q
    credential: github
    served_by: ["team=platform"]
`, api.RoleRouter, api.RoleNode, api.RoleRouter, api.RoleNode, sdkMeshEgressHost, egress.URL)
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	injectPolicyYAML(t, cpPort, sdkMeshAdminToken, policyFile)

	// Two routers, as the testnets run several: a member authenticates with
	// every one and reserves a relay slot on the first the control plane
	// lists for it, a different one from member to member.
	routerA, _ := startRouter(t, t.TempDir(), cpPort, mintToken, "router-a")
	routerB, _ := startRouter(t, t.TempDir(), cpPort, mintToken, "router-b")
	routerAddrs := []string{routerA, routerB}
	routerAddr := routerA

	cpPriv, cpPub, err := store.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("failed to load control plane signing key: %v", err)
	}

	// The Go node: a sam-node enrolled through OIDC, listening on loopback,
	// serving the MCP service "calc" from a backend this test runs.
	backend := httptest.NewServer(newBoundaryMCPHandler(t))
	t.Cleanup(backend.Close)
	nodeBin := buildBinary(t, "./cmd/sam-node")
	nodeHome := filepath.Join(t.TempDir(), "node")
	if err := os.MkdirAll(nodeHome, 0o755); err != nil {
		t.Fatal(err)
	}
	secrets := filepath.Join(nodeHome, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "github"), []byte(sdkMeshEgressCredential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	samNode := launchNode(t, nodeBin,
		append(os.Environ(), "HOME="+nodeHome, "XDG_CONFIG_HOME="+filepath.Join(nodeHome, ".config")),
		nodeHome, "run",
		"--control-plane", baseURL,
		"--jwt", mintToken(map[string]interface{}{"sub": "mock-user", "roles": []string{api.RoleNode}}),
		"--allow-loopback",
		"--api-token-path", tokenPath(t, "node-token"),
		"--discovery-interval", "100ms",
		"--config", writeNodeConfig(t, nodeHome, sdkMeshLabels, svcDecl{Type: "mcp", Name: "calc", TargetURL: backend.URL}),
		"--secrets-dir", secrets,
		"--log-level", "debug",
	)
	return &sdkMesh{
		root:        root,
		store:       store,
		publisher:   publisher,
		baseURL:     baseURL,
		adminToken:  sdkMeshAdminToken,
		cpPort:      cpPort,
		cpPriv:      cpPriv,
		cpPub:       cpPub,
		routerAddr:  routerAddr,
		routerPeer:  extractPeerID(routerAddr),
		routerAddrs: routerAddrs,
		samNode:     samNode,
		nodeAPI:     samNode.waitForAPI(t),
		egressSeen: func() []*http.Request {
			egressMu.Lock()
			defer egressMu.Unlock()
			return append([]*http.Request(nil), egressSeen...)
		},
		mintToken: mintToken,
	}
}

// sdkMember is a running SDK conformance-join runner: a mesh member written
// in another language that the test drives over stdin/stdout. Both runners
// (sdk/js/src/conformance-join.ts, sdk/python/src/agent_mesh/conformance_join.py)
// speak the same line protocol.
type sdkMember struct {
	name   string
	report sdkJoinReport
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  *bufio.Scanner
	stderr *bytes.Buffer
}

// sdkJoinReport is the first line a runner prints once on the mesh.
type sdkJoinReport struct {
	SDK     string `json:"sdk"`
	PeerID  string `json:"peer_id"`
	Routers []struct {
		PeerID string   `json:"peer_id"`
		Addr   string   `json:"addr"`
		Roles  []string `json:"roles"`
	} `json:"routers"`
	RelayAddresses  []string `json:"relay_addresses"`
	DirectAddresses []string `json:"direct_addresses"`
	Biscuit         string   `json:"biscuit"`
}

// sdkAuthResult answers an {"cmd":"auth"} command.
type sdkAuthResult struct {
	OK         bool              `json:"ok"`
	Error      string            `json:"error"`
	PeerID     string            `json:"peer_id"`
	Roles      []string          `json:"roles"`
	Labels     map[string]string `json:"labels"`
	Expiration int64             `json:"expiration"`
}

var sdkMemberLaunchers = []sdkRunner{
	{
		name: "js",
		cmd: func(root string) (*exec.Cmd, string) {
			entry := filepath.Join(root, "sdk", "js", "dist", "conformance-join.js")
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
			if err := exec.Command(python, "-c", "import agent_mesh.session").Run(); err != nil {
				return nil, "agent_mesh is not importable with libp2p (pip install -e sdk/python)"
			}
			return exec.Command(python, "-m", "agent_mesh.conformance_join"), ""
		},
	},
}

// TestNativeSDKsMesh runs one mesh: a control plane, a sam-router, a
// sam-node serving an MCP service, and one member per SDK, all real. It
// then walks the connectivity matrix. Every member authenticates with the
// router and gets a relay reservation, which the router grants only to
// admitted peers. Each SDK member reaches the sam-node directly and the
// other SDK member both directly and through the router, and on every path
// both ends verify each other's credential with the /sam/auth/1.0.0
// handshake. The sam-node reaches each SDK member through the router. A Go
// peer that is itself admitted does the same and also checks that a forged
// credential gets no answer. Then each SDK member discovers the sam-node's
// service in the DHT, lists and calls its tools over /sam/mcp/1.0.0 through
// the router, reads the node's own catalog, and is refused a service the
// node does not have. Every member and the sam-node attest the same labels,
// and the caller-side label requirement is run as one matrix from each SDK
// against the node and from the node against each SDK agent, so the three
// implementations agree on what a requirement of several pairs means. Then
// each SDK member accepts A2A requests for its
// agent: the sam-node reaches it by peer ID through its egress proxy
// (/sam/<peer>/a2a/agent/...), the other SDK member does the same over the
// mesh, the agent is in no discovery table, the member speaks no
// /sam/mcp/1.0.0, and a Go peer holding a role the policy grants nothing is
// refused with 403. Any SDK whose toolchain is missing is skipped, and the
// matrix shrinks to the members present.
func TestNativeSDKsMesh(t *testing.T) {
	mesh := startSDKMesh(t)
	root, baseURL, adminToken, cpPort := mesh.root, mesh.baseURL, mesh.adminToken, mesh.cpPort
	routerAddr, cpPriv, cpPub := mesh.routerAddr, mesh.cpPriv, mesh.cpPub
	store, publisher, samNode, nodeAPI := mesh.store, mesh.publisher, mesh.samNode, mesh.nodeAPI
	const serviceName = "calc"
	ctx := context.Background()

	// One member per SDK, each listening directly on loopback too so both
	// the direct and the relayed path can be walked.
	var members []*sdkMember
	for _, launcher := range sdkMemberLaunchers {
		cmd, skip := launcher.cmd(root)
		if skip != "" {
			t.Logf("%s SDK skipped: %s", launcher.name, skip)
			continue
		}
		members = append(members, startSDKMember(t, launcher.name, cmd, root, baseURL, adminToken, mesh.routerAddrs))
	}
	if len(members) == 0 {
		t.Skip("no SDK toolchain available; see sdk/README.md")
	}

	// The router reports every member connected to the control plane.
	waitForPeerOnRouter(t, cpPort, adminToken, samNode.peerID.String(), 5*time.Second)
	for _, m := range members {
		waitForPeerOnRouter(t, cpPort, adminToken, m.report.PeerID, 5*time.Second)
	}

	goPeer := newAdmittedGoPeer(t, ctx, cpPriv, mesh.routerAddrs)

	for _, m := range members {
		m := m
		t.Run(m.name, func(t *testing.T) {
			// SDK -> sam-node, directly: the node's HandleAuthHandshake
			// verifies the member's biscuit and answers with its own.
			nodeCred := m.auth(t, samNode.p2pAddr)
			if nodeCred.PeerID != samNode.peerID.String() || !contains(nodeCred.Roles, api.RoleNode) {
				t.Fatalf("%s verified the node as %+v", m.name, nodeCred)
			}
			if !strings.Contains(samNode.log(), "Successfully authenticated peer "+m.report.PeerID) {
				t.Errorf("sam-node log does not record admitting %s", m.report.PeerID)
			}

			// sam-node -> SDK, through the router: the node reaches the member
			// on its relayed address, which the router only serves for
			// authenticated peers on both ends.
			connectPeerWithToken(t, nodeAPI, "node-token", m.report.RelayAddresses[0])

			// SDK -> every other SDK, directly and through the router.
			for _, other := range members {
				if other == m {
					continue
				}
				for _, addr := range []string{pickDirectAddr(t, other.report.DirectAddresses, other.report.PeerID), other.report.RelayAddresses[0]} {
					cred := m.auth(t, addr)
					if cred.PeerID != other.report.PeerID || !contains(cred.Roles, api.RoleNode) {
						t.Fatalf("%s verified %s at %s as %+v", m.name, other.name, addr, cred)
					}
				}
			}

			// Go peer -> SDK, through the router, both ways of the handshake.
			target := multiaddr.StringCast(m.report.RelayAddresses[0])
			sdkPeer, _ := peer.Decode(m.report.PeerID)
			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := goPeer.Connect(dialCtx, peer.AddrInfo{ID: sdkPeer, Addrs: []multiaddr.Multiaddr{target}}); err != nil {
				t.Fatalf("go peer could not reach %s at %s: %v", m.name, target, err)
			}
			memberBiscuit := authHandshake(t, ctx, goPeer, sdkPeer, goHostBiscuit(t, cpPriv, goPeer.ID()))
			if _, err := identity.VerifyBiscuitAndGetExpiry(memberBiscuit, sdkPeer, []ed25519.PublicKey{cpPub}, 5*time.Second); err != nil {
				t.Fatalf("%s answered with a credential that does not verify: %v", m.name, err)
			}
			if err := identity.VerifyBiscuitRole(memberBiscuit, cpPub, api.RoleNode, 5*time.Second); err != nil {
				t.Fatalf("%s credential lacks the node role: %v", m.name, err)
			}
			if want, _ := base64.StdEncoding.DecodeString(m.report.Biscuit); !bytes.Equal(want, memberBiscuit) {
				t.Fatal("member answered with a different biscuit than it reported holding")
			}
			refuseForgedFrame(t, ctx, goPeer, sdkPeer)

			// A peer that is not on the mesh cannot be reached: the address
			// names an unknown peer behind the router.
			stranger, _ := peer.Decode("12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB")
			if res := m.authRaw(t, routerAddr+"/p2p-circuit/p2p/"+stranger.String()); res.OK {
				t.Fatalf("%s reached a peer that is not on the mesh", m.name)
			}

			// Services. The node advertises calc in the DHT once its backend
			// answered a probe; the member finds it there and calls it through
			// the router, the way sam-node's call_remote_tool would.
			providers := m.discoverUntil(t, "mcp", serviceName, samNode.peerID.String(), 20*time.Second)
			if len(providers) != 1 {
				t.Fatalf("%s discovered %+v for %s, want only the node", m.name, providers, serviceName)
			}
			// By peer ID: the node reserved on a router of its choosing, and
			// the member finds the relayed path through whichever of the
			// routers it joined through relays for the node.
			nodeRelayAddr := samNode.peerID.String()
			if tools := m.tools(t, nodeRelayAddr, "mcp://"+serviceName); !contains(tools, "add") {
				t.Fatalf("%s listed %v on mcp://%s, want add", m.name, tools, serviceName)
			}
			if res := m.call(t, nodeRelayAddr, "mcp://"+serviceName, "add", map[string]any{"a": 1, "b": 2}); res.IsError || !contains(res.Text, "fake-result:add") {
				t.Fatalf("%s calling add: %+v", m.name, res)
			}
			// The node's own catalog is the empty target.
			if tools := m.tools(t, samNode.p2pAddr, ""); !contains(tools, "list_local_services") {
				t.Fatalf("%s listed %v on the node's catalog", m.name, tools)
			}
			if res := m.call(t, samNode.p2pAddr, "", "list_local_services", nil); res.IsError || !strings.Contains(strings.Join(res.Text, "\n"), serviceName) {
				t.Fatalf("%s list_local_services: %+v", m.name, res)
			}
			// A service the node does not have gets the stream closed on it.
			if res := m.callRaw(t, nodeRelayAddr, "mcp://no-such-service", "add", nil); res.OK {
				t.Fatalf("%s called a service the node does not serve: %+v", m.name, res)
			}
		})
	}

	// The caller-side label requirement means the same thing in every
	// implementation: a requirement of several pairs is met by any one of
	// them, none of them is a refusal, and a value is matched whole. The node
	// and every SDK member attest the same labels, so the matrix below runs
	// each requirement from each caller against a credential each provider
	// minted: SDK -> node over /sam/mcp/1.0.0, and node -> SDK through the
	// egress proxy's X-Sam-Required-Labels, which runs checkPeerLabels.
	t.Run("required-labels", func(t *testing.T) {
		for _, m := range members {
			if got := m.auth(t, samNode.p2pAddr).Labels; got["region"] != sdkMeshLabels["region"] || got["team"] != sdkMeshLabels["team"] {
				t.Fatalf("%s sees the node's labels as %v, want %v", m.name, got, sdkMeshLabels)
			}
		}
		for _, tc := range sdkMeshLabelRequirements {
			t.Run(tc.name, func(t *testing.T) {
				nodeRelayAddr := samNode.peerID.String()
				for _, m := range members {
					res := m.toolsRequiring(t, nodeRelayAddr, "mcp://"+serviceName, tc.required)
					if res.OK != tc.allowed {
						t.Errorf("%s requiring %v of the node: ok=%v (%s), want %v", m.name, tc.required, res.OK, res.Error, tc.allowed)
					}
					if !tc.allowed && res.OK == false && !strings.Contains(res.Error, "LabelsNotSatisfied") {
						t.Errorf("%s requiring %v of the node was refused for another reason: %s", m.name, tc.required, res.Error)
					}
				}
			})
		}
	})

	// A member whose egress floor nobody attests is refused before anything is
	// sent, MCP and HTTP alike; the members above carry a floor the mesh does
	// satisfy (launchSDKMember). MCP to an SDK member fails before the floor: no /sam/mcp.
	t.Run("egress-floor", func(t *testing.T) {
		for _, launcher := range sdkMemberLaunchers {
			cmd, skip := launcher.cmd(root)
			if skip != "" {
				continue
			}
			floored := launchSDKMember(t, launcher.name+"-floored", cmd, root, baseURL, adminToken, "SAM_SDK_EGRESS_REQUIRE_LABELS=team=nobody")
			byFloor := func(what, target, err string) {
				if !strings.Contains(err, "LabelsNotSatisfied") {
					t.Errorf("%s %s to %s was not refused by the floor: %q", floored.name, what, target, err)
				}
			}
			nodeRelayAddr := samNode.peerID.String()
			byFloor("tools", "the node", floored.toolsRequiring(t, nodeRelayAddr, "mcp://"+serviceName, nil).Error)
			byFloor("call", "the node", floored.callRaw(t, nodeRelayAddr, "mcp://"+serviceName, "add", nil).Error)
			byFloor("http", "the node", floored.httpRaw(t, nodeRelayAddr, "egress://"+sdkMeshEgressHost, "/").Error)
			for _, m := range members {
				byFloor("http", m.name, floored.httpRaw(t, m.report.PeerID, "a2a://agent", "/card").Error)
				if res := floored.toolsRequiring(t, m.report.PeerID, "mcp://"+serviceName, nil); res.OK {
					t.Errorf("%s listed tools of %s, an SDK member: %v", floored.name, m.name, res.Tools)
				}
				if res := floored.callRaw(t, m.report.PeerID, "mcp://"+serviceName, "add", nil); res.OK {
					t.Errorf("%s called a tool of %s, an SDK member: %+v", floored.name, m.name, res)
				}
			}
			floored.quit(t)
		}
	})

	// Every SDK member is an agent: it accepts A2A requests for a2a://agent,
	// answered in the runner's process, reachable by peer ID through the
	// router. It publishes nothing; the policy rules it evaluates are the
	// ones the control plane renders.
	for _, m := range members {
		m.accept(t, "agent")
	}
	guest := newGuestGoPeer(t, ctx, cpPriv, mesh.routerAddrs)
	for _, m := range members {
		m := m
		t.Run(m.name+"-accepts", func(t *testing.T) {
			sdkPeer, _ := peer.Decode(m.report.PeerID)

			// sam-node -> SDK agent, through the egress proxy: the node
			// verifies the member's credential, then the member authorizes
			// the node's and answers with who called.
			status, body := egressGet(t, nodeAPI, "node-token", "/sam/"+m.report.PeerID+"/a2a/agent/card")
			if status != 200 {
				t.Fatalf("sam-node egress to %s agent: status %d, body %s", m.name, status, body)
			}
			var seen struct {
				SDK  string `json:"sdk"`
				Peer string `json:"peer"`
				Path string `json:"path"`
			}
			if json.Unmarshal([]byte(body), &seen) != nil || seen.SDK != m.name || seen.Peer != samNode.peerID.String() || seen.Path != "/card" {
				t.Fatalf("sam-node egress to %s agent answered %s", m.name, body)
			}

			// The node's caller-side requirement against the member's
			// credential, the same matrix the members ran against the node's.
			for _, tc := range sdkMeshLabelRequirements {
				want := http.StatusForbidden
				if tc.allowed {
					want = http.StatusOK
				}
				status, body := egressGetRequiring(t, nodeAPI, "node-token", "/sam/"+m.report.PeerID+"/a2a/agent/card", tc.required)
				if status != want {
					t.Errorf("sam-node requiring %v of %s (%s): status %d %s, want %d", tc.required, m.name, tc.name, status, strings.TrimSpace(body), want)
				}
			}

			// The agent is not in the discovery table: nothing was announced.
			if providers := m.discoverOnce(t, "a2a", "agent"); len(providers) != 0 {
				t.Fatalf("%s discovered %+v for a2a://agent, want nothing: an agent is not published", m.name, providers)
			}

			// SDK -> SDK: the other member reaches the agent by peer ID
			// through the router, with no lookup.
			for _, other := range members {
				if other == m {
					continue
				}
				res := other.http(t, m.report.PeerID, "a2a://agent", "/card")
				if res.Status != 200 || !strings.Contains(res.Body, other.report.PeerID) {
					t.Fatalf("%s calling a2a://agent on %s: %+v", other.name, m.name, res)
				}
				// Another agent name the policy grants: authorized, then 404.
				if r := other.http(t, m.report.PeerID, "a2a://other", "/card"); r.Status != 404 {
					t.Fatalf("%s calling an agent name %s does not answer: %+v", other.name, m.name, r)
				}
			}

			// An SDK member serves no MCP: the stream is refused at the
			// protocol negotiation, before any frame is read.
			if err := tryMCPStream(ctx, guest, sdkPeer, multiaddr.StringCast(m.report.RelayAddresses[0])); err == nil {
				t.Fatalf("%s accepted a /sam/mcp/1.0.0 stream; an SDK member serves no MCP", m.name)
			}

			// A peer the control plane vouches for, but whose role the policy
			// grants nothing, is refused with 403 on the HTTP path.
			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := guest.Connect(dialCtx, peer.AddrInfo{ID: sdkPeer, Addrs: []multiaddr.Multiaddr{multiaddr.StringCast(m.report.RelayAddresses[0])}}); err != nil {
				t.Fatalf("guest peer could not reach %s: %v", m.name, err)
			}
			if status, _ := libp2pHTTPGet(t, ctx, guest, sdkPeer, guestHostBiscuit(t, cpPriv, guest.ID()), "/a2a/agent/card"); status != 403 {
				t.Fatalf("%s answered a guest's HTTP request with %d, want 403", m.name, status)
			}
			// The same peer with a node-role token is answered: the refusal was the policy, not the peer.
			if status, body := libp2pHTTPGet(t, ctx, guest, sdkPeer, goHostBiscuit(t, cpPriv, guest.ID()), "/a2a/agent/card"); status != 200 || !strings.Contains(body, guest.ID().String()) {
				t.Fatalf("%s answered a node-role HTTP request with %d %s", m.name, status, body)
			}
		})
	}

	// Everyone who ran the handshake against a member is in its admitted set.
	for _, m := range members {
		peers := m.peers(t)
		if !contains(peers, goPeer.ID().String()) {
			t.Errorf("%s admitted peers %v lack the Go peer %s", m.name, peers, goPeer.ID())
		}
		for _, other := range members {
			if other != m && !contains(peers, other.report.PeerID) {
				t.Errorf("%s admitted peers %v lack %s (%s)", m.name, peers, other.name, other.report.PeerID)
			}
		}
	}

	// Control plane state reaches the members while they run. A ban travels
	// as a gossip event through the router and is enforced without a pull;
	// a key rotation lands with the next pull, and a credential that
	// predates it is refreshed under the new key.
	t.Run("ban-and-rotation", func(t *testing.T) {
		// An enrolled peer the control plane can ban: a node record, admitted
		// by every member over the router.
		outcast := newAdmittedGoPeer(t, ctx, cpPriv, mesh.routerAddrs)
		outcastBiscuit := goHostBiscuit(t, cpPriv, outcast.ID())
		outcastPub, err := crypto.MarshalPublicKey(outcast.Peerstore().PubKey(outcast.ID()))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnrollNode(ctx, &storage.EnrolledNode{
			PeerID:         outcast.ID().String(),
			PublicKey:      outcastPub,
			Biscuit:        outcastBiscuit,
			Role:           api.RoleNode,
			EnrollmentType: "BOOTSTRAP",
			EnrolledAt:     time.Now(),
			ExpiresAt:      time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("failed to enroll the outcast: %v", err)
		}
		for _, m := range members {
			sdkPeer, _ := peer.Decode(m.report.PeerID)
			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := outcast.Connect(dialCtx, peer.AddrInfo{ID: sdkPeer, Addrs: []multiaddr.Multiaddr{multiaddr.StringCast(m.report.RelayAddresses[0])}}); err != nil {
				cancel()
				t.Fatalf("outcast could not reach %s: %v", m.name, err)
			}
			cancel()
			authHandshake(t, ctx, outcast, sdkPeer, outcastBiscuit)
			if !contains(m.peers(t), outcast.ID().String()) {
				t.Fatalf("%s did not admit the outcast before the ban", m.name)
			}
		}

		// The operator bans it. The event goes control plane -> router -> members.
		revokeBody, _ := proto.Marshal(&api.TokenRevokeRequest{PeerId: outcast.ID().String()})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/admin/revoke", bytes.NewReader(revokeBody))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/x-protobuf")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /admin/revoke: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /admin/revoke: %s", resp.Status)
		}
		for _, m := range members {
			state := m.bannedUntil(t, outcast.ID().String(), 10*time.Second)
			if contains(state.AuthenticatedPeers, outcast.ID().String()) {
				t.Errorf("%s kept the outcast admitted after the ban", m.name)
			}
			// Its credential still verifies; it is refused all the same.
			sdkPeer, _ := peer.Decode(m.report.PeerID)
			if err := tryAuthHandshake(ctx, outcast, sdkPeer, multiaddr.StringCast(m.report.RelayAddresses[0]), outcastBiscuit); err == nil {
				t.Errorf("%s admitted the banned outcast again", m.name)
			}
			// A pull agrees with the event and does not lift the ban.
			if res := m.sync(t); !contains(res.Banned, outcast.ID().String()) {
				t.Errorf("%s: /info does not list the outcast as banned after the pull: %+v", m.name, res)
			}
		}

		// The control plane rotates its signing key; the retiring key stays
		// valid for its grace period, and the rotation is announced as the
		// sam-control-plane binary announces it. A member learns the new key
		// from the event or from its next pull, and since its credential
		// predates the rotation, refreshes it under the new key.
		newPub, newPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RotateKeys(ctx, newPriv, newPub, time.Hour); err != nil {
			t.Fatalf("RotateKeys: %v", err)
		}
		if err := publisher.PublishEvent(ctx, api.MeshEvent_KEY_ROTATION, "", newPub); err != nil {
			t.Fatalf("publish KEY_ROTATION: %v", err)
		}
		for _, m := range members {
			// Idempotent: the event may already have brought a pull forward.
			res := m.sync(t)
			if !contains(res.TrustedKeys, hex.EncodeToString(newPub)) || !contains(res.TrustedKeys, hex.EncodeToString(cpPub)) {
				t.Fatalf("%s trusts %v after the rotation, want both keys", m.name, res.TrustedKeys)
			}
			if res.Biscuit == m.report.Biscuit {
				t.Fatalf("%s still holds the credential minted before the rotation", m.name)
			}
			fresh, err := base64.StdEncoding.DecodeString(res.Biscuit)
			if err != nil {
				t.Fatal(err)
			}
			sdkPeer, _ := peer.Decode(m.report.PeerID)
			if _, err := identity.VerifyBiscuitAndGetExpiry(fresh, sdkPeer, []ed25519.PublicKey{newPub}, 5*time.Second); err != nil {
				t.Fatalf("%s refreshed credential does not verify under the new key: %v", m.name, err)
			}
			if _, err := identity.VerifyBiscuitAndGetExpiry(fresh, sdkPeer, []ed25519.PublicKey{cpPub}, 5*time.Second); err == nil {
				t.Fatalf("%s refreshed credential still verifies under the retiring key", m.name)
			}
			// The mesh keeps working under the new credential: the sam-node
			// learned the key from the same event.
			deadline := time.Now().Add(10 * time.Second)
			for {
				cred := m.authRaw(t, samNode.p2pAddr)
				if cred.OK && cred.PeerID == samNode.peerID.String() {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s could not authenticate with the node under its refreshed credential: %+v", m.name, cred)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	})

	for _, m := range members {
		m.quit(t)
	}
}

// TestNativeSDKsAcrossRouters is the datapath between two members that joined
// through different routers: one member per SDK on router A and one on router
// B, none with an address of its own, so the relayed path is the only one.
// Every member on one router calls the agent of every member on the other by
// peer ID, over /libp2p-http, and authenticates with it. Which router a peer
// happened to reserve on must not decide whether it can be reached; the
// caller finds the peer through the routers and is admitted by the one that
// relays for it on the way.
func TestNativeSDKsAcrossRouters(t *testing.T) {
	mesh := startSDKMesh(t)
	if len(mesh.routerAddrs) < 2 {
		t.Fatalf("the fixture runs %d router(s), want two", len(mesh.routerAddrs))
	}

	type placed struct {
		*sdkMember
		router string
	}
	var members []placed
	for _, launcher := range sdkMemberLaunchers {
		for _, routerAddr := range mesh.routerAddrs {
			cmd, skip := launcher.cmd(mesh.root)
			if skip != "" {
				t.Logf("%s SDK skipped: %s", launcher.name, skip)
				break
			}
			router := extractPeerID(routerAddr)
			m := launchSDKMember(t, launcher.name+"@"+router[len(router)-6:], cmd, mesh.root, mesh.baseURL, mesh.adminToken, "SAM_SDK_ROUTERS="+router)
			if got := routerIDs(m.report); !reflect.DeepEqual(got, []string{router}) {
				t.Fatalf("%s joined through %v, want %s only", m.name, got, router)
			}
			for _, a := range m.report.RelayAddresses {
				if !strings.HasPrefix(a, routerAddr) {
					t.Fatalf("%s reserved on %s, want %s", m.name, a, routerAddr)
				}
			}
			if len(m.report.DirectAddresses) != 0 {
				t.Fatalf("%s listens on %v, want the relayed path to be the only one", m.name, m.report.DirectAddresses)
			}
			m.accept(t, "agent")
			members = append(members, placed{m, router})
		}
	}
	if len(members) == 0 {
		t.Skip("no SDK toolchain available; see sdk/README.md")
	}
	for _, m := range members {
		waitForPeerOnRouter(t, mesh.cpPort, mesh.adminToken, m.report.PeerID, 5*time.Second)
	}

	// A pair that talked once stays connected, so only the first contact
	// between two members has to find its way through the other router.
	connected := map[[2]string]bool{}
	for _, caller := range members {
		for _, agent := range members {
			if caller.router == agent.router {
				continue
			}
			t.Run(caller.name+"-reaches-"+agent.name, func(t *testing.T) {
				pair := [2]string{caller.report.PeerID, agent.report.PeerID}
				if pair[0] > pair[1] {
					pair[0], pair[1] = pair[1], pair[0]
				}
				firstContact := !connected[pair]
				connected[pair] = true

				// The agent names the verified caller in its answer.
				res := caller.http(t, agent.report.PeerID, "a2a://agent", "/hello")
				if res.Status != 200 || !strings.Contains(res.Body, caller.report.PeerID) {
					t.Fatalf("%s -> %s: %d %s", caller.name, agent.name, res.Status, res.Body)
				}
				verified := caller.auth(t, agent.report.PeerID)
				if verified.PeerID != agent.report.PeerID {
					t.Fatalf("%s authenticated %s, want %s", caller.name, verified.PeerID, agent.report.PeerID)
				}
				// The agent's router admitted the caller on the way and stays admitted.
				if got := caller.routers(t); firstContact && !contains(got, agent.router) {
					t.Fatalf("%s admitted routers %v after reaching a peer on %s", caller.name, got, agent.router)
				}
			})
		}
	}
	for _, m := range members {
		m.quit(t)
	}
}

// routerIDs lists the routers a join report says admitted the member.
func routerIDs(report sdkJoinReport) []string {
	var ids []string
	for _, r := range report.Routers {
		ids = append(ids, r.PeerID)
	}
	return ids
}

func startSDKMember(t *testing.T, name string, cmd *exec.Cmd, root, baseURL, adminToken string, routerAddrs []string) *sdkMember {
	t.Helper()
	m := launchSDKMember(t, name, cmd, root, baseURL, adminToken, "SAM_SDK_LISTEN_ADDRS=/ip4/127.0.0.1/tcp/0")
	// Every router the control plane named admitted the member, in whatever
	// order it was handed them; it reserved on the first of its own list.
	var admitted []string
	for _, r := range m.report.Routers {
		admitted = append(admitted, r.PeerID)
		if !contains(r.Roles, api.RoleRouter) {
			t.Fatalf("%s: router %s credential roles %v lack %s", name, r.PeerID, r.Roles, api.RoleRouter)
		}
	}
	var want []string
	for _, a := range routerAddrs {
		want = append(want, extractPeerID(a))
	}
	sort.Strings(admitted)
	sort.Strings(want)
	if !reflect.DeepEqual(admitted, want) {
		t.Fatalf("%s report routers %v, want every router the control plane listed %v", name, admitted, want)
	}
	if len(m.report.RelayAddresses) == 0 {
		t.Fatalf("%s: no relay address, the router did not grant a reservation", name)
	}
	first := m.report.Routers[0]
	for _, a := range m.report.RelayAddresses {
		if !strings.HasPrefix(a, first.Addr) || !strings.HasSuffix(a, "/p2p-circuit/p2p/"+m.report.PeerID) {
			t.Fatalf("%s relay address %s is not <router>/p2p-circuit/p2p/<self> for its first router %s (%s)", name, a, first.PeerID, first.Addr)
		}
	}
	return m
}

// launchSDKMember starts a conformance-join runner with a fresh bootstrap
// token, the labels the matrix uses and an egress floor every provider in the
// mesh satisfies, plus env (a later entry wins), and reads its join report.
func launchSDKMember(t *testing.T, name string, cmd *exec.Cmd, root, baseURL, adminToken string, env ...string) *sdkMember {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "bootstrap.token")
	if err := os.WriteFile(tokenPath, []byte(mintBootstrapToken(t, baseURL, adminToken)+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write bootstrap token: %v", err)
	}
	cmd.Env = append(append(os.Environ(),
		"SAM_CONTROL_PLANE_URL="+baseURL,
		"SAM_BOOTSTRAP_TOKEN_PATH="+tokenPath,
		"SAM_SDK_STATE_DIR="+filepath.Join(t.TempDir(), "state"),
		"SAM_SDK_LABELS="+labelsEnv(sdkMeshLabels),
		"SAM_SDK_EGRESS_REQUIRE_LABELS=region="+sdkMeshLabels["region"],
	), env...)
	cmd.Dir = root
	m := &sdkMember{name: name, cmd: cmd, stderr: &bytes.Buffer{}}
	cmd.Stderr = m.stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	m.stdin = stdin
	m.lines = bufio.NewScanner(stdout)
	m.lines.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start %s member: %v", name, err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
		if t.Failed() {
			t.Logf("%s member stderr:\n%s", name, m.stderr.String())
		}
	})

	if line := m.readLine(t, 20*time.Second); json.Unmarshal(line, &m.report) != nil {
		t.Fatalf("%s member printed no join report, got: %q", name, line)
	}
	if _, err := peer.Decode(m.report.PeerID); err != nil {
		t.Fatalf("%s report peer_id %q: %v", name, m.report.PeerID, err)
	}
	return m
}

func (m *sdkMember) send(t *testing.T, command map[string]string) []byte {
	t.Helper()
	line, _ := json.Marshal(command)
	if _, err := m.stdin.Write(append(line, '\n')); err != nil {
		t.Fatalf("%s member: write command: %v", m.name, err)
	}
	return m.readLine(t, 20*time.Second)
}

// authRaw asks the member to connect to addr and run the auth handshake.
func (m *sdkMember) authRaw(t *testing.T, addr string) sdkAuthResult {
	t.Helper()
	var res sdkAuthResult
	if line := m.send(t, map[string]string{"cmd": "auth", "addr": addr}); json.Unmarshal(line, &res) != nil {
		t.Fatalf("%s member: auth answered %q", m.name, line)
	}
	return res
}

// auth is authRaw that must succeed.
func (m *sdkMember) auth(t *testing.T, addr string) sdkAuthResult {
	t.Helper()
	res := m.authRaw(t, addr)
	if !res.OK {
		t.Fatalf("%s member could not authenticate with %s: %s", m.name, addr, res.Error)
	}
	if res.Expiration <= time.Now().Unix() {
		t.Fatalf("%s member accepted a credential from %s that is already expired", m.name, addr)
	}
	return res
}

func (m *sdkMember) peers(t *testing.T) []string {
	t.Helper()
	var res struct {
		AuthenticatedPeers []string `json:"authenticated_peers"`
	}
	if line := m.send(t, map[string]string{"cmd": "peers"}); json.Unmarshal(line, &res) != nil {
		t.Fatalf("%s member: peers answered %q", m.name, line)
	}
	return res.AuthenticatedPeers
}

// sdkBanned answers a {"cmd":"banned"} command.
type sdkBanned struct {
	Banned             []string `json:"banned"`
	AuthenticatedPeers []string `json:"authenticated_peers"`
}

// bannedUntil polls the member's ban set, without asking it to pull, until
// wantPeer is in it: this is how long a gossip event takes to land.
func (m *sdkMember) bannedUntil(t *testing.T, wantPeer string, timeout time.Duration) sdkBanned {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var res sdkBanned
		if line := m.send(t, map[string]string{"cmd": "banned"}); json.Unmarshal(line, &res) != nil {
			t.Fatalf("%s member: banned answered %q", m.name, line)
		}
		if contains(res.Banned, wantPeer) {
			return res
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s member never learned the ban of %s from the gossip event; banned=%v\nstderr:\n%s", m.name, wantPeer, res.Banned, m.stderr.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// sdkSyncResult answers a {"cmd":"sync"} command.
type sdkSyncResult struct {
	OK              bool     `json:"ok"`
	Error           string   `json:"error"`
	KeysChanged     bool     `json:"keys_changed"`
	Refreshed       bool     `json:"refreshed"`
	TrustedKeys     []string `json:"trusted_keys"`
	Biscuit         string   `json:"biscuit"`
	Banned          []string `json:"banned"`
	RouterAddresses []string `json:"router_addresses"`
}

// sync asks the member to pull from the control plane now; every part must land.
func (m *sdkMember) sync(t *testing.T) sdkSyncResult {
	t.Helper()
	var res sdkSyncResult
	if line := m.send(t, map[string]string{"cmd": "sync"}); json.Unmarshal(line, &res) != nil {
		t.Fatalf("%s member: sync answered %q", m.name, line)
	}
	if !res.OK {
		t.Fatalf("%s member: sync failed: %s", m.name, res.Error)
	}
	return res
}

// sdkProvider is one entry of a {"cmd":"discover"} answer.
type sdkProvider struct {
	PeerID string   `json:"peer_id"`
	Addrs  []string `json:"addrs"`
}

// discoverUntil repeats the DHT lookup until wantPeer is among the providers
// or the deadline passes; a node advertises a service only after probing
// its backend, on its own schedule.
func (m *sdkMember) discoverUntil(t *testing.T, serviceType, name, wantPeer string, timeout time.Duration) []sdkProvider {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []sdkProvider
	for {
		var res struct {
			OK        bool          `json:"ok"`
			Error     string        `json:"error"`
			Providers []sdkProvider `json:"providers"`
		}
		if line := m.send(t, map[string]string{"cmd": "discover", "type": serviceType, "name": name}); json.Unmarshal(line, &res) != nil {
			t.Fatalf("%s member: discover answered %q", m.name, line)
		}
		if !res.OK {
			t.Fatalf("%s member: discover failed: %s", m.name, res.Error)
		}
		last = res.Providers
		for _, p := range res.Providers {
			if p.PeerID == wantPeer {
				return res.Providers
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s member never discovered %s as a provider of %s://%s; last answer %+v", m.name, wantPeer, serviceType, name, last)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// discoverOnce is one DHT lookup, whatever it returns.
func (m *sdkMember) discoverOnce(t *testing.T, serviceType, name string) []sdkProvider {
	t.Helper()
	var res struct {
		OK        bool          `json:"ok"`
		Error     string        `json:"error"`
		Providers []sdkProvider `json:"providers"`
	}
	if line := m.send(t, map[string]string{"cmd": "discover", "type": serviceType, "name": name}); json.Unmarshal(line, &res) != nil {
		t.Fatalf("%s member: discover answered %q", m.name, line)
	}
	if !res.OK {
		t.Fatalf("%s member: discover failed: %s", m.name, res.Error)
	}
	return res.Providers
}

func (m *sdkMember) tools(t *testing.T, addr, service string) []string {
	t.Helper()
	res := m.toolsRequiring(t, addr, service, nil)
	if !res.OK {
		t.Fatalf("%s member could not list tools of %q at %s: %s", m.name, service, addr, res.Error)
	}
	return res.Tools
}

// sdkToolsResult answers a {"cmd":"tools"} command.
type sdkToolsResult struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error"`
	Tools []string `json:"tools"`
}

// toolsRequiring lists a provider's tools with a caller-side label requirement
// on the provider's credential, and reports a refusal instead of failing.
func (m *sdkMember) toolsRequiring(t *testing.T, addr, service string, required map[string]string) sdkToolsResult {
	t.Helper()
	command := map[string]any{"cmd": "tools", "addr": addr, "service": service}
	if required != nil {
		command["required_labels"] = required
	}
	line, _ := json.Marshal(command)
	if _, err := m.stdin.Write(append(line, '\n')); err != nil {
		t.Fatalf("%s member: write command: %v", m.name, err)
	}
	var res sdkToolsResult
	if answer := m.readLine(t, 20*time.Second); json.Unmarshal(answer, &res) != nil {
		t.Fatalf("%s member: tools answered %q", m.name, answer)
	}
	return res
}

// sdkCallResult answers a {"cmd":"call"} command.
type sdkCallResult struct {
	OK      bool     `json:"ok"`
	Error   string   `json:"error"`
	IsError bool     `json:"is_error"`
	Text    []string `json:"text"`
}

func (m *sdkMember) callRaw(t *testing.T, addr, service, tool string, args map[string]any) sdkCallResult {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	line, _ := json.Marshal(map[string]any{"cmd": "call", "addr": addr, "service": service, "tool": tool, "args": args})
	if _, err := m.stdin.Write(append(line, '\n')); err != nil {
		t.Fatalf("%s member: write command: %v", m.name, err)
	}
	var res sdkCallResult
	if answer := m.readLine(t, 20*time.Second); json.Unmarshal(answer, &res) != nil {
		t.Fatalf("%s member: call answered %q", m.name, answer)
	}
	return res
}

// call is callRaw that must reach the tool.
func (m *sdkMember) call(t *testing.T, addr, service, tool string, args map[string]any) sdkCallResult {
	t.Helper()
	res := m.callRaw(t, addr, service, tool, args)
	if !res.OK {
		t.Fatalf("%s member could not call %s on %q at %s: %s", m.name, tool, service, addr, res.Error)
	}
	return res
}

// accept asks the member to accept A2A requests for its agent, answered in
// its own process.
func (m *sdkMember) accept(t *testing.T, name string) {
	t.Helper()
	var res struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Service string `json:"service"`
	}
	if line := m.send(t, map[string]string{"cmd": "accept", "name": name}); json.Unmarshal(line, &res) != nil {
		t.Fatalf("%s member: accept answered %q", m.name, line)
	}
	if !res.OK {
		t.Fatalf("%s member could not accept a2a://%s: %s", m.name, name, res.Error)
	}
	if res.Service != "a2a://"+name {
		t.Fatalf("%s member accepts %q after asking for a2a://%s", m.name, res.Service, name)
	}
}

// sdkHTTPResult answers an {"cmd":"http"} command.
type sdkHTTPResult struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error"`
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// httpRaw asks the member to call an inference or A2A service over
// /libp2p-http, and reports a refusal instead of failing.
func (m *sdkMember) httpRaw(t *testing.T, addr, service, path string) sdkHTTPResult {
	t.Helper()
	var res sdkHTTPResult
	if line := m.send(t, map[string]string{"cmd": "http", "addr": addr, "service": service, "path": path}); json.Unmarshal(line, &res) != nil {
		t.Fatalf("%s member: http answered %q", m.name, line)
	}
	return res
}

// http is httpRaw that must be answered.
func (m *sdkMember) http(t *testing.T, addr, service, path string) sdkHTTPResult {
	t.Helper()
	res := m.httpRaw(t, addr, service, path)
	if !res.OK {
		t.Fatalf("%s member could not call %s%s at %s: %s", m.name, service, path, addr, res.Error)
	}
	return res
}

// routers asks the member which routers admitted it so far.
func (m *sdkMember) routers(t *testing.T) []string {
	t.Helper()
	var res struct {
		OK      bool     `json:"ok"`
		Error   string   `json:"error"`
		Routers []string `json:"routers"`
	}
	if line := m.send(t, map[string]string{"cmd": "routers"}); json.Unmarshal(line, &res) != nil {
		t.Fatalf("%s member: routers answered %q", m.name, line)
	}
	if !res.OK {
		t.Fatalf("%s member: routers: %s", m.name, res.Error)
	}
	return res.Routers
}

func (m *sdkMember) quit(t *testing.T) {
	t.Helper()
	m.send(t, map[string]string{"cmd": "quit"})
	_ = m.stdin.Close()
	exited := make(chan error, 1)
	go func() { exited <- m.cmd.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("%s member exited with %v\nstderr:\n%s", m.name, err, m.stderr.String())
		}
	case <-time.After(15 * time.Second):
		_ = m.cmd.Process.Kill()
		<-exited
		t.Errorf("%s member did not exit after quit\nstderr:\n%s", m.name, m.stderr.String())
	}
}

// readLine returns the member's next stdout line or fails after timeout; a
// runner that hangs must not hang the test.
func (m *sdkMember) readLine(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	type result struct {
		line []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		if m.lines.Scan() {
			ch <- result{line: append([]byte(nil), m.lines.Bytes()...)}
			return
		}
		err := m.lines.Err()
		if err == nil {
			err = io.EOF
		}
		ch <- result{err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("%s member stdout ended: %v\nstderr:\n%s", m.name, r.err, m.stderr.String())
		}
		return r.line
	case <-time.After(timeout):
		t.Fatalf("%s member printed nothing within %v\nstderr:\n%s", m.name, timeout, m.stderr.String())
		return nil
	}
}

// newAdmittedGoPeer is a libp2p host configured like sam-node's, connected
// to every router and past their auth handshakes, so each relays for it.
func newAdmittedGoPeer(t *testing.T, ctx context.Context, cpPriv ed25519.PrivateKey, routerAddrs []string) host.Host {
	t.Helper()
	h, err := libp2p.New(
		libp2p.NoListenAddrs,
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.EnableRelay(),
	)
	if err != nil {
		t.Fatalf("failed to create go peer: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	for _, routerAddr := range routerAddrs {
		info, err := peer.AddrInfoFromString(routerAddr)
		if err != nil {
			t.Fatalf("router address %s: %v", routerAddr, err)
		}
		connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = h.Connect(connectCtx, *info)
		cancel()
		if err != nil {
			t.Fatalf("go peer could not connect to router %s: %v", routerAddr, err)
		}
		routerBiscuit := authHandshake(t, ctx, h, info.ID, goHostBiscuit(t, cpPriv, h.ID()))
		if err := identity.VerifyBiscuitRole(routerBiscuit, cpPriv.Public().(ed25519.PublicKey), api.RoleRouter, 5*time.Second); err != nil {
			t.Fatalf("router credential lacks the router role: %v", err)
		}
	}
	return h
}

func goHostBiscuit(t *testing.T, cpPriv ed25519.PrivateKey, id peer.ID) []byte {
	t.Helper()
	b, err := identity.MintBootstrapBiscuitToken(cpPriv, id, api.RoleNode, time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatalf("failed to mint biscuit for %s: %v", id, err)
	}
	return b
}

// guestHostBiscuit is a valid control plane credential for a role the mesh
// policy does not know, so it grants nothing anywhere.
func guestHostBiscuit(t *testing.T, cpPriv ed25519.PrivateKey, id peer.ID) []byte {
	t.Helper()
	b, err := identity.MintBootstrapBiscuitToken(cpPriv, id, "sam:role:guest", time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatalf("failed to mint guest biscuit for %s: %v", id, err)
	}
	return b
}

// newGuestGoPeer is a Go peer admitted by the routers with a node-role token;
// what it presents to providers is chosen per request.
func newGuestGoPeer(t *testing.T, ctx context.Context, cpPriv ed25519.PrivateKey, routerAddrs []string) host.Host {
	t.Helper()
	return newAdmittedGoPeer(t, ctx, cpPriv, routerAddrs)
}

// tryMCPStream opens /sam/mcp/1.0.0 to target through addr and reports
// whether the peer speaks it at all.
func tryMCPStream(ctx context.Context, h host.Host, target peer.ID, addr multiaddr.Multiaddr) error {
	ctx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "mcp"), 10*time.Second)
	defer cancel()
	if err := h.Connect(ctx, peer.AddrInfo{ID: target, Addrs: []multiaddr.Multiaddr{addr}}); err != nil {
		return err
	}
	s, err := h.NewStream(ctx, target, api.MCPProtocolID)
	if err != nil {
		return err
	}
	_ = s.Close()
	return nil
}

// libp2pHTTPGet is one GET over /libp2p-http with the biscuit in
// X-Sam-Biscuit, the way sam-node's egress proxy sends it.
func libp2pHTTPGet(t *testing.T, ctx context.Context, h host.Host, target peer.ID, biscuit []byte, path string) (int, string) {
	t.Helper()
	client := &http.Client{Transport: libp2phttp.NewTransport(h), Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(network.WithAllowLimitedConn(ctx, "http"), http.MethodGet, "libp2p://"+target.String()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(api.HeaderSamBiscuit, base64.StdEncoding.EncodeToString(biscuit))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s on %s: %v", path, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// egressGet is a GET through sam-node's egress proxy with the node API token.
func egressGet(t *testing.T, apiAddr, token, path string) (int, string) {
	t.Helper()
	return egressGetRequiring(t, apiAddr, token, path, nil)
}

// egressGetRequiring is egressGet with a caller-side label requirement on the
// destination, as X-Sam-Required-Labels carries it.
func egressGetRequiring(t *testing.T, apiAddr, token, path string, required map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+apiAddr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(api.HeaderSamAuthentication, "Bearer "+token)
	if required != nil {
		req.Header.Set(api.HeaderSamRequiredLabels, labelsEnv(required))
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s through the sidecar: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// labelsEnv renders labels as "k=v,k2=v2", the form the runners' SAM_SDK_LABELS
// and sam-node's X-Sam-Required-Labels both take, keys sorted.
func labelsEnv(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+labels[k])
	}
	return strings.Join(pairs, ",")
}

// authHandshake runs the client side of /sam/auth/1.0.0 against target and
// returns the credential target answers with.
func authHandshake(t *testing.T, ctx context.Context, h host.Host, target peer.ID, biscuit []byte) []byte {
	t.Helper()
	streamCtx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "auth"), 10*time.Second)
	defer cancel()
	s, err := h.NewStream(streamCtx, target, api.AuthProtocolID)
	if err != nil {
		t.Fatalf("open auth stream to %s: %v", target, err)
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	frame, _ := proto.Marshal(&api.AuthFrame{Biscuit: biscuit})
	if err := msgio.NewVarintWriter(s).WriteMsg(frame); err != nil {
		t.Fatalf("write auth frame to %s: %v", target, err)
	}
	msg, err := msgio.NewVarintReaderSize(s, 64*1024).ReadMsg()
	if err != nil {
		t.Fatalf("read auth response from %s: %v", target, err)
	}
	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		t.Fatalf("auth response from %s: %v", target, err)
	}
	if !resp.Success {
		t.Fatalf("%s refused the handshake: %s", target, resp.Error)
	}
	return resp.Biscuit
}

// tryAuthHandshake reconnects to target through addr if needed and runs the
// client side of /sam/auth/1.0.0, returning the error a refusal produces: a
// connection the gate denies, or a stream closed without an answer.
func tryAuthHandshake(ctx context.Context, h host.Host, target peer.ID, addr multiaddr.Multiaddr, biscuit []byte) error {
	dialCtx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "auth"), 10*time.Second)
	defer cancel()
	if err := h.Connect(dialCtx, peer.AddrInfo{ID: target, Addrs: []multiaddr.Multiaddr{addr}}); err != nil {
		return err
	}
	s, err := h.NewStream(dialCtx, target, api.AuthProtocolID)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	frame, _ := proto.Marshal(&api.AuthFrame{Biscuit: biscuit})
	if err := msgio.NewVarintWriter(s).WriteMsg(frame); err != nil {
		return err
	}
	msg, err := msgio.NewVarintReaderSize(s, 64*1024).ReadMsg()
	if err != nil {
		return err
	}
	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("refused: %s", resp.Error)
	}
	return nil
}

// refuseForgedFrame checks that target answers a frame it cannot verify
// with a closed stream and nothing else, as sam-node does.
func refuseForgedFrame(t *testing.T, ctx context.Context, h host.Host, target peer.ID) {
	t.Helper()
	s, err := h.NewStream(network.WithAllowLimitedConn(ctx, "auth"), target, api.AuthProtocolID)
	if err != nil {
		t.Fatalf("open auth stream for the forged frame: %v", err)
	}
	defer func() { _ = s.Close() }()
	forged, _ := proto.Marshal(&api.AuthFrame{Biscuit: []byte("not a biscuit")})
	if err := msgio.NewVarintWriter(s).WriteMsg(forged); err != nil {
		t.Fatalf("write forged frame: %v", err)
	}
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if msg, err := msgio.NewVarintReaderSize(s, 64*1024).ReadMsg(); err == nil {
		t.Fatalf("%s answered a forged frame with %d bytes", target, len(msg))
	}
}

// pickDirectAddr is the member's loopback TCP address with its peer ID.
func pickDirectAddr(t *testing.T, addrs []string, peerID string) string {
	t.Helper()
	for _, a := range addrs {
		if strings.HasPrefix(a, "/ip4/127.0.0.1/tcp/") {
			if strings.Contains(a, "/p2p/") {
				return a
			}
			return a + "/p2p/" + peerID
		}
	}
	t.Fatalf("no loopback TCP address among %v", addrs)
	return ""
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
