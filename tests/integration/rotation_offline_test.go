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
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
)

// TestKeyRotationWhileMembersOffline is the outage the testnets had twice:
// the control plane rotates its signing key while a member is not running.
// The routers refresh their credentials under the new key within a second
// of the rotation. The member comes back with what it persisted, a
// credential and a trusted key set that both predate the rotation, and
// must still join: pull the new key from the control plane, where the
// retiring key vouches for it, refresh its credential under it, and be
// admitted by routers whose credentials it could not have verified with the
// keys it had on disk. Both SDKs and the Go node are each enrolled, stopped,
// and started again from their state after the rotation, with no enrollment
// token to fall back on, so a member that re-enrolled instead of resuming
// would fail here too.
func TestKeyRotationWhileMembersOffline(t *testing.T) {
	mesh := startSDKMesh(t)
	ctx := context.Background()
	members := enrollMembersThenStop(t, mesh)

	newPub := rotateSigningKey(t, ctx, mesh, time.Hour)

	// The Go node starts from its stored identity, with no token: it pulls
	// from the control plane before it starts and comes up under the new key.
	node := members.startNode(t, false)
	members.assertNodeBackUnderKey(t, node, mesh, newPub)

	// The SDK members start again from their state directories. The token
	// path names no file: the member resumes or fails, it cannot enroll.
	for _, s := range members.sdk {
		m := s.start(t, mesh, " resumed", "SAM_BOOTSTRAP_TOKEN_PATH="+filepath.Join(t.TempDir(), "no-token"))
		s.assertBackUnderKey(t, m, mesh, newPub, node)
		if res := m.sync(t); !res.OK {
			t.Fatalf("%s: pull after the resume failed: %s", m.name, res.Error)
		}
		m.quit(t)
	}
	node.kill()
}

// TestKeyRotationPastGraceWhileMembersOffline is the same outage with a
// longer absence: the member comes back after the key that signed its
// credential has left the control plane's set. Nothing can verify or
// refresh that credential, and the control plane's /keys answer is signed
// by no key the member trusts, so it cannot adopt the new one either. A
// member with a token at hand, as every canary has its projected service
// account token, must enroll again with the identity it keeps, rather than
// resume a dead credential and fail at every router until it expires. The
// default grace period is shorter than a credential's lifetime, so this is
// where any member off for a day lands.
func TestKeyRotationPastGraceWhileMembersOffline(t *testing.T) {
	mesh := startSDKMesh(t)
	ctx := context.Background()
	members := enrollMembersThenStop(t, mesh)

	newPub := rotateSigningKey(t, ctx, mesh, time.Second)
	waitForKeysRetired(t, mesh.cpPort, [][]byte{mesh.cpPub})

	// The node comes back with a fresh platform token on disk.
	if err := os.WriteFile(members.jwtPath, []byte(members.freshJWT()), 0o600); err != nil {
		t.Fatal(err)
	}
	node := members.startNode(t, true)
	members.assertNodeBackUnderKey(t, node, mesh, newPub)

	// Each SDK member comes back with a fresh token available and enrolls
	// again as the identity it persisted.
	for _, s := range members.sdk {
		m := s.start(t, mesh, " past grace")
		s.assertBackUnderKey(t, m, mesh, newPub, node)
		m.quit(t)
	}
	node.kill()
}

// offlineSDKMember is an SDK member that enrolled and stopped, keeping its
// state directory.
type offlineSDKMember struct {
	launcher sdkRunner
	stateDir string
	peerID   string
	biscuit  string
}

// start brings the member back from its state directory. launchSDKMember
// writes a fresh bootstrap token; env is appended and wins.
func (s *offlineSDKMember) start(t *testing.T, mesh *sdkMesh, suffix string, env ...string) *sdkMember {
	t.Helper()
	cmd, _ := s.launcher.cmd(mesh.root)
	return launchSDKMember(t, s.launcher.name+suffix, cmd, mesh.root, mesh.baseURL, mesh.adminToken, append([]string{"SAM_SDK_STATE_DIR=" + s.stateDir}, env...)...)
}

// assertBackUnderKey checks the member came back as the identity it kept,
// admitted by every router, holding a credential signed by pub alone, and
// able to reach the node that came back too, across the mesh.
func (s *offlineSDKMember) assertBackUnderKey(t *testing.T, m *sdkMember, mesh *sdkMesh, pub ed25519.PublicKey, node *backgroundNode) {
	t.Helper()
	if m.report.PeerID != s.peerID {
		t.Fatalf("%s came back as %s, want the identity it persisted, %s", m.name, m.report.PeerID, s.peerID)
	}
	assertAdmittedByEveryRouter(t, m, mesh.routerAddrs)
	if m.report.Biscuit == s.biscuit {
		t.Fatalf("%s still holds the credential minted before the rotation", m.name)
	}
	assertSignedOnlyBy(t, m.name, m.report.Biscuit, m.report.PeerID, pub, mesh.cpPub)
	if cred := m.auth(t, node.p2pAddr); cred.PeerID != node.peerID.String() {
		t.Fatalf("%s verified the node as %+v after coming back", m.name, cred)
	}
}

// offlineMembers is one member per SDK and a Go node, each enrolled under
// the key current at the time and then stopped.
type offlineMembers struct {
	sdk []offlineSDKMember

	nodeBin      string
	nodeHome     string
	nodeEnv      []string
	nodeArgs     []string
	jwtPath      string
	freshJWT     func() string
	socketClient *http.Client
	nodePeer     peer.ID
	nodeBefore   api.IdentityEvidenceResponse
}

func enrollMembersThenStop(t *testing.T, mesh *sdkMesh) *offlineMembers {
	t.Helper()
	members := &offlineMembers{nodeBin: buildBinary(t, "./cmd/sam-node")}

	// A token is read only to enroll, so the file can go once the member
	// holds a credential.
	for _, launcher := range sdkMemberLaunchers {
		cmd, skip := launcher.cmd(mesh.root)
		if skip != "" {
			t.Logf("%s SDK skipped: %s", launcher.name, skip)
			continue
		}
		stateDir := filepath.Join(t.TempDir(), "state")
		m := launchSDKMember(t, launcher.name, cmd, mesh.root, mesh.baseURL, mesh.adminToken, "SAM_SDK_STATE_DIR="+stateDir)
		members.sdk = append(members.sdk, offlineSDKMember{launcher: launcher, stateDir: stateDir, peerID: m.report.PeerID, biscuit: m.report.Biscuit})
		m.quit(t)
	}

	// The Go node: enrolled through a platform token on disk, its identity
	// and mesh config in its data directory, its credential readable on the
	// owner socket.
	members.nodeHome = filepath.Join(t.TempDir(), "node")
	if err := os.MkdirAll(members.nodeHome, 0o755); err != nil {
		t.Fatal(err)
	}
	members.nodeEnv = append(os.Environ(), "HOME="+members.nodeHome, "XDG_CONFIG_HOME="+filepath.Join(members.nodeHome, ".config"))
	socketDir, err := os.MkdirTemp("", "sam-rot-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	members.freshJWT = func() string {
		return mesh.mintToken(map[string]interface{}{"sub": "mock-user", "roles": []string{api.RoleNode}})
	}
	members.jwtPath = filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(members.jwtPath, []byte(members.freshJWT()), 0o600); err != nil {
		t.Fatal(err)
	}
	nodeSocket := filepath.Join(socketDir, "node.sock")
	members.nodeArgs = []string{"run",
		"--control-plane", mesh.baseURL,
		"--allow-loopback",
		"--api-token-path", tokenPath(t, "node-token"),
		"--socket-path", nodeSocket,
		"--log-level", "debug",
	}
	node := members.startNode(t, true)
	members.socketClient = identityEvidenceSocketClient(nodeSocket)
	waitForIdentityEvidenceSocket(t, members.socketClient)
	getIdentityEvidenceJSON(t, members.socketClient, "/sam/identity", &members.nodeBefore)
	members.nodePeer, err = peer.Decode(members.nodeBefore.PeerId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBiscuitForApplication(members.nodeBefore.Biscuit, members.nodePeer, []ed25519.PublicKey{mesh.cpPub}); err != nil {
		t.Fatalf("node credential before the rotation does not verify under the current key: %v", err)
	}
	node.kill()
	return members
}

// startNode brings the node up from its data directory, with the platform
// token on disk offered or not.
func (o *offlineMembers) startNode(t *testing.T, withToken bool) *backgroundNode {
	t.Helper()
	args := o.nodeArgs
	if withToken {
		args = append(append([]string{}, args...), "--jwt-path", o.jwtPath)
	}
	node := launchNode(t, o.nodeBin, o.nodeEnv, o.nodeHome, args...)
	node.waitForAPI(t)
	return node
}

func (o *offlineMembers) assertNodeBackUnderKey(t *testing.T, node *backgroundNode, mesh *sdkMesh, pub ed25519.PublicKey) {
	t.Helper()
	waitForIdentityEvidenceSocket(t, o.socketClient)
	var after api.IdentityEvidenceResponse
	getIdentityEvidenceJSON(t, o.socketClient, "/sam/identity", &after)
	if after.PeerId != o.nodeBefore.PeerId {
		t.Fatalf("node came back as %s, want its stored identity %s", after.PeerId, o.nodeBefore.PeerId)
	}
	if _, err := verifyBiscuitForApplication(after.Biscuit, o.nodePeer, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("node credential after coming back does not verify under the new key: %v\n--- node.log ---\n%s", err, node.log())
	}
	if _, err := verifyBiscuitForApplication(after.Biscuit, o.nodePeer, []ed25519.PublicKey{mesh.cpPub}); err == nil {
		t.Fatal("node credential after coming back still verifies under the retiring key: it was not refreshed")
	}
	waitForPeerOnRouter(t, mesh.cpPort, mesh.adminToken, o.nodeBefore.PeerId, 10*time.Second)
}

// rotateSigningKey rotates as the sam-control-plane binary does: a new
// current key, the old one retiring over grace, the event on the mesh. It
// returns once every router presents a credential under the new key.
func rotateSigningKey(t *testing.T, ctx context.Context, mesh *sdkMesh, grace time.Duration) ed25519.PublicKey {
	t.Helper()
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mesh.store.RotateKeys(ctx, newPriv, newPub, grace); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if err := mesh.publisher.PublishEvent(ctx, api.MeshEvent_KEY_ROTATION, "", newPub); err != nil {
		t.Fatalf("publish KEY_ROTATION: %v", err)
	}
	waitForRoutersUnderKey(t, ctx, mesh, newPub)
	return newPub
}

// waitForRoutersUnderKey returns once every router presents a credential
// signed by pub in the auth handshake. A Go peer holding a credential under
// the retiring key, still valid, runs the handshake.
func waitForRoutersUnderKey(t *testing.T, ctx context.Context, mesh *sdkMesh, pub ed25519.PublicKey) {
	t.Helper()
	h, err := libp2p.New(libp2p.NoListenAddrs, libp2p.Security(libp2ptls.ID, libp2ptls.New))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	for _, routerAddr := range mesh.routerAddrs {
		info, err := peer.AddrInfoFromString(routerAddr)
		if err != nil {
			t.Fatal(err)
		}
		connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = h.Connect(connectCtx, *info)
		cancel()
		if err != nil {
			t.Fatalf("could not connect to router %s: %v", routerAddr, err)
		}
		for {
			routerBiscuit := authHandshake(t, ctx, h, info.ID, goHostBiscuit(t, mesh.cpPriv, h.ID()))
			if err := identity.VerifyBiscuitRole(routerBiscuit, pub, api.RoleRouter, 5*time.Second); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("router %s did not refresh its credential under the new key", info.ID)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// assertAdmittedByEveryRouter checks the join report names every router the
// control plane lists, each verified as holding the router role.
func assertAdmittedByEveryRouter(t *testing.T, m *sdkMember, routerAddrs []string) {
	t.Helper()
	var admitted, want []string
	for _, r := range m.report.Routers {
		admitted = append(admitted, r.PeerID)
		if !contains(r.Roles, api.RoleRouter) {
			t.Fatalf("%s: router %s credential roles %v lack %s", m.name, r.PeerID, r.Roles, api.RoleRouter)
		}
	}
	for _, a := range routerAddrs {
		want = append(want, extractPeerID(a))
	}
	sort.Strings(admitted)
	sort.Strings(want)
	if fmt.Sprint(admitted) != fmt.Sprint(want) {
		t.Fatalf("%s was admitted by %v, want every router %v", m.name, admitted, want)
	}
}

// assertSignedOnlyBy checks a base64 credential verifies for peerID under
// signer and under none of the others.
func assertSignedOnlyBy(t *testing.T, who, encoded, peerID string, signer ed25519.PublicKey, others ...ed25519.PublicKey) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("%s credential is not base64: %v", who, err)
	}
	id, err := peer.Decode(peerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.VerifyBiscuitAndGetExpiry(raw, id, []ed25519.PublicKey{signer}, 5*time.Second); err != nil {
		t.Fatalf("%s credential does not verify under the new key: %v", who, err)
	}
	for _, other := range others {
		if _, err := identity.VerifyBiscuitAndGetExpiry(raw, id, []ed25519.PublicKey{other}, 5*time.Second); err == nil {
			t.Fatalf("%s credential still verifies under a retiring key", who)
		}
	}
}
