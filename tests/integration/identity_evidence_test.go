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
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// TestIdentityEvidenceOperatorFlow exercises the same owner-side sequence as
// an external receipt verifier: trust the local Unix socket, identify this
// node, connect to an exact peer, and collect fresh independently verifiable
// peer evidence before any provider request.
func TestIdentityEvidenceOperatorFlow(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/agentmesh-node")
	_, controlPlaneURL, pinnedControlPlaneKey := startMockRouterWithControlPlaneKey(t)

	ownerHome := t.TempDir()
	providerHome := t.TempDir()
	socketDir, err := os.MkdirTemp("", "agentmesh-evidence-")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	ownerSocket := filepath.Join(socketDir, "owner.sock")

	owner := startBackgroundNode(t, nodeBin, controlPlaneURL, ownerHome,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
		"--socket-path", ownerSocket,
	)
	provider := startBackgroundNode(t, nodeBin, controlPlaneURL, providerHome,
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--discovery-interval", "100ms",
	)

	ownerAPI := owner.waitForAPI(t)
	provider.waitForAPI(t)

	providerAddr := provider.p2pAddr
	providerPeerID := getPeerIDFromAddr(providerAddr)
	if providerPeerID == "" {
		t.Fatalf("provider address %q has no PeerID", providerAddr)
	}
	connectPeer(t, ownerAPI, providerAddr)

	client := identityEvidenceSocketClient(ownerSocket)
	waitForIdentityEvidenceSocket(t, client)

	var local api.IdentityEvidenceResponse
	getIdentityEvidenceJSON(t, client, "/mesh/identity", &local)

	var remote api.PeerEvidenceResponse
	getIdentityEvidenceJSON(t, client, "/mesh/peer/"+url.PathEscape(providerPeerID.String())+"/evidence", &remote)

	verifyIdentityEvidence(t, controlPlaneURL, pinnedControlPlaneKey, providerPeerID, &local, &remote)
}

// verifyIdentityEvidence models the trust decision of an owner application.
// It has only its pinned control-plane key and the two sidecar responses.
func verifyIdentityEvidence(t *testing.T, controlPlaneURL string, pinnedControlPlaneKey ed25519.PublicKey, expectedProvider peer.ID, local *api.IdentityEvidenceResponse, remote *api.PeerEvidenceResponse) {
	t.Helper()

	if local.ControlPlaneUrl != controlPlaneURL || len(local.Biscuit) == 0 || local.CheckTime == nil || local.BiscuitExpireTime == nil || local.BiscuitExpireTime.AsTime().Before(local.CheckTime.AsTime()) {
		t.Fatalf("invalid local identity evidence: %+v", local)
	}
	localPeer, err := peer.Decode(local.PeerId)
	if err != nil {
		t.Fatalf("decode local PeerID: %v", err)
	}
	trustedKeys := parseEvidenceKeys(t, local.TrustedControlPlaneKeys)
	if !containsEvidenceKey(trustedKeys, pinnedControlPlaneKey) {
		t.Fatal("local response does not contain the independently pinned control-plane key")
	}
	if _, err := verifyBiscuitForApplication(local.Biscuit, localPeer, []ed25519.PublicKey{pinnedControlPlaneKey}); err != nil {
		t.Fatalf("third-party verification of local Biscuit failed: %v", err)
	}

	if remote.PeerId != expectedProvider.String() || len(remote.Biscuit) == 0 || len(remote.VerifyingKey) == 0 || remote.CheckTime == nil || remote.ExpireTime == nil || remote.ExpireTime.AsTime().Before(remote.CheckTime.AsTime()) || len(remote.RevocationIds) == 0 {
		t.Fatalf("invalid remote identity evidence: %+v", remote)
	}
	if len(remote.Roles) != 1 || remote.Roles[0] != api.RoleNode || len(remote.Labels) != 0 {
		t.Fatalf("unexpected remote claims: roles=%v labels=%v", remote.Roles, remote.Labels)
	}
	remotePeer, err := peer.Decode(remote.PeerId)
	if err != nil {
		t.Fatalf("decode remote PeerID: %v", err)
	}
	verifyingKey := parseEvidenceKey(t, remote.VerifyingKey)
	if !containsEvidenceKey(trustedKeys, verifyingKey) {
		t.Fatal("remote verifying key is absent from the local trusted key set")
	}
	verifiedRemote, err := verifyBiscuitForApplication(remote.Biscuit, remotePeer, []ed25519.PublicKey{verifyingKey})
	if err != nil {
		t.Fatalf("third-party verification of remote Biscuit failed: %v", err)
	}
	if !matchesRevocationIDs(remote.RevocationIds, verifiedRemote.RevocationIds()) {
		t.Fatalf("published revocation IDs %v do not match the verified Biscuit", remote.RevocationIds)
	}

	untrustedKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unrelated verification key: %v", err)
	}
	if _, err := verifyBiscuitForApplication(remote.Biscuit, remotePeer, []ed25519.PublicKey{untrustedKey}); err == nil {
		t.Fatal("remote Biscuit verified with an unrelated control-plane key")
	}
}

func verifyBiscuitForApplication(encodedBiscuit []byte, expectedPeer peer.ID, trustedKeys []ed25519.PublicKey) (*biscuit.Biscuit, error) {
	parsed, err := biscuit.Unmarshal(encodedBiscuit)
	if err != nil {
		return nil, err
	}
	for _, trustedKey := range trustedKeys {
		authorizer, err := parsed.Authorizer(trustedKey, biscuit.WithWorldOptions(datalog.WithMaxDuration(5*time.Second)))
		if err != nil {
			continue
		}
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactTime,
			IDs:  []biscuit.Term{biscuit.Date(time.Now())},
		}})
		authorizer.AddCheck(api.ControlPlaneStaticTimeCheck)
		authorizer.AddPolicy(api.AllowIfTruePolicy)
		if err := authorizer.Authorize(); err != nil {
			continue
		}
		boundPeer := biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactNode,
			IDs:  []biscuit.Term{biscuit.String(expectedPeer.String())},
		}}
		if blockID, err := parsed.GetBlockID(boundPeer); err == nil && blockID == 0 {
			return parsed, nil
		}
	}
	return nil, fmt.Errorf("Biscuit is not valid for peer %s and the configured control-plane keys", expectedPeer)
}

func parseEvidenceKeys(t *testing.T, encodedKeys [][]byte) []ed25519.PublicKey {
	t.Helper()
	keys := make([]ed25519.PublicKey, 0, len(encodedKeys))
	for _, encodedKey := range encodedKeys {
		keys = append(keys, parseEvidenceKey(t, encodedKey))
	}
	return keys
}

func parseEvidenceKey(t *testing.T, encodedKey []byte) ed25519.PublicKey {
	t.Helper()
	parsed, err := x509.ParsePKIXPublicKey(encodedKey)
	if err != nil {
		t.Fatalf("parse control-plane SPKI: %v", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("control-plane SPKI has type %T, want Ed25519", parsed)
	}
	return key
}

func containsEvidenceKey(keys []ed25519.PublicKey, expected ed25519.PublicKey) bool {
	for _, key := range keys {
		if key.Equal(expected) {
			return true
		}
	}
	return false
}

func matchesRevocationIDs(published []string, rawIDs [][]byte) bool {
	if len(published) != len(rawIDs) {
		return false
	}
	for index, rawID := range rawIDs {
		if published[index] != hex.EncodeToString(rawID) {
			return false
		}
	}
	return true
}

func identityEvidenceSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
}

func waitForIdentityEvidenceSocket(t *testing.T, client *http.Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://localhost/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timeout waiting for owner Unix socket")
}

func getIdentityEvidenceJSON(t *testing.T, client *http.Client, path string, target proto.Message) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		t.Fatalf("build evidence request: %v", err)
	}
	resp, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s over owner socket: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		t.Fatalf("GET %s status = %d, body = %q", path, resp.StatusCode, body)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET %s returned unsafe response headers: %v", path, resp.Header)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read response from %s: %v", path, err)
	}
	if err := protojson.Unmarshal(body, target); err != nil {
		t.Fatalf("decode closed response from %s: %v", path, err)
	}
}
