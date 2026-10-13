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

package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Enrollment hands out a biscuit signed by the current key and then learns
// the full key set, grace key included. Neither step is a rotation the new
// biscuit predates; a rotation that follows is.
func TestEnrollmentPinsIdentityKeySet(t *testing.T) {
	currentPub, currentPriv := mustGenerateKey(t)
	gracePub, gracePriv := mustGenerateKey(t)
	rotatedPub, _ := mustGenerateKey(t)
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	privateKey := GetOrGenerateKey(store)
	peerID, err := peer.IDFromPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	credential := mintRoleBiscuit(t, currentPriv, peerID, api.RoleNode)
	mux := http.NewServeMux()
	mux.HandleFunc("/register", protoHandler(t, &api.EnrollResponse{
		BiscuitToken:          credential,
		ControlPlanePublicKey: currentPub,
		ExpireTime:            timestamppb.New(time.Now().Add(24 * time.Hour)),
	}))
	mux.HandleFunc("/keys", keysHandler(t, []ed25519.PublicKey{gracePub, currentPub}, []ed25519.PrivateKey{gracePriv, currentPriv}))
	mux.HandleFunc("/info", protoHandler(t, &api.ControlPlaneInfoResponse{}))
	mux.HandleFunc("/policies", protoHandler(t, &api.PolicyConfigGetResponse{}))
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, request *http.Request) {
		t.Error("freshly enrolled credential must not be refreshed")
		http.Error(w, "unexpected refresh", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	if err := store.SaveControlPlaneURL(server.URL); err != nil {
		t.Fatal(err)
	}
	node := &AgentMeshNode{Store: store, BiscuitTimeout: time.Second, config: Options{RequiredRole: api.RoleNode}}
	if _, err := node.enrollHTTP(context.Background(), server.URL, "test-jwt", peerID, privateKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(node.GetIdentity(), credential) || len(node.trustedKeys) != 2 {
		t.Fatal("enrollment must adopt the credential and both trusted keys")
	}
	if node.identityPredatesRotation() {
		t.Error("a freshly enrolled identity predates no rotation")
	}
	if err := node.SyncControlPlane(context.Background()); err != nil {
		t.Fatalf("sync after enrollment: %v", err)
	}
	pinned, err := store.LoadIdentityKeySet()
	if err != nil || len(pinned) != 2 {
		t.Fatalf("identity key set = %d keys, err %v; want the grace and current keys", len(pinned), err)
	}

	node.handleKeyRotationEvent(&api.MeshEvent{NewPublicKey: rotatedPub})
	if !node.identityPredatesRotation() {
		t.Fatal("a key learned after issuance must mark the identity for refresh")
	}
	restarted := &AgentMeshNode{Store: store}
	if stored, err := store.LoadTrustedKeys(); err != nil {
		t.Fatal(err)
	} else {
		restarted.trustedKeys = stored
	}
	if !restarted.identityPredatesRotation() {
		t.Fatal("the refresh decision must survive a restart")
	}
}

// startMockRouterWithKey runs a minimal router whose auth response biscuit is
// signed by the given CP key, so nodes trusting that key can authenticate.
func startMockRouterWithKey(t *testing.T, cpPriv ed25519.PrivateKey, role string) string {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create mock router host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	builder := biscuit.NewBuilder(cpPriv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(h.ID().String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(role)}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(24 * time.Hour))}}},
		api.MarkerFact(api.FactTargetUnrestricted),
	} {
		if err := builder.AddAuthorityFact(f); err != nil {
			t.Fatalf("failed to add router fact: %v", err)
		}
	}
	tok, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build router biscuit: %v", err)
	}
	routerBiscuit, err := tok.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize router biscuit: %v", err)
	}

	h.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		defer func() { _ = s.Close() }()
		reader := msgio.NewVarintReaderSize(s, 1024*64)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		reader.ReleaseMsg(msg)
		data, err := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: routerBiscuit})
		if err != nil {
			return
		}
		_ = msgio.NewVarintWriter(s).WriteMsg(data)
	})

	return h.Addrs()[0].String() + "/p2p/" + h.ID().String()
}

// TestStartRecoversStaleIdentityViaRefreshToken covers #321: a stored
// identity signed by a fully rotated-out key must heal at startup through
// refresh grant + HTTP re-enrollment, keeping the PeerID, instead of fataling.
func TestStartRecoversStaleIdentityViaRefreshToken(t *testing.T) {
	cpPub, cpPriv, _ := ed25519.GenerateKey(nil)
	_, stalePriv, _ := ed25519.GenerateKey(nil)

	routerAddr := startMockRouterWithKey(t, cpPriv, api.RoleRouter)

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// Fix the node keypair up front so the mock CP can assert PeerID is kept
	privKey := GetOrGenerateKey(store)
	wantPeerID, err := peer.IDFromPublicKey(privKey.GetPublic())
	if err != nil {
		t.Fatal(err)
	}

	mint := func(priv ed25519.PrivateKey, peerID string) []byte {
		builder := biscuit.NewBuilder(priv)
		for _, f := range []biscuit.Fact{
			{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(peerID)}}},
			{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
			{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(24 * time.Hour))}}},
		} {
			if err := builder.AddAuthorityFact(f); err != nil {
				t.Fatalf("failed to add fact: %v", err)
			}
		}
		tok, err := builder.Build()
		if err != nil {
			t.Fatalf("failed to build biscuit: %v", err)
		}
		b, err := tok.Serialize()
		if err != nil {
			t.Fatalf("failed to serialize biscuit: %v", err)
		}
		return b
	}

	// Stored identity is signed by a key the node no longer trusts
	if err := store.SaveIdentity(mint(stalePriv, wantPeerID.String())); err != nil {
		t.Fatal(err)
	}

	// Mock OIDC issuer honouring the refresh grant
	oidcMux := http.NewServeMux()
	oidcMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "http://" + r.Host,
			"token_endpoint":         "http://" + r.Host + "/token",
			"authorization_endpoint": "http://" + r.Host + "/auth",
		})
	})
	oidcMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "refresh_token" || r.FormValue("refresh_token") != "stored_refresh" {
			http.Error(w, "invalid grant", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "unused",
			"id_token":      "recovered_jwt",
			"refresh_token": "rotated_refresh",
		})
	})
	oidcSrv := httptest.NewServer(oidcMux)
	defer oidcSrv.Close()

	// Mock control plane: re-enrolls the peer with a freshly signed biscuit
	var mu sync.Mutex
	var gotPeerID, gotJWT string
	cpMux := http.NewServeMux()
	cpMux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req api.EnrollRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		gotPeerID, gotJWT = req.PeerId, req.Jwt
		mu.Unlock()
		resp := &api.EnrollResponse{
			BiscuitToken:          mint(cpPriv, req.PeerId),
			ControlPlanePublicKey: cpPub,
			RouterAddresses:       []string{routerAddr},
			ExpireTime:            timestamppb.New(time.Now().Add(24 * time.Hour)),
		}
		data, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(data)
	})
	cpSrv := httptest.NewServer(cpMux)
	defer cpSrv.Close()

	if err := store.SaveOIDCConfig(oidcSrv.URL, "client_id_test", "agentmesh"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRefreshToken("stored_refresh"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveControlPlaneURL(cpSrv.URL); err != nil {
		t.Fatal(err)
	}

	// A decoy key ahead of the real one: the router handshake must build its
	// authorizer from the key that verified, not from trustedKeys[0].
	decoyKey, _, _ := ed25519.GenerateKey(nil)
	if err := store.SaveTrustedKeys([]TrustedKey{
		{Key: decoyKey, ReceivedAt: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}

	node, err := NewAgentMeshNode(Options{
		PrivKey:            privKey,
		Store:              store,
		ControlPlanePubKey: cpPub,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := node.Start(ctx); err != nil {
		t.Fatalf("Start should have recovered the stale identity, got: %v", err)
	}

	mu.Lock()
	if gotPeerID != wantPeerID.String() {
		t.Errorf("re-enrollment peer id: got %q, want %q (PeerID must survive recovery)", gotPeerID, wantPeerID)
	}
	if gotJWT != "recovered_jwt" {
		t.Errorf("re-enrollment JWT: got %q, want refresh-grant token", gotJWT)
	}
	mu.Unlock()

	if err := identity.VerifyBiscuitRole(node.GetIdentity(), cpPub, api.RoleNode, time.Second); err != nil {
		t.Errorf("recovered identity does not verify under the current CP key: %v", err)
	}

	// The router addresses from the re-enrollment must be adopted in-memory,
	// not only persisted: the static relay setup runs right after recovery.
	if len(node.config.RouterAddrs) != 1 || node.config.RouterAddrs[0].String() != routerAddr {
		t.Errorf("recovered router addresses not adopted: got %v, want %s", node.config.RouterAddrs, routerAddr)
	}
}

// TestStartRecoversStaleIdentityViaAutonomousRefresh covers #367 from the
// node's side: a bootstrap node has no OIDC refresh grant, so when its
// stored identity is signed by a retired key the only silent recovery is
// /refresh with peer_id set, which the control plane honours if the operator
// opted the node in. The node must send peer_id and adopt the result.
func TestStartRecoversStaleIdentityViaAutonomousRefresh(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, stalePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	routerAddr := startMockRouterWithKey(t, cpPriv, api.RoleRouter)

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	privKey := GetOrGenerateKey(store)
	wantPeerID, err := peer.IDFromPublicKey(privKey.GetPublic())
	if err != nil {
		t.Fatal(err)
	}

	mint := func(priv ed25519.PrivateKey, peerID string) []byte {
		builder := biscuit.NewBuilder(priv)
		for _, f := range []biscuit.Fact{
			{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(peerID)}}},
			{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
			{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(24 * time.Hour))}}},
		} {
			if err := builder.AddAuthorityFact(f); err != nil {
				t.Fatalf("failed to add fact: %v", err)
			}
		}
		tok, err := builder.Build()
		if err != nil {
			t.Fatalf("failed to build biscuit: %v", err)
		}
		b, err := tok.Serialize()
		if err != nil {
			t.Fatalf("failed to serialize biscuit: %v", err)
		}
		return b
	}

	staleBiscuit := mint(stalePriv, wantPeerID.String())
	if err := store.SaveIdentity(staleBiscuit); err != nil {
		t.Fatal(err)
	}

	// Mock control plane: /refresh behaves like the opted-in fallback - it
	// cannot verify the bearer, finds the node by peer_id, checks the bearer
	// is the last one it issued and the challenge is signed by the node key.
	var mu sync.Mutex
	var gotPeerID string
	var gotBearer []byte
	cpMux := http.NewServeMux()
	cpMux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		bearer, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			http.Error(w, "bad bearer", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read /refresh body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var req api.TokenRefreshRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		gotPeerID, gotBearer = req.PeerId, bearer
		mu.Unlock()
		if req.PeerId != wantPeerID.String() || !bytes.Equal(bearer, staleBiscuit) {
			http.Error(w, "Invalid biscuit", http.StatusUnauthorized)
			return
		}
		ok, err := privKey.GetPublic().Verify(api.RefreshChallenge(req.PeerId, req.ChallengeUnixMs), req.ChallengeSignature)
		if err != nil || !ok {
			http.Error(w, "Challenge verification failed", http.StatusUnauthorized)
			return
		}
		data, err := proto.Marshal(&api.TokenRefreshResponse{
			BiscuitToken: mint(cpPriv, req.PeerId),
			ExpireTime:   timestamppb.New(time.Now().Add(24 * time.Hour)),
		})
		if err != nil {
			t.Errorf("marshal TokenRefreshResponse: %v", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		if _, err := w.Write(data); err != nil {
			t.Errorf("write /refresh response: %v", err)
		}
	})
	cpMux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		t.Error("/register must not be hit: a bootstrap node has no OIDC grant to re-enroll with")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	cpSrv := httptest.NewServer(cpMux)
	defer cpSrv.Close()

	if err := store.SaveControlPlaneURL(cpSrv.URL); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMeshConfig(cpPub, []string{routerAddr}); err != nil {
		t.Fatal(err)
	}

	node, err := NewAgentMeshNode(Options{
		PrivKey:            privKey,
		Store:              store,
		ControlPlanePubKey: cpPub,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := node.Start(ctx); err != nil {
		t.Fatalf("Start should have recovered the stale identity via /refresh, got: %v", err)
	}

	mu.Lock()
	if gotPeerID != wantPeerID.String() {
		t.Errorf("/refresh peer_id: got %q, want %q", gotPeerID, wantPeerID)
	}
	if !bytes.Equal(gotBearer, staleBiscuit) {
		t.Error("/refresh must present the stored (stale) biscuit for the control plane to byte-match")
	}
	mu.Unlock()

	if err := identity.VerifyBiscuitRole(node.GetIdentity(), cpPub, api.RoleNode, time.Second); err != nil {
		t.Errorf("recovered identity does not verify under the current CP key: %v", err)
	}
	stored, err := store.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, node.GetIdentity()) {
		t.Error("in-memory identity and stored identity diverged after recovery")
	}
}

// Without a refresh token the startup failure must stay fatal.
func TestStartStaleIdentityWithoutRefreshTokenFails(t *testing.T) {
	cpPub, _, _ := ed25519.GenerateKey(nil)
	_, stalePriv, _ := ed25519.GenerateKey(nil)

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	privKey := GetOrGenerateKey(store)
	peerID, _ := peer.IDFromPublicKey(privKey.GetPublic())

	builder := biscuit.NewBuilder(stalePriv)
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(peerID.String())}}})
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}})
	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	staleBiscuit, err := tok.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveIdentity(staleBiscuit); err != nil {
		t.Fatal(err)
	}

	node, err := NewAgentMeshNode(Options{
		PrivKey:            privKey,
		Store:              store,
		ControlPlanePubKey: cpPub,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = node.Start(ctx)
	if err == nil {
		t.Fatal("Start should fail when recovery is impossible")
	}
	if !strings.Contains(err.Error(), "fails role requirement") {
		t.Errorf("error should keep the role-requirement guidance, got: %v", err)
	}
}

func TestGetOrGenerateKey(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// First call should generate a key
	key1 := GetOrGenerateKey(store)
	if key1 == nil {
		t.Fatal("Expected key to be generated")
	}

	// Second call should retrieve the same key
	key2 := GetOrGenerateKey(store)
	if key2 == nil {
		t.Fatal("Expected key to be retrieved")
	}

	// Verify they are the same key
	raw1, _ := crypto.MarshalPrivateKey(key1)
	raw2, _ := crypto.MarshalPrivateKey(key2)
	if !bytes.Equal(raw1, raw2) {
		t.Error("Expected retrieved key to match generated key")
	}
}

func TestEnroll_InvalidControlPlanePublicKeySize(t *testing.T) {
	// 1. Start a fake control plane enrollment server
	invalidKey := []byte("too-short") // Not ed25519.PublicKeySize (32 bytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := &api.EnrollResponse{
			BiscuitToken:          []byte("mock-token"),
			ExpireTime:            timestamppb.New(time.Now().Add(1 * time.Hour)),
			ControlPlanePublicKey: invalidKey,
			RouterAddresses:       []string{"/ip4/127.0.0.1/tcp/4001"},
		}
		data, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	// 2. Setup mock node options
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	node, err := NewAgentMeshNode(Options{
		PrivKey:     priv,
		Store:       store,
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := node.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// 3. Call enroll which should fail due to public key validation
	err = node.Enroll(context.Background(), srv.URL, "dummy-jwt")
	if err == nil {
		t.Fatal("Expected Enroll to fail with invalid public key size, but it succeeded")
	}
	if !strings.Contains(err.Error(), "received invalid control plane public key size") {
		t.Fatalf("Expected invalid public key size error, got: %v", err)
	}
}

// TestEnrollTrustsRouterSignedByGraceKey is the hub testnet outage of
// 2026-09-20: the control plane had rotated its signing key, the routers
// still presented biscuits signed by the retiring key (legitimately in its
// grace period), and the enroll response carries only the newest key. A
// fresh node must fetch the full set from /keys before the router handshake
// or it refuses every router and enrollment fails.
func TestEnrollTrustsRouterSignedByGraceKey(t *testing.T) {
	retiredPub, retiredPriv := mustGenerateKey(t)
	currentPub, currentPriv := mustGenerateKey(t)

	routerAddr := startMockRouterWithKey(t, retiredPriv, api.RoleRouter)

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	privKey := GetOrGenerateKey(store)

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read /register body: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req api.EnrollRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			t.Errorf("decode /register body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		peerID, err := peer.Decode(req.PeerId)
		if err != nil {
			t.Errorf("decode enrolling peer id %q: %v", req.PeerId, err)
			http.Error(w, "bad peer id", http.StatusBadRequest)
			return
		}
		protoHandler(t, &api.EnrollResponse{
			BiscuitToken:          mintRoleBiscuit(t, currentPriv, peerID, api.RoleNode),
			ControlPlanePublicKey: currentPub,
			RouterAddresses:       []string{routerAddr},
			ExpireTime:            timestamppb.New(time.Now().Add(24 * time.Hour)),
		})(w, r)
	})
	mux.HandleFunc("/keys", keysHandler(t, []ed25519.PublicKey{retiredPub, currentPub}, []ed25519.PrivateKey{retiredPriv, currentPriv}))
	cpSrv := httptest.NewServer(mux)
	defer cpSrv.Close()

	node, err := NewAgentMeshNode(Options{
		PrivKey:       privKey,
		Store:         store,
		ListenAddrs:   []string{"/ip4/127.0.0.1/tcp/0"},
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := node.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = node.Host.Close() }()

	if err := node.Enroll(ctx, cpSrv.URL, "dummy-jwt"); err != nil {
		t.Fatalf("Enroll must accept a router signed by the key still in grace: %v", err)
	}

	for _, want := range []ed25519.PublicKey{retiredPub, currentPub} {
		if !containsTrustedKey(node.trustedKeys, want) {
			t.Errorf("trust set %d keys, missing %x", len(node.trustedKeys), want)
		}
	}
	stored, err := store.LoadTrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 {
		t.Errorf("persisted trust set has %d keys, want both", len(stored))
	}
}

func TestProcessEnrollResponse_Errors(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	node, err := NewAgentMeshNode(Options{
		PrivKey:     priv,
		Store:       store,
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Non200Status", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Body:       io.NopCloser(strings.NewReader("bad request details")),
		}
		_, err := node.processEnrollResponse(resp)
		if err == nil || !strings.Contains(err.Error(), "enrollment failed with status 400") {
			t.Fatalf("Expected status 400 error, got: %v", err)
		}
	})

	t.Run("ErrorMessageInResponse", func(t *testing.T) {
		enrollResp := &api.EnrollResponse{ErrorMessage: "unauthorized user"}
		data, _ := proto.Marshal(enrollResp)
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(data)),
		}
		_, err := node.processEnrollResponse(resp)
		if err == nil || !strings.Contains(err.Error(), "enrollment failed: unauthorized user") {
			t.Fatalf("Expected enrollment failed error message, got: %v", err)
		}
	})

	t.Run("EmptyBiscuitToken", func(t *testing.T) {
		enrollResp := &api.EnrollResponse{
			BiscuitToken:          nil,
			ControlPlanePublicKey: make([]byte, 32),
		}
		data, _ := proto.Marshal(enrollResp)
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(data)),
		}
		_, err := node.processEnrollResponse(resp)
		if err == nil || !strings.Contains(err.Error(), "received empty biscuit token") {
			t.Fatalf("Expected empty biscuit token error, got: %v", err)
		}
	})
}

func TestConnectToRouters_EmptyAddrs(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	node, err := NewAgentMeshNode(Options{
		PrivKey:     priv,
		Store:       store,
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = node.connectToRouters(context.Background(), "", nil)
	if err == nil || !strings.Contains(err.Error(), "returned no router addresses") {
		t.Fatalf("Expected no router addresses error, got: %v", err)
	}
}
