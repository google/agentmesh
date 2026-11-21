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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

func TestMergeTrustedKeys(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-2 * time.Hour)
	keyA, _, _ := ed25519.GenerateKey(nil)
	keyB, _, _ := ed25519.GenerateKey(nil)
	keyC, _, _ := ed25519.GenerateKey(nil)

	existing := []TrustedKey{
		{Key: keyA, ReceivedAt: earlier},
		{Key: keyC, ReceivedAt: earlier}, // expired at the CP: absent from /keys
	}
	got := mergeTrustedKeys(existing, []ed25519.PublicKey{keyA, keyB}, now)

	if len(got) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(got))
	}
	if !got[0].Key.Equal(keyA) || !got[0].ReceivedAt.Equal(now) {
		t.Errorf("a key the control plane still lists must get the sync time: got %+v", got[0])
	}
	if !got[1].Key.Equal(keyB) || !got[1].ReceivedAt.Equal(now) {
		t.Errorf("new key must get the sync time: got %+v", got[1])
	}
	for _, tk := range got {
		if tk.Key.Equal(keyC) {
			t.Error("key expired at the control plane must be dropped")
		}
	}
}

// mustGenerateKey is an ed25519 key pair or a failed test.
func mustGenerateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// keysServer serves /keys with the given set, signed by the matching private
// keys; a nil signer leaves the answer unsigned.
func keysServer(t *testing.T, pubs []ed25519.PublicKey, privs []ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	return httptest.NewServer(keysHandler(t, pubs, privs))
}

func keysHandler(t *testing.T, pubs []ed25519.PublicKey, privs []ed25519.PrivateKey) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		resp := &api.KeysResponse{}
		for _, p := range pubs {
			resp.PublicKeys = append(resp.PublicKeys, p)
		}
		if privs != nil {
			if err := api.SignKeysResponse(resp, privs, time.Now()); err != nil {
				t.Errorf("SignKeysResponse: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		protoHandler(t, resp)(w, r)
	}
}

// protoHandler answers with msg; a marshal failure fails the test rather
// than handing the client an empty body it might accept.
func protoHandler(t *testing.T, msg proto.Message) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := proto.Marshal(msg)
		if err != nil {
			t.Errorf("proto.Marshal(%T): %v", msg, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		if _, err := w.Write(data); err != nil {
			t.Errorf("write %T: %v", msg, err)
		}
	}
}

func TestSyncTrustedKeys(t *testing.T) {
	retiredPub, retiredPriv := mustGenerateKey(t)
	currentPub, currentPriv := mustGenerateKey(t)
	strangerPub, strangerPriv := mustGenerateKey(t)

	newNode := func(t *testing.T) *AgentMeshNode {
		store, err := NewStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return &AgentMeshNode{Store: store, trustedKeys: []TrustedKey{{Key: currentPub, ReceivedAt: time.Now()}}}
	}

	t.Run("adopts the set a trusted key vouches for", func(t *testing.T) {
		srv := keysServer(t, []ed25519.PublicKey{retiredPub, currentPub}, []ed25519.PrivateKey{retiredPriv, currentPriv})
		defer srv.Close()
		n := newNode(t)
		if err := n.syncTrustedKeys(context.Background(), srv.URL); err != nil {
			t.Fatalf("syncTrustedKeys: %v", err)
		}
		if len(n.trustedKeys) != 2 || !containsTrustedKey(n.trustedKeys, retiredPub) || !containsTrustedKey(n.trustedKeys, currentPub) {
			t.Errorf("trust set = %d keys, want retired and current", len(n.trustedKeys))
		}
		stored, err := n.Store.LoadTrustedKeys()
		if err != nil {
			t.Fatal(err)
		}
		if len(stored) != 2 {
			t.Errorf("persisted %d keys, want 2", len(stored))
		}
		if n.identityPredatesRotation() {
			t.Error("a node without an identity has nothing to refresh")
		}
	})

	t.Run("rejects a set no trusted key signed", func(t *testing.T) {
		srv := keysServer(t, []ed25519.PublicKey{strangerPub}, []ed25519.PrivateKey{strangerPriv})
		defer srv.Close()
		n := newNode(t)
		if err := n.syncTrustedKeys(context.Background(), srv.URL); err == nil {
			t.Fatal("a /keys answer signed only by an unknown key must not be adopted")
		}
		if len(n.trustedKeys) != 1 || !n.trustedKeys[0].Key.Equal(currentPub) {
			t.Errorf("trust set changed on a rejected answer: %d keys", len(n.trustedKeys))
		}
	})

	t.Run("rejects an unsigned set", func(t *testing.T) {
		srv := keysServer(t, []ed25519.PublicKey{currentPub, strangerPub}, nil)
		defer srv.Close()
		n := newNode(t)
		if err := n.syncTrustedKeys(context.Background(), srv.URL); err == nil {
			t.Fatal("an unsigned /keys answer must not be adopted")
		}
		if containsTrustedKey(n.trustedKeys, strangerPub) {
			t.Error("unsigned answer widened the trust set")
		}
	})

	t.Run("nothing trusted yet is an error, not a wipe", func(t *testing.T) {
		srv := keysServer(t, []ed25519.PublicKey{currentPub}, []ed25519.PrivateKey{currentPriv})
		defer srv.Close()
		n := newNode(t)
		n.trustedKeys = nil
		if err := n.syncTrustedKeys(context.Background(), srv.URL); err == nil {
			t.Fatal("with no trusted key there is nothing to verify /keys against")
		}
	})
}

// A ban the control plane holds is applied, one it no longer holds is lifted,
// and one recorded after the answer was requested is left alone: the answer
// predates it and cannot speak to it. The wire form may be any encoding of
// the peer ID; the cache is keyed on the canonical one.
func TestReconcileBannedPeers(t *testing.T) {
	stillBanned := randomPeerID(t)
	unbanned := randomPeerID(t)
	newlyBanned := randomPeerID(t)
	bannedAfterFetch := randomPeerID(t)

	cache, err := lru.New[string, int64](10)
	if err != nil {
		t.Fatal(err)
	}
	n := &AgentMeshNode{revokedPeers: cache}
	fetchedAt := time.Now()
	n.revokedPeers.Add(stillBanned.String(), fetchedAt.Add(-time.Hour).UnixMilli())
	n.revokedPeers.Add(unbanned.String(), fetchedAt.Add(-time.Hour).UnixMilli())
	n.revokedPeers.Add(bannedAfterFetch.String(), fetchedAt.UnixMilli())

	n.reconcileBannedPeers([]string{stillBanned.String(), peer.ToCid(newlyBanned).String(), "not-a-peer-id"}, fetchedAt)

	for _, want := range []peer.ID{stillBanned, newlyBanned, bannedAfterFetch} {
		if !n.revokedPeers.Contains(want.String()) {
			t.Errorf("%s must be banned after reconciliation", want)
		}
	}
	if n.revokedPeers.Contains(peer.ToCid(newlyBanned).String()) {
		t.Error("the cache must be keyed on the canonical peer ID, not the wire encoding")
	}
	if n.revokedPeers.Contains(unbanned.String()) {
		t.Error("a peer absent from the control plane's ban set must be unbanned")
	}
}

// One pull brings keys, bans and policy together, and a failing part does
// not stop the others from landing.
func TestSyncControlPlane(t *testing.T) {
	oldPub, oldPriv := mustGenerateKey(t)
	newPub, newPriv := mustGenerateKey(t)
	banned := randomPeerID(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", keysHandler(t, []ed25519.PublicKey{oldPub, newPub}, []ed25519.PrivateKey{oldPriv, newPriv}))
	mux.HandleFunc("/info", protoHandler(t, &api.ControlPlaneInfoResponse{
		RouterAddresses: []string{"/ip4/10.0.0.1/tcp/4501/p2p/" + randomPeerID(t).String()},
		BannedPeerIds:   []string{banned.String()},
	}))
	mux.HandleFunc("/policies", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "policy store down", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := store.SaveControlPlaneURL(srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMeshConfig(oldPub, nil); err != nil {
		t.Fatal(err)
	}
	cache, err := lru.New[string, int64](10)
	if err != nil {
		t.Fatal(err)
	}
	n := &AgentMeshNode{Store: store, revokedPeers: cache, trustedKeys: []TrustedKey{{Key: oldPub, ReceivedAt: time.Now()}}}
	n.SetIdentityCache([]byte("identity"))

	err = n.SyncControlPlane(context.Background())
	if err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("SyncControlPlane = %v, want the policy failure reported", err)
	}
	if !containsTrustedKey(n.trustedKeys, newPub) {
		t.Error("rotated key not learned although /keys answered")
	}
	if !n.revokedPeers.Contains(banned.String()) {
		t.Error("ban not applied although /info answered")
	}
	_, addrs, err := store.LoadMeshConfig()
	if err != nil {
		t.Fatalf("LoadMeshConfig: %v", err)
	}
	if len(addrs) != 1 {
		t.Errorf("router addresses not persisted: got %v, want 1", addrs)
	}
	// Before Start the answer also becomes the static relays Start will dial.
	if len(n.config.RouterAddrs) != 1 || n.config.RouterAddrs[0].String() != addrs[0] {
		t.Errorf("router addresses not adopted before start: got %v, want %v", n.config.RouterAddrs, addrs)
	}
}

// datalog_rules is the only source of mesh policy rules: the node evaluates
// the text as it arrives and never derives rules from roles and bindings, so
// a control plane that still sends those is reported instead of tolerated.
func TestSyncMeshPolicyUsesDatalogRules(t *testing.T) {
	// What a control plane from before the contract sends: roles and bindings
	// in the field numbers PolicyConfigGetResponse now reserves.
	oldPolicy := &api.PolicyConfigGetResponse{}
	oldWire, err := proto.Marshal(&api.PolicyConfig{
		Roles:    []*api.PolicyRole{{Name: "dev", AllowedServices: []string{"mcp://git"}}},
		Bindings: []*api.PolicyBinding{{Role: "dev", Members: []string{"group:developers"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	oldPolicy.ProtoReflect().SetUnknown(oldWire)

	tests := []struct {
		name      string
		resp      *api.PolicyConfigGetResponse
		wantRules int
		wantErr   string
	}{
		{
			name:      "text rules are adopted as sent",
			resp:      &api.PolicyConfigGetResponse{DatalogRules: []string{`role("dev") <- group("developers")`}},
			wantRules: 1,
		},
		{
			name:    "roles and bindings name an old control plane",
			resp:    oldPolicy,
			wantErr: "predates datalog_rules",
		},
		{
			name:    "one unparseable rule rejects the whole set",
			resp:    &api.PolicyConfigGetResponse{DatalogRules: []string{`role("dev") <- group("developers")`, `broken(`}},
			wantErr: "unparseable rule",
		},
		{
			name:      "empty policy is empty",
			resp:      &api.PolicyConfigGetResponse{},
			wantRules: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/policies", protoHandler(t, tt.resp))
			srv := httptest.NewServer(mux)
			defer srv.Close()

			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			if err := store.SaveControlPlaneURL(srv.URL); err != nil {
				t.Fatal(err)
			}
			n := &AgentMeshNode{Store: store}
			n.SetIdentityCache([]byte("identity"))

			err = n.syncMeshPolicy(context.Background())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("syncMeshPolicy error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("syncMeshPolicy: %v", err)
			}
			if got := len(n.MeshPolicyRules); got != tt.wantRules {
				t.Fatalf("adopted %d rules, want %d", got, tt.wantRules)
			}
		})
	}
}

// The loop is what turns a missed gossip event into a delay rather than a
// permanent split: a running node picks the successor key up on its own, and
// a trigger brings the next pull forward.
func TestControlPlaneSyncLoop(t *testing.T) {
	oldPub, oldPriv := mustGenerateKey(t)
	newPub, newPriv := mustGenerateKey(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", keysHandler(t, []ed25519.PublicKey{oldPub, newPub}, []ed25519.PrivateKey{oldPriv, newPriv}))
	mux.HandleFunc("/info", protoHandler(t, &api.ControlPlaneInfoResponse{}))
	mux.HandleFunc("/policies", protoHandler(t, &api.PolicyConfigGetResponse{}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := store.SaveControlPlaneURL(srv.URL); err != nil {
		t.Fatal(err)
	}

	priv := GetOrGenerateKey(store)
	n := &AgentMeshNode{
		Store:                   store,
		trustedKeys:             []TrustedKey{{Key: oldPub, ReceivedAt: time.Now()}},
		controlPlaneSyncTrigger: make(chan struct{}, 1),
		config:                  Options{PrivKey: priv, ControlPlaneSyncJitter: time.Millisecond},
	}
	n.SetIdentityCache([]byte("identity"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A long interval: only the trigger can make the first pull happen in time.
	n.startControlPlaneSyncLoop(ctx, time.Hour)
	n.triggerControlPlaneSync()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n.keysMu.RLock()
		learned := containsTrustedKey(n.trustedKeys, newPub)
		n.keysMu.RUnlock()
		if learned {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("triggered control plane sync never picked up the rotated key")
}

func TestFetchControlPlaneInfo(t *testing.T) {
	expectedInfo := &api.ControlPlaneInfoResponse{
		RouterAddresses: []string{"/ip4/127.0.0.1/tcp/4001"},
		OidcIssuer:      "https://issuer.example.com",
		ClientId:        "client-id",
	}

	body, err := proto.Marshal(expectedInfo)
	if err != nil {
		t.Fatalf("Failed to marshal info: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/info" {
			t.Errorf("Expected path /info, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	info, err := FetchControlPlaneInfo(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchControlPlaneInfo failed: %v", err)
	}

	if !reflect.DeepEqual(info.RouterAddresses, expectedInfo.RouterAddresses) {
		t.Errorf("Expected RouterAddresses %v, got %v", expectedInfo.RouterAddresses, info.RouterAddresses)
	}
	if info.OidcIssuer != expectedInfo.OidcIssuer {
		t.Errorf("Expected OidcIssuer %s, got %s", expectedInfo.OidcIssuer, info.OidcIssuer)
	}
	if info.ClientId != expectedInfo.ClientId {
		t.Errorf("Expected ClientId %s, got %s", expectedInfo.ClientId, info.ClientId)
	}
}

func TestFetchControlPlaneInfo_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := FetchControlPlaneInfo(context.Background(), server.URL)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "control plane returned status 500 Internal Server Error") {
		t.Errorf("Expected error to contain '500 Internal Server Error', got %v", err)
	}
}

func TestFetchControlPlaneInfo_InvalidProto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid data"))
	}))
	defer server.Close()

	_, err := FetchControlPlaneInfo(context.Background(), server.URL)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode /info response") {
		t.Errorf("Expected error to contain 'failed to decode /info response', got %v", err)
	}
}

// A node built from stored config, as agentmesh-node run does, must come out of
// its pre-start pull with the control plane's current router addresses and
// the full key set, both in memory and on disk; and an unreachable control
// plane must leave the stored config in place rather than blank it.
func TestSyncControlPlaneBeforeStart(t *testing.T) {
	cpPub, cpPriv := mustGenerateKey(t)
	gracePub, gracePriv := mustGenerateKey(t)
	freshRouter := "/ip4/10.0.0.9/tcp/4501/p2p/" + randomPeerID(t).String()

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", keysHandler(t, []ed25519.PublicKey{cpPub, gracePub}, []ed25519.PrivateKey{cpPriv, gracePriv}))
	mux.HandleFunc("/info", protoHandler(t, &api.ControlPlaneInfoResponse{RouterAddresses: []string{freshRouter}}))
	mux.HandleFunc("/policies", protoHandler(t, &api.PolicyConfigGetResponse{}))
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		var refresh api.TokenRefreshRequest
		if err != nil || proto.Unmarshal(body, &refresh) != nil {
			t.Error("invalid refresh request")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		peerID, err := peer.Decode(refresh.PeerId)
		if err != nil {
			t.Error(err)
			return
		}
		writeRefreshResponse(t, w, mintRoleBiscuit(t, cpPriv, peerID, api.RoleNode))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	newStoredNode := func(t *testing.T, controlPlaneURL string) *AgentMeshNode {
		t.Helper()
		store, err := NewStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if err := store.SaveMeshConfig(cpPub, []string{"/ip4/1.2.3.4/tcp/1234"}); err != nil {
			t.Fatal(err)
		}
		if err := store.SaveControlPlaneURL(controlPlaneURL); err != nil {
			t.Fatal(err)
		}
		if err := store.SaveTrustedKeys([]TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}}); err != nil {
			t.Fatal(err)
		}
		stale, err := multiaddr.NewMultiaddr("/ip4/1.2.3.4/tcp/1234")
		if err != nil {
			t.Fatal(err)
		}
		priv := GetOrGenerateKey(store)
		peerID, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		n, err := NewAgentMeshNode(Options{PrivKey: priv, Store: store, ControlPlanePubKey: cpPub, RouterAddrs: []multiaddr.Multiaddr{stale}})
		if err != nil {
			t.Fatal(err)
		}
		identity := mintRoleBiscuit(t, cpPriv, peerID, api.RoleNode)
		if err := store.SaveIdentity(identity); err != nil {
			t.Fatal(err)
		}
		n.SetIdentityCache(identity)
		return n
	}

	t.Run("reachable control plane", func(t *testing.T) {
		n := newStoredNode(t, srv.URL)
		if err := n.SyncControlPlane(context.Background()); err != nil {
			t.Fatalf("SyncControlPlane: %v", err)
		}
		if len(n.config.RouterAddrs) != 1 || n.config.RouterAddrs[0].String() != freshRouter {
			t.Errorf("RouterAddrs = %v, want the control plane's %s", n.config.RouterAddrs, freshRouter)
		}
		if len(n.trustedKeys) != 2 || !containsTrustedKey(n.trustedKeys, gracePub) {
			t.Errorf("trust set = %d keys, want the enrollment key and the grace key", len(n.trustedKeys))
		}
		savedPub, savedAddrs, err := n.Store.LoadMeshConfig()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(savedPub, cpPub) || len(savedAddrs) != 1 || savedAddrs[0] != freshRouter {
			t.Errorf("persisted mesh config = (%x, %v), want (%x, [%s])", savedPub, savedAddrs, cpPub, freshRouter)
		}
		stored, err := n.Store.LoadTrustedKeys()
		if err != nil {
			t.Fatal(err)
		}
		if len(stored) != 2 {
			t.Errorf("persisted %d trusted keys, want 2", len(stored))
		}
	})

	t.Run("unreachable control plane keeps the stored config", func(t *testing.T) {
		down := httptest.NewServer(http.NotFoundHandler())
		down.Close()
		n := newStoredNode(t, down.URL)
		if err := n.SyncControlPlane(context.Background()); err == nil {
			t.Fatal("SyncControlPlane against a closed server must report the failure")
		}
		if len(n.config.RouterAddrs) != 1 || n.config.RouterAddrs[0].String() != "/ip4/1.2.3.4/tcp/1234" {
			t.Errorf("RouterAddrs = %v, want the stored address kept", n.config.RouterAddrs)
		}
		if len(n.trustedKeys) != 1 || !n.trustedKeys[0].Key.Equal(cpPub) {
			t.Errorf("trust set = %d keys, want the stored key kept", len(n.trustedKeys))
		}
	})
}

// Whoever answers /keys must already be the control plane: a set that is not
// signed by a key the node trusts leaves the trust set untouched, in memory
// and on disk, while the rest of the pull still lands.
func TestSyncControlPlaneRefusesUntrustedKeySet(t *testing.T) {
	cpPub, _ := mustGenerateKey(t)
	attackerPub, attackerPriv := mustGenerateKey(t)

	for name, keysResp := range map[string]*api.KeysResponse{
		"unsigned set": {PublicKeys: [][]byte{cpPub, attackerPub}},
		"set signed only by the attacker": func() *api.KeysResponse {
			r := &api.KeysResponse{PublicKeys: [][]byte{cpPub, attackerPub}}
			if err := api.SignKeysResponse(r, []ed25519.PrivateKey{attackerPriv, attackerPriv}, time.Now()); err != nil {
				t.Fatal(err)
			}
			return r
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/keys", protoHandler(t, keysResp))
			mux.HandleFunc("/info", protoHandler(t, &api.ControlPlaneInfoResponse{RouterAddresses: []string{"/ip4/127.0.0.1/tcp/4001"}}))
			mux.HandleFunc("/policies", protoHandler(t, &api.PolicyConfigGetResponse{}))
			srv := httptest.NewServer(mux)
			defer srv.Close()

			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			if err := store.SaveMeshConfig(cpPub, nil); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveControlPlaneURL(srv.URL); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveTrustedKeys([]TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}}); err != nil {
				t.Fatal(err)
			}
			n := &AgentMeshNode{Store: store, trustedKeys: []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}}}
			n.SetIdentityCache([]byte("identity"))

			err = n.SyncControlPlane(context.Background())
			if err == nil || !strings.Contains(err.Error(), "keys") {
				t.Fatalf("SyncControlPlane = %v, want the /keys rejection reported", err)
			}
			if len(n.trustedKeys) != 1 || !n.trustedKeys[0].Key.Equal(cpPub) {
				t.Fatalf("in-memory trust set was replaced by an unverified /keys answer: %d keys", len(n.trustedKeys))
			}
			trusted, err := store.LoadTrustedKeys()
			if err != nil {
				t.Fatal(err)
			}
			if len(trusted) != 1 || !trusted[0].Key.Equal(cpPub) {
				t.Fatalf("persisted trust set was replaced by an unverified /keys answer: %d keys", len(trusted))
			}
			if len(n.config.RouterAddrs) != 1 {
				t.Errorf("a rejected /keys must not stop /info from landing: RouterAddrs = %v", n.config.RouterAddrs)
			}
		})
	}
}

// The control plane is the trust root, so a plaintext hop to it is refused
// unless the operator opted in; loopback is the standalone case and is fine.
func TestControlPlaneClientRefusesPlaintextToNonLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := proto.Marshal(&api.ControlPlaneInfoResponse{})
		_, _ = w.Write(body)
	}))
	defer server.Close()
	// httptest binds 127.0.0.1; spell it as a non-loopback name that the
	// transport must refuse before any connection is attempted.
	nonLoopbackURL := strings.Replace(server.URL, "127.0.0.1", "agentmesh-control-plane.invalid", 1)

	t.Cleanup(func() { SetAllowInsecureControlPlane(false) })

	if _, err := FetchControlPlaneInfo(context.Background(), server.URL); err != nil {
		t.Fatalf("loopback plaintext must be accepted: %v", err)
	}

	_, err := FetchControlPlaneInfo(context.Background(), nonLoopbackURL)
	if !errors.Is(err, api.ErrInsecureControlPlaneURL) {
		t.Fatalf("plaintext to a non-loopback host: err = %v, want %v", err, api.ErrInsecureControlPlaneURL)
	}

	// With the opt-in the request is attempted; the name does not resolve,
	// which is a dial error, not the policy error.
	SetAllowInsecureControlPlane(true)
	_, err = FetchControlPlaneInfo(context.Background(), nonLoopbackURL)
	if err == nil || errors.Is(err, api.ErrInsecureControlPlaneURL) {
		t.Fatalf("with --insecure-control-plane the policy must not be what fails: %v", err)
	}
}

func TestReportNodeCatalog(t *testing.T) {
	services := []*api.ServiceInfo{
		{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "stvv-compliance-docs", Description: "doc lookup"},
	}

	var gotAuth, gotContentType string
	var gotReq api.NodeCatalogReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/nodes/catalog" {
			t.Errorf("Expected path /nodes/catalog, got %s", r.URL.Path)
		}
		if userAgent := r.UserAgent(); !strings.HasPrefix(userAgent, "agentmesh-node/") || userAgent == "agentmesh-node/" {
			t.Errorf("Expected versioned agentmesh-node User-Agent, got %q", userAgent)
		}
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
		}
		if err := proto.Unmarshal(body, &gotReq); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	biscuitToken := []byte("fake-biscuit-bytes")
	if err := ReportNodeCatalog(context.Background(), server.URL, biscuitToken, services); err != nil {
		t.Fatalf("ReportNodeCatalog failed: %v", err)
	}

	wantAuth := "Bearer " + base64.StdEncoding.EncodeToString(biscuitToken)
	if gotAuth != wantAuth {
		t.Errorf("Expected Authorization header %q, got %q", wantAuth, gotAuth)
	}
	if gotContentType != "application/x-protobuf" {
		t.Errorf("Expected Content-Type application/x-protobuf, got %q", gotContentType)
	}
	if len(gotReq.Services) != 1 || gotReq.Services[0].Name != "stvv-compliance-docs" || gotReq.Services[0].Type != api.ServiceType_SERVICE_TYPE_MCP {
		t.Errorf("Expected relayed services %v, got %v", services, gotReq.Services)
	}
}

func TestReportNodeCatalog_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "node not enrolled or not admitted", http.StatusUnauthorized)
	}))
	defer server.Close()

	err := ReportNodeCatalog(context.Background(), server.URL, []byte("fake-biscuit-bytes"), nil)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), "control plane returned status 401") {
		t.Errorf("Expected error to mention status 401, got %v", err)
	}
}

// newCatalogTestNode is a AgentMeshNode with just enough state for the catalog
// loop: a store holding the control-plane URL, a cached identity, and a
// registry with one service.
func newCatalogTestNode(t *testing.T, controlPlaneURL string) *AgentMeshNode {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if controlPlaneURL != "" {
		if err := store.SaveControlPlaneURL(controlPlaneURL); err != nil {
			t.Fatalf("SaveControlPlaneURL: %v", err)
		}
	}
	node := &AgentMeshNode{Store: store, services: newServiceRegistryForTest(&fakeDHT{})}
	node.services.insertService(newFakeSvc("calc", api.ServiceType_SERVICE_TYPE_MCP))
	return node
}

func TestReportNodeCatalog_Preconditions(t *testing.T) {
	noURL := newCatalogTestNode(t, "")
	noURL.SetIdentityCache([]byte("biscuit"))
	if err := noURL.reportNodeCatalog(context.Background()); err == nil || !strings.Contains(err.Error(), "control plane URL") {
		t.Errorf("without a control-plane URL: got %v, want a URL error", err)
	}

	noIdentity := newCatalogTestNode(t, "http://127.0.0.1:1")
	if err := noIdentity.reportNodeCatalog(context.Background()); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Errorf("without an identity: got %v, want an identity error", err)
	}
}

// The loop must report once after the initial delay and then keep reporting
// every interval, carrying the live service list each time.
func TestStartCatalogReportLoop(t *testing.T) {
	reports := make(chan *api.NodeCatalogReport, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/catalog" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var report api.NodeCatalogReport
		if err := proto.Unmarshal(body, &report); err != nil {
			t.Errorf("decode report: %v", err)
		}
		reports <- &report
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	node := newCatalogTestNode(t, server.URL)
	node.SetIdentityCache([]byte("biscuit"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node.startCatalogReportLoop(ctx, 10*time.Millisecond, 20*time.Millisecond)

	for i := 0; i < 3; i++ {
		select {
		case report := <-reports:
			if len(report.Services) != 1 || report.Services[0].Name != "calc" {
				t.Fatalf("report %d: got services %v, want [calc]", i, report.Services)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for report %d", i)
		}
	}

	// Cancelling stops the loop: no report after the in-flight one settles.
	cancel()
	time.Sleep(100 * time.Millisecond)
	for len(reports) > 0 {
		<-reports
	}
	select {
	case <-reports:
		t.Fatal("loop kept reporting after context cancellation")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestOptionsDefault_CatalogReport(t *testing.T) {
	var o Options
	o.Default()
	if o.CatalogReportInterval != time.Minute {
		t.Errorf("CatalogReportInterval = %v, want 1m", o.CatalogReportInterval)
	}
	if o.CatalogReportInitialDelay != 5*time.Second {
		t.Errorf("CatalogReportInitialDelay = %v, want 5s", o.CatalogReportInitialDelay)
	}

	custom := Options{CatalogReportInterval: 3 * time.Second, CatalogReportInitialDelay: time.Second}
	custom.Default()
	if custom.CatalogReportInterval != 3*time.Second || custom.CatalogReportInitialDelay != time.Second {
		t.Errorf("Default overwrote explicit values: %+v", custom)
	}
}
