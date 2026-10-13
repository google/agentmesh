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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// refreshHarness is a node with a stored identity and a mock control plane
// whose /refresh answer the test chooses.
type refreshHarness struct {
	node     *AgentMeshNode
	cpPub    ed25519.PublicKey
	cpPriv   ed25519.PrivateKey
	peerID   peer.ID
	identity []byte
}

func mintRoleBiscuit(t *testing.T, priv ed25519.PrivateKey, peerID peer.ID, role string) []byte {
	t.Helper()
	builder := biscuit.NewBuilder(priv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(peerID.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(role)}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(24 * time.Hour))}}},
	} {
		if err := builder.AddAuthorityFact(f); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	b, err := tok.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newRefreshHarness(t *testing.T, refresh http.HandlerFunc) *refreshHarness {
	t.Helper()
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	privKey := GetOrGenerateKey(store)
	peerID, err := peer.IDFromPublicKey(privKey.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	current := mintRoleBiscuit(t, cpPriv, peerID, api.RoleNode)
	if err := store.SaveIdentity(current); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveIdentityKeySet([]ed25519.PublicKey{cpPub}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/refresh", refresh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if err := store.SaveControlPlaneURL(srv.URL); err != nil {
		t.Fatal(err)
	}

	node := &AgentMeshNode{
		Store:          store,
		trustedKeys:    []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
		config:         Options{RequiredRole: api.RoleNode},
	}
	node.SetIdentityCache(current)
	return &refreshHarness{node: node, cpPub: cpPub, cpPriv: cpPriv, peerID: peerID, identity: current}
}

func writeRefreshResponse(t *testing.T, w http.ResponseWriter, token []byte) {
	t.Helper()
	data, err := proto.Marshal(&api.TokenRefreshResponse{BiscuitToken: token, ExpireTime: timestamppb.New(time.Now().Add(24 * time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(data)
}

func TestRotationRefreshDuringControlPlaneSync(t *testing.T) {
	for _, viaEvent := range []bool{false, true} {
		name := "periodic sync"
		if viaEvent {
			name = "rotation event"
		}
		t.Run(name, func(t *testing.T) {
			newPub, newPriv := mustGenerateKey(t)
			var fresh []byte
			var refreshes atomic.Int32
			refresh := func(w http.ResponseWriter, request *http.Request) {
				if refreshes.Add(1) == 1 {
					http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
					return
				}
				writeRefreshResponse(t, w, fresh)
			}
			harness := newRefreshHarness(t, refresh)
			fresh = mintRoleBiscuit(t, newPriv, harness.peerID, api.RoleNode)
			mux := http.NewServeMux()
			mux.HandleFunc("/keys", keysHandler(t, []ed25519.PublicKey{harness.cpPub, newPub}, []ed25519.PrivateKey{harness.cpPriv, newPriv}))
			mux.HandleFunc("/refresh", refresh)
			mux.HandleFunc("/info", protoHandler(t, &api.ControlPlaneInfoResponse{}))
			mux.HandleFunc("/policies", protoHandler(t, &api.PolicyConfigGetResponse{}))
			server := httptest.NewServer(mux)
			defer server.Close()
			if err := harness.node.Store.SaveControlPlaneURL(server.URL); err != nil {
				t.Fatal(err)
			}
			if viaEvent {
				harness.node.controlPlaneSyncTrigger = make(chan struct{}, 1)
				harness.node.handleKeyRotationEvent(&api.MeshEvent{NewPublicKey: newPub})
				select {
				case <-harness.node.controlPlaneSyncTrigger:
				default:
					t.Fatal("rotation event did not trigger a control-plane sync")
				}
			}
			if err := harness.node.SyncControlPlane(context.Background()); err == nil {
				t.Fatal("sync must report the failed credential refresh")
			}
			harness.storedIdentityUnchanged(t)
			if err := harness.node.SyncControlPlane(context.Background()); err != nil {
				t.Fatalf("retry refresh: %v", err)
			}
			if !bytes.Equal(harness.node.GetIdentity(), fresh) {
				t.Fatal("node kept a credential signed by the retiring key")
			}
			if err := harness.node.SyncControlPlane(context.Background()); err != nil {
				t.Fatalf("unchanged keys: %v", err)
			}
			if got := refreshes.Load(); got != 2 {
				t.Fatalf("refresh attempts = %d, want one failure and one success", got)
			}
		})
	}
}

// A rotation learned before a restart must still be acted on after it: the
// persisted key set is then unchanged, so the decision cannot hinge on
// noticing a new key. Identities issued by builds that recorded no key set
// fall back to the enrollment key stored in the mesh config.
func TestRotationRefreshSurvivesRestart(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "recorded key set"
		if legacy {
			name = "pre-upgrade identity"
		}
		t.Run(name, func(t *testing.T) {
			newPub, newPriv := mustGenerateKey(t)
			var fresh []byte
			var refreshes atomic.Int32
			refresh := func(w http.ResponseWriter, request *http.Request) {
				if refreshes.Add(1) == 1 {
					http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
					return
				}
				writeRefreshResponse(t, w, fresh)
			}
			harness := newRefreshHarness(t, refresh)
			fresh = mintRoleBiscuit(t, newPriv, harness.peerID, api.RoleNode)
			store := harness.node.Store
			if legacy {
				if err := store.SaveIdentityKeySet(nil); err != nil {
					t.Fatal(err)
				}
				if err := store.SaveMeshConfig(harness.cpPub, nil); err != nil {
					t.Fatal(err)
				}
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/keys", keysHandler(t, []ed25519.PublicKey{harness.cpPub, newPub}, []ed25519.PrivateKey{harness.cpPriv, newPriv}))
			mux.HandleFunc("/refresh", refresh)
			mux.HandleFunc("/info", protoHandler(t, &api.ControlPlaneInfoResponse{}))
			mux.HandleFunc("/policies", protoHandler(t, &api.PolicyConfigGetResponse{}))
			server := httptest.NewServer(mux)
			defer server.Close()
			if err := store.SaveControlPlaneURL(server.URL); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveTrustedKeys([]TrustedKey{{Key: harness.cpPub, ReceivedAt: time.Now()}}); err != nil {
				t.Fatal(err)
			}

			if err := harness.node.SyncControlPlane(context.Background()); err == nil {
				t.Fatal("sync must report the failed credential refresh")
			}
			harness.storedIdentityUnchanged(t)

			// Restart: only what the store holds carries over.
			restarted, err := NewAgentMeshNode(Options{PrivKey: GetOrGenerateKey(store), Store: store, ControlPlanePubKey: harness.cpPub, RequiredRole: api.RoleNode, BiscuitTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if len(restarted.trustedKeys) != 2 {
				t.Fatalf("restarted node loaded %d trusted keys, want the persisted pair", len(restarted.trustedKeys))
			}
			if err := restarted.SyncControlPlane(context.Background()); err != nil {
				t.Fatalf("refresh after restart: %v", err)
			}
			if !bytes.Equal(restarted.GetIdentity(), fresh) {
				t.Fatal("restarted node kept a credential signed by the retiring key")
			}
			if err := restarted.SyncControlPlane(context.Background()); err != nil {
				t.Fatalf("settled sync: %v", err)
			}
			if got := refreshes.Load(); got != 2 {
				t.Fatalf("refresh attempts = %d, want one failure before and one success after the restart", got)
			}
		})
	}
}

// The control plane redeems only the last biscuit it issued, so the rotation
// sync and the expiry renewal loop must not refresh at the same time: the
// loser would present an already-rotated biscuit and be refused as a replay.
func TestConcurrentRefreshesAreSerialized(t *testing.T) {
	var mu sync.Mutex
	var lastIssued []byte
	var harness *refreshHarness
	harness = newRefreshHarness(t, func(w http.ResponseWriter, request *http.Request) {
		presented, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !bytes.Equal(presented, lastIssued) {
			http.Error(w, "Biscuit already rotated", http.StatusUnauthorized)
			return
		}
		lastIssued = mintRoleBiscuit(t, harness.cpPriv, harness.peerID, api.RoleNode)
		writeRefreshResponse(t, w, lastIssued)
	})
	lastIssued = harness.identity

	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- harness.node.RefreshEnrollment(context.Background()) }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent refresh: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(harness.node.GetIdentity(), lastIssued) {
		t.Fatal("node does not hold the last biscuit the control plane issued")
	}
}

func (h *refreshHarness) storedIdentityUnchanged(t *testing.T) {
	t.Helper()
	stored, err := h.node.Store.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, h.identity) {
		t.Error("stored identity was replaced by a response that must not have been accepted")
	}
	if !bytes.Equal(h.node.GetIdentity(), h.identity) {
		t.Error("cached identity was replaced by a response that must not have been accepted")
	}
}

// A 403 from whoever answers /refresh is not the control plane's word that
// this node is banned; that is a verified MeshEvent_BANNED. The node reports
// the refusal and keeps its current identity instead of exiting.
func TestRefreshEnrollmentForbiddenDoesNotExit(t *testing.T) {
	h := newRefreshHarness(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "node banned", http.StatusForbidden)
	})

	err := h.node.RefreshEnrollment(context.Background())
	var rerr *RefreshError
	if !errors.As(err, &rerr) || rerr.StatusCode != http.StatusForbidden {
		t.Fatalf("RefreshEnrollment = %v, want *RefreshError with 403", err)
	}
	h.storedIdentityUnchanged(t)
}

// The refreshed token is held to the same bar as the enrolled one: signed by
// a key this node already trusts, bound to this peer, carrying its role.
func TestRefreshEnrollmentRejectsUntrustworthyToken(t *testing.T) {
	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPeer := randomPeerID(t)

	tests := []struct {
		name string
		mint func(h *refreshHarness) []byte
	}{
		{"signed by an untrusted key", func(h *refreshHarness) []byte {
			return mintRoleBiscuit(t, strangerPriv, h.peerID, api.RoleNode)
		}},
		{"bound to another peer", func(h *refreshHarness) []byte {
			return mintRoleBiscuit(t, h.cpPriv, otherPeer, api.RoleNode)
		}},
		{"wrong role", func(h *refreshHarness) []byte {
			return mintRoleBiscuit(t, h.cpPriv, h.peerID, api.RoleRouter)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h *refreshHarness
			h = newRefreshHarness(t, func(w http.ResponseWriter, r *http.Request) {
				writeRefreshResponse(t, w, tt.mint(h))
			})
			if err := h.node.RefreshEnrollment(context.Background()); err == nil {
				t.Fatal("RefreshEnrollment accepted a token it must have rejected")
			}
			h.storedIdentityUnchanged(t)
		})
	}

	t.Run("a good token is adopted", func(t *testing.T) {
		var h *refreshHarness
		h = newRefreshHarness(t, func(w http.ResponseWriter, r *http.Request) {
			writeRefreshResponse(t, w, mintRoleBiscuit(t, h.cpPriv, h.peerID, api.RoleNode))
		})
		if err := h.node.RefreshEnrollment(context.Background()); err != nil {
			t.Fatalf("RefreshEnrollment: %v", err)
		}
		if bytes.Equal(h.node.GetIdentity(), h.identity) {
			t.Error("a valid refreshed token must replace the current identity")
		}
	})
}
