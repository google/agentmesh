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

package router

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
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// A router pointed at a plaintext control plane on another host has no way
// to know who it is talking to, so Options refuse it unless the operator
// says the network is trusted. Loopback is the standalone case.
func TestOptionsValidateControlPlaneTransport(t *testing.T) {
	tests := []struct {
		url      string
		insecure bool
		wantErr  bool
	}{
		{"http://127.0.0.1:8080", false, false},
		{"https://cp.example.com", false, false},
		{"http://agentmesh-control-plane:8080", false, true},
		{"http://agentmesh-control-plane:8080", true, false},
	}
	for _, tt := range tests {
		o := Options{ControlPlaneURL: tt.url, AllowInsecureControlPlane: tt.insecure}
		o.Default()
		err := o.Validate()
		if (err != nil) != tt.wantErr {
			t.Errorf("Validate(%q, insecure=%v) = %v, wantErr %v", tt.url, tt.insecure, err, tt.wantErr)
		}
		if tt.wantErr && !errors.Is(err, api.ErrInsecureControlPlaneURL) {
			t.Errorf("Validate(%q) = %v, want %v", tt.url, err, api.ErrInsecureControlPlaneURL)
		}
	}
}

// The transport re-checks the policy on every hop, so a stored or redirected
// plaintext URL is refused just like a flag-supplied one.
func TestControlPlaneClientRefusesPlaintextHop(t *testing.T) {
	r := &Router{config: Options{}}
	req, err := http.NewRequest(http.MethodGet, "http://agentmesh-control-plane:8080/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.controlPlaneClient(time.Second).Do(req)
	if !errors.Is(err, api.ErrInsecureControlPlaneURL) {
		t.Fatalf("Do = %v, want %v", err, api.ErrInsecureControlPlaneURL)
	}
}

// /keys may only replace the trust set when signed by a key already in it.
func TestSyncKeysRequiresTrustedSignature(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	newRouter := func() *Router {
		return &Router{ctx: context.Background(), config: Options{ControlPlaneURL: srv.URL}, trustedPublicKeys: []ed25519.PublicKey{oldPub}}
	}
	marshal := func(resp *api.KeysResponse) []byte {
		data, err := proto.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	t.Run("rotation signed by the retiring key is adopted", func(t *testing.T) {
		resp := &api.KeysResponse{PublicKeys: [][]byte{oldPub, newPub}}
		if err := api.SignKeysResponse(resp, []ed25519.PrivateKey{oldPriv, newPriv}, time.Now()); err != nil {
			t.Fatal(err)
		}
		body = marshal(resp)
		r := newRouter()
		if err := r.syncKeys(); err != nil {
			t.Fatalf("syncKeys: %v", err)
		}
		if keys := r.getTrustedPublicKeys(); len(keys) != 2 || !keys[1].Equal(newPub) {
			t.Errorf("trusted keys = %d, want old and new", len(keys))
		}
	})

	t.Run("empty set preserves trusted keys", func(t *testing.T) {
		body = marshal(&api.KeysResponse{SignTime: timestamppb.Now()})
		router := newRouter()
		if err := router.syncKeys(); err == nil {
			t.Fatal("an empty /keys answer must not be adopted")
		}
		if keys := router.getTrustedPublicKeys(); len(keys) != 1 || !keys[0].Equal(oldPub) {
			t.Errorf("trust set changed on an empty answer: %d keys", len(keys))
		}
	})

	t.Run("unsigned set is refused", func(t *testing.T) {
		body = marshal(&api.KeysResponse{PublicKeys: [][]byte{oldPub, attackerPub}})
		r := newRouter()
		if err := r.syncKeys(); err == nil {
			t.Fatal("an unsigned /keys answer must not be adopted")
		}
		if keys := r.getTrustedPublicKeys(); len(keys) != 1 || !keys[0].Equal(oldPub) {
			t.Errorf("trust set changed on a refused answer: %d keys", len(keys))
		}
	})

	t.Run("set signed only by a stranger is refused", func(t *testing.T) {
		resp := &api.KeysResponse{PublicKeys: [][]byte{oldPub, attackerPub}}
		if err := api.SignKeysResponse(resp, []ed25519.PrivateKey{attackerPriv, attackerPriv}, time.Now()); err != nil {
			t.Fatal(err)
		}
		body = marshal(resp)
		r := newRouter()
		if err := r.syncKeys(); err == nil {
			t.Fatal("a /keys answer signed by an untrusted key must not be adopted")
		}
		if keys := r.getTrustedPublicKeys(); len(keys) != 1 || !keys[0].Equal(oldPub) {
			t.Errorf("trust set changed on a refused answer: %d keys", len(keys))
		}
	})
}

func TestKeysSyncLoopCoalescesTriggers(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := &api.KeysResponse{PublicKeys: [][]byte{publicKey}}
	if err := api.SignKeysResponse(keys, []ed25519.PrivateKey{privateKey}, time.Now()); err != nil {
		t.Fatal(err)
	}
	body, err := proto.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan struct{}, 4)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- struct{}{}
		select {
		case <-release:
			_, _ = w.Write(body)
		case <-request.Context().Done():
		}
	}))
	t.Cleanup(server.Close)
	router, err := NewRouter(context.Background(), Options{ControlPlaneURL: server.URL, KeysSyncInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	router.trustedPublicKeys = []ed25519.PublicKey{publicKey}
	router.wg.Add(1)
	go router.runKeysSyncLoop()
	t.Cleanup(func() {
		router.cancel()
		router.wg.Wait()
	})
	await := func(signal <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-signal:
		case <-time.After(2 * time.Second):
			t.Fatal(message)
		}
	}
	router.triggerKeysSync()
	await(requests, "key sync did not start")
	notified := make(chan struct{})
	go func() {
		for range 10 {
			router.triggerKeysSync()
		}
		router.getTrustedPublicKeys()
		close(notified)
	}()
	await(notified, "notifications or key readers blocked on the control-plane request")
	if pending := len(router.keysSyncTrigger); pending != 1 {
		t.Fatalf("pending triggers = %d, want one coalesced follow-up", pending)
	}
	release <- struct{}{}
	await(requests, "pending key sync was lost")
	if pending := len(router.keysSyncTrigger); pending != 0 {
		t.Fatalf("pending triggers = %d after follow-up", pending)
	}
}

func TestSyncKeysRefreshesOnRotation(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	fresh := mintRouterBiscuit(t, newPriv, peerID, api.RoleRouter)
	keys := &api.KeysResponse{PublicKeys: [][]byte{oldPub, newPub}}
	if err := api.SignKeysResponse(keys, []ed25519.PrivateKey{oldPriv, newPriv}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var response proto.Message
		switch request.URL.Path {
		case "/keys":
			response = keys
		case "/refresh":
			if refreshes.Add(1) == 1 {
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			response = &api.TokenRefreshResponse{BiscuitToken: fresh, ExpireTime: timestamppb.New(time.Now().Add(24 * time.Hour))}
		default:
			t.Errorf("unexpected request to %s", request.URL.Path)
			http.NotFound(w, request)
			return
		}
		body, marshalErr := proto.Marshal(response)
		if marshalErr != nil {
			t.Error(marshalErr)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	router := &Router{
		ctx:               context.Background(),
		privKey:           priv,
		credential:        credential{biscuit: mintRouterBiscuit(t, oldPriv, peerID, api.RoleRouter), issuedUnder: []ed25519.PublicKey{oldPub}},
		trustedPublicKeys: []ed25519.PublicKey{oldPub},
		config:            Options{ControlPlaneURL: server.URL, RequiredRole: api.RoleRouter, BiscuitTimeout: time.Second},
	}
	if err := router.syncKeys(); err == nil {
		t.Fatal("rotation sync must report the failed credential refresh")
	}
	if err := router.syncKeys(); err != nil {
		t.Fatalf("retry refresh: %v", err)
	}
	if !bytes.Equal(router.credential.biscuit, fresh) {
		t.Fatal("router kept a credential signed by the retiring key")
	}
	if err := router.syncKeys(); err != nil {
		t.Fatalf("unchanged keys: %v", err)
	}
	if got := refreshes.Load(); got != 2 {
		t.Fatalf("refresh attempts = %d, want one failure and one success", got)
	}

	// A freshly enrolled router knows one key; its first sync learns the
	// grace key too. That is not a rotation its new biscuit predates.
	enrolled := &Router{
		ctx:               context.Background(),
		privKey:           priv,
		credential:        credential{biscuit: fresh},
		trustedPublicKeys: []ed25519.PublicKey{newPub},
		config:            Options{ControlPlaneURL: server.URL, RequiredRole: api.RoleRouter, BiscuitTimeout: time.Second},
	}
	if err := enrolled.syncKeys(); err != nil {
		t.Fatalf("first sync after enrollment: %v", err)
	}
	if got := refreshes.Load(); got != 2 {
		t.Fatalf("first sync after enrollment refreshed (%d attempts total)", got)
	}
	if len(enrolled.credential.issuedUnder) != 2 {
		t.Fatalf("issuance set = %d keys, want the synced pair", len(enrolled.credential.issuedUnder))
	}
}

// The control plane redeems only the last biscuit it issued, so the keys
// loop, the renewal loop and lease recovery must not refresh concurrently.
func TestRouterConcurrentRefreshesAreSerialized(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	lastIssued := mintRouterBiscuit(t, cpPriv, peerID, api.RoleRouter)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
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
		lastIssued = mintRouterBiscuit(t, cpPriv, peerID, api.RoleRouter)
		body, err := proto.Marshal(&api.TokenRefreshResponse{BiscuitToken: lastIssued, ExpireTime: timestamppb.New(time.Now().Add(time.Hour))})
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	router := &Router{
		privKey:           priv,
		credential:        credential{biscuit: lastIssued},
		trustedPublicKeys: []ed25519.PublicKey{cpPub},
		config:            Options{ControlPlaneURL: server.URL, RequiredRole: api.RoleRouter, BiscuitTimeout: time.Second},
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- router.RefreshEnrollment(context.Background()) }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent refresh: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(router.credential.biscuit, lastIssued) {
		t.Fatal("router does not hold the last biscuit the control plane issued")
	}
}

func mintRouterBiscuit(t *testing.T, priv ed25519.PrivateKey, peerID peer.ID, role string) []byte {
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

// A 403 from /refresh is reported, not obeyed with an exit; and a refreshed
// token is held to the enrollment bar (trusted signer, this peer, router role).
func TestRouterRefreshEnrollmentHardening(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	current := mintRouterBiscuit(t, cpPriv, peerID, api.RoleRouter)

	var respond func(w http.ResponseWriter)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/refresh" {
			t.Errorf("unexpected request to %s", r.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
			return
		}
		respond(w)
	}))
	defer srv.Close()

	newRouter := func() *Router {
		return &Router{
			privKey:           priv,
			credential:        credential{biscuit: current},
			trustedPublicKeys: []ed25519.PublicKey{cpPub},
			config:            Options{ControlPlaneURL: srv.URL, RequiredRole: api.RoleRouter, BiscuitTimeout: time.Second},
		}
	}
	tokenResponse := func(token []byte) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			data, err := proto.Marshal(&api.TokenRefreshResponse{BiscuitToken: token, ExpireTime: timestamppb.New(time.Now().Add(time.Hour))})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(data)
		}
	}

	t.Run("403 is an error, not an exit", func(t *testing.T) {
		respond = func(w http.ResponseWriter) { http.Error(w, "router banned", http.StatusForbidden) }
		r := newRouter()
		err := r.RefreshEnrollment(context.Background())
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("RefreshEnrollment = %v, want a 403 error", err)
		}
		if !bytes.Equal(r.credential.biscuit, current) {
			t.Error("the current biscuit must be kept on a refused refresh")
		}
	})

	for name, token := range map[string][]byte{
		"token signed by an untrusted key": mintRouterBiscuit(t, strangerPriv, peerID, api.RoleRouter),
		"token bound to another peer":      mintRouterBiscuit(t, cpPriv, newTestPeerID(t), api.RoleRouter),
		"token without the router role":    mintRouterBiscuit(t, cpPriv, peerID, api.RoleNode),
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			respond = tokenResponse(token)
			r := newRouter()
			if err := r.RefreshEnrollment(context.Background()); err == nil {
				t.Fatal("RefreshEnrollment adopted a token it must have refused")
			}
			if !bytes.Equal(r.credential.biscuit, current) {
				t.Error("the current biscuit must be kept when the refreshed one is refused")
			}
		})
	}

	t.Run("a good token is adopted", func(t *testing.T) {
		fresh := mintRouterBiscuit(t, cpPriv, peerID, api.RoleRouter)
		respond = tokenResponse(fresh)
		r := newRouter()
		if err := r.RefreshEnrollment(context.Background()); err != nil {
			t.Fatalf("RefreshEnrollment: %v", err)
		}
		if !bytes.Equal(r.credential.biscuit, fresh) {
			t.Error("a valid refreshed token must replace the current one")
		}
	})
}
