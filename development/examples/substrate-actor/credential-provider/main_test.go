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

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/pkg/proto/credproviderpb"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const demoActor = "spiffe://substrate-actor.local/actor/ate-demo-sandbox/demo"

// fakeNode is the token endpoint: it verifies the assertion against the
// provider's own JWKS, the way the control plane does, and answers with a
// Biscuit for a bound subject or an OAuth error for anyone else.
func fakeNode(t *testing.T, s *signer, bound string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	var keys jwt.VerificationKeySet
	var set struct {
		Keys []struct {
			Kid, X, Y string
		} `json:"keys"`
	}
	if err := json.Unmarshal(s.jwks, &set); err != nil || len(set.Keys) != 1 || set.Keys[0].Kid != s.kid {
		t.Fatalf("jwks: %v %s", err, s.jwks)
	}
	keys.Keys = append(keys.Keys, &s.key.PublicKey)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/oauth/token" || r.FormValue("grant_type") != grantTypeTokenExchange || r.FormValue("subject_token_type") != tokenTypeJWT {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		claims := jwt.MapClaims{}
		tok, err := jwt.ParseWithClaims(r.FormValue("subject_token"), claims, func(*jwt.Token) (any, error) { return keys, nil },
			jwt.WithIssuer(s.issuer), jwt.WithAudience(s.audience), jwt.WithValidMethods([]string{"ES256"}))
		if err != nil || !tok.Valid || tok.Header["kid"] != s.kid {
			http.Error(w, "bad assertion: "+err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if sub, _ := claims["sub"].(string); sub != bound {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "no role for " + sub})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "biscuit-for-" + bound, "token_type": "Bearer", "expires_in": 300})
	}))
}

func newTestProvider(t *testing.T, node string, ttl time.Duration) (*provider, *signer) {
	t.Helper()
	s, err := newSigner("http://provider.test", "agentmesh")
	if err != nil {
		t.Fatal(err)
	}
	return &provider{
		name: "agentmesh", instance: "mesh", trustDomain: "substrate-actor.local", signer: s, node: node,
		cacheTTL: ttl, http: &http.Client{Timeout: 5 * time.Second}, cache: map[string]*cached{},
	}, s
}

func TestFetchSecretMintsAndCachesPerActor(t *testing.T) {
	var calls atomic.Int32
	p, s := newTestProvider(t, "", time.Minute)
	node := fakeNode(t, s, demoActor, &calls)
	defer node.Close()
	p.node = node.URL

	req := &credproviderpb.FetchSecretRequest{Uri: "ate-secret://agentmesh/mesh/biscuit", ActorSpiffeId: demoActor}
	for i := range 3 {
		resp, err := p.FetchSecret(context.Background(), req)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if string(resp.GetOpaqueBytes()) != "biscuit-for-"+demoActor {
			t.Fatalf("call %d: credential %q", i, resp.GetOpaqueBytes())
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected one token exchange for three requests, got %d", got)
	}

	// A different actor is a different subject and a different exchange.
	other := "spiffe://substrate-actor.local/actor/ate-demo-sandbox/rogue"
	_, err := p.FetchSecret(context.Background(), &credproviderpb.FetchSecretRequest{Uri: req.Uri, ActorSpiffeId: other})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unbound actor: got %v, want PermissionDenied", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected the unbound actor to reach the node once, got %d calls", got)
	}
}

func TestFetchSecretRefusesWhatItDoesNotServe(t *testing.T) {
	var calls atomic.Int32
	p, s := newTestProvider(t, "", time.Minute)
	node := fakeNode(t, s, demoActor, &calls)
	defer node.Close()
	p.node = node.URL

	for _, tc := range []struct {
		name, uri, actor string
		code             codes.Code
	}{
		{"other provider", "ate-secret://k8s.io/agentmesh/secret/key", demoActor, codes.NotFound},
		{"other instance", "ate-secret://agentmesh/other/biscuit", demoActor, codes.NotFound},
		{"other tail", "ate-secret://agentmesh/mesh/token", demoActor, codes.NotFound},
		{"query", "ate-secret://agentmesh/mesh/biscuit?scope=x", demoActor, codes.NotFound},
		{"pod identity, not an actor", "ate-secret://agentmesh/mesh/biscuit", "spiffe://cluster.local/ns/ate-system/sa/atenet-egress", codes.PermissionDenied},
		{"ateom identity, not an actor", "ate-secret://agentmesh/mesh/biscuit", "spiffe://substrate-actor.local/ateom-for-actor/a/b", codes.PermissionDenied},
		{"empty actor", "ate-secret://agentmesh/mesh/biscuit", "", codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.FetchSecret(context.Background(), &credproviderpb.FetchSecretRequest{Uri: tc.uri, ActorSpiffeId: tc.actor})
			if status.Code(err) != tc.code {
				t.Fatalf("got %v, want %v", err, tc.code)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("a refused request must not reach the node")
	}
}

func TestCacheHonoursTTL(t *testing.T) {
	var calls atomic.Int32
	p, s := newTestProvider(t, "", 0)
	node := fakeNode(t, s, demoActor, &calls)
	defer node.Close()
	p.node = node.URL
	req := &credproviderpb.FetchSecretRequest{Uri: "ate-secret://agentmesh/mesh/biscuit", ActorSpiffeId: demoActor}
	for range 2 {
		if _, err := p.FetchSecret(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("cache-ttl 0 must mint on every request, got %d calls", calls.Load())
	}
}

func TestDiscoveryDocument(t *testing.T) {
	s, err := newSigner("http://provider.test", "agentmesh")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct {
		Issuer  string   `json:"issuer"`
		JWKSURI string   `json:"jwks_uri"`
		Algs    []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Issuer != "http://provider.test" || doc.JWKSURI != "http://provider.test/keys" || len(doc.Algs) != 1 || doc.Algs[0] != "ES256" {
		t.Fatalf("discovery document: %+v", doc)
	}
	keys, err := http.Get(srv.URL + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Body.Close()
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(keys.Body).Decode(&set); err != nil || len(set.Keys) != 1 || set.Keys[0]["kid"] != s.kid || set.Keys[0]["crv"] != "P-256" {
		t.Fatalf("jwks: %v %+v", err, set)
	}
}
