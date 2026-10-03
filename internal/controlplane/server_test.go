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

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/node"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func startCustomMockOIDC(t *testing.T) (string, func(claims map[string]interface{}) string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   issuer,
			"jwks_uri": issuer + "/keys",
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "mock-key",
					"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				},
			},
		})
	})

	mintToken := func(customClaims map[string]interface{}) string {
		claims := jwt.MapClaims{
			"iss": issuer,
			"aud": "sam-mesh-audience",
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		for k, v := range customClaims {
			claims[k] = v
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "mock-key"
		jwtStr, err := token.SignedString(privKey)
		if err != nil {
			t.Fatalf("failed to sign jwt: %v", err)
		}
		return jwtStr
	}

	return issuer, mintToken
}

func setupTestServer(t *testing.T, oidcIssuer string, overrides ...func(*Options)) (*Server, storage.Store, string) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "sam-cp-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	dbPath := filepath.Join(tempDir, "control-plane.db")
	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	opts := Options{
		ListenAddr:            "127.0.0.1:0", // Auto-allocate port
		DriverName:            "sqlite",
		DataSourceName:        dbPath,
		OIDCIssuer:            oidcIssuer,
		AllowedAudiences:      []string{"sam-mesh-audience"},
		LeaseDuration:         10 * time.Second,
		KeyRotationInterval:   12 * time.Hour,
		KeyGracePeriod:        10 * time.Minute,
		InsecureSkipTLSVerify: true,
		BiscuitTimeout:        10 * time.Second,
	}
	for _, fn := range overrides {
		fn(&opts)
	}

	srv, err := NewServer(opts, store)
	if err != nil {
		t.Fatalf("failed to create control plane server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start control plane server: %v", err)
	}

	serverAddr := srv.listener.Addr().String()

	return srv, store, "http://" + serverAddr
}

func TestControlPlaneBasic(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	client := &http.Client{Timeout: 5 * time.Second}

	// Test /healthz
	respHealth, err := client.Get(baseURL + "/healthz")
	if err != nil || respHealth.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz failed: %v, status: %v", err, respHealth.Status)
	}
	_ = respHealth.Body.Close()

	// Test /readyz
	respReady, err := client.Get(baseURL + "/readyz")
	if err != nil || respReady.StatusCode != http.StatusOK {
		t.Fatalf("GET /readyz failed: %v, status: %v", err, respReady.Status)
	}
	_ = respReady.Body.Close()

	// Test /metrics
	respMetrics, err := client.Get(baseURL + "/metrics")
	if err != nil || respMetrics.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics failed: %v, status: %v", err, respMetrics.Status)
	}
	_ = respMetrics.Body.Close()

	// 1. Test /info (no routers registered yet)
	resp, err := client.Get(baseURL + "/info")
	if err != nil {
		t.Fatalf("GET /info failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected GET /info status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read /info body: %v", err)
	}

	var info api.ControlPlaneInfoResponse
	if err := proto.Unmarshal(body, &info); err != nil {
		t.Fatalf("failed to unmarshal ControlPlaneInfoResponse: %v", err)
	}
	if info.OidcIssuer != issuer || info.ClientId != "sam-mesh-audience" {
		t.Errorf("unexpected info response claims: %+v", &info)
	}
	if len(info.RouterAddresses) != 0 {
		t.Errorf("expected 0 active routers, got %d", len(info.RouterAddresses))
	}

	// With an explicit OIDC client id, /info must advertise it while the
	// audience stays the first allowed audience.
	t.Run("explicit oidc client id", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "cp-clientid.db")
		st, err := storage.NewSQLStore("sqlite", dbPath)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		defer func() { _ = st.Close() }()

		srv2, err := NewServer(Options{
			DriverName:       "sqlite",
			DataSourceName:   dbPath,
			OIDCIssuer:       issuer,
			OIDCClientID:     "sam-cli-app",
			AllowedAudiences: []string{"sam-mesh-audience"},
		}, st)
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		rec := httptest.NewRecorder()
		srv2.HandleInfo(rec, httptest.NewRequest(http.MethodGet, "/info", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("unexpected /info status: %d", rec.Code)
		}
		var info2 api.ControlPlaneInfoResponse
		if err := proto.Unmarshal(rec.Body.Bytes(), &info2); err != nil {
			t.Fatalf("failed to unmarshal ControlPlaneInfoResponse: %v", err)
		}
		if info2.ClientId != "sam-cli-app" || info2.Audience != "sam-mesh-audience" {
			t.Errorf("unexpected client id/audience: %+v", &info2)
		}
	})

	// 2. Test /keys
	resp, err = client.Get(baseURL + "/keys")
	if err != nil {
		t.Fatalf("GET /keys failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected GET /keys status: %s", resp.Status)
	}
	body, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read /keys body: %v", err)
	}

	var keys api.KeysResponse
	if err := proto.Unmarshal(body, &keys); err != nil {
		t.Fatalf("failed to unmarshal KeysResponse: %v", err)
	}
	if len(keys.PublicKeys) != 1 {
		t.Errorf("expected 1 valid public key, got %d", len(keys.PublicKeys))
	}
	// The set is self-certifying for anyone already holding a listed key.
	verified, err := api.VerifyKeysResponse(&keys, []ed25519.PublicKey{ed25519.PublicKey(keys.PublicKeys[0])}, time.Now())
	if err != nil {
		t.Fatalf("/keys response does not verify under its own listed key: %v", err)
	}
	if len(verified) != 1 {
		t.Errorf("verified key set has %d keys, want 1", len(verified))
	}
}

func TestNodeAndRouterRegistrationFlow(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()

	// 1. Setup policy configuration in the database
	roles := []*api.PolicyRole{
		{
			Name:            api.RoleRouter,
			AllowedServices: []string{"*"},
			AllowedTargets:  []string{"*"},
		},
		{
			Name:            "user-role",
			AllowedServices: []string{"mcp:read"},
		},
	}
	bindings := []*api.PolicyBinding{
		{Role: api.RoleRouter, Members: []string{"group:routers"}},
		{Role: api.RoleNode, Members: []string{"group:users"}},
		{Role: "user-role", Members: []string{"group:users"}},
	}
	if err := store.SaveMeshPolicy(ctx, roles, bindings); err != nil {
		t.Fatalf("failed to seed policy: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// 2. Enroll a Node
	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	nodeJWT := mintToken(map[string]interface{}{
		"sub":    "node-alice",
		"groups": []string{"users"},
	})

	nodePubKeyBytes, _ := crypto.MarshalPublicKey(privNode.GetPublic())
	nodeTS, nodeSig := registerPoP(t, privNode, nodePeer.String())
	enrollNodeReq := &api.EnrollRequest{
		Jwt:                nodeJWT,
		PeerId:             nodePeer.String(),
		PublicKey:          nodePubKeyBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    nodeTS,
		ChallengeSignature: nodeSig,
	}
	reqData, _ := proto.Marshal(enrollNodeReq)

	resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("node /register failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("node /register status failure: %s (body: %s)", resp.Status, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollNodeResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollNodeResp); err != nil {
		t.Fatalf("failed to unmarshal EnrollResponse: %v", err)
	}
	if len(enrollNodeResp.BiscuitToken) == 0 {
		t.Fatalf("received empty biscuit token for node")
	}

	// 3. Enroll a Router
	privRouter, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	routerPeer, err := peer.IDFromPrivateKey(privRouter)
	if err != nil {
		t.Fatal(err)
	}

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-host-1",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	routerPubKeyBytes, _ := crypto.MarshalPublicKey(privRouter.GetPublic())
	routerTS, routerSig := registerPoP(t, privRouter, routerPeer.String())
	enrollRouterReq := &api.EnrollRequest{
		Jwt:                routerJWT,
		PeerId:             routerPeer.String(),
		PublicKey:          routerPubKeyBytes,
		RequestedRole:      api.RoleRouter,
		ChallengeUnixMs:    routerTS,
		ChallengeSignature: routerSig,
	}
	reqData, _ = proto.Marshal(enrollRouterReq)

	resp, err = client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("router /register failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("router /register status failure: %s", resp.Status)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollRouterResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollRouterResp); err != nil {
		t.Fatalf("failed to unmarshal EnrollResponse: %v", err)
	}
	if len(enrollRouterResp.BiscuitToken) == 0 {
		t.Fatalf("received empty biscuit token for router")
	}

	// 4. Register Router Lease
	routerAddresses := []string{"/ip4/127.0.0.1/tcp/5001/p2p/" + routerPeer.String()}
	leaseTS, leaseSig := leasePoP(t, privRouter, routerPeer.String())
	leaseReq := &api.RouterLeaseRequest{
		PeerId:             routerPeer.String(),
		Addresses:          routerAddresses,
		Biscuit:            enrollRouterResp.BiscuitToken,
		ChallengeUnixMs:    leaseTS,
		ChallengeSignature: leaseSig,
	}
	reqData, _ = proto.Marshal(leaseReq)

	resp, err = client.Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("POST /routers/lease failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /routers/lease status failure: %s (body: %s)", resp.Status, string(body))
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var leaseResp api.RouterLeaseResponse
	if err := proto.Unmarshal(body, &leaseResp); err != nil {
		t.Fatalf("failed to unmarshal RouterLeaseResponse: %v", err)
	}
	if !leaseResp.Success {
		t.Errorf("lease registration was not successful: %s", leaseResp.Error)
	}

	// 5. Query /info again, checking if the active router address list is now populated
	resp, err = client.Get(baseURL + "/info")
	if err != nil {
		t.Fatalf("GET /info failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var info api.ControlPlaneInfoResponse
	_ = proto.Unmarshal(body, &info)

	if !reflect.DeepEqual(info.RouterAddresses, routerAddresses) {
		t.Errorf("expected active routers address list %v, got %v", routerAddresses, info.RouterAddresses)
	}

	// 5b. Leases that would redirect joiners are refused: malformed
	// multiaddrs and addresses terminating at another peer.
	for name, badAddr := range map[string]string{
		"not a multiaddr": "not-even-a-multiaddr",
		"missing p2p":     "/ip4/203.0.113.66/tcp/4001",
		"foreign peer":    "/ip4/203.0.113.66/tcp/4001/p2p/" + nodePeer.String(),
	} {
		badTS, badSig := leasePoP(t, privRouter, routerPeer.String())
		badLease := &api.RouterLeaseRequest{
			PeerId:             routerPeer.String(),
			Addresses:          []string{badAddr},
			Biscuit:            enrollRouterResp.BiscuitToken,
			ChallengeUnixMs:    badTS,
			ChallengeSignature: badSig,
		}
		reqData, _ = proto.Marshal(badLease)
		resp, err = client.Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(reqData))
		if err != nil {
			t.Fatalf("POST bad lease (%s) failed: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for lease with %s, got: %s", name, resp.Status)
		}
	}

	// 6. Rogue Node tries to lease as a router (lacks 'router' role)
	rogueTS, rogueSig := leasePoP(t, privNode, nodePeer.String())
	rogueLeaseReq := &api.RouterLeaseRequest{
		PeerId:             nodePeer.String(),
		Addresses:          []string{"/ip4/127.0.0.1/tcp/6001/p2p/" + nodePeer.String()},
		Biscuit:            enrollNodeResp.BiscuitToken, // Node biscuit doesn't have router role
		ChallengeUnixMs:    rogueTS,
		ChallengeSignature: rogueSig,
	}
	reqData, _ = proto.Marshal(rogueLeaseReq)

	resp, err = client.Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("POST rogue /routers/lease failed: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expectedStatusForbidden (403) for rogue router lease, got: %s", resp.Status)
	}

	// 7. Lease poisoning by an enrolled node. Routers send their biscuit to
	// every peer they authenticate, so the node holds a copy; a lease that
	// needed only the biscuit let it rewrite the router's addresses for every
	// joining peer. The node signs the challenge with the only key it has.
	for name, poisoned := range map[string]*api.RouterLeaseRequest{
		"no challenge": {
			PeerId:    routerPeer.String(),
			Addresses: []string{},
			Biscuit:   enrollRouterResp.BiscuitToken,
		},
		"challenge signed with the node's key": func() *api.RouterLeaseRequest {
			ts, sig := leasePoP(t, privNode, routerPeer.String())
			return &api.RouterLeaseRequest{
				PeerId:             routerPeer.String(),
				Addresses:          []string{"/ip4/203.0.113.66/tcp/4001/p2p/" + routerPeer.String()},
				Biscuit:            enrollRouterResp.BiscuitToken,
				ChallengeUnixMs:    ts,
				ChallengeSignature: sig,
			}
		}(),
		"stale router signature": func() *api.RouterLeaseRequest {
			ts := time.Now().Add(-challengeMaxAge - time.Minute).UnixMilli()
			sig, err := privRouter.Sign(api.RouterLeaseChallenge(routerPeer.String(), ts))
			if err != nil {
				t.Fatal(err)
			}
			return &api.RouterLeaseRequest{
				PeerId:             routerPeer.String(),
				Addresses:          []string{},
				Biscuit:            enrollRouterResp.BiscuitToken,
				ChallengeUnixMs:    ts,
				ChallengeSignature: sig,
			}
		}(),
	} {
		reqData, err := proto.Marshal(poisoned)
		if err != nil {
			t.Fatalf("marshal poisoned lease (%s): %v", name, err)
		}
		resp, err = client.Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(reqData))
		if err != nil {
			t.Fatalf("POST poisoned lease (%s) failed: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("poisoned lease (%s): got %s, want 401", name, resp.Status)
		}
	}
	// The router's advertised addresses are untouched.
	resp, err = client.Get(baseURL + "/info")
	if err != nil {
		t.Fatalf("GET /info failed: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read /info: %v", err)
	}
	var infoAfter api.ControlPlaneInfoResponse
	if err := proto.Unmarshal(body, &infoAfter); err != nil {
		t.Fatalf("unmarshal /info: %v", err)
	}
	if !reflect.DeepEqual(infoAfter.RouterAddresses, routerAddresses) {
		t.Errorf("router addresses after poisoning attempts = %v, want %v", infoAfter.RouterAddresses, routerAddresses)
	}
}

// The console renders this JSON for editing and posts the result straight back,
// so anything the render drops is silently deleted from the mesh policy on the
// next save. protojson is generated, which is the point: a hand-written renderer
// is what lost custom_datalog before.
// Members reserve on the first router they are handed, so every router has
// to come first for some of them, and a router's addresses have to stay
// together so "the first router" is one router.
func TestRouterAddressesSpreadMembersAcrossRouters(t *testing.T) {
	routers := func() []storage.RouterLease {
		return []storage.RouterLease{
			{PeerID: "a", Addresses: []string{"/ip4/10.0.0.1/tcp/4501/p2p/a", "/ip4/10.0.0.1/udp/4501/quic-v1/p2p/a"}},
			{PeerID: "b", Addresses: []string{"/ip4/10.0.0.2/tcp/4501/p2p/b", "/ip4/10.0.0.2/udp/4501/quic-v1/p2p/b"}},
			{PeerID: "c", Addresses: []string{"/ip4/10.0.0.3/tcp/4501/p2p/c"}},
		}
	}
	routerOf := func(addr string) string { return addr[strings.LastIndex(addr, "/")+1:] }
	first := map[string]int{}
	for i := 0; i < 300; i++ {
		addrs := routerAddresses(routers())
		if len(addrs) != 5 {
			t.Fatalf("got %d addresses, want every router's 5", len(addrs))
		}
		first[routerOf(addrs[0])]++
		// Once a router's run of addresses ends, that router is not seen again.
		seen := map[string]bool{}
		for j, addr := range addrs {
			id := routerOf(addr)
			if seen[id] && routerOf(addrs[j-1]) != id {
				t.Fatalf("router %s's addresses are split in %v", id, addrs)
			}
			seen[id] = true
		}
	}
	// (2/3)^300 that a router never comes first by chance.
	for _, id := range []string{"a", "b", "c"} {
		if first[id] == 0 {
			t.Errorf("router %s never came first in 300 responses: %v", id, first)
		}
	}
}

func TestMarshalPolicyJSONRoundTrip(t *testing.T) {
	roles := []*api.PolicyRole{
		{
			Name:            "dev",
			AllowedServices: []string{"mcp://git"},
			AllowedTargets:  []string{"node:abc"},
			CustomDatalog:   []string{"right(\"data:read\");"},
		},
		{
			Name:            "ops",
			AllowedServices: []string{"mcp://deploy"},
		},
	}
	bindings := []*api.PolicyBinding{
		{Role: "dev", Members: []string{"group:developers"}},
		{Role: "ops", Members: []string{"user:root"}},
	}

	rendered, err := marshalPolicyJSON(roles, bindings, nil)
	if err != nil {
		t.Fatalf("rendering the policy: %v", err)
	}

	// Proto names, because that is what the docs and the Helm bootstrap job use.
	if !strings.Contains(rendered, "allowed_services") || !strings.Contains(rendered, "custom_datalog") {
		t.Fatalf("rendered policy does not use proto field names:\n%s", rendered)
	}

	// Exactly what the console posts back.
	parsed := &api.PolicyConfig{}
	if err := protojson.Unmarshal([]byte(rendered), parsed); err != nil {
		t.Fatalf("parsing back the rendered policy: %v\n%s", err, rendered)
	}

	if len(parsed.Roles) != len(roles) {
		t.Fatalf("got %d roles, want %d", len(parsed.Roles), len(roles))
	}
	for i, want := range roles {
		if !proto.Equal(parsed.Roles[i], want) {
			t.Errorf("role %d round-tripped as %v, want %v", i, parsed.Roles[i], want)
		}
	}
	if len(parsed.Bindings) != len(bindings) {
		t.Fatalf("got %d bindings, want %d", len(parsed.Bindings), len(bindings))
	}
	for i, want := range bindings {
		if !proto.Equal(parsed.Bindings[i], want) {
			t.Errorf("binding %d round-tripped as %v, want %v", i, parsed.Bindings[i], want)
		}
	}

	// The result must survive the same validation a POST applies.
	if err := validatePolicyConfig(parsed); err != nil {
		t.Errorf("round-tripped policy failed validation: %v", err)
	}
}

// The console posts the policy editor's contents as protojson, so this is the
// path the only editor a mesh operator has depends on.
func TestPoliciesAcceptConsoleJSON(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	client := &http.Client{Timeout: 5 * time.Second}

	// Proto field names, exactly as the docs and the Helm bootstrap job write them.
	policy := `{
	  "roles": [
	    {
	      "name": "dev",
	      "allowed_services": ["mcp://git"],
	      "allowed_targets": ["group:eng"],
	      "custom_datalog": ["right(\"data:read\");"]
	    }
	  ],
	  "bindings": [{"role": "dev", "members": ["user:bob"]}]
	}`

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/policies", strings.NewReader(policy))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /policies: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /policies as JSON: got %s (body: %s)", resp.Status, body)
	}

	roles, bindings, err := store.GetMeshPolicy(context.Background())
	if err != nil {
		t.Fatalf("reading back the stored policy: %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "dev" {
		t.Fatalf("stored roles = %v, want a single role named dev", roles)
	}
	if len(roles[0].CustomDatalog) != 1 {
		t.Errorf("custom_datalog was dropped on save: %v", roles[0])
	}
	if len(bindings) != 1 || bindings[0].Role != "dev" {
		t.Fatalf("stored bindings = %v, want a single binding for dev", bindings)
	}

	// What /status hands the console must be postable back unchanged.
	rendered, err := marshalPolicyJSON(roles, bindings, nil)
	if err != nil {
		t.Fatalf("rendering the stored policy: %v", err)
	}
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/policies", strings.NewReader(rendered))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("re-posting the rendered policy: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-posting the rendered policy: got %s (body: %s)", resp.Status, body)
	}
}

// A misspelled field is the difference between a permission being granted and
// silently not existing, so it has to be an error rather than a discarded key.
func TestPoliciesRejectUnknownJSONFields(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	client := &http.Client{Timeout: 5 * time.Second}

	for name, policy := range map[string]string{
		"misspelled role field": `{"roles": [{"name": "dev", "allowed_service": ["mcp://git"]}]}`,
		"misspelled top level":  `{"role": [{"name": "dev"}]}`,
		"legacy version key":    `{"version": "v1alpha1", "roles": [{"name": "dev"}]}`,
	} {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/policies", strings.NewReader(policy))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer super-secret-admin-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: POST /policies: %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: got status %d, want %d", name, resp.StatusCode, http.StatusBadRequest)
		}
	}

	// Nothing should have been stored by any of those.
	roles, bindings, err := store.GetMeshPolicy(context.Background())
	if err != nil && err != storage.ErrNotFound {
		t.Fatalf("reading back the stored policy: %v", err)
	}
	if len(roles) != 0 || len(bindings) != 0 {
		t.Errorf("a rejected policy was stored anyway: roles=%v bindings=%v", roles, bindings)
	}
}

func TestPoliciesConfigurationREST(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Get policies without token (should return 401)
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/policies", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated request, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Get policies with incorrect token (should return 401)
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/policies", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid token, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 3. The admin token is not a node credential: GET /policies is the mesh
	// protocol, operators read the document at GET /admin/policy.
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/policies", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for admin token at GET /policies, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, baseURL+"/admin/policy", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/policy failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated GET /admin/policy, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, baseURL+"/admin/policy", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/policy failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for empty policy, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 4. Put policies (should succeed)
	updateReq := &api.PolicyConfig{
		Roles: []*api.PolicyRole{
			{
				Name:            "dev",
				AllowedServices: []string{"mcp://git"},
			},
		},
		Bindings: []*api.PolicyBinding{
			{Role: "dev", Members: []string{"group:developers"}},
		},
	}
	reqData, _ := proto.Marshal(updateReq)

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/policies", bytes.NewReader(reqData))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected POST /policies status: %s (body: %s)", resp.Status, string(body))
	}
	_ = resp.Body.Close()

	// 5. Read the document back as the operator sees it: protojson of
	// PolicyConfig, which is exactly what POST /policies accepts.
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/admin/policy", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/policy failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/policy status failed: %s", resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("GET /admin/policy Content-Type = %q, want application/json", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var getResp api.PolicyConfig
	if err := protojson.Unmarshal(body, &getResp); err != nil {
		t.Fatalf("failed to unmarshal PolicyConfig: %v\n%s", err, body)
	}
	if !strings.Contains(string(body), "allowed_services") {
		t.Errorf("GET /admin/policy does not use proto field names:\n%s", body)
	}
	if !proto.Equal(&getResp, updateReq) {
		t.Errorf("GET /admin/policy = %v, want the posted document %v", &getResp, updateReq)
	}
}

func TestEnrollmentWorkflow(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	// Configure admin token
	srv.config.AdminToken = "super-secret-admin-token"

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Create Bootstrap Token (Manual Approval Gate)
	srv.config.AutoApproveEnrollment = false

	adminReqBody := []byte(`{
		"role": "sam:role:router",
		"ttl_hours": 2,
		"max_usages": 2,
		"description": "Test Mode B"
	}`)

	req, _ := http.NewRequest("POST", baseURL+"/admin/bootstrap-tokens", bytes.NewBuffer(adminReqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to create bootstrap token: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status creating token: %s", resp.Status)
	}

	var tokenDetails struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenDetails)
	_ = resp.Body.Close()

	if tokenDetails.Token == "" || tokenDetails.ID == "" {
		t.Fatalf("empty token details received: %+v", tokenDetails)
	}

	// Generate Client node key
	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, _ := peer.IDFromPrivateKey(privNode)
	pubBytes, _ := crypto.MarshalPublicKey(pubNode)

	// 2. Submit Enrollment Request (Mode B -> PENDING)
	enrollTS, enrollSig := enrollPoP(t, privNode, pID.String())
	enrollReq := &api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleRouter,
		ChallengeUnixMs:    enrollTS,
		ChallengeSignature: enrollSig,
	}
	enrollReqData, _ := proto.Marshal(enrollReq)

	resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewBuffer(enrollReqData))
	if err != nil {
		t.Fatalf("failed to enroll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected enroll status: %s", resp.Status)
	}

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollResp api.BootstrapEnrollResponse
	if err := proto.Unmarshal(body, &enrollResp); err != nil {
		t.Fatalf("failed to unmarshal enroll response: %v", err)
	}
	if enrollResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		t.Errorf("expected PENDING status, got %v", enrollResp.Status)
	}

	// 3. Poll Enrollment Status -> PENDING (signed by the enrollee's key)
	resp, err = client.Do(signedEnrollStatusRequest(t, baseURL, privNode, pID.String(), time.Now().UnixMilli()))
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var statusResp api.BootstrapEnrollResponse
	_ = proto.Unmarshal(body, &statusResp)
	if statusResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		t.Errorf("expected polled status to be PENDING, got %v", statusResp.Status)
	}

	// 4. Admin query list & approve
	req, _ = http.NewRequest("GET", baseURL+"/admin/enrollments", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var enrollList []storage.EnrollmentRequest
	_ = json.NewDecoder(resp.Body).Decode(&enrollList)
	_ = resp.Body.Close()

	if len(enrollList) != 1 || enrollList[0].PeerID != pID.String() {
		t.Fatalf("unexpected enrollments list: %+v", enrollList)
	}
	reqID := enrollList[0].ID

	// Approve
	req, _ = http.NewRequest("POST", baseURL+"/admin/enrollments/"+reqID+"/approve", nil)
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to approve enrollment: %s", resp.Status)
	}
	_ = resp.Body.Close()

	// 5. Poll Status -> APPROVED & Validate Biscuit
	resp, err = client.Do(signedEnrollStatusRequest(t, baseURL, privNode, pID.String(), time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	_ = proto.Unmarshal(body, &statusResp)
	if statusResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		t.Fatalf("expected APPROVED, got %v", statusResp.Status)
	}
	if len(statusResp.BiscuitToken) == 0 {
		t.Fatalf("biscuit token is empty")
	}
	if len(statusResp.ControlPlanePublicKey) == 0 {
		t.Fatalf("control plane public key is empty")
	}

	// Verify Biscuit router rights
	_, cpPub, err := store.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := biscuit.Unmarshal(statusResp.BiscuitToken)
	if err != nil {
		t.Fatalf("failed to unmarshal biscuit: %v", err)
	}
	authorizer, err := b.Authorizer(cpPub, biscuit.WithWorldOptions(datalog.WithMaxDuration(srv.config.BiscuitTimeout)))
	if err != nil {
		t.Fatal(err)
	}
	checkRelay := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRight, IDs: []biscuit.Term{biscuit.String(api.RightRelay)}},
			},
		},
	}}
	authorizer.AddCheck(checkRelay)
	authorizer.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{},
		},
	}, Kind: biscuit.PolicyKindAllow})

	if err := authorizer.Authorize(); err != nil {
		t.Errorf("biscuit validation failed: %v", err)
	}

	// 6. Test Mode A (Auto-Approve)
	srv.config.AutoApproveEnrollment = true

	// Generate new client key
	privNode2, pubNode2, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	pID2, _ := peer.IDFromPrivateKey(privNode2)
	pubBytes2, _ := crypto.MarshalPublicKey(pubNode2)

	enrollTS2, enrollSig2 := enrollPoP(t, privNode2, pID2.String())
	enrollReq2 := &api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token, // use remaining usage
		PeerId:             pID2.String(),
		PublicKey:          pubBytes2,
		RequestedRole:      api.RoleRouter,
		ChallengeUnixMs:    enrollTS2,
		ChallengeSignature: enrollSig2,
	}
	enrollReqData2, _ := proto.Marshal(enrollReq2)

	resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewBuffer(enrollReqData2))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollResp2 api.BootstrapEnrollResponse
	_ = proto.Unmarshal(body, &enrollResp2)
	if enrollResp2.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		t.Errorf("expected immediate APPROVED status in Auto-Approve mode, got %v", enrollResp2.Status)
	}
	if len(enrollResp2.BiscuitToken) == 0 {
		t.Error("biscuit token empty in Auto-Approve response")
	}
}

// signedEnrollStatusRequest builds a GET /enroll/status request carrying the
// proof-of-possession challenge headers signed by priv.
func signedEnrollStatusRequest(t *testing.T, baseURL string, priv crypto.PrivKey, peerID string, ts int64) *http.Request {
	t.Helper()
	sig, err := priv.Sign(api.EnrollStatusChallenge(peerID, ts))
	if err != nil {
		t.Fatalf("failed to sign enroll status challenge: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/enroll/status?peer_id="+peerID, nil)
	if err != nil {
		t.Fatalf("failed to build enroll status request: %v", err)
	}
	req.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(sig))
	return req
}

// enrollPoP returns the timestamp/challenge_signature pair proving possession
// of priv for a POST /enroll as peerID.
func enrollPoP(t *testing.T, priv crypto.PrivKey, peerID string) (int64, []byte) {
	t.Helper()
	ts := time.Now().UnixMilli()
	sig, err := priv.Sign(api.EnrollChallenge(peerID, ts))
	if err != nil {
		t.Fatalf("failed to sign enroll challenge: %v", err)
	}
	return ts, sig
}

// registerPoP signs the POST /register proof-of-possession challenge.
func registerPoP(t *testing.T, priv crypto.PrivKey, peerID string) (int64, []byte) {
	t.Helper()
	ts := time.Now().UnixMilli()
	sig, err := priv.Sign(api.RegisterChallenge(peerID, ts))
	if err != nil {
		t.Fatalf("failed to sign register challenge: %v", err)
	}
	return ts, sig
}

// leasePoP signs the POST /routers/lease proof-of-possession challenge.
func leasePoP(t *testing.T, priv crypto.PrivKey, peerID string) (int64, []byte) {
	t.Helper()
	ts := time.Now().UnixMilli()
	sig, err := priv.Sign(api.RouterLeaseChallenge(peerID, ts))
	if err != nil {
		t.Fatalf("failed to sign lease challenge: %v", err)
	}
	return ts, sig
}

// TestRegisterRequiresProofOfPossession pins audit finding H1: POST /register
// trusted peer_id from the body, so any OIDC identity with a node binding
// could register a victim's peer_id with any public key, overwrite the
// victim's record (NULLing owner_id and autonomous_recovery) and break the
// victim's next /refresh. The JWT says who is asking; the signed challenge
// says they hold the key they are binding.
func TestRegisterRequiresProofOfPossession(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Second}

	if err := store.SaveMeshPolicy(ctx, nil, []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
	}); err != nil {
		t.Fatal(err)
	}

	post := func(req *api.EnrollRequest) (int, string) {
		t.Helper()
		data, err := proto.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(data))
		if err != nil {
			t.Fatalf("/register failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read /register response: %v", err)
		}
		return resp.StatusCode, string(body)
	}

	victimPriv, victimID := newTestKey(t)
	victimPub, err := crypto.MarshalPublicKey(victimPriv.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	attackerPriv, attackerID := newTestKey(t)
	attackerPub, err := crypto.MarshalPublicKey(attackerPriv.GetPublic())
	if err != nil {
		t.Fatal(err)
	}

	// The victim enrolls, with the admin-granted flag the hijack used to strip.
	ts, sig := registerPoP(t, victimPriv, victimID.String())
	if status, body := post(&api.EnrollRequest{
		Jwt: mintToken(map[string]interface{}{"sub": "victim"}), PeerId: victimID.String(), PublicKey: victimPub,
		RequestedRole: api.RoleNode, ChallengeUnixMs: ts, ChallengeSignature: sig,
	}); status != http.StatusOK {
		t.Fatalf("victim registration: got %d (%s), want 200", status, body)
	}
	if err := store.SetNodeAutonomousRecovery(ctx, victimID.String(), true); err != nil {
		t.Fatal(err)
	}

	attackerJWT := mintToken(map[string]interface{}{"sub": "attacker"})
	cases := map[string]struct {
		req  *api.EnrollRequest
		want int
	}{
		"victim peer_id, attacker key, no challenge": {
			req:  &api.EnrollRequest{Jwt: attackerJWT, PeerId: victimID.String(), PublicKey: attackerPub, RequestedRole: api.RoleNode},
			want: http.StatusBadRequest, // peer_id is not the key's own
		},
		"victim peer_id and public key, no challenge": {
			req:  &api.EnrollRequest{Jwt: attackerJWT, PeerId: victimID.String(), PublicKey: victimPub, RequestedRole: api.RoleNode},
			want: http.StatusUnauthorized,
		},
		"victim peer_id and public key, challenge signed by the attacker": {
			req: func() *api.EnrollRequest {
				ts, sig := registerPoP(t, attackerPriv, victimID.String())
				return &api.EnrollRequest{Jwt: attackerJWT, PeerId: victimID.String(), PublicKey: victimPub, RequestedRole: api.RoleNode, ChallengeUnixMs: ts, ChallengeSignature: sig}
			}(),
			want: http.StatusUnauthorized,
		},
		"own key, challenge for another endpoint": {
			req: func() *api.EnrollRequest {
				ts, sig := enrollPoP(t, attackerPriv, attackerID.String())
				return &api.EnrollRequest{Jwt: attackerJWT, PeerId: attackerID.String(), PublicKey: attackerPub, RequestedRole: api.RoleNode, ChallengeUnixMs: ts, ChallengeSignature: sig}
			}(),
			want: http.StatusUnauthorized,
		},
		"own key, stale challenge": {
			req: func() *api.EnrollRequest {
				ts := time.Now().Add(-challengeMaxAge - time.Minute).UnixMilli()
				sig, err := attackerPriv.Sign(api.RegisterChallenge(attackerID.String(), ts))
				if err != nil {
					t.Fatal(err)
				}
				return &api.EnrollRequest{Jwt: attackerJWT, PeerId: attackerID.String(), PublicKey: attackerPub, RequestedRole: api.RoleNode, ChallengeUnixMs: ts, ChallengeSignature: sig}
			}(),
			want: http.StatusUnauthorized,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if status, body := post(tc.req); status != tc.want {
				t.Errorf("got %d (%s), want %d", status, body, tc.want)
			}
		})
	}

	// The victim's record survived every attempt intact.
	victim, err := store.GetNode(ctx, victimID.String())
	if err != nil {
		t.Fatalf("victim record: %v", err)
	}
	if !bytes.Equal(victim.PublicKey, victimPub) {
		t.Error("victim's public key was overwritten")
	}
	if !victim.AutonomousRecovery {
		t.Error("victim's autonomous_recovery flag was reset")
	}
	if _, err := store.GetNode(ctx, attackerID.String()); err != storage.ErrNotFound {
		t.Errorf("attacker's failed attempts left a record: err = %v", err)
	}

	// The same attacker, proving its own key, registers normally.
	ts, sig = registerPoP(t, attackerPriv, attackerID.String())
	if status, body := post(&api.EnrollRequest{
		Jwt: attackerJWT, PeerId: attackerID.String(), PublicKey: attackerPub,
		RequestedRole: api.RoleNode, ChallengeUnixMs: ts, ChallengeSignature: sig,
	}); status != http.StatusOK {
		t.Fatalf("honest registration: got %d (%s), want 200", status, body)
	}
}

// TestBootstrapEnrollmentRequiresProofOfPossession pins the fix for
// GHSA-hp3x-79wr-rx66 on both bootstrap endpoints: neither GET /enroll/status
// nor a repeated POST /enroll may reveal an enrollment's status or biscuit to
// a caller that cannot sign with the enrollee's key — holding a valid
// bootstrap token is not enough.
func TestBootstrapEnrollmentRequiresProofOfPossession(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"
	srv.config.AutoApproveEnrollment = true

	client := &http.Client{Timeout: 5 * time.Second}

	adminReqBody := []byte(`{"role": "sam:role:router", "ttl_hours": 2, "max_usages": 2, "description": "PoP test"}`)
	req, _ := http.NewRequest("POST", baseURL+"/admin/bootstrap-tokens", bytes.NewBuffer(adminReqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to create bootstrap token: %v", err)
	}
	var tokenDetails struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenDetails)
	_ = resp.Body.Close()
	if tokenDetails.Token == "" {
		t.Fatal("empty bootstrap token")
	}

	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, _ := peer.IDFromPrivateKey(priv)
	pubBytes, _ := crypto.MarshalPublicKey(pub)

	enrollTS, enrollSig := enrollPoP(t, priv, pID.String())
	enrollData, _ := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleRouter,
		ChallengeUnixMs:    enrollTS,
		ChallengeSignature: enrollSig,
	})
	resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewReader(enrollData))
	if err != nil {
		t.Fatalf("failed to enroll: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var enrollResp api.BootstrapEnrollResponse
	_ = proto.Unmarshal(body, &enrollResp)
	if enrollResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || len(enrollResp.BiscuitToken) == 0 {
		t.Fatalf("expected auto-approved enrollment with biscuit, got %v", enrollResp.Status)
	}

	otherKey, otherPub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	otherPID, _ := peer.IDFromPrivateKey(otherKey)

	anonReq, _ := http.NewRequest(http.MethodGet, baseURL+"/enroll/status?peer_id="+pID.String(), nil)
	denied := map[string]*http.Request{
		"anonymous poll":  anonReq,
		"wrong key":       signedEnrollStatusRequest(t, baseURL, otherKey, pID.String(), time.Now().UnixMilli()),
		"stale timestamp": signedEnrollStatusRequest(t, baseURL, priv, pID.String(), time.Now().Add(-6*time.Minute).UnixMilli()),
		"unknown peer":    signedEnrollStatusRequest(t, baseURL, otherKey, otherPID.String(), time.Now().UnixMilli()),
	}
	for name, dr := range denied {
		resp, err := client.Do(dr)
		if err != nil {
			t.Fatalf("%s: request failed: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %s (body %q)", name, resp.Status, body)
		}
		if bytes.Contains(body, enrollResp.BiscuitToken) {
			t.Errorf("%s: response leaked the enrollment biscuit", name)
		}
	}

	// Positive control: the enrollee itself still collects its biscuit.
	resp, err = client.Do(signedEnrollStatusRequest(t, baseURL, priv, pID.String(), time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed poll failed: %s (body %q)", resp.Status, body)
	}
	var statusResp api.BootstrapEnrollResponse
	if err := proto.Unmarshal(body, &statusResp); err != nil {
		t.Fatalf("failed to unmarshal status response: %v", err)
	}
	if statusResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || !bytes.Equal(statusResp.BiscuitToken, enrollResp.BiscuitToken) {
		t.Fatalf("signed poll did not return the approved biscuit: %v", statusResp.Status)
	}

	// POST /enroll is gated the same way: the existing-enrollment branch
	// re-mints a fresh biscuit for the peer, so a bootstrap token holder who
	// is not the peer must never reach it.
	postEnroll := func(name string, payload []byte) *api.BootstrapEnrollResponse {
		t.Helper()
		resp, err := client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("%s: POST /enroll failed: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var r api.BootstrapEnrollResponse
		_ = proto.Unmarshal(body, &r)
		return &r
	}

	otherPubBytes, _ := crypto.MarshalPublicKey(otherPub)
	crossTS, crossSig := enrollPoP(t, otherKey, pID.String())
	for name, payload := range map[string]*api.BootstrapEnrollRequest{
		"cross-peer re-fetch with wrong key": {
			BootstrapToken:     tokenDetails.Token,
			PeerId:             pID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleRouter,
			ChallengeUnixMs:    crossTS,
			ChallengeSignature: crossSig,
		},
		"peer_id not derived from public_key": {
			BootstrapToken:     tokenDetails.Token,
			PeerId:             pID.String(),
			PublicKey:          otherPubBytes,
			RequestedRole:      api.RoleRouter,
			ChallengeUnixMs:    crossTS,
			ChallengeSignature: crossSig,
		},
		"missing challenge": {
			BootstrapToken: tokenDetails.Token,
			PeerId:         pID.String(),
			PublicKey:      pubBytes,
			RequestedRole:  api.RoleRouter,
		},
	} {
		data, _ := proto.Marshal(payload)
		r := postEnroll(name, data)
		if r.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
			t.Errorf("%s: expected REJECTED, got %v", name, r.Status)
		}
		if len(r.BiscuitToken) != 0 {
			t.Errorf("%s: response leaked a biscuit", name)
		}
	}

	// The enrollee itself retries POST /enroll idempotently.
	retryTS, retrySig := enrollPoP(t, priv, pID.String())
	retryData, _ := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleRouter,
		ChallengeUnixMs:    retryTS,
		ChallengeSignature: retrySig,
	})
	r := postEnroll("enrollee retry", retryData)
	if r.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		t.Fatalf("enrollee retry did not return APPROVED: %v", r.Status)
	}
	if len(r.BiscuitToken) == 0 {
		t.Fatal("enrollee retry returned an empty biscuit")
	}
	// Re-minting is unconditional now (see remintApprovedBootstrapBiscuit), so
	// the retry gets a freshly minted biscuit rather than the original
	// byte-for-byte -- it must still verify for the same peer.
	cpPubKey := ed25519.PublicKey(enrollResp.ControlPlanePublicKey)
	if _, _, err := identity.VerifyBiscuitAndGetKey(r.BiscuitToken, pID, []ed25519.PublicKey{cpPubKey}, srv.config.BiscuitTimeout); err != nil {
		t.Fatalf("enrollee retry's biscuit does not verify: %v", err)
	}

	// Domain separation: a signature captured from one endpoint must verify
	// nowhere else, even signed by the right key within the freshness window.
	crossEndpointTS := time.Now().UnixMilli()
	statusSig, err := priv.Sign(api.EnrollStatusChallenge(pID.String(), crossEndpointTS))
	if err != nil {
		t.Fatal(err)
	}
	replayData, _ := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleRouter,
		ChallengeUnixMs:    crossEndpointTS,
		ChallengeSignature: statusSig, // valid /enroll/status signature, wrong endpoint
	})
	if r := postEnroll("cross-endpoint replay", replayData); r.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED || len(r.BiscuitToken) != 0 {
		t.Errorf("an /enroll/status signature was accepted at /enroll: %v", r.Status)
	}

	enrollSigForStatus, err := priv.Sign(api.EnrollChallenge(pID.String(), crossEndpointTS))
	if err != nil {
		t.Fatal(err)
	}
	statusReplay, _ := http.NewRequest(http.MethodGet, baseURL+"/enroll/status?peer_id="+pID.String(), nil)
	statusReplay.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(crossEndpointTS, 10))
	statusReplay.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(enrollSigForStatus))
	resp, err = client.Do(statusReplay)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an /enroll signature was accepted at /enroll/status: %s", resp.Status)
	}
}

// TestEnrollStatusRateLimited pins that /enroll/status shares the enrollment
// rate limit: the advisory's PoC relied on polling it without bound.
func TestEnrollStatusRateLimited(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	limited := false
	for i := 0; i < EnrollBurst+10; i++ {
		resp, err := client.Get(baseURL + "/enroll/status?peer_id=unknown")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatalf("no 429 after %d rapid /enroll/status requests", EnrollBurst+10)
	}
}

// TestRouterLeaseRevocation pins that revocation cuts off lease renewal: a
// biscuit stays cryptographically valid until its TTL, so /routers/lease has
// to check admission on every renewal, exactly as /refresh and /policies do.
func TestRouterLeaseRevocation(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"

	ctx := context.Background()
	cpPriv, _, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}

	// enrollLeaseRouter mints a router biscuit and, unless orphan, the
	// EnrolledNode record backing it.
	enrollLeaseRouter := func(expiresAt time.Time, orphan bool) (crypto.PrivKey, peer.ID, []byte) {
		t.Helper()
		priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		routerPeer, _ := peer.IDFromPrivateKey(priv)
		pubBytes, _ := crypto.MarshalPublicKey(pub)
		routerBiscuit, err := identity.MintBootstrapBiscuitToken(cpPriv, routerPeer, api.RoleRouter, time.Now().Add(time.Hour), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !orphan {
			if err := store.EnrollNode(ctx, &storage.EnrolledNode{
				PeerID:         routerPeer.String(),
				PublicKey:      pubBytes,
				Biscuit:        routerBiscuit,
				Role:           api.RoleRouter,
				EnrollmentType: "BOOTSTRAP",
				EnrolledAt:     time.Now(),
				ExpiresAt:      expiresAt,
			}); err != nil {
				t.Fatal(err)
			}
		}
		return priv, routerPeer, routerBiscuit
	}

	postLease := func(priv crypto.PrivKey, routerPeer peer.ID, routerBiscuit []byte) int {
		t.Helper()
		ts, sig := leasePoP(t, priv, routerPeer.String())
		leaseData, _ := proto.Marshal(&api.RouterLeaseRequest{
			PeerId:             routerPeer.String(),
			Addresses:          []string{"/ip4/127.0.0.1/tcp/4001/p2p/" + routerPeer.String()},
			Biscuit:            routerBiscuit,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		})
		resp, err := client.Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(leaseData))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// Admitted router renews; the same router refuses after /admin/revoke.
	routerPriv, routerPeer, routerBiscuit := enrollLeaseRouter(time.Time{}, false)
	if got := postLease(routerPriv, routerPeer, routerBiscuit); got != http.StatusOK {
		t.Fatalf("lease before revocation: got %d, want 200", got)
	}
	revokeData, _ := proto.Marshal(&api.TokenRevokeRequest{PeerId: routerPeer.String()})
	revokeReq, _ := http.NewRequest(http.MethodPost, baseURL+"/admin/revoke", bytes.NewReader(revokeData))
	revokeReq.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err := client.Do(revokeReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: got %s, want 200", resp.Status)
	}
	if got := postLease(routerPriv, routerPeer, routerBiscuit); got != http.StatusForbidden {
		t.Fatalf("lease after revocation: got %d, want 403", got)
	}

	// A lapsed OIDC session is the other admission arm.
	expiredPriv, expiredPeer, expiredBiscuit := enrollLeaseRouter(time.Now().Add(-time.Hour), false)
	if got := postLease(expiredPriv, expiredPeer, expiredBiscuit); got != http.StatusUnauthorized {
		t.Fatalf("lease with lapsed session: got %d, want 401", got)
	}

	// A valid biscuit with no enrollment record behind it renews nothing.
	orphanPriv, orphanPeer, orphanBiscuit := enrollLeaseRouter(time.Time{}, true)
	if got := postLease(orphanPriv, orphanPeer, orphanBiscuit); got != http.StatusUnauthorized {
		t.Fatalf("lease without enrollment record: got %d, want 401", got)
	}
}

// TestRouterLeaseUnderRotatedKey covers the rotation grace window on
// /routers/lease: both keys are valid, the retiring one is listed first, and
// the biscuit is signed by the new one, so the role check has to run under the
// key that verified it rather than the first key in the ring.
func TestRouterLeaseUnderRotatedKey(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	ctx := context.Background()

	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RotateKeys(ctx, newPriv, newPub, time.Hour); err != nil {
		t.Fatal(err)
	}
	valid, err := store.GetAllValidKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(valid) != 2 || bytes.Equal(valid[0].Public, newPub) {
		t.Fatalf("keyring is not [retiring, new]: %d keys", len(valid))
	}

	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	routerPeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	routerBiscuit, err := identity.MintBootstrapBiscuitToken(newPriv, routerPeer, api.RoleRouter, time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnrollNode(ctx, &storage.EnrolledNode{
		PeerID:         routerPeer.String(),
		PublicKey:      pubBytes,
		Biscuit:        routerBiscuit,
		Role:           api.RoleRouter,
		EnrollmentType: "BOOTSTRAP",
		EnrolledAt:     time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	leaseTS, leaseSig := leasePoP(t, priv, routerPeer.String())
	leaseData, err := proto.Marshal(&api.RouterLeaseRequest{
		PeerId:             routerPeer.String(),
		Addresses:          []string{"/ip4/127.0.0.1/tcp/4001/p2p/" + routerPeer.String()},
		Biscuit:            routerBiscuit,
		ChallengeUnixMs:    leaseTS,
		ChallengeSignature: leaseSig,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(baseURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(leaseData))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lease with biscuit signed by the new key: got %d (%s), want 200", resp.StatusCode, body)
	}
}

// enrollRefreshTestNode enrolls a bootstrap node directly in the store and
// returns its key and currently issued biscuit, ready to drive /refresh.
func enrollRefreshTestNode(t *testing.T, ctx context.Context, store storage.Store) (crypto.PrivKey, []byte) {
	t.Helper()

	cpPriv, _, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}

	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	nodePeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	pubKeyBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPublicKey: %v", err)
	}

	biscuitBytes, err := identity.MintBootstrapBiscuitToken(
		cpPriv,
		nodePeer,
		api.RoleNode,
		time.Now().Add(api.BiscuitTokenTTL),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}

	if err := store.EnrollNode(ctx, &storage.EnrolledNode{
		PeerID:         nodePeer.String(),
		PublicKey:      pubKeyBytes,
		Biscuit:        biscuitBytes,
		Role:           api.RoleNode,
		EnrollmentType: "Bootstrap",
		EnrolledAt:     time.Now(),
		ExpiresAt:      time.Now().Add(api.OIDCSessionTTL),
	}); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	return priv, biscuitBytes
}

// signedRefreshRequest builds a marshaled /refresh body for the given timestamp.
func signedRefreshRequest(t *testing.T, priv crypto.PrivKey, timestamp int64) []byte {
	t.Helper()

	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	sig, err := priv.Sign(api.RefreshChallenge(pid.String(), timestamp))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := proto.Marshal(&api.TokenRefreshRequest{
		ChallengeSignature: sig,
		ChallengeUnixMs:    timestamp,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

// doRefresh posts a prebuilt /refresh body under the given biscuit and returns
// the response status and body.
func doRefresh(t *testing.T, cpURL string, biscuit, body []byte) (int, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, cpURL+"/refresh", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(biscuit))
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// TestHandleRefresh_TimestampFreshness walks the challenge timestamp across
// the ±5m freshness window. Each case enrolls its own node because a
// successful refresh rotates the biscuit and would bleed into the next case.
func TestHandleRefresh_TimestampFreshness(t *testing.T) {
	t.Parallel()

	srv, store, cpURL := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()

	cases := []struct {
		name       string
		timestamp  func() int64
		wantStatus int
	}{
		{"fresh", func() int64 { return time.Now().UnixMilli() }, http.StatusOK},
		{"within window past", func() int64 { return time.Now().Add(-4 * time.Minute).UnixMilli() }, http.StatusOK},
		{"within window future", func() int64 { return time.Now().Add(4 * time.Minute).UnixMilli() }, http.StatusOK},
		{"stale", func() int64 { return time.Now().Add(-2 * time.Hour).UnixMilli() }, http.StatusUnauthorized},
		{"far future", func() int64 { return time.Now().Add(2 * time.Hour).UnixMilli() }, http.StatusUnauthorized},
		{"seconds instead of milliseconds", func() int64 { return time.Now().Unix() }, http.StatusUnauthorized},
		// Absent and malformed timestamps are authentication failures like
		// every other bad challenge: one uniform 401, no oracle.
		{"zero", func() int64 { return 0 }, http.StatusUnauthorized},
		{"negative", func() int64 { return -1 }, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, biscuitBytes := enrollRefreshTestNode(t, ctx, store)
			status, body := doRefresh(t, cpURL, biscuitBytes, signedRefreshRequest(t, priv, tc.timestamp()))
			if status != tc.wantStatus {
				t.Errorf("got status %d, want %d (body: %s)", status, tc.wantStatus, body)
			}
		})
	}
}

// TestHandleRefresh_BiscuitIsSingleUse pins refresh-token rotation: a biscuit
// can be redeemed exactly once, so a captured request replayed inside the
// freshness window mints nothing, while the rotated token keeps refreshing.
func TestHandleRefresh_BiscuitIsSingleUse(t *testing.T) {
	t.Parallel()

	srv, store, cpURL := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()
	priv, biscuitBytes := enrollRefreshTestNode(t, ctx, store)

	refreshData := signedRefreshRequest(t, priv, time.Now().UnixMilli())

	status, body := doRefresh(t, cpURL, biscuitBytes, refreshData)
	if status != http.StatusOK {
		t.Fatalf("first refresh: got %d: %s", status, body)
	}
	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(body, &refreshResp); err != nil {
		t.Fatalf("unmarshal TokenRefreshResponse: %v", err)
	}
	if bytes.Equal(refreshResp.BiscuitToken, biscuitBytes) {
		t.Fatal("refresh returned the same biscuit instead of rotating it")
	}

	// Byte-identical replay of the captured request: the timestamp is still
	// fresh, but the presented biscuit has been rotated.
	status, body = doRefresh(t, cpURL, biscuitBytes, refreshData)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected replayed refresh to be rejected with 401, got %d: %s", status, body)
	}

	// The rotated token is the one redeemable credential.
	status, body = doRefresh(t, cpURL, refreshResp.BiscuitToken, signedRefreshRequest(t, priv, time.Now().UnixMilli()))
	if status != http.StatusOK {
		t.Fatalf("refresh with rotated biscuit: got %d: %s", status, body)
	}
}

func TestTokenRefreshAndRevocation(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, cpURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	ctx := context.Background()

	// Setup policy configuration in the database
	roles2 := []*api.PolicyRole{}
	bindings2 := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{"group:users"}},
	}
	if err := store.SaveMeshPolicy(ctx, roles2, bindings2); err != nil {
		t.Fatal(err)
	}

	// 1. Enroll client node via OIDC
	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	nodeJWT := mintToken(map[string]interface{}{
		"sub":    "node-alice",
		"groups": []string{"users"},
	})

	nodePubKeyBytes, _ := crypto.MarshalPublicKey(pubNode)
	nodeTS, nodeSig := registerPoP(t, privNode, nodePeer.String())
	enrollNodeReq := &api.EnrollRequest{
		Jwt:                nodeJWT,
		PeerId:             nodePeer.String(),
		PublicKey:          nodePubKeyBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    nodeTS,
		ChallengeSignature: nodeSig,
	}
	reqData, _ := proto.Marshal(enrollNodeReq)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(cpURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("node /register failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("node /register status failure: %s (body: %s)", resp.Status, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollNodeResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollNodeResp); err != nil {
		t.Fatalf("failed to unmarshal EnrollResponse: %v", err)
	}
	biscuitToken := enrollNodeResp.BiscuitToken

	// 2. Perform refresh
	timestamp := time.Now().UnixMilli()
	refreshPID, _ := peer.IDFromPrivateKey(privNode)
	challengeSig, err := privNode.Sign(api.RefreshChallenge(refreshPID.String(), timestamp))
	if err != nil {
		t.Fatalf("failed to generate challenge signature: %v", err)
	}

	refreshReq := &api.TokenRefreshRequest{
		ChallengeSignature: challengeSig,
		ChallengeUnixMs:    timestamp,
	}
	refreshData, _ := proto.Marshal(refreshReq)

	reqRefresh, _ := http.NewRequest("POST", cpURL+"/refresh", bytes.NewReader(refreshData))
	b64Biscuit := base64.StdEncoding.EncodeToString(biscuitToken)
	reqRefresh.Header.Set("Authorization", "Bearer "+b64Biscuit)
	reqRefresh.Header.Set("Content-Type", "application/x-protobuf")

	resp, err = client.Do(reqRefresh)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("refresh response failure status %s: %s", resp.Status, string(body))
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(body, &refreshResp); err != nil {
		t.Fatalf("failed to unmarshal TokenRefreshResponse: %v", err)
	}
	if len(refreshResp.BiscuitToken) == 0 {
		t.Fatal("refreshed biscuit token is empty")
	}

	// 3. Admin Revocation
	revokeReq := &api.TokenRevokeRequest{
		PeerId: nodePeer.String(),
	}
	revokeData, _ := proto.Marshal(revokeReq)

	req, _ := http.NewRequest("POST", cpURL+"/admin/revoke", bytes.NewReader(revokeData))
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("admin revoke failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin revoke response status failure: %s (body: %s)", resp.Status, string(body))
	}
	_ = resp.Body.Close()

	// 4. Verify refresh is rejected after revocation
	reqRefreshCompromised, _ := http.NewRequest("POST", cpURL+"/refresh", bytes.NewReader(refreshData))
	reqRefreshCompromised.Header.Set("Authorization", "Bearer "+b64Biscuit)
	reqRefreshCompromised.Header.Set("Content-Type", "application/x-protobuf")

	resp, err = client.Do(reqRefreshCompromised)
	if err != nil {
		t.Fatalf("refresh check failed: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected refresh to be forbidden after revocation, got %s", resp.Status)
	}
	_ = resp.Body.Close()
}

func TestNodeProactiveTokenRefresh(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, cpURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "super-secret-admin-token"
	ctx := context.Background()

	// Setup policy configuration in the database
	roles3 := []*api.PolicyRole{}
	bindings3 := []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{"group:users"}},
	}
	if err := store.SaveMeshPolicy(ctx, roles3, bindings3); err != nil {
		t.Fatal(err)
	}

	// Generate node keys
	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	nodeJWT := mintToken(map[string]interface{}{
		"sub":    "node-refresh-test",
		"groups": []string{"users"},
	})

	// Enroll via registration endpoint
	nodePubKeyBytes, _ := crypto.MarshalPublicKey(pubNode)
	nodeTS, nodeSig := registerPoP(t, privNode, nodePeer.String())
	enrollNodeReq := &api.EnrollRequest{
		Jwt:                nodeJWT,
		PeerId:             nodePeer.String(),
		PublicKey:          nodePubKeyBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    nodeTS,
		ChallengeSignature: nodeSig,
	}
	reqData, _ := proto.Marshal(enrollNodeReq)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(cpURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("node /register failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("node /register status failure: %s (body: %s)", resp.Status, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var enrollNodeResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollNodeResp); err != nil {
		t.Fatalf("failed to unmarshal EnrollResponse: %v", err)
	}
	biscuitToken := enrollNodeResp.BiscuitToken

	// Set up local node Store
	tempDir := t.TempDir()
	nStore, err := node.NewStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create node store: %v", err)
	}

	privKeyBytes, err := crypto.MarshalPrivateKey(privNode)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	if err := nStore.SaveKey(privKeyBytes); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}
	if err := nStore.SaveControlPlaneURL(cpURL); err != nil {
		t.Fatalf("failed to save control plane URL: %v", err)
	}
	if err := nStore.SaveIdentity(biscuitToken); err != nil {
		t.Fatalf("failed to save initial identity: %v", err)
	}
	if err := nStore.SaveIdentityExpiration(enrollNodeResp.GetExpireTime().AsTime().Unix()); err != nil {
		t.Fatalf("failed to save initial expiration: %v", err)
	}

	// The node trusts the key enrollment handed it, as a real node would; the
	// refreshed token is verified against that key before it is adopted.
	n, err := node.NewSamNode(node.Options{
		PrivKey:            privNode,
		Store:              nStore,
		ControlPlanePubKey: enrollNodeResp.ControlPlanePublicKey,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
	})
	if err != nil {
		t.Fatalf("NewSamNode: %v", err)
	}

	// Trigger proactive refresh
	err = n.RefreshEnrollment(ctx)
	if err != nil {
		t.Fatalf("RefreshEnrollment failed: %v", err)
	}

	// Assert that token and expiration updated
	refreshedToken, err := nStore.LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	refreshedExpiration, err := nStore.LoadIdentityExpiration()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(refreshedToken, biscuitToken) {
		t.Error("biscuit token did not change after refresh")
	}
	if refreshedExpiration <= enrollNodeResp.GetExpireTime().AsTime().Unix() {
		t.Errorf("expected refreshed expiration %d to be after initial expiration %d", refreshedExpiration, enrollNodeResp.GetExpireTime().AsTime().Unix())
	}
}

func TestAdminPanelAndUI(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	srv.config.AdminToken = "test-admin-pass"

	testUser := &storage.User{
		ID:        "oidc-sub-123",
		Email:     "user@example.com",
		Role:      "user",
		CreatedAt: time.Now(),
	}
	if err := store.SaveUser(context.Background(), testUser); err != nil {
		t.Fatalf("failed to save test user: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Query /admin/status without token -> should fail with 401
	resp, err := client.Get(baseURL + "/admin/status")
	if err != nil {
		t.Fatalf("GET /admin/status failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 status for unauthenticated status query, got: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Query /admin/status with token -> should succeed
	req, _ := http.NewRequest("GET", baseURL+"/admin/status", nil)
	req.Header.Set("Authorization", "Bearer test-admin-pass")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/status failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 status for authenticated status query, got: %d", resp.StatusCode)
	}

	var statusData map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&statusData); err != nil {
		t.Fatalf("failed to decode admin status response: %v", err)
	}
	_ = resp.Body.Close()

	if _, ok := statusData["active_routers"]; !ok {
		t.Error("status response missing active_routers")
	}
	if _, ok := statusData["enrolled_nodes"]; !ok {
		t.Error("status response missing enrolled_nodes")
	}
	if _, ok := statusData["enrollment_requests"]; !ok {
		t.Error("status response missing enrollment_requests")
	}
	if _, ok := statusData["bootstrap_tokens"]; !ok {
		t.Error("status response missing bootstrap_tokens")
	}
	users, ok := statusData["users"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("expected 1 user in status response, got: %v", statusData["users"])
	}
	if got := users[0].(map[string]any)["ID"]; got != testUser.ID {
		t.Errorf("expected user ID %q, got %v", testUser.ID, got)
	}

	// 3. Query /admin/ UI page -> should fail with 404 as it is removed
	resp, err = client.Get(baseURL + "/admin/")
	if err != nil {
		t.Fatalf("GET /admin/ failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 status for /admin/ UI page, got: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 4. Query /policies without token -> should fail with 401
	resp, err = client.Get(baseURL + "/policies")
	if err != nil {
		t.Fatalf("GET /policies failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 status for unauthenticated GET /policies, got: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestUserStatusAndTenancy(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	s, store, _ := setupTestServer(t, issuer)
	defer func() { _ = s.Close() }()

	baseURL := "http://" + s.Addr()
	client := &http.Client{}

	userA := &storage.User{
		ID:        "user-a-sub",
		Email:     "user-a@example.com",
		Role:      "user",
		CreatedAt: time.Now(),
	}
	userB := &storage.User{
		ID:        "user-b-sub",
		Email:     "user-b@example.com",
		Role:      "user",
		CreatedAt: time.Now(),
	}
	errUserA := store.SaveUser(context.Background(), userA)
	if errUserA != nil {
		t.Fatalf("SaveUser A failed: %v", errUserA)
	}
	errUserB := store.SaveUser(context.Background(), userB)
	if errUserB != nil {
		t.Fatalf("SaveUser B failed: %v", errUserB)
	}

	privA, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair A failed: %v", err)
	}
	peerA, err := peer.IDFromPrivateKey(privA)
	if err != nil {
		t.Fatalf("IDFromPrivateKey A failed: %v", err)
	}
	privB, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair B failed: %v", err)
	}
	peerB, err := peer.IDFromPrivateKey(privB)
	if err != nil {
		t.Fatalf("IDFromPrivateKey B failed: %v", err)
	}

	nodeA := &storage.EnrolledNode{
		PeerID:    peerA.String(),
		PublicKey: []byte("pubkey-a"),
		Biscuit:   []byte("dummy-biscuit-a"),
		Role:      "sam:role:node",
		OwnerID:   userA.ID,
	}
	nodeB := &storage.EnrolledNode{
		PeerID:    peerB.String(),
		PublicKey: []byte("pubkey-b"),
		Biscuit:   []byte("dummy-biscuit-b"),
		Role:      "sam:role:node",
		OwnerID:   userB.ID,
	}
	errNodeA := store.EnrollNode(context.Background(), nodeA)
	if errNodeA != nil {
		t.Fatalf("EnrollNode A failed: %v", errNodeA)
	}
	errNodeB := store.EnrollNode(context.Background(), nodeB)
	if errNodeB != nil {
		t.Fatalf("EnrollNode B failed: %v", errNodeB)
	}

	tokenA := mintToken(map[string]interface{}{
		"iss":   issuer,
		"sub":   userA.ID,
		"email": userA.Email,
		"aud":   "sam-mesh-audience",
	})

	req, _ := http.NewRequest("GET", baseURL+"/user/status", nil)
	req.Header.Set("Authorization", "Bearer "+tokenA)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /user/status failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got: %d", resp.StatusCode)
	}

	var data map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&data)
	_ = resp.Body.Close()

	enrolledNodes, ok := data["enrolled_nodes"].([]interface{})
	if !ok {
		t.Fatal("enrolled_nodes is not an array")
	}
	if len(enrolledNodes) != 1 {
		t.Fatalf("expected 1 node for User A, got: %d", len(enrolledNodes))
	}
	nodeMap := enrolledNodes[0].(map[string]interface{})
	if nodeMap["PeerID"] != peerA.String() {
		t.Errorf("expected node %q, got: %s", peerA.String(), nodeMap["PeerID"])
	}

	reqRevoke, _ := http.NewRequest("POST", baseURL+"/user/revoke?id="+peerB.String(), nil)
	reqRevoke.Header.Set("Authorization", "Bearer "+tokenA)
	respRevoke, err := client.Do(reqRevoke)
	if err != nil {
		t.Fatalf("POST /user/revoke failed: %v", err)
	}
	if respRevoke.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for revoking someone else's node, got: %d", respRevoke.StatusCode)
	}
	_ = respRevoke.Body.Close()

	reqRevokeSelf, _ := http.NewRequest("POST", baseURL+"/user/revoke?id="+peerA.String(), nil)
	reqRevokeSelf.Header.Set("Authorization", "Bearer "+tokenA)
	respRevokeSelf, err := client.Do(reqRevokeSelf)
	if err != nil {
		t.Fatalf("POST /user/revoke self failed: %v", err)
	}
	if respRevokeSelf.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for revoking own node, got: %d", respRevokeSelf.StatusCode)
	}
	_ = respRevokeSelf.Body.Close()

	nodeAUpdated, _ := store.GetNode(context.Background(), peerA.String())
	if !nodeAUpdated.Banned {
		t.Error("expected node A to be banned/revoked in DB")
	}
}

func TestResolveRolesAndRoleImpersonationProtection(t *testing.T) {
	bindings := []*api.PolicyBinding{
		{
			Role:    api.RoleRouter,
			Members: []string{"group:routers", "idp_role:oidc-router-role"},
		},
		{
			Role:    api.RoleNode,
			Members: []string{"user:node-admin-sub"},
		},
		{
			// A binding on the mesh role fact itself: must never resolve from a
			// claim, or an issuer emitting roles: ["sam:role:router"] gets in.
			Role:    "legacy-role-prefix",
			Members: []string{"role:oidc-router-role"},
		},
	}

	t.Run("OIDC claims role is not blindly trusted without explicit binding", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":   "attacker-sub",
			"roles": []string{api.RoleRouter, api.RoleNode, "unbound-role"},
		}
		roles := resolveRoles("peer-123", claims, bindings)
		for _, r := range roles {
			if r == api.RoleRouter || r == api.RoleNode {
				t.Errorf("Security flaw: resolveRoles granted capability role %q from raw OIDC claims without explicit binding", r)
			}
		}
	})

	t.Run("Explicit idp_role mapping in binding grants capability role", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":   "router-sub",
			"roles": []string{"oidc-router-role"},
		}
		roles := resolveRoles("peer-123", claims, bindings)
		if !slices.Contains(roles, api.RoleRouter) {
			t.Errorf("Expected role %q to be granted via explicit idp_role binding mapping", api.RoleRouter)
		}
		if slices.Contains(roles, "legacy-role-prefix") {
			t.Errorf("a role: member resolved from the IdP roles claim; the claim must only feed idp_role")
		}
	})

	t.Run("Group membership grants bound capability role", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":    "router-user",
			"groups": []string{"routers"},
		}
		roles := resolveRoles("peer-456", claims, bindings)
		hasRouter := false
		for _, r := range roles {
			if r == api.RoleRouter {
				hasRouter = true
			}
		}
		if !hasRouter {
			t.Errorf("Expected role %q to be granted via group binding", api.RoleRouter)
		}
	})

	t.Run("User sub grants bound capability role", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "node-admin-sub",
		}
		roles := resolveRoles("peer-789", claims, bindings)
		hasNode := false
		for _, r := range roles {
			if r == api.RoleNode {
				hasNode = true
			}
		}
		if !hasNode {
			t.Errorf("Expected role %q to be granted via user sub binding", api.RoleNode)
		}
	})
}

func TestDiscoverProviderWithRetry(t *testing.T) {
	t.Run("succeeds after transient failures", func(t *testing.T) {
		var attempts int32
		mux := http.NewServeMux()
		srv := httptest.NewServer(mux)
		defer srv.Close()
		issuer := srv.URL

		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&attempts, 1) < 3 {
				http.Error(w, "upstream connect error", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":   issuer,
				"jwks_uri": issuer + "/keys",
			})
		})

		if _, err := discoverProviderWithRetry(context.Background(), issuer, 5, time.Millisecond, 5*time.Millisecond); err != nil {
			t.Fatalf("expected discovery to eventually succeed, got: %v", err)
		}
		if got := atomic.LoadInt32(&attempts); got != 3 {
			t.Errorf("expected 3 attempts, got %d", got)
		}
	})

	t.Run("gives up after max attempts", func(t *testing.T) {
		mux := http.NewServeMux()
		srv := httptest.NewServer(mux)
		defer srv.Close()

		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "always down", http.StatusServiceUnavailable)
		})

		if _, err := discoverProviderWithRetry(context.Background(), srv.URL, 3, time.Millisecond, 5*time.Millisecond); err == nil {
			t.Fatal("expected discovery to fail after exhausting retries")
		}
	})
}

// TestAuthDenialPaths exercises the negative/rejection paths of the
// zero-trust boundary: malformed input, wrong audience, oversized bodies,
// and bad admin credentials must never reach business logic.
func TestAuthDenialPaths(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"

	client := &http.Client{Timeout: 5 * time.Second}

	newEnrollBody := func(jwtStr string) []byte {
		privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		pID, err := peer.IDFromPrivateKey(privNode)
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, _ := crypto.MarshalPublicKey(pubNode)
		ts, sig := registerPoP(t, privNode, pID.String())
		reqData, _ := proto.Marshal(&api.EnrollRequest{
			Jwt:                jwtStr,
			PeerId:             pID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleNode,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		})
		return reqData
	}

	t.Run("malformed protobuf body is rejected", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader([]byte("not-a-protobuf-message")))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for malformed protobuf body, got %d", resp.StatusCode)
		}
	})

	t.Run("malformed JWT is rejected", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(newEnrollBody("not-a-valid-jwt")))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for malformed JWT, got %d", resp.StatusCode)
		}
	})

	t.Run("wrong audience JWT is rejected", func(t *testing.T) {
		badAudJWT := mintToken(map[string]interface{}{
			"sub": "node-mallory",
			"aud": "some-other-audience",
		})
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(newEnrollBody(badAudJWT)))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for wrong-audience JWT, got %d", resp.StatusCode)
		}
	})

	t.Run("oversized body is rejected", func(t *testing.T) {
		oversized := bytes.Repeat([]byte("a"), maxRequestBodyBytes+1)
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(oversized))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("expected oversized body to be rejected, got %d", resp.StatusCode)
		}
	})

	t.Run("admin endpoint rejects wrong token", func(t *testing.T) {
		req, _ := http.NewRequest("GET", baseURL+"/admin/status", nil)
		req.Header.Set("Authorization", "Bearer this-is-not-the-admin-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for wrong admin token, got %d", resp.StatusCode)
		}
	})

	t.Run("node enrollment is closed until a binding grants it", func(t *testing.T) {
		// No sam:role:node binding exists yet; the removed fallback used to
		// enroll any authenticated identity here (GHSA-cgmg-9xf6-rrgw).
		anybodyJWT := mintToken(map[string]interface{}{
			"sub": "node-anybody",
		})
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(newEnrollBody(anybodyJWT)))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 for unbound sam:role:node enrollment, got %d", resp.StatusCode)
		}
	})

	t.Run("register rejects role not granted by policy", func(t *testing.T) {
		if err := store.SaveMeshPolicy(context.Background(), nil, []*api.PolicyBinding{
			{Role: api.RoleNode, Members: []string{"group:users"}},
		}); err != nil {
			t.Fatal(err)
		}
		unauthorizedJWT := mintToken(map[string]interface{}{
			"sub":    "node-outsider",
			"groups": []string{"outsiders"},
		})
		reqData := newEnrollBody(unauthorizedJWT)
		var req api.EnrollRequest
		_ = proto.Unmarshal(reqData, &req)
		req.RequestedRole = "custom-role" // not granted to "group:outsiders"
		reqData, _ = proto.Marshal(&req)

		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403 for unauthorized role request, got %d", resp.StatusCode)
		}
	})
}

// TestOIDCSessionTTLIsConfigurable pins the GHSA-cgmg-9xf6-rrgw session-length
// answer: how long one OIDC login stays refreshable is the operator's
// --oidc-session-ttl decision. A lapsed session refuses refresh (forcing
// interactive re-auth) and the first biscuit never outlives the session.
func TestOIDCSessionTTLIsConfigurable(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	const sessionTTL = 2 * time.Second
	srv, store, baseURL := setupTestServer(t, issuer, func(o *Options) {
		o.OIDCSessionTTL = sessionTTL
	})
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Second}

	if err := store.SaveMeshPolicy(ctx, nil, []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
	}); err != nil {
		t.Fatal(err)
	}

	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := crypto.MarshalPublicKey(pubNode)
	enrolledAt := time.Now()
	regTS, regSig := registerPoP(t, privNode, nodePeer.String())
	reqData, _ := proto.Marshal(&api.EnrollRequest{
		Jwt:                mintToken(map[string]interface{}{"sub": "short-session"}),
		PeerId:             nodePeer.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    regTS,
		ChallengeSignature: regSig,
	})
	resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("/register failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/register status %s (body: %s)", resp.Status, body)
	}
	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollResp); err != nil {
		t.Fatal(err)
	}

	// The configured TTL, not the 90-day default, bounds the session record
	// and the first biscuit alike.
	nodeRecord, err := store.GetNode(ctx, nodePeer.String())
	if err != nil {
		t.Fatal(err)
	}
	if skew := nodeRecord.ExpiresAt.Sub(enrolledAt.Add(sessionTTL)); skew < -2*time.Second || skew > 2*time.Second {
		t.Errorf("session ExpiresAt is %v, want ~%v", nodeRecord.ExpiresAt, enrolledAt.Add(sessionTTL))
	}
	if reported := enrollResp.GetExpireTime().AsTime(); reported.After(nodeRecord.ExpiresAt.Add(2 * time.Second)) {
		t.Errorf("biscuit expiration %v outlives the session %v", reported, nodeRecord.ExpiresAt)
	}

	// Once the session lapses, a correctly signed refresh is refused: the
	// identity has to go back to the OIDC provider.
	time.Sleep(sessionTTL + 500*time.Millisecond)

	timestamp := time.Now().UnixMilli()
	challengeSig, err := privNode.Sign(api.RefreshChallenge(nodePeer.String(), timestamp))
	if err != nil {
		t.Fatal(err)
	}
	refreshData, _ := proto.Marshal(&api.TokenRefreshRequest{
		ChallengeSignature: challengeSig,
		ChallengeUnixMs:    timestamp,
	})
	req, _ := http.NewRequest("POST", baseURL+"/refresh", bytes.NewReader(refreshData))
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(enrollResp.BiscuitToken))
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh after session expiry: got %s (body: %s), want 401", resp.Status, body)
	}
}

// TestBanSurvivesKeypairRegeneration pins the fix for the GHSA-cgmg-9xf6-rrgw
// ban-bypass claim: bans were keyed only on peer_id, which the node itself
// mints, so a banned operator regenerated a keypair and re-enrolled. Revoking
// now also bans the OIDC identity (issuer|subject) and /register checks both.
func TestBanSurvivesKeypairRegeneration(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"

	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Second}

	if err := store.SaveMeshPolicy(ctx, nil, []*api.PolicyBinding{
		{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
	}); err != nil {
		t.Fatal(err)
	}

	enrollKey := func(t *testing.T, priv crypto.PrivKey, sub string) int {
		t.Helper()
		pID, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := crypto.MarshalPublicKey(priv.GetPublic())
		if err != nil {
			t.Fatal(err)
		}
		ts, sig := registerPoP(t, priv, pID.String())
		reqData, _ := proto.Marshal(&api.EnrollRequest{
			Jwt:                mintToken(map[string]interface{}{"sub": sub}),
			PeerId:             pID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleNode,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		})
		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
		if err != nil {
			t.Fatalf("/register failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	newKey := func(t *testing.T) crypto.PrivKey {
		t.Helper()
		priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		return priv
	}

	bannedKey := newKey(t)
	if status := enrollKey(t, bannedKey, "ban-me"); status != http.StatusOK {
		t.Fatalf("initial enrollment: got %d, want 200", status)
	}

	bannedPeer, _ := peer.IDFromPrivateKey(bannedKey)
	revokeData, _ := proto.Marshal(&api.TokenRevokeRequest{PeerId: bannedPeer.String()})
	req, _ := http.NewRequest("POST", baseURL+"/admin/revoke", bytes.NewReader(revokeData))
	req.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("/admin/revoke failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin/revoke: got %d, want 200", resp.StatusCode)
	}

	if status := enrollKey(t, bannedKey, "ban-me"); status != http.StatusForbidden {
		t.Errorf("re-enrollment with the banned keypair: got %d, want 403", status)
	}
	// Same identity behind a fresh keypair: the bypass this test exists for.
	if status := enrollKey(t, newKey(t), "ban-me"); status != http.StatusForbidden {
		t.Errorf("re-enrollment with a fresh keypair: got %d, want 403", status)
	}
	// An unrelated identity keeps working.
	if status := enrollKey(t, newKey(t), "somebody-else"); status != http.StatusOK {
		t.Errorf("unrelated identity: got %d, want 200", status)
	}
}

// TestUndecodablePeerIDRejectedAtBoundary pins that handlers decoding peer
// IDs at the trust boundary answer 401/400 for garbage instead of letting
// the raw string through to storage lookups.
func TestUndecodablePeerIDRejectedAtBoundary(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"

	user := &storage.User{
		ID:        "boundary-sub",
		Email:     "boundary@example.com",
		Role:      "user",
		CreatedAt: time.Now(),
	}
	if err := store.SaveUser(context.Background(), user); err != nil {
		t.Fatalf("SaveUser failed: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UnixMilli()
	sig, err := priv.Sign(api.EnrollStatusChallenge("not-a-peer-id", ts))
	if err != nil {
		t.Fatal(err)
	}
	statusReq, _ := http.NewRequest(http.MethodGet, baseURL+"/enroll/status?peer_id=not-a-peer-id", nil)
	statusReq.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(ts, 10))
	statusReq.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(sig))
	resp, err := client.Do(statusReq)
	if err != nil {
		t.Fatalf("GET /enroll/status failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/enroll/status with undecodable peer_id: got %d, want 401", resp.StatusCode)
	}

	revokeData, _ := proto.Marshal(&api.TokenRevokeRequest{PeerId: "not-a-peer-id"})
	adminReq, _ := http.NewRequest(http.MethodPost, baseURL+"/admin/revoke", bytes.NewReader(revokeData))
	adminReq.Header.Set("Authorization", "Bearer super-secret-admin-token")
	resp, err = client.Do(adminReq)
	if err != nil {
		t.Fatalf("POST /admin/revoke failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("/admin/revoke with undecodable peer_id: got %d, want 400", resp.StatusCode)
	}

	userToken := mintToken(map[string]interface{}{
		"iss":   issuer,
		"sub":   user.ID,
		"email": user.Email,
		"aud":   "sam-mesh-audience",
	})
	userReq, _ := http.NewRequest(http.MethodPost, baseURL+"/user/revoke?id=not-a-peer-id", nil)
	userReq.Header.Set("Authorization", "Bearer "+userToken)
	resp, err = client.Do(userReq)
	if err != nil {
		t.Fatalf("POST /user/revoke failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("/user/revoke with undecodable peer_id: got %d, want 400", resp.StatusCode)
	}
}

// TestBootstrapTokenOwnerPropagatesToNode ensures a node enrolled with a user-owned
// bootstrap token is attributed to that user, which is what makes the console's
// per-user node listing work.
func TestBootstrapTokenOwnerPropagatesToNode(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AutoApproveEnrollment = true

	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Second}

	const ownerSub = "owner-sub-id"
	userJWT := mintToken(map[string]interface{}{"sub": ownerSub, "email": "owner@example.com"})

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/user/bootstrap-tokens",
		bytes.NewBufferString(`{"role":"`+api.RoleNode+`","max_usages":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userJWT)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to create bootstrap token: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("unexpected status creating token: %s (%s)", resp.Status, body)
	}
	var tokenDetails struct {
		Token   string `json:"token"`
		OwnerID string `json:"owner_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenDetails)
	_ = resp.Body.Close()

	if tokenDetails.OwnerID != ownerSub {
		t.Fatalf("token owner = %q, want %q", tokenDetails.OwnerID, ownerSub)
	}

	privNode, pubNode, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, _ := peer.IDFromPrivateKey(privNode)
	pubBytes, _ := crypto.MarshalPublicKey(pubNode)

	ownerTS, ownerSig := enrollPoP(t, privNode, pID.String())
	enrollData, _ := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     tokenDetails.Token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    ownerTS,
		ChallengeSignature: ownerSig,
	})
	resp, err = client.Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewBuffer(enrollData))
	if err != nil {
		t.Fatalf("failed to enroll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("unexpected enroll status: %s (%s)", resp.Status, body)
	}
	_ = resp.Body.Close()

	enrolled, err := store.GetNode(ctx, pID.String())
	if err != nil {
		t.Fatalf("failed to load enrolled node: %v", err)
	}
	if enrolled.OwnerID != ownerSub {
		t.Errorf("enrolled node owner = %q, want %q", enrolled.OwnerID, ownerSub)
	}
}

// TestInitRegisterRoutesEmbedded pins the embedder seam used by single-binary
// distributions: Init + RegisterRoutes on an externally owned mux/listener,
// with no OIDC issuer configured, and a Close that never saw Start.
func TestInitRegisterRoutesEmbedded(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cp-embedded.db")
	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	srv, err := NewServer(Options{
		DriverName:       "sqlite",
		DataSourceName:   dbPath,
		AllowedAudiences: []string{"sam-mesh-audience"},
	}, store)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := srv.Init(); err != nil {
		t.Fatalf("Init() with empty OIDC issuer failed: %v", err)
	}
	if _, _, err := store.GetCurrentKey(context.Background()); err != nil {
		t.Fatalf("Init() did not bootstrap the signing keyring: %v", err)
	}
	if got := srv.Addr(); got != "" {
		t.Errorf("Addr() without an owned listener = %q, want empty", got)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/healthz", "/readyz", "/keys", "/info"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s failed: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %s, want 200", path, resp.Status)
		}
		if path != "/info" {
			_ = resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("failed to read /info body: %v", err)
		}
		var info api.ControlPlaneInfoResponse
		if err := proto.Unmarshal(body, &info); err != nil {
			t.Fatalf("failed to unmarshal ControlPlaneInfoResponse: %v", err)
		}
		if info.OidcIssuer != "" {
			t.Errorf("/info issuer = %q, want empty (no OIDC configured)", info.OidcIssuer)
		}
	}

	// Close must shut down the rotation loop cleanly even though the server
	// never owned an http.Server or listener.
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() without Start failed: %v", err)
	}
}

// TestMeshSurfaceCORS pins what a member in a browser needs from the control
// plane and what it must not get: the mesh protocol's endpoints answer a
// preflight and mark every response for any origin, the operator plane
// does neither.
func TestMeshSurfaceCORS(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cp-cors.db")
	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()
	srv, err := NewServer(Options{DriverName: "sqlite", DataSourceName: dbPath, AllowedAudiences: []string{"sam-mesh-audience"}, AdminToken: "admin-token"}, store)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Init(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	for _, path := range []string{"/info", "/keys", "/enroll", "/enroll/status", "/register", "/refresh", "/policies"} {
		req, _ := http.NewRequest(http.MethodOptions, ts.URL+path, nil)
		req.Header.Set("Origin", "https://agent.example")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type, "+api.HeaderChallengeTimestamp)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("OPTIONS %s = %s, want 204", path, resp.Status)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("OPTIONS %s Access-Control-Allow-Origin = %q, want *", path, got)
		}
		for _, h := range []string{"Authorization", "Content-Type", api.HeaderChallengeTimestamp, api.HeaderChallengeSignature} {
			if !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), h) {
				t.Errorf("OPTIONS %s does not allow header %s: %q", path, h, resp.Header.Get("Access-Control-Allow-Headers"))
			}
		}
	}
	resp, err := client.Get(ts.URL + "/info")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("GET /info Access-Control-Allow-Origin = %q, want *", got)
	}

	for _, path := range []string{"/admin/status", "/user/status", "/routers/lease"} {
		req, _ := http.NewRequest(http.MethodOptions, ts.URL+path, nil)
		req.Header.Set("Origin", "https://agent.example")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("OPTIONS %s Access-Control-Allow-Origin = %q, want none", path, got)
		}
		if resp.StatusCode == http.StatusNoContent {
			t.Errorf("OPTIONS %s answered a preflight", path)
		}
	}
}

// TestAdminBootstrapTokensList pins the admin listing surface used by
// `sam-one token list`: created tokens show up, and the list is admin-gated.
func TestAdminBootstrapTokensList(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cp-admin-tokens.db")
	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	srv, err := NewServer(Options{
		DriverName:       "sqlite",
		DataSourceName:   dbPath,
		AdminToken:       "test-admin-token",
		AllowedAudiences: []string{"sam-mesh-audience"},
	}, store)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	// Create one token through the existing POST surface.
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/admin/bootstrap-tokens",
		strings.NewReader(`{"role":"sam:role:node","ttl_hours":1,"max_usages":3,"description":"cli test"}`))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-admin-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /admin/bootstrap-tokens failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /admin/bootstrap-tokens status = %s, want 201", resp.Status)
	}

	// GET with the admin token returns it.
	req, err = http.NewRequest(http.MethodGet, ts.URL+"/admin/bootstrap-tokens", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/bootstrap-tokens failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/bootstrap-tokens status = %s, want 200", resp.Status)
	}
	var list []storage.BootstrapToken
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("failed to decode token list: %v", err)
	}
	_ = resp.Body.Close()
	if len(list) != 1 {
		t.Fatalf("token list length = %d, want 1", len(list))
	}
	if list[0].Role != "sam:role:node" || list[0].MaxUsages != 3 || list[0].Description != "cli test" {
		t.Errorf("unexpected token record: %+v", list[0])
	}

	// GET without credentials is refused.
	resp, err = client.Get(ts.URL + "/admin/bootstrap-tokens")
	if err != nil {
		t.Fatalf("unauthenticated GET failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET status = %s, want 401", resp.Status)
	}
}

// A bootstrap token's role used to default to router, the most privileged one,
// when omitted. It is now required, and the plaintext-token response is
// marked uncacheable.
func TestAdminBootstrapTokenRoleRequiredAndNoStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cp.db")
	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer func() { _ = store.Close() }()
	srv, err := NewServer(Options{
		DriverName:       "sqlite",
		DataSourceName:   dbPath,
		AdminToken:       "test-admin-token",
		AllowedAudiences: []string{"sam-mesh-audience"},
	}, store)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	post := func(body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/bootstrap-tokens", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-admin-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_ = resp.Body.Close()
		return resp
	}

	if resp := post(`{"max_usages":1}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing role: status = %s, want 400", resp.Status)
	}
	resp := post(`{"role":"sam:role:node","max_usages":1}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("with role: status = %s, want 201", resp.Status)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// /info carries the whole ban set so a node or router that restarted, or was
// offline when MeshEvent_BANNED was published, can reconcile against it. A
// peer that is not banned must not appear, or consumers would blocklist it.
func TestHandleInfoPublishesBanSet(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, st, _ := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = st.Close()
	}()
	ctx := context.Background()

	const (
		bannedPeer  = "12D3KooWBanned000000000000000000000000000000000001"
		allowedPeer = "12D3KooWAllowed00000000000000000000000000000000002"
	)
	for _, peerID := range []string{bannedPeer, allowedPeer} {
		if err := st.EnrollNode(ctx, &storage.EnrolledNode{
			PeerID:    peerID,
			PublicKey: []byte("test-public-key"),
			Biscuit:   []byte("test-biscuit"),
			Role:      "agent",
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("EnrollNode(%s): %v", peerID, err)
		}
	}
	// The path /admin/revoke takes: enrollment always starts unbanned.
	if err := st.SetNodeBanned(ctx, bannedPeer, true); err != nil {
		t.Fatalf("SetNodeBanned: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.HandleInfo(rec, httptest.NewRequest(http.MethodGet, "/info", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected /info status: %d", rec.Code)
	}
	var info api.ControlPlaneInfoResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("unmarshal ControlPlaneInfoResponse: %v", err)
	}

	got := info.GetBannedPeerIds()
	if len(got) != 1 || got[0] != bannedPeer {
		t.Errorf("banned_peer_ids = %v, want exactly [%s]", got, bannedPeer)
	}

	// An unban must show up as absence, since that is the only signal
	// consumers get: there is no unban event.
	if err := st.SetNodeBanned(ctx, bannedPeer, false); err != nil {
		t.Fatalf("SetNodeBanned(false): %v", err)
	}
	rec = httptest.NewRecorder()
	srv.HandleInfo(rec, httptest.NewRequest(http.MethodGet, "/info", nil))
	var after api.ControlPlaneInfoResponse
	if err := proto.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatalf("unmarshal ControlPlaneInfoResponse: %v", err)
	}
	if len(after.GetBannedPeerIds()) != 0 {
		t.Errorf("after unban banned_peer_ids = %v, want empty", after.GetBannedPeerIds())
	}
}

// createAdminBootstrapToken creates a bootstrap token for role via the admin
// API and returns the plaintext token string.
func createAdminBootstrapToken(t *testing.T, baseURL, adminToken, role string, maxUsages int) string {
	t.Helper()
	body := fmt.Sprintf(`{"role":%q,"ttl_hours":2,"max_usages":%d,"description":"re-enroll test"}`, role, maxUsages)
	return createAdminBootstrapTokenJSON(t, baseURL, adminToken, body)
}

// createAdminBootstrapTokenJSON posts body verbatim to /admin/bootstrap-tokens
// and returns the plaintext token string.
func createAdminBootstrapTokenJSON(t *testing.T, baseURL, adminToken, body string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/admin/bootstrap-tokens", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("failed to create bootstrap token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tokenDetails struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenDetails)
	if tokenDetails.Token == "" {
		t.Fatal("empty bootstrap token")
	}
	return tokenDetails.Token
}

// bootstrapEnroll drives POST /enroll for peer priv/pID with the given
// bootstrap token, requested role and labels, and returns the decoded
// response. A REJECTED status is still HTTP 200 (see writeEnrollError), so
// callers check the response's own Status field, not just the transport
// status.
func bootstrapEnroll(t *testing.T, baseURL, token string, priv crypto.PrivKey, pID peer.ID, pubBytes []byte, role string, labels map[string]string) *api.BootstrapEnrollResponse {
	t.Helper()
	ts, sig := enrollPoP(t, priv, pID.String())
	data, err := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken:     token,
		PeerId:             pID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      role,
		Labels:             labels,
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(baseURL+"/enroll", "application/x-protobuf", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("/enroll failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/enroll status %s: %s", resp.Status, string(body))
	}
	var out api.BootstrapEnrollResponse
	if err := proto.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal BootstrapEnrollResponse: %v", err)
	}
	return &out
}

// TestReEnrollAfterExpiryMintsFreshBiscuit pins the fix for the bootstrap
// enrollment stale-biscuit-replay bug, and the follow-up hardening requested
// in review: re-minting must be unconditional rather than gated by how stale
// the stored token looks, must never happen on the /enroll/status poll
// (which has no ban check and no live-token requirement), must ignore
// whatever role or labels a re-enroll request itself declares in favor of
// the enrolled node record, and must refuse a peer that is no longer
// admitted.
//
// Before the original fix, both /enroll's existing-request branch and
// /enroll/status returned existingReq.BiscuitToken verbatim forever, so a
// router hitting a 401 on lease renewal and re-enrolling would receive the
// exact same expired token every time -- an unbreakable enroll -> reject ->
// re-enroll loop, identical to the one HandleRouterLease logs as "failed
// biscuit verification: ... $time <= $exp".
func TestReEnrollAfterExpiryMintsFreshBiscuit(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	const adminToken = "super-secret-admin-token"

	// start spins up a fresh server and a fresh bootstrap token, so no
	// subtest's enrollment state can leak into another's.
	start := func(t *testing.T, role string, maxUsages int) (*Server, storage.Store, string, string) {
		t.Helper()
		srv, store, baseURL := setupTestServer(t, issuer)
		t.Cleanup(func() {
			_ = srv.Close()
			_ = store.Close()
		})
		srv.config.AdminToken = adminToken
		srv.config.AutoApproveEnrollment = true
		// Auto-approve still runs declared labels through LabelPatternsAllow;
		// without a policy granting role, that always rejects a non-empty
		// label set, so the label-mutation subtest would never get an
		// enrolled node to check in the first place.
		if err := store.SaveMeshPolicy(context.Background(), []*api.PolicyRole{
			{Name: role, AllowedLabels: []string{"*"}},
		}, nil); err != nil {
			t.Fatal(err)
		}
		token := createAdminBootstrapToken(t, baseURL, adminToken, role, maxUsages)
		return srv, store, baseURL, token
	}

	newPeer := func(t *testing.T) (crypto.PrivKey, peer.ID, []byte) {
		t.Helper()
		priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		pID, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := crypto.MarshalPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return priv, pID, pubBytes
	}

	t.Run("re-enroll mints a fresh, verifying biscuit unconditionally", func(t *testing.T) {
		srv, _, baseURL, token := start(t, api.RoleRouter, 5)
		priv, pID, pubBytes := newPeer(t)

		first := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		if first.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
			t.Fatalf("expected APPROVED on first enroll, got %v", first.Status)
		}
		cpPubKey := ed25519.PublicKey(first.ControlPlanePublicKey)
		trustedKeys := []ed25519.PublicKey{cpPubKey}
		if _, _, err := identity.VerifyBiscuitAndGetKey(first.BiscuitToken, pID, trustedKeys, srv.config.BiscuitTimeout); err != nil {
			t.Fatalf("first biscuit failed to verify immediately after issuance: %v", err)
		}

		// No sleep needed: re-minting is unconditional now, so an immediate
		// re-enroll must still get back a brand-new, verifying biscuit -- a
		// stronger assertion than "eventually, once stale enough" was.
		second := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		if second.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
			t.Fatalf("expected APPROVED on re-enroll, got %v", second.Status)
		}
		if bytes.Equal(second.BiscuitToken, first.BiscuitToken) {
			t.Fatal("re-enroll returned the exact same biscuit instead of minting a fresh one")
		}
		if _, _, err := identity.VerifyBiscuitAndGetKey(second.BiscuitToken, pID, trustedKeys, srv.config.BiscuitTimeout); err != nil {
			t.Fatalf("refreshed biscuit from re-enroll does not verify: %v", err)
		}
	})

	t.Run("enroll status never mints and never resurrects a stale token", func(t *testing.T) {
		_, store, baseURL, token := start(t, api.RoleRouter, 5)
		priv, pID, pubBytes := newPeer(t)

		first := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)

		statusResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(signedEnrollStatusRequest(t, baseURL, priv, pID.String(), time.Now().UnixMilli()))
		if err != nil {
			t.Fatal(err)
		}
		statusBody, _ := io.ReadAll(statusResp.Body)
		_ = statusResp.Body.Close()
		var polled api.BootstrapEnrollResponse
		if err := proto.Unmarshal(statusBody, &polled); err != nil {
			t.Fatalf("unmarshal polled BootstrapEnrollResponse: %v", err)
		}
		if !bytes.Equal(polled.BiscuitToken, first.BiscuitToken) {
			t.Fatal("GET /enroll/status minted a new biscuit instead of returning the stored one unchanged")
		}

		record, err := store.GetNode(context.Background(), pID.String())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(record.Biscuit, first.BiscuitToken) {
			t.Fatal("GET /enroll/status mutated the enrolled node record's biscuit")
		}
	})

	t.Run("re-enrolled biscuit refreshes cleanly via refresh", func(t *testing.T) {
		_, _, baseURL, token := start(t, api.RoleRouter, 5)
		priv, pID, pubBytes := newPeer(t)

		bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		second := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)

		// refreshNode's reuse-detection compares the presented biscuit
		// against the node record's stored one -- exactly what the re-mint's
		// nodeRecord.Biscuit sync protects; it fails outright if that drifted.
		refreshed := refreshNode(t, baseURL, priv, second.BiscuitToken)
		if len(refreshed.BiscuitToken) == 0 {
			t.Fatal("refresh after re-enroll returned an empty biscuit")
		}
	})

	t.Run("re-enroll recovers a node whose signing key retired past grace", func(t *testing.T) {
		// The #367 scenario: the node's biscuit is signed by a key the
		// control plane has since retired, so /refresh structurally cannot
		// accept it. The manual recovery lever is a fresh bootstrap token,
		// and re-enroll must then mint under the *active* key.
		srv, store, baseURL, token := start(t, api.RoleRouter, 5)
		priv, pID, pubBytes := newPeer(t)

		first := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		oldKey := ed25519.PublicKey(first.ControlPlanePublicKey)

		newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// A negative grace period retires the old key immediately.
		if err := store.RotateKeys(context.Background(), newPriv, newPub, -time.Second); err != nil {
			t.Fatal(err)
		}

		if code := refreshStatus(t, baseURL, priv, first.BiscuitToken); code != http.StatusUnauthorized {
			t.Fatalf("/refresh with a retired-key biscuit: got %d, want 401", code)
		}

		second := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		if second.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
			t.Fatalf("re-enroll after key retirement: got %v, want APPROVED", second.Status)
		}
		if !bytes.Equal(second.ControlPlanePublicKey, newPub) {
			t.Fatal("re-enroll response did not advertise the active signing key")
		}
		if _, _, err := identity.VerifyBiscuitAndGetKey(second.BiscuitToken, pID, []ed25519.PublicKey{oldKey}, srv.config.BiscuitTimeout); err == nil {
			t.Fatal("re-minted biscuit still verifies under the retired key")
		}
		if _, _, err := identity.VerifyBiscuitAndGetKey(second.BiscuitToken, pID, []ed25519.PublicKey{newPub}, srv.config.BiscuitTimeout); err != nil {
			t.Fatalf("re-minted biscuit does not verify under the active key: %v", err)
		}
		if refreshed := refreshNode(t, baseURL, priv, second.BiscuitToken); len(refreshed.BiscuitToken) == 0 {
			t.Fatal("refresh after key-retirement re-enroll returned an empty biscuit")
		}
	})

	t.Run("re-enroll ignores the request's own declared labels", func(t *testing.T) {
		_, store, baseURL, token := start(t, api.RoleRouter, 5)
		priv, pID, pubBytes := newPeer(t)

		bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, map[string]string{"component": "original"})

		// Same token, so RequestedRole must still equal the token's own role
		// to pass /enroll's earlier check, but a different declared label
		// set -- the existing-request branch must not let this through.
		bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, map[string]string{"component": "attacker-supplied"})

		record, err := store.GetNode(context.Background(), pID.String())
		if err != nil {
			t.Fatal(err)
		}
		if record.Labels["component"] != "original" {
			t.Fatalf("re-enroll changed the enrolled node's stored labels to %v, want the original attested set unchanged", record.Labels)
		}
	})

	t.Run("a banned peer is refused, not re-minted", func(t *testing.T) {
		_, store, baseURL, token := start(t, api.RoleRouter, 5)
		priv, pID, pubBytes := newPeer(t)

		bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		if err := store.SetNodeBanned(context.Background(), pID.String(), true); err != nil {
			t.Fatal(err)
		}

		out := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		if out.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
			t.Fatalf("expected REJECTED for a banned peer's re-enroll, got %v", out.Status)
		}
	})

	t.Run("a node whose record role no longer matches the token's is refused", func(t *testing.T) {
		_, store, baseURL, token := start(t, api.RoleRouter, 5)
		priv, pID, pubBytes := newPeer(t)

		bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)

		// Simulate the node record's role having drifted since approval
		// (e.g. a manual admin change) rather than via a real HTTP path,
		// since there isn't one for it -- the defensive check exists
		// precisely because this shouldn't be trusted to never happen.
		record, err := store.GetNode(context.Background(), pID.String())
		if err != nil {
			t.Fatal(err)
		}
		record.Role = api.RoleNode
		if err := store.EnrollNode(context.Background(), record); err != nil {
			t.Fatal(err)
		}

		out := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		if out.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
			t.Fatalf("expected REJECTED for a token/node role mismatch, got %v", out.Status)
		}
	})
}

// TestAdminRevokeBootstrapToken pins DELETE /admin/bootstrap-tokens/{id}
// (#368's other half): a soft revoke, 404 only for an id that names no
// token at all, idempotent otherwise, enforced at /enroll for both a brand
// new enrollment and a re-enroll of an already-approved one.
func TestAdminRevokeBootstrapToken(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	const adminToken = "super-secret-admin-token"
	srv.config.AdminToken = adminToken
	srv.config.AutoApproveEnrollment = true

	client := &http.Client{Timeout: 5 * time.Second}
	deleteToken := func(id string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodDelete, baseURL+"/admin/bootstrap-tokens/"+id, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("DELETE /admin/bootstrap-tokens/%s: %v", id, err)
		}
		return resp
	}

	if resp := deleteToken("no-such-id"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoking an unknown token id: got %d, want 404", resp.StatusCode)
	}

	token := createAdminBootstrapToken(t, baseURL, adminToken, api.RoleRouter, 5)

	// createAdminBootstrapToken returns the plaintext; the id path parameter
	// is its sha256 hash (see HandleAdminBootstrapTokens), so fetch it back
	// via the list rather than recomputing the hash here.
	req, err := http.NewRequest(http.MethodGet, baseURL+"/admin/bootstrap-tokens", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	listResp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var listed []struct {
		ID string
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	_ = listResp.Body.Close()
	if len(listed) != 1 {
		t.Fatalf("GET /admin/bootstrap-tokens returned %d tokens, want 1", len(listed))
	}
	tokenID := listed[0].ID

	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	first := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
	if first.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		t.Fatalf("expected APPROVED before revocation, got %v", first.Status)
	}

	if resp := deleteToken(tokenID); resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("revoke: got %d: %s", resp.StatusCode, body)
	}
	// Idempotent: revoking the same token again must still succeed.
	if resp := deleteToken(tokenID); resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("second revoke: got %d: %s", resp.StatusCode, body)
	}

	// A revoked token can neither enroll a brand new peer...
	otherPriv, otherPub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	otherPID, err := peer.IDFromPrivateKey(otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	otherPubBytes, err := crypto.MarshalPublicKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	if out := bootstrapEnroll(t, baseURL, token, otherPriv, otherPID, otherPubBytes, api.RoleRouter, nil); out.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
		t.Errorf("new enrollment with a revoked token: got %v, want REJECTED", out.Status)
	}

	// ...nor re-mint a fresh biscuit for the peer that enrolled before it was
	// revoked - a revoked token must not become an exception to the
	// unconditional re-mint enforced above.
	if out := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil); out.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
		t.Errorf("re-enroll with a revoked token: got %v, want REJECTED", out.Status)
	}
}

// TestAutonomousRecovery pins the opt-in retired-key fallback on /refresh
// (#367). A bootstrap node whose biscuit is signed by a key the control plane
// has since retired cannot have that biscuit verified, so /refresh normally
// refuses it and the node needs an operator to mint a new bootstrap token.
// With autonomous_recovery set on the node record - seeded from the token
// that enrolled it, or toggled per node by an admin - the control plane
// instead identifies the node by TokenRefreshRequest.peer_id, authenticates
// the biscuit by byte-matching the last one it issued, verifies the fresh
// challenge against the stored key, re-checks admission, and mints under the
// active key. Off by default: a node that can always come back on its own
// key holds a credential that never expires.
func TestAutonomousRecovery(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	const adminToken = "super-secret-admin-token"

	type fixture struct {
		srv     *Server
		store   storage.Store
		baseURL string
		priv    crypto.PrivKey
		pID     peer.ID
		biscuit []byte
		cpKey   ed25519.PublicKey
	}

	// enroll brings up a fresh control plane, enrolls a router with a token
	// minted with the given autonomous_recovery flag, and returns everything
	// a subtest needs to drive /refresh for it.
	enroll := func(t *testing.T, autonomous bool) *fixture {
		t.Helper()
		srv, store, baseURL := setupTestServer(t, issuer)
		t.Cleanup(func() {
			_ = srv.Close()
			_ = store.Close()
		})
		srv.config.AdminToken = adminToken
		srv.config.AutoApproveEnrollment = true

		body := fmt.Sprintf(`{"role":%q,"ttl_hours":2,"max_usages":5,"autonomous_recovery":%t}`, api.RoleRouter, autonomous)
		token := createAdminBootstrapTokenJSON(t, baseURL, adminToken, body)

		priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		pID, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := crypto.MarshalPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		resp := bootstrapEnroll(t, baseURL, token, priv, pID, pubBytes, api.RoleRouter, nil)
		if resp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
			t.Fatalf("enroll: got %v, want APPROVED", resp.Status)
		}

		record, err := store.GetNode(context.Background(), pID.String())
		if err != nil {
			t.Fatal(err)
		}
		if record.AutonomousRecovery != autonomous {
			t.Fatalf("node record AutonomousRecovery = %t, want %t (must be copied from the token)", record.AutonomousRecovery, autonomous)
		}
		return &fixture{srv: srv, store: store, baseURL: baseURL, priv: priv, pID: pID, biscuit: resp.BiscuitToken, cpKey: ed25519.PublicKey(resp.ControlPlanePublicKey)}
	}

	// retireSigningKey rotates to a new key with a negative grace period so
	// the key that signed every biscuit issued so far is gone at once.
	retireSigningKey := func(t *testing.T, store storage.Store) ed25519.PublicKey {
		t.Helper()
		newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RotateKeys(context.Background(), newPriv, newPub, -time.Second); err != nil {
			t.Fatal(err)
		}
		return newPub
	}

	// refresh drives /refresh with peer_id set, the way a node does, and
	// returns status and body.
	refresh := func(t *testing.T, f *fixture, biscuit []byte) (int, []byte) {
		t.Helper()
		return refreshAs(t, f.baseURL, f.priv, biscuit, f.pID.String())
	}

	setRecovery := func(t *testing.T, f *fixture, peerID string, enabled bool) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, f.baseURL+"/admin/nodes/"+peerID+"/autonomous-recovery", bytes.NewBufferString(fmt.Sprintf(`{"enabled":%t}`, enabled)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("opted in via token recovers across key retirement", func(t *testing.T) {
		f := enroll(t, true)
		newKey := retireSigningKey(t, f.store)

		code, body := refresh(t, f, f.biscuit)
		if code != http.StatusOK {
			t.Fatalf("/refresh after key retirement: got %d %s, want 200", code, body)
		}
		var out api.TokenRefreshResponse
		if err := proto.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		if _, _, err := identity.VerifyBiscuitAndGetKey(out.BiscuitToken, f.pID, []ed25519.PublicKey{newKey}, f.srv.config.BiscuitTimeout); err != nil {
			t.Fatalf("recovered biscuit does not verify under the active key: %v", err)
		}
		if _, _, err := identity.VerifyBiscuitAndGetKey(out.BiscuitToken, f.pID, []ed25519.PublicKey{f.cpKey}, f.srv.config.BiscuitTimeout); err == nil {
			t.Fatal("recovered biscuit still verifies under the retired key")
		}
		// And the recovered biscuit is a normal one from here on.
		if next := refreshNode(t, f.baseURL, f.priv, out.BiscuitToken); len(next.BiscuitToken) == 0 {
			t.Fatal("refresh after recovery returned an empty biscuit")
		}
	})

	t.Run("not opted in is refused and told to re-enroll", func(t *testing.T) {
		f := enroll(t, false)
		retireSigningKey(t, f.store)

		code, body := refresh(t, f, f.biscuit)
		if code != http.StatusUnauthorized {
			t.Fatalf("/refresh without opt-in: got %d %s, want 401", code, body)
		}
		if !strings.Contains(string(body), "not opted in to autonomous recovery") {
			t.Fatalf("refusal should tell the operator what to change, got: %s", body)
		}
		record, err := f.store.GetNode(context.Background(), f.pID.String())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(record.Biscuit, f.biscuit) {
			t.Fatal("a refused recovery must not rotate the stored biscuit")
		}
	})

	t.Run("banned stays out even when opted in", func(t *testing.T) {
		f := enroll(t, true)
		retireSigningKey(t, f.store)
		if err := f.store.SetNodeBanned(context.Background(), f.pID.String(), true); err != nil {
			t.Fatal(err)
		}

		code, body := refresh(t, f, f.biscuit)
		if code != http.StatusForbidden {
			t.Fatalf("banned node's recovery: got %d %s, want 403", code, body)
		}
	})

	t.Run("a replayed superseded biscuit is refused", func(t *testing.T) {
		f := enroll(t, true)
		// Rotate B1 -> B2 while the key is still live, then retire the key.
		// Only B2 is redeemable; a captured B1 must not recover anything.
		second := refreshNode(t, f.baseURL, f.priv, f.biscuit)
		retireSigningKey(t, f.store)

		code, body := refresh(t, f, f.biscuit)
		if code != http.StatusUnauthorized {
			t.Fatalf("replayed B1: got %d %s, want 401", code, body)
		}
		if code, body := refresh(t, f, second.BiscuitToken); code != http.StatusOK {
			t.Fatalf("B2 recovery: got %d %s, want 200", code, body)
		}
	})

	t.Run("recovery needs the node key, not just the biscuit", func(t *testing.T) {
		f := enroll(t, true)
		retireSigningKey(t, f.store)

		// Same peer_id and last-issued biscuit, but the challenge is signed
		// by someone else's key.
		thief, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		ts := time.Now().UnixMilli()
		sig, err := thief.Sign(api.RefreshChallenge(f.pID.String(), ts))
		if err != nil {
			t.Fatal(err)
		}
		reqData, err := proto.Marshal(&api.TokenRefreshRequest{ChallengeUnixMs: ts, ChallengeSignature: sig, PeerId: f.pID.String()})
		if err != nil {
			t.Fatal(err)
		}
		if code, _ := doRefresh(t, f.baseURL, f.biscuit, reqData); code != http.StatusUnauthorized {
			t.Fatalf("stolen-biscuit recovery: got %d, want 401", code)
		}
	})

	t.Run("fallback does not reveal which peers are enrolled", func(t *testing.T) {
		f := enroll(t, true)
		retireSigningKey(t, f.store)

		// Garbage bearer, no peer_id: the pre-#367 refusal.
		garbage := []byte("not-a-biscuit")
		baselineCode, baselineBody := refreshAs(t, f.baseURL, f.priv, garbage, "")
		if baselineCode != http.StatusUnauthorized {
			t.Fatalf("baseline: got %d, want 401", baselineCode)
		}

		// Garbage bearer with an enrolled peer_id: byte-match fails.
		enrolledCode, enrolledBody := refreshAs(t, f.baseURL, f.priv, garbage, f.pID.String())

		// Garbage bearer with a never-enrolled peer_id: record lookup fails.
		stranger, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		strangerID, err := peer.IDFromPrivateKey(stranger)
		if err != nil {
			t.Fatal(err)
		}
		strangerCode, strangerBody := refreshAs(t, f.baseURL, stranger, garbage, strangerID.String())

		for name, got := range map[string]struct {
			code int
			body []byte
		}{
			"enrolled peer": {enrolledCode, enrolledBody},
			"unknown peer":  {strangerCode, strangerBody},
		} {
			if got.code != baselineCode || !bytes.Equal(got.body, baselineBody) {
				t.Errorf("%s: got %d %q, want the baseline %d %q", name, got.code, got.body, baselineCode, baselineBody)
			}
		}
	})

	t.Run("admin toggle opts an enrolled node in and out", func(t *testing.T) {
		f := enroll(t, false)

		if code := setRecovery(t, f, f.pID.String(), true); code != http.StatusNoContent {
			t.Fatalf("enable: got %d, want 204", code)
		}
		retireSigningKey(t, f.store)
		code, body := refresh(t, f, f.biscuit)
		if code != http.StatusOK {
			t.Fatalf("/refresh after admin opt-in: got %d %s, want 200", code, body)
		}
		var out api.TokenRefreshResponse
		if err := proto.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}

		// A refresh must not clear the flag on its way through EnrollNode.
		record, err := f.store.GetNode(context.Background(), f.pID.String())
		if err != nil {
			t.Fatal(err)
		}
		if !record.AutonomousRecovery {
			t.Fatal("refresh cleared AutonomousRecovery")
		}

		if code := setRecovery(t, f, f.pID.String(), false); code != http.StatusNoContent {
			t.Fatalf("disable: got %d, want 204", code)
		}
		retireSigningKey(t, f.store)
		if code, body := refresh(t, f, out.BiscuitToken); code != http.StatusUnauthorized {
			t.Fatalf("/refresh after admin opt-out: got %d %s, want 401", code, body)
		}

		unknown, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		unknownID, err := peer.IDFromPrivateKey(unknown)
		if err != nil {
			t.Fatal(err)
		}
		if code := setRecovery(t, f, unknownID.String(), true); code != http.StatusNotFound {
			t.Fatalf("toggle on a never-enrolled peer: got %d, want 404", code)
		}
		if code := setRecovery(t, f, "not-a-peer-id", true); code != http.StatusBadRequest {
			t.Fatalf("toggle on a malformed peer id: got %d, want 400", code)
		}
	})

	t.Run("peer_id must match a verifiable biscuit", func(t *testing.T) {
		f := enroll(t, true)
		other, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatal(err)
		}
		otherID, err := peer.IDFromPrivateKey(other)
		if err != nil {
			t.Fatal(err)
		}
		if code, body := refreshAs(t, f.baseURL, f.priv, f.biscuit, otherID.String()); code != http.StatusUnauthorized {
			t.Fatalf("valid biscuit with a foreign peer_id: got %d %s, want 401", code, body)
		}
	})

	t.Run("only admins may mint tokens with autonomous_recovery", func(t *testing.T) {
		f := enroll(t, false)
		// A non-admin OIDC user hits the user endpoint.
		userJWT := mintToken(map[string]interface{}{"sub": "plain-user", "email": "user@example.com"})
		body := fmt.Sprintf(`{"role":%q,"autonomous_recovery":true}`, api.RoleNode)
		req, err := http.NewRequest(http.MethodPost, f.baseURL+"/user/bootstrap-tokens", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+userJWT)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("non-admin minting an autonomous_recovery token: got %d, want 403", resp.StatusCode)
		}
	})
}
