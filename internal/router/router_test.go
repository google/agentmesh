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
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/controlplane"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/ratelimit"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func setupControlPlane(t *testing.T, oidcIssuer string) (*controlplane.Server, storage.Store, string) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "control-plane.db")

	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	opts := controlplane.Options{
		ListenAddr:            "127.0.0.1:0", // Auto-allocate
		DriverName:            "sqlite",
		DataSourceName:        dbPath,
		OIDCIssuer:            oidcIssuer,
		AllowedAudiences:      []string{"sam-mesh-audience"},
		LeaseDuration:         5 * time.Second,
		KeyRotationInterval:   12 * time.Hour,
		KeyGracePeriod:        10 * time.Minute,
		InsecureSkipTLSVerify: true,
		BiscuitTimeout:        1 * time.Second,
	}

	// Bootstrap Policy granting 'router' role to group 'routers'
	roles := []*api.PolicyRole{
		{
			Name:            api.RoleRouter,
			AllowedServices: []string{"*"},
			AllowedTargets:  []string{"*"},
		},
		{
			Name:            "user-role",
			AllowedServices: []string{"mcp://read"},
		},
	}
	bindings := []*api.PolicyBinding{
		{Role: api.RoleRouter, Members: []string{"group:routers"}},
		{Role: api.RoleNode, Members: []string{"group:users"}},
		{Role: "user-role", Members: []string{"group:users"}},
	}

	if err := store.SaveMeshPolicy(context.Background(), roles, bindings); err != nil {
		t.Fatalf("failed to save policy: %v", err)
	}

	srv, err := controlplane.NewServer(opts, store)
	if err != nil {
		t.Fatalf("failed to create CP server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start CP: %v", err)
	}

	return srv, store, "http://" + srv.Addr()
}

func TestRouterIntegration(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()
	routerKeyPath := filepath.Join(tempDir, "router.key")

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-1",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	// 1. Create and Start Router
	rOpts := Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   2 * time.Second,
		LeaseRenewInterval: 2 * time.Second,
		OIDCToken:          routerJWT,
		KeysDBPath:         routerKeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	}

	r, err := NewRouter(context.Background(), rOpts)
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	if err := r.Start(); err != nil {
		t.Fatalf("failed to start router: %v", err)
	}
	defer func() { _ = r.Close() }()

	// Verify lease renewal populated the database
	time.Sleep(3 * time.Second) // wait for lease renewal loop to fire
	activeRouters, err := cpStore.GetActiveRouters(context.Background())
	if err != nil {
		t.Fatalf("failed to get active routers from store: %v", err)
	}
	if len(activeRouters) != 1 {
		t.Fatalf("expected 1 active router in DB, got %d", len(activeRouters))
	}
	if activeRouters[0].PeerID != r.Host.ID().String() {
		t.Errorf("router peer ID mismatch in DB lease")
	}

	// 2. Perform client connection and Mutual Auth Handshake
	// Boot a client node and register it on control plane to get a Biscuit
	nodeJWT := mintToken(map[string]interface{}{
		"sub":    "node-user-1",
		"groups": []string{"users"},
	})

	nodeKeyPath := filepath.Join(tempDir, "node.key")
	nodePrivKey, err := getOrGeneratePeerKey(nodeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	nodePeerID, _ := peer.IDFromPrivateKey(nodePrivKey)

	// Fetch biscuit for client node via Control Plane HTTP client
	client := &http.Client{Timeout: 5 * time.Second}
	nodePubKeyBytes, err := crypto.MarshalPublicKey(nodePrivKey.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	regTS := time.Now().UnixMilli()
	regSig, err := nodePrivKey.Sign(api.RegisterChallenge(nodePeerID.String(), regTS))
	if err != nil {
		t.Fatal(err)
	}
	enrollNodeReq := &api.EnrollRequest{
		Jwt:                nodeJWT,
		PeerId:             nodePeerID.String(),
		PublicKey:          nodePubKeyBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    regTS,
		ChallengeSignature: regSig,
	}
	reqData, _ := proto.Marshal(enrollNodeReq)
	resp, err := client.Post(cpURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var enrollNodeResp api.EnrollResponse
	_ = proto.Unmarshal(body, &enrollNodeResp)

	// Now create a client libp2p Host
	clientHost, err := libp2p.New(
		libp2p.Identity(nodePrivKey),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	// Connect to Router
	routerAddr := r.Host.Addrs()[0]
	routerInfo, err := peer.AddrInfoFromP2pAddr(routerAddr.Encapsulate(multiaddr.StringCast("/p2p/" + r.Host.ID().String())))
	if err != nil {
		t.Fatal(err)
	}

	if err := clientHost.Connect(context.Background(), *routerInfo); err != nil {
		t.Fatalf("failed to connect client to router: %v", err)
	}

	// Open mutual auth stream
	s, err := clientHost.NewStream(context.Background(), routerInfo.ID, api.AuthProtocolID)
	if err != nil {
		t.Fatalf("failed to open auth stream: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Send Node Biscuit
	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: enrollNodeResp.BiscuitToken}
	data, _ := proto.Marshal(authFrame)
	if err := writer.WriteMsg(data); err != nil {
		t.Fatalf("failed to write auth frame: %v", err)
	}

	// Read Router response
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var authResp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &authResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !authResp.Success {
		t.Fatalf("mutual auth rejected: %s", authResp.Error)
	}

	// Verify Router Biscuit
	// Fetch CP public keys to verify router biscuit
	validKeys, _ := cpStore.GetAllValidKeys(context.Background())
	var cpPubKeys []ed25519.PublicKey
	for _, k := range validKeys {
		cpPubKeys = append(cpPubKeys, k.Public)
	}

	_, err = identity.VerifyBiscuit(authResp.Biscuit, r.Host.ID(), cpPubKeys, 1*time.Second)
	if err != nil {
		t.Fatalf("failed client-side verification of router biscuit: %v", err)
	}

	t.Log("Mutual Authentication completed successfully!")
}

func TestRouterFederation(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()

	// Mint token for Router 1
	router1JWT := mintToken(map[string]interface{}{
		"sub":    "router-1",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})
	// Mint token for Router 2
	router2JWT := mintToken(map[string]interface{}{
		"sub":    "router-2",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	r1KeyPath := filepath.Join(tempDir, "router1.key")
	r1, err := NewRouter(context.Background(), Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   2 * time.Second,
		LeaseRenewInterval: 2 * time.Second,
		OIDCToken:          router1JWT,
		KeysDBPath:         r1KeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r1.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r1.Close() }()

	r2KeyPath := filepath.Join(tempDir, "router2.key")
	r2, err := NewRouter(context.Background(), Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   2 * time.Second,
		LeaseRenewInterval: 2 * time.Second,
		OIDCToken:          router2JWT,
		KeysDBPath:         r2KeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r2.Close() }()

	// Wait for both routers to renew their lease so they are both in control plane DB
	time.Sleep(3 * time.Second)

	// Trigger connection sync manually to form the federation link
	r1.connectBootstrapRouters()
	r2.connectBootstrapRouters()

	// Wait a moment for stream handshakes to complete
	time.Sleep(1 * time.Second)

	// Assert that Router 1 connected to Router 2
	if len(r1.Host.Network().ConnsToPeer(r2.Host.ID())) == 0 {
		t.Errorf("Router 1 is not connected to Router 2")
	}

	// Assert that Router 1 mutually authenticated Router 2
	if _, authenticated := r1.authenticatedPeers.Load(r2.Host.ID()); !authenticated {
		t.Errorf("Router 2 is not authenticated in Router 1's peers")
	}

	// Assert that Router 2 mutually authenticated Router 1
	if _, authenticated := r2.authenticatedPeers.Load(r1.Host.ID()); !authenticated {
		t.Errorf("Router 1 is not authenticated in Router 2's peers")
	}
}

func TestRouterProactiveTokenRefresh(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()
	routerKeyPath := filepath.Join(tempDir, "router.key")

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-refresh-test",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	rOpts := Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   20 * time.Second,
		LeaseRenewInterval: 20 * time.Second,
		OIDCToken:          routerJWT,
		KeysDBPath:         routerKeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	}

	r, err := NewRouter(context.Background(), rOpts)
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	if err := r.Start(); err != nil {
		t.Fatalf("failed to start router: %v", err)
	}
	defer func() { _ = r.Close() }()

	// Capture initial token and expiration
	initialToken := r.credential.biscuit
	initialExpiration := r.credential.expiration

	if len(initialToken) == 0 {
		t.Fatal("initial router biscuit token is empty")
	}

	// Trigger proactive refresh manually
	err = r.RefreshEnrollment(context.Background())
	if err != nil {
		t.Fatalf("manually triggered RefreshEnrollment failed: %v", err)
	}

	// Assert that token and expiration updated
	if bytes.Equal(r.credential.biscuit, initialToken) {
		t.Error("biscuit token did not change after refresh")
	}
	if !r.credential.expiration.After(initialExpiration) {
		t.Errorf("expected refreshed expiration %v to be after initial expiration %v", r.credential.expiration, initialExpiration)
	}
}

func TestRouterLeaseRenewalReEnrollOn401(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()
	routerKeyPath := filepath.Join(tempDir, "router.key")

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-reenroll-test",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	rOpts := Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   20 * time.Second,
		LeaseRenewInterval: 20 * time.Second,
		OIDCToken:          routerJWT,
		KeysDBPath:         routerKeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	}

	r, err := NewRouter(context.Background(), rOpts)
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	if err := r.Start(); err != nil {
		t.Fatalf("failed to start router: %v", err)
	}
	defer func() { _ = r.Close() }()

	// Corrupt router's biscuit token to simulate key rotation/expiration
	r.keysMu.Lock()
	r.credential.biscuit = []byte("invalid-corrupted-biscuit")
	r.keysMu.Unlock()

	// Call renewLease which should fail with 401, trigger reEnroll, and succeed
	r.renewLease()

	// Verify that the biscuit was replaced with a valid non-corrupted token
	r.keysMu.RLock()
	currentToken := r.credential.biscuit
	r.keysMu.RUnlock()

	if bytes.Equal(currentToken, []byte("invalid-corrupted-biscuit")) {
		t.Error("expected the biscuit to be updated after 401 re-enrollment, but it remained corrupted")
	}
}

func TestRouterLeaseRenewalRepeated401Terminates(t *testing.T) {
	serverCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls++
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("failed to create libp2p host: %v", err)
	}
	defer func() { _ = h.Close() }()

	r := &Router{
		Host:       h,
		privKey:    h.Peerstore().PrivKey(h.ID()),
		credential: credential{biscuit: []byte("dummy-biscuit")},
		config: Options{
			ControlPlaneURL: ts.URL,
		},
	}

	r.renewLease()

	if serverCalls > 2 {
		t.Errorf("renewLease made %d HTTP calls; expected at most 2 calls before terminating", serverCalls)
	}
}

func TestRouterReEnrollUninitializedHostGuard(t *testing.T) {
	r := &Router{}
	err := r.reEnroll()
	if err == nil {
		t.Fatal("expected reEnroll to return error when r.Host is nil, got nil")
	}
	expectedMsg := "cannot re-enroll: router host is not initialized"
	if err.Error() != expectedMsg {
		t.Fatalf("expected error %q, got %q", expectedMsg, err.Error())
	}
}

func TestRouterProactiveRefreshReEnrollOn401(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()
	routerKeyPath := filepath.Join(tempDir, "router.key")

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-refresh-401-test",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	rOpts := Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   20 * time.Second,
		LeaseRenewInterval: 20 * time.Second,
		OIDCToken:          routerJWT,
		KeysDBPath:         routerKeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	}

	r, err := NewRouter(context.Background(), rOpts)
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}

	if err := r.Start(); err != nil {
		t.Fatalf("failed to start router: %v", err)
	}
	defer func() { _ = r.Close() }()

	// Corrupt router's biscuit token to simulate key rotation
	r.keysMu.Lock()
	r.credential.biscuit = []byte("stale-biscuit-signed-by-purged-key")
	r.keysMu.Unlock()

	// Trigger proactive refresh which should fail with 401, trigger reEnroll, and succeed
	err = r.RefreshEnrollment(context.Background())
	if err != nil {
		t.Fatalf("expected RefreshEnrollment to recover via reEnroll, but got error: %v", err)
	}

	// Verify that the biscuit was replaced with a valid fresh token
	r.keysMu.RLock()
	currentToken := r.credential.biscuit
	r.keysMu.RUnlock()

	if bytes.Equal(currentToken, []byte("stale-biscuit-signed-by-purged-key")) {
		t.Error("expected the biscuit to be updated after 401 refresh fallback, but it remained stale")
	}
}

func TestRouterGossipSubBannedEvent(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()
	routerKeyPath := filepath.Join(tempDir, "router.key")

	routerJWT := mintToken(map[string]interface{}{
		"sub":    "router-banned-test",
		"groups": []string{"routers"},
		"roles":  []string{api.RoleRouter},
	})

	rOpts := Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   20 * time.Second,
		LeaseRenewInterval: 20 * time.Second,
		OIDCToken:          routerJWT,
		KeysDBPath:         routerKeyPath,
		AllowLoopback:      true,
		BiscuitTimeout:     1 * time.Second,
	}

	r, err := NewRouter(context.Background(), rOpts)
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("failed to start router: %v", err)
	}
	defer func() { _ = r.Close() }()

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate node keypair: %v", err)
	}
	bannedPeerID, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatalf("failed to get peer ID from keypair: %v", err)
	}
	bannedPeerIDStr := bannedPeerID.String()

	// Manually insert bannedPeer into router's authenticatedPeers
	r.authenticatedPeers.Store(bannedPeerID, true)
	if _, ok := r.authenticatedPeers.Load(bannedPeerID); !ok {
		t.Fatalf("failed to seed authenticatedPeers map")
	}

	// Get CP's signing key from store to sign the MeshEvent
	cpPrivKey, _, err := cpStore.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("failed to get CP key: %v", err)
	}

	event := &api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    bannedPeerIDStr,
		EventTime: timestamppb.Now(),
	}
	eventData, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}
	event.Signature = ed25519.Sign(cpPrivKey, eventData)
	signedData, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal signed event: %v", err)
	}

	// Poll until authenticatedPeers no longer contains bannedPeerID,
	// periodically publishing in case GossipSub subscription goroutine was still starting.
	deadline := time.Now().Add(5 * time.Second)
	evicted := false
	for time.Now().Before(deadline) {
		_ = r.EventTopic.Publish(context.Background(), signedData)
		if _, ok := r.authenticatedPeers.Load(bannedPeerID); !ok {
			evicted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !evicted {
		t.Errorf("expected peer %s to be evicted from authenticatedPeers upon receiving MeshEvent_BANNED", bannedPeerIDStr)
	}

	if _, banned := r.bannedPeers.Load(bannedPeerID); !banned {
		t.Errorf("expected peer %s to be stored in bannedPeers blocklist upon receiving MeshEvent_BANNED", bannedPeerIDStr)
	}
}

func TestRouterEnrollWithTokensResolution(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"biscuit":"dummy-biscuit-bootstrap"}`))
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"biscuit":"dummy-biscuit-oidc"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("BootstrapTokenPath updates BootstrapToken", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bootstrap-token")
		if err := os.WriteFile(path, []byte("  boot-123  \n"), 0o600); err != nil {
			t.Fatalf("failed to write bootstrap token: %v", err)
		}

		r := &Router{config: Options{BootstrapTokenPath: path, ControlPlaneURL: srv.URL}}
		priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		r.privKey = priv

		err := r.enrollWithTokens(peer.ID("dummy"))
		if err == nil || !strings.Contains(err.Error(), "failed to unmarshal") {
			// We expect a proto unmarshal error because the dummy biscuit is just JSON,
			// but we want to assert the token was read correctly first.
			t.Logf("expected proto unmarshal error, got: %v", err)
		}
		if r.config.BootstrapToken != "boot-123" {
			t.Fatalf("expected BootstrapToken %q, got %q", "boot-123", r.config.BootstrapToken)
		}
	})

	t.Run("JWTPath updates OIDCToken", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "oidc-token")
		if err := os.WriteFile(path, []byte("  oidc-123  \n"), 0o600); err != nil {
			t.Fatalf("failed to write oidc token: %v", err)
		}

		r := &Router{config: Options{JWTPath: path, ControlPlaneURL: srv.URL}}
		priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		r.privKey = priv

		err := r.enrollWithTokens(peer.ID("dummy"))
		if err == nil || !strings.Contains(err.Error(), "failed to unmarshal") {
			t.Logf("expected proto unmarshal error, got: %v", err)
		}
		if r.config.OIDCToken != "oidc-123" {
			t.Fatalf("expected OIDCToken %q, got %q", "oidc-123", r.config.OIDCToken)
		}
	})

	t.Run("No tokens returns error", func(t *testing.T) {
		r := &Router{config: Options{ControlPlaneURL: srv.URL}}
		err := r.enrollWithTokens(peer.ID("dummy"))
		if err == nil || err.Error() != "no enrollment token available" {
			t.Fatalf("expected 'no enrollment token available', got %v", err)
		}
	})
}

func TestRouterConnectionManagerWatermarks(t *testing.T) {
	opts := Options{
		LowWaterMark:  500,
		HighWaterMark: 1500,
	}
	opts.Default()
	if opts.LowWaterMark != 500 || opts.HighWaterMark != 1500 {
		t.Fatalf("expected explicit watermarks to be preserved, got Low: %d, High: %d", opts.LowWaterMark, opts.HighWaterMark)
	}

	defaultOpts := Options{}
	defaultOpts.Default()
	if defaultOpts.LowWaterMark != 1000 || defaultOpts.HighWaterMark != 4000 {
		t.Fatalf("expected default watermarks 1000/4000, got Low: %d, High: %d", defaultOpts.LowWaterMark, defaultOpts.HighWaterMark)
	}
}

func TestRouterDefaultBiscuitTimeout(t *testing.T) {
	opts := Options{}
	opts.Default()
	if opts.BiscuitTimeout != identity.DefaultAuthorizerTimeout {
		t.Fatalf("expected default biscuit timeout %v, got %v", identity.DefaultAuthorizerTimeout, opts.BiscuitTimeout)
	}
}

// TestPerformMutualAuth covers the two decisions the client side makes about
// the remote biscuit. Rotated key: the biscuit is signed by the second trusted
// key, so the role check must run under the key that verified, not
// trustedKeys[0]. Missing role: a valid biscuit that lacks the required role
// is refused and the peer is not recorded.
func TestPerformMutualAuth(t *testing.T) {
	oldPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name       string
		serverRole string
		wantOK     bool
	}{
		{"rotated key", api.RoleRouter, true},
		{"missing role", api.RoleNode, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			serverHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = serverHost.Close() }()

			clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = clientHost.Close() }()

			serverBiscuit, err := identity.MintBootstrapBiscuitToken(newPriv, serverHost.ID(), tt.serverRole, time.Now().Add(time.Hour), nil, nil)
			if err != nil {
				t.Fatal(err)
			}

			serverHost.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
				defer func() { _ = s.Close() }()
				reader := msgio.NewVarintReaderSize(s, 1024*64)
				msg, err := reader.ReadMsg()
				if err != nil {
					return
				}
				reader.ReleaseMsg(msg)
				respBytes, err := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: serverBiscuit})
				if err != nil {
					return
				}
				_ = msgio.NewVarintWriter(s).WriteMsg(respBytes)
			})

			r := &Router{
				Host:              clientHost,
				credential:        credential{biscuit: []byte("client-biscuit")},
				trustedPublicKeys: []ed25519.PublicKey{oldPub, newPub},
				config: Options{
					BiscuitTimeout: time.Second,
					RequiredRole:   api.RoleRouter,
				},
			}

			if err := clientHost.Connect(context.Background(), peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
				t.Fatal(err)
			}
			s, err := clientHost.NewStream(context.Background(), serverHost.ID(), api.AuthProtocolID)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()

			err = r.performMutualAuth(s)
			_, recorded := r.authenticatedPeers.Load(serverHost.ID())
			if tt.wantOK {
				if err != nil {
					t.Fatalf("mutual auth failed: %v", err)
				}
				if !recorded {
					t.Fatal("peer not recorded as authenticated")
				}
				return
			}
			if err == nil {
				t.Fatal("peer without the required role accepted")
			}
			if recorded {
				t.Fatal("rejected peer recorded as authenticated")
			}
		})
	}
}

// The router's /sam/auth handler is reachable by any internet peer. An idle
// stream must be closed on the router's schedule, and a peer handshaking in a
// tight loop must be cut off before every frame is verified.
func TestHandleAuthHandshakeBoundsUnauthenticatedPeers(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	serverHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverHost.Close() }()
	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	r, err := NewRouter(ctx, Options{BiscuitTimeout: time.Second, RequiredRole: api.RoleRouter})
	if err != nil {
		t.Fatal(err)
	}
	r.Host = serverHost
	r.credential.biscuit = []byte("router-biscuit")
	r.trustedPublicKeys = []ed25519.PublicKey{cpPub}
	serverHost.SetStreamHandler(api.AuthProtocolID, r.HandleAuthHandshake)
	if err := clientHost.Connect(ctx, peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
		t.Fatal(err)
	}

	t.Run("idle stream is closed by the deadline", func(t *testing.T) {
		old := authHandshakeTimeout
		authHandshakeTimeout = 200 * time.Millisecond
		t.Cleanup(func() { authHandshakeTimeout = old })

		s, err := clientHost.NewStream(ctx, serverHost.ID(), api.AuthProtocolID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		if err := s.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := msgio.NewVarintReaderSize(s, 1024*64).ReadMsg(); err == nil {
			t.Fatal("idle handshake stream answered")
		}
		if took := time.Since(start); took > 4*time.Second {
			t.Fatalf("idle stream was held for %v; the router did not apply its own deadline", took)
		}
	})

	t.Run("tight loop is rate limited", func(t *testing.T) {
		token, err := identity.MintBootstrapBiscuitToken(cpPriv, clientHost.ID(), api.RoleNode, time.Now().Add(time.Hour), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := proto.Marshal(&api.AuthFrame{Biscuit: token})
		if err != nil {
			t.Fatal(err)
		}

		attempts := 3 * ratelimit.PeerBurst
		answered := 0
		for i := 0; i < attempts; i++ {
			s, err := clientHost.NewStream(ctx, serverHost.ID(), api.AuthProtocolID)
			if err != nil {
				t.Fatal(err)
			}
			_ = s.SetDeadline(time.Now().Add(5 * time.Second))
			if err := msgio.NewVarintWriter(s).WriteMsg(frame); err == nil {
				if _, err := msgio.NewVarintReaderSize(s, 1024*64).ReadMsg(); err == nil {
					answered++
				}
			}
			_ = s.Close()
		}
		if answered < ratelimit.PeerBurst {
			t.Errorf("only %d of the first %d handshakes answered; limiter is too strict", answered, ratelimit.PeerBurst)
		}
		if answered == attempts {
			t.Errorf("all %d back-to-back handshakes were verified; no per-peer limit applied", attempts)
		}
	})
}

// reconcileBannedPeers replaces the blocklist with the control plane's ban
// set rather than merging into it. The removal half is the point: the control
// plane can unban a peer and there is no event for that, so a peer that drops
// off /info has to drop out of the blocklist too.
func TestReconcileBannedPeers(t *testing.T) {
	newPeer := func(t *testing.T) peer.ID {
		t.Helper()
		priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	stillBanned := newPeer(t)
	unbanned := newPeer(t)
	newlyBanned := newPeer(t)

	r := &Router{}
	// Prior state, as a running router would hold it.
	past := time.Now().Add(-time.Minute)
	r.bannedPeers.Store(stillBanned, past)
	r.bannedPeers.Store(unbanned, past)
	r.authenticatedPeers.Store(newlyBanned, true)

	fetchedAt := time.Now()
	r.reconcileBannedPeers([]string{stillBanned.String(), newlyBanned.String()}, fetchedAt)

	if _, banned := r.bannedPeers.Load(stillBanned); !banned {
		t.Error("a peer still in the ban set must stay banned")
	}
	if _, banned := r.bannedPeers.Load(newlyBanned); !banned {
		t.Error("a peer newly in the ban set must become banned")
	}
	if _, banned := r.bannedPeers.Load(unbanned); banned {
		t.Error("a peer no longer in the ban set must be unbanned: /info is the only signal an unban has")
	}
	if _, admitted := r.authenticatedPeers.Load(newlyBanned); admitted {
		t.Error("banning a peer must drop any prior admission")
	}

	// An undecodable entry must be skipped, not abort the reconciliation.
	r.reconcileBannedPeers([]string{"not-a-peer-id", stillBanned.String()}, time.Now())
	if _, banned := r.bannedPeers.Load(stillBanned); !banned {
		t.Error("a malformed entry must not discard the valid ones")
	}

	// A ban recorded in the same tick as the fetch must survive. The answer
	// was issued no later than the ban, so its silence cannot mean unbanned,
	// and a clock too coarse to separate the two -- Windows readily is -- must
	// not be what decides it. This is the startup race, and a strict
	// comparison here let it through: TestRouterGossipSubBannedEvent failed
	// roughly one run in ten with the ban deleted at the instant it arrived.
	simultaneous := newPeer(t)
	tick := time.Now()
	r.bannedPeers.Store(simultaneous, tick)
	r.reconcileBannedPeers(nil, tick)
	if _, banned := r.bannedPeers.Load(simultaneous); !banned {
		t.Error("a ban recorded at the fetch instant must survive: the answer is not newer than the ban, so it cannot report it unbanned")
	}
}

func TestRouterRefreshEnrollmentReattestsJWT(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)
	cp, cpStore, cpURL := setupControlPlane(t, issuer)
	defer func() {
		_ = cp.Close()
		_ = cpStore.Close()
	}()

	tempDir := t.TempDir()
	jwtPath := filepath.Join(tempDir, "router.jwt")
	initialJWT := mintToken(map[string]interface{}{
		"sub":    "system:serviceaccount:sam-system:sam-router",
		"groups": []string{"routers"},
	})
	if err := os.WriteFile(jwtPath, []byte(initialJWT+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	r, err := NewRouter(context.Background(), Options{
		ControlPlaneURL:    cpURL,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		KeysSyncInterval:   time.Hour,
		LeaseRenewInterval: time.Hour,
		JWTPath:            jwtPath,
		KeysDBPath:         filepath.Join(tempDir, "router.key"),
		AllowLoopback:      true,
		BiscuitTimeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("r.Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	rotatedJWT := mintToken(map[string]interface{}{
		"sub":    "system:serviceaccount:sam-system:sam-router",
		"groups": []string{"routers"},
		"email":  "sam-router@cluster.local",
	})
	if err := os.WriteFile(jwtPath, []byte(rotatedJWT), 0600); err != nil {
		t.Fatal(err)
	}

	if err := r.RefreshEnrollment(context.Background()); err != nil {
		t.Fatalf("RefreshEnrollment with rotated JWT: %v", err)
	}

	rec, err := cpStore.GetNode(context.Background(), r.Host.ID().String())
	if err != nil || rec == nil {
		t.Fatalf("GetNode: %v", err)
	}
	if !strings.Contains(rec.ClaimsJSON, "sam-router@cluster.local") {
		t.Errorf("ClaimsJSON = %s, want updated claim from rotated router JWT", rec.ClaimsJSON)
	}
}
