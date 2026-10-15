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
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// postCatalog POSTs a raw body to /nodes/catalog under the given
// Authorization header value and optional node key (for signing the PoP
// challenge) and returns the response status.
func postCatalog(t *testing.T, cpURL, authHeader string, priv crypto.PrivKey, body []byte) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, cpURL+"/nodes/catalog", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if priv != nil {
		pID, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatalf("IDFromPrivateKey: %v", err)
		}
		ts := time.Now().UnixMilli()
		sig, err := priv.Sign(api.NodesCatalogChallenge(pID.String(), ts))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		req.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(ts, 10))
		req.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(sig))
	}
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func bearer(biscuit []byte) string {
	return "Bearer " + base64.StdEncoding.EncodeToString(biscuit)
}

func catalogBody(t *testing.T, services ...*api.ServiceInfo) []byte {
	t.Helper()
	body, err := proto.Marshal(&api.NodeCatalogReport{Services: services})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return body
}

// adminStatus fetches /admin/status with the admin token.
func adminStatus(t *testing.T, cpURL, adminToken string) *api.AdminStatusResponse {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, cpURL+"/admin/status", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/status: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/status: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /admin/status: %v", err)
	}
	status := &api.AdminStatusResponse{}
	if err := protojson.Unmarshal(body, status); err != nil {
		t.Fatalf("decode /admin/status: %v", err)
	}
	return status
}

func TestHandleNodeCatalog(t *testing.T) {
	t.Parallel()

	srv, store, cpURL := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"

	ctx := context.Background()
	priv, biscuitBytes := enrollRefreshTestNode(t, ctx, store)
	nodePeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}

	body := catalogBody(t,
		&api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "stvv-compliance-docs", Description: "doc lookup"},
		&api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_INFERENCE, Name: "llama", Description: "local model"},
	)
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusNoContent {
		t.Fatalf("HandleNodeCatalog: got status %d, want %d", got, http.StatusNoContent)
	}

	snap := srv.catalogSnapshot()
	entry, ok := snap[nodePeer.String()]
	if !ok || len(snap) != 1 {
		t.Fatalf("expected exactly the reporting peer in the catalog, got %v", snap)
	}
	if len(entry.Services) != 2 || entry.ReportedAt.IsZero() {
		t.Fatalf("unexpected cached entry: %+v", entry)
	}

	// A second report replaces the first rather than accumulating.
	body = catalogBody(t, &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_A2A, Name: "planner"})
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusNoContent {
		t.Fatalf("second report: got status %d, want %d", got, http.StatusNoContent)
	}
	entry = srv.catalogSnapshot()[nodePeer.String()]
	if len(entry.Services) != 1 || entry.Services[0].Name != "planner" {
		t.Fatalf("second report must replace the first, got %+v", entry.Services)
	}

	// The console sees the reported services with the report time.
	view := adminStatus(t, cpURL, srv.config.AdminToken).GetNodeCatalog()
	got, ok := view[nodePeer.String()]
	if !ok || len(view) != 1 {
		t.Fatalf("expected the reporting peer in node_catalog, got %v", view)
	}
	want := &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_A2A, Name: "planner"}
	if len(got.GetServices()) != 1 || !proto.Equal(got.GetServices()[0], want) || got.GetReportTime() == nil {
		t.Fatalf("node_catalog view = %+v, want services %+v", got, want)
	}

	// An empty report is valid and clears the node's services.
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, catalogBody(t)); got != http.StatusNoContent {
		t.Fatalf("empty report: got status %d, want %d", got, http.StatusNoContent)
	}
	if view := adminStatus(t, cpURL, srv.config.AdminToken).GetNodeCatalog(); len(view[nodePeer.String()].GetServices()) != 0 {
		t.Fatalf("empty report must clear services, got %+v", view)
	}
}

func TestHandleNodeCatalog_Rejections(t *testing.T) {
	t.Parallel()

	srv, store, cpURL := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()

	ctx := context.Background()
	priv, biscuitBytes := enrollRefreshTestNode(t, ctx, store)
	cpPriv, _, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}

	// A biscuit minted by a key the control plane never trusted.
	_, rogueKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	strangerPriv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	strangerPeer, err := peer.IDFromPrivateKey(strangerPriv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	forged, err := identity.MintBootstrapBiscuitToken(rogueKey, strangerPeer, api.RoleNode, time.Now().Add(api.BiscuitTokenTTL), nil, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken(rogue): %v", err)
	}
	// A valid biscuit for a peer that was never enrolled.
	unenrolled, err := identity.MintBootstrapBiscuitToken(cpPriv, strangerPeer, api.RoleNode, time.Now().Add(api.BiscuitTokenTTL), nil, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken(unenrolled): %v", err)
	}

	tooMany := make([]*api.ServiceInfo, maxCatalogServices+1)
	for i := range tooMany {
		tooMany[i] = &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "svc"}
	}

	ok := catalogBody(t)
	tests := []struct {
		name string
		auth string
		priv crypto.PrivKey
		body []byte
		want int
	}{
		{name: "missing authorization", auth: "", body: ok, want: http.StatusUnauthorized},
		{name: "not a bearer token", auth: "Basic abc", body: ok, want: http.StatusUnauthorized},
		{name: "malformed base64", auth: "Bearer %%%not-base64", body: ok, want: http.StatusUnauthorized},
		{name: "not a biscuit", auth: bearer([]byte("garbage")), body: ok, want: http.StatusUnauthorized},
		{name: "forged signature", auth: bearer(forged), priv: strangerPriv, body: ok, want: http.StatusUnauthorized},
		{name: "unenrolled peer", auth: bearer(unenrolled), priv: strangerPriv, body: ok, want: http.StatusUnauthorized},
		{name: "missing challenge", auth: bearer(biscuitBytes), body: ok, want: http.StatusUnauthorized},
		{name: "invalid body", auth: bearer(biscuitBytes), priv: priv, body: []byte(`{"services":[]}`), want: http.StatusBadRequest},
		{name: "too many services", auth: bearer(biscuitBytes), priv: priv, body: catalogBody(t, tooMany...), want: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := postCatalog(t, cpURL, tc.auth, tc.priv, tc.body); got != tc.want {
				t.Fatalf("got status %d, want %d", got, tc.want)
			}
		})
	}
	if len(srv.catalogSnapshot()) != 0 {
		t.Fatalf("rejected reports must not be cached, got %v", srv.catalogSnapshot())
	}

	resp, err := http.Get(cpURL + "/nodes/catalog")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /nodes/catalog: got status %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// A node's catalog is only ever as trustworthy as its enrollment: once the
// record is banned or its session lapses, new reports are refused and the
// cached one drops out of the console view.
func TestHandleNodeCatalog_Admission(t *testing.T) {
	t.Parallel()

	srv, store, cpURL := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"

	ctx := context.Background()
	priv, biscuitBytes := enrollRefreshTestNode(t, ctx, store)
	nodePeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	body := catalogBody(t, &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "calc"})
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusNoContent {
		t.Fatalf("admitted node: got status %d, want %d", got, http.StatusNoContent)
	}
	if _, ok := adminStatus(t, cpURL, srv.config.AdminToken).GetNodeCatalog()[nodePeer.String()]; !ok {
		t.Fatal("admitted node's report missing from node_catalog")
	}

	// Session lapsed: the cache still holds the report but the view hides it.
	record, err := store.GetNode(ctx, nodePeer.String())
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	record.ExpiresAt = time.Now().Add(-time.Hour)
	if err := store.EnrollNode(ctx, record); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusUnauthorized {
		t.Fatalf("expired session: got status %d, want %d", got, http.StatusUnauthorized)
	}
	expired := adminStatus(t, cpURL, srv.config.AdminToken)
	if view := expired.GetNodeCatalog(); len(view) != 0 {
		t.Fatalf("expired node must not appear in node_catalog, got %v", view)
	}
	if nodes := expired.GetEnrolledNodes(); len(nodes) != 0 {
		t.Fatalf("expired node must not appear in enrolled_nodes, got %v", nodes)
	}

	// Banned through the server path: the entry is evicted outright.
	record.ExpiresAt = time.Now().Add(time.Hour)
	if err := store.EnrollNode(ctx, record); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	if err := srv.banNode(ctx, record); err != nil {
		t.Fatalf("banNode: %v", err)
	}
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusUnauthorized {
		t.Fatalf("banned node: got status %d, want %d", got, http.StatusUnauthorized)
	}
	if snap := srv.catalogSnapshot(); len(snap) != 0 {
		t.Fatalf("banning must evict the cached report, got %v", snap)
	}
}

// failingStore is a store whose reads fail on demand, the way a database
// that stopped answering looks to the control plane.
type failingStore struct {
	storage.Store
	fail atomic.Bool
}

func (f *failingStore) GetAllValidPublicKeys(ctx context.Context) ([]ed25519.PublicKey, error) {
	if f.fail.Load() {
		return nil, errors.New("store: connection refused")
	}
	return f.Store.GetAllValidPublicKeys(ctx)
}

func (f *failingStore) GetNode(ctx context.Context, peerID string) (*storage.EnrolledNode, error) {
	if f.fail.Load() {
		return nil, errors.New("store: connection refused")
	}
	return f.Store.GetNode(ctx, peerID)
}

// A store that does not answer is an outage, not a refusal: the member is
// told 503 and the control plane logs it, where before it was told 401, the
// answer a revoked credential gets, and nothing was logged. On the testnet
// a database stall produced hundreds of such 401s per step of the ladder.
func TestMemberAuthAnswersStoreFailureAs503(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "control-plane.db")
	real, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store := &failingStore{Store: real}
	srv, err := NewServer(Options{
		ListenAddr: "127.0.0.1:0", DriverName: "sqlite", DataSourceName: dbPath,
		AllowedAudiences: []string{"agentmesh-audience"}, BiscuitTimeout: 10 * time.Second,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Close()
		_ = real.Close()
	}()
	cpURL := "http://" + srv.listener.Addr().String()

	ctx := context.Background()
	priv, biscuitBytes := enrollRefreshTestNode(t, ctx, real)
	body := catalogBody(t, &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "calc"})
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusNoContent {
		t.Fatalf("admitted node with a healthy store: got status %d, want %d", got, http.StatusNoContent)
	}

	store.fail.Store(true)
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusServiceUnavailable {
		t.Fatalf("admitted node with a failing store: got status %d, want %d, not a refusal", got, http.StatusServiceUnavailable)
	}

	store.fail.Store(false)
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusNoContent {
		t.Fatalf("admitted node once the store answers again: got status %d, want %d", got, http.StatusNoContent)
	}
}

// The cache is keyed by the canonical base58 form from the verified biscuit,
// but the enrollment record's PeerID comes off the wire and may be any valid
// encoding of the same peer (e.g. CIDv1 base32). The view lookup and the
// ban eviction must still hit the entry.
func TestCatalogPeerIDCanonicalization(t *testing.T) {
	t.Parallel()

	srv, store, cpURL := setupTestServer(t, "")
	defer func() {
		_ = srv.Close()
		_ = store.Close()
	}()
	srv.config.AdminToken = "super-secret-admin-token"

	ctx := context.Background()
	priv, biscuitBytes := enrollRefreshTestNode(t, ctx, store)
	nodePeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}

	// Re-enroll the same peer under its CIDv1 base32 encoding, as a raw wire
	// string would arrive before the in-flight canonicalization PR lands.
	record, err := store.GetNode(ctx, nodePeer.String())
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	cidForm := peer.ToCid(nodePeer).String()
	if cidForm == nodePeer.String() {
		t.Fatal("test needs a non-canonical encoding, got the canonical one")
	}
	record.PeerID = cidForm
	if err := store.EnrollNode(ctx, record); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}

	body := catalogBody(t, &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "calc"})
	if got := postCatalog(t, cpURL, bearer(biscuitBytes), priv, body); got != http.StatusNoContent {
		t.Fatalf("report: got status %d, want %d", got, http.StatusNoContent)
	}

	// The view must join the CIDv1 record with the canonically-keyed entry,
	// displayed under the record's own spelling.
	view := adminStatus(t, cpURL, srv.config.AdminToken).GetNodeCatalog()
	if _, ok := view[cidForm]; !ok || len(view[cidForm].GetServices()) != 1 {
		t.Fatalf("CIDv1-enrolled node's report missing from node_catalog, got %v", view)
	}

	// Ban via the stored record: eviction must hit the canonical cache key.
	if err := srv.banNode(ctx, record); err != nil {
		t.Fatalf("banNode: %v", err)
	}
	if snap := srv.catalogSnapshot(); len(snap) != 0 {
		t.Fatalf("banning a CIDv1-enrolled node must evict its cached report, got %v", snap)
	}
}
