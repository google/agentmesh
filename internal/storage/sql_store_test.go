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

package storage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	// Use a temporary file for SQLite testing to avoid concurrency sharing bugs in parallel tests
	tempDir, err := os.MkdirTemp("", "agentmesh-store-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	dbPath := filepath.Join(tempDir, "test.db")
	store, err := NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	return store
}

// TestSQLiteFilesAreOwnerOnly pins the on-disk mode of the database and its
// WAL side files: the keyring table holds the mesh signing private keys.
func TestSQLiteFilesAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keys.db")
	// A pre-existing world-readable file (e.g. created by an older release)
	// must be tightened on open, not just newly created ones.
	if err := os.WriteFile(dbPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	// A write forces the WAL and SHM files into existence.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := store.SaveInitialKey(context.Background(), priv, pub); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if mode := fi.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode = %o, want 0600", p, mode)
		}
	}
}

func TestSQLiteFilePath(t *testing.T) {
	cases := map[string]string{
		"keys.db":                               "keys.db",
		"/data/keys.db?_pragma=busy_timeout(5)": "/data/keys.db",
		"file:/data/keys.db?mode=rwc":           "/data/keys.db",
		":memory:":                              "",
		"file::memory:?cache=shared":            "",
		"":                                      "",
	}
	for dsn, want := range cases {
		if got := sqliteFilePath(dsn); got != want {
			t.Errorf("sqliteFilePath(%q) = %q, want %q", dsn, got, want)
		}
	}
}

func TestKeyRingOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Initial State: Keyring empty
	_, _, err := store.GetCurrentKey(ctx)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Generate and save initial key
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	err = store.SaveInitialKey(ctx, priv1, pub1)
	if err != nil {
		t.Fatalf("failed to save initial key: %v", err)
	}

	// GetCurrentKey
	curPriv, curPub, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("failed to get current key: %v", err)
	}
	if !bytes.Equal(curPriv, priv1) || !bytes.Equal(curPub, pub1) {
		t.Fatalf("returned key pair does not match initial key pair")
	}

	// Get all valid keys (only 1 valid key right now)
	validKeys, err := store.GetAllValidKeys(ctx)
	if err != nil {
		t.Fatalf("failed to get all valid keys: %v", err)
	}
	if len(validKeys) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(validKeys))
	}
	if !bytes.Equal(validKeys[0].Private, priv1) {
		t.Fatalf("valid key mismatch")
	}

	// Rotate keys
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	gracePeriod := 1 * time.Hour
	err = store.RotateKeys(ctx, priv2, pub2, gracePeriod)
	if err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	// GetCurrentKey should return the new key
	curPriv, curPub, err = store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("failed to get current key: %v", err)
	}
	if !bytes.Equal(curPriv, priv2) || !bytes.Equal(curPub, pub2) {
		t.Fatalf("returned key pair does not match rotated key pair")
	}

	// GetAllValidKeys should return both
	validKeys, err = store.GetAllValidKeys(ctx)
	if err != nil {
		t.Fatalf("failed to get all valid keys: %v", err)
	}
	if len(validKeys) != 2 {
		t.Fatalf("expected 2 valid keys, got %d", len(validKeys))
	}

	// Wait, check if key clean up works. Let's rotate with negative grace period to expire the second key immediately
	pub3, priv3, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	err = store.RotateKeys(ctx, priv3, pub3, -1*time.Second) // Expires immediately
	if err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	// GetAllValidKeys should only return 2 keys now (the new current key [pub3] and key 2 [pub2] since it hasn't expired, but key 1 [pub1] was cleaned up because its expiration was reached)
	validKeys, err = store.GetAllValidKeys(ctx)
	if err != nil {
		t.Fatalf("failed to get all valid keys: %v", err)
	}
	if len(validKeys) != 2 {
		t.Fatalf("expected 2 valid keys, got %d", len(validKeys))
	}
}

func TestClaimKeyRotation(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	t0 := time.Now()
	interval := 24 * time.Hour

	// Fresh state: the first replica to tick claims the window.
	claimed, err := store.ClaimKeyRotation(ctx, t0, interval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claimed {
		t.Fatal("expected first claim to succeed")
	}

	// A second replica racing for the same window loses.
	claimed, err = store.ClaimKeyRotation(ctx, t0.Add(time.Second), interval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claimed {
		t.Fatal("expected concurrent claim in the same window to fail")
	}

	// Once the interval has elapsed, the next window can be claimed again.
	claimed, err = store.ClaimKeyRotation(ctx, t0.Add(interval+time.Second), interval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claimed {
		t.Fatal("expected claim after the interval elapsed to succeed")
	}
}

func TestScheduleKeyRotationIfUnset(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	t0 := time.Now().Truncate(time.Millisecond)
	interval := 24 * time.Hour

	next, err := store.NextKeyRotation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !next.IsZero() {
		t.Fatalf("fresh store has a rotation deadline %s, want none", next)
	}

	// The first replica to start schedules; a replica starting later, or
	// the same one restarting, leaves the deadline alone.
	scheduled, err := store.ScheduleKeyRotationIfUnset(ctx, t0.Add(interval))
	if err != nil {
		t.Fatal(err)
	}
	if !scheduled {
		t.Fatal("first schedule on a fresh store was not applied")
	}
	scheduled, err = store.ScheduleKeyRotationIfUnset(ctx, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if scheduled {
		t.Fatal("a second schedule replaced the deadline; want it kept")
	}
	next, err = store.NextKeyRotation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Equal(t0.Add(interval)) {
		t.Fatalf("deadline = %s, want %s", next, t0.Add(interval))
	}

	// Not due before the deadline, due at it; a claim moves it one interval on.
	claimed, err := store.ClaimKeyRotation(ctx, t0.Add(interval-time.Second), interval)
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("claim before the deadline succeeded")
	}
	claimed, err = store.ClaimKeyRotation(ctx, t0.Add(interval), interval)
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatal("claim at the deadline failed")
	}
	next, err = store.NextKeyRotation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Equal(t0.Add(2 * interval)) {
		t.Fatalf("deadline after the claim = %s, want %s", next, t0.Add(2*interval))
	}
}

func TestReleaseKeyRotationClaim(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	t0 := time.Now()
	interval := 24 * time.Hour

	claimed, err := store.ClaimKeyRotation(ctx, t0, interval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claimed {
		t.Fatal("expected first claim to succeed")
	}

	// A failed rotation releases the claim instead of stranding the window
	// for a full interval.
	if err := store.ReleaseKeyRotationClaim(ctx, t0, interval); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The window can now be reclaimed immediately, without waiting for the
	// interval to elapse.
	claimed, err = store.ClaimKeyRotation(ctx, t0.Add(time.Second), interval)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claimed {
		t.Fatal("expected claim to succeed after release")
	}
}

func TestClaimKeyRotationConcurrent(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	now := time.Now()
	interval := 24 * time.Hour

	// Simulate several control-plane replicas racing to claim the same
	// rotation window concurrently; exactly one must win.
	const replicas = 10
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claimed, err := store.ClaimKeyRotation(ctx, now, interval)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if claimed {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := wins.Load(); got != 1 {
		t.Fatalf("expected exactly 1 replica to win the claim, got %d", got)
	}
}

func TestNodeEnrollmentOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	peerID := "12D3KooWLTpP4335eb4e414e21415eb66b"

	// Not enrolled yet
	_, err := store.GetNode(ctx, peerID)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	banned, err := store.IsNodeBanned(ctx, peerID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if banned {
		t.Fatalf("expected not banned by default")
	}

	// Enroll node
	biscuitData := []byte("some-biscuit-token")
	expiresAt := time.Now().Add(24 * time.Hour)
	mockPubKey := []byte("mock-public-key-32bytes-long-12345")
	nodeRecord := &EnrolledNode{
		PeerID:         peerID,
		PublicKey:      mockPubKey,
		Biscuit:        biscuitData,
		Role:           "node",
		EnrollmentType: "OIDC",
		Labels:         map[string]string{"region": "eu-de"},
		EnrolledAt:     time.Now(),
		ExpiresAt:      expiresAt,
	}
	err = store.EnrollNode(ctx, nodeRecord)
	if err != nil {
		t.Fatalf("failed to enroll node: %v", err)
	}

	// Get node
	n, err := store.GetNode(ctx, peerID)
	if err != nil {
		t.Fatalf("failed to get enrolled node: %v", err)
	}
	if n.PeerID != peerID || !bytes.Equal(n.Biscuit, biscuitData) || n.Banned {
		t.Fatalf("node data mismatch: %+v", n)
	}
	if n.Labels["region"] != "eu-de" {
		t.Fatalf("node labels mismatch: got %+v, want region=eu-de", n.Labels)
	}

	// Ban node
	err = store.SetNodeBanned(ctx, peerID, true)
	if err != nil {
		t.Fatalf("failed to ban node: %v", err)
	}

	banned, err = store.IsNodeBanned(ctx, peerID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !banned {
		t.Fatalf("expected node to be banned")
	}

	// Re-enroll (unbans? No, re-enroll updates details, but let's check what our schema does. We set banned to false or keep? Wait, our EnrollNode query does 'FALSE' / 0 on INSERT, but during UPDATE it doesn't modify banned)
	nodeRecord.Biscuit = []byte("new-biscuit")
	err = store.EnrollNode(ctx, nodeRecord)
	if err != nil {
		t.Fatalf("failed to enroll node: %v", err)
	}

	banned, err = store.IsNodeBanned(ctx, peerID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !banned {
		t.Fatalf("expected node to remain banned unless explicitly unbanned")
	}
}

func TestIdentityBanOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	identity := "http://issuer.example|banned-sub"

	banned, err := store.IsIdentityBanned(ctx, identity)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if banned {
		t.Fatalf("expected identity not banned by default")
	}

	if err := store.SetIdentityBanned(ctx, identity, true); err != nil {
		t.Fatalf("failed to ban identity: %v", err)
	}
	// Banning twice must not error: two revoked nodes can share one identity.
	if err := store.SetIdentityBanned(ctx, identity, true); err != nil {
		t.Fatalf("re-banning identity: %v", err)
	}

	banned, err = store.IsIdentityBanned(ctx, identity)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !banned {
		t.Fatalf("expected identity to be banned")
	}

	if err := store.SetIdentityBanned(ctx, identity, false); err != nil {
		t.Fatalf("failed to unban identity: %v", err)
	}
	banned, err = store.IsIdentityBanned(ctx, identity)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if banned {
		t.Fatalf("expected identity to be unbanned")
	}

	if err := store.SetIdentityBanned(ctx, "", true); err == nil {
		t.Fatalf("expected an error banning the empty identity")
	}
}

// A ban names the device and the identity behind it in one transaction: an
// unknown peer rolls the identity ban back, so the two never disagree.
func TestSetNodeAndIdentityBannedIsAtomic(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	const identity = "http://issuer.example|atomic-sub"

	err := store.SetNodeAndIdentityBanned(ctx, "12D3KooWNoSuchNode", identity, true)
	if err != ErrNotFound {
		t.Fatalf("banning an unknown node: got %v, want ErrNotFound", err)
	}
	if banned, _ := store.IsIdentityBanned(ctx, identity); banned {
		t.Fatal("identity ban survived the rolled-back node ban")
	}

	node := &EnrolledNode{PeerID: "12D3KooWAtomicNode", PublicKey: []byte("pk"), Biscuit: []byte("b"), Role: api.RoleNode, EnrollmentType: "oidc", EnrolledAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.EnrollNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	if err := store.SetNodeAndIdentityBanned(ctx, node.PeerID, identity, true); err != nil {
		t.Fatalf("ban: %v", err)
	}
	nodeBanned, _ := store.IsNodeBanned(ctx, node.PeerID)
	identityBanned, _ := store.IsIdentityBanned(ctx, identity)
	if !nodeBanned || !identityBanned {
		t.Fatalf("after ban: node=%v identity=%v, want both true", nodeBanned, identityBanned)
	}
	if err := store.SetNodeAndIdentityBanned(ctx, node.PeerID, identity, false); err != nil {
		t.Fatalf("unban: %v", err)
	}
	nodeBanned, _ = store.IsNodeBanned(ctx, node.PeerID)
	identityBanned, _ = store.IsIdentityBanned(ctx, identity)
	if nodeBanned || identityBanned {
		t.Fatalf("after unban: node=%v identity=%v, want both false", nodeBanned, identityBanned)
	}
	// A bootstrap-enrolled node has no identity to ban.
	if err := store.SetNodeAndIdentityBanned(ctx, node.PeerID, "", true); err != nil {
		t.Fatalf("ban without identity: %v", err)
	}
}

func TestRouterLeaseOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	peerID := "12D3KooWLTpRouterPeer"

	// No routers
	routers, err := store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}
	if len(routers) != 0 {
		t.Fatalf("expected 0 routers, got %d", len(routers))
	}

	// Add a lease
	lease1 := &RouterLease{
		PeerID:      peerID,
		Addresses:   []string{"/ip4/127.0.0.1/tcp/5001/p2p/" + peerID},
		LastRenewal: time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Second),
	}
	err = store.UpsertRouterLease(ctx, lease1)
	if err != nil {
		t.Fatalf("failed to upsert router lease: %v", err)
	}

	// Get active routers
	routers, err = store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}
	if len(routers) != 1 {
		t.Fatalf("expected 1 router, got %d", len(routers))
	}
	if routers[0].PeerID != peerID || !reflect.DeepEqual(routers[0].Addresses, lease1.Addresses) {
		t.Fatalf("lease details mismatch: %+v", routers[0])
	}

	// Add an expired lease
	expiredLease := &RouterLease{
		PeerID:      "expired-router",
		Addresses:   []string{"/ip4/127.0.0.1/tcp/5002/p2p/expired-router"},
		LastRenewal: time.Now().Add(-5 * time.Minute),
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
	}
	err = store.UpsertRouterLease(ctx, expiredLease)
	if err != nil {
		t.Fatalf("failed to upsert expired lease: %v", err)
	}

	// Active routers should still be 1
	routers, err = store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}
	if len(routers) != 1 {
		t.Fatalf("expected 1 router, got %d", len(routers))
	}

	// More routers come back in one order, by peer ID, whatever the order
	// they leased in: the store reads the same to every replica, and what a
	// member is handed is shuffled from this by the control plane.
	for _, id := range []string{"12D3KooWZzzLastRouter", "12D3KooWAaaFirstRouter"} {
		if err := store.UpsertRouterLease(ctx, &RouterLease{
			PeerID:      id,
			Addresses:   []string{"/ip4/127.0.0.1/tcp/5003/p2p/" + id},
			LastRenewal: time.Now(),
			ExpiresAt:   time.Now().Add(10 * time.Second),
		}); err != nil {
			t.Fatalf("failed to upsert router lease %s: %v", id, err)
		}
	}
	routers, err = store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}
	var got []string
	for _, r := range routers {
		got = append(got, r.PeerID)
	}
	if want := []string{"12D3KooWAaaFirstRouter", peerID, "12D3KooWZzzLastRouter"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("active routers %v, want them ordered by peer ID %v", got, want)
	}
}

func TestPolicyOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Policy should be empty initially
	roles, bindings, err := store.GetMeshPolicy(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(roles) != 0 || len(bindings) != 0 {
		t.Fatalf("expected empty policy initially, got %d roles and %d bindings", len(roles), len(bindings))
	}

	// Save policy
	p := &api.PolicyRole{
		Name:            "admin",
		AllowedServices: []string{"*"},
		AllowedTargets:  []string{"*"},
	}
	err = store.SaveMeshPolicy(ctx, []*api.PolicyRole{p}, []*api.PolicyBinding{
		{Role: "admin", Members: []string{"user:alice"}},
	})
	if err != nil {
		t.Fatalf("failed to save policy: %v", err)
	}

	// Get policy
	retRoles, retBindings, err := store.GetMeshPolicy(ctx)
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if len(retRoles) != 1 || retRoles[0].Name != "admin" || len(retBindings) != 1 || retBindings[0].Role != "admin" {
		t.Fatalf("policy contents mismatch")
	}
}

func TestTimezoneComparison(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	peerID := "12D3KooWTimezoneRouter"

	// Create a lease with ExpiresAt using a different timezone (e.g., Eastern Standard Time)
	estZone := time.FixedZone("EST", -5*3600)
	expiresAt := time.Now().In(estZone).Add(10 * time.Second)

	lease := &RouterLease{
		PeerID:      peerID,
		Addresses:   []string{"/ip4/127.0.0.1/tcp/5001/p2p/" + peerID},
		LastRenewal: time.Now().In(estZone),
		ExpiresAt:   expiresAt,
	}

	if err := store.UpsertRouterLease(ctx, lease); err != nil {
		t.Fatalf("failed to upsert router lease: %v", err)
	}

	// Query using UTC timezone time
	routers, err := store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("failed to get active routers: %v", err)
	}

	if len(routers) != 1 {
		t.Fatalf("expected 1 router, got %d (timezone comparison failed)", len(routers))
	}
	if routers[0].PeerID != peerID {
		t.Fatalf("expected router %s, got %s", peerID, routers[0].PeerID)
	}
}

func TestDeleteStaleEnrollmentRequestsUsesTokenRetention(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		ephemeral bool
		age       time.Duration
		resolved  bool
		want      int64
	}{
		{name: "regular past regular cutoff", age: 2 * time.Hour, want: 1},
		{name: "ephemeral within ephemeral retention", ephemeral: true, age: 2 * time.Hour},
		{name: "ephemeral past ephemeral cutoff", ephemeral: true, age: 4 * time.Hour, want: 1},
		{name: "ephemeral exactly at cutoff", ephemeral: true, age: 3 * time.Hour},
		{name: "ephemeral resolved inside retention", ephemeral: true, age: 2 * time.Hour, resolved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Errorf("close store: %v", err)
				}
			})
			ctx := t.Context()
			if err := store.SaveBootstrapToken(ctx, &BootstrapToken{ID: "token", TokenHash: "hash", Role: "member", CreatedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(time.Hour), Ephemeral: tc.ephemeral}); err != nil {
				t.Fatalf("save token: %v", err)
			}
			request := &EnrollmentRequest{ID: "request", PeerID: "peer", TokenID: "token", PublicKey: []byte("key"), CreatedAt: now.Add(-tc.age), Status: api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING}
			if tc.resolved {
				request.CreatedAt = now.Add(-24 * time.Hour)
				resolvedAt := now.Add(-tc.age)
				request.ResolvedAt = &resolvedAt
				request.Status = api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED
			}
			if err := store.CreateEnrollmentRequest(ctx, request); err != nil {
				t.Fatalf("create enrollment request: %v", err)
			}
			got, err := store.DeleteStaleEnrollmentRequests(ctx, now.Add(-time.Hour), now.Add(-3*time.Hour))
			if err != nil {
				t.Fatalf("DeleteStaleEnrollmentRequests: %v", err)
			}
			if got != tc.want {
				t.Fatalf("deleted %d enrollment requests, want %d", got, tc.want)
			}
		})
	}
}

func TestBootstrapTokensAndEnrollmentRequestsOps(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// 1. Test BootstrapToken Operations
	tok := &BootstrapToken{
		ID:          "token-id-1",
		TokenHash:   "hash-1",
		Role:        "mesh:role:router",
		MaxUsages:   5,
		UsagesCount: 0,
		Description: "Router join token",
		CreatedAt:   time.Now().Truncate(time.Second),
		ExpiresAt:   time.Now().Add(24 * time.Hour).Truncate(time.Second),
	}

	if err := store.SaveBootstrapToken(ctx, tok); err != nil {
		t.Fatalf("failed to save bootstrap token: %v", err)
	}

	ret, err := store.GetBootstrapToken(ctx, tok.ID)
	if err != nil {
		t.Fatalf("failed to get bootstrap token: %v", err)
	}
	if ret.TokenHash != tok.TokenHash || ret.Role != tok.Role || ret.MaxUsages != tok.MaxUsages {
		t.Errorf("retrieved token mismatch: %+v", ret)
	}

	if err := store.ConsumeBootstrapTokenUsage(ctx, tok.ID, time.Now()); err != nil {
		t.Fatalf("failed to consume usage: %v", err)
	}
	ret2, err := store.GetBootstrapToken(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ret2.UsagesCount != 1 {
		t.Errorf("expected usage count 1, got %d", ret2.UsagesCount)
	}

	// 2. Test EnrollmentRequest Operations
	req := &EnrollmentRequest{
		ID:           "req-id-1",
		PeerID:       "peer-id-1",
		PublicKey:    []byte("my-public-key-bytes"),
		TokenID:      tok.ID,
		Status:       api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
		Labels:       map[string]string{"region": "na-us"},
		BiscuitToken: nil,
		CreatedAt:    time.Now().Truncate(time.Second),
	}

	if err := store.CreateEnrollmentRequest(ctx, req); err != nil {
		t.Fatalf("failed to create enrollment request: %v", err)
	}

	gotReq, err := store.GetEnrollmentRequest(ctx, req.PeerID)
	if err != nil {
		t.Fatalf("failed to get enrollment request by PeerID: %v", err)
	}
	if gotReq.ID != req.ID || gotReq.Status != req.Status || !bytes.Equal(gotReq.PublicKey, req.PublicKey) {
		t.Errorf("retrieved request mismatch: %+v", gotReq)
	}
	if gotReq.Labels["region"] != "na-us" {
		t.Errorf("retrieved request labels mismatch: got %+v, want region=na-us", gotReq.Labels)
	}

	gotReqByID, err := store.GetEnrollmentRequestByID(ctx, req.ID)
	if err != nil {
		t.Fatalf("failed to get enrollment request by ID: %v", err)
	}
	if gotReqByID.PeerID != req.PeerID {
		t.Errorf("retrieved request by ID mismatch: %+v", gotReqByID)
	}

	list, err := store.ListEnrollmentRequests(ctx)
	if err != nil {
		t.Fatalf("failed to list enrollment requests: %v", err)
	}
	if len(list) != 1 || list[0].ID != req.ID {
		t.Errorf("unexpected list size or content: %+v", list)
	}

	// 3. Test UpdateEnrollmentRequest
	biscuitToken := []byte("signed-biscuit-token-bytes")
	err = store.UpdateEnrollmentRequest(ctx, req.ID, api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, biscuitToken, "admin-oidc")
	if err != nil {
		t.Fatalf("failed to update enrollment request: %v", err)
	}

	updatedReq, _ := store.GetEnrollmentRequestByID(ctx, req.ID)
	if updatedReq.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || !bytes.Equal(updatedReq.BiscuitToken, biscuitToken) || updatedReq.ResolvedBy != "admin-oidc" || updatedReq.ResolvedAt == nil {
		t.Errorf("updated request details mismatch: %+v", updatedReq)
	}
}

// The usage cap used to be read-then-increment, so N concurrent enrollments
// on a 1-use token could all pass the read. The consume is now one statement
// that also refuses expired and revoked tokens.
func TestConsumeBootstrapTokenUsageIsAtomicAndGated(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	now := time.Now()

	save := func(id string, max int, expiresAt time.Time) {
		t.Helper()
		if err := store.SaveBootstrapToken(ctx, &BootstrapToken{
			ID: id, TokenHash: "h-" + id, Role: "mesh:role:node", MaxUsages: max,
			CreatedAt: now, ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("cap under concurrency", func(t *testing.T) {
		save("cap", 3, now.Add(time.Hour))
		const attempts = 20
		var wg sync.WaitGroup
		var ok atomic.Int32
		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := store.ConsumeBootstrapTokenUsage(ctx, "cap", now)
				switch err {
				case nil:
					ok.Add(1)
				case ErrBootstrapTokenUnusable:
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 3 {
			t.Errorf("%d of %d concurrent consumes succeeded on a 3-use token, want exactly 3", ok.Load(), attempts)
		}
		tok, err := store.GetBootstrapToken(ctx, "cap")
		if err != nil {
			t.Fatal(err)
		}
		if tok.UsagesCount != 3 {
			t.Errorf("usages_count = %d, want 3", tok.UsagesCount)
		}
	})

	t.Run("expired", func(t *testing.T) {
		save("expired", 5, now.Add(-time.Minute))
		if err := store.ConsumeBootstrapTokenUsage(ctx, "expired", now); err != ErrBootstrapTokenUnusable {
			t.Errorf("err = %v, want ErrBootstrapTokenUnusable", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		save("revoked", 5, now.Add(time.Hour))
		if err := store.RevokeBootstrapToken(ctx, "revoked"); err != nil {
			t.Fatal(err)
		}
		if err := store.ConsumeBootstrapTokenUsage(ctx, "revoked", now); err != ErrBootstrapTokenUnusable {
			t.Errorf("err = %v, want ErrBootstrapTokenUnusable", err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		if err := store.ConsumeBootstrapTokenUsage(ctx, "nope", now); err != ErrBootstrapTokenUnusable {
			t.Errorf("err = %v, want ErrBootstrapTokenUnusable", err)
		}
	})
}

// Two admins acting on one pending request: only the first resolution lands.
func TestResolveEnrollmentRequestOnlyWhilePending(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	if err := store.SaveBootstrapToken(ctx, &BootstrapToken{
		ID: "tok", TokenHash: "h", Role: "mesh:role:node", MaxUsages: 1,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateEnrollmentRequest(ctx, &EnrollmentRequest{
		ID: "req", PeerID: "peer", PublicKey: []byte("pk"), TokenID: "tok",
		Status: api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.ResolveEnrollmentRequest(ctx, "req", api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, []byte("b1"), "admin-1"); err != nil {
		t.Fatalf("first resolution: %v", err)
	}
	err := store.ResolveEnrollmentRequest(ctx, "req", api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED, nil, "admin-2")
	if err != ErrEnrollmentAlreadyResolved {
		t.Fatalf("second resolution: err = %v, want ErrEnrollmentAlreadyResolved", err)
	}
	got, err := store.GetEnrollmentRequestByID(ctx, "req")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED || got.ResolvedBy != "admin-1" || !bytes.Equal(got.BiscuitToken, []byte("b1")) {
		t.Errorf("losing resolution overwrote the request: %+v", got)
	}
}

func TestSaveInitialKeyIsIdempotentWhenActiveKeyExists(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.SaveInitialKey(ctx, priv1, pub1); err != nil {
		t.Fatalf("first SaveInitialKey: %v", err)
	}
	if err := store.SaveInitialKey(ctx, priv2, pub2); err != nil {
		t.Fatalf("second SaveInitialKey: %v", err)
	}

	gotPriv, gotPub, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	if !bytes.Equal(gotPub, pub1) || !bytes.Equal(gotPriv, priv1) {
		t.Fatalf("current key was overwritten by second SaveInitialKey: got %x, want %x", gotPub, pub1)
	}
	validKeys, err := store.GetAllValidPublicKeys(ctx)
	if err != nil {
		t.Fatalf("GetAllValidPublicKeys: %v", err)
	}
	if len(validKeys) != 1 || !bytes.Equal(validKeys[0], pub1) {
		t.Fatalf("GetAllValidPublicKeys = %d keys, want 1 (%x)", len(validKeys), pub1)
	}

	if err := store.SaveInitialOIDCKey(ctx, "kid-1", []byte("priv-1"), []byte("pub-1")); err != nil {
		t.Fatalf("first SaveInitialOIDCKey: %v", err)
	}
	if err := store.SaveInitialOIDCKey(ctx, "kid-2", []byte("priv-2"), []byte("pub-2")); err != nil {
		t.Fatalf("second SaveInitialOIDCKey: %v", err)
	}
	oidcKeys, err := store.GetAllValidOIDCKeys(ctx)
	if err != nil {
		t.Fatalf("GetAllValidOIDCKeys: %v", err)
	}
	if len(oidcKeys) != 1 || oidcKeys[0].Kid != "kid-1" {
		t.Fatalf("GetAllValidOIDCKeys = %+v, want single kid-1", oidcKeys)
	}
}
