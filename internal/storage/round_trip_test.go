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
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
)

// Every record here is taken apart into named columns on the way in and put
// back together on the way out, and the two lists are written by hand. A field
// added to the struct but not to both lists is stored nowhere and read back
// zero, with nothing failing: the caller saves, the API returns what it was
// given, and the value quietly does not exist. That is how a role's
// allowed_agents shipped inert.
//
// These tests are built so that adding a field breaks them. requireAllFieldsSet
// runs over the value being saved, so a new field left out of the literal fails
// before any database work happens, which is the moment to ask whether the
// store writes it.

// requireAllFieldsSet fails when an exported field is still at its zero value.
// skip names fields a save path deliberately ignores; each needs a reason.
func requireAllFieldsSet(t *testing.T, v any, skip ...string) {
	t.Helper()
	skipped := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipped[s] = true
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}
	for i := 0; i < val.NumField(); i++ {
		field := val.Type().Field(i)
		if !field.IsExported() || skipped[field.Name] {
			continue
		}
		if val.Field(i).IsZero() {
			t.Fatalf("%s.%s is not set in this test: populate it and check the store persists it",
				val.Type().Name(), field.Name)
		}
	}
}

// requireFieldsRoundTrip compares exported fields one by one so a failure names
// the field that was dropped rather than dumping two structs.
func requireFieldsRoundTrip(t *testing.T, want, got any, skip ...string) {
	t.Helper()
	skipped := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipped[s] = true
	}

	w := reflect.ValueOf(want)
	g := reflect.ValueOf(got)
	if w.Kind() == reflect.Pointer {
		w, g = w.Elem(), g.Elem()
	}
	for i := 0; i < w.NumField(); i++ {
		field := w.Type().Field(i)
		if !field.IsExported() || skipped[field.Name] {
			continue
		}
		if !valuesEqual(w.Field(i), g.Field(i)) {
			t.Errorf("%s.%s did not round trip: saved %v, loaded %v",
				w.Type().Name(), field.Name, w.Field(i).Interface(), g.Field(i).Interface())
		}
	}
}

// valuesEqual compares timestamps at the precision the columns store, unix
// milliseconds, so a table that fell back to seconds would fail here.
func valuesEqual(w, g reflect.Value) bool {
	switch wv := w.Interface().(type) {
	case time.Time:
		gv, ok := g.Interface().(time.Time)
		return ok && wv.UnixMilli() == gv.UnixMilli()
	case *time.Time:
		gv, ok := g.Interface().(*time.Time)
		if !ok || (wv == nil) != (gv == nil) {
			return false
		}
		return wv == nil || wv.UnixMilli() == gv.UnixMilli()
	}
	return reflect.DeepEqual(w.Interface(), g.Interface())
}

func TestEnrolledNodeRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &EnrolledNode{
		PeerID:         "12D3KooWRoundTrip",
		PublicKey:      []byte("public-key-bytes"),
		Biscuit:        []byte("biscuit-bytes"),
		Role:           api.RoleNode,
		EnrollmentType: "OIDC",
		ClaimsJSON:     `{"sub":"alice"}`,
		OwnerID:        "owner-1",
		Labels:         map[string]string{"region": "emea"},
		EnrolledAt:     time.Now().Add(-time.Hour),
		ExpiresAt:      time.Now().Add(time.Hour),
		// Non-default so the round trip proves the column is read back.
		AutonomousRecovery: true,
		Ephemeral:          true,
	}
	// Banned is never set by enrollment; a node cannot un-ban itself by
	// re-enrolling. TestReEnrollmentKeepsAnExistingBan covers that.
	requireAllFieldsSet(t, want, "Banned")

	if err := store.EnrollNode(ctx, want); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}

	got, err := store.GetNode(ctx, want.PeerID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	requireFieldsRoundTrip(t, want, got, "Banned")

	// ListNodes selects its own column list, so it can drift from GetNode.
	// It leaves the two blobs out on purpose: a list is a view of the rows.
	listed, err := store.ListNodes(ctx, NodeFilter{})
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListNodes returned %d nodes, want 1", len(listed))
	}
	requireFieldsRoundTrip(t, want, &listed[0], "Banned", "PublicKey", "Biscuit")
	if len(listed[0].PublicKey) != 0 || len(listed[0].Biscuit) != 0 {
		t.Errorf("ListNodes read the blobs: public key %d bytes, biscuit %d bytes; GetNode is what reads them", len(listed[0].PublicKey), len(listed[0].Biscuit))
	}
}

// Autonomous recovery is a per-node, server-side opt-in: it must default
// off, flip on and off via SetNodeAutonomousRecovery, and report ErrNotFound
// for a peer that was never enrolled (so an admin toggle can 404 instead of
// silently updating zero rows).
func TestSetNodeAutonomousRecovery(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	node := &EnrolledNode{
		PeerID:         "12D3KooWRecover",
		PublicKey:      []byte("pub"),
		Biscuit:        []byte("biscuit"),
		Role:           api.RoleRouter,
		EnrollmentType: "BOOTSTRAP",
		EnrolledAt:     time.Now(),
	}
	if err := store.EnrollNode(ctx, node); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	got, err := store.GetNode(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.AutonomousRecovery {
		t.Fatal("AutonomousRecovery must default to false")
	}

	if err := store.SetNodeAutonomousRecovery(ctx, node.PeerID, true); err != nil {
		t.Fatalf("SetNodeAutonomousRecovery(true): %v", err)
	}
	got, err = store.GetNode(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("GetNode after enable: %v", err)
	}
	if !got.AutonomousRecovery {
		t.Fatal("SetNodeAutonomousRecovery(true) did not persist")
	}
	if err := store.SetNodeAutonomousRecovery(ctx, node.PeerID, false); err != nil {
		t.Fatalf("SetNodeAutonomousRecovery(false): %v", err)
	}
	got, err = store.GetNode(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("GetNode after disable: %v", err)
	}
	if got.AutonomousRecovery {
		t.Fatal("SetNodeAutonomousRecovery(false) did not persist")
	}

	if err := store.SetNodeAutonomousRecovery(ctx, "12D3KooWNobody", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetNodeAutonomousRecovery(unknown peer) = %v, want ErrNotFound", err)
	}
}

// A ban is the mesh's way of turning a node off. Re-enrolling must not clear
// it, or revocation would last only until the node asked again.
func TestReEnrollmentKeepsAnExistingBan(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	node := &EnrolledNode{
		PeerID:         "12D3KooWBanned",
		PublicKey:      []byte("pub"),
		Biscuit:        []byte("biscuit"),
		Role:           api.RoleNode,
		EnrollmentType: "OIDC",
		EnrolledAt:     time.Now(),
	}
	if err := store.EnrollNode(ctx, node); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	if err := store.SetNodeBanned(ctx, node.PeerID, true); err != nil {
		t.Fatalf("SetNodeBanned: %v", err)
	}

	// The same node enrols again, as it would after a restart.
	if err := store.EnrollNode(ctx, node); err != nil {
		t.Fatalf("re-EnrollNode: %v", err)
	}

	got, err := store.GetNode(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if !got.Banned {
		t.Error("re-enrolling cleared the ban; a banned node could restart its way back in")
	}
	banned, err := store.IsNodeBanned(ctx, node.PeerID)
	if err != nil {
		t.Fatalf("IsNodeBanned: %v", err)
	}
	if !banned {
		t.Error("IsNodeBanned disagrees with the loaded record")
	}
}

// Expiry-based deletion must never take a ban with it, nor touch a node that
// never had a session bound: the first is how a node is kept out, the second
// has no expiry to have lapsed.
// A bootstrap row has no session, so what decides its deletion is how long
// ago it last refreshed, with a shorter retention for a member an ephemeral
// token enrolled. Rows with a session, and banned rows, are left to
// DeleteExpiredNodes and to nobody.
func TestDeleteSilentBootstrapNodes(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	enroll := func(id, kind string, lastRefresh, expiresAt time.Time, ephemeral bool) {
		t.Helper()
		if err := store.EnrollNode(ctx, &EnrolledNode{
			PeerID: id, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode,
			EnrollmentType: kind, EnrolledAt: lastRefresh, ExpiresAt: expiresAt, Ephemeral: ephemeral,
		}); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	var never time.Time
	enroll("regular-fresh", "BOOTSTRAP", now.Add(-time.Hour), never, false)
	enroll("regular-stale", "BOOTSTRAP", now.Add(-40*24*time.Hour), never, false)
	enroll("ephemeral-fresh", "BOOTSTRAP", now.Add(-10*time.Minute), never, true)
	enroll("ephemeral-stale", "BOOTSTRAP", now.Add(-2*time.Hour), never, true)
	enroll("oidc-stale", "OIDC", now.Add(-40*24*time.Hour), now.Add(50*24*time.Hour), false)
	enroll("banned-stale", "BOOTSTRAP", now.Add(-40*24*time.Hour), never, false)
	if err := store.SetNodeBanned(ctx, "banned-stale", true); err != nil {
		t.Fatal(err)
	}

	regular, ephemeral, err := store.DeleteSilentBootstrapNodes(ctx, now.Add(-30*24*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("DeleteSilentBootstrapNodes: %v", err)
	}
	if regular != 1 || ephemeral != 1 {
		t.Errorf("deleted regular=%d ephemeral=%d, want 1 and 1", regular, ephemeral)
	}
	nodes, err := store.ListNodes(ctx, NodeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, n := range nodes {
		left = append(left, n.PeerID)
	}
	slices.Sort(left)
	want := []string{"banned-stale", "ephemeral-fresh", "oidc-stale", "regular-fresh"}
	if !slices.Equal(left, want) {
		t.Errorf("remaining = %v, want %v", left, want)
	}
}

func TestDeleteStaleEnrollmentRecords(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	day := 24 * time.Hour
	token := func(id string, expiresAt time.Time, ephemeral bool) {
		t.Helper()
		if err := store.SaveBootstrapToken(ctx, &BootstrapToken{
			ID: id, TokenHash: "hash-" + id, Role: api.RoleNode, MaxUsages: 10,
			CreatedAt: expiresAt.Add(-day), ExpiresAt: expiresAt, Ephemeral: ephemeral,
		}); err != nil {
			t.Fatalf("token %s: %v", id, err)
		}
	}
	request := func(id, tokenID string, createdAt time.Time, resolvedAt *time.Time) {
		t.Helper()
		if err := store.CreateEnrollmentRequest(ctx, &EnrollmentRequest{
			ID: id, PeerID: "peer-" + id, PublicKey: []byte("pub"), TokenID: tokenID,
			Status: api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED, CreatedAt: createdAt, ResolvedAt: resolvedAt,
		}); err != nil {
			t.Fatalf("request %s: %v", id, err)
		}
	}
	at := func(ago time.Duration) *time.Time { ts := now.Add(-ago); return &ts }

	// A token still in use, one that expired long ago but whose request is
	// recent, one expired long ago with an old request, an ephemeral one
	// whose requests are two hours old, and one that just expired.
	token("live", now.Add(day), false)
	token("old-with-recent-request", now.Add(-40*day), false)
	token("old", now.Add(-40*day), false)
	token("ephemeral", now.Add(-2*time.Hour), true)
	token("just-expired", now.Add(-time.Hour), false)
	request("live-1", "live", now.Add(-time.Hour), at(time.Hour))
	request("recent-on-old-token", "old-with-recent-request", now.Add(-41*day), at(2*day))
	request("old-resolved", "old", now.Add(-41*day), at(40*day))
	request("old-pending", "old", now.Add(-41*day), nil)
	request("ephemeral-1", "ephemeral", now.Add(-2*time.Hour), at(2*time.Hour))
	request("ephemeral-2", "ephemeral", now.Add(-2*time.Hour), at(2*time.Hour))
	request("ephemeral-fresh", "ephemeral", now.Add(-10*time.Minute), at(10*time.Minute))

	requests, err := store.DeleteStaleEnrollmentRequests(ctx, now.Add(-30*day), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("DeleteStaleEnrollmentRequests: %v", err)
	}
	if requests != 4 {
		t.Errorf("deleted %d requests, want 4 (old-resolved, old-pending, ephemeral-1, ephemeral-2)", requests)
	}
	left, err := store.ListEnrollmentRequests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var leftIDs []string
	for _, r := range left {
		leftIDs = append(leftIDs, r.ID)
	}
	slices.Sort(leftIDs)
	if want := []string{"ephemeral-fresh", "live-1", "recent-on-old-token"}; !slices.Equal(leftIDs, want) {
		t.Errorf("remaining requests = %v, want %v", leftIDs, want)
	}

	// "old" lost both requests and goes; "old-with-recent-request" is still
	// referred to and stays; "ephemeral" keeps its fresh request; "just-expired"
	// is within the retention.
	tokens, err := store.DeleteExpiredBootstrapTokens(ctx, now.Add(-30*day))
	if err != nil {
		t.Fatalf("DeleteExpiredBootstrapTokens: %v", err)
	}
	if tokens != 1 {
		t.Errorf("deleted %d tokens, want 1 (old)", tokens)
	}
	remaining, err := store.ListBootstrapTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var tokenIDs []string
	for i := range remaining {
		tokenIDs = append(tokenIDs, remaining[i].ID)
	}
	slices.Sort(tokenIDs)
	if want := []string{"ephemeral", "just-expired", "live", "old-with-recent-request"}; !slices.Equal(tokenIDs, want) {
		t.Errorf("remaining tokens = %v, want %v", tokenIDs, want)
	}
}

func TestCountEnrollmentRequestsByStatus(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	if err := store.SaveBootstrapToken(ctx, &BootstrapToken{ID: "tok", TokenHash: "hash", Role: api.RoleNode, MaxUsages: 10, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for i, status := range []api.EnrollmentStatus{
		api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
		api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
		api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
		api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED,
	} {
		if err := store.CreateEnrollmentRequest(ctx, &EnrollmentRequest{
			ID: fmt.Sprintf("req-%d", i), PeerID: fmt.Sprintf("peer-%d", i), PublicKey: []byte("pub"), TokenID: "tok", Status: status, CreatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := store.CountEnrollmentRequests(ctx)
	if err != nil {
		t.Fatalf("CountEnrollmentRequests: %v", err)
	}
	want := map[api.EnrollmentStatus]int64{
		api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING:  1,
		api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED: 2,
		api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED: 1,
	}
	if len(counts) != len(want) {
		t.Fatalf("counts = %v, want %v", counts, want)
	}
	for status, n := range want {
		if counts[status] != n {
			t.Errorf("%s = %d, want %d", status, counts[status], n)
		}
	}
	// The list and the count agree, so the admin view and the gauge do.
	list, err := store.ListEnrollmentRequests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 {
		t.Errorf("ListEnrollmentRequests returned %d, want 4", len(list))
	}
}

// A node written without a last-seen instant is seen now, not at the zero
// time: the silent-member sweep would otherwise collect it on the control
// plane's first sweep, which raced with every test that enrolled a node
// this way (TestUserStatusAndTenancy failed so in CI).
func TestEnrollNodeWithoutEnrolledAtIsSeenNow(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	before := time.Now().Add(-time.Second)
	node := &EnrolledNode{PeerID: "fresh", PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode}
	if err := store.EnrollNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetNode(ctx, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	if got.EnrolledAt.Before(before) {
		t.Fatalf("EnrolledAt = %s, want about now", got.EnrolledAt)
	}
	regular, ephemeral, err := store.DeleteSilentBootstrapNodes(ctx, time.Now().Add(-30*24*time.Hour), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if regular != 0 || ephemeral != 0 {
		t.Fatalf("the sweep deleted regular=%d ephemeral=%d rows; a node enrolled now is not silent", regular, ephemeral)
	}
}

func TestDeleteExpiredRouterLeases(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	lease := func(id string, expiresAt time.Time) {
		t.Helper()
		if err := store.UpsertRouterLease(ctx, &RouterLease{
			PeerID: id, Addresses: []string{"/ip4/127.0.0.1/tcp/1"}, LastRenewal: expiresAt.Add(-time.Minute), ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("lease %s: %v", id, err)
		}
	}
	lease("live", now.Add(time.Minute))
	lease("lapsed-today", now.Add(-time.Hour))
	lease("gone", now.Add(-40*24*time.Hour))

	deleted, err := store.DeleteExpiredRouterLeases(ctx, now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("DeleteExpiredRouterLeases: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted %d leases, want 1 (gone)", deleted)
	}
	counts, err := store.CountRows(ctx)
	if err != nil {
		t.Fatalf("CountRows: %v", err)
	}
	if counts["routers"] != 2 {
		t.Errorf("routers rows = %d, want 2 (live, lapsed-today); counts %v", counts["routers"], counts)
	}
	active, err := store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].PeerID != "live" {
		t.Errorf("active routers = %+v, want only live", active)
	}
}

func TestCountRowsCoversEveryGrowingTable(t *testing.T) {
	store := newTestStore(t)
	counts, err := store.CountRows(context.Background())
	if err != nil {
		t.Fatalf("CountRows: %v", err)
	}
	for _, table := range []string{"nodes", "enrollment_requests", "bootstrap_tokens", "routers", "revoked_biscuits", "banned_identities", "users", "keyring"} {
		if _, ok := counts[table]; !ok {
			t.Errorf("CountRows lacks %q: %v", table, counts)
		}
	}
}

func TestDeleteExpiredNodesSparesBannedAndUnbounded(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	enroll := func(id string, expiresAt time.Time) {
		t.Helper()
		if err := store.EnrollNode(ctx, &EnrolledNode{
			PeerID: id, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode,
			EnrollmentType: "OIDC", EnrolledAt: now.Add(-48 * time.Hour), ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	enroll("lapsed-long-ago", now.Add(-24*time.Hour))
	enroll("lapsed-just-now", now.Add(-time.Minute))
	enroll("still-admitted", now.Add(time.Hour))
	enroll("lapsed-but-banned", now.Add(-24*time.Hour))
	enroll("never-bounded", time.Time{})
	if err := store.SetNodeBanned(ctx, "lapsed-but-banned", true); err != nil {
		t.Fatal(err)
	}

	deleted, err := store.DeleteExpiredNodes(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("DeleteExpiredNodes: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted %d rows, want 1", deleted)
	}

	remaining, err := store.ListNodes(ctx, NodeFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, n := range remaining {
		got[n.PeerID] = true
	}
	for _, want := range []string{"lapsed-just-now", "still-admitted", "lapsed-but-banned", "never-bounded"} {
		if !got[want] {
			t.Errorf("%s was deleted", want)
		}
	}
	if got["lapsed-long-ago"] {
		t.Error("lapsed-long-ago survived")
	}
	if banned, _ := store.IsNodeBanned(ctx, "lapsed-but-banned"); !banned {
		t.Error("the ban did not survive the sweep")
	}
}

// The console lists, pages and revokes from what ListNodes selects, so each
// state must hold exactly what CheckAdmission says, an owner filter must never
// widen, and paging must not lose a row that shares its enrollment time with
// the end of the previous page.
func TestListNodes(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	for _, id := range []string{"alice", "bob"} {
		if err := store.SaveUser(ctx, &User{ID: id, Role: "user", CreatedAt: now}); err != nil {
			t.Fatalf("save user %s: %v", id, err)
		}
	}
	enrolled := now.Add(-48 * time.Hour)
	for _, n := range []struct {
		id, owner, role       string
		enrolledAt, expiresAt time.Time
	}{
		{"live-a", "alice", api.RoleNode, enrolled, now.Add(time.Hour)},
		{"live-b", "bob", api.RoleNode, enrolled, now.Add(time.Hour)},
		{"never", "alice", api.RoleRouter, enrolled.Add(-time.Hour), time.Time{}},
		{"exp-a", "alice", api.RoleNode, enrolled.Add(-2 * time.Hour), now.Add(-time.Minute)},
		{"exp-unowned", "", api.RoleNode, enrolled.Add(-3 * time.Hour), now.Add(-time.Hour)},
		{"banned", "alice", api.RoleNode, enrolled.Add(-4 * time.Hour), now.Add(-24 * time.Hour)},
	} {
		if err := store.EnrollNode(ctx, &EnrolledNode{
			PeerID: n.id, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: n.role,
			EnrollmentType: "OIDC", OwnerID: n.owner, EnrolledAt: n.enrolledAt, ExpiresAt: n.expiresAt,
		}); err != nil {
			t.Fatalf("enroll %s: %v", n.id, err)
		}
	}
	if err := store.SetNodeBanned(ctx, "banned", true); err != nil {
		t.Fatal(err)
	}

	list := func(t *testing.T, filter NodeFilter) []string {
		t.Helper()
		nodes, err := store.ListNodes(ctx, filter)
		if err != nil {
			t.Fatalf("ListNodes(%+v): %v", filter, err)
		}
		var ids []string
		for _, n := range nodes {
			ids = append(ids, n.PeerID)
		}
		return ids
	}

	all := []string{"live-b", "live-a", "never", "exp-a", "exp-unowned", "banned"}
	for _, tc := range []struct {
		name   string
		filter NodeFilter
		want   []string
	}{
		{"zero filter", NodeFilter{}, all},
		{"admitted", NodeFilter{States: []NodeState{NodeAdmitted}, Now: now}, []string{"live-b", "live-a", "never"}},
		{"expired", NodeFilter{States: []NodeState{NodeExpired}, Now: now}, []string{"exp-a", "exp-unowned"}},
		{"banned", NodeFilter{States: []NodeState{NodeBanned}, Now: now}, []string{"banned"}},
		{"admitted or banned", NodeFilter{States: []NodeState{NodeAdmitted, NodeBanned}, Now: now}, []string{"live-b", "live-a", "never", "banned"}},
		{"one owner", NodeFilter{OwnerID: new("alice")}, []string{"live-a", "never", "exp-a", "banned"}},
		{"owner without nodes", NodeFilter{OwnerID: new("carol")}, nil},
		// An empty ID must never widen to every owner, unowned rows included.
		{"empty owner", NodeFilter{OwnerID: new("")}, nil},
		{"role", NodeFilter{Role: api.RoleRouter}, []string{"never"}},
		{"owner and state", NodeFilter{States: []NodeState{NodeExpired}, Now: now, OwnerID: new("alice")}, []string{"exp-a"}},
		{"cursor from another owner's row", NodeFilter{OwnerID: new("alice"), After: &NodeCursor{EnrolledAt: enrolled, PeerID: "live-b"}}, []string{"live-a", "never", "exp-a", "banned"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := list(t, tc.filter); !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}

	for _, pageSize := range []int{1, 4} {
		t.Run("pages of "+strconv.Itoa(pageSize), func(t *testing.T) {
			var got []string
			var after *NodeCursor
			for range len(all) + 1 {
				page, err := store.ListNodes(ctx, NodeFilter{After: after, Limit: pageSize})
				if err != nil {
					t.Fatal(err)
				}
				if len(page) == 0 {
					break
				}
				for _, n := range page {
					got = append(got, n.PeerID)
				}
				last := page[len(page)-1]
				after = &NodeCursor{EnrolledAt: last.EnrolledAt, PeerID: last.PeerID}
			}
			if !slices.Equal(got, all) {
				t.Errorf("paging visited %v, want %v", got, all)
			}
		})
	}

	t.Run("CountNodes buckets as ListNodes filters", func(t *testing.T) {
		counts, err := store.CountNodes(ctx, now)
		if err != nil {
			t.Fatalf("CountNodes: %v", err)
		}
		got := map[NodeCount]bool{}
		for _, c := range counts {
			got[c] = true
		}
		want := map[NodeCount]bool{
			{Role: api.RoleNode, State: NodeAdmitted, Count: 2}:   true,
			{Role: api.RoleRouter, State: NodeAdmitted, Count: 1}: true,
			{Role: api.RoleNode, State: NodeExpired, Count: 2}:    true,
			{Role: api.RoleNode, State: NodeBanned, Count: 1}:     true,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("CountNodes = %v, want %v", counts, want)
		}
	})

	if _, err := store.ListNodes(ctx, NodeFilter{States: []NodeState{"lapsed"}}); err == nil {
		t.Error("ListNodes accepted an unknown state")
	}
}

func TestBootstrapTokenRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &BootstrapToken{
		ID:          "token-id",
		TokenHash:   "hash",
		Role:        api.RoleNode,
		OwnerID:     "owner-1",
		MaxUsages:   5,
		UsagesCount: 2,
		Description: "a description",
		CreatedAt:   time.Now().Add(-time.Hour),
		ExpiresAt:   time.Now().Add(time.Hour),
		// Non-default so the round trip proves the column is read back.
		AutonomousRecovery: true,
		Ephemeral:          true,
	}
	// RevokedAt is never set at creation - only RevokeBootstrapToken sets it,
	// covered separately below.
	requireAllFieldsSet(t, want, "RevokedAt")

	if err := store.SaveBootstrapToken(ctx, want); err != nil {
		t.Fatalf("SaveBootstrapToken: %v", err)
	}

	got, err := store.GetBootstrapToken(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetBootstrapToken: %v", err)
	}
	requireFieldsRoundTrip(t, want, got)
	if got.IsRevoked() {
		t.Error("a freshly saved token must not start out revoked")
	}

	listed, err := store.ListBootstrapTokens(ctx)
	if err != nil {
		t.Fatalf("ListBootstrapTokens: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListBootstrapTokens returned %d, want 1", len(listed))
	}
	requireFieldsRoundTrip(t, want, &listed[0])

	if err := store.RevokeBootstrapToken(ctx, want.ID); err != nil {
		t.Fatalf("RevokeBootstrapToken: %v", err)
	}
	revoked, err := store.GetBootstrapToken(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetBootstrapToken after revoke: %v", err)
	}
	if !revoked.IsRevoked() {
		t.Fatal("RevokedAt was not persisted by RevokeBootstrapToken")
	}

	// Idempotent: revoking an already-revoked token is not an error and does
	// not un-set RevokedAt.
	if err := store.RevokeBootstrapToken(ctx, want.ID); err != nil {
		t.Fatalf("RevokeBootstrapToken (second call): %v", err)
	}
	revokedAgain, err := store.GetBootstrapToken(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetBootstrapToken after second revoke: %v", err)
	}
	if !revokedAgain.IsRevoked() {
		t.Error("a second RevokeBootstrapToken call must not un-revoke the token")
	}

	// Revoking an unknown id is also not an error - the HTTP layer is what
	// distinguishes "unknown" via a preceding GetBootstrapToken.
	if err := store.RevokeBootstrapToken(ctx, "no-such-token"); err != nil {
		t.Errorf("RevokeBootstrapToken(unknown id) = %v, want nil", err)
	}
}

func TestEnrollmentRequestRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	resolvedAt := time.Now().Add(-time.Minute)
	want := &EnrollmentRequest{
		ID:        "request-id",
		PeerID:    "12D3KooWPending",
		PublicKey: []byte("pub"),
		TokenID:   "token-id",
		Status:    api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
		// Labels decide what the minted biscuit attests, so losing them here
		// would silently drop a node's attested claims.
		Labels:       map[string]string{"region": "emea"},
		BiscuitToken: []byte("biscuit"),
		CreatedAt:    time.Now().Add(-time.Hour),
		ResolvedAt:   &resolvedAt,
		ResolvedBy:   "admin",
	}
	requireAllFieldsSet(t, want)

	if err := store.CreateEnrollmentRequest(ctx, want); err != nil {
		t.Fatalf("CreateEnrollmentRequest: %v", err)
	}

	byPeer, err := store.GetEnrollmentRequest(ctx, want.PeerID)
	if err != nil {
		t.Fatalf("GetEnrollmentRequest: %v", err)
	}
	requireFieldsRoundTrip(t, want, byPeer)

	byID, err := store.GetEnrollmentRequestByID(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetEnrollmentRequestByID: %v", err)
	}
	requireFieldsRoundTrip(t, want, byID)

	listed, err := store.ListEnrollmentRequests(ctx)
	if err != nil {
		t.Fatalf("ListEnrollmentRequests: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListEnrollmentRequests returned %d, want 1", len(listed))
	}
	requireFieldsRoundTrip(t, want, &listed[0])
}

func TestRouterLeaseRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &RouterLease{
		PeerID:          "12D3KooWRouter",
		Addresses:       []string{"/ip4/127.0.0.1/tcp/4001"},
		LastRenewal:     time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
		ConnectedPeers:  []string{"12D3KooWPeerA"},
		DHTSize:         42,
		Connections:     1200,
		ConnectionLimit: 4000,
		IngressURL:      "https://bananas.sam-mesh.dev/ingress",
	}
	requireAllFieldsSet(t, want)

	if err := store.UpsertRouterLease(ctx, want); err != nil {
		t.Fatalf("UpsertRouterLease: %v", err)
	}

	active, err := store.GetActiveRouters(ctx)
	if err != nil {
		t.Fatalf("GetActiveRouters: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("GetActiveRouters returned %d, want 1", len(active))
	}
	requireFieldsRoundTrip(t, want, &active[0])
}

func TestUserRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &User{
		ID:        "user-1",
		Issuer:    "https://idp.example",
		Email:     "alice@example.com",
		Role:      "admin",
		CreatedAt: time.Now().Add(-time.Hour),
	}
	requireAllFieldsSet(t, want)

	if err := store.SaveUser(ctx, want); err != nil {
		t.Fatalf("SaveUser: %v", err)
	}

	got, err := store.GetUser(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	requireFieldsRoundTrip(t, want, got)

	listed, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListUsers returned %d, want 1", len(listed))
	}
	requireFieldsRoundTrip(t, want, &listed[0])
}

// PolicyBinding is what attaches a role to an identity, so a field lost here
// would mean a binding that reads as configured and grants nothing.
func TestPolicyBindingRoundTripsEveryField(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	want := &api.PolicyBinding{
		Role:    api.RoleNode,
		Members: []string{"group:platform", api.SystemAuthenticated},
	}
	requireProtoFieldsSet(t, want)

	if err := store.SaveMeshPolicy(ctx, nil, []*api.PolicyBinding{want}); err != nil {
		t.Fatalf("SaveMeshPolicy: %v", err)
	}

	_, bindings, err := store.GetMeshPolicy(ctx)
	if err != nil {
		t.Fatalf("GetMeshPolicy: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("got %d bindings, want 1", len(bindings))
	}
	got := bindings[0]

	if got.Role != want.Role {
		t.Errorf("PolicyBinding.Role did not round trip: saved %q, loaded %q", want.Role, got.Role)
	}
	if !reflect.DeepEqual(got.Members, want.Members) {
		t.Errorf("PolicyBinding.Members did not round trip: saved %v, loaded %v", want.Members, got.Members)
	}
}

// requireProtoFieldsSet is requireAllFieldsSet for generated messages, whose
// unexported state and internal fields have to be stepped over.
func requireProtoFieldsSet(t *testing.T, v any) {
	t.Helper()
	val := reflect.ValueOf(v).Elem()
	for i := 0; i < val.NumField(); i++ {
		field := val.Type().Field(i)
		if !field.IsExported() || strings.HasPrefix(field.Name, "XXX_") {
			continue
		}
		switch field.Type.Kind() {
		case reflect.String, reflect.Slice, reflect.Map:
			if val.Field(i).IsZero() {
				t.Fatalf("%s.%s is not set in this test: populate it and check the store persists it",
					val.Type().Name(), field.Name)
			}
		}
	}
}
