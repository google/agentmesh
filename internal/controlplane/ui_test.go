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
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/storage"
	"google.golang.org/protobuf/encoding/protojson"
)

// An expired OIDC node can renew in place, so its owner and every admin must
// be able to page through it to revoke it, and nobody else may see it.
func TestHandleListNodes(t *testing.T) {
	h := newLifecycleHarness(t)
	ctx := context.Background()
	now := time.Now()
	const adminToken = "super-secret-admin-token"
	aliceToken := h.mintToken(map[string]interface{}{"sub": "alice"})

	for _, id := range []string{"alice", "bob"} {
		if err := h.store.SaveUser(ctx, &storage.User{ID: id, Role: "user", CreatedAt: now}); err != nil {
			t.Fatalf("save user %s: %v", id, err)
		}
	}
	enrolled := now.Add(-48 * time.Hour)
	for _, n := range []struct {
		id, owner             string
		enrolledAt, expiresAt time.Time
	}{
		{"alice-1", "alice", enrolled, now.Add(-time.Hour)},
		{"bob-1", "bob", enrolled, now.Add(-time.Hour)},
		{"alice-2", "alice", enrolled.Add(-time.Hour), now.Add(-2 * time.Hour)},
		{"bob-2", "bob", enrolled.Add(-time.Hour), now.Add(-2 * time.Hour)},
		{"alice-live", "alice", enrolled, now.Add(time.Hour)},
		{"alice-banned", "alice", enrolled, now.Add(-3 * time.Hour)},
	} {
		if err := h.store.EnrollNode(ctx, &storage.EnrolledNode{
			PeerID: n.id, PublicKey: []byte("pub"), Biscuit: []byte("b"), Role: api.RoleNode,
			EnrollmentType: "OIDC", ClaimsJSON: `{"sub":"` + n.owner + `"}`, OwnerID: n.owner,
			EnrolledAt: n.enrolledAt, ExpiresAt: n.expiresAt,
		}); err != nil {
			t.Fatalf("enroll %s: %v", n.id, err)
		}
	}
	if err := h.store.SetNodeBanned(ctx, "alice-banned", true); err != nil {
		t.Fatal(err)
	}

	get := func(t *testing.T, path, bearer string) []byte {
		t.Helper()
		status, body := h.do(http.MethodGet, path, bearer, nil, "")
		if status != http.StatusOK {
			t.Fatalf("GET %s: status %d, body %s", path, status, body)
		}
		return body
	}
	page := func(t *testing.T, query, bearer string) *api.NodeListResponse {
		t.Helper()
		resp := &api.NodeListResponse{}
		if err := protojson.Unmarshal(get(t, "/user/nodes?"+query, bearer), resp); err != nil {
			t.Fatalf("decode /user/nodes: %v", err)
		}
		return resp
	}
	ids := func(nodes []*api.EnrolledNode) []string {
		var out []string
		for _, n := range nodes {
			out = append(out, n.GetPeerId())
		}
		return out
	}
	// pageAll follows next_page_token from the first page to the last.
	pageAll := func(t *testing.T, bearer string) []string {
		t.Helper()
		var got []string
		token := ""
		for range 10 {
			resp := page(t, "state=expired&page_size=1&page_token="+url.QueryEscape(token), bearer)
			got = append(got, ids(resp.GetNodes())...)
			if token = resp.GetNextPageToken(); token == "" {
				return got
			}
		}
		t.Fatalf("next_page_token never ran out, visited %v", got)
		return nil
	}

	t.Run("admin sees every expired node", func(t *testing.T) {
		want := []string{"bob-1", "alice-1", "bob-2", "alice-2"}
		if got := pageAll(t, adminToken); !slices.Equal(got, want) {
			t.Errorf("admin paged through %v, want %v", got, want)
		}
	})

	t.Run("user sees only its own expired nodes", func(t *testing.T) {
		want := []string{"alice-1", "alice-2"}
		if got := pageAll(t, aliceToken); !slices.Equal(got, want) {
			t.Errorf("alice paged through %v, want %v", got, want)
		}
	})

	t.Run("a cursor from another owner's row does not widen the scope", func(t *testing.T) {
		token := encodeNodesPageToken(storage.NodeCursor{EnrolledAt: enrolled, PeerID: "bob-1"})
		want := []string{"alice-1", "alice-2"}
		if got := ids(page(t, "state=expired&page_token="+token, aliceToken).GetNodes()); !slices.Equal(got, want) {
			t.Errorf("alice after bob-1's cursor got %v, want %v", got, want)
		}
	})

	t.Run("admin narrows by owner and state", func(t *testing.T) {
		want := []string{"alice-live", "alice-banned"}
		if got := ids(page(t, "owner_id=alice&state=admitted&state=banned", adminToken).GetNodes()); !slices.Equal(got, want) {
			t.Errorf("admin listing alice's admitted and banned nodes got %v, want %v", got, want)
		}
	})

	t.Run("a user may name only itself as owner", func(t *testing.T) {
		want := []string{"alice-live", "alice-banned", "alice-1", "alice-2"}
		if got := ids(page(t, "owner_id=alice", aliceToken).GetNodes()); !slices.Equal(got, want) {
			t.Errorf("alice listing her own nodes got %v, want %v", got, want)
		}
		if status, body := h.do(http.MethodGet, "/user/nodes?owner_id=bob", aliceToken, nil, ""); status != http.StatusForbidden {
			t.Errorf("alice listing bob's nodes: status %d (%s), want %d", status, body, http.StatusForbidden)
		}
	})

	t.Run("claims stay admin-only", func(t *testing.T) {
		body := get(t, "/user/nodes", aliceToken)
		for _, field := range []string{`"claims_json"`, `"biscuit"`, `"public_key"`} {
			if bytes.Contains(body, []byte(field)) {
				t.Errorf("non-admin body carries %s: %s", field, body)
			}
		}
		if body := get(t, "/user/nodes", adminToken); !bytes.Contains(body, []byte(`"claims_json"`)) {
			t.Errorf("admin body lacks \"claims_json\": %s", body)
		}
	})

	t.Run("GET /user/status leaves expired nodes out", func(t *testing.T) {
		status := &api.UserStatusResponse{}
		if err := protojson.Unmarshal(get(t, "/user/status", aliceToken), status); err != nil {
			t.Fatalf("decode /user/status: %v", err)
		}
		got := ids(status.GetEnrolledNodes())
		if !slices.Contains(got, "alice-live") || slices.Contains(got, "alice-1") {
			t.Errorf("enrolled_nodes = %v, want alice-live listed and alice-1 left out", got)
		}
	})

	for _, tc := range []struct {
		name, bearer, query string
		want                int
	}{
		{"malformed page_token", adminToken, "page_token=%21%21", http.StatusBadRequest},
		{"page_token without a peer ID", adminToken, "page_token=" + base64.RawURLEncoding.EncodeToString([]byte("1700000000000")), http.StatusBadRequest},
		{"page_size zero", adminToken, "page_size=0", http.StatusBadRequest},
		{"page_size not a number", adminToken, "page_size=ten", http.StatusBadRequest},
		{"unknown state", adminToken, "state=lapsed", http.StatusBadRequest},
		{"unauthenticated", "", "", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if status, body := h.do(http.MethodGet, "/user/nodes?"+tc.query, tc.bearer, nil, ""); status != tc.want {
				t.Errorf("status %d (%s), want %d", status, body, tc.want)
			}
		})
	}
}

// The default and the ceiling are what keep one console request one bounded query.
func TestParseNodesPageSize(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{"", defaultNodesPageSize, false},
		{"7", 7, false},
		{"5000", maxNodesPageSize, false},
		{"0", 0, true},
		{"-3", 0, true},
		{"ten", 0, true},
	} {
		got, err := parseNodesPageSize(tc.raw)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("parseNodesPageSize(%q) = %d, %v; want %d, error %t", tc.raw, got, err, tc.want, tc.wantErr)
		}
	}
}
