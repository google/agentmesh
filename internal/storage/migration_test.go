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
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
)

// openAtSchemaVersion creates a sqlite database migrated up to and including
// version, the way a control plane of that era left it.
func openAtSchemaVersion(t *testing.T, path string, version int) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version > version {
			break
		}
		for _, q := range m.sqlite {
			if _, err := db.Exec(q); err != nil {
				t.Fatalf("migration %d: %v", m.version, err)
			}
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, m.version); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// Before schema version 15 four tables stored instants as unix seconds while
// the rest of the schema used milliseconds. The migration rewrites those
// rows once, and leaves rows that already hold milliseconds alone.
func TestMigrationConvertsSecondsToMillis(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.db")
	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	expires := created.Add(48 * time.Hour)
	revoked := created.Add(time.Hour)
	resolved := created.Add(2 * time.Minute)

	db := openAtSchemaVersion(t, path, 14)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO users (id, issuer, email, role, created_at) VALUES ('alice', 'https://idp', 'alice@example.com', 'user', ?)`, created.Unix())
	exec(`INSERT INTO bootstrap_tokens (id, token_hash, role, max_usages, usages_count, description, created_at, expires_at, revoked_at)
		VALUES ('old', 'old', 'mesh:role:node', 2, 0, 'seconds era', ?, ?, NULL)`, created.Unix(), expires.Unix())
	exec(`INSERT INTO bootstrap_tokens (id, token_hash, role, max_usages, usages_count, description, created_at, expires_at, revoked_at)
		VALUES ('old-revoked', 'old-revoked', 'mesh:role:node', 1, 0, 'seconds era', ?, ?, ?)`, created.Unix(), expires.Unix(), revoked.Unix())
	// A row written in milliseconds must come through the guard untouched.
	exec(`INSERT INTO bootstrap_tokens (id, token_hash, role, max_usages, usages_count, description, created_at, expires_at, revoked_at)
		VALUES ('new', 'new', 'mesh:role:node', 1, 0, 'millis era', ?, ?, NULL)`, created.UnixMilli(), expires.UnixMilli())
	exec(`INSERT INTO enrollment_requests (id, peer_id, public_key, token_id, status, created_at, resolved_at, resolved_by)
		VALUES ('req', '12D3KooWPeer', X'00', 'old', ?, ?, ?, 'admin')`, int(api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED), created.Unix(), resolved.Unix())
	exec(`INSERT INTO banned_identities (identity, banned_at) VALUES ('https://idp|mallory', ?)`, created.Unix())
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLStore("sqlite", path)
	if err != nil {
		t.Fatalf("opening the store runs the migration: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	var version int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version < 15 {
		t.Fatalf("schema version = %d, want at least 15", version)
	}

	user, err := store.GetUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !user.CreatedAt.Equal(created) {
		t.Errorf("user created_at = %v, want %v", user.CreatedAt, created)
	}

	for _, id := range []string{"old", "new"} {
		tok, err := store.GetBootstrapToken(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !tok.CreatedAt.Equal(created) || !tok.ExpiresAt.Equal(expires) || tok.RevokedAt != nil {
			t.Errorf("token %s = created %v expires %v revoked %v; want %v %v nil", id, tok.CreatedAt, tok.ExpiresAt, tok.RevokedAt, created, expires)
		}
	}
	tok, err := store.GetBootstrapToken(ctx, "old-revoked")
	if err != nil {
		t.Fatal(err)
	}
	if tok.RevokedAt == nil || !tok.RevokedAt.Equal(revoked) {
		t.Errorf("token old-revoked revoked_at = %v, want %v", tok.RevokedAt, revoked)
	}
	// The usability check compares expires_at against the clock in the same
	// unit; a token still valid in its own era stays valid.
	if err := store.ConsumeBootstrapTokenUsage(ctx, "old", expires.Add(-time.Minute)); err != nil {
		t.Errorf("consuming a converted token before its expiry: %v", err)
	}
	if err := store.ConsumeBootstrapTokenUsage(ctx, "old", expires.Add(time.Minute)); err == nil {
		t.Error("consuming a converted token after its expiry succeeded")
	}

	req, err := store.GetEnrollmentRequestByID(ctx, "req")
	if err != nil {
		t.Fatal(err)
	}
	if !req.CreatedAt.Equal(created) || req.ResolvedAt == nil || !req.ResolvedAt.Equal(resolved) {
		t.Errorf("enrollment request = created %v resolved %v; want %v %v", req.CreatedAt, req.ResolvedAt, created, resolved)
	}

	var bannedAt int64
	if err := store.db.QueryRow(`SELECT banned_at FROM banned_identities WHERE identity = 'https://idp|mallory'`).Scan(&bannedAt); err != nil {
		t.Fatal(err)
	}
	if bannedAt != created.UnixMilli() {
		t.Errorf("banned_at = %d, want %d", bannedAt, created.UnixMilli())
	}
}

// Migrations 16 and 19 index the scans that run on every bootstrap, every GC
// pass and every console refresh; the index list is the contract the planner
// relies on.
func TestMigrationCreatesIndexes(t *testing.T) {
	store, err := NewSQLStore("sqlite", filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	rows, err := store.db.Query(`SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got = append(got, name)
	}
	want := []string{
		"idx_enrollment_requests_created_at",
		"idx_nodes_banned_expires_at",
		"idx_nodes_enrolled_at",
		"idx_nodes_owner_id",
		"idx_revoked_biscuits_expires_at",
		"idx_routers_expires_at",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("indexes = %v, want %v", got, want)
	}
}

func TestMigrationRenamesSamPrefixesToMesh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.db")
	now := time.Now().UnixMilli()

	db := openAtSchemaVersion(t, path, 16)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	exec(`INSERT INTO roles (name, description, created_at) VALUES ('sam:role:node', '', ?), ('sam:role:router', '', ?)`, now, now)
	exec(`INSERT INTO role_permissions (role_name, resource_type, resource_value) VALUES
		('sam:role:node', 'service', 'system://sam.catalog'),
		('sam:role:router', 'service', '*')`)
	exec(`INSERT INTO role_bindings (role_name, member) VALUES
		('sam:role:node', 'sam:system:authenticated'),
		('sam:role:router', 'group:routers')`)
	exec(`INSERT INTO nodes (peer_id, public_key, biscuit_token, role, enrollment_type, enrolled_at, expires_at, banned)
		VALUES ('12D3KooWNode', X'01', X'02', 'sam:role:node', 'OIDC', ?, ?, 0)`, now, now+3600000)
	exec(`INSERT INTO bootstrap_tokens (id, token_hash, role, max_usages, usages_count, description, created_at, expires_at)
		VALUES ('tok1', 'tok1', 'sam:role:router', 1, 0, 'legacy router token', ?, ?)`, now, now+3600000)
	exec(`INSERT INTO egress_destinations (name, target_url, credential, served_by, config_json)
		VALUES ('api.example.com', 'https://api.example.com', 'TOKEN', '["sam:role:node"]', '{"name":"api.example.com","target_url":"https://api.example.com","credential":"TOKEN","served_by":["sam:role:node"]}')`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLStore("sqlite", path)
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	roles, bindings, err := store.GetMeshPolicy(ctx)
	if err != nil {
		t.Fatalf("GetMeshPolicy: %v", err)
	}
	roleMap := make(map[string]*api.PolicyRole)
	for _, r := range roles {
		roleMap[r.Name] = r
	}
	if _, ok := roleMap["sam:role:node"]; ok {
		t.Errorf("legacy sam:role:node still present in roles")
	}
	nodeRole, ok := roleMap["mesh:role:node"]
	if !ok {
		t.Fatalf("mesh:role:node missing from migrated roles: %+v", roleMap)
	}
	if !reflect.DeepEqual(nodeRole.AllowedServices, []string{"system://mesh.catalog"}) {
		t.Errorf("mesh:role:node AllowedServices = %v, want [system://mesh.catalog]", nodeRole.AllowedServices)
	}

	bindingMap := make(map[string][]string)
	for _, b := range bindings {
		bindingMap[b.Role] = b.Members
	}
	if !reflect.DeepEqual(bindingMap["mesh:role:node"], []string{"mesh:system:authenticated"}) {
		t.Errorf("mesh:role:node members = %v, want [mesh:system:authenticated]", bindingMap["mesh:role:node"])
	}
	if !reflect.DeepEqual(bindingMap["mesh:role:router"], []string{"group:routers"}) {
		t.Errorf("mesh:role:router members = %v, want [group:routers]", bindingMap["mesh:role:router"])
	}

	node, err := store.GetNode(ctx, "12D3KooWNode")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if node.Role != "mesh:role:node" {
		t.Errorf("node.Role = %q, want mesh:role:node", node.Role)
	}

	tok, err := store.GetBootstrapToken(ctx, "tok1")
	if err != nil {
		t.Fatalf("GetBootstrapToken: %v", err)
	}
	if tok.Role != "mesh:role:router" {
		t.Errorf("tok.Role = %q, want mesh:role:router", tok.Role)
	}

	egress, err := store.GetEgressDestinations(ctx)
	if err != nil {
		t.Fatalf("GetEgressDestinations: %v", err)
	}
	if len(egress) != 1 || !reflect.DeepEqual(egress[0].GetServedBy(), []string{"mesh:role:node"}) {
		t.Errorf("egress ServedBy = %+v, want [mesh:role:node]", egress)
	}
}
