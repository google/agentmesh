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
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	log "github.com/ipfs/go-log/v2"
	"google.golang.org/protobuf/encoding/protojson"

	// Register PG and SQLite drivers
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var logger = log.Logger("agentmesh-storage")

// SQLStore implements Store interface using database/sql.
type SQLStore struct {
	db         *sql.DB
	driverName string
}

// NewSQLStore creates a new SQLStore, connects to the database, and initializes tables.
func NewSQLStore(driverName, dataSourceName string) (*SQLStore, error) {
	actualDriver := driverName
	if driverName == "postgres" || driverName == "postgresql" {
		actualDriver = "pgx"
	}
	if driverName == "sqlite" && !strings.Contains(dataSourceName, "?") {
		// SQLite driver options are configured via DSN query parameters so they apply
		// to all connections in the connection pool. We default to WAL mode for write
		// concurrency and busy_timeout to prevent SQLITE_BUSY locking errors.
		// Callers (e.g. integration tests that copy DB files) can override this by
		// passing a DSN containing custom query parameter parameters (e.g. "?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)").
		dataSourceName = dataSourceName + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	if driverName == "sqlite" {
		if err := restrictSQLiteFileMode(dataSourceName); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open(actualDriver, dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// For postgres, retry Ping() to allow DB container to finish booting
	if actualDriver == "pgx" {
		var pingErr error
		for i := 0; i < 30; i++ {
			pingErr = db.Ping()
			if pingErr == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
		if pingErr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to ping database: %w", pingErr)
		}

		// Bound the pool so a busy control-plane can't exhaust the postgres
		// server's max_connections; recycle connections periodically so
		// long-lived ones don't accumulate stale server-side state.
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)
	} else {
		if strings.Contains(dataSourceName, ":memory:") {
			// A lone connection keeps ":memory:" DSNs (used by tests)
			// consistent, since each additional sql.DB connection to
			// ":memory:" is otherwise its own independent, empty database.
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
		} else {
			// File-backed SQLite in WAL mode supports concurrent readers
			// with a single writer, so allow a small pool instead of
			// serializing every access through one connection.
			db.SetMaxOpenConns(10)
			db.SetMaxIdleConns(2)
		}
	}

	store := &SQLStore{
		db:         db,
		driverName: driverName,
	}

	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return store, nil
}

func (s *SQLStore) isPostgres() bool {
	return strings.Contains(s.driverName, "postgres") || strings.Contains(s.driverName, "pgx")
}

// sqliteFilePath extracts the on-disk path from a SQLite DSN, or "" for
// in-memory databases.
func sqliteFilePath(dsn string) string {
	path := strings.TrimPrefix(dsn, "file:")
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" || strings.Contains(path, ":memory:") {
		return ""
	}
	return path
}

// restrictSQLiteFileMode makes the database owner-only. The keyring holds the
// mesh signing private keys, and the SQLite driver otherwise creates the file
// 0644 (minus umask). The file is created here, before the driver opens it,
// because SQLite gives the -wal and -shm side files the main file's mode.
func restrictSQLiteFileMode(dsn string) error {
	path := sqliteFilePath(dsn)
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create database file %s: %w", path, err)
	}
	_ = f.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to restrict permissions on %s: %w", p, err)
		}
	}
	return nil
}

type migration struct {
	version  int
	sqlite   []string
	postgres []string
}

var migrations = []migration{
	{
		version: 1,
		postgres: []string{
			`CREATE TABLE IF NOT EXISTS keyring (
				id SERIAL PRIMARY KEY,
				private_key BYTEA NOT NULL,
				public_key BYTEA NOT NULL UNIQUE,
				expiration BIGINT,
				created_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS nodes (
				peer_id VARCHAR(255) PRIMARY KEY,
				public_key BYTEA NOT NULL,
				biscuit_token BYTEA NOT NULL,
				role VARCHAR(64) NOT NULL,
				enrollment_type VARCHAR(64) NOT NULL,
				claims_json TEXT,
				enrolled_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL,
				banned BOOLEAN DEFAULT FALSE NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS routers (
				peer_id VARCHAR(255) PRIMARY KEY,
				multiaddresses TEXT NOT NULL,
				last_lease_renewal BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS policies (
				id VARCHAR(255) PRIMARY KEY,
				content TEXT NOT NULL,
				updated_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS bootstrap_tokens (
				id VARCHAR(64) PRIMARY KEY,
				token_hash VARCHAR(64) UNIQUE NOT NULL,
				role VARCHAR(64) NOT NULL,
				max_usages INT NOT NULL,
				usages_count INT NOT NULL,
				description TEXT,
				created_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS enrollment_requests (
				id VARCHAR(64) PRIMARY KEY,
				peer_id VARCHAR(255) UNIQUE NOT NULL,
				public_key BYTEA NOT NULL,
				token_id VARCHAR(64) REFERENCES bootstrap_tokens(id),
				status INT NOT NULL,
				biscuit_token BYTEA,
				created_at BIGINT NOT NULL,
				resolved_at BIGINT,
				resolved_by VARCHAR(255)
			)`,
		},
		sqlite: []string{
			`CREATE TABLE IF NOT EXISTS keyring (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				private_key BLOB NOT NULL,
				public_key BLOB NOT NULL UNIQUE,
				expiration BIGINT,
				created_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS nodes (
				peer_id TEXT PRIMARY KEY,
				public_key BLOB NOT NULL,
				biscuit_token BLOB NOT NULL,
				role TEXT NOT NULL,
				enrollment_type TEXT NOT NULL,
				claims_json TEXT,
				enrolled_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL,
				banned BOOLEAN DEFAULT FALSE NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS routers (
				peer_id TEXT PRIMARY KEY,
				multiaddresses TEXT NOT NULL,
				last_lease_renewal BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS policies (
				id TEXT PRIMARY KEY,
				content TEXT NOT NULL,
				updated_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS bootstrap_tokens (
				id TEXT PRIMARY KEY,
				token_hash TEXT UNIQUE NOT NULL,
				role TEXT NOT NULL,
				max_usages INTEGER NOT NULL,
				usages_count INTEGER NOT NULL,
				description TEXT,
				created_at BIGINT NOT NULL,
				expires_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS enrollment_requests (
				id TEXT PRIMARY KEY,
				peer_id TEXT UNIQUE NOT NULL,
				public_key BLOB NOT NULL,
				token_id TEXT REFERENCES bootstrap_tokens(id),
				status INTEGER NOT NULL,
				biscuit_token BLOB,
				created_at BIGINT NOT NULL,
				resolved_at BIGINT,
				resolved_by TEXT
			)`,
		},
	},
	{
		version: 2,
		postgres: []string{
			`ALTER TABLE routers ADD COLUMN IF NOT EXISTS connected_peers TEXT`,
			`ALTER TABLE routers ADD COLUMN IF NOT EXISTS dht_size INT`,
		},
		sqlite: []string{
			`ALTER TABLE routers ADD COLUMN connected_peers TEXT`,
			`ALTER TABLE routers ADD COLUMN dht_size INTEGER`,
		},
	},
	{
		version: 3,
		postgres: []string{
			`CREATE TABLE IF NOT EXISTS users (
				id VARCHAR(255) PRIMARY KEY,
				email VARCHAR(255) NOT NULL,
				role VARCHAR(64) NOT NULL,
				created_at BIGINT NOT NULL
			)`,
			`ALTER TABLE nodes ADD COLUMN owner_id VARCHAR(255) REFERENCES users(id)`,
			`ALTER TABLE bootstrap_tokens ADD COLUMN owner_id VARCHAR(255) REFERENCES users(id)`,
		},
		sqlite: []string{
			`CREATE TABLE IF NOT EXISTS users (
				id TEXT PRIMARY KEY,
				email TEXT NOT NULL,
				role TEXT NOT NULL,
				created_at BIGINT NOT NULL
			)`,
			`ALTER TABLE nodes ADD COLUMN owner_id TEXT REFERENCES users(id)`,
			`ALTER TABLE bootstrap_tokens ADD COLUMN owner_id TEXT REFERENCES users(id)`,
		},
	},
	{
		version: 4,
		postgres: []string{
			`DROP TABLE IF EXISTS policies`,
			`CREATE TABLE IF NOT EXISTS roles (
				name VARCHAR(64) PRIMARY KEY,
				description TEXT,
				created_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS role_permissions (
				id SERIAL PRIMARY KEY,
				role_name VARCHAR(64) REFERENCES roles(name) ON DELETE CASCADE,
				resource_type VARCHAR(64) NOT NULL,
				resource_value TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS role_bindings (
				id SERIAL PRIMARY KEY,
				role_name VARCHAR(64) REFERENCES roles(name) ON DELETE CASCADE,
				member VARCHAR(255) NOT NULL
			)`,
		},
		sqlite: []string{
			`DROP TABLE IF EXISTS policies`,
			`CREATE TABLE IF NOT EXISTS roles (
				name TEXT PRIMARY KEY,
				description TEXT,
				created_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS role_permissions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				role_name TEXT REFERENCES roles(name) ON DELETE CASCADE,
				resource_type TEXT NOT NULL,
				resource_value TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS role_bindings (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				role_name TEXT REFERENCES roles(name) ON DELETE CASCADE,
				member TEXT NOT NULL
			)`,
		},
	},
	{
		version: 5,
		postgres: []string{
			`ALTER TABLE nodes ADD COLUMN region VARCHAR(16) DEFAULT '' NOT NULL`,
			`ALTER TABLE enrollment_requests ADD COLUMN region VARCHAR(16) DEFAULT '' NOT NULL`,
		},
		sqlite: []string{
			`ALTER TABLE nodes ADD COLUMN region TEXT DEFAULT '' NOT NULL`,
			`ALTER TABLE enrollment_requests ADD COLUMN region TEXT DEFAULT '' NOT NULL`,
		},
	},
	{
		// rotation_lock backs ClaimKeyRotation: a singleton row whose
		// next_rotation_at only advances via a conditional UPDATE, so it
		// doubles as a driver-agnostic mutex across control-plane replicas.
		version: 6,
		postgres: []string{
			`CREATE TABLE IF NOT EXISTS rotation_lock (
				id SMALLINT PRIMARY KEY,
				next_rotation_at BIGINT NOT NULL
			)`,
			`INSERT INTO rotation_lock (id, next_rotation_at) VALUES (1, 0) ON CONFLICT (id) DO NOTHING`,
		},
		sqlite: []string{
			`CREATE TABLE IF NOT EXISTS rotation_lock (
				id INTEGER PRIMARY KEY,
				next_rotation_at BIGINT NOT NULL
			)`,
			`INSERT OR IGNORE INTO rotation_lock (id, next_rotation_at) VALUES (1, 0)`,
		},
	},
	{
		// Replaces the region-specific claim with a generic key=value label
		// set (see api/labels.go): no built-in taxonomy or hierarchy, just a
		// JSON-encoded map an operator can populate with as many labels as
		// their composition needs.
		version: 7,
		postgres: []string{
			`ALTER TABLE nodes DROP COLUMN IF EXISTS region`,
			`ALTER TABLE nodes ADD COLUMN IF NOT EXISTS labels_json TEXT DEFAULT '' NOT NULL`,
			`ALTER TABLE enrollment_requests DROP COLUMN IF EXISTS region`,
			`ALTER TABLE enrollment_requests ADD COLUMN IF NOT EXISTS labels_json TEXT DEFAULT '' NOT NULL`,
		},
		sqlite: []string{
			`ALTER TABLE nodes DROP COLUMN region`,
			`ALTER TABLE nodes ADD COLUMN labels_json TEXT DEFAULT '' NOT NULL`,
			`ALTER TABLE enrollment_requests DROP COLUMN region`,
			`ALTER TABLE enrollment_requests ADD COLUMN labels_json TEXT DEFAULT '' NOT NULL`,
		},
	},
	{
		// A ban must outlive the keypair that carried it: banning a node also
		// bans the enrolled OIDC identity (issuer|subject), which a fresh
		// peer id cannot shed.
		version: 8,
		postgres: []string{
			`CREATE TABLE IF NOT EXISTS banned_identities (
				identity VARCHAR(512) PRIMARY KEY,
				banned_at BIGINT NOT NULL
			)`,
		},
		sqlite: []string{
			`CREATE TABLE IF NOT EXISTS banned_identities (
				identity TEXT PRIMARY KEY,
				banned_at BIGINT NOT NULL
			)`,
		},
	},
	{
		// Soft revoke, not delete: enrollment_requests.token_id has an FK to
		// this table, and a revoked_at column keeps the audit trail distinct
		// from the token's own natural expiry.
		version: 9,
		postgres: []string{
			`ALTER TABLE bootstrap_tokens ADD COLUMN IF NOT EXISTS revoked_at BIGINT`,
		},
		sqlite: []string{
			`ALTER TABLE bootstrap_tokens ADD COLUMN revoked_at BIGINT`,
		},
	},
	{
		// Opt-in autonomous recovery (#367): a per-node flag, seeded from the
		// enrolling bootstrap token, that lets /refresh re-issue a biscuit
		// whose signing key has been retired. Deny by default.
		version: 10,
		postgres: []string{
			`ALTER TABLE nodes ADD COLUMN IF NOT EXISTS autonomous_recovery BOOLEAN DEFAULT FALSE NOT NULL`,
			`ALTER TABLE bootstrap_tokens ADD COLUMN IF NOT EXISTS autonomous_recovery BOOLEAN DEFAULT FALSE NOT NULL`,
		},
		sqlite: []string{
			`ALTER TABLE nodes ADD COLUMN autonomous_recovery BOOLEAN DEFAULT FALSE NOT NULL`,
			`ALTER TABLE bootstrap_tokens ADD COLUMN autonomous_recovery BOOLEAN DEFAULT FALSE NOT NULL`,
		},
	},
	{
		// Identity bans are keyed on issuer|subject; a user row keyed on the
		// bare subject could not be matched against them, so the surfaces a
		// user drives with an ID token (bootstrap tokens, revocation) did not
		// see the ban. Empty for rows from before this migration until the
		// user next logs in.
		version: 11,
		postgres: []string{
			`ALTER TABLE users ADD COLUMN IF NOT EXISTS issuer VARCHAR(512) DEFAULT '' NOT NULL`,
		},
		sqlite: []string{
			`ALTER TABLE users ADD COLUMN issuer TEXT DEFAULT '' NOT NULL`,
		},
	},
	{
		// Egress destinations are part of the policy document (PolicyConfig.egress)
		// but are not role-scoped, so they get their own table. served_by is a
		// JSON array of role names and key=value labels.
		version: 12,
		postgres: []string{
			`CREATE TABLE IF NOT EXISTS egress_destinations (
				name VARCHAR(253) PRIMARY KEY,
				target_url TEXT NOT NULL,
				credential VARCHAR(64) NOT NULL,
				served_by TEXT NOT NULL
			)`,
		},
		sqlite: []string{
			`CREATE TABLE IF NOT EXISTS egress_destinations (
				name TEXT PRIMARY KEY,
				target_url TEXT NOT NULL,
				credential TEXT NOT NULL,
				served_by TEXT NOT NULL
			)`,
		},
	},
	{
		// Persist the full EgressDestination protojson (broker, inspection,
		// mode, ports, preserve_host, forward_context) while keeping the
		// existing columns for backward compatibility.
		version: 13,
		postgres: []string{
			`ALTER TABLE egress_destinations ADD COLUMN IF NOT EXISTS config_json TEXT DEFAULT '' NOT NULL`,
		},
		sqlite: []string{
			`ALTER TABLE egress_destinations ADD COLUMN config_json TEXT DEFAULT '' NOT NULL`,
		},
	},
	{
		// Persist OIDC ES256 signing keys and root Biscuit revocation IDs so
		// multi-replica control planes and restarts preserve JWKS and revocations.
		version: 14,
		postgres: []string{
			`CREATE TABLE IF NOT EXISTS oidc_keyring (
				id SERIAL PRIMARY KEY,
				kid VARCHAR(64) NOT NULL UNIQUE,
				private_key BYTEA NOT NULL,
				public_key BYTEA NOT NULL UNIQUE,
				expiration BIGINT,
				created_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS revoked_biscuits (
				revocation_id VARCHAR(255) PRIMARY KEY,
				expires_at BIGINT NOT NULL
			)`,
		},
		sqlite: []string{
			`CREATE TABLE IF NOT EXISTS oidc_keyring (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				kid TEXT NOT NULL UNIQUE,
				private_key BLOB NOT NULL,
				public_key BLOB NOT NULL UNIQUE,
				expiration BIGINT,
				created_at BIGINT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS revoked_biscuits (
				revocation_id TEXT PRIMARY KEY,
				expires_at BIGINT NOT NULL
			)`,
		},
	},
	{
		// Every BIGINT instant is unix milliseconds. These four tables held
		// seconds; the guard tells the two apart (10^11 seconds is the year
		// 5138, 10^11 milliseconds is 1973), so a row is converted once.
		version:  15,
		postgres: secondsToMillisMigration,
		sqlite:   secondsToMillisMigration,
	},
	{
		// The scans that run on every bootstrap (/info's ban set), every
		// lease lookup, every revocation pull and the node GC; nodes is the
		// one table that grows with the mesh.
		version:  16,
		postgres: indexMigration,
		sqlite:   indexMigration,
	},
	{
		// Migrate persisted roles, bindings, catalog service grants, enrolled
		// nodes, bootstrap tokens, and egress selectors from the legacy "sam:"
		// wire prefix to "mesh:".
		version:  17,
		postgres: meshPrefixMigration,
		sqlite:   meshPrefixMigration,
	},
	{
		// A router's load as of its last lease, for /info to list.
		version: 18,
		postgres: []string{
			`ALTER TABLE routers ADD COLUMN IF NOT EXISTS connections INT`,
			`ALTER TABLE routers ADD COLUMN IF NOT EXISTS connection_limit INT`,
		},
		sqlite: []string{
			`ALTER TABLE routers ADD COLUMN connections INTEGER`,
			`ALTER TABLE routers ADD COLUMN connection_limit INTEGER`,
		},
	},
	{
		// A user's node list searches owner_id, and a GET /user/nodes page
		// walks enrolled_at instead of sorting every matching row.
		version: 19,
		postgres: []string{
			`CREATE INDEX IF NOT EXISTS idx_nodes_owner_id ON nodes (owner_id)`,
			`CREATE INDEX IF NOT EXISTS idx_nodes_enrolled_at ON nodes (enrolled_at, peer_id)`,
		},
		sqlite: []string{
			`CREATE INDEX IF NOT EXISTS idx_nodes_owner_id ON nodes (owner_id)`,
			`CREATE INDEX IF NOT EXISTS idx_nodes_enrolled_at ON nodes (enrolled_at, peer_id)`,
		},
	},
}

var meshPrefixMigration = []string{
	`INSERT INTO roles (name, description, created_at)
		SELECT 'mesh:role:' || SUBSTR(name, 10), description, created_at
		FROM roles WHERE name LIKE 'sam:role:%'
		ON CONFLICT (name) DO NOTHING`,
	`UPDATE role_permissions SET role_name = 'mesh:role:' || SUBSTR(role_name, 10) WHERE role_name LIKE 'sam:role:%'`,
	`UPDATE role_bindings SET role_name = 'mesh:role:' || SUBSTR(role_name, 10) WHERE role_name LIKE 'sam:role:%'`,
	`DELETE FROM roles WHERE name LIKE 'sam:role:%'`,
	`UPDATE role_bindings SET member = 'mesh:system:authenticated' WHERE member = 'sam:system:authenticated'`,
	`UPDATE role_permissions SET resource_value = 'system://mesh.catalog' WHERE resource_type = 'service' AND resource_value = 'system://sam.catalog'`,
	`UPDATE nodes SET role = 'mesh:role:' || SUBSTR(role, 10) WHERE role LIKE 'sam:role:%'`,
	`UPDATE bootstrap_tokens SET role = 'mesh:role:' || SUBSTR(role, 10) WHERE role LIKE 'sam:role:%'`,
	`UPDATE egress_destinations SET served_by = REPLACE(served_by, '"sam:role:', '"mesh:role:'), config_json = REPLACE(config_json, '"sam:role:', '"mesh:role:') WHERE served_by LIKE '%"sam:role:%' OR config_json LIKE '%"sam:role:%'`,
}

var indexMigration = []string{
	`CREATE INDEX IF NOT EXISTS idx_nodes_banned_expires_at ON nodes (banned, expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_routers_expires_at ON routers (expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_revoked_biscuits_expires_at ON revoked_biscuits (expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_enrollment_requests_created_at ON enrollment_requests (created_at)`,
}

var secondsToMillisMigration = []string{
	`UPDATE bootstrap_tokens SET created_at = created_at * 1000 WHERE created_at < 100000000000`,
	`UPDATE bootstrap_tokens SET expires_at = expires_at * 1000 WHERE expires_at < 100000000000`,
	`UPDATE bootstrap_tokens SET revoked_at = revoked_at * 1000 WHERE revoked_at IS NOT NULL AND revoked_at < 100000000000`,
	`UPDATE enrollment_requests SET created_at = created_at * 1000 WHERE created_at < 100000000000`,
	`UPDATE enrollment_requests SET resolved_at = resolved_at * 1000 WHERE resolved_at IS NOT NULL AND resolved_at < 100000000000`,
	`UPDATE users SET created_at = created_at * 1000 WHERE created_at < 100000000000`,
	`UPDATE banned_identities SET banned_at = banned_at * 1000 WHERE banned_at < 100000000000`,
}

func (s *SQLStore) initSchema() error {
	if s.isPostgres() {
		return s.initSchemaPostgres()
	}

	return s.initSchemaDefault()
}

// logSchemaMigrated reports a migration run in one line; an up-to-date
// database says nothing.
func logSchemaMigrated(from, to int) {
	if from == to {
		return
	}
	if from == 0 {
		logger.Infof("Initialized database schema at version %d", to)
		return
	}
	logger.Infof("Migrated database schema from version %d to %d", from, to)
}

func (s *SQLStore) initSchemaDefault() error {
	// Create schema_migrations table
	createMigrationsTable := `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`
	if _, err := s.db.Exec(createMigrationsTable); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	var currentVersion int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to check current schema version: %w", err)
	}
	startVersion := currentVersion

	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}

		err := func() error {
			tx, err := s.db.Begin()
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()

			queries := m.sqlite
			for _, query := range queries {
				if _, err := tx.Exec(query); err != nil {
					errStr := strings.ToLower(err.Error())
					if strings.Contains(errStr, "duplicate column") || strings.Contains(errStr, "already exists") {
						continue
					}
					return fmt.Errorf("migration version %d failed: query %q failed: %w", m.version, query, err)
				}
			}

			insertQuery := s.rebind("INSERT INTO schema_migrations (version) VALUES (?)")
			if _, err := tx.Exec(insertQuery, m.version); err != nil {
				return fmt.Errorf("failed to update schema_migrations version: %w", err)
			}

			if err := tx.Commit(); err != nil {
				return err
			}
			logger.Debugf("Applied schema migration version %d", m.version)
			currentVersion = m.version
			return nil
		}()
		if err != nil {
			return err
		}
	}
	logSchemaMigrated(startVersion, currentVersion)
	return nil
}

func (s *SQLStore) initSchemaPostgres() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("SELECT pg_advisory_xact_lock(7345892)"); err != nil {
		return fmt.Errorf("failed to acquire migration advisory lock: %w", err)
	}

	createMigrationsTable := `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`
	if _, err := tx.Exec(createMigrationsTable); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	var currentVersion int
	err = tx.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to check current schema version: %w", err)
	}
	startVersion := currentVersion

	for _, m := range migrations {
		if m.version <= currentVersion {
			continue
		}

		for _, query := range m.postgres {
			if _, err := tx.Exec(query); err != nil {
				errStr := strings.ToLower(err.Error())
				if strings.Contains(errStr, "duplicate column") || strings.Contains(errStr, "already exists") {
					continue
				}
				return fmt.Errorf("migration version %d failed: query %q failed: %w", m.version, query, err)
			}
		}

		insertQuery := s.rebind("INSERT INTO schema_migrations (version) VALUES (?)")
		if _, err := tx.Exec(insertQuery, m.version); err != nil {
			return fmt.Errorf("failed to update schema_migrations version: %w", err)
		}

		logger.Debugf("Applied schema migration version %d", m.version)
		currentVersion = m.version
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	logSchemaMigrated(startVersion, currentVersion)

	return nil
}

func (s *SQLStore) rebind(query string) string {
	if !s.isPostgres() {
		return query
	}
	var result strings.Builder
	paramIndex := 1
	for _, char := range query {
		if char == '?' {
			fmt.Fprintf(&result, "$%d", paramIndex)
			paramIndex++
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// GetCurrentKey implements Store.
func (s *SQLStore) GetCurrentKey(ctx context.Context) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	query := s.rebind(`SELECT private_key, public_key FROM keyring WHERE expiration IS NULL ORDER BY id DESC LIMIT 1`)
	var privBytes, pubBytes []byte
	err := s.db.QueryRowContext(ctx, query).Scan(&privBytes, &pubBytes)
	if err == sql.ErrNoRows {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return ed25519.PrivateKey(privBytes), ed25519.PublicKey(pubBytes), nil
}

// GetAllValidKeys implements Store.
func (s *SQLStore) GetAllValidKeys(ctx context.Context) ([]KeyPair, error) {
	query := s.rebind(`SELECT private_key, public_key, expiration FROM keyring WHERE expiration IS NULL OR expiration > ?`)
	rows, err := s.db.QueryContext(ctx, query, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var keys []KeyPair
	for rows.Next() {
		var priv, pub []byte
		var exp sql.NullInt64
		if err := rows.Scan(&priv, &pub, &exp); err != nil {
			return nil, err
		}
		var expiration time.Time
		if exp.Valid {
			expiration = time.UnixMilli(exp.Int64)
		}
		privCopy := make([]byte, len(priv))
		copy(privCopy, priv)
		pubCopy := make([]byte, len(pub))
		copy(pubCopy, pub)
		keys = append(keys, KeyPair{
			Private:    ed25519.PrivateKey(privCopy),
			Public:     ed25519.PublicKey(pubCopy),
			Expiration: expiration,
		})
	}
	return keys, rows.Err()
}

// GetAllValidPublicKeys implements Store.
func (s *SQLStore) GetAllValidPublicKeys(ctx context.Context) ([]ed25519.PublicKey, error) {
	query := s.rebind(`SELECT public_key FROM keyring WHERE expiration IS NULL OR expiration > ?`)
	rows, err := s.db.QueryContext(ctx, query, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var keys []ed25519.PublicKey
	for rows.Next() {
		var pub []byte
		if err := rows.Scan(&pub); err != nil {
			return nil, err
		}
		pubCopy := make([]byte, len(pub))
		copy(pubCopy, pub)
		keys = append(keys, ed25519.PublicKey(pubCopy))
	}
	return keys, rows.Err()
}

// ClaimKeyRotation implements Store.
func (s *SQLStore) ClaimKeyRotation(ctx context.Context, now time.Time, interval time.Duration) (bool, error) {
	query := s.rebind(`UPDATE rotation_lock SET next_rotation_at = ? WHERE id = 1 AND next_rotation_at <= ?`)
	res, err := s.db.ExecContext(ctx, query, now.Add(interval).UnixMilli(), now.UnixMilli())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// ReleaseKeyRotationClaim implements Store. It only resets the deadline if
// it still holds the exact value this claim set, so it can't clobber a
// newer claim.
func (s *SQLStore) ReleaseKeyRotationClaim(ctx context.Context, now time.Time, interval time.Duration) error {
	query := s.rebind(`UPDATE rotation_lock SET next_rotation_at = ? WHERE id = 1 AND next_rotation_at = ?`)
	_, err := s.db.ExecContext(ctx, query, now.UnixMilli(), now.Add(interval).UnixMilli())
	return err
}

// RotateKeys implements Store.
func (s *SQLStore) RotateKeys(ctx context.Context, newPriv ed25519.PrivateKey, newPub ed25519.PublicKey, gracePeriod time.Duration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	expireTime := now.Add(gracePeriod)

	// Set expiration on the current active key
	updateQuery := s.rebind(`UPDATE keyring SET expiration = ? WHERE expiration IS NULL`)
	if _, err := tx.ExecContext(ctx, updateQuery, expireTime.UnixMilli()); err != nil {
		return err
	}

	// Insert the new key
	insertQuery := s.rebind(`INSERT INTO keyring (private_key, public_key, created_at) VALUES (?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, insertQuery, []byte(newPriv), []byte(newPub), now.UnixMilli()); err != nil {
		return err
	}

	// Clean up expired keys
	deleteQuery := s.rebind(`DELETE FROM keyring WHERE expiration <= ?`)
	if _, err := tx.ExecContext(ctx, deleteQuery, now.UnixMilli()); err != nil {
		return err
	}

	return tx.Commit()
}

// SaveInitialKey implements Store.
func (s *SQLStore) SaveInitialKey(ctx context.Context, priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	query := s.rebind(`INSERT INTO keyring (private_key, public_key, created_at) VALUES (?, ?, ?)`)
	_, err := s.db.ExecContext(ctx, query, []byte(priv), []byte(pub), time.Now().UnixMilli())
	return err
}

// EnrollNode implements Store.
func (s *SQLStore) EnrollNode(ctx context.Context, node *EnrolledNode) error {
	labelsJSON, err := json.Marshal(node.Labels)
	if err != nil {
		return fmt.Errorf("failed to marshal labels: %w", err)
	}

	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO nodes (peer_id, public_key, biscuit_token, role, enrollment_type, claims_json, owner_id, labels_json, enrolled_at, expires_at, autonomous_recovery, banned) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)
			ON CONFLICT (peer_id) 
			DO UPDATE SET public_key = EXCLUDED.public_key, biscuit_token = EXCLUDED.biscuit_token, role = EXCLUDED.role, enrollment_type = EXCLUDED.enrollment_type, claims_json = EXCLUDED.claims_json, owner_id = EXCLUDED.owner_id, labels_json = EXCLUDED.labels_json, enrolled_at = EXCLUDED.enrolled_at, expires_at = EXCLUDED.expires_at, autonomous_recovery = EXCLUDED.autonomous_recovery`)
	} else {
		query = s.rebind(`
			INSERT INTO nodes (peer_id, public_key, biscuit_token, role, enrollment_type, claims_json, owner_id, labels_json, enrolled_at, expires_at, autonomous_recovery, banned) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
			ON CONFLICT (peer_id) 
			DO UPDATE SET public_key = excluded.public_key, biscuit_token = excluded.biscuit_token, role = excluded.role, enrollment_type = excluded.enrollment_type, claims_json = excluded.claims_json, owner_id = excluded.owner_id, labels_json = excluded.labels_json, enrolled_at = excluded.enrolled_at, expires_at = excluded.expires_at, autonomous_recovery = excluded.autonomous_recovery`)
	}

	ownerIDNull := sql.NullString{String: node.OwnerID, Valid: node.OwnerID != ""}
	_, err = s.db.ExecContext(ctx, query,
		node.PeerID,
		node.PublicKey,
		node.Biscuit,
		node.Role,
		node.EnrollmentType,
		node.ClaimsJSON,
		ownerIDNull,
		string(labelsJSON),
		node.EnrolledAt.UnixMilli(),
		node.ExpiresAt.UnixMilli(),
		node.AutonomousRecovery,
	)
	return err
}

// GetNode implements Store.
func (s *SQLStore) GetNode(ctx context.Context, peerID string) (*EnrolledNode, error) {
	query := s.rebind(`SELECT peer_id, public_key, biscuit_token, role, enrollment_type, claims_json, owner_id, labels_json, enrolled_at, expires_at, banned, autonomous_recovery FROM nodes WHERE peer_id = ?`)
	var node EnrolledNode
	var claimsJSON, ownerID, labelsJSON sql.NullString
	var enrolledAtUnix, expiresAtUnix int64
	err := s.db.QueryRowContext(ctx, query, peerID).Scan(
		&node.PeerID,
		&node.PublicKey,
		&node.Biscuit,
		&node.Role,
		&node.EnrollmentType,
		&claimsJSON,
		&ownerID,
		&labelsJSON,
		&enrolledAtUnix,
		&expiresAtUnix,
		&node.Banned,
		&node.AutonomousRecovery,
	)
	if claimsJSON.Valid {
		node.ClaimsJSON = claimsJSON.String
	}
	if ownerID.Valid {
		node.OwnerID = ownerID.String
	}
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if labelsJSON.Valid && labelsJSON.String != "" {
		if err := json.Unmarshal([]byte(labelsJSON.String), &node.Labels); err != nil {
			return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
		}
	}
	node.EnrolledAt = time.UnixMilli(enrolledAtUnix)
	node.ExpiresAt = time.UnixMilli(expiresAtUnix)
	return &node, nil
}

// SetNodeBanned implements Store.
func (s *SQLStore) SetNodeBanned(ctx context.Context, peerID string, banned bool) error {
	query := s.rebind(`UPDATE nodes SET banned = ? WHERE peer_id = ?`)
	res, err := s.db.ExecContext(ctx, query, banned, peerID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetNodeAutonomousRecovery implements Store.
func (s *SQLStore) SetNodeAutonomousRecovery(ctx context.Context, peerID string, enabled bool) error {
	query := s.rebind(`UPDATE nodes SET autonomous_recovery = ? WHERE peer_id = ?`)
	res, err := s.db.ExecContext(ctx, query, enabled, peerID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// IsNodeBanned implements Store.
func (s *SQLStore) IsNodeBanned(ctx context.Context, peerID string) (bool, error) {
	query := s.rebind(`SELECT banned FROM nodes WHERE peer_id = ?`)
	var banned bool
	err := s.db.QueryRowContext(ctx, query, peerID).Scan(&banned)
	if err == sql.ErrNoRows {
		return false, nil // Not found nodes are not banned by default
	}
	if err != nil {
		return false, err
	}
	return banned, nil
}

// SetIdentityBanned implements Store.
func (s *SQLStore) SetIdentityBanned(ctx context.Context, identity string, banned bool) error {
	if identity == "" {
		return fmt.Errorf("identity cannot be empty")
	}
	if banned {
		query := s.rebind(`INSERT INTO banned_identities (identity, banned_at) VALUES (?, ?) ON CONFLICT (identity) DO NOTHING`)
		_, err := s.db.ExecContext(ctx, query, identity, time.Now().UnixMilli())
		return err
	}
	query := s.rebind(`DELETE FROM banned_identities WHERE identity = ?`)
	_, err := s.db.ExecContext(ctx, query, identity)
	return err
}

// SetNodeAndIdentityBanned implements Store.
func (s *SQLStore) SetNodeAndIdentityBanned(ctx context.Context, peerID, identity string, banned bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, s.rebind(`UPDATE nodes SET banned = ? WHERE peer_id = ?`), banned, peerID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if identity != "" {
		if banned {
			_, err = tx.ExecContext(ctx, s.rebind(`INSERT INTO banned_identities (identity, banned_at) VALUES (?, ?) ON CONFLICT (identity) DO NOTHING`), identity, time.Now().UnixMilli())
		} else {
			_, err = tx.ExecContext(ctx, s.rebind(`DELETE FROM banned_identities WHERE identity = ?`), identity)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// IsIdentityBanned implements Store.
func (s *SQLStore) IsIdentityBanned(ctx context.Context, identity string) (bool, error) {
	query := s.rebind(`SELECT 1 FROM banned_identities WHERE identity = ?`)
	var one int
	err := s.db.QueryRowContext(ctx, query, identity).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// DeleteExpiredNodes implements Store.
func (s *SQLStore) DeleteExpiredNodes(ctx context.Context, before time.Time) (int64, error) {
	expired, args, err := nodeStateWhere(NodeExpired, before)
	if err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM nodes WHERE `+expired), args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListBannedPeerIDs implements Store.
func (s *SQLStore) ListBannedPeerIDs(ctx context.Context) ([]string, error) {
	query := s.rebind(`SELECT peer_id FROM nodes WHERE banned = ?`)
	rows, err := s.db.QueryContext(ctx, query, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var peerIDs []string
	for rows.Next() {
		var peerID string
		if err := rows.Scan(&peerID); err != nil {
			return nil, err
		}
		peerIDs = append(peerIDs, peerID)
	}
	return peerIDs, rows.Err()
}

// UpsertRouterLease implements Store.
func (s *SQLStore) UpsertRouterLease(ctx context.Context, lease *RouterLease) error {
	addrsBytes, err := json.Marshal(lease.Addresses)
	if err != nil {
		return err
	}
	peersBytes, err := json.Marshal(lease.ConnectedPeers)
	if err != nil {
		return err
	}

	const columns = `peer_id, multiaddresses, last_lease_renewal, expires_at, connected_peers, dht_size, connections, connection_limit`
	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO routers (` + columns + `)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (peer_id)
			DO UPDATE SET multiaddresses = EXCLUDED.multiaddresses, last_lease_renewal = EXCLUDED.last_lease_renewal, expires_at = EXCLUDED.expires_at, connected_peers = EXCLUDED.connected_peers, dht_size = EXCLUDED.dht_size, connections = EXCLUDED.connections, connection_limit = EXCLUDED.connection_limit`)
	} else {
		query = s.rebind(`
			INSERT INTO routers (` + columns + `)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (peer_id)
			DO UPDATE SET multiaddresses = excluded.multiaddresses, last_lease_renewal = excluded.last_lease_renewal, expires_at = excluded.expires_at, connected_peers = excluded.connected_peers, dht_size = excluded.dht_size, connections = excluded.connections, connection_limit = excluded.connection_limit`)
	}

	_, err = s.db.ExecContext(ctx, query, lease.PeerID, string(addrsBytes), lease.LastRenewal.UnixMilli(), lease.ExpiresAt.UnixMilli(), string(peersBytes), lease.DHTSize, lease.Connections, lease.ConnectionLimit)
	return err
}

// GetActiveRouters implements Store. The order is by peer ID, so the store
// reads the same to every replica and caller; the control plane shuffles the
// list it hands members (routerAddresses) so they spread across the routers.
func (s *SQLStore) GetActiveRouters(ctx context.Context) ([]RouterLease, error) {
	query := s.rebind(`SELECT peer_id, multiaddresses, last_lease_renewal, expires_at, connected_peers, dht_size, connections, connection_limit FROM routers WHERE expires_at > ? ORDER BY peer_id`)
	rows, err := s.db.QueryContext(ctx, query, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var leases []RouterLease
	for rows.Next() {
		var l RouterLease
		var addrsStr string
		var peersStr sql.NullString
		var dhtSize, connections, connectionLimit sql.NullInt64
		var lastRenewalUnix, expiresAtUnix int64
		if err := rows.Scan(&l.PeerID, &addrsStr, &lastRenewalUnix, &expiresAtUnix, &peersStr, &dhtSize, &connections, &connectionLimit); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(addrsStr), &l.Addresses); err != nil {
			return nil, err
		}
		if peersStr.Valid && peersStr.String != "" {
			if err := json.Unmarshal([]byte(peersStr.String), &l.ConnectedPeers); err != nil {
				return nil, err
			}
		}
		if dhtSize.Valid {
			l.DHTSize = int(dhtSize.Int64)
		}
		if connections.Valid {
			l.Connections = int(connections.Int64)
		}
		if connectionLimit.Valid {
			l.ConnectionLimit = int(connectionLimit.Int64)
		}
		l.LastRenewal = time.UnixMilli(lastRenewalUnix)
		l.ExpiresAt = time.UnixMilli(expiresAtUnix)
		leases = append(leases, l)
	}
	return leases, rows.Err()
}

// SaveMeshPolicy replaces the entire mesh policy with the provided roles and bindings.
func (s *SQLStore) SaveMeshPolicy(ctx context.Context, roles []*api.PolicyRole, bindings []*api.PolicyBinding) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		return s.saveMeshPolicyTx(ctx, tx, roles, bindings)
	})
}

// SavePolicyDocument replaces roles, bindings and egress destinations in one
// transaction, so a POST /policies is applied whole or not at all.
func (s *SQLStore) SavePolicyDocument(ctx context.Context, roles []*api.PolicyRole, bindings []*api.PolicyBinding, egress []*api.EgressDestination) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := s.saveMeshPolicyTx(ctx, tx, roles, bindings); err != nil {
			return err
		}
		return s.saveEgressDestinationsTx(ctx, tx, egress)
	})
}

// inTx runs fn in a transaction and commits when it returns nil.
func (s *SQLStore) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) saveMeshPolicyTx(ctx context.Context, tx *sql.Tx, roles []*api.PolicyRole, bindings []*api.PolicyBinding) error {
	// For simplicity in replacing policy, we clear all and insert new.
	if _, err := tx.ExecContext(ctx, "DELETE FROM role_permissions"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM role_bindings"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM roles"); err != nil {
		return err
	}

	for _, r := range roles {
		if r == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO roles (name, description, created_at) VALUES (?, '', ?)"), r.Name, time.Now().UnixMilli()); err != nil {
			return err
		}
		for _, target := range r.AllowedTargets {
			if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO role_permissions (role_name, resource_type, resource_value) VALUES (?, 'target', ?)"), r.Name, target); err != nil {
				return err
			}
		}
		for _, svc := range r.AllowedServices {
			if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO role_permissions (role_name, resource_type, resource_value) VALUES (?, 'service', ?)"), r.Name, svc); err != nil {
				return err
			}
		}
		for _, dl := range r.CustomDatalog {
			if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO role_permissions (role_name, resource_type, resource_value) VALUES (?, 'custom_datalog', ?)"), r.Name, dl); err != nil {
				return err
			}
		}
		for _, label := range r.AllowedLabels {
			if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO role_permissions (role_name, resource_type, resource_value) VALUES (?, 'label', ?)"), r.Name, label); err != nil {
				return err
			}
		}
		for _, svc := range r.AllowedPublish {
			if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO role_permissions (role_name, resource_type, resource_value) VALUES (?, 'publish', ?)"), r.Name, svc); err != nil {
				return err
			}
		}
		// One row per narrowed entry, as protojson: the shape is the proto's
		// and a new HTTPGrant field needs no schema change here.
		for _, g := range r.Http {
			if g == nil {
				continue
			}
			encoded, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(g)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO role_permissions (role_name, resource_type, resource_value) VALUES (?, 'http', ?)"), r.Name, string(encoded)); err != nil {
				return err
			}
		}
	}

	for _, b := range bindings {
		if b == nil {
			continue
		}
		for _, member := range b.Members {
			if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO role_bindings (role_name, member) VALUES (?, ?)"), b.Role, member); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetMeshPolicy retrieves the entire mesh policy as structured data, in an
// order that does not change between reads: the policy is rendered to text
// a member compares with the last text it fetched to tell a change.
func (s *SQLStore) GetMeshPolicy(ctx context.Context) ([]*api.PolicyRole, []*api.PolicyBinding, error) {
	rolesRows, err := s.db.QueryContext(ctx, s.rebind("SELECT name FROM roles ORDER BY name"))
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rolesRows.Close() }()

	rolesMap := make(map[string]*api.PolicyRole)
	var roles []*api.PolicyRole

	for rolesRows.Next() {
		var name string
		if err := rolesRows.Scan(&name); err != nil {
			return nil, nil, err
		}
		role := &api.PolicyRole{Name: name}
		rolesMap[name] = role
		roles = append(roles, role)
	}
	if err := rolesRows.Err(); err != nil {
		return nil, nil, err
	}

	permsRows, err := s.db.QueryContext(ctx, s.rebind("SELECT role_name, resource_type, resource_value FROM role_permissions ORDER BY role_name, resource_type, resource_value"))
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = permsRows.Close() }()

	for permsRows.Next() {
		var roleName, resType, resValue string
		if err := permsRows.Scan(&roleName, &resType, &resValue); err != nil {
			return nil, nil, err
		}
		if r, ok := rolesMap[roleName]; ok {
			switch resType {
			case "target":
				r.AllowedTargets = append(r.AllowedTargets, resValue)
			case "service":
				r.AllowedServices = append(r.AllowedServices, resValue)
			case "custom_datalog":
				r.CustomDatalog = append(r.CustomDatalog, resValue)
			case "label":
				r.AllowedLabels = append(r.AllowedLabels, resValue)
			case "publish":
				r.AllowedPublish = append(r.AllowedPublish, resValue)
			case "http":
				g := &api.HTTPGrant{}
				if err := protojson.Unmarshal([]byte(resValue), g); err != nil {
					return nil, nil, fmt.Errorf("role %s: stored http grant does not parse: %w", roleName, err)
				}
				r.Http = append(r.Http, g)
			}
		}
	}
	if err := permsRows.Err(); err != nil {
		return nil, nil, err
	}

	bindingsRows, err := s.db.QueryContext(ctx, s.rebind("SELECT role_name, member FROM role_bindings ORDER BY role_name, member"))
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = bindingsRows.Close() }()

	var bindings []*api.PolicyBinding
	for bindingsRows.Next() {
		var roleName, member string
		if err := bindingsRows.Scan(&roleName, &member); err != nil {
			return nil, nil, err
		}
		if n := len(bindings); n > 0 && bindings[n-1].Role == roleName {
			bindings[n-1].Members = append(bindings[n-1].Members, member)
			continue
		}
		bindings = append(bindings, &api.PolicyBinding{Role: roleName, Members: []string{member}})
	}
	if err := bindingsRows.Err(); err != nil {
		return nil, nil, err
	}

	return roles, bindings, nil
}

// SaveEgressDestinations replaces the egress section of the mesh policy.
func (s *SQLStore) SaveEgressDestinations(ctx context.Context, egress []*api.EgressDestination) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		return s.saveEgressDestinationsTx(ctx, tx, egress)
	})
}

func (s *SQLStore) saveEgressDestinationsTx(ctx context.Context, tx *sql.Tx, egress []*api.EgressDestination) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM egress_destinations"); err != nil {
		return err
	}
	marshaler := protojson.MarshalOptions{UseProtoNames: true}
	for _, d := range egress {
		if d == nil {
			continue
		}
		servedBy, err := json.Marshal(d.GetServedBy())
		if err != nil {
			return err
		}
		cfgBytes, err := marshaler.Marshal(d)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rebind("INSERT INTO egress_destinations (name, target_url, credential, served_by, config_json) VALUES (?, ?, ?, ?, ?)"),
			d.GetName(), d.GetTargetUrl(), d.GetCredential(), string(servedBy), string(cfgBytes)); err != nil {
			return err
		}
	}
	return nil
}

// GetEgressDestinations loads the egress section of the mesh policy, in name
// order so the rendered document and rules are stable.
func (s *SQLStore) GetEgressDestinations(ctx context.Context) ([]*api.EgressDestination, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind("SELECT name, target_url, credential, served_by, config_json FROM egress_destinations ORDER BY name"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	var egress []*api.EgressDestination
	for rows.Next() {
		var name, targetURL, credential, servedByJSON, configJSON string
		if err := rows.Scan(&name, &targetURL, &credential, &servedByJSON, &configJSON); err != nil {
			return nil, err
		}
		if strings.TrimSpace(configJSON) != "" {
			var dest api.EgressDestination
			if err := unmarshaler.Unmarshal([]byte(configJSON), &dest); err != nil {
				return nil, fmt.Errorf("egress %s: stored config_json does not parse: %w", name, err)
			}
			egress = append(egress, &dest)
			continue
		}
		var servedBy []string
		if err := json.Unmarshal([]byte(servedByJSON), &servedBy); err != nil {
			return nil, fmt.Errorf("egress %s: stored served_by does not parse: %w", name, err)
		}
		egress = append(egress, &api.EgressDestination{Name: name, TargetUrl: targetURL, Credential: credential, ServedBy: servedBy})
	}
	return egress, rows.Err()
}

// SaveBootstrapToken persists a new bootstrap token.
func (s *SQLStore) SaveBootstrapToken(ctx context.Context, token *BootstrapToken) error {
	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO bootstrap_tokens (id, token_hash, role, owner_id, max_usages, usages_count, description, created_at, expires_at, autonomous_recovery)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO NOTHING`)
	} else {
		query = s.rebind(`
			INSERT INTO bootstrap_tokens (id, token_hash, role, owner_id, max_usages, usages_count, description, created_at, expires_at, autonomous_recovery)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO NOTHING`)
	}
	ownerIDNull := sql.NullString{String: token.OwnerID, Valid: token.OwnerID != ""}
	_, err := s.db.ExecContext(ctx, query,
		token.ID,
		token.TokenHash,
		token.Role,
		ownerIDNull,
		token.MaxUsages,
		token.UsagesCount,
		token.Description,
		token.CreatedAt.UnixMilli(),
		token.ExpiresAt.UnixMilli(),
		token.AutonomousRecovery,
	)
	return err
}

// GetBootstrapToken retrieves a bootstrap token by its ID (sha256 hash).
func (s *SQLStore) GetBootstrapToken(ctx context.Context, id string) (*BootstrapToken, error) {
	query := s.rebind(`SELECT id, token_hash, role, owner_id, max_usages, usages_count, description, created_at, expires_at, revoked_at, autonomous_recovery FROM bootstrap_tokens WHERE id = ?`)
	var t BootstrapToken
	var created, expires int64
	var ownerID sql.NullString
	var revokedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&t.ID,
		&t.TokenHash,
		&t.Role,
		&ownerID,
		&t.MaxUsages,
		&t.UsagesCount,
		&t.Description,
		&created,
		&expires,
		&revokedAt,
		&t.AutonomousRecovery,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if ownerID.Valid {
		t.OwnerID = ownerID.String
	}
	t.CreatedAt = time.UnixMilli(created)
	t.ExpiresAt = time.UnixMilli(expires)
	if revokedAt.Valid {
		rt := time.UnixMilli(revokedAt.Int64)
		t.RevokedAt = &rt
	}
	return &t, nil
}

// ConsumeBootstrapTokenUsage implements Store. The validity conditions live
// in the WHERE clause so the check and the increment are one statement.
func (s *SQLStore) ConsumeBootstrapTokenUsage(ctx context.Context, id string, now time.Time) error {
	query := `UPDATE bootstrap_tokens SET usages_count = usages_count + 1
		WHERE id = ? AND usages_count < max_usages AND revoked_at IS NULL AND expires_at > ?`
	res, err := s.db.ExecContext(ctx, s.rebind(query), id, now.UnixMilli())
	if err != nil {
		return fmt.Errorf("failed to consume token usage: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to consume token usage: %w", err)
	}
	if n == 0 {
		return ErrBootstrapTokenUnusable
	}
	return nil
}

// RevokeBootstrapToken soft-revokes a token: see the Store interface comment
// for why this doesn't delete the row. The WHERE clause makes a repeat call
// a no-op rather than clobbering the original revocation time.
func (s *SQLStore) RevokeBootstrapToken(ctx context.Context, id string) error {
	query := `UPDATE bootstrap_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`
	_, err := s.db.ExecContext(ctx, s.rebind(query), time.Now().UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("failed to revoke bootstrap token: %w", err)
	}
	return nil
}

// CreateEnrollmentRequest saves a new pending request.
func (s *SQLStore) CreateEnrollmentRequest(ctx context.Context, req *EnrollmentRequest) error {
	labelsJSON, err := json.Marshal(req.Labels)
	if err != nil {
		return fmt.Errorf("failed to marshal labels: %w", err)
	}
	query := `INSERT INTO enrollment_requests (id, peer_id, public_key, token_id, status, labels_json, biscuit_token, created_at, resolved_at, resolved_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	var resAt sql.NullInt64
	if req.ResolvedAt != nil {
		resAt = sql.NullInt64{Int64: req.ResolvedAt.UnixMilli(), Valid: true}
	}
	_, err = s.db.ExecContext(ctx, s.rebind(query),
		req.ID,
		req.PeerID,
		req.PublicKey,
		req.TokenID,
		int(req.Status),
		string(labelsJSON),
		req.BiscuitToken,
		req.CreatedAt.UnixMilli(),
		resAt,
		req.ResolvedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create enrollment request: %w", err)
	}
	return nil
}

// GetEnrollmentRequest retrieves request by PeerID.
func (s *SQLStore) GetEnrollmentRequest(ctx context.Context, peerID string) (*EnrollmentRequest, error) {
	query := `SELECT id, peer_id, public_key, token_id, status, labels_json, biscuit_token, created_at, resolved_at, resolved_by 
		FROM enrollment_requests WHERE peer_id = ?`
	return s.scanEnrollmentRequest(s.db.QueryRowContext(ctx, s.rebind(query), peerID))
}

// GetEnrollmentRequestByID retrieves request by UUID.
func (s *SQLStore) GetEnrollmentRequestByID(ctx context.Context, id string) (*EnrollmentRequest, error) {
	query := `SELECT id, peer_id, public_key, token_id, status, labels_json, biscuit_token, created_at, resolved_at, resolved_by 
		FROM enrollment_requests WHERE id = ?`
	return s.scanEnrollmentRequest(s.db.QueryRowContext(ctx, s.rebind(query), id))
}

type scannable interface {
	Scan(dest ...any) error
}

func (s *SQLStore) scanEnrollmentRequest(row scannable) (*EnrollmentRequest, error) {
	var created int64
	var resAt sql.NullInt64
	var statusVal int
	var labelsJSON sql.NullString
	var req EnrollmentRequest

	err := row.Scan(
		&req.ID,
		&req.PeerID,
		&req.PublicKey,
		&req.TokenID,
		&statusVal,
		&labelsJSON,
		&req.BiscuitToken,
		&created,
		&resAt,
		&req.ResolvedBy,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("failed to scan enrollment request: %w", err)
	}
	if labelsJSON.Valid && labelsJSON.String != "" {
		if err := json.Unmarshal([]byte(labelsJSON.String), &req.Labels); err != nil {
			return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
		}
	}

	req.CreatedAt = time.UnixMilli(created)
	req.Status = api.EnrollmentStatus(statusVal)
	if resAt.Valid {
		t := time.UnixMilli(resAt.Int64)
		req.ResolvedAt = &t
	}

	pubCopy := make([]byte, len(req.PublicKey))
	copy(pubCopy, req.PublicKey)
	req.PublicKey = pubCopy

	biscuitCopy := make([]byte, len(req.BiscuitToken))
	copy(biscuitCopy, req.BiscuitToken)
	req.BiscuitToken = biscuitCopy

	return &req, nil
}

// ListEnrollmentRequests retrieves all requests.
func (s *SQLStore) ListEnrollmentRequests(ctx context.Context) ([]EnrollmentRequest, error) {
	query := `SELECT id, peer_id, public_key, token_id, status, labels_json, biscuit_token, created_at, resolved_at, resolved_by 
		FROM enrollment_requests ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, s.rebind(query))
	if err != nil {
		return nil, fmt.Errorf("failed to query enrollment requests: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var reqs []EnrollmentRequest
	for rows.Next() {
		req, err := s.scanEnrollmentRequest(rows)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, *req)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return reqs, nil
}

// UpdateEnrollmentRequest updates status, timestamp and biscuit token.
func (s *SQLStore) UpdateEnrollmentRequest(ctx context.Context, id string, status api.EnrollmentStatus, biscuit []byte, resolvedBy string) error {
	query := `UPDATE enrollment_requests SET status = ?, biscuit_token = ?, resolved_at = ?, resolved_by = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, s.rebind(query),
		int(status),
		biscuit,
		time.Now().UnixMilli(),
		resolvedBy,
		id,
	)
	if err != nil {
		return fmt.Errorf("failed to update enrollment request: %w", err)
	}
	return nil
}

// ResolveEnrollmentRequest implements Store.
func (s *SQLStore) ResolveEnrollmentRequest(ctx context.Context, id string, status api.EnrollmentStatus, biscuit []byte, resolvedBy string) error {
	query := `UPDATE enrollment_requests SET status = ?, biscuit_token = ?, resolved_at = ?, resolved_by = ?
		WHERE id = ? AND status = ?`
	res, err := s.db.ExecContext(ctx, s.rebind(query),
		int(status),
		biscuit,
		time.Now().UnixMilli(),
		resolvedBy,
		id,
		int(api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING),
	)
	if err != nil {
		return fmt.Errorf("failed to resolve enrollment request: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to resolve enrollment request: %w", err)
	}
	if n == 0 {
		return ErrEnrollmentAlreadyResolved
	}
	return nil
}

// ListNodes implements Store.
func (s *SQLStore) ListNodes(ctx context.Context, filter NodeFilter) ([]EnrolledNode, error) {
	where, args, err := nodeFilterWhere(filter)
	if err != nil {
		return nil, err
	}
	// Neither blob is read: a list is a view of the rows, and the biscuit is
	// a 2 KB column per row that only GetNode's single-row callers need.
	query := `SELECT peer_id, role, enrollment_type, claims_json, owner_id, labels_json, enrolled_at, expires_at, banned, autonomous_recovery FROM nodes` + where + ` ORDER BY enrolled_at DESC, peer_id DESC`
	if filter.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, filter.Limit)
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var nodes []EnrolledNode
	for rows.Next() {
		var node EnrolledNode
		var claimsJSON, ownerID, labelsJSON sql.NullString
		var enrolledAtUnix, expiresAtUnix int64
		err := rows.Scan(
			&node.PeerID,
			&node.Role,
			&node.EnrollmentType,
			&claimsJSON,
			&ownerID,
			&labelsJSON,
			&enrolledAtUnix,
			&expiresAtUnix,
			&node.Banned,
			&node.AutonomousRecovery,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan enrolled node: %w", err)
		}
		if claimsJSON.Valid {
			node.ClaimsJSON = claimsJSON.String
		}
		if ownerID.Valid {
			node.OwnerID = ownerID.String
		}
		if labelsJSON.Valid && labelsJSON.String != "" {
			if err := json.Unmarshal([]byte(labelsJSON.String), &node.Labels); err != nil {
				return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
			}
		}
		node.EnrolledAt = time.UnixMilli(enrolledAtUnix)
		node.ExpiresAt = time.UnixMilli(expiresAtUnix)
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

// nodeFilterWhere renders filter as a WHERE clause, empty for the zero filter.
func nodeFilterWhere(filter NodeFilter) (string, []any, error) {
	var conds []string
	var args []any
	if len(filter.States) > 0 {
		now := filter.Now
		if now.IsZero() {
			now = time.Now()
		}
		arms := make([]string, 0, len(filter.States))
		for _, state := range filter.States {
			arm, armArgs, err := nodeStateWhere(state, now)
			if err != nil {
				return "", nil, err
			}
			arms = append(arms, arm)
			args = append(args, armArgs...)
		}
		conds = append(conds, "("+strings.Join(arms, " OR ")+")")
	}
	if filter.OwnerID != nil {
		conds = append(conds, "owner_id = ?")
		args = append(args, *filter.OwnerID)
	}
	if filter.Role != "" {
		conds = append(conds, "role = ?")
		args = append(args, filter.Role)
	}
	if filter.After != nil {
		at := filter.After.EnrolledAt.UnixMilli()
		conds = append(conds, "enrolled_at <= ? AND (enrolled_at < ? OR peer_id < ?)")
		args = append(args, at, at, filter.After.PeerID)
	}
	if len(conds) == 0 {
		return "", nil, nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args, nil
}

// nodeStateWhere is CheckAdmission in SQL. A zero ExpiresAt round-trips as a
// negative UnixMilli, so it never expires. Each arm leads with banned so it
// can search the (banned, expires_at) index.
func nodeStateWhere(state NodeState, now time.Time) (string, []any, error) {
	ms := now.UnixMilli()
	switch state {
	case NodeBanned:
		return "banned = ?", []any{true}, nil
	case NodeExpired:
		return "(banned = ? AND expires_at > 0 AND expires_at < ?)", []any{false, ms}, nil
	case NodeAdmitted:
		// Parenthesised like the other arms, so a caller may AND it with more.
		return "((banned = ? AND expires_at <= 0) OR (banned = ? AND expires_at >= ?))", []any{false, false, ms}, nil
	}
	return "", nil, fmt.Errorf("unknown node state %q", state)
}

// CountNodes implements Store. The CASE tests a ban first, as CheckAdmission does.
func (s *SQLStore) CountNodes(ctx context.Context, now time.Time) ([]NodeCount, error) {
	banned, args, err := nodeStateWhere(NodeBanned, now)
	if err != nil {
		return nil, err
	}
	expired, expiredArgs, err := nodeStateWhere(NodeExpired, now)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf(`SELECT role, CASE WHEN %s THEN '%s' WHEN %s THEN '%s' ELSE '%s' END, COUNT(*) FROM nodes GROUP BY 1, 2`,
		banned, NodeBanned, expired, NodeExpired, NodeAdmitted)
	rows, err := s.db.QueryContext(ctx, s.rebind(query), append(args, expiredArgs...)...)
	if err != nil {
		return nil, fmt.Errorf("failed to count nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var counts []NodeCount
	for rows.Next() {
		var c NodeCount
		if err := rows.Scan(&c.Role, &c.State, &c.Count); err != nil {
			return nil, fmt.Errorf("failed to scan node count: %w", err)
		}
		counts = append(counts, c)
	}
	return counts, rows.Err()
}

// ListBootstrapTokens retrieves all bootstrap tokens.
func (s *SQLStore) ListBootstrapTokens(ctx context.Context) ([]BootstrapToken, error) {
	query := s.rebind(`SELECT id, token_hash, role, owner_id, max_usages, usages_count, description, created_at, expires_at, revoked_at, autonomous_recovery FROM bootstrap_tokens ORDER BY created_at DESC`)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query bootstrap tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []BootstrapToken
	for rows.Next() {
		var t BootstrapToken
		var desc sql.NullString
		var ownerID sql.NullString
		var created, expires int64
		var revokedAt sql.NullInt64
		err := rows.Scan(
			&t.ID,
			&t.TokenHash,
			&t.Role,
			&ownerID,
			&t.MaxUsages,
			&t.UsagesCount,
			&desc,
			&created,
			&expires,
			&revokedAt,
			&t.AutonomousRecovery,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan bootstrap token: %w", err)
		}
		if desc.Valid {
			t.Description = desc.String
		}
		if ownerID.Valid {
			t.OwnerID = ownerID.String
		}
		t.CreatedAt = time.UnixMilli(created)
		t.ExpiresAt = time.UnixMilli(expires)
		if revokedAt.Valid {
			rt := time.UnixMilli(revokedAt.Int64)
			t.RevokedAt = &rt
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

// SaveUser creates or updates a user.
func (s *SQLStore) SaveUser(ctx context.Context, user *User) error {
	var query string
	if s.isPostgres() {
		query = s.rebind(`
			INSERT INTO users (id, issuer, email, role, created_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET issuer = EXCLUDED.issuer, email = EXCLUDED.email, role = EXCLUDED.role`)
	} else {
		query = s.rebind(`
			INSERT INTO users (id, issuer, email, role, created_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET issuer = excluded.issuer, email = excluded.email, role = excluded.role`)
	}

	_, err := s.db.ExecContext(ctx, query,
		user.ID,
		user.Issuer,
		user.Email,
		user.Role,
		user.CreatedAt.UnixMilli(),
	)
	return err
}

// GetUser retrieves a user by ID.
func (s *SQLStore) GetUser(ctx context.Context, id string) (*User, error) {
	query := s.rebind(`SELECT id, issuer, email, role, created_at FROM users WHERE id = ?`)
	var user User
	var created int64
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Issuer,
		&user.Email,
		&user.Role,
		&created,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	user.CreatedAt = time.UnixMilli(created)
	return &user, nil
}

// ListUsers retrieves all registered users.
func (s *SQLStore) ListUsers(ctx context.Context) ([]User, error) {
	query := `SELECT id, issuer, email, role, created_at FROM users`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var user User
		var created int64
		if err := rows.Scan(
			&user.ID,
			&user.Issuer,
			&user.Email,
			&user.Role,
			&created,
		); err != nil {
			return nil, err
		}
		user.CreatedAt = time.UnixMilli(created)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// GetCurrentOIDCKey implements Store.
func (s *SQLStore) GetCurrentOIDCKey(ctx context.Context) (*OIDCKeyPair, error) {
	query := s.rebind(`SELECT kid, private_key, public_key FROM oidc_keyring WHERE expiration IS NULL ORDER BY id DESC LIMIT 1`)
	var kid string
	var privBytes, pubBytes []byte
	err := s.db.QueryRowContext(ctx, query).Scan(&kid, &privBytes, &pubBytes)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &OIDCKeyPair{
		Kid:        kid,
		PrivateKey: privBytes,
		PublicKey:  pubBytes,
	}, nil
}

// GetAllValidOIDCKeys implements Store.
func (s *SQLStore) GetAllValidOIDCKeys(ctx context.Context) ([]OIDCKeyPair, error) {
	query := s.rebind(`SELECT kid, private_key, public_key, expiration FROM oidc_keyring WHERE expiration IS NULL OR expiration > ? ORDER BY id DESC`)
	rows, err := s.db.QueryContext(ctx, query, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var keys []OIDCKeyPair
	for rows.Next() {
		var kid string
		var priv, pub []byte
		var exp sql.NullInt64
		if err := rows.Scan(&kid, &priv, &pub, &exp); err != nil {
			return nil, err
		}
		var expiration time.Time
		if exp.Valid {
			expiration = time.UnixMilli(exp.Int64)
		}
		privCopy := make([]byte, len(priv))
		copy(privCopy, priv)
		pubCopy := make([]byte, len(pub))
		copy(pubCopy, pub)
		keys = append(keys, OIDCKeyPair{
			Kid:        kid,
			PrivateKey: privCopy,
			PublicKey:  pubCopy,
			Expiration: expiration,
		})
	}
	return keys, rows.Err()
}

// SaveInitialOIDCKey implements Store.
func (s *SQLStore) SaveInitialOIDCKey(ctx context.Context, kid string, priv, pub []byte) error {
	var query string
	if s.isPostgres() {
		query = s.rebind(`INSERT INTO oidc_keyring (kid, private_key, public_key, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (kid) DO NOTHING`)
	} else {
		query = s.rebind(`INSERT OR IGNORE INTO oidc_keyring (kid, private_key, public_key, created_at) VALUES (?, ?, ?, ?)`)
	}
	_, err := s.db.ExecContext(ctx, query, kid, priv, pub, time.Now().UnixMilli())
	return err
}

// RotateOIDCKeys implements Store.
func (s *SQLStore) RotateOIDCKeys(ctx context.Context, kid string, newPriv, newPub []byte, gracePeriod time.Duration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	if gracePeriod > 0 {
		expireTime := now.Add(gracePeriod)
		updateQuery := s.rebind(`UPDATE oidc_keyring SET expiration = ? WHERE expiration IS NULL`)
		if _, err := tx.ExecContext(ctx, updateQuery, expireTime.UnixMilli()); err != nil {
			return err
		}
	} else {
		deleteActiveQuery := s.rebind(`DELETE FROM oidc_keyring WHERE expiration IS NULL`)
		if _, err := tx.ExecContext(ctx, deleteActiveQuery); err != nil {
			return err
		}
	}

	insertQuery := s.rebind(`INSERT INTO oidc_keyring (kid, private_key, public_key, created_at) VALUES (?, ?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, insertQuery, kid, newPriv, newPub, now.UnixMilli()); err != nil {
		return err
	}

	deleteQuery := s.rebind(`DELETE FROM oidc_keyring WHERE expiration IS NOT NULL AND expiration <= ?`)
	if _, err := tx.ExecContext(ctx, deleteQuery, now.UnixMilli()); err != nil {
		return err
	}

	return tx.Commit()
}

// SaveRevokedBiscuit implements Store.
func (s *SQLStore) SaveRevokedBiscuit(ctx context.Context, revocationID string, expiresAt time.Time) error {
	if revocationID == "" {
		return nil
	}
	var query string
	if s.isPostgres() {
		query = s.rebind(`INSERT INTO revoked_biscuits (revocation_id, expires_at) VALUES (?, ?) ON CONFLICT (revocation_id) DO UPDATE SET expires_at = EXCLUDED.expires_at`)
	} else {
		query = s.rebind(`INSERT INTO revoked_biscuits (revocation_id, expires_at) VALUES (?, ?) ON CONFLICT (revocation_id) DO UPDATE SET expires_at = excluded.expires_at`)
	}
	_, err := s.db.ExecContext(ctx, query, revocationID, expiresAt.UnixMilli())
	return err
}

// ListRevokedBiscuits implements Store.
func (s *SQLStore) ListRevokedBiscuits(ctx context.Context, now time.Time) (map[string]time.Time, error) {
	nowMs := now.UnixMilli()
	pruneQuery := s.rebind(`DELETE FROM revoked_biscuits WHERE expires_at <= ?`)
	_, _ = s.db.ExecContext(ctx, pruneQuery, nowMs)

	query := s.rebind(`SELECT revocation_id, expires_at FROM revoked_biscuits WHERE expires_at > ?`)
	rows, err := s.db.QueryContext(ctx, query, nowMs)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	res := make(map[string]time.Time)
	for rows.Next() {
		var revID string
		var expMs int64
		if err := rows.Scan(&revID, &expMs); err != nil {
			return nil, err
		}
		res[revID] = time.UnixMilli(expMs)
	}
	return res, rows.Err()
}

// IsBiscuitRevoked implements Store.
func (s *SQLStore) IsBiscuitRevoked(ctx context.Context, revocationID string, now time.Time) (bool, error) {
	if revocationID == "" {
		return false, nil
	}
	query := s.rebind(`SELECT 1 FROM revoked_biscuits WHERE revocation_id = ? AND expires_at > ? LIMIT 1`)
	var one int
	err := s.db.QueryRowContext(ctx, query, revocationID, now.UnixMilli()).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Ping implements Store.
func (s *SQLStore) Ping(ctx context.Context) error {
	if s.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	return s.db.PingContext(ctx)
}

// Close implements Store.
func (s *SQLStore) Close() error {
	return s.db.Close()
}
