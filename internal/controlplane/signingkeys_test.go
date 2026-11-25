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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/storage"
	"google.golang.org/protobuf/proto"
)

// pemPKCS8 encodes a private key as one "PRIVATE KEY" block.
func pemPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return priv
}

func writeKeyFile(t *testing.T, blocks ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing-keys.pem")
	var data []byte
	for _, b := range blocks {
		data = append(data, b...)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadOperatorSigningKeys(t *testing.T) {
	edA, edB := newEd25519(t), newEd25519(t)
	ecA := newP256(t)

	t.Run("pkcs8 ed25519 and p256 in file order", func(t *testing.T) {
		path := writeKeyFile(t, pemPKCS8(t, edA), pemPKCS8(t, ecA), pemPKCS8(t, edB))
		keys, err := loadOperatorSigningKeys(path)
		if err != nil {
			t.Fatalf("loadOperatorSigningKeys: %v", err)
		}
		if len(keys.ed25519) != 2 || !keys.ed25519[0].Equal(edA) || !keys.ed25519[1].Equal(edB) {
			t.Fatalf("ed25519 keys = %d in wrong order, want [A B]", len(keys.ed25519))
		}
		if len(keys.es256) != 1 || !keys.es256[0].Equal(ecA) {
			t.Fatalf("es256 keys = %d, want [A]", len(keys.es256))
		}
	})

	t.Run("sec1 ec block", func(t *testing.T) {
		der, err := x509.MarshalECPrivateKey(ecA)
		if err != nil {
			t.Fatalf("MarshalECPrivateKey: %v", err)
		}
		path := writeKeyFile(t, pemPKCS8(t, edA), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		keys, err := loadOperatorSigningKeys(path)
		if err != nil {
			t.Fatalf("loadOperatorSigningKeys: %v", err)
		}
		if len(keys.es256) != 1 || !keys.es256[0].Equal(ecA) {
			t.Fatalf("es256 keys = %d, want the SEC 1 key", len(keys.es256))
		}
	})

	t.Run("rsa is refused", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		_, err = loadOperatorSigningKeys(writeKeyFile(t, pemPKCS8(t, rsaKey)))
		if err == nil || !strings.Contains(err.Error(), "unsupported key type") {
			t.Fatalf("err = %v, want unsupported key type", err)
		}
	})

	t.Run("other curve is refused", func(t *testing.T) {
		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		_, err = loadOperatorSigningKeys(writeKeyFile(t, pemPKCS8(t, p384)))
		if err == nil || !strings.Contains(err.Error(), "want P-256") {
			t.Fatalf("err = %v, want an error naming P-256 as the only accepted curve", err)
		}
	})

	t.Run("certificate block is refused", func(t *testing.T) {
		_, err := loadOperatorSigningKeys(writeKeyFile(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})))
		if err == nil || !strings.Contains(err.Error(), "unsupported PEM block") {
			t.Fatalf("err = %v, want unsupported PEM block", err)
		}
	})

	// pem.Decode skips a block whose body does not decode and returns the
	// next one; the file must be refused, not loaded with the next key
	// signing in place of the damaged one.
	t.Run("damaged block is refused", func(t *testing.T) {
		damaged := pemPKCS8(t, edA)
		damaged[strings.IndexByte(string(damaged), '\n')+5] = '*'
		keys, err := loadOperatorSigningKeys(writeKeyFile(t, damaged, pemPKCS8(t, edB), pemPKCS8(t, ecA)))
		if err == nil {
			t.Fatalf("loadOperatorSigningKeys loaded %d Ed25519 key(s) from a file whose first block is damaged, want a refusal", len(keys.ed25519))
		}
		if !strings.Contains(err.Error(), "do not decode") {
			t.Fatalf("err = %v, want a refusal naming the blocks that do not decode", err)
		}
	})

	t.Run("damaged BEGIN line is refused", func(t *testing.T) {
		damaged := pemPKCS8(t, edA)[1:] // "----BEGIN PRIVATE KEY-----"
		keys, err := loadOperatorSigningKeys(writeKeyFile(t, damaged, pemPKCS8(t, edB), pemPKCS8(t, ecA)))
		if err == nil {
			t.Fatalf("loadOperatorSigningKeys loaded %d Ed25519 key(s) from a file whose first BEGIN line is damaged, want a refusal", len(keys.ed25519))
		}
		if !strings.Contains(err.Error(), "do not decode") {
			t.Fatalf("err = %v, want a refusal naming the blocks that do not decode", err)
		}
	})

	t.Run("truncated block is refused", func(t *testing.T) {
		whole := pemPKCS8(t, edB)
		_, err := loadOperatorSigningKeys(writeKeyFile(t, pemPKCS8(t, edA), pemPKCS8(t, ecA), whole[:len(whole)/2]))
		if err == nil || !strings.Contains(err.Error(), "do not decode") {
			t.Fatalf("err = %v, want a refusal naming the blocks that do not decode", err)
		}
	})

	t.Run("empty file is refused", func(t *testing.T) {
		_, err := loadOperatorSigningKeys(writeKeyFile(t, []byte("not pem at all\n")))
		if err == nil || !strings.Contains(err.Error(), "no Ed25519 key") {
			t.Fatalf("err = %v, want a refusal naming the missing Ed25519 key", err)
		}
	})

	t.Run("one kind only is refused", func(t *testing.T) {
		_, err := loadOperatorSigningKeys(writeKeyFile(t, pemPKCS8(t, edA)))
		if err == nil || !strings.Contains(err.Error(), "no P-256 key") {
			t.Fatalf("err = %v, want a refusal naming the missing P-256 key", err)
		}
		_, err = loadOperatorSigningKeys(writeKeyFile(t, pemPKCS8(t, ecA)))
		if err == nil || !strings.Contains(err.Error(), "no Ed25519 key") {
			t.Fatalf("err = %v, want a refusal naming the missing Ed25519 key", err)
		}
	})

	t.Run("missing file is refused", func(t *testing.T) {
		if _, err := loadOperatorSigningKeys(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
			t.Fatal("loadOperatorSigningKeys on a missing file returned nil")
		}
	})
}

func TestReconcileEd25519Keyring(t *testing.T) {
	ctx := context.Background()
	newStore := func(t *testing.T) storage.Store {
		t.Helper()
		store, err := storage.NewSQLStore("sqlite", ":memory:")
		if err != nil {
			t.Fatalf("NewSQLStore: %v", err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	pubOf := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	validPubs := func(t *testing.T, store storage.Store) map[string]bool {
		t.Helper()
		valid, err := store.GetAllValidKeys(ctx)
		if err != nil {
			t.Fatalf("GetAllValidKeys: %v", err)
		}
		out := map[string]bool{}
		for _, k := range valid {
			out[string(k.Public)] = true
		}
		return out
	}
	current, previous := newEd25519(t), newEd25519(t)

	t.Run("empty store: first key current, rest valid", func(t *testing.T) {
		store := newStore(t)
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current, previous}, time.Hour); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		_, gotPub, err := store.GetCurrentKey(ctx)
		if err != nil {
			t.Fatalf("GetCurrentKey: %v", err)
		}
		if !gotPub.Equal(pubOf(current)) {
			t.Fatalf("current key = %s, want %s (first in file)", keyFingerprint(gotPub), keyFingerprint(pubOf(current)))
		}
		valid := validPubs(t, store)
		if len(valid) != 2 || !valid[string(pubOf(current))] || !valid[string(pubOf(previous))] {
			t.Fatalf("valid keys = %d, want both file keys", len(valid))
		}
	})

	t.Run("matching store is left alone", func(t *testing.T) {
		store := newStore(t)
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current}, time.Hour); err != nil {
			t.Fatalf("first reconcile: %v", err)
		}
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current}, time.Hour); err != nil {
			t.Fatalf("second reconcile: %v", err)
		}
		if valid := validPubs(t, store); len(valid) != 1 {
			t.Fatalf("valid keys = %d after a no-op reconcile, want 1", len(valid))
		}
	})

	t.Run("generated key stays valid for the grace period", func(t *testing.T) {
		store := newStore(t)
		generated := newEd25519(t)
		if err := store.SaveInitialKey(ctx, generated, pubOf(generated)); err != nil {
			t.Fatalf("SaveInitialKey: %v", err)
		}
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current}, time.Hour); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		_, gotPub, err := store.GetCurrentKey(ctx)
		if err != nil {
			t.Fatalf("GetCurrentKey: %v", err)
		}
		if !gotPub.Equal(pubOf(current)) {
			t.Fatalf("current key = %s, want %s (the operator key)", keyFingerprint(gotPub), keyFingerprint(pubOf(current)))
		}
		valid := validPubs(t, store)
		if !valid[string(pubOf(generated))] {
			t.Fatal("the key the control plane generated before the operator took over is no longer valid; credentials it signed would break at once")
		}
	})

	t.Run("rollback: previous key moved back to the front", func(t *testing.T) {
		store := newStore(t)
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current, previous}, time.Hour); err != nil {
			t.Fatalf("reconcile [current previous]: %v", err)
		}
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{previous, current}, time.Hour); err != nil {
			t.Fatalf("reconcile [previous current]: %v", err)
		}
		_, gotPub, err := store.GetCurrentKey(ctx)
		if err != nil {
			t.Fatalf("GetCurrentKey: %v", err)
		}
		if !gotPub.Equal(pubOf(previous)) {
			t.Fatalf("current key = %s, want %s (moved back to the front)", keyFingerprint(gotPub), keyFingerprint(pubOf(previous)))
		}
		if valid := validPubs(t, store); len(valid) != 2 {
			t.Fatalf("valid keys = %d after the rollback, want 2", len(valid))
		}
	})

	t.Run("persistent store: restart after the grace period", func(t *testing.T) {
		// The store outlives the control plane (SQLite file, PostgreSQL). The
		// operator published [current previous], the previous key was dropped
		// from the file, its grace period ran out, and the control plane
		// restarts on a file that lists it again as verifying: the expired
		// row must not stop the start.
		dbPath := filepath.Join(t.TempDir(), "cp.db")
		store, err := storage.NewSQLStore("sqlite", dbPath)
		if err != nil {
			t.Fatalf("NewSQLStore: %v", err)
		}
		const grace = 20 * time.Millisecond
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current, previous}, grace); err != nil {
			t.Fatalf("reconcile v1: %v", err)
		}
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current}, grace); err != nil {
			t.Fatalf("reconcile drop: %v", err)
		}
		time.Sleep(2 * grace)
		if valid := validPubs(t, store); valid[string(pubOf(previous))] {
			t.Fatal("dropped key still valid after its grace period")
		}
		if err := store.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		store, err = storage.NewSQLStore("sqlite", dbPath)
		if err != nil {
			t.Fatalf("NewSQLStore (restart): %v", err)
		}
		defer func() { _ = store.Close() }()
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current, previous}, grace); err != nil {
			t.Fatalf("reconcile after restart with an expired row of a listed key: %v", err)
		}
		valid := validPubs(t, store)
		if len(valid) != 2 || !valid[string(pubOf(previous))] {
			t.Fatalf("valid keys = %d after restart, want both listed keys", len(valid))
		}
		_, gotPub, err := store.GetCurrentKey(ctx)
		if err != nil {
			t.Fatalf("GetCurrentKey: %v", err)
		}
		if !gotPub.Equal(pubOf(current)) {
			t.Fatalf("current key = %s, want %s", keyFingerprint(gotPub), keyFingerprint(pubOf(current)))
		}
	})

	t.Run("operator rotation: new key first, previous kept", func(t *testing.T) {
		store := newStore(t)
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{previous}, time.Hour); err != nil {
			t.Fatalf("reconcile v1: %v", err)
		}
		if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{current, previous}, time.Hour); err != nil {
			t.Fatalf("reconcile v2: %v", err)
		}
		_, gotPub, err := store.GetCurrentKey(ctx)
		if err != nil {
			t.Fatalf("GetCurrentKey: %v", err)
		}
		if !gotPub.Equal(pubOf(current)) {
			t.Fatalf("current key = %s after rotation, want %s (the new first key)", keyFingerprint(gotPub), keyFingerprint(pubOf(current)))
		}
		if valid := validPubs(t, store); len(valid) != 2 || !valid[string(pubOf(previous))] {
			t.Fatalf("valid keys = %d, want the previous key still valid", len(valid))
		}
	})
}

func TestReconcileES256Keyring(t *testing.T) {
	ctx := context.Background()
	store, err := storage.NewSQLStore("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	kidOf := func(t *testing.T, k *ecdsa.PrivateKey) string {
		t.Helper()
		pub, err := k.PublicKey.Bytes()
		if err != nil {
			t.Fatalf("PublicKey.Bytes: %v", err)
		}
		return es256Kid(pub)
	}
	v1, v2 := newP256(t), newP256(t)

	if err := reconcileES256Keyring(ctx, store, []*ecdsa.PrivateKey{v1}, time.Hour); err != nil {
		t.Fatalf("reconcile v1: %v", err)
	}
	cur, err := store.GetCurrentOIDCKey(ctx)
	if err != nil || cur == nil {
		t.Fatalf("GetCurrentOIDCKey: %v (%v)", err, cur)
	}
	if cur.Kid != kidOf(t, v1) {
		t.Fatalf("current kid = %s, want %s", cur.Kid, kidOf(t, v1))
	}
	if err := reconcileES256Keyring(ctx, store, []*ecdsa.PrivateKey{v2, v1}, time.Hour); err != nil {
		t.Fatalf("reconcile v2: %v", err)
	}
	cur, err = store.GetCurrentOIDCKey(ctx)
	if err != nil || cur == nil {
		t.Fatalf("GetCurrentOIDCKey: %v (%v)", err, cur)
	}
	if cur.Kid != kidOf(t, v2) {
		t.Fatalf("current kid after rotation = %s, want %s", cur.Kid, kidOf(t, v2))
	}
	all, err := store.GetAllValidOIDCKeys(ctx)
	if err != nil {
		t.Fatalf("GetAllValidOIDCKeys: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("valid ES256 keys = %d after rotation, want 2 (previous kept while listed)", len(all))
	}
	// Rollback: v1 moved back to the front.
	if err := reconcileES256Keyring(ctx, store, []*ecdsa.PrivateKey{v1, v2}, time.Hour); err != nil {
		t.Fatalf("reconcile rollback: %v", err)
	}
	cur, err = store.GetCurrentOIDCKey(ctx)
	if err != nil || cur == nil {
		t.Fatalf("GetCurrentOIDCKey: %v (%v)", err, cur)
	}
	if cur.Kid != kidOf(t, v1) {
		t.Fatalf("current kid after rollback = %s, want %s", cur.Kid, kidOf(t, v1))
	}
	// Drop v2 with a short grace, let it expire, list it again: the expired
	// row is replaced, not a constraint error.
	const grace = 20 * time.Millisecond
	if err := reconcileES256Keyring(ctx, store, []*ecdsa.PrivateKey{v1}, grace); err != nil {
		t.Fatalf("reconcile drop: %v", err)
	}
	time.Sleep(2 * grace)
	if err := reconcileES256Keyring(ctx, store, []*ecdsa.PrivateKey{v1, v2}, grace); err != nil {
		t.Fatalf("reconcile with an expired row of a listed key: %v", err)
	}
	all, err = store.GetAllValidOIDCKeys(ctx)
	if err != nil {
		t.Fatalf("GetAllValidOIDCKeys: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("valid ES256 keys = %d after relisting an expired key, want 2", len(all))
	}
}

// TestServerOperatorSigningKeys starts a control plane on operator keys and
// checks what verifiers see: /keys carries exactly the file's Ed25519 keys,
// /jwks the file's P-256 key, and no automatic rotation is scheduled.
func TestServerOperatorSigningKeys(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	edCurrent, edPrevious := newEd25519(t), newEd25519(t)
	ec := newP256(t)
	path := writeKeyFile(t, pemPKCS8(t, edCurrent), pemPKCS8(t, edPrevious), pemPKCS8(t, ec))

	srv, store, baseURL := setupTestServer(t, issuer, func(o *Options) {
		o.SigningKeyPath = path
	})
	defer func() { _ = srv.Close() }()

	resp, err := http.Get(baseURL + "/keys")
	if err != nil {
		t.Fatalf("GET /keys: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read /keys: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /keys = %d: %s", resp.StatusCode, body)
	}
	var keys api.KeysResponse
	if err := proto.Unmarshal(body, &keys); err != nil {
		t.Fatalf("Unmarshal KeysResponse: %v", err)
	}
	got := map[string]bool{}
	for _, k := range keys.PublicKeys {
		got[string(k)] = true
	}
	if len(got) != 2 || !got[string(edCurrent.Public().(ed25519.PublicKey))] || !got[string(edPrevious.Public().(ed25519.PublicKey))] {
		t.Fatalf("/keys has %d keys, want exactly the two Ed25519 keys from the file", len(got))
	}
	_, currentPub, err := store.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	if !currentPub.Equal(edCurrent.Public().(ed25519.PublicKey)) {
		t.Fatalf("current key = %s, want %s (the first Ed25519 key in the file)", keyFingerprint(currentPub), keyFingerprint(edCurrent.Public().(ed25519.PublicKey)))
	}

	jwksResp, err := http.Get(baseURL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	var jwks JSONWebKeySet
	err = json.NewDecoder(jwksResp.Body).Decode(&jwks)
	_ = jwksResp.Body.Close()
	if err != nil {
		t.Fatalf("decode /jwks: %v", err)
	}
	ecPub, err := ec.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != es256Kid(ecPub) {
		t.Fatalf("/jwks = %d keys (kid %s), want the one P-256 key from the file (kid %s)", len(jwks.Keys), firstKid(jwks), es256Kid(ecPub))
	}

	next, err := store.NextKeyRotation(context.Background())
	if err != nil {
		t.Fatalf("NextKeyRotation: %v", err)
	}
	if !next.IsZero() {
		t.Fatalf("automatic rotation scheduled at %s although the operator owns the keys", next)
	}
}

func firstKid(jwks JSONWebKeySet) string {
	if len(jwks.Keys) == 0 {
		return ""
	}
	return jwks.Keys[0].Kid
}

// TestOperatorSigningKeysReload is a rotation as the operator performs it:
// the file changes under a running control plane and nothing is restarted.
// The new first key becomes the signing key, the previous one stays for
// verification, and a file that does not parse leaves the keys in use.
func TestOperatorSigningKeysReload(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	v1, v2 := newEd25519(t), newEd25519(t)
	ec := newP256(t)
	path := writeKeyFile(t, pemPKCS8(t, v1), pemPKCS8(t, ec))

	srv, store, baseURL := setupTestServer(t, issuer, func(o *Options) {
		o.SigningKeyPath = path
	})
	defer func() { _ = srv.Close() }()
	ctx := context.Background()
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	keysOnWire := func(t *testing.T) map[string]bool {
		t.Helper()
		resp, err := http.Get(baseURL + "/keys")
		if err != nil {
			t.Fatalf("GET /keys: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read /keys: %v", err)
		}
		var keys api.KeysResponse
		if err := proto.Unmarshal(body, &keys); err != nil {
			t.Fatalf("Unmarshal KeysResponse: %v", err)
		}
		out := map[string]bool{}
		for _, k := range keys.PublicKeys {
			out[string(k)] = true
		}
		return out
	}

	// No change: a reload pass installs nothing.
	srv.reloadOperatorSigningKeys()
	if got := keysOnWire(t); len(got) != 1 || !got[string(pub(v1))] {
		t.Fatalf("/keys after a no-op reload = %d keys, want only v1", len(got))
	}

	// A file that does not parse is refused and the keys in use stay.
	if err := os.WriteFile(path, []byte("-----BEGIN GARBAGE-----\nAAAA\n-----END GARBAGE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.reloadOperatorSigningKeys()
	if got := keysOnWire(t); len(got) != 1 || !got[string(pub(v1))] {
		t.Fatalf("/keys after a bad file = %d keys, want only v1 kept", len(got))
	}

	// The rotation: v2 first, v1 kept.
	if err := os.WriteFile(path, append(append(pemPKCS8(t, v2), pemPKCS8(t, v1)...), pemPKCS8(t, ec)...), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.reloadOperatorSigningKeys()
	got := keysOnWire(t)
	if len(got) != 2 || !got[string(pub(v1))] || !got[string(pub(v2))] {
		t.Fatalf("/keys after rotation = %d keys, want v1 and v2", len(got))
	}
	_, current, err := store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	if !current.Equal(pub(v2)) {
		t.Fatalf("signing key after rotation = %s, want %s (v2, first in the file)", keyFingerprint(current), keyFingerprint(pub(v2)))
	}
	// The ES256 key did not change and was not reinstalled.
	all, err := store.GetAllValidOIDCKeys(ctx)
	if err != nil {
		t.Fatalf("GetAllValidOIDCKeys: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("ES256 keys after a rotation of the Ed25519 key = %d, want 1", len(all))
	}

	// Dropping v1 from the file: v2 stays current, v1 keeps verifying until
	// its grace period ends (the store's business, not the file's).
	if err := os.WriteFile(path, append(pemPKCS8(t, v2), pemPKCS8(t, ec)...), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.reloadOperatorSigningKeys()
	_, current, err = store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey: %v", err)
	}
	if !current.Equal(pub(v2)) {
		t.Fatalf("signing key after dropping v1 = %s, want %s (v2)", keyFingerprint(current), keyFingerprint(pub(v2)))
	}
}
