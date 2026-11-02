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

package node

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStore_NewStore_And_Close(t *testing.T) {
	tempDir := t.TempDir()

	store, err := NewStore(tempDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	dbPath := filepath.Join(tempDir, "agent.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file does not exist at %s", dbPath)
	}

	if err := store.Close(); err != nil {
		t.Errorf("Failed to close store: %v", err)
	}
}

func TestStore_TrustedKeys(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Empty store: no keys, no error
	keys, err := store.LoadTrustedKeys()
	if err != nil {
		t.Fatalf("LoadTrustedKeys on empty store: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no keys, got %d", len(keys))
	}

	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	want := []TrustedKey{
		{Key: pub1, ReceivedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Second)},
		{Key: pub2, ReceivedAt: time.Now().UTC().Truncate(time.Second)},
	}
	if err := store.SaveTrustedKeys(want); err != nil {
		t.Fatalf("SaveTrustedKeys: %v", err)
	}
	got, err := store.LoadTrustedKeys()
	if err != nil {
		t.Fatalf("LoadTrustedKeys: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d keys, want %d", len(got), len(want))
	}
	for i := range got {
		if !got[i].Key.Equal(want[i].Key) || !got[i].ReceivedAt.Equal(want[i].ReceivedAt) {
			t.Errorf("key %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	// Mesh reset must clear the persisted trust set
	if err := store.ResetMeshIdentity(); err != nil {
		t.Fatalf("ResetMeshIdentity: %v", err)
	}
	got, err = store.LoadTrustedKeys()
	if err != nil {
		t.Fatalf("LoadTrustedKeys after reset: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected trust set cleared after mesh reset, got %d keys", len(got))
	}
}

func TestStore_Identity(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading identity when not set should fail
	_, err = store.LoadIdentity()
	if err == nil {
		t.Error("Expected error loading identity when none is saved, got nil")
	}

	biscuit := []byte("dummy-biscuit-data")
	if err := store.SaveIdentity(biscuit); err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	loaded, err := store.LoadIdentity()
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}

	if !bytes.Equal(loaded, biscuit) {
		t.Errorf("Expected loaded identity %s, got %s", string(biscuit), string(loaded))
	}
}

func TestStore_IdentityExpiration(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set should fail
	_, err = store.LoadIdentityExpiration()
	if err == nil {
		t.Error("Expected error loading identity expiration when none is saved, got nil")
	}

	exp := int64(1782418067)
	if err := store.SaveIdentityExpiration(exp); err != nil {
		t.Fatalf("SaveIdentityExpiration failed: %v", err)
	}

	loadedExp, err := store.LoadIdentityExpiration()
	if err != nil {
		t.Fatalf("LoadIdentityExpiration failed: %v", err)
	}

	if loadedExp != exp {
		t.Errorf("Expected loaded expiration %d, got %d", exp, loadedExp)
	}
}

func TestStore_RefreshToken(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set should fail
	_, err = store.LoadRefreshToken()
	if err == nil {
		t.Error("Expected error loading refresh token when none is saved, got nil")
	}

	token := "refresh-token-xyz"
	if err := store.SaveRefreshToken(token); err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	loaded, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("LoadRefreshToken failed: %v", err)
	}

	if loaded != token {
		t.Errorf("Expected loaded refresh token %q, got %q", token, loaded)
	}
}

func TestStore_OIDCConfig(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set returns empty strings
	iss, cid, aud, err := store.LoadOIDCConfig()
	if err != nil {
		t.Fatalf("LoadOIDCConfig failed: %v", err)
	}
	if iss != "" || cid != "" || aud != "" {
		t.Errorf("Expected empty OIDC config, got issuer=%q, clientID=%q, audience=%q", iss, cid, aud)
	}

	issuer := "https://auth.example.com"
	clientID := "client-123"
	audience := "agentmesh"

	if err := store.SaveOIDCConfig(issuer, clientID, audience); err != nil {
		t.Fatalf("SaveOIDCConfig failed: %v", err)
	}

	loadedIss, loadedCID, loadedAud, err := store.LoadOIDCConfig()
	if err != nil {
		t.Fatalf("LoadOIDCConfig failed: %v", err)
	}

	if loadedIss != issuer || loadedCID != clientID || loadedAud != audience {
		t.Errorf("Expected OIDC config (%q, %q, %q), got (%q, %q, %q)", issuer, clientID, audience, loadedIss, loadedCID, loadedAud)
	}
}

func TestStore_Key(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set should return nil or empty
	loaded, err := store.LoadKey()
	if err != nil {
		t.Fatalf("LoadKey failed: %v", err)
	}
	if len(loaded) > 0 {
		t.Errorf("Expected empty key, got len %d", len(loaded))
	}

	key := []byte("private-key-bytes")
	if err := store.SaveKey(key); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	loaded, err = store.LoadKey()
	if err != nil {
		t.Fatalf("LoadKey failed: %v", err)
	}

	if !bytes.Equal(loaded, key) {
		t.Errorf("Expected loaded key %v, got %v", key, loaded)
	}
}

func TestStore_MeshConfig(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set
	pubKey, addrs, err := store.LoadMeshConfig()
	if err != nil {
		t.Fatalf("LoadMeshConfig failed: %v", err)
	}
	if len(pubKey) > 0 || len(addrs) > 0 {
		t.Errorf("Expected empty mesh config, got pubKey=%v, addrs=%v", pubKey, addrs)
	}

	controlPlanePubKey := bytes.Repeat([]byte{7}, ed25519.PublicKeySize)
	routerAddrs := []string{"/ip4/127.0.0.1/tcp/5001", "/dns4/cp.example.com/tcp/5001"}

	if err := store.SaveMeshConfig(controlPlanePubKey, routerAddrs); err != nil {
		t.Fatalf("SaveMeshConfig failed: %v", err)
	}

	loadedPubKey, loadedAddrs, err := store.LoadMeshConfig()
	if err != nil {
		t.Fatalf("LoadMeshConfig failed: %v", err)
	}

	if !bytes.Equal(loadedPubKey, controlPlanePubKey) {
		t.Errorf("Expected loaded control plane pubkey %v, got %v", controlPlanePubKey, loadedPubKey)
	}
	if !reflect.DeepEqual(loadedAddrs, routerAddrs) {
		t.Errorf("Expected loaded router addrs %v, got %v", routerAddrs, loadedAddrs)
	}

	// Enrollment's key is trusted and is what the identity was issued under.
	trusted, err := store.LoadTrustedKeys()
	if err != nil || len(trusted) != 1 || !bytes.Equal(trusted[0].Key, controlPlanePubKey) {
		t.Fatalf("trusted keys after enrollment = %v, %v; want the enrollment key", trusted, err)
	}
	issuance, err := store.LoadIdentityKeySet()
	if err != nil || len(issuance) != 1 || !bytes.Equal(issuance[0], controlPlanePubKey) {
		t.Fatalf("identity key set after enrollment = %v, %v; want the enrollment key", issuance, err)
	}
}

// TestStore_MigratesLegacyLayout opens a database written by a build that
// kept one entry per field and finds the same state as one MemberCredential.
func TestStore_MigratesLegacyLayout(t *testing.T) {
	dir := t.TempDir()
	enrollmentKey := bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	rotatedKey := bytes.Repeat([]byte{2}, ed25519.PublicKeySize)
	received := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	trustedJSON, _ := json.Marshal([]TrustedKey{{Key: rotatedKey, ReceivedAt: received}})
	addrsJSON, _ := json.Marshal([]string{"/dns4/router.example/tcp/4001/p2p/12D3KooWP8iKhDf3iCMo2H3butNVfdTUtYwYWYQ75jTGnynXPFMp"})
	db, err := bbolt.Open(filepath.Join(dir, StoreFile), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketIdentity))
		if err != nil {
			return err
		}
		for k, v := range map[string][]byte{
			keyPrivKey:                 []byte("private-key-bytes"),
			"identity_biscuit":         []byte("biscuit-bytes"),
			"identity_expiration":      []byte("1790000000"),
			"refresh_token":            []byte("refresh-secret"),
			"oidc_issuer":              []byte("https://issuer.example"),
			"oidc_client_id":           []byte("client"),
			"oidc_audience":            []byte("aud"),
			"trusted_keys":             trustedJSON,
			"control_plane_public_key": enrollmentKey,
			"router_addresses":         addrsJSON,
			"control_plane_url":        []byte("https://cp.example"),
		} {
			if err := b.Put([]byte(k), v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore on a legacy database: %v", err)
	}
	defer func() { _ = store.Close() }()

	if key, _ := store.LoadKey(); string(key) != "private-key-bytes" {
		t.Errorf("private key = %q, want it untouched", key)
	}
	if biscuit, err := store.LoadIdentity(); err != nil || string(biscuit) != "biscuit-bytes" {
		t.Errorf("biscuit = %q, %v", biscuit, err)
	}
	if exp, err := store.LoadIdentityExpiration(); err != nil || exp != 1790000000 {
		t.Errorf("expiration = %d, %v", exp, err)
	}
	if tok, err := store.LoadRefreshToken(); err != nil || tok != "refresh-secret" {
		t.Errorf("refresh token = %q, %v", tok, err)
	}
	if iss, cid, aud, err := store.LoadOIDCConfig(); err != nil || iss != "https://issuer.example" || cid != "client" || aud != "aud" {
		t.Errorf("oidc = %q %q %q, %v", iss, cid, aud, err)
	}
	if url, _ := store.LoadControlPlaneURL(); url != "https://cp.example" {
		t.Errorf("control plane url = %q", url)
	}
	pubKey, addrs, _ := store.LoadMeshConfig()
	if len(addrs) != 1 || !bytes.Equal(pubKey, rotatedKey) {
		t.Errorf("mesh config = %x, %v; want the first trusted key and one router", pubKey, addrs)
	}
	// The rotated key keeps its timestamp; the enrollment key joins the
	// trusted set and, since the old build recorded no issuance set, stands
	// for it.
	trusted, _ := store.LoadTrustedKeys()
	if len(trusted) != 2 || !bytes.Equal(trusted[0].Key, rotatedKey) || !trusted[0].ReceivedAt.Equal(received) || !bytes.Equal(trusted[1].Key, enrollmentKey) {
		t.Errorf("trusted keys = %+v", trusted)
	}
	if issuance, _ := store.LoadIdentityKeySet(); len(issuance) != 1 || !bytes.Equal(issuance[0], enrollmentKey) {
		t.Errorf("identity key set = %x, want the enrollment key", issuance)
	}

	// The legacy entries are gone; only the key and the credential remain.
	if err := store.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		for _, k := range legacyKeys {
			if b.Get([]byte(k)) != nil {
				t.Errorf("legacy entry %q survived the migration", k)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestStore_CredentialRoundTrip is what `agentmesh-node state export | import`
// relies on: the message out is the message in.
func TestStore_CredentialRoundTrip(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	want := &api.MemberCredential{
		ControlPlaneUrl: "https://cp.example",
		Biscuit:         []byte("biscuit"),
		ExpireTime:      timestamppb.New(time.Unix(1790000000, 0)),
		TrustedKeys:     []*api.TrustedSigningKey{{PublicKey: bytes.Repeat([]byte{3}, ed25519.PublicKeySize), ReceiveTime: timestamppb.New(time.Unix(1780000000, 0))}},
		IssuedUnderKeys: [][]byte{bytes.Repeat([]byte{3}, ed25519.PublicKeySize)},
		RouterAddresses: []string{"/dns4/router.example/tcp/4001/p2p/12D3KooWP8iKhDf3iCMo2H3butNVfdTUtYwYWYQ75jTGnynXPFMp"},
	}
	if err := store.SetCredential(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Credential()
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(want, got) {
		t.Fatalf("credential round trip:\n got %v\nwant %v", got, want)
	}
	if err := store.ResetMeshIdentity(); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Credential(); !proto.Equal(got, &api.MemberCredential{}) {
		t.Fatalf("credential after reset = %v, want empty", got)
	}
}

func TestStore_ControlPlaneURL(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Loading when not set
	url, err := store.LoadControlPlaneURL()
	if err != nil {
		t.Fatalf("LoadControlPlaneURL failed: %v", err)
	}
	if url != "" {
		t.Errorf("Expected empty Control plane URL, got %q", url)
	}

	controlPlaneURL := "https://cp.example.com"
	if err := store.SaveControlPlaneURL(controlPlaneURL); err != nil {
		t.Fatalf("SaveControlPlaneURL failed: %v", err)
	}

	loaded, err := store.LoadControlPlaneURL()
	if err != nil {
		t.Fatalf("LoadControlPlaneURL failed: %v", err)
	}

	if loaded != controlPlaneURL {
		t.Errorf("Expected loaded control plane URL %q, got %q", controlPlaneURL, loaded)
	}
}

func TestStore_ErrStoreLocked(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// The CLI relies on this sentinel to tell "a node is already running" from
	// a genuine store failure, so it must survive the wrapping in NewStore.
	if _, err := NewStore(dir); !errors.Is(err, ErrStoreLocked) {
		t.Errorf("opening a locked data directory: got %v, want ErrStoreLocked", err)
	}
}

func TestStore_ResetMeshIdentity(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	if err := store.SaveIdentity([]byte("biscuit")); err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}
	if err := store.SaveMeshConfig([]byte("pubkey"), []string{"/ip4/1.2.3.4/tcp/1"}); err != nil {
		t.Fatalf("SaveMeshConfig failed: %v", err)
	}
	if err := store.SaveControlPlaneURL("https://cp.example.com"); err != nil {
		t.Fatalf("SaveControlPlaneURL failed: %v", err)
	}
	if err := store.SaveOIDCConfig("issuer", "client", "audience"); err != nil {
		t.Fatalf("SaveOIDCConfig failed: %v", err)
	}
	key := []byte("node-private-key-bytes")
	if err := store.SaveKey(key); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	if err := store.ResetMeshIdentity(); err != nil {
		t.Fatalf("ResetMeshIdentity failed: %v", err)
	}

	if _, err := store.LoadIdentity(); err == nil {
		t.Error("expected identity to be cleared")
	}
	if pubKey, _, _ := store.LoadMeshConfig(); len(pubKey) != 0 {
		t.Errorf("expected mesh config pubkey to be cleared, got %v", pubKey)
	}
	if url, _ := store.LoadControlPlaneURL(); url != "" {
		t.Errorf("expected control plane URL to be cleared, got %q", url)
	}
	issuer, _, _, _ := store.LoadOIDCConfig()
	if issuer != "" {
		t.Errorf("expected OIDC config to be cleared, got issuer %q", issuer)
	}

	// The libp2p private key must survive the reset so the PeerID is stable.
	loadedKey, err := store.LoadKey()
	if err != nil {
		t.Fatalf("LoadKey failed: %v", err)
	}
	if string(loadedKey) != string(key) {
		t.Errorf("expected private key to survive reset, got %v want %v", loadedKey, key)
	}
}
func TestGetDefaultDataDir(t *testing.T) {
	dir, err := GetDefaultDataDir()
	if err != nil {
		t.Fatalf("GetDefaultDataDir failed: %v", err)
	}
	if dir == "" {
		t.Error("Expected non-empty directory path")
	}

	custom := filepath.Join(t.TempDir(), "custom-agentmesh-dir")
	t.Setenv("AGENTMESH_DATA_DIR", custom)
	got, err := GetDefaultDataDir()
	if err != nil {
		t.Fatalf("GetDefaultDataDir with AGENTMESH_DATA_DIR failed: %v", err)
	}
	if got != custom {
		t.Fatalf("GetDefaultDataDir = %q, want %q", got, custom)
	}
}
