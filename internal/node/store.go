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
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"go.etcd.io/bbolt"
	bbolterrors "go.etcd.io/bbolt/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// StoreFile is the node database inside the data directory.
	StoreFile = "agent.db"

	bucketIdentity = "identity"
	// keyPrivKey holds the libp2p PrivateKey encoding, as identity.key in a
	// state directory does.
	keyPrivKey = "node_private_key"
	// keyCredential holds the binary api.MemberCredential, the same message a
	// state directory keeps as credential.json.
	keyCredential = "member_credential"
)

// legacyKeys are the per-field entries the database held before the
// credential became one message. A store that still has them is migrated on
// open and they are removed.
var legacyKeys = []string{
	"identity_biscuit",
	"identity_expiration",
	"refresh_token",
	"oidc_issuer",
	"oidc_client_id",
	"oidc_audience",
	"trusted_keys",
	"identity_key_set",
	"control_plane_public_key",
	"router_addresses",
	"control_plane_url",
}

// Store is the node's persistent state: its private key and its
// api.MemberCredential, in a bbolt database whose file lock also tells a
// second agentmesh-node that this data directory is in use.
type Store struct {
	db *bbolt.DB
}

// ErrStoreLocked reports that another process already holds the data
// directory, which for a node data directory means a node is running.
var ErrStoreLocked = errors.New("another agentmesh-node instance is using this data directory")

func GetDefaultDataDir() (string, error) {
	if envDir := strings.TrimSpace(os.Getenv("AGENTMESH_DATA_DIR")); envDir != "" {
		if err := os.MkdirAll(envDir, 0700); err != nil {
			return "", err
		}
		return envDir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "agentmesh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	dbPath := filepath.Join(dir, StoreFile)
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		if errors.Is(err, bbolterrors.ErrTimeout) {
			return nil, fmt.Errorf("%w: timed out waiting for the file lock on %s", ErrStoreLocked, dbPath)
		}
		return nil, err
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketIdentity))
		if err != nil {
			return err
		}
		return migrateLegacyCredential(b)
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrateLegacyCredential folds the per-field entries of an older database
// into one MemberCredential. The enrollment key seeds both key sets when the
// old database recorded neither, which is what the code reading them assumed.
func migrateLegacyCredential(b *bbolt.Bucket) error {
	if b.Get([]byte(keyCredential)) != nil {
		return nil
	}
	present := false
	for _, k := range legacyKeys {
		if b.Get([]byte(k)) != nil {
			present = true
			break
		}
	}
	if !present {
		return nil
	}
	c := &api.MemberCredential{
		ControlPlaneUrl: string(b.Get([]byte("control_plane_url"))),
		Biscuit:         append([]byte(nil), b.Get([]byte("identity_biscuit"))...),
	}
	if raw := b.Get([]byte("identity_expiration")); len(raw) > 0 {
		if exp, err := strconv.ParseInt(string(raw), 10, 64); err == nil {
			c.ExpireTime = timestamppb.New(time.Unix(exp, 0))
		}
	}
	if raw := b.Get([]byte("router_addresses")); len(raw) > 0 {
		if err := json.Unmarshal(raw, &c.RouterAddresses); err != nil {
			return fmt.Errorf("migrating router_addresses: %w", err)
		}
	}
	if raw := b.Get([]byte("trusted_keys")); len(raw) > 0 {
		var keys []TrustedKey
		if err := json.Unmarshal(raw, &keys); err != nil {
			return fmt.Errorf("migrating trusted_keys: %w", err)
		}
		c.TrustedKeys = trustedKeysToProto(keys)
	}
	if raw := b.Get([]byte("identity_key_set")); len(raw) > 0 {
		var keys []ed25519.PublicKey
		if err := json.Unmarshal(raw, &keys); err != nil {
			return fmt.Errorf("migrating identity_key_set: %w", err)
		}
		for _, k := range keys {
			c.IssuedUnderKeys = append(c.IssuedUnderKeys, []byte(k))
		}
	}
	if enrollmentKey := b.Get([]byte("control_plane_public_key")); len(enrollmentKey) == ed25519.PublicKeySize {
		if !containsKeyBytes(trustedKeyBytes(c.TrustedKeys), enrollmentKey) {
			c.TrustedKeys = append(c.TrustedKeys, &api.TrustedSigningKey{PublicKey: append([]byte(nil), enrollmentKey...), ReceiveTime: timestamppb.Now()})
		}
		if len(c.IssuedUnderKeys) == 0 {
			c.IssuedUnderKeys = [][]byte{append([]byte(nil), enrollmentKey...)}
		}
	}
	issuer, clientID, audience := string(b.Get([]byte("oidc_issuer"))), string(b.Get([]byte("oidc_client_id"))), string(b.Get([]byte("oidc_audience")))
	refresh := string(b.Get([]byte("refresh_token")))
	if issuer != "" || clientID != "" || audience != "" || refresh != "" {
		c.OidcSession = &api.OIDCSession{Issuer: issuer, ClientId: clientID, Audience: audience, RefreshToken: refresh}
	}
	if err := putCredential(b, c); err != nil {
		return err
	}
	for _, k := range legacyKeys {
		if err := b.Delete([]byte(k)); err != nil {
			return err
		}
	}
	return nil
}

func putCredential(b *bbolt.Bucket, c *api.MemberCredential) error {
	data, err := proto.Marshal(c)
	if err != nil {
		return err
	}
	return b.Put([]byte(keyCredential), data)
}

func getCredential(b *bbolt.Bucket) (*api.MemberCredential, error) {
	c := &api.MemberCredential{}
	if raw := b.Get([]byte(keyCredential)); len(raw) > 0 {
		if err := proto.Unmarshal(raw, c); err != nil {
			return nil, fmt.Errorf("corrupt member credential in store: %w", err)
		}
	}
	return c, nil
}

// view reads the credential; an empty message stands for a node that has not enrolled.
func (s *Store) view(fn func(c *api.MemberCredential) error) error {
	return s.db.View(func(tx *bbolt.Tx) error {
		c, err := getCredential(tx.Bucket([]byte(bucketIdentity)))
		if err != nil {
			return err
		}
		return fn(c)
	})
}

// update applies fn to the credential and writes it back in one transaction.
func (s *Store) update(fn func(c *api.MemberCredential) error) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketIdentity))
		c, err := getCredential(b)
		if err != nil {
			return err
		}
		if err := fn(c); err != nil {
			return err
		}
		return putCredential(b, c)
	})
}

// Credential returns a copy of everything the node persists besides its
// private key. A node that has not enrolled holds an empty message.
func (s *Store) Credential() (*api.MemberCredential, error) {
	var out *api.MemberCredential
	err := s.view(func(c *api.MemberCredential) error {
		out = proto.Clone(c).(*api.MemberCredential)
		return nil
	})
	return out, err
}

// SetCredential replaces everything the node persists besides its private
// key; `agentmesh-node state import` uses it.
func (s *Store) SetCredential(c *api.MemberCredential) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putCredential(tx.Bucket([]byte(bucketIdentity)), c)
	})
}

func (s *Store) SaveIdentity(biscuit []byte) error {
	return s.update(func(c *api.MemberCredential) error {
		c.Biscuit = append([]byte(nil), biscuit...)
		return nil
	})
}

func (s *Store) LoadIdentity() ([]byte, error) {
	var val []byte
	if err := s.view(func(c *api.MemberCredential) error {
		val = append([]byte(nil), c.Biscuit...)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(val) == 0 {
		return nil, fmt.Errorf("no identity found")
	}
	return val, nil
}

func (s *Store) SaveIdentityExpiration(exp int64) error {
	return s.update(func(c *api.MemberCredential) error {
		c.ExpireTime = timestamppb.New(time.Unix(exp, 0))
		return nil
	})
}

func (s *Store) LoadIdentityExpiration() (int64, error) {
	var exp *timestamppb.Timestamp
	if err := s.view(func(c *api.MemberCredential) error {
		exp = c.ExpireTime
		return nil
	}); err != nil {
		return 0, err
	}
	if exp == nil {
		return 0, fmt.Errorf("no identity expiration found")
	}
	return exp.AsTime().Unix(), nil
}

func (s *Store) SaveRefreshToken(token string) error {
	return s.update(func(c *api.MemberCredential) error {
		if c.OidcSession == nil {
			c.OidcSession = &api.OIDCSession{}
		}
		c.OidcSession.RefreshToken = token
		return nil
	})
}

func (s *Store) LoadRefreshToken() (string, error) {
	var token string
	if err := s.view(func(c *api.MemberCredential) error {
		token = c.GetOidcSession().GetRefreshToken()
		return nil
	}); err != nil {
		return "", err
	}
	if token == "" {
		return "", fmt.Errorf("no refresh token found")
	}
	return token, nil
}

func (s *Store) SaveOIDCConfig(issuer, clientID, audience string) error {
	return s.update(func(c *api.MemberCredential) error {
		if c.OidcSession == nil {
			c.OidcSession = &api.OIDCSession{}
		}
		c.OidcSession.Issuer, c.OidcSession.ClientId, c.OidcSession.Audience = issuer, clientID, audience
		return nil
	})
}

func (s *Store) LoadOIDCConfig() (string, string, string, error) {
	var issuer, clientID, audience string
	err := s.view(func(c *api.MemberCredential) error {
		issuer, clientID, audience = c.GetOidcSession().GetIssuer(), c.GetOidcSession().GetClientId(), c.GetOidcSession().GetAudience()
		return nil
	})
	return issuer, clientID, audience, err
}

func (s *Store) SaveKey(key []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketIdentity)).Put([]byte(keyPrivKey), key)
	})
}

func (s *Store) LoadKey() ([]byte, error) {
	var val []byte
	_ = s.db.View(func(tx *bbolt.Tx) error {
		val = append([]byte(nil), tx.Bucket([]byte(bucketIdentity)).Get([]byte(keyPrivKey))...)
		return nil
	})
	return val, nil
}

// SaveMeshConfig records what enrollment handed out: the control plane key
// that signed the biscuit and the routers to join through. The key enters
// the trusted set, and seeds the issuance set when nothing recorded it yet.
// Later calls, from the sync that follows router changes, pass the key
// LoadMeshConfig returned and only move the addresses.
func (s *Store) SaveMeshConfig(pubKey []byte, addrs []string) error {
	return s.update(func(c *api.MemberCredential) error {
		c.RouterAddresses = append([]string(nil), addrs...)
		if len(pubKey) != ed25519.PublicKeySize {
			return nil
		}
		if !containsKeyBytes(trustedKeyBytes(c.TrustedKeys), pubKey) {
			c.TrustedKeys = append(c.TrustedKeys, &api.TrustedSigningKey{PublicKey: append([]byte(nil), pubKey...), ReceiveTime: timestamppb.Now()})
		}
		if len(c.IssuedUnderKeys) == 0 {
			c.IssuedUnderKeys = [][]byte{append([]byte(nil), pubKey...)}
		}
		return nil
	})
}

// LoadMeshConfig returns the first trusted control plane key, which is the
// one enrollment handed out until a rotation retires it, and the router
// addresses.
func (s *Store) LoadMeshConfig() ([]byte, []string, error) {
	var pubKey []byte
	var addrs []string
	err := s.view(func(c *api.MemberCredential) error {
		if len(c.TrustedKeys) > 0 {
			pubKey = append([]byte(nil), c.TrustedKeys[0].PublicKey...)
		}
		addrs = append([]string(nil), c.RouterAddresses...)
		return nil
	})
	return pubKey, addrs, err
}

func (s *Store) SaveControlPlaneURL(url string) error {
	return s.update(func(c *api.MemberCredential) error {
		c.ControlPlaneUrl = url
		return nil
	})
}

// SaveTrustedKeys persists the full set of control plane public keys the
// node currently trusts, so keys learned from rotation events or /keys
// survive restarts.
func (s *Store) SaveTrustedKeys(keys []TrustedKey) error {
	return s.update(func(c *api.MemberCredential) error {
		c.TrustedKeys = trustedKeysToProto(keys)
		return nil
	})
}

func (s *Store) LoadTrustedKeys() ([]TrustedKey, error) {
	var keys []TrustedKey
	err := s.view(func(c *api.MemberCredential) error {
		keys = trustedKeysFromProto(c.TrustedKeys)
		return nil
	})
	return keys, err
}

// SaveIdentityKeySet records the control plane public keys known when the
// stored identity was issued. A key that later appears outside this set is
// a rotation the identity predates, which is why it survives restarts.
func (s *Store) SaveIdentityKeySet(keys []ed25519.PublicKey) error {
	return s.update(func(c *api.MemberCredential) error {
		c.IssuedUnderKeys = c.IssuedUnderKeys[:0]
		for _, k := range keys {
			c.IssuedUnderKeys = append(c.IssuedUnderKeys, append([]byte(nil), k...))
		}
		return nil
	})
}

// LoadIdentityKeySet returns the set saved by SaveIdentityKeySet, or nil when
// nothing recorded it.
func (s *Store) LoadIdentityKeySet() ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	err := s.view(func(c *api.MemberCredential) error {
		for _, k := range c.IssuedUnderKeys {
			keys = append(keys, ed25519.PublicKey(append([]byte(nil), k...)))
		}
		return nil
	})
	return keys, err
}

func (s *Store) LoadControlPlaneURL() (string, error) {
	var url string
	err := s.view(func(c *api.MemberCredential) error {
		url = c.ControlPlaneUrl
		return nil
	})
	return url, err
}

// ResetMeshIdentity clears everything about a node's mesh membership (its
// Biscuit, mesh/control-plane config, and OIDC session state) so it can join
// a different mesh. It keeps the long-lived libp2p key (node_private_key), so
// the node's PeerID survives the switch.
func (s *Store) ResetMeshIdentity() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketIdentity)).Delete([]byte(keyCredential))
	})
}

func trustedKeysToProto(keys []TrustedKey) []*api.TrustedSigningKey {
	out := make([]*api.TrustedSigningKey, 0, len(keys))
	for _, k := range keys {
		tk := &api.TrustedSigningKey{PublicKey: append([]byte(nil), k.Key...)}
		if !k.ReceivedAt.IsZero() {
			tk.ReceiveTime = timestamppb.New(k.ReceivedAt)
		}
		out = append(out, tk)
	}
	return out
}

// trustedKeysFromProto reads a key learned at an unknown time as learned now,
// so it is the newest and survives the grace period like a fresh rotation.
func trustedKeysFromProto(keys []*api.TrustedSigningKey) []TrustedKey {
	if len(keys) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]TrustedKey, 0, len(keys))
	for _, k := range keys {
		tk := TrustedKey{Key: ed25519.PublicKey(append([]byte(nil), k.PublicKey...)), ReceivedAt: now}
		if k.ReceiveTime != nil {
			tk.ReceivedAt = k.ReceiveTime.AsTime()
		}
		out = append(out, tk)
	}
	return out
}

func trustedKeyBytes(keys []*api.TrustedSigningKey) [][]byte {
	out := make([][]byte, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.PublicKey)
	}
	return out
}

func containsKeyBytes(keys [][]byte, want []byte) bool {
	for _, k := range keys {
		if string(k) == string(want) {
			return true
		}
	}
	return false
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Peer bans are deliberately not kept here. A ban on disk cannot be undone by
// the control plane -- there is no unban event -- and it says nothing about a
// node that was offline when the ban was published. Both are handled instead by
// reconciling against the ban set in /info before start and on every sync
// (see SyncControlPlane), with MeshEvent_BANNED as the sub-second path for
// nodes that are already up.
