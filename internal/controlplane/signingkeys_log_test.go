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
	"errors"
	"strings"
	"testing"
	"time"

	golog "github.com/ipfs/go-log/v2"

	"github.com/google/agentmesh/internal/logging"
	"github.com/google/agentmesh/internal/storage"
)

// keyringReadFailStore fails GetAllValidKeys and GetAllValidOIDCKeys from
// their failFrom'th call on, each counted on its own.
type keyringReadFailStore struct {
	storage.Store
	calls, oidcCalls int
	failFrom         int
}

var errKeyringRead = errors.New("keyring read failed")

func (s *keyringReadFailStore) GetAllValidKeys(ctx context.Context) ([]storage.KeyPair, error) {
	s.calls++
	if s.calls >= s.failFrom {
		return nil, errKeyringRead
	}
	return s.Store.GetAllValidKeys(ctx)
}

func (s *keyringReadFailStore) GetAllValidOIDCKeys(ctx context.Context) ([]storage.OIDCKeyPair, error) {
	s.oidcCalls++
	if s.oidcCalls >= s.failFrom {
		return nil, errKeyringRead
	}
	return s.Store.GetAllValidOIDCKeys(ctx)
}

// When a keyring cannot be read back after an install, the failure is
// logged with its error instead of an install line listing no valid keys.
func TestReconcileKeyringLogsAFailedReadBack(t *testing.T) {
	prev := golog.GetConfig()
	logging.Setup(logging.Options{RingBuffer: true})
	t.Cleanup(func() { golog.SetupLogging(prev) })

	for _, tc := range []struct {
		name string
		// install puts the first key in place, then installs the second in
		// front of it through store, and returns the second key's id.
		install func(t *testing.T, base, store storage.Store) string
	}{
		{"ed25519", func(t *testing.T, base, store storage.Store) string {
			first, second := newEd25519(t), newEd25519(t)
			if err := reconcileEd25519Keyring(context.Background(), base, []ed25519.PrivateKey{first}, time.Hour); err != nil {
				t.Fatalf("install the first key: %v", err)
			}
			if err := reconcileEd25519Keyring(context.Background(), store, []ed25519.PrivateKey{second, first}, time.Hour); err != nil {
				t.Fatalf("install the second key: %v", err)
			}
			return keyFingerprint(second.Public().(ed25519.PublicKey))
		}},
		{"es256", func(t *testing.T, base, store storage.Store) string {
			first, second := newP256(t), newP256(t)
			if err := reconcileES256Keyring(context.Background(), base, []*ecdsa.PrivateKey{first}, time.Hour); err != nil {
				t.Fatalf("install the first key: %v", err)
			}
			if err := reconcileES256Keyring(context.Background(), store, []*ecdsa.PrivateKey{second, first}, time.Hour); err != nil {
				t.Fatalf("install the second key: %v", err)
			}
			pub, err := second.PublicKey.Bytes()
			if err != nil {
				t.Fatalf("encode the second key: %v", err)
			}
			return es256Kid(pub)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, err := storage.NewSQLStore("sqlite", ":memory:")
			if err != nil {
				t.Fatalf("NewSQLStore: %v", err)
			}
			t.Cleanup(func() { _ = base.Close() })
			// Call 1 is the read before the keyring is set, call 2 the read after it.
			signing := tc.install(t, base, &keyringReadFailStore{Store: base, failFrom: 2})

			logged := false
			for _, line := range logging.RecentLogs() {
				if strings.Contains(line, errKeyringRead.Error()) && strings.Contains(line, signing) {
					logged = true
				}
				if strings.Contains(line, "Operator signing keys installed	") && strings.Contains(line, signing) {
					t.Fatalf("install line %q claims a keyring that was not read", line)
				}
			}
			if !logged {
				t.Fatalf("no log line names the failed read back (%v) for signing key %s", errKeyringRead, signing)
			}
		})
	}
}
