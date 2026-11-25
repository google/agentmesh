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
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	golog "github.com/ipfs/go-log/v2"

	"github.com/google/agentmesh/internal/logging"
	"github.com/google/agentmesh/internal/storage"
)

// keyringReadFailStore fails GetAllValidKeys from its failFrom'th call on.
type keyringReadFailStore struct {
	storage.Store
	calls    int
	failFrom int
}

var errKeyringRead = errors.New("keyring read failed")

func (s *keyringReadFailStore) GetAllValidKeys(ctx context.Context) ([]storage.KeyPair, error) {
	s.calls++
	if s.calls >= s.failFrom {
		return nil, errKeyringRead
	}
	return s.Store.GetAllValidKeys(ctx)
}

// When the keyring cannot be read back after an install, the failure is
// logged with its error instead of an install line listing no valid keys.
func TestReconcileKeyringLogsAFailedReadBack(t *testing.T) {
	prev := golog.GetConfig()
	logging.Setup(logging.Options{RingBuffer: true})
	t.Cleanup(func() { golog.SetupLogging(prev) })
	ctx := context.Background()
	base, err := storage.NewSQLStore("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })

	first, second := newEd25519(t), newEd25519(t)
	if err := reconcileEd25519Keyring(ctx, base, []ed25519.PrivateKey{first}, time.Hour); err != nil {
		t.Fatalf("install the first key: %v", err)
	}
	// Call 1 is the read before SetKeyring, call 2 the read after it.
	store := &keyringReadFailStore{Store: base, failFrom: 2}
	if err := reconcileEd25519Keyring(ctx, store, []ed25519.PrivateKey{second, first}, time.Hour); err != nil {
		t.Fatalf("install the second key: %v", err)
	}

	secondFP := keyFingerprint(second.Public().(ed25519.PublicKey))
	logged := false
	for _, line := range logging.RecentLogs() {
		if strings.Contains(line, errKeyringRead.Error()) && strings.Contains(line, secondFP) {
			logged = true
		}
		if strings.Contains(line, "Operator signing keys installed\t") && strings.Contains(line, secondFP) {
			t.Fatalf("install line %q claims a keyring that was not read", line)
		}
	}
	if !logged {
		t.Fatalf("no log line names the failed read back (%v) for signing key %s", errKeyringRead, secondFP)
	}
}
