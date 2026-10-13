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

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/controlplane"
	"github.com/google/agentmesh/internal/storage"
)

// startTokenTestControlPlane brings up a control plane wired to a mock OIDC provider
// and returns its base URL, a JWT minter, and the backing store.
func startTokenTestControlPlane(t *testing.T) (string, func(claims map[string]interface{}) string, storage.Store) {
	t.Helper()

	oidcURL, mintToken := startCustomMockOIDC(t)

	// foreign_keys(1) makes SQLite enforce owner_id REFERENCES users(id) as Postgres does.
	dsn := filepath.Join(t.TempDir(), "cp.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	store, err := storage.NewSQLStore("sqlite", dsn)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	opts := controlplane.Options{
		ListenAddr:       "127.0.0.1:0",
		AdminToken:       "test-admin-token",
		OIDCIssuer:       oidcURL,
		AllowedAudiences: []string{"agentmesh-audience"},
	}
	srv, err := controlplane.NewServer(opts, store)
	if err != nil {
		t.Fatalf("failed to create control plane: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	return "http://" + srv.Addr(), mintToken, store
}

type tokenResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Role    string `json:"role"`
	OwnerID string `json:"owner_id"`
}

// requestBootstrapToken posts to /user/bootstrap-tokens and returns the status and decoded body.
func requestBootstrapToken(t *testing.T, baseURL, bearer string, payload map[string]interface{}) (int, tokenResponse, string) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/user/bootstrap-tokens", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	var decoded tokenResponse
	if resp.StatusCode == http.StatusCreated {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("failed to decode body %q: %v", raw, err)
		}
	}
	return resp.StatusCode, decoded, string(raw)
}

// TestBootstrapTokenOwnership pins down who ends up owning a token generated through
// the console: the owner defaults to the caller's session and only admins may override it.
func TestBootstrapTokenOwnership(t *testing.T) {
	baseURL, mintToken, store := startTokenTestControlPlane(t)
	ctx := context.Background()

	const (
		aliceSub = "alice-subject-id"
		bobSub   = "bob-subject-id"
	)
	aliceJWT := mintToken(map[string]interface{}{"sub": aliceSub, "email": "alice@example.com"})
	bobJWT := mintToken(map[string]interface{}{"sub": bobSub, "email": "bob@example.com"})

	// Both users must exist in the store before an admin can delegate to them,
	// which happens implicitly on first authenticated call.
	for _, jwt := range []string{aliceJWT, bobJWT} {
		if status, _, body := requestBootstrapToken(t, baseURL, jwt, map[string]interface{}{
			"role": api.RoleNode,
		}); status != http.StatusCreated {
			t.Fatalf("failed to auto-register user: status %d body %q", status, body)
		}
	}

	t.Run("owner defaults to session when omitted", func(t *testing.T) {
		status, res, body := requestBootstrapToken(t, baseURL, aliceJWT, map[string]interface{}{
			"role":        api.RoleNode,
			"description": "no owner supplied",
		})
		if status != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", status, body)
		}
		if res.OwnerID != aliceSub {
			t.Errorf("expected owner %q, got %q", aliceSub, res.OwnerID)
		}
		assertStoredOwner(t, ctx, store, res.ID, aliceSub)
	})

	t.Run("owner may be set explicitly to self", func(t *testing.T) {
		status, res, body := requestBootstrapToken(t, baseURL, aliceJWT, map[string]interface{}{
			"role":     api.RoleNode,
			"owner_id": aliceSub,
		})
		if status != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", status, body)
		}
		if res.OwnerID != aliceSub {
			t.Errorf("expected owner %q, got %q", aliceSub, res.OwnerID)
		}
	})

	t.Run("non-admin cannot issue on behalf of another user", func(t *testing.T) {
		status, _, body := requestBootstrapToken(t, baseURL, aliceJWT, map[string]interface{}{
			"role":     api.RoleNode,
			"owner_id": bobSub,
		})
		if status != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", status, body)
		}
	})

	t.Run("admin may issue on behalf of an existing user", func(t *testing.T) {
		status, res, body := requestBootstrapToken(t, baseURL, "test-admin-token", map[string]interface{}{
			"role":     api.RoleNode,
			"owner_id": bobSub,
		})
		if status != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", status, body)
		}
		if res.OwnerID != bobSub {
			t.Errorf("expected owner %q, got %q", bobSub, res.OwnerID)
		}
		assertStoredOwner(t, ctx, store, res.ID, bobSub)
	})

	t.Run("admin cannot issue on behalf of an unknown user", func(t *testing.T) {
		status, _, body := requestBootstrapToken(t, baseURL, "test-admin-token", map[string]interface{}{
			"role":     api.RoleNode,
			"owner_id": "nobody-has-ever-logged-in-as-this",
		})
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", status, body)
		}
	})

	t.Run("admin token session owns no token", func(t *testing.T) {
		status, res, body := requestBootstrapToken(t, baseURL, "test-admin-token", map[string]interface{}{
			"role": api.RoleNode,
		})
		if status != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", status, body)
		}
		if res.OwnerID != "" {
			t.Errorf("expected no owner, got %q", res.OwnerID)
		}
		assertStoredOwner(t, ctx, store, res.ID, "")
	})

	t.Run("non-admin cannot request router role", func(t *testing.T) {
		status, _, body := requestBootstrapToken(t, baseURL, aliceJWT, map[string]interface{}{
			"role": api.RoleRouter,
		})
		if status != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", status, body)
		}
	})

	t.Run("unauthenticated requests are rejected", func(t *testing.T) {
		status, _, body := requestBootstrapToken(t, baseURL, "not-a-real-token", map[string]interface{}{
			"role": api.RoleNode,
		})
		if status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d: %s", status, body)
		}
	})
}

func assertStoredOwner(t *testing.T, ctx context.Context, store storage.Store, tokenID, wantOwner string) {
	t.Helper()
	stored, err := store.GetBootstrapToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("failed to load token %s: %v", tokenID, err)
	}
	if stored.OwnerID != wantOwner {
		t.Errorf("persisted owner = %q, want %q", stored.OwnerID, wantOwner)
	}
}
