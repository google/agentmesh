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
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// biscuitExpiration reads the expiration() authority fact out of a minted token.
func biscuitExpiration(t *testing.T, tokenBytes []byte, cpPubKey ed25519.PublicKey, timeout time.Duration) time.Time {
	t.Helper()

	b, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		t.Fatalf("malformed biscuit: %v", err)
	}
	authorizer, err := b.Authorizer(cpPubKey, identity.AuthorizerOptions(timeout)...)
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	authorizer.AddPolicy(api.AllowIfTruePolicy)
	if err := authorizer.Authorize(); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	rule, err := parser.FromStringRule(fmt.Sprintf(`get_exp($e) <- %s($e)`, api.FactExpiration))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := authorizer.Query(rule)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(facts) != 1 || len(facts[0].IDs) != 1 {
		t.Fatalf("expected exactly one expiration fact, got %v", facts)
	}
	date, ok := facts[0].IDs[0].(biscuit.Date)
	if !ok {
		t.Fatalf("expiration term is %T, want biscuit.Date", facts[0].IDs[0])
	}
	return time.Time(date)
}

// registerNode enrolls a fresh peer over /register and returns its keys and the response.
func registerNode(t *testing.T, cpURL, jwtToken string) (crypto.PrivKey, peer.ID, *api.EnrollResponse) {
	t.Helper()

	priv, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	ts, sig := registerPoP(t, priv, peerID.String())
	reqData, err := proto.Marshal(&api.EnrollRequest{
		Jwt:                jwtToken,
		PeerId:             peerID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(cpURL+"/register", "application/x-protobuf", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("/register failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/register status %s: %s", resp.Status, string(body))
	}

	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollResp); err != nil {
		t.Fatalf("unmarshal EnrollResponse: %v", err)
	}
	return priv, peerID, &enrollResp
}

// refreshNode drives /refresh with a signed challenge and returns the new token.
func refreshNode(t *testing.T, cpURL string, priv crypto.PrivKey, currentBiscuit []byte) *api.TokenRefreshResponse {
	t.Helper()

	resp := postRefresh(t, cpURL, priv, currentBiscuit, "")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /refresh body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/refresh status %s: %s", resp.Status, string(body))
	}

	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(body, &refreshResp); err != nil {
		t.Fatalf("unmarshal TokenRefreshResponse: %v", err)
	}
	return &refreshResp
}

// refreshStatus drives /refresh like refreshNode but returns the HTTP status
// instead of failing on a non-200, for tests that expect a refusal.
func refreshStatus(t *testing.T, cpURL string, priv crypto.PrivKey, currentBiscuit []byte) int {
	t.Helper()
	code, _ := refreshAs(t, cpURL, priv, currentBiscuit, "")
	return code
}

// refreshAs drives /refresh signing the challenge with priv and sending peerID
// in the body, and returns the HTTP status and body without judging them.
func refreshAs(t *testing.T, cpURL string, priv crypto.PrivKey, currentBiscuit []byte, peerID string) (int, []byte) {
	t.Helper()
	resp := postRefresh(t, cpURL, priv, currentBiscuit, peerID)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /refresh body: %v", err)
	}
	return resp.StatusCode, body
}

// postRefresh posts a signed TokenRefreshRequest for priv's peer. peerID, when
// non-empty, is sent in the request body's peer_id field.
func postRefresh(t *testing.T, cpURL string, priv crypto.PrivKey, currentBiscuit []byte, peerID string) *http.Response {
	t.Helper()

	timestamp := time.Now().UnixMilli()
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := priv.Sign(api.RefreshChallenge(pid.String(), timestamp))
	if err != nil {
		t.Fatal(err)
	}
	reqData, err := proto.Marshal(&api.TokenRefreshRequest{
		ChallengeUnixMs:    timestamp,
		ChallengeSignature: sig,
		PeerId:             peerID,
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, cpURL+"/refresh", bytes.NewReader(reqData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(currentBiscuit))

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("/refresh failed: %v", err)
	}
	return resp
}

// assertNear fails unless got is within a second of want, absorbing the
// whole-second resolution of Biscuit date terms and the minting round trip.
func assertNear(t *testing.T, what string, got, want time.Time) {
	t.Helper()
	if skew := got.Sub(want); skew < -2*time.Second || skew > 2*time.Second {
		t.Errorf("%s = %v, want ~%v (skew %v)", what, got.UTC(), want.UTC(), skew)
	}
}

// TestBiscuitExpiryIsCappedByItsVoucher pins the rule that a biscuit never
// outlives whatever authorized it: the OIDC ID token on interactive enrollment,
// and the recorded OIDC session on refresh (where no live token is presented).
// The configured --biscuit-ttl is a ceiling, never a floor.
func TestBiscuitExpiryIsCappedByItsVoucher(t *testing.T) {
	issuer, mintToken := startCustomMockOIDC(t)

	newJWT := func(oidcTTL time.Duration) string {
		return mintToken(map[string]interface{}{
			"sub":    "ttl-test",
			"groups": []string{"users"},
			"exp":    time.Now().Add(oidcTTL).Unix(),
		})
	}

	// Each case gets its own server with BiscuitTTL set before Start(). Sharing
	// one server and mutating config after Serve() races with HandleRegister
	// and lets a previous subtest's TTL leak into the next.
	start := func(t *testing.T, ttl time.Duration) (*Server, storage.Store, string) {
		t.Helper()
		srv, store, cpURL := setupTestServer(t, issuer, func(o *Options) {
			o.BiscuitTTL = ttl
			o.BiscuitTimeout = 5 * time.Second
		})
		t.Cleanup(func() {
			_ = srv.Close()
			_ = store.Close()
		})
		if err := store.SaveMeshPolicy(context.Background(), []*api.PolicyRole{}, []*api.PolicyBinding{
			{Role: api.RoleNode, Members: []string{"group:users"}},
		}); err != nil {
			t.Fatal(err)
		}
		return srv, store, cpURL
	}

	t.Run("register clamps to the OIDC token when it expires first", func(t *testing.T) {
		srv, _, cpURL := start(t, 24*time.Hour)
		oidcExpiry := time.Now().Add(10 * time.Minute)

		_, _, resp := registerNode(t, cpURL, newJWT(10*time.Minute))
		cpPubKey := ed25519.PublicKey(resp.ControlPlanePublicKey)

		assertNear(t, "biscuit expiration()", biscuitExpiration(t, resp.BiscuitToken, cpPubKey, srv.config.BiscuitTimeout), oidcExpiry)
		assertNear(t, "EnrollResponse.expire_time", resp.GetExpireTime().AsTime(), oidcExpiry)
	})

	t.Run("register uses the configured TTL when it expires first", func(t *testing.T) {
		srv, _, cpURL := start(t, 5*time.Minute)
		want := time.Now().Add(5 * time.Minute)

		_, _, resp := registerNode(t, cpURL, newJWT(time.Hour))
		cpPubKey := ed25519.PublicKey(resp.ControlPlanePublicKey)

		assertNear(t, "biscuit expiration()", biscuitExpiration(t, resp.BiscuitToken, cpPubKey, srv.config.BiscuitTimeout), want)
		assertNear(t, "EnrollResponse.expire_time", resp.GetExpireTime().AsTime(), want)
	})

	t.Run("refresh clamps to the end of the OIDC session", func(t *testing.T) {
		srv, store, cpURL := start(t, 24*time.Hour)
		priv, peerID, resp := registerNode(t, cpURL, newJWT(time.Hour))
		cpPubKey := ed25519.PublicKey(resp.ControlPlanePublicKey)

		// Wind the 90-day session down to its last 10 minutes.
		sessionEnd := time.Now().Add(10 * time.Minute)
		record, err := store.GetNode(context.Background(), peerID.String())
		if err != nil {
			t.Fatal(err)
		}
		record.ExpiresAt = sessionEnd
		if err := store.EnrollNode(context.Background(), record); err != nil {
			t.Fatal(err)
		}

		refreshed := refreshNode(t, cpURL, priv, resp.BiscuitToken)
		assertNear(t, "refreshed biscuit expiration()", biscuitExpiration(t, refreshed.BiscuitToken, cpPubKey, srv.config.BiscuitTimeout), sessionEnd)
		assertNear(t, "TokenRefreshResponse.expire_time", refreshed.GetExpireTime().AsTime(), sessionEnd)
	})

	t.Run("refresh uses the configured TTL when the session never expires", func(t *testing.T) {
		srv, store, cpURL := start(t, 30*time.Minute)
		priv, peerID, resp := registerNode(t, cpURL, newJWT(time.Hour))
		cpPubKey := ed25519.PublicKey(resp.ControlPlanePublicKey)

		// Bootstrap-style record: no session deadline at all.
		record, err := store.GetNode(context.Background(), peerID.String())
		if err != nil {
			t.Fatal(err)
		}
		record.ExpiresAt = time.Time{}
		if err := store.EnrollNode(context.Background(), record); err != nil {
			t.Fatal(err)
		}

		want := time.Now().Add(30 * time.Minute)
		refreshed := refreshNode(t, cpURL, priv, resp.BiscuitToken)
		assertNear(t, "refreshed biscuit expiration()", biscuitExpiration(t, refreshed.BiscuitToken, cpPubKey, srv.config.BiscuitTimeout), want)
	})
}
