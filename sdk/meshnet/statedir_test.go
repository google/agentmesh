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

package meshnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/node"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestWriteAndReadStateDir(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	privBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	tok := mintTestBiscuit(t, cpPriv, pid.String(), api.RoleNode, time.Now().Add(time.Hour))

	recvAt := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	expAt := time.Date(2026, 11, 1, 11, 0, 0, 0, time.UTC)
	want := &api.MemberCredential{
		ControlPlaneUrl: "https://bananas.sam-mesh.dev",
		Biscuit:         tok,
		ExpireTime:      timestamppb.New(expAt),
		TrustedKeys: []*api.TrustedSigningKey{
			{PublicKey: cpPub, ReceiveTime: timestamppb.New(recvAt)},
		},
		RouterAddresses: []string{"/ip4/127.0.0.1/tcp/4001/p2p/" + pid.String()},
		OidcSession: &api.OIDCSession{
			Issuer:       "https://accounts.example.com",
			ClientId:     "meshnet-cli",
			RefreshToken: "rt-initial",
		},
		IssuedUnderKeys: [][]byte{cpPub},
	}

	dir := filepath.Join(t.TempDir(), "state")
	if err := WriteStateDir(dir, privBytes, want); err != nil {
		t.Fatalf("WriteStateDir: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(%s): %v", dir, err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %04o, want 0700", perm)
	}
	for _, name := range []string{StateDirIdentityFile, StateDirCredentialFile} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("Stat(%s): %v", name, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s perm = %04o, want 0600", name, perm)
		}
	}

	gotPriv, gotCred, err := ReadStateDir(dir)
	if err != nil {
		t.Fatalf("ReadStateDir: %v", err)
	}
	if !bytes.Equal(gotPriv, privBytes) {
		t.Errorf("ReadStateDir privKey mismatch")
	}
	if !proto.Equal(gotCred, want) {
		t.Errorf("ReadStateDir credential mismatch:\ngot:  %v\nwant: %v", gotCred, want)
	}

	t.Run("rejects_invalid_private_key", func(t *testing.T) {
		if err := WriteStateDir(t.TempDir(), []byte("not-a-key"), want); err == nil {
			t.Fatal("WriteStateDir accepted invalid private key, want error")
		}
		badDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(badDir, StateDirIdentityFile), []byte("corrupt"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadStateDir(badDir); err == nil {
			t.Fatal("ReadStateDir accepted corrupt identity.key, want error")
		}
	})

	t.Run("rejects_unknown_fields_in_credential_json", func(t *testing.T) {
		badDir := t.TempDir()
		if err := WriteStateDir(badDir, privBytes, want); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(badDir, StateDirCredentialFile), []byte(`{"control_plane_url":"https://example.com","unknown_field":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadStateDir(badDir); err == nil {
			t.Fatal("ReadStateDir accepted unknown field in credential.json, want error")
		}
	})
}

func TestEnrollmentAndRenewal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cp := newFakeControlPlaneHTTP(t)

	t.Run("bootstrap_pending_then_approved", func(t *testing.T) {
		cp.pendingBootstrapPolls.Store(1)
		tokFile := filepath.Join(t.TempDir(), "bootstrap.token")
		if err := os.WriteFile(tokFile, []byte("boot-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stateDir := t.TempDir()
		s := &Server{
			StateDir:           stateDir,
			ControlPlaneURL:    cp.srv.URL,
			BootstrapTokenPath: tokFile,
			AllowInsecure:      true,
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := s.ensureCredential(ctx); err != nil {
			t.Fatalf("ensureCredential: %v", err)
		}
		if len(s.node.GetIdentity()) == 0 {
			t.Fatal("GetIdentity is empty after bootstrap enrollment")
		}
		_, cred, err := ReadStateDir(stateDir)
		if err != nil {
			t.Fatalf("ReadStateDir: %v", err)
		}
		if cred.GetControlPlaneUrl() != cp.srv.URL {
			t.Errorf("ControlPlaneUrl = %q, want %q", cred.GetControlPlaneUrl(), cp.srv.URL)
		}
		if len(cred.GetTrustedKeys()) == 0 {
			t.Error("TrustedKeys not persisted in credential.json")
		}
	})

	t.Run("resume_cached_credential_and_offline_fallback", func(t *testing.T) {
		stateDir := t.TempDir()
		seed := &Server{
			StateDir:        stateDir,
			ControlPlaneURL: cp.srv.URL,
			BootstrapToken:  "boot-secret",
			AllowInsecure:   true,
		}
		if err := seed.ensureCredential(ctx); err != nil {
			t.Fatalf("seed ensureCredential: %v", err)
		}
		if err := seed.Close(); err != nil {
			t.Fatalf("seed.Close: %v", err)
		}
		enrollsBefore := cp.bootstrapEnrolls.Load()
		refreshesBefore := cp.refreshes.Load()

		// 1. Online resume: >5m remaining and valid signing key skips both /refresh and /enroll.
		online := &Server{
			StateDir:      stateDir,
			AllowInsecure: true,
		}
		if err := online.ensureCredential(ctx); err != nil {
			t.Fatalf("online resume ensureCredential: %v", err)
		}
		if err := online.Close(); err != nil {
			t.Fatalf("online.Close: %v", err)
		}
		if cp.bootstrapEnrolls.Load() != enrollsBefore || cp.refreshes.Load() != refreshesBefore {
			t.Errorf("online resume called enroll/refresh (%d/%d), want (%d/%d)",
				cp.bootstrapEnrolls.Load(), cp.refreshes.Load(), enrollsBefore, refreshesBefore)
		}

		// 2. Offline control plane fallback: /keys and /refresh both unavailable, cached credential used.
		cp.failKeys.Store(true)
		cp.failRefresh.Store(true)
		defer func() {
			cp.failKeys.Store(false)
			cp.failRefresh.Store(false)
		}()

		resumed := &Server{
			StateDir:      stateDir,
			AllowInsecure: true,
		}
		t.Cleanup(func() { _ = resumed.Close() })
		if err := resumed.ensureCredential(ctx); err != nil {
			t.Fatalf("resumed ensureCredential with offline CP: %v", err)
		}
		if cp.bootstrapEnrolls.Load() != enrollsBefore {
			t.Errorf("bootstrapEnrolls = %d, want %d (must resume cached credential)", cp.bootstrapEnrolls.Load(), enrollsBefore)
		}
		if resumed.cpURL != cp.srv.URL {
			t.Errorf("resumed.cpURL = %q, want %q", resumed.cpURL, cp.srv.URL)
		}
	})

	t.Run("jwt_path_and_proactive_refresh", func(t *testing.T) {
		jwtFile := filepath.Join(t.TempDir(), "id.jwt")
		if err := os.WriteFile(jwtFile, []byte("jwt-initial\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stateDir := t.TempDir()
		s := &Server{
			StateDir:        stateDir,
			ControlPlaneURL: cp.srv.URL,
			JWTPath:         jwtFile,
			TokenSource: func(context.Context) (string, error) {
				return "jwt-refreshed", nil
			},
			Labels:        map[string]string{"env": "prod"},
			AllowInsecure: true,
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := s.ensureCredential(ctx); err != nil {
			t.Fatalf("ensureCredential(JWT): %v", err)
		}
		firstBiscuit := append([]byte(nil), s.node.GetIdentity()...)
		refreshesBefore := cp.refreshes.Load()

		if err := s.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if cp.refreshes.Load() != refreshesBefore+1 {
			t.Errorf("refreshes = %d, want %d", cp.refreshes.Load(), refreshesBefore+1)
		}
		if bytes.Equal(firstBiscuit, s.node.GetIdentity()) {
			t.Error("expected Refresh to update credential via POST /refresh")
		}
	})

	t.Run("oidc_session_refresh_token_recovery_and_immediate_persistence", func(t *testing.T) {
		priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privBytes, err := crypto.MarshalPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		cpPub, cpPriv := cp.currentKeys()
		expired := mintTestBiscuit(t, cpPriv, pid.String(), api.RoleNode, time.Now().Add(-time.Minute))

		// Reject direct /refresh AND fail /register on the first attempt to prove
		// a rotated one-time refresh_token is persisted BEFORE /register runs.
		cp.failRefresh.Store(true)
		cp.failRegister.Store(true)
		defer func() {
			cp.failRefresh.Store(false)
			cp.failRegister.Store(false)
		}()

		stateDir := t.TempDir()
		err = WriteStateDir(stateDir, privBytes, &api.MemberCredential{
			ControlPlaneUrl: cp.srv.URL,
			Biscuit:         expired,
			ExpireTime:      timestamppb.New(time.Now().Add(-time.Minute)),
			TrustedKeys:     []*api.TrustedSigningKey{{PublicKey: cpPub, ReceiveTime: timestamppb.New(time.Now())}},
			OidcSession: &api.OIDCSession{
				Issuer:       cp.srv.URL,
				ClientId:     "meshnet-test",
				RefreshToken: "rt-old",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		first := &Server{
			StateDir:      stateDir,
			AllowInsecure: true,
		}
		t.Cleanup(func() { _ = first.Close() })
		if err := first.ensureCredential(ctx); err == nil {
			t.Fatal("expected ensureCredential to fail while POST /register is down")
		}
		_, afterFailedRegister, err := ReadStateDir(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		if got := afterFailedRegister.GetOidcSession().GetRefreshToken(); got != "rt-rotated" {
			t.Fatalf("refresh_token after failed /register = %q, want %q (must persist before /register)", got, "rt-rotated")
		}

		// Now bring /register back up: the second attempt uses the persisted
		// "rt-rotated" token (one-time rotation to "rt-rotated-2") and succeeds.
		cp.failRegister.Store(false)
		second := &Server{
			StateDir:      stateDir,
			AllowInsecure: true,
		}
		t.Cleanup(func() { _ = second.Close() })
		if err := second.ensureCredential(ctx); err != nil {
			t.Fatalf("second ensureCredential via persisted rotated refresh_token: %v", err)
		}
		_, updated, err := ReadStateDir(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		if got := updated.GetOidcSession().GetRefreshToken(); got != "rt-rotated-2" {
			t.Errorf("rotated refresh_token after recovery = %q, want %q", got, "rt-rotated-2")
		}
	})

	t.Run("retired_signing_key_returns_ErrCredentialRetired", func(t *testing.T) {
		stateDir := t.TempDir()
		seed := &Server{
			StateDir:        stateDir,
			ControlPlaneURL: cp.srv.URL,
			BootstrapToken:  "boot-secret",
			AllowInsecure:   true,
		}
		if err := seed.ensureCredential(ctx); err != nil {
			t.Fatalf("seed ensureCredential: %v", err)
		}
		if err := seed.Close(); err != nil {
			t.Fatalf("seed.Close: %v", err)
		}

		// Rotate control-plane key completely (dropping old key from KeysResponse).
		cp.rotateKeyHard(t)

		resumed := &Server{
			StateDir:      stateDir,
			AllowInsecure: true,
		}
		t.Cleanup(func() { _ = resumed.Close() })
		err := resumed.ensureCredential(ctx)
		if !errors.Is(err, ErrCredentialRetired) {
			t.Fatalf("ensureCredential err = %v, want ErrCredentialRetired", err)
		}
	})

	t.Run("rejects_non_loopback_plaintext_http_without_AllowInsecure", func(t *testing.T) {
		s := &Server{
			ControlPlaneURL: "http://198.51.100.10:8080",
			BootstrapToken:  "boot-secret",
			AllowInsecure:   false,
		}
		err := s.ensureCredential(ctx)
		if !errors.Is(err, api.ErrInsecureControlPlaneURL) {
			t.Fatalf("ensureCredential err = %v, want api.ErrInsecureControlPlaneURL", err)
		}
	})
}

func TestStateDirLockAndEphemeralTempCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	env := newStartedTestServer(t, ctx)

	t.Run("ephemeral_empty_StateDir_uses_0700_temp_dir_and_cleans_up", func(t *testing.T) {
		emptyTmp := t.TempDir()
		t.Setenv("TMPDIR", emptyTmp)

		failed := &Server{
			ControlPlaneURL: env.cp.srv.URL,
			BootstrapToken:  "wrong-token",
			ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
			AllowInsecure:   true,
		}
		if _, err := failed.Up(ctx); err == nil {
			_ = failed.Close()
			t.Fatal("failed.Up succeeded with wrong token, want error")
		}
		failedEntries, err := os.ReadDir(emptyTmp)
		if err != nil {
			t.Fatalf("ReadDir(TMPDIR) after failed Up: %v", err)
		}
		if len(failedEntries) != 0 {
			t.Fatalf("failed ephemeral Up left %d entries in TMPDIR (%v), want 0", len(failedEntries), failedEntries)
		}

		ephemeral := &Server{
			ControlPlaneURL: env.cp.srv.URL,
			BootstrapToken:  "boot-secret",
			ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
			AllowInsecure:   true,
		}
		st, err := ephemeral.Up(ctx)
		if err != nil {
			t.Fatalf("ephemeral.Up: %v", err)
		}
		if st.PeerID == "" {
			t.Fatal("ephemeral PeerID is empty")
		}

		duringEntries, err := os.ReadDir(emptyTmp)
		if err != nil {
			t.Fatalf("ReadDir(TMPDIR) while running: %v", err)
		}
		if len(duringEntries) != 1 {
			t.Fatalf("TMPDIR entries while running = %d, want 1", len(duringEntries))
		}
		info, err := duringEntries[0].Info()
		if err != nil {
			t.Fatalf("entry.Info: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Fatalf("ephemeral temp dir permissions = %04o, want 0700", perm)
		}

		if err := ephemeral.Close(); err != nil {
			t.Fatalf("ephemeral.Close: %v", err)
		}
		afterEntries, err := os.ReadDir(emptyTmp)
		if err != nil {
			t.Fatalf("ReadDir(TMPDIR) after Close: %v", err)
		}
		if len(afterEntries) != 0 {
			t.Fatalf("ephemeral Server left %d entries in TMPDIR (%v), want 0", len(afterEntries), afterEntries)
		}
	})

	t.Run("concurrent_Servers_on_same_StateDir_return_ErrStateDirLocked", func(t *testing.T) {
		sharedDir := t.TempDir()
		s1 := &Server{
			StateDir:        sharedDir,
			ControlPlaneURL: env.cp.srv.URL,
			BootstrapToken:  "boot-secret",
			ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
			AllowInsecure:   true,
		}
		st1, err := s1.Up(ctx)
		if err != nil {
			t.Fatalf("s1.Up: %v", err)
		}
		t.Cleanup(func() { _ = s1.Close() })

		s2 := &Server{
			StateDir:        sharedDir,
			ControlPlaneURL: env.cp.srv.URL,
			BootstrapToken:  "boot-secret",
			ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
			AllowInsecure:   true,
		}
		if _, err := s2.Up(ctx); !errors.Is(err, ErrStateDirLocked) || !errors.Is(err, node.ErrStoreLocked) {
			_ = s2.Close()
			t.Fatalf("s2.Up on locked StateDir = %v, want ErrStateDirLocked + node.ErrStoreLocked", err)
		}

		if err := s1.Close(); err != nil {
			t.Fatalf("s1.Close: %v", err)
		}

		st2, err := s2.Up(ctx)
		if err != nil {
			t.Fatalf("s2.Up after s1.Close: %v", err)
		}
		t.Cleanup(func() { _ = s2.Close() })
		if st2.PeerID != st1.PeerID {
			t.Fatalf("s2 PeerID = %q, want %q from shared StateDir", st2.PeerID, st1.PeerID)
		}
	})
}

func TestNextRenewalDelay(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	initBackoff := 2 * time.Second

	for _, tc := range []struct {
		name           string
		expTime        time.Time
		failureBackoff time.Duration
		want           time.Duration
	}{
		{
			name:    "unknown_expiry_uses_fallback",
			expTime: time.Time{},
			want:    node.DefaultRenewalFallback,
		},
		{
			name:    "healthy_long_lived_renews_before_expiry_buffer",
			expTime: now.Add(24 * time.Hour),
			want:    24*time.Hour - node.RenewalBuffer,
		},
		{
			name:    "short_lived_renews_at_half_lifetime",
			expTime: now.Add(4 * time.Minute),
			want:    2 * time.Minute,
		},
		{
			name:    "very_short_lived_floored_at_initBackoff",
			expTime: now.Add(500 * time.Millisecond),
			want:    initBackoff,
		},
		{
			name:    "already_expired_without_prior_failure_retries_within_1s",
			expTime: now.Add(-time.Minute),
			want:    time.Second,
		},
		{
			name:           "failure_backoff_honored_before_expiry",
			expTime:        now.Add(2 * time.Minute),
			failureBackoff: 8 * time.Second,
			want:           8 * time.Second,
		},
		{
			name:           "failure_backoff_honored_after_expiry",
			expTime:        now.Add(-time.Minute),
			failureBackoff: 16 * time.Second,
			want:           16 * time.Second,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextRenewalDelay(now, tc.expTime, tc.failureBackoff, initBackoff); got != tc.want {
				t.Fatalf("nextRenewalDelay() = %v, want %v", got, tc.want)
			}
		})
	}
}

type fakeControlPlaneHTTP struct {
	mu                    sync.Mutex
	cpPub                 ed25519.PublicKey
	cpPriv                ed25519.PrivateKey
	routerAddrs           []string
	routers               []*api.RouterInfo
	bannedPeerIDs         []string
	extraDatalogRules     []string
	srv                   *httptest.Server
	failKeys              atomic.Bool
	failRefresh           atomic.Bool
	failRegister          atomic.Bool
	failEnroll            atomic.Bool
	pendingBootstrapPolls atomic.Int32
	bootstrapEnrolls      atomic.Int32
	refreshes             atomic.Int32
}

func newFakeControlPlaneHTTP(t *testing.T) *fakeControlPlaneHTTP {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newFakeControlPlaneHTTPWithKeys(t, pub, priv, nil)
}

func newFakeControlPlaneHTTPWithKeys(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, routerAddrs []string) *fakeControlPlaneHTTP {
	t.Helper()
	f := &fakeControlPlaneHTTP{cpPub: pub, cpPriv: priv, routerAddrs: routerAddrs}
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		if f.failKeys.Load() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		pubKey, privKey := f.currentKeys()
		resp := &api.KeysResponse{PublicKeys: [][]byte{pubKey}}
		if err := api.SignKeysResponse(resp, []ed25519.PrivateKey{privKey}, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeProto(w, resp)
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		addrs := append([]string(nil), f.routerAddrs...)
		routers := append([]*api.RouterInfo(nil), f.routers...)
		banned := append([]string(nil), f.bannedPeerIDs...)
		f.mu.Unlock()
		writeProto(w, &api.ControlPlaneInfoResponse{
			RouterAddresses: addrs,
			Routers:         routers,
			BannedPeerIds:   banned,
		})
	})
	mux.HandleFunc("/policies", func(w http.ResponseWriter, _ *http.Request) {
		compiled, warnings := api.BuildPolicyRules([]*api.PolicyRole{
			{
				Name:            api.RoleNode,
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"*"},
				AllowedPublish:  []string{"*"},
			},
		}, nil)
		if len(warnings) > 0 {
			http.Error(w, strings.Join(warnings, "; "), http.StatusInternalServerError)
			return
		}
		texts := make([]string, 0, len(compiled))
		for _, r := range compiled {
			texts = append(texts, r.Text)
		}
		f.mu.Lock()
		texts = append(texts, f.extraDatalogRules...)
		f.mu.Unlock()
		writeProto(w, &api.PolicyConfigGetResponse{DatalogRules: texts})
	})
	mux.HandleFunc("/revocations", func(w http.ResponseWriter, _ *http.Request) {
		writeProto(w, &api.RevocationsResponse{})
	})
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		if f.failEnroll.Load() {
			http.Error(w, "enroll unavailable", http.StatusServiceUnavailable)
			return
		}
		f.bootstrapEnrolls.Add(1)
		var req api.BootstrapEnrollRequest
		if !readProto(w, r, &req) {
			return
		}
		if req.GetBootstrapToken() != "boot-secret" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		if f.pendingBootstrapPolls.Load() > 0 {
			writeProto(w, &api.BootstrapEnrollResponse{
				Status:              api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
				PollIntervalSeconds: 1,
			})
			return
		}
		pid, err := peer.Decode(req.GetPeerId())
		if err != nil {
			http.Error(w, "invalid peer_id", http.StatusBadRequest)
			return
		}
		pubKey, privKey := f.currentKeys()
		f.mu.Lock()
		addrs := append([]string(nil), f.routerAddrs...)
		f.mu.Unlock()
		exp := f.credentialExpiry()
		tok := mintTestBiscuit(t, privKey, pid.String(), api.RoleNode, exp)
		writeProto(w, &api.BootstrapEnrollResponse{
			Status:                api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
			BiscuitToken:          tok,
			ControlPlanePublicKey: pubKey,
			ExpireTime:            timestamppb.New(exp),
			RouterAddresses:       addrs,
		})
	})
	mux.HandleFunc("/enroll/status", func(w http.ResponseWriter, r *http.Request) {
		rawPeerID := r.URL.Query().Get("peer_id")
		pid, err := peer.Decode(rawPeerID)
		if err != nil {
			http.Error(w, "invalid peer_id", http.StatusBadRequest)
			return
		}
		if f.pendingBootstrapPolls.Add(-1) >= 1 {
			writeProto(w, &api.BootstrapEnrollResponse{
				Status:              api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING,
				PollIntervalSeconds: 1,
			})
			return
		}
		pubKey, privKey := f.currentKeys()
		f.mu.Lock()
		addrs := append([]string(nil), f.routerAddrs...)
		f.mu.Unlock()
		exp := f.credentialExpiry()
		tok := mintTestBiscuit(t, privKey, pid.String(), api.RoleNode, exp)
		writeProto(w, &api.BootstrapEnrollResponse{
			Status:                api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
			BiscuitToken:          tok,
			ControlPlanePublicKey: pubKey,
			ExpireTime:            timestamppb.New(exp),
			RouterAddresses:       addrs,
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if f.failRegister.Load() {
			http.Error(w, "register rejected", http.StatusBadRequest)
			return
		}
		var req api.EnrollRequest
		if !readProto(w, r, &req) {
			return
		}
		pid, err := peer.Decode(req.GetPeerId())
		if err != nil {
			http.Error(w, "invalid peer_id", http.StatusBadRequest)
			return
		}
		pubKey, privKey := f.currentKeys()
		f.mu.Lock()
		addrs := append([]string(nil), f.routerAddrs...)
		f.mu.Unlock()
		exp := f.credentialExpiry()
		tok := mintTestBiscuit(t, privKey, pid.String(), api.RoleNode, exp)
		writeProto(w, &api.EnrollResponse{
			BiscuitToken:          tok,
			ControlPlanePublicKey: pubKey,
			ExpireTime:            timestamppb.New(exp),
			RouterAddresses:       addrs,
		})
	})
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		if f.failRefresh.Load() {
			http.Error(w, "refresh disabled", http.StatusUnauthorized)
			return
		}
		f.refreshes.Add(1)
		var req api.TokenRefreshRequest
		if !readProto(w, r, &req) {
			return
		}
		pid, err := peer.Decode(req.GetPeerId())
		if err != nil {
			http.Error(w, "invalid peer_id", http.StatusBadRequest)
			return
		}
		rawAuth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		biscuitBytes, err := base64.StdEncoding.DecodeString(rawAuth)
		if err != nil {
			http.Error(w, "invalid bearer biscuit", http.StatusUnauthorized)
			return
		}
		pubKey, privKey := f.currentKeys()
		b, err := biscuit.Unmarshal(biscuitBytes)
		if err != nil {
			http.Error(w, "invalid biscuit", http.StatusUnauthorized)
			return
		}
		if _, err := b.Authorizer(pubKey); err != nil {
			http.Error(w, "untrusted biscuit", http.StatusUnauthorized)
			return
		}
		exp := time.Now().Add(2 * time.Hour)
		tok := mintTestBiscuit(t, privKey, pid.String(), api.RoleNode, exp)
		writeProto(w, &api.TokenRefreshResponse{
			BiscuitToken: tok,
			ExpireTime:   timestamppb.New(exp),
		})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         f.srv.URL,
			"token_endpoint": f.srv.URL + "/oidc/token",
		})
	})
	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("grant_type") != "refresh_token" {
			http.Error(w, "bad grant_type", http.StatusUnauthorized)
			return
		}
		var nextRT string
		switch r.FormValue("refresh_token") {
		case "rt-old":
			nextRT = "rt-rotated"
		case "rt-rotated":
			nextRT = "rt-rotated-2"
		default:
			http.Error(w, "bad refresh_token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token":      "oidc-refreshed-id-token",
			"refresh_token": nextRT,
		})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeControlPlaneHTTP) credentialExpiry() time.Time {
	return time.Now().Add(time.Hour)
}

func (f *fakeControlPlaneHTTP) currentKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cpPub, f.cpPriv
}

func (f *fakeControlPlaneHTTP) rotateKeyHard(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.cpPub = pub
	f.cpPriv = priv
	f.mu.Unlock()
}

func readProto(w http.ResponseWriter, r *http.Request, msg proto.Message) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	if err := proto.Unmarshal(body, msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeProto(w http.ResponseWriter, msg proto.Message) {
	raw, err := proto.Marshal(msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(raw)
}

func mintTestBiscuit(t *testing.T, cpPriv ed25519.PrivateKey, peerID, role string, expiry time.Time) []byte {
	t.Helper()
	b := biscuit.NewBuilder(cpPriv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(peerID)}}},
		{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(peerID)}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(role)}}},
		{Predicate: biscuit.Predicate{Name: api.FactEmail, IDs: []biscuit.Term{biscuit.String("alice@example.com")}}},
		{Predicate: biscuit.Predicate{Name: api.FactLabel, IDs: []biscuit.Term{biscuit.String("env"), biscuit.String("prod")}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(expiry)}}},
		api.MarkerFact(api.FactTargetUnrestricted),
	} {
		if err := b.AddAuthorityFact(f); err != nil {
			t.Fatalf("AddAuthorityFact: %v", err)
		}
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	out, err := tok.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return out
}
