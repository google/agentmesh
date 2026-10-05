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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFileTokenSource(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	p := filepath.Join(dir, "jwt.token")

	if err := os.WriteFile(p, []byte("  test-jwt-token \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := NewFileTokenSource(p)
	got, err := src.FetchToken(ctx)
	if err != nil {
		t.Fatalf("FetchToken: %v", err)
	}
	if got != "test-jwt-token" {
		t.Errorf("got %q, want %q", got, "test-jwt-token")
	}

	if err := os.WriteFile(p, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := src.FetchToken(ctx); err == nil {
		t.Error("expected error for empty token file")
	}

	missing := NewFileTokenSource(filepath.Join(dir, "missing"))
	if _, err := missing.FetchToken(ctx); err == nil {
		t.Error("expected error for missing token file")
	}
}

func TestGCPMetadataTokenSourceAndProbe(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/identity", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor", http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("audience") != "https://cp.example.com" {
			http.Error(w, "wrong audience: "+r.URL.Query().Get("audience"), http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("format") != "full" {
			http.Error(w, "wrong format: "+r.URL.Query().Get("format"), http.StatusBadRequest)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		_, _ = w.Write([]byte("gcp-metadata-id-token\n"))
	})
	mux.HandleFunc("/computeMetadata/v1/instance/service-accounts/default/email", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor", http.StatusForbidden)
			return
		}
		w.Header().Set("Metadata-Flavor", "Google")
		_, _ = w.Write([]byte("worker@proj.iam.gserviceaccount.com"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	endpoint := srv.URL + "/computeMetadata/v1/instance/service-accounts/default/identity"
	src := NewGCPMetadataTokenSource("https://cp.example.com", endpoint, srv.Client())
	tok, err := src.FetchToken(ctx)
	if err != nil {
		t.Fatalf("FetchToken: %v", err)
	}
	if tok != "gcp-metadata-id-token" {
		t.Errorf("got %q, want %q", tok, "gcp-metadata-id-token")
	}

	if !ProbeGCPMetadata(ctx, endpoint, srv.Client()) {
		t.Error("ProbeGCPMetadata returned false for valid mock metadata server")
	}

	// Verify ResolveTokenSource with --cloud-provider=auto and --cloud-provider=gcp.
	for _, provider := range []string{"gcp", "auto"} {
		resolved, continuous, err := ResolveTokenSource(ctx, TokenSourceConfig{
			CloudProvider:    provider,
			Audience:         "https://cp.example.com",
			MetadataEndpoint: endpoint,
			HTTPClient:       srv.Client(),
		})
		if err != nil {
			t.Fatalf("ResolveTokenSource(%s): %v", provider, err)
		}
		if !continuous {
			t.Errorf("ResolveTokenSource(%s) continuous = false, want true", provider)
		}
		got, err := resolved.FetchToken(ctx)
		if err != nil || got != "gcp-metadata-id-token" {
			t.Errorf("ResolveTokenSource(%s) FetchToken = (%q, %v)", provider, got, err)
		}
	}

	// Unsupported provider must fail closed.
	if _, _, err := ResolveTokenSource(ctx, TokenSourceConfig{CloudProvider: "azure"}); err == nil {
		t.Error("expected error for unsupported --cloud-provider=azure")
	}
}

type staticOrErrTokenSource struct {
	token string
	err   error
}

func (s *staticOrErrTokenSource) FetchToken(_ context.Context) (string, error) {
	return s.token, s.err
}

func TestRefreshEnrollmentSendsPlatformJWT(t *testing.T) {
	SetAllowInsecureControlPlane(true)
	ctx := context.Background()

	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	initialExp := time.Now().Add(time.Hour)
	initialBiscuit, _, err := identity.MintBiscuitToken(cpPriv, jwt.MapClaims{"sub": "worker-1"}, nil, pID, initialExp, []string{api.RoleNode}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	var receivedJWT string
	cpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/refresh" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req api.TokenRefreshRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedJWT = req.Jwt
		newExp := time.Now().Add(2 * time.Hour)
		nextBiscuit, _, err := identity.MintBiscuitToken(cpPriv, jwt.MapClaims{"sub": "worker-1"}, nil, pID, newExp, []string{api.RoleNode}, nil, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respBytes, _ := proto.Marshal(&api.TokenRefreshResponse{
			BiscuitToken: nextBiscuit,
			ExpireTime:   timestamppb.New(newExp),
		})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(respBytes)
	}))
	defer cpSrv.Close()

	nStore, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nStore.Close() }()
	privBytes, err := crypto.MarshalPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}
	if err := nStore.SaveKey(privBytes); err != nil {
		t.Fatal(err)
	}
	if err := nStore.SaveControlPlaneURL(cpSrv.URL); err != nil {
		t.Fatal(err)
	}
	if err := nStore.SaveIdentity(initialBiscuit); err != nil {
		t.Fatal(err)
	}
	if err := nStore.SaveIdentityExpiration(initialExp.Unix()); err != nil {
		t.Fatal(err)
	}

	n, err := NewSamNode(Options{
		PrivKey:            privNode,
		Store:              nStore,
		ControlPlanePubKey: cpPub,
		ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
		TokenSource:        &staticOrErrTokenSource{token: "fresh-platform-jwt-1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := n.RefreshEnrollment(ctx); err != nil {
		t.Fatalf("RefreshEnrollment with live TokenSource: %v", err)
	}
	if receivedJWT != "fresh-platform-jwt-1" {
		t.Errorf("received TokenRefreshRequest.jwt = %q, want %q", receivedJWT, "fresh-platform-jwt-1")
	}

	// Transient TokenSource failure falls back to session-backed refresh (empty jwt).
	n.SetTokenSource(&staticOrErrTokenSource{err: errors.New("temporary metadata outage")})
	if err := n.RefreshEnrollment(ctx); err != nil {
		t.Fatalf("RefreshEnrollment with failing TokenSource: %v", err)
	}
	if receivedJWT != "" {
		t.Errorf("expected empty jwt on transient TokenSource failure, got %q", receivedJWT)
	}
}
