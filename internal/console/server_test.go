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

package console

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/version"
	"google.golang.org/protobuf/proto"
)

// startNoOIDCControlPlaneStub serves a /info with no issuer, the
// bootstrap-token-only mode sam-one runs the console in.
func startNoOIDCControlPlaneStub(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		data, err := proto.Marshal(&api.ControlPlaneInfoResponse{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(data)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestNewServerEmbeddedAssets pins the compiled-in frontend path used by
// sam-one and the cmd default: StaticFS serving, SPA fallback, StaticDir
// precedence for live-editing, and the fail-fast when no assets are set.
func TestNewServerEmbeddedAssets(t *testing.T) {
	cpStub := startNoOIDCControlPlaneStub(t)

	t.Run("no assets configured", func(t *testing.T) {
		if _, err := NewServer(Config{ControlPlaneURL: cpStub.URL, AdminToken: "x"}); err == nil {
			t.Fatal("NewServer without StaticDir or StaticFS should fail")
		}
	})

	srv, err := NewServer(Config{
		ControlPlaneURL: cpStub.URL,
		AdminToken:      "x",
		StaticFS:        EmbeddedAssets(),
	})
	if err != nil {
		t.Fatalf("failed to create server with embedded assets: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s failed: %v", path, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("failed to read %s body: %v", path, err)
		}
		return resp.StatusCode, string(body)
	}

	if code, body := get("/"); code != http.StatusOK || !strings.Contains(body, "<html") {
		t.Errorf("GET / = %d, want 200 with the embedded index.html", code)
	}
	if code, _ := get("/app.js"); code != http.StatusOK {
		t.Errorf("GET /app.js = %d, want 200", code)
	}
	// SPA fallback: unknown paths serve index.html.
	if code, body := get("/some/client/route"); code != http.StatusOK || !strings.Contains(body, "<html") {
		t.Errorf("GET /some/client/route = %d, want 200 with index.html fallback", code)
	}

	t.Run("StaticDir wins over StaticFS", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("live-edited marker"), 0o644); err != nil {
			t.Fatalf("failed to write marker: %v", err)
		}
		srv, err := NewServer(Config{
			ControlPlaneURL: cpStub.URL,
			AdminToken:      "x",
			StaticDir:       dir,
			StaticFS:        EmbeddedAssets(),
		})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		ts := httptest.NewServer(srv.Handler())
		defer ts.Close()
		resp, err := http.Get(ts.URL + "/")
		if err != nil {
			t.Fatalf("GET / failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !strings.Contains(string(body), "live-edited marker") {
			t.Errorf("StaticDir did not take precedence over StaticFS: %q", body)
		}
	})
}

func TestNewServer_OIDCAutoDiscovery(t *testing.T) {
	// 1. Generate a mock RSA key for OIDC signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// 2. Start mock control plane + OIDC server
	var serverURL string
	mux := http.NewServeMux()

	// Mock Control Plane /info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := &api.ControlPlaneInfoResponse{
			OidcIssuer: serverURL,
			ClientId:   "mock-console-client",
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	// Mock OIDC Discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]any{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/auth",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/keys",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})

	// Mock OIDC JWKS keys endpoint
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		// Minimum empty JWKS to satisfy client discovery
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"n":   privateKey.N.String(),
					"e":   "AQAB",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mockSrv := httptest.NewServer(mux)
	defer mockSrv.Close()
	serverURL = mockSrv.URL

	// 3. Instantiate console Server with auto-discovery flags (empty issuer and client ID)
	cfg := Config{
		ControlPlaneURL: serverURL,
		AdminToken:      "test-admin-token",
		StaticDir:       t.TempDir(),
	}

	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 4. Verify OIDC parameters were discovered and set
	if srv.provider == nil {
		t.Fatal("provider config was not initialized")
	}
	if srv.clientID != "mock-console-client" {
		t.Errorf("expected clientID 'mock-console-client', got '%s'", srv.clientID)
	}
	if srv.provider.Endpoint().AuthURL != serverURL+"/auth" {
		t.Errorf("expected AuthURL '%s', got '%s'", serverURL+"/auth", srv.provider.Endpoint().AuthURL)
	}
}

// TestNewServer_OIDCDiscoveryRetriesTransientFailure guards against a real
// deployment race: if the OIDC issuer (e.g. Dex) is still starting up when
// sam-console boots, discovery must retry instead of permanently disabling
// login for the life of the pod (console's /info reports healthy either way,
// so Kubernetes never restarts it to retry on its own).
func TestNewServer_OIDCDiscoveryRetriesTransientFailure(t *testing.T) {
	var attempts int32
	var serverURL string
	mux := http.NewServeMux()

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := &api.ControlPlaneInfoResponse{
			OidcIssuer: serverURL,
			ClientId:   "mock-console-client",
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			http.Error(w, "upstream connect error", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/auth",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/keys",
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{}})
	})

	mockSrv := httptest.NewServer(mux)
	defer mockSrv.Close()
	serverURL = mockSrv.URL

	srv, err := NewServer(Config{
		ControlPlaneURL: serverURL,
		AdminToken:      "test-admin-token",
		StaticDir:       t.TempDir(),
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if srv.provider == nil {
		t.Fatal("expected OIDC discovery to succeed after transient failures, provider is nil")
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("expected discovery to take 3 attempts, got %d", got)
	}
}

func TestDiscoverProviderWithRetry(t *testing.T) {
	t.Run("succeeds after transient failures", func(t *testing.T) {
		var attempts int32
		mux := http.NewServeMux()
		srv := httptest.NewServer(mux)
		defer srv.Close()
		issuer := srv.URL

		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&attempts, 1) < 3 {
				http.Error(w, "upstream connect error", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   issuer,
				"jwks_uri": issuer + "/keys",
			})
		})

		if _, err := discoverProviderWithRetry(context.Background(), issuer, 5, time.Millisecond, 5*time.Millisecond); err != nil {
			t.Fatalf("expected discovery to eventually succeed, got: %v", err)
		}
		if got := atomic.LoadInt32(&attempts); got != 3 {
			t.Errorf("expected 3 attempts, got %d", got)
		}
	})

	t.Run("gives up after max attempts", func(t *testing.T) {
		mux := http.NewServeMux()
		srv := httptest.NewServer(mux)
		defer srv.Close()

		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "always down", http.StatusServiceUnavailable)
		})

		if _, err := discoverProviderWithRetry(context.Background(), srv.URL, 3, time.Millisecond, 5*time.Millisecond); err == nil {
			t.Fatal("expected discovery to fail after exhausting retries")
		}
	})

	// A hung connection (issuer accepts but never responds) must not block
	// discovery forever: the client attached via oidc.ClientContext needs its
	// own timeout, since neither the retry loop nor context.Background() bound
	// a single attempt's duration on their own.
	t.Run("does not hang on an unresponsive issuer", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn // accepted but deliberately never responds, to simulate a hang
			}
		}()

		client := &http.Client{Timeout: 50 * time.Millisecond}
		ctx := oidc.ClientContext(context.Background(), client)

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = discoverProviderWithRetry(ctx, "http://"+ln.Addr().String(), 2, time.Millisecond, 5*time.Millisecond)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("discoverProviderWithRetry hung on an unresponsive issuer instead of timing out")
		}
	})
}

// TestNewServer_BasePathServesBothPrefixes: with a BasePath the console must answer both the
// prefixed URLs it hands out (so a proxy can forward /console/* untouched) and the root.
func TestNewServer_BasePathServesBothPrefixes(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // empty /info: no OIDC, which the console tolerates
	}))
	defer controlPlane.Close()

	srv, err := NewServer(Config{
		ControlPlaneURL: controlPlane.URL,
		AdminToken:      "test-admin-token",
		StaticDir:       t.TempDir(),
		BasePath:        "/console",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	console := httptest.NewServer(srv.Handler())
	defer console.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for path, want := range map[string]int{
		"/info":         http.StatusOK,
		"/console/info": http.StatusOK,
	} {
		resp, err := client.Get(console.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s: got %d, want %d", path, resp.StatusCode, want)
		}
	}

	// ServeMux sends the bare base path to the subtree root. Which 3xx it picks
	// is the standard library's business and has changed between Go releases;
	// what the console depends on is landing on /console/.
	resp, err := client.Get(console.URL + "/console")
	if err != nil {
		t.Fatalf("GET /console: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		t.Errorf("GET /console: got %d, want a redirect to the subtree root", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/console/" {
		t.Errorf("GET /console: Location = %q, want %q", got, "/console/")
	}
}

// The console holds mesh admin credentials, so a pasted token must land in an
// httpOnly cookie rather than anywhere JavaScript can read it.
func TestHandleTokenLogin(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // empty /info: no OIDC, which the console tolerates
	}))
	defer controlPlane.Close()

	srv, err := NewServer(Config{
		ControlPlaneURL: controlPlane.URL,
		AdminToken:      "test-admin-token",
		StaticDir:       t.TempDir(),
		BasePath:        "/console",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	console := httptest.NewServer(srv.Handler())
	defer console.Close()

	post := func(t *testing.T, contentType, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, console.URL+"/console/auth/token", strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := console.Client().Do(req)
		if err != nil {
			t.Fatalf("POST /console/auth/token: %v", err)
		}
		return resp
	}

	sessionCookie := func(resp *http.Response) *http.Cookie {
		for _, c := range resp.Cookies() {
			if c.Name == "sam_session" {
				return c
			}
		}
		return nil
	}

	t.Run("sets an httpOnly session cookie", func(t *testing.T) {
		resp := post(t, "application/json", `{"token":"test-admin-token"}`)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("got status %d, want %d", resp.StatusCode, http.StatusNoContent)
		}
		c := sessionCookie(resp)
		if c == nil {
			t.Fatal("no sam_session cookie set")
		}
		if c.Value != "test-admin-token" {
			t.Errorf("cookie value = %q, want %q", c.Value, "test-admin-token")
		}
		if !c.HttpOnly {
			t.Error("cookie is not HttpOnly, so an XSS could read the mesh admin token")
		}
		if c.Path != "/console/" {
			t.Errorf("cookie path = %q, want %q", c.Path, "/console/")
		}
	})

	t.Run("strips a Bearer prefix", func(t *testing.T) {
		resp := post(t, "application/json", `{"token":"  BeArEr   test-admin-token  "}`)
		defer func() { _ = resp.Body.Close() }()
		c := sessionCookie(resp)
		if c == nil || c.Value != "test-admin-token" {
			t.Fatalf("cookie = %+v, want value %q", c, "test-admin-token")
		}
	})

	// An HTML form can only send these content types, so rejecting them is what
	// stops a cross-origin POST from planting an attacker's session cookie.
	t.Run("rejects form content types", func(t *testing.T) {
		for _, ct := range []string{"application/x-www-form-urlencoded", "text/plain", "multipart/form-data"} {
			resp := post(t, ct, `{"token":"test-admin-token"}`)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Errorf("Content-Type %s: got status %d, want %d", ct, resp.StatusCode, http.StatusUnsupportedMediaType)
			}
			if c := sessionCookie(resp); c != nil {
				t.Errorf("Content-Type %s: session cookie was set anyway", ct)
			}
		}
	})

	t.Run("rejects bad tokens", func(t *testing.T) {
		for name, body := range map[string]string{
			"empty":                `{"token":""}`,
			"whitespace only":      `{"token":"   "}`,
			"bearer with no token": `{"token":"Bearer "}`,
			"not json":             `nonsense`,
			"cookie separator":     `{"token":"abc;def"}`,
			"control char":         `{"token":"abc\ndef"}`,
		} {
			resp := post(t, "application/json", body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s: got status %d, want %d", name, resp.StatusCode, http.StatusBadRequest)
			}
			if c := sessionCookie(resp); c != nil {
				t.Errorf("%s: session cookie was set anyway", name)
			}
		}
	})

	t.Run("rejects GET", func(t *testing.T) {
		resp, err := console.Client().Get(console.URL + "/console/auth/token")
		if err != nil {
			t.Fatalf("GET /console/auth/token: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})
}

// A deletion cookie must carry the same attributes as the cookie it clears,
// or browsers may keep the original session cookie alive after logout.
func TestHandleLogoutCookieAttributes(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer controlPlane.Close()

	srv, err := NewServer(Config{
		ControlPlaneURL: controlPlane.URL,
		AdminToken:      "test-admin-token",
		StaticDir:       t.TempDir(),
		BasePath:        "/console",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/console/auth/logout", nil)
	rec := httptest.NewRecorder()
	srv.HandleLogout(rec, req)

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sam_session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("logout did not set a sam_session deletion cookie")
	}
	if cookie.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative to delete the cookie", cookie.MaxAge)
	}
	if !cookie.HttpOnly {
		t.Error("deletion cookie is not HttpOnly, unlike the session cookie it clears")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax to match the session cookie", cookie.SameSite)
	}
	if cookie.Path != "/console/" {
		t.Errorf("cookie path = %q, want %q", cookie.Path, "/console/")
	}
}

// BasePath is concatenated into cookie paths, redirect URLs and mux patterns, so malformed
// flag values (trailing slash, missing leading slash) must be normalized where the flag is read.
func TestNormalizeBasePath(t *testing.T) {
	for input, want := range map[string]string{
		"":               "",
		"/":              "",
		"/console":       "/console",
		"/console/":      "/console",
		"console":        "/console",
		"console//":      "/console",
		"//console":      "/console",
		"/console//sub/": "/console/sub",
	} {
		if got := NormalizeBasePath(input); got != want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestConsoleCSRFAndSecurityHeaders(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info" {
			data, _ := proto.Marshal(&api.ControlPlaneInfoResponse{})
			w.Header().Set("Content-Type", "application/x-protobuf")
			_, _ = w.Write(data)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer controlPlane.Close()

	srv, err := NewServer(Config{
		ControlPlaneURL: controlPlane.URL,
		AdminToken:      "test-admin-token",
		StaticFS:        EmbeddedAssets(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	console := httptest.NewServer(srv.Handler())
	defer console.Close()

	// 1. Check anti-clickjacking headers on GET /
	getResp, err := http.Get(console.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	_ = getResp.Body.Close()
	if got := getResp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := getResp.Header.Get("Content-Security-Policy"); got != "frame-ancestors 'none'" {
		t.Errorf("Content-Security-Policy = %q, want frame-ancestors 'none'", got)
	}

	// 2. Cross-origin cookie-authenticated POST /api/policies must be rejected with 403
	crossReq, _ := http.NewRequest(http.MethodPost, console.URL+"/api/policies", strings.NewReader(`{}`))
	crossReq.Header.Set("Content-Type", "application/json")
	crossReq.Header.Set("Origin", "https://evil.example.com")
	crossReq.AddCookie(&http.Cookie{Name: "sam_session", Value: "test-admin-token"})
	crossResp, err := http.DefaultClient.Do(crossReq)
	if err != nil {
		t.Fatalf("POST /api/policies: %v", err)
	}
	_ = crossResp.Body.Close()
	if crossResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST /api/policies got %d, want 403", crossResp.StatusCode)
	}

	// 3. HTML form Content-Type on cookie-authenticated POST /api/* must be rejected with 415
	formReq, _ := http.NewRequest(http.MethodPost, console.URL+"/api/admin/enrollments/123/approve", strings.NewReader("a=b"))
	formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formReq.AddCookie(&http.Cookie{Name: "sam_session", Value: "test-admin-token"})
	formResp, err := http.DefaultClient.Do(formReq)
	if err != nil {
		t.Fatalf("POST /api/admin/enrollments/123/approve: %v", err)
	}
	_ = formResp.Body.Close()
	if formResp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("form POST /api/* got %d, want 415", formResp.StatusCode)
	}

	// 4. Same-origin JSON POST /api/policies succeeds
	sameReq, _ := http.NewRequest(http.MethodPost, console.URL+"/api/policies", strings.NewReader(`{}`))
	sameReq.Header.Set("Content-Type", "application/json")
	sameReq.Header.Set("Origin", console.URL)
	sameReq.Header.Set("Sec-Fetch-Site", "same-origin")
	sameReq.AddCookie(&http.Cookie{Name: "sam_session", Value: "test-admin-token"})
	sameResp, err := http.DefaultClient.Do(sameReq)
	if err != nil {
		t.Fatalf("same-origin POST /api/policies: %v", err)
	}
	_ = sameResp.Body.Close()
	if sameResp.StatusCode != http.StatusOK {
		t.Errorf("same-origin POST /api/policies got %d, want 200", sameResp.StatusCode)
	}
}

// TestNewServer_StampsVersionIntoIndex: every path that serves index.html must carry the
// build version, or the sidebar shows the raw placeholder.
func TestNewServer_StampsVersionIntoIndex(t *testing.T) {
	previous := version.Version
	version.Version = "v9.9.9-test"
	t.Cleanup(func() { version.Version = previous })

	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // empty /info: no OIDC, which the console tolerates
	}))
	defer controlPlane.Close()

	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("<span>"+versionPlaceholder+"</span>"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Config{
		ControlPlaneURL: controlPlane.URL,
		AdminToken:      "test-admin-token",
		StaticDir:       staticDir,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	console := httptest.NewServer(srv.Handler())
	defer console.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, path := range []string{"/", "/index.html", "/some/spa/route"} {
		resp, err := client.Get(console.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "<span>v9.9.9-test</span>" {
			t.Errorf("GET %s: got %d %q, want 200 with the stamped version", path, resp.StatusCode, body)
		}
	}
}
