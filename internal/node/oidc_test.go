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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func useEphemeralOIDCPort(t *testing.T) {
	t.Helper()
	orig := oidcLoopbackPorts
	oidcLoopbackPorts = []string{"0"}
	t.Cleanup(func() { oidcLoopbackPorts = orig })
}

func TestInteractiveLogin(t *testing.T) {
	useEphemeralOIDCPort(t)
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_TTY", "")

	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" {
			http.Error(w, "Invalid grant_type", http.StatusBadRequest)
			return
		}
		if r.FormValue("code") != "dev_code_123" {
			http.Error(w, "Invalid code", http.StatusBadRequest)
			return
		}
		if r.FormValue("code_verifier") == "" {
			http.Error(w, "Missing code_verifier", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"access_token": "access_token_xyz",
			"id_token":     "id_token_abc",
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Mock openBrowser to simulate the user authorizing in the browser
	originalOpenBrowser := openBrowserFunc
	openBrowserFunc = func(urlStr string) error {
		u, _ := url.Parse(urlStr)
		redirectURI := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")

		go func() {
			time.Sleep(100 * time.Millisecond)
			if resp, gErr := http.Get(redirectURI + "?code=dev_code_123&state=" + state); gErr == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	defer func() { openBrowserFunc = originalOpenBrowser }()

	token, err := node.InteractiveLogin(ctx, "http://auth.example.com/auth", server.URL+"/token", "client_id_test", "agentmesh-e2e", false, false)
	if err != nil {
		t.Fatalf("InteractiveLogin failed: %v", err)
	}

	if token != "id_token_abc" {
		t.Errorf("Expected token 'id_token_abc', got '%s'", token)
	}
}

func TestDiscoverEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 "http://" + r.Host,
			"token_endpoint":         "http://" + r.Host + "/token",
			"authorization_endpoint": "http://" + r.Host + "/auth",
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond}
	ctx := context.Background()

	tokenURL, authURL, err := node.DiscoverEndpoints(ctx, server.URL)
	if err != nil {
		t.Fatalf("DiscoverEndpoints failed: %v", err)
	}

	if tokenURL != server.URL+"/token" {
		t.Errorf("Expected tokenURL %s, got %s", server.URL+"/token", tokenURL)
	}
	if authURL != server.URL+"/auth" {
		t.Errorf("Expected authURL %s, got %s", server.URL+"/auth", authURL)
	}
}

func TestDiscoverEndpointsWithDevice(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                        "http://" + r.Host,
			"token_endpoint":                "http://" + r.Host + "/token",
			"authorization_endpoint":        "http://" + r.Host + "/auth",
			"device_authorization_endpoint": "http://" + r.Host + "/device",
		}); err != nil {
			t.Errorf("Failed to encode response: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond}
	ctx := context.Background()

	endpoints, err := node.DiscoverEndpointsWithDevice(ctx, server.URL)
	if err != nil {
		t.Fatalf("DiscoverEndpointsWithDevice failed: %v", err)
	}

	if endpoints.TokenURL != server.URL+"/token" {
		t.Errorf("Expected tokenURL %s, got %s", server.URL+"/token", endpoints.TokenURL)
	}
	if endpoints.AuthURL != server.URL+"/auth" {
		t.Errorf("Expected authURL %s, got %s", server.URL+"/auth", endpoints.AuthURL)
	}
	if endpoints.DeviceAuthURL != server.URL+"/device" {
		t.Errorf("Expected deviceAuthURL %s, got %s", server.URL+"/device", endpoints.DeviceAuthURL)
	}
}

// TestDiscoverEndpointsDoesNotHangOnUnresponsiveIssuer guards against an
// unbounded hang: DiscoverEndpoints/DiscoverTokenURL used to call
// oidc.NewProvider with no client timeout, so an issuer that accepts a
// connection but never responds could block "join"/"run --join" forever.
func TestDiscoverEndpointsDoesNotHangOnUnresponsiveIssuer(t *testing.T) {
	origTimeout := oidcDiscoveryTimeout
	oidcDiscoveryTimeout = 50 * time.Millisecond
	defer func() { oidcDiscoveryTimeout = origTimeout }()

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

	node := &AgentMeshNode{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := node.DiscoverEndpoints(context.Background(), "http://"+ln.Addr().String()); err == nil {
			t.Error("expected DiscoverEndpoints to fail against an unresponsive issuer")
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("DiscoverEndpoints hung on an unresponsive issuer instead of timing out")
	}
}

func TestInteractiveLoginWithRefresh(t *testing.T) {
	useEphemeralOIDCPort(t)
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_TTY", "")

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" {
			http.Error(w, "Invalid grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "access_token_xyz",
			"id_token":      "id_token_abc",
			"refresh_token": "refresh_token_123",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Initialize Store
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	node := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond, Store: store}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	originalOpenBrowser := openBrowserFunc
	openBrowserFunc = func(urlStr string) error {
		u, _ := url.Parse(urlStr)
		redirectURI := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")

		// Verify offline_access scope and prompt are present
		scope := u.Query().Get("scope")
		if !strings.Contains(scope, "offline_access") {
			t.Errorf("Expected scope to contain 'offline_access', got %q", scope)
		}
		if u.Query().Get("access_type") != "offline" {
			t.Errorf("Expected access_type to be 'offline', got %q", u.Query().Get("access_type"))
		}

		go func() {
			time.Sleep(100 * time.Millisecond)
			if resp, gErr := http.Get(redirectURI + "?code=dev_code_123&state=" + state); gErr == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	defer func() { openBrowserFunc = originalOpenBrowser }()

	token, err := node.InteractiveLogin(ctx, "http://auth.example.com/auth", server.URL+"/token", "client_id_test", "agentmesh-e2e", true, false)
	if err != nil {
		t.Fatalf("InteractiveLogin failed: %v", err)
	}

	if token != "id_token_abc" {
		t.Errorf("Expected token 'id_token_abc', got '%s'", token)
	}

	// Verify refresh token is saved in the database
	savedRefresh, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("Failed to load refresh token from store: %v", err)
	}
	if savedRefresh != "refresh_token_123" {
		t.Errorf("Expected saved refresh token 'refresh_token_123', got '%s'", savedRefresh)
	}
}

func TestInteractiveLoginWithDeviceAuth_Headless(t *testing.T) {
	t.Setenv("SSH_CLIENT", "1")
	t.Setenv("SSH_TTY", "")

	mux := http.NewServeMux()

	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("client_id") != "client_id_test" {
			http.Error(w, "Invalid client_id", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "dev_code_1",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://example.com/device",
			"verification_uri_complete": "https://example.com/device?user_code=ABCD-EFGH",
			"expires_in":                60,
			"interval":                  1,
		})
	})

	pollCount := 0
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			http.Error(w, "Invalid grant_type", http.StatusBadRequest)
			return
		}
		pollCount++
		w.Header().Set("Content-Type", "application/json")
		if pollCount < 2 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "authorization_pending",
				"error_description": "waiting",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token":      "id_token_from_device",
			"refresh_token": "refresh_from_device",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	node := &AgentMeshNode{Store: store}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	originalOpenBrowser := openBrowserFunc
	openBrowserFunc = func(_ string) error {
		t.Error("openBrowser should not be called when device flow is used")
		return nil
	}
	defer func() { openBrowserFunc = originalOpenBrowser }()

	token, err := node.InteractiveLoginWithDeviceAuth(
		ctx,
		"http://auth.example.com/auth",
		server.URL+"/token",
		server.URL+"/device",
		"client_id_test",
		"agentmesh-e2e",
		true,
		true,
	)
	if err != nil {
		t.Fatalf("InteractiveLoginWithDeviceAuth failed: %v", err)
	}
	if token != "id_token_from_device" {
		t.Fatalf("Expected id_token_from_device, got %q", token)
	}

	savedRefresh, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("Failed to load refresh token: %v", err)
	}
	if savedRefresh != "refresh_from_device" {
		t.Fatalf("Expected refresh_from_device, got %q", savedRefresh)
	}
}

// TestInteractiveLoginBrowserFailFallsBackToDevice verifies that in an
// interactive (non-headless) flow, if the browser cannot be opened, Agent Mesh falls
// back to the device authorization flow when the provider advertises one,
// instead of leaving the user to paste a callback code.
func TestInteractiveLoginBrowserFailFallsBackToDevice(t *testing.T) {
	useEphemeralOIDCPort(t)
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_TTY", "")

	mux := http.NewServeMux()

	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("client_id") != "client_id_test" {
			http.Error(w, "Invalid client_id", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dev_code_1",
			"user_code":        "WXYZ-1234",
			"verification_uri": "https://example.com/device",
			"expires_in":       60,
			"interval":         1,
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			http.Error(w, "Invalid grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id_token": "id_token_after_browser_fail",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &AgentMeshNode{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	originalOpenBrowser := openBrowserFunc
	openBrowserFunc = func(_ string) error {
		return fmt.Errorf("no browser available")
	}
	defer func() { openBrowserFunc = originalOpenBrowser }()

	token, err := node.InteractiveLoginWithDeviceAuth(
		ctx,
		"http://auth.example.com/auth",
		server.URL+"/token",
		server.URL+"/device",
		"client_id_test",
		"agentmesh-e2e",
		false,
		false, // interactive: browser flow attempted first, then device fallback
	)
	if err != nil {
		t.Fatalf("InteractiveLoginWithDeviceAuth failed: %v", err)
	}
	if token != "id_token_after_browser_fail" {
		t.Fatalf("Expected id_token_after_browser_fail, got %q", token)
	}
}

// TestDeviceLoginRetriesOnTransientTokenError verifies that a transient
// network error while polling the token endpoint doesn't abort the device
// flow: DeviceLogin should log a warning, wait for the next poll interval,
// and keep polling until it succeeds (or the context/expiry ends it).
func TestDeviceLoginRetriesOnTransientTokenError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dev_code_1",
			"user_code":        "AAAA-BBBB",
			"verification_uri": "https://example.com/device",
			"expires_in":       60,
			"interval":         1,
		})
	})

	var pollCount int32
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&pollCount, 1) == 1 {
			// Simulate a transient network error on the first poll by closing
			// the connection without writing a response.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("ResponseWriter does not support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("failed to hijack connection: %v", err)
			}
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "token_after_retry"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &AgentMeshNode{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, err := node.DeviceLogin(ctx, server.URL+"/device", server.URL+"/token", "client_id_test", "agentmesh-e2e", false)
	if err != nil {
		t.Fatalf("DeviceLogin failed: %v", err)
	}
	if token != "token_after_retry" {
		t.Fatalf("Expected token_after_retry, got %q", token)
	}
	if got := atomic.LoadInt32(&pollCount); got < 2 {
		t.Fatalf("expected at least 2 poll attempts, got %d", got)
	}
}

// TestDeviceLoginPending401 verifies polling survives providers (e.g. dex)
// that return authorization_pending with HTTP 401 instead of the
// RFC 8628-mandated 400: the OAuth error code in the body wins over the
// HTTP status code.
func TestDeviceLoginPending401(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dev_code_1",
			"user_code":        "CCCC-DDDD",
			"verification_uri": "https://example.com/device",
			"expires_in":       60,
			"interval":         1,
		})
	})

	var pollCount int32
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if atomic.AddInt32(&pollCount, 1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "token_after_pending_401"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &AgentMeshNode{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, err := node.DeviceLogin(ctx, server.URL+"/device", server.URL+"/token", "client_id_test", "agentmesh-e2e", false)
	if err != nil {
		t.Fatalf("DeviceLogin failed: %v", err)
	}
	if token != "token_after_pending_401" {
		t.Fatalf("Expected token_after_pending_401, got %q", token)
	}
	if got := atomic.LoadInt32(&pollCount); got < 2 {
		t.Fatalf("expected at least 2 poll attempts, got %d", got)
	}
}

// TestDeviceLoginFatalErrors verifies polling aborts on terminal responses:
// a non-OAuth error body (regardless of status) and an OAuth error code
// that is not a pending/slow_down signal.
func TestDeviceLoginFatalErrors(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"non-oauth 401", http.StatusUnauthorized, `{"message":"nope"}`, "token request failed with status"},
		{"invalid_client 401", http.StatusUnauthorized, `{"error":"invalid_client","error_description":"unknown client"}`, "invalid_client"},
		{"access_denied 400", http.StatusBadRequest, `{"error":"access_denied"}`, "denied"},
		{"oauth-shaped 500 is not a protocol error", http.StatusInternalServerError, `{"error":"server_error"}`, "server_error"},
		{"html 502 surfaces the body", http.StatusBadGateway, `<html>bad gateway</html>`, "bad gateway"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"device_code":      "dev_code_1",
					"user_code":        "EEEE-FFFF",
					"verification_uri": "https://example.com/device",
					"expires_in":       60,
					"interval":         1,
				})
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})

			server := httptest.NewServer(mux)
			defer server.Close()

			node := &AgentMeshNode{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := node.DeviceLogin(ctx, server.URL+"/device", server.URL+"/token", "client_id_test", "agentmesh-e2e", false)
			if err == nil {
				t.Fatal("expected DeviceLogin to fail")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestParseAuthMode(t *testing.T) {
	cases := []struct {
		in      string
		want    AuthMode
		wantErr bool
	}{
		{"", AuthModeAuto, false},
		{"auto", AuthModeAuto, false},
		{"AUTO", AuthModeAuto, false},
		{" device ", AuthModeDevice, false},
		{"oob", AuthModeOOB, false},
		{"browser", AuthModeBrowser, false},
		{"nonsense", "", true},
	}
	for _, tc := range cases {
		got, err := ParseAuthMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseAuthMode(%q): expected error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAuthMode(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseAuthMode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestAuthModeDeviceForcedWhenInteractive verifies that auth-mode=device uses
// the device flow even in a non-headless environment, and never touches the
// browser.
func TestAuthModeDeviceForcedWhenInteractive(t *testing.T) {
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_TTY", "")

	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dev_code_1",
			"user_code":        "AAAA-BBBB",
			"verification_uri": "https://example.com/device",
			"expires_in":       60,
			"interval":         1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			http.Error(w, "Invalid grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "forced_device_token"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &AgentMeshNode{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	originalOpenBrowser := openBrowserFunc
	openBrowserFunc = func(_ string) error {
		t.Error("openBrowser should not be called when auth-mode=device")
		return nil
	}
	defer func() { openBrowserFunc = originalOpenBrowser }()

	token, err := node.InteractiveLoginWithMode(
		ctx,
		"http://auth.example.com/auth",
		server.URL+"/token",
		server.URL+"/device",
		"client_id_test",
		"agentmesh-e2e",
		false,
		false,
		AuthModeDevice,
	)
	if err != nil {
		t.Fatalf("InteractiveLoginWithMode failed: %v", err)
	}
	if token != "forced_device_token" {
		t.Fatalf("Expected forced_device_token, got %q", token)
	}
}

// TestAuthModeDeviceWithoutEndpointErrors verifies that auth-mode=device fails
// fast when the provider advertises no device endpoint.
func TestAuthModeDeviceWithoutEndpointErrors(t *testing.T) {
	node := &AgentMeshNode{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := node.InteractiveLoginWithMode(
		ctx,
		"http://auth.example.com/auth",
		"http://token.example.com/token",
		"", // no device endpoint
		"client_id_test",
		"agentmesh-e2e",
		false,
		true,
		AuthModeDevice,
	)
	if err == nil {
		t.Fatal("expected an error when auth-mode=device but no device endpoint is available")
	}
	if !strings.Contains(err.Error(), "device_authorization_endpoint") {
		t.Fatalf("expected device endpoint error, got: %v", err)
	}
}

// TestAuthModeBrowserIgnoresDevice verifies that auth-mode=browser uses the
// loopback flow even under a headless (SSH) environment with a device
// endpoint available, and never falls back to device flow.
func TestAuthModeBrowserIgnoresDevice(t *testing.T) {
	useEphemeralOIDCPort(t)
	t.Setenv("SSH_CLIENT", "1")
	t.Setenv("SSH_TTY", "")

	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		t.Error("device endpoint should not be used when auth-mode=browser")
		http.Error(w, "unexpected", http.StatusBadRequest)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" {
			http.Error(w, "Invalid grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "browser_mode_token"})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	node := &AgentMeshNode{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	originalOpenBrowser := openBrowserFunc
	openBrowserFunc = func(urlStr string) error {
		u, _ := url.Parse(urlStr)
		redirectURI := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")
		go func() {
			time.Sleep(50 * time.Millisecond)
			if resp, gErr := http.Get(redirectURI + "?code=dev_code_123&state=" + state); gErr == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	defer func() { openBrowserFunc = originalOpenBrowser }()

	token, err := node.InteractiveLoginWithMode(
		ctx,
		"http://auth.example.com/auth",
		server.URL+"/token",
		server.URL+"/device",
		"client_id_test",
		"agentmesh-e2e",
		false,
		true, // headless requested, but browser mode overrides it
		AuthModeBrowser,
	)
	if err != nil {
		t.Fatalf("InteractiveLoginWithMode failed: %v", err)
	}
	if token != "browser_mode_token" {
		t.Fatalf("Expected browser_mode_token, got %q", token)
	}
}

func TestRenewWithRefreshToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 "http://" + r.Host,
			"token_endpoint":         "http://" + r.Host + "/token",
			"authorization_endpoint": "http://" + r.Host + "/auth",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "refresh_token" {
			http.Error(w, "Invalid grant_type: "+r.FormValue("grant_type"), http.StatusBadRequest)
			return
		}
		if r.FormValue("refresh_token") != "old_refresh_123" {
			http.Error(w, "Invalid refresh token", http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != "client_id_test" {
			http.Error(w, "Invalid client_id", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "new_access_token_xyz",
			"id_token":      "new_id_token_abc",
			"refresh_token": "new_refresh_token_456",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Initialize Store
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("failed to close store: %v", err)
		}
	}()

	// Store OIDC Config and old refresh token
	if err := store.SaveOIDCConfig(server.URL, "client_id_test", "agentmesh-e2e"); err != nil {
		t.Fatalf("Failed to save OIDC Config: %v", err)
	}
	if err := store.SaveRefreshToken("old_refresh_123"); err != nil {
		t.Fatalf("Failed to save Refresh Token: %v", err)
	}

	node := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond, Store: store}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	newJWT, err := node.renewWithRefreshToken(ctx, "")
	if err != nil {
		t.Fatalf("renewWithRefreshToken failed: %v", err)
	}

	if newJWT != "new_id_token_abc" {
		t.Errorf("Expected new JWT 'new_id_token_abc', got '%s'", newJWT)
	}

	// Verify that the new refresh token is saved
	newRefresh, err := store.LoadRefreshToken()
	if err != nil {
		t.Fatalf("Failed to load new refresh token from store: %v", err)
	}
	if newRefresh != "new_refresh_token_456" {
		t.Errorf("Expected updated refresh token 'new_refresh_token_456', got '%s'", newRefresh)
	}
}

func TestOIDCMethodsRejectPlaintextNonLoopbackTransport(t *testing.T) {
	prevGlobal := allowInsecureControlPlane.Load()
	SetAllowInsecureControlPlane(false)
	t.Cleanup(func() { SetAllowInsecureControlPlane(prevGlobal) })

	// 192.0.2.10 is RFC 5737 TEST-NET-1: if RoundTrip attempted a TCP dial
	// instead of failing at api.ValidateControlPlaneTransport, the short context
	// would time out with context.DeadlineExceeded rather than a transport policy error.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	strictNode := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond}
	// An in-process node opting into AllowInsecureControlPlane must stay scoped
	// to that instance and leave strictNode rejecting plaintext non-loopback URLs.
	_ = &AgentMeshNode{
		BiscuitTimeout: 500 * time.Millisecond,
		config:         Options{AllowInsecureControlPlane: true},
	}

	const nonLoopbackIssuer = "http://192.0.2.10:8080"
	cases := []struct {
		name string
		call func() error
	}{
		{
			name: "DiscoverTokenURL",
			call: func() error {
				_, err := strictNode.DiscoverTokenURL(ctx, nonLoopbackIssuer)
				return err
			},
		},
		{
			name: "DiscoverEndpointsWithDevice",
			call: func() error {
				_, err := strictNode.DiscoverEndpointsWithDevice(ctx, nonLoopbackIssuer)
				return err
			},
		},
		{
			name: "DeviceLogin",
			call: func() error {
				_, err := strictNode.DeviceLogin(ctx, nonLoopbackIssuer+"/device", nonLoopbackIssuer+"/token", "client-id", "aud", false)
				return err
			},
		},
		{
			name: "RefreshJWT",
			call: func() error {
				_, _, err := strictNode.RefreshJWT(ctx, nonLoopbackIssuer+"/token", "client-id", "", "rt-123")
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatalf("%s accepted plaintext non-loopback URL %s, want error", tc.name, nonLoopbackIssuer)
			}
			if ctx.Err() != nil {
				t.Fatalf("%s dialed the network and hit context deadline (%v) instead of failing closed at transport check: %v", tc.name, ctx.Err(), err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "https") && !strings.Contains(strings.ToLower(err.Error()), "plaintext") && !strings.Contains(strings.ToLower(err.Error()), "insecure") {
				t.Errorf("%s error = %v, want transport policy rejection mentioning https/plaintext/insecure", tc.name, err)
			}
		})
	}
}
