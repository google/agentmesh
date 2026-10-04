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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
)

// TestSTSTaskScopedSecurityCUJ validates the Phase 3 Security Token Service (STS),
// Task-Scoped Biscuit Attenuation, OAuth 2.1 / PKCE, Envoy ext_authz, RFC 7009
// Revocation, and Outbound Border JWT Minting journeys end-to-end across real
// sam-control-plane, sam-router, and sam-node processes.
func TestSTSTaskScopedSecurityCUJ(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	tmpDir := t.TempDir()
	oidcURL, mintToken := startCustomMockOIDC(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyYAML := fmt.Sprintf(`roles:
  - name: pep
    allowed_services: ["egress://api.github.com"]
    allowed_targets: ["*"]
  - name: developer
    allowed_services: ["egress://api.github.com"]
    allowed_targets: ["*"]
    http:
      - service: "egress://api.github.com"
        methods: ["GET", "POST"]
        paths: ["/repos/acme/*"]
  - name: contractor
    allowed_services: ["egress://api.github.com"]
    allowed_targets: ["*"]
    http:
      - service: "egress://api.github.com"
        methods: ["GET"]
        paths: ["/repos/acme/public/*"]
bindings:
  - role: pep
    members: ["user:pep-user"]
  - role: developer
    members: ["user:dev-user"]
  - role: contractor
    members: ["user:contractor-user"]
  - role: sam:role:node
    members: ["user:pep-user", "user:dev-user"]
egress:
  - name: api.github.com
    target_url: %q
    credential: github-token
    served_by: ["pep"]
`, upstream.URL)
	if err := os.WriteFile(policyFile, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	cpPort, cleanupCP := startControlPlaneAndRouter(t, tmpDir, oidcURL, mintToken, policyFile)
	defer cleanupCP()
	controlPlane := fmt.Sprintf("http://127.0.0.1:%d", cpPort)

	secrets := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "github-token"), []byte("ghp_upstream_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pepToken := "test-token"
	pep := launchNode(t, nodeBin, os.Environ(), filepath.Join(tmpDir, "pep"), "run",
		"--control-plane", controlPlane,
		"--data-dir", filepath.Join(tmpDir, "pep"),
		"--api-token-path", tokenPath(t, pepToken),
		"--jwt", mintToken(map[string]any{"sub": "pep-user", "roles": []string{api.RoleNode}}),
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--allow-loopback",
		"--discovery-interval", "100ms",
		"--control-plane-sync-interval", "1s",
		"--secrets-dir", secrets,
	)
	pepAPI := pep.waitForAPI(t)

	callerToken := "test-token"
	caller := launchNode(t, nodeBin, os.Environ(), filepath.Join(tmpDir, "caller"), "run",
		"--control-plane", controlPlane,
		"--data-dir", filepath.Join(tmpDir, "caller"),
		"--api-token-path", tokenPath(t, callerToken),
		"--jwt", mintToken(map[string]any{"sub": "dev-user", "roles": []string{api.RoleNode}}),
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--allow-loopback",
		"--discovery-interval", "100ms",
		"--control-plane-sync-interval", "1s",
	)
	callerAPI := caller.waitForAPI(t)
	connectPeer(t, callerAPI, pep.p2pAddr)
	waitForDHTPeers(t, pepAPI)
	pepPeer := extractPeerID(pep.p2pAddr)
	waitForDiscoverableService(t, callerAPI, callerToken, "egress", "api.github.com")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Run("OIDC discovery, JWKS, and OAuth 2.1 PKCE on control plane and protected resource metadata on node", func(t *testing.T) {
		for _, endpoint := range []string{
			controlPlane + "/.well-known/openid-configuration",
			controlPlane + "/.well-known/oauth-authorization-server",
			controlPlane + "/jwks",
			"http://" + callerAPI + "/.well-known/oauth-protected-resource",
		} {
			resp, err := client.Get(endpoint)
			if err != nil {
				t.Fatalf("GET %s: %v", endpoint, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s: status %d, want 200", endpoint, resp.StatusCode)
			}
		}

		// OAuth 2.1 Authorization Code + PKCE S256 flow
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		userJWT := mintToken(map[string]any{"sub": "dev-user", "email": "dev@example.com"})

		authURL, _ := url.Parse(controlPlane + "/oauth/authorize")
		q := authURL.Query()
		q.Set("response_type", "code")
		q.Set("client_id", "mcp-desktop-client")
		q.Set("redirect_uri", "http://127.0.0.1:54321/callback")
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
		q.Set("resource", "egress://api.github.com")
		q.Set("scope", "method:GET path:/repos/acme/public/*")
		q.Set("id_token_hint", userJWT)
		q.Set("state", "xyz-state")
		authURL.RawQuery = q.Encode()

		authResp, err := client.Get(authURL.String())
		if err != nil {
			t.Fatalf("GET /oauth/authorize: %v", err)
		}
		_ = authResp.Body.Close()
		if authResp.StatusCode != http.StatusFound {
			t.Fatalf("/oauth/authorize status = %d, want 302", authResp.StatusCode)
		}
		loc, err := url.Parse(authResp.Header.Get("Location"))
		if err != nil {
			t.Fatalf("parse redirect Location: %v", err)
		}
		code := loc.Query().Get("code")
		if code == "" {
			t.Fatalf("missing code in redirect Location %q", loc.String())
		}

		tokenForm := url.Values{}
		tokenForm.Set("grant_type", api.GrantTypeAuthorizationCode)
		tokenForm.Set("code", code)
		tokenForm.Set("redirect_uri", "http://127.0.0.1:54321/callback")
		tokenForm.Set("client_id", "mcp-desktop-client")
		tokenForm.Set("code_verifier", verifier)
		tokenResp, err := client.PostForm(controlPlane+"/oauth/token", tokenForm)
		if err != nil {
			t.Fatalf("POST /oauth/token: %v", err)
		}
		defer func() { _ = tokenResp.Body.Close() }()
		if tokenResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(tokenResp.Body)
			t.Fatalf("POST /oauth/token status = %d: %s", tokenResp.StatusCode, string(body))
		}
	})

	t.Run("Inbound external JWT exchange and role isolation via ext_authz", func(t *testing.T) {
		contractorJWT := mintToken(map[string]any{"sub": "contractor-user", "email": "contractor@example.com"})

		// contractor is allowed GET /repos/acme/public/*
		reqAllow, _ := http.NewRequest(http.MethodGet, "http://"+callerAPI+"/ext_authz/egress/api.github.com/repos/acme/public/readme", nil)
		reqAllow.Header.Set("Authorization", "Bearer "+contractorJWT)
		respAllow, err := client.Do(reqAllow)
		if err != nil {
			t.Fatalf("ext_authz allow request: %v", err)
		}
		_ = respAllow.Body.Close()
		if respAllow.StatusCode != http.StatusOK {
			t.Fatalf("ext_authz allow status = %d, want 200", respAllow.StatusCode)
		}
		if got := respAllow.Header.Get(api.HeaderSamRoles); got != "contractor" {
			t.Fatalf("ext_authz X-Sam-Roles = %q, want \"contractor\" (no node role leakage)", got)
		}

		// contractor is denied GET /repos/acme/private/secret (even though caller node has developer role!)
		reqDeny, _ := http.NewRequest(http.MethodGet, "http://"+callerAPI+"/ext_authz/egress/api.github.com/repos/acme/private/secret", nil)
		reqDeny.Header.Set("Authorization", "Bearer "+contractorJWT)
		respDeny, err := client.Do(reqDeny)
		if err != nil {
			t.Fatalf("ext_authz deny request: %v", err)
		}
		_ = respDeny.Body.Close()
		if respDeny.StatusCode != http.StatusForbidden {
			t.Fatalf("ext_authz deny status = %d, want 403", respDeny.StatusCode)
		}
	})

	t.Run("Task biscuit attenuation, mesh enforcement, outbound STS JWT minting, and task revocation", func(t *testing.T) {
		// 1. Exchange caller node's standing Biscuit into a narrowed Task Biscuit
		//    only allowing GET /repos/acme/public/* on egress://api.github.com.
		form := url.Values{}
		form.Set("grant_type", api.GrantTypeTokenExchange)
		form.Add("resource", "egress://api.github.com")
		form.Set("scope", "method:GET path:/repos/acme/public/*")

		reqEx, _ := http.NewRequest(http.MethodPost, "http://"+callerAPI+"/oauth/token", strings.NewReader(form.Encode()))
		reqEx.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqEx.Header.Set("Authorization", "Bearer "+callerToken)
		respEx, err := client.Do(reqEx)
		if err != nil {
			t.Fatalf("POST /oauth/token on caller node: %v", err)
		}
		var tokData map[string]any
		_ = json.NewDecoder(respEx.Body).Decode(&tokData)
		_ = respEx.Body.Close()
		if respEx.StatusCode != http.StatusOK {
			t.Fatalf("POST /oauth/token status = %d, want 200", respEx.StatusCode)
		}
		taskBiscuit, _ := tokData["access_token"].(string)
		if taskBiscuit == "" {
			t.Fatal("empty access_token from /oauth/token")
		}

		baseMeshURL := fmt.Sprintf("http://%s/sam/%s/egress/api.github.com", callerAPI, pepPeer)
		doWithCred := func(method, path, cred string) int {
			req, _ := http.NewRequest(method, baseMeshURL+path, nil)
			req.Header.Set(api.HeaderSamAuthentication, "Bearer "+cred)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			_ = resp.Body.Close()
			return resp.StatusCode
		}

		// 2. Allowed by both developer role and tar_block: GET /repos/acme/public/readme
		if got := doWithCred(http.MethodGet, "/repos/acme/public/readme", taskBiscuit); got != http.StatusNoContent {
			t.Fatalf("GET /repos/acme/public/readme with taskBiscuit: %d, want 204", got)
		}

		// 3. Denied by tar_block method constraint (developer role allows POST, but tar_block only allows GET):
		if got := doWithCred(http.MethodPost, "/repos/acme/public/readme", taskBiscuit); got != http.StatusForbidden {
			t.Fatalf("POST /repos/acme/public/readme with taskBiscuit: %d, want 403", got)
		}

		// 4. Denied by tar_block path constraint (developer role allows /repos/acme/*, but tar_block only allows /repos/acme/public/*):
		if got := doWithCred(http.MethodGet, "/repos/acme/private/secret", taskBiscuit); got != http.StatusForbidden {
			t.Fatalf("GET /repos/acme/private/secret with taskBiscuit: %d, want 403", got)
		}

		// 5. Outbound Border STS JWT Minting at the PEP node for egress://api.github.com:
		stsForm := url.Values{}
		stsForm.Set("grant_type", api.GrantTypeTokenExchange)
		stsForm.Set("subject_token", taskBiscuit)
		stsForm.Set("subject_token_type", api.TokenTypeBiscuit)
		stsForm.Set("requested_token_type", api.TokenTypeJWT)
		stsForm.Add("resource", "egress://api.github.com")
		stsForm.Set("audience", "https://sts.googleapis.com")
		stsResp, err := client.PostForm("http://"+pepAPI+"/oauth/token", stsForm)
		if err != nil {
			t.Fatalf("POST /oauth/token (border JWT): %v", err)
		}
		var stsData map[string]any
		_ = json.NewDecoder(stsResp.Body).Decode(&stsData)
		_ = stsResp.Body.Close()
		if stsResp.StatusCode != http.StatusOK {
			t.Fatalf("border JWT status = %d, want 200: %v", stsResp.StatusCode, stsData)
		}
		borderJWT, _ := stsData["access_token"].(string)
		if strings.Count(borderJWT, ".") != 2 {
			t.Fatalf("expected compact JWT with 2 dots, got %q", borderJWT)
		}

		// 6. Revoke taskBiscuit on the PEP node (and caller node) via RFC 7009 POST /oauth/revoke:
		revForm := url.Values{}
		revForm.Set("token", taskBiscuit)
		for _, addr := range []string{pepAPI, callerAPI} {
			revResp, err := client.PostForm("http://"+addr+"/oauth/revoke", revForm)
			if err != nil {
				t.Fatalf("POST /oauth/revoke on %s: %v", addr, err)
			}
			_ = revResp.Body.Close()
			if revResp.StatusCode != http.StatusOK {
				t.Fatalf("POST /oauth/revoke status = %d, want 200", revResp.StatusCode)
			}
		}

		// Revoked taskBiscuit is now rejected immediately, while caller's parent node identity still works!
		if got := doWithCred(http.MethodGet, "/repos/acme/public/readme", taskBiscuit); got != http.StatusForbidden {
			t.Fatalf("revoked taskBiscuit status = %d, want 403", got)
		}
		if got := doWithCred(http.MethodGet, "/repos/acme/private/secret", callerToken); got != http.StatusNoContent {
			t.Fatalf("parent node identity status = %d, want 204", got)
		}
	})
}
