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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/agentmesh/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type cujExtProcCallout struct {
	extprocv3.UnimplementedExternalProcessorServer
}

func (c *cujExtProcCallout) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var resp *extprocv3.ProcessingResponse
		if rh := req.GetRequestHeaders(); rh != nil {
			var path string
			for _, hv := range rh.GetHeaders().GetHeaders() {
				if hv.GetKey() == ":path" {
					path = hv.GetValue()
					if path == "" {
						path = string(hv.GetRawValue())
					}
				}
			}
			if strings.HasSuffix(path, "/blocked-by-dlp") {
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_ImmediateResponse{
						ImmediateResponse: &extprocv3.ImmediateResponse{
							Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
							Body:    []byte("blocked by ext_proc callout"),
							Details: "dlp_violation",
						},
					},
				}
			} else {
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestHeaders{
						RequestHeaders: &extprocv3.HeadersResponse{
							Response: &extprocv3.CommonResponse{
								Status: extprocv3.CommonResponse_CONTINUE,
								HeaderMutation: &extprocv3.HeaderMutation{
									SetHeaders: []*corev3.HeaderValueOption{
										{Header: &corev3.HeaderValue{Key: "X-Ext-Proc-Inspected", Value: "true"}},
									},
								},
							},
						},
					},
				}
			}
		} else if req.GetResponseHeaders() != nil {
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
						},
					},
				},
			}
		}
		if resp != nil {
			if err := stream.Send(resp); err != nil {
				return err
			}
			if resp.GetImmediateResponse() != nil {
				return nil
			}
		}
	}
}

func startGRPCExtProcCallout(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv, &cujExtProcCallout{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln.Addr().String()
}

// TestSTSTaskScopedSecurityCUJ validates the Phase 3 Security Token Service (STS),
// Task-Scoped Biscuit Attenuation, OAuth 2.1 / PKCE, Envoy ext_authz and ext_proc,
// RFC 7009 Revocation, and Outbound Border JWT Minting journeys end-to-end across
// real agentmesh-control-plane, agentmesh-router, and agentmesh-node processes.
func TestSTSTaskScopedSecurityCUJ(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/agentmesh-node")
	tmpDir := t.TempDir()
	oidcURL, mintToken := startCustomMockOIDC(t)

	var upstreamAuthHeader atomic.Value
	var upstreamInspectedHeader atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthHeader.Store(r.Header.Get("Authorization"))
		upstreamInspectedHeader.Store(r.Header.Get("X-Ext-Proc-Inspected"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"path":%q,"auth":%q,"roles":%q}`, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get(api.HeaderMeshRoles))
	}))
	defer upstream.Close()

	extProcCalloutAddr := startGRPCExtProcCallout(t)

	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyYAML := fmt.Sprintf(`roles:
  - name: pep
    allowed_services: ["egress://api.github.com", "mcp://github"]
    allowed_targets: ["*"]
  - name: developer
    allowed_services: ["egress://api.github.com", "mcp://github"]
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
  - role: mesh:role:node
    members: ["user:pep-user", "user:dev-user"]
egress:
  - name: api.github.com
    target_url: %q
    credential: github-token
    served_by: ["pep"]
    inspection:
      inspectors:
        - ext_proc:
            target: %q
            allow_mode_override: true
`, upstream.URL, extProcCalloutAddr)
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

	var mcpBackendCalls atomic.Int32
	mcpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpc struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &rpc)
		w.Header().Set("Content-Type", "application/json")
		switch rpc.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"github","version":"1.0"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_pr","description":"Get PR"},{"name":"delete_repo","description":"Delete repo"}]}}`))
		default:
			mcpBackendCalls.Add(1)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"PR #42 from %s peer=%s biscuit=%s"}]}}`,
				r.Header.Get(api.HeaderMeshPrincipal),
				r.Header.Get(api.HeaderPeerID),
				r.Header.Get(api.HeaderMeshBiscuit))
		}
	}))
	defer mcpBackend.Close()

	pepDir := filepath.Join(tmpDir, "pep")
	if err := os.MkdirAll(pepDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pepCfg := writeNodeConfig(t, pepDir, nil, svcDecl{Type: "mcp", Name: "github", TargetURL: mcpBackend.URL})
	pepToken := "test-token"
	pep := launchNode(t, nodeBin, os.Environ(), pepDir, "run",
		"--control-plane", controlPlane,
		"--data-dir", pepDir,
		"--api-token-path", tokenPath(t, pepToken),
		"--jwt", mintToken(map[string]any{"sub": "pep-user", "roles": []string{api.RoleNode}}),
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--allow-loopback",
		"--discovery-interval", "100ms",
		"--control-plane-sync-interval", "1s",
		"--secrets-dir", secrets,
		"--config", pepCfg,
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
	callerPeer := extractPeerID(caller.p2pAddr)
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

	t.Run("Inbound external JWT exchange and role isolation via ext_authz datapath", func(t *testing.T) {
		contractorJWT := mintToken(map[string]any{"sub": "contractor-user", "email": "contractor@example.com"})

		// Gateway proxy in front of caller node's mesh dataplane that consults
		// caller node's /ext_authz before forwarding through /mesh/<pepPeer>/egress/api.github.com.
		extAuthzGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			checkURL := "http://" + callerAPI + "/ext_authz/egress/api.github.com" + r.URL.Path
			checkReq, err := http.NewRequestWithContext(r.Context(), r.Method, checkURL, nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			checkReq.Header = r.Header.Clone()
			checkResp, err := client.Do(checkReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			_ = checkResp.Body.Close()
			if checkResp.StatusCode != http.StatusOK {
				w.WriteHeader(checkResp.StatusCode)
				return
			}

			// Forward the authorized request into caller node's mesh dataplane using the
			// X-Mesh-Biscuit injected by ext_authz.
			meshURL := fmt.Sprintf("http://%s/mesh/%s/egress/api.github.com%s", callerAPI, pepPeer, r.URL.Path)
			fwdReq, err := http.NewRequestWithContext(r.Context(), r.Method, meshURL, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, h := range []string{api.HeaderMeshBiscuit, api.HeaderMeshPrincipal, api.HeaderMeshRoles, api.HeaderMeshTask} {
				if v := checkResp.Header.Get(h); v != "" {
					fwdReq.Header.Set(h, v)
				}
			}
			fwdResp, err := client.Do(fwdReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer func() { _ = fwdResp.Body.Close() }()
			for k, vals := range fwdResp.Header {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set(api.HeaderMeshRoles, checkResp.Header.Get(api.HeaderMeshRoles))
			w.WriteHeader(fwdResp.StatusCode)
			_, _ = io.Copy(w, fwdResp.Body)
		}))
		defer extAuthzGateway.Close()

		// 1. contractor is allowed GET /repos/acme/public/readme -> traverses ext_authz -> caller node -> libp2p -> pep node -> ext_proc callout -> upstream!
		reqAllow, _ := http.NewRequest(http.MethodGet, extAuthzGateway.URL+"/repos/acme/public/readme", nil)
		reqAllow.Header.Set("Authorization", "Bearer "+contractorJWT)
		respAllow, err := client.Do(reqAllow)
		if err != nil {
			t.Fatalf("ext_authz gateway allow request: %v", err)
		}
		allowBody, _ := io.ReadAll(respAllow.Body)
		_ = respAllow.Body.Close()
		if respAllow.StatusCode != http.StatusOK {
			t.Fatalf("ext_authz datapath allow status = %d, want 200: %s", respAllow.StatusCode, string(allowBody))
		}
		if got := respAllow.Header.Get(api.HeaderMeshRoles); got != "contractor" {
			t.Fatalf("ext_authz X-Mesh-Roles = %q, want \"contractor\" (no node role leakage)", got)
		}
		if !strings.Contains(string(allowBody), `"path":"/repos/acme/public/readme"`) || !strings.Contains(string(allowBody), `"auth":"Bearer ghp_upstream_secret"`) {
			t.Fatalf("unexpected upstream datapath payload: %s", string(allowBody))
		}

		// 2. contractor is denied GET /repos/acme/private/secret (even though caller node has developer role!)
		reqDeny, _ := http.NewRequest(http.MethodGet, extAuthzGateway.URL+"/repos/acme/private/secret", nil)
		reqDeny.Header.Set("Authorization", "Bearer "+contractorJWT)
		respDeny, err := client.Do(reqDeny)
		if err != nil {
			t.Fatalf("ext_authz gateway deny request: %v", err)
		}
		_ = respDeny.Body.Close()
		if respDeny.StatusCode != http.StatusForbidden {
			t.Fatalf("ext_authz datapath deny status = %d, want 403", respDeny.StatusCode)
		}
	})

	t.Run("RFC 7523 client assertion grant from a header-injecting sandbox proxy", func(t *testing.T) {
		// What an OpenShell token grant does: the supervisor holds the
		// sandbox's workload JWT, trades it at the node token endpoint with
		// grant_type=client_credentials, then puts the result on
		// X-Mesh-Authentication for every request that leaves the sandbox. The
		// workload JWT is the mock issuer's; a SPIFFE JWT-SVID or Substrate
		// actor JWT differs only in the issuer the control plane trusts.
		workloadJWT := mintToken(map[string]any{"sub": "contractor-user"})

		meta, err := client.Get("http://" + callerAPI + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatalf("GET authorization server metadata: %v", err)
		}
		var asMeta struct {
			TokenEndpoint string   `json:"token_endpoint"`
			GrantTypes    []string `json:"grant_types_supported"`
			AuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
		}
		if err := json.NewDecoder(meta.Body).Decode(&asMeta); err != nil {
			t.Fatalf("decode authorization server metadata: %v", err)
		}
		_ = meta.Body.Close()
		if !slices.Contains(asMeta.GrantTypes, api.GrantTypeClientCredentials) || !slices.Contains(asMeta.AuthMethods, "spiffe_jwt") {
			t.Fatalf("metadata does not advertise client_credentials/spiffe_jwt: %+v", asMeta)
		}

		grant := func(t *testing.T, form url.Values) (int, map[string]any) {
			t.Helper()
			resp, err := client.PostForm(asMeta.TokenEndpoint, form)
			if err != nil {
				t.Fatalf("POST %s: %v", asMeta.TokenEndpoint, err)
			}
			defer func() { _ = resp.Body.Close() }()
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode token response: %v", err)
			}
			return resp.StatusCode, body
		}

		// 1. client_credentials + jwt-spiffe assertion, narrowed by scope the
		//    way an OpenShell profile's token_grant.scopes would.
		status, body := grant(t, url.Values{
			"grant_type":            {api.GrantTypeClientCredentials},
			"client_assertion_type": {api.ClientAssertionTypeJWTSPIFFE},
			"client_assertion":      {workloadJWT},
			"resource":              {"egress://api.github.com"},
			"scope":                 {"method:GET path:/repos/acme/public/*"},
		})
		if status != http.StatusOK {
			t.Fatalf("client_credentials grant status = %d: %v", status, body)
		}
		if body["issued_token_type"] != api.TokenTypeBiscuit || body["token_type"] != "Bearer" {
			t.Fatalf("unexpected token response: %v", body)
		}
		sandboxToken, _ := body["access_token"].(string)

		// 2. The proxy injects it; the mesh enforces the contractor role and the
		//    scope, and the upstream still sees the brokered credential only.
		meshURL := fmt.Sprintf("http://%s/mesh/%s/egress/api.github.com", callerAPI, pepPeer)
		reqAllow, _ := http.NewRequest(http.MethodGet, meshURL+"/repos/acme/public/readme", nil)
		reqAllow.Header.Set(api.HeaderMeshAuthentication, "Bearer "+sandboxToken)
		respAllow, err := client.Do(reqAllow)
		if err != nil {
			t.Fatalf("mesh egress with granted biscuit: %v", err)
		}
		allowBody, _ := io.ReadAll(respAllow.Body)
		_ = respAllow.Body.Close()
		if respAllow.StatusCode != http.StatusOK {
			t.Fatalf("granted biscuit allow status = %d, want 200: %s", respAllow.StatusCode, allowBody)
		}
		if !strings.Contains(string(allowBody), `"auth":"Bearer ghp_upstream_secret"`) {
			t.Fatalf("upstream did not receive the brokered credential: %s", allowBody)
		}
		reqDeny, _ := http.NewRequest(http.MethodGet, meshURL+"/repos/acme/private/secret", nil)
		reqDeny.Header.Set(api.HeaderMeshAuthentication, "Bearer "+sandboxToken)
		respDeny, err := client.Do(reqDeny)
		if err != nil {
			t.Fatalf("mesh egress deny: %v", err)
		}
		_ = respDeny.Body.Close()
		if respDeny.StatusCode != http.StatusForbidden {
			t.Fatalf("granted biscuit deny status = %d, want 403", respDeny.StatusCode)
		}

		// 3. The RFC 7523 section 2.1 authorization grant, as an identity-chaining
		//    caller sends it, yields the same identity.
		status, body = grant(t, url.Values{
			"grant_type": {api.GrantTypeJWTBearer},
			"assertion":  {workloadJWT},
		})
		if status != http.StatusOK || body["issued_token_type"] != api.TokenTypeBiscuit {
			t.Fatalf("jwt-bearer grant status = %d: %v", status, body)
		}

		// 4. An assertion the control plane does not trust is refused as a
		//    client authentication failure and never becomes a credential.
		forged := strings.Join(append(strings.Split(workloadJWT, ".")[:2], base64.RawURLEncoding.EncodeToString([]byte("forged"))), ".")
		status, body = grant(t, url.Values{
			"grant_type":            {api.GrantTypeClientCredentials},
			"client_assertion_type": {api.ClientAssertionTypeJWTSPIFFE},
			"client_assertion":      {forged},
		})
		if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("forged assertion: status %d body %v, want 401 invalid_client", status, body)
		}
		status, body = grant(t, url.Values{"grant_type": {api.GrantTypeClientCredentials}})
		if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("missing assertion: status %d body %v, want 401 invalid_client", status, body)
		}
	})

	t.Run("Task biscuit attenuation, mesh enforcement, egress ext_proc callout, outbound STS JWT minting, and task revocation", func(t *testing.T) {
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

		baseMeshURL := fmt.Sprintf("http://%s/mesh/%s/egress/api.github.com", callerAPI, pepPeer)
		doWithCred := func(method, path, cred string) (int, string) {
			req, _ := http.NewRequest(method, baseMeshURL+path, nil)
			req.Header.Set(api.HeaderMeshAuthentication, "Bearer "+cred)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return resp.StatusCode, string(body)
		}

		// 2. Allowed by both developer role and tar_block: GET /repos/acme/public/readme
		//    Also verifies the egress ext_proc callout mutated X-Ext-Proc-Inspected=true
		//    and agentmesh-node injected Authorization: Bearer ghp_upstream_secret.
		if got, body := doWithCred(http.MethodGet, "/repos/acme/public/readme", taskBiscuit); got != http.StatusOK || !strings.Contains(body, `"auth":"Bearer ghp_upstream_secret"`) {
			t.Fatalf("GET /repos/acme/public/readme with taskBiscuit: status=%d body=%s", got, body)
		}
		if got, _ := upstreamAuthHeader.Load().(string); got != "Bearer ghp_upstream_secret" {
			t.Fatalf("upstream Authorization = %q, want Bearer ghp_upstream_secret", got)
		}
		if got, _ := upstreamInspectedHeader.Load().(string); got != "true" {
			t.Fatalf("upstream X-Ext-Proc-Inspected = %q, want true", got)
		}

		// 2b. Blocked by egress ext_proc callout ImmediateResponse (path allowed by RBAC + TAR, blocked by DLP callout):
		if got, _ := doWithCred(http.MethodGet, "/repos/acme/public/blocked-by-dlp", taskBiscuit); got != http.StatusForbidden {
			t.Fatalf("GET /repos/acme/public/blocked-by-dlp with taskBiscuit: %d, want 403 (blocked by ext_proc callout)", got)
		}

		// 3. Denied by tar_block method constraint (developer role allows POST, but tar_block only allows GET):
		if got, _ := doWithCred(http.MethodPost, "/repos/acme/public/readme", taskBiscuit); got != http.StatusForbidden {
			t.Fatalf("POST /repos/acme/public/readme with taskBiscuit: %d, want 403", got)
		}

		// 4. Denied by tar_block path constraint (developer role allows /repos/acme/*, but tar_block only allows /repos/acme/public/*):
		if got, _ := doWithCred(http.MethodGet, "/repos/acme/private/secret", taskBiscuit); got != http.StatusForbidden {
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
		if got, _ := doWithCred(http.MethodGet, "/repos/acme/public/readme", taskBiscuit); got != http.StatusForbidden {
			t.Fatalf("revoked taskBiscuit status = %d, want 403", got)
		}
		if got, _ := doWithCred(http.MethodGet, "/repos/acme/private/secret", callerToken); got != http.StatusOK {
			t.Fatalf("parent node identity status = %d, want 200", got)
		}
	})

	t.Run("Gateway ext_proc over h2c datapath on live agentmesh-node (egress credential injection and MCP tools/call across mesh)", func(t *testing.T) {
		cc, err := grpc.NewClient("passthrough:///"+pepAPI, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatalf("grpc.NewClient: %v", err)
		}
		defer func() { _ = cc.Close() }()
		epClient := extprocv3.NewExternalProcessorClient(cc)
		mcpBackendCalls.Store(0)

		// Envoy-compatible Gateway proxy that runs the ExternalProcessor/Process gRPC stream
		// against pepAPI (including ModeOverride BUFFERED body inspection and HeaderMutation)
		// before forwarding to the target backend or mesh dataplane.
		gatewayProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var bodyBytes []byte
			if r.Body != nil {
				bodyBytes, _ = io.ReadAll(r.Body)
				_ = r.Body.Close()
			}

			stream, err := epClient.Process(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer func() { _ = stream.CloseSend() }()

			hdrs := []*corev3.HeaderValue{
				{Key: ":method", Value: r.Method},
				{Key: ":authority", Value: r.Host},
				{Key: ":path", Value: r.URL.RequestURI()},
			}
			for k, vals := range r.Header {
				hdrs = append(hdrs, &corev3.HeaderValue{Key: strings.ToLower(k), Value: strings.Join(vals, ", ")})
			}
			if err := stream.Send(&extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestHeaders{
					RequestHeaders: &extprocv3.HttpHeaders{
						EndOfStream: len(bodyBytes) == 0,
						Headers:     &corev3.HeaderMap{Headers: hdrs},
					},
				},
			}); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}

			procResp, err := stream.Recv()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			if imm := procResp.GetImmediateResponse(); imm != nil {
				w.WriteHeader(int(imm.GetStatus().GetCode()))
				_, _ = w.Write(imm.GetBody())
				return
			}

			applyMuts := func(mut *extprocv3.HeaderMutation) {
				if mut == nil {
					return
				}
				for _, rem := range mut.GetRemoveHeaders() {
					r.Header.Del(rem)
				}
				for _, sh := range mut.GetSetHeaders() {
					k := sh.GetHeader().GetKey()
					v := sh.GetHeader().GetValue()
					if v == "" {
						v = string(sh.GetHeader().GetRawValue())
					}
					r.Header.Set(k, v)
				}
			}
			applyMuts(procResp.GetRequestHeaders().GetResponse().GetHeaderMutation())

			if len(bodyBytes) > 0 && procResp.GetModeOverride().GetRequestBodyMode() == extprocv3http.ProcessingMode_BUFFERED {
				if err := stream.Send(&extprocv3.ProcessingRequest{
					Request: &extprocv3.ProcessingRequest_RequestBody{
						RequestBody: &extprocv3.HttpBody{
							Body:        bodyBytes,
							EndOfStream: true,
						},
					},
				}); err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}

				bodyProcResp, err := stream.Recv()
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				if imm := bodyProcResp.GetImmediateResponse(); imm != nil {
					w.WriteHeader(int(imm.GetStatus().GetCode()))
					_, _ = w.Write(imm.GetBody())
					return
				}
				applyMuts(bodyProcResp.GetRequestBody().GetResponse().GetHeaderMutation())
			}

			// Route /mesh/... requests through caller node's real libp2p mesh proxy,
			// and direct egress Host-routed requests to upstream.
			targetBase := upstream.URL
			if strings.HasPrefix(r.URL.Path, "/mesh/") {
				targetBase = "http://" + callerAPI
			}
			fwdReq, _ := http.NewRequestWithContext(r.Context(), r.Method, targetBase+r.URL.RequestURI(), strings.NewReader(string(bodyBytes)))
			fwdReq.Header = r.Header.Clone()
			fwdResp, err := client.Do(fwdReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer func() { _ = fwdResp.Body.Close() }()
			w.WriteHeader(fwdResp.StatusCode)
			_, _ = io.Copy(w, fwdResp.Body)
		}))
		defer gatewayProxy.Close()

		// 1. Egress credential brokering datapath over Gateway ext_proc:
		//    Contractor sends contractorJWT with Host: api.github.com -> gateway ext_proc exchanges JWT,
		//    strips contractorJWT, injects Authorization: Bearer ghp_upstream_secret & X-Mesh-Roles: contractor,
		//    and forwards to upstream.
		contractorJWT := mintToken(map[string]any{"sub": "contractor-user", "email": "contractor@example.com"})
		egressReq, _ := http.NewRequest(http.MethodGet, gatewayProxy.URL+"/repos/acme/public/readme", nil)
		egressReq.Host = "api.github.com"
		egressReq.Header.Set("Authorization", "Bearer "+contractorJWT)
		egressResp, err := client.Do(egressReq)
		if err != nil {
			t.Fatalf("gateway ext_proc egress request: %v", err)
		}
		egressBody, _ := io.ReadAll(egressResp.Body)
		_ = egressResp.Body.Close()
		if egressResp.StatusCode != http.StatusOK {
			t.Fatalf("gateway ext_proc egress status = %d, want 200: %s", egressResp.StatusCode, string(egressBody))
		}
		if !strings.Contains(string(egressBody), `"auth":"Bearer ghp_upstream_secret"`) || !strings.Contains(string(egressBody), `"roles":"contractor"`) {
			t.Fatalf("expected upstream to receive injected secret and contractor role, got %s", string(egressBody))
		}

		// 2. MCP tools/call datapath over Gateway ext_proc AND across the libp2p mesh:
		//    Mint a Task Biscuit on caller node scoped to tool:get_pr on mcp://github.
		mcpForm := url.Values{}
		mcpForm.Set("grant_type", api.GrantTypeTokenExchange)
		mcpForm.Add("resource", "mcp://github")
		mcpForm.Set("scope", "tool:get_pr")
		reqMCPTok, _ := http.NewRequest(http.MethodPost, "http://"+callerAPI+"/oauth/token", strings.NewReader(mcpForm.Encode()))
		reqMCPTok.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqMCPTok.Header.Set("Authorization", "Bearer "+callerToken)
		respMCPTok, err := client.Do(reqMCPTok)
		if err != nil {
			t.Fatalf("POST /oauth/token (mcp task biscuit): %v", err)
		}
		var mcpTokData map[string]any
		_ = json.NewDecoder(respMCPTok.Body).Decode(&mcpTokData)
		_ = respMCPTok.Body.Close()
		mcpTaskBiscuit, _ := mcpTokData["access_token"].(string)
		if mcpTaskBiscuit == "" {
			t.Fatalf("expected mcpTaskBiscuit, got %v", mcpTokData)
		}

		mcpMeshPath := fmt.Sprintf("/mesh/%s/mcp/github", pepPeer)

		// 2a. Allowed MCP tool "get_pr" traverses:
		//     gatewayProxy -> ext_proc (RequestHeaders -> ModeOverride BUFFERED -> RequestBody) ->
		//     caller node (/mesh/<pepPeer>/mcp/github) -> libp2p (/libp2p-http) -> pep node -> mcpBackend!
		mcpAllowReq, _ := http.NewRequest(http.MethodPost, gatewayProxy.URL+mcpMeshPath,
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pr"}}`))
		mcpAllowReq.Header.Set("Authorization", "Bearer "+mcpTaskBiscuit)
		mcpAllowReq.Header.Set("Content-Type", "application/json")
		mcpAllowResp, err := client.Do(mcpAllowReq)
		if err != nil {
			t.Fatalf("gateway ext_proc MCP allow: %v", err)
		}
		mcpAllowBody, _ := io.ReadAll(mcpAllowResp.Body)
		_ = mcpAllowResp.Body.Close()
		wantText := fmt.Sprintf("PR #42 from dev-user peer=%s biscuit=", callerPeer)
		if mcpAllowResp.StatusCode != http.StatusOK || !strings.Contains(string(mcpAllowBody), wantText) {
			t.Fatalf("expected 200 OK with %q, got %d: %s", wantText, mcpAllowResp.StatusCode, string(mcpAllowBody))
		}
		if mcpBackendCalls.Load() != 1 {
			t.Fatalf("expected 1 mcpBackend call, got %d", mcpBackendCalls.Load())
		}

		// 2b. Unauthorized MCP tool "delete_repo" is blocked at the gateway by ext_proc ImmediateResponse(403)
		//     before ever entering the mesh or reaching mcpBackend.
		mcpDenyReq, _ := http.NewRequest(http.MethodPost, gatewayProxy.URL+mcpMeshPath,
			strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo"}}`))
		mcpDenyReq.Header.Set("Authorization", "Bearer "+mcpTaskBiscuit)
		mcpDenyReq.Header.Set("Content-Type", "application/json")
		mcpDenyResp, err := client.Do(mcpDenyReq)
		if err != nil {
			t.Fatalf("gateway ext_proc MCP deny: %v", err)
		}
		_ = mcpDenyResp.Body.Close()
		if mcpDenyResp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for unauthorized MCP tool delete_repo at gateway, got %d", mcpDenyResp.StatusCode)
		}
		if mcpBackendCalls.Load() != 1 {
			t.Fatalf("expected mcpBackendCalls to remain 1 after gateway blocked tool call, got %d", mcpBackendCalls.Load())
		}

		// 2c. Even if a caller bypasses the gateway proxy and sends "delete_repo" directly across
		//     the libp2p mesh to pep node, pep node's /libp2p-http ingress inspects the JSON-RPC body
		//     and enforces the Task Biscuit's tool:get_pr constraint with 403 Forbidden!
		directMeshDenyReq, _ := http.NewRequest(http.MethodPost, "http://"+callerAPI+mcpMeshPath,
			strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_repo"}}`))
		directMeshDenyReq.Header.Set(api.HeaderMeshAuthentication, "Bearer "+mcpTaskBiscuit)
		directMeshDenyReq.Header.Set("Content-Type", "application/json")
		directMeshDenyResp, err := client.Do(directMeshDenyReq)
		if err != nil {
			t.Fatalf("direct mesh MCP deny: %v", err)
		}
		_ = directMeshDenyResp.Body.Close()
		if directMeshDenyResp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden from provider node on direct mesh call for unauthorized tool, got %d", directMeshDenyResp.StatusCode)
		}
		if mcpBackendCalls.Load() != 1 {
			t.Fatalf("expected mcpBackendCalls to remain 1 after provider node blocked tool call, got %d", mcpBackendCalls.Load())
		}
	})
}
