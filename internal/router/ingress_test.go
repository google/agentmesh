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

package router

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/ratelimit"
	lru "github.com/hashicorp/golang-lru/v2"
	gostream "github.com/libp2p/go-libp2p-gostream"
	kb "github.com/libp2p/go-libp2p-kbucket"
	"github.com/libp2p/go-libp2p/core/host"
)

func TestIngressOptionsValidate(t *testing.T) {
	base := func() Options {
		opts := Options{
			ControlPlaneURL: "http://127.0.0.1:8080",
			KeysDBPath:      filepath.Join(t.TempDir(), "router.key"),
		}
		opts.Default()
		return opts
	}

	cases := []struct {
		name    string
		mutate  func(*Options)
		wantErr bool
	}{
		{
			name: "loopback IngressAddr allowed without TLS",
			mutate: func(o *Options) {
				o.IngressAddr = "127.0.0.1:0"
				o.IngressURL = "http://127.0.0.1:8080/ingress/"
			},
			wantErr: false,
		},
		{
			name: "localhost IngressAddr allowed without TLS",
			mutate: func(o *Options) {
				o.IngressAddr = "localhost:0"
			},
			wantErr: false,
		},
		{
			name: "non-loopback IngressAddr rejected without TLS or opt-in",
			mutate: func(o *Options) {
				o.IngressAddr = "0.0.0.0:8080"
			},
			wantErr: true,
		},
		{
			name: "non-loopback IngressAddr allowed behind TLS proxy with AllowInsecureIngressHTTP",
			mutate: func(o *Options) {
				o.IngressAddr = "0.0.0.0:8080"
				o.AllowInsecureIngressHTTP = true
				o.IngressURL = "https://bananas.sam-mesh.dev/ingress"
			},
			wantErr: false,
		},
		{
			name: "non-loopback IngressAddr allowed with TLS cert and key",
			mutate: func(o *Options) {
				o.IngressAddr = "0.0.0.0:8443"
				o.IngressTLSCertPath = "/etc/tls/tls.crt"
				o.IngressTLSKeyPath = "/etc/tls/tls.key"
			},
			wantErr: false,
		},
		{
			name: "mismatched TLS cert without key rejected",
			mutate: func(o *Options) {
				o.IngressAddr = "0.0.0.0:8443"
				o.IngressTLSCertPath = "/etc/tls/tls.crt"
			},
			wantErr: true,
		},
		{
			name: "non-loopback http IngressURL rejected without AllowInsecureIngressHTTP",
			mutate: func(o *Options) {
				o.IngressURL = "http://bananas.sam-mesh.dev/ingress"
			},
			wantErr: true,
		},
		{
			name: "non-loopback http IngressURL allowed with AllowInsecureIngressHTTP",
			mutate: func(o *Options) {
				o.IngressURL = "http://bananas.sam-mesh.dev/ingress"
				o.AllowInsecureIngressHTTP = true
			},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base()
			tc.mutate(&opts)
			err := opts.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() succeeded, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() failed: %v", err)
			}
		})
	}
}

func attachWithRole(t *testing.T, r *Router, pub ed25519.PublicKey, priv ed25519.PrivateKey, role *api.PolicyRole) host.Host {
	t.Helper()
	m := newClient(t, r)
	r.authenticatedPeers.Store(m.ID(), time.Now().Add(time.Hour))
	tok, _, err := identity.MintBiscuitToken(priv, jwt.MapClaims{"sub": "member"}, nil, m.ID(), time.Now().Add(time.Hour), []string{role.GetName()}, []*api.PolicyRole{role}, nil)
	if err != nil {
		t.Fatalf("MintBiscuitToken: %v", err)
	}
	b, err := biscuit.Unmarshal(tok)
	if err != nil {
		t.Fatalf("biscuit.Unmarshal: %v", err)
	}
	r.credentials.Store(m.ID(), memberCredential{biscuit: b, key: pub})
	return m
}

func provideWithIngress(key []byte, service string, ing *api.ServiceIngress, addrs ...string) *api.DirectoryRequest {
	return &api.DirectoryRequest{
		Request: &api.DirectoryRequest_Provide{
			Provide: &api.DirectoryProvide{
				Key:     key,
				Service: service,
				Ingress: ing,
				Addrs:   addrs,
			},
		},
	}
}

func TestDirectoryIngressEnforcementAndPropagation(t *testing.T) {
	a, b, c := newDirectoryRouter(t), newDirectoryRouter(t), newDirectoryRouter(t)
	federate(t, a, b)
	federate(t, a, c)
	federate(t, b, c)
	a.directory.Replication = 1

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	edgeMember := attachWithRole(t, a, pub, priv, &api.PolicyRole{
		Name:           "edge-publisher",
		AllowedPublish: []string{"a2a://*", "egress://openai"},
		AllowedIngress: []*api.IngressGrant{
			{Services: []string{"a2a://assistant"}},
		},
	})
	memberAddr := edgeMember.Addrs()[0].String() + "/p2p/" + edgeMember.ID().String()

	assistantKey, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, "assistant")
	if err != nil {
		t.Fatalf("ServiceKey: %v", err)
	}

	t.Run("PASSTHROUGH denied when role only grants default EDGE", func(t *testing.T) {
		before := directoryCount(t, directoryOpProvide, directoryResultDenied)
		resp := ask(t, edgeMember, a.Host.ID(), provideWithIngress(
			assistantKey,
			"a2a://assistant",
			&api.ServiceIngress{AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH},
			memberAddr,
		))
		if resp.GetError() == "" {
			t.Fatal("PASSTHROUGH announcement succeeded, want denial")
		}
		if got := directoryCount(t, directoryOpProvide, directoryResultDenied); got != before+1 {
			t.Fatalf("denied count = %v, want %v", got, before+1)
		}
	})

	t.Run("invalid ingress targets rejected", func(t *testing.T) {
		typeWideKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, "")
		egressKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_EGRESS, "openai")
		for label, req := range map[string]*api.DirectoryRequest{
			"type-wide key": provideWithIngress(typeWideKey, "a2a://assistant", &api.ServiceIngress{AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE}, memberAddr),
			"peer key":      provideWithIngress(api.PeerKey(edgeMember.ID()), "", &api.ServiceIngress{AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE}, memberAddr),
			"egress":        provideWithIngress(egressKey, "egress://openai", &api.ServiceIngress{AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE}, memberAddr),
		} {
			before := directoryCount(t, directoryOpProvide, directoryResultInvalid)
			resp := ask(t, edgeMember, a.Host.ID(), req)
			if resp.GetError() == "" {
				t.Fatalf("%s: accepted, want invalid refusal", label)
			}
			if got := directoryCount(t, directoryOpProvide, directoryResultInvalid); got != before+1 {
				t.Fatalf("%s: invalid count = %v, want %v", label, got, before+1)
			}
		}
	})

	t.Run("EDGE announcement accepted and propagated across federated routers", func(t *testing.T) {
		ing := &api.ServiceIngress{
			AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
			Allow:    []string{"email:alice@example.com"},
		}
		resp := ask(t, edgeMember, a.Host.ID(), provideWithIngress(assistantKey, "a2a://assistant", ing, memberAddr))
		if resp.GetError() != "" {
			t.Fatalf("EDGE provide failed: %s", resp.GetError())
		}

		closest := a.DHT.RoutingTable().NearestPeers(kb.ConvertKey(string(assistantKey)), 1)
		if len(closest) != 1 {
			t.Fatalf("closest = %v, want 1 router", closest)
		}

		for name, rtr := range map[string]*Router{"own": a, "peer_b": b, "peer_c": c} {
			asker := attach(t, rtr)
			found := ask(t, asker, rtr.Host.ID(), findProviders(assistantKey))
			if found.GetError() != "" {
				t.Fatalf("%s find_providers failed: %s", name, found.GetError())
			}
			if len(found.GetProviders()) != 1 {
				t.Fatalf("%s providers = %v, want 1", name, found.GetProviders())
			}
			gotIng := found.GetProviders()[0].GetIngress()
			if gotIng == nil || gotIng.GetAuthMode() != api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE {
				t.Fatalf("%s ingress = %v, want EDGE", name, gotIng)
			}
			if len(gotIng.GetAllow()) != 1 || gotIng.GetAllow()[0] != "email:alice@example.com" {
				t.Fatalf("%s ingress.allow = %v, want [email:alice@example.com]", name, gotIng.GetAllow())
			}
		}
	})
}

func newTestOIDCServer(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "test-kid",
					"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				},
			},
		})
	})
	return srv.URL, privKey
}

func signTestOIDCJWT(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-kid"
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func TestRouterIngressHandlerEndToEnd(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	oidcIssuer, oidcKey := newTestOIDCServer(t)

	r := newDirectoryRouter(t)
	r.config.ControlPlaneURL = "https://hub.example.com"
	r.config.OIDCIssuer = oidcIssuer
	r.config.Audience = api.DefaultAudience
	r.config.BiscuitTimeout = 2 * time.Second
	limiter, err := ratelimit.NewPeerRateLimiterWithRate(128, ingressRateLimitPerIP, ingressRateBurstPerIP)
	if err != nil {
		t.Fatalf("NewPeerRateLimiterWithRate: %v", err)
	}
	r.ingressLimiter = limiter
	revoked, err := lru.New[string, time.Time](128)
	if err != nil {
		t.Fatalf("lru.New: %v", err)
	}
	r.revokedTokens = revoked

	routerBiscuitRaw, err := identity.MintBootstrapBiscuitToken(cpPriv, r.Host.ID(), api.RoleRouter, time.Now().Add(time.Hour), []*api.PolicyRole{
		{Name: api.RoleRouter, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}},
	}, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken(router): %v", err)
	}
	r.keysMu.Lock()
	r.trustedPublicKeys = []ed25519.PublicKey{cpPub}
	r.credential = credential{biscuit: routerBiscuitRaw, expiration: time.Now().Add(time.Hour)}
	r.keysMu.Unlock()

	providerRole := &api.PolicyRole{
		Name:           "agent-host",
		AllowedPublish: []string{"a2a://*", "mcp://*"},
		AllowedIngress: []*api.IngressGrant{
			{
				Services: []string{"a2a://echo", "mcp://calc"},
			},
			{
				Services:         []string{"a2a://paired"},
				AllowedAuthModes: []api.IngressAuthMode{api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH},
			},
		},
	}
	callerRole := &api.PolicyRole{
		Name:            "caller",
		AllowedServices: []string{"a2a://echo", "mcp://calc"},
		AllowedTargets:  []string{"*"},
	}
	roles := []*api.PolicyRole{providerRole, callerRole}
	bindings := []*api.PolicyBinding{
		{Role: "caller", Members: []string{"email:alice@example.com", "email:bob@example.com"}},
	}
	compiled, warnings := api.BuildPolicyRules(roles, bindings)
	if len(warnings) != 0 {
		t.Fatalf("BuildPolicyRules warnings: %v", warnings)
	}
	meshRules, err := api.ParseDatalogRules(api.PolicyRuleTexts(compiled))
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}
	r.policy.Store(&meshPolicy{rules: meshRules})

	provider := attachWithRole(t, r, cpPub, cpPriv, providerRole)
	providerAddr := provider.Addrs()[0].String() + "/p2p/" + provider.ID().String()

	// Simulated node /mesh/ingress/1.0.0 HTTP listener inspecting forwarded headers.
	type capturedReq struct {
		Path          string `json:"path"`
		Auth          string `json:"auth"`
		MeshIngress   string `json:"mesh_ingress"`
		MeshBiscuit   bool   `json:"mesh_biscuit"`
		CallerBiscuit bool   `json:"caller_biscuit"`
		CallerClaims  string `json:"caller_claims"`
		SpoofedHeader string `json:"spoofed_header"`
	}
	ingListener, err := gostream.Listen(provider, api.IngressProtocolID)
	if err != nil {
		t.Fatalf("gostream.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ingListener.Close() })

	upstreamMux := http.NewServeMux()
	upstreamMux.HandleFunc("/a2a/echo/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		card := a2a.AgentCard{
			Name:        "Echo Agent",
			Description: "Test A2A service",
			Version:     "1.0.0",
			SupportedInterfaces: []*a2a.AgentInterface{
				{ProtocolBinding: a2a.TransportProtocolJSONRPC, URL: ""},
			},
			Signatures: []a2a.AgentCardSignature{{Protected: "p", Signature: "s"}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	})
	upstreamMux.HandleFunc("/a2a/paired/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		card := a2a.AgentCard{
			Name:        "Paired Agent",
			Description: "Passthrough A2A service",
			Version:     "1.0.0",
			SupportedInterfaces: []*a2a.AgentInterface{
				{ProtocolBinding: a2a.TransportProtocolJSONRPC, URL: "rpc"},
			},
			SecuritySchemes: a2a.NamedSecuritySchemes{
				"pair_token": a2a.HTTPAuthSecurityScheme{Scheme: "bearer", Description: "a2a-serve pair token"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	})
	upstreamMux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(capturedReq{
			Path:          req.URL.Path,
			Auth:          req.Header.Get("Authorization"),
			MeshIngress:   req.Header.Get(api.HeaderMeshIngress),
			MeshBiscuit:   req.Header.Get(api.HeaderMeshBiscuit) != "",
			CallerBiscuit: req.Header.Get(api.HeaderMeshIngressCallerBiscuit) != "",
			CallerClaims:  req.Header.Get(api.HeaderMeshIngressClaims),
			SpoofedHeader: req.Header.Get("X-Mesh-Spoofed"),
		})
	})
	upstreamSrv := &http.Server{Handler: upstreamMux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = upstreamSrv.Serve(ingListener) }()
	t.Cleanup(func() { _ = upstreamSrv.Close() })

	// Announce:
	// 1. a2a://internal (no ingress -> must 404 externally)
	// 2. a2a://echo (EDGE + allow: ["email:alice@example.com"])
	// 3. mcp://calc (EDGE)
	// 4. a2a://paired (PASSTHROUGH)
	mustProvide := func(svcType api.ServiceType, name string, ing *api.ServiceIngress) {
		t.Helper()
		key, err := api.ServiceKey(svcType, name)
		if err != nil {
			t.Fatal(err)
		}
		typeStr, _ := api.ServiceTypeToString(svcType)
		resp := ask(t, provider, r.Host.ID(), provideWithIngress(key, typeStr+"://"+name, ing, providerAddr))
		if resp.GetError() != "" {
			t.Fatalf("provide %s://%s failed: %s", typeStr, name, resp.GetError())
		}
	}
	mustProvide(api.ServiceType_SERVICE_TYPE_A2A, "internal", nil)
	mustProvide(api.ServiceType_SERVICE_TYPE_A2A, "echo", &api.ServiceIngress{
		AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
		Allow:    []string{"email:alice@example.com"},
	})
	mustProvide(api.ServiceType_SERVICE_TYPE_MCP, "calc", &api.ServiceIngress{
		AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
	})
	mustProvide(api.ServiceType_SERVICE_TYPE_A2A, "paired", &api.ServiceIngress{
		AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
	})

	if err := r.serveIngress("127.0.0.1:0"); err != nil {
		t.Fatalf("serveIngress: %v", err)
	}
	t.Cleanup(func() {
		if r.ingressServer != nil {
			_ = r.ingressServer.Close()
		}
	})
	r.isReady.Store(true)

	if r.IngressAddr() == nil {
		t.Fatal("IngressAddr() is nil after serveIngress")
	}
	baseURL := "http://" + r.IngressAddr().String() + "/ingress"
	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("healthz and RFC 9728 protected resource metadata", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/healthz")
		if err != nil {
			t.Fatalf("GET /ingress/healthz: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
		}

		metaResp, err := client.Get(baseURL + "/.well-known/oauth-protected-resource")
		if err != nil {
			t.Fatalf("GET oauth-protected-resource: %v", err)
		}
		defer func() { _ = metaResp.Body.Close() }()
		if metaResp.StatusCode != http.StatusOK {
			t.Fatalf("metadata status = %d, want 200", metaResp.StatusCode)
		}
		var doc api.OAuthProtectedResourceMetadata
		if err := json.NewDecoder(metaResp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
		if doc.Resource != baseURL {
			t.Fatalf("Resource = %q, want %q", doc.Resource, baseURL)
		}
		if len(doc.AuthorizationServers) < 2 || doc.AuthorizationServers[0] != "https://hub.example.com" || doc.AuthorizationServers[1] != oidcIssuer {
			t.Fatalf("AuthorizationServers = %v, want [https://hub.example.com %s]", doc.AuthorizationServers, oidcIssuer)
		}
	})

	t.Run("internal-only service returns 404", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/" + provider.ID().String() + "/a2a/internal/.well-known/agent-card.json")
		if err != nil {
			t.Fatalf("GET internal service: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("internal service status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("EDGE unauthenticated request returns 401 with RFC 9728 WWW-Authenticate", func(t *testing.T) {
		resp, err := client.Post(baseURL+"/"+provider.ID().String()+"/a2a/echo", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("POST echo: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		www := resp.Header.Get("WWW-Authenticate")
		wantSub := baseURL + "/.well-known/oauth-protected-resource"
		if !strings.Contains(www, wantSub) {
			t.Fatalf("WWW-Authenticate = %q, want substring %q", www, wantSub)
		}
	})

	t.Run("EDGE AgentCard discovery rewrites URL, injects SecuritySchemes, and honors ETag", func(t *testing.T) {
		cardEndpoint := baseURL + "/" + provider.ID().String() + "/a2a/echo"
		resp, err := client.Get(cardEndpoint)
		if err != nil {
			t.Fatalf("GET bare A2A service URL: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("AgentCard status = %d (%s), want 200", resp.StatusCode, string(body))
		}
		etag := resp.Header.Get("ETag")
		if etag == "" {
			t.Fatal("missing ETag header on AgentCard response")
		}
		var card a2a.AgentCard
		if err := json.Unmarshal(body, &card); err != nil {
			t.Fatalf("Unmarshal AgentCard: %v", err)
		}
		if len(card.SupportedInterfaces) != 1 || card.SupportedInterfaces[0].URL != cardEndpoint {
			t.Fatalf("SupportedInterfaces = %+v, want URL %q", card.SupportedInterfaces, cardEndpoint)
		}
		if len(card.Signatures) != 0 {
			t.Fatalf("Signatures = %v, want cleared after URL rewrite", card.Signatures)
		}
		for _, schemeName := range []a2a.SecuritySchemeName{"bearer", "agentmesh_oauth2", "oidc"} {
			if _, ok := card.SecuritySchemes[schemeName]; !ok {
				t.Fatalf("SecuritySchemes missing %q: %+v", schemeName, card.SecuritySchemes)
			}
		}

		// Conditional GET with If-None-Match returns 304 Not Modified.
		condReq, _ := http.NewRequest(http.MethodGet, cardEndpoint+"/.well-known/agent-card.json", nil)
		condReq.Header.Set("If-None-Match", etag)
		condResp, err := client.Do(condReq)
		if err != nil {
			t.Fatalf("conditional GET AgentCard: %v", err)
		}
		_ = condResp.Body.Close()
		if condResp.StatusCode != http.StatusNotModified {
			t.Fatalf("conditional GET status = %d, want 304", condResp.StatusCode)
		}
	})

	t.Run("EDGE Delegated Session Biscuit, ServiceIngress.allow, TAR MCP tool check, and revocation", func(t *testing.T) {
		aliceRaw, err := identity.MintDelegatedBiscuitToken(cpPriv, jwt.MapClaims{
			"sub":   "alice",
			"email": "alice@example.com",
		}, provider.ID(), time.Now().Add(time.Hour), []string{"caller"}, roles, &api.TaskAuthorizationRule{
			Name: "calc-add-only",
			Rules: []*api.TaskRule{
				{AllowedServices: []string{"a2a://echo"}},
				{
					AllowedServices: []string{"mcp://calc"},
					Operation:       &api.TaskOperation{AllowedTools: []string{"add"}},
				},
			},
		}, true)
		if err != nil {
			t.Fatalf("MintDelegatedBiscuitToken(alice): %v", err)
		}
		aliceTok := base64.StdEncoding.EncodeToString(aliceRaw)

		// Authorized A2A POST from Alice -> 200, headers sanitized, caller biscuit attached.
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/a2a/echo/message:send", strings.NewReader(`{"jsonrpc":"2.0"}`))
		req.Header.Set("Authorization", "Bearer "+aliceTok)
		req.Header.Set("X-Mesh-Spoofed", "evil")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST echo as alice: %v", err)
		}
		var got capturedReq
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode upstream echo: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("alice status = %d, want 200", resp.StatusCode)
		}
		if got.Path != "/a2a/echo/message:send" || got.MeshIngress != api.IngressAuthModeStringEdge || !got.MeshBiscuit || !got.CallerBiscuit || got.Auth != "" || got.SpoofedHeader != "" {
			t.Fatalf("unexpected upstream headers: %+v", got)
		}

		// Bob has mesh role "caller", but a2a://echo sets ServiceIngress.allow: ["email:alice@example.com"] -> 403.
		bobRaw, err := identity.MintDelegatedBiscuitToken(cpPriv, jwt.MapClaims{
			"sub":   "bob",
			"email": "bob@example.com",
		}, provider.ID(), time.Now().Add(time.Hour), []string{"caller"}, roles, nil, false)
		if err != nil {
			t.Fatalf("MintDelegatedBiscuitToken(bob): %v", err)
		}
		bobReq, _ := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/a2a/echo/message:send", strings.NewReader(`{}`))
		bobReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(bobRaw))
		bobResp, err := client.Do(bobReq)
		if err != nil {
			t.Fatalf("POST echo as bob: %v", err)
		}
		_ = bobResp.Body.Close()
		if bobResp.StatusCode != http.StatusForbidden {
			t.Fatalf("bob status = %d, want 403 (blocked by ServiceIngress.allow)", bobResp.StatusCode)
		}

		// MCP tools/call: "add" allowed by TAR -> 200; "drop_db" denied by TAR -> 403.
		addReq, _ := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/mcp/calc", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add"}}`))
		addReq.Header.Set("Authorization", "Bearer "+aliceTok)
		addResp, err := client.Do(addReq)
		if err != nil {
			t.Fatalf("MCP add: %v", err)
		}
		_ = addResp.Body.Close()
		if addResp.StatusCode != http.StatusOK {
			t.Fatalf("MCP add status = %d, want 200", addResp.StatusCode)
		}

		dropReq, _ := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/mcp/calc", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"drop_db"}}`))
		dropReq.Header.Set("Authorization", "Bearer "+aliceTok)
		dropResp, err := client.Do(dropReq)
		if err != nil {
			t.Fatalf("MCP drop_db: %v", err)
		}
		_ = dropResp.Body.Close()
		if dropResp.StatusCode != http.StatusForbidden {
			t.Fatalf("MCP drop_db status = %d, want 403", dropResp.StatusCode)
		}

		// Revoked Biscuit -> 401.
		aliceB, _ := biscuit.Unmarshal(aliceRaw)
		for _, revID := range aliceB.RevocationIds() {
			r.recordRevokedBiscuitID(hex.EncodeToString(revID), time.Now().Add(time.Hour))
		}
		revReq, _ := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/a2a/echo", bytes.NewReader([]byte(`{}`)))
		revReq.Header.Set("Authorization", "Bearer "+aliceTok)
		revResp, err := client.Do(revReq)
		if err != nil {
			t.Fatalf("POST with revoked biscuit: %v", err)
		}
		_ = revResp.Body.Close()
		if revResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked biscuit status = %d, want 401", revResp.StatusCode)
		}
	})

	t.Run("EDGE OIDC JWT verification forwards attested claims", func(t *testing.T) {
		jwtStr := signTestOIDCJWT(t, oidcKey, jwt.MapClaims{
			"iss":            oidcIssuer,
			"sub":            "oidc-alice",
			"aud":            api.DefaultAudience,
			"email":          "alice@example.com",
			"email_verified": true,
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Add(-time.Minute).Unix(),
		})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/a2a/echo", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+jwtStr)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST with OIDC JWT: %v", err)
		}
		var got capturedReq
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode OIDC upstream: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("OIDC JWT status = %d, want 200", resp.StatusCode)
		}
		if got.CallerClaims == "" || got.Auth != "" {
			t.Fatalf("expected CallerClaims set and Authorization stripped, got %+v", got)
		}
		claimsMap, err := identity.UnmarshalIngressClaimsHeader(got.CallerClaims)
		if err != nil {
			t.Fatalf("UnmarshalIngressClaimsHeader: %v", err)
		}
		if len(claimsMap[api.FactEmail]) != 1 || claimsMap[api.FactEmail][0] != "alice@example.com" {
			t.Fatalf("forwarded email claims = %v, want [alice@example.com]", claimsMap[api.FactEmail])
		}
	})

	t.Run("PASSTHROUGH preserves backend Authorization and SecuritySchemes while stripping X-Mesh-*", func(t *testing.T) {
		cardEndpoint := baseURL + "/" + provider.ID().String() + "/a2a/paired"
		cardResp, err := client.Get(cardEndpoint + "/.well-known/agent-card.json")
		if err != nil {
			t.Fatalf("GET paired AgentCard: %v", err)
		}
		var card a2a.AgentCard
		if err := json.NewDecoder(cardResp.Body).Decode(&card); err != nil {
			t.Fatalf("decode paired AgentCard: %v", err)
		}
		_ = cardResp.Body.Close()
		if len(card.SupportedInterfaces) != 1 || card.SupportedInterfaces[0].URL != cardEndpoint+"/rpc" {
			t.Fatalf("paired SupportedInterfaces = %+v, want %q", card.SupportedInterfaces, cardEndpoint+"/rpc")
		}
		if _, ok := card.SecuritySchemes["pair_token"]; !ok {
			t.Fatalf("PASSTHROUGH overwrote backend SecuritySchemes: %+v", card.SecuritySchemes)
		}

		req, _ := http.NewRequest(http.MethodPost, cardEndpoint+"/rpc", strings.NewReader(`{"jsonrpc":"2.0"}`))
		req.Header.Set("Authorization", "Bearer a2p_secret_pair_token")
		req.Header.Set("X-Mesh-Spoofed", "evil")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST passthrough: %v", err)
		}
		var got capturedReq
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode passthrough upstream: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("passthrough status = %d, want 200", resp.StatusCode)
		}
		if got.Auth != "Bearer a2p_secret_pair_token" || got.MeshIngress != api.IngressAuthModeStringPassthrough || got.SpoofedHeader != "" {
			t.Fatalf("unexpected passthrough upstream headers: %+v", got)
		}
	})

	t.Run("banned provider returns immediate 404", func(t *testing.T) {
		r.bannedPeers.Store(provider.ID(), struct{}{})
		r.records.removePeer(provider.ID())
		resp, err := client.Get(baseURL + "/" + provider.ID().String() + "/a2a/paired/.well-known/agent-card.json")
		if err != nil {
			t.Fatalf("GET banned provider: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("banned provider status = %d, want 404", resp.StatusCode)
		}
	})
}
