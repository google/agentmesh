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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
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
	gostream "github.com/libp2p/go-libp2p-gostream"
	kb "github.com/libp2p/go-libp2p-kbucket"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
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

	t.Run("providerEntryOfRecord rejects invalid ingress metadata from peer router", func(t *testing.T) {
		badRec := &api.PeerRecord{
			PeerId: edgeMember.ID().String(),
			Addrs:  []string{memberAddr},
			Ingress: &api.ServiceIngress{
				AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
				Allow:    []string{"email:alice@example.com"},
			},
		}
		if _, err := providerEntryOfRecord(badRec); err == nil {
			t.Fatal("providerEntryOfRecord accepted PASSTHROUGH with allow list, want error")
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

func TestRouterIngressHandlerEndToEnd(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	r := newDirectoryRouter(t)
	r.config.ControlPlaneURL = "https://hub.example.com"
	r.config.BiscuitTimeout = 2 * time.Second
	limiter, err := ratelimit.NewPeerRateLimiterWithRate(128, ingressRateLimitPerIP, ingressRateBurstPerIP)
	if err != nil {
		t.Fatalf("NewPeerRateLimiterWithRate: %v", err)
	}
	r.ingressLimiter = limiter

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
		if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != "https://hub.example.com" {
			t.Fatalf("AuthorizationServers = %v, want [https://hub.example.com]", doc.AuthorizationServers)
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

	t.Run("EDGE rejects raw compact JWT with 401 pointing callers to /oauth/token exchange", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/a2a/echo", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST with compact JWT: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("compact JWT status = %d, want 401", resp.StatusCode)
		}
		www := resp.Header.Get("WWW-Authenticate")
		wantSub := baseURL + "/.well-known/oauth-protected-resource"
		if !strings.Contains(www, wantSub) {
			t.Fatalf("WWW-Authenticate = %q, want substring %q", www, wantSub)
		}
	})

	t.Run("EDGE AgentCard discovery rewrites URL, injects Biscuit + OAuth2 SecuritySchemes, and honors ETag", func(t *testing.T) {
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
		for _, schemeName := range []a2a.SecuritySchemeName{"bearer", "agentmesh_oauth2"} {
			if _, ok := card.SecuritySchemes[schemeName]; !ok {
				t.Fatalf("SecuritySchemes missing %q: %+v", schemeName, card.SecuritySchemes)
			}
		}
		if _, hasOIDC := card.SecuritySchemes["oidc"]; hasOIDC {
			t.Fatalf("SecuritySchemes unexpectedly advertised raw oidc scheme: %+v", card.SecuritySchemes)
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

		// Revoked Biscuit -> 401 (both hex and base64url revocation IDs work).
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

func TestLeasedIngressURLAndHostHeaderHardening(t *testing.T) {
	r := &Router{
		config: Options{
			ControlPlaneURL:       "https://internal-cp.cluster.local:8443",
			PublicControlPlaneURL: "https://bananas.sam-mesh.dev",
		},
	}

	for _, addr := range []*net.TCPAddr{
		{IP: net.IPv4zero, Port: 8090},
		{IP: net.IPv6zero, Port: 8090},
	} {
		r.ingressAddr = addr
		if got := r.leasedIngressURL(); got != "" {
			t.Fatalf("leasedIngressURL() for unspecified %s = %q, want empty string", addr, got)
		}
		if got := r.effectiveIngressBaseURL(); got != "https://bananas.sam-mesh.dev/ingress" {
			t.Fatalf("effectiveIngressBaseURL() for unspecified %s = %q, want https://bananas.sam-mesh.dev/ingress", addr, got)
		}
	}

	// Unbound IngressHandler must never reflect a spoofed Host header into
	// RFC 9728 metadata or WWW-Authenticate headers.
	r.ingressAddr = nil
	h := r.IngressHandler()
	req := httptest.NewRequest(http.MethodGet, "http://evil.attacker.example/ingress/.well-known/oauth-protected-resource", nil)
	req.Host = "evil.attacker.example"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "evil.attacker.example") {
		t.Fatalf("metadata leaked spoofed Host header: %s", rec.Body.String())
	}
	var doc api.OAuthProtectedResourceMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("Unmarshal metadata: %v", err)
	}
	if doc.Resource != "https://bananas.sam-mesh.dev/ingress" {
		t.Fatalf("Resource = %q, want https://bananas.sam-mesh.dev/ingress", doc.Resource)
	}
}

func TestEdgeIngressPreDialRejectsBeforeDialingProvider(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	r := newDirectoryRouter(t)
	r.config.ControlPlaneURL = "https://hub.example.com"
	r.config.BiscuitTimeout = 2 * time.Second
	r.isReady.Store(true)

	routerBiscuitRaw, err := identity.MintBootstrapBiscuitToken(cpPriv, r.Host.ID(), api.RoleRouter, time.Now().Add(time.Hour), []*api.PolicyRole{
		{Name: api.RoleRouter, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}},
	}, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}
	r.keysMu.Lock()
	r.trustedPublicKeys = []ed25519.PublicKey{cpPub}
	r.credential = credential{biscuit: routerBiscuitRaw, expiration: time.Now().Add(time.Hour)}
	r.keysMu.Unlock()

	// Create a synthetic unreachable provider PeerID with a closed loopback port.
	// If handleIngressRequest dialed the provider before checking the caller's
	// Biscuit, it would fail with 502 Bad Gateway instead of 401/403.
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	unreachablePeer, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	key, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, "echo")
	if err != nil {
		t.Fatalf("ServiceKey: %v", err)
	}
	r.records.putWithIngress(
		key,
		unreachablePeer,
		[]multiaddr.Multiaddr{multiaddr.StringCast("/ip4/127.0.0.1/tcp/1")},
		&api.ServiceIngress{
			AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
			Allow:    []string{"email:alice@example.com"},
		},
		time.Now(),
	)

	callerRole := &api.PolicyRole{
		Name:            "caller",
		AllowedServices: []string{"a2a://echo"},
		AllowedTargets:  []string{"*"},
	}
	bobRaw, err := identity.MintDelegatedBiscuitToken(cpPriv, jwt.MapClaims{
		"sub":   "bob",
		"email": "bob@example.com",
	}, unreachablePeer, time.Now().Add(time.Hour), []string{"caller"}, []*api.PolicyRole{callerRole}, nil, false)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken(bob): %v", err)
	}
	standingNodeRaw, _, err := identity.MintBiscuitToken(cpPriv, jwt.MapClaims{
		"sub":   "alice",
		"email": "alice@example.com",
	}, nil, unreachablePeer, time.Now().Add(time.Hour), []string{"caller"}, []*api.PolicyRole{callerRole}, nil)
	if err != nil {
		t.Fatalf("MintBiscuitToken(standing): %v", err)
	}

	h := r.IngressHandler()
	targetPath := "/ingress/" + unreachablePeer.String() + "/a2a/echo/message:send"

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "unauthenticated rejected 401 before dial",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "compact JWT rejected 401 before dial",
			authHeader: "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ServiceIngress.allow mismatch rejected 403 before dial",
			authHeader: "Bearer " + base64.StdEncoding.EncodeToString(bobRaw),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unattenuated standing node Biscuit rejected 403 before dial",
			authHeader: "Bearer " + base64.StdEncoding.EncodeToString(standingNodeRaw),
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, targetPath, strings.NewReader(`{}`))
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d (%s), want %d (must not dial unreachable provider)", rec.Code, strings.TrimSpace(rec.Body.String()), tc.wantStatus)
			}
		})
	}
}

func TestRevocationSetDoesNotEvictLiveEntries(t *testing.T) {
	_, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	firstRaw, err := identity.MintDelegatedBiscuitToken(cpPriv, jwt.MapClaims{"sub": "first"}, pid, time.Now().Add(time.Hour), nil, nil, nil, false)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken: %v", err)
	}
	firstB, err := biscuit.Unmarshal(firstRaw)
	if err != nil {
		t.Fatalf("biscuit.Unmarshal: %v", err)
	}

	var set revocationSet
	now := time.Now()
	// Record the first Biscuit's root revocation ID in hex format.
	set.add(hex.EncodeToString(firstB.RevocationIds()[0]), now.Add(time.Hour))

	// Add 5,000 more live revocations (> old 4096 LRU capacity) plus expired entries.
	for i := 0; i < 5000; i++ {
		var id [32]byte
		id[0] = byte(i >> 8)
		id[1] = byte(i)
		id[2] = 1
		set.add(base64.RawURLEncoding.EncodeToString(id[:]), now.Add(time.Hour))
	}
	set.mu.Lock()
	set.entries["already-expired"] = now.Add(-time.Minute)
	set.mu.Unlock()

	if !set.isRevoked(firstB, now) {
		t.Fatal("first revoked Biscuit was evicted after 5000 inserts; deny list must never evict live entries")
	}
	if got := set.activeCount(now); got != 5001 {
		t.Fatalf("activeCount = %d, want 5001", got)
	}
}

func TestGatewaySafeIngressRateLimiting(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	r := newDirectoryRouter(t)
	r.config.ControlPlaneURL = "https://hub.example.com"
	r.config.BiscuitTimeout = 2 * time.Second
	limiter, err := ratelimit.NewPeerRateLimiterWithRate(128, 1, 2)
	if err != nil {
		t.Fatalf("NewPeerRateLimiterWithRate: %v", err)
	}
	r.ingressLimiter = limiter
	r.isReady.Store(true)

	routerBiscuitRaw, err := identity.MintBootstrapBiscuitToken(cpPriv, r.Host.ID(), api.RoleRouter, time.Now().Add(time.Hour), []*api.PolicyRole{
		{Name: api.RoleRouter, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}},
	}, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}
	r.keysMu.Lock()
	r.trustedPublicKeys = []ed25519.PublicKey{cpPub}
	r.credential = credential{biscuit: routerBiscuitRaw, expiration: time.Now().Add(time.Hour)}
	r.keysMu.Unlock()

	providerRole := &api.PolicyRole{
		Name:           "agent-host",
		AllowedPublish: []string{"a2a://*"},
		AllowedIngress: []*api.IngressGrant{{Services: []string{"a2a://echo"}}},
	}
	callerRole := &api.PolicyRole{
		Name:            "caller",
		AllowedServices: []string{"a2a://echo"},
		AllowedTargets:  []string{"*"},
	}
	roles := []*api.PolicyRole{providerRole, callerRole}
	provider := attachWithRole(t, r, cpPub, cpPriv, providerRole)
	providerAddr := provider.Addrs()[0].String() + "/p2p/" + provider.ID().String()

	ingListener, err := gostream.Listen(provider, api.IngressProtocolID)
	if err != nil {
		t.Fatalf("gostream.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ingListener.Close() })
	upstreamSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = upstreamSrv.Serve(ingListener) }()
	t.Cleanup(func() { _ = upstreamSrv.Close() })

	key, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, "echo")
	resp := ask(t, provider, r.Host.ID(), provideWithIngress(key, "a2a://echo", &api.ServiceIngress{
		AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
	}, providerAddr))
	if resp.GetError() != "" {
		t.Fatalf("provide failed: %s", resp.GetError())
	}

	mintCaller := func(sub string) string {
		raw, err := identity.MintDelegatedBiscuitToken(cpPriv, jwt.MapClaims{"sub": sub}, provider.ID(), time.Now().Add(time.Hour), []string{"caller"}, roles, nil, false)
		if err != nil {
			t.Fatalf("MintDelegatedBiscuitToken(%s): %v", sub, err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	tokA := mintCaller("alice")
	tokB := mintCaller("bob")

	h := r.IngressHandler()
	sharedGatewayRemoteAddr := "10.128.0.5:44321"
	targetPath := "/ingress/" + provider.ID().String() + "/a2a/echo"

	send := func(tok string) int {
		req := httptest.NewRequest(http.MethodPost, targetPath, strings.NewReader(`{}`))
		req.RemoteAddr = sharedGatewayRemoteAddr
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Exhaust Caller A's burst of 2 through the shared Gateway IP.
	if code := send(tokA); code != http.StatusOK {
		t.Fatalf("Caller A req 1 = %d, want 200", code)
	}
	if code := send(tokA); code != http.StatusOK {
		t.Fatalf("Caller A req 2 = %d, want 200", code)
	}
	if code := send(tokA); code != http.StatusTooManyRequests {
		t.Fatalf("Caller A req 3 = %d, want 429", code)
	}

	// Caller B sharing the exact same Gateway RemoteAddr must NOT be starved.
	if code := send(tokB); code != http.StatusOK {
		t.Fatalf("Caller B behind same Gateway IP = %d, want 200", code)
	}
}
