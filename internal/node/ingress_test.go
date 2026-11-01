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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func mustTestPeerID(t *testing.T) (peer.ID, libp2pcrypto.PrivKey) {
	t.Helper()
	priv, _, err := libp2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	return pid, priv
}

type fakeIngressDHT struct {
	fakeDHT
	ingressCalls   []ingressProvideCall
	failIngressErr error
}

type ingressProvideCall struct {
	key     []byte
	service string
	ingress *api.ServiceIngress
}

func (f *fakeIngressDHT) ProvideWithIngress(_ context.Context, key []byte, service string, ing *api.ServiceIngress) error {
	f.ingressCalls = append(f.ingressCalls, ingressProvideCall{
		key:     append([]byte(nil), key...),
		service: service,
		ingress: ing,
	})
	return f.failIngressErr
}

func TestServiceRegistry_ProvideWithIngressOnlyOnNamedKey(t *testing.T) {
	dht := &fakeIngressDHT{}
	reg := newServiceRegistryForTest(dht)

	var callbackInfo *api.ServiceInfo
	reg.onIngressRegistered = func(info *api.ServiceInfo) {
		callbackInfo = info
	}

	svc := &fakeService{
		info: &api.ServiceInfo{
			Name: "assistant",
			Type: api.ServiceType_SERVICE_TYPE_A2A,
			Ingress: &api.ServiceIngress{
				AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
				Allow:    []string{"email:alice@example.com"},
			},
		},
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
	}
	if err := reg.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(dht.ingressCalls) != 1 {
		t.Fatalf("ProvideWithIngress calls = %d, want 1", len(dht.ingressCalls))
	}
	if dht.ingressCalls[0].service != "a2a://assistant" {
		t.Errorf("ProvideWithIngress service = %q, want a2a://assistant", dht.ingressCalls[0].service)
	}
	if len(dht.calls) != 1 {
		t.Fatalf("plain Provide calls (type key) = %d, want 1", len(dht.calls))
	}
	if callbackInfo == nil || callbackInfo.GetName() != "assistant" {
		t.Errorf("onIngressRegistered callback info = %v, want assistant", callbackInfo)
	}
}

func TestCompleteNodeConfig_ValidatesServiceIngress(t *testing.T) {
	cfg := api.NodeConfig{
		Services: []api.ServiceConfig{
			{
				Name:      "assistant",
				Type:      "a2a",
				TargetURL: "http://127.0.0.1:8081",
				Ingress:   &api.IngressConfig{AuthMode: "edge", Allow: []string{"email:alice@example.com"}},
			},
		},
	}
	if _, err := CompleteNodeConfig(cfg); err != nil {
		t.Fatalf("CompleteNodeConfig valid ingress failed: %v", err)
	}

	badCfg := api.NodeConfig{
		Services: []api.ServiceConfig{
			{
				Name:      "assistant",
				Type:      "a2a",
				TargetURL: "http://127.0.0.1:8081",
				Ingress:   &api.IngressConfig{AuthMode: "bogus"},
			},
		},
	}
	if _, err := CompleteNodeConfig(badCfg); err == nil {
		t.Fatal("CompleteNodeConfig accepted invalid ingress auth_mode")
	}
}

func TestServiceRegistry_RefusedIngressFallsBackToInternalProvide(t *testing.T) {
	dht := &fakeIngressDHT{
		failIngressErr: errors.New("router refused ingress role ceiling"),
	}
	reg := newServiceRegistryForTest(dht)

	var callbackInfo *api.ServiceInfo
	reg.onIngressRegistered = func(info *api.ServiceInfo) {
		callbackInfo = info
	}

	svc := &fakeService{
		info: &api.ServiceInfo{
			Name: "ungranted",
			Type: api.ServiceType_SERVICE_TYPE_A2A,
			Ingress: &api.ServiceIngress{
				AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
			},
		},
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
	}

	beforeIngressFail := counterValue(t, serviceProvideFailuresTotal.WithLabelValues(provideFailureScopeIngress))
	if err := reg.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	afterIngressFail := counterValue(t, serviceProvideFailuresTotal.WithLabelValues(provideFailureScopeIngress))
	if afterIngressFail != beforeIngressFail+1 {
		t.Errorf("ingress failure counter = %v, want %v", afterIngressFail, beforeIngressFail+1)
	}
	if callbackInfo != nil {
		t.Errorf("onIngressRegistered called with %v when ingress announcement failed, want nil", callbackInfo)
	}
	if len(dht.ingressCalls) != 1 {
		t.Fatalf("ProvideWithIngress calls = %d, want 1", len(dht.ingressCalls))
	}
	nameKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, "ungranted")
	typeKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, "")
	if len(dht.calls) != 2 || !bytes.Equal(dht.calls[0], nameKey) || !bytes.Equal(dht.calls[1], typeKey) {
		t.Fatalf("plain Provide calls = %d, want 2 (fallback nameKey + typeKey)", len(dht.calls))
	}

	// ReprovideAll also falls back while ingress remains refused, then succeeds without fallback once granted.
	if withheld := reg.ReprovideAll(context.Background()); withheld != 0 {
		t.Fatalf("ReprovideAll withheld = %d, want 0", withheld)
	}
	if len(dht.ingressCalls) != 2 || len(dht.calls) != 4 {
		t.Fatalf("after refused ReprovideAll: ingressCalls=%d calls=%d, want 2 and 4", len(dht.ingressCalls), len(dht.calls))
	}

	dht.failIngressErr = nil
	if withheld := reg.ReprovideAll(context.Background()); withheld != 0 {
		t.Fatalf("ReprovideAll after policy fix withheld = %d, want 0", withheld)
	}
	if len(dht.ingressCalls) != 3 || len(dht.calls) != 5 {
		t.Fatalf("after policy fix ReprovideAll: ingressCalls=%d calls=%d, want 3 and 5 (typeKey only)", len(dht.ingressCalls), len(dht.calls))
	}
}

func TestPassthroughWithBackendCredentialRejected(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(authFile, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("CompleteNodeConfig rejects passthrough with target_auth_path", func(t *testing.T) {
		cfg := api.NodeConfig{
			Services: []api.ServiceConfig{
				{
					Name:           "webhook",
					Type:           "a2a",
					TargetURL:      "http://127.0.0.1:8081",
					TargetAuthPath: authFile,
					Ingress:        &api.IngressConfig{AuthMode: "passthrough"},
				},
			},
		}
		if _, err := CompleteNodeConfig(cfg); err == nil {
			t.Fatal("expected error for passthrough + target_auth_path, got nil")
		}
	})

	t.Run("CompleteNodeConfig rejects passthrough with inline target_url credential", func(t *testing.T) {
		cfg := api.NodeConfig{
			Services: []api.ServiceConfig{
				{
					Name:      "webhook",
					Type:      "a2a",
					TargetURL: "http://bearer:secret-token@127.0.0.1:8081",
					Ingress:   &api.IngressConfig{AuthMode: "passthrough"},
				},
			},
		}
		if _, err := CompleteNodeConfig(cfg); err == nil {
			t.Fatal("expected error for passthrough + inline target_url credential, got nil")
		}
	})

	t.Run("CompleteNodeConfig allows edge with target_auth_path", func(t *testing.T) {
		cfg := api.NodeConfig{
			Services: []api.ServiceConfig{
				{
					Name:           "assistant",
					Type:           "a2a",
					TargetURL:      "http://127.0.0.1:8081",
					TargetAuthPath: authFile,
					Ingress:        &api.IngressConfig{AuthMode: "edge"},
				},
			},
		}
		if _, err := CompleteNodeConfig(cfg); err != nil {
			t.Fatalf("expected edge + target_auth_path to succeed, got: %v", err)
		}
	})

	t.Run("buildRegisterRequest and NewServiceFromRequest reject passthrough with credential", func(t *testing.T) {
		if _, err := buildRegisterRequest(api.ServiceConfig{
			Name:           "webhook",
			Type:           "a2a",
			TargetURL:      "http://127.0.0.1:8081",
			TargetAuthPath: authFile,
			Ingress:        &api.IngressConfig{AuthMode: "passthrough"},
		}); err == nil {
			t.Fatal("buildRegisterRequest accepted passthrough + target_auth_path")
		}
		if _, err := buildRegisterRequest(api.ServiceConfig{
			Name:      "webhook",
			Type:      "a2a",
			TargetURL: "http://bearer:secret-token@127.0.0.1:8081",
			Ingress:   &api.IngressConfig{AuthMode: "passthrough"},
		}); err == nil {
			t.Fatal("buildRegisterRequest accepted passthrough + inline target_url credential")
		}
		if _, err := NewServiceFromRequest(&api.RegisterServiceRequest{
			Service: &api.ServiceInfo{
				Name: "webhook",
				Type: api.ServiceType_SERVICE_TYPE_A2A,
				Ingress: &api.ServiceIngress{
					AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
				},
			},
			Backend: &api.RegisterServiceRequest_TargetUrl{
				TargetUrl: "http://bearer:secret-token@127.0.0.1:8081",
			},
		}); err == nil {
			t.Fatal("NewServiceFromRequest accepted passthrough + inline backend credential")
		}
	})
}

func TestExternalIngressHandler(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	routerPID, _ := mustTestPeerID(t)
	otherRouterPID, _ := mustTestPeerID(t)
	memberPID, _ := mustTestPeerID(t)
	servingPID, servingPriv := mustTestPeerID(t)
	actorPID, _ := mustTestPeerID(t)

	exp := time.Now().Add(time.Hour)

	routerBiscuit, _, err := identity.MintBiscuitToken(
		cpPriv,
		jwt.MapClaims{"sub": "router-1"},
		nil,
		routerPID,
		exp,
		[]string{api.RoleRouter},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("MintBiscuitToken router: %v", err)
	}
	routerB64 := base64.StdEncoding.EncodeToString(routerBiscuit)

	memberBiscuit, _, err := identity.MintBiscuitToken(
		cpPriv,
		jwt.MapClaims{"sub": "member-1", "email": "alice@example.com"},
		nil,
		memberPID,
		exp,
		[]string{"external-caller"},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("MintBiscuitToken member: %v", err)
	}
	memberB64 := base64.StdEncoding.EncodeToString(memberBiscuit)

	servingBiscuit, _, err := identity.MintBiscuitToken(
		cpPriv,
		jwt.MapClaims{"sub": "owner-1", "email": "owner@example.com"},
		nil,
		servingPID,
		exp,
		[]string{"provider"},
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("MintBiscuitToken serving node: %v", err)
	}

	policyRoles := []*api.PolicyRole{
		{
			Name:            "external-caller",
			AllowedServices: []string{"a2a://assistant", "mcp://files"},
			AllowedTargets:  []string{"email:owner@example.com"},
		},
	}
	policyBindings := []*api.PolicyBinding{
		{
			Role:    "external-caller",
			Members: []string{"email:alice@example.com", "email:bob@example.com"},
		},
	}
	compiled, warnings := api.BuildPolicyRules(policyRoles, policyBindings)
	if len(warnings) != 0 {
		t.Fatalf("BuildPolicyRules warnings: %v", warnings)
	}
	meshRules, err := api.ParseDatalogRules(api.PolicyRuleTexts(compiled))
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}

	delegatedAlice, err := identity.MintDelegatedBiscuitToken(
		cpPriv,
		jwt.MapClaims{"sub": "user-alice", "email": "alice@example.com"},
		actorPID,
		exp,
		[]string{"external-caller"},
		policyRoles,
		&api.TaskAuthorizationRule{
			Name: "task-read-only",
			Rules: []*api.TaskRule{
				{
					AllowedServices: []string{"a2a://assistant"},
				},
				{
					AllowedServices: []string{"mcp://files"},
					Operation:       &api.TaskOperation{AllowedTools: []string{"read_file"}},
				},
			},
		},
		true,
	)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken alice: %v", err)
	}
	delegatedAliceB64 := base64.StdEncoding.EncodeToString(delegatedAlice)

	delegatedBob, err := identity.MintDelegatedBiscuitToken(
		cpPriv,
		jwt.MapClaims{"sub": "user-bob", "email": "bob@example.com"},
		actorPID,
		exp,
		[]string{"external-caller"},
		policyRoles,
		nil,
		true,
	)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken bob: %v", err)
	}
	delegatedBobB64 := base64.StdEncoding.EncodeToString(delegatedBob)

	localDenyAdmin, err := parser.FromStringPolicy(`deny if path($p), $p == "/admin"`)
	if err != nil {
		t.Fatalf("FromStringPolicy: %v", err)
	}

	reg := newServiceRegistryForTest(&fakeDHT{})

	var capturedHeaders http.Header
	var capturedPath string

	recordHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		capturedPath = r.URL.Path
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"assistant","version":"1.0.0"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	for _, svc := range []*fakeService{
		{
			info: &api.ServiceInfo{
				Name: "assistant",
				Type: api.ServiceType_SERVICE_TYPE_A2A,
				Ingress: &api.ServiceIngress{
					AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
					Allow:    []string{"email:alice@example.com"},
				},
			},
			handler: recordHandler,
		},
		{
			info: &api.ServiceInfo{
				Name: "files",
				Type: api.ServiceType_SERVICE_TYPE_MCP,
				Ingress: &api.ServiceIngress{
					AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
				},
			},
			handler: recordHandler,
		},
		{
			info: &api.ServiceInfo{
				Name: "webhook",
				Type: api.ServiceType_SERVICE_TYPE_A2A,
				Ingress: &api.ServiceIngress{
					AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
				},
			},
			handler: recordHandler,
		},
		{
			info: &api.ServiceInfo{
				Name: "internal-only",
				Type: api.ServiceType_SERVICE_TYPE_A2A,
			},
			handler: recordHandler,
		},
	} {
		if err := reg.Register(context.Background(), svc); err != nil {
			t.Fatalf("Register %s: %v", svc.info.Name, err)
		}
	}

	n := &AgentMeshNode{
		config:          Options{PrivKey: servingPriv},
		trustedKeys:     []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}},
		MeshPolicyRules: meshRules,
		nodeConfig:      &NodeConfigComplete{Policies: []biscuit.Policy{localDenyAdmin}},
		services:        reg,
		BiscuitTimeout:  time.Second,
	}
	n.SetIdentityCache(servingBiscuit)

	h := n.externalIngressHandler()

	t.Run("non-router peer rejected with 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/", strings.NewReader(`{}`))
		req.RemoteAddr = memberPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, memberB64)
		req.Header.Set(api.HeaderMeshIngressCallerBiscuit, delegatedAliceB64)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("router biscuit bound to different peer rejected with 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/", strings.NewReader(`{}`))
		req.RemoteAddr = otherRouterPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, routerB64)
		req.Header.Set(api.HeaderMeshIngressCallerBiscuit, delegatedAliceB64)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("internal-only service rejected with 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/internal-only/", strings.NewReader(`{}`))
		req.RemoteAddr = routerPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, routerB64)
		req.Header.Set(api.HeaderMeshIngressCallerBiscuit, delegatedAliceB64)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unauthenticated A2A agent card GET allowed in edge mode, POST denied", func(t *testing.T) {
		getReq := httptest.NewRequest(http.MethodGet, "http://mesh/a2a/assistant/.well-known/agent-card.json", nil)
		getReq.RemoteAddr = routerPID.String()
		getReq.Header.Set(api.HeaderMeshBiscuit, routerB64)
		getReq.Header.Set("Authorization", "Bearer should-be-stripped")
		getReq.Header.Set("Cookie", "session=secret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, getReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET agent-card status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if capturedHeaders.Get("Authorization") != "" || capturedHeaders.Get("Cookie") != "" {
			t.Errorf("expected Authorization and Cookie stripped on agent card fetch, got %v", capturedHeaders)
		}

		postReq := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/", strings.NewReader(`{}`))
		postReq.RemoteAddr = routerPID.String()
		postReq.Header.Set(api.HeaderMeshBiscuit, routerB64)
		postRec := httptest.NewRecorder()
		h.ServeHTTP(postRec, postReq)
		if postRec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated POST status = %d, want 401: %s", postRec.Code, postRec.Body.String())
		}
	})

	t.Run("edge delegated biscuit succeeds and stamps verified caller headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/v1/messages", strings.NewReader(`{}`))
		req.RemoteAddr = routerPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, routerB64)
		req.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringEdge)
		req.Header.Set(api.HeaderMeshIngressCallerBiscuit, delegatedAliceB64)
		req.Header.Set("Authorization", "Bearer external-raw")
		req.Header.Set("Cookie", "sid=123")
		req.Header.Set(api.HeaderMeshPrincipal, "spoofed@evil.example")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if capturedPath != "/v1/messages" {
			t.Errorf("backend path = %q, want /v1/messages", capturedPath)
		}
		if got := capturedHeaders.Get(api.HeaderMeshPrincipal); got != "alice@example.com" {
			t.Errorf("X-Mesh-Principal = %q, want alice@example.com", got)
		}
		if got := capturedHeaders.Get(api.HeaderMeshTask); got != "task-read-only" {
			t.Errorf("X-Mesh-Task = %q, want task-read-only", got)
		}
		if got := capturedHeaders.Get(api.HeaderMeshIngress); got != api.IngressAuthModeStringEdge {
			t.Errorf("X-Mesh-Ingress = %q, want edge", got)
		}
		if got := capturedHeaders.Get(api.HeaderPeerID); got != routerPID.String() {
			t.Errorf("X-Peer-Id = %q, want %s", got, routerPID)
		}
		if capturedHeaders.Get("Authorization") != "" || capturedHeaders.Get("Cookie") != "" || capturedHeaders.Get(api.HeaderMeshIngressCallerBiscuit) != "" {
			t.Errorf("sensitive headers leaked to backend: %v", capturedHeaders)
		}
	})

	t.Run("edge allow list rejects bob even though mesh role permits bob", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/", strings.NewReader(`{}`))
		req.RemoteAddr = routerPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, routerB64)
		req.Header.Set(api.HeaderMeshIngressCallerBiscuit, delegatedBobB64)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("standing transport member biscuit rejected as edge caller token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/", strings.NewReader(`{}`))
		req.RemoteAddr = routerPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, routerB64)
		req.Header.Set(api.HeaderMeshIngressCallerBiscuit, memberB64)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("local nodeConfig policy denies /admin on edge delegated biscuit", func(t *testing.T) {
		adminReq := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/admin", strings.NewReader(`{}`))
		adminReq.RemoteAddr = routerPID.String()
		adminReq.Header.Set(api.HeaderMeshBiscuit, routerB64)
		adminReq.Header.Set(api.HeaderMeshIngressCallerBiscuit, delegatedAliceB64)
		adminRec := httptest.NewRecorder()
		h.ServeHTTP(adminRec, adminReq)
		if adminRec.Code != http.StatusForbidden {
			t.Fatalf("local /admin deny status = %d, want 403: %s", adminRec.Code, adminRec.Body.String())
		}
	})

	t.Run("uninitialized service registry returns 503 and increments invalid counter", func(t *testing.T) {
		uninitNode := &AgentMeshNode{
			config:         Options{PrivKey: servingPriv},
			trustedKeys:    []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}},
			BiscuitTimeout: time.Second,
		}
		before := counterValue(t, externalIngressRequestsTotal.WithLabelValues("unknown", externalIngressOutcomeInvalid))
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/", strings.NewReader(`{}`))
		req.RemoteAddr = routerPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, routerB64)
		rec := httptest.NewRecorder()
		uninitNode.externalIngressHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
		}
		after := counterValue(t, externalIngressRequestsTotal.WithLabelValues("unknown", externalIngressOutcomeInvalid))
		if after != before+1 {
			t.Errorf("invalid counter = %v, want %v", after, before+1)
		}
	})

	t.Run("MCP tool-level TAR enforced on external edge ingress", func(t *testing.T) {
		allowBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`
		allowReq := httptest.NewRequest(http.MethodPost, "http://mesh/mcp/files/", bytes.NewBufferString(allowBody))
		allowReq.RemoteAddr = routerPID.String()
		allowReq.Header.Set(api.HeaderMeshBiscuit, routerB64)
		allowReq.Header.Set(api.HeaderMeshIngressCallerBiscuit, delegatedAliceB64)
		allowRec := httptest.NewRecorder()
		h.ServeHTTP(allowRec, allowReq)
		if allowRec.Code != http.StatusOK {
			t.Fatalf("allowed MCP tool status = %d, want 200: %s", allowRec.Code, allowRec.Body.String())
		}

		denyBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file"}}`
		denyReq := httptest.NewRequest(http.MethodPost, "http://mesh/mcp/files/", bytes.NewBufferString(denyBody))
		denyReq.RemoteAddr = routerPID.String()
		denyReq.Header.Set(api.HeaderMeshBiscuit, routerB64)
		denyReq.Header.Set(api.HeaderMeshIngressCallerBiscuit, delegatedAliceB64)
		denyRec := httptest.NewRecorder()
		h.ServeHTTP(denyRec, denyReq)
		if denyRec.Code != http.StatusForbidden {
			t.Fatalf("denied MCP tool status = %d, want 403: %s", denyRec.Code, denyRec.Body.String())
		}
	})

	t.Run("passthrough preserves Authorization and strips Cookie and X-Mesh-*", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/webhook/events", strings.NewReader(`{"event":"ping"}`))
		req.RemoteAddr = routerPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, routerB64)
		req.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringPassthrough)
		req.Header.Set("Authorization", "Bearer backend-app-secret")
		req.Header.Set("X-Hub-Signature-256", "sha256=abcdef")
		req.Header.Set("Cookie", "evil=cookie")
		req.Header.Set(api.HeaderMeshPrincipal, "spoofed@evil.example")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("passthrough status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if got := capturedHeaders.Get("Authorization"); got != "Bearer backend-app-secret" {
			t.Errorf("Authorization = %q, want Bearer backend-app-secret", got)
		}
		if got := capturedHeaders.Get("X-Hub-Signature-256"); got != "sha256=abcdef" {
			t.Errorf("X-Hub-Signature-256 = %q, want sha256=abcdef", got)
		}
		if got := capturedHeaders.Get(api.HeaderMeshIngress); got != api.IngressAuthModeStringPassthrough {
			t.Errorf("X-Mesh-Ingress = %q, want passthrough", got)
		}
		if capturedHeaders.Get("Cookie") != "" || capturedHeaders.Get(api.HeaderMeshPrincipal) != "" {
			t.Errorf("expected Cookie and X-Mesh-Principal stripped in passthrough, got %v", capturedHeaders)
		}
	})

	t.Run("mode mismatch header rejected fail-closed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://mesh/a2a/assistant/", strings.NewReader(`{}`))
		req.RemoteAddr = routerPID.String()
		req.Header.Set(api.HeaderMeshBiscuit, routerB64)
		req.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringPassthrough)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("mode mismatch status = %d, want 403: %s", rec.Code, rec.Body.String())
		}
	})
}
