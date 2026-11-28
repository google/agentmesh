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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/audit"
	"github.com/google/agentmesh/internal/identity"
	gostream "github.com/libp2p/go-libp2p-gostream"
	"github.com/libp2p/go-libp2p/core/host"
)

type routerAuditBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	notify chan struct{}
}

func newRouterAuditBuffer() *routerAuditBuffer {
	return &routerAuditBuffer{
		notify: make(chan struct{}, 100),
	}
}

func (b *routerAuditBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	n, err = b.buf.Write(p)
	b.mu.Unlock()
	if b.notify != nil {
		select {
		case b.notify <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (b *routerAuditBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *routerAuditBuffer) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw := strings.TrimSpace(b.buf.String())
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

func (b *routerAuditBuffer) WaitForLines(count int, timeout time.Duration) []string {
	deadline := time.Now().Add(timeout)
	for {
		if lines := b.Lines(); len(lines) >= count {
			return lines
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return b.Lines()
		}
		select {
		case <-b.notify:
		case <-time.After(remaining):
			return b.Lines()
		}
	}
}

type routerErrWriter struct{}

func (e *routerErrWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("simulated disk full")
}

func setupIngressAuditRouter(t *testing.T, auditLogger *audit.Logger) (*Router, host.Host, ed25519.PrivateKey, []*api.PolicyRole) {
	t.Helper()

	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	r := newDirectoryRouter(t)
	r.config.ControlPlaneURL = "https://hub.example.com"
	r.config.BiscuitTimeout = 2 * time.Second
	r.callAuditLogger = auditLogger

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
		AllowedPublish: []string{"mcp://*"},
		AllowedIngress: []*api.IngressGrant{
			{
				Services: []string{"mcp://calc"},
			},
		},
	}
	callerRole := &api.PolicyRole{
		Name:            "caller",
		AllowedServices: []string{"mcp://calc"},
		AllowedTargets:  []string{"*"},
	}
	roles := []*api.PolicyRole{providerRole, callerRole}
	bindings := []*api.PolicyBinding{
		{Role: "caller", Members: []string{"email:alice@example.com"}},
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

	ingListener, err := gostream.Listen(provider, api.IngressProtocolID)
	if err != nil {
		t.Fatalf("gostream.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ingListener.Close() })

	upstreamMux := http.NewServeMux()
	upstreamMux.HandleFunc("/mcp/calc", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"sum":3}}`))
	})
	upstreamSrv := &http.Server{Handler: upstreamMux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = upstreamSrv.Serve(ingListener) }()
	t.Cleanup(func() { _ = upstreamSrv.Close() })

	key, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "calc")
	if err != nil {
		t.Fatal(err)
	}
	resp := ask(t, provider, r.Host.ID(), provideWithIngress(key, "mcp://calc", &api.ServiceIngress{
		AuthMode: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
	}, providerAddr))
	if resp.GetError() != "" {
		t.Fatalf("provide mcp://calc failed: %s", resp.GetError())
	}

	if err := r.serveIngress("127.0.0.1:0"); err != nil {
		t.Fatalf("serveIngress: %v", err)
	}
	t.Cleanup(func() {
		if r.ingressServer != nil {
			_ = r.ingressServer.Close()
		}
	})
	r.isReady.Store(true)

	return r, provider, cpPriv, roles
}

func mintTestCallerToken(t *testing.T, cpPriv ed25519.PrivateKey, provider host.Host, roles []*api.PolicyRole, labels map[string]string, allowedTools []string) string {
	t.Helper()

	var taskRule *api.TaskAuthorizationRule
	if len(allowedTools) > 0 {
		taskRule = &api.TaskAuthorizationRule{
			Name: "calc-task",
			Rules: []*api.TaskRule{
				{
					AllowedServices: []string{"mcp://calc"},
					Operation:       &api.TaskOperation{AllowedTools: allowedTools},
				},
			},
		}
	}

	claims := jwt.MapClaims{
		"sub":   "alice",
		"email": "alice@example.com",
	}

	tok, _, err := identity.MintBiscuitToken(cpPriv, claims, nil, provider.ID(), time.Now().Add(time.Hour), []string{"caller"}, roles, labels)
	if err != nil {
		t.Fatalf("MintBiscuitToken: %v", err)
	}
	if taskRule != nil {
		tok, err = identity.AttenuateBiscuit(tok, taskRule)
		if err != nil {
			t.Fatalf("AttenuateBiscuit: %v", err)
		}
	}
	tok, err = identity.SealBiscuit(tok)
	if err != nil {
		t.Fatalf("SealBiscuit: %v", err)
	}
	return base64.StdEncoding.EncodeToString(tok)
}

func TestRouterIngressAudit_DisabledByDefault(t *testing.T) {
	r, provider, cpPriv, roles := setupIngressAuditRouter(t, nil)
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://" + r.IngressAddr().String() + "/ingress"

	tok := mintTestCallerToken(t, cpPriv, provider, roles, nil, []string{"add"})

	req, err := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/mcp/calc",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":1,"b":2}}}`))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if r.CallAuditLogger() != nil {
		t.Errorf("expected CallAuditLogger() to be nil when disabled")
	}
}

func TestRouterIngressAudit_SuccessAndPayloadExclusion(t *testing.T) {
	buf := newRouterAuditBuffer()
	logger := audit.New(buf)

	r, provider, cpPriv, roles := setupIngressAuditRouter(t, logger)
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://" + r.IngressAddr().String() + "/ingress"

	labels := map[string]string{"env": "prod", "tier": "gold"}
	tok := mintTestCallerToken(t, cpPriv, provider, roles, labels, []string{"add"})

	secretPayload := "super_secret_payload_argument_value"
	bodyStr := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":1,"b":2,"secret":"` + secretPayload + `"}}}`

	req, err := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/mcp/calc", strings.NewReader(bodyStr))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	lines := buf.WaitForLines(1, 2*time.Second)
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit record, got %d: %v", len(lines), lines)
	}

	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("json.Unmarshal audit record: %v", err)
	}

	if rec.ProviderPeerID != provider.ID().String() {
		t.Errorf("ProviderPeerID = %q, want %q", rec.ProviderPeerID, provider.ID().String())
	}
	if rec.ServiceName != "calc" {
		t.Errorf("ServiceName = %q, want %q", rec.ServiceName, "calc")
	}
	if rec.ToolName != "add" {
		t.Errorf("ToolName = %q, want %q", rec.ToolName, "add")
	}
	if rec.Outcome != audit.OutcomeOK {
		t.Errorf("Outcome = %q, want %q", rec.Outcome, audit.OutcomeOK)
	}
	if rec.CallerLabels["env"] != "prod" || rec.CallerLabels["tier"] != "gold" {
		t.Errorf("CallerLabels = %v, want env=prod, tier=gold", rec.CallerLabels)
	}
	if rec.Timestamp == "" {
		t.Errorf("Timestamp is empty")
	} else if _, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err != nil {
		t.Errorf("Timestamp %q is not RFC3339: %v", rec.Timestamp, err)
	}
	if rec.BytesIn <= 0 {
		t.Errorf("BytesIn = %d, want > 0", rec.BytesIn)
	}
	if rec.BytesOut <= 0 {
		t.Errorf("BytesOut = %d, want > 0", rec.BytesOut)
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, secretPayload) {
		t.Errorf("SECURITY LEAK: audit log contains sensitive payload: %s", logOutput)
	}
	if strings.Contains(logOutput, tok) {
		t.Errorf("SECURITY LEAK: audit log contains bearer token: %s", logOutput)
	}
}

func TestRouterIngressAudit_PreDialTARRejection(t *testing.T) {
	buf := newRouterAuditBuffer()
	logger := audit.New(buf)

	r, provider, cpPriv, roles := setupIngressAuditRouter(t, logger)
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://" + r.IngressAddr().String() + "/ingress"

	// Token only allows "add", so "drop_database" is denied pre-dial.
	tok := mintTestCallerToken(t, cpPriv, provider, roles, map[string]string{"env": "test"}, []string{"add"})

	req, err := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/mcp/calc",
		strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"drop_database"}}`))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 Forbidden", resp.StatusCode)
	}

	lines := buf.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit record, got %d: %v", len(lines), lines)
	}

	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if rec.ToolName != "drop_database" {
		t.Errorf("ToolName = %q, want drop_database", rec.ToolName)
	}
	if rec.Outcome != audit.OutcomeUnauthorized {
		t.Errorf("Outcome = %q, want %q", rec.Outcome, audit.OutcomeUnauthorized)
	}
	if rec.ServiceName != "calc" {
		t.Errorf("ServiceName = %q, want calc", rec.ServiceName)
	}
	if rec.CallerLabels["env"] != "test" {
		t.Errorf("CallerLabels = %v, want env=test", rec.CallerLabels)
	}
}

func TestRouterIngressAudit_LoggingFailureTolerance(t *testing.T) {
	logger := audit.New(&routerErrWriter{})

	r, provider, cpPriv, roles := setupIngressAuditRouter(t, logger)
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := "http://" + r.IngressAddr().String() + "/ingress"

	tok := mintTestCallerToken(t, cpPriv, provider, roles, nil, []string{"add"})

	req, err := http.NewRequest(http.MethodPost, baseURL+"/"+provider.ID().String()+"/mcp/calc",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":1,"b":2}}}`))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Even though audit logger write fails, the ingress tool call must succeed!
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 OK despite logger failure", resp.StatusCode)
	}
}
