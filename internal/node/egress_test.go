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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// mintFor builds a token bound to peerID carrying facts, as the control plane
// would, and returns it with the verifying key.
func mintFor(t *testing.T, peerID peer.ID, facts ...biscuit.Fact) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	builder := biscuit.NewBuilder(priv)
	base := []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(peerID.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(peerID.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
	}
	for _, f := range append(base, facts...) {
		if err := builder.AddAuthorityFact(f); err != nil {
			t.Fatal(err)
		}
	}
	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	token, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token, pub
}

// TestAuthorizeHTTPFacts pins that method(), path(), host() and port() are
// injected from the RequestContext and decide both a narrowed grant and a
// node's local attenuation, and that a request without HTTP facts does not
// match a narrowed grant.
func TestAuthorizeHTTPFacts(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	caller := peer.ID("caller-peer")
	narrowed := api.BuildHTTPGrantFacts(&api.HTTPGrant{
		Service: "egress://api.github.com",
		Methods: []string{"GET"},
		Paths:   []string{"/repos/acme/*"},
	})
	token, pub := mintFor(t, caller, append(narrowed, api.MarkerFact(api.FactTargetUnrestricted))...)

	node := &SamNode{
		Store:          store,
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}
	request := func(method, path string) RequestContext {
		rc := RequestContext{PeerID: caller, Protocol: "/libp2p-http", Target: "egress://api.github.com",
			Egress: &EgressFacts{Host: "api.github.com", Port: 443}}
		if method != "" {
			rc.HTTP = &HTTPRequestFacts{Method: method, Path: path}
		}
		return rc
	}

	if err := node.Authorize(token, request("GET", "/repos/acme/x"), pub); err != nil {
		t.Errorf("GET under the granted prefix: %v", err)
	}
	if err := node.Authorize(token, request("POST", "/repos/acme/x"), pub); err == nil {
		t.Error("POST was allowed on a GET-only grant")
	}
	if err := node.Authorize(token, request("GET", "/user"), pub); err == nil {
		t.Error("a path outside the grant was allowed")
	}
	if err := node.Authorize(token, request("CONNECT", ""), pub); err == nil {
		t.Error("a tunnel was allowed on a narrowed grant")
	}
	if err := node.Authorize(token, request("", ""), pub); err == nil {
		t.Error("a request without HTTP facts was allowed on a narrowed grant")
	}

	// Local attenuation sees the same facts.
	cfg, err := CompleteNodeConfig(api.NodeConfig{Attenuation: api.Attenuation{Policies: []string{
		`deny if port($p), !($p == 443);`,
		`deny if host("payroll.internal.example.com");`,
		`deny if path($p), $p.starts_with("/repos/acme/secret");`,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	node.nodeConfig = cfg
	if err := node.Authorize(token, request("GET", "/repos/acme/x"), pub); err != nil {
		t.Errorf("attenuation denied a request it should not: %v", err)
	}
	if err := node.Authorize(token, request("GET", "/repos/acme/secret/1"), pub); err == nil {
		t.Error("attenuation on path() did not fire")
	}
	rc := request("GET", "/repos/acme/x")
	rc.Egress.Port = 8080
	if err := node.Authorize(token, rc, pub); err == nil {
		t.Error("attenuation on port() did not fire")
	}
}

// TestAuthorizeLocalIsSelfTargeted: a node authorizing a local client's
// request on its own credential passes the target check without a target
// grant, and nothing else is relaxed.
func TestAuthorizeLocalIsSelfTargeted(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	self := peer.ID("self-peer")
	grant := biscuit.Fact{Predicate: biscuit.Predicate{Name: api.FactGrantedServiceExact,
		IDs: []biscuit.Term{biscuit.String("egress"), biscuit.String("api.github.com")}}}
	token, pub := mintFor(t, self, grant)
	node := &SamNode{Store: store, trustedKeys: []TrustedKey{{Key: pub, ReceivedAt: time.Now()}}, BiscuitTimeout: 500 * time.Millisecond}

	local := RequestContext{PeerID: self, Protocol: "local-api", Target: "egress://api.github.com",
		HTTP: &HTTPRequestFacts{Method: "GET", Path: "/"}, Local: true}
	if err := node.Authorize(token, local, pub); err != nil {
		t.Errorf("local request on own credential denied: %v", err)
	}
	remote := local
	remote.Local = false
	if err := node.Authorize(token, remote, pub); err == nil {
		t.Error("the target check was skipped for a request that is not local")
	}
	other := local
	other.Target = "egress://other.example"
	if err := node.Authorize(token, other, pub); err == nil {
		t.Error("Local relaxed the service grant")
	}
}

// TestEgressServiceProxiesWithTheNodesCredential pins what the destination
// sees: the node's credential from the secrets directory, none of the
// caller's headers, the path as requested; and that a missing credential is
// refused at Init.
func TestEgressServiceProxiesWithTheNodesCredential(t *testing.T) {
	var got *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	secrets := t.TempDir()
	if err := os.WriteFile(filepath.Join(secrets, "github-eu"), []byte("ghp_token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &api.EgressDestination{Name: "api.github.com", TargetUrl: upstream.URL, Credential: "github-eu"}
	svc, err := newEgressService(d, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if facts := egressFactsFor(svc); facts == nil || facts.Host != "api.github.com" || facts.Port != mustPort(t, upstream.URL) {
		t.Errorf("egressFactsFor = %+v", facts)
	}

	req := httptest.NewRequest(http.MethodGet, "/repos/acme/x?state=open", nil)
	req.Header.Set("Authorization", "Bearer the-callers-token")
	req.Header.Set("Cookie", "session=the-callers-session")
	req.Header.Set(api.HeaderPeerID, "12D3KooWCaller")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if got.Header.Get("Authorization") != "Bearer ghp_token" {
		t.Errorf("upstream Authorization = %q, want the node's credential", got.Header.Get("Authorization"))
	}
	for _, h := range []string{"Cookie", api.HeaderPeerID, "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if got.Header.Get(h) != "" {
			t.Errorf("upstream saw %s=%q", h, got.Header.Get(h))
		}
	}
	if got.Header.Get("Accept") != "application/json" {
		t.Errorf("an ordinary header was dropped")
	}
	if got.URL.RequestURI() != "/repos/acme/x?state=open" {
		t.Errorf("upstream path = %q", got.URL.RequestURI())
	}

	// Rotation by the platform applies without a restart.
	if err := os.WriteFile(filepath.Join(secrets, "github-eu"), []byte("user:pass"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.HasPrefix(got.Header.Get("Authorization"), "Basic ") {
		t.Errorf("rotated credential not applied: %q", got.Header.Get("Authorization"))
	}

	// A credential that disappears after registration is a configuration
	// error the client can tell from the destination's own answer.
	if err := os.Remove(filepath.Join(secrets, "github-eu")); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	svc.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusBadGateway || rr.Header().Get("Proxy-Status") != "sam-node; error=proxy_configuration_error" {
		t.Errorf("missing credential at request time: %d %q", rr.Code, rr.Header().Get("Proxy-Status"))
	}

	// A credential the platform did not deliver is refused at Init.
	missing, err := newEgressService(&api.EgressDestination{Name: "x.example", Credential: "absent"}, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if err := missing.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("Init with a missing credential: %v", err)
	}
	// No credential named: the destination is reached anonymously.
	anon, err := newEgressService(&api.EgressDestination{Name: "x.example", TargetUrl: upstream.URL}, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if err := anon.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	anon.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got.Header.Get("Authorization") != "" {
		t.Errorf("anonymous destination received %q", got.Header.Get("Authorization"))
	}
}

func mustPort(t *testing.T, rawURL string) int {
	t.Helper()
	svc, err := newEgressService(&api.EgressDestination{Name: "p.example", TargetUrl: rawURL}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return svc.port()
}

// TestApplyEgressAssignmentsReconciles: assignments are registered, changed
// ones replaced, withdrawn ones unregistered, and one broken assignment does
// not stop the others.
func TestApplyEgressAssignmentsReconciles(t *testing.T) {
	secrets := t.TempDir()
	if err := os.WriteFile(filepath.Join(secrets, "cred"), []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	node := &SamNode{services: NewServiceRegistry(&fakeDHT{}, time.Second), config: Options{SecretsDir: secrets}}
	ctx := context.Background()
	assignments := func(outcome string) float64 {
		return counterValue(t, egressAssignmentsTotal.WithLabelValues(outcome))
	}
	registeredBefore, withdrawnBefore, refusedBefore := assignments("registered"), assignments("withdrawn"), assignments("refused")

	err := node.applyEgressAssignments(ctx, []*api.EgressDestination{
		{Name: "a.example", Credential: "cred"},
		{Name: "b.example"},
		{Name: "broken.example", Credential: "missing"},
	})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected the broken assignment to be reported, got %v", err)
	}
	if names := egressNames(node); !equalStrings(names, []string{"a.example", "b.example"}) {
		t.Fatalf("registered %v", names)
	}
	if got := assignments("registered") - registeredBefore; got != 2 {
		t.Errorf("registered counter moved by %v, want 2", got)
	}
	if got := assignments("refused") - refusedBefore; got != 1 {
		t.Errorf("refused counter moved by %v, want 1", got)
	}

	// b changes its target, a is withdrawn, c appears.
	if err := node.applyEgressAssignments(ctx, []*api.EgressDestination{
		{Name: "b.example", TargetUrl: "http://b.internal:8080"},
		{Name: "c.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if names := egressNames(node); !equalStrings(names, []string{"b.example", "c.example"}) {
		t.Fatalf("registered %v", names)
	}
	b, _ := node.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, "b.example")
	if facts := egressFactsFor(b); facts.Port != 8080 {
		t.Errorf("b was not replaced: %+v", facts)
	}
	if got := assignments("withdrawn") - withdrawnBefore; got != 1 {
		t.Errorf("withdrawn counter moved by %v, want 1", got)
	}
}

func egressNames(node *SamNode) []string {
	var names []string
	for _, info := range node.services.List(api.ServiceType_SERVICE_TYPE_EGRESS) {
		names = append(names, info.GetName())
	}
	return names
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}

// TestNodeConfigRefusesEgressServices: a destination is the control plane's
// to assign, so the node config cannot declare one.
func TestNodeConfigRefusesEgressServices(t *testing.T) {
	_, err := CompleteNodeConfig(api.NodeConfig{Services: []api.ServiceConfig{{Type: "egress", Name: "api.github.com", TargetURL: "https://api.github.com"}}})
	if err == nil || !strings.Contains(err.Error(), "assigned by the control plane") {
		t.Fatalf("CompleteNodeConfig accepted an egress service: %v", err)
	}
	_, err = NewServiceFromRequest(&api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_EGRESS, Name: "api.github.com"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "https://api.github.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "assigned by the control plane") {
		t.Fatalf("NewServiceFromRequest accepted an egress service: %v", err)
	}
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}
