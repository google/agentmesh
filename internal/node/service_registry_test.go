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
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
)

type fakeDHT struct {
	calls     [][]byte
	withdrawn [][]byte
	failNth   int
	count     int32
}

func (f *fakeDHT) Provide(ctx context.Context, key []byte, service string) error {
	n := atomic.AddInt32(&f.count, 1)
	f.calls = append(f.calls, key)
	if f.failNth > 0 && int(n) == f.failNth {
		return errors.New("fake dht failure")
	}
	return nil
}

func (f *fakeDHT) Withdraw(ctx context.Context, key []byte) error {
	f.withdrawn = append(f.withdrawn, key)
	return nil
}

type fakeService struct {
	info          *api.ServiceInfo
	initCalls     int
	teardownCalls int
	initErr       error
	handler       http.Handler
}

func (f *fakeService) Info() *api.ServiceInfo { return f.info }
func (f *fakeService) Init(ctx context.Context) error {
	f.initCalls++
	return f.initErr
}
func (f *fakeService) Handler() http.Handler { return f.handler }
func (f *fakeService) Teardown() error {
	f.teardownCalls++
	return nil
}

func newFakeSvc(name string, st api.ServiceType) *fakeService {
	return &fakeService{
		info:    &api.ServiceInfo{Name: name, Type: st},
		handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
	}
}

// newServiceRegistryForTest builds a registry against the fake DHT for tests.
func newServiceRegistryForTest(d directoryProvider) *ServiceRegistry {
	return &ServiceRegistry{
		services:            map[string]Service{},
		dht:                 d,
		backendProbeTimeout: defaultDHTProbeTimeout,
	}
}

func TestServiceRegistry_RegisterCallsInitThenProvide(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if svc.initCalls != 1 {
		t.Errorf("Init called %d times, want 1", svc.initCalls)
	}
	if len(dht.calls) != 2 {
		t.Fatalf("Provide called %d times, want 2 (name + type CID)", len(dht.calls))
	}
}

func TestServiceRegistry_InitErrorBlocksProvideAndInsertion(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	svc.initErr = errors.New("init failed")
	if err := r.Register(context.Background(), svc); err == nil {
		t.Fatal("expected error from Register, got nil")
	}
	if len(dht.calls) != 0 {
		t.Errorf("Provide called %d times after Init failure, want 0", len(dht.calls))
	}
	if _, ok := r.Get("demo"); ok {
		t.Error("service should not be in map after Init failure")
	}
}

// H2: policy is evaluated on type://name and the registry was keyed on name
// alone, so a peer granted a2a://reports reached mcp://reports. A name now
// belongs to one type, and dispatch looks it up under the granted type.
func TestServiceRegistry_OneNameOneType(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	ctx := context.Background()

	mcpSvc := newFakeSvc("reports", api.ServiceType_SERVICE_TYPE_MCP)
	if err := r.Register(ctx, mcpSvc); err != nil {
		t.Fatalf("Register mcp://reports: %v", err)
	}

	a2aSvc := newFakeSvc("reports", api.ServiceType_SERVICE_TYPE_A2A)
	if err := r.Register(ctx, a2aSvc); err == nil {
		t.Fatal("a2a://reports registered beside mcp://reports")
	}
	if a2aSvc.initCalls != 0 {
		t.Error("the refused service was initialised")
	}
	if svc, _ := r.Get("reports"); svc != mcpSvc {
		t.Error("the refused registration replaced the existing service")
	}

	// Re-registering the same name under the same type is the normal
	// re-declare path and stays allowed.
	if err := r.Register(ctx, newFakeSvc("reports", api.ServiceType_SERVICE_TYPE_MCP)); err != nil {
		t.Errorf("same-type re-registration refused: %v", err)
	}

	if _, ok := r.GetTyped(api.ServiceType_SERVICE_TYPE_MCP, "reports"); !ok {
		t.Error("GetTyped(mcp, reports) missed the registered service")
	}
	if _, ok := r.GetTyped(api.ServiceType_SERVICE_TYPE_A2A, "reports"); ok {
		t.Error("GetTyped(a2a, reports) returned the mcp service: a grant for one type would reach the other")
	}
}

func TestServiceRegistry_UnregisterRemovesAndCallsTeardown(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	_ = r.Register(context.Background(), svc)
	if err := r.Unregister(context.Background(), "demo"); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if svc.teardownCalls != 1 {
		t.Errorf("Teardown called %d times, want 1", svc.teardownCalls)
	}
	if _, ok := r.Get("demo"); ok {
		t.Error("service still present after Unregister")
	}
}

func TestServiceRegistry_UnregisterUnknownIsNoOp(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	if err := r.Unregister(context.Background(), "missing"); err != nil {
		t.Fatalf("Unregister missing: %v", err)
	}
}

func TestServiceRegistry_ListFiltersByType(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	_ = r.Register(context.Background(), newFakeSvc("a", api.ServiceType_SERVICE_TYPE_MCP))
	_ = r.Register(context.Background(), newFakeSvc("b", api.ServiceType_SERVICE_TYPE_INFERENCE))

	all := r.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)
	if len(all) != 2 {
		t.Errorf("List(all): got %d, want 2", len(all))
	}
	mcpOnly := r.List(api.ServiceType_SERVICE_TYPE_MCP)
	if len(mcpOnly) != 1 || mcpOnly[0].Name != "a" {
		t.Errorf("List(MCP): got %v, want [a]", mcpOnly)
	}
}

func TestServiceRegistry_ResolveMCPByHostPath(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	insertMCP := func(name, targetURL string) {
		r.insertService(&MCPService{
			baseService: baseService{
				info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: name},
				backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: targetURL},
			},
		})
	}
	insertMCP("github-copilot", "https://:secret@api.githubcopilot.com/mcp")
	insertMCP("root-mcp", "https://tools.example.com")
	insertMCP("sub-mcp", "https://tools.example.com/v2/mcp")
	// Command-backed MCP and non-MCP services must be ignored.
	r.insertService(&MCPService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "stdio-mcp"},
			backend: &api.RegisterServiceRequest_Command{Command: &api.CommandBackend{Command: []string{"echo"}}},
		},
	})
	r.insertService(&A2AService{
		baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_A2A, Name: "other-a2a"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "https://a2a.example.com/"},
		},
	})

	cases := []struct {
		name      string
		host      string
		path      string
		wantName  string
		wantAmbig bool
	}{
		{name: "exact subpath", host: "api.githubcopilot.com", path: "/mcp", wantName: "github-copilot"},
		{name: "trailing slash subpath", host: "api.githubcopilot.com", path: "/mcp/", wantName: "github-copilot"},
		{name: "nested subpath", host: "api.githubcopilot.com", path: "/mcp/tools", wantName: "github-copilot"},
		{name: "segment boundary rejects sibling prefix", host: "api.githubcopilot.com", path: "/mcp-other", wantName: ""},
		{name: "root target matches any path", host: "tools.example.com", path: "/rpc", wantName: "root-mcp"},
		{name: "longest prefix wins over root", host: "tools.example.com", path: "/v2/mcp/call", wantName: "sub-mcp"},
		{name: "non-MCP service ignored", host: "a2a.example.com", path: "/", wantName: ""},
		{name: "unknown host", host: "unknown.example.com", path: "/mcp", wantName: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ambig := r.ResolveMCPByHostPath(tc.host, tc.path)
			if got != tc.wantName || ambig != tc.wantAmbig {
				t.Fatalf("ResolveMCPByHostPath(%q, %q) = (%q, %v), want (%q, %v)", tc.host, tc.path, got, ambig, tc.wantName, tc.wantAmbig)
			}
		})
	}

	// Two distinct MCP services matching the same host+prefix must fail closed as ambiguous.
	insertMCP("dup-a", "https://dup.example.com/mcp")
	insertMCP("dup-b", "https://dup.example.com/mcp/")
	got, ambig := r.ResolveMCPByHostPath("dup.example.com", "/mcp/")
	if got != "" || !ambig {
		t.Fatalf("ambiguous match = (%q, %v), want (\"\", true)", got, ambig)
	}
}

func TestServiceRegistry_TeardownAllContinuesOnError(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	a := newFakeSvc("a", api.ServiceType_SERVICE_TYPE_MCP)
	b := newFakeSvc("b", api.ServiceType_SERVICE_TYPE_MCP)
	_ = r.Register(context.Background(), a)
	_ = r.Register(context.Background(), b)

	r.TeardownAll()

	if a.teardownCalls != 1 || b.teardownCalls != 1 {
		t.Errorf("teardown calls: a=%d b=%d, want both 1", a.teardownCalls, b.teardownCalls)
	}
	if len(r.List(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)) != 0 {
		t.Error("registry not empty after TeardownAll")
	}
}

// probingService is a service whose backend can be asked whether it answers.
type probingService struct {
	*fakeService
	mu         sync.Mutex
	probeErr   error
	probeCalls int
}

func (p *probingService) Probe(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probeCalls++
	return p.probeErr
}

func (p *probingService) setProbeErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probeErr = err
}

func newProbingSvc(name string, probeErr error) *probingService {
	return &probingService{
		fakeService: newFakeSvc(name, api.ServiceType_SERVICE_TYPE_MCP),
		probeErr:    probeErr,
	}
}

// A backend that is not an MCP server at all -- the canary that answers HTTP
// but fails MCP initialize -- must not be advertised as one. It stays
// registered so the reprovide loop can pick it up if it starts answering.
func TestServiceRegistry_UnreachableBackendIsRegisteredButNotAdvertised(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newProbingSvc("dummy-http", errors.New(`calling "initialize": EOF`))
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(dht.calls) != 0 {
		t.Errorf("Provide called %d times for an unreachable backend, want 0", len(dht.calls))
	}
	if _, ok := r.Get("dummy-http"); !ok {
		t.Error("service should stay registered so it can recover")
	}
}

// A service registered after the reprovide loop's last cycle would otherwise
// wait a whole interval to be advertised, which is minutes.
func TestServiceRegistry_WithheldRegistrationAsksForAReprovide(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	var asked int
	r.reprovideNow = func() { asked++ }

	if err := r.Register(context.Background(), newProbingSvc("late", errors.New("not up yet"))); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if asked != 1 {
		t.Errorf("reprovide requested %d times for a withheld service, want 1", asked)
	}

	if err := r.Register(context.Background(), newProbingSvc("healthy", nil)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if asked != 1 {
		t.Errorf("reprovide requested %d times, want 1: an advertised service needs no retry", asked)
	}
}

func TestServiceRegistry_ReprovideWithholdsUnreachableBackend(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newProbingSvc("demo", nil)
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(dht.calls) != 2 {
		t.Fatalf("Provide called %d times at registration, want 2", len(dht.calls))
	}

	svc.setProbeErr(errors.New("backend went away"))
	if withheld := r.ReprovideAll(context.Background()); withheld != 1 {
		t.Errorf("ReprovideAll reported %d withheld, want 1: the retry cadence depends on it", withheld)
	}
	if len(dht.calls) != 2 {
		t.Errorf("Provide called %d times total, want 2: a backend that stopped answering must fall out of the DHT", len(dht.calls))
	}
}

func TestServiceRegistry_ReprovideResumesWhenBackendRecovers(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)

	svc := newProbingSvc("demo", errors.New("not up yet"))
	if err := r.Register(context.Background(), svc); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(dht.calls) != 0 {
		t.Fatalf("Provide called %d times while the backend was down, want 0", len(dht.calls))
	}

	svc.setProbeErr(nil)
	if withheld := r.ReprovideAll(context.Background()); withheld != 0 {
		t.Errorf("ReprovideAll reported %d withheld after recovery, want 0", withheld)
	}
	if len(dht.calls) != 2 {
		t.Errorf("Provide called %d times after recovery, want 2 (name + type CID)", len(dht.calls))
	}
}

// slowProbingService is a backendProber whose Probe is deadline-inspecting
// and context-controlled rather than timer-based: it records the deadline
// it was given, and for the timeout case blocks on ctx.Done() instead of
// sleeping a real duration. This keeps the tests below deterministic and
// free of real-time dependencies - no CI flakiness from scheduling jitter,
// no slow test suite from real sleeps - while still exercising the same
// behavior a real command-spawned backend with a slow cold-start would hit.
type slowProbingService struct {
	*fakeService
	shouldTimeout bool
	lastDeadline  time.Time
	hasDeadline   bool
}

func newSlowProbingSvc(name string) *slowProbingService {
	return &slowProbingService{
		fakeService: newFakeSvc(name, api.ServiceType_SERVICE_TYPE_MCP),
	}
}

func (p *slowProbingService) Probe(ctx context.Context) error {
	p.lastDeadline, p.hasDeadline = ctx.Deadline()
	if p.shouldTimeout {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

// The bug behind #376: defaultDHTProbeTimeout was a hard-coded 2s with no way to
// raise it, so a backend whose own cold-start cost alone exceeds that -
// measured in practice for moderately-featured MCP server stacks - could
// never be advertised on its first registration. NewServiceRegistry's
// backendProbeTimeout parameter (wired from --backend-probe-timeout) is the
// fix: the same slow backend must fail to advertise under the default and
// succeed once constructed with more time.
func TestServiceRegistry_BackendProbeTimeoutIsConfigurable(t *testing.T) {
	t.Run("default timeout is too short for a slow backend", func(t *testing.T) {
		dht := &fakeDHT{}
		r := NewServiceRegistry(dht, 10*time.Millisecond)

		svc := newSlowProbingSvc("slow")
		svc.shouldTimeout = true
		if err := r.Register(context.Background(), svc); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if len(dht.calls) != 0 {
			t.Errorf("Provide called %d times for a backend slower than the probe timeout, want 0", len(dht.calls))
		}
	})

	t.Run("raising the timeout applies the configured duration to the probe context", func(t *testing.T) {
		dht := &fakeDHT{}
		timeout := 500 * time.Millisecond
		r := NewServiceRegistry(dht, timeout)

		svc := newSlowProbingSvc("slow")
		if err := r.Register(context.Background(), svc); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if len(dht.calls) != 2 {
			t.Errorf("Provide called %d times once given enough time to probe, want 2 (name + type CID)", len(dht.calls))
		}
		if !svc.hasDeadline {
			t.Fatal("expected probe context to have a deadline")
		}
		remaining := time.Until(svc.lastDeadline)
		if remaining > timeout || remaining < timeout-100*time.Millisecond {
			t.Errorf("expected probe deadline to be close to %v, got remaining %v", timeout, remaining)
		}
	})

	t.Run("zero or negative backendProbeTimeout falls back to defaultDHTProbeTimeout", func(t *testing.T) {
		for _, d := range []time.Duration{0, -1 * time.Second} {
			r := NewServiceRegistry(&fakeDHT{}, d)
			if got := r.backendProbeTimeout; got != defaultDHTProbeTimeout {
				t.Errorf("NewServiceRegistry(dht, %v).backendProbeTimeout = %v, want %v", d, got, defaultDHTProbeTimeout)
			}
		}
	})
}

// registering the name again replaces the entry, so the displaced instance is
// only reachable if this call tears it down
func TestServiceRegistry_ReplacingServiceTearsDownPrevious(t *testing.T) {
	r := newServiceRegistryForTest(&fakeDHT{})
	ctx := context.Background()

	first := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	if err := r.Register(ctx, first); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	second := newFakeSvc("demo", api.ServiceType_SERVICE_TYPE_MCP)
	if err := r.Register(ctx, second); err != nil {
		t.Fatalf("second Register: %v", err)
	}

	if first.teardownCalls != 1 {
		t.Errorf("replaced service Teardown called %d times, want 1: "+
			"the replaced instance is no longer reachable from the map, so nothing else can ever tear it down", first.teardownCalls)
	}
	if second.teardownCalls != 0 {
		t.Errorf("replacement service Teardown called %d times, want 0", second.teardownCalls)
	}
	if got, ok := r.Get("demo"); !ok || got != Service(second) {
		t.Error("registry should hold the replacement instance")
	}
}

// Unregistering a service withdraws its record by name, and its record by
// type only once no service of that type is left; leaving the mesh
// withdraws every record.
func TestServiceRegistry_UnregisterWithdrawsRecords(t *testing.T) {
	dht := &fakeDHT{}
	r := newServiceRegistryForTest(dht)
	for _, name := range []string{"calc", "weather"} {
		if err := r.Register(context.Background(), newFakeSvc(name, api.ServiceType_SERVICE_TYPE_MCP)); err != nil {
			t.Fatalf("Register %s: %v", name, err)
		}
	}
	calcKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "calc")
	weatherKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "weather")
	typeKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_MCP, "")

	if err := r.Unregister(context.Background(), "calc"); err != nil {
		t.Fatal(err)
	}
	if len(dht.withdrawn) != 1 || !bytes.Equal(dht.withdrawn[0], calcKey) {
		t.Fatalf("withdrawn after unregistering calc = %d keys, want calc's alone: weather still serves the type", len(dht.withdrawn))
	}
	if err := r.Unregister(context.Background(), "weather"); err != nil {
		t.Fatal(err)
	}
	if len(dht.withdrawn) != 3 || !bytes.Equal(dht.withdrawn[1], weatherKey) || !bytes.Equal(dht.withdrawn[2], typeKey) {
		t.Fatalf("withdrawn after unregistering weather = %d keys, want weather's then the type's", len(dht.withdrawn))
	}
	if err := r.Unregister(context.Background(), "nobody"); err != nil || len(dht.withdrawn) != 3 {
		t.Fatalf("unregistering an unknown service: err %v, %d withdrawals; want a no-op", err, len(dht.withdrawn))
	}

	dht.withdrawn = nil
	if err := r.Register(context.Background(), newFakeSvc("calc", api.ServiceType_SERVICE_TYPE_MCP)); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(context.Background(), newFakeSvc("llm", api.ServiceType_SERVICE_TYPE_INFERENCE)); err != nil {
		t.Fatal(err)
	}
	r.WithdrawAll(context.Background())
	inferenceKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_INFERENCE, "")
	llmKey, _ := api.ServiceKey(api.ServiceType_SERVICE_TYPE_INFERENCE, "llm")
	want := map[string]bool{string(calcKey): true, string(typeKey): true, string(llmKey): true, string(inferenceKey): true}
	got := map[string]bool{}
	for _, k := range dht.withdrawn {
		got[string(k)] = true
	}
	if len(dht.withdrawn) != 4 || len(got) != 4 {
		t.Fatalf("WithdrawAll withdrew %d keys, want 4 distinct: two names, two types", len(dht.withdrawn))
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("WithdrawAll did not withdraw %x", k)
		}
	}
}
