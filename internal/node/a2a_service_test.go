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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/agentmesh/api"
)

func TestA2AServiceInitRejectsCommand(t *testing.T) {
	svc := &A2AService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_A2A, Name: "agent"},
		backend: &api.RegisterServiceRequest_Command{Command: &api.CommandBackend{Command: []string{"echo"}}},
	}}
	if err := svc.Init(context.Background()); err == nil {
		t.Fatal("command backend must be rejected for a2a services")
	}
}

func TestA2AServiceInitURLBackend(t *testing.T) {
	svc := &A2AService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_A2A, Name: "agent"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://127.0.0.1:9999"},
	}}
	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("url backend must be accepted: %v", err)
	}
	if svc.Handler() == nil {
		t.Fatal("nil handler after Init")
	}
}

func TestNewServiceFromRequestA2A(t *testing.T) {
	req := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_A2A, Name: "agent"},
		Backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: "http://127.0.0.1:9999"},
	}
	svc, err := NewServiceFromRequest(req)
	if err != nil {
		t.Fatalf("factory must accept a2a: %v", err)
	}
	if _, ok := svc.(*A2AService); !ok {
		t.Fatalf("factory returned %T, want *A2AService", svc)
	}
}

// TestA2AServiceProbe pins advertisement gating on the agent card: an a2a
// service may be declared before its agent is up (a sandbox that has not
// bound its port), and must probe as down until the card is served.
func TestA2AServiceProbe(t *testing.T) {
	newSvc := func(target string) *A2AService {
		return &A2AService{baseService: baseService{
			info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_A2A, Name: "agent"},
			backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: target},
		}}
	}

	t.Run("card served means ready", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/agent-card.json" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"name":"agent","version":"1.0.0"}`))
		}))
		defer backend.Close()
		if err := newSvc(backend.URL).Probe(context.Background()); err != nil {
			t.Fatalf("Probe with a served card: %v", err)
		}
	})

	t.Run("no card means not ready", func(t *testing.T) {
		backend := httptest.NewServer(http.NotFoundHandler())
		defer backend.Close()
		if err := newSvc(backend.URL).Probe(context.Background()); err == nil {
			t.Fatal("Probe must fail while the card is not served")
		}
	})

	t.Run("dead backend means not ready", func(t *testing.T) {
		// A declared sandbox service whose agent never bound its port.
		if err := newSvc("http://127.0.0.1:1").Probe(context.Background()); err == nil {
			t.Fatal("Probe must fail when nothing listens")
		}
	})

	t.Run("non-json card means not ready", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>login page</html>"))
		}))
		defer backend.Close()
		if err := newSvc(backend.URL).Probe(context.Background()); err == nil {
			t.Fatal("Probe must fail on a non-JSON card")
		}
	})
}

func TestA2AEgressHookNonA2APassthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mesh/12D3KooWpeer/mcp/svc/foo", nil)
	req.Header.Set(api.HeaderMeshRequiredLabels, "region=eu")
	_, ok := applyEgressMiddleware(nil, rec, req)
	if !ok {
		t.Fatal("non-a2a path must pass through")
	}
	if req.Header.Get(api.HeaderMeshRequiredLabels) == "" {
		t.Fatal("labels header on non-a2a path must be left untouched")
	}
}

func TestA2AEgressHookMalformedLabels(t *testing.T) {
	// ",," is the fail-open shape: it must not parse to "no requirement".
	for _, header := range []string{"not-a-label", ",,"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/mesh/12D3KooWpeer/a2a/agent/", nil)
		req.Header.Set(api.HeaderMeshRequiredLabels, header)
		_, ok := applyEgressMiddleware(nil, rec, req)
		if ok {
			t.Fatalf("labels header %q must be refused", header)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("labels header %q: status = %d, want 400", header, rec.Code)
		}
	}
}

// roundTripFunc fakes the mesh transport for agent-card fetches.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func cardResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestA2AServeAgentCardRegenerates(t *testing.T) {
	const upstreamCard = `{
	  "name": "T",
	  "description": "d",
	  "version": "1.0.0",
	  "capabilities": {"streaming": true},
	  "supportedInterfaces": [
	    {"url": "http://localhost:7777/", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
	    {"url": "localhost:50051", "protocolBinding": "GRPC", "protocolVersion": "1.0"}
	  ],
	  "signatures": [{"protected": "eyJh", "signature": "sig"}],
	  "defaultInputModes": ["text"],
	  "defaultOutputModes": ["text"],
	  "skills": []
	}`
	var outbound *http.Request
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		outbound = r
		return cardResponse(http.StatusOK, upstreamCard), nil
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mesh/12D3KooWpeer/a2a/agent/.well-known/agent-card.json", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set(api.HeaderMeshBiscuit, "b64-biscuit")
	req.Header.Set("Accept-Encoding", "gzip")
	if !serveEgressLocally(nil, rt, rec, req) {
		t.Fatal("agent-card GET must be handled locally")
	}

	wantURL := "libp2p://12D3KooWpeer/a2a/agent/.well-known/agent-card.json"
	if got := outbound.URL.String(); got != wantURL {
		t.Errorf("outbound fetch URL = %q, want %q", got, wantURL)
	}
	if outbound.Header.Get(api.HeaderMeshBiscuit) != "b64-biscuit" {
		t.Error("egress headers must be carried on the card fetch")
	}
	if outbound.Header.Get("Accept-Encoding") != "" {
		t.Error("card fetch must negotiate identity encoding")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	var card a2a.AgentCard
	if err := json.Unmarshal(rec.Body.Bytes(), &card); err != nil {
		t.Fatalf("regenerated card is not a valid AgentCard: %v", err)
	}
	base := "http://127.0.0.1:8080/mesh/12D3KooWpeer/a2a/agent"
	if len(card.SupportedInterfaces) != 1 {
		t.Fatalf("want 1 HTTP interface after dropping gRPC, got %v", card.SupportedInterfaces)
	}
	if card.SupportedInterfaces[0].URL != base {
		t.Errorf("interface url = %q, want %q", card.SupportedInterfaces[0].URL, base)
	}
	if card.SupportedInterfaces[0].ProtocolBinding != a2a.TransportProtocolJSONRPC {
		t.Errorf("binding = %q, want JSONRPC", card.SupportedInterfaces[0].ProtocolBinding)
	}
	if card.Capabilities.Streaming {
		t.Error("streaming must be advertised off through the mesh")
	}
	if len(card.Signatures) != 0 {
		t.Error("stale signatures must be dropped from the regenerated card")
	}
	if card.Name != "T" || card.Version != "1.0.0" {
		t.Errorf("agent identity fields must survive regeneration: %+v", card)
	}
}

func TestA2AServeAgentCardMinimalCardStaysParseable(t *testing.T) {
	// An upstream card that omits skills/defaultInputModes/defaultOutputModes:
	// the regenerated card must keep them as arrays, not null, or strict SDK
	// parsers (pydantic) refuse the whole card.
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return cardResponse(http.StatusOK, `{"name":"minimal",`+
			`"supportedInterfaces":[{"url":"http://localhost:7777","protocolBinding":"JSONRPC"}],`+
			`"capabilities":{}}`), nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mesh/12D3KooWpeer/a2a/agent/.well-known/agent-card.json", nil)
	if !serveEgressLocally(nil, rt, rec, req) {
		t.Fatal("card GET must be handled locally")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("regenerated card is not JSON: %v", err)
	}
	for _, key := range []string{"skills", "defaultInputModes", "defaultOutputModes", "supportedInterfaces"} {
		if _, ok := raw[key].([]any); !ok {
			t.Errorf("%s = %v (%T), must be a JSON array", key, raw[key], raw[key])
		}
	}
}

func TestA2AServeAgentCardAtServiceRoot(t *testing.T) {
	// a2a-go's stock resolver treats a pathful base URL as the card URL
	// itself, so the bare service root must serve the card too; the fetch
	// upstream still targets the agent's well-known path.
	var outbound *http.Request
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		outbound = r
		return cardResponse(http.StatusOK,
			`{"name":"T","supportedInterfaces":[{"url":"http://localhost:7777","protocolBinding":"JSONRPC"}]}`), nil
	})
	for _, path := range []string{"/mesh/12D3KooWpeer/a2a/agent", "/mesh/12D3KooWpeer/a2a/agent/"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "127.0.0.1:8080"
		if !serveEgressLocally(nil, rt, rec, req) {
			t.Fatalf("GET %s must serve the card", path)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, body: %s", path, rec.Code, rec.Body.String())
		}
		if want := "libp2p://12D3KooWpeer/a2a/agent/.well-known/agent-card.json"; outbound.URL.String() != want {
			t.Errorf("upstream fetch URL = %q, want %q", outbound.URL.String(), want)
		}
		var card a2a.AgentCard
		if err := json.Unmarshal(rec.Body.Bytes(), &card); err != nil {
			t.Fatalf("GET %s: invalid card: %v", path, err)
		}
		if len(card.SupportedInterfaces) != 1 || card.SupportedInterfaces[0].URL != "http://127.0.0.1:8080/mesh/12D3KooWpeer/a2a/agent" {
			t.Errorf("GET %s: interfaces = %+v", path, card.SupportedInterfaces)
		}
	}
}

func TestA2AServeAgentCardIgnoresNonCardRequests(t *testing.T) {
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("no mesh fetch expected")
		return nil, nil
	})
	for _, tc := range []struct{ method, path string }{
		{"POST", "/mesh/12D3KooWpeer/a2a/agent/.well-known/agent-card.json"},
		{"POST", "/mesh/12D3KooWpeer/a2a/agent"},
		{"GET", "/mesh/12D3KooWpeer/a2a/agent/tasks/1"},
		{"GET", "/mesh/12D3KooWpeer/mcp/svc/.well-known/agent-card.json"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if serveEgressLocally(nil, rt, rec, req) {
			t.Errorf("%s %s must stream through the proxy", tc.method, tc.path)
		}
	}
}

func TestA2AEgressHookInvalidPeerID(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mesh/not-a-peer/a2a/agent/", nil)
	req.Header.Set(api.HeaderMeshRequiredLabels, "region=eu")
	_, ok := applyEgressMiddleware(nil, rec, req)
	if ok {
		t.Fatal("invalid peer ID must be refused")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestA2AServeAgentCardNoHTTPBindingFailsClosed(t *testing.T) {
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return cardResponse(http.StatusOK,
			`{"name":"T","supportedInterfaces":[{"url":"localhost:50051","protocolBinding":"GRPC"}]}`), nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mesh/12D3KooWpeer/a2a/agent/.well-known/agent-card.json", nil)
	if !serveEgressLocally(nil, rt, rec, req) {
		t.Fatal("card GET must be handled locally")
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "mesh can carry") {
		t.Errorf("error must name the refusal reason, got: %s", rec.Body.String())
	}
}

func TestA2AServeAgentCardPre10CardFailsClosed(t *testing.T) {
	// A2A v0.3-shaped card: interfaces live in additionalInterfaces, which the
	// v1.0 type does not carry, so regeneration must refuse rather than serve
	// a card with no usable interface.
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return cardResponse(http.StatusOK, `{"name":"T","url":"http://localhost:9999",`+
			`"preferredTransport":"JSONRPC",`+
			`"additionalInterfaces":[{"url":"http://localhost:9999","transport":"JSONRPC"}]}`), nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mesh/12D3KooWpeer/a2a/agent/.well-known/agent-card.json", nil)
	if !serveEgressLocally(nil, rt, rec, req) {
		t.Fatal("card GET must be handled locally")
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pre-1.0") {
		t.Errorf("error must hint at the card vintage, got: %s", rec.Body.String())
	}
}

func TestA2AServeAgentCardRelaysUpstreamError(t *testing.T) {
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := cardResponse(http.StatusNotFound, "no card here")
		resp.Header.Set("Content-Type", "text/plain")
		return resp, nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mesh/12D3KooWpeer/a2a/agent/.well-known/agent-card.json", nil)
	if !serveEgressLocally(nil, rt, rec, req) {
		t.Fatal("card GET must be handled locally")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want the agent's own 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no card here") {
		t.Errorf("agent's error body must be relayed, got: %s", rec.Body.String())
	}
}

func TestA2AServeAgentCardFetchErrorIs502(t *testing.T) {
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("peer unreachable")
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mesh/12D3KooWpeer/a2a/agent/.well-known/agent-card.json", nil)
	if !serveEgressLocally(nil, rt, rec, req) {
		t.Fatal("card GET must be handled locally")
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestA2AEgressHookUppercaseTypeIsGated(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/mesh/not-a-peer/A2A/agent/", nil)
	req.Header.Set(api.HeaderMeshRequiredLabels, "region=eu")
	_, ok := applyEgressMiddleware(nil, rec, req)
	if ok {
		t.Fatal("uppercase A2A path must not bypass the labels gate")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (invalid peer reached after gate engaged)", rec.Code)
	}
	if req.Header.Get(api.HeaderMeshRequiredLabels) != "" {
		t.Fatal("labels header must be stripped on a2a paths regardless of case")
	}
}

// TestA2AServeAgentCardCaching pins the card's HTTP caching through the mesh
// (A2A 1.0, section 8.6.1): the agent's Cache-Control and Last-Modified reach
// the client, the validator matches the regenerated bytes rather than the
// agent's, and a client revalidating with it gets 304.
func TestA2AServeAgentCardCaching(t *testing.T) {
	const upstreamCard = `{"name":"T","version":"1.0.0","supportedInterfaces":[{"url":"http://localhost:7777","protocolBinding":"JSONRPC"}]}`
	var outbound *http.Request
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		outbound = r
		resp := cardResponse(http.StatusOK, upstreamCard)
		resp.Header.Set("Cache-Control", "max-age=300")
		resp.Header.Set("Last-Modified", "Mon, 12 Oct 2026 08:00:00 GMT")
		resp.Header.Set("ETag", `"agent-v1"`)
		return resp, nil
	})
	get := func(ifNoneMatch string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/mesh/12D3KooWpeer/a2a/agent/.well-known/agent-card.json", nil)
		req.Host = "127.0.0.1:8080"
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
			req.Header.Set("If-Modified-Since", "Mon, 12 Oct 2026 08:00:00 GMT")
		}
		if !serveEgressLocally(nil, rt, rec, req) {
			t.Fatal("card GET must be handled locally")
		}
		return rec
	}

	first := get("")
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", first.Code)
	}
	if got := first.Header().Get("Cache-Control"); got != "max-age=300" {
		t.Errorf("Cache-Control = %q, want the agent's max-age=300", got)
	}
	if got := first.Header().Get("Last-Modified"); got != "Mon, 12 Oct 2026 08:00:00 GMT" {
		t.Errorf("Last-Modified = %q, want the agent's", got)
	}
	etag := first.Header().Get("ETag")
	if etag == "" || etag == `"agent-v1"` {
		t.Fatalf("ETag = %q, want a validator of the regenerated card, not the agent's", etag)
	}
	sum := sha256.Sum256(first.Body.Bytes())
	if want := `"` + hex.EncodeToString(sum[:16]) + `"`; etag != want {
		t.Errorf("ETag = %q, want %q for the served bytes", etag, want)
	}

	for _, header := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		again := get(header)
		if again.Code != http.StatusNotModified {
			t.Errorf("If-None-Match %s: status = %d, want 304", header, again.Code)
		}
		if again.Body.Len() != 0 {
			t.Errorf("If-None-Match %s: 304 carries a body", header)
		}
		if outbound.Header.Get("If-None-Match") != "" || outbound.Header.Get("If-Modified-Since") != "" {
			t.Errorf("If-None-Match %s: the node's own fetch must ask the agent for the whole card", header)
		}
	}
	if stale := get(`"agent-v1"`); stale.Code != http.StatusOK {
		t.Errorf("If-None-Match with the agent's validator: status = %d, want 200", stale.Code)
	}
}
