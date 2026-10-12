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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

func init() {
	registerEgressMiddleware(api.ServiceTypeStringA2A, egressMiddleware{
		gateRequest: a2aEgressGate,
		serveLocal:  a2aServeAgentCard,
	})
}

// A2AService proxies Agent2Agent (A2A) JSON-RPC/REST traffic to a local
// agent process. URL backends only: a command backend would wire the A2A
// route to an MCP stdio bridge no A2A client can talk to.
type A2AService struct{ baseService }

func (s *A2AService) Init(ctx context.Context) error {
	switch x := s.backend.(type) {
	case *api.RegisterServiceRequest_TargetUrl:
		h, err := newReverseProxyHandler(x.TargetUrl)
		if err != nil {
			return err
		}
		s.handler = h
	case *api.RegisterServiceRequest_Command:
		return fmt.Errorf("command-based backends are not supported for A2AService")
	default:
		return fmt.Errorf("unsupported backend type %T for A2AService", s.backend)
	}
	return nil
}

// Probe asks the backend for its agent card, which is the protocol's own
// definition of ready: an A2A agent is up exactly when it serves its card.
// Gating advertisement on it lets a service be declared before its agent is
// (a sandbox that has not bound its port yet probes as down and stays out of
// discovery). Deliberately not cached, like the MCP probe.
func (s *A2AService) Probe(ctx context.Context) error {
	target, ok := s.backend.(*api.RegisterServiceRequest_TargetUrl)
	if !ok {
		return fmt.Errorf("a2a service %q has no URL backend to probe", s.info.GetName())
	}
	backend, err := parseBackendTarget(target.TargetUrl)
	if err != nil {
		return err
	}
	cardURL := strings.TrimSuffix(backend.url.String(), "/") + "/.well-known/agent-card.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cardURL, nil)
	if err != nil {
		return err
	}
	resp, err := backend.client().Do(req)
	if err != nil {
		return fmt.Errorf("fetch agent card of %q: %w", s.info.GetName(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent card of %q: %s", s.info.GetName(), resp.Status)
	}
	var card map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&card); err != nil {
		return fmt.Errorf("agent card of %q is not JSON: %w", s.info.GetName(), err)
	}
	return nil
}

// a2aEgressGate runs the caller-side A2A checks on a raw egress request:
// the fail-closed labels gate. On refusal it writes the HTTP error itself
// and returns ok=false.
func a2aEgressGate(node *AgentMeshNode, w http.ResponseWriter, r *http.Request, route egressRoute) (*http.Request, bool) {
	if labelsHeader := r.Header.Get(api.HeaderMeshRequiredLabels); labelsHeader != "" {
		r.Header.Del(api.HeaderMeshRequiredLabels)
		required, err := parseRequiredLabels(labelsHeader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid %s header: %v", api.HeaderMeshRequiredLabels, err), http.StatusBadRequest)
			return r, false
		}
		pid, err := peer.Decode(route.peerID)
		if err != nil {
			http.Error(w, "Invalid peer ID", http.StatusBadRequest)
			return r, false
		}
		if err := node.VerifyPeerLabels(r.Context(), pid, required); err != nil {
			logger.Warnf("[A2A] label gate refused egress to %s: %v", route.peerID, err)
			text, status := labelGateStatus(err, "Required labels not attested by provider")
			http.Error(w, text, status)
			return r, false
		}
	}
	return r, true
}

// a2aAgentCardPath is the well-known agent card location (A2A spec / RFC 8615).
const a2aAgentCardPath = ".well-known/agent-card.json"

// maxAgentCardBytes bounds how much of a remote agent card the node ingests.
const maxAgentCardBytes = 1 << 20

// a2aServeAgentCard impersonates the remote agent's card endpoint: it holds
// the client request, fetches the card from the agent over the mesh, and
// serves a regenerated card whose interfaces point at the local mesh URL.
// Stock A2A clients then talk to the agent through this node unmodified.
// The card is served both at the well-known path (resolvers that append it,
// e.g. the python SDK) and at the bare service root (resolvers that treat a
// pathful base URL as the card location, e.g. a2a-go; a root GET is not part
// of any A2A binding, JSON-RPC being POST-only). Everything else is left to
// the streaming egress proxy.
func a2aServeAgentCard(node *AgentMeshNode, rt http.RoundTripper, w http.ResponseWriter, r *http.Request, route egressRoute) bool {
	if r.Method != http.MethodGet || (route.upstreamPath != a2aAgentCardPath && route.upstreamPath != "") {
		return false
	}
	resp, err := fetchRemoteAgentCard(node, rt, r, route)
	if err != nil {
		logger.Warnf("[A2A] agent card fetch from %s failed: %v", route.peerID, err)
		http.Error(w, "Bad Gateway: agent card fetch failed", http.StatusBadGateway)
		return true
	}
	defer func() { _ = resp.Body.Close() }()

	body := io.LimitReader(resp.Body, maxAgentCardBytes)
	if resp.StatusCode != http.StatusOK {
		// The agent's own error; relay it as-is.
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, body)
		return true
	}

	var card a2a.AgentCard
	if err := json.NewDecoder(body).Decode(&card); err != nil {
		logger.Warnf("[A2A] agent card from %s is not valid JSON: %v", route.peerID, err)
		http.Error(w, "Bad Gateway: agent card is not valid JSON", http.StatusBadGateway)
		return true
	}
	base := fmt.Sprintf("http://%s/mesh/%s/%s/%s", r.Host, route.peerID, route.serviceType, route.serviceName)
	if err := regenerateAgentCardForMesh(&card, base); err != nil {
		logger.Warnf("[A2A] agent card from %s unusable through the mesh: %v", route.peerID, err)
		http.Error(w, fmt.Sprintf("Bad Gateway: %v", err), http.StatusBadGateway)
		return true
	}
	out, err := json.Marshal(&card)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return true
	}
	// Caching (A2A 1.0, section 8.6.1): the agent's freshness and
	// modification time still describe the card, but its validator does not
	// once the content changed, so the node derives its own from the bytes it
	// serves and answers a matching If-None-Match itself.
	for _, h := range []string{"Cache-Control", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	etag := agentCardETag(out)
	w.Header().Set("ETag", etag)
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	_, _ = w.Write(out)
	return true
}

// agentCardETag is a strong validator for the card bytes the node serves.
func agentCardETag(card []byte) string {
	sum := sha256.Sum256(card)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// etagMatches applies If-None-Match's weak comparison (RFC 9110, section
// 13.1.2) of a request header against the card's validator.
func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}

// fetchRemoteAgentCard performs the mesh-side GET for the agent card, reusing
// the headers already prepared for egress (biscuit, agent claim, passthrough
// Authorization) on the incoming request.
func fetchRemoteAgentCard(node *AgentMeshNode, rt http.RoundTripper, r *http.Request, route egressRoute) (*http.Response, error) {
	ctx := allowLimitedEgressConn(r.Context())
	if node != nil {
		node.prepareEgressPeer(ctx, route.peerID)
	}
	url := fmt.Sprintf("libp2p://%s/%s/%s/%s", route.peerID, route.serviceType, route.serviceName, a2aAgentCardPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = r.Header.Clone()
	// The node decodes the card itself, so negotiate identity encoding
	// regardless of what the held client asked for, and ask for the whole
	// card: the client's validators are for the card this node serves, which
	// the agent never saw.
	req.Header.Del("Accept-Encoding")
	req.Header.Del("If-None-Match")
	req.Header.Del("If-Modified-Since")
	req.Host = route.peerID
	return (&http.Client{Transport: rt}).Do(req)
}

// regenerateAgentCardForMesh rebuilds a fetched agent card for mesh use:
// interface URLs point back at the mesh path, bindings the mesh cannot carry
// (gRPC) are dropped, streaming is advertised off until verified, and the
// original signatures are removed since they no longer match the content.
func regenerateAgentCardForMesh(card *a2a.AgentCard, base string) error {
	kept := make([]*a2a.AgentInterface, 0, len(card.SupportedInterfaces))
	for _, iface := range card.SupportedInterfaces {
		if iface == nil || !a2aBindingOverHTTP(iface.ProtocolBinding) {
			continue
		}
		iface.URL = base
		kept = append(kept, iface)
	}
	if len(kept) == 0 {
		return fmt.Errorf("agent card advertises no supported interface the mesh can carry (JSONRPC or HTTP+JSON); is the agent serving a pre-1.0 A2A card?")
	}
	card.SupportedInterfaces = kept
	card.Capabilities.Streaming = false
	card.Signatures = nil
	// Required list fields must stay arrays: encoding/json marshals nil
	// slices as null, which strict SDK card parsers (pydantic) reject.
	if card.Skills == nil {
		card.Skills = []a2a.AgentSkill{}
	}
	if card.DefaultInputModes == nil {
		card.DefaultInputModes = []string{}
	}
	if card.DefaultOutputModes == nil {
		card.DefaultOutputModes = []string{}
	}
	return nil
}

// a2aBindingOverHTTP reports whether an A2A protocol binding can traverse the
// mesh's HTTP-over-libp2p path; gRPC needs its own end-to-end connection.
func a2aBindingOverHTTP(binding a2a.TransportProtocol) bool {
	switch strings.ToUpper(string(binding)) {
	case string(a2a.TransportProtocolJSONRPC), string(a2a.TransportProtocolHTTPJSON):
		return true
	}
	return false
}
