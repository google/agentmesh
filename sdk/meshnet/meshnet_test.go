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

package meshnet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAttenuateToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	t.Run("rejects_before_up_and_nil_rule", func(t *testing.T) {
		var unstarted Server
		if _, _, err := unstarted.AttenuateToken(&api.TaskAuthorizationRule{Name: "t1"}, time.Minute, false); err == nil {
			t.Fatal("AttenuateToken succeeded before Up, want error")
		}
		env := newStartedTestServer(t, ctx)
		if _, _, err := env.server.AttenuateToken(nil, time.Minute, false); err == nil {
			t.Fatal("AttenuateToken(nil) succeeded, want error")
		}
	})

	t.Run("attenuates_caps_ttl_and_seals", func(t *testing.T) {
		env := newStartedTestServer(t, ctx)
		rule := &api.TaskAuthorizationRule{
			Name:        "review-pr-42",
			DisplayName: "Review PR 42",
			Rules: []*api.TaskRule{
				{
					AllowedServices: []string{"a2a://coder"},
					Operation:       &api.TaskOperation{AllowedMethods: []string{"POST"}},
				},
			},
		}

		unsealedB64, exp, err := env.server.AttenuateToken(rule, 5*time.Minute, false)
		if err != nil {
			t.Fatalf("AttenuateToken(seal=false): %v", err)
		}
		if d := time.Until(exp); d <= 0 || d > 5*time.Minute+time.Second {
			t.Errorf("attenuated expiry delta = %v, want (0, 5m]", d)
		}
		rawUnsealed, err := base64.RawURLEncoding.DecodeString(unsealedB64)
		if err != nil {
			t.Fatalf("DecodeString: %v", err)
		}
		unsealedTok, err := biscuit.Unmarshal(rawUnsealed)
		if err != nil {
			t.Fatalf("biscuit.Unmarshal(unsealed): %v", err)
		}
		codes := unsealedTok.Code()
		if len(codes) != 1 {
			t.Fatalf("len(unsealedTok.Code()) = %d, want 1 appended block", len(codes))
		}
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(codes[0]), "Block {"), "}"))
		decodedRule, err := api.ParseTARBlockSource(inner)
		if err != nil || decodedRule.GetName() != "review-pr-42" {
			t.Fatalf("ParseTARBlockSource(%q) = %v, err=%v; want review-pr-42", inner, decodedRule, err)
		}

		// A second attenuation block can be appended to an unsealed token.
		nextFact, err := api.EncodeTARBlockFact(&api.TaskAuthorizationRule{
			Name:       "narrower",
			ExpireTime: decodedRule.GetExpireTime(),
			Rules:      decodedRule.GetRules(),
		})
		if err != nil {
			t.Fatalf("EncodeTARBlockFact: %v", err)
		}
		bb := unsealedTok.CreateBlock()
		if err := bb.AddFact(nextFact); err != nil {
			t.Fatalf("AddFact: %v", err)
		}
		if _, err := unsealedTok.Append(rand.Reader, bb.Build()); err != nil {
			t.Fatalf("expected unsealed token to allow further attenuation: %v", err)
		}

		// With seal=true, downstream holders cannot append another block.
		sealedB64, _, err := env.server.AttenuateToken(rule, 5*time.Minute, true)
		if err != nil {
			t.Fatalf("AttenuateToken(seal=true): %v", err)
		}
		rawSealed, err := base64.RawURLEncoding.DecodeString(sealedB64)
		if err != nil {
			t.Fatalf("DecodeString(sealed): %v", err)
		}
		sealedTok, err := biscuit.Unmarshal(rawSealed)
		if err != nil {
			t.Fatalf("biscuit.Unmarshal(sealed): %v", err)
		}
		forgedBB := sealedTok.CreateBlock()
		if err := forgedBB.AddFact(nextFact); err != nil {
			t.Fatalf("AddFact(forged): %v", err)
		}
		if _, err := sealedTok.Append(rand.Reader, forgedBB.Build()); err == nil {
			t.Fatal("Append succeeded on a sealed token, want error")
		}
	})
}

func TestSanitizeCallerHeadersAndAgentCardRelativize(t *testing.T) {
	peerID := "12D3KooWExamplePeer"
	privRoot := "/mesh/" + peerID + "/a2a/coder"
	pubRoot := "/ingress/" + peerID + "/a2a/coder"
	roots := []string{pubRoot, privRoot, ""}

	orig := &a2a.AgentCard{
		Name:        "coder",
		Description: "Laptop coder",
		Version:     "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{
			{URL: "https://bananas.sam-mesh.dev" + pubRoot + "/invoke?mode=fast", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
			{URL: "http://agentmesh.local" + privRoot, ProtocolBinding: a2a.TransportProtocolHTTPJSON, ProtocolVersion: "1.0"},
			{URL: "http://127.0.0.1:9090/v1/rpc", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
		},
		Signatures: []a2a.AgentCardSignature{{Protected: "hdr", Signature: "sig"}},
	}
	rawOrig, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://agentmesh.local/.well-known/agent-card.json", nil)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(rawOrig)),
		ContentLength: int64(len(rawOrig)),
		Request:       req,
	}
	if err := (&Server{}).relativizeAgentCardMultiRoot("coder", roots)(resp); err != nil {
		t.Fatalf("relativizeAgentCardMultiRoot: %v", err)
	}
	relBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var relCard a2a.AgentCard
	if err := json.Unmarshal(relBytes, &relCard); err != nil {
		t.Fatalf("Unmarshal relativized card: %v", err)
	}
	if got := relCard.SupportedInterfaces[0].URL; got != "invoke?mode=fast" {
		t.Errorf("interface[0].URL = %q, want %q", got, "invoke?mode=fast")
	}
	if got := relCard.SupportedInterfaces[1].URL; got != "" {
		t.Errorf("interface[1].URL = %q, want empty relative root", got)
	}
	if got := relCard.SupportedInterfaces[2].URL; got != "v1/rpc" {
		t.Errorf("interface[2].URL = %q, want %q", got, "v1/rpc")
	}

	inHdr := http.Header{
		"Authorization":                    {"Bearer app-token"},
		"Cookie":                           {"sid=secret"},
		"X-Mesh-Principal":                 {"spoofed"},
		api.HeaderPeerID:                   {"spoofed-peer"},
		api.HeaderMeshRequiredLabels:       {"env=prod"},
		api.HeaderMeshAuthentication:       {"Bearer task-token"},
		api.HeaderMeshIngressCallerBiscuit: {"spoofed-caller"},
	}
	sanitized := sanitizeCallerMeshHeaders(inHdr)
	if sanitized.Get("Cookie") != "" || sanitized.Get("X-Mesh-Principal") != "" || sanitized.Get(api.HeaderPeerID) != "" || sanitized.Get(api.HeaderMeshIngressCallerBiscuit) != "" {
		t.Errorf("sanitizeCallerMeshHeaders leaked restricted headers: %v", sanitized)
	}
	if sanitized.Get("Authorization") != "Bearer app-token" {
		t.Errorf("Authorization header was dropped: %v", sanitized)
	}
	if sanitized.Get(api.HeaderMeshRequiredLabels) != "env=prod" {
		t.Errorf("X-Mesh-Required-Labels was dropped: %v", sanitized)
	}
	if sanitized.Get(api.HeaderMeshAuthentication) != "Bearer task-token" {
		t.Errorf("X-Mesh-Authentication was dropped: %v", sanitized)
	}
}

func TestHTTPClientPathAndRequiredLabelValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env := newStartedTestServer(t, ctx)
	hc := env.server.HTTPClient()
	validBase := fmt.Sprintf("http://agentmesh.local/mesh/%s/a2a/coder", env.routerHost.ID().String())

	for _, tc := range []struct {
		name   string
		url    string
		labels string
	}{
		{name: "dot_segment", url: validBase + "/../admin"},
		{name: "non_mesh_prefix", url: "http://agentmesh.local/v1/models"},
		{name: "invalid_peer_id", url: "http://agentmesh.local/mesh/not-a-peer/a2a/coder"},
		{name: "invalid_service_type", url: fmt.Sprintf("http://agentmesh.local/mesh/%s/unknown/coder", env.routerHost.ID().String())},
		{name: "lone_commas_in_required_labels", url: validBase + "/invoke", labels: ",,"},
		{name: "missing_equals_in_required_labels", url: validBase + "/invoke", labels: "env-prod"},
		{name: "duplicate_key_in_required_labels", url: validBase + "/invoke", labels: "env=prod,env=staging"},
		{name: "invalid_key_in_required_labels", url: validBase + "/invoke", labels: "BAD KEY!=val"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, tc.url, strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if tc.labels != "" {
				req.Header.Set(api.HeaderMeshRequiredLabels, tc.labels)
			}
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatalf("hc.Do(%s): %v", tc.url, err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 Bad Request", resp.StatusCode)
			}
		})
	}
}

func TestListenA2AWhoIsDiscoverAndHTTPClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mesh := newInProcessMeshPair(t, ctx)
	provider := mesh.provider
	caller := mesh.caller

	ep, err := provider.ListenA2A(ctx, A2AOptions{
		Name:        "coder",
		Description: "In-process coding agent",
	})
	if err != nil {
		t.Fatalf("ListenA2A: %v", err)
	}
	if ep.PublicURL != nil {
		t.Fatalf("PublicURL = %v, want nil when Public=false", ep.PublicURL)
	}

	var seenCaller CallerInfo
	var seenRemoteAddr string
	var callerMu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		card := &a2a.AgentCard{
			Name:        "coder",
			Description: "In-process coding agent",
			Version:     "1.0.0",
			SupportedInterfaces: []*a2a.AgentInterface{
				{URL: ep.PrivateURL.String() + "/invoke", ProtocolBinding: a2a.TransportProtocolJSONRPC, ProtocolVersion: "1.0"},
			},
			Signatures: []a2a.AgentCardSignature{{Protected: "hdr", Signature: "sig"}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	})
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		info, ok := provider.WhoIs(r.RemoteAddr)
		if !ok || info == nil {
			http.Error(w, "missing WhoIs", http.StatusInternalServerError)
			return
		}
		// Mutate returned copy to verify WhoIs returns a defensive copy.
		if len(info.Roles) > 0 {
			info.Roles[0] = "mutated"
		}
		info.Labels["env"] = "mutated"

		fresh, ok := provider.WhoIs(r.RemoteAddr)
		if !ok {
			http.Error(w, "missing second WhoIs", http.StatusInternalServerError)
			return
		}
		callerMu.Lock()
		seenCaller = *fresh
		seenRemoteAddr = r.RemoteAddr
		callerMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ep.PrivateListener) }()
	t.Cleanup(func() {
		_ = httpSrv.Close()
		_ = ep.Close()
	})

	// 1. Targeted discovery & type-wide catalog discovery.
	byName, err := caller.Discover(ctx, api.ServiceType_SERVICE_TYPE_A2A, "coder")
	if err != nil {
		t.Fatalf("Discover(by name): %v", err)
	}
	if len(byName) != 1 || byName[0].GetLocalProxyUrl() != ep.PrivateURL.String() {
		t.Fatalf("Discover(by name) = %v, want [%s]", byName, ep.PrivateURL.String())
	}

	byType, err := caller.Discover(ctx, api.ServiceType_SERVICE_TYPE_A2A, "")
	if err != nil {
		t.Fatalf("Discover(by type): %v", err)
	}
	if len(byType) != 1 || byType[0].GetSrvDescription() != "In-process coding agent" {
		t.Fatalf("Discover(by type) = %v, want description 'In-process coding agent'", byType)
	}

	// 2. AgentCard fetch via caller.HTTPClient() rewrites URL & supports ETag/304.
	hc := caller.HTTPClient()
	cardResp, err := hc.Get(ep.PrivateURL.String() + "/.well-known/agent-card.json")
	if err != nil {
		t.Fatalf("GET agent-card.json: %v", err)
	}
	cardBody, err := io.ReadAll(cardResp.Body)
	_ = cardResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(agent-card.json): %v", err)
	}
	if cardResp.StatusCode != http.StatusOK {
		t.Fatalf("agent-card status = %d: %s", cardResp.StatusCode, cardBody)
	}
	var gotCard a2a.AgentCard
	if err := json.Unmarshal(cardBody, &gotCard); err != nil {
		t.Fatalf("unmarshal card: %v", err)
	}
	if len(gotCard.SupportedInterfaces) != 1 || gotCard.SupportedInterfaces[0].URL != ep.PrivateURL.String()+"/invoke" {
		t.Fatalf("SupportedInterfaces = %+v, want %s/invoke", gotCard.SupportedInterfaces, ep.PrivateURL.String())
	}
	if len(gotCard.Signatures) != 0 {
		t.Errorf("Signatures = %v, want stripped on regenerated mesh card", gotCard.Signatures)
	}
	etag := cardResp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag header on regenerated AgentCard")
	}

	req304, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.PrivateURL.String()+"/.well-known/agent-card.json", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext(304): %v", err)
	}
	req304.Header.Set("If-None-Match", etag)
	resp304, err := hc.Do(req304)
	if err != nil {
		t.Fatalf("GET agent-card with If-None-Match: %v", err)
	}
	_ = resp304.Body.Close()
	if resp304.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match status = %d, want 304", resp304.StatusCode)
	}

	// 3. POST /invoke verifies WhoIs caller identity, defensive copy, and post-close cleanup.
	invReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.PrivateURL.String()+"/invoke", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext(invoke): %v", err)
	}
	invReq.Header.Set(api.HeaderMeshRequiredLabels, "env=prod")
	invResp, err := hc.Do(invReq)
	if err != nil {
		t.Fatalf("POST /invoke: %v", err)
	}
	_, readErr := io.ReadAll(invResp.Body)
	_ = invResp.Body.Close()
	if readErr != nil {
		t.Fatalf("io.ReadAll(invoke): %v", readErr)
	}
	if invResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /invoke status = %d, want 200", invResp.StatusCode)
	}

	callerMu.Lock()
	gotCaller := seenCaller
	remoteAddr := seenRemoteAddr
	callerMu.Unlock()

	if gotCaller.PeerID != caller.Status().PeerID {
		t.Errorf("WhoIs PeerID = %q, want %q", gotCaller.PeerID, caller.Status().PeerID)
	}
	if gotCaller.Principal != "alice@example.com" {
		t.Errorf("WhoIs Principal = %q, want %q", gotCaller.Principal, "alice@example.com")
	}
	if len(gotCaller.Roles) != 1 || gotCaller.Roles[0] != api.RoleNode {
		t.Errorf("WhoIs Roles = %v, want [%s]", gotCaller.Roles, api.RoleNode)
	}
	if gotCaller.Labels["env"] != "prod" {
		t.Errorf("WhoIs Labels[env] = %q, want prod", gotCaller.Labels["env"])
	}

	// Wait briefly for trackedConn.Close() to evict remoteAddr from activeConns.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, still := provider.WhoIs(remoteAddr); !still {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, still := provider.WhoIs(remoteAddr); still {
		t.Errorf("WhoIs(%q) still present after connection closed", remoteAddr)
	}

	// 4. Required-label mismatch fails closed BEFORE sending request bytes.
	badLabelReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.PrivateURL.String()+"/invoke", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext(badLabel): %v", err)
	}
	badLabelReq.Header.Set(api.HeaderMeshRequiredLabels, "env=staging")
	badLabelResp, err := hc.Do(badLabelReq)
	if err != nil {
		t.Fatalf("POST with mismatched required label: %v", err)
	}
	_ = badLabelResp.Body.Close()
	if badLabelResp.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched required label status = %d, want 403", badLabelResp.StatusCode)
	}
}

func TestHTTPClientAuthorizerRunLimitReturns504And500(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mesh := newInProcessMeshPair(t, ctx)
	ep, err := mesh.provider.ListenA2A(ctx, A2AOptions{Name: "coder"})
	if err != nil {
		t.Fatalf("ListenA2A: %v", err)
	}
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() { _ = httpSrv.Serve(ep.PrivateListener) }()
	t.Cleanup(func() {
		_ = httpSrv.Close()
		_ = ep.Close()
	})

	hc := mesh.caller.HTTPClient()

	// 1. Transient Datalog evaluation timeout -> 504 Gateway Timeout (not 403).
	mesh.caller.node.BiscuitTimeout = time.Nanosecond
	resp504, err := hc.Post(ep.PrivateURL.String()+"/invoke", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST with 1ns BiscuitTimeout: %v", err)
	}
	body504, readErr := io.ReadAll(resp504.Body)
	_ = resp504.Body.Close()
	if readErr != nil {
		t.Fatalf("io.ReadAll(resp504): %v", readErr)
	}
	if resp504.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("authorizer timeout status = %d (%s), want 504 Gateway Timeout", resp504.StatusCode, body504)
	}

	// 2. Deterministic Datalog max-facts limit -> 500 Internal Server Error (not 403).
	mesh.caller.node.BiscuitTimeout = time.Second
	texts := make([]string, 0, 1100)
	for i := range 1100 {
		texts = append(texts, fmt.Sprintf("limit_fact_%d(true) <- role(%q)", i, api.RoleNode))
	}
	rules, err := api.ParseDatalogRules(texts)
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}
	mesh.caller.node.MeshPolicyMu.Lock()
	mesh.caller.node.MeshPolicyRules = rules
	mesh.caller.node.MeshPolicyMu.Unlock()

	resp500, err := hc.Post(ep.PrivateURL.String()+"/invoke", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST over Datalog fact limit: %v", err)
	}
	body500, readErr := io.ReadAll(resp500.Body)
	_ = resp500.Body.Close()
	if readErr != nil {
		t.Fatalf("io.ReadAll(resp500): %v", readErr)
	}
	if resp500.StatusCode != http.StatusInternalServerError {
		t.Fatalf("authorizer max-facts status = %d (%s), want 500 Internal Server Error", resp500.StatusCode, body500)
	}
}

func TestListenA2APublicNoAnnounceReturnsNilPublicURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rh.Close() })

	routerBiscuit := mintTestBiscuit(t, cpPriv, rh.ID().String(), api.RoleRouter, time.Now().Add(time.Hour))
	rh.SetStreamHandler(api.AuthProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, rErr := reader.ReadMsg()
		if rErr != nil {
			return
		}
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: routerBiscuit})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})
	rh.SetStreamHandler(api.DirectoryProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, rErr := reader.ReadMsg()
		if rErr != nil {
			return
		}
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.DirectoryResponse{})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})

	var routerAddrs []string
	for _, a := range rh.Addrs() {
		routerAddrs = append(routerAddrs, a.String()+"/p2p/"+rh.ID().String())
	}
	cp := newFakeControlPlaneHTTPWithKeys(t, cpPub, cpPriv, routerAddrs)
	cp.mu.Lock()
	cp.routers = []*api.RouterInfo{
		{
			PeerId:     rh.ID().String(),
			Addresses:  routerAddrs,
			IngressUrl: "https://bananas.sam-mesh.dev/ingress",
		},
	}
	cp.mu.Unlock()

	s := &Server{
		StateDir:        t.TempDir(),
		ControlPlaneURL: cp.srv.URL,
		BootstrapToken:  "boot-secret",
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
	}
	if _, err := s.Up(ctx); err != nil {
		t.Fatalf("Server.Up: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	unannounced, err := s.ListenA2A(ctx, A2AOptions{
		Name:       "unannounced-agent",
		Public:     true,
		NoAnnounce: true,
	})
	if err != nil {
		t.Fatalf("ListenA2A(NoAnnounce=true): %v", err)
	}
	t.Cleanup(func() { _ = unannounced.Close() })
	if unannounced.PublicListener == nil {
		t.Fatal("PublicListener is nil, want non-nil when Public=true")
	}
	if unannounced.PublicURL != nil {
		t.Fatalf("PublicURL = %v, want nil when NoAnnounce=true (routers have no directory route)", unannounced.PublicURL)
	}

	announced, err := s.ListenA2A(ctx, A2AOptions{
		Name:   "announced-agent",
		Public: true,
	})
	if err != nil {
		t.Fatalf("ListenA2A(NoAnnounce=false): %v", err)
	}
	t.Cleanup(func() { _ = announced.Close() })
	wantPubURL := fmt.Sprintf("https://bananas.sam-mesh.dev/ingress/%s/a2a/announced-agent", s.Status().PeerID)
	if announced.PublicURL == nil || announced.PublicURL.String() != wantPubURL {
		t.Fatalf("PublicURL = %v, want %s", announced.PublicURL, wantPubURL)
	}
}

func TestServerMetricsRegistererNoCollisionAndCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rh.Close() })

	routerBiscuit := mintTestBiscuit(t, cpPriv, rh.ID().String(), api.RoleRouter, time.Now().Add(time.Hour))
	rh.SetStreamHandler(api.AuthProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, rErr := reader.ReadMsg()
		if rErr != nil {
			return
		}
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: routerBiscuit})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})
	rh.SetStreamHandler(api.DirectoryProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, rErr := reader.ReadMsg()
		if rErr != nil {
			return
		}
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.DirectoryResponse{})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})

	var routerAddrs []string
	for _, a := range rh.Addrs() {
		routerAddrs = append(routerAddrs, a.String()+"/p2p/"+rh.ID().String())
	}
	cp := newFakeControlPlaneHTTPWithKeys(t, cpPub, cpPriv, routerAddrs)

	reg := prometheus.NewRegistry()
	dir1 := t.TempDir()
	s1 := &Server{
		StateDir:        dir1,
		ControlPlaneURL: cp.srv.URL,
		BootstrapToken:  "boot-secret",
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
		Registerer:      reg,
	}
	st1, err := s1.Up(ctx)
	if err != nil {
		t.Fatalf("s1.Up: %v", err)
	}
	t.Cleanup(func() { _ = s1.Close() })

	s2 := &Server{
		StateDir:        t.TempDir(),
		ControlPlaneURL: cp.srv.URL,
		BootstrapToken:  "boot-secret",
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
		Registerer:      reg,
	}
	st2, err := s2.Up(ctx)
	if err != nil {
		t.Fatalf("s2.Up (shared Registerer): %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	// Trigger a gated stream refusal on s1 and verify s1's counter increments.
	stranger, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stranger.Close() })
	if err := stranger.Connect(ctx, peer.AddrInfo{ID: s1.node.Host.ID(), Addrs: s1.node.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	st, err := stranger.NewStream(ctx, s1.node.Host.ID(), api.IngressProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Reset() }()
	if _, err := st.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	_ = st.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := st.Read(buf); err == nil {
		t.Fatalf("%s answered %q to an unauthenticated peer", api.IngressProtocolID, buf[:n])
	}
	if err := stranger.Network().ClosePeer(s1.node.Host.ID()); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, func() uint64 {
		return s1.refusedStreamCount("unauthenticated", api.IngressProtocolID)
	}, 1, 5*time.Second)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("reg.Gather: %v", err)
	}
	if v, ok := findMetricValue(families, "agentmesh_meshnet_ready", map[string]string{"peer_id": st1.PeerID}); !ok || v != 1 {
		t.Errorf("s1 agentmesh_meshnet_ready = %v (ok=%v), want 1", v, ok)
	}
	if v, ok := findMetricValue(families, "agentmesh_meshnet_ready", map[string]string{"peer_id": st2.PeerID}); !ok || v != 1 {
		t.Errorf("s2 agentmesh_meshnet_ready = %v (ok=%v), want 1", v, ok)
	}
	if v, ok := findMetricValue(families, "agentmesh_meshnet_routers", map[string]string{"peer_id": st1.PeerID, "state": "attached"}); !ok || v < 1 {
		t.Errorf("s1 attached routers gauge = %v (ok=%v), want >= 1", v, ok)
	}
	if v, ok := findMetricValue(families, "agentmesh_meshnet_streams_refused_total", map[string]string{
		"peer_id":  st1.PeerID,
		"scope":    "unauthenticated",
		"protocol": string(api.IngressProtocolID),
	}); !ok || v < 1 {
		t.Errorf("s1 streams_refused_total = %v (ok=%v), want >= 1", v, ok)
	}

	// Closing s1 unregisters its collectors so the same PeerID can re-register cleanly.
	if err := s1.Close(); err != nil {
		t.Fatalf("s1.Close: %v", err)
	}
	afterClose, err := reg.Gather()
	if err != nil {
		t.Fatalf("reg.Gather after s1.Close: %v", err)
	}
	if _, ok := findMetricValue(afterClose, "agentmesh_meshnet_ready", map[string]string{"peer_id": st1.PeerID}); ok {
		t.Fatal("s1 metrics remained registered after Close")
	}

	s1Restarted := &Server{
		StateDir:        dir1,
		ControlPlaneURL: cp.srv.URL,
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
		Registerer:      reg,
	}
	if _, err := s1Restarted.Up(ctx); err != nil {
		t.Fatalf("s1Restarted.Up with same PeerID and Registerer: %v", err)
	}
	t.Cleanup(func() { _ = s1Restarted.Close() })
}

func TestCredentialLapseExponentialBackoffAndSignal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rh.Close() })

	routerBiscuit := mintTestBiscuit(t, cpPriv, rh.ID().String(), api.RoleRouter, time.Now().Add(time.Hour))
	rh.SetStreamHandler(api.AuthProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, rErr := reader.ReadMsg()
		if rErr != nil {
			return
		}
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: routerBiscuit})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})
	rh.SetStreamHandler(api.DirectoryProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, rErr := reader.ReadMsg()
		if rErr != nil {
			return
		}
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.DirectoryResponse{})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})

	var routerAddrs []string
	for _, a := range rh.Addrs() {
		routerAddrs = append(routerAddrs, a.String()+"/p2p/"+rh.ID().String())
	}

	var allowTokenSource atomic.Bool
	allowTokenSource.Store(true)

	// Dedicated fake CP whose /refresh blocks until the initial short-lived
	// credential reaches its expiry boundary, then fails immediately so the
	// very first failed renewal lands right at expiry with initial backoff.
	var expUnix atomic.Int64
	mux := http.NewServeMux()
	var cpURL string
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		resp := &api.KeysResponse{PublicKeys: [][]byte{cpPub}}
		_ = api.SignKeysResponse(resp, []ed25519.PrivateKey{cpPriv}, time.Now())
		writeProto(w, resp)
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, _ *http.Request) {
		writeProto(w, &api.ControlPlaneInfoResponse{RouterAddresses: routerAddrs})
	})
	mux.HandleFunc("/policies", func(w http.ResponseWriter, _ *http.Request) {
		compiled, _ := api.BuildPolicyRules([]*api.PolicyRole{
			{Name: api.RoleNode, AllowedTargets: []string{"*"}, AllowedServices: []string{"*"}, AllowedPublish: []string{"*"}, AllowedIngress: []*api.IngressGrant{{Services: []string{"*"}}}},
		}, nil)
		texts := make([]string, 0, len(compiled))
		for _, r := range compiled {
			texts = append(texts, r.Text)
		}
		writeProto(w, &api.PolicyConfigGetResponse{DatalogRules: texts})
	})
	mux.HandleFunc("/revocations", func(w http.ResponseWriter, _ *http.Request) {
		writeProto(w, &api.RevocationsResponse{})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var req api.EnrollRequest
		if !readProto(w, r, &req) {
			return
		}
		var exp time.Time
		if req.GetJwt() == "jwt-initial" {
			exp = time.Now().Truncate(time.Second).Add(2 * time.Second)
			expUnix.Store(exp.Unix())
		} else {
			exp = time.Now().Add(time.Hour)
			expUnix.Store(exp.Unix())
		}
		tok := mintTestBiscuit(t, cpPriv, req.GetPeerId(), api.RoleNode, exp)
		writeProto(w, &api.EnrollResponse{
			BiscuitToken:          tok,
			ControlPlanePublicKey: cpPub,
			ExpireTime:            timestamppb.New(exp),
			RouterAddresses:       routerAddrs,
		})
	})
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		target := time.Unix(expUnix.Load(), 0)
		if wait := time.Until(target); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-r.Context().Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		http.Error(w, "refresh unavailable", http.StatusServiceUnavailable)
	})
	cpSrv := httptest.NewServer(mux)
	cpURL = cpSrv.URL
	t.Cleanup(cpSrv.Close)

	var lapseMu sync.Mutex
	var lapseTimes []time.Time
	lapseCh := make(chan struct{}, 8)

	reg := prometheus.NewRegistry()
	s := &Server{
		StateDir:        t.TempDir(),
		ControlPlaneURL: cpURL,
		TokenSource: func(context.Context) (string, error) {
			if !allowTokenSource.Load() {
				return "", errors.New("idp unavailable")
			}
			if expUnix.Load() == 0 {
				return "jwt-initial", nil
			}
			return "jwt-recovered", nil
		},
		ListenAddrs:           []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:         true,
		Registerer:            reg,
		renewalInitialBackoff: 80 * time.Millisecond,
		renewalMaxBackoff:     time.Second,
		OnCredentialLapse: func(err error) {
			if !errors.Is(err, ErrCredentialLapsed) {
				t.Errorf("OnCredentialLapse error %v does not wrap ErrCredentialLapsed", err)
			}
			lapseMu.Lock()
			lapseTimes = append(lapseTimes, time.Now())
			lapseMu.Unlock()
			select {
			case lapseCh <- struct{}{}:
			default:
			}
		},
	}
	st, err := s.Up(ctx)
	if err != nil {
		t.Fatalf("s.Up: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Break TokenSource before expiry so fallback re-enrollment also fails.
	allowTokenSource.Store(false)

	select {
	case <-s.Done():
	case <-ctx.Done():
		t.Fatal("timed out waiting for s.Done() on credential lapse")
	}
	if !errors.Is(s.Err(), ErrCredentialLapsed) {
		t.Fatalf("s.Err() = %v, want ErrCredentialLapsed", s.Err())
	}
	if !s.Status().CredentialLapsed {
		t.Fatal("Status().CredentialLapsed = false, want true")
	}

	// Collect 3 consecutive lapse callbacks and verify exponential backoff (80ms -> 160ms).
	for range 3 {
		select {
		case <-lapseCh:
		case <-ctx.Done():
			t.Fatal("timed out waiting for 3 exponential-backoff lapse callbacks")
		}
	}
	lapseMu.Lock()
	t0, t1, t2 := lapseTimes[0], lapseTimes[1], lapseTimes[2]
	lapseMu.Unlock()

	gap1 := t1.Sub(t0)
	gap2 := t2.Sub(t1)
	if gap1 < 50*time.Millisecond {
		t.Errorf("first backoff gap = %v, want >= 50ms (initial 80ms)", gap1)
	}
	if gap2 < gap1+40*time.Millisecond {
		t.Errorf("second backoff gap = %v, did not grow exponentially over first gap %v", gap2, gap1)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("reg.Gather: %v", err)
	}
	if v, ok := findMetricValue(families, "agentmesh_meshnet_credential_lapsed", map[string]string{"peer_id": st.PeerID}); !ok || v != 1 {
		t.Errorf("agentmesh_meshnet_credential_lapsed = %v (ok=%v), want 1", v, ok)
	}
	if v, ok := findMetricValue(families, "agentmesh_meshnet_credential_lapses_total", map[string]string{"peer_id": st.PeerID}); !ok || v < 3 {
		t.Errorf("agentmesh_meshnet_credential_lapses_total = %v (ok=%v), want >= 3", v, ok)
	}

	// Restore TokenSource and verify the next backoff retry recovers Status().CredentialLapsed.
	allowTokenSource.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !s.Status().CredentialLapsed {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if s.Status().CredentialLapsed {
		t.Fatal("Status().CredentialLapsed remained true after TokenSource recovered")
	}
}

func findMetricValue(families []*dto.MetricFamily, name string, wantLabels map[string]string) (float64, bool) {
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			matched := true
			for k, want := range wantLabels {
				got := ""
				for _, lp := range m.GetLabel() {
					if lp.GetName() == k {
						got = lp.GetValue()
						break
					}
				}
				if got != want {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			if m.Gauge != nil {
				return m.Gauge.GetValue(), true
			}
			if m.Counter != nil {
				return m.Counter.GetValue(), true
			}
		}
	}
	return 0, false
}

func TestLocalMCPAndInferenceHandlers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mesh := newInProcessMeshPair(t, ctx)
	_, err := mesh.provider.ListenA2A(ctx, A2AOptions{Name: "helper", Description: "Helper agent"})
	if err != nil {
		t.Fatalf("ListenA2A: %v", err)
	}

	// 1. Local MCPServer + MCPHandler over StreamableHTTP.
	if mesh.caller.MCPServer() == nil {
		t.Fatal("MCPServer() returned nil")
	}
	mcpHTTP := httptest.NewServer(mesh.caller.MCPHandler())
	t.Cleanup(mcpHTTP.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-caller", Version: "1.0.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: mcpHTTP.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatalf("MCP Connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	toolsRes, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(toolsRes.Tools) != 6 {
		t.Fatalf("len(Tools) = %d, want 6 mesh tools", len(toolsRes.Tools))
	}

	infoRes, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "get_mesh_info"})
	if err != nil || infoRes.IsError {
		t.Fatalf("get_mesh_info failed: err=%v res=%+v", err, infoRes)
	}

	discRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_remote_services",
		Arguments: map[string]any{"type": "a2a"},
	})
	if err != nil || discRes.IsError {
		t.Fatalf("discover_remote_services failed: err=%v res=%+v", err, discRes)
	}
	discText := discRes.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(discText, "helper") {
		t.Errorf("discover_remote_services = %s, want helper", discText)
	}

	localRes, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "list_local_services"})
	if err != nil || localRes.IsError {
		t.Fatalf("list_local_services failed: err=%v res=%+v", err, localRes)
	}

	// CIDv1 representation of self PeerID is canonicalized and rejected by find_remote_tools.
	selfCIDv1 := peer.ToCid(mesh.caller.peerID).String()
	selfToolRes, selfToolErr := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "find_remote_tools",
		Arguments: map[string]any{"peer_id": selfCIDv1},
	})
	if selfToolErr == nil && (selfToolRes == nil || !selfToolRes.IsError) {
		t.Fatalf("find_remote_tools accepted CIDv1 self peer_id %q, want error", selfCIDv1)
	}

	// 2. Local InferenceHandler routes and validation.
	infHTTP := httptest.NewServer(mesh.caller.InferenceHandler())
	t.Cleanup(infHTTP.Close)

	modelsResp, err := http.Get(infHTTP.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	modelsBody, err := io.ReadAll(modelsResp.Body)
	_ = modelsResp.Body.Close()
	if err != nil {
		t.Fatalf("io.ReadAll(/v1/models): %v", err)
	}
	if modelsResp.StatusCode != http.StatusOK || !strings.Contains(string(modelsBody), `"object":"list"`) {
		t.Fatalf("GET /v1/models = %d: %s", modelsResp.StatusCode, modelsBody)
	}

	resp405, err := http.Post(infHTTP.URL+"/v1/models", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp405.Body.Close()
	if resp405.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /v1/models = %d, want 405", resp405.StatusCode)
	}

	resp404, err := http.Get(infHTTP.URL + "/v1/unknown")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("GET /v1/unknown = %d, want 404", resp404.StatusCode)
	}

	resp400, err := http.Post(infHTTP.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp400.Body.Close()
	if resp400.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /v1/chat/completions missing model = %d, want 400", resp400.StatusCode)
	}

	respUnknownModel, err := http.Post(infHTTP.URL+"/v1/chat/completions", "application/json", bytes.NewReader([]byte(`{"model":"gpt-4o"}`)))
	if err != nil {
		t.Fatal(err)
	}
	_ = respUnknownModel.Body.Close()
	if respUnknownModel.StatusCode != http.StatusNotFound {
		t.Errorf("POST /v1/chat/completions with unknown model = %d, want 404", respUnknownModel.StatusCode)
	}
}

func TestExternalIngressCanonicalizesActorNodePeerID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env := newStartedTestServer(t, ctx)
	s := env.server

	ep, err := s.ListenA2A(ctx, A2AOptions{
		Name:        "coder",
		Public:      true,
		IngressAuth: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
		NoAnnounce:  true,
	})
	if err != nil {
		t.Fatalf("ListenA2A: %v", err)
	}
	t.Cleanup(func() { _ = ep.Close() })

	var gotPeerID string
	var mu sync.Mutex
	pubSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if info, ok := s.WhoIs(r.RemoteAddr); ok && info != nil {
				mu.Lock()
				gotPeerID = info.PeerID
				mu.Unlock()
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() { _ = pubSrv.Serve(ep.PublicListener) }()
	t.Cleanup(func() { _ = pubSrv.Close() })

	actorHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = actorHost.Close() })
	cidv1Actor := peer.ToCid(actorHost.ID()).String()
	if cidv1Actor == actorHost.ID().String() {
		t.Fatalf("peer.ToCid(%s) produced identical string", actorHost.ID())
	}

	routerPeer := newAdmittedTestPeer(t, ctx, s, env.cpPriv, api.RoleRouter)
	routerBiscuit := mintTestBiscuit(t, env.cpPriv, routerPeer.ID().String(), api.RoleRouter, time.Now().Add(time.Hour))

	b := biscuit.NewBuilder(env.cpPriv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactActorNode, IDs: []biscuit.Term{biscuit.String(cidv1Actor)}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
		{Predicate: biscuit.Predicate{Name: api.FactEmail, IDs: []biscuit.Term{biscuit.String("carol@example.com")}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
		api.MarkerFact(api.FactTargetUnrestricted),
	} {
		if err := b.AddAuthorityFact(f); err != nil {
			t.Fatalf("AddAuthorityFact: %v", err)
		}
	}
	built, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	callerBytes, err := built.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://mesh/a2a/coder/invoke", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set(api.HeaderMeshBiscuit, base64.RawURLEncoding.EncodeToString(routerBiscuit))
	req.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringEdge)
	req.Header.Set(api.HeaderMeshIngressCallerBiscuit, base64.RawURLEncoding.EncodeToString(callerBytes))

	st, err := routerPeer.NewStream(ctx, s.node.Host.ID(), api.IngressProtocolID)
	if err != nil {
		t.Fatalf("NewStream(%s): %v", api.IngressProtocolID, err)
	}
	defer func() { _ = st.Close() }()
	if err := req.Write(st); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(st), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	respBody, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("io.ReadAll(resp): %v", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("external ingress status = %d (%s), want 200", resp.StatusCode, string(respBody))
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPeerID != actorHost.ID().String() {
		t.Fatalf("WhoIs PeerID = %q, want canonical %q (from CIDv1 %q)", gotPeerID, actorHost.ID().String(), cidv1Actor)
	}
}

func TestWhoIsUnverifiedExternalAndOIDCUserPeerID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env := newStartedTestServer(t, ctx)
	s := env.server

	edgeEP, err := s.ListenA2A(ctx, A2AOptions{
		Name:        "edge-agent",
		Public:      true,
		IngressAuth: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
		NoAnnounce:  true,
	})
	if err != nil {
		t.Fatalf("ListenA2A(edge-agent): %v", err)
	}
	t.Cleanup(func() { _ = edgeEP.Close() })

	passEP, err := s.ListenA2A(ctx, A2AOptions{
		Name:        "pass-agent",
		Public:      true,
		IngressAuth: api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
		NoAnnounce:  true,
	})
	if err != nil {
		t.Fatalf("ListenA2A(pass-agent): %v", err)
	}
	t.Cleanup(func() { _ = passEP.Close() })

	type whoIsObs struct {
		ok   bool
		info *CallerInfo
	}
	var obsMu sync.Mutex
	var lastObs whoIsObs

	recordHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := s.WhoIs(r.RemoteAddr)
		obsMu.Lock()
		lastObs = whoIsObs{ok: ok, info: info}
		obsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"agent"}`))
	})

	edgePubSrv := &http.Server{Handler: recordHandler}
	passPubSrv := &http.Server{Handler: recordHandler}
	go func() { _ = edgePubSrv.Serve(edgeEP.PublicListener) }()
	go func() { _ = passPubSrv.Serve(passEP.PublicListener) }()
	t.Cleanup(func() {
		_ = edgePubSrv.Close()
		_ = passPubSrv.Close()
	})

	routerPeer := newAdmittedTestPeer(t, ctx, s, env.cpPriv, api.RoleRouter)
	routerBiscuit := mintTestBiscuit(t, env.cpPriv, routerPeer.ID().String(), api.RoleRouter, time.Now().Add(time.Hour))

	sendIngressReq := func(t *testing.T, method, rawURL string, hdr http.Header) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		for k, vals := range hdr {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}
		req.Header.Set(api.HeaderMeshBiscuit, base64.RawURLEncoding.EncodeToString(routerBiscuit))

		st, err := routerPeer.NewStream(ctx, s.node.Host.ID(), api.IngressProtocolID)
		if err != nil {
			t.Fatalf("NewStream: %v", err)
		}
		defer func() { _ = st.Close() }()
		if err := req.Write(st); err != nil {
			t.Fatalf("req.Write: %v", err)
		}
		_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(st), req)
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatalf("io.ReadAll: %v", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d (%s), want 200", resp.StatusCode, string(respBody))
		}
	}

	// 1. Anonymous GET /.well-known/agent-card.json in EDGE mode -> WhoIs returns (nil, false).
	sendIngressReq(t, http.MethodGet, "http://mesh/a2a/edge-agent/.well-known/agent-card.json", http.Header{
		api.HeaderMeshIngress: {api.IngressAuthModeStringEdge},
	})
	obsMu.Lock()
	anonObs := lastObs
	obsMu.Unlock()
	if anonObs.ok || anonObs.info != nil {
		t.Fatalf("anonymous agent-card WhoIs = (%+v, %v), want (nil, false)", anonObs.info, anonObs.ok)
	}

	// 2. PASSTHROUGH request -> WhoIs returns (nil, false), never router's PeerID.
	sendIngressReq(t, http.MethodPost, "http://mesh/a2a/pass-agent/invoke", http.Header{
		api.HeaderMeshIngress: {api.IngressAuthModeStringPassthrough},
		"Authorization":       {"Bearer pair-token"},
	})
	obsMu.Lock()
	passObs := lastObs
	obsMu.Unlock()
	if passObs.ok || passObs.info != nil {
		t.Fatalf("PASSTHROUGH WhoIs = (%+v, %v), want (nil, false)", passObs.info, passObs.ok)
	}

	// 3. Verified standalone external OIDC user Biscuit from /oauth/token (actor_node bound to
	// control-plane Biscuit authority signing key, not a mesh node) -> WhoIs returns ok=true with PeerID == "".
	cpAuthorityPeerID := authorityKeyPeerID(env.cpPub)
	if cpAuthorityPeerID == "" {
		t.Fatal("authorityKeyPeerID(env.cpPub) returned empty string")
	}
	userBuilder := biscuit.NewBuilder(env.cpPriv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactActorNode, IDs: []biscuit.Term{biscuit.String(cpAuthorityPeerID)}}},
		{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(cpAuthorityPeerID)}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
		{Predicate: biscuit.Predicate{Name: api.FactEmail, IDs: []biscuit.Term{biscuit.String("carol@example.com")}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
		api.MarkerFact(api.FactTargetUnrestricted),
	} {
		if err := userBuilder.AddAuthorityFact(f); err != nil {
			t.Fatalf("AddAuthorityFact: %v", err)
		}
	}
	userTok, err := userBuilder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	userBytes, err := userTok.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	sendIngressReq(t, http.MethodPost, "http://mesh/a2a/edge-agent/invoke", http.Header{
		api.HeaderMeshIngress:              {api.IngressAuthModeStringEdge},
		api.HeaderMeshIngressCallerBiscuit: {base64.RawURLEncoding.EncodeToString(userBytes)},
	})
	obsMu.Lock()
	userObs := lastObs
	obsMu.Unlock()
	if !userObs.ok || userObs.info == nil {
		t.Fatal("verified external OIDC user WhoIs returned (nil, false), want verified CallerInfo")
	}
	if userObs.info.Principal != "carol@example.com" {
		t.Errorf("user WhoIs Principal = %q, want carol@example.com", userObs.info.Principal)
	}
	if userObs.info.PeerID != "" {
		t.Errorf("user WhoIs PeerID = %q, want empty string (must not leak router %q or authority key %q)", userObs.info.PeerID, routerPeer.ID(), cpAuthorityPeerID)
	}

	// 4. Delegated Biscuit exchanged by an actual mesh actor node -> WhoIs preserves actor node PeerID.
	actorHost, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		t.Fatalf("libp2p.New(actorHost): %v", err)
	}
	t.Cleanup(func() { _ = actorHost.Close() })
	actorBuilder := biscuit.NewBuilder(env.cpPriv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactActorNode, IDs: []biscuit.Term{biscuit.String(actorHost.ID().String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(actorHost.ID().String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleNode)}}},
		{Predicate: biscuit.Predicate{Name: api.FactEmail, IDs: []biscuit.Term{biscuit.String("carol@example.com")}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
		api.MarkerFact(api.FactTargetUnrestricted),
	} {
		if err := actorBuilder.AddAuthorityFact(f); err != nil {
			t.Fatalf("AddAuthorityFact(actor): %v", err)
		}
	}
	actorTok, err := actorBuilder.Build()
	if err != nil {
		t.Fatalf("Build(actor): %v", err)
	}
	actorBytes, err := actorTok.Serialize()
	if err != nil {
		t.Fatalf("Serialize(actor): %v", err)
	}
	sendIngressReq(t, http.MethodPost, "http://mesh/a2a/edge-agent/invoke", http.Header{
		api.HeaderMeshIngress:              {api.IngressAuthModeStringEdge},
		api.HeaderMeshIngressCallerBiscuit: {base64.RawURLEncoding.EncodeToString(actorBytes)},
	})
	obsMu.Lock()
	actorObs := lastObs
	obsMu.Unlock()
	if !actorObs.ok || actorObs.info == nil {
		t.Fatal("actor-delegated WhoIs returned (nil, false), want verified CallerInfo")
	}
	if actorObs.info.PeerID != actorHost.ID().String() {
		t.Errorf("actor-delegated WhoIs PeerID = %q, want %q", actorObs.info.PeerID, actorHost.ID().String())
	}
}

func TestHTTPClientCanonicalizesCIDv1PeerIDAndRecoversAbort(t *testing.T) {
	t.Run("canonicalizes_cidv1_peer_id_on_egress", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		mesh := newInProcessMeshPair(t, ctx)
		ep, err := mesh.provider.ListenA2A(ctx, A2AOptions{Name: "coder"})
		if err != nil {
			t.Fatalf("ListenA2A: %v", err)
		}
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("cidv1-ok"))
			}),
		}
		go func() { _ = srv.Serve(ep.PrivateListener) }()
		t.Cleanup(func() {
			_ = srv.Close()
			_ = ep.Close()
		})

		cidv1Provider := peer.ToCid(mesh.provider.peerID).String()
		if cidv1Provider == mesh.provider.peerID.String() {
			t.Fatalf("peer.ToCid(%s) did not produce distinct CIDv1 string", mesh.provider.peerID)
		}

		resp, err := mesh.caller.HTTPClient().Get(fmt.Sprintf("http://agentmesh.local/mesh/%s/a2a/coder/ping", cidv1Provider))
		if err != nil {
			t.Fatalf("GET with CIDv1 peer ID: %v", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatalf("io.ReadAll: %v", readErr)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "cidv1-ok" {
			t.Fatalf("CIDv1 egress = %d %q, want 200 cidv1-ok", resp.StatusCode, string(body))
		}
	})

	t.Run("recovers_ErrAbortHandler_before_headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://agentmesh.local/mesh/test", nil)
		pr, pw := io.Pipe()
		rw := newPipeResponseWriter(req, pw)

		go serveEgressSafe(&Server{}, req.URL.String(), req, rw, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(http.ErrAbortHandler)
		}))

		resp, err := rw.waitResponse(pr)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("waitResponse err = %v (resp=%v), want io.ErrUnexpectedEOF", err, resp)
		}
	})

	t.Run("recovers_ErrAbortHandler_mid_stream", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://agentmesh.local/mesh/test", nil)
		pr, pw := io.Pipe()
		rw := newPipeResponseWriter(req, pw)

		go serveEgressSafe(&Server{}, req.URL.String(), req, rw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("partial-chunk"))
			panic(http.ErrAbortHandler)
		}))

		resp, err := rw.waitResponse(pr)
		if err != nil {
			t.Fatalf("waitResponse after headers: %v", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "partial-chunk" {
			t.Errorf("partial body = %q, want partial-chunk", string(body))
		}
		if !errors.Is(readErr, io.ErrUnexpectedEOF) {
			t.Fatalf("io.ReadAll after mid-stream abort = %v, want io.ErrUnexpectedEOF", readErr)
		}
	})

	t.Run("recovers_unexpected_handler_panic", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://agentmesh.local/mesh/test", nil)
		pr, pw := io.Pipe()
		rw := newPipeResponseWriter(req, pw)

		go serveEgressSafe(&Server{}, req.URL.String(), req, rw, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("unexpected-boom")
		}))

		resp, err := rw.waitResponse(pr)
		if err == nil || !strings.Contains(err.Error(), "unexpected-boom") {
			t.Fatalf("waitResponse on unexpected panic = (%v, %v), want error containing unexpected-boom", resp, err)
		}
	})
}

func TestServerConcurrentStatusMetricsAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	env := newStartedTestServer(t, ctx)
	reg := prometheus.NewRegistry()
	s := &Server{
		ControlPlaneURL: env.cp.srv.URL,
		BootstrapToken:  "boot-secret",
		ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
		AllowInsecure:   true,
		Registerer:      reg,
	}
	if _, err := s.Up(ctx); err != nil {
		t.Fatalf("s.Up: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = s.Status()
				_, _ = reg.Gather()
				_, _, _ = s.AttenuateToken(&api.TaskAuthorizationRule{Name: "race-check"}, time.Minute, false)
				s.onStreamRefused("unauthenticated", string(api.IngressProtocolID))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		_ = s.Close()
	}()
	wg.Wait()
}

type inProcessMeshPair struct {
	provider *Server
	caller   *Server
}

func newInProcessMeshPair(t *testing.T, ctx context.Context) *inProcessMeshPair {
	t.Helper()
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rh, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rh.Close() })

	var dirMu sync.Mutex
	providersByKey := map[string]map[peer.ID]*api.PeerRecord{}
	peersByID := map[peer.ID]*api.PeerRecord{}

	routerBiscuit := mintTestBiscuit(t, cpPriv, rh.ID().String(), api.RoleRouter, time.Now().Add(24*time.Hour))
	rh.SetStreamHandler(api.AuthProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		reader.ReleaseMsg(msg)
		reply, _ := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: routerBiscuit})
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})
	rh.SetStreamHandler(api.DirectoryProtocolID, func(st network.Stream) {
		defer func() { _ = st.Close() }()
		remote := st.Conn().RemotePeer()

		reader := msgio.NewVarintReaderSize(st, 64*1024)
		msg, err := reader.ReadMsg()
		if err != nil {
			return
		}
		var req api.DirectoryRequest
		_ = proto.Unmarshal(msg, &req)
		reader.ReleaseMsg(msg)

		resp := &api.DirectoryResponse{}
		dirMu.Lock()
		entry := peersByID[remote]
		if entry == nil {
			var addrs []string
			for _, ma := range rh.Peerstore().Addrs(remote) {
				addrs = append(addrs, ma.String())
			}
			entry = &api.PeerRecord{PeerId: remote.String(), Addrs: addrs}
			peersByID[remote] = entry
		}
		switch op := req.GetRequest().(type) {
		case *api.DirectoryRequest_Provide:
			k := string(op.Provide.GetKey())
			if providersByKey[k] == nil {
				providersByKey[k] = map[peer.ID]*api.PeerRecord{}
			}
			providersByKey[k][remote] = entry
		case *api.DirectoryRequest_Withdraw:
			delete(providersByKey[string(op.Withdraw.GetKey())], remote)
		case *api.DirectoryRequest_FindProviders:
			for _, p := range providersByKey[string(op.FindProviders.GetKey())] {
				resp.Providers = append(resp.Providers, p)
			}
		case *api.DirectoryRequest_FindPeer:
			if pid, err := peer.Decode(op.FindPeer.GetPeerId()); err == nil {
				resp.Peer = peersByID[pid]
			}
		}
		dirMu.Unlock()

		reply, _ := proto.Marshal(resp)
		_ = msgio.NewVarintWriter(st).WriteMsg(reply)
	})

	var routerAddrs []string
	for _, a := range rh.Addrs() {
		routerAddrs = append(routerAddrs, a.String()+"/p2p/"+rh.ID().String())
	}
	cp := newFakeControlPlaneHTTPWithKeys(t, cpPub, cpPriv, routerAddrs)

	startOne := func() *Server {
		s := &Server{
			StateDir:        t.TempDir(),
			ControlPlaneURL: cp.srv.URL,
			BootstrapToken:  "boot-secret",
			ListenAddrs:     []string{"/ip4/127.0.0.1/tcp/0"},
			AllowInsecure:   true,
		}
		if _, err := s.Up(ctx); err != nil {
			t.Fatalf("Server.Up: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}

	p := startOne()
	c := startOne()
	// Ensure router peerstore has listen multiaddrs of both peers for FindProviders/FindPeer.
	dirMu.Lock()
	for _, srv := range []*Server{p, c} {
		var maddrs []string
		for _, ma := range srv.node.Host.Addrs() {
			maddrs = append(maddrs, ma.String())
		}
		peersByID[srv.node.Host.ID()] = &api.PeerRecord{PeerId: srv.node.Host.ID().String(), Addrs: maddrs}
	}
	dirMu.Unlock()

	return &inProcessMeshPair{provider: p, caller: c}
}

// TestDeliverHTTPHandlerThatIgnoresBody drives deliverHTTP over its net.Pipe
// against a handler that answers without reading the request body, as an
// agent-card GET or an early refusal does. The transport must keep the
// connection alive so net/http's server drains the body before it closes;
// with Connection: close the server closed first and the transport's body
// write raced the response, surfacing as a 502 under load.
func TestDeliverHTTPHandlerThatIgnoresBody(t *testing.T) {
	s := &Server{}
	ln := newInprocListener("meshnet:test:ignore-body")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})

	body := bytes.Repeat([]byte("x"), 64<<10)
	caller := &CallerInfo{PeerID: "12D3KooWTestPeer", Principal: "node:test"}
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://agentmesh.local/invoke", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		s.deliverHTTP(rec, req, ln, caller, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, body = %q, want 200", i, rec.Code, rec.Body.String())
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		live := 0
		s.activeConns.Range(func(_, _ any) bool { live++; return true })
		if live == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.activeConns.Range(func(k, _ any) bool {
		t.Errorf("WhoIs entry %v still present after its connection closed", k)
		return true
	})
}
