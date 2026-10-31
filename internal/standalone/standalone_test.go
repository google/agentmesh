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

package standalone

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestWsListenMultiaddr(t *testing.T) {
	cases := []struct {
		bind    string
		want    string
		wantErr bool
	}{
		{bind: "0.0.0.0:8080", want: "/ip4/0.0.0.0/tcp/8080/ws"},
		{bind: "127.0.0.1:0", want: "/ip4/127.0.0.1/tcp/0/ws"},
		{bind: ":9090", want: "/ip4/0.0.0.0/tcp/9090/ws"},
		{bind: "[::1]:8080", want: "/ip6/::1/tcp/8080/ws"},
		{bind: "example.com:8080", wantErr: true},
		{bind: "8080", wantErr: true},
	}
	for _, tc := range cases {
		got, err := wsListenMultiaddr(tc.bind)
		if tc.wantErr {
			if err == nil {
				t.Errorf("wsListenMultiaddr(%q) = %q, want error", tc.bind, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("wsListenMultiaddr(%q) failed: %v", tc.bind, err)
			continue
		}
		if got != tc.want {
			t.Errorf("wsListenMultiaddr(%q) = %q, want %q", tc.bind, got, tc.want)
		}
	}
}

func TestExternalMultiaddr(t *testing.T) {
	cases := []struct {
		url     string
		want    string
		wantErr bool
	}{
		{url: "https://my-agentmesh.a.run.app", want: "/dns4/my-agentmesh.a.run.app/tcp/443/wss"},
		{url: "http://192-168-1-50.nip.io:8080", want: "/dns4/192-168-1-50.nip.io/tcp/8080/ws"},
		{url: "http://192.168.1.50:8080", want: "/ip4/192.168.1.50/tcp/8080/ws"},
		{url: "https://mesh.example:8443", want: "/dns4/mesh.example/tcp/8443/wss"},
		{url: "ftp://mesh.example", wantErr: true},
		{url: "http://", wantErr: true},
	}
	for _, tc := range cases {
		got, err := externalMultiaddr(tc.url)
		if tc.wantErr {
			if err == nil {
				t.Errorf("externalMultiaddr(%q) = %q, want error", tc.url, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("externalMultiaddr(%q) failed: %v", tc.url, err)
			continue
		}
		if got != tc.want {
			t.Errorf("externalMultiaddr(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestEnsureRouterKeyDeterministic(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	key1 := filepath.Join(dir1, routerKeyFile)
	key2 := filepath.Join(dir2, routerKeyFile)

	if err := ensureRouterKey(key1, "mesh_adm_fixed_secret"); err != nil {
		t.Fatalf("ensureRouterKey(key1): %v", err)
	}
	if err := ensureRouterKey(key2, "mesh_adm_fixed_secret"); err != nil {
		t.Fatalf("ensureRouterKey(key2): %v", err)
	}

	b1, err := os.ReadFile(key1)
	if err != nil {
		t.Fatalf("ReadFile(key1): %v", err)
	}
	b2, err := os.ReadFile(key2)
	if err != nil {
		t.Fatalf("ReadFile(key2): %v", err)
	}
	p1, err := crypto.UnmarshalPrivateKey(b1)
	if err != nil {
		t.Fatalf("UnmarshalPrivateKey(b1): %v", err)
	}
	p2, err := crypto.UnmarshalPrivateKey(b2)
	if err != nil {
		t.Fatalf("UnmarshalPrivateKey(b2): %v", err)
	}
	id1, _ := peer.IDFromPrivateKey(p1)
	id2, _ := peer.IDFromPrivateKey(p2)
	if id1 != id2 {
		t.Fatalf("peer IDs differ for same adminToken: %s vs %s", id1, id2)
	}

	// Existing key file must not be overwritten by a different admin token.
	if err := ensureRouterKey(key1, "mesh_adm_other_secret"); err != nil {
		t.Fatalf("ensureRouterKey existing: %v", err)
	}
	b1After, err := os.ReadFile(key1)
	if err != nil {
		t.Fatalf("ReadFile(key1 after): %v", err)
	}
	if string(b1) != string(b1After) {
		t.Fatalf("ensureRouterKey overwrote an existing router.key")
	}
}

// A hub behind a reverse proxy that did not state --external-url advertises
// its own listener, which members behind the proxy cannot reach. The first
// proxied request says so, every proxied request is counted, and the
// request itself is served unchanged. With --external-url, or without
// forwarded headers, nothing is counted.
func TestWrapPublicHTTPHandlerCountsProxiedRequestsWithoutExternalURL(t *testing.T) {
	served := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		w.WriteHeader(http.StatusNoContent)
	})
	counter := func(t *testing.T) float64 {
		t.Helper()
		var m dto.Metric
		if err := proxiedWithoutExternalURL.Write(&m); err != nil {
			t.Fatal(err)
		}
		return m.GetCounter().GetValue()
	}
	serve := func(h http.Handler, forwardedProto, forwardedHost string) int {
		req := httptest.NewRequest(http.MethodGet, "http://0.0.0.0:8080/info", nil)
		if forwardedProto != "" {
			req.Header.Set("X-Forwarded-Proto", forwardedProto)
		}
		if forwardedHost != "" {
			req.Header.Set("X-Forwarded-Host", forwardedHost)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	inferring := (&Server{opts: Options{}}).wrapPublicHTTPHandler(next)
	before := counter(t)
	if code := serve(inferring, "", ""); code != http.StatusNoContent {
		t.Fatalf("plain request: status %d, want 204", code)
	}
	if got := counter(t); got != before {
		t.Errorf("plain request counted: %v, want %v", got, before)
	}
	if code := serve(inferring, "https", "agentmesh-one-xyz-uc.a.run.app"); code != http.StatusNoContent {
		t.Fatalf("proxied request: status %d, want 204 (served unchanged)", code)
	}
	if code := serve(inferring, "", "agentmesh-one-xyz-uc.a.run.app"); code != http.StatusNoContent {
		t.Fatalf("proxied request (host only): status %d, want 204", code)
	}
	if got := counter(t); got != before+2 {
		t.Errorf("two proxied requests counted as %v, want %v", got-before, 2)
	}

	explicit := (&Server{opts: Options{ExternalURL: "https://mesh.example.com"}}).wrapPublicHTTPHandler(next)
	before = counter(t)
	if code := serve(explicit, "https", "agentmesh-one-xyz-uc.a.run.app"); code != http.StatusNoContent {
		t.Fatalf("with --external-url: status %d, want 204", code)
	}
	if got := counter(t); got != before {
		t.Errorf("with --external-url a proxied request was counted: %v, want %v", got, before)
	}
	if served != 4 {
		t.Errorf("next handler served %d requests, want 4", served)
	}
}

func TestStandaloneSinglePortIngressAndSeededPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	srv, err := New(Options{
		BindAddress: "127.0.0.1:0",
		DataDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	wantIngressURL := srv.PublicURL() + "/ingress"
	if got := srv.IngressURL(); got != wantIngressURL {
		t.Fatalf("srv.IngressURL() = %q, want %q", got, wantIngressURL)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Wait briefly for the embedded router's initial lease to be visible on /info.
	var leasedIngressURL string
	deadline := time.Now().Add(5 * time.Second)
	for {
		infoReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.PublicURL()+"/info", nil)
		infoReq.Header.Set("Accept", "application/x-protobuf")
		resp, err := client.Do(infoReq)
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			var info api.ControlPlaneInfoResponse
			if proto.Unmarshal(body, &info) == nil && len(info.GetRouters()) == 1 {
				leasedIngressURL = info.GetRouters()[0].GetIngressUrl()
				if leasedIngressURL != "" {
					break
				}
			}
		} else if resp != nil {
			_ = resp.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("router lease on /info never advertised ingress_url (got %q)", leasedIngressURL)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if leasedIngressURL != wantIngressURL {
		t.Fatalf("/info router ingress_url = %q, want %q", leasedIngressURL, wantIngressURL)
	}

	// RFC 9728 metadata on /ingress/.well-known/oauth-protected-resource must
	// advertise the public single-port URL, not the internal loopback CP port.
	metaResp, err := client.Get(srv.IngressURL() + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET oauth-protected-resource: %v", err)
	}
	defer func() { _ = metaResp.Body.Close() }()
	if metaResp.StatusCode != http.StatusOK {
		t.Fatalf("oauth-protected-resource status = %d, want 200", metaResp.StatusCode)
	}
	var meta api.OAuthProtectedResourceMetadata
	if err := json.NewDecoder(metaResp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if meta.Resource != wantIngressURL {
		t.Fatalf("meta.Resource = %q, want %q", meta.Resource, wantIngressURL)
	}
	if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != srv.PublicURL() {
		t.Fatalf("meta.AuthorizationServers = %v, want [%s]", meta.AuthorizationServers, srv.PublicURL())
	}

	// Seeded dev policy includes allowed_ingress on mesh:role:node.
	polReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.PublicURL()+"/admin/policy", nil)
	polReq.Header.Set("Authorization", "Bearer "+srv.AdminToken())
	polResp, err := client.Do(polReq)
	if err != nil {
		t.Fatalf("GET /admin/policy: %v", err)
	}
	polBody, _ := io.ReadAll(polResp.Body)
	_ = polResp.Body.Close()
	if polResp.StatusCode != http.StatusOK {
		t.Fatalf("/admin/policy status = %d: %s", polResp.StatusCode, string(polBody))
	}
	var pol api.PolicyConfig
	if err := protojson.Unmarshal(polBody, &pol); err != nil {
		t.Fatalf("unmarshal PolicyConfig: %v", err)
	}
	foundNodeIngress := false
	for _, role := range pol.GetRoles() {
		if role.GetName() == api.RoleNode && len(role.GetAllowedIngress()) > 0 {
			foundNodeIngress = true
			break
		}
	}
	if !foundNodeIngress {
		t.Fatalf("seeded PolicyConfig for %s lacks allowed_ingress: %+v", api.RoleNode, pol.GetRoles())
	}
}
