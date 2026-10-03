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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
)

// TestLocalEgressRoute is the life of a request from a local client through
// /egress/{host}/{path}: the node's own credential decides, with the
// request's method and path and the assignment's host and port; a narrowed
// grant, the agent the client names and local attenuation all apply; the
// destination sees the node's credential and none of the client's headers.
func TestLocalEgressRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	node, cleanup := startBareNode(t, ctx)
	defer cleanup()

	var seen []*http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Clone(context.Background()))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	// The node's credential, as the control plane would mint it for a role
	// selected to serve api.github.com: the serving grant narrowed to GET
	// under /repos/acme/.
	narrowed := api.BuildHTTPGrantFacts(&api.HTTPGrant{Service: "egress://api.github.com", Methods: []string{"GET"}, Paths: []string{"/repos/acme/*"}})
	facts := append(narrowed,
		biscuit.Fact{Predicate: biscuit.Predicate{Name: api.FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String("egress"), biscuit.String("open.example")}}},
	)
	token, pub := mintFor(t, node.Host.ID(), facts...)
	node.SetIdentityCache(token)
	node.trustedKeys = []TrustedKey{{Key: pub, ReceivedAt: time.Now()}}

	secrets := t.TempDir()
	if err := os.WriteFile(filepath.Join(secrets, "github-eu"), []byte("ghp_secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	node.config.SecretsDir = secrets
	cfg, err := CompleteNodeConfig(api.NodeConfig{Attenuation: api.Attenuation{Policies: []string{
		`deny if path($p), $p.starts_with("/repos/acme/vault");`,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	node.nodeConfig = cfg
	if err := node.applyEgressAssignments(ctx, []*api.EgressDestination{
		{Name: "api.github.com", TargetUrl: upstream.URL, Credential: "github-eu"},
		{Name: "open.example", TargetUrl: upstream.URL},
	}); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(t.TempDir(), "node.sock")
	srv, err := StartSidecarServer(node, "127.0.0.1:0", socketPath, "api-token", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	waitForSocket(t, socketPath)
	base := "http://" + node.BoundHTTPAddr

	do := func(t *testing.T, method, path string, headers map[string]string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		// The app sends the node's API token as its bearer, as it would send
		// a provider key; the destination must never see it.
		req.Header.Set("Authorization", "Bearer api-token")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}

	// The node's own refusals name themselves, so an app can tell a policy
	// denial from a 403 the destination sent.
	proxyStatus := map[int]string{
		http.StatusForbidden: "sam-node; error=http_request_denied",
		http.StatusNotFound:  "sam-node; error=destination_not_found",
	}

	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		want    int
	}{
		{"allowed method under the granted prefix", "GET", "/egress/api.github.com/repos/acme/dubbing/pulls?state=open", nil, http.StatusNoContent},
		{"method outside the narrowed grant", "POST", "/egress/api.github.com/repos/acme/dubbing/pulls", nil, http.StatusForbidden},
		{"path outside the narrowed grant", "GET", "/egress/api.github.com/user", nil, http.StatusForbidden},
		{"local attenuation on path", "GET", "/egress/api.github.com/repos/acme/vault/keys", nil, http.StatusForbidden},
		{"a destination with a plain grant takes any method", "DELETE", "/egress/open.example/anything", nil, http.StatusNoContent},
		{"a destination not assigned to this node", "GET", "/egress/other.example/x", nil, http.StatusNotFound},
		{"a mesh name is not an egress destination", "GET", "/egress/tools.mcp.sam.alt/x", nil, http.StatusNotFound},
	}
	decisions := func(destination, outcome string) float64 {
		return counterValue(t, egressDecisionsTotal.WithLabelValues(destination, outcome))
	}
	before := map[[2]string]float64{}
	for _, k := range [][2]string{{"api.github.com", egressOutcomeAllow}, {"api.github.com", egressOutcomeDeny}, {"open.example", egressOutcomeAllow}, {"other.example", egressOutcomeNotAssigned}} {
		before[k] = decisions(k[0], k[1])
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, tc.method, tc.path, tc.headers)
			if resp.StatusCode != tc.want {
				t.Errorf("%s %s: status %d, want %d", tc.method, tc.path, resp.StatusCode, tc.want)
			}
			if want, ok := proxyStatus[tc.want]; ok && resp.Header.Get("Proxy-Status") != want {
				t.Errorf("%s %s: Proxy-Status %q, want %q", tc.method, tc.path, resp.Header.Get("Proxy-Status"), want)
			}
			if tc.want == http.StatusNoContent && resp.Header.Get("Proxy-Status") != "" {
				t.Errorf("%s %s: an allowed request carries Proxy-Status %q", tc.method, tc.path, resp.Header.Get("Proxy-Status"))
			}
		})
	}

	// Every decision above is one increment of the decisions counter, by
	// destination and outcome, so an operator can alert on denials and on
	// requests for destinations nobody assigned.
	for k, want := range map[[2]string]float64{
		{"api.github.com", egressOutcomeAllow}:      1,
		{"api.github.com", egressOutcomeDeny}:       3,
		{"open.example", egressOutcomeAllow}:        1,
		{"other.example", egressOutcomeNotAssigned}: 1,
	} {
		if got := decisions(k[0], k[1]) - before[k]; got != want {
			t.Errorf("decisions{destination=%q,outcome=%q} moved by %v, want %v", k[0], k[1], got, want)
		}
	}

	// Without the API token the gate refuses before anything is evaluated.
	req, _ := http.NewRequest(http.MethodGet, base+"/egress/api.github.com/repos/acme/x", nil)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("untokened request: %d, want 401", resp.StatusCode)
	}

	// A dot segment never reaches the destination, however the mux and the
	// handler split the work of refusing it.
	if resp := do(t, http.MethodGet, "/egress/api.github.com/repos/acme/../../user", nil); resp.StatusCode == http.StatusNoContent {
		t.Error("a traversal was forwarded")
	}

	// What the destination saw for the allowed requests.
	if len(seen) == 0 {
		t.Fatal("upstream saw no request")
	}
	for _, r := range seen {
		if strings.Contains(r.URL.Path, "..") || r.URL.Path == "/user" {
			t.Errorf("upstream saw a traversal: %s", r.URL.Path)
		}
	}
	first := seen[0]
	if first.URL.RequestURI() != "/repos/acme/dubbing/pulls?state=open" {
		t.Errorf("upstream URI = %q", first.URL.RequestURI())
	}
	if first.Header.Get("Authorization") != "Bearer ghp_secret" {
		t.Errorf("upstream Authorization = %q, want the node's credential", first.Header.Get("Authorization"))
	}
	for _, r := range seen {
		for name := range r.Header {
			if strings.HasPrefix(name, "X-Sam-") || strings.HasPrefix(name, "X-Forwarded-") || name == api.HeaderPeerID {
				t.Errorf("upstream saw %s", name)
			}
		}
		if strings.Contains(r.Header.Get("Authorization"), "api-token") {
			t.Error("the client's API token reached the destination")
		}
	}
}
