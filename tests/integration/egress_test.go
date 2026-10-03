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

package integration_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/sam/api"
)

// TestEgressDestinationCUJ is the egress story end to end, with real
// binaries: an admin posts one policy document naming destinations, the
// credentials to use and the roles or labels that serve them; a node
// selected by role and by label starts serving them with no configuration
// of its own, and refuses the one whose credential the platform did not
// deliver; an application on that node's host reaches a destination through
// the local API, naming the agent it acts for; another mesh member reaches
// it through the PEP node, narrowed to the methods and paths its role
// allows; each destination sees the node's credential for it and nothing of
// the callers; and a policy update withdraws a destination without a
// restart.
func TestEgressDestinationCUJ(t *testing.T) {
	nodeBin := buildBinary(t, "./cmd/sam-node")
	tmpDir := t.TempDir()
	oidcURL, mintToken := startCustomMockOIDC(t)

	// Two destinations, standing in for api.github.com and an internal API.
	recordingServer := func(seen *[]*http.Request, mu *sync.Mutex) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			*seen = append(*seen, r.Clone(context.Background()))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}))
	}
	var mu sync.Mutex
	var seen, seenInternal []*http.Request
	upstream := recordingServer(&seen, &mu)
	defer upstream.Close()
	internal := recordingServer(&seenInternal, &mu)
	defer internal.Close()

	// One document: who serves what with which credential, and who may call
	// it how. api.github.com is served by role, the internal API by label; the
	// third destination names a credential nobody delivered. The contractor
	// may only GET under /repos/acme/.
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policyYAML := fmt.Sprintf(`roles:
  - name: pep
    allowed_targets: ["*"]
    allowed_labels: ["site=eu"]
  - name: contractor
    allowed_services: ["egress://api.github.com"]
    allowed_targets: ["*"]
    http:
      - service: "egress://api.github.com"
        methods: ["GET"]
        paths: ["/repos/acme/*"]
bindings:
  - role: pep
    members: ["user:pep-user"]
  - role: contractor
    members: ["user:contractor-user"]
  - role: sam:role:node
    members: ["user:pep-user", "user:contractor-user"]
egress:
  - name: api.github.com
    target_url: %q
    credential: github-eu
    served_by: ["pep"]
  - name: mam.internal.example.com
    target_url: %q
    credential: mam-basic
    served_by: ["site=eu"]
  - name: broken.example
    target_url: %q
    credential: never-delivered
    served_by: ["pep"]
`, upstream.URL, internal.URL, internal.URL)
	if err := os.WriteFile(policyFile, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	cpPort, cleanupCP := startControlPlaneAndRouter(t, tmpDir, oidcURL, mintToken, policyFile)
	defer cleanupCP()
	controlPlane := fmt.Sprintf("http://127.0.0.1:%d", cpPort)

	// The platform delivered two credentials to the PEP host as files, in
	// the two forms the node accepts; the third destination's is missing.
	secrets := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "github-eu"), []byte("ghp_pep_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "mam-basic"), []byte("svc:s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The PEP declares the label the second destination selects on. Nothing
	// about egress appears here.
	pepConfig := filepath.Join(tmpDir, "pep.yaml")
	if err := os.WriteFile(pepConfig, []byte("version: \"v1alpha1\"\nlabels:\n  site: eu\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pepToken := "test-token"
	pep := launchNode(t, nodeBin, os.Environ(), filepath.Join(tmpDir, "pep"), "run",
		"--control-plane", controlPlane,
		"--data-dir", filepath.Join(tmpDir, "pep"),
		"--api-token-path", tokenPath(t, pepToken),
		"--jwt", mintToken(map[string]interface{}{"sub": "pep-user", "roles": []string{api.RoleNode}}),
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--allow-loopback",
		"--discovery-interval", "100ms",
		"--control-plane-sync-interval", "1s",
		"--config", pepConfig,
		"--secrets-dir", secrets,
	)
	pepAPI := pep.waitForAPI(t)

	callerToken := "test-token"
	caller := launchNode(t, nodeBin, os.Environ(), filepath.Join(tmpDir, "caller"), "run",
		"--control-plane", controlPlane,
		"--data-dir", filepath.Join(tmpDir, "caller"),
		"--api-token-path", tokenPath(t, callerToken),
		"--jwt", mintToken(map[string]interface{}{"sub": "contractor-user", "roles": []string{api.RoleNode}}),
		"--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--allow-loopback",
		"--discovery-interval", "100ms",
	)
	callerAPI := caller.waitForAPI(t)
	connectPeer(t, callerAPI, pep.p2pAddr)
	waitForDHTPeers(t, pepAPI)
	pepPeer := extractPeerID(pep.p2pAddr)

	client := &http.Client{Timeout: 10 * time.Second}
	do := func(t *testing.T, method, rawURL, token string, headers map[string]string) int {
		t.Helper()
		req, err := http.NewRequest(method, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(api.HeaderSamAuthentication, "Bearer "+token)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, rawURL, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// The PEP picked its assignments up from the control plane and announced
	// them: the caller can discover egress://api.github.com like any service.
	waitForDiscoverableService(t, callerAPI, callerToken, "egress", "api.github.com")

	t.Run("an application on the PEP host, through the local API", func(t *testing.T) {
		// The app is configured with the node's API as its base URL and the
		// API token as its bearer, the way it would hold a provider key.
		req, _ := http.NewRequest(http.MethodGet, "http://"+pepAPI+"/egress/api.github.com/repos/acme/dubbing/pulls?state=open", nil)
		req.Header.Set("Authorization", "Bearer "+pepToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("local GET: %d, want 204", resp.StatusCode)
		}
		// The serving role is not narrowed, so any method passes here.
		if got := do(t, http.MethodPost, "http://"+pepAPI+"/egress/api.github.com/repos/acme/x", pepToken, nil); got != http.StatusNoContent {
			t.Errorf("local POST on an un-narrowed grant: %d, want 204", got)
		}
		if got := do(t, http.MethodGet, "http://"+pepAPI+"/egress/other.example/x", pepToken, nil); got != http.StatusNotFound {
			t.Errorf("a destination not assigned: %d, want 404", got)
		}
		// Selected by the node's attested label, with a Basic credential.
		if got := do(t, http.MethodGet, "http://"+pepAPI+"/egress/mam.internal.example.com/v2/clips/99", pepToken, nil); got != http.StatusNoContent {
			t.Errorf("a destination served by label: %d, want 204", got)
		}
		// Assigned, but its credential was never delivered: refused at
		// registration, so it is not served, and the others still are.
		if got := do(t, http.MethodGet, "http://"+pepAPI+"/egress/broken.example/x", pepToken, nil); got != http.StatusNotFound {
			t.Errorf("a destination with a missing credential: %d, want 404", got)
		}
	})

	t.Run("a mesh member, through the PEP node", func(t *testing.T) {
		base := fmt.Sprintf("http://%s/sam/%s/egress/api.github.com", callerAPI, pepPeer)
		for _, tc := range []struct {
			name   string
			method string
			path   string
			want   int
		}{
			{"GET under the granted prefix", http.MethodGet, "/repos/acme/dubbing/pulls?state=open", http.StatusNoContent},
			{"POST is outside the narrowed grant", http.MethodPost, "/repos/acme/dubbing/pulls", http.StatusForbidden},
			{"a path outside the narrowed grant", http.MethodGet, "/user", http.StatusForbidden},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := do(t, tc.method, base+tc.path, callerToken, nil); got != tc.want {
					t.Errorf("%s %s: %d, want %d", tc.method, tc.path, got, tc.want)
				}
			})
		}
	})

	// What the destinations saw: the node's credential for each, the requested
	// path, and no trace of the callers.
	mu.Lock()
	if len(seen) == 0 || len(seenInternal) == 0 {
		mu.Unlock()
		t.Fatalf("the destinations saw %d and %d requests", len(seen), len(seenInternal))
	}
	for _, r := range seen {
		if r.Header.Get("Authorization") != "Bearer ghp_pep_secret" {
			t.Errorf("api.github.com saw Authorization %q, want the PEP's bearer credential", r.Header.Get("Authorization"))
		}
		if r.URL.Path == "/user" || strings.Contains(r.URL.Path, "..") {
			t.Errorf("a refused request reached the destination: %s", r.URL.Path)
		}
	}
	for _, r := range seenInternal {
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("svc:s3cret")) {
			t.Errorf("internal API saw Authorization %q, want the PEP's Basic credential", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/v2/clips/99" {
			t.Errorf("internal API saw path %q", r.URL.Path)
		}
	}
	for _, r := range append(append([]*http.Request{}, seen...), seenInternal...) {
		for name := range r.Header {
			if strings.HasPrefix(name, "X-Sam-") || strings.HasPrefix(name, "X-Forwarded-") || name == api.HeaderPeerID {
				t.Errorf("a destination saw %s", name)
			}
		}
	}
	if seen[0].URL.RequestURI() != "/repos/acme/dubbing/pulls?state=open" {
		t.Errorf("first request URI = %q", seen[0].URL.RequestURI())
	}
	mu.Unlock()

	t.Run("a policy update withdraws a destination without a restart", func(t *testing.T) {
		// The admin reassigns api.github.com to nodes that do not exist. The
		// control plane publishes the update; the PEP re-syncs and withdraws.
		current, err := os.ReadFile(policyFile)
		if err != nil {
			t.Fatal(err)
		}
		updated := strings.Replace(string(current), `served_by: ["pep"]`, `served_by: ["site=nowhere"]`, 1)
		if updated == string(current) {
			t.Fatal("policy file did not contain the assignment to change")
		}
		if err := os.WriteFile(policyFile, []byte(updated), 0o644); err != nil {
			t.Fatal(err)
		}
		injectPolicyYAML(t, cpPort, "test-admin-token", policyFile)

		deadline := time.Now().Add(8 * time.Second)
		for {
			got := do(t, http.MethodGet, "http://"+pepAPI+"/egress/api.github.com/repos/acme/x", pepToken, nil)
			if got == http.StatusNotFound {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("api.github.com still served after the update: %d", got)
			}
			time.Sleep(200 * time.Millisecond)
		}
		// The destination selected by label is untouched.
		if got := do(t, http.MethodGet, "http://"+pepAPI+"/egress/mam.internal.example.com/v2/clips/1", pepToken, nil); got != http.StatusNoContent {
			t.Errorf("the other destination after the update: %d, want 204", got)
		}
	})

	// The node's log tells the operator what it serves, what it refused and
	// why, and what it withdrew.
	log := pep.log()
	for _, want := range []string{
		"Serving egress://api.github.com",
		"Serving egress://mam.internal.example.com",
		`credential "never-delivered"`,
		"Withdrawn egress://api.github.com",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("PEP log lacks %q", want)
		}
	}
	if strings.Contains(log, "Serving egress://broken.example") {
		t.Error("PEP served a destination whose credential was never delivered")
	}
}
