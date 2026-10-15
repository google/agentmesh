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
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// oidcMember is a member enrolled with an OIDC token, driven over the
// control plane API alone: the test decides when it refreshes and with what.
type oidcMember struct {
	priv    crypto.PrivKey
	peerID  peer.ID
	sub     string
	biscuit []byte
}

// enrollOIDCMember enrolls a fresh key at POST /register with a token for sub.
func enrollOIDCMember(t *testing.T, cpPort int, mintToken func(map[string]interface{}) string, sub string) *oidcMember {
	t.Helper()
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	pID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := registerOnControlPlane(t, cpPort, pID, priv, mintToken(map[string]interface{}{"sub": sub, "roles": []string{api.RoleNode}}))
	return &oidcMember{priv: priv, peerID: pID, sub: sub, biscuit: enrolled.BiscuitToken}
}

// refresh is one POST /refresh with the member's current credential and,
// when jwt is set, a fresh platform token that renews the session; on
// success the member holds the new credential. It returns status and body.
func (m *oidcMember) refresh(t *testing.T, cpURL, jwt string) (int, string) {
	t.Helper()
	ts := time.Now().UnixMilli()
	sig, err := m.priv.Sign(api.RefreshChallenge(m.peerID.String(), ts))
	if err != nil {
		t.Fatal(err)
	}
	body, err := proto.Marshal(&api.TokenRefreshRequest{ChallengeUnixMs: ts, ChallengeSignature: sig, Jwt: jwt})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, cpURL+"/refresh", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(m.biscuit))
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST /refresh: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		var refreshed api.TokenRefreshResponse
		if err := proto.Unmarshal(data, &refreshed); err != nil {
			t.Fatal(err)
		}
		m.biscuit = refreshed.BiscuitToken
	}
	return resp.StatusCode, string(data)
}

// listNodes is GET /user/nodes as the administrator, one page.
func listNodes(t *testing.T, cpURL, adminToken, query string) *api.NodeListResponse {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, cpURL+"/user/nodes?"+query, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET /user/nodes?%s: %v", query, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /user/nodes?%s: %d %s", query, resp.StatusCode, data)
	}
	var page api.NodeListResponse
	if err := protojson.Unmarshal(data, &page); err != nil {
		t.Fatalf("GET /user/nodes?%s: %v", query, err)
	}
	return &page
}

// controlPlaneMetric reads one series from the control plane's /metrics.
func controlPlaneMetric(t *testing.T, cpURL, series string) (float64, bool) {
	t.Helper()
	resp, err := http.Get(cpURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, series+" ") {
			var v float64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, series+" "), "%g", &v); err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return v, true
		}
	}
	return 0, false
}

// TestLapsedMembersAreCollected is the testnet's nodes table in seconds. A
// probe CronJob enrolls a fresh identity every run and never comes back for
// it; such rows stayed forever, the table grew without bound, the metrics
// scrape read every row every 30 seconds and the control plane stalled on
// it. One member keeps its session alive by refreshing with a fresh token;
// sixteen enroll and leave.
func TestLapsedMembersAreCollected(t *testing.T) {
	tmpDir := t.TempDir()
	oidcURL, mintToken := startCustomMockOIDC(t)
	policyFile := filepath.Join(tmpDir, "policies.yaml")
	policy := fmt.Sprintf("roles: []\nbindings:\n  - role: %s\n    members: [%q]\n", api.RoleNode, api.SystemAuthenticated)
	if err := os.WriteFile(policyFile, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	// Sessions of two seconds, kept for one more after they lapse; the GC
	// sweeps at a tenth of the retention, no less often than every second.
	cpPort, _ := startControlPlane(t, tmpDir, oidcURL, policyFile,
		"--oidc-session-ttl", "2s",
		"--node-retention", "1s",
	)
	cpURL := fmt.Sprintf("http://127.0.0.1:%d", cpPort)

	// Under the enrollment limiter's burst (controlplane.EnrollBurst), which
	// is a guard this test leaves in force.
	const leaving = 16
	stayer := enrollOIDCMember(t, cpPort, mintToken, "stayer")
	leavers := make([]*oidcMember, leaving)
	for i := range leavers {
		leavers[i] = enrollOIDCMember(t, cpPort, mintToken, fmt.Sprintf("leaver-%02d", i))
	}
	enrolledAt := time.Now()

	// The one that stays refreshes with a fresh token well within its
	// session; each such refresh renews the session.
	stop := make(chan struct{})
	stopRefreshing := sync.OnceFunc(func() { close(stop) })
	t.Cleanup(stopRefreshing)
	refreshed := make(chan error, 1)
	go func() {
		defer close(refreshed)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				ts := time.Now().UnixMilli()
				sig, err := stayer.priv.Sign(api.RefreshChallenge(stayer.peerID.String(), ts))
				if err != nil {
					refreshed <- err
					return
				}
				jwt := mintToken(map[string]interface{}{"sub": stayer.sub, "roles": []string{api.RoleNode}})
				body, _ := proto.Marshal(&api.TokenRefreshRequest{ChallengeUnixMs: ts, ChallengeSignature: sig, Jwt: jwt})
				req, _ := http.NewRequest(http.MethodPost, cpURL+"/refresh", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(stayer.biscuit))
				req.Header.Set("Content-Type", "application/x-protobuf")
				resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				if err != nil {
					refreshed <- err
					return
				}
				data, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					refreshed <- fmt.Errorf("refresh of the member that stays: %d %s", resp.StatusCode, data)
					return
				}
				var out api.TokenRefreshResponse
				if err := proto.Unmarshal(data, &out); err != nil {
					refreshed <- err
					return
				}
				stayer.biscuit = out.BiscuitToken
			}
		}
	}()

	// Every member is admitted; the status lists them all.
	if got := len(fetchAdminStatus(t, cpPort, testAdminToken).GetEnrolledNodes()); got != leaving+1 {
		t.Fatalf("admin status lists %d nodes right after enrollment, want %d", got, leaving+1)
	}

	// The leavers' sessions lapse. A lapsed member is refused at /refresh
	// and told what to do; it is out of the status and in the expired list,
	// which pages; and the metrics count it by state without listing it.
	time.Sleep(time.Until(enrolledAt.Add(2500 * time.Millisecond)))
	if status, body := leavers[0].refresh(t, cpURL, ""); status != http.StatusUnauthorized || !strings.Contains(body, "Session expired") {
		t.Fatalf("refresh of a lapsed member: %d %s, want 401 naming the lapsed session", status, strings.TrimSpace(body))
	}
	if nodes := fetchAdminStatus(t, cpPort, testAdminToken).GetEnrolledNodes(); len(nodes) != 1 || nodes[0].GetPeerId() != stayer.peerID.String() {
		t.Fatalf("admin status after the sessions lapsed lists %d nodes, want only the one that refreshes", len(nodes))
	}
	var expired []string
	pageToken := ""
	for pages := 0; ; pages++ {
		page := listNodes(t, cpURL, testAdminToken, "state=expired&page_size=5&page_token="+pageToken)
		for _, n := range page.GetNodes() {
			expired = append(expired, n.GetPeerId())
		}
		if page.GetNextPageToken() == "" {
			if pages != 3 {
				t.Errorf("%d expired nodes came in %d pages of 5, want 4", len(expired), pages+1)
			}
			break
		}
		pageToken = page.GetNextPageToken()
	}
	if len(expired) != leaving {
		t.Fatalf("expired list holds %d nodes, want the %d that left: %v", len(expired), leaving, expired)
	}
	for _, id := range expired {
		if id == stayer.peerID.String() {
			t.Fatalf("the member that refreshes is in the expired list")
		}
	}
	if v, ok := controlPlaneMetric(t, cpURL, `agentmesh_control_plane_enrolled_nodes{role="mesh:role:node",state="expired"}`); !ok || v != leaving {
		t.Errorf("enrolled_nodes{state=expired} = %v (present %v), want %d", v, ok, leaving)
	}
	if v, ok := controlPlaneMetric(t, cpURL, `agentmesh_control_plane_enrolled_nodes{role="mesh:role:node",state="admitted"}`); !ok || v != 1 {
		t.Errorf("enrolled_nodes{state=admitted} = %v (present %v), want 1", v, ok)
	}

	// The retention passes and the GC deletes the lapsed rows; the member
	// that refreshes is untouched.
	deadline := time.Now().Add(6 * time.Second)
	for {
		left := listNodes(t, cpURL, testAdminToken, "state=expired&page_size=200").GetNodes()
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d lapsed rows still in the table %s after they lapsed; want them deleted after the retention", len(left), time.Since(enrolledAt))
		}
		time.Sleep(200 * time.Millisecond)
	}
	if v, ok := controlPlaneMetric(t, cpURL, "agentmesh_control_plane_nodes_deleted_total"); !ok || v != leaving {
		t.Errorf("nodes_deleted_total = %v (present %v), want %d", v, ok, leaving)
	}
	stopRefreshing()
	if err := <-refreshed; err != nil {
		t.Fatalf("the member that kept refreshing was refused: %v", err)
	}
	if status, body := stayer.refresh(t, cpURL, ""); status != http.StatusOK {
		t.Fatalf("the member that kept refreshing is refused after the sweep: %d %s", status, body)
	}
	if nodes := fetchAdminStatus(t, cpPort, testAdminToken).GetEnrolledNodes(); len(nodes) != 1 {
		t.Fatalf("admin status after the sweep lists %d nodes, want 1", len(nodes))
	}
}
