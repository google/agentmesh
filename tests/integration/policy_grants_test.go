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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Every other integration test mints tokens with the mock control plane in
// minimal_helpers_test.go, which builds a biscuit directly and never touches
// the policy store. That is exactly the blind spot that let allowed_agents ship
// while SaveMeshPolicy dropped it on the floor: the grant was configured, the
// API returned it, and the token was minted without it.
//
// This drives the real sam-control-plane binary over its own REST API, so the
// path under test is the deployed one: POST /policies -> database -> enrollment
// -> the facts actually inside the signed token.
func TestPolicyGrantsReachTheMintedToken(t *testing.T) {
	cpBin := buildBinary(t, "./cmd/sam-control-plane")
	tmpDir := t.TempDir()

	const adminToken = "integration-admin-token"
	adminTokenPath := filepath.Join(tmpDir, "admin-token")
	if err := os.WriteFile(adminTokenPath, []byte(adminToken), 0600); err != nil {
		t.Fatal(err)
	}

	oidcURL, mintToken := startCustomMockOIDC(t)
	cpPort := getFreePort(t)

	cpCmd := exec.Command(cpBin,
		"--bind-address", fmt.Sprintf("127.0.0.1:%d", cpPort),
		"--db-dsn", filepath.Join(tmpDir, "cp.db"),
		"--issuer", oidcURL,
		"--insecure-skip-tls-verify",
		"--admin-token-path", adminTokenPath,
	)
	cpCmd.Stdout = os.Stdout
	cpCmd.Stderr = os.Stderr
	if err := cpCmd.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}
	defer func() { _ = cpCmd.Process.Kill(); _ = cpCmd.Wait() }()
	waitForControlPlane(t, cpPort)

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", cpPort)
	client := &http.Client{Timeout: 5 * time.Second}

	// Every repeated field of PolicyRole, so a grant that does not survive the
	// round trip is caught whichever one it is.
	wantRole := &api.PolicyRole{
		Name:            api.RoleNode,
		AllowedServices: []string{"mcp://tool"},
		AllowedTargets:  []string{"group:backend"},
		CustomDatalog:   []string{`region("emea")`},
		AllowedLabels:   []string{"region=*"},
	}
	policyBody, err := proto.Marshal(&api.PolicyConfig{
		Roles: []*api.PolicyRole{wantRole},
		Bindings: []*api.PolicyBinding{{
			Role:    api.RoleNode,
			Members: []string{api.SystemAuthenticated},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/policies", bytes.NewReader(policyBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /policies: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /policies status %d: %s", resp.StatusCode, body)
	}

	t.Run("every grant survives the policy store", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, baseURL+"/admin/policy", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /admin/policy: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /admin/policy status %d: %s", resp.StatusCode, body)
		}

		var got api.PolicyConfig
		if err := protojson.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal policy: %v", err)
		}
		if len(got.Roles) != 1 {
			t.Fatalf("got %d roles, want 1", len(got.Roles))
		}
		r := got.Roles[0]

		for _, tc := range []struct {
			field string
			want  []string
			got   []string
		}{
			{"allowed_services", wantRole.AllowedServices, r.AllowedServices},
			{"allowed_targets", wantRole.AllowedTargets, r.AllowedTargets},
			{"custom_datalog", wantRole.CustomDatalog, r.CustomDatalog},
			{"allowed_labels", wantRole.AllowedLabels, r.AllowedLabels},
		} {
			if len(tc.got) != len(tc.want) || (len(tc.want) > 0 && tc.got[0] != tc.want[0]) {
				t.Errorf("%s did not survive the store: sent %v, read back %v", tc.field, tc.want, tc.got)
			}
		}
	})

	enroll := func(t *testing.T, labels map[string]string) (*api.EnrollResponse, int) {
		t.Helper()
		privKey, pubKey, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPublicKey(pubKey)
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := crypto.MarshalPublicKey(pubKey)
		if err != nil {
			t.Fatal(err)
		}
		ts := time.Now().UnixMilli()
		sig, err := privKey.Sign(api.RegisterChallenge(peerID.String(), ts))
		if err != nil {
			t.Fatal(err)
		}

		reqBytes, err := proto.Marshal(&api.EnrollRequest{
			Jwt:                mintToken(map[string]interface{}{"sub": "node-alice"}),
			PeerId:             peerID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleNode,
			Labels:             labels,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqBytes))
		if err != nil {
			t.Fatalf("POST /register: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, resp.StatusCode
		}
		var enrollResp api.EnrollResponse
		if err := proto.Unmarshal(body, &enrollResp); err != nil {
			t.Fatalf("unmarshal EnrollResponse: %v", err)
		}
		return &enrollResp, resp.StatusCode
	}

	t.Run("the role and label grants reach the signed token", func(t *testing.T) {
		enrollResp, status := enroll(t, map[string]string{"region": "emea"})
		if status != http.StatusOK {
			t.Fatalf("enrollment status %d, want %d", status, http.StatusOK)
		}

		cpPubKey := ed25519.PublicKey(enrollResp.ControlPlanePublicKey)

		if got := queryTokenFact(t, enrollResp.BiscuitToken, cpPubKey, api.FactRole); got != api.RoleNode {
			t.Errorf("%s in token = %q, want %q", api.FactRole, got, api.RoleNode)
		}

		// The permitted label is attested, which is what peers gate on.
		if got := queryTokenLabel(t, enrollResp.BiscuitToken, cpPubKey, "region"); got != "emea" {
			t.Errorf("label(region) in token = %q, want %q", got, "emea")
		}
	})

	t.Run("a label the role does not grant is refused", func(t *testing.T) {
		if _, status := enroll(t, map[string]string{"team": "platform"}); status != http.StatusForbidden {
			t.Errorf("enrollment status %d, want %d", status, http.StatusForbidden)
		}
	})
}

// queryTokenFact returns the single string argument of a one-term authority fact.
func queryTokenFact(t *testing.T, tokenBytes []byte, pub ed25519.PublicKey, factName string) string {
	t.Helper()
	authorizer := authorizeToken(t, tokenBytes, pub)

	rule, err := parser.FromStringRule(fmt.Sprintf(`q($v) <- %s($v)`, factName))
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	facts, err := authorizer.Query(rule)
	if err != nil {
		t.Fatalf("query %s: %v", factName, err)
	}
	if len(facts) == 0 {
		return ""
	}
	s, _ := facts[0].IDs[0].(biscuit.String)
	return string(s)
}

// queryTokenLabel returns the value of a label(key, value) authority fact.
func queryTokenLabel(t *testing.T, tokenBytes []byte, pub ed25519.PublicKey, key string) string {
	t.Helper()
	authorizer := authorizeToken(t, tokenBytes, pub)

	rule, err := parser.FromStringRule(fmt.Sprintf(`q($v) <- %s(%q, $v)`, api.FactLabel, key))
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	facts, err := authorizer.Query(rule)
	if err != nil {
		t.Fatalf("query label: %v", err)
	}
	if len(facts) == 0 {
		return ""
	}
	s, _ := facts[0].IDs[0].(biscuit.String)
	return string(s)
}

func authorizeToken(t *testing.T, tokenBytes []byte, pub ed25519.PublicKey) biscuit.Authorizer {
	t.Helper()
	b, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		t.Fatalf("unmarshal biscuit: %v", err)
	}
	authorizer, err := b.Authorizer(pub, identity.AuthorizerOptions(5*time.Second)...)
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	// The world is only populated once the authorizer runs.
	authorizer.AddPolicy(biscuit.DefaultAllowPolicy)
	if err := authorizer.Authorize(); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return authorizer
}
