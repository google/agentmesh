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

package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestPolicyClaimsIssuerScopingLimitsAndSTSPropagation(t *testing.T) {
	corpIssuer, mintCorpOIDC := startCustomMockOIDC(t)
	partnerIssuer, mintPartnerOIDC := startCustomMockOIDC(t)

	store, err := storage.NewSQLStore("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	opts := Options{
		ListenAddr:            "127.0.0.1:0",
		DriverName:            "sqlite",
		DataSourceName:        ":memory:",
		OIDCIssuer:            corpIssuer + "," + partnerIssuer,
		WorkloadIssuer:        corpIssuer + "=.workloads.corp.example",
		AllowedAudiences:      []string{api.DefaultAudience},
		AdminToken:            "test-admin-token",
		AutoApproveEnrollment: true,
		BiscuitTimeout:        5 * time.Second,
	}
	srv, err := NewServer(opts, store)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = srv.Close() }()
	baseURL := "http://" + srv.Addr()

	postPolicy := func(cfg *api.PolicyConfig) (int, string) {
		t.Helper()
		b, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal PolicyConfig: %v", err)
		}
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/policies", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer test-admin-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /policies: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	// 1. Policy exceeding api.MaxAttestedClaims must be rejected with 400.
	tooManyClaims := make([]string, api.MaxAttestedClaims+1)
	for i := range tooManyClaims {
		tooManyClaims[i] = fmt.Sprintf("claim_%02d", i)
	}
	code, body := postPolicy(&api.PolicyConfig{
		Roles:          []*api.PolicyRole{{Name: api.RoleNode}},
		Bindings:       []*api.PolicyBinding{{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}}},
		AttestedClaims: tooManyClaims,
	})
	if code != http.StatusBadRequest || !strings.Contains(body, "maximum is") {
		t.Fatalf("over-limit attested_claims: status=%d body=%q, want 400 cap error", code, body)
	}

	// 2. Post policy using structured PolicyBinding.claims (including "iss") + attested_claims.
	policyCfg := &api.PolicyConfig{
		Roles: []*api.PolicyRole{
			{
				Name:          api.RoleNode,
				AllowedLabels: []string{"*"}, // Wide label grant proves label() can never spoof claim().
			},
			{
				Name:            "workstation-remote-caller",
				AllowedServices: []string{"a2a://dev-agent"},
				AllowedTargets:  []string{"*"},
			},
			{
				Name:            "sandbox-workload",
				AllowedServices: []string{"egress://bigquery.googleapis.com"},
				AllowedTargets:  []string{"*"},
			},
		},
		Bindings: []*api.PolicyBinding{
			{
				Role:    api.RoleNode,
				Members: []string{"email:*@corp.example"},
				Claims: map[string]string{
					"iss":               corpIssuer,
					"device.trust_tier": "high",
					"device.type":       "managed_workstation",
				},
			},
			{
				Role:    api.RoleNode,
				Members: []string{"email:*@corp.example"},
				Claims: map[string]string{
					"iss":               corpIssuer,
					"device.trust_tier": "high",
					"device.type":       "managed_mobile",
					"device.management": "fully_managed",
				},
			},
			{
				Role:    api.RoleNode,
				Members: []string{"email:*@bots.workloads.corp.example"},
				Claims: map[string]string{
					"iss":          corpIssuer,
					"workload.env": "sandbox",
				},
			},
			{
				Role:    "workstation-remote-caller",
				Members: []string{"email:*@corp.example"},
				Claims: map[string]string{
					"iss":               corpIssuer,
					"device.trust_tier": "high",
					"device.type":       "managed_workstation",
				},
			},
			{
				Role:    "workstation-remote-caller",
				Members: []string{"email:*@corp.example"},
				Claims: map[string]string{
					"iss":               corpIssuer,
					"device.trust_tier": "high",
					"device.type":       "managed_mobile",
					"device.management": "fully_managed",
				},
			},
			{
				Role:    "sandbox-workload",
				Members: []string{"email:*@bots.workloads.corp.example"},
				Claims: map[string]string{
					"iss":          corpIssuer,
					"workload.env": "sandbox",
				},
			},
		},
		Egress: []*api.EgressDestination{
			{
				Name:     "bigquery.googleapis.com",
				ServedBy: []string{"mesh:role:node"},
				Broker: &api.CredentialBroker{
					Kind: &api.CredentialBroker_OidcFederation{
						OidcFederation: &api.OIDCFederation{
							TokenEndpoint: "https://sts.googleapis.com/v1/token",
							Audience:      "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/mesh/providers/cp",
						},
					},
				},
			},
		},
		AttestedClaims: []string{"amr"},
	}
	if code, body := postPolicy(policyCfg); code != http.StatusOK {
		t.Fatalf("POST /policies status=%d: %s", code, body)
	}

	// Verify GET /admin/policy round-trips attested_claims and distinct bindings cleanly.
	getReq, _ := http.NewRequest(http.MethodGet, baseURL+"/admin/policy", nil)
	getReq.Header.Set("Authorization", "Bearer test-admin-token")
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("GET /admin/policy: %v", err)
	}
	getBytes, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	var loaded api.PolicyConfig
	if err := protojson.Unmarshal(getBytes, &loaded); err != nil {
		t.Fatalf("unmarshal GET /admin/policy: %v", err)
	}
	if !reflect.DeepEqual(loaded.AttestedClaims, []string{"amr"}) {
		t.Fatalf("GET /admin/policy attested_claims = %v, want [amr]", loaded.AttestedClaims)
	}
	if len(loaded.Bindings) != len(policyCfg.Bindings) {
		t.Fatalf("GET /admin/policy bindings len = %d, want %d", len(loaded.Bindings), len(policyCfg.Bindings))
	}

	registerNode := func(jwtStr string, declaredLabels map[string]string) (int, []byte, crypto.PrivKey, peer.ID) {
		t.Helper()
		priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		pid, err := peer.IDFromPublicKey(pub)
		if err != nil {
			t.Fatalf("peer id: %v", err)
		}
		pubBytes, _ := crypto.MarshalPublicKey(pub)
		ts := time.Now().UnixMilli()
		sig, err := priv.Sign(api.RegisterChallenge(pid.String(), ts))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		reqBytes, _ := proto.Marshal(&api.EnrollRequest{
			Jwt:                jwtStr,
			PeerId:             pid.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleNode,
			Labels:             declaredLabels,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		})
		resp, err := http.Post(baseURL+"/register", "application/x-protobuf", bytes.NewReader(reqBytes))
		if err != nil {
			t.Fatalf("POST /register: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, priv, pid
	}

	// 3. Cross-issuer protection: partnerIssuer asserting identical device claims is denied because "iss" does not match corpIssuer.
	partnerJWT := mintPartnerOIDC(map[string]any{
		"sub":            "alice",
		"email":          "alice@corp.example",
		"email_verified": true,
		"device": map[string]any{
			"trust_tier": "high",
			"type":       "managed_workstation",
		},
	})
	if code, _, _, _ := registerNode(partnerJWT, nil); code != http.StatusForbidden {
		t.Fatalf("partner issuer /register status = %d, want 403 (iss mismatch)", code)
	}

	// 4. Unmanaged device declaring spoofed node labels STILL cannot satisfy PolicyBinding.claims (claim() != label()).
	unmanagedJWT := mintCorpOIDC(map[string]any{
		"sub":            "alice",
		"email":          "alice@corp.example",
		"email_verified": true,
		"device": map[string]any{
			"trust_tier": "basic",
			"type":       "unmanaged_mobile",
		},
	})
	if code, _, _, _ := registerNode(unmanagedJWT, map[string]string{"device.trust_tier": "high", "device.type": "managed_workstation"}); code != http.StatusForbidden {
		t.Fatalf("unmanaged device with spoofed labels /register status = %d, want 403", code)
	}

	// 5. Corp managed workstation succeeds, minting both node labels and claim(k, v) facts (including multi-valued amr and iss).
	workstationJWT := mintCorpOIDC(map[string]any{
		"sub":            "alice",
		"email":          "alice@corp.example",
		"email_verified": true,
		"amr":            []any{"hwk", "mfa"},
		"tenant":         "eng",
		"device": map[string]any{
			"trust_tier": "high",
			"type":       "managed_workstation",
		},
	})
	code, respBytes, wsPriv, wsPeerID := registerNode(workstationJWT, map[string]string{"region": "us-west1"})
	if code != http.StatusOK {
		t.Fatalf("workstation /register status = %d: %s", code, string(respBytes))
	}
	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(respBytes, &enrollResp); err != nil {
		t.Fatalf("unmarshal EnrollResponse: %v", err)
	}
	cpPub := ed25519.PublicKey(enrollResp.ControlPlanePublicKey)
	wsClaims, err := identity.InspectVerifiedBiscuit(enrollResp.BiscuitToken, []ed25519.PublicKey{cpPub}, 5*time.Second)
	if err != nil {
		t.Fatalf("InspectVerifiedBiscuit(workstation): %v", err)
	}
	if wsClaims.Labels["region"] != "us-west1" {
		t.Errorf("workstation labels = %v, want region=us-west1", wsClaims.Labels)
	}
	if !reflect.DeepEqual(wsClaims.Claims["iss"], []string{corpIssuer}) {
		t.Errorf("workstation claim[iss] = %v, want [%s]", wsClaims.Claims["iss"], corpIssuer)
	}
	if !reflect.DeepEqual(wsClaims.Claims["amr"], []string{"hwk", "mfa"}) {
		t.Errorf("workstation claim[amr] = %v, want [hwk mfa]", wsClaims.Claims["amr"])
	}
	if !reflect.DeepEqual(wsClaims.Claims["device.trust_tier"], []string{"high"}) {
		t.Errorf("workstation claim[device.trust_tier] = %v, want [high]", wsClaims.Claims["device.trust_tier"])
	}
	if !slices.Contains(wsClaims.Roles, "workstation-remote-caller") {
		t.Fatalf("workstation roles = %v, want workstation-remote-caller", wsClaims.Roles)
	}

	// 6. Dynamic policy update: adding "tenant" to attested_claims takes effect on /refresh from stored ClaimsJSON without re-enrolling.
	policyCfg.AttestedClaims = []string{"amr", "tenant"}
	if code, body := postPolicy(policyCfg); code != http.StatusOK {
		t.Fatalf("POST /policies (add tenant) status=%d: %s", code, body)
	}
	dynTS := time.Now().UnixMilli()
	dynSig, _ := wsPriv.Sign(api.RefreshChallenge(wsPeerID.String(), dynTS))
	dynBytes, _ := proto.Marshal(&api.TokenRefreshRequest{
		ChallengeUnixMs:    dynTS,
		ChallengeSignature: dynSig,
	})
	dynReq, _ := http.NewRequest(http.MethodPost, baseURL+"/refresh", bytes.NewReader(dynBytes))
	dynReq.Header.Set("Content-Type", "application/x-protobuf")
	dynReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(enrollResp.BiscuitToken))
	dynResp, err := http.DefaultClient.Do(dynReq)
	if err != nil {
		t.Fatalf("POST /refresh (dynamic attested_claims): %v", err)
	}
	dynBody, _ := io.ReadAll(dynResp.Body)
	_ = dynResp.Body.Close()
	if dynResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /refresh (dynamic attested_claims) status=%d: %s", dynResp.StatusCode, string(dynBody))
	}
	var dynRefreshOut api.TokenRefreshResponse
	if err := proto.Unmarshal(dynBody, &dynRefreshOut); err != nil {
		t.Fatalf("unmarshal TokenRefreshResponse: %v", err)
	}
	refreshedClaims, err := identity.InspectVerifiedBiscuit(dynRefreshOut.BiscuitToken, []ed25519.PublicKey{cpPub}, 5*time.Second)
	if err != nil {
		t.Fatalf("InspectVerifiedBiscuit(refreshed): %v", err)
	}
	if !reflect.DeepEqual(refreshedClaims.Claims["tenant"], []string{"eng"}) {
		t.Fatalf("refreshed claim[tenant] = %v, want [eng]", refreshedClaims.Claims["tenant"])
	}
	// Update enrollResp.BiscuitToken to the active refreshed credential (previous credential is superseded).
	enrollResp.BiscuitToken = dynRefreshOut.BiscuitToken

	// 6b. Posture downgrade on /refresh with fresh JWT refuses seat immediately.
	downgradedJWT := mintCorpOIDC(map[string]any{
		"sub":            "alice",
		"email":          "alice@corp.example",
		"email_verified": true,
		"device": map[string]any{
			"trust_tier": "basic",
			"type":       "managed_workstation",
		},
	})
	refreshTS := time.Now().UnixMilli()
	refreshSig, _ := wsPriv.Sign(api.RefreshChallenge(wsPeerID.String(), refreshTS))
	refreshBytes, _ := proto.Marshal(&api.TokenRefreshRequest{
		ChallengeUnixMs:    refreshTS,
		ChallengeSignature: refreshSig,
		Jwt:                downgradedJWT,
	})
	refreshReq, _ := http.NewRequest(http.MethodPost, baseURL+"/refresh", bytes.NewReader(refreshBytes))
	refreshReq.Header.Set("Content-Type", "application/x-protobuf")
	refreshReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(enrollResp.BiscuitToken))
	refreshResp, err := http.DefaultClient.Do(refreshReq)
	if err != nil {
		t.Fatalf("POST /refresh: %v", err)
	}
	_ = refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusForbidden {
		t.Fatalf("downgraded posture /refresh status = %d, want 403", refreshResp.StatusCode)
	}

	// 7. Token exchange (/token/exchange) stamps claim(k, v) onto Delegated Session Biscuits,
	// and /sts/token propagates mesh_claims into the signed ES256 border JWT.
	exchange := func(subjectJWT string) *api.TokenExchangeResponse {
		t.Helper()
		ts := time.Now().UnixMilli()
		sig, _ := wsPriv.Sign(api.TokenExchangeChallenge(wsPeerID.String(), ts))
		exBytes, _ := proto.Marshal(&api.TokenExchangeRequest{
			SubjectToken:       subjectJWT,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/token/exchange", bytes.NewReader(exBytes))
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(enrollResp.BiscuitToken))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /token/exchange: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /token/exchange status=%d: %s", resp.StatusCode, string(b))
		}
		var out api.TokenExchangeResponse
		if err := proto.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal TokenExchangeResponse: %v", err)
		}
		return &out
	}

	sandboxJWT := mintCorpOIDC(map[string]any{
		"sub":            "bot-alice",
		"email":          "bot-alice@bots.workloads.corp.example",
		"email_verified": true,
		"amr":            []any{"workload_attestation"},
		"workload":       map[string]any{"env": "sandbox"},
	})
	sandboxEx := exchange(sandboxJWT)
	if !slices.Contains(sandboxEx.Roles, "sandbox-workload") || slices.Contains(sandboxEx.Roles, "workstation-remote-caller") {
		t.Fatalf("sandbox roles = %v, want sandbox-workload only", sandboxEx.Roles)
	}

	stsTS := time.Now().UnixMilli()
	stsSig, _ := wsPriv.Sign(api.STSTokenChallenge(wsPeerID.String(), stsTS))
	stsBytes, _ := proto.Marshal(&api.STSTokenRequest{
		Biscuit:            sandboxEx.BiscuitToken,
		Destination:        "bigquery.googleapis.com",
		ChallengeUnixMs:    stsTS,
		ChallengeSignature: stsSig,
	})
	stsReq, _ := http.NewRequest(http.MethodPost, baseURL+"/sts/token", bytes.NewReader(stsBytes))
	stsReq.Header.Set("Content-Type", "application/x-protobuf")
	stsReq.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(enrollResp.BiscuitToken))
	stsResp, err := http.DefaultClient.Do(stsReq)
	if err != nil {
		t.Fatalf("POST /sts/token: %v", err)
	}
	stsBody, _ := io.ReadAll(stsResp.Body)
	_ = stsResp.Body.Close()
	if stsResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /sts/token status=%d: %s", stsResp.StatusCode, string(stsBody))
	}
	var stsOut api.STSTokenResponse
	if err := proto.Unmarshal(stsBody, &stsOut); err != nil {
		t.Fatalf("unmarshal STSTokenResponse: %v", err)
	}
	parsedJWT, _, err := jwt.NewParser().ParseUnverified(stsOut.Jwt, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse STS JWT: %v", err)
	}
	stsClaims := parsedJWT.Claims.(jwt.MapClaims)
	meshClaims, ok := stsClaims["mesh_claims"].(map[string]any)
	if !ok || meshClaims["workload.env"] != "sandbox" || meshClaims["iss"] != corpIssuer {
		t.Fatalf("STS JWT mesh_claims = %#v, want workload.env=sandbox and iss=%s", stsClaims["mesh_claims"], corpIssuer)
	}
}
