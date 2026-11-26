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
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestLoadNodeConfigTaskScopeAttenuation(t *testing.T) {
	cfg, err := CompleteNodeConfig(api.NodeConfig{
		Version: api.NodeConfigVersionV1Alpha1,
		Attenuation: api.Attenuation{
			Policies: []string{
				`deny if claim("workload.env", "sandbox");`,
				`deny if claim("device.type", "unmanaged_mobile");`,
			},
			Checks: []string{
				`check if claim("device.trust_tier", "high"), claim("device.type", "managed_workstation") or claim("device.trust_tier", "high"), claim("device.type", "managed_mobile"), claim("device.management", "fully_managed");`,
			},
			RequireTaskScope: true,
			MaxTaskTTL:       "15m",
		},
	})
	if err != nil {
		t.Fatalf("CompleteNodeConfig: %v", err)
	}
	if len(cfg.Policies) != 2 || len(cfg.Checks) != 1 {
		t.Fatalf("got %d policies and %d checks, want 2 and 1", len(cfg.Policies), len(cfg.Checks))
	}
	if !cfg.RequireTaskScope || cfg.MaxTaskTTL != 15*time.Minute {
		t.Fatalf("RequireTaskScope=%v MaxTaskTTL=%v, want true / 15m", cfg.RequireTaskScope, cfg.MaxTaskTTL)
	}

	// max_task_ttl alone implies require_task_scope.
	implied, err := CompleteNodeConfig(api.NodeConfig{
		Version:     api.NodeConfigVersionV1Alpha1,
		Attenuation: api.Attenuation{MaxTaskTTL: "10m"},
	})
	if err != nil || !implied.RequireTaskScope || implied.MaxTaskTTL != 10*time.Minute {
		t.Fatalf("max_task_ttl implied require_task_scope = (%v, %v, %v)", implied, implied != nil && implied.RequireTaskScope, err)
	}

	for i, bad := range []api.NodeConfig{
		{Version: api.NodeConfigVersionV1Alpha1, Attenuation: api.Attenuation{MaxTaskTTL: "not-a-duration"}},
		{Version: api.NodeConfigVersionV1Alpha1, Attenuation: api.Attenuation{MaxTaskTTL: "-5m"}},
		{Version: api.NodeConfigVersionV1Alpha1, Attenuation: api.Attenuation{MaxTaskTTL: "0s"}},
	} {
		if _, err := CompleteNodeConfig(bad); err == nil {
			t.Errorf("bad[%d] expected error, got nil", i)
		}
	}
}

func TestWorkstationPEPPostureIsolationTaskScopeAndProvenance(t *testing.T) {
	h := newSTSNodeHarness(t)

	// Standard Biscuit Datalog checks/policies over first-class claim(k, v) facts
	// combined with require_task_scope and max_task_ttl.
	wsCfg, err := CompleteNodeConfig(api.NodeConfig{
		Version: api.NodeConfigVersionV1Alpha1,
		Attenuation: api.Attenuation{
			Policies: []string{
				`deny if claim("workload.env", "sandbox");`,
				`deny if claim("device.type", "unmanaged_mobile");`,
				`deny if claim("device.management", "work_profile");`,
			},
			Checks: []string{
				`check if claim("device.trust_tier", "high"), claim("device.type", "managed_workstation") or claim("device.trust_tier", "high"), claim("device.type", "managed_mobile"), claim("device.management", "fully_managed");`,
			},
			RequireTaskScope: true,
			MaxTaskTTL:       "15m",
		},
	})
	if err != nil {
		t.Fatalf("CompleteNodeConfig: %v", err)
	}
	h.node.nodeConfig = wsCfg

	broadRoles := []*api.PolicyRole{
		{
			Name:            "workstation-caller",
			AllowedServices: []string{"a2a://dev-agent", "mcp://github"},
			AllowedTargets:  []string{"*"},
		},
	}

	mintDelegated := func(email string, attestedClaims map[string][]string, tar *api.TaskAuthorizationRule, biscuitTTL time.Duration) []byte {
		t.Helper()
		raw, err := identity.MintDelegatedBiscuitTokenWithClaims(
			h.cpPriv,
			jwt.MapClaims{"sub": email, "email": email},
			h.peerID,
			time.Now().Add(biscuitTTL),
			[]string{"workstation-caller"},
			broadRoles,
			attestedClaims,
			tar,
			true,
		)
		if err != nil {
			t.Fatalf("MintDelegatedBiscuitTokenWithClaims: %v", err)
		}
		return raw
	}

	shortTAR := &api.TaskAuthorizationRule{
		Name:       "pr-review-task",
		ExpireTime: timestamppb.New(time.Now().Add(10 * time.Minute)),
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"mcp://github"},
				Operation:       &api.TaskOperation{AllowedTools: []string{"get_pr"}},
			},
			{
				AllowedServices: []string{"a2a://dev-agent"},
				Operation:       &api.TaskOperation{AllowedMethods: []string{"POST"}, AllowedPaths: []string{"/tasks"}},
			},
		},
	}
	longTAR := &api.TaskAuthorizationRule{
		Name:       "too-long-task",
		ExpireTime: timestamppb.New(time.Now().Add(2 * time.Hour)),
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"mcp://github"},
				Operation:       &api.TaskOperation{AllowedTools: []string{"get_pr"}},
			},
		},
	}

	cases := []struct {
		name       string
		biscuit    []byte
		wantStatus int
		wantClaims string
	}{
		{
			name: "Fully managed mobile high trust with 10m sealed TAR allowed",
			biscuit: mintDelegated("alice@corp.example", map[string][]string{
				"device.trust_tier": {"high"},
				"device.type":       {"managed_mobile"},
				"device.management": {"fully_managed"},
				"amr":               {"hwk", "mfa"},
			}, shortTAR, time.Hour),
			wantStatus: http.StatusOK,
			wantClaims: "amr=hwk,amr=mfa,device.management=fully_managed,device.trust_tier=high,device.type=managed_mobile",
		},
		{
			name: "Managed workstation high trust with 10m sealed TAR allowed",
			biscuit: mintDelegated("alice@corp.example", map[string][]string{
				"device.trust_tier": {"high"},
				"device.type":       {"managed_workstation"},
			}, shortTAR, time.Hour),
			wantStatus: http.StatusOK,
			wantClaims: "device.trust_tier=high,device.type=managed_workstation",
		},
		{
			name: "Standing credential without TAR denied by require_task_scope",
			biscuit: mintDelegated("alice@corp.example", map[string][]string{
				"device.trust_tier": {"high"},
				"device.type":       {"managed_workstation"},
			}, nil, 10*time.Minute),
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Managed workstation with 2h TAR denied by max_task_ttl",
			biscuit: mintDelegated("alice@corp.example", map[string][]string{
				"device.trust_tier": {"high"},
				"device.type":       {"managed_workstation"},
			}, longTAR, 3*time.Hour),
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Unmanaged mobile denied",
			biscuit: mintDelegated("alice@corp.example", map[string][]string{
				"device.trust_tier": {"high"},
				"device.type":       {"unmanaged_mobile"},
			}, shortTAR, time.Hour),
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Work profile mobile denied",
			biscuit: mintDelegated("alice@corp.example", map[string][]string{
				"device.trust_tier": {"high"},
				"device.type":       {"managed_mobile"},
				"device.management": {"work_profile"},
			}, shortTAR, time.Hour),
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Sandbox denied by deny policy even if posture claims are also present",
			biscuit: mintDelegated("bot-alice@bots.workloads.corp.example", map[string][]string{
				"workload.env":      {"sandbox"},
				"device.trust_tier": {"high"},
				"device.type":       {"managed_workstation"},
			}, shortTAR, time.Hour),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Missing posture claims denied fail-closed",
			biscuit:    mintDelegated("alice@corp.example", nil, shortTAR, time.Hour),
			wantStatus: http.StatusForbidden,
		},
	}

	// The tool of an MCP call is in the request body.
	const getPRCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pr"}}`

	for _, tc := range cases {
		t.Run("ext_authz/"+tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/ext_authz/mcp/github", strings.NewReader(getPRCall))
			req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(tc.biscuit))
			rec := httptest.NewRecorder()
			handleExtAuthzHTTP(h.node, rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				if got := rec.Header().Get(api.HeaderMeshClaims); got != tc.wantClaims {
					t.Errorf("X-Mesh-Claims = %q, want %q", got, tc.wantClaims)
				}
				if got := rec.Header().Get(api.HeaderMeshOrigin); got != api.MeshOriginGateway {
					t.Errorf("X-Mesh-Origin = %q, want %q", got, api.MeshOriginGateway)
				}
				if got := rec.Header().Get(api.HeaderMeshActorNode); got != h.peerID.String() {
					t.Errorf("X-Mesh-Actor-Node = %q, want %q", got, h.peerID.String())
				}
				if got := rec.Header().Get(api.HeaderMeshTaskID); got != "pr-review-task" {
					t.Errorf("X-Mesh-Task-Id = %q, want pr-review-task", got)
				}
			}
		})
	}

	// Verify gRPC ext_authz also enforces posture + strips spoofed headers.
	managedMobileBiscuit := mintDelegated("alice@corp.example", map[string][]string{
		"device.trust_tier": {"high"},
		"device.type":       {"managed_mobile"},
		"device.management": {"fully_managed"},
	}, shortTAR, time.Hour)
	grpcResp, err := newNodeEnvoyGateway(h.node).Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST",
					Path:   "/mcp/github",
					Body:   getPRCall,
					Headers: map[string]string{
						"authorization":  "Bearer " + base64.StdEncoding.EncodeToString(managedMobileBiscuit),
						"x-mesh-spoofed": "attacker",
						"x-mesh-claims":  "forged=true",
						"x-peer-id":      "forged-peer",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("gRPC Check: %v", err)
	}
	if grpcResp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("gRPC Check status = %v, want OK", grpcResp.GetStatus())
	}
	removed := grpcResp.GetOkResponse().GetHeadersToRemove()
	if !strings.Contains(strings.Join(removed, ","), "x-mesh-spoofed") || !strings.Contains(strings.Join(removed, ","), "x-peer-id") {
		t.Fatalf("expected spoofed headers in HeadersToRemove, got %v", removed)
	}

	// Verify external ingress enforces local Datalog claim() checks + require_task_scope + identity allow list.
	evalParams, err := h.node.buildExternalIngressEvalParams("a2a", "dev-agent", http.MethodPost, "/tasks", []string{"email:alice@corp.example"})
	if err != nil {
		t.Fatalf("buildExternalIngressEvalParams: %v", err)
	}

	verifiedMobile, err := h.node.VerifyLocalBiscuit(managedMobileBiscuit)
	if err != nil {
		t.Fatalf("VerifyLocalBiscuit(mobile): %v", err)
	}
	callerRes, err := identity.AuthorizeIngressDelegatedBiscuit(verifiedMobile, evalParams)
	if err != nil {
		t.Fatalf("AuthorizeIngressDelegatedBiscuit(managed mobile) failed: %v", err)
	}
	if api.FormatClaims(callerRes.Claims) != "device.management=fully_managed,device.trust_tier=high,device.type=managed_mobile" {
		t.Fatalf("unexpected ingress caller claims: %v", callerRes.Claims)
	}

	// Standing delegated token without TAR must fail on external ingress when require_task_scope=true.
	standingMobile := mintDelegated("alice@corp.example", map[string][]string{
		"device.trust_tier": {"high"},
		"device.type":       {"managed_mobile"},
		"device.management": {"fully_managed"},
	}, nil, 10*time.Minute)
	verifiedStanding, err := h.node.VerifyLocalBiscuit(standingMobile)
	if err != nil {
		t.Fatalf("VerifyLocalBiscuit(standing): %v", err)
	}
	if _, err := identity.AuthorizeIngressDelegatedBiscuit(verifiedStanding, evalParams); err == nil {
		t.Fatal("expected standing delegated token without TAR to be rejected on external ingress")
	}

	// Verify EgressService with forward_context=true forwards attested X-Mesh-Claims
	// and X-Mesh-Actor-Node while stripping caller-spoofed headers.
	var egressCaptured http.Header
	egressUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		egressCaptured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer egressUpstream.Close()

	egressSvc, err := newEgressServiceForNode(h.node, &api.EgressDestination{
		Name:           "api.approved.example",
		TargetUrl:      egressUpstream.URL,
		ForwardContext: true,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("newEgressServiceForNode: %v", err)
	}
	if err := egressSvc.Init(context.Background()); err != nil {
		t.Fatalf("egressSvc.Init: %v", err)
	}
	t.Cleanup(func() { _ = egressSvc.Teardown() })

	egressReq := httptest.NewRequest(http.MethodGet, "/v1/files", nil)
	egressReq = egressReq.WithContext(WithCallerBiscuit(egressReq.Context(), managedMobileBiscuit))
	egressReq.Header.Set(api.HeaderMeshClaims, "device.trust_tier=spoofed")
	egressReq.Header.Set(api.HeaderMeshActorNode, "forged-node")
	egressRec := httptest.NewRecorder()
	egressSvc.Handler().ServeHTTP(egressRec, egressReq)
	if egressRec.Code != http.StatusOK {
		t.Fatalf("egress forward_context status = %d, want 200", egressRec.Code)
	}
	if want := "device.management=fully_managed,device.trust_tier=high,device.type=managed_mobile"; egressCaptured.Get(api.HeaderMeshClaims) != want {
		t.Errorf("egress upstream X-Mesh-Claims = %q, want %q", egressCaptured.Get(api.HeaderMeshClaims), want)
	}
	if got := egressCaptured.Get(api.HeaderMeshActorNode); got != h.peerID.String() {
		t.Errorf("egress upstream X-Mesh-Actor-Node = %q, want %q", got, h.peerID.String())
	}
}
