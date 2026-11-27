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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/node"
	"github.com/google/agentmesh/internal/standalone"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestDevicePostureAndWorkloadIsolationCUJ validates end-to-end policy-driven
// OIDC claim attestation (claim(k, v) facts, including "iss"), structured
// PolicyBinding.claims, workload isolation, mandatory task scoping, and
// tamper-proof gateway provenance across standalone agentmesh-one and an
// agentmesh-node PEP:
//  1. Zero CLI claim flags: PolicyBinding.claims and PolicyConfig.attested_claims
//     drive automatic extraction of verified JWT claims into Block 0 claim(k, v).
//  2. Issuer scoping ("iss" in PolicyBinding.claims) blocks a second trusted
//     issuer from asserting corporate device posture.
//  3. Node Datalog attenuation (claim() checks + deny policies) combined with
//     require_task_scope and max_task_ttl enforces posture and sandbox isolation
//     across both Envoy gRPC ext_authz and external router ingress.
//  4. Spoofed X-Mesh-* / X-Peer-Id headers are stripped and verified provenance
//     headers (X-Mesh-Principal, X-Mesh-Claims, X-Mesh-Actor-Node,
//     X-Mesh-Origin, X-Mesh-Task-Id / X-Mesh-Task) are stamped.
func TestDevicePostureAndWorkloadIsolationCUJ(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	corpIssuer, mintCorpOIDC := startCustomMockOIDC(t)
	partnerIssuer, mintPartnerOIDC := startCustomMockOIDC(t)
	tmpDir := t.TempDir()

	var capturedHeaders atomic.Value
	workstationBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders.Store(r.Header.Clone())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer workstationBackend.Close()

	policyCfg := &api.PolicyConfig{
		Roles: []*api.PolicyRole{
			{
				Name:            api.RoleRouter,
				AllowedTargets:  []string{"*"},
				AllowedServices: []string{"*"},
			},
			{
				Name:          api.RoleNode,
				AllowedLabels: []string{"region=*"},
			},
			{
				Name:           "workstation-host",
				AllowedPublish: []string{"a2a://dev-agent"},
				AllowedIngress: []*api.IngressGrant{
					{
						Services:         []string{"a2a://dev-agent"},
						AllowedAuthModes: []api.IngressAuthMode{api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE},
					},
				},
			},
			{
				Name:            "workstation-remote-caller",
				AllowedServices: []string{"a2a://dev-agent"},
				AllowedTargets:  []string{"*"},
			},
			{
				Name:            "sandbox-workload",
				AllowedServices: []string{"egress://api.approved.example"},
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
				Role:    "workstation-host",
				Members: []string{"email:*@corp.example"},
				Claims: map[string]string{
					"iss":               corpIssuer,
					"device.trust_tier": "high",
					"device.type":       "managed_workstation",
					"workload.env":      "workstation",
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
		AttestedClaims: []string{"amr"},
	}
	policyBytes, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(policyCfg)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	policyPath := filepath.Join(tmpDir, "policy.json")
	if err := os.WriteFile(policyPath, policyBytes, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	srv, err := standalone.New(standalone.Options{
		BindAddress:      "127.0.0.1:0",
		DataDir:          filepath.Join(tmpDir, "one"),
		DisableJoinToken: true,
		PolicyFile:       policyPath,
		OIDCIssuer:       corpIssuer + "," + partnerIssuer,
		AllowedAudiences: []string{api.DefaultAudience},
	})
	if err != nil {
		t.Fatalf("standalone.New: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("standalone.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cpURL := srv.PublicURL()

	// Build workstation attenuation using standard Biscuit Datalog over claim(k, v)
	// plus require_task_scope and max_task_ttl.
	nodeCfg, err := node.CompleteNodeConfig(api.NodeConfig{
		Version: api.NodeConfigVersionV1Alpha1,
		Attenuation: api.Attenuation{
			Policies: []string{
				`deny if claim("workload.env", "sandbox");`,
				`deny if claim("device.type", "unmanaged_mobile");`,
				`deny if claim("device.management", "work_profile");`,
			},
			Checks: []string{
				fmt.Sprintf(`check if claim("iss", %q), claim("device.trust_tier", "high"), claim("device.type", "managed_workstation") or claim("iss", %q), claim("device.trust_tier", "high"), claim("device.type", "managed_mobile"), claim("device.management", "fully_managed");`, corpIssuer, corpIssuer),
			},
			RequireTaskScope: true,
			MaxTaskTTL:       "15m",
		},
	})
	if err != nil {
		t.Fatalf("CompleteNodeConfig: %v", err)
	}

	workstationJWT := mintCorpOIDC(map[string]any{
		"sub":            "alice",
		"email":          "alice@corp.example",
		"email_verified": true,
		"amr":            []any{"hwk"},
		"device": map[string]any{
			"trust_tier": "high",
			"type":       "managed_workstation",
		},
		"workload": map[string]any{
			"env": "workstation",
		},
	})

	nodeStore, err := node.NewStore(filepath.Join(tmpDir, "workstation-node"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = nodeStore.Close() })

	priv := node.GetOrGenerateKey(nodeStore)
	enrollNode, err := node.NewAgentMeshNode(node.Options{
		PrivKey:       priv,
		Store:         nodeStore,
		ListenAddrs:   []string{"/ip4/127.0.0.1/tcp/0"},
		AllowLoopback: true,
		RequiredRole:  api.RoleNode,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode(enroll): %v", err)
	}
	enrollCtx, enrollCancel := context.WithCancel(ctx)
	if err := enrollNode.Start(enrollCtx); err != nil {
		enrollCancel()
		t.Fatalf("enrollNode.Start: %v", err)
	}
	if err := enrollNode.Enroll(enrollCtx, cpURL, workstationJWT); err != nil {
		_ = enrollNode.Teardown()
		enrollCancel()
		t.Fatalf("workstation Enroll: %v", err)
	}
	if err := nodeStore.SaveControlPlaneURL(cpURL); err != nil {
		t.Fatalf("SaveControlPlaneURL: %v", err)
	}
	_ = enrollNode.Teardown()
	enrollCancel()

	cpPub, storedAddrs, err := nodeStore.LoadMeshConfig()
	if err != nil {
		t.Fatalf("LoadMeshConfig: %v", err)
	}
	var rAddrs []multiaddr.Multiaddr
	for _, s := range storedAddrs {
		if ma, mErr := multiaddr.NewMultiaddr(s); mErr == nil {
			rAddrs = append(rAddrs, ma)
		}
	}

	workstationNode, err := node.NewAgentMeshNode(node.Options{
		PrivKey:                  priv,
		ControlPlanePubKey:       cpPub,
		RouterAddrs:              rAddrs,
		Store:                    nodeStore,
		NodeConfig:               nodeCfg,
		ListenAddrs:              []string{"/ip4/127.0.0.1/tcp/0"},
		AllowLoopback:            true,
		RequiredRole:             api.RoleNode,
		Reachability:             node.ReachabilityPrivate,
		DiscoveryInterval:        "100ms",
		AutoRelayBootDelay:       50 * time.Millisecond,
		AutoRelayMinInterval:     50 * time.Millisecond,
		AutoRelayBackoff:         50 * time.Millisecond,
		ControlPlaneSyncInterval: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgentMeshNode(runtime): %v", err)
	}
	if err := workstationNode.SyncControlPlane(ctx); err != nil {
		t.Fatalf("workstationNode.SyncControlPlane: %v", err)
	}
	if err := workstationNode.Start(ctx); err != nil {
		t.Fatalf("workstationNode.Start: %v", err)
	}
	t.Cleanup(func() { _ = workstationNode.Teardown() })

	if err := workstationNode.RegisterStaticServices(ctx, []api.ServiceConfig{
		{
			Type:        "a2a",
			Name:        "dev-agent",
			Description: "Loopback-only workstation agent service",
			TargetURL:   workstationBackend.URL,
			Ingress: &api.IngressConfig{
				AuthMode: api.IngressAuthModeStringEdge,
				Allow:    []string{"email:alice@corp.example"},
			},
		},
	}); err != nil {
		t.Fatalf("RegisterStaticServices: %v", err)
	}

	sidecarToken := "local-gateway-token"
	sidecarSrv, err := node.StartSidecarServer(workstationNode, "127.0.0.1:0", "", sidecarToken, "", "", "")
	if err != nil {
		t.Fatalf("StartSidecarServer: %v", err)
	}
	t.Cleanup(func() { _ = sidecarSrv.Close() })
	sidecarAddr := workstationNode.BoundHTTPAddr

	exchangeOAuth := func(subjectJWT string, tar *api.TaskAuthorizationRule) string {
		t.Helper()
		form := url.Values{}
		form.Set("grant_type", api.GrantTypeTokenExchange)
		form.Set("subject_token", subjectJWT)
		form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
		form.Set("seal", "true")
		if tar != nil {
			b, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(tar)
			if err != nil {
				t.Fatalf("marshal TAR: %v", err)
			}
			form.Set("options", string(b))
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+sidecarAddr+"/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(api.HeaderMeshAuthentication, "Bearer "+sidecarToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /oauth/token: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /oauth/token status=%d: %s", resp.StatusCode, string(body))
		}
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
			t.Fatalf("unexpected /oauth/token body: %s", string(body))
		}
		return out.AccessToken
	}

	shortTAR := &api.TaskAuthorizationRule{
		Name:       "workstation-status-task",
		ExpireTime: timestamppb.New(time.Now().Add(10 * time.Minute)),
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"a2a://dev-agent"},
				Operation: &api.TaskOperation{
					AllowedMethods: []string{"POST"},
					AllowedPaths:   []string{"/tasks/*"},
				},
			},
		},
	}

	managedMobileJWT := mintCorpOIDC(map[string]any{
		"sub":            "alice",
		"email":          "alice@corp.example",
		"email_verified": true,
		"amr":            []any{"hwk", "mfa"},
		"device": map[string]any{
			"trust_tier": "high",
			"type":       "managed_mobile",
			"management": "fully_managed",
		},
	})
	partnerManagedMobileJWT := mintPartnerOIDC(map[string]any{
		"sub":            "alice",
		"email":          "alice@corp.example",
		"email_verified": true,
		"device": map[string]any{
			"trust_tier": "high",
			"type":       "managed_mobile",
			"management": "fully_managed",
		},
	})
	workProfileJWT := mintCorpOIDC(map[string]any{
		"sub":            "alice",
		"email":          "alice@corp.example",
		"email_verified": true,
		"device": map[string]any{
			"trust_tier": "high",
			"type":       "managed_mobile",
			"management": "work_profile",
		},
	})
	sandboxJWT := mintCorpOIDC(map[string]any{
		"sub":            "bot-alice",
		"email":          "bot-alice@bots.workloads.corp.example",
		"email_verified": true,
		"workload": map[string]any{
			"env": "sandbox",
		},
	})

	managedMobileTaskBiscuit := exchangeOAuth(managedMobileJWT, shortTAR)
	managedMobileStandingBiscuit := exchangeOAuth(managedMobileJWT, nil)
	partnerMobileTaskBiscuit := exchangeOAuth(partnerManagedMobileJWT, shortTAR)
	workProfileTaskBiscuit := exchangeOAuth(workProfileJWT, shortTAR)
	sandboxTaskBiscuit := exchangeOAuth(sandboxJWT, shortTAR)

	conn, err := grpc.NewClient("passthrough:///"+sidecarAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	authClient := authv3.NewAuthorizationClient(conn)

	checkExtAuthz := func(biscuitB64 string, extra map[string]string) *authv3.CheckResponse {
		t.Helper()
		hdrs := map[string]string{
			"authorization": "Bearer " + biscuitB64,
		}
		for k, v := range extra {
			hdrs[k] = v
		}
		resp, err := authClient.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  "POST",
						Path:    "/a2a/dev-agent/tasks/run",
						Headers: hdrs,
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("ext_authz Check: %v", err)
		}
		return resp
	}

	wantClaims := fmt.Sprintf("amr=hwk,amr=mfa,device.management=fully_managed,device.trust_tier=high,device.type=managed_mobile,iss=%s", corpIssuer)

	// 1. Fully managed high-trust mobile from corpIssuer + 10m sealed TAR passes ext_authz and strips spoofed headers.
	okResp := checkExtAuthz(managedMobileTaskBiscuit, map[string]string{
		"x-mesh-spoofed": "forged",
		"x-peer-id":      "forged-peer",
	})
	if okResp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("managed mobile ext_authz = %v, want OK", okResp.GetStatus())
	}
	stamped := make(map[string]string)
	for _, h := range okResp.GetOkResponse().GetHeaders() {
		k := h.GetHeader().GetKey()
		if k != strings.ToLower(k) {
			t.Errorf("ext_authz emitted non-lowercase HTTP/2 header key %q", k)
		}
		stamped[k] = h.GetHeader().GetValue()
	}
	if stamped[strings.ToLower(api.HeaderMeshPrincipal)] != "alice@corp.example" {
		t.Errorf("X-Mesh-Principal = %q, want alice@corp.example", stamped[strings.ToLower(api.HeaderMeshPrincipal)])
	}
	if stamped[strings.ToLower(api.HeaderMeshOrigin)] != api.MeshOriginGateway {
		t.Errorf("X-Mesh-Origin = %q, want %q", stamped[strings.ToLower(api.HeaderMeshOrigin)], api.MeshOriginGateway)
	}
	if stamped[strings.ToLower(api.HeaderMeshClaims)] != wantClaims {
		t.Errorf("X-Mesh-Claims = %q, want %q", stamped[strings.ToLower(api.HeaderMeshClaims)], wantClaims)
	}
	if stamped[strings.ToLower(api.HeaderMeshTaskID)] != "workstation-status-task" {
		t.Errorf("X-Mesh-Task-Id = %q, want workstation-status-task", stamped[strings.ToLower(api.HeaderMeshTaskID)])
	}
	removed := strings.Join(okResp.GetOkResponse().GetHeadersToRemove(), ",")
	if !strings.Contains(removed, "x-mesh-spoofed") || !strings.Contains(removed, "x-peer-id") {
		t.Errorf("HeadersToRemove = %q, want x-mesh-spoofed and x-peer-id", removed)
	}

	// 2. Standing token (no TAR), wrong issuer (partnerIssuer), work-profile mobile, and sandbox workload must all be denied.
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"standing high-trust token without TAR", managedMobileStandingBiscuit},
		{"partner issuer asserting posture", partnerMobileTaskBiscuit},
		{"work-profile mobile device", workProfileTaskBiscuit},
		{"isolated sandbox workload", sandboxTaskBiscuit},
	} {
		denyResp := checkExtAuthz(tc.token, nil)
		if denyResp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
			t.Errorf("%s: ext_authz code = %v, want PermissionDenied", tc.name, denyResp.GetStatus())
		}
	}

	// 3. External router ingress (/ingress/<peer>/a2a/dev-agent/tasks/run) end-to-end.
	ingressURL := fmt.Sprintf("%s/ingress/%s/a2a/dev-agent/tasks/run", cpURL, workstationNode.Host.ID().String())
	deadline := time.Now().Add(8 * time.Second)
	var lastStatus int
	var lastBody string
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ingressURL, strings.NewReader(`{"prompt":"status"}`))
		req.Header.Set("Authorization", "Bearer "+managedMobileTaskBiscuit)
		req.Header.Set(api.HeaderMeshClaims, "device.trust_tier=spoofed")
		req.Header.Set(api.HeaderMeshOrigin, "spoofed")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			lastStatus = resp.StatusCode
			lastBody = string(b)
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastStatus != http.StatusOK {
		t.Fatalf("external ingress managed mobile status = %d (body: %q), want 200", lastStatus, lastBody)
	}
	gotHdrs, _ := capturedHeaders.Load().(http.Header)
	if gotHdrs == nil {
		t.Fatal("workstation backend did not capture headers")
	}
	if got := gotHdrs.Get(api.HeaderMeshOrigin); got != api.MeshOriginExternalIngress {
		t.Errorf("backend X-Mesh-Origin = %q, want %q", got, api.MeshOriginExternalIngress)
	}
	if got := gotHdrs.Get(api.HeaderMeshClaims); got != wantClaims {
		t.Errorf("backend X-Mesh-Claims = %q, want %q", got, wantClaims)
	}
	if got := gotHdrs.Get(api.HeaderMeshPrincipal); got != "alice@corp.example" {
		t.Errorf("backend X-Mesh-Principal = %q, want alice@corp.example", got)
	}
	if got := gotHdrs.Get(api.HeaderMeshTask); got != "workstation-status-task" {
		t.Errorf("backend X-Mesh-Task = %q, want workstation-status-task", got)
	}

	// Verify wrong issuer, sandbox, work-profile, and standing tokens are refused at router external ingress too.
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"partner issuer via ingress", partnerMobileTaskBiscuit},
		{"work-profile mobile via ingress", workProfileTaskBiscuit},
		{"sandbox workload via ingress", sandboxTaskBiscuit},
		{"standing high-trust without TAR via ingress", managedMobileStandingBiscuit},
	} {
		if _, err := base64.StdEncoding.DecodeString(tc.token); err != nil {
			t.Fatalf("%s: invalid base64 biscuit: %v", tc.name, err)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ingressURL, strings.NewReader(`{"prompt":"hi"}`))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s request failed: %v", tc.name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403 Forbidden", tc.name, resp.StatusCode)
		}
	}
}
