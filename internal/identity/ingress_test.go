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

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func testGenPeerID(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	return id
}

func TestRequireIngress(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	providerPeer := testGenPeerID(t)
	roles := []*api.PolicyRole{
		{
			Name:           "agent-host",
			AllowedPublish: []string{"a2a://*"},
			AllowedIngress: []*api.IngressGrant{
				{Services: []string{"a2a://assistant"}},
				{
					Services:         []string{"a2a://paired"},
					AllowedAuthModes: []api.IngressAuthMode{api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH},
				},
			},
		},
	}

	raw, err := MintBootstrapBiscuitToken(priv, providerPeer, "agent-host", time.Now().Add(time.Hour), roles, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}
	b, key, err := VerifyBiscuitAndGetKey(raw, providerPeer, []ed25519.PublicKey{pub}, time.Second)
	if err != nil {
		t.Fatalf("VerifyBiscuitAndGetKey: %v", err)
	}

	if err := RequireIngress(b, key, "a2a", "assistant", api.IngressAuthModeStringEdge, nil, time.Second); err != nil {
		t.Fatalf("expected a2a://assistant edge to be allowed: %v", err)
	}
	if err := RequireIngress(b, key, "a2a", "assistant", api.IngressAuthModeStringPassthrough, nil, time.Second); err == nil {
		t.Fatal("expected a2a://assistant passthrough to be denied")
	}
	if err := RequireIngress(b, key, "a2a", "paired", api.IngressAuthModeStringPassthrough, nil, time.Second); err != nil {
		t.Fatalf("expected a2a://paired passthrough to be allowed: %v", err)
	}

	// Verify Delegated Session Biscuits NEVER receive allowed_ingress facts.
	delRaw, err := MintDelegatedBiscuitToken(priv, jwt.MapClaims{"email": "alice@example.com"}, providerPeer, time.Now().Add(time.Hour), []string{"agent-host"}, roles, nil, false)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken: %v", err)
	}
	delB, _, err := UnmarshalInbound(delRaw)
	if err != nil {
		t.Fatalf("UnmarshalInbound: %v", err)
	}
	if err := RequireIngress(delB, pub, "a2a", "assistant", api.IngressAuthModeStringEdge, nil, time.Second); err == nil {
		t.Fatal("delegated session token must never grant ingress publishing")
	}
}

func TestAuthorizeIngressCallers(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	actorPeer := testGenPeerID(t)
	providerPeer := testGenPeerID(t)

	roles := []*api.PolicyRole{
		{
			Name:            "caller-role",
			AllowedServices: []string{"a2a://assistant", "mcp://calc"},
			AllowedTargets:  []string{"node:" + providerPeer.String()},
		},
	}
	bindings := []*api.PolicyBinding{
		{Role: "caller-role", Members: []string{"email:*@google.com"}},
	}
	compiled, warnings := api.BuildPolicyRules(roles, bindings)
	if len(warnings) != 0 {
		t.Fatalf("BuildPolicyRules warnings: %v", warnings)
	}
	meshRules, err := api.ParseDatalogRules(api.PolicyRuleTexts(compiled))
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}

	provRaw, err := MintBootstrapBiscuitToken(priv, providerPeer, "agent-host", time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}
	provB, err := biscuit.Unmarshal(provRaw)
	if err != nil {
		t.Fatalf("Unmarshal provider biscuit: %v", err)
	}
	targetFacts, err := TargetFactsFromBiscuit(provB, []ed25519.PublicKey{pub}, time.Second)
	if err != nil {
		t.Fatalf("TargetFactsFromBiscuit: %v", err)
	}

	// 1. Unattenuated transport member Biscuit MUST be rejected as an HTTP edge Bearer token.
	memberRaw, err := MintBootstrapBiscuitToken(priv, actorPeer, "caller-role", time.Now().Add(time.Hour), roles, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}
	memberClaims, err := InspectVerifiedBiscuit(memberRaw, []ed25519.PublicKey{pub}, time.Second)
	if err != nil {
		t.Fatalf("InspectVerifiedBiscuit: %v", err)
	}
	if _, err := AuthorizeIngressDelegatedBiscuit(memberClaims, IngressEvalParams{
		ServiceType:     "a2a",
		ServiceName:     "assistant",
		Method:          "POST",
		Path:            "/message:send",
		TargetFacts:     targetFacts,
		MeshPolicyRules: meshRules,
		Timeout:         time.Second,
	}); err == nil {
		t.Fatal("expected unattenuated member transport biscuit to be rejected at HTTP edge")
	}

	// 1b. Task-attenuated member Biscuit (minted via RFC 8693 /oauth/token on a node)
	// IS accepted for its narrowed service and rejected outside its TAR scope.
	attMemberRaw, err := AttenuateBiscuit(memberRaw, &api.TaskAuthorizationRule{
		Name: "node-task-a2a",
		Rules: []*api.TaskRule{
			{AllowedServices: []string{"a2a://assistant"}},
		},
	})
	if err != nil {
		t.Fatalf("AttenuateBiscuit: %v", err)
	}
	attMemberClaims, err := InspectVerifiedBiscuit(attMemberRaw, []ed25519.PublicKey{pub}, time.Second)
	if err != nil {
		t.Fatalf("InspectVerifiedBiscuit attenuated member: %v", err)
	}
	attRes, err := AuthorizeIngressDelegatedBiscuit(attMemberClaims, IngressEvalParams{
		ServiceType:     "a2a",
		ServiceName:     "assistant",
		Method:          "POST",
		Path:            "/message:send",
		TargetFacts:     targetFacts,
		MeshPolicyRules: meshRules,
		Timeout:         time.Second,
	})
	if err != nil {
		t.Fatalf("expected task-attenuated member biscuit to be accepted: %v", err)
	}
	if attRes.ActorNodeID != actorPeer.String() || attRes.TaskName != "node-task-a2a" {
		t.Fatalf("unexpected task-attenuated result: %+v", attRes)
	}
	if _, err := AuthorizeIngressDelegatedBiscuit(attMemberClaims, IngressEvalParams{
		ServiceType:        "mcp",
		ServiceName:        "calc",
		Method:             "POST",
		Path:               "/",
		AllowMCPStreamInit: true,
		TargetFacts:        targetFacts,
		MeshPolicyRules:    meshRules,
		Timeout:            time.Second,
	}); err == nil {
		t.Fatal("expected out-of-scope mcp://calc to be rejected for task-attenuated member biscuit")
	}

	// 2. Delegated Session Biscuit with TAR attenuation and allow list.
	tarRule := &api.TaskAuthorizationRule{
		Name: "assist-only",
		Rules: []*api.TaskRule{
			{AllowedServices: []string{"a2a://assistant"}},
		},
	}
	delRaw, err := MintDelegatedBiscuitToken(priv, jwt.MapClaims{
		"sub":   "uid-1",
		"email": "yaroslav@google.com",
	}, actorPeer, time.Now().Add(time.Hour), []string{"caller-role"}, roles, tarRule, true)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(delRaw)
	decoded, err := DecodeBase64Biscuit(b64)
	if err != nil {
		t.Fatalf("DecodeBase64Biscuit: %v", err)
	}
	delClaims, err := InspectVerifiedBiscuit(decoded, []ed25519.PublicKey{pub}, time.Second)
	if err != nil {
		t.Fatalf("InspectVerifiedBiscuit: %v", err)
	}

	res, err := AuthorizeIngressDelegatedBiscuit(delClaims, IngressEvalParams{
		ServiceType:     "a2a",
		ServiceName:     "assistant",
		Method:          "POST",
		Path:            "/message:send",
		TargetFacts:     targetFacts,
		MeshPolicyRules: meshRules,
		Allow:           []string{"email:yaroslav@google.com"},
		Timeout:         time.Second,
	})
	if err != nil {
		t.Fatalf("AuthorizeIngressDelegatedBiscuit: %v", err)
	}
	if res.Principal != "yaroslav@google.com" || res.TaskName != "assist-only" {
		t.Fatalf("got principal=%q task=%q, want yaroslav@google.com / assist-only", res.Principal, res.TaskName)
	}

	// TAR blocks mcp://calc even though role grants it.
	if _, err := AuthorizeIngressDelegatedBiscuit(delClaims, IngressEvalParams{
		ServiceType:     "mcp",
		ServiceName:     "calc",
		Method:          "POST",
		Path:            "/mcp",
		TargetFacts:     targetFacts,
		MeshPolicyRules: meshRules,
		Timeout:         time.Second,
	}); err == nil {
		t.Fatal("expected TAR to deny mcp://calc")
	}

	// Allow list blocks non-matching email.
	if _, err := AuthorizeIngressDelegatedBiscuit(delClaims, IngressEvalParams{
		ServiceType:     "a2a",
		ServiceName:     "assistant",
		Method:          "POST",
		Path:            "/message:send",
		TargetFacts:     targetFacts,
		MeshPolicyRules: meshRules,
		Allow:           []string{"email:someone-else@google.com"},
		Timeout:         time.Second,
	}); err == nil {
		t.Fatal("expected allow list mismatch to deny")
	}

	// 3. Router Biscuits (even if attenuated with a TAR block) MUST be rejected as HTTP edge bearer tokens.
	routerRaw, err := MintBootstrapBiscuitToken(priv, actorPeer, api.RoleRouter, time.Now().Add(time.Hour), []*api.PolicyRole{
		{Name: api.RoleRouter, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}},
	}, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken(router): %v", err)
	}
	attRouterRaw, err := AttenuateBiscuit(routerRaw, tarRule)
	if err != nil {
		t.Fatalf("AttenuateBiscuit(router): %v", err)
	}
	routerClaims, err := InspectVerifiedBiscuit(attRouterRaw, []ed25519.PublicKey{pub}, time.Second)
	if err != nil {
		t.Fatalf("InspectVerifiedBiscuit(router): %v", err)
	}
	if _, err := ValidateIngressCallerPreDial(routerClaims, IngressEvalParams{
		ServiceType: "a2a",
		ServiceName: "assistant",
		Method:      "POST",
		Path:        "/message:send",
	}); err == nil {
		t.Fatal("expected router biscuit to be rejected at HTTP edge")
	}
}

func TestConcurrentSharedBiscuitAuthorizerNoRace(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	providerPID := testGenPeerID(t)
	roles := []*api.PolicyRole{
		{
			Name:            api.RoleNode,
			AllowedTargets:  []string{"*"},
			AllowedServices: []string{"*"},
			AllowedPublish:  []string{"*"},
			AllowedIngress: []*api.IngressGrant{
				{
					Services: []string{"*"},
					AllowedAuthModes: []api.IngressAuthMode{
						api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
					},
				},
			},
		},
	}
	raw, _, err := MintBiscuitToken(priv, jwt.MapClaims{"sub": "node-1"}, nil, providerPID, time.Now().Add(time.Hour), []string{api.RoleNode}, roles, map[string]string{"env": "prod"})
	if err != nil {
		t.Fatalf("MintBiscuitToken: %v", err)
	}
	sharedBiscuit, err := biscuit.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	meshRules, _ := api.BuildPolicyRules(roles, nil)
	var rules []biscuit.Rule
	for _, pr := range meshRules {
		rules = append(rules, pr.Rule)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := RequirePublish(sharedBiscuit, pub, "a2a", "coder", rules, time.Second); err != nil {
					t.Errorf("RequirePublish: %v", err)
					return
				}
				if err := RequireIngress(sharedBiscuit, pub, "a2a", "coder", "edge", rules, time.Second); err != nil {
					t.Errorf("RequireIngress: %v", err)
					return
				}
				if err := RequireRole(sharedBiscuit, pub, api.RoleNode, time.Second); err != nil {
					t.Errorf("RequireRole: %v", err)
					return
				}
				if _, err := TargetFactsFromBiscuit(sharedBiscuit, []ed25519.PublicKey{pub}, time.Second); err != nil {
					t.Errorf("TargetFactsFromBiscuit: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
