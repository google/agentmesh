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
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

// meshAuthzFixture is one mesh for the authorizer tests: a control plane key,
// a provider whose credential carries a target fact, a policy that grants
// callers bound by email, and the rules the control plane would render.
type meshAuthzFixture struct {
	pub          ed25519.PublicKey
	priv         ed25519.PrivateKey
	providerPeer peer.ID
	otherPeer    peer.ID
	targetFacts  []biscuit.Fact
	meshRules    []biscuit.Rule
}

func newMeshAuthzFixture(t *testing.T) *meshAuthzFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	f := &meshAuthzFixture{pub: pub, priv: priv, providerPeer: testGenPeerID(t), otherPeer: testGenPeerID(t)}

	roles := []*api.PolicyRole{
		{
			Name:            "caller",
			AllowedServices: []string{"a2a://assistant", "mcp://calc"},
			AllowedTargets:  []string{"node:" + f.providerPeer.String()},
			Http:            []*api.HTTPGrant{{Service: "a2a://assistant", Methods: []string{"POST"}, Paths: []string{"/invoke"}}},
		},
		{
			Name:            "anywhere",
			AllowedServices: []string{"a2a://assistant"},
			AllowedTargets:  []string{"*"},
		},
	}
	bindings := []*api.PolicyBinding{
		{Role: "caller", Members: []string{"email:alice@example.com"}},
		{Role: "anywhere", Members: []string{"email:bob@example.com"}},
	}
	compiled, warnings := api.BuildPolicyRules(roles, bindings)
	if len(warnings) != 0 {
		t.Fatalf("BuildPolicyRules warnings: %v", warnings)
	}
	f.meshRules, err = api.ParseDatalogRules(api.PolicyRuleTexts(compiled))
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}

	provRaw, err := MintBootstrapBiscuitToken(priv, f.providerPeer, "agent-host", time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken: %v", err)
	}
	provB, err := biscuit.Unmarshal(provRaw)
	if err != nil {
		t.Fatalf("Unmarshal provider biscuit: %v", err)
	}
	f.targetFacts, err = TargetFactsFromBiscuit(provB, []ed25519.PublicKey{pub}, time.Second)
	if err != nil {
		t.Fatalf("TargetFactsFromBiscuit: %v", err)
	}
	return f
}

// delegated mints a Delegated Session Biscuit for email, bound to actor, and
// returns an authorizer on it under the fixture's key.
func (f *meshAuthzFixture) delegated(t *testing.T, email string, actor peer.ID) biscuit.Authorizer {
	t.Helper()
	raw, err := MintDelegatedBiscuitToken(f.priv, jwt.MapClaims{"email": email}, actor, time.Now().Add(time.Hour), nil, nil, nil, false)
	if err != nil {
		t.Fatalf("MintDelegatedBiscuitToken: %v", err)
	}
	b, _, err := UnmarshalInbound(raw)
	if err != nil {
		t.Fatalf("UnmarshalInbound: %v", err)
	}
	a, err := b.Authorizer(f.pub, AuthorizerOptions(time.Second)...)
	if err != nil {
		t.Fatalf("Authorizer: %v", err)
	}
	return a
}

func (f *meshAuthzFixture) policy() MeshPolicy {
	return MeshPolicy{TargetFacts: f.targetFacts, MeshRules: f.meshRules}
}

// The one assembly behind every enforcement point: which facts and checks a
// request contributes is decided by MeshRequest alone, and each absent field
// fails closed rather than open.
func TestAuthorizeMeshRequest(t *testing.T) {
	f := newMeshAuthzFixture(t)
	invoke := MeshRequest{ServiceType: "a2a", ServiceName: "assistant", HasHTTP: true, Method: "POST", Path: "/invoke"}

	tests := []struct {
		name    string
		email   string
		actor   peer.ID
		req     MeshRequest
		pol     MeshPolicy
		wantErr bool
	}{
		{
			name:  "granted service, matching target, HTTP grant satisfied",
			email: "alice@example.com", actor: f.otherPeer, req: invoke, pol: f.policy(),
		},
		{
			name:  "service outside the grant is denied",
			email: "alice@example.com", actor: f.otherPeer,
			req: MeshRequest{ServiceType: "a2a", ServiceName: "other", HasHTTP: true, Method: "POST", Path: "/invoke"}, pol: f.policy(),
			wantErr: true,
		},
		{
			name:  "HTTP-narrowed grant has nothing to match on a bare stream and fails closed",
			email: "alice@example.com", actor: f.otherPeer,
			req: MeshRequest{ServiceType: "a2a", ServiceName: "assistant"}, pol: f.policy(),
			wantErr: true,
		},
		{
			name:  "HTTP-narrowed grant denies another method",
			email: "alice@example.com", actor: f.otherPeer,
			req: MeshRequest{ServiceType: "a2a", ServiceName: "assistant", HasHTTP: true, Method: "DELETE", Path: "/invoke"}, pol: f.policy(),
			wantErr: true,
		},
		{
			name:  "target check is always on: a provider without target facts admits no node-scoped grant",
			email: "alice@example.com", actor: f.otherPeer, req: invoke, pol: MeshPolicy{MeshRules: f.meshRules},
			wantErr: true,
		},
		{
			name:  "target check is always on: an unrestricted grant still passes without target facts",
			email: "bob@example.com", actor: f.otherPeer,
			req: MeshRequest{ServiceType: "a2a", ServiceName: "assistant"}, pol: MeshPolicy{MeshRules: f.meshRules},
		},
		{
			name:  "Unrestricted request admits a node-scoped grant without provider facts",
			email: "alice@example.com", actor: f.otherPeer,
			req: MeshRequest{ServiceType: "a2a", ServiceName: "assistant", HasHTTP: true, Method: "POST", Path: "/invoke", Unrestricted: true},
			pol: MeshPolicy{MeshRules: f.meshRules},
		},
		{
			name:  "connection peer matching client_peer_id passes the replay check",
			email: "alice@example.com", actor: f.otherPeer,
			req: MeshRequest{ServiceType: "a2a", ServiceName: "assistant", HasHTTP: true, Method: "POST", Path: "/invoke", ConnectionPeer: f.otherPeer},
			pol: f.policy(),
		},
		{
			name:  "connection peer other than client_peer_id is a replay and is denied",
			email: "alice@example.com", actor: f.otherPeer,
			req:     MeshRequest{ServiceType: "a2a", ServiceName: "assistant", HasHTTP: true, Method: "POST", Path: "/invoke", ConnectionPeer: f.providerPeer},
			pol:     f.policy(),
			wantErr: true,
		},
		{
			name:  "no connection peer adds no replay check: a border bearer is evaluated on policy alone",
			email: "alice@example.com", actor: f.providerPeer, req: invoke, pol: f.policy(),
		},
		{
			name:  "local deny policy of the enforcement point applies",
			email: "alice@example.com", actor: f.otherPeer, req: invoke,
			pol:     MeshPolicy{TargetFacts: f.targetFacts, MeshRules: f.meshRules, LocalPolicies: []biscuit.Policy{mustPolicy(t, `deny if path("/invoke")`)}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AuthorizeMeshRequest(f.delegated(t, tt.email, tt.actor), tt.req, tt.pol)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AuthorizeMeshRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// The ingress evaluator is the shared assembly and nothing more: for the same
// credential, service and policy it reaches the decision AuthorizeMeshRequest
// reaches for a border bearer. A difference here is a rule one path has and
// the other lacks.
func TestIngressEvalParamsMatchMeshRequest(t *testing.T) {
	f := newMeshAuthzFixture(t)

	cases := []struct {
		name   string
		email  string
		params IngressEvalParams
	}{
		{"granted POST", "alice@example.com", IngressEvalParams{ServiceType: "a2a", ServiceName: "assistant", Method: "POST", Path: "/invoke", TargetFacts: f.targetFacts, MeshPolicyRules: f.meshRules}},
		{"method outside the HTTP grant", "alice@example.com", IngressEvalParams{ServiceType: "a2a", ServiceName: "assistant", Method: "GET", Path: "/invoke", TargetFacts: f.targetFacts, MeshPolicyRules: f.meshRules}},
		{"service outside the grant", "alice@example.com", IngressEvalParams{ServiceType: "mcp", ServiceName: "other", Method: "POST", Path: "/", TargetFacts: f.targetFacts, MeshPolicyRules: f.meshRules}},
		{"no provider target facts", "alice@example.com", IngressEvalParams{ServiceType: "a2a", ServiceName: "assistant", Method: "POST", Path: "/invoke", MeshPolicyRules: f.meshRules}},
		{"unrestricted grant without target facts", "bob@example.com", IngressEvalParams{ServiceType: "a2a", ServiceName: "assistant", Method: "POST", Path: "/", MeshPolicyRules: f.meshRules}},
		{"local deny", "alice@example.com", IngressEvalParams{ServiceType: "a2a", ServiceName: "assistant", Method: "POST", Path: "/invoke", TargetFacts: f.targetFacts, MeshPolicyRules: f.meshRules, LocalPolicies: []biscuit.Policy{mustPolicy(t, `deny if path("/invoke")`)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, viaIngress := runIngressAuthorizer(f.delegated(t, tc.email, f.otherPeer), tc.params)
			viaMesh := AuthorizeMeshRequest(f.delegated(t, tc.email, f.otherPeer), tc.params.meshRequest(), tc.params.meshPolicy())
			if (viaIngress == nil) != (viaMesh == nil) {
				t.Fatalf("ingress evaluator and mesh authorizer disagree: ingress err = %v, mesh err = %v", viaIngress, viaMesh)
			}
			if tr := tc.params.meshRequest().TaskRequest(); tr.ServiceType != tc.params.ServiceType || tr.ServiceName != tc.params.ServiceName || !tr.HasHTTP || tr.Method != tc.params.Method || tr.Path != tc.params.Path {
				t.Fatalf("TaskRequest() = %+v does not describe %+v", tr, tc.params)
			}
		})
	}
}

func mustPolicy(t *testing.T, src string) biscuit.Policy {
	t.Helper()
	pol, err := parser.FromStringPolicy(src)
	if err != nil {
		t.Fatalf("parse policy %q: %v", src, err)
	}
	return pol
}
