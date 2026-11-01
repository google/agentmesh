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

package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func testPeerID(t *testing.T) peer.ID {
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

func TestValidateServiceIngress(t *testing.T) {
	pid := testPeerID(t)
	cases := []struct {
		name    string
		svcType ServiceType
		ing     *ServiceIngress
		wantErr bool
	}{
		{
			name:    "nil ingress allowed on any type",
			svcType: ServiceType_SERVICE_TYPE_EGRESS,
			ing:     nil,
		},
		{
			name:    "default edge mode on a2a",
			svcType: ServiceType_SERVICE_TYPE_A2A,
			ing:     &ServiceIngress{},
		},
		{
			name:    "edge mode with email and domain wildcard allow",
			svcType: ServiceType_SERVICE_TYPE_MCP,
			ing: &ServiceIngress{
				AuthMode: IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
				Allow:    []string{"email:alice@example.com", "email:*@example.com", "node:" + pid.String()},
			},
		},
		{
			name:    "passthrough without allow",
			svcType: ServiceType_SERVICE_TYPE_A2A,
			ing:     &ServiceIngress{AuthMode: IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH},
		},
		{
			name:    "passthrough with allow rejected",
			svcType: ServiceType_SERVICE_TYPE_A2A,
			ing: &ServiceIngress{
				AuthMode: IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
				Allow:    []string{"email:alice@example.com"},
			},
			wantErr: true,
		},
		{
			name:    "egress rejected",
			svcType: ServiceType_SERVICE_TYPE_EGRESS,
			ing:     &ServiceIngress{},
			wantErr: true,
		},
		{
			name:    "invalid allow entry rejected",
			svcType: ServiceType_SERVICE_TYPE_INFERENCE,
			ing: &ServiceIngress{
				Allow: []string{"email:*"},
			},
			wantErr: true,
		},
		{
			name:    "invalid node peer id in allow rejected",
			svcType: ServiceType_SERVICE_TYPE_A2A,
			ing: &ServiceIngress{
				Allow: []string{"node:not-a-peer-id"},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateServiceIngress(tc.svcType, tc.ing)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateServiceIngress() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestServiceIngressFromConfig(t *testing.T) {
	got, err := ServiceIngressFromConfig(ServiceType_SERVICE_TYPE_A2A, nil)
	if err != nil || got != nil {
		t.Fatalf("nil config = (%v, %v), want (nil, nil)", got, err)
	}

	got, err = ServiceIngressFromConfig(ServiceType_SERVICE_TYPE_A2A, &IngressConfig{
		Allow: []string{"email:carol@example.com"},
	})
	if err != nil {
		t.Fatalf("ServiceIngressFromConfig default mode: %v", err)
	}
	if EffectiveIngressAuthMode(got) != IngressAuthMode_INGRESS_AUTH_MODE_EDGE {
		t.Fatalf("EffectiveIngressAuthMode = %v, want EDGE", EffectiveIngressAuthMode(got))
	}

	if _, err := ServiceIngressFromConfig(ServiceType_SERVICE_TYPE_A2A, &IngressConfig{AuthMode: "bogus"}); err == nil {
		t.Fatal("expected error for invalid auth_mode")
	}

	// A node: entry is stored in canonical form whatever the operator typed:
	// the CIDv1 spelling of a peer ID decodes to the same ID as its base58
	// spelling, and the record carries the latter.
	id := testPeerID(t)
	cidForm := peer.ToCid(id).String()
	if cidForm == id.String() {
		t.Fatalf("test needs a non-canonical spelling; ToCid gave %q", cidForm)
	}
	got, err = ServiceIngressFromConfig(ServiceType_SERVICE_TYPE_A2A, &IngressConfig{
		Allow: []string{"node:" + cidForm, "email:alice@example.com"},
	})
	if err != nil {
		t.Fatalf("ServiceIngressFromConfig with CID peer ID: %v", err)
	}
	if want := []string{"node:" + id.String(), "email:alice@example.com"}; !slices.Equal(got.Allow, want) {
		t.Fatalf("Allow = %v, want canonical %v", got.Allow, want)
	}
}

func TestValidateIngressGrants(t *testing.T) {
	cases := []struct {
		name    string
		grants  []*IngressGrant
		wantErr bool
	}{
		{
			name: "empty modes defaults to edge",
			grants: []*IngressGrant{
				{Services: []string{"a2a://*", "mcp://calc"}},
			},
		},
		{
			name: "wildcard and explicit modes",
			grants: []*IngressGrant{
				{
					Services:         []string{"*"},
					AllowedAuthModes: []IngressAuthMode{IngressAuthMode_INGRESS_AUTH_MODE_EDGE, IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH},
				},
			},
		},
		{
			name: "empty services rejected",
			grants: []*IngressGrant{
				{},
			},
			wantErr: true,
		},
		{
			name: "egress service rejected",
			grants: []*IngressGrant{
				{Services: []string{"egress://api.github.com"}},
			},
			wantErr: true,
		},
		{
			name: "unspecified auth mode in list rejected",
			grants: []*IngressGrant{
				{
					Services:         []string{"a2a://*"},
					AllowedAuthModes: []IngressAuthMode{IngressAuthMode_INGRESS_AUTH_MODE_UNSPECIFIED},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIngressGrants(tc.grants, "test-role")
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateIngressGrants() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateIngressURL(t *testing.T) {
	got, err := ValidateIngressURL(" https://bananas.sam-mesh.dev/ingress/ ")
	if err != nil {
		t.Fatalf("ValidateIngressURL: %v", err)
	}
	if got != "https://bananas.sam-mesh.dev/ingress" {
		t.Fatalf("got %q, want %q", got, "https://bananas.sam-mesh.dev/ingress")
	}

	if got, err := ValidateIngressURL(""); err != nil || got != "" {
		t.Fatalf("empty URL = (%q, %v), want (\"\", nil)", got, err)
	}

	for _, bad := range []string{
		"ftp://example.com/ingress",
		"https:///ingress",
		"https://user:pass@example.com/ingress",
		"https://example.com/ingress?foo=bar",
		"https://example.com/ingress#frag",
	} {
		if _, err := ValidateIngressURL(bad); err == nil {
			t.Errorf("ValidateIngressURL(%q) succeeded, want error", bad)
		}
	}
}

func TestMatchIngressAllow(t *testing.T) {
	pid := testPeerID(t)
	claims := map[string][]string{
		FactEmail: {"carol@example.com"},
		FactGroup: {"a2a-team"},
		FactNode:  {pid.String()},
	}

	if !MatchIngressAllow(nil, nil) {
		t.Fatal("empty allow must return true")
	}
	if MatchIngressAllow([]string{SystemAuthenticated}, nil) {
		t.Fatal("non-empty allow with empty claims must return false")
	}
	if !MatchIngressAllow([]string{SystemAuthenticated}, claims) {
		t.Fatal("SystemAuthenticated must match non-empty identity claims")
	}
	if !MatchIngressAllow([]string{"email:*@example.com"}, claims) {
		t.Fatal("wildcard domain should match carol@example.com")
	}
	if !MatchIngressAllow([]string{"node:" + pid.String()}, claims) {
		t.Fatal("exact node peer ID should match")
	}
	if MatchIngressAllow([]string{"email:other@example.com", "group:ops"}, claims) {
		t.Fatal("non-matching allow entries must return false")
	}
}

func TestIngressDatalogPolicyEvaluation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	roles := []*PolicyRole{
		{
			Name: "laptop-agent",
			AllowedIngress: []*IngressGrant{
				{
					// Empty AllowedAuthModes -> grants EDGE only.
					Services: []string{"a2a://*", "mcp://calc", "mcp://notes"},
				},
				{
					Services:         []string{"a2a://paired.*"},
					AllowedAuthModes: []IngressAuthMode{IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH},
				},
			},
		},
	}
	bindings := []*PolicyBinding{
		{Role: "laptop-agent", Members: []string{"email:dev@example.com"}},
	}

	compiled, warnings := BuildPolicyRules(roles, bindings)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	parsedRules, err := ParseDatalogRules(PolicyRuleTexts(compiled))
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}

	builder := biscuit.NewBuilder(priv)
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: FactEmail,
		IDs:  []biscuit.Term{biscuit.String("dev@example.com")},
	}}); err != nil {
		t.Fatalf("AddAuthorityFact: %v", err)
	}
	tok, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	check := func(svcType, svcName, mode string) bool {
		auth, err := tok.Authorizer(pub)
		if err != nil {
			t.Fatalf("Authorizer: %v", err)
		}
		auth.AddFact(IngressFact(svcType, svcName, mode))
		for _, r := range parsedRules {
			auth.AddRule(r)
		}
		for _, p := range IngressPolicies {
			auth.AddPolicy(p)
		}
		return auth.Authorize() == nil
	}

	if !check("a2a", "assistant", IngressAuthModeStringEdge) {
		t.Error("expected a2a://assistant edge to be allowed")
	}
	if check("a2a", "assistant", IngressAuthModeStringPassthrough) {
		t.Error("expected a2a://assistant passthrough to be denied without explicit grant")
	}
	if !check("a2a", "paired.coder", IngressAuthModeStringPassthrough) {
		t.Error("expected a2a://paired.coder passthrough to be allowed")
	}
	if !check("mcp", "calc", IngressAuthModeStringEdge) {
		t.Error("expected mcp://calc set grant edge to be allowed")
	}
	if check("inference", "vllm", IngressAuthModeStringEdge) {
		t.Error("expected ungranted inference://vllm edge to be denied")
	}
}
