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
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
)

// TestResolveRolesCoversEveryMappedClaim walks api.OIDCClaimToFact instead of a
// hardcoded list, so a claim added to the map is covered without anyone
// remembering to extend this test. resolveRoles used to read the four claims by
// name, so a new entry in the map reached the token but never resolved a
// binding, and the binding looked configured while granting nothing.
func TestResolveRolesCoversEveryMappedClaim(t *testing.T) {
	for claimKey, factName := range api.OIDCClaimToFact() {
		t.Run(claimKey, func(t *testing.T) {
			bindings := []*api.PolicyBinding{{
				Role:    "resolved",
				Members: []string{factName + ":wanted"},
			}}

			got := resolveRoles("peer-id", jwt.MapClaims{claimKey: "wanted"}, bindings)
			if len(got) != 1 || got[0] != "resolved" {
				t.Errorf("claim %q with member %s:wanted resolved %v, want [resolved]", claimKey, factName, got)
			}

			// The same binding must not resolve for a different claim value.
			if got := resolveRoles("peer-id", jwt.MapClaims{claimKey: "other"}, bindings); len(got) != 0 {
				t.Errorf("claim %q with a non-matching value resolved %v, want none", claimKey, got)
			}
		})
	}
}

// TestResolveRolesMatchesNodeOnThePeerID pins that node: is matched against the
// connecting peer and not against a claim, since it is the one member prefix
// that does not come from the token.
func TestResolveRolesMatchesNodeOnThePeerID(t *testing.T) {
	bindings := []*api.PolicyBinding{{
		Role:    "node-bound",
		Members: []string{api.FactNode + ":12D3KooWExamplePeer"},
	}}

	if got := resolveRoles("12D3KooWExamplePeer", jwt.MapClaims{}, bindings); len(got) != 1 || got[0] != "node-bound" {
		t.Errorf("matching peer resolved %v, want [node-bound]", got)
	}
	if got := resolveRoles("12D3KooWSomeoneElse", jwt.MapClaims{}, bindings); len(got) != 0 {
		t.Errorf("non-matching peer resolved %v, want none", got)
	}
}

func TestResolveRolesWildcardsAndValidation(t *testing.T) {
	bindings := []*api.PolicyBinding{
		{
			Role: "k8s-payments",
			Members: []string{
				"user:system:serviceaccount:payments:*",
				"user:spiffe://cluster.local/ns/payments/sa/*",
			},
		},
		{
			Role: "gcp-sa",
			Members: []string{
				"email:*@proj-123.iam.gserviceaccount.com",
			},
		},
	}

	if got := resolveRoles("peer-1", jwt.MapClaims{"sub": "system:serviceaccount:payments:worker-a"}, bindings); len(got) != 1 || got[0] != "k8s-payments" {
		t.Errorf("k8s SA prefix wildcard resolved %v, want [k8s-payments]", got)
	}
	if got := resolveRoles("peer-1", jwt.MapClaims{"sub": "spiffe://cluster.local/ns/payments/sa/worker-b"}, bindings); len(got) != 1 || got[0] != "k8s-payments" {
		t.Errorf("spiffe prefix wildcard resolved %v, want [k8s-payments]", got)
	}
	if got := resolveRoles("peer-1", jwt.MapClaims{"sub": "system:serviceaccount:other:worker-a"}, bindings); len(got) != 0 {
		t.Errorf("non-matching namespace resolved %v, want none", got)
	}
	if got := resolveRoles("peer-1", jwt.MapClaims{"email": "runner@proj-123.iam.gserviceaccount.com"}, bindings); len(got) != 1 || got[0] != "gcp-sa" {
		t.Errorf("email suffix wildcard resolved %v, want [gcp-sa]", got)
	}

	validCfg := &api.PolicyConfig{
		Roles: []*api.PolicyRole{
			{Name: "k8s-payments", AllowedServices: []string{"mcp://Echo"}},
			{Name: "gcp-sa", AllowedServices: []string{"mcp://Echo"}},
		},
		Bindings: bindings,
	}
	if err := ValidatePolicyConfig(validCfg); err != nil {
		t.Fatalf("ValidatePolicyConfig rejected valid wildcard bindings: %v", err)
	}

	invalidMembers := []string{
		"user:*",
		"email:*",
		"node:*",
		"node:12D3KooW*",
		"user:system:*:worker",
		`user:foo"); role("admin") <- true; //`,
	}
	for _, bad := range invalidMembers {
		cfg := &api.PolicyConfig{
			Roles:    []*api.PolicyRole{{Name: "r1", AllowedServices: []string{"mcp://Echo"}}},
			Bindings: []*api.PolicyBinding{{Role: "r1", Members: []string{bad}}},
		}
		if err := ValidatePolicyConfig(cfg); err == nil {
			t.Errorf("ValidatePolicyConfig accepted invalid member %q", bad)
		}
	}
}
