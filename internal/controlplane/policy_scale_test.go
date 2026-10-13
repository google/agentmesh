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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestPolicyScale is not a benchmark: it exercises the admin policy pipeline
// (config validation, role resolution, biscuit minting and authorization) at
// increasing numbers of roles/bindings and logs sizes and timings, so we have
// a record of where the current implementation starts to strain.
//
// validatePolicyConfig now rejects configs whose worst-case fact budget
// (summed across all roles, see maxIdentityFactBudget) approaches biscuit-go's
// default 1000-fact authorizer world limit, so scaling further is expected to
// be caught there rather than at mint/authorize time. Hitting either limit is
// an expected, informative outcome of pushing the scale further rather than a
// bug: once reached, the test logs it and stops escalating instead of failing.
// Any other error (validation, role resolution, or minting) still fails the
// test. Probe further with e.g.:
//
//	AGENTMESH_POLICY_SCALE_MAX=5000 go test ./internal/controlplane -run TestPolicyScale -v
func TestPolicyScale(t *testing.T) {
	tiers := []int{10, 100, 500}
	if extra := os.Getenv("AGENTMESH_POLICY_SCALE_MAX"); extra != "" {
		n, err := strconv.Atoi(extra)
		if err != nil {
			t.Fatalf("invalid AGENTMESH_POLICY_SCALE_MAX=%q: %v", extra, err)
		}
		tiers = append(tiers, n)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nodeKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range tiers {
		roles := make([]*api.PolicyRole, 0, n)
		bindings := make([]*api.PolicyBinding, 0, n)
		roleNames := make([]string, 0, n)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("role-%d", i)
			roleNames = append(roleNames, name)
			roles = append(roles, &api.PolicyRole{
				Name: name,
				AllowedServices: []string{
					fmt.Sprintf("mcp://svc-%d-a.example", i),
					fmt.Sprintf("mcp://svc-%d-b.example", i),
				},
				AllowedTargets: []string{
					fmt.Sprintf("group:team-%d", i),
				},
			})
			bindings = append(bindings, &api.PolicyBinding{
				Role:    name,
				Members: []string{"node:" + nodePeer.String()},
			})
		}
		req := &api.PolicyConfig{Roles: roles, Bindings: bindings}

		start := time.Now()
		if err := validatePolicyConfig(req); err != nil {
			if !strings.Contains(err.Error(), "exceeding the safe budget") {
				t.Fatalf("validatePolicyConfig failed at n=%d for an unexpected reason: %v", n, err)
			}
			t.Logf("roles=%-6d validate: hit admin-time fact budget guard (%v) - stopping", n, err)
			break
		}
		validateDur := time.Since(start)

		claims := jwt.MapClaims{}
		start = time.Now()
		resolved := resolveRoles(nodePeer.String(), claims, bindings)
		resolveDur := time.Since(start)
		if len(resolved) != n {
			t.Fatalf("expected %d resolved roles, got %d", n, len(resolved))
		}

		start = time.Now()
		biscuitBytes, _, err := identity.MintBiscuitToken(priv, claims, nil, nodePeer, time.Now().Add(time.Hour), roleNames, roles, nil)
		mintDur := time.Since(start)
		if err != nil {
			t.Fatalf("mint failed at n=%d: %v", n, err)
		}

		start = time.Now()
		_, authErr := identity.VerifyBiscuit(biscuitBytes, nodePeer, []ed25519.PublicKey{pub}, 5*time.Second)
		authorizeDur := time.Since(start)

		if authErr != nil {
			if !strings.Contains(authErr.Error(), datalog.ErrWorldRunLimitMaxFacts.Error()) {
				t.Fatalf("authorize failed at n=%d for an unexpected reason: %v", n, authErr)
			}
			t.Logf("roles=%-6d validate=%-12s resolve=%-12s mint=%-12s biscuit_size=%-10dB authorize: hit current limit (%v) - stopping",
				n, validateDur, resolveDur, mintDur, len(biscuitBytes), authErr)
			break
		}

		total := validateDur + resolveDur + mintDur + authorizeDur
		t.Logf("roles=%-6d validate=%-12s resolve=%-12s mint=%-12s biscuit_size=%-10dB authorize=%-12s total=%s",
			n, validateDur, resolveDur, mintDur, len(biscuitBytes), authorizeDur, total)
	}
}

// TestPolicyScaleSetEncoding demonstrates that aggregating a role's exact
// AllowedServices/AllowedTargets grants into Set-valued Datalog facts (one
// fact per service type / target fact name, instead of one fact per entry)
// keeps minting and authorization working far beyond what previously was a
// hard ceiling for a single role granting many exact entries.
//
// Before the Set-based encoding, a single role with a few hundred exact
// service/target entries could, by itself, exhaust the biscuit-go
// authorizer's default 1000-fact world limit (see TestPolicyScale). With
// Set-based encoding the same role contributes a small, constant number of
// facts (one granted_service_set + one granted_target_set) regardless of how
// many exact entries it grants. Probe further with e.g.:
//
//	AGENTMESH_POLICY_SCALE_SET_MAX=20000 go test ./internal/controlplane -run TestPolicyScaleSetEncoding -v
func TestPolicyScaleSetEncoding(t *testing.T) {
	entryTiers := []int{10, 100, 2000}
	if extra := os.Getenv("AGENTMESH_POLICY_SCALE_SET_MAX"); extra != "" {
		n, err := strconv.Atoi(extra)
		if err != nil {
			t.Fatalf("invalid AGENTMESH_POLICY_SCALE_SET_MAX=%q: %v", extra, err)
		}
		entryTiers = append(entryTiers, n)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nodeKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range entryTiers {
		services := make([]string, 0, n)
		targets := make([]string, 0, n)
		for i := 0; i < n; i++ {
			services = append(services, fmt.Sprintf("mcp://svc-%d.example", i))
			targets = append(targets, fmt.Sprintf("group:team-%d", i))
		}
		roles := []*api.PolicyRole{{
			Name:            "bulk-role",
			AllowedServices: services,
			AllowedTargets:  targets,
		}}

		// A single role with many exact entries should stay well under the
		// admin-time fact budget guard, since Set-based encoding collapses it
		// to a couple of facts regardless of entry count.
		bindings := []*api.PolicyBinding{{Role: "bulk-role", Members: []string{"node:" + nodePeer.String()}}}
		if err := validatePolicyConfig(&api.PolicyConfig{Roles: roles, Bindings: bindings}); err != nil {
			t.Fatalf("validatePolicyConfig unexpectedly rejected a single bulk role with n=%d exact entries: %v", n, err)
		}

		claims := jwt.MapClaims{}
		start := time.Now()
		biscuitBytes, _, err := identity.MintBiscuitToken(priv, claims, nil, nodePeer, time.Now().Add(time.Hour), []string{"bulk-role"}, roles, nil)
		mintDur := time.Since(start)
		if err != nil {
			t.Fatalf("mint failed at n=%d exact entries: %v", n, err)
		}

		start = time.Now()
		_, authErr := identity.VerifyBiscuit(biscuitBytes, nodePeer, []ed25519.PublicKey{pub}, 5*time.Second)
		authorizeDur := time.Since(start)
		if authErr != nil {
			t.Fatalf("authorize failed at n=%d exact entries granted by a single role (Set-based encoding should keep this well below the fact limit): %v", n, authErr)
		}

		t.Logf("exact_entries_per_role=%-6d mint=%-12s biscuit_size=%-10dB authorize=%-12s", n, mintDur, len(biscuitBytes), authorizeDur)
	}
}

// TestValidatePolicyConfigFactBudget verifies that validatePolicyConfig itself
// rejects configs whose worst-case per-identity fact budget would approach
// biscuit-go's default authorizer fact limit, instead of letting the problem
// surface later as an authorization failure for real users.
func TestValidatePolicyConfigFactBudget(t *testing.T) {
	newRoles := func(n int) ([]*api.PolicyRole, []*api.PolicyBinding) {
		roles := make([]*api.PolicyRole, 0, n)
		bindings := make([]*api.PolicyBinding, 0, n)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("role-%d", i)
			roles = append(roles, &api.PolicyRole{
				Name:            name,
				AllowedServices: []string{fmt.Sprintf("mcp://svc-%d.example", i)},
				AllowedTargets:  []string{fmt.Sprintf("group:team-%d", i)},
			})
			bindings = append(bindings, &api.PolicyBinding{
				Role:    name,
				Members: []string{"group:everyone"},
			})
		}
		return roles, bindings
	}

	t.Run("rejects a config that could push a single identity over the fact budget", func(t *testing.T) {
		roles, bindings := newRoles(500)
		err := validatePolicyConfig(&api.PolicyConfig{Roles: roles, Bindings: bindings})
		if err == nil {
			t.Fatal("expected validatePolicyConfig to reject an over-budget config, got nil error")
		}
		if !strings.Contains(err.Error(), "exceeding the safe budget") {
			t.Errorf("expected a fact budget error, got: %v", err)
		}
	})

	t.Run("accepts a config comfortably under the fact budget", func(t *testing.T) {
		roles, bindings := newRoles(50)
		if err := validatePolicyConfig(&api.PolicyConfig{Roles: roles, Bindings: bindings}); err != nil {
			t.Errorf("expected a small config to pass validation, got: %v", err)
		}
	})
}

// TestPolicyScaleManyRoles demonstrates that mintBiscuit now merges exact
// grants across ALL of an identity's matched roles (not just within a single
// role, see TestPolicyScaleSetEncoding) into one Set fact per service type /
// target fact name for the whole token, instead of one Set fact per role.
// That removes what used to be the dominant per-role cost (~2-3 facts/role),
// leaving only the one role(X) fact biscuit-go still has to add per matched
// role - a much cheaper, but still O(matched roles), residual cost. So the
// ceiling for "many roles matching one identity" grows roughly 3-4x (from
// ~300 to ~900 roles) rather than becoming flat; going meaningfully higher
// would require not embedding one role(X) fact per matched role at all.
//
// This deliberately bypasses validatePolicyConfig: that guard stays
// conservative (see maxIdentityFactBudget) because it must also bound
// internal/node/policy.go's mesh policy rules, which resolve roles
// dynamically from live claims at request time and so cannot pre-merge
// grants across roles the way mint time can. Probe further with e.g.:
//
//	AGENTMESH_POLICY_SCALE_ROLES_MAX=900 go test ./internal/controlplane -run TestPolicyScaleManyRoles -v
func TestPolicyScaleManyRoles(t *testing.T) {
	roleTiers := []int{10, 100, 800}
	if extra := os.Getenv("AGENTMESH_POLICY_SCALE_ROLES_MAX"); extra != "" {
		n, err := strconv.Atoi(extra)
		if err != nil {
			t.Fatalf("invalid AGENTMESH_POLICY_SCALE_ROLES_MAX=%q: %v", extra, err)
		}
		roleTiers = append(roleTiers, n)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	nodeKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	nodePeer, err := peer.IDFromPrivateKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range roleTiers {
		roles := make([]*api.PolicyRole, 0, n)
		roleNames := make([]string, 0, n)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("role-%d", i)
			roleNames = append(roleNames, name)
			roles = append(roles, &api.PolicyRole{
				Name: name,
				AllowedServices: []string{
					fmt.Sprintf("mcp://svc-%d-a.example", i),
					fmt.Sprintf("mcp://svc-%d-b.example", i),
				},
				AllowedTargets: []string{fmt.Sprintf("group:team-%d", i)},
			})
		}

		claims := jwt.MapClaims{}
		start := time.Now()
		biscuitBytes, _, err := identity.MintBiscuitToken(priv, claims, nil, nodePeer, time.Now().Add(time.Hour), roleNames, roles, nil)
		mintDur := time.Since(start)
		if err != nil {
			t.Fatalf("mint failed at n=%d matched roles: %v", n, err)
		}

		start = time.Now()
		_, authErr := identity.VerifyBiscuit(biscuitBytes, nodePeer, []ed25519.PublicKey{pub}, 5*time.Second)
		authorizeDur := time.Since(start)
		if authErr != nil {
			t.Fatalf("authorize failed at n=%d matched roles (cross-role Set merging should keep this well below the fact limit): %v", n, authErr)
		}

		t.Logf("matched_roles=%-6d mint=%-12s biscuit_size=%-10dB authorize=%-12s", n, mintDur, len(biscuitBytes), authorizeDur)
	}
}
