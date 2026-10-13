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
	reflect "reflect"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
)

// helper to generate keypair for tests
func makeKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return pub, priv
}

func TestBaselinePolicies(t *testing.T) {
	pub, priv := makeKeyPair(t)

	tests := []struct {
		name          string
		tokenFacts    []biscuit.Fact
		requestTarget string // e.g. "mcp://calculator/add"
		expectAllow   bool
	}{
		{
			name: "Exact match allowed",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calculator")}}},
			},
			requestTarget: "mcp://calculator",
			expectAllow:   true,
		},
		{
			name: "Exact match denied (mismatched service)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("database")}}},
			},
			requestTarget: "mcp://calculator",
			expectAllow:   false,
		},
		{
			name: "Prefix wildcard allowed (subdomain prefix match)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServicePrefix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calc.")}}},
			},
			requestTarget: "mcp://calc.service.internal",
			expectAllow:   true,
		},
		{
			name: "Prefix wildcard denied (mismatched prefix)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServicePrefix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calc.")}}},
			},
			requestTarget: "mcp://db.service.internal",
			expectAllow:   false,
		},
		{
			name: "Suffix wildcard allowed (domain suffix match)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceSuffix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String(".internal")}}},
			},
			requestTarget: "mcp://calc.service.internal",
			expectAllow:   true,
		},
		{
			name: "Suffix wildcard denied (mismatched suffix)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceSuffix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String(".internal")}}},
			},
			requestTarget: "mcp://calc.service.external",
			expectAllow:   false,
		},
		{
			name: "All services matching scheme allowed",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceAll, IDs: []biscuit.Term{biscuit.String("mcp")}}},
			},
			requestTarget: "mcp://any-random-service",
			expectAllow:   true,
		},
		{
			name: "All services matching scheme denied (mismatched scheme)",
			tokenFacts: []biscuit.Fact{
				{Predicate: biscuit.Predicate{Name: FactGrantedServiceAll, IDs: []biscuit.Term{biscuit.String("mcp")}}},
			},
			requestTarget: "inference://any-random-service",
			expectAllow:   false,
		},
		{
			name: "Global wildcard allows everything",
			tokenFacts: []biscuit.Fact{
				MarkerFact(FactGrantedServiceAllTypes),
			},
			requestTarget: "mcp://calculator",
			expectAllow:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			for _, fact := range tt.tokenFacts {
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatalf("failed to add authority fact: %v", err)
				}
			}

			tok, err := builder.Build()
			if err != nil {
				t.Fatalf("failed to build token: %v", err)
			}

			authorizer, err := tok.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(5*time.Second)))
			if err != nil {
				t.Fatalf("failed to create authorizer: %v", err)
			}

			// Parse target like middleware
			opType, opName := ParseServiceTarget(tt.requestTarget)
			authorizer.AddFact(biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: FactService,
					IDs:  []biscuit.Term{biscuit.String(opType), biscuit.String(opName)},
				},
			})

			// Add baseline policies
			for _, p := range BaselinePolicies {
				authorizer.AddPolicy(p)
			}

			err = authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

func TestBaselineReplayCheck(t *testing.T) {
	pub, priv := makeKeyPair(t)

	tests := []struct {
		name             string
		clientPeerID     string
		connectionPeerID string
		expectAllow      bool
	}{
		{
			name:             "Peer IDs match",
			clientPeerID:     "12D3KooWP2G8nJCLASp1Kb4TmQS4wCpMH2vpSUz8ug8DYEJiuf1i",
			connectionPeerID: "12D3KooWP2G8nJCLASp1Kb4TmQS4wCpMH2vpSUz8ug8DYEJiuf1i",
			expectAllow:      true,
		},
		{
			name:             "Peer IDs mismatch",
			clientPeerID:     "12D3KooWP2G8nJCLASp1Kb4TmQS4wCpMH2vpSUz8ug8DYEJiuf1i",
			connectionPeerID: "12D3KooWLgPBrLFKA533cKkXaecYUKfSZ48BkhwwYQ7ThDn1XwHb",
			expectAllow:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			// client_peer_id is embedded in the token authority block
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: FactClientPeerID,
				IDs:  []biscuit.Term{biscuit.String(tt.clientPeerID)},
			}})

			tok, _ := builder.Build()
			authorizer, err := tok.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(5*time.Second)))
			if err != nil {
				t.Fatalf("failed to create authorizer: %v", err)
			}

			// connection_peer_id is injected as a runtime connection fact
			authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: FactConnectionPeerID,
				IDs:  []biscuit.Term{biscuit.String(tt.connectionPeerID)},
			}})

			// Add replay check and generic allow
			authorizer.AddCheck(BaselineReplayCheck)
			authorizer.AddPolicy(AllowIfTruePolicy)

			err = authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

func TestBaselineTargetCheck(t *testing.T) {
	pub, priv := makeKeyPair(t)

	tests := []struct {
		name        string
		tokenFacts  []biscuit.Fact
		targetFact  string // e.g. "node" or "group"
		targetVal   string // e.g. "12D3Koo..." or "backend"
		expectAllow bool
	}{
		{
			name: "Exact target matching allows",
			tokenFacts: []biscuit.Fact{
				MarkerFact(FactTargetRestricted),
				{Predicate: biscuit.Predicate{Name: FactGrantedTargetExact, IDs: []biscuit.Term{biscuit.String("group"), biscuit.String("backend")}}},
			},
			targetFact:  "group",
			targetVal:   "backend",
			expectAllow: true,
		},
		{
			name: "Mismatched target denied when restricted",
			tokenFacts: []biscuit.Fact{
				MarkerFact(FactTargetRestricted),
				{Predicate: biscuit.Predicate{Name: FactGrantedTargetExact, IDs: []biscuit.Term{biscuit.String("group"), biscuit.String("backend")}}},
			},
			targetFact:  "group",
			targetVal:   "frontend",
			expectAllow: false,
		},
		{
			name: "Any target allowed when target_unrestricted",
			tokenFacts: []biscuit.Fact{
				MarkerFact(FactTargetUnrestricted),
			},
			targetFact:  "group",
			targetVal:   "any-group",
			expectAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			for _, fact := range tt.tokenFacts {
				_ = builder.AddAuthorityFact(fact)
			}

			tok, _ := builder.Build()
			authorizer, err := tok.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(5*time.Second)))
			if err != nil {
				t.Fatalf("failed to create authorizer: %v", err)
			}

			// target_fact is evaluated at runtime (e.g. node(...) or group(...))
			authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: tt.targetFact,
				IDs:  []biscuit.Term{biscuit.String(tt.targetVal)},
			}})

			// Add target check, baseline rules, and generic allow
			authorizer.AddCheck(BaselineTargetCheck)
			for _, r := range BaselineRules {
				authorizer.AddRule(r)
			}
			// targetFactRules parses facts like node(...) -> target_fact("node", ...)
			for _, r := range TargetFactRules {
				authorizer.AddRule(r)
			}
			authorizer.AddPolicy(AllowIfTruePolicy)

			err = authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

func TestControlPlaneStaticTimeCheck(t *testing.T) {
	pub, priv := makeKeyPair(t)

	tests := []struct {
		name        string
		expiry      time.Time
		timeNow     time.Time
		expectAllow bool
	}{
		{
			name:        "Token not expired",
			expiry:      time.Now().Add(1 * time.Hour),
			timeNow:     time.Now(),
			expectAllow: true,
		},
		{
			name:        "Token expired",
			expiry:      time.Now().Add(-1 * time.Hour),
			timeNow:     time.Now(),
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: FactExpiration,
				IDs:  []biscuit.Term{biscuit.Date(tt.expiry)},
			}})

			tok, _ := builder.Build()
			authorizer, _ := tok.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(5*time.Second)))

			authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: FactTime,
				IDs:  []biscuit.Term{biscuit.Date(tt.timeNow)},
			}})

			authorizer.AddCheck(ControlPlaneStaticTimeCheck)
			authorizer.AddPolicy(AllowIfTruePolicy)

			err := authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

func TestOIDCClaimToFact(t *testing.T) {
	facts := OIDCClaimToFact()

	want := map[string]string{
		"sub":    FactUser,
		"email":  FactEmail,
		"groups": FactGroup,
		"roles":  FactIdpRole,
	}

	if !reflect.DeepEqual(facts, want) {
		t.Errorf("OIDCClaimToFact() = %v, want %v", facts, want)
	}
	// role() is minted from mesh policy only. An issuer whose "roles" claim
	// landed there could name mesh:role:router and become a router.
	for claim, fact := range facts {
		if fact == FactRole {
			t.Errorf("claim %q maps to the mesh role fact %q", claim, FactRole)
		}
	}
	if p := BindingMemberPrefixes(); slices.Contains(p, FactRole) || !slices.Contains(p, FactIdpRole) || !slices.Contains(p, FactNode) {
		t.Errorf("BindingMemberPrefixes() = %v; want idp_role and node, not role", p)
	}

	// Verify that modifying the returned map does not mutate the internal map.
	facts["new_claim"] = "new_fact"
	facts2 := OIDCClaimToFact()

	if _, ok := facts2["new_claim"]; ok {
		t.Errorf("OIDCClaimToFact() returned map is not a clone, modifications affect internal state")
	}
}

func TestBuildServiceDatalogFact(t *testing.T) {
	tests := []struct {
		input    string
		expected biscuit.Fact
	}{
		{
			input:    "*",
			expected: MarkerFact(FactGrantedServiceAllTypes),
		},
		{
			input:    "mcp://*",
			expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedServiceAll, IDs: []biscuit.Term{biscuit.String("mcp")}}},
		},
		{
			input:    "mcp://*.local",
			expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedServiceSuffix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String(".local")}}},
		},
		{
			input:    "mcp://calc.*",
			expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedServicePrefix, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calc.")}}},
		},
		{
			input:    "mcp://calculator",
			expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calculator")}}},
		},
	}

	for _, tt := range tests {
		got := BuildServiceDatalogFact(tt.input)
		if got.String() != tt.expected.String() {
			t.Errorf("BuildServiceDatalogFact(%q) = %s, want %s", tt.input, got.String(), tt.expected.String())
		}
	}
}

func TestBuildTargetDatalogFact(t *testing.T) {
	tests := []struct {
		input    string
		expected biscuit.Fact
	}{
		{
			input:    "*",
			expected: MarkerFact(FactGrantedTargetAllFacts),
		},
		{
			input:    "user:*",
			expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedTargetAll, IDs: []biscuit.Term{biscuit.String("user")}}},
		},
		{
			input:    "group:*.internal",
			expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedTargetSuffix, IDs: []biscuit.Term{biscuit.String("group"), biscuit.String(".internal")}}},
		},
		{
			input:    "group:backend.*",
			expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedTargetPrefix, IDs: []biscuit.Term{biscuit.String("group"), biscuit.String("backend.")}}},
		},
		{
			input:    "group:backend",
			expected: biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedTargetExact, IDs: []biscuit.Term{biscuit.String("group"), biscuit.String("backend")}}},
		},
	}

	for _, tt := range tests {
		got := BuildTargetDatalogFact(tt.input)
		if got.String() != tt.expected.String() {
			t.Errorf("BuildTargetDatalogFact(%q) = %s, want %s", tt.input, got.String(), tt.expected.String())
		}
	}
}

func factStrings(facts []biscuit.Fact) []string {
	strs := make([]string, len(facts))
	for i, f := range facts {
		strs[i] = f.String()
	}
	sort.Strings(strs)
	return strs
}

func TestBuildServiceDatalogFacts(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "single exact entry aggregates into one Set fact",
			input:    []string{"mcp://calculator"},
			expected: []string{`granted_service_set("mcp", ["calculator"])`},
		},
		{
			name:  "multiple exact entries of the same type aggregate into one Set fact",
			input: []string{"mcp://calculator", "mcp://jupyter"},
			expected: []string{
				`granted_service_set("mcp", ["calculator", "jupyter"])`,
			},
		},
		{
			name:  "exact entries of different types produce one Set fact per type",
			input: []string{"mcp://calculator", "inference://model-a"},
			expected: []string{
				`granted_service_set("inference", ["model-a"])`,
				`granted_service_set("mcp", ["calculator"])`,
			},
		},
		{
			name:  "wildcard, prefix and suffix entries keep the existing single-fact representation",
			input: []string{"*", "mcp://*", "mcp://*.local", "mcp://calc.*", "mcp://calculator"},
			expected: []string{
				BuildServiceDatalogFact("*").String(),
				BuildServiceDatalogFact("mcp://*").String(),
				BuildServiceDatalogFact("mcp://*.local").String(),
				BuildServiceDatalogFact("mcp://calc.*").String(),
				`granted_service_set("mcp", ["calculator"])`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := factStrings(BuildServiceDatalogFacts(tt.input))
			want := append([]string(nil), tt.expected...)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("BuildServiceDatalogFacts(%v) = %v, want %v", tt.input, got, want)
			}
		})
	}
}

func TestBuildTargetDatalogFacts(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "single exact entry aggregates into one Set fact",
			input:    []string{"group:backend"},
			expected: []string{`granted_target_set("group", ["backend"])`},
		},
		{
			name:  "multiple exact entries of the same fact name aggregate into one Set fact",
			input: []string{"node:peer-abc", "legacy-peer"},
			expected: []string{
				`granted_target_set("node", ["legacy-peer", "peer-abc"])`,
			},
		},
		{
			name:  "exact entries of different fact names produce one Set fact each",
			input: []string{"node:peer-abc", "group:backend"},
			expected: []string{
				`granted_target_set("group", ["backend"])`,
				`granted_target_set("node", ["peer-abc"])`,
			},
		},
		{
			name:  "wildcard, prefix and suffix entries keep the existing single-fact representation",
			input: []string{"*", "user:*", "group:*.internal", "group:backend.*", "group:backend"},
			expected: []string{
				BuildTargetDatalogFact("*").String(),
				BuildTargetDatalogFact("user:*").String(),
				BuildTargetDatalogFact("group:*.internal").String(),
				BuildTargetDatalogFact("group:backend.*").String(),
				`granted_target_set("group", ["backend"])`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := factStrings(BuildTargetDatalogFacts(tt.input))
			want := append([]string(nil), tt.expected...)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("BuildTargetDatalogFacts(%v) = %v, want %v", tt.input, got, want)
			}
		})
	}
}

func TestLabelFactsAndCheck(t *testing.T) {
	pub, priv := makeKeyPair(t)

	if facts := LabelFacts(nil); facts != nil {
		t.Errorf("LabelFacts(nil) = %v, want nil", facts)
	}

	tests := []struct {
		name        string
		claimed     map[string]string // minted into the token via LabelFacts
		required    map[string]string
		expectAllow bool
	}{
		{"exact match", map[string]string{"region": "us-east-1"}, map[string]string{"region": "us-east-1"}, true},
		{"every pair present", map[string]string{"region": "us-east-1", "team": "platform", "tier": "gold"}, map[string]string{"region": "us-east-1", "team": "platform"}, true},
		{"one pair of two missing", map[string]string{"region": "us-east-1"}, map[string]string{"region": "us-east-1", "team": "platform"}, false},
		{"one pair of two wrong", map[string]string{"region": "us-east-1", "team": "platform"}, map[string]string{"region": "eu", "team": "platform"}, false},
		{"case-sensitive value mismatch", map[string]string{"region": "us-east-1"}, map[string]string{"region": "US-EAST-1"}, false},
		{"no built-in hierarchy: coarser requirement does not match a finer claim", map[string]string{"region": "us-east-1"}, map[string]string{"region": "us"}, false},
		{"disjoint labels", map[string]string{"region": "us-east-1"}, map[string]string{"region": "eu-west-1"}, false},
		{"unattested token fails closed", nil, map[string]string{"region": "us-east-1"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			for _, fact := range LabelFacts(tt.claimed) {
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatalf("failed to add label fact: %v", err)
				}
			}
			tok, err := builder.Build()
			if err != nil {
				t.Fatalf("failed to build token: %v", err)
			}

			authorizer, err := tok.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(5*time.Second)))
			if err != nil {
				t.Fatalf("failed to create authorizer: %v", err)
			}
			check, err := LabelCheck(tt.required)
			if err != nil {
				t.Fatalf("LabelCheck(%v): %v", tt.required, err)
			}
			authorizer.AddCheck(check)
			authorizer.AddPolicy(AllowIfTruePolicy)

			err = authorizer.Authorize()
			if tt.expectAllow && err != nil {
				t.Errorf("expected authorized, got error: %v", err)
			} else if !tt.expectAllow && err == nil {
				t.Error("expected denied, but authorization succeeded")
			}
		})
	}
}

// A requirement of several pairs is a conjunction, pinned on the compiled
// shape rather than on the rendered string: one query body carrying every
// predicate, not one body per pair.
func TestLabelCheckIsConjunction(t *testing.T) {
	both := map[string]string{"jurisdiction": "eu", "compliance": "gdpr"}

	check, err := LabelCheck(both)
	if err != nil {
		t.Fatalf("LabelCheck: %v", err)
	}
	if len(check.Queries) != 1 {
		t.Fatalf("a requirement must compile to a single conjunctive body, got %d alternatives", len(check.Queries))
	}
	if got := len(check.Queries[0].Body); got != len(both) {
		t.Errorf("the body carries %d predicates, want all %d", got, len(both))
	}
}

func TestLabelCheckRejectsBadInput(t *testing.T) {
	if _, err := LabelCheck(nil); err == nil {
		t.Error("LabelCheck(nil): expected error, got nil")
	}
	if _, err := LabelCheck(map[string]string{"region": "bad,value"}); err == nil {
		t.Error("LabelCheck(invalid value): expected error, got nil")
	}
	if _, err := LabelCheck(map[string]string{"bad key!": "v"}); err == nil {
		t.Error("LabelCheck(invalid key): expected error, got nil")
	}
}

func TestLabelsSatisfy(t *testing.T) {
	required := map[string]string{"jurisdiction": "eu", "compliance": "gdpr"}
	tests := []struct {
		name    string
		claimed map[string]string
		want    bool
	}{
		{"every pair present", map[string]string{"jurisdiction": "eu", "compliance": "gdpr", "region": "de"}, true},
		{"one pair missing", map[string]string{"jurisdiction": "eu"}, false},
		{"one pair wrong", map[string]string{"jurisdiction": "eu", "compliance": "hipaa"}, false},
		{"nothing claimed", nil, false},
	}
	for _, tt := range tests {
		if got := LabelsSatisfy(required, tt.claimed); got != tt.want {
			t.Errorf("%s: LabelsSatisfy = %v, want %v", tt.name, got, tt.want)
		}
	}
	// An empty requirement constrains nothing, so callers can pass it unconditionally.
	if !LabelsSatisfy(nil, nil) {
		t.Error("an empty requirement must be satisfied by anything")
	}
}

// The two predicates differ on one case, and it is the case that matters: a
// peer silent on a pair the requirement names. Gossip is partial, so silence
// must not read as failure before the gate has seen attested facts.
func TestLabelsContradictTreatsSilenceAsUnknown(t *testing.T) {
	required := map[string]string{"jurisdiction": "eu", "compliance": "gdpr"}

	partial := map[string]string{"jurisdiction": "eu"}
	if LabelsContradict(required, partial) {
		t.Error("a claim silent on one pair does not contradict the requirement")
	}
	if LabelsSatisfy(required, partial) {
		t.Error("but it does not satisfy it either")
	}

	conflicting := map[string]string{"jurisdiction": "us"}
	if !LabelsContradict(required, conflicting) {
		t.Error("a different value for a required key is a contradiction")
	}

	if LabelsContradict(required, nil) {
		t.Error("no claims at all cannot contradict anything")
	}
	if LabelsContradict(required, map[string]string{"jurisdiction": "eu", "compliance": "gdpr"}) {
		t.Error("a fully satisfying claim must not read as a contradiction")
	}
}
