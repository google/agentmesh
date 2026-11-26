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
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

func TestValidateAndCollectPolicyClaims(t *testing.T) {
	// Valid claim keys include top-level "iss", dotted paths, and namespaced URIs.
	for _, k := range []string{"iss", "acr", "amr", "device.trust_tier", "https://corp.example/tier"} {
		if err := ValidateClaimKey(k); err != nil {
			t.Errorf("ValidateClaimKey(%q) unexpected error: %v", k, err)
		}
	}
	for _, bad := range []string{"", "has space", "a,b", "a=b", `a"b`, `a\b`, "a\nb", strings.Repeat("x", MaxClaimKeyLen+1)} {
		if err := ValidateClaimKey(bad); err == nil {
			t.Errorf("ValidateClaimKey(%q) expected error, got nil", bad)
		}
	}

	// Valid claim values include issuer URLs with colons and slashes.
	for _, v := range []string{"high", "https://idp.corp.example/realms/main", "hwk"} {
		if err := ValidateClaimValue(v); err != nil {
			t.Errorf("ValidateClaimValue(%q) unexpected error: %v", v, err)
		}
	}
	for _, bad := range []string{"", "a,b", `a"b`, `a\b`, "a\nb", strings.Repeat("x", MaxClaimValueLen+1)} {
		if err := ValidateClaimValue(bad); err == nil {
			t.Errorf("ValidateClaimValue(%q) expected error, got nil", bad)
		}
	}

	// CollectPolicyClaimPaths deduplicates and sorts the union of bindings and attested_claims.
	bindings := []*PolicyBinding{
		{Role: "r1", Members: []string{"email:*@corp.example"}, Claims: map[string]string{"iss": "https://idp.corp.example", "device.trust_tier": "high"}},
		{Role: "r2", Members: []string{"email:*@corp.example"}, Claims: map[string]string{"device.trust_tier": "high", "device.type": "managed_workstation"}},
	}
	paths, err := CollectPolicyClaimPaths(bindings, []string{"amr", "iss"})
	if err != nil {
		t.Fatalf("CollectPolicyClaimPaths: %v", err)
	}
	wantPaths := []string{"amr", "device.trust_tier", "device.type", "iss"}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("CollectPolicyClaimPaths = %v, want %v", paths, wantPaths)
	}

	// Enforce MaxAttestedClaims cap across the combined policy document.
	atLimit := make([]string, MaxAttestedClaims)
	for i := range atLimit {
		atLimit[i] = fmt.Sprintf("claim_%02d", i)
	}
	if _, err := CollectPolicyClaimPaths(nil, atLimit); err != nil {
		t.Fatalf("CollectPolicyClaimPaths at MaxAttestedClaims (%d) failed: %v", MaxAttestedClaims, err)
	}
	overLimit := append(append([]string(nil), atLimit...), "claim_overflow")
	if _, err := CollectPolicyClaimPaths(nil, overLimit); err == nil {
		t.Fatalf("CollectPolicyClaimPaths with %d claims expected error, got nil", len(overLimit))
	}
	// Combined bindings + attested_claims exceeding MaxAttestedClaims must also fail.
	if _, err := CollectPolicyClaimPaths([]*PolicyBinding{{Role: "r", Members: []string{SystemAuthenticated}, Claims: map[string]string{"extra": "v"}}}, atLimit); err == nil {
		t.Fatalf("CollectPolicyClaimPaths combined > MaxAttestedClaims expected error, got nil")
	}
}

func TestExtractVerifiedClaimsAndLimits(t *testing.T) {
	tooMany := make([]any, MaxValuesPerClaim+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("v%d", i)
	}

	raw := map[string]any{
		"iss": "https://idp.corp.example",
		"device": map[string]any{
			"trust_tier": "high",
			"managed":    true,
			"tier_num":   float64(30),
		},
		"auth_time":                 float64(1700000000),
		"level_int":                 42,
		"level_json":                json.Number("7"),
		"https://corp.example/tier": "gold",
		"amr":                       []any{"mfa", "hwk", "hwk"},
		"num_arr":                   []any{float64(1), float64(2.5)},
		"bad_nan":                   math.NaN(),
		"too_many":                  tooMany,
		"bad_obj":                   map[string]any{"nested": "x"},
		"bad_comma":                 "a,b",
	}

	paths := []string{"iss", "device.trust_tier", "device.managed", "device.tier_num", "auth_time", "level_int", "level_json", "https://corp.example/tier", "amr", "num_arr", "bad_nan", "missing", "too_many", "bad_obj", "bad_comma"}
	got, warnings := ExtractVerifiedClaims(raw, paths)

	want := map[string][]string{
		"iss":                       {"https://idp.corp.example"},
		"device.trust_tier":         {"high"},
		"device.managed":            {"true"},
		"device.tier_num":           {"30"},
		"auth_time":                 {"1700000000"},
		"level_int":                 {"42"},
		"level_json":                {"7"},
		"https://corp.example/tier": {"gold"},
		"amr":                       {"hwk", "mfa"},
		"num_arr":                   {"1", "2.5"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractVerifiedClaims = %#v, want %#v", got, want)
	}
	if len(warnings) != 4 {
		t.Fatalf("expected 4 warnings (bad_nan, too_many, bad_obj, bad_comma), got %d: %v", len(warnings), warnings)
	}

	if !MatchBindingClaims(got, map[string]string{"iss": "https://idp.corp.example", "amr": "hwk", "device.trust_tier": "high", "device.tier_num": "30", "auth_time": "1700000000"}) {
		t.Fatal("MatchBindingClaims expected true for matching iss + amr + device.trust_tier + numeric claims")
	}
	if MatchBindingClaims(got, map[string]string{"iss": "https://other-idp.example", "device.trust_tier": "high"}) {
		t.Fatal("MatchBindingClaims expected false on mismatched iss")
	}

	wantFormatted := "amr=hwk,amr=mfa,auth_time=1700000000,device.managed=true,device.tier_num=30,device.trust_tier=high,https://corp.example/tier=gold,iss=https://idp.corp.example,level_int=42,level_json=7,num_arr=1,num_arr=2.5"
	if s := FormatClaims(got); s != wantFormatted {
		t.Errorf("FormatClaims = %q, want %q", s, wantFormatted)
	}

	border := ClaimsForBorderJWT(got)
	if border["iss"] != "https://idp.corp.example" {
		t.Errorf("ClaimsForBorderJWT[iss] = %#v, want string", border["iss"])
	}
	if !reflect.DeepEqual(border["amr"], []string{"hwk", "mfa"}) {
		t.Errorf("ClaimsForBorderJWT[amr] = %#v, want []string{hwk, mfa}", border["amr"])
	}
}

func TestBuildPolicyRulesWithStructuredBindingClaims(t *testing.T) {
	roles := []*PolicyRole{
		{Name: "workstation-caller", AllowedServices: []string{"a2a://dev-agent"}},
	}
	bindings := []*PolicyBinding{
		{
			Role:    "workstation-caller",
			Members: []string{"email:*@corp.example", "email:alice@corp.example"},
			Claims: map[string]string{
				"iss":               "https://idp.corp.example",
				"device.trust_tier": "high",
				"device.type":       "managed_workstation",
			},
		},
		{
			Role:    "workstation-caller",
			Members: []string{SystemAuthenticated},
			Claims: map[string]string{
				"iss":               "https://idp.corp.example",
				"device.trust_tier": "high",
				"device.type":       "managed_mobile",
				"device.management": "fully_managed",
			},
		},
	}

	rules, warnings := BuildPolicyRules(roles, bindings)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	texts := PolicyRuleTexts(rules)
	wantRules := []string{
		`role("workstation-caller") <- email($v), $v.ends_with("@corp.example"), claim("device.trust_tier", "high"), claim("device.type", "managed_workstation"), claim("iss", "https://idp.corp.example")`,
		`role("workstation-caller") <- email("alice@corp.example"), claim("device.trust_tier", "high"), claim("device.type", "managed_workstation"), claim("iss", "https://idp.corp.example")`,
		`role("workstation-caller") <- claim("device.management", "fully_managed"), claim("device.trust_tier", "high"), claim("device.type", "managed_mobile"), claim("iss", "https://idp.corp.example")`,
	}
	for _, want := range wantRules {
		if !slices.Contains(texts, want) {
			t.Errorf("missing compiled rule %q in %v", want, texts)
		}
		if _, err := parser.FromStringRule(want); err != nil {
			t.Errorf("compiled rule %q failed to parse: %v", want, err)
		}
	}

	// Verify real Biscuit Datalog evaluation against ClaimFacts + compiled rules.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	eval := func(email string, claims map[string][]string) bool {
		t.Helper()
		builder := biscuit.NewBuilder(priv)
		if email != "" {
			if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: FactEmail, IDs: []biscuit.Term{biscuit.String(email)}}}); err != nil {
				t.Fatal(err)
			}
		}
		for _, f := range ClaimFacts(claims) {
			if err := builder.AddAuthorityFact(f); err != nil {
				t.Fatal(err)
			}
		}
		tok, err := builder.Build()
		if err != nil {
			t.Fatal(err)
		}
		auth, err := tok.Authorizer(pub)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			auth.AddRule(r.Rule)
		}
		auth.AddPolicy(biscuit.Policy{
			Kind: biscuit.PolicyKindAllow,
			Queries: []biscuit.Rule{{
				Body: []biscuit.Predicate{{Name: FactRole, IDs: []biscuit.Term{biscuit.String("workstation-caller")}}},
			}},
		})
		return auth.Authorize() == nil
	}

	if !eval("bob@corp.example", map[string][]string{"iss": {"https://idp.corp.example"}, "device.trust_tier": {"high"}, "device.type": {"managed_workstation"}}) {
		t.Error("expected managed workstation from trusted issuer to derive workstation-caller")
	}
	if eval("bob@corp.example", map[string][]string{"iss": {"https://untrusted-partner.example"}, "device.trust_tier": {"high"}, "device.type": {"managed_workstation"}}) {
		t.Error("expected wrong issuer to fail iss claim check")
	}
	if !eval("carol@corp.example", map[string][]string{"iss": {"https://idp.corp.example"}, "device.trust_tier": {"high"}, "device.type": {"managed_mobile"}, "device.management": {"fully_managed"}}) {
		t.Error("expected fully managed mobile to derive workstation-caller via second binding")
	}
	if eval("carol@corp.example", map[string][]string{"iss": {"https://idp.corp.example"}, "device.trust_tier": {"high"}, "device.type": {"managed_mobile"}, "device.management": {"work_profile"}}) {
		t.Error("expected work_profile mobile to be denied")
	}
}

func TestFormatLabels(t *testing.T) {
	if got := FormatLabels(nil); got != "" {
		t.Fatalf("FormatLabels(nil) = %q, want empty", got)
	}
	got := FormatLabels(map[string]string{"zone": "a", "region": "us-west1"})
	if want := "region=us-west1,zone=a"; got != want {
		t.Fatalf("FormatLabels() = %q, want %q", got, want)
	}
}
