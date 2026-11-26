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
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/eclipse-biscuit/biscuit-go/v2"
)

const (
	// MaxAttestedClaims bounds the total number of distinct OIDC JWT claim paths
	// configured across PolicyConfig.attested_claims and all PolicyBinding.claims.
	// Keeping this bounded prevents noisy JWTs from exhausting the Biscuit
	// authorizer fact budget or bloating request headers.
	MaxAttestedClaims = 16

	// MaxValuesPerClaim bounds how many values a single multi-valued JWT claim
	// (for example RFC 8176 "amr") may emit as claim(k, v) authority facts.
	// Claims exceeding this cap are omitted fail-closed with a warning.
	MaxValuesPerClaim = 16

	// MaxClaimKeyLen bounds OIDC claim path names (including namespaced URL claims).
	MaxClaimKeyLen = 128

	// MaxClaimValueLen bounds individual OIDC claim values (including issuer URLs).
	MaxClaimValueLen = 255
)

// ValidateClaimKey checks that an OIDC claim path is well-formed, bounded, and
// safe for Biscuit Datalog strings and comma-separated header encoding.
// It accepts top-level keys (including "iss", "acr", "amr"), dotted JSON paths
// (such as "device.trust_tier"), and namespaced URI claims (such as
// "https://corp.example/tier").
func ValidateClaimKey(key string) error {
	if key == "" {
		return fmt.Errorf("claim key must not be empty")
	}
	if len(key) > MaxClaimKeyLen {
		return fmt.Errorf("claim key %q exceeds %d characters", key, MaxClaimKeyLen)
	}
	for _, r := range key {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '"' || r == '\\' || r == ',' || r == '=' {
			return fmt.Errorf("claim key %q contains disallowed character %q", key, r)
		}
	}
	return nil
}

// ValidateClaimValue checks that an OIDC claim value is non-empty, bounded, and
// safe for Biscuit Datalog strings and comma-separated header encoding.
// Colons and slashes are permitted so issuer URLs ("iss") work naturally.
func ValidateClaimValue(value string) error {
	if value == "" {
		return fmt.Errorf("claim value must not be empty")
	}
	if len(value) > MaxClaimValueLen {
		return fmt.Errorf("claim value %q exceeds %d characters", value, MaxClaimValueLen)
	}
	if strings.ContainsAny(value, ",\n\r\t") {
		return fmt.Errorf("claim value %q must not contain ',' or control characters", value)
	}
	if err := validateBindingMemberCharset(value); err != nil {
		return fmt.Errorf("claim value %q %w", value, err)
	}
	return nil
}

// ValidateBindingClaims validates the structured PolicyBinding.claims map for
// a single role binding.
func ValidateBindingClaims(claims map[string]string, role string) error {
	if len(claims) == 0 {
		return nil
	}
	if len(claims) > MaxAttestedClaims {
		return fmt.Errorf("binding for role %q specifies %d claims, maximum is %d", role, len(claims), MaxAttestedClaims)
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := ValidateClaimKey(k); err != nil {
			return fmt.Errorf("binding for role %q has invalid claim key %q: %w", role, k, err)
		}
		if err := ValidateClaimValue(claims[k]); err != nil {
			return fmt.Errorf("binding for role %q has invalid claim value for %q: %w", role, k, err)
		}
	}
	return nil
}

// ValidateAttestedClaims validates PolicyConfig.attested_claims entries and
// enforces MaxAttestedClaims.
func ValidateAttestedClaims(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if err := ValidateClaimKey(p); err != nil {
			return fmt.Errorf("attested_claims entry %q: %w", p, err)
		}
		seen[p] = true
	}
	if len(seen) > MaxAttestedClaims {
		return fmt.Errorf("policy configures %d attested_claims, maximum is %d", len(seen), MaxAttestedClaims)
	}
	return nil
}

// CollectPolicyClaimPaths returns the sorted, deduplicated union of all claim
// paths referenced in PolicyBinding.claims and PolicyConfig.attested_claims,
// enforcing MaxAttestedClaims across the entire policy document.
func CollectPolicyClaimPaths(bindings []*PolicyBinding, attestedClaims []string) ([]string, error) {
	seen := make(map[string]bool)
	for _, p := range attestedClaims {
		if err := ValidateClaimKey(p); err != nil {
			return nil, fmt.Errorf("attested_claims entry %q: %w", p, err)
		}
		seen[p] = true
	}
	for _, b := range bindings {
		if b == nil {
			continue
		}
		for k := range b.GetClaims() {
			if err := ValidateClaimKey(k); err != nil {
				return nil, fmt.Errorf("binding for role %q has invalid claim key %q: %w", b.GetRole(), k, err)
			}
			seen[k] = true
		}
	}
	if len(seen) > MaxAttestedClaims {
		return nil, fmt.Errorf("policy references %d distinct OIDC claims across attested_claims and bindings, maximum is %d", len(seen), MaxAttestedClaims)
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// ExtractVerifiedClaims reads configured claimPaths from verified OIDC JWT
// claims and returns validated multi-valued claim sets plus deterministic
// warnings for claims that exceed MaxValuesPerClaim or contain unsupported or
// invalid values. Missing claims are omitted silently so deny-by-default rules
// fail closed. Top-level claims such as "iss" always resolve directly.
func ExtractVerifiedClaims(rawClaims map[string]any, claimPaths []string) (map[string][]string, []string) {
	if len(rawClaims) == 0 || len(claimPaths) == 0 {
		return nil, nil
	}
	paths := append([]string(nil), claimPaths...)
	sort.Strings(paths)

	var out map[string][]string
	var warnings []string
	seenPath := make(map[string]bool, len(paths))
	for _, path := range paths {
		if seenPath[path] {
			continue
		}
		seenPath[path] = true

		raw, found := lookupJWTClaimPath(rawClaims, path)
		if !found || raw == nil {
			continue
		}
		vals, warn := extractClaimValues(path, raw)
		if warn != "" {
			warnings = append(warnings, warn)
		}
		if len(vals) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string][]string)
		}
		out[path] = vals
	}
	return out, warnings
}

func lookupJWTClaimPath(claims map[string]any, claimPath string) (any, bool) {
	if v, ok := claims[claimPath]; ok {
		return v, true
	}
	parts := strings.Split(claimPath, ".")
	if len(parts) < 2 {
		return nil, false
	}
	var cur any = claims
	for _, part := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, exists := m[part]
		if !exists {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func formatScalarClaim(raw any) (string, bool) {
	switch v := raw.(type) {
	case string:
		return v, true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return "", false
		}
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case json.Number:
		s := v.String()
		if _, err := v.Float64(); err != nil {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}

func extractClaimValues(path string, raw any) ([]string, string) {
	var rawStrings []string
	switch v := raw.(type) {
	case []string:
		if len(v) > MaxValuesPerClaim {
			return nil, fmt.Sprintf("claim %q has %d values (max %d); omitted", path, len(v), MaxValuesPerClaim)
		}
		rawStrings = v
	case []any:
		if len(v) > MaxValuesPerClaim {
			return nil, fmt.Sprintf("claim %q has %d values (max %d); omitted", path, len(v), MaxValuesPerClaim)
		}
		for _, elem := range v {
			s, ok := formatScalarClaim(elem)
			if !ok {
				return nil, fmt.Sprintf("claim %q contains non-scalar element; omitted", path)
			}
			if s != "" {
				rawStrings = append(rawStrings, s)
			}
		}
	default:
		s, ok := formatScalarClaim(raw)
		if !ok {
			return nil, fmt.Sprintf("claim %q is not a string, boolean, finite number, or scalar array; omitted", path)
		}
		if s == "" {
			return nil, fmt.Sprintf("claim %q is empty; omitted", path)
		}
		rawStrings = []string{s}
	}

	seen := make(map[string]bool, len(rawStrings))
	vals := make([]string, 0, len(rawStrings))
	for _, s := range rawStrings {
		if err := ValidateClaimValue(s); err != nil {
			return nil, fmt.Sprintf("claim %q has invalid value: %v; omitted", path, err)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		vals = append(vals, s)
	}
	if len(vals) > MaxValuesPerClaim {
		return nil, fmt.Sprintf("claim %q has %d distinct values (max %d); omitted", path, len(vals), MaxValuesPerClaim)
	}
	sort.Strings(vals)
	return vals, ""
}

// MatchBindingClaims reports whether extracted verified JWT claims satisfy
// every key=value requirement in required.
func MatchBindingClaims(extracted map[string][]string, required map[string]string) bool {
	if len(required) == 0 {
		return true
	}
	if len(extracted) == 0 {
		return false
	}
	for k, want := range required {
		if !slices.Contains(extracted[k], want) {
			return false
		}
	}
	return true
}

// ClaimFacts turns validated OIDC claims into authority-block Biscuit facts
// claim(key, value) in deterministic sorted order.
func ClaimFacts(claims map[string][]string) []biscuit.Fact {
	if len(claims) == 0 {
		return nil
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var facts []biscuit.Fact
	for _, k := range keys {
		vals := append([]string(nil), claims[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			facts = append(facts, biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: FactClaim,
					IDs:  []biscuit.Term{biscuit.String(k), biscuit.String(v)},
				},
			})
		}
	}
	return facts
}

// FormatClaims renders verified claims into canonical sorted comma-separated
// "key=value" pairs for headers and structured audit logs.
func FormatClaims(claims map[string][]string) string {
	if len(claims) == 0 {
		return ""
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), claims[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, ",")
}

// ClaimsForBorderJWT converts verified Biscuit claims into a JSON-friendly map
// for the outbound ES256 border JWT "mesh_claims" claim: single-valued claims
// serialize as strings and multi-valued claims as sorted string slices.
func ClaimsForBorderJWT(claims map[string][]string) map[string]any {
	if len(claims) == 0 {
		return nil
	}
	out := make(map[string]any, len(claims))
	for k, vals := range claims {
		if len(vals) == 0 {
			continue
		}
		sorted := append([]string(nil), vals...)
		sort.Strings(sorted)
		if len(sorted) == 1 {
			out[k] = sorted[0]
		} else {
			out[k] = sorted
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
