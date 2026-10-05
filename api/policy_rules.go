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
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/libp2p/go-libp2p/core/peer"
)

func validateBindingMemberCharset(s string) error {
	for _, r := range s {
		if unicode.IsControl(r) || r == '"' || r == '\\' {
			return fmt.Errorf("contains disallowed character %q", r)
		}
	}
	return nil
}

// ValidateRoleName checks that a PolicyRole.name is non-empty and free of
// characters that could break or inject Datalog rules.
func ValidateRoleName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("role name cannot be empty")
	}
	if err := validateBindingMemberCharset(name); err != nil {
		return fmt.Errorf("role name %q is invalid: %w", name, err)
	}
	return nil
}

// ValidateBindingMember checks a single PolicyBinding.members entry.
// It permits sam:system:authenticated, exact "<prefix>:<value>" members, and
// a single leading "*<suffix>" or trailing "<prefix>*" wildcard on non-node
// prefixes. Bare "<prefix>:*" is rejected as a disguised sam:system:authenticated,
// and values containing '"', '\', or control characters are rejected to
// prevent Datalog rule injection.
func ValidateBindingMember(member string, role string) error {
	if member == SystemAuthenticated {
		return nil
	}
	parts := strings.SplitN(member, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return fmt.Errorf("member %q in binding for role %q is invalid, must be in format 'type:value' or %q", member, role, SystemAuthenticated)
	}
	prefix, value := parts[0], parts[1]
	if !slices.Contains(BindingMemberPrefixes(), prefix) {
		return fmt.Errorf("member prefix %q in member %q is invalid", prefix, member)
	}
	if err := validateBindingMemberCharset(value); err != nil {
		return fmt.Errorf("member %q in binding for role %q is invalid: %w", member, role, err)
	}
	if strings.Contains(value, "*") {
		if prefix == FactNode {
			return fmt.Errorf("wildcard is not permitted in node binding member %q for role %q", member, role)
		}
		if value == "*" {
			return fmt.Errorf("bare wildcard %q in binding for role %q is not permitted; use %q to match every authenticated identity", member, role, SystemAuthenticated)
		}
		leading := strings.HasPrefix(value, "*") && !strings.Contains(value[1:], "*")
		trailing := strings.HasSuffix(value, "*") && !strings.Contains(value[:len(value)-1], "*")
		if !leading && !trailing {
			return fmt.Errorf("wildcard in binding member %q for role %q must be a single leading or trailing '*'", member, role)
		}
	}
	return nil
}

// MatchBindingMemberValue reports whether any candidate claim value satisfies
// pattern (exact match, "<prefix>*" starts_with, or "*<suffix>" ends_with).
func MatchBindingMemberValue(candidates []string, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return false
	}
	if strings.Contains(pattern, "*") {
		if strings.HasSuffix(pattern, "*") && !strings.Contains(pattern[:len(pattern)-1], "*") {
			prefix := pattern[:len(pattern)-1]
			for _, c := range candidates {
				if strings.HasPrefix(c, prefix) {
					return true
				}
			}
			return false
		}
		if strings.HasPrefix(pattern, "*") && !strings.Contains(pattern[1:], "*") {
			suffix := pattern[1:]
			for _, c := range candidates {
				if strings.HasSuffix(c, suffix) {
					return true
				}
			}
			return false
		}
		return false
	}
	return slices.Contains(candidates, pattern)
}

// PolicyRule is one mesh policy rule in both the form biscuit-go evaluates
// and the Datalog text every other Biscuit implementation parses.
type PolicyRule struct {
	Rule biscuit.Rule
	Text string
}

// BuildPolicyRules turns the mesh policy into the Datalog rules a provider
// adds to its authorizer: bindings grant role() from attested identity facts,
// roles grant granted_* facts from role(). Warnings name entries that were
// skipped or that widen the mesh more than an operator may expect; the caller
// decides how to surface them.
func BuildPolicyRules(roles []*PolicyRole, bindings []*PolicyBinding) (rules []PolicyRule, warnings []string) {
	add := func(head biscuit.Predicate, body ...biscuit.Predicate) {
		r := biscuit.Rule{Head: head, Body: body}
		rules = append(rules, PolicyRule{Rule: r, Text: renderRule(r)})
	}

	// A binding member becomes the body of a rule that grants a mesh role,
	// so only facts the control plane attests in the authority block may
	// appear there: agent() is the caller's own claim, and role() would
	// grant a role from a role.
	allowedMemberPrefix := make(map[string]bool)
	for _, p := range BindingMemberPrefixes() {
		allowedMemberPrefix[p] = true
	}

	for _, b := range bindings {
		if b == nil {
			continue
		}
		if err := ValidateRoleName(b.Role); err != nil {
			warnings = append(warnings, fmt.Sprintf("Binding has invalid role %q: %v", b.Role, err))
			continue
		}
		roleHead := biscuit.Predicate{Name: FactRole, IDs: []biscuit.Term{biscuit.String(b.Role)}}
		for _, m := range b.Members {
			if m == SystemAuthenticated {
				add(roleHead)
				continue
			}
			parts := strings.SplitN(m, ":", 2)
			if len(parts) != 2 || !allowedMemberPrefix[parts[0]] {
				continue
			}
			prefix, value := parts[0], parts[1]
			// A token carries node() in peer.ID.String() form; an operator may
			// have written any encoding peer.Decode accepts.
			if prefix == FactNode {
				id, err := peer.Decode(value)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("Binding member %q is not a peer ID and grants role %s to nobody: %v", m, b.Role, err))
					continue
				}
				value = id.String()
				add(roleHead, biscuit.Predicate{Name: prefix, IDs: []biscuit.Term{biscuit.String(value)}})
				continue
			}
			if strings.Contains(value, "*") {
				if err := validateBindingMemberCharset(value); err != nil {
					warnings = append(warnings, fmt.Sprintf("Binding member %q for role %s %v and grants role to nobody", m, b.Role, err))
					continue
				}
				var text string
				roleLiteral := fmt.Sprintf("%s(%s)", FactRole, strconv.Quote(b.Role))
				switch {
				case value == "*":
					warnings = append(warnings, fmt.Sprintf("Binding member %q has a bare wildcard and grants role %s to nobody", m, b.Role))
					continue
				case strings.HasSuffix(value, "*") && !strings.Contains(value[:len(value)-1], "*"):
					affix := value[:len(value)-1]
					text = fmt.Sprintf("%s <- %s($v), $v.starts_with(%s)", roleLiteral, prefix, strconv.Quote(affix))
				case strings.HasPrefix(value, "*") && !strings.Contains(value[1:], "*"):
					affix := value[1:]
					text = fmt.Sprintf("%s <- %s($v), $v.ends_with(%s)", roleLiteral, prefix, strconv.Quote(affix))
				default:
					warnings = append(warnings, fmt.Sprintf("Binding member %q has an invalid wildcard and grants role %s to nobody", m, b.Role))
					continue
				}
				r, err := parser.FromStringRule(text)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("Failed to parse wildcard binding rule %q for role %s: %v", text, b.Role, err))
					continue
				}
				rules = append(rules, PolicyRule{Rule: r, Text: text})
				continue
			}
			add(roleHead, biscuit.Predicate{Name: prefix, IDs: []biscuit.Term{biscuit.String(value)}})
		}
	}

	for _, role := range roles {
		if role == nil {
			continue
		}
		if err := ValidateRoleName(role.Name); err != nil {
			warnings = append(warnings, fmt.Sprintf("Role has invalid name %q: %v", role.Name, err))
			continue
		}
		roleName := role.Name
		fromRole := biscuit.Predicate{Name: FactRole, IDs: []biscuit.Term{biscuit.String(roleName)}}

		plainServices, narrowed := SplitHTTPGrants(role)
		for _, fact := range BuildServiceDatalogFacts(plainServices) {
			add(fact.Predicate, fromRole)
		}
		for _, g := range narrowed {
			for _, fact := range BuildHTTPGrantFacts(g) {
				add(fact.Predicate, fromRole)
			}
		}

		hasUnrestricted := false
		var nonWildcardTargets []string
		for _, t := range role.AllowedTargets {
			if t == "*" {
				hasUnrestricted = true
			} else {
				nonWildcardTargets = append(nonWildcardTargets, t)
			}
		}
		if hasUnrestricted {
			add(MarkerFact(FactTargetUnrestricted).Predicate, fromRole)
		}
		if len(nonWildcardTargets) > 0 {
			add(MarkerFact(FactTargetRestricted).Predicate, fromRole)
		}
		for _, fact := range BuildTargetDatalogFacts(nonWildcardTargets) {
			add(fact.Predicate, fromRole)
		}

		// Custom entries keep their source text: it may carry expressions,
		// which biscuit-go cannot print back.
		for _, dl := range role.CustomDatalog {
			trimmed := strings.TrimRight(strings.TrimSpace(dl), ";")
			if trimmed == "" {
				continue
			}
			r, err := parser.FromStringRule(trimmed)
			if err == nil {
				rules = append(rules, PolicyRule{Rule: r, Text: trimmed})
				continue
			}
			f, err2 := parser.FromStringFact(trimmed)
			if err2 == nil {
				add(f.Predicate)
				continue
			}
			warnings = append(warnings, fmt.Sprintf("Failed to parse custom Datalog rule/fact %q for role %s: rule_err=%v, fact_err=%v", dl, roleName, err, err2))
		}
	}

	return rules, warnings
}

// renderRule writes a predicate-only rule as Datalog text. An unconditional
// rule is written `head <- true` so that it stays a rule for every parser.
func renderRule(r biscuit.Rule) string {
	if len(r.Body) == 0 {
		return r.Head.String() + " <- true"
	}
	parts := make([]string, 0, len(r.Body))
	for _, p := range r.Body {
		parts = append(parts, p.String())
	}
	return r.Head.String() + " <- " + strings.Join(parts, ", ")
}

// PolicyRuleTexts is the Datalog text of rules, one entry per rule.
func PolicyRuleTexts(rules []PolicyRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Text)
	}
	return out
}

// ParseDatalogRules parses PolicyConfigGetResponse.datalog_rules. One
// unparseable entry fails the whole set: a provider that silently dropped a
// rule would enforce a policy the operator never wrote.
func ParseDatalogRules(texts []string) ([]biscuit.Rule, error) {
	rules := make([]biscuit.Rule, 0, len(texts))
	for i, text := range texts {
		r, err := parser.FromStringRule(text)
		if err != nil {
			return nil, fmt.Errorf("datalog_rules[%d] %q: %w", i, text, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}
