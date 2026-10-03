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
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/libp2p/go-libp2p/core/peer"
)

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
			value := parts[1]
			// A token carries node() in peer.ID.String() form; an operator may
			// have written any encoding peer.Decode accepts.
			if parts[0] == FactNode {
				id, err := peer.Decode(value)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("Binding member %q is not a peer ID and grants role %s to nobody: %v", m, b.Role, err))
					continue
				}
				value = id.String()
			}
			add(roleHead, biscuit.Predicate{Name: parts[0], IDs: []biscuit.Term{biscuit.String(value)}})
		}
	}

	for _, role := range roles {
		if role == nil {
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
