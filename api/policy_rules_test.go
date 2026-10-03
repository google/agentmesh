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
	"strings"
	"testing"

	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestBuildPolicyRules(t *testing.T) {
	// A node member written in the CIDv1 encoding peer.Decode also accepts;
	// the rule must carry the base58 form a token's node() fact uses.
	const nodeID = "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB"
	decoded, err := peer.Decode(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	nodeCID := peer.ToCid(decoded).String()
	if nodeCID == nodeID {
		t.Fatal("test needs a non-canonical encoding")
	}

	roles := []*PolicyRole{
		{
			Name:            "test-role",
			AllowedTargets:  []string{"*", "node:peer-abc", "custom-fact:custom-val", "legacy-peer"},
			AllowedServices: []string{"*:*", "mcp:*", "mcp:*.suffix", "mcp:prefix.*", "mcp:exact"},
			CustomDatalog: []string{
				"custom_rule($x) <- fact($x), $x > 3;",
				"custom_fact(\"hello\")",
				"not datalog at all(",
			},
		},
	}
	bindings := []*PolicyBinding{
		{
			Role:    "test-role",
			Members: []string{"sam:system:authenticated", "user:alice", "role:admin", "agent:spoofed", "node:" + nodeCID, "node:not-a-peer-id"},
		},
	}

	rules, warnings := BuildPolicyRules(roles, bindings)

	expectedStrings := map[string]bool{
		"role(\"test-role\") <- true":                                                          false,
		"role(\"test-role\") <- user(\"alice\")":                                               false,
		"role(\"test-role\") <- node(\"" + nodeID + "\")":                                      false,
		"granted_service_all_types(true) <- role(\"test-role\")":                               false,
		"granted_service_all(\"mcp\") <- role(\"test-role\")":                                  false,
		"granted_service_suffix(\"mcp\", \".suffix\") <- role(\"test-role\")":                  false,
		"granted_service_prefix(\"mcp\", \"prefix.\") <- role(\"test-role\")":                  false,
		"granted_service_set(\"mcp\", [\"exact\"]) <- role(\"test-role\")":                     false,
		"target_unrestricted(true) <- role(\"test-role\")":                                     false,
		"target_restricted(true) <- role(\"test-role\")":                                       false,
		"granted_target_set(\"node\", [\"legacy-peer\", \"peer-abc\"]) <- role(\"test-role\")": false,
		"granted_target_set(\"custom-fact\", [\"custom-val\"]) <- role(\"test-role\")":         false,
		"custom_rule($x) <- fact($x), $x > 3":                                                  false,
		"custom_fact(\"hello\") <- true":                                                       false,
	}

	for _, rule := range rules {
		if _, ok := expectedStrings[rule.Text]; !ok {
			t.Errorf("Unexpected rule generated: %q", rule.Text)
			continue
		}
		expectedStrings[rule.Text] = true
		// The text is what other implementations parse; it must round-trip here too.
		if _, err := parser.FromStringRule(rule.Text); err != nil {
			t.Errorf("rendered rule %q does not parse: %v", rule.Text, err)
		}
	}

	for k, v := range expectedStrings {
		if !v {
			t.Errorf("Expected rule was not generated: %q", k)
		}
	}

	if len(warnings) != 2 {
		t.Fatalf("warnings = %q, want one for the unparseable entry and one for the bad peer ID", warnings)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), `"node:not-a-peer-id"`) {
		t.Errorf("warnings = %q, want one naming the member that is not a peer ID", warnings)
	}

	// The text is the contract every member evaluates; it must yield the same
	// rules here as the structured form does.
	parsed, err := ParseDatalogRules(PolicyRuleTexts(rules))
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}
	if len(parsed) != len(rules) {
		t.Fatalf("parsed %d rules from text, built %d", len(parsed), len(rules))
	}
	for i := range rules {
		if parsed[i].Head.String() != rules[i].Rule.Head.String() {
			t.Errorf("rule %d head: text %s, built %s", i, parsed[i].Head.String(), rules[i].Rule.Head.String())
		}
	}
}

func TestParseDatalogRulesRejectsWholeSet(t *testing.T) {
	_, err := ParseDatalogRules([]string{`role("a") <- user("b")`, `broken(`})
	if err == nil {
		t.Fatal("expected an error for an unparseable rule")
	}
}
