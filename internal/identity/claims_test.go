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
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
)

// TestEveryMappedClaimBecomesAFact walks api.OIDCClaimToFact rather than a
// hardcoded list, so a claim added to the map is covered here without anyone
// remembering to extend this test. Minting used to special-case which facts
// were multi-valued, which meant a new entry in the map was accepted by the
// map's own consumers and then silently dropped at mint time.
func TestEveryMappedClaimBecomesAFact(t *testing.T) {
	for claimKey, factName := range api.OIDCClaimToFact() {
		t.Run(claimKey, func(t *testing.T) {
			got := map[string][]string{}
			collect := func(f biscuit.Fact) error {
				for _, id := range f.IDs {
					if s, ok := id.(biscuit.String); ok {
						got[f.Name] = append(got[f.Name], string(s))
					}
				}
				return nil
			}

			// A scalar claim, which is how sub and email arrive.
			if err := translateClaimsToFacts(collect, map[string]any{claimKey: "scalar-value"}); err != nil {
				t.Fatalf("translateClaimsToFacts: %v", err)
			}
			if vals := got[factName]; len(vals) != 1 || vals[0] != "scalar-value" {
				t.Errorf("claim %q produced %s = %v, want [scalar-value]", claimKey, factName, vals)
			}

			// A list claim, which is how groups and roles arrive.
			got = map[string][]string{}
			if err := translateClaimsToFacts(collect, map[string]any{claimKey: []any{"a", "b", "a"}}); err != nil {
				t.Fatalf("translateClaimsToFacts: %v", err)
			}
			if vals := got[factName]; len(vals) != 2 {
				t.Errorf("claim %q produced %s = %v, want two deduplicated values", claimKey, factName, vals)
			}
		})
	}
}
