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
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
)

// TestMintSkipsRuleFormCustomDatalog covers the availability half of
// custom_datalog: entries may be facts, which belong in the token, or rules,
// which are distributed to nodes and applied by their authorizer. Minting only
// ever understood facts and treated anything else as fatal, so a rule-form entry
// — which the control plane's own validator accepts and nodes consume happily —
// made every enroll and refresh for that role return 500. Refresh is the worse
// half: a later config edit would break already-enrolled nodes at renewal.
func TestMintSkipsRuleFormCustomDatalog(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID := newTestPeer(t)

	mint := func(t *testing.T, entries []string) ([]byte, error) {
		t.Helper()
		return MintBootstrapBiscuitToken(priv, peerID, "dev", time.Now().Add(time.Hour),
			[]*api.PolicyRole{{Name: "dev", CustomDatalog: entries}}, nil)
	}

	t.Run("rule-form entries are skipped, not fatal", func(t *testing.T) {
		token, err := mint(t, []string{`role("escalated") <- group("developers")`})
		if err != nil {
			t.Fatalf("minting failed on a rule-form entry, so enroll and refresh 500 for this role: %v", err)
		}
		if len(token) == 0 {
			t.Fatal("no token minted")
		}
	})

	t.Run("fact-form entries still reach the token", func(t *testing.T) {
		token, err := mint(t, []string{`region("emea")`})
		if err != nil {
			t.Fatalf("minting failed on a fact-form entry: %v", err)
		}
		if got := queryToken(t, token, pub, "region"); got != "emea" {
			t.Errorf("region fact = %q, want %q", got, "emea")
		}
	})

	// Mixing the two is the realistic config: the rule is dropped, and the fact
	// beside it must survive rather than be lost with it.
	t.Run("a rule does not discard the facts around it", func(t *testing.T) {
		token, err := mint(t, []string{
			`role("escalated") <- group("developers")`,
			`region("apac")`,
		})
		if err != nil {
			t.Fatalf("minting failed on a mixed entry list: %v", err)
		}
		if got := queryToken(t, token, pub, "region"); got != "apac" {
			t.Errorf("region fact = %q, want %q", got, "apac")
		}
	})

	t.Run("entries that are neither still fail", func(t *testing.T) {
		if _, err := mint(t, []string{`this is not datalog at all`}); err == nil {
			t.Fatal("minting accepted an unparseable entry; a typo must not be silently dropped")
		} else if !strings.Contains(err.Error(), "custom Datalog") {
			t.Errorf("error %q does not name the offending input", err)
		}
	})
}

// queryToken returns the single string argument of the named authority fact.
func queryToken(t *testing.T, tokenBytes []byte, pub ed25519.PublicKey, factName string) string {
	t.Helper()

	b, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	authorizer, err := b.Authorizer(pub, AuthorizerOptions(time.Second)...)
	if err != nil {
		t.Fatalf("Authorizer: %v", err)
	}
	// The world is only loaded once the authorizer runs, so Query before this
	// returns nothing regardless of what the token holds.
	authorizer.AddPolicy(biscuit.DefaultAllowPolicy)
	if err := authorizer.Authorize(); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return queryOne(t, authorizer, factName)
}
