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
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"

	"github.com/google/sam/api"
)

// TestAttenuationBlockFactsAreInvisibleToTheAuthorizer records a property of
// Biscuit that is easy to assume away when designing delegation on top of it.
//
// A fact added in an appended block is NOT visible to the authorizer's policy
// evaluation. Authorize() merges only the authority block's facts and rules
// into the authorizer's world; each appended block is evaluated in a world of
// its own, so its facts can satisfy that block's own checks and nothing else.
//
// That is deliberate, and it is what makes attenuation safe: if a holder could
// append facts the authorizer sees, appending would be able to *grant*
// authority rather than only narrow it, and any bearer of a token could promote
// itself.
//
// The consequence for this project: "append a block naming the principal, and
// let the far end authorize on it" does not work. A claim about who a request
// is for has to travel some other way, and it is worth being clear that doing
// so loses nothing cryptographically — whoever can append a block can append
// any block, so a token holder's claim is worth exactly what the holder is
// worth either way. Only a block signed by a third party (the principal
// itself) would change that, and biscuit-go v2 does not implement those.
func TestAttenuationBlockFactsAreInvisibleToTheAuthorizer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	builder := biscuit.NewBuilder(priv)
	mustAddAuthorityFact(t, builder, api.FactNode, biscuit.String("12D3KooWtestpeer"))
	mustAddAuthorityFact(t, builder, api.FactExpiration, biscuit.Date(time.Now().Add(time.Hour)))

	token, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	block := token.CreateBlock()
	if err := block.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "custom_claim",
		IDs:  []biscuit.Term{biscuit.String("reviewer-7.prod.acme.example")},
	}}); err != nil {
		t.Fatalf("AddFact: %v", err)
	}
	attenuated, err := token.Append(rand.Reader, block.Build())
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// The block really is in the token, signed as part of the chain...
	if attenuated.BlockCount() != 1 {
		t.Fatalf("appended block count = %d, want 1", attenuated.BlockCount())
	}

	authorizer, err := attenuated.Authorizer(pub, AuthorizerOptions(5*time.Second)...)
	if err != nil {
		t.Fatalf("Authorizer: %v", err)
	}
	authorizer.AddPolicy(biscuit.DefaultAllowPolicy)
	if err := authorizer.Authorize(); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// ...and the authority block's facts are visible, so the query itself works.
	if got := queryOne(t, authorizer, api.FactNode); got != "12D3KooWtestpeer" {
		t.Fatalf("authority fact = %q, want the peer id; the query is not measuring what it should", got)
	}

	// ...but the appended block's fact is not.
	if got := queryOne(t, authorizer, "custom_claim"); got != "" {
		t.Errorf("appended block fact is visible to the authorizer as %q."+
			" If this now passes, biscuit-go changed its scoping and delegation"+
			" by attenuation is worth revisiting", got)
	}
}

func mustAddAuthorityFact(t *testing.T, builder biscuit.Builder, name string, term biscuit.Term) {
	t.Helper()
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: name,
		IDs:  []biscuit.Term{term},
	}}); err != nil {
		t.Fatalf("AddAuthorityFact(%s): %v", name, err)
	}
}

// queryOne returns the single string argument of the named fact, or "" when the
// authorizer cannot see it.
func queryOne(t *testing.T, authorizer biscuit.Authorizer, factName string) string {
	t.Helper()

	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q", IDs: []biscuit.Term{biscuit.Variable("v")}},
		Body: []biscuit.Predicate{{Name: factName, IDs: []biscuit.Term{biscuit.Variable("v")}}},
	})
	if err != nil {
		t.Fatalf("Query(%s): %v", factName, err)
	}
	if len(facts) == 0 {
		return ""
	}
	value, ok := facts[0].IDs[0].(biscuit.String)
	if !ok {
		t.Fatalf("fact %s is not a string: %v", factName, facts[0].IDs[0])
	}
	return string(value)
}
