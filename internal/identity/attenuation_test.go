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
	"errors"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

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

func TestTARAttenuationAndSealing(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID := newTestPeer(t)
	keys := []ed25519.PublicKey{pub}
	authExp := time.Now().Add(time.Hour).Truncate(time.Second)

	rootToken, err := MintBootstrapBiscuitToken(priv, peerID, api.RoleNode, authExp, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	hop1Exp := time.Now().Add(20 * time.Minute).Truncate(time.Second)
	hop1 := &api.TaskAuthorizationRule{
		Name:        "hop-1",
		DisplayName: "Orchestrator Hop",
		ExpireTime:  timestamppb.New(hop1Exp),
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"mcp://weather", "egress://api.github.com"},
			Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather", "get_forecast"}},
		}},
	}
	att1, err := AttenuateBiscuit(rootToken, hop1)
	if err != nil {
		t.Fatalf("AttenuateBiscuit hop1: %v", err)
	}

	hop2Exp := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	hop2 := &api.TaskAuthorizationRule{
		Name:        "hop-2",
		DisplayName: "Leaf Sandbox Hop",
		ExpireTime:  timestamppb.New(hop2Exp),
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"mcp://weather"},
			Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather"}},
		}},
	}
	att2, err := AttenuateBiscuit(att1, hop2)
	if err != nil {
		t.Fatalf("AttenuateBiscuit hop2: %v", err)
	}

	sealed, err := SealBiscuit(att2)
	if err != nil {
		t.Fatalf("SealBiscuit: %v", err)
	}

	// Appending after sealing must fail.
	if _, err := AttenuateBiscuit(sealed, hop2); err == nil {
		t.Fatal("expected AttenuateBiscuit on a sealed token to fail")
	}

	// Extracting rules from the sealed token must return [hop1, hop2].
	rules, err := ExtractTaskRules(sealed)
	if err != nil {
		t.Fatalf("ExtractTaskRules on sealed token: %v", err)
	}
	if len(rules) != 2 || !proto.Equal(rules[0], hop1) || !proto.Equal(rules[1], hop2) {
		t.Fatalf("ExtractTaskRules mismatch: got %v", rules)
	}

	// VerifyBiscuitAndGetExpiry must return the effective TAR expiry (hop2Exp).
	gotExp, err := VerifyBiscuitAndGetExpiry(sealed, peerID, keys, time.Second)
	if err != nil {
		t.Fatalf("VerifyBiscuitAndGetExpiry on sealed token: %v", err)
	}
	if !gotExp.Equal(hop2Exp) {
		t.Fatalf("VerifyBiscuitAndGetExpiry = %v, want %v", gotExp, hop2Exp)
	}

	// A token with an expired TAR block must be rejected even when authority expiration is in the future.
	expiredHop := &api.TaskAuthorizationRule{
		Name:       "expired-hop",
		ExpireTime: timestamppb.New(time.Now().Add(-1 * time.Minute)),
		Rules:      []*api.TaskRule{{AllowedServices: []string{"*"}}},
	}
	attExpired, err := AttenuateBiscuit(rootToken, expiredHop)
	if err != nil {
		t.Fatalf("AttenuateBiscuit expiredHop: %v", err)
	}
	if _, err := VerifyBiscuitAndGetExpiry(attExpired, peerID, keys, time.Second); err == nil {
		t.Fatal("expected VerifyBiscuitAndGetExpiry to reject expired TAR block")
	}
}

func TestUnmarshalInboundRejectsInvalidAppendedBlocks(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID := newTestPeer(t)
	rootBytes, err := MintBootstrapBiscuitToken(priv, peerID, api.RoleNode, time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	validTAR := &api.TaskAuthorizationRule{
		Name:  "valid",
		Rules: []*api.TaskRule{{AllowedServices: []string{"mcp://calc"}}},
	}
	validFact, err := api.EncodeTARBlockFact(validTAR)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Exceeding MaxAttenuationBlocks (9 blocks)
	cur := rootBytes
	for i := 0; i < api.MaxAttenuationBlocks; i++ {
		cur, err = AttenuateBiscuit(cur, validTAR)
		if err != nil {
			t.Fatalf("append block %d: %v", i+1, err)
		}
	}
	if _, err := AttenuateBiscuit(cur, validTAR); !errors.Is(err, ErrAppendedBlocks) {
		t.Fatalf("9th AttenuateBiscuit err = %v, want ErrAppendedBlocks", err)
	}
	// Manually append a 9th block via biscuit-go and verify UnmarshalInbound rejects it.
	b8, err := biscuit.Unmarshal(cur)
	if err != nil {
		t.Fatal(err)
	}
	bb9 := b8.CreateBlock()
	_ = bb9.AddFact(validFact)
	b9, err := b8.Append(rand.Reader, bb9.Build())
	if err != nil {
		t.Fatal(err)
	}
	b9Bytes, _ := b9.Serialize()
	if _, _, err := UnmarshalInbound(b9Bytes); !errors.Is(err, ErrAppendedBlocks) {
		t.Fatalf("UnmarshalInbound on 9-block token: err = %v, want ErrAppendedBlocks", err)
	}

	// 2. Appended block with a rule
	rootB, _ := biscuit.Unmarshal(rootBytes)
	bbRule := rootB.CreateBlock()
	_ = bbRule.AddFact(validFact)
	r, _ := parser.FromStringRule(`x($a) <- tar_block($a)`)
	_ = bbRule.AddRule(r)
	bWithRule, _ := rootB.Append(rand.Reader, bbRule.Build())
	bWithRuleBytes, _ := bWithRule.Serialize()
	if _, _, err := UnmarshalInbound(bWithRuleBytes); !errors.Is(err, ErrAppendedBlocks) {
		t.Fatalf("UnmarshalInbound on block with rule: err = %v, want ErrAppendedBlocks", err)
	}

	// 3. Appended block with a check
	bbCheck := rootB.CreateBlock()
	_ = bbCheck.AddFact(validFact)
	chk, _ := parser.FromStringCheck(`check if tar_block($a)`)
	_ = bbCheck.AddCheck(chk)
	bWithCheck, _ := rootB.Append(rand.Reader, bbCheck.Build())
	bWithCheckBytes, _ := bWithCheck.Serialize()
	if _, _, err := UnmarshalInbound(bWithCheckBytes); !errors.Is(err, ErrAppendedBlocks) {
		t.Fatalf("UnmarshalInbound on block with check: err = %v, want ErrAppendedBlocks", err)
	}

	// 4. Appended block with 2 facts
	bbTwoFacts := rootB.CreateBlock()
	_ = bbTwoFacts.AddFact(validFact)
	_ = bbTwoFacts.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTARBlock,
		IDs:  []biscuit.Term{biscuit.String("extra")},
	}})
	bTwoFacts, _ := rootB.Append(rand.Reader, bbTwoFacts.Build())
	bTwoFactsBytes, _ := bTwoFacts.Serialize()
	if _, _, err := UnmarshalInbound(bTwoFactsBytes); !errors.Is(err, ErrAppendedBlocks) {
		t.Fatalf("UnmarshalInbound on block with 2 facts: err = %v, want ErrAppendedBlocks", err)
	}

	// 5. Appended block with non-string term (bytes)
	bbBytesTerm := rootB.CreateBlock()
	_ = bbBytesTerm.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTARBlock,
		IDs:  []biscuit.Term{biscuit.Bytes([]byte{1, 2, 3})},
	}})
	bBytesTerm, _ := rootB.Append(rand.Reader, bbBytesTerm.Build())
	bBytesTermBytes, _ := bBytesTerm.Serialize()
	if _, _, err := UnmarshalInbound(bBytesTermBytes); !errors.Is(err, ErrAppendedBlocks) {
		t.Fatalf("UnmarshalInbound on block with bytes term: err = %v, want ErrAppendedBlocks", err)
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
