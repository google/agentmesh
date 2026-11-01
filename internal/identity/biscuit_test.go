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
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// testTimeout bounds datalog evaluation in these tests. It is deliberately
// generous: WithMaxDuration is a wall-clock bound, and under -race on an
// oversubscribed CI runner a goroutine can be starved long past a sub-second
// budget purely by scheduling. No test here asserts anything about timing.
const testTimeout = time.Minute

func TestVerifyBiscuit_Expiration(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		expiry      time.Time
		expectError bool
	}{
		{
			name:        "Valid unexpired token",
			expiry:      time.Now().Add(1 * time.Hour),
			expectError: false,
		},
		{
			name:        "Expired token",
			expiry:      time.Now().Add(-1 * time.Hour),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &oidc.IDToken{
				Expiry: tt.expiry,
			}
			claims := jwt.MapClaims{
				"roles": []any{"admin"},
			}

			biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, []string{"admin"}, nil, nil)
			if err != nil {
				t.Fatalf("MintBiscuitToken failed: %v", err)
			}

			_, err = VerifyBiscuit(biscuitData, dummyPeer, []ed25519.PublicKey{pub}, testTimeout)
			if tt.expectError && err == nil {
				t.Errorf("Expected error due to expiration, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}
		})
	}
}

func TestMintBiscuitToken_ClaimsTranslation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}

	claims := jwt.MapClaims{
		"sub":    "user-12345",
		"email":  "agent@example.com",
		"groups": []any{"beta-testers", "engineering"},
	}

	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, nil, nil, nil)
	if err != nil {
		t.Fatalf("Failed to mint biscuit: %v", err)
	}

	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		t.Fatalf("Failed to unmarshal biscuit: %v", err)
	}

	authorizer, err := b.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(testTimeout)))
	if err != nil {
		t.Fatalf("Failed to get authorizer: %v", err)
	}

	// Verify user("user-12345") fact is present
	checkUser := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "user", IDs: []biscuit.Term{biscuit.String("user-12345")}},
			},
		},
	}}
	authorizer.AddCheck(checkUser)

	// Verify email("agent@example.com") fact is present
	checkEmail := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "email", IDs: []biscuit.Term{biscuit.String("agent@example.com")}},
			},
		},
	}}
	authorizer.AddCheck(checkEmail)

	// Verify group("beta-testers") fact is present
	checkGroupBeta := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "group", IDs: []biscuit.Term{biscuit.String("beta-testers")}},
			},
		},
	}}
	authorizer.AddCheck(checkGroupBeta)

	// Verify group("engineering") fact is present
	checkGroupEng := biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: "group", IDs: []biscuit.Term{biscuit.String("engineering")}},
			},
		},
	}}
	authorizer.AddCheck(checkGroupEng)

	authorizer.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{},
		},
	}, Kind: biscuit.PolicyKindAllow})

	if err := authorizer.Authorize(); err != nil {
		t.Errorf("Authorization/Checks failed: %v\nWorld:\n%s", err, authorizer.PrintWorld())
	}
}

func TestVerifyBiscuit_Concurrent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}
	claims := jwt.MapClaims{
		"sub":   "user-123",
		"roles": []any{"admin"},
	}

	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, []string{"admin"}, nil, nil)
	if err != nil {
		t.Fatalf("MintBiscuitToken failed: %v", err)
	}

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, err := VerifyBiscuit(biscuitData, dummyPeer, []ed25519.PublicKey{pub}, testTimeout)
				if err != nil {
					t.Errorf("Concurrent verification failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestMintBiscuitToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}

	claims := jwt.MapClaims{
		"sub":    "test-user",
		"groups": []any{"group1", "group2"},
		"roles":  []any{"admin", "user"},
	}
	biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, []string{"admin", "user"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := b.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(testTimeout)))
	if err != nil {
		t.Fatal(err)
	}

	// Add policies to check that facts were added correctly.
	authorizer.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
			Body: []biscuit.Predicate{
				{Name: "user", IDs: []biscuit.Term{biscuit.String("test-user")}},
				{Name: "group", IDs: []biscuit.Term{biscuit.String("group1")}},
				{Name: "group", IDs: []biscuit.Term{biscuit.String("group2")}},
				{Name: "role", IDs: []biscuit.Term{biscuit.String("admin")}},
				{Name: "role", IDs: []biscuit.Term{biscuit.String("user")}},
			},
		},
	}, Kind: biscuit.PolicyKindAllow})

	if err := authorizer.Authorize(); err != nil {
		t.Errorf("Expected facts to be present, got error: %v\nWorld:\n%s", err, authorizer.PrintWorld())
	}
}

func TestMintBiscuitToken_VariousClaimsTypes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}

	tests := []struct {
		name           string
		rolesClaim     any
		groupsClaim    any
		expectedRoles  []string
		expectedGroups []string
	}{
		{
			name:           "String slice (standard go code paths)",
			rolesClaim:     []string{"admin", "eng-role"},
			groupsClaim:    []string{"eng-group", "beta"},
			expectedRoles:  []string{"admin", "eng-role"},
			expectedGroups: []string{"eng-group", "beta"},
		},
		{
			name:           "Interface slice (standard JSON unmarshalled jwt paths)",
			rolesClaim:     []any{"admin", "eng-role"},
			groupsClaim:    []any{"eng-group", "beta"},
			expectedRoles:  []string{"admin", "eng-role"},
			expectedGroups: []string{"eng-group", "beta"},
		},
		{
			name:           "Single string claims",
			rolesClaim:     "admin",
			groupsClaim:    "eng-group",
			expectedRoles:  []string{"admin"},
			expectedGroups: []string{"eng-group"},
		},
		{
			name:           "Missing or nil claims",
			rolesClaim:     nil,
			groupsClaim:    nil,
			expectedRoles:  nil,
			expectedGroups: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			if tt.rolesClaim != nil {
				claims["roles"] = tt.rolesClaim
			}
			if tt.groupsClaim != nil {
				claims["groups"] = tt.groupsClaim
			}

			biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, tt.expectedRoles, nil, nil)
			if err != nil {
				t.Fatalf("MintBiscuitToken failed: %v", err)
			}

			b, err := biscuit.Unmarshal(biscuitData)
			if err != nil {
				t.Fatalf("Unmarshal biscuit failed: %v", err)
			}

			authorizer, err := b.Authorizer(pub, AuthorizerOptions(testTimeout)...)
			if err != nil {
				t.Fatalf("Authorizer failed: %v", err)
			}

			for _, r := range tt.expectedRoles {
				authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
					{
						Body: []biscuit.Predicate{
							{Name: "role", IDs: []biscuit.Term{biscuit.String(r)}},
						},
					},
				}})
			}

			for _, g := range tt.expectedGroups {
				authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
					{
						Body: []biscuit.Predicate{
							{Name: "group", IDs: []biscuit.Term{biscuit.String(g)}},
						},
					},
				}})
			}

			authorizer.AddPolicy(biscuit.Policy{Queries: []biscuit.Rule{
				{
					Head: biscuit.Predicate{Name: "allow", IDs: []biscuit.Term{}},
					Body: []biscuit.Predicate{},
				},
			}, Kind: biscuit.PolicyKindAllow})

			if err := authorizer.Authorize(); err != nil {
				t.Errorf("Verification failed for case %s: %v\nWorld:\n%s", tt.name, err, authorizer.PrintWorld())
			}
		})
	}
}

func TestMintBiscuitToken_WithPolicyRoles(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	token := &oidc.IDToken{
		Expiry: time.Now().Add(1 * time.Hour),
	}
	claims := jwt.MapClaims{"sub": "alice"}

	policyRoles := []*api.PolicyRole{
		{
			Name:            "data-scientist",
			AllowedServices: []string{"mcp://calculator"},
			AllowedTargets:  []string{"group:backend"},
			CustomDatalog:   []string{"right(\"data:read\");"},
		},
	}

	t.Run("Mint with matching policy role", func(t *testing.T) {
		biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, []string{"data-scientist"}, policyRoles, nil)
		if err != nil {
			t.Fatalf("MintBiscuitToken failed: %v", err)
		}

		b, err := biscuit.Unmarshal(biscuitData)
		if err != nil {
			t.Fatalf("Unmarshal biscuit failed: %v", err)
		}

		authorizer, err := b.Authorizer(pub, AuthorizerOptions(testTimeout)...)
		if err != nil {
			t.Fatalf("Authorizer failed: %v", err)
		}

		// Verify granted_service_exact, granted_target_exact, and custom datalog right fact
		authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
			{Body: []biscuit.Predicate{{Name: api.FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String("mcp"), biscuit.String("calculator")}}}},
			{Body: []biscuit.Predicate{{Name: api.FactGrantedTargetExact, IDs: []biscuit.Term{biscuit.String("group"), biscuit.String("backend")}}}},
			{Body: []biscuit.Predicate{{Name: api.FactRight, IDs: []biscuit.Term{biscuit.String("data:read")}}}},
		}})
		authorizer.AddPolicy(api.AllowIfTruePolicy)

		if err := authorizer.Authorize(); err != nil {
			t.Errorf("Expected policy facts to be present in Biscuit, got error: %v\nWorld:\n%s", err, authorizer.PrintWorld())
		}
	})

	t.Run("Mint with unmapped role when policy exists", func(t *testing.T) {
		biscuitData, _, err := MintBiscuitToken(priv, claims, token, dummyPeer, token.Expiry, []string{"unmapped-role"}, policyRoles, nil)
		if err != nil {
			t.Fatalf("MintBiscuitToken failed: %v", err)
		}

		b, err := biscuit.Unmarshal(biscuitData)
		if err != nil {
			t.Fatalf("Unmarshal biscuit failed: %v", err)
		}

		authorizer, err := b.Authorizer(pub, AuthorizerOptions(testTimeout)...)
		if err != nil {
			t.Fatalf("Authorizer failed: %v", err)
		}

		// Verify target_unrestricted and granted_service_all_types are NOT present
		authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
			{Body: []biscuit.Predicate{api.MarkerFact(api.FactTargetUnrestricted).Predicate}},
		}})
		authorizer.AddPolicy(api.AllowIfTruePolicy)

		if err := authorizer.Authorize(); err == nil {
			t.Errorf("Expected target_unrestricted check to fail for unmapped role, but it succeeded\nWorld:\n%s", authorizer.PrintWorld())
		}
	})
}

func TestMintBiscuitToken_LabelFacts(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer := peer.ID("dummy-peer-region")

	labels := map[string]string{"region": "eu-de", "team": "platform"}
	biscuitData, err := MintBootstrapBiscuitToken(priv, dummyPeer, api.RoleNode, time.Now().Add(1*time.Hour), nil, labels)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken failed: %v", err)
	}
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		t.Fatalf("Unmarshal biscuit failed: %v", err)
	}

	// Every declared label is present as its own fact.
	for k, v := range labels {
		authorizer, err := b.Authorizer(pub, AuthorizerOptions(testTimeout)...)
		if err != nil {
			t.Fatalf("Authorizer failed: %v", err)
		}
		authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
			{Body: []biscuit.Predicate{{Name: api.FactLabel, IDs: []biscuit.Term{biscuit.String(k), biscuit.String(v)}}}},
		}})
		authorizer.AddPolicy(api.AllowIfTruePolicy)
		if err := authorizer.Authorize(); err != nil {
			t.Errorf("expected label(%q, %q) fact, got error: %v", k, v, err)
		}
	}

	// No label facts when minted without any claims.
	noLabelsData, err := MintBootstrapBiscuitToken(priv, dummyPeer, api.RoleNode, time.Now().Add(1*time.Hour), nil, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken failed: %v", err)
	}
	b2, err := biscuit.Unmarshal(noLabelsData)
	if err != nil {
		t.Fatalf("Unmarshal biscuit failed: %v", err)
	}
	authorizer, err := b2.Authorizer(pub, AuthorizerOptions(testTimeout)...)
	if err != nil {
		t.Fatalf("Authorizer failed: %v", err)
	}
	authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
		{Body: []biscuit.Predicate{{Name: api.FactLabel, IDs: []biscuit.Term{biscuit.Variable("k"), biscuit.Variable("v")}}}},
	}})
	authorizer.AddPolicy(api.AllowIfTruePolicy)
	if err := authorizer.Authorize(); err == nil {
		t.Error("expected no label facts for an unclaimed node, but check passed")
	}
}

func TestVerifyAndExtractPeerID_MultipleTrustedKeys(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	biscuitData, err := MintBootstrapBiscuitToken(priv2, dummyPeer, api.RoleNode, time.Now().Add(1*time.Hour), nil, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken failed: %v", err)
	}

	// trustedPublicKeys has pub1 first, pub2 second (pub2 is the signer)
	trustedKeys := []ed25519.PublicKey{pub1, pub2}

	extractedPeer, err := VerifyAndExtractPeerID(trustedKeys, biscuitData, testTimeout)
	if err != nil {
		t.Fatalf("VerifyAndExtractPeerID failed with multiple trusted keys: %v", err)
	}

	if extractedPeer != dummyPeer {
		t.Errorf("expected peer ID %s, got %s", dummyPeer, extractedPeer)
	}
}

// TestExtractPeerIDExpiry pins that adding the expiration check still rejects an
// expired token even though neither variant adds a policy, i.e. that a failed
// check outranks ErrNoMatchingPolicy.
func TestExtractPeerIDExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}
	trustedKeys := []ed25519.PublicKey{pub}

	fresh, err := MintBootstrapBiscuitToken(priv, dummyPeer, api.RoleNode, time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := MintBootstrapBiscuitToken(priv, dummyPeer, api.RoleNode, time.Now().Add(-time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyAndExtractPeerID(trustedKeys, fresh, testTimeout); err != nil {
		t.Errorf("unexpired token rejected: %v", err)
	}
	if _, err := VerifyAndExtractPeerID(trustedKeys, expired, testTimeout); err == nil {
		t.Error("expired token accepted by the expiry-enforcing variant")
	}

	// The refresh flow depends on the exempt variant staying permissive.
	if got, err := VerifyExpiredAndExtractPeerID(trustedKeys, expired, testTimeout); err != nil {
		t.Errorf("expired token rejected by the refresh variant: %v", err)
	} else if got != dummyPeer {
		t.Errorf("got peer %s, want %s", got, dummyPeer)
	}
}

func TestVerifyBiscuitRole_TimeoutIsHonored(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privNode, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	dummyPeer, err := peer.IDFromPrivateKey(privNode)
	if err != nil {
		t.Fatal(err)
	}

	biscuitData, err := MintBootstrapBiscuitToken(priv, dummyPeer, api.RoleRouter, time.Now().Add(1*time.Hour), nil, nil)
	if err != nil {
		t.Fatalf("MintBootstrapBiscuitToken failed: %v", err)
	}

	// A zero timeout must fall back to the generous default, not to the 2ms
	// biscuit-go default which spuriously fails under load.
	if err := VerifyBiscuitRole(biscuitData, pub, api.RoleRouter, 0); err != nil {
		t.Errorf("VerifyBiscuitRole with zero timeout failed: %v", err)
	}

	// An explicit timeout must reach the Datalog world.
	err = VerifyBiscuitRole(biscuitData, pub, api.RoleRouter, time.Nanosecond)
	if !errors.Is(err, datalog.ErrWorldRunLimitTimeout) {
		t.Errorf("expected datalog timeout error, got %v", err)
	}

	// Verification keeps the reason too, so a caller can tell a world that
	// ran out of time from a credential no trusted key signed.
	_, _, err = VerifyBiscuitAndGetKey(biscuitData, dummyPeer, []ed25519.PublicKey{pub}, time.Nanosecond)
	if !errors.Is(err, datalog.ErrWorldRunLimitTimeout) {
		t.Errorf("VerifyBiscuitAndGetKey with a 1ns timeout = %v, want an error wrapping %v", err, datalog.ErrWorldRunLimitTimeout)
	}
}

// TestRequireRole covers the role gate every router-only path shares. The
// appended-block case is the one that matters: appending needs no root key, so
// a node could otherwise promote itself to router by attenuating its own token.
func TestRequireRole(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data, err := MintBootstrapBiscuitToken(priv, newTestPeer(t), api.RoleNode, time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := biscuit.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}

	if err := RequireRole(token, pub, api.RoleNode, testTimeout); err != nil {
		t.Errorf("granted role rejected: %v", err)
	}
	if err := RequireRole(token, pub, api.RoleRouter, testTimeout); err == nil {
		t.Error("missing role accepted")
	}
	if err := RequireRole(token, otherPub, api.RoleNode, testTimeout); err == nil {
		t.Error("token accepted under a key that did not sign it")
	}

	block := token.CreateBlock()
	if err := block.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactRole,
		IDs:  []biscuit.Term{biscuit.String(api.RoleRouter)},
	}}); err != nil {
		t.Fatal(err)
	}
	promoted, err := token.Append(rand.Reader, block.Build())
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireRole(promoted, pub, api.RoleRouter, testTimeout); err == nil {
		t.Error("role from an appended block satisfied the check")
	}
}

// TestVerifyBiscuitAndGetExpiry pins the instant the peer-admission cache is
// keyed on: the token's own expiration, and with several the earliest, since
// that is the one the expiry check starts failing on.
func TestVerifyBiscuitAndGetExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID := newTestPeer(t)
	keys := []ed25519.PublicKey{pub}

	mint := func(expirations ...time.Time) []byte {
		builder := biscuit.NewBuilder(priv)
		mustAddAuthorityFact(t, builder, api.FactNode, biscuit.String(peerID.String()))
		for _, e := range expirations {
			mustAddAuthorityFact(t, builder, api.FactExpiration, biscuit.Date(e))
		}
		token, err := builder.Build()
		if err != nil {
			t.Fatal(err)
		}
		data, err := token.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	// Biscuit dates are whole seconds.
	sameInstant := func(got, want time.Time) bool { return got.Sub(want).Abs() <= time.Second }

	soon := time.Now().Add(time.Hour)
	later := soon.Add(time.Hour)

	got, err := VerifyBiscuitAndGetExpiry(mint(soon), peerID, keys, testTimeout)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if !sameInstant(got, soon) {
		t.Errorf("expiry = %v, want %v", got, soon)
	}

	got, err = VerifyBiscuitAndGetExpiry(mint(later, soon), peerID, keys, testTimeout)
	if err != nil {
		t.Fatalf("token with two expirations rejected: %v", err)
	}
	if !sameInstant(got, soon) {
		t.Errorf("expiry = %v, want the earlier %v", got, soon)
	}

	if _, err := VerifyBiscuitAndGetExpiry(mint(time.Now().Add(-time.Hour)), peerID, keys, testTimeout); err == nil {
		t.Error("expired token admitted")
	}
	if _, err := VerifyBiscuitAndGetExpiry(mint(), peerID, keys, testTimeout); err == nil {
		t.Error("token without an expiration admitted")
	}
	if _, err := VerifyBiscuitAndGetExpiry(mint(soon), newTestPeer(t), keys, testTimeout); err == nil {
		t.Error("token bound to another peer admitted")
	}
}

// A role's allowed_publish is minted as granted_publish_* facts, which
// RequirePublish decides with api.PublishPolicies: the same patterns as
// allowed_services, and the same matching. A delegated subject gets none:
// it is a caller the actor speaks for, not a member that serves.
func TestMintBiscuitToken_PublishFacts(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := peer.ID("publisher")
	roles := []*api.PolicyRole{{Name: "publisher", AllowedPublish: []string{"mcp://calc", "mcp://weather", "inference://*", "a2a://*.agents", "mcp://tools.*"}}}
	data, err := MintBootstrapBiscuitToken(priv, p, "publisher", time.Now().Add(time.Hour), roles, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := biscuit.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		svcType, svcName string
		granted          bool
	}{
		{"mcp", "calc", true},
		{"mcp", "weather", true},
		{"mcp", "clock", false},
		{"inference", "anything", true},
		{"a2a", "helper.agents", true},
		{"a2a", "helper", false},
		{"mcp", "tools.v2", true},
		{"mcp", "tools", false},
		{"egress", "api.github.com", false},
	} {
		err := RequirePublish(b, pub, tc.svcType, tc.svcName, nil, testTimeout)
		if (err == nil) != tc.granted {
			t.Errorf("RequirePublish(%s://%s) = %v, want granted %v", tc.svcType, tc.svcName, err, tc.granted)
		}
	}

	// A refusal keeps the authorizer's reason: no policy matched is not the
	// same as a Datalog world that ran out of time on a granted service.
	if err := RequirePublish(b, pub, "mcp", "clock", nil, testTimeout); !errors.Is(err, biscuit.ErrNoMatchingPolicy) {
		t.Errorf("RequirePublish(mcp://clock) = %v, want an error wrapping %v", err, biscuit.ErrNoMatchingPolicy)
	}
	if err := RequirePublish(b, pub, "mcp", "calc", nil, time.Nanosecond); !errors.Is(err, datalog.ErrWorldRunLimitTimeout) {
		t.Errorf("RequirePublish(mcp://calc) with a 1ns timeout = %v, want an error wrapping %v", err, datalog.ErrWorldRunLimitTimeout)
	}

	none, err := MintBootstrapBiscuitToken(priv, p, "publisher", time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := biscuit.Unmarshal(none)
	if err := RequirePublish(nb, pub, "mcp", "calc", nil, testTimeout); err == nil {
		t.Error("a credential minted under no policy role grants publishing nothing")
	}

	// The mesh policy rules reach a verifier before the holder's credential
	// is minted again: a credential carrying only role("publisher") is
	// granted what the current policy gives that role, and only that.
	rules, warnings := api.BuildPolicyRules(roles, nil)
	if len(warnings) != 0 {
		t.Fatalf("BuildPolicyRules warnings: %v", warnings)
	}
	parsed, err := api.ParseDatalogRules(api.PolicyRuleTexts(rules))
	if err != nil {
		t.Fatal(err)
	}
	if err := RequirePublish(nb, pub, "mcp", "calc", parsed, testTimeout); err != nil {
		t.Errorf("the policy rules grant role publisher mcp://calc, RequirePublish = %v", err)
	}
	if err := RequirePublish(nb, pub, "mcp", "clock", parsed, testTimeout); err == nil {
		t.Error("the policy rules do not grant role publisher mcp://clock, RequirePublish = nil")
	}

	delegated, err := MintDelegatedBiscuitToken(priv, jwt.MapClaims{"sub": "user"}, p, time.Now().Add(time.Hour), []string{"publisher"}, roles, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := biscuit.Unmarshal(delegated)
	if err := RequirePublish(db, pub, "mcp", "calc", nil, testTimeout); err == nil {
		t.Error("a delegated credential grants publishing nothing")
	}
}
