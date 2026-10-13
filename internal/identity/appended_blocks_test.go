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
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/google/agentmesh/api"
)

// appendJoinBomb attenuates token with a block any holder can add offline: a
// few hundred facts and a 3-way self-join over them. biscuit-go runs a rule
// to completion before it checks the deadline, so evaluating this block
// pins a core for the whole budget and leaks the worker goroutine.
func appendJoinBomb(t *testing.T, token *biscuit.Biscuit, facts int) []byte {
	t.Helper()
	block := token.CreateBlock()
	for i := 0; i < facts; i++ {
		f, err := parser.FromStringFact(fmt.Sprintf(`f(%d)`, i))
		if err != nil {
			t.Fatal(err)
		}
		if err := block.AddFact(f); err != nil {
			t.Fatal(err)
		}
	}
	rule, err := parser.FromStringRule(`g($a, $b, $c) <- f($a), f($b), f($c)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := block.AddRule(rule); err != nil {
		t.Fatal(err)
	}
	bombed, err := token.Append(rand.Reader, block.Build())
	if err != nil {
		t.Fatal(err)
	}
	data, err := bombed.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Every inbound verify path must refuse a token with appended blocks before
// building an authorizer: rejection has to cost microseconds regardless of
// the block's contents, and must not leave a Datalog worker running.
func TestInboundVerifyRejectsAppendedBlocksWithoutEvaluatingThem(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID := newTestPeer(t)
	keys := []ed25519.PublicKey{pub}

	clean, err := MintBootstrapBiscuitToken(priv, peerID, api.RoleNode, time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := biscuit.Unmarshal(clean)
	if err != nil {
		t.Fatal(err)
	}
	if token.BlockCount() != 0 {
		t.Fatalf("freshly minted token reports %d appended blocks, want 0", token.BlockCount())
	}
	bombed := appendJoinBomb(t, token, 200)

	// The budget is what an attacker would pin per call; the assertion is that
	// rejection does not come anywhere near it.
	const budget = 2 * time.Second
	const fastEnough = budget / 4

	paths := map[string]func([]byte) error{
		"VerifyBiscuit": func(d []byte) error {
			_, err := VerifyBiscuit(d, peerID, keys, budget)
			return err
		},
		"VerifyBiscuitAndGetKey": func(d []byte) error {
			_, _, err := VerifyBiscuitAndGetKey(d, peerID, keys, budget)
			return err
		},
		"VerifyBiscuitAndGetExpiry": func(d []byte) error {
			_, err := VerifyBiscuitAndGetExpiry(d, peerID, keys, budget)
			return err
		},
		"VerifyAndExtractPeerID": func(d []byte) error {
			_, err := VerifyAndExtractPeerID(keys, d, budget)
			return err
		},
		"VerifyExpiredAndExtractPeerID": func(d []byte) error {
			_, err := VerifyExpiredAndExtractPeerID(keys, d, budget)
			return err
		},
		"VerifyBiscuitRole": func(d []byte) error {
			return VerifyBiscuitRole(d, pub, api.RoleNode, budget)
		},
	}

	for name, verify := range paths {
		t.Run(name, func(t *testing.T) {
			if err := verify(clean); err != nil {
				t.Fatalf("clean token rejected: %v", err)
			}

			before := runtime.NumGoroutine()
			start := time.Now()
			err := verify(bombed)
			took := time.Since(start)
			if err == nil {
				t.Fatal("token with an appended block accepted")
			}
			if !errors.Is(err, ErrAppendedBlocks) {
				t.Errorf("err = %v, want ErrAppendedBlocks", err)
			}
			if took > fastEnough {
				t.Errorf("rejection took %v; the block was evaluated", took)
			}
			// Give a leaked worker a moment to show up before counting.
			time.Sleep(20 * time.Millisecond)
			if after := runtime.NumGoroutine(); after > before {
				t.Errorf("goroutines grew %d -> %d; a Datalog worker was left running", before, after)
			}
		})
	}
}
