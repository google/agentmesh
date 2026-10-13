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

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestGetBlockIDIndexesTheAuthorityBlockAsZero pins the library behaviour that
// RequireAuthorityBinding rests on. If biscuit-go ever renumbers blocks, the
// binding check silently starts accepting appended facts again, so this has to
// fail loudly rather than be re-derived from the docs.
func TestGetBlockIDIndexesTheAuthorityBlockAsZero(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	authorityFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String("authority")},
	}}
	appendedFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String("appended")},
	}}

	builder := biscuit.NewBuilder(priv)
	if err := builder.AddAuthorityFact(authorityFact); err != nil {
		t.Fatalf("AddAuthorityFact: %v", err)
	}
	token, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	block := token.CreateBlock()
	if err := block.AddFact(appendedFact); err != nil {
		t.Fatalf("AddFact: %v", err)
	}
	attenuated, err := token.Append(rand.Reader, block.Build())
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	if id, err := attenuated.GetBlockID(authorityFact); err != nil || id != authorityBlockID {
		t.Errorf("authority fact reported block %d (err %v), want %d", id, err, authorityBlockID)
	}
	if id, err := attenuated.GetBlockID(appendedFact); err != nil || id == authorityBlockID {
		t.Errorf("appended fact reported block %d (err %v), want a non-authority block", id, err)
	}
}

// TestPeerBindingRejectsAppendedBlock is the regression test for the binding
// bypass: appending a block needs no root key, so a holder of *any* valid token
// could append node(<their own peer id>) and pass a binding check that only
// looked at GetBlockID's error. The signature chain still verifies and the
// authority facts are untouched, which is exactly what made it dangerous.
func TestPeerBindingRejectsAppendedBlock(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	victim := newTestPeer(t)
	attacker := newTestPeer(t)

	builder := biscuit.NewBuilder(priv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(victim.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(api.RoleRouter)}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
	} {
		if err := builder.AddAuthorityFact(f); err != nil {
			t.Fatalf("AddAuthorityFact: %v", err)
		}
	}
	token, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	block := token.CreateBlock()
	if err := block.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(attacker.String())},
	}}); err != nil {
		t.Fatalf("AddFact: %v", err)
	}
	attenuated, err := token.Append(rand.Reader, block.Build())
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	forged, err := attenuated.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	keys := []ed25519.PublicKey{pub}

	if err := RequireAuthorityBinding(attenuated, attacker); err == nil {
		t.Error("RequireAuthorityBinding accepted a peer bound only by an appended block")
	}
	if err := RequireAuthorityBinding(attenuated, victim); err != nil {
		t.Errorf("RequireAuthorityBinding rejected the token's real owner: %v", err)
	}

	if _, err := VerifyBiscuit(forged, attacker, keys, time.Second); err == nil {
		t.Error("VerifyBiscuit admitted a token re-bound by an appended block")
	}
	// Nor is the token accepted from its real owner: appended blocks are the
	// one place a holder can put Datalog of their own, and even a check there
	// is a rule biscuit-go runs to completion with no deadline, so Agent Mesh does
	// not evaluate any (ErrAppendedBlocks). RequireAuthorityBinding above is
	// the defence in depth behind that gate.
	if _, err := VerifyBiscuit(forged, victim, keys, time.Second); !errors.Is(err, ErrAppendedBlocks) {
		t.Errorf("VerifyBiscuit on an attenuated token: err = %v, want ErrAppendedBlocks", err)
	}
}

func newTestPeer(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IDFromPrivateKey: %v", err)
	}
	return id
}
