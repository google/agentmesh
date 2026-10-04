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

package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/ratelimit"
	lru "github.com/hashicorp/golang-lru/v2"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockConn struct {
	remotePeer peer.ID
}

func (c *mockConn) RemotePeer() peer.ID                               { return c.remotePeer }
func (c *mockConn) LocalPeer() peer.ID                                { return "" }
func (c *mockConn) LocalMultiaddr() multiaddr.Multiaddr               { return nil }
func (c *mockConn) RemoteMultiaddr() multiaddr.Multiaddr              { return nil }
func (c *mockConn) Stat() network.ConnStats                           { return network.ConnStats{} }
func (c *mockConn) Scope() network.ConnScope                          { return nil }
func (c *mockConn) Close() error                                      { return nil }
func (c *mockConn) CloseWithError(network.ConnErrorCode) error        { return nil }
func (c *mockConn) ConnState() network.ConnectionState                { return network.ConnectionState{} }
func (c *mockConn) GetStreams() []network.Stream                      { return nil }
func (c *mockConn) ID() string                                        { return "" }
func (c *mockConn) IsClosed() bool                                    { return false }
func (c *mockConn) NewStream(context.Context) (network.Stream, error) { return nil, nil }
func (c *mockConn) RemotePublicKey() crypto.PubKey                    { return nil }
func (c *mockConn) As(interface{}) bool                               { return false }

type mockStream struct {
	r        io.Reader
	w        io.Writer
	protocol protocol.ID
	conn     network.Conn
}

func (s *mockStream) Read(p []byte) (n int, err error)             { return s.r.Read(p) }
func (s *mockStream) Write(p []byte) (n int, err error)            { return s.w.Write(p) }
func (s *mockStream) Close() error                                 { return nil }
func (s *mockStream) Protocol() protocol.ID                        { return s.protocol }
func (s *mockStream) ID() string                                   { return "" }
func (s *mockStream) SetProtocol(protocol.ID) error                { return nil }
func (s *mockStream) CloseRead() error                             { return nil }
func (s *mockStream) CloseWrite() error                            { return nil }
func (s *mockStream) Reset() error                                 { return nil }
func (s *mockStream) ResetWithError(network.StreamErrorCode) error { return nil }
func (s *mockStream) SetDeadline(time.Time) error                  { return nil }
func (s *mockStream) SetReadDeadline(time.Time) error              { return nil }
func (s *mockStream) SetWriteDeadline(time.Time) error             { return nil }
func (s *mockStream) Stat() network.Stats                          { return network.Stats{} }
func (s *mockStream) Conn() network.Conn                           { return s.conn }
func (s *mockStream) Scope() network.StreamScope                   { return nil }

func TestAuthorize(t *testing.T) {
	dir, err := os.MkdirTemp("", "middleware-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = store.Close()
	}()
	golog.SetAllLoggers(golog.LevelDebug)

	// Create a biscuit token
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	builder := biscuit.NewBuilder(priv)
	_ = builder.AddAuthorityFact(api.MarkerFact(api.FactTargetUnrestricted))
	dummyPeer := peer.ID("dummy-peer")

	// Bind to peer
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Add client_peer_id for replay check
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}

	// Add fact to match baseline rule
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactGrantedServiceExact,
		IDs:  []biscuit.Term{biscuit.String(api.SystemNamespace), biscuit.String("/test/proto")},
	}})
	if err != nil {
		t.Fatal(err)
	}

	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
	}})
	if err != nil {
		t.Fatal(err)
	}

	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		Store:          store,
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	req := RequestContext{
		PeerID:   dummyPeer,
		Protocol: "/test/proto",
	}

	if err := node.Authorize(tokenBytes, req, pub); err != nil {
		t.Fatalf("Authorize failed: %v", err)
	}
}

// TestAuthorizeRejectsExpiredBiscuit reproduces #296: SamNode.Authorize did not
// inject the time(now) fact nor the ControlPlaneStaticTimeCheck, so an expired
// biscuit that would be rejected by identity.VerifyBiscuit was still accepted
// on the node dataplane.
func TestAuthorizeRejectsExpiredBiscuit(t *testing.T) {
	dir, err := os.MkdirTemp("", "middleware-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = store.Close()
	}()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dummyPeer := peer.ID("dummy-peer")

	builder := biscuit.NewBuilder(priv)
	_ = builder.AddAuthorityFact(api.MarkerFact(api.FactTargetUnrestricted))
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactClientPeerID,
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactGrantedServiceExact,
		IDs:  []biscuit.Term{biscuit.String(api.SystemNamespace), biscuit.String("/test/proto")},
	}})
	// Expired an hour ago.
	_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(-time.Hour))},
	}})

	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		Store:          store,
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	req := RequestContext{
		PeerID:   dummyPeer,
		Protocol: "/test/proto",
	}

	if err := node.Authorize(tokenBytes, req, pub); err == nil {
		t.Fatal("Authorize succeeded with an expired biscuit; expiration is not enforced on the node dataplane")
	}
}

// TestAuthorizeRejectsAppendedPeerBinding covers the dataplane half of the
// binding bypass. Appending a block needs no root key, so a peer holding any
// valid token could append node(<its own peer id>) and connect under its own
// libp2p key; the binding must only honour the authority block.
func TestAuthorizeRejectsAppendedPeerBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	victim := peer.ID("victim-peer")
	attacker := peer.ID("attacker-peer")

	builder := biscuit.NewBuilder(priv)
	for _, f := range []biscuit.Fact{
		api.MarkerFact(api.FactTargetUnrestricted),
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(victim.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(attacker.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String(api.SystemNamespace), biscuit.String("/test/proto")}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
	} {
		if err := builder.AddAuthorityFact(f); err != nil {
			t.Fatal(err)
		}
	}

	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	block := b.CreateBlock()
	if err := block.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(attacker.String())},
	}}); err != nil {
		t.Fatal(err)
	}
	attenuated, err := b.Append(cryptorand.Reader, block.Build())
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes, err := attenuated.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	req := RequestContext{PeerID: attacker, Protocol: "/test/proto"}
	if err := node.Authorize(tokenBytes, req, pub); err == nil {
		t.Fatal("Authorize accepted a token re-bound to the caller by an appended block")
	}
}

func TestBaselineRules(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dummyPeer := peer.ID("dummy-peer")

	tests := []struct {
		name          string
		mintToken     func(t *testing.T, builder biscuit.Builder)
		protocol      string
		target        string
		expectSuccess bool
	}{
		{
			name: "Baseline Rule 1: Exact Match",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp", "test_tool")`, api.FactGrantedServiceExact)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "test_tool",
			target:        "mcp://test_tool",
			expectSuccess: true,
		},
		{
			name: "Baseline Rule 1b: Exact Set Match",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp", ["other_tool", "test_tool"])`, api.FactGrantedServiceSet)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "test_tool",
			target:        "mcp://test_tool",
			expectSuccess: true,
		},
		{
			name: "Baseline Rule 1c: Exact Set Rejection for non-member",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp", ["other_tool"])`, api.FactGrantedServiceSet)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "test_tool",
			target:        "mcp://test_tool",
			expectSuccess: false,
		},
		{
			name: "Baseline Rule 2: Global Wildcard",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s(true)`, api.FactGrantedServiceAllTypes)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "anything",
			target:        "mcp://anything",
			expectSuccess: true,
		},

		{
			name: "Baseline Rule 4: Type Wildcard",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp")`, api.FactGrantedServiceAll)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "test_tool",
			target:        "mcp://test_tool",
			expectSuccess: true,
		},
		{
			name: "Baseline Rule Rejection: Type Wildcard does not allow other types",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp")`, api.FactGrantedServiceAll)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
			},
			protocol:      "test_tool",
			target:        "system://test_tool",
			expectSuccess: false,
		},
		{
			name: "Baseline Replay Check Rejection: mismatched peer ID",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				factStr := fmt.Sprintf(`%s("mcp", "test_tool")`, api.FactGrantedServiceExact)
				fact, _ := parser.FromStringFact(factStr)
				_ = builder.AddAuthorityFact(fact)
				// deliberately add a different client_peer_id than the connection peer ID
				err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactClientPeerID,
					IDs:  []biscuit.Term{biscuit.String("different-peer")},
				}})
			},
			protocol:      "test_tool",
			target:        "mcp://test_tool",
			expectSuccess: false, // Should fail the connection_peer_id check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			_ = builder.AddAuthorityFact(api.MarkerFact(api.FactTargetUnrestricted))
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: "node",
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactExpiration,
				IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
			}})

			// For the happy paths, add the matching client_peer_id
			if tt.name != "Baseline Replay Check Rejection: mismatched peer ID" {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: "client_peer_id",
					IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
				}})
			}

			tt.mintToken(t, builder)

			b, _ := builder.Build()
			tokenBytes, _ := b.Serialize()

			node := &SamNode{
				trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
				BiscuitTimeout: 500 * time.Millisecond,
			}

			req := RequestContext{
				PeerID:   dummyPeer,
				Protocol: tt.protocol,
				Target:   tt.target,
			}

			err = node.Authorize(tokenBytes, req, pub)
			if tt.expectSuccess && err != nil {
				t.Errorf("expected success, got error: %v", err)
			} else if !tt.expectSuccess && err == nil {
				t.Error("expected failure, got success")
			}
		})
	}
}

func TestEnterprisePolicyEngine(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dummyPeer := peer.ID("dummy-peer")

	tests := []struct {
		name            string
		mintToken       func(t *testing.T, builder biscuit.Builder)
		operation       string
		localPolicyYAML string
		expectSuccess   bool
	}{
		{
			name: "Case 1 (Happy Path)",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				fact, err := parser.FromStringFact(fmt.Sprintf(`%s(%q, "query_db")`, api.FactGrantedServiceExact, api.SystemNamespace))
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatal(err)
				}
			},
			operation:     "query_db",
			expectSuccess: true,
		},
		{
			name: "Case 2 (Unauthorized Tool)",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				fact, err := parser.FromStringFact(fmt.Sprintf(`%s(%q, "query_db")`, api.FactGrantedServiceExact, api.SystemNamespace))
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatal(err)
				}
			},
			operation:     "reboot_server",
			expectSuccess: false,
		},
		{
			name: "Case 3 (Wildcard Access)",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				fact, err := parser.FromStringFact(fmt.Sprintf(`%s(true)`, api.FactGrantedServiceAllTypes))
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact); err != nil {
					t.Fatal(err)
				}
			},
			operation:     "anything",
			expectSuccess: true,
		},
		{
			name: "Case 4 (Local Attenuation Override)",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				fact1, err := parser.FromStringFact(fmt.Sprintf(`%s(true)`, api.FactGrantedServiceAllTypes))
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact1); err != nil {
					t.Fatal(err)
				}
				fact2, err := parser.FromStringFact(`user("alice")`)
				if err != nil {
					t.Fatal(err)
				}
				if err := builder.AddAuthorityFact(fact2); err != nil {
					t.Fatal(err)
				}
			},
			operation: "query_db",
			localPolicyYAML: `
version: "v1alpha1"
attenuation:
  policies:
    - 'deny if user("alice");'
`,
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			_ = builder.AddAuthorityFact(api.MarkerFact(api.FactTargetUnrestricted))

			err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactNode,
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			if err != nil {
				t.Fatal(err)
			}

			// Add client_peer_id for replay check
			err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactClientPeerID,
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			if err != nil {
				t.Fatal(err)
			}

			err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactExpiration,
				IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
			}})
			if err != nil {
				t.Fatal(err)
			}

			tt.mintToken(t, builder)

			b, err := builder.Build()
			if err != nil {
				t.Fatal(err)
			}

			tokenBytes, err := b.Serialize()
			if err != nil {
				t.Fatal(err)
			}

			var nodeConfigComplete *NodeConfigComplete
			if tt.localPolicyYAML != "" {
				dir := t.TempDir()
				policyFile := filepath.Join(dir, "local_policy.yaml")
				if err := os.WriteFile(policyFile, []byte(tt.localPolicyYAML), 0644); err != nil {
					t.Fatal(err)
				}
				var err error
				nodeConfigComplete, err = LoadNodeConfig(policyFile)
				if err != nil {
					t.Fatalf("failed to load local policy: %v", err)
				}
			}

			node := &SamNode{
				trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
				nodeConfig:     nodeConfigComplete,
				BiscuitTimeout: 500 * time.Millisecond,
			}

			req := RequestContext{
				PeerID:   dummyPeer,
				Protocol: string(tt.operation),
			}

			err = node.Authorize(tokenBytes, req, pub)
			if tt.expectSuccess {
				if err != nil {
					t.Errorf("expected success, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected failure, got success")
				}
			}
		})
	}
}

func TestRevocation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	dummyPeer := peer.ID("dummy-peer-id") // Must match mockStream.Conn().RemotePeer()

	builder := biscuit.NewBuilder(priv)
	_ = builder.AddAuthorityFact(api.MarkerFact(api.FactTargetUnrestricted))
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "node",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}
	err = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "client_peer_id",
		IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
	}})
	if err != nil {
		t.Fatal(err)
	}

	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}

	tokenBytes, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	cache, _ := lru.New[string, int64](10000)
	rl, _ := ratelimit.NewPeerRateLimiter(100)
	node := &SamNode{
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		revokedPeers:   cache,
		rateLimiter:    rl,
		BiscuitTimeout: 500 * time.Millisecond,
	}

	// Mark as revoked
	node.revokedPeers.Add(dummyPeer.String(), time.Now().Unix())

	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()

	serverStream := &mockStream{r: pr1, w: pw2, protocol: protocol.ID("/test/proto"), conn: &mockConn{remotePeer: dummyPeer}}

	// Run handler in goroutine
	go func() {
		handler := node.WithBiscuitAuth(func(s network.Stream, reqCtx RequestContext) {
			t.Error("Handler should not be called for revoked peer")
		})
		handler(serverStream)
	}()

	// Send AuthFrame
	writer := msgio.NewVarintWriter(pw1)
	authFrame := &api.AuthFrame{Biscuit: tokenBytes}
	data, _ := proto.Marshal(authFrame)
	if err := writer.WriteMsg(data); err != nil {
		t.Fatal(err)
	}

	// Read response
	reader := msgio.NewVarintReaderSize(pr2, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Success {
		t.Error("expected failure for revoked peer, got success")
	}
	if resp.Error != "peer is revoked" {
		t.Errorf("expected error 'peer is revoked', got %q", resp.Error)
	}
}

func TestWithBiscuitAuth_MutualBiscuit(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	clientPeer := peer.ID("dummy-peer-id")
	serverPeer := peer.ID("server-peer-id")

	// Client token satisfying replay, service and target checks.
	builder := biscuit.NewBuilder(priv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: "node", IDs: []biscuit.Term{biscuit.String(clientPeer.String())}}},
		{Predicate: biscuit.Predicate{Name: "client_peer_id", IDs: []biscuit.Term{biscuit.String(clientPeer.String())}}},
		api.MarkerFact(api.FactGrantedServiceAllTypes),
		api.MarkerFact(api.FactTargetUnrestricted),
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
	} {
		if err := builder.AddAuthorityFact(f); err != nil {
			t.Fatal(err)
		}
	}
	b, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes, err := b.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Server identity: control-plane-minted with an attested label.
	serverIdentity, err := identity.MintBootstrapBiscuitToken(priv, serverPeer, api.RoleNode, time.Now().Add(time.Hour), nil, map[string]string{"region": "eu-de"})
	if err != nil {
		t.Fatal(err)
	}

	rl, _ := ratelimit.NewPeerRateLimiter(100)
	node := &SamNode{
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		rateLimiter:    rl,
		BiscuitTimeout: 500 * time.Millisecond,
	}
	node.SetIdentityCache(serverIdentity)

	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()
	serverStream := &mockStream{r: pr1, w: pw2, protocol: protocol.ID("/test/proto"), conn: &mockConn{remotePeer: clientPeer}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handler := node.WithBiscuitAuth(func(s network.Stream, reqCtx RequestContext) {})
		handler(serverStream)
	}()

	writer := msgio.NewVarintWriter(pw1)
	data, _ := proto.Marshal(&api.AuthFrame{Biscuit: tokenBytes})
	if err := writer.WriteMsg(data); err != nil {
		t.Fatal(err)
	}

	reader := msgio.NewVarintReaderSize(pr2, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success {
		t.Fatalf("handshake failed: %s", resp.Error)
	}
	if !bytes.Equal(resp.Biscuit, serverIdentity) {
		t.Error("mutual auth response must carry the server's identity biscuit")
	}

	// The returned biscuit satisfies the consumer-side label gate.
	if err := node.checkPeerLabels(resp.Biscuit, serverPeer, map[string]string{"region": "eu-de"}); err != nil {
		t.Errorf("label gate rejected the mutual-auth biscuit: %v", err)
	}
	if err := node.checkPeerLabels(resp.Biscuit, serverPeer, map[string]string{"region": "na-us"}); err == nil {
		t.Error("label gate must reject a non-matching requirement")
	}
	<-done
}

func TestVerifyEvent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	event := &api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    "attacker-peer",
		EventTime: timestamppb.Now(),
	}

	// Sign it
	event.Signature = nil
	data, err := proto.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Signature = ed25519.Sign(priv, data)

	// Case 1: Valid signature
	if !node.verifyEvent(event) {
		t.Error("Expected event to be verified, got false")
	}

	// Case 2: Invalid signature
	event.Signature = []byte("invalid-sig")
	if node.verifyEvent(event) {
		t.Error("Expected event verification to fail, got true")
	}

	// Case 3: Missing signature
	event.Signature = nil
	if node.verifyEvent(event) {
		t.Error("Expected event verification to fail for missing signature, got true")
	}
}

func TestMiddlewareTargetChecks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	dummyPeer := peer.ID("dummy-peer")

	tests := []struct {
		name          string
		mintToken     func(t *testing.T, builder biscuit.Builder)
		req           RequestContext
		expectSuccess bool
	}{
		{
			name: "Target Check: Allowed by User Fact",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactGrantedTargetExact,
					IDs:  []biscuit.Term{biscuit.String("user"), biscuit.String("bob")},
				}})
			},
			req: RequestContext{
				PeerID:   dummyPeer,
				Protocol: "test_tool",
				Target:   "mcp://test_tool",
				User:     "bob",
			},
			expectSuccess: true,
		},
		{
			name: "Target Check: Rejected by wrong User Fact",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactGrantedTargetExact,
					IDs:  []biscuit.Term{biscuit.String("user"), biscuit.String("alice")},
				}})
			},
			req: RequestContext{
				PeerID:   dummyPeer,
				Protocol: "test_tool",
				Target:   "mcp://test_tool",
				User:     "bob",
			},
			expectSuccess: false,
		},
		{
			name: "Target Check: Allowed by Group Fact",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactGrantedTargetExact,
					IDs:  []biscuit.Term{biscuit.String("group"), biscuit.String("eng")},
				}})
			},
			req: RequestContext{
				PeerID:   dummyPeer,
				Protocol: "test_tool",
				Target:   "mcp://test_tool",
				Group:    "eng",
			},
			expectSuccess: true,
		},
		{
			name: "Target Check: Allowed by Group Set Fact",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactGrantedTargetSet,
					IDs:  []biscuit.Term{biscuit.String("group"), biscuit.Set{biscuit.String("eng"), biscuit.String("sales")}},
				}})
			},
			req: RequestContext{
				PeerID:   dummyPeer,
				Protocol: "test_tool",
				Target:   "mcp://test_tool",
				Group:    "eng",
			},
			expectSuccess: true,
		},
		{
			name: "Target Check: Rejected by Group Set Fact for non-member",
			mintToken: func(t *testing.T, builder biscuit.Builder) {
				_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: api.FactGrantedTargetSet,
					IDs:  []biscuit.Term{biscuit.String("group"), biscuit.Set{biscuit.String("sales")}},
				}})
			},
			req: RequestContext{
				PeerID:   dummyPeer,
				Protocol: "test_tool",
				Target:   "mcp://test_tool",
				Group:    "eng",
			},
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := biscuit.NewBuilder(priv)
			// Required basic facts
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactClientPeerID,
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactNode,
				IDs:  []biscuit.Term{biscuit.String(dummyPeer.String())},
			}})
			_ = builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactExpiration,
				IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
			}})
			// Allow exact service
			factStr := fmt.Sprintf(`%s("mcp", "test_tool")`, api.FactGrantedServiceExact)
			fact, _ := parser.FromStringFact(factStr)
			_ = builder.AddAuthorityFact(fact)

			tt.mintToken(t, builder)

			b, _ := builder.Build()
			tokenBytes, _ := b.Serialize()

			// Build the Node Identity Token
			idBuilder := biscuit.NewBuilder(priv)
			if tt.req.User != "" {
				_ = idBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: "user",
					IDs:  []biscuit.Term{biscuit.String(tt.req.User)},
				}})
			}
			if tt.req.Group != "" {
				_ = idBuilder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
					Name: "group",
					IDs:  []biscuit.Term{biscuit.String(tt.req.Group)},
				}})
			}
			idB, _ := idBuilder.Build()
			idTokenBytes, _ := idB.Serialize()

			node := &SamNode{
				trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
				BiscuitTimeout: 500 * time.Millisecond,
			}
			node.SetIdentityCache(idTokenBytes)

			err = node.Authorize(tokenBytes, tt.req, pub)
			if tt.expectSuccess && err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
			if !tt.expectSuccess && err == nil {
				t.Errorf("expected failure, got success")
			}
		})
	}
}

func TestTrackingStream(t *testing.T) {
	var pr1 bytes.Buffer
	var pw1 bytes.Buffer

	// Create mock underlying stream
	mock := &mockStream{r: &pr1, w: &pw1, protocol: protocol.ID("/test")}
	ts := &trackingStream{Stream: mock}

	// Write data
	writeData := []byte("hello world")
	n, err := ts.Write(writeData)
	if err != nil || n != len(writeData) {
		t.Fatalf("Write failed: %v", err)
	}
	if ts.bytesWritten.Load() != int64(len(writeData)) {
		t.Errorf("Expected bytesWritten to be %d, got %d", len(writeData), ts.bytesWritten.Load())
	}

	// Read data
	pr1.Write([]byte("response")) // Pre-load the read buffer
	readBuf := make([]byte, 10)
	n, err = ts.Read(readBuf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if ts.bytesRead.Load() != int64(n) {
		t.Errorf("Expected bytesRead to be %d, got %d", n, ts.bytesRead.Load())
	}
}

func TestAuthorize_WithTARBlocks(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	callerKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatal(err)
	}
	callerPeer, err := peer.IDFromPrivateKey(callerKey)
	if err != nil {
		t.Fatal(err)
	}

	// Mint an authority Biscuit that grants wildcard services and targets.
	builder := biscuit.NewBuilder(priv)
	for _, f := range []biscuit.Fact{
		{Predicate: biscuit.Predicate{Name: api.FactClientPeerID, IDs: []biscuit.Term{biscuit.String(callerPeer.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(callerPeer.String())}}},
		{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))}}},
		api.MarkerFact(api.FactGrantedServiceAllTypes),
		api.MarkerFact(api.FactTargetUnrestricted),
	} {
		if err := builder.AddAuthorityFact(f); err != nil {
			t.Fatal(err)
		}
	}
	rootBiscuit, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := rootBiscuit.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Attenuate with Hop 1 (allows mcp://weather and egress://api.github.com GET/POST /repos/acme/*)
	hop1 := &api.TaskAuthorizationRule{
		Name:       "hop-1",
		ExpireTime: timestamppb.New(time.Now().Add(10 * time.Minute)),
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"mcp://weather"},
				Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather", "get_forecast"}},
			},
			{
				AllowedServices: []string{"egress://api.github.com"},
				Operation: &api.TaskOperation{
					AllowedMethods: []string{"GET", "POST"},
					AllowedPaths:   []string{"/repos/acme/*"},
				},
			},
		},
	}
	att1, err := identity.AttenuateBiscuit(rootBytes, hop1)
	if err != nil {
		t.Fatal(err)
	}

	// Attenuate with Hop 2 (narrows to GET /repos/acme/public/* and get_weather) and seal.
	hop2 := &api.TaskAuthorizationRule{
		Name:       "hop-2",
		ExpireTime: timestamppb.New(time.Now().Add(5 * time.Minute)),
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"mcp://weather"},
				Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather"}},
			},
			{
				AllowedServices: []string{"egress://api.github.com"},
				Operation: &api.TaskOperation{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/repos/acme/public/*"},
				},
			},
		},
	}
	att2, err := identity.AttenuateBiscuit(att1, hop2)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := identity.SealBiscuit(att2)
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	// 1. Allowed HTTP GET under narrowed prefix
	if err := node.Authorize(sealed, RequestContext{
		PeerID:   callerPeer,
		Protocol: "/libp2p-http",
		Target:   "egress://api.github.com",
		HTTP:     &HTTPRequestFacts{Method: "GET", Path: "/repos/acme/public/readme"},
	}, pub); err != nil {
		t.Errorf("expected allowed HTTP GET to succeed, got: %v", err)
	}

	// 2. Denied HTTP POST (dropped in hop 2)
	if err := node.Authorize(sealed, RequestContext{
		PeerID:   callerPeer,
		Protocol: "/libp2p-http",
		Target:   "egress://api.github.com",
		HTTP:     &HTTPRequestFacts{Method: "POST", Path: "/repos/acme/public/readme"},
	}, pub); err == nil {
		t.Error("expected HTTP POST to be denied by hop 2 TAR")
	}

	// 3. Denied service outside TAR (even though standing RBAC grants *)
	if err := node.Authorize(sealed, RequestContext{
		PeerID:   callerPeer,
		Protocol: "/libp2p-http",
		Target:   "inference://llama3",
		HTTP:     &HTTPRequestFacts{Method: "POST", Path: "/v1/chat/completions"},
	}, pub); err == nil {
		t.Error("expected inference://llama3 to be denied by TAR")
	}

	// 4. Allowed MCP stream handshake on api.MCPProtocolID
	if err := node.Authorize(sealed, RequestContext{
		PeerID:   callerPeer,
		Protocol: string(api.MCPProtocolID),
		Target:   "mcp://weather",
	}, pub); err != nil {
		t.Errorf("expected MCP stream handshake to mcp://weather to succeed, got: %v", err)
	}
}

func TestTARConformanceVectors(t *testing.T) {
	rawJSON, err := os.ReadFile(filepath.Join("..", "..", "sdk", "testdata", "tar_conformance.json"))
	if err != nil {
		t.Fatalf("failed to read tar_conformance.json: %v", err)
	}
	var suite struct {
		PublicKeyB64       string   `json:"public_key_b64"`
		CallerPeerID       string   `json:"caller_peer_id"`
		ProviderBiscuitB64 string   `json:"provider_biscuit_b64"`
		PolicyDatalogRules []string `json:"policy_datalog_rules"`
		Vectors            []struct {
			Name                        string  `json:"name"`
			BiscuitB64                  string  `json:"biscuit_b64"`
			TargetService               string  `json:"target_service"`
			Protocol                    string  `json:"protocol"`
			Method                      *string `json:"method,omitempty"`
			Path                        string  `json:"path,omitempty"`
			MCPTool                     string  `json:"mcp_tool,omitempty"`
			Allow                       bool    `json:"allow"`
			ExpectedEffectiveExpiration string  `json:"expected_effective_expiration,omitempty"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(rawJSON, &suite); err != nil {
		t.Fatalf("failed to unmarshal tar_conformance.json: %v", err)
	}

	rootPubBytes, err := base64.StdEncoding.DecodeString(suite.PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	rootPub := ed25519.PublicKey(rootPubBytes)
	callerPeer, err := peer.Decode(suite.CallerPeerID)
	if err != nil {
		t.Fatal(err)
	}
	providerBytes, err := base64.StdEncoding.DecodeString(suite.ProviderBiscuitB64)
	if err != nil {
		t.Fatal(err)
	}
	meshRules, err := api.ParseDatalogRules(suite.PolicyDatalogRules)
	if err != nil {
		t.Fatal(err)
	}

	node := &SamNode{
		trustedKeys:     []TrustedKey{{Key: rootPub, ReceivedAt: time.Now()}},
		MeshPolicyRules: meshRules,
		BiscuitTimeout:  500 * time.Millisecond,
	}
	node.SetIdentityCache(providerBytes)

	for _, vec := range suite.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			tokenBytes, err := base64.StdEncoding.DecodeString(vec.BiscuitB64)
			if err != nil {
				t.Fatal(err)
			}
			if vec.ExpectedEffectiveExpiration != "" {
				claims, verifyErr := identity.InspectVerifiedBiscuit(tokenBytes, []ed25519.PublicKey{rootPub}, 500*time.Millisecond)
				if verifyErr != nil {
					t.Fatalf("InspectVerifiedBiscuit failed: %v", verifyErr)
				}
				wantExp, err := time.Parse(time.RFC3339, vec.ExpectedEffectiveExpiration)
				if err != nil {
					t.Fatal(err)
				}
				if !claims.Expiration.Equal(wantExp) {
					t.Fatalf("effective expiration = %v, want %v", claims.Expiration, wantExp)
				}
			}

			req := RequestContext{
				PeerID:   callerPeer,
				Protocol: vec.Protocol,
				Target:   vec.TargetService,
				MCPTool:  vec.MCPTool,
			}
			if vec.Method != nil {
				req.HTTP = &HTTPRequestFacts{
					Method: *vec.Method,
					Path:   vec.Path,
				}
			}
			authErr := node.Authorize(tokenBytes, req, rootPub)
			if vec.Allow && authErr != nil {
				t.Fatalf("expected allow=true, got error: %v", authErr)
			}
			if !vec.Allow && authErr == nil {
				t.Fatalf("expected allow=false, got nil")
			}
		})
	}
}
