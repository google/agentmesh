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
	"crypto/rand"
	"sync"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

// recordingPeer is a libp2p peer that answers the auth handshake with a fixed
// response and records every AuthFrame it receives, per protocol.
type recordingPeer struct {
	mu     sync.Mutex
	frames map[protocol.ID][]*api.AuthFrame
}

func startRecordingPeer(t *testing.T, reply func() *api.AuthResponse) (peer.AddrInfo, *recordingPeer) {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("start recording peer: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	rec := &recordingPeer{frames: map[protocol.ID][]*api.AuthFrame{}}
	for _, id := range []protocol.ID{api.AuthProtocolID, api.MCPProtocolID} {
		h.SetStreamHandler(id, rec.handle(id, reply))
	}
	return peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()}, rec
}

func (r *recordingPeer) handle(id protocol.ID, reply func() *api.AuthResponse) network.StreamHandler {
	return func(s network.Stream) {
		defer func() { _ = s.Close() }()
		msg, err := msgio.NewVarintReaderSize(s, 64*1024).ReadMsg()
		if err != nil {
			return
		}
		var frame api.AuthFrame
		if err := proto.Unmarshal(msg, &frame); err != nil {
			return
		}
		r.mu.Lock()
		r.frames[id] = append(r.frames[id], &frame)
		r.mu.Unlock()
		out, err := proto.Marshal(reply())
		if err != nil {
			return
		}
		_ = msgio.NewVarintWriter(s).WriteMsg(out)
	}
}

func (r *recordingPeer) received(id protocol.ID) []*api.AuthFrame {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*api.AuthFrame(nil), r.frames[id]...)
}

// TestConnectMCPSessionVerifiesProviderBeforeSendingCallerBiscuit pins that a
// peer which is not a verified provider of the service never receives the
// caller's Biscuit: only this node's own credential goes out, on the auth
// handshake, and the MCP stream is never opened.
func TestConnectMCPSessionVerifiesProviderBeforeSendingCallerBiscuit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nodeA, cleanup := startBareNode(t, ctx)
	defer cleanup()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	if err := buildAndSaveBiscuit(nodeA, rootPriv); err != nil {
		t.Fatalf("save node A biscuit: %v", err)
	}
	nodeA.keysMu.Lock()
	nodeA.trustedKeys = append(nodeA.trustedKeys, TrustedKey{Key: rootPub, ReceivedAt: time.Now()})
	nodeA.keysMu.Unlock()

	callerBiscuit, err := identity.MintDelegatedBiscuitToken(rootPriv, jwt.MapClaims{
		"sub":   "user-42",
		"email": "alice@example.com",
	}, nodeA.Host.ID(), time.Now().Add(time.Hour), []string{"user"}, nil, nil, false)
	if err != nil {
		t.Fatalf("mint caller biscuit: %v", err)
	}

	tests := []struct {
		name  string
		reply func(rogue peer.ID) *api.AuthResponse
	}{
		{
			name:  "peer with no credential",
			reply: func(peer.ID) *api.AuthResponse { return &api.AuthResponse{Success: true} },
		},
		{
			name: "enrolled node not granted the service",
			reply: func(rogue peer.ID) *api.AuthResponse {
				b, err := identity.MintBootstrapBiscuitToken(rootPriv, rogue, api.RoleNode, time.Now().Add(time.Hour), nil, nil)
				if err != nil {
					t.Errorf("mint rogue biscuit: %v", err)
				}
				return &api.AuthResponse{Success: true, Biscuit: b}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var rogueID peer.ID
			info, rec := startRecordingPeer(t, func() *api.AuthResponse { return tc.reply(rogueID) })
			rogueID = info.ID
			if err := nodeA.Host.Connect(ctx, info); err != nil {
				t.Fatalf("connect to rogue: %v", err)
			}

			session, closeSession, err := nodeA.ConnectMCPSession(WithCallerBiscuit(ctx, callerBiscuit), rogueID, "mcp://code-reviewer", nil)
			if err == nil {
				closeSession()
				_ = session.Close()
				t.Fatal("ConnectMCPSession succeeded against an unverified peer, want an error")
			}

			if got := rec.received(api.MCPProtocolID); len(got) != 0 {
				t.Fatalf("rogue received %d frame(s) on %s, want 0", len(got), api.MCPProtocolID)
			}
			for i, f := range rec.received(api.AuthProtocolID) {
				if bytes.Equal(f.Biscuit, callerBiscuit) {
					t.Fatalf("auth frame %d carried the caller's Biscuit, want node A's own", i)
				}
				if !bytes.Equal(f.Biscuit, nodeA.GetIdentity()) {
					t.Fatalf("auth frame %d carried an unknown credential, want node A's own", i)
				}
			}
		})
	}
}
