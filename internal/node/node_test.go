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
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/ratelimit"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAnnounceFilter(t *testing.T) {
	const (
		loopback  = "/ip4/127.0.0.1/tcp/5002"
		linkLocal = "/ip4/169.254.10.1/tcp/5002"
		private   = "/ip4/192.168.94.13/tcp/5002"
		public    = "/ip4/34.91.220.211/udp/8192/quic-v1"
		// Relay path whose router sits on a private address, as in an on-premises mesh.
		circuit = "/ip4/10.0.0.7/tcp/4501/p2p/12D3KooWG1pA6goegCncqwbZLSr8pnjUZ6JMAAe6SmnHTgUNCk88/p2p-circuit"
	)
	input := []multiaddr.Multiaddr{}
	for _, s := range []string{loopback, linkLocal, private, public, circuit} {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", s, err)
		}
		input = append(input, ma)
	}

	announce := true
	suppress := false

	tests := []struct {
		name            string
		allowLoopback   bool
		announcePrivate *bool
		want            []string
	}{
		{
			name: "default keeps private addresses so LAN meshes stay reachable",
			want: []string{private, public, circuit},
		},
		{
			name:            "explicit announce private matches the default",
			announcePrivate: &announce,
			want:            []string{private, public, circuit},
		},
		{
			name:            "suppressing private addresses still announces relay paths",
			announcePrivate: &suppress,
			want:            []string{public, circuit},
		},
		{
			name:          "allow loopback publishes everything",
			allowLoopback: true,
			want:          []string{loopback, linkLocal, private, public, circuit},
		},
		{
			name:            "allow loopback combined with suppressed private addresses",
			allowLoopback:   true,
			announcePrivate: &suppress,
			want:            []string{loopback, linkLocal, public, circuit},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &AgentMeshNode{config: Options{
				AllowLoopback:        tt.allowLoopback,
				AnnouncePrivateAddrs: tt.announcePrivate,
			}}
			got := n.announceFilter(input)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i, addr := range got {
				if addr.String() != tt.want[i] {
					t.Errorf("addr %d: got %s, want %s", i, addr, tt.want[i])
				}
			}
		})
	}
}

// A router AutoRelay holds a reservation on is announced as a circuit
// address even when AutoRelay itself publishes none for it (a router on a
// loopback or private IP); a router merely attached is not, and an address
// AutoRelay already published is not repeated.
func TestAnnounceFilterAddsReservedCircuits(t *testing.T) {
	cm, err := connmgr.NewConnManager(10, 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cm.Close() })
	realCandidate := func() routerCandidate {
		priv, _, err := crypto.GenerateEd25519Key(nil)
		if err != nil {
			t.Fatal(err)
		}
		id, err := peer.IDFromPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return routerCandidate{AddrInfo: peer.AddrInfo{ID: id}}
	}
	reserved := realCandidate()
	reserved.Addrs = []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/127.0.0.1/tcp/4501"), multiaddr.StringCast("/ip4/10.0.0.7/tcp/4501")}
	attachedOnly := realCandidate()
	attachedOnly.Addrs = []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/127.0.0.1/tcp/4502")}
	n := &AgentMeshNode{config: Options{AllowLoopback: true}, connMgr: cm}
	n.routerCatalog = []routerCandidate{reserved, attachedOnly}
	cm.Protect(attachedOnly.ID, routerTag)
	cm.Protect(reserved.ID, routerTag)
	cm.Protect(reserved.ID, autorelayTag)

	already := multiaddr.StringCast("/ip4/10.0.0.7/tcp/4501/p2p/" + reserved.ID.String() + "/p2p-circuit")
	got := n.announceFilter([]multiaddr.Multiaddr{multiaddr.StringCast("/ip4/127.0.0.1/tcp/5002"), already})
	want := []string{
		"/ip4/127.0.0.1/tcp/5002",
		already.String(),
		"/ip4/127.0.0.1/tcp/4501/p2p/" + reserved.ID.String() + "/p2p-circuit",
	}
	if len(got) != len(want) {
		t.Fatalf("announced %v, want %v", got, want)
	}
	for i, addr := range got {
		if addr.String() != want[i] {
			t.Errorf("addr %d: got %s, want %s", i, addr, want[i])
		}
	}
}

func TestHandleBannedEvent(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	banned, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	for _, spelling := range []string{banned.String(), peer.ToCid(banned).String()} {
		revokedCache, _ := lru.New[string, int64](10)
		node := &AgentMeshNode{
			revokedPeers:   revokedCache,
			BiscuitTimeout: 500 * time.Millisecond,
		}

		node.handleBannedEvent(&api.MeshEvent{
			Type:      api.MeshEvent_BANNED,
			PeerId:    spelling,
			EventTime: timestamppb.Now(),
		})

		if !node.revokedPeers.Contains(banned.String()) {
			t.Errorf("peer announced as %q is not revoked under its canonical id", spelling)
		}
		if gater := (&nodeConnGate{node: node}); gater.InterceptPeerDial(banned) {
			t.Errorf("peer announced as %q was not blocked by the gater", spelling)
		}
	}
}

func TestBannedPeerCanonicalisation(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	p, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to derive peer ID: %v", err)
	}
	canonicalID := p.String()
	cidv1ID := peer.ToCid(p).String()

	revokedCache, err := lru.New[string, int64](10)
	if err != nil {
		t.Fatalf("failed to create revocation cache: %v", err)
	}
	node := &AgentMeshNode{
		revokedPeers:      revokedCache,
		peerLastEventTime: make(map[string]int64),
		BiscuitTimeout:    500 * time.Millisecond,
	}

	ts := time.Now().UnixMilli()
	node.handleBannedEvent(&api.MeshEvent{
		Type:      api.MeshEvent_BANNED,
		PeerId:    cidv1ID,
		EventTime: timestamppb.New(time.UnixMilli(ts)),
	})

	if !node.revokedPeers.Contains(canonicalID) {
		t.Errorf("revokedPeers missing canonical ID %q (event used %q)", canonicalID, cidv1ID)
	}
	if got := node.peerLastEventTime[canonicalID]; got != ts {
		t.Errorf("peerLastEventTime[%q] = %d, want %d", canonicalID, got, ts)
	}
}

func TestHandleKeyRotationEvent(t *testing.T) {
	node := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	event := &api.MeshEvent{
		Type:         api.MeshEvent_KEY_ROTATION,
		NewPublicKey: pub,
		EventTime:    timestamppb.Now(),
	}

	node.handleKeyRotationEvent(event)

	if len(node.trustedKeys) != 1 {
		t.Errorf("Expected 1 trusted key, got %d", len(node.trustedKeys))
	}
	if node.identityPredatesRotation() {
		t.Error("an unenrolled node has nothing to refresh")
	}
}

// TestKeyRotationEventSurvivesRestart covers the offline/restart half of
// #325: a key learned from a rotation event must outlive the process, or a
// restarted node falls back to its stale enrollment-time key.
func TestKeyRotationEventSurvivesRestart(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	enrollKey, _, _ := ed25519.GenerateKey(nil)
	rotatedKey, _, _ := ed25519.GenerateKey(nil)

	node := &AgentMeshNode{Store: store, trustedKeys: []TrustedKey{{Key: enrollKey, ReceivedAt: time.Now()}}}
	node.handleKeyRotationEvent(&api.MeshEvent{
		Type:         api.MeshEvent_KEY_ROTATION,
		NewPublicKey: rotatedKey,
		EventTime:    timestamppb.Now(),
	})
	// Duplicate event must not grow the persisted set
	node.handleKeyRotationEvent(&api.MeshEvent{
		Type:         api.MeshEvent_KEY_ROTATION,
		NewPublicKey: rotatedKey,
		EventTime:    timestamppb.Now(),
	})

	// "Restart": a fresh node built from the same store must trust the rotated key
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	restarted, err := NewAgentMeshNode(Options{PrivKey: priv, Store: store, ControlPlanePubKey: enrollKey})
	if err != nil {
		t.Fatal(err)
	}
	if len(restarted.trustedKeys) != 2 {
		t.Fatalf("expected 2 trusted keys after restart, got %d", len(restarted.trustedKeys))
	}
	if !containsTrustedKey(restarted.trustedKeys, rotatedKey) {
		t.Error("rotated key lost across restart")
	}
	if !containsTrustedKey(restarted.trustedKeys, enrollKey) {
		t.Error("enrollment key missing after restart")
	}
}

func TestNewAgentMeshNodeIgnoresCorruptPersistedKeys(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	goodKey, _, _ := ed25519.GenerateKey(nil)
	if err := store.SaveTrustedKeys([]TrustedKey{
		{Key: []byte("corrupt"), ReceivedAt: time.Now()},
		{Key: goodKey, ReceivedAt: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}

	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	node, err := NewAgentMeshNode(Options{PrivKey: priv, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if len(node.trustedKeys) != 1 || !node.trustedKeys[0].Key.Equal(goodKey) {
		t.Fatalf("expected only the valid key to survive loading, got %d keys", len(node.trustedKeys))
	}
}

// TestPruneTrustedKeys covers the trust-set floor: a node that runs past the
// grace period without witnessing a rotation must not age out its only key.
func TestPruneTrustedKeys(t *testing.T) {
	now := time.Now()
	grace := 24 * time.Hour
	k := func(age time.Duration) TrustedKey {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return TrustedKey{Key: pub, ReceivedAt: now.Add(-age)}
	}

	stale := k(48 * time.Hour)
	staler := k(72 * time.Hour)
	fresh := k(time.Hour)

	tests := []struct {
		name string
		in   []TrustedKey
		want []TrustedKey
	}{
		{"sole stale key survives", []TrustedKey{stale}, []TrustedKey{stale}},
		{"stale dropped when fresher exists", []TrustedKey{staler, fresh}, []TrustedKey{fresh}},
		{"newest of two stale keys survives", []TrustedKey{staler, stale}, []TrustedKey{stale}},
		{"fresh keys all kept", []TrustedKey{fresh, k(2 * time.Hour)}, nil}, // want computed below
		{"empty", nil, nil},
	}
	tests[3].want = tests[3].in

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pruneTrustedKeys(tt.in, now, grace)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d keys, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if !got[i].Key.Equal(tt.want[i].Key) {
					t.Errorf("key %d: got %x, want %x", i, got[i].Key, tt.want[i].Key)
				}
			}
		})
	}
}

// TestHandleAuthHandshake covers the admission office: the relay ACL trusts
// authPeers, so the cached instant must be the token's own expiry, and a token
// that is expired or bound to another peer must leave no entry at all (#296).
func TestHandleAuthHandshake(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	serverHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverHost.Close() }()
	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	node := &AgentMeshNode{
		trustedKeys:    []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout: time.Second,
	}
	serverHost.SetStreamHandler(api.AuthProtocolID, node.HandleAuthHandshake)
	if err := clientHost.Connect(ctx, peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
		t.Fatal(err)
	}

	mint := func(boundTo peer.ID, expiration time.Time) []byte {
		builder := biscuit.NewBuilder(priv)
		for _, f := range []biscuit.Fact{
			{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(boundTo.String())}}},
			{Predicate: biscuit.Predicate{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Date(expiration)}}},
		} {
			if err := builder.AddAuthorityFact(f); err != nil {
				t.Fatal(err)
			}
		}
		b, err := builder.Build()
		if err != nil {
			t.Fatal(err)
		}
		data, err := b.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	// handshake presents token and returns the node's answer; a rejected peer
	// gets the stream closed on it with no answer at all.
	handshake := func(token []byte) (*api.AuthResponse, error) {
		s, err := clientHost.NewStream(ctx, serverHost.ID(), api.AuthProtocolID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		if err := s.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		frame, err := proto.Marshal(&api.AuthFrame{Biscuit: token})
		if err != nil {
			t.Fatal(err)
		}
		if err := msgio.NewVarintWriter(s).WriteMsg(frame); err != nil {
			t.Fatal(err)
		}
		reader := msgio.NewVarintReaderSize(s, 1024*64)
		msg, err := reader.ReadMsg()
		if err != nil {
			return nil, err
		}
		defer reader.ReleaseMsg(msg)
		var resp api.AuthResponse
		if err := proto.Unmarshal(msg, &resp); err != nil {
			t.Fatal(err)
		}
		return &resp, nil
	}

	want := time.Now().Add(time.Hour)
	resp, err := handshake(mint(clientHost.ID(), want))
	if err != nil {
		t.Fatalf("valid token got no answer: %v", err)
	}
	if !resp.Success {
		t.Fatalf("valid token rejected: %s", resp.Error)
	}
	v, ok := node.authPeers.Load(clientHost.ID())
	if !ok {
		t.Fatal("admitted peer not recorded in authPeers")
	}
	expiry, ok := v.(time.Time)
	if !ok {
		t.Fatalf("authPeers holds %T, want time.Time", v)
	}
	// The admission is cached against this instant, so it has to be the token's.
	if skew := expiry.Sub(want).Abs(); skew > time.Second {
		t.Errorf("cached expiry %v, want ~%v", expiry, want)
	}

	for name, token := range map[string][]byte{
		"expired":               mint(clientHost.ID(), time.Now().Add(-time.Hour)),
		"bound to another peer": mint(serverHost.ID(), want),
	} {
		node.authPeers.Delete(clientHost.ID())
		if resp, err := handshake(token); err == nil {
			t.Errorf("%s: token answered with %+v, want the stream closed", name, resp)
		}
		if _, admitted := node.authPeers.Load(clientHost.ID()); admitted {
			t.Errorf("%s: peer admitted", name)
		}
	}
}

// Any internet peer can open /mesh/auth streams. An idle one must be closed on
// the node's schedule, not the peer's, and a peer opening them in a tight loop
// must be cut off before the node verifies every frame it sends.
func TestHandleAuthHandshakeBoundsUnauthenticatedPeers(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	serverHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverHost.Close() }()
	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	limiter, err := ratelimit.NewPeerRateLimiter(16)
	if err != nil {
		t.Fatal(err)
	}
	node := &AgentMeshNode{
		trustedKeys:      []TrustedKey{{Key: pub, ReceivedAt: time.Now()}},
		BiscuitTimeout:   time.Second,
		handshakeLimiter: limiter,
	}
	serverHost.SetStreamHandler(api.AuthProtocolID, node.HandleAuthHandshake)
	if err := clientHost.Connect(ctx, peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
		t.Fatal(err)
	}

	t.Run("idle stream is closed by the deadline", func(t *testing.T) {
		old := authHandshakeTimeout
		authHandshakeTimeout = 200 * time.Millisecond
		t.Cleanup(func() { authHandshakeTimeout = old })

		s, err := clientHost.NewStream(ctx, serverHost.ID(), api.AuthProtocolID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		// Send nothing. The node must give up on us, which the client sees as
		// its read failing; without the deadline this read blocks forever.
		if err := s.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err = msgio.NewVarintReaderSize(s, 1024*64).ReadMsg()
		if err == nil {
			t.Fatal("idle handshake stream answered")
		}
		if took := time.Since(start); took > 4*time.Second {
			t.Fatalf("idle stream was held for %v; the node did not apply its own deadline", took)
		}
	})

	t.Run("tight loop is rate limited", func(t *testing.T) {
		builder := biscuit.NewBuilder(priv)
		for _, f := range []biscuit.Fact{
			{Predicate: biscuit.Predicate{Name: api.FactNode, IDs: []biscuit.Term{biscuit.String(clientHost.ID().String())}}},
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
		token, err := b.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		frame, err := proto.Marshal(&api.AuthFrame{Biscuit: token})
		if err != nil {
			t.Fatal(err)
		}

		attempts := 3 * ratelimit.PeerBurst
		answered := 0
		for i := 0; i < attempts; i++ {
			s, err := clientHost.NewStream(ctx, serverHost.ID(), api.AuthProtocolID)
			if err != nil {
				t.Fatal(err)
			}
			_ = s.SetDeadline(time.Now().Add(5 * time.Second))
			if err := msgio.NewVarintWriter(s).WriteMsg(frame); err == nil {
				if _, err := msgio.NewVarintReaderSize(s, 1024*64).ReadMsg(); err == nil {
					answered++
				}
			}
			_ = s.Close()
		}
		// The token is valid, so every answer is a success: the only reason
		// some go unanswered is the limiter.
		if answered < ratelimit.PeerBurst {
			t.Errorf("only %d of the first %d handshakes answered; limiter is too strict", answered, ratelimit.PeerBurst)
		}
		if answered == attempts {
			t.Errorf("all %d back-to-back handshakes were verified; no per-peer limit applied", attempts)
		}
	})
}

// TestPerformRouterAuthHandshakeRequiresRouterRole: a router whose biscuit
// verifies but carries no role("router") is a fatal auth failure, so the node
// gives up on it instead of retrying.
func TestPerformRouterAuthHandshakeRequiresRouterRole(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientHost.Close() }()

	node := &AgentMeshNode{
		trustedKeys:    []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}},
		BiscuitTimeout: time.Second,
	}

	for _, tt := range []struct {
		role   string
		wantOK bool
	}{
		{api.RoleRouter, true},
		{api.RoleNode, false},
	} {
		t.Run(tt.role, func(t *testing.T) {
			info, err := peer.AddrInfoFromString(startMockRouterWithKey(t, cpPriv, tt.role))
			if err != nil {
				t.Fatal(err)
			}
			if err := clientHost.Connect(ctx, *info); err != nil {
				t.Fatal(err)
			}
			s, err := clientHost.NewStream(ctx, info.ID, api.AuthProtocolID)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			if err := s.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}

			ok, err := node.performRouterAuthHandshake(s, []byte("node-biscuit"), info.ID)
			if tt.wantOK {
				if err != nil || !ok {
					t.Fatalf("router with role %q rejected: ok=%v err=%v", tt.role, ok, err)
				}
				return
			}
			if err == nil || ok {
				t.Fatalf("router with role %q accepted", tt.role)
			}
			if !errors.Is(err, ErrFatalAuth) {
				t.Errorf("got %v, want ErrFatalAuth", err)
			}
		})
	}
}

func TestStartRenewalLoop_ExpiredAndFails(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		store, _ := NewStore(t.TempDir())
		// Set expiration to the past
		_ = store.SaveIdentityExpiration(time.Now().Add(-1 * time.Hour).Unix())

		node := &AgentMeshNode{
			BiscuitTimeout: 500 * time.Millisecond,
			Store:          store,
		}

		// Run the renewal loop. Since there's no JWT/Issuer provided, it fails to renew.
		// It will see that it's expired and it failed to renew, so it will log.Fatalf
		node.StartRenewalLoop(context.Background(), "", "", "", "")
		time.Sleep(2 * time.Second)
		os.Exit(0) // should not be reached
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestStartRenewalLoop_ExpiredAndFails")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return // Successful fatal exit
	}
	t.Fatalf("process ran with err %v, want exit status 1 (fatal crash)", err)
}

func TestConnectionMonitor_CrashesAfterFailures(t *testing.T) {
	if os.Getenv("BE_CRASHER_MONITOR") == "1" {
		priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		store, _ := NewStore(t.TempDir())
		node, err := NewAgentMeshNode(Options{
			PrivKey:           priv,
			RouterAddrs:       nil,
			Store:             store,
			DiscoveryInterval: "10s",
			ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
			EnableRelay:       false,
			NodeConfig:        nil,
			KeyGracePeriod:    0,
			AllowLoopback:     false,
			MonitorBootstrap:  2 * time.Minute,
			MonitorInterval:   1 * time.Minute,
		})
		if err != nil {
			os.Exit(0) // Ignore NewAgentMeshNode errors for this crasher
		}
		if err := node.Start(context.Background()); err != nil {
			os.Exit(0)
		}

		// Use very short durations
		node.startConnectionMonitor(context.Background(), 10*time.Millisecond, 10*time.Millisecond, 3)
		time.Sleep(1 * time.Second)
		os.Exit(0) // should not be reached
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestConnectionMonitor_CrashesAfterFailures")
	cmd.Env = append(os.Environ(), "BE_CRASHER_MONITOR=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return // Successful fatal exit
	}
	t.Fatalf("process ran with err %v, want exit status 1 (fatal crash)", err)
}

func TestNewAgentMeshNode_Validation(t *testing.T) {
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	store, _ := NewStore(t.TempDir())
	defer func() { _ = store.Close() }()

	t.Run("nil PrivKey", func(t *testing.T) {
		_, err := NewAgentMeshNode(Options{
			PrivKey: nil,
			Store:   store,
		})
		if err == nil || err.Error() != "private key is required" {
			t.Errorf("expected 'private key is required' error, got: %v", err)
		}
	})

	t.Run("nil Store", func(t *testing.T) {
		_, err := NewAgentMeshNode(Options{
			PrivKey: priv,
			Store:   nil,
		})
		if err == nil || err.Error() != "store is required" {
			t.Errorf("expected 'store is required' error, got: %v", err)
		}
	})
}

func TestNewAgentMeshNode_BiscuitTimeout(t *testing.T) {
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	store, _ := NewStore(t.TempDir())
	defer func() { _ = store.Close() }()

	t.Run("defaults when unset", func(t *testing.T) {
		node, err := NewAgentMeshNode(Options{
			PrivKey: priv,
			Store:   store,
		})
		if err != nil {
			t.Fatalf("NewAgentMeshNode: %v", err)
		}
		if node.BiscuitTimeout != identity.DefaultAuthorizerTimeout {
			t.Errorf("BiscuitTimeout = %v, want default %v", node.BiscuitTimeout, identity.DefaultAuthorizerTimeout)
		}
	})

	t.Run("explicit value respected", func(t *testing.T) {
		node, err := NewAgentMeshNode(Options{
			PrivKey:        priv,
			Store:          store,
			BiscuitTimeout: 10 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewAgentMeshNode: %v", err)
		}
		if node.BiscuitTimeout != 10*time.Second {
			t.Errorf("BiscuitTimeout = %v, want 10s", node.BiscuitTimeout)
		}
	})
}

func TestNewAgentMeshNode_DHTOptions(t *testing.T) {
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	store, _ := NewStore(t.TempDir())
	defer func() { _ = store.Close() }()

	opts := Options{
		PrivKey:              priv,
		Store:                store,
		ListenAddrs:          []string{"/ip4/127.0.0.1/tcp/0"},
		DHTLookupLimit:       50,
		DiscoveryConcurrency: 5,
	}

	node, err := NewAgentMeshNode(opts)
	if err != nil {
		t.Fatalf("failed to create node with DHT options: %v", err)
	}

	if node.config.DHTLookupLimit != 50 {
		t.Errorf("expected DHTLookupLimit to be 50, got %d", node.config.DHTLookupLimit)
	}
	if node.config.DiscoveryConcurrency != 5 {
		t.Errorf("expected DiscoveryConcurrency to be 5, got %d", node.config.DiscoveryConcurrency)
	}
}

// newDHTHost returns a host wired to a DHT on the /mesh prefix. Client mode
// keeps the host out of its peers' routing tables, so nothing dials it except
// the code under test.
func newDHTHost(t *testing.T, mode dht.ModeOpt) (host.Host, *dht.IpfsDHT) {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	d, err := dht.New(h, dht.Mode(mode), dht.ProtocolPrefix("/mesh"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return h, d
}

// waitForRoutingTable polls until the DHT has learned about a peer.
func waitForRoutingTable(t *testing.T, d *dht.IpfsDHT) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for d.RoutingTable().Size() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("routing table still empty after 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFindProvidersSkipsRevoked(t *testing.T) {
	ctx := context.Background()

	hostA, dhtA := newDHTHost(t, dht.ModeServer)
	hostB, dhtB := newDHTHost(t, dht.ModeServer)
	if err := hostA.Connect(ctx, peer.AddrInfo{ID: hostB.ID(), Addrs: hostB.Addrs()}); err != nil {
		t.Fatal(err)
	}
	waitForRoutingTable(t, dhtA)
	waitForRoutingTable(t, dhtB)

	c, err := serviceNameToCID(api.ServiceType_SERVICE_TYPE_MCP, "revoked-svc")
	if err != nil {
		t.Fatal(err)
	}
	if err := dhtB.Provide(ctx, c, true); err != nil {
		t.Fatal(err)
	}

	revokedCache, err := lru.New[string, int64](10)
	if err != nil {
		t.Fatal(err)
	}
	node := &AgentMeshNode{Host: hostA, DHT: dhtA, revokedPeers: revokedCache}

	// Positive control: the provider record is findable before the ban, so a
	// later empty result is the guard and not a lookup that never worked.
	providers, err := node.FindProvidersByName(ctx, api.ServiceType_SERVICE_TYPE_MCP, "revoked-svc")
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].ID != hostB.ID() {
		t.Fatalf("expected to find %s as provider, got %v", hostB.ID(), providers)
	}

	node.revokedPeers.Add(hostB.ID().String(), time.Now().UnixMilli())

	providers, err = node.FindProvidersByName(ctx, api.ServiceType_SERVICE_TYPE_MCP, "revoked-svc")
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 0 {
		t.Errorf("revoked peer returned as provider: %v", providers)
	}
}
