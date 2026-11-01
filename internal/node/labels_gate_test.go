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
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/multiformats/go-multiaddr"
)

// The gate guards calls that ride relayed connections (egress proxy, MCP
// sessions). If its own auth stream could not, every relay-only peer would be
// refused as "no addresses" before the call it was checking ever ran.
func TestLabelGateDialsOverLimitedConnections(t *testing.T) {
	if allowed, _ := network.GetAllowLimitedConn(context.Background()); allowed {
		t.Fatal("a plain context must not allow limited connections; the test would prove nothing")
	}
	if allowed, _ := network.GetAllowLimitedConn(labelGateDialContext(context.Background())); !allowed {
		t.Fatal("the label gate's dial context must allow a relayed (limited) connection")
	}
}

func TestCheckPeerLabels(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPub

	providerPeer := peer.ID("provider-peer-id")
	expiry := time.Now().Add(time.Hour)

	mint := func(key ed25519.PrivateKey, p peer.ID, labels map[string]string) []byte {
		t.Helper()
		b, err := identity.MintBootstrapBiscuitToken(key, p, api.RoleNode, expiry, nil, labels)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		return b
	}

	node := &AgentMeshNode{
		trustedKeys:    []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}},
		BiscuitTimeout: 500 * time.Millisecond,
	}

	tests := []struct {
		name      string
		biscuit   []byte
		required  map[string]string
		expectErr bool
	}{
		{"exact match", mint(cpPriv, providerPeer, map[string]string{"region": "us-east-1"}), map[string]string{"region": "us-east-1"}, false},
		{"every pair of two attested", mint(cpPriv, providerPeer, map[string]string{"region": "na-us", "team": "platform"}), map[string]string{"region": "na-us", "team": "platform"}, false},
		{"one pair of two wrong fails", mint(cpPriv, providerPeer, map[string]string{"region": "na-us", "team": "platform"}), map[string]string{"region": "eu", "team": "platform"}, true},
		{"one pair of two missing fails", mint(cpPriv, providerPeer, map[string]string{"region": "na-us"}), map[string]string{"region": "na-us", "team": "platform"}, true},
		{"no built-in hierarchy: coarser requirement fails a finer claim", mint(cpPriv, providerPeer, map[string]string{"region": "us-east-1"}), map[string]string{"region": "us"}, true},
		{"disjoint labels fail", mint(cpPriv, providerPeer, map[string]string{"region": "na-us"}), map[string]string{"region": "eu"}, true},
		{"unattested token fails closed", mint(cpPriv, providerPeer, nil), map[string]string{"region": "eu"}, true},
		{"empty biscuit fails closed", nil, map[string]string{"region": "eu"}, true},
		{"untrusted signer fails", mint(otherPriv, providerPeer, map[string]string{"region": "eu"}), map[string]string{"region": "eu"}, true},
		{"token bound to another peer fails", mint(cpPriv, peer.ID("other-peer"), map[string]string{"region": "eu"}), map[string]string{"region": "eu"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := node.checkPeerLabels(tt.biscuit, providerPeer, tt.required)
			if tt.expectErr && err == nil {
				t.Error("expected error, got nil")
			} else if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	t.Run("no trusted keys fails closed", func(t *testing.T) {
		bare := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond}
		if err := bare.checkPeerLabels(mint(cpPriv, providerPeer, map[string]string{"region": "eu"}), providerPeer, map[string]string{"region": "eu"}); err == nil {
			t.Error("expected error, got nil")
		}
	})

	// A router's biscuit is a valid, trusted, peer-bound identity, but a
	// router is not a service provider; only role(node) may be dialled as one.
	t.Run("router biscuit is not a provider", func(t *testing.T) {
		routerTok, err := identity.MintBootstrapBiscuitToken(cpPriv, providerPeer, api.RoleRouter, expiry, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := node.checkPeerLabels(routerTok, providerPeer, nil); err == nil {
			t.Error("a router's biscuit must not pass the provider gate")
		}
		if err := node.checkPeerLabels(mint(cpPriv, providerPeer, nil), providerPeer, nil); err != nil {
			t.Errorf("a node's biscuit with no requirement must pass: %v", err)
		}
	})

	// A call that names a service is sent only to a provider whose credential
	// grants serving it, whatever the directory said; a call that names none
	// (the peer's catalog) needs no grant.
	t.Run("the provider must be granted the service the call names", func(t *testing.T) {
		mintPublish := func(publish ...string) []byte {
			role := &api.PolicyRole{Name: api.RoleNode, AllowedPublish: publish}
			b, err := identity.MintBootstrapBiscuitToken(cpPriv, providerPeer, api.RoleNode, expiry, []*api.PolicyRole{role}, nil)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		for name, tc := range map[string]struct {
			publish []string
			service string
			wantErr bool
		}{
			"granted by name":            {publish: []string{"mcp://calc"}, service: "mcp://calc"},
			"granted by type":            {publish: []string{"mcp://*"}, service: "mcp://calc"},
			"granted everything":         {publish: []string{"*"}, service: "inference://llm"},
			"another service":            {publish: []string{"mcp://calc"}, service: "mcp://weather", wantErr: true},
			"another type":               {publish: []string{"mcp://*"}, service: "inference://calc", wantErr: true},
			"no grant at all":            {publish: nil, service: "mcp://calc", wantErr: true},
			"no grant, no service named": {publish: nil, service: ""},
			"a service that is not one":  {publish: []string{"*"}, service: "calc", wantErr: true},
		} {
			t.Run(name, func(t *testing.T) {
				err := node.checkProvider(mintPublish(tc.publish...), providerPeer, nil, tc.service)
				if (err != nil) != tc.wantErr {
					t.Fatalf("checkProvider(%v, %q) = %v, wantErr %v", tc.publish, tc.service, err, tc.wantErr)
				}
				if tc.wantErr && tc.service != "calc" && !errors.Is(err, ErrProviderNotGranted) {
					t.Fatalf("err = %v, want ErrProviderNotGranted so the caller is told the provider is enrolled and not granted", err)
				}
			})
		}

		// The synced mesh policy grants too, from the provider's role, so a
		// policy change reaches the caller at its next sync and not at the
		// provider's next credential.
		t.Run("granted by the mesh policy", func(t *testing.T) {
			ungranted := mintPublish()
			if err := node.checkProvider(ungranted, providerPeer, nil, "mcp://calc"); !errors.Is(err, ErrProviderNotGranted) {
				t.Fatalf("checkProvider before the policy = %v, want ErrProviderNotGranted", err)
			}
			rules, _ := api.BuildPolicyRules([]*api.PolicyRole{{Name: api.RoleNode, AllowedPublish: []string{"mcp://calc"}}}, nil)
			parsed, err := api.ParseDatalogRules(api.PolicyRuleTexts(rules))
			if err != nil {
				t.Fatal(err)
			}
			node.MeshPolicyMu.Lock()
			node.MeshPolicyRules = parsed
			node.MeshPolicyMu.Unlock()
			t.Cleanup(func() {
				node.MeshPolicyMu.Lock()
				node.MeshPolicyRules = nil
				node.MeshPolicyMu.Unlock()
			})
			if err := node.checkProvider(ungranted, providerPeer, nil, "mcp://calc"); err != nil {
				t.Fatalf("checkProvider with the policy granting the node role mcp://calc = %v", err)
			}
			if err := node.checkProvider(ungranted, providerPeer, nil, "mcp://weather"); !errors.Is(err, ErrProviderNotGranted) {
				t.Fatalf("checkProvider(mcp://weather) = %v, want ErrProviderNotGranted: the policy grants mcp://calc only", err)
			}
		})
	})
}

// The egress floor is the operator's, and a caller cannot waive it by asking
// for nothing or by asking for something else. It is ANDed with the caller's
// requirement, so both hold independently: the caller may narrow the choice of
// provider, never widen it past the floor.
func TestCheckPeerLabelsEnforcesEgressFloor(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	providerPeer := peer.ID("provider-peer-id")
	expiry := time.Now().Add(time.Hour)

	mint := func(labels map[string]string) []byte {
		t.Helper()
		b, err := identity.MintBootstrapBiscuitToken(cpPriv, providerPeer, api.RoleNode, expiry, nil, labels)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		return b
	}

	nodeWithFloor := func(floor map[string]string) *AgentMeshNode {
		return &AgentMeshNode{
			trustedKeys:    []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}},
			BiscuitTimeout: 500 * time.Millisecond,
			nodeConfig:     &NodeConfigComplete{EgressRequireLabels: floor},
		}
	}

	euGdpr := map[string]string{"jurisdiction": "eu", "compliance": "gdpr"}

	tests := []struct {
		name      string
		floor     map[string]string
		required  map[string]string
		attested  map[string]string
		expectErr bool
	}{{
		name:     "caller requires nothing but the floor still applies",
		floor:    map[string]string{"jurisdiction": "eu"},
		required: nil,
		attested: map[string]string{"jurisdiction": "eu"},
	}, {
		name:      "caller requires nothing and the provider is outside the floor",
		floor:     map[string]string{"jurisdiction": "eu"},
		required:  nil,
		attested:  map[string]string{"jurisdiction": "us"},
		expectErr: true,
	}, {
		name:      "the floor is a conjunction: one pair short is not enough",
		floor:     euGdpr,
		required:  nil,
		attested:  map[string]string{"jurisdiction": "eu"},
		expectErr: true,
	}, {
		name:     "the floor is satisfied when every pair is attested",
		floor:    euGdpr,
		required: nil,
		attested: map[string]string{"jurisdiction": "eu", "compliance": "gdpr", "region": "de"},
	}, {
		// The whole reason the two are separate checks. Merged into one
		// disjunction, region=us-east-1 alone would satisfy it.
		name:      "a caller cannot widen the floor by naming another label",
		floor:     map[string]string{"jurisdiction": "eu"},
		required:  map[string]string{"region": "us-east-1"},
		attested:  map[string]string{"jurisdiction": "us", "region": "us-east-1"},
		expectErr: true,
	}, {
		name:     "caller and floor both satisfied",
		floor:    map[string]string{"jurisdiction": "eu"},
		required: map[string]string{"region": "de-txl"},
		attested: map[string]string{"jurisdiction": "eu", "region": "de-txl"},
	}, {
		name:      "caller narrows within the floor and the provider misses the narrowing",
		floor:     map[string]string{"jurisdiction": "eu"},
		required:  map[string]string{"region": "de-txl"},
		attested:  map[string]string{"jurisdiction": "eu", "region": "fr-par"},
		expectErr: true,
	}, {
		name:      "no floor configured leaves the caller's requirement alone",
		floor:     nil,
		required:  map[string]string{"region": "eu"},
		attested:  map[string]string{"region": "eu"},
		expectErr: false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := nodeWithFloor(tt.floor).checkPeerLabels(mint(tt.attested), providerPeer, tt.required)
			if tt.expectErr && err == nil {
				t.Errorf("expected rejection, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("expected acceptance, got %v", err)
			}
		})
	}
}

// VerifyPeerLabels has no short-circuit: with nothing to attest it still has
// to establish that the peer is an enrolled member, and with a floor
// configured there is always something to attest. Either way a caller that
// asked for nothing is gated, which is the difference between a floor and a
// suggestion, and between a provider and a peer that merely announced.
func TestVerifyPeerLabelsDoesNotShortCircuit(t *testing.T) {
	node := &AgentMeshNode{
		BiscuitTimeout: 500 * time.Millisecond,
		nodeConfig:     &NodeConfigComplete{EgressRequireLabels: map[string]string{"jurisdiction": "eu"}},
	}
	cache, err := lru.New[string, time.Time](8)
	if err != nil {
		t.Fatal(err)
	}
	node.peerLabelGate = cache

	// No identity, so the biscuit fetch cannot succeed. Reaching that failure
	// is the proof the gate ran at all; returning nil would mean it skipped.
	err = node.VerifyPeerLabels(context.Background(), peer.ID("some-peer"), nil)
	if err == nil {
		t.Fatal("a caller requiring nothing must still be gated when a floor is configured")
	}

	// Without a floor the gate still runs: an unenrolled peer is not a
	// provider just because nobody asked for a label.
	node.nodeConfig = &NodeConfigComplete{}
	if err := node.VerifyPeerLabels(context.Background(), peer.ID("some-peer"), nil); err == nil {
		t.Error("with no floor and no requirement the gate must still verify the peer's identity")
	}
}

// A provider that cannot be reached is not one that refused: the gate marks
// the first so a caller is answered 502 and may retry, and a verdict on a
// credential that was read stays a 403. On the testnet every caller of a
// provider that was down, or too busy to answer in time, was told
// "destination is not an enrolled peer".
func TestLabelGateTellsUnreachableFromDenied(t *testing.T) {
	node := &AgentMeshNode{BiscuitTimeout: 500 * time.Millisecond, nodeConfig: &NodeConfigComplete{}}
	cache, err := lru.New[string, time.Time](8)
	if err != nil {
		t.Fatal(err)
	}
	node.peerLabelGate = cache

	// No host, no identity: the biscuit fetch fails before any credential
	// is read, which is the unreachable case.
	err = node.VerifyPeerLabels(context.Background(), peer.ID("some-peer"), nil)
	if !errors.Is(err, ErrProviderUnreachable) {
		t.Fatalf("fetch failure: err = %v, want ErrProviderUnreachable", err)
	}
	if text, status := labelGateStatus(err, "denied"); status != http.StatusBadGateway || text == "denied" {
		t.Errorf("unreachable: got %d %q, want 502", status, text)
	}

	// A credential that was read and found wanting is a verdict.
	err = node.checkPeerLabels(nil, peer.ID("some-peer"), nil)
	if err == nil || errors.Is(err, ErrProviderUnreachable) {
		t.Fatalf("empty credential: err = %v, want a denial", err)
	}
	if text, status := labelGateStatus(err, "denied"); status != http.StatusForbidden || text != "denied" {
		t.Errorf("denied: got %d %q, want 403 denied", status, text)
	}
}

// authorizerFactLimitRules are mesh policy rules that derive more facts
// from role(node) than the authorizer admits, so any check that adds them
// stops at datalog.ErrWorldRunLimitMaxFacts before it reaches a verdict.
func authorizerFactLimitRules(t *testing.T) []biscuit.Rule {
	t.Helper()
	texts := make([]string, 0, 1100)
	for i := range 1100 {
		texts = append(texts, fmt.Sprintf("limit_fact_%d(true) <- role(%q)", i, api.RoleNode))
	}
	rules, err := api.ParseDatalogRules(texts)
	if err != nil {
		t.Fatalf("ParseDatalogRules: %v", err)
	}
	return rules
}

// An authorizer that stops at a run limit reaches no verdict on the
// provider's credential, so the caller is not told it was denied. Time
// depends on load: 504, and the caller may retry. The facts and iterations
// limits are reached again with the same credential and policy: 500.
func TestLabelGateTellsAuthorizerLimitFromDenied(t *testing.T) {
	cpPub, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	providerPeer := peer.ID("provider-peer-id")
	role := &api.PolicyRole{Name: api.RoleNode, AllowedPublish: []string{"mcp://calc"}}
	granted, err := identity.MintBootstrapBiscuitToken(cpPriv, providerPeer, api.RoleNode, time.Now().Add(time.Hour), []*api.PolicyRole{role}, nil)
	if err != nil {
		t.Fatal(err)
	}
	trusted := []TrustedKey{{Key: cpPub, ReceivedAt: time.Now()}}

	slow := &AgentMeshNode{trustedKeys: trusted, BiscuitTimeout: time.Nanosecond}
	err = slow.checkProvider(granted, providerPeer, nil, "mcp://calc")
	if !errors.Is(err, datalog.ErrWorldRunLimitTimeout) {
		t.Fatalf("checkProvider with a 1ns timeout = %v, want an error wrapping %v", err, datalog.ErrWorldRunLimitTimeout)
	}
	if text, status := labelGateStatus(err, "denied"); status != http.StatusGatewayTimeout || text == "denied" {
		t.Errorf("timeout: got %d %q, want 504", status, text)
	}

	full := &AgentMeshNode{trustedKeys: trusted, BiscuitTimeout: 500 * time.Millisecond, MeshPolicyRules: authorizerFactLimitRules(t)}
	err = full.checkProvider(granted, providerPeer, nil, "mcp://calc")
	if !errors.Is(err, datalog.ErrWorldRunLimitMaxFacts) || errors.Is(err, ErrProviderNotGranted) {
		t.Fatalf("checkProvider over the facts limit = %v, want an error wrapping %v and not %v", err, datalog.ErrWorldRunLimitMaxFacts, ErrProviderNotGranted)
	}
	if text, status := labelGateStatus(err, "denied"); status != http.StatusInternalServerError || text == "denied" {
		t.Errorf("facts limit: got %d %q, want 500", status, text)
	}
}

// The cache key has to separate the caller's requirement from the floor, or a
// pass recorded under one floor could be replayed under another.
func TestLabelGateKeySeparatesFloorFromRequirement(t *testing.T) {
	p := peer.ID("peer")
	a := labelGateKey(p, map[string]string{"jurisdiction": "eu"}, nil)
	b := labelGateKey(p, nil, map[string]string{"jurisdiction": "eu"})
	if a == b {
		t.Errorf("a requirement and a floor with the same pair must not share a cache key (%q)", a)
	}
}

// The key's separators are printable characters a label value is allowed to
// contain, so the encoding's unambiguity rests on ValidateLabelValue rejecting
// "=": a value can hold "|" or "#floor" but cannot forge the "|<key>=" that
// begins an entry. These are the shapes that would collide if it could.
func TestLabelGateKeyIsUnambiguousWithSeparatorsInValues(t *testing.T) {
	p := peer.ID("peer")
	// Every value here is valid input: the validator rejects only a comma, an
	// equals sign, and the three whitespace control characters.
	for _, v := range []string{"eu|x", "eu#floor", "#floor|b", "a|b#floor|c"} {
		if err := api.ValidateLabelValue(v); err != nil {
			t.Fatalf("test premise wrong, %q is not a valid label value: %v", v, err)
		}
	}

	seen := map[string][]string{}
	add := func(desc string, required, floor map[string]string) {
		k := labelGateKey(p, required, floor)
		seen[k] = append(seen[k], desc)
	}
	add("value carrying the entry separator", map[string]string{"a": "eu|x"}, nil)
	add("two entries", map[string]string{"a": "eu", "x": "1"}, nil)
	add("value carrying the floor marker", map[string]string{"a": "eu#floor"}, nil)
	add("floor holding the same pair", nil, map[string]string{"a": "eu"})
	add("requirement holding the same pair", map[string]string{"a": "eu"}, nil)
	add("value that looks like a floor section", map[string]string{"a": "#floor|b"}, nil)
	add("split across both sets", map[string]string{"a": "eu"}, map[string]string{"b": "1"})
	add("both sets, values with separators", map[string]string{"a": "a|b#floor|c"}, map[string]string{"b": "1"})

	for key, descs := range seen {
		if len(descs) > 1 {
			t.Errorf("these distinct inputs share cache key %q: %v", key, descs)
		}
	}
}

// A provider the caller did not reach is one 502 whatever happened; the
// counter tells the cases apart from the error libp2p hands back.
func TestReachFailureClassifiesWhatKeptTheProviderAway(t *testing.T) {
	peerID := peer.ID("12D3KooWtest")
	relayRefused := &swarm.DialError{Peer: peerID, Cause: swarm.ErrAllDialsFailed, DialErrors: []swarm.TransportError{
		{Address: multiaddr.StringCast("/p2p-circuit"), Cause: errors.New("error opening relay circuit: PERMISSION_DENIED (202)")},
	}}
	timedOut := &swarm.DialError{Peer: peerID, Cause: context.DeadlineExceeded}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("failed to open auth stream: %w", relayRefused), reachRelayRefused},
		{fmt.Errorf("failed to open auth stream: %w", timedOut), reachDialTimeout},
		{fmt.Errorf("failed to open auth stream: %w", &swarm.DialError{Peer: peerID, Cause: swarm.ErrNoAddresses}), reachNoAddress},
		{fmt.Errorf("failed to open auth stream: %w", &swarm.DialError{Peer: peerID, Cause: swarm.ErrAllDialsFailed, DialErrors: []swarm.TransportError{{Cause: errors.New("connection refused")}}}), reachDialFailed},
		{fmt.Errorf("failed to open auth stream: %w", context.DeadlineExceeded), reachDialTimeout},
		{errors.New("read auth response (peer may predate mutual auth): EOF"), reachNoAnswer},
		{errors.New("auth rejected: expired"), reachAuthRejected},
		{errors.New("something else"), reachOtherFailure},
	} {
		if got := reachFailure(tc.err); got != tc.want {
			t.Errorf("reachFailure(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}
