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
	"sync"
	"testing"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func candidate(t *testing.T, name string, labels map[string]string, connections, limit int) routerCandidate {
	t.Helper()
	// A peer ID is derived from the name so the test can tell them apart.
	id, err := peer.Decode("12D3KooW" + name)
	if err != nil {
		// Not a real ID: build one from the name's bytes instead.
		id = peer.ID("router-" + name)
	}
	addr := multiaddr.StringCast("/ip4/127.0.0.1/tcp/4501")
	return routerCandidate{
		AddrInfo:        peer.AddrInfo{ID: id, Addrs: []multiaddr.Multiaddr{addr}},
		Labels:          labels,
		Connections:     connections,
		ConnectionLimit: limit,
	}
}

func ids(infos []peer.AddrInfo) []peer.ID {
	out := make([]peer.ID, 0, len(infos))
	for _, pi := range infos {
		out = append(out, pi.ID)
	}
	return out
}

// TestSelectRouters pins the choice of routers: the selector is a
// requirement on every pair, the preference orders by pairs attested, load
// orders among equals, and routers already attached or shunned are left
// out. The second result tells "none match" from "all taken".
func TestSelectRouters(t *testing.T) {
	euEmpty := candidate(t, "eu-empty", map[string]string{"region": "eu", "zone": "eu-a"}, 100, 4000)
	euFull := candidate(t, "eu-full", map[string]string{"region": "eu", "zone": "eu-b"}, 3900, 4000)
	usEmpty := candidate(t, "us-empty", map[string]string{"region": "us"}, 0, 4000)
	unlabelled := candidate(t, "plain", nil, 0, 0)
	all := []routerCandidate{euFull, usEmpty, unlabelled, euEmpty}

	t.Run("by load when nothing else is said", func(t *testing.T) {
		picked, matched := selectRouters(all, 2, nil, nil, nil)
		if matched != 4 {
			t.Fatalf("matched = %d, want all 4", matched)
		}
		got := ids(picked)
		// The full router comes last; the unlabelled one with unknown load
		// sits in the middle at 0.5.
		if len(got) != 2 || got[0] == euFull.ID || got[1] == euFull.ID {
			t.Fatalf("picked %v, want the two with the most room", got)
		}
	})

	t.Run("selector is a requirement on every pair", func(t *testing.T) {
		picked, matched := selectRouters(all, 3, map[string]string{"region": "eu", "zone": "eu-a"}, nil, nil)
		if matched != 1 || len(picked) != 1 || picked[0].ID != euEmpty.ID {
			t.Fatalf("picked %v (matched %d), want only eu-a", ids(picked), matched)
		}
		_, matched = selectRouters(all, 3, map[string]string{"region": "apac"}, nil, nil)
		if matched != 0 {
			t.Fatalf("matched = %d for a region no router attests, want 0", matched)
		}
	})

	t.Run("preference orders before load", func(t *testing.T) {
		picked, _ := selectRouters(all, 2, nil, map[string]string{"region": "eu"}, nil)
		got := ids(picked)
		if len(got) != 2 || got[0] != euEmpty.ID || got[1] != euFull.ID {
			t.Fatalf("picked %v, want the eu routers first, the emptier one before the full one", got)
		}
		// More pairs attested ranks higher.
		picked, _ = selectRouters(all, 1, nil, map[string]string{"region": "eu", "zone": "eu-b"}, nil)
		if len(picked) != 1 || picked[0].ID != euFull.ID {
			t.Fatalf("picked %v, want eu-b for attesting both preferred pairs although full", ids(picked))
		}
	})

	t.Run("attached and shunned routers are left out, but still count as matching", func(t *testing.T) {
		exclude := map[peer.ID]bool{euEmpty.ID: true, usEmpty.ID: true}
		picked, matched := selectRouters(all, 5, nil, nil, exclude)
		if matched != 4 || len(picked) != 2 {
			t.Fatalf("picked %d (matched %d), want 2 of 4", len(picked), matched)
		}
		for _, pi := range picked {
			if exclude[pi.ID] {
				t.Fatalf("picked an excluded router %s", pi.ID)
			}
		}
	})

	t.Run("k is clamped", func(t *testing.T) {
		picked, _ := selectRouters(all[:1], 3, nil, nil, nil)
		if len(picked) != 1 {
			t.Fatalf("picked %d from 1 candidate, want 1", len(picked))
		}
	})
}

// A control plane that predates RouterInfo lists addresses alone; they
// become candidates with no labels and unknown load, so a selector matches
// none and a plain node still has something to attach to.
func TestCandidatesFromInfoFallsBackToAddresses(t *testing.T) {
	id, _ := peer.Decode("12D3KooWGvdRCJLYATauVWfsieF2j3a2wXZoEQJUS2MsvRdDtgLM")
	addr := "/ip4/127.0.0.1/tcp/4501/p2p/" + id.String()
	old := &api.ControlPlaneInfoResponse{RouterAddresses: []string{addr}}
	cands := candidatesFromInfo(context.Background(), old)
	if len(cands) != 1 || cands[0].ID != id || cands[0].Labels != nil || cands[0].ConnectionLimit != 0 {
		t.Fatalf("candidates from an address-only /info = %+v, want one unlabelled router", cands)
	}

	current := &api.ControlPlaneInfoResponse{
		RouterAddresses: []string{addr},
		Routers: []*api.RouterInfo{{
			PeerId: id.String(), Addresses: []string{addr},
			Labels: map[string]string{"region": "eu"}, Connections: 10, ConnectionLimit: 4000,
		}},
	}
	cands = candidatesFromInfo(context.Background(), current)
	if len(cands) != 1 || cands[0].Labels["region"] != "eu" || cands[0].Connections != 10 {
		t.Fatalf("candidates from /info = %+v, want the labelled router with its load", cands)
	}
}

// A router's /info entry lists it under a dnsaddr, and a dnsaddr resolves
// to every router behind the name. The entry's labels and load belong to
// the peer it names and to no other, so a node with a selector is not
// attached to a router that carries another router's labels.
func TestCandidatesFromInfoKeepOnlyTheNamedPeer(t *testing.T) {
	idA, _ := peer.Decode("12D3KooWGvdRCJLYATauVWfsieF2j3a2wXZoEQJUS2MsvRdDtgLM")
	idB, _ := peer.Decode("12D3KooWKgpmErz5j2Trn1xfUveATnszHSTBnJRZRrTpsFHkDXnp")
	addrA := "/ip4/10.0.0.1/tcp/4501/p2p/" + idA.String()
	addrB := "/ip4/10.0.0.2/tcp/4501/p2p/" + idB.String()
	// What resolving the shared name yields for each entry: both routers.
	both := []string{addrA, addrB}
	info := &api.ControlPlaneInfoResponse{
		Routers: []*api.RouterInfo{
			{PeerId: idA.String(), Addresses: both, Labels: map[string]string{"site": "a"}, Connections: 1, ConnectionLimit: 100},
			{PeerId: idB.String(), Addresses: both, Labels: map[string]string{"site": "b"}, Connections: 90, ConnectionLimit: 100},
		},
	}
	cands := candidatesFromInfo(context.Background(), info)
	if len(cands) != 2 {
		t.Fatalf("got %d candidates, want 2 (one per router): %+v", len(cands), cands)
	}
	byID := map[peer.ID]routerCandidate{}
	for _, c := range cands {
		byID[c.ID] = c
	}
	if byID[idA].Labels["site"] != "a" || byID[idA].Connections != 1 {
		t.Fatalf("router A = %+v, want site=a with 1 connection", byID[idA])
	}
	if byID[idB].Labels["site"] != "b" || byID[idB].Connections != 90 {
		t.Fatalf("router B = %+v, want site=b with 90 connections", byID[idB])
	}
	picked, matched := selectRouters(cands, 2, map[string]string{"site": "a"}, nil, nil)
	if matched != 1 || len(picked) != 1 || picked[0].ID != idA {
		t.Fatalf("selector site=a picked %v (matched %d), want router A alone", ids(picked), matched)
	}
}

// A node wants as many routers as it is configured for, but no more than
// attest its selector: with one matching router it is complete at one, and
// the monitor does not keep topping up.
func TestWantRoutersCountsSelectorMatches(t *testing.T) {
	n := &AgentMeshNode{config: Options{Routers: 2}}
	n.routerCatalog = []routerCandidate{
		candidate(t, "a", map[string]string{"site": "a"}, 0, 100),
		candidate(t, "b", map[string]string{"site": "b"}, 0, 100),
		candidate(t, "c", nil, 0, 100),
	}
	if got := n.wantRouters(); got != 2 {
		t.Fatalf("wantRouters without selector = %d, want 2", got)
	}
	n.config.RouterSelector = map[string]string{"site": "a"}
	if got := n.wantRouters(); got != 1 {
		t.Fatalf("wantRouters with selector site=a = %d, want 1", got)
	}
	n.config.RouterSelector = map[string]string{"site": "z"}
	if got := n.wantRouters(); got != 0 {
		t.Fatalf("wantRouters with a selector no router attests = %d, want 0", got)
	}
}

// Concurrent callers (admitByRouters, HandleGoAway, connection monitor) must
// never reserve more than Options.Routers in-flight + attached routers or pick
// the same router twice.
func TestConcurrentTopUpRoutersNeverOvershoots(t *testing.T) {
	n := &AgentMeshNode{
		config:               Options{Routers: 2},
		authenticatedRouters: map[peer.ID]bool{},
		reprovideTrigger:     make(chan struct{}, 1),
		routerCatalog: []routerCandidate{
			candidate(t, "r1", nil, 0, 100),
			candidate(t, "r2", nil, 0, 100),
			candidate(t, "r3", nil, 0, 100),
			candidate(t, "r4", nil, 0, 100),
			candidate(t, "r5", nil, 0, 100),
		},
	}

	const callers = 16
	start := make(chan struct{})
	results := make([][]peer.AddrInfo, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = n.reserveRoutersToAttach()
		}(i)
	}
	close(start)
	wg.Wait()

	seen := map[peer.ID]bool{}
	total := 0
	for _, batch := range results {
		for _, pi := range batch {
			total++
			if seen[pi.ID] {
				t.Fatalf("router %s reserved twice across concurrent callers", pi.ID)
			}
			seen[pi.ID] = true
		}
	}
	if total != 2 {
		t.Fatalf("concurrent reserveRoutersToAttach reserved %d routers, want 2", total)
	}

	var first, second peer.ID
	for pid := range seen {
		if first == "" {
			first = pid
		} else {
			second = pid
		}
	}
	n.mu.Lock()
	n.authenticatedRouters[first] = true
	n.mu.Unlock()
	n.finishDialAndAttach(first)

	// Releasing the second failed dial leaves exactly 1 slot open.
	n.clearDialing([]peer.AddrInfo{{ID: second}})
	repl := n.reserveRoutersToAttach()
	if len(repl) != 1 {
		t.Fatalf("replacement reserveRoutersToAttach = %d, want 1", len(repl))
	}
	if repl[0].ID == first {
		t.Fatalf("replacement picked already-attached router %s", first)
	}
}
