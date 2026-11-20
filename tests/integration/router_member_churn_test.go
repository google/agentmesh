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

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
)

// churnUpstreamLeaksEnv runs the checks that fail on the libp2p releases
// go.mod pins today. They are skipped by default so CI stays green, and are
// meant to run unconditionally in the change that bumps both modules to
// releases carrying libp2p/go-libp2p-pubsub#735 and libp2p/go-libp2p#3559.
const churnUpstreamLeaksEnv = "AGENTMESH_TEST_UPSTREAM_LEAKS"

const (
	// churnMembers is how many members join and leave: enough that a
	// per-member leak stands far above the noise, few enough to stay fast.
	churnMembers = 50
	// churnGoroutineTolerance absorbs the mesh's own background work (DHT
	// refresh, leases, timers) between the baseline and the final count. A
	// per-member leak is churnMembers or more.
	churnGoroutineTolerance = 5
	// churnAddrBookGC is how often pstoremem garbage collects expired addrs.
	churnAddrBookGC = time.Minute
	// pubsubPerPeerContext is the gossipsub function that derives each
	// peer's writer context from the PubSub context with context.WithCancel.
	pubsubPerPeerContext = "github.com/libp2p/go-libp2p-pubsub.(*PubSub).handleNewPeer"
)

// churnLabel marks every goroutine the control plane and router start, and
// every goroutine those start, so their count can be told apart from the
// members' in one process.
var churnLabel = pprof.Labels("agentmesh_test", "mesh")

// TestRouterReleasesDepartedMembers is the regression test for item 1 of
// #277: router memory that stays allocated after members leave. Members
// join a router, authenticate, and leave; afterwards nothing the router
// holds per member may remain. Everything is read from outside the router:
// the goroutine profile, the heap profile, and the router's libp2p host.
// The goroutine and connection checks pass today. The gossipsub and
// peerstore checks pin the two upstream leaks behind that item and fail
// until go.mod picks up libp2p/go-libp2p-pubsub#735 and
// libp2p/go-libp2p#3559; set AGENTMESH_TEST_UPSTREAM_LEAKS=1 to run them.
func TestRouterReleasesDepartedMembers(t *testing.T) {
	timeout := 3 * time.Minute
	if os.Getenv(churnUpstreamLeaksEnv) != "" {
		// The peerstore check waits out RecentlyConnectedAddrTTL in wall time.
		timeout += peerstore.RecentlyConnectedAddrTTL + 2*churnAddrBookGC
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)

	// Record every allocation, so the heap profile counts each live
	// per-peer gossipsub context rather than a sample of them.
	prevRate := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	t.Cleanup(func() { runtime.MemProfileRate = prevRate })

	var mesh *readmissionMesh
	pprof.Do(ctx, churnLabel, func(ctx context.Context) {
		mesh = startReadmissionMesh(t, ctx)
	})
	rtr := mesh.router.Host
	routerInfo, err := peer.AddrInfoFromString(mesh.routerAddr)
	if err != nil {
		t.Fatal(err)
	}

	baseGoroutines := churnSettledGoroutines(t, ctx)
	baseContexts := liveAllocsUnder(pubsubPerPeerContext, "context.WithCancel")
	basePeers := len(rtr.Network().Peers())
	t.Logf("baseline: %d mesh goroutines, %d live gossipsub per-peer contexts, %d router peers", baseGoroutines, baseContexts, basePeers)

	// Join: every member authenticates, and the router's gossipsub opens a
	// stream to it on a context derived from the PubSub context, while
	// identify files each member's addrs in the router's peerstore.
	members := make([]host.Host, 0, churnMembers)
	for range churnMembers {
		members = append(members, joinChurnMember(t, ctx, mesh, *routerInfo))
	}
	churnWaitFor(t, ctx, 15*time.Second, func() (bool, string) {
		got := liveAllocsUnder(pubsubPerPeerContext, "context.WithCancel") - baseContexts
		return got >= churnMembers, fmt.Sprintf("live gossipsub per-peer contexts above baseline = %d, want at least %d", got, churnMembers)
	})
	churnWaitFor(t, ctx, 15*time.Second, func() (bool, string) {
		missing := 0
		filed := rtr.Peerstore().PeersWithAddrs()
		for _, m := range members {
			if !slices.Contains(filed, m.ID()) {
				missing++
			}
		}
		return missing == 0, fmt.Sprintf("%d of %d members have no addrs in the router's peerstore", missing, len(members))
	})
	attached := churnGoroutines(t)
	if want := baseGoroutines + churnMembers; attached < want {
		t.Fatalf("mesh goroutines with %d members attached = %d, want at least %d", churnMembers, attached, want)
	}
	t.Logf("%d members joined; %d mesh goroutines while attached", churnMembers, attached)

	// Leave: each member closes its host, and with it every connection.
	departed := make([]peer.ID, 0, len(members))
	for _, m := range members {
		departed = append(departed, m.ID())
		_ = m.Close()
	}

	t.Run("router drops departed connections", func(t *testing.T) {
		churnWaitFor(t, ctx, 15*time.Second, func() (bool, string) {
			held := 0
			for _, p := range rtr.Network().Peers() {
				if slices.Contains(departed, p) {
					held++
				}
			}
			return held == 0, fmt.Sprintf("router still connected to %d of %d departed members", held, len(departed))
		})
	})

	t.Run("goroutines return to baseline", func(t *testing.T) {
		churnWaitFor(t, ctx, 15*time.Second, func() (bool, string) {
			got := churnGoroutines(t)
			return got <= baseGoroutines+churnGoroutineTolerance,
				fmt.Sprintf("mesh goroutines = %d after %d members left, want at most %d (baseline %d + %d)", got, churnMembers, baseGoroutines+churnGoroutineTolerance, baseGoroutines, churnGoroutineTolerance)
		})
	})

	t.Run("gossipsub releases per-peer contexts", func(t *testing.T) {
		churnSkipUnlessUpstreamLeaks(t, "go-libp2p-pubsub v0.18.0", "libp2p/go-libp2p-pubsub#735", "the writer context of every departed peer stays registered with the PubSub context")
		churnWaitFor(t, ctx, 15*time.Second, func() (bool, string) {
			got := liveAllocsUnder(pubsubPerPeerContext, "context.WithCancel")
			return got <= baseContexts, fmt.Sprintf("live gossipsub per-peer contexts after %d members left = %d, want the baseline %d", churnMembers, got, baseContexts)
		})
	})

	t.Run("peerstore drops departed members after RecentlyConnectedAddrTTL", func(t *testing.T) {
		churnSkipUnlessUpstreamLeaks(t, "go-libp2p v0.49.0", "libp2p/go-libp2p#3559", "addrs downgraded from ConnectedAddrTTL never enter the expiry heap, so the addr book keeps them past their TTL")
		// On a member's last disconnect identify moves its addrs to
		// RecentlyConnectedAddrTTL; past that TTL the addr book's next gc
		// must drop them. With no clock to move, this waits in wall time.
		churnWaitFor(t, ctx, peerstore.RecentlyConnectedAddrTTL+2*churnAddrBookGC, func() (bool, string) {
			held := 0
			for _, p := range rtr.Peerstore().PeersWithAddrs() {
				if slices.Contains(departed, p) {
					held++
				}
			}
			return held == 0, fmt.Sprintf("%d of %d departed members still have addrs in the router's peerstore past RecentlyConnectedAddrTTL and the addr book's gc", held, len(departed))
		})
	})
}

// joinChurnMember starts a member that runs gossipsub, connects to the
// router and completes the mesh handshake with a node credential.
func joinChurnMember(t *testing.T, ctx context.Context, mesh *readmissionMesh, routerInfo peer.AddrInfo) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if _, err := pubsub.NewGossipSub(ctx, h); err != nil {
		t.Fatalf("gossipsub: %v", err)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := h.Connect(connectCtx, routerInfo); err != nil {
		t.Fatalf("connect to router: %v", err)
	}
	authHandshake(t, ctx, h, routerInfo.ID, goHostBiscuit(t, mesh.cpPriv, h.ID()))
	return h
}

func churnSkipUnlessUpstreamLeaks(t *testing.T, pinned, fix, leak string) {
	t.Helper()
	if os.Getenv(churnUpstreamLeaksEnv) == "" {
		t.Skipf("fails on %s until %s is released and picked up: %s; set %s=1 to run", pinned, fix, leak, churnUpstreamLeaksEnv)
	}
}

// liveAllocsUnder counts the heap objects still live that were allocated
// with both functions on the stack, after two collections so the heap
// profile reflects every free.
func liveAllocsUnder(caller, callee string) int64 {
	runtime.GC()
	runtime.GC()
	var records []runtime.MemProfileRecord
	n, _ := runtime.MemProfile(nil, true)
	for {
		records = make([]runtime.MemProfileRecord, n+64)
		var ok bool
		if n, ok = runtime.MemProfile(records, true); ok {
			records = records[:n]
			break
		}
	}
	var live int64
	for _, r := range records {
		if r.InUseObjects() == 0 {
			continue
		}
		var sawCaller, sawCallee bool
		frames := runtime.CallersFrames(r.Stack())
		for {
			f, more := frames.Next()
			sawCaller = sawCaller || f.Function == caller
			sawCallee = sawCallee || f.Function == callee
			if !more {
				break
			}
		}
		if sawCaller && sawCallee {
			live += r.InUseObjects()
		}
	}
	return live
}

// churnGoroutines counts the goroutines that carry churnLabel, from the
// debug=1 goroutine profile.
func churnGoroutines(t *testing.T) int {
	t.Helper()
	var buf bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&buf, 1); err != nil {
		t.Fatalf("goroutine profile: %v", err)
	}
	total := 0
	for _, group := range strings.Split(buf.String(), "\n\n") {
		lines := strings.Split(strings.TrimSpace(group), "\n")
		if len(lines) < 2 || !strings.HasPrefix(lines[1], "# labels: ") || !strings.Contains(lines[1], `"agentmesh_test":"mesh"`) {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(lines[0], "%d @", &n); err == nil {
			total += n
		}
	}
	return total
}

// churnSettledGoroutines waits until the labelled goroutine count holds
// still for a second, startup work done, and returns it.
func churnSettledGoroutines(t *testing.T, ctx context.Context) int {
	t.Helper()
	last, same := -1, 0
	churnWaitFor(t, ctx, 20*time.Second, func() (bool, string) {
		now := churnGoroutines(t)
		if now == last {
			same++
		} else {
			same = 0
		}
		last = now
		return same >= 20, fmt.Sprintf("mesh goroutines did not settle; last count %d", now)
	})
	return last
}

// churnWaitFor polls cond until it holds, and fails the test with cond's
// last message when timeout passes first.
func churnWaitFor(t *testing.T, ctx context.Context, timeout time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		ok, msg := cond()
		if ok {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", msg, ctx.Err())
		case <-deadline.C:
			t.Fatalf("after %v: %s", timeout, msg)
		case <-tick.C:
		}
	}
}
