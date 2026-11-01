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
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// The replacement authenticates while the old router's redial is in flight.
// Letting that redial finish must not leave the node holding K+1 routers.
func TestRouterReplacementDuringRedial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	old := newFakeRouter(t, "/ip4/127.0.0.1/tcp/0")
	kept := newFakeRouterWithKey(t, old.cpPub, old.cpPriv, "/ip4/127.0.0.1/tcp/0")
	spare := newFakeRouterWithKey(t, old.cpPub, old.cpPriv, "/ip4/127.0.0.1/tcp/0")
	node := old.startNode(t, ctx, append(slices.Clone(old.routerAddrs), kept.routerAddrs...), func(o *Options) {
		o.Routers = 2
		o.RouterRedialDelay = time.Millisecond
		o.MonitorBootstrap = time.Hour
	})
	node.setRouterCatalog(candidatesFromAddrs(ctx, append(append(slices.Clone(old.routerAddrs), kept.routerAddrs...), spare.routerAddrs...)))
	waitForRouterState(t, ctx, "both initial attachments", func() bool { return node.AttachedRouters() == 2 })

	started, resume := make(chan struct{}), make(chan struct{})
	var startedOnce, resumeOnce sync.Once
	defer resumeOnce.Do(func() { close(resume) })
	old.h.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		startedOnce.Do(func() { close(started) })
		select {
		case <-resume:
			old.admit(s)
		case <-ctx.Done():
			_ = s.Reset()
		}
	})
	dropFromRouter(t, old.h, node)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("old router's redial never reached its handshake")
	}
	if got := node.topUpRouters(ctx); got != 2 {
		t.Fatalf("top-up holds %d routers, want 2", got)
	}
	if node.isAttached(old.h.ID()) {
		t.Error("replaced router is still held while its redial is pending")
	}
	resumeOnce.Do(func() { close(resume) })
	waitForRouterState(t, ctx, "old router's redial to finish", func() bool {
		node.mu.Lock()
		defer node.mu.Unlock()
		return !node.redialing[old.h.ID()]
	})
	got := node.attachedRouters()
	if len(got) != 2 || !slices.Contains(got, kept.h.ID()) || !slices.Contains(got, spare.h.ID()) {
		t.Errorf("routers after redial = %v, want kept %s and spare %s", got, kept.h.ID(), spare.h.ID())
	}
	if node.connMgr.IsProtected(old.h.ID(), routerTag) {
		t.Error("replaced router is still protected by the attachment tag")
	}
	node.mu.Lock()
	relays := slices.Clone(node.currentRelays)
	node.mu.Unlock()
	if len(relays) != 2 {
		t.Errorf("AutoRelay candidates = %v, want the two remaining attachments", relays)
	}
	for _, relay := range relays {
		if relay.ID == old.h.ID() {
			t.Error("replaced router is still offered to AutoRelay")
		}
	}
}

// A delayed top-up and concurrent top-ups can finish after another path has
// already filled the target. Admission must check the live count atomically.
func TestAttachKeepsRouterLimit(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "already full"
		if lost {
			name = "concurrent replacements"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			kept := newFakeRouter(t, "/ip4/127.0.0.1/tcp/0")
			one := newFakeRouterWithKey(t, kept.cpPub, kept.cpPriv, "/ip4/127.0.0.1/tcp/0")
			two := newFakeRouterWithKey(t, kept.cpPub, kept.cpPriv, "/ip4/127.0.0.1/tcp/0")
			node := kept.startNode(t, ctx, kept.routerAddrs, func(o *Options) {
				o.Routers = 1
				o.RouterRedialDelay = -1
				o.MonitorBootstrap = time.Hour
			})
			node.setRouterCatalog(candidatesFromAddrs(ctx, append(append(slices.Clone(kept.routerAddrs), one.routerAddrs...), two.routerAddrs...)))
			if lost {
				dropFromRouter(t, kept.h, node)
				waitForRouterState(t, ctx, "old session to clear", func() bool {
					node.mu.Lock()
					defer node.mu.Unlock()
					return !node.authenticatedRouters[kept.h.ID()]
				})
			}
			identity, err := node.loadIdentityForAuth()
			if err != nil {
				t.Fatal(err)
			}
			for _, router := range []*fakeRouter{one, two} {
				if err := node.authRouter(ctx, peer.AddrInfo{ID: router.h.ID(), Addrs: router.h.Addrs()}, identity); err != nil {
					t.Fatal(err)
				}
			}
			ready := make(chan struct{})
			var attaching sync.WaitGroup
			for _, id := range []peer.ID{one.h.ID(), two.h.ID()} {
				attaching.Go(func() {
					<-ready
					node.attach(id)
				})
			}
			close(ready)
			attaching.Wait()
			got := node.attachedRouters()
			if len(got) != 1 {
				t.Fatalf("routers = %v, want exactly one", got)
			}
			if !lost && got[0] != kept.h.ID() {
				t.Errorf("router = %s, want existing live router %s", got[0], kept.h.ID())
			}
			if lost && got[0] == kept.h.ID() {
				t.Errorf("router = %s, want one of the replacements", got[0])
			}
			for _, id := range []peer.ID{kept.h.ID(), one.h.ID(), two.h.ID()} {
				want := id == got[0]
				if node.isAttached(id) != want || node.connMgr.IsProtected(id, routerTag) != want {
					t.Errorf("router %s attachment/protection must be %v", id, want)
				}
			}
		})
	}
}

func TestAttachRetainsRedialUntilTargetIsFull(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	old := newFakeRouter(t, "/ip4/127.0.0.1/tcp/0")
	one := newFakeRouterWithKey(t, old.cpPub, old.cpPriv, "/ip4/127.0.0.1/tcp/0")
	two := newFakeRouterWithKey(t, old.cpPub, old.cpPriv, "/ip4/127.0.0.1/tcp/0")
	node := old.startNode(t, ctx, old.routerAddrs, func(o *Options) {
		o.Routers = 2
		o.RouterRedialDelay = -1
		o.MonitorBootstrap = time.Hour
	})
	all := append(append(slices.Clone(old.routerAddrs), one.routerAddrs...), two.routerAddrs...)
	node.setRouterCatalog(candidatesFromAddrs(ctx, all))
	dropFromRouter(t, old.h, node)
	waitForRouterState(t, ctx, "old router's session to clear", func() bool {
		node.mu.Lock()
		defer node.mu.Unlock()
		return !node.authenticatedRouters[old.h.ID()]
	})
	identity, err := node.loadIdentityForAuth()
	if err != nil {
		t.Fatal(err)
	}
	for i, router := range []*fakeRouter{one, two} {
		if err := node.authRouter(ctx, peer.AddrInfo{ID: router.h.ID(), Addrs: router.h.Addrs()}, identity); err != nil {
			t.Fatal(err)
		}
		node.attach(router.h.ID())
		if got := node.isAttached(old.h.ID()); got != (i == 0) {
			t.Errorf("old router held = %v after replacement %d, want %v", got, i+1, i == 0)
		}
	}
}

func waitForRouterState(t *testing.T, ctx context.Context, description string, ready func() bool) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %s: %v", description, ctx.Err())
		case <-tick.C:
		}
	}
}
