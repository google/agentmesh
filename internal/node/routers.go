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
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// routerCandidate is one router as the node knows it: where to reach it,
// the labels the control plane attested for it and its load as of its last
// lease. From /info when the control plane answered, from stored addresses
// alone when it did not.
type routerCandidate struct {
	peer.AddrInfo
	Labels          map[string]string
	Connections     int
	ConnectionLimit int
	IngressURL      string
}

// loadRatio is how full the router is, 0 to 1; 0.5 when its last lease
// said nothing.
func (c routerCandidate) loadRatio() float64 {
	if c.ConnectionLimit <= 0 {
		return 0.5
	}
	return float64(c.Connections) / float64(c.ConnectionLimit)
}

// routerTag protects an attached router's connection from the node's own
// connection manager, which otherwise trims by age and tag value and would
// take the router before a stranger.
const routerTag = "agentmesh-router"

// autorelayTag is the tag go-libp2p's AutoRelay protects a relay with once
// it holds a reservation there; reading it is how the node knows which
// routers relay for it.
const autorelayTag = "autorelay"

// candidatesFromInfo reads the routers /info lists. A control plane that
// predates RouterInfo lists addresses only; those become candidates without
// labels or load.
func candidatesFromInfo(ctx context.Context, info *api.ControlPlaneInfoResponse) []routerCandidate {
	if len(info.GetRouters()) == 0 {
		return candidatesFromAddrs(ctx, parseMultiaddrs(info.GetRouterAddresses()))
	}
	var out []routerCandidate
	seen := map[peer.ID]bool{}
	for _, r := range info.GetRouters() {
		id, err := peer.Decode(r.GetPeerId())
		if err != nil || seen[id] {
			continue
		}
		// A dnsaddr resolves to every router behind the name; only the peer
		// this entry is about carries its labels and load.
		for _, pi := range routerPeers(ctx, parseMultiaddrs(r.GetAddresses())) {
			if pi.ID != id {
				continue
			}
			seen[id] = true
			out = append(out, routerCandidate{
				AddrInfo:        pi,
				Labels:          r.GetLabels(),
				Connections:     int(r.GetConnections()),
				ConnectionLimit: int(r.GetConnectionLimit()),
				IngressURL:      r.GetIngressUrl(),
			})
		}
	}
	return out
}

func candidatesFromAddrs(ctx context.Context, addrs []multiaddr.Multiaddr) []routerCandidate {
	peers := routerPeers(ctx, addrs)
	out := make([]routerCandidate, 0, len(peers))
	for _, pi := range peers {
		out = append(out, routerCandidate{AddrInfo: pi})
	}
	return out
}

// selectRouters chooses up to k routers from cands: those that attest every
// pair of selector and are not excluded, ordered by how many pairs of prefer
// they attest, then by how full they are. A little noise on the load keeps a
// fleet that reads the same /info from piling onto one router before its
// next lease reports the change. The second result is how many candidates
// passed the selector, so a caller can tell "none match" from "all taken".
func selectRouters(cands []routerCandidate, k int, selector, prefer map[string]string, exclude map[peer.ID]bool) ([]peer.AddrInfo, int) {
	type scored struct {
		routerCandidate
		preferred int
		load      float64
	}
	var eligible []scored
	matched := 0
	for _, c := range cands {
		if len(selector) > 0 && !api.LabelsSatisfy(selector, c.Labels) {
			continue
		}
		matched++
		if exclude[c.ID] {
			continue
		}
		preferred := 0
		for key, value := range prefer {
			if c.Labels[key] == value {
				preferred++
			}
		}
		load := c.loadRatio() + rand.Float64()*0.05
		eligible = append(eligible, scored{c, preferred, load})
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].preferred != eligible[j].preferred {
			return eligible[i].preferred > eligible[j].preferred
		}
		return eligible[i].load < eligible[j].load
	})
	if k > len(eligible) {
		k = len(eligible)
	}
	out := make([]peer.AddrInfo, 0, k)
	for _, s := range eligible[:k] {
		out = append(out, s.AddrInfo)
	}
	return out, matched
}

// setRouterCatalog replaces what the node knows about the routers and keeps
// their addresses in the peerstore, so a circuit through any of them can be
// built later.
func (n *AgentMeshNode) setRouterCatalog(cands []routerCandidate) {
	n.mu.Lock()
	n.routerCatalog = cands
	n.mu.Unlock()
	if n.Host != nil {
		for _, c := range cands {
			n.Host.Peerstore().AddAddrs(c.ID, c.Addrs, peerstore.PermanentAddrTTL)
		}
	}
}

func (n *AgentMeshNode) routerCandidates() []routerCandidate {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]routerCandidate(nil), n.routerCatalog...)
}

// refreshRouterCatalog re-reads /info. Best effort: a node started from its
// stored addresses with no control plane in reach keeps what it has.
func (n *AgentMeshNode) refreshRouterCatalog(ctx context.Context) error {
	if n.Store == nil {
		return errors.New("no store")
	}
	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil || controlPlaneURL == "" {
		return errors.New("no control plane URL in store")
	}
	info, err := FetchControlPlaneInfo(ctx, controlPlaneURL)
	if err != nil {
		return err
	}
	if len(info.GetRouterAddresses()) == 0 && len(info.GetRouters()) == 0 {
		return errors.New("control plane lists no routers")
	}
	n.setRouterCatalog(candidatesFromInfo(ctx, info))
	return nil
}

// wantRouters is how many routers the node holds: its --routers, capped by
// the routers that attest its selector, so a selector that one router
// matches is a node that holds one router and is not short.
func (n *AgentMeshNode) wantRouters() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	matched := 0
	for _, c := range n.routerCatalog {
		if len(n.config.RouterSelector) == 0 || api.LabelsSatisfy(n.config.RouterSelector, c.Labels) {
			matched++
		}
	}
	return min(n.config.Routers, matched)
}

// attachedRouters lists the routers the node keeps and holds a live
// authenticated session with.
func (n *AgentMeshNode) attachedRouters() []peer.ID {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []peer.ID
	for pid := range n.attached {
		if n.authenticatedRouters[pid] && n.Host.Network().Connectedness(pid) == network.Connected {
			out = append(out, pid)
		}
	}
	return out
}

// AttachedRouters is how many routers the node keeps a live session with.
func (n *AgentMeshNode) AttachedRouters() int { return len(n.attachedRouters()) }

// WantRouters is how many routers the node keeps.
func (n *AgentMeshNode) WantRouters() int { return n.wantRouters() }

// RefreshRouters re-reads the routers from the control plane.
func (n *AgentMeshNode) RefreshRouters(ctx context.Context) error { return n.refreshRouterCatalog(ctx) }

// attach marks a router as one the node keeps: protected from the node's
// connection manager, redialled when it drops, and offered to AutoRelay for
// a reservation.
func (n *AgentMeshNode) attach(router peer.ID) {
	n.mu.Lock()
	if n.attached == nil {
		n.attached = map[peer.ID]bool{}
	}
	n.attached[router] = true
	n.mu.Unlock()
	if n.connMgr != nil {
		n.connMgr.Protect(router, routerTag)
	}
	n.refreshRelays()
	// A router to announce to: services registered before this one was
	// held, as the egress assignments are at start, go to the directory now.
	n.triggerReprovide()
}

// detach gives a router up: the node stops redialling it and lets the
// monitor top up from the others.
func (n *AgentMeshNode) detach(router peer.ID) {
	n.mu.Lock()
	delete(n.attached, router)
	n.mu.Unlock()
	if n.connMgr != nil {
		n.connMgr.Unprotect(router, routerTag)
	}
	n.refreshRelays()
}

func (n *AgentMeshNode) isAttached(router peer.ID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.attached[router]
}

// refreshRelays offers AutoRelay the routers the node is attached to: a
// reservation needs an authenticated session, which only those have.
func (n *AgentMeshNode) refreshRelays() {
	n.mu.Lock()
	defer n.mu.Unlock()
	var relays []peer.AddrInfo
	for _, c := range n.routerCatalog {
		if n.attached[c.ID] {
			relays = append(relays, c.AddrInfo)
		}
	}
	n.currentRelays = relays
}

// pickRouters chooses k routers to attach to, from the catalog, leaving out
// those already attached and those that sent the node away. When the
// catalog has routers and none passes the selector, the warning names both
// sides, since that is a configuration to fix rather than a router to wait
// for.
func (n *AgentMeshNode) pickRouters(k int) []peer.AddrInfo {
	cands := n.routerCandidates()
	n.mu.Lock()
	exclude := make(map[peer.ID]bool, len(n.attached)+len(n.shunned))
	for pid := range n.attached {
		exclude[pid] = true
	}
	now := time.Now()
	for pid, until := range n.shunned {
		if now.Before(until) {
			exclude[pid] = true
		} else {
			delete(n.shunned, pid)
		}
	}
	n.mu.Unlock()
	picked, matched := selectRouters(cands, k, n.config.RouterSelector, n.config.RouterPrefer, exclude)
	if matched == 0 && len(cands) > 0 && len(n.config.RouterSelector) > 0 {
		var seen []string
		for _, c := range cands {
			seen = append(seen, fmt.Sprintf("%s %v", c.ID.ShortString(), c.Labels))
		}
		logger.Warnf("[AuthN] No router attests the selector %v; routers listed: %s", n.config.RouterSelector, strings.Join(seen, ", "))
	}
	return picked
}

// shun keeps the node off a router for a while: one that told it to go
// away, or one that would not come back on redial.
func (n *AgentMeshNode) shun(router peer.ID, d time.Duration) {
	n.mu.Lock()
	if n.shunned == nil {
		n.shunned = map[peer.ID]time.Time{}
	}
	n.shunned[router] = time.Now().Add(d)
	n.mu.Unlock()
}

// dialAndAttach runs authRouter against each router at once and attaches
// the ones that admit the node, delivering one outcome per router on the
// returned channel in completion order. A caller may stop reading early:
// the dials still in flight attach on their own as they land.
func (n *AgentMeshNode) dialAndAttach(ctx context.Context, routers []peer.AddrInfo, biscuitBytes []byte) <-chan error {
	results := make(chan error, len(routers))
	for _, router := range routers {
		go func() {
			err := n.authRouter(ctx, router, biscuitBytes)
			if err != nil {
				logger.Warnf("[AuthN] Failed to bootstrap and auth with router %s: %v", router.ID, err)
			} else {
				n.attach(router.ID)
			}
			results <- err
		}()
	}
	return results
}

// topUpRouters attaches to routers until the node keeps as many as it
// wants, choosing from the catalog, and returns how many it then keeps.
// Every dial is waited for here: this is the monitor's path, where there
// is no one to be ready for.
func (n *AgentMeshNode) topUpRouters(ctx context.Context) int {
	have := n.AttachedRouters()
	want := n.wantRouters()
	if have >= want {
		return have
	}
	biscuitBytes, err := n.loadIdentityForAuth()
	if err != nil {
		logger.Errorf("[AuthN] Cannot attach to routers without an identity: %v", err)
		return have
	}
	targets := n.pickRouters(want - have)
	if len(targets) == 0 {
		return have
	}
	results := n.dialAndAttach(ctx, targets, biscuitBytes)
	for range targets {
		<-results
	}
	return n.AttachedRouters()
}

// TopUp attaches to more routers from what the node knows and returns how
// many it then keeps.
func (n *AgentMeshNode) TopUp(ctx context.Context) int { return n.topUpRouters(ctx) }

// goAwayMaxRetryAfter caps what a router may ask: a mistaken or hostile
// value does not keep the node off a router for good.
const goAwayMaxRetryAfter = time.Hour

// HandleGoAway takes a router's word that it will no longer hold this node:
// the node lets the router go, stays off it for the time the router named
// and attaches elsewhere now, rather than when the connection dies. Only a
// router the node holds is listened to; anyone may open the stream.
func (n *AgentMeshNode) HandleGoAway(ctx context.Context, s network.Stream) {
	defer func() { _ = s.Close() }()
	router := s.Conn().RemotePeer()
	if !n.isAttached(router) {
		logger.Debugf("[GoAway] Ignoring go-away from %s: not a router this node holds", router)
		_ = s.Reset()
		return
	}
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg, err := msgio.NewVarintReaderSize(s, 1024).ReadMsg()
	if err != nil {
		logger.Debugf("[GoAway] Reading go-away from %s: %v", router, err)
		_ = s.Reset()
		return
	}
	var goAway api.RouterGoAway
	if err := proto.Unmarshal(msg, &goAway); err != nil {
		logger.Debugf("[GoAway] Malformed go-away from %s: %v", router, err)
		_ = s.Reset()
		return
	}
	retryAfter := goAway.GetRetryAfter().AsDuration()
	if retryAfter <= 0 {
		retryAfter = n.config.RouterShunDuration
	}
	retryAfter = min(retryAfter, goAwayMaxRetryAfter)
	logger.Infof("[GoAway] Router %s sent this node away (%s); attaching elsewhere and staying off it for %s", router, goAway.GetReason(), retryAfter)
	goAwayReceivedTotal.WithLabelValues(goAway.GetReason().String()).Inc()
	n.shun(router, retryAfter)
	n.detach(router)
	n.mu.Lock()
	delete(n.authenticatedRouters, router)
	n.mu.Unlock()
	go n.topUpRouters(ctx)
}
