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

package meshnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	cpclient "github.com/google/agentmesh/internal/controlplane/client"
	"github.com/google/agentmesh/internal/identity"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"google.golang.org/protobuf/proto"
)

const (
	routerTag    = "agentmesh-router"
	autorelayTag = "autorelay"

	routerConnectTimeout    = 10 * time.Second
	routerRedialDelay       = 2 * time.Second
	routerRedialAttempts    = 3
	routerAuthAttempts      = 4
	controlPlaneSyncDefault = 30 * time.Second
	eventFreshnessThreshold = 5 * time.Minute
	keyGracePeriod          = 24 * time.Hour
	reEnrollMinInterval     = time.Minute
)

var (
	errFatalAuth       = errors.New("fatal router auth failure")
	readmitRetryDelays = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}
)

type routerCandidate struct {
	peer.AddrInfo
	Labels          map[string]string
	Connections     int
	ConnectionLimit int
	IngressURL      string
}

func (c routerCandidate) loadRatio() float64 {
	if c.ConnectionLimit <= 0 {
		return 0.5
	}
	return float64(c.Connections) / float64(c.ConnectionLimit)
}

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

func parseMultiaddrs(addrs []string) []multiaddr.Multiaddr {
	out := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, raw := range addrs {
		ma, err := multiaddr.NewMultiaddr(raw)
		if err != nil {
			continue
		}
		out = append(out, ma)
	}
	return out
}

func stripP2pFromDnsaddr(addr multiaddr.Multiaddr) multiaddr.Multiaddr {
	if _, err := addr.ValueForProtocol(multiaddr.P_DNSADDR); err != nil {
		return addr
	}
	parts := multiaddr.Split(addr)
	var components []multiaddr.Multiaddrer
	for _, p := range parts {
		if _, err := p.ValueForProtocol(multiaddr.P_P2P); err != nil {
			components = append(components, multiaddr.Multiaddr{p})
		}
	}
	if len(components) > 0 {
		return multiaddr.Join(components...)
	}
	return addr
}

func resolveAddrIfNeeded(ctx context.Context, addr multiaddr.Multiaddr) ([]multiaddr.Multiaddr, error) {
	if _, err := addr.ValueForProtocol(multiaddr.P_DNSADDR); err != nil {
		return []multiaddr.Multiaddr{addr}, nil
	}
	return madns.DefaultResolver.Resolve(ctx, stripP2pFromDnsaddr(addr))
}

func routerPeers(ctx context.Context, addrs []multiaddr.Multiaddr) []peer.AddrInfo {
	var order []peer.ID
	byPeer := map[peer.ID]*peer.AddrInfo{}
	for _, addr := range addrs {
		resolved, err := resolveAddrIfNeeded(ctx, addr)
		if err != nil {
			resolved = []multiaddr.Multiaddr{addr}
		}
		for _, r := range resolved {
			info, err := peer.AddrInfoFromP2pAddr(r)
			if err != nil || info.ID == "" {
				continue
			}
			known, seen := byPeer[info.ID]
			if !seen {
				byPeer[info.ID] = info
				order = append(order, info.ID)
				continue
			}
			for _, a := range info.Addrs {
				if !slices.ContainsFunc(known.Addrs, a.Equal) {
					known.Addrs = append(known.Addrs, a)
				}
			}
		}
	}
	out := make([]peer.AddrInfo, 0, len(order))
	for _, id := range order {
		out = append(out, *byPeer[id])
	}
	return out
}

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
		for key, val := range prefer {
			if c.Labels[key] == val {
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
	for _, item := range eligible[:k] {
		out = append(out, item.AddrInfo)
	}
	return out, matched
}

func (s *Server) setRouterCatalog(cands []routerCandidate) {
	s.mu.Lock()
	s.routerCatalog = cands
	s.mu.Unlock()
	if s.host != nil {
		for _, c := range cands {
			s.host.Peerstore().AddAddrs(c.ID, c.Addrs, peerstore.PermanentAddrTTL)
		}
	}
}

func (s *Server) routerCandidates() []routerCandidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.routerCatalog)
}

func (s *Server) isCatalogRouter(p peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.routerCatalog {
		if c.ID == p {
			return true
		}
	}
	return false
}

func (s *Server) routerIngressURLs() []string {
	cands := s.routerCandidates()
	seen := make(map[string]bool, len(cands))
	var out []string
	for _, c := range cands {
		u := strings.TrimSuffix(strings.TrimSpace(c.IngressURL), "/")
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func (s *Server) wantRouters() int {
	target := s.Routers
	if target <= 0 {
		target = 2
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	matched := 0
	for _, c := range s.routerCatalog {
		if len(s.RouterSelector) == 0 || api.LabelsSatisfy(s.RouterSelector, c.Labels) {
			matched++
		}
	}
	return min(target, matched)
}

func (s *Server) attachedRouters() []peer.ID {
	if s.host == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []peer.ID
	for pid := range s.attached {
		if s.authenticatedRouters[pid] && s.host.Network().Connectedness(pid) == network.Connected {
			out = append(out, pid)
		}
	}
	return out
}

func (s *Server) authenticatedRouterIDs() []peer.ID {
	if s.host == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]peer.ID, 0, len(s.authenticatedRouters))
	for pid := range s.authenticatedRouters {
		if s.host.Network().Connectedness(pid) == network.Connected {
			out = append(out, pid)
		}
	}
	return out
}

func (s *Server) isAuthenticatedAndConnected(router peer.ID) bool {
	if s.host == nil {
		return false
	}
	s.mu.Lock()
	authed := s.authenticatedRouters[router]
	s.mu.Unlock()
	return authed && s.host.Network().Connectedness(router) == network.Connected
}

func (s *Server) isAttached(router peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attached[router]
}

func (s *Server) attach(router peer.ID) {
	s.mu.Lock()
	if s.attached == nil {
		s.attached = map[peer.ID]bool{}
	}
	s.attached[router] = true
	s.mu.Unlock()
	if s.connMgr != nil {
		s.connMgr.Protect(router, routerTag)
	}
	s.refreshRelays()
	s.triggerReprovide()
}

func (s *Server) detach(router peer.ID) {
	s.mu.Lock()
	delete(s.attached, router)
	s.mu.Unlock()
	if s.connMgr != nil {
		s.connMgr.Unprotect(router, routerTag)
	}
	s.refreshRelays()
}

func (s *Server) refreshRelays() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var relays []peer.AddrInfo
	for _, c := range s.routerCatalog {
		if s.attached[c.ID] {
			relays = append(relays, c.AddrInfo)
		}
	}
	s.currentRelays = relays
}

func (s *Server) shun(router peer.ID, d time.Duration) {
	s.mu.Lock()
	if s.shunned == nil {
		s.shunned = map[peer.ID]time.Time{}
	}
	s.shunned[router] = time.Now().Add(d)
	s.mu.Unlock()
}

func (s *Server) pickRouters(k int) []peer.AddrInfo {
	cands := s.routerCandidates()
	s.mu.Lock()
	exclude := make(map[peer.ID]bool, len(s.attached)+len(s.shunned))
	for pid := range s.attached {
		exclude[pid] = true
	}
	now := time.Now()
	for pid, until := range s.shunned {
		if now.Before(until) {
			exclude[pid] = true
		} else {
			delete(s.shunned, pid)
		}
	}
	s.mu.Unlock()

	picked, matched := selectRouters(cands, k, s.RouterSelector, s.RouterPrefer, exclude)
	if matched == 0 && len(cands) > 0 && len(s.RouterSelector) > 0 {
		s.log().Warn("no router attests RouterSelector", "selector", s.RouterSelector)
	}
	return picked
}

func (s *Server) admitByRouters(ctx context.Context) error {
	if len(s.routerCandidates()) == 0 {
		return errors.New("meshnet: control plane lists no routers")
	}
	biscuitBytes := s.currentBiscuit()
	if len(biscuitBytes) == 0 {
		return errors.New("meshnet: missing member biscuit")
	}
	delay := routerRedialDelay
	for attempt := 1; ; attempt++ {
		if attempt > 1 {
			_ = s.syncMeshInfo(ctx)
		}
		targets := s.pickRouters(s.wantRouters())
		var fatal error
		if len(targets) > 0 {
			results := s.dialAndAttach(ctx, targets, biscuitBytes)
			for range targets {
				err := <-results
				if err == nil {
					return nil
				}
				if errors.Is(err, errFatalAuth) {
					fatal = err
				}
			}
		}
		if fatal != nil {
			return fatal
		}
		if attempt >= routerAuthAttempts {
			return errors.New("meshnet: failed to authenticate with any router")
		}
		s.log().Warn("no router admitted member; retrying", "attempt", attempt, "delay", delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
}

func (s *Server) dialAndAttach(ctx context.Context, routers []peer.AddrInfo, biscuitBytes []byte) <-chan error {
	results := make(chan error, len(routers))
	for _, r := range routers {
		go func() {
			err := s.authRouter(ctx, r, biscuitBytes)
			if err != nil {
				s.log().Warn("failed to connect and authenticate with router", "router_peer_id", r.ID.String(), "error", err)
			} else {
				s.attach(r.ID)
			}
			results <- err
		}()
	}
	return results
}

func (s *Server) topUpRouters(ctx context.Context) {
	have := len(s.attachedRouters())
	want := s.wantRouters()
	if have >= want {
		return
	}
	biscuitBytes := s.currentBiscuit()
	if len(biscuitBytes) == 0 {
		return
	}
	targets := s.pickRouters(want - have)
	if len(targets) == 0 {
		return
	}
	results := s.dialAndAttach(ctx, targets, biscuitBytes)
	for range targets {
		<-results
	}
}

func (s *Server) authRouter(ctx context.Context, router peer.AddrInfo, biscuitBytes []byte) error {
	if s.isAuthenticatedAndConnected(router.ID) {
		return nil
	}
	s.mu.Lock()
	if done, inFlight := s.handshaking[router.ID]; inFlight {
		s.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		if s.isAuthenticatedAndConnected(router.ID) {
			return nil
		}
		return fmt.Errorf("router %s: concurrent handshake did not succeed", router.ID)
	}
	if s.handshaking == nil {
		s.handshaking = map[peer.ID]chan struct{}{}
	}
	done := make(chan struct{})
	s.handshaking[router.ID] = done
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.handshaking, router.ID)
		s.mu.Unlock()
		close(done)
	}()

	routerCtx, cancel := context.WithTimeout(ctx, routerConnectTimeout)
	defer cancel()
	if len(router.Addrs) == 0 && s.host != nil {
		router.Addrs = s.host.Peerstore().Addrs(router.ID)
	}
	if err := s.host.Connect(routerCtx, router); err != nil {
		if strings.Contains(err.Error(), "peer id mismatch") {
			return fmt.Errorf("%w: %w", errFatalAuth, err)
		}
		return fmt.Errorf("connect to router %s: %w", router.ID, err)
	}
	if err := s.authenticateRouterSession(routerCtx, router.ID, biscuitBytes); err != nil {
		return fmt.Errorf("router %s: %w", router.ID, err)
	}
	s.authOnce.Do(func() {
		close(s.authSuccess)
	})
	return nil
}

func (s *Server) authenticateRouterSession(ctx context.Context, router peer.ID, biscuitBytes []byte) error {
	st, err := s.host.NewStream(ctx, router, api.AuthProtocolID)
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	_ = st.SetDeadline(time.Now().Add(5 * time.Second))
	if err := s.performRouterAuthHandshake(st, biscuitBytes, router); err != nil {
		_ = st.Reset()
		return err
	}
	_ = st.Close()

	s.mu.Lock()
	if st.Conn().IsClosed() {
		s.mu.Unlock()
		return fmt.Errorf("router %s closed connection immediately after admission", router)
	}
	if s.authenticatedRouters == nil {
		s.authenticatedRouters = map[peer.ID]bool{}
	}
	s.authenticatedRouters[router] = true
	s.mu.Unlock()
	s.log().Info("authenticated with router", "router_peer_id", router.String())
	return nil
}

func (s *Server) performRouterAuthHandshake(st network.Stream, biscuitBytes []byte, expectedRouter peer.ID) error {
	data, err := proto.Marshal(&api.AuthFrame{Biscuit: biscuitBytes})
	if err != nil {
		return err
	}
	if err := msgio.NewVarintWriter(st).WriteMsg(data); err != nil {
		return fmt.Errorf("write auth frame: %w", err)
	}
	reader := msgio.NewVarintReaderSize(st, 64*1024)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		return fmt.Errorf("decode auth response: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("%w: %s", errFatalAuth, resp.GetError())
	}
	if len(resp.GetBiscuit()) == 0 {
		return fmt.Errorf("%w: router returned empty biscuit", errFatalAuth)
	}
	trusted := s.trustedPublicKeys()
	if len(trusted) == 0 {
		return fmt.Errorf("%w: no trusted control plane keys loaded", errFatalAuth)
	}
	b, verifyingKey, err := identity.VerifyBiscuitAndGetKey(resp.GetBiscuit(), expectedRouter, trusted, s.biscuitTimeout())
	if err != nil {
		return fmt.Errorf("%w: verify router biscuit: %w", errFatalAuth, err)
	}
	if err := identity.RequireRole(b, verifyingKey, api.RoleRouter, s.biscuitTimeout()); err != nil {
		return fmt.Errorf("%w: peer lacks router role: %w", errFatalAuth, err)
	}
	return nil
}

func (s *Server) readmitRouters(ctx context.Context) {
	if s.host == nil {
		return
	}
	biscuitBytes := s.currentBiscuit()
	if len(biscuitBytes) == 0 {
		return
	}
	for _, router := range s.authenticatedRouterIDs() {
		s.readmitRouter(ctx, router, biscuitBytes)
	}
}

func (s *Server) readmitRouter(ctx context.Context, router peer.ID, biscuitBytes []byte) {
	for attempt := 0; ; attempt++ {
		rCtx, cancel := context.WithTimeout(ctx, routerConnectTimeout)
		err := s.authenticateRouterSession(rCtx, router, biscuitBytes)
		cancel()
		if err == nil {
			return
		}
		if attempt >= len(readmitRetryDelays) {
			s.log().Warn("router did not accept refreshed credential; clearing session", "router_peer_id", router.String(), "error", err)
			s.mu.Lock()
			delete(s.authenticatedRouters, router)
			s.mu.Unlock()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(readmitRetryDelays[attempt]):
		}
	}
}

func (s *Server) redialRouter(ctx context.Context, router peer.ID) {
	s.mu.Lock()
	if s.redialing == nil {
		s.redialing = map[peer.ID]bool{}
	}
	if s.redialing[router] {
		s.mu.Unlock()
		return
	}
	s.redialing[router] = true
	s.mu.Unlock()

	go func() {
		if s.redialUntilUp(ctx, router) {
			return
		}
		s.mu.Lock()
		delete(s.redialing, router)
		s.mu.Unlock()
		s.topUpRouters(ctx)
	}()
}

func (s *Server) redialUntilUp(ctx context.Context, router peer.ID) bool {
	biscuitBytes := s.currentBiscuit()
	if len(biscuitBytes) == 0 {
		return false
	}
	delay := routerRedialDelay
	for attempt := 1; attempt <= routerRedialAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(delay):
		}
		if s.releaseRedialIfUp(router) {
			return true
		}
		if !s.isAttached(router) {
			return false
		}
		addrs := s.host.Peerstore().Addrs(router)
		if len(addrs) == 0 {
			s.detach(router)
			return false
		}
		err := s.authRouter(ctx, peer.AddrInfo{ID: router, Addrs: addrs}, biscuitBytes)
		if err == nil && s.releaseRedialIfUp(router) {
			s.triggerReprovide()
			return true
		}
		if errors.Is(err, errFatalAuth) {
			s.detach(router)
			s.shun(router, defaultShunDuration)
			return false
		}
		delay *= 2
	}
	s.detach(router)
	s.shun(router, defaultShunDuration)
	return false
}

func (s *Server) releaseRedialIfUp(router peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authenticatedRouters[router] || s.host.Network().Connectedness(router) != network.Connected {
		return false
	}
	delete(s.redialing, router)
	return true
}

func (s *Server) announceFilter(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if !s.AllowInsecure {
		var filtered []multiaddr.Multiaddr
		for _, addr := range addrs {
			if hasCircuit(addr) {
				filtered = append(filtered, addr)
				continue
			}
			if isLoopbackOrLinkLocal(addr) {
				continue
			}
			filtered = append(filtered, addr)
		}
		addrs = filtered
	}
	extra := s.reservedCircuitAddrs(addrs)
	if len(extra) == 0 {
		return addrs
	}
	out := make([]multiaddr.Multiaddr, 0, len(addrs)+len(extra))
	out = append(out, addrs...)
	return append(out, extra...)
}

func (s *Server) reservedCircuitAddrs(have []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if s.connMgr == nil {
		return nil
	}
	seen := make(map[string]bool, len(have))
	for _, a := range have {
		seen[a.String()] = true
	}
	var out []multiaddr.Multiaddr
	for _, c := range s.routerCandidates() {
		if !s.connMgr.IsProtected(c.ID, autorelayTag) {
			continue
		}
		circuit := multiaddr.StringCast("/p2p/" + c.ID.String() + "/p2p-circuit")
		for _, addr := range c.Addrs {
			full := addr.Encapsulate(circuit)
			if !seen[full.String()] {
				seen[full.String()] = true
				out = append(out, full)
			}
		}
	}
	return out
}

func isLoopbackOrLinkLocal(addr multiaddr.Multiaddr) bool {
	for _, p := range addr.Protocols() {
		if p.Code != multiaddr.P_IP4 && p.Code != multiaddr.P_IP6 {
			continue
		}
		val, err := addr.ValueForProtocol(p.Code)
		if err != nil {
			continue
		}
		ip := net.ParseIP(val)
		if ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
			return true
		}
	}
	return false
}

func isPrivateIP(addr multiaddr.Multiaddr) bool {
	for _, p := range addr.Protocols() {
		if p.Code != multiaddr.P_IP4 && p.Code != multiaddr.P_IP6 {
			continue
		}
		val, err := addr.ValueForProtocol(p.Code)
		if err != nil {
			continue
		}
		ip := net.ParseIP(val)
		if ip != nil && ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasCircuit(addr multiaddr.Multiaddr) bool {
	for _, p := range addr.Protocols() {
		if p.Code == multiaddr.P_CIRCUIT {
			return true
		}
	}
	return false
}

func tcpFirstDialRanker(addrs []multiaddr.Multiaddr) []network.AddrDelay {
	out := make([]network.AddrDelay, 0, len(addrs))
	hasDirectTCP := false
	for _, a := range addrs {
		if !hasCircuit(a) {
			if _, err := a.ValueForProtocol(multiaddr.P_TCP); err == nil {
				hasDirectTCP = true
				break
			}
		}
	}
	for _, a := range addrs {
		var delay time.Duration
		switch {
		case hasCircuit(a):
			delay = 250 * time.Millisecond
		case hasDirectTCP:
			if _, err := a.ValueForProtocol(multiaddr.P_QUIC_V1); err == nil {
				delay = 50 * time.Millisecond
			}
		}
		out = append(out, network.AddrDelay{Addr: a, Delay: delay})
	}
	return out
}

// Control-plane pull sync & GossipSub events.

func (s *Server) syncControlPlane(ctx context.Context) error {
	err := s.syncControlPlaneOnce(ctx)
	if err != nil && controlPlaneForgotUs(err) && s.recoverEnrollment(ctx) {
		return s.syncControlPlaneOnce(ctx)
	}
	return err
}

func controlPlaneForgotUs(err error) bool {
	var statusErr *cpclient.StatusError
	return errors.As(err, &statusErr) && statusErr.Code == http.StatusUnauthorized
}

func (s *Server) recoverEnrollment(ctx context.Context) bool {
	s.reenrollMu.Lock()
	defer s.reenrollMu.Unlock()
	if time.Since(s.lastReenroll) < reEnrollMinInterval {
		return false
	}
	kind, tok, err := s.resolveJoinSecret(ctx)
	if err != nil || kind != joinSecretBootstrap {
		return false
	}
	s.lastReenroll = time.Now()
	if err := s.enrollBootstrap(ctx, tok, true); err != nil {
		s.log().Warn("control plane re-enrollment failed", "error", err)
		return false
	}
	return true
}

func (s *Server) syncControlPlaneOnce(ctx context.Context) error {
	var errs []error
	if err := s.syncTrustedKeys(ctx); err != nil {
		errs = append(errs, fmt.Errorf("keys: %w", err))
	} else if s.identityPredatesRotation() {
		if err := s.Refresh(ctx); err != nil {
			errs = append(errs, fmt.Errorf("refresh after key rotation: %w", err))
		}
	}
	if err := s.syncMeshInfo(ctx); err != nil {
		errs = append(errs, fmt.Errorf("info: %w", err))
	}
	if err := s.syncMeshPolicy(ctx); err != nil {
		errs = append(errs, fmt.Errorf("policy: %w", err))
	}
	if err := s.syncRevocations(ctx); err != nil {
		errs = append(errs, fmt.Errorf("revocations: %w", err))
	}
	return errors.Join(errs...)
}

func (s *Server) syncTrustedKeys(ctx context.Context) error {
	s.keysMu.RLock()
	existing := slices.Clone(s.trustedKeys)
	trustedPubs := s.publicKeysLocked()
	s.keysMu.RUnlock()
	if len(trustedPubs) == 0 {
		return errors.New("no trusted control plane keys loaded")
	}

	keys, err := s.cpClient().FetchKeys(ctx, trustedPubs)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("/keys returned no keys")
	}

	now := time.Now()
	merged := make([]trustedKey, 0, len(keys))
	for _, k := range keys {
		recv := now
		for _, prev := range existing {
			if bytes.Equal(prev.key, k) {
				recv = prev.receivedAt
				break
			}
		}
		merged = append(merged, trustedKey{key: slices.Clone(k), receivedAt: recv})
	}
	merged = pruneTrustedKeys(merged, now, keyGracePeriod)

	s.keysMu.Lock()
	s.trustedKeys = merged
	s.keysMu.Unlock()
	_ = s.persistState()
	return nil
}

func pruneTrustedKeys(keys []trustedKey, now time.Time, grace time.Duration) []trustedKey {
	if len(keys) == 0 {
		return keys
	}
	newest := 0
	for i, tk := range keys {
		if tk.receivedAt.After(keys[newest].receivedAt) {
			newest = i
		}
	}
	out := make([]trustedKey, 0, len(keys))
	for i, tk := range keys {
		if i == newest || now.Sub(tk.receivedAt) <= grace {
			out = append(out, tk)
		}
	}
	return out
}

func (s *Server) identityPredatesRotation() bool {
	if len(s.currentBiscuit()) == 0 {
		return false
	}
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	if len(s.issuedUnderKeys) == 0 {
		return false
	}
	for _, tk := range s.trustedKeys {
		found := false
		for _, issued := range s.issuedUnderKeys {
			if issued.Equal(tk.key) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func (s *Server) syncMeshInfo(ctx context.Context) error {
	fetchedAt := time.Now()
	info, err := s.cpClient().FetchInfo(ctx)
	if err != nil {
		return err
	}
	if len(info.GetRouterAddresses()) > 0 || len(info.GetRouters()) > 0 {
		if len(info.GetRouterAddresses()) > 0 {
			s.credMu.Lock()
			s.storedRouterAddrs = slices.Clone(info.GetRouterAddresses())
			s.credMu.Unlock()
			_ = s.persistState()
		}
		s.setRouterCatalog(candidatesFromInfo(ctx, info))
	}
	settings := api.DirectorySettingsFrom(info.GetDirectory())
	s.mu.Lock()
	s.dirSettings = settings
	s.mu.Unlock()
	s.reconcileBannedPeers(info.GetBannedPeerIds(), fetchedAt)
	return nil
}

func (s *Server) syncMeshPolicy(ctx context.Context) error {
	tok := s.currentBiscuit()
	if len(tok) == 0 {
		return nil
	}
	resp, err := s.cpClient().FetchPolicy(ctx, tok)
	if err != nil {
		return err
	}
	if len(resp.ProtoReflect().GetUnknown()) > 0 {
		return fmt.Errorf("control plane %s predates datalog_rules", s.cpURL)
	}
	rules, err := api.ParseDatalogRules(resp.GetDatalogRules())
	if err != nil {
		return fmt.Errorf("parse mesh policy datalog: %w", err)
	}
	s.policyMu.Lock()
	changed := s.meshPolicyTexts != nil && !slices.Equal(s.meshPolicyTexts, resp.GetDatalogRules())
	s.meshPolicyRules = rules
	s.meshPolicyTexts = slices.Clone(resp.GetDatalogRules())
	s.policyMu.Unlock()

	if changed {
		s.triggerReprovide()
	}
	return nil
}

func (s *Server) syncRevocations(ctx context.Context) error {
	tok := s.currentBiscuit()
	if len(tok) == 0 {
		return nil
	}
	fetchedAt := time.Now()
	resp, err := s.cpClient().FetchRevocations(ctx, tok)
	if errors.Is(err, cpclient.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	expiry := fetchedAt.Add(24 * time.Hour)
	for _, revID := range resp.GetRevocationIds() {
		s.revokeBiscuitID(revID, expiry)
	}
	if len(resp.GetBannedPeerIds()) > 0 {
		s.reconcileBannedPeers(resp.GetBannedPeerIds(), fetchedAt)
	}
	return nil
}

func (s *Server) startControlPlaneSyncLoop(ctx context.Context) {
	interval := s.syncInterval
	if interval <= 0 {
		interval = controlPlaneSyncDefault
	}
	go func() {
		for {
			jitter := time.Duration(rand.Int64N(int64(interval/5) + 1))
			timer := time.NewTimer(interval + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			case <-s.syncTrigger:
				timer.Stop()
			}
			if err := s.syncControlPlane(ctx); err != nil && ctx.Err() == nil {
				s.log().Warn("control plane sync completed with errors", "error", err)
			}
			s.topUpRouters(ctx)
		}
	}()
}

func (s *Server) triggerControlPlaneSync() {
	select {
	case s.syncTrigger <- struct{}{}:
	default:
	}
}

func (s *Server) reconcileBannedPeers(peerIDs []string, fetchedAt time.Time) {
	if s.revokedPeers == nil {
		return
	}
	banned := make(map[string]peer.ID, len(peerIDs))
	for _, id := range peerIDs {
		p, err := peer.Decode(id)
		if err != nil {
			continue
		}
		banned[p.String()] = p
	}
	fetchedAtMs := fetchedAt.UnixMilli()
	for _, key := range s.revokedPeers.Keys() {
		if _, still := banned[key]; still {
			continue
		}
		if bannedAt, ok := s.revokedPeers.Peek(key); ok && bannedAt >= fetchedAtMs {
			continue
		}
		s.revokedPeers.Remove(key)
	}
	for key, p := range banned {
		if s.revokedPeers.Contains(key) {
			continue
		}
		s.banPeer(p, fetchedAtMs)
	}
}

func (s *Server) banPeer(p peer.ID, bannedAtMs int64) {
	if s.revokedPeers != nil {
		s.revokedPeers.Add(p.String(), bannedAtMs)
	}
	s.forgetAdmission(p)
	if s.host != nil {
		_ = s.host.Network().ClosePeer(p)
	}
	s.log().Info("banned peer evicted", "peer_id", p.String())
}

func (s *Server) isPeerBanned(p peer.ID) bool {
	return s.revokedPeers != nil && s.revokedPeers.Contains(p.String())
}

func (s *Server) revokeBiscuitID(revocationID string, expiry time.Time) {
	if revocationID == "" || s.revokedTokens == nil {
		return
	}
	if expiry.IsZero() {
		expiry = time.Now().Add(api.BiscuitTokenTTL)
	}
	s.revokedTokens.Add(revocationID, expiry)
	if raw, err := hex.DecodeString(revocationID); err == nil && len(raw) > 0 {
		s.revokedTokens.Add(base64.RawURLEncoding.EncodeToString(raw), expiry)
	}
}

func (s *Server) isBiscuitRevoked(b *biscuit.Biscuit) bool {
	if s.revokedTokens == nil || b == nil {
		return false
	}
	now := time.Now()
	for _, id := range b.RevocationIds() {
		key := base64.RawURLEncoding.EncodeToString(id)
		if exp, ok := s.revokedTokens.Get(key); ok {
			if now.Before(exp) {
				return true
			}
			s.revokedTokens.Remove(key)
		}
	}
	return false
}

func (s *Server) validateMeshEvent(_ context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	var evt api.MeshEvent
	if err := proto.Unmarshal(msg.Data, &evt); err != nil {
		s.log().Warn("rejecting undecodable gossip event", "peer_id", from.String())
		return pubsub.ValidationReject
	}
	if !s.verifyEventSignature(&evt) {
		s.log().Warn("rejecting gossip event with invalid signature", "peer_id", from.String())
		return pubsub.ValidationReject
	}
	if evt.GetEventTime() == nil {
		return pubsub.ValidationReject
	}
	t := evt.GetEventTime().AsTime()
	if time.Since(t) > eventFreshnessThreshold || time.Until(t) > eventFreshnessThreshold {
		return pubsub.ValidationIgnore
	}
	return pubsub.ValidationAccept
}

func (s *Server) verifyEventSignature(evt *api.MeshEvent) bool {
	cloned := proto.Clone(evt).(*api.MeshEvent)
	sig := cloned.Signature
	cloned.Signature = nil
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(cloned)
	if err != nil {
		return false
	}
	for _, k := range s.trustedPublicKeys() {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, data, sig) {
			return true
		}
	}
	return false
}

func (s *Server) listenForControlPlaneEvents(ctx context.Context) {
	if s.pubsub == nil {
		return
	}
	topic, err := s.pubsub.Join(api.GossipEvents)
	if err != nil {
		return
	}
	defer func() { _ = topic.Close() }()

	sub, err := topic.Subscribe()
	if err != nil {
		return
	}
	defer sub.Cancel()

	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return
		}
		if s.rateLimiter != nil && !s.rateLimiter.Allow(msg.GetFrom().String()) {
			continue
		}
		var evt api.MeshEvent
		if err := proto.Unmarshal(msg.Data, &evt); err != nil {
			continue
		}
		switch evt.GetType() {
		case api.MeshEvent_BANNED:
			p, err := peer.Decode(evt.GetPeerId())
			if err != nil {
				continue
			}
			canonical := p.String()
			eventMs := evt.GetEventTime().AsTime().UnixMilli()
			s.mu.Lock()
			if s.peerLastEventTime == nil {
				s.peerLastEventTime = map[string]int64{}
			}
			if eventMs < s.peerLastEventTime[canonical] {
				s.mu.Unlock()
				continue
			}
			s.peerLastEventTime[canonical] = eventMs
			s.mu.Unlock()
			s.banPeer(p, eventMs)
		case api.MeshEvent_KEY_ROTATION:
			if len(evt.GetNewPublicKey()) == ed25519.PublicKeySize {
				s.addTrustedKey(ed25519.PublicKey(slices.Clone(evt.GetNewPublicKey())))
				s.triggerControlPlaneSync()
			}
		case api.MeshEvent_POLICY_UPDATE:
			s.triggerControlPlaneSync()
		}
	}
}
