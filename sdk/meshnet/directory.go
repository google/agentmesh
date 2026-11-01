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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

const (
	directoryRequestTimeout       = 10 * time.Second
	directoryMaxMessage           = 64 * 1024
	directoryDefaultLimit         = 20
	dhtLookupTimeout              = 5 * time.Second
	discoveryFanoutTimeout        = 30 * time.Second
	discoveryConcurrency          = 10
	peerstoreKeyPrivateIPFailed   = "mesh_private_ip_failed"
	transitCatalogRefreshInterval = 10 * time.Second
)

var errNoDirectoryRouter = errors.New("meshnet: no attached router available for directory request")

type routerDirectory struct {
	host    host.Host
	routers func() []peer.ID
	addrs   func() []multiaddr.Multiaddr
	log     func() *slog.Logger
}

func (d *routerDirectory) provide(ctx context.Context, key []byte, service string) error {
	return d.provideWithIngress(ctx, key, service, nil)
}

func (d *routerDirectory) provideWithIngress(ctx context.Context, key []byte, service string, ingress *api.ServiceIngress) error {
	addrs := d.addrs()
	if len(addrs) > api.DirectoryMaxAddrs {
		addrs = addrs[:api.DirectoryMaxAddrs]
	}
	rec := &api.DirectoryProvide{
		Key:     key,
		Service: service,
		Addrs:   make([]string, 0, len(addrs)),
		Ingress: ingress,
	}
	for _, a := range addrs {
		rec.Addrs = append(rec.Addrs, a.String())
	}
	_, err := d.request(ctx, "provide", &api.DirectoryRequest{
		Request: &api.DirectoryRequest_Provide{Provide: rec},
	})
	return err
}

func (d *routerDirectory) withdraw(ctx context.Context, key []byte) error {
	_, err := d.request(ctx, "withdraw", &api.DirectoryRequest{
		Request: &api.DirectoryRequest_Withdraw{Withdraw: &api.DirectoryWithdraw{Key: key}},
	})
	return err
}

func (d *routerDirectory) findProviders(ctx context.Context, key []byte, limit int) ([]peer.AddrInfo, error) {
	if limit <= 0 {
		limit = directoryDefaultLimit
	}
	resp, err := d.request(ctx, "find_providers", &api.DirectoryRequest{
		Request: &api.DirectoryRequest_FindProviders{
			FindProviders: &api.DirectoryFindProviders{Key: key, Limit: uint32(limit)},
		},
	})
	if err != nil {
		return nil, err
	}
	out := make([]peer.AddrInfo, 0, len(resp.GetProviders()))
	for _, rec := range resp.GetProviders() {
		info, err := addrInfoOf(rec)
		if err != nil {
			d.log().Warn("skipping malformed provider record from router", "error", err)
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

func (d *routerDirectory) findPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
	resp, err := d.request(ctx, "find_peer", &api.DirectoryRequest{
		Request: &api.DirectoryRequest_FindPeer{
			FindPeer: &api.DirectoryFindPeer{PeerId: p.String()},
		},
	})
	if err != nil {
		return peer.AddrInfo{}, err
	}
	if resp.GetPeer() == nil {
		return peer.AddrInfo{ID: p}, routing.ErrNotFound
	}
	info, err := addrInfoOf(resp.GetPeer())
	if err != nil {
		return peer.AddrInfo{ID: p}, err
	}
	if info.ID != p {
		return peer.AddrInfo{ID: p}, fmt.Errorf("router answered for %s instead of %s", info.ID, p)
	}
	return info, nil
}

func (d *routerDirectory) request(ctx context.Context, op string, req *api.DirectoryRequest) (*api.DirectoryResponse, error) {
	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	routers := d.routers()
	if len(routers) == 0 {
		return nil, errNoDirectoryRouter
	}
	lookup := op == "find_providers" || op == "find_peer"
	var lastErr error
	var empty *api.DirectoryResponse
	for _, router := range routers {
		resp, err := d.ask(ctx, router, data)
		if err == nil {
			if lookup && len(resp.GetProviders()) == 0 && resp.GetPeer() == nil {
				empty = resp
				continue
			}
			return resp, nil
		}
		lastErr = err
		d.log().Warn("directory request through router failed", "op", op, "router_peer_id", router.String(), "error", err)
		if ctx.Err() != nil {
			break
		}
	}
	if empty != nil {
		return empty, nil
	}
	return nil, fmt.Errorf("%s: no attached router answered: %w", op, lastErr)
}

func (d *routerDirectory) ask(ctx context.Context, router peer.ID, data []byte) (*api.DirectoryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, directoryRequestTimeout)
	defer cancel()
	st, err := d.host.NewStream(ctx, router, api.DirectoryProtocolID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(deadline)
	}
	if err := msgio.NewVarintWriter(st).WriteMsg(data); err != nil {
		_ = st.Reset()
		return nil, err
	}
	reader := msgio.NewVarintReaderSize(st, directoryMaxMessage)
	frame, err := reader.ReadMsg()
	if err != nil {
		_ = st.Reset()
		return nil, err
	}
	defer reader.ReleaseMsg(frame)
	var resp api.DirectoryResponse
	if err := proto.Unmarshal(frame, &resp); err != nil {
		return nil, err
	}
	if resp.GetError() != "" {
		return nil, errors.New(resp.GetError())
	}
	return &resp, nil
}

func addrInfoOf(rec *api.PeerRecord) (peer.AddrInfo, error) {
	p, err := peer.Decode(rec.GetPeerId())
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("peer %q: %w", rec.GetPeerId(), err)
	}
	info := peer.AddrInfo{ID: p}
	for _, a := range rec.GetAddrs() {
		ma, err := multiaddr.NewMultiaddr(a)
		if err != nil {
			return peer.AddrInfo{}, fmt.Errorf("address %q of %s: %w", a, p, err)
		}
		transport, named := peer.SplitAddr(ma)
		if named != "" && named != p {
			continue
		}
		if transport != nil {
			info.Addrs = append(info.Addrs, transport)
		}
	}
	return info, nil
}

func rememberAddrs(ps peerstore.Peerstore, infos ...peer.AddrInfo) {
	for _, info := range infos {
		if len(info.Addrs) > 0 {
			ps.AddAddrs(info.ID, info.Addrs, peerstore.TempAddrTTL)
		}
	}
}

// Discover looks up mesh providers for svcType. Pass an empty name to browse
// all reachable services of that type (fanning out over system://mesh.catalog),
// or pass a specific service name for a targeted directory lookup.
//
// Each returned DiscoveredProvider has LocalProxyUrl populated with a synthetic
// mesh URL ("http://agentmesh.local/mesh/<peer_id>/<type>/<name>") directly
// usable with s.HTTPClient() and stock A2A/OpenAI clients.
func (s *Server) Discover(ctx context.Context, svcType api.ServiceType, name string) ([]*api.DiscoveredProvider, error) {
	if s.host == nil || s.dir == nil {
		return nil, errors.New("meshnet: Server is not running (call Up first)")
	}
	typeStr, err := api.ServiceTypeToString(svcType)
	if err != nil || svcType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return nil, fmt.Errorf("meshnet: invalid service type %v", svcType)
	}
	if name != "" {
		return s.discoverByName(ctx, svcType, typeStr, name)
	}
	return s.discoverByType(ctx, svcType, typeStr)
}

func (s *Server) localMeshURL(peerID peer.ID, typeStr, svcName string) string {
	return fmt.Sprintf("http://agentmesh.local/mesh/%s/%s/%s", peerID.String(), typeStr, svcName)
}

func (s *Server) findProviders(ctx context.Context, key []byte) ([]peer.AddrInfo, error) {
	if s.dir == nil {
		return nil, errors.New("meshnet: directory is not initialized")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	found, err := s.dir.findProviders(lookupCtx, key, directoryDefaultLimit)
	if errors.Is(err, errNoDirectoryRouter) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	providers := make([]peer.AddrInfo, 0, len(found))
	for _, p := range found {
		if s.isPeerBanned(p.ID) {
			continue
		}
		rememberAddrs(s.host.Peerstore(), p)
		providers = append(providers, p)
	}
	return providers, nil
}

func (s *Server) discoverByName(ctx context.Context, svcType api.ServiceType, typeStr, name string) ([]*api.DiscoveredProvider, error) {
	key, err := api.ServiceKey(svcType, name)
	if err != nil {
		return nil, err
	}
	peers, err := s.findProviders(ctx, key)
	if err != nil {
		return nil, err
	}
	out := make([]*api.DiscoveredProvider, 0, len(peers))
	for _, p := range peers {
		if p.ID == s.peerID {
			continue
		}
		out = append(out, &api.DiscoveredProvider{
			PeerId:        p.ID.String(),
			LocalProxyUrl: s.localMeshURL(p.ID, typeStr, name),
			SrvName:       name,
		})
	}
	return out, nil
}

func (s *Server) discoverByType(ctx context.Context, svcType api.ServiceType, typeStr string) ([]*api.DiscoveredProvider, error) {
	key, err := api.ServiceKey(svcType, "")
	if err != nil {
		return nil, err
	}
	peers, err := s.findProviders(ctx, key)
	if err != nil {
		return nil, err
	}

	fanoutCtx, cancel := context.WithTimeout(ctx, discoveryFanoutTimeout)
	defer cancel()

	type peerCatalog struct {
		peerID   peer.ID
		services []*api.ServiceInfo
	}
	results := make(chan peerCatalog, len(peers))
	sem := make(chan struct{}, discoveryConcurrency)
	var wg sync.WaitGroup
	for _, p := range peers {
		if p.ID == s.peerID {
			continue
		}
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-fanoutCtx.Done():
				return
			}
			services, err := s.fetchRemoteServiceCatalog(fanoutCtx, peerID, typeStr)
			if err != nil {
				s.log().Debug("remote catalog fetch failed during discovery", "peer_id", peerID.String(), "error", err)
				return
			}
			results <- peerCatalog{peerID: peerID, services: services}
		}(p.ID)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	out := []*api.DiscoveredProvider{}
	for r := range results {
		for _, info := range r.services {
			if info == nil {
				continue
			}
			out = append(out, &api.DiscoveredProvider{
				PeerId:         r.peerID.String(),
				LocalProxyUrl:  s.localMeshURL(r.peerID, typeStr, info.GetName()),
				SrvName:        info.GetName(),
				SrvDescription: info.GetDescription(),
			})
		}
	}
	return out, nil
}

func (s *Server) preparePeerAddrs(ctx context.Context, targetPeer peer.ID) {
	if s.host == nil || s.dir == nil {
		return
	}
	cond := s.host.Network().Connectedness(targetPeer)
	if cond == network.Connected || cond == network.Limited {
		conns := s.host.Network().ConnsToPeer(targetPeer)
		hasDirectPrivateIP := false
		for _, c := range conns {
			remoteAddr := c.RemoteMultiaddr()
			if isPrivateIP(remoteAddr) && !hasCircuit(remoteAddr) {
				hasDirectPrivateIP = true
				break
			}
		}
		_ = s.host.Peerstore().Put(targetPeer, peerstoreKeyPrivateIPFailed, !hasDirectPrivateIP)
	}

	changed := false
	addrs := s.host.Peerstore().Addrs(targetPeer)
	if len(addrs) == 0 {
		findCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
		addrInfo, err := s.dir.findPeer(findCtx, targetPeer)
		cancel()
		addrs = addrInfo.Addrs
		if len(addrs) > 0 {
			changed = true
		} else if err != nil && !errors.Is(err, routing.ErrNotFound) {
			s.log().Debug("directory find_peer failed", "peer_id", targetPeer.String(), "error", err)
		}
	}

	var validAddrs []multiaddr.Multiaddr
	seen := make(map[string]struct{}, len(addrs))
	addUnique := func(ma multiaddr.Multiaddr) bool {
		str := ma.String()
		if _, ok := seen[str]; !ok {
			seen[str] = struct{}{}
			validAddrs = append(validAddrs, ma)
			return true
		}
		return false
	}

	for _, ma := range addrs {
		parts := multiaddr.Split(ma)
		isCircuit := len(parts) >= 2 && parts[len(parts)-1].Protocol().Code == multiaddr.P_CIRCUIT
		if !isCircuit {
			if isPrivateIP(ma) && !s.AllowInsecure {
				if val, err := s.host.Peerstore().Get(targetPeer, peerstoreKeyPrivateIPFailed); err == nil {
					if failed, ok := val.(bool); ok && failed {
						changed = true
						continue
					}
				}
			}
			addUnique(ma)
			continue
		}

		addUnique(ma)
		p2pPart := parts[len(parts)-2]
		if p2pPart.Protocol().Code != multiaddr.P_P2P {
			continue
		}
		relayID, err := peer.Decode(p2pPart.Value())
		if err != nil {
			continue
		}
		if len(s.host.Peerstore().Addrs(relayID)) == 0 {
			findCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
			if addrInfo, err := s.dir.findPeer(findCtx, relayID); err == nil {
				rememberAddrs(s.host.Peerstore(), addrInfo)
			}
			cancel()
		}
		if circuitAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s/p2p-circuit", relayID.String())); err == nil {
			if addUnique(circuitAddr) {
				changed = true
			}
		}
	}

	if !slices.ContainsFunc(validAddrs, func(ma multiaddr.Multiaddr) bool { return circuitRelay(ma) != "" }) {
		for _, router := range s.authenticatedRouterIDs() {
			if circuitAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s/p2p-circuit", router.String())); err == nil {
				if addUnique(circuitAddr) {
					changed = true
				}
			}
		}
	}

	if kept := s.selectTransit(ctx, validAddrs); len(kept) != len(validAddrs) {
		validAddrs = kept
		changed = true
	}

	if changed && len(validAddrs) > 0 {
		s.host.Peerstore().ClearAddrs(targetPeer)
		s.host.Peerstore().AddAddrs(targetPeer, validAddrs, peerstore.TempAddrTTL)
		if sw, ok := s.host.Network().(*swarm.Swarm); ok {
			sw.Backoff().Clear(targetPeer)
		}
	}
}

func circuitRelay(ma multiaddr.Multiaddr) peer.ID {
	parts := multiaddr.Split(ma)
	if len(parts) < 2 || parts[len(parts)-1].Protocol().Code != multiaddr.P_CIRCUIT || parts[len(parts)-2].Protocol().Code != multiaddr.P_P2P {
		return ""
	}
	relayID, err := peer.Decode(parts[len(parts)-2].Value())
	if err != nil {
		return ""
	}
	return relayID
}

func relayTransportAddr(ma multiaddr.Multiaddr) multiaddr.Multiaddr {
	if circuitRelay(ma) == "" {
		return nil
	}
	parts := multiaddr.Split(ma)
	if len(parts) < 3 {
		return nil
	}
	return multiaddr.Multiaddr(slices.Clone(parts[:len(parts)-2]))
}

func (s *Server) selectTransit(ctx context.Context, addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	var relays []peer.ID
	relayAddrs := map[peer.ID][]multiaddr.Multiaddr{}
	for _, ma := range addrs {
		relay := circuitRelay(ma)
		if relay == "" {
			continue
		}
		if _, seen := relayAddrs[relay]; !seen {
			relays = append(relays, relay)
		}
		if via := relayTransportAddr(ma); via != nil {
			relayAddrs[relay] = append(relayAddrs[relay], via)
		} else if _, seen := relayAddrs[relay]; !seen {
			relayAddrs[relay] = nil
		}
	}
	if len(relays) == 0 {
		return addrs
	}

	routers := map[peer.ID]routerCandidate{}
	for _, c := range s.routerCandidates() {
		routers[c.ID] = c
	}
	var unlisted []peer.ID
	for _, r := range relays {
		if _, isRouter := routers[r]; !isRouter {
			unlisted = append(unlisted, r)
		}
	}
	if len(unlisted) > 0 && s.refreshCatalogForTransit(ctx) {
		routers = map[peer.ID]routerCandidate{}
		for _, c := range s.routerCandidates() {
			routers[c.ID] = c
		}
		unlisted = unlisted[:0]
		for _, r := range relays {
			if _, isRouter := routers[r]; !isRouter {
				unlisted = append(unlisted, r)
			}
		}
	}
	var viaRouters []peer.ID
	for _, r := range relays {
		if _, isRouter := routers[r]; isRouter {
			viaRouters = append(viaRouters, r)
		}
	}

	usable := map[peer.ID]bool{}
	for _, r := range relays {
		if s.isAuthenticatedAndConnected(r) {
			usable[r] = true
		}
	}
	if len(usable) == 0 {
		sort.SliceStable(viaRouters, func(i, j int) bool {
			return routers[viaRouters[i]].loadRatio() < routers[viaRouters[j]].loadRatio()
		})
		biscuitBytes := s.currentBiscuit()
		if len(biscuitBytes) == 0 {
			return addrs
		}
		for _, r := range append(viaRouters, unlisted...) {
			router := peer.AddrInfo{ID: r, Addrs: append(s.host.Peerstore().Addrs(r), relayAddrs[r]...)}
			if err := s.authRouter(ctx, router, biscuitBytes); err != nil {
				s.log().Warn("transit router did not admit member", "router_peer_id", r.String(), "error", err)
				continue
			}
			usable[r] = true
			break
		}
		if len(usable) == 0 {
			return addrs
		}
	}

	kept := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, ma := range addrs {
		relay := circuitRelay(ma)
		if _, isRouter := routers[relay]; relay != "" && isRouter && !usable[relay] {
			continue
		}
		kept = append(kept, ma)
	}
	return kept
}

func (s *Server) refreshCatalogForTransit(ctx context.Context) bool {
	s.mu.Lock()
	due := time.Since(s.transitCatalogRefreshedAt) >= transitCatalogRefreshInterval
	if due {
		s.transitCatalogRefreshedAt = time.Now()
	}
	s.mu.Unlock()
	if !due {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.syncMeshInfo(ctx) == nil
}

func (s *Server) triggerReprovide() {
	if s.reprovideTrigger == nil {
		return
	}
	select {
	case s.reprovideTrigger <- struct{}{}:
	default:
	}
}

func (s *Server) reprovideInterval() time.Duration {
	s.mu.Lock()
	d := s.dirSettings.Reprovide
	s.mu.Unlock()
	if d <= 0 {
		return api.DefaultReprovideInterval
	}
	return d
}

func (s *Server) startReprovideLoop(ctx context.Context) {
	go func() {
		s.announceAll(ctx)
		for {
			interval := s.reprovideInterval()
			jitter := time.Duration(rand.Int64N(int64(interval/5) + 1))
			timer := time.NewTimer(interval + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			case <-s.reprovideTrigger:
				timer.Stop()
			}
			s.announceAll(ctx)
		}
	}()
}

func (s *Server) announceAll(ctx context.Context) {
	if s.dir == nil || s.host == nil {
		return
	}
	peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := s.dir.provide(peerCtx, api.PeerKey(s.peerID), ""); err != nil && ctx.Err() == nil && !errors.Is(err, errNoDirectoryRouter) {
		s.log().Debug("peer directory announcement failed", "error", err)
	}
	cancel()

	for _, entry := range s.listA2AEntries() {
		if entry.noAnnounce {
			continue
		}
		s.announceA2AEntry(ctx, entry)
	}
}
