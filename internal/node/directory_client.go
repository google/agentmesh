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
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/protobuf/proto"

	"github.com/google/agentmesh/api"
)

// Directory is the mesh's directory as a member sees it: where it
// announces what it serves and where it is reached, and where it looks
// peers and services up. The routers the member is attached to answer for
// it over api.DirectoryProtocolID; the member keeps no DHT of its own.
type Directory interface {
	// Provide announces this member as a provider of key, at the
	// addresses it announces, to a router it is attached to; the router
	// keeps the record and places it on the routers closest to the key.
	// service is what the record is about, "<type>://<name>", and "" for
	// the member's own record under its peer key.
	Provide(ctx context.Context, key []byte, service string) error
	// Withdraw removes this member's record under key from the router it is
	// attached to and from the routers the record was placed on.
	Withdraw(ctx context.Context, key []byte) error
	// FindProviders is who provides key, up to limit, with their addresses.
	FindProviders(ctx context.Context, key []byte, limit int) ([]peer.AddrInfo, error)
	// FindPeer is where p is reached; routing.ErrNotFound when nobody knows.
	FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error)
}

const (
	// directoryRequestTimeout bounds one request to one router: the router's
	// lookup on the routers closest to the key included, which is one round
	// between routers that all know each other.
	directoryRequestTimeout = 10 * time.Second
	directoryMaxMessage     = 64 * 1024
	directoryDefaultLimit   = 20
)

var errNoDirectoryRouter = errors.New("no attached router to ask")

var directoryRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_node_directory_requests_total",
		Help: "Directory requests this node made to its routers, by operation and result; failed is a request no attached router answered",
	},
	[]string{"op", "result"},
)

var directoryRequestSeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "agentmesh_node_directory_request_seconds",
		Help:    "Time a directory request took, the router's lookup included",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	},
	[]string{"op"},
)

const (
	directoryOpProvide       = "provide"
	directoryOpWithdraw      = "withdraw"
	directoryOpFindProviders = "find_providers"
	directoryOpFindPeer      = "find_peer"

	directoryResultOK     = "ok"
	directoryResultEmpty  = "empty"
	directoryResultFailed = "failed"
)

func init() {
	for _, op := range []string{directoryOpProvide, directoryOpWithdraw, directoryOpFindProviders, directoryOpFindPeer} {
		for _, result := range []string{directoryResultOK, directoryResultEmpty, directoryResultFailed} {
			directoryRequestsTotal.WithLabelValues(op, result)
		}
	}
}

// routerDirectory asks the routers the node is attached to. A request goes
// to one of them; when it fails, the next is asked, so one router that is
// restarting costs a request a timeout and not an answer.
type routerDirectory struct {
	host    host.Host // the gated host: a stream to a router follows its handshake
	routers func() []peer.ID
	addrs   func() []multiaddr.Multiaddr

	mu        sync.Mutex
	announced []multiaddr.Multiaddr // the addresses of the record last announced
}

func (d *routerDirectory) Provide(ctx context.Context, key []byte, service string) error {
	return d.ProvideWithIngress(ctx, key, service, nil)
}

func (d *routerDirectory) ProvideWithIngress(ctx context.Context, key []byte, service string, ingress *api.ServiceIngress) error {
	addrs := d.addrs()
	if len(addrs) > api.DirectoryMaxAddrs {
		addrs = addrs[:api.DirectoryMaxAddrs]
	}
	rec := &api.DirectoryProvide{Key: key, Service: service, Addrs: make([]string, 0, len(addrs)), Ingress: ingress}
	for _, a := range addrs {
		rec.Addrs = append(rec.Addrs, a.String())
	}
	if _, err := d.request(ctx, directoryOpProvide, &api.DirectoryRequest{Request: &api.DirectoryRequest_Provide{Provide: rec}}); err != nil {
		return err
	}
	d.mu.Lock()
	d.announced = addrs
	d.mu.Unlock()
	return nil
}

func (d *routerDirectory) Withdraw(ctx context.Context, key []byte) error {
	_, err := d.request(ctx, directoryOpWithdraw, &api.DirectoryRequest{Request: &api.DirectoryRequest_Withdraw{Withdraw: &api.DirectoryWithdraw{Key: key}}})
	return err
}

// Announced is the addresses of the record this member last announced:
// what the directory holds for it, as against what it would announce now.
func (d *routerDirectory) Announced() []multiaddr.Multiaddr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.announced)
}

func (d *routerDirectory) FindProviders(ctx context.Context, key []byte, limit int) ([]peer.AddrInfo, error) {
	if limit <= 0 {
		limit = directoryDefaultLimit
	}
	resp, err := d.request(ctx, directoryOpFindProviders, &api.DirectoryRequest{Request: &api.DirectoryRequest_FindProviders{
		FindProviders: &api.DirectoryFindProviders{Key: key, Limit: uint32(limit)},
	}})
	if err != nil {
		return nil, err
	}
	out := make([]peer.AddrInfo, 0, len(resp.GetProviders()))
	for _, rec := range resp.GetProviders() {
		info, err := addrInfoOf(rec)
		if err != nil {
			logger.Warnf("[Directory] Skipping a provider record the router sent: %v", err)
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

func (d *routerDirectory) FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
	resp, err := d.request(ctx, directoryOpFindPeer, &api.DirectoryRequest{Request: &api.DirectoryRequest_FindPeer{
		FindPeer: &api.DirectoryFindPeer{PeerId: p.String()},
	}})
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
		return peer.AddrInfo{ID: p}, fmt.Errorf("the router answered for %s", info.ID)
	}
	return info, nil
}

// request sends req to the attached routers in turn until one answers. A
// lookup one router answers with nothing is put to the next as well: a
// router cut off from the routers closest to the key answers from what it
// can reach, and the member holds another that may not be.
func (d *routerDirectory) request(ctx context.Context, op string, req *api.DirectoryRequest) (*api.DirectoryResponse, error) {
	start := time.Now()
	defer func() { directoryRequestSeconds.WithLabelValues(op).Observe(time.Since(start).Seconds()) }()
	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	routers := d.routers()
	if len(routers) == 0 {
		directoryRequestsTotal.WithLabelValues(op, directoryResultFailed).Inc()
		logger.Warnf("[Directory] %s: %v", op, errNoDirectoryRouter)
		return nil, errNoDirectoryRouter
	}
	lookup := op == directoryOpFindProviders || op == directoryOpFindPeer
	var lastErr error
	var empty *api.DirectoryResponse
	for _, router := range routers {
		resp, err := d.ask(ctx, router, data)
		if err == nil {
			if lookup && len(resp.GetProviders()) == 0 && resp.GetPeer() == nil {
				empty = resp
				continue
			}
			directoryRequestsTotal.WithLabelValues(op, directoryResultOK).Inc()
			return resp, nil
		}
		lastErr = err
		logger.Warnf("[Directory] %s through router %s failed: %v", op, router, err)
		if ctx.Err() != nil {
			break
		}
	}
	if empty != nil {
		directoryRequestsTotal.WithLabelValues(op, directoryResultEmpty).Inc()
		return empty, nil
	}
	directoryRequestsTotal.WithLabelValues(op, directoryResultFailed).Inc()
	return nil, fmt.Errorf("%s: no attached router answered: %w", op, lastErr)
}

// ask sends one encoded request to one router and reads its answer.
func (d *routerDirectory) ask(ctx context.Context, router peer.ID, data []byte) (*api.DirectoryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, directoryRequestTimeout)
	defer cancel()
	s, err := d.host.NewStream(ctx, router, api.DirectoryProtocolID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}
	if err := msgio.NewVarintWriter(s).WriteMsg(data); err != nil {
		_ = s.Reset()
		return nil, err
	}
	reader := msgio.NewVarintReaderSize(s, directoryMaxMessage)
	frame, err := reader.ReadMsg()
	if err != nil {
		_ = s.Reset()
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

// addrInfoOf parses a record into a peer and its transport addresses, the
// peer suffix off, as the peerstore keeps them; an address naming another
// peer is the router's mistake and is dropped.
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

// rememberAddrs keeps what a lookup learned for a dial that follows.
func rememberAddrs(ps peerstore.Peerstore, infos ...peer.AddrInfo) {
	for _, info := range infos {
		if len(info.Addrs) > 0 {
			ps.AddAddrs(info.ID, info.Addrs, peerstore.TempAddrTTL)
		}
	}
}
