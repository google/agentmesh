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

package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	kb "github.com/libp2p/go-libp2p-kbucket"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/protobuf/proto"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
)

const (
	// directoryRequestTimeout bounds one request from a member, the lookup
	// on the routers closest to the key included.
	directoryRequestTimeout = 20 * time.Second
	// directoryLookupTimeout bounds what a lookup waits for one peer router:
	// the routers are a full mesh, so an answer is one round trip, and a
	// router that does not answer in this time is left out of the answer.
	directoryLookupTimeout = 5 * time.Second
	// directoryMaxMessage bounds a request or response frame.
	directoryMaxMessage = 64 * 1024
	// directoryDefaultLimit and directoryMaxLimit bound how many providers
	// a find_providers returns.
	directoryDefaultLimit = 20
	directoryMaxLimit     = 100
)

const (
	directoryOpProvide       = "provide"
	directoryOpWithdraw      = "withdraw"
	directoryOpFindProviders = "find_providers"
	directoryOpFindPeer      = "find_peer"
	directoryOpPlace         = "place"
	directoryOpLookup        = "lookup"

	directoryResultOK      = "ok"
	directoryResultEmpty   = "empty"
	directoryResultInvalid = "invalid"
	directoryResultDenied  = "denied"
	directoryResultError   = "error"
)

var directoryRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_router_directory_requests_total",
		Help: "Directory requests served to members and routers, by operation and result; denied is a record for a service the member's credential does not grant; place is a record or withdrawal another router put here, lookup a find another router ran here",
	},
	[]string{"op", "result"},
)

var directoryRequestSeconds = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "agentmesh_router_directory_request_seconds",
		Help:    "Time to answer a directory request, the lookup on the closest routers included",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	},
	[]string{"op"},
)

var directoryPlacementsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_router_directory_placements_total",
		Help: "Copies of a member's record, or of its withdrawal, this router placed on the routers closest to the key, by result",
	},
	[]string{"result"},
)

var directoryLookupsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "agentmesh_router_directory_lookups_total",
		Help: "Peer routers asked during a lookup, by result; error is a router that did not answer in time",
	},
	[]string{"result"},
)

func init() {
	for _, op := range []string{directoryOpProvide, directoryOpWithdraw, directoryOpFindProviders, directoryOpFindPeer, directoryOpPlace, directoryOpLookup} {
		for _, result := range []string{directoryResultOK, directoryResultEmpty, directoryResultInvalid, directoryResultDenied, directoryResultError} {
			directoryRequestsTotal.WithLabelValues(op, result)
		}
	}
	for _, result := range []string{directoryResultOK, directoryResultError} {
		directoryPlacementsTotal.WithLabelValues(result)
		directoryLookupsTotal.WithLabelValues(result)
	}
}

var errDirectoryNotUp = errors.New("the directory is not up")

// handleDirectory serves one DirectoryRequest on a stream from a member
// or a router. It is registered through the auth gate, so the peer has
// authenticated by the time it runs. A member keeps no DHT: it announces
// and withdraws its records here, and the router keeps them and places
// them on the routers closest to the key; it looks keys up here, and the
// router asks those routers.
func (r *Router) handleDirectory(s network.Stream) {
	defer func() { _ = s.Close() }()
	remote := s.Conn().RemotePeer()
	_ = s.SetDeadline(time.Now().Add(directoryRequestTimeout))
	ctx, cancel := context.WithTimeout(r.lifetime(), directoryRequestTimeout)
	defer cancel()

	var req api.DirectoryRequest
	reader := msgio.NewVarintReaderSize(s, directoryMaxMessage)
	frame, err := reader.ReadMsg()
	if err != nil {
		logger.Debugf("[Directory] Request from %s not read: %v", remote, err)
		_ = s.Reset()
		return
	}
	err = proto.Unmarshal(frame, &req)
	reader.ReleaseMsg(frame)
	if err != nil {
		logger.Warnf("[Directory] Request from %s not decoded: %v", remote, err)
		directoryRequestsTotal.WithLabelValues("unknown", directoryResultInvalid).Inc()
		_ = s.Reset()
		return
	}

	op, resp := r.serveDirectory(ctx, remote, &req)
	data, err := proto.Marshal(resp)
	if err != nil {
		logger.Errorf("[Directory] Response to %s not encoded: %v", remote, err)
		_ = s.Reset()
		return
	}
	if err := msgio.NewVarintWriter(s).WriteMsg(data); err != nil {
		logger.Debugf("[Directory] Response to %s (%s) not written: %v", remote, op, err)
		_ = s.Reset()
	}
}

// serveDirectory answers one request and accounts for it.
func (r *Router) serveDirectory(ctx context.Context, remote peer.ID, req *api.DirectoryRequest) (string, *api.DirectoryResponse) {
	start := time.Now()
	var op string
	var resp *api.DirectoryResponse
	var err error
	switch q := req.GetRequest().(type) {
	case *api.DirectoryRequest_Provide:
		op = directoryOpProvide
		if q.Provide.GetProvider() != "" {
			op = directoryOpPlace
		}
		resp, err = r.directoryProvide(ctx, remote, q.Provide)
	case *api.DirectoryRequest_Withdraw:
		op = directoryOpWithdraw
		if q.Withdraw.GetProvider() != "" {
			op = directoryOpPlace
		}
		resp, err = r.directoryWithdraw(ctx, remote, q.Withdraw)
	case *api.DirectoryRequest_FindProviders:
		op = directoryOpFindProviders
		if r.isAuthenticatedPeerRouter(remote) {
			op = directoryOpLookup
		}
		resp, err = r.directoryFindProviders(ctx, remote, q.FindProviders)
	case *api.DirectoryRequest_FindPeer:
		op = directoryOpFindPeer
		if r.isAuthenticatedPeerRouter(remote) {
			op = directoryOpLookup
		}
		resp, err = r.directoryFindPeer(ctx, remote, q.FindPeer)
	default:
		return "unknown", r.directoryRefused("unknown", remote, errInvalidDirectoryRequest)
	}
	directoryRequestSeconds.WithLabelValues(op).Observe(time.Since(start).Seconds())
	if err != nil {
		return op, r.directoryRefused(op, remote, err)
	}
	result := directoryResultOK
	if len(resp.GetProviders()) == 0 && resp.GetPeer() == nil && (op == directoryOpFindProviders || op == directoryOpFindPeer || op == directoryOpLookup) {
		result = directoryResultEmpty
	}
	directoryRequestsTotal.WithLabelValues(op, result).Inc()
	return op, resp
}

var errInvalidDirectoryRequest = errors.New("request is not provide, withdraw, find_providers or find_peer")

// directoryRefused answers a request the router did not run, and says why
// at the level the cause deserves: a malformed request is the peer's
// doing, a record its credential does not grant is a policy decision, a
// failed lookup is the mesh's.
func (r *Router) directoryRefused(op string, remote peer.ID, err error) *api.DirectoryResponse {
	var invalid *directoryInvalidError
	var denied *directoryDeniedError
	if errors.As(err, &invalid) {
		directoryRequestsTotal.WithLabelValues(op, directoryResultInvalid).Inc()
		logger.Warnf("[Directory] Refusing %s from %s: %v", op, remote, err)
	} else if errors.As(err, &denied) {
		directoryRequestsTotal.WithLabelValues(op, directoryResultDenied).Inc()
		logger.Warnw("[Directory] Record denied", "op", op, "peer_id", remote.String(), "service", denied.service, "reason", denied.err.Error())
	} else {
		directoryRequestsTotal.WithLabelValues(op, directoryResultError).Inc()
		logger.Warnf("[Directory] %s from %s failed: %v", op, remote, err)
	}
	return &api.DirectoryResponse{Error: err.Error()}
}

// directoryInvalidError is a request the peer got wrong.
type directoryInvalidError struct{ err error }

func (e *directoryInvalidError) Error() string { return e.err.Error() }
func (e *directoryInvalidError) Unwrap() error { return e.err }

func invalidDirectoryRequest(format string, args ...any) error {
	return &directoryInvalidError{err: fmt.Errorf(format, args...)}
}

// directoryDeniedError is a record for a service the member's credential
// does not grant serving.
type directoryDeniedError struct {
	service string
	err     error
}

func (e *directoryDeniedError) Error() string { return e.err.Error() }
func (e *directoryDeniedError) Unwrap() error { return e.err }

// requirePublish checks the admitted member's credential grants serving
// the service a record names: its own granted_publish_* facts, or those
// the mesh policy rules derive from its role() and label() facts, so that
// a policy change reaches the directory at the next sync and not at the
// member's next credential. A record under the member's own peer key
// names no service and needs no grant: a member may always say where it
// is reached.
func (r *Router) requirePublish(provider peer.ID, svcType api.ServiceType, svcName string) error {
	if svcName == "" {
		return nil
	}
	typeStr, err := api.ServiceTypeToString(svcType)
	if err != nil {
		return invalidDirectoryRequest("%w", err)
	}
	v, ok := r.credentials.Load(provider)
	if !ok {
		return &directoryDeniedError{service: typeStr + "://" + svcName, err: errors.New("no credential held for the member")}
	}
	cred := v.(memberCredential)
	if err := identity.RequirePublish(cred.biscuit, cred.key, typeStr, svcName, r.meshPolicyRules(), r.config.BiscuitTimeout); err != nil {
		return &directoryDeniedError{service: typeStr + "://" + svcName, err: err}
	}
	return nil
}

// requireIngress checks that the admitted member's credential grants exposing
// svcType://svcName on router HTTP ingress with the requested auth mode.
func (r *Router) requireIngress(provider peer.ID, svcType api.ServiceType, svcName string, mode api.IngressAuthMode) error {
	typeStr, err := api.ServiceTypeToString(svcType)
	if err != nil {
		return invalidDirectoryRequest("%w", err)
	}
	modeStr, err := api.IngressAuthModeToString(mode)
	if err != nil {
		return invalidDirectoryRequest("%w", err)
	}
	v, ok := r.credentials.Load(provider)
	if !ok {
		return &directoryDeniedError{service: typeStr + "://" + svcName, err: errors.New("no credential held for the member")}
	}
	cred := v.(memberCredential)
	if err := identity.RequireIngress(cred.biscuit, cred.key, typeStr, svcName, modeStr, r.meshPolicyRules(), r.config.BiscuitTimeout); err != nil {
		return &directoryDeniedError{service: typeStr + "://" + svcName, err: err}
	}
	return nil
}

// recordProvider is whose record a provide or withdraw is about: the
// sender's own, or the member a peer router names, which only a router may.
func (r *Router) recordProvider(remote peer.ID, named string) (provider peer.ID, placed bool, err error) {
	if named == "" {
		return remote, false, nil
	}
	if !r.isAuthenticatedPeerRouter(remote) {
		return "", false, invalidDirectoryRequest("only a router may name a provider; %s is not one", remote)
	}
	p, err := peer.Decode(named)
	if err != nil {
		return "", false, invalidDirectoryRequest("provider: %w", err)
	}
	return p, true, nil
}

// directoryProvide stores a record. From a member it is the member's own,
// kept here and placed on the routers closest to the key; from a router it
// is a member's record that router placed here. A new record for the same
// key and provider replaces the addresses of the old one.
func (r *Router) directoryProvide(ctx context.Context, remote peer.ID, q *api.DirectoryProvide) (*api.DirectoryResponse, error) {
	if err := api.ValidateDirectoryKey(q.GetKey()); err != nil {
		return nil, invalidDirectoryRequest("%w", err)
	}
	provider, placed, err := r.recordProvider(remote, q.GetProvider())
	if err != nil {
		return nil, err
	}
	addrs, err := recordAddrs(provider, q.GetAddrs())
	if err != nil {
		return nil, invalidDirectoryRequest("%w", err)
	}
	if !placed {
		// The member's own router checks what the record is about and that
		// the member may serve it; a placed copy was checked by the router
		// that holds the member.
		svcType, svcName, err := api.ServiceOfRecord(provider, q.GetKey(), q.GetService())
		if err != nil {
			return nil, invalidDirectoryRequest("%w", err)
		}
		if err := r.requirePublish(provider, svcType, svcName); err != nil {
			return nil, err
		}
		if q.GetIngress() != nil {
			if svcName == "" {
				return nil, invalidDirectoryRequest("ingress may only be advertised on a named service record")
			}
			nameKey, err := api.ServiceKey(svcType, svcName)
			if err != nil || !bytes.Equal(q.GetKey(), nameKey) {
				return nil, invalidDirectoryRequest("ingress may only be advertised on a named service key")
			}
			if err := api.ValidateServiceIngress(svcType, q.GetIngress()); err != nil {
				return nil, invalidDirectoryRequest("%w", err)
			}
			if err := r.requireIngress(provider, svcType, svcName, api.EffectiveIngressAuthMode(q.GetIngress())); err != nil {
				return nil, err
			}
		}
	} else if q.GetIngress() != nil {
		svcType, svcName, err := api.ServiceOfRecord(provider, q.GetKey(), q.GetService())
		if err != nil || svcName == "" {
			return nil, invalidDirectoryRequest("placed ingress record must name a valid service")
		}
		nameKey, err := api.ServiceKey(svcType, svcName)
		if err != nil || !bytes.Equal(q.GetKey(), nameKey) {
			return nil, invalidDirectoryRequest("placed ingress record must use a named service key")
		}
		if err := api.ValidateServiceIngress(svcType, q.GetIngress()); err != nil {
			return nil, invalidDirectoryRequest("%w", err)
		}
	}
	if r.records == nil {
		return nil, errDirectoryNotUp
	}
	r.records.putWithIngress(q.GetKey(), provider, addrs, q.GetIngress(), time.Now())
	if !placed {
		r.placeRecord(ctx, provider, &api.DirectoryRequest{Request: &api.DirectoryRequest_Provide{Provide: &api.DirectoryProvide{
			Key: q.GetKey(), Addrs: q.GetAddrs(), Provider: provider.String(), Service: q.GetService(), Ingress: cloneServiceIngress(q.GetIngress()),
		}}})
	}
	return &api.DirectoryResponse{}, nil
}

// directoryWithdraw removes a record: a member's own, from here and from
// the routers closest to the key, or one a peer router withdraws for a
// member it holds. Withdrawing a record that is not here is not an error:
// it may have expired, or never have been placed here.
func (r *Router) directoryWithdraw(ctx context.Context, remote peer.ID, q *api.DirectoryWithdraw) (*api.DirectoryResponse, error) {
	if err := api.ValidateDirectoryKey(q.GetKey()); err != nil {
		return nil, invalidDirectoryRequest("%w", err)
	}
	provider, placed, err := r.recordProvider(remote, q.GetProvider())
	if err != nil {
		return nil, err
	}
	if r.records == nil {
		return nil, errDirectoryNotUp
	}
	if !r.records.remove(q.GetKey(), provider) {
		logger.Debugf("[Directory] %s withdrew a record this router did not hold", provider)
	}
	if !placed {
		r.placeRecord(ctx, provider, &api.DirectoryRequest{Request: &api.DirectoryRequest_Withdraw{Withdraw: &api.DirectoryWithdraw{
			Key: q.GetKey(), Provider: provider.String(),
		}}})
	}
	return &api.DirectoryResponse{}, nil
}

// recordAddrs parses a record's addresses: at most DirectoryMaxAddrs, each
// with no peer suffix or the provider's own, stored without it as the
// peerstore keeps them.
func recordAddrs(provider peer.ID, raw []string) ([]multiaddr.Multiaddr, error) {
	if len(raw) > api.DirectoryMaxAddrs {
		return nil, fmt.Errorf("%d addresses, at most %d", len(raw), api.DirectoryMaxAddrs)
	}
	addrs := make([]multiaddr.Multiaddr, 0, len(raw))
	for _, a := range raw {
		ma, err := multiaddr.NewMultiaddr(a)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", a, err)
		}
		transport, p := peer.SplitAddr(ma)
		if p != "" && p != provider {
			return nil, fmt.Errorf("address %q names %s, the record is %s's", a, p, provider)
		}
		if transport == nil {
			return nil, fmt.Errorf("address %q has no transport", a)
		}
		addrs = append(addrs, transport)
	}
	return addrs, nil
}

// closestRouters is the peer routers closest to key, as many as the
// mesh's replication: where a record is placed and where a lookup asks.
func (r *Router) closestRouters(key []byte) []peer.ID {
	if r.DHT == nil {
		return nil
	}
	return r.DHT.RoutingTable().NearestPeers(kb.ConvertKey(string(key)), r.directory.Replication)
}

// placeRecord puts a member's record, or its withdrawal, on the routers
// closest to the key, over the directory protocol with the provider named.
// Every copy is attempted; a router that fails to take it is logged and
// counted, the member's own router keeps its copy regardless.
func (r *Router) placeRecord(ctx context.Context, provider peer.ID, req *api.DirectoryRequest) {
	var key []byte
	switch q := req.GetRequest().(type) {
	case *api.DirectoryRequest_Provide:
		key = q.Provide.GetKey()
	case *api.DirectoryRequest_Withdraw:
		key = q.Withdraw.GetKey()
	}
	r.ensureFederated(ctx)
	data, err := proto.Marshal(req)
	if err != nil {
		logger.Errorf("[Directory] Placement for %s not encoded: %v", provider, err)
		return
	}
	var wg sync.WaitGroup
	for _, target := range r.closestRouters(key) {
		wg.Add(1)
		go func(target peer.ID) {
			defer wg.Done()
			if _, err := r.sendDirectory(ctx, target, data); err != nil {
				directoryPlacementsTotal.WithLabelValues(directoryResultError).Inc()
				logger.Warnf("[Directory] Record of %s not placed on router %s: %v", provider, target, err)
				return
			}
			directoryPlacementsTotal.WithLabelValues(directoryResultOK).Inc()
		}(target)
	}
	wg.Wait()
}

// sendDirectory sends one encoded request to a peer router and returns its
// answer, over the gated host so the router has authenticated first.
func (r *Router) sendDirectory(ctx context.Context, target peer.ID, data []byte) (*api.DirectoryResponse, error) {
	s, err := r.gated.NewStream(ctx, target, api.DirectoryProtocolID)
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

// directoryFindProviders answers who provides a key.
func (r *Router) directoryFindProviders(ctx context.Context, remote peer.ID, q *api.DirectoryFindProviders) (*api.DirectoryResponse, error) {
	if err := api.ValidateDirectoryKey(q.GetKey()); err != nil {
		return nil, invalidDirectoryRequest("%w", err)
	}
	limit := int(q.GetLimit())
	if limit <= 0 {
		limit = directoryDefaultLimit
	}
	if limit > directoryMaxLimit {
		limit = directoryMaxLimit
	}
	records, err := r.lookupProviders(ctx, remote, q.GetKey(), limit)
	if err != nil {
		return nil, err
	}
	return &api.DirectoryResponse{Providers: records}, nil
}

// lookupProviders is the lookup both find_providers and find_peer run.
// For a member it is this router's records and the routers' closest to
// the key, asked at once; a peer router asking is itself running such a
// lookup, and gets this router's records alone. A lookup that finds
// nothing re-reads the control plane's router list once and asks again:
// a router that joined since the last pass may hold the record.
func (r *Router) lookupProviders(ctx context.Context, remote peer.ID, key []byte, limit int) ([]*api.PeerRecord, error) {
	if r.records == nil {
		return nil, errDirectoryNotUp
	}
	if r.isAuthenticatedPeerRouter(remote) {
		return r.freshRecords(r.records.providerEntries(key, time.Now()), limit), nil
	}
	r.ensureFederated(ctx)
	found := r.findProviders(ctx, key, limit)
	if len(found) == 0 && r.refederateIfStale() {
		found = r.findProviders(ctx, key, limit)
	}
	if err := ctx.Err(); err != nil && len(found) == 0 {
		return nil, fmt.Errorf("lookup: %w", err)
	}
	return r.freshRecords(found, limit), nil
}

// findProviders merges this router's records under key with what the
// routers closest to it hold, each asked within directoryLookupTimeout.
func (r *Router) findProviders(ctx context.Context, key []byte, limit int) []providerEntry {
	req := &api.DirectoryRequest{Request: &api.DirectoryRequest_FindProviders{FindProviders: &api.DirectoryFindProviders{Key: key, Limit: uint32(limit)}}}
	data, err := proto.Marshal(req)
	if err != nil {
		logger.Errorf("[Directory] Lookup not encoded: %v", err)
		return r.records.providerEntries(key, time.Now())
	}
	targets := r.closestRouters(key)
	answers := make(chan []providerEntry, len(targets))
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(target peer.ID) {
			defer wg.Done()
			askCtx, cancel := context.WithTimeout(ctx, directoryLookupTimeout)
			defer cancel()
			resp, err := r.sendDirectory(askCtx, target, data)
			if err != nil {
				directoryLookupsTotal.WithLabelValues(directoryResultError).Inc()
				logger.Warnf("[Directory] Router %s did not answer a lookup: %v", target, err)
				return
			}
			directoryLookupsTotal.WithLabelValues(directoryResultOK).Inc()
			var entries []providerEntry
			for _, rec := range resp.GetProviders() {
				entry, err := providerEntryOfRecord(rec)
				if err != nil {
					logger.Warnf("[Directory] Dropping invalid provider record %q from router %s: %v", rec.GetPeerId(), target, err)
					continue
				}
				entries = append(entries, entry)
			}
			answers <- entries
		}(target)
	}
	wg.Wait()
	close(answers)

	merged := r.records.providerEntries(key, time.Now())
	index := map[peer.ID]int{}
	for i, entry := range merged {
		index[entry.info.ID] = i
	}
	for entries := range answers {
		for _, entry := range entries {
			i, seen := index[entry.info.ID]
			if !seen {
				index[entry.info.ID] = len(merged)
				merged = append(merged, entry)
				continue
			}
			for _, a := range entry.info.Addrs {
				if !containsAddr(merged[i].info.Addrs, a) {
					merged[i].info.Addrs = append(merged[i].info.Addrs, a)
				}
			}
			if merged[i].ingress == nil && entry.ingress != nil {
				merged[i].ingress = entry.ingress
			}
		}
	}
	return merged
}

// freshRecords renders up to limit providers, each at the addresses this
// router sees for it when it holds the provider, which are ahead of the
// record, and at the record's otherwise.
func (r *Router) freshRecords(entries []providerEntry, limit int) []*api.PeerRecord {
	records := make([]*api.PeerRecord, 0, min(limit, len(entries)))
	for _, entry := range entries {
		if len(records) >= limit {
			break
		}
		if r.isPeerAuthenticated(entry.info.ID) && r.Host.Network().Connectedness(entry.info.ID) == network.Connected {
			if addrs := r.Host.Peerstore().Addrs(entry.info.ID); len(addrs) > 0 {
				entry.info.Addrs = addrs
			}
		}
		rec := peerRecord(entry.info)
		rec.Ingress = cloneServiceIngress(entry.ingress)
		records = append(records, rec)
	}
	return records
}

// providerEntryOfRecord parses a record another router answered with.
func providerEntryOfRecord(rec *api.PeerRecord) (providerEntry, error) {
	p, err := peer.Decode(rec.GetPeerId())
	if err != nil {
		return providerEntry{}, err
	}
	addrs, err := recordAddrs(p, rec.GetAddrs())
	if err != nil {
		return providerEntry{}, err
	}
	if err := api.ValidatePeerRecordIngress(rec.GetIngress()); err != nil {
		return providerEntry{}, err
	}
	return providerEntry{
		info:    peer.AddrInfo{ID: p, Addrs: addrs},
		ingress: cloneServiceIngress(rec.GetIngress()),
	}, nil
}

func containsAddr(addrs []multiaddr.Multiaddr, a multiaddr.Multiaddr) bool {
	for _, b := range addrs {
		if b.Equal(a) {
			return true
		}
	}
	return false
}

// directoryFindPeer answers where a peer is reached: from this router's
// own peerstore for a member attached here, from the record the member
// announced under its peer key otherwise.
func (r *Router) directoryFindPeer(ctx context.Context, remote peer.ID, q *api.DirectoryFindPeer) (*api.DirectoryResponse, error) {
	p, err := peer.Decode(q.GetPeerId())
	if err != nil {
		return nil, invalidDirectoryRequest("peer_id: %w", err)
	}
	if r.isPeerAuthenticated(p) && r.Host.Network().Connectedness(p) == network.Connected {
		if addrs := r.Host.Peerstore().Addrs(p); len(addrs) > 0 {
			return &api.DirectoryResponse{Peer: peerRecord(peer.AddrInfo{ID: p, Addrs: addrs})}, nil
		}
	}
	records, err := r.lookupProviders(ctx, remote, api.PeerKey(p), 1)
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		if recPID, decErr := peer.Decode(rec.GetPeerId()); decErr == nil && recPID == p {
			return &api.DirectoryResponse{Peer: rec}, nil
		}
	}
	return &api.DirectoryResponse{}, nil
}

// peerRecord renders a peer and its addresses, each with the peer suffix.
func peerRecord(info peer.AddrInfo) *api.PeerRecord {
	rec := &api.PeerRecord{PeerId: info.ID.String()}
	for _, a := range info.Addrs {
		if _, p := peer.SplitAddr(a); p == "" {
			a = a.Encapsulate(multiaddr.StringCast("/p2p/" + info.ID.String()))
		}
		rec.Addrs = append(rec.Addrs, a.String())
	}
	return rec
}
