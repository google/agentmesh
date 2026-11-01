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
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/protobuf/proto"
)

var directoryRecordsExpiredTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "agentmesh_router_directory_records_expired_total",
	Help: "Directory records dropped because their provider stopped announcing them for the mesh's record TTL",
})

// recordStore is the directory records this router holds: its own members'
// and the copies other routers placed on it, by key and provider. A record
// carries the addresses of its provider's last announcement, which the next
// announcement replaces, and lives for the mesh's record TTL after it;
// a withdrawal removes it at once.
type recordStore struct {
	ttl time.Duration

	mu   sync.Mutex
	keys map[string]map[peer.ID]*directoryRecord
}

type directoryRecord struct {
	addrs   []multiaddr.Multiaddr
	ingress *api.ServiceIngress
	expires time.Time
}

type providerEntry struct {
	info    peer.AddrInfo
	ingress *api.ServiceIngress
}

func cloneServiceIngress(ing *api.ServiceIngress) *api.ServiceIngress {
	if ing == nil {
		return nil
	}
	return proto.Clone(ing).(*api.ServiceIngress)
}

func newRecordStore(ttl time.Duration) *recordStore {
	return &recordStore{ttl: ttl, keys: map[string]map[peer.ID]*directoryRecord{}}
}

// put stores or replaces the provider's record under key.
func (s *recordStore) put(key []byte, p peer.ID, addrs []multiaddr.Multiaddr, now time.Time) {
	s.putWithIngress(key, p, addrs, nil, now)
}

// putWithIngress stores or replaces the provider's record and optional external
// ingress configuration under key.
func (s *recordStore) putWithIngress(key []byte, p peer.ID, addrs []multiaddr.Multiaddr, ingress *api.ServiceIngress, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	providers := s.keys[string(key)]
	if providers == nil {
		providers = map[peer.ID]*directoryRecord{}
		s.keys[string(key)] = providers
	}
	providers[p] = &directoryRecord{
		addrs:   slices.Clone(addrs),
		ingress: cloneServiceIngress(ingress),
		expires: now.Add(s.ttl),
	}
}

// remove drops the provider's record under key and reports whether there
// was one.
func (s *recordStore) remove(key []byte, p peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	providers := s.keys[string(key)]
	if _, ok := providers[p]; !ok {
		return false
	}
	delete(providers, p)
	if len(providers) == 0 {
		delete(s.keys, string(key))
	}
	return true
}

// removePeer drops all records held for p across every key (e.g. when p is banned).
func (s *recordStore) removePeer(p peer.ID) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, providers := range s.keys {
		delete(providers, p)
		if len(providers) == 0 {
			delete(s.keys, k)
		}
	}
}

// providerEntries is the unexpired records under key, in peer ID order so that
// two routers holding the same records answer in the same order.
func (s *recordStore) providerEntries(key []byte, now time.Time) []providerEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []providerEntry
	for p, rec := range s.keys[string(key)] {
		if !now.Before(rec.expires) {
			continue
		}
		out = append(out, providerEntry{
			info:    peer.AddrInfo{ID: p, Addrs: slices.Clone(rec.addrs)},
			ingress: cloneServiceIngress(rec.ingress),
		})
	}
	slices.SortFunc(out, func(a, b providerEntry) int { return strings.Compare(string(a.info.ID), string(b.info.ID)) })
	return out
}

// providers is the unexpired records under key, in peer ID order so that
// two routers holding the same records answer in the same order.
func (s *recordStore) providers(key []byte, now time.Time) []peer.AddrInfo {
	entries := s.providerEntries(key, now)
	out := make([]peer.AddrInfo, len(entries))
	for i, e := range entries {
		out[i] = e.info
	}
	return out
}

// sweep drops the records that expired and returns how many.
func (s *recordStore) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	expired := 0
	for key, providers := range s.keys {
		for p, rec := range providers {
			if !now.Before(rec.expires) {
				delete(providers, p)
				expired++
			}
		}
		if len(providers) == 0 {
			delete(s.keys, key)
		}
	}
	return expired
}

// size is how many records are held, expired ones not yet swept included.
func (s *recordStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, providers := range s.keys {
		n += len(providers)
	}
	return n
}

// recordSweepInterval is how often expired records are dropped: a third
// of their TTL, and at most every minute, so a record outlives its TTL by
// little.
func recordSweepInterval(ttl time.Duration) time.Duration {
	return max(time.Second, min(ttl/3, time.Minute))
}

// runSweep drops expired records every interval until ctx ends.
func (s *recordStore) runSweep(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if expired := s.sweep(now); expired > 0 {
				directoryRecordsExpiredTotal.Add(float64(expired))
				logger.Infof("[Directory] %d record(s) expired; %d held", expired, s.size())
			}
		}
	}
}
