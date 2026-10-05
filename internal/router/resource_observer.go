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
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Why the resource manager refused an inbound connection. A refusal happens
// before any byte of TLS: the dialer sees the TCP connection close at once,
// and libp2p's own metrics count only the scope-limit case.
const (
	refusedPerIP     = "per_ip_limit"
	refusedRateLimit = "rate_limit"
	refusedScope     = "scope_limit"
	refusedOther     = "other"
)

var inboundRefusedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "sam_router_inbound_connections_refused_total",
		Help: "Inbound connections the resource manager refused before the handshake, by reason",
	},
	[]string{"reason"},
)

// refusalLogInterval bounds how often one source IP's refusals are logged;
// the counter carries the rate.
const refusalLogInterval = time.Minute

func init() {
	for _, v := range []string{refusedPerIP, refusedRateLimit, refusedScope, refusedOther} {
		inboundRefusedTotal.WithLabelValues(v)
	}
}

// observedResourceManager counts and logs what the wrapped manager refuses.
// It keeps the wrapped manager's connection limit visible to libp2p's
// connmgr sanity check, and leaves every scope it returns untouched.
type observedResourceManager struct {
	network.ResourceManager
	mu        sync.Mutex
	lastLogAt map[string]time.Time
	now       func() time.Time
}

func observeResourceManager(inner network.ResourceManager) *observedResourceManager {
	return &observedResourceManager{ResourceManager: inner, lastLogAt: map[string]time.Time{}, now: time.Now}
}

func (m *observedResourceManager) OpenConnection(dir network.Direction, usefd bool, endpoint multiaddr.Multiaddr) (network.ConnManagementScope, error) {
	scope, err := m.ResourceManager.OpenConnection(dir, usefd, endpoint)
	if err != nil && dir == network.DirInbound {
		m.refused(endpoint, err)
	}
	return scope, err
}

// GetConnLimit is what libp2p compares the connection manager's high water
// mark against at host construction.
func (m *observedResourceManager) GetConnLimit() int {
	if l, ok := m.ResourceManager.(connmgr.GetConnLimiter); ok {
		return l.GetConnLimit()
	}
	return 0
}

func (m *observedResourceManager) refused(endpoint multiaddr.Multiaddr, err error) {
	reason := refusalReason(err)
	inboundRefusedTotal.WithLabelValues(reason).Inc()

	source := "?"
	if ip, ipErr := manet.ToIP(endpoint); ipErr == nil {
		source = ip.String()
	}
	m.mu.Lock()
	last, seen := m.lastLogAt[source]
	now := m.now()
	shouldLog := !seen || now.Sub(last) >= refusalLogInterval
	if shouldLog {
		m.lastLogAt[source] = now
		for k, t := range m.lastLogAt {
			if now.Sub(t) >= refusalLogInterval {
				delete(m.lastLogAt, k)
			}
		}
	}
	m.mu.Unlock()
	if shouldLog {
		logger.Warnf("[Conn] Refused inbound connection from %s (%s): %v; the dialer sees the connection close before TLS", source, reason, err)
	}
}

// refusalReason maps the resource manager's errors to the counter's labels.
// The per-IP and rate-limit paths return plain strings, not sentinel errors.
func refusalReason(err error) string {
	if errors.Is(err, network.ErrResourceLimitExceeded) {
		return refusedScope
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connections per ip limit"):
		return refusedPerIP
	case strings.Contains(msg, "rate limit exceeded"):
		return refusedRateLimit
	}
	return refusedOther
}

// connsPerSourceIPDesc exports the cap in force, so a dashboard can read the
// refusal counter against it.
var connsPerSourceIPDesc = prometheus.NewDesc(
	"sam_router_conns_per_source_ip_limit",
	"Inbound connections allowed from one source IP",
	nil, nil)

// defaultConnsPerSourceIP is libp2p's cap when --conns-per-source-ip is unset.
const defaultConnsPerSourceIP = 8

var _ connmgr.GetConnLimiter = (*observedResourceManager)(nil)

// effectiveConnsPerSourceIP is the cap a dashboard should compare against.
func effectiveConnsPerSourceIP(configured int) int {
	if configured > 0 {
		return configured
	}
	return defaultConnsPerSourceIP
}

// perPeerLogLimiter admits one log line per peer per interval. Entries older
// than the interval are dropped on the way, so it holds only recent peers.
type perPeerLogLimiter struct {
	mu     sync.Mutex
	lastAt map[peer.ID]time.Time
}

const perPeerLogInterval = time.Minute

func (l *perPeerLogLimiter) allow(p peer.ID, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastAt == nil {
		l.lastAt = map[peer.ID]time.Time{}
	}
	if last, ok := l.lastAt[p]; ok && now.Sub(last) < perPeerLogInterval {
		return false
	}
	for k, t := range l.lastAt {
		if now.Sub(t) >= perPeerLogInterval {
			delete(l.lastAt, k)
		}
	}
	l.lastAt[p] = now
	return true
}
