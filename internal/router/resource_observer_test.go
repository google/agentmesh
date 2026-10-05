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
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// refusingResourceManager answers every OpenConnection with one error.
type refusingResourceManager struct {
	network.NullResourceManager
	err   error
	limit int
}

func (m *refusingResourceManager) OpenConnection(network.Direction, bool, multiaddr.Multiaddr) (network.ConnManagementScope, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &network.NullScope{}, nil
}

func (m *refusingResourceManager) GetConnLimit() int { return m.limit }

func TestObservedResourceManagerCountsAndClassifiesRefusals(t *testing.T) {
	endpoint := multiaddr.StringCast("/ip4/104.197.44.137/tcp/51234")
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{fmt.Errorf("connections per ip limit exceeded for %s", endpoint), refusedPerIP},
		{errors.New("rate limit exceeded"), refusedRateLimit},
		{fmt.Errorf("cannot reserve inbound connection: %w", network.ErrResourceLimitExceeded), refusedScope},
		{errors.New("something else"), refusedOther},
	} {
		before := counterValue(t, inboundRefusedTotal.WithLabelValues(tc.reason))
		m := observeResourceManager(&refusingResourceManager{err: tc.err})
		if _, err := m.OpenConnection(network.DirInbound, true, endpoint); err == nil {
			t.Fatalf("%s: refusal not returned", tc.reason)
		}
		if got := counterValue(t, inboundRefusedTotal.WithLabelValues(tc.reason)); got != before+1 {
			t.Errorf("%s: counter %v, want %v", tc.reason, got, before+1)
		}
	}

	// An outbound failure is not an inbound refusal.
	before := counterValue(t, inboundRefusedTotal.WithLabelValues(refusedOther))
	m := observeResourceManager(&refusingResourceManager{err: errors.New("dial side")})
	_, _ = m.OpenConnection(network.DirOutbound, true, endpoint)
	if got := counterValue(t, inboundRefusedTotal.WithLabelValues(refusedOther)); got != before {
		t.Errorf("outbound failure counted as an inbound refusal")
	}

	// A granted connection is passed through and not counted.
	ok := observeResourceManager(&refusingResourceManager{limit: 42})
	if _, err := ok.OpenConnection(network.DirInbound, true, endpoint); err != nil {
		t.Fatalf("granted connection refused: %v", err)
	}
	if ok.GetConnLimit() != 42 {
		t.Errorf("GetConnLimit = %d, want the wrapped manager's 42", ok.GetConnLimit())
	}
}

func TestObservedResourceManagerLogsOneSourceOncePerInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := observeResourceManager(&refusingResourceManager{err: errors.New("rate limit exceeded")})
	m.now = func() time.Time { return now }
	a := multiaddr.StringCast("/ip4/10.0.0.1/tcp/1")
	b := multiaddr.StringCast("/ip4/10.0.0.2/tcp/1")

	for i := 0; i < 3; i++ {
		_, _ = m.OpenConnection(network.DirInbound, true, a)
	}
	_, _ = m.OpenConnection(network.DirInbound, true, b)
	if len(m.lastLogAt) != 2 {
		t.Fatalf("sources remembered = %d, want 2", len(m.lastLogAt))
	}
	if !m.lastLogAt["10.0.0.1"].Equal(now) {
		t.Errorf("first source logged at %v, want the first refusal's time", m.lastLogAt["10.0.0.1"])
	}

	// Past the interval the source is logged again and stale ones are dropped.
	now = now.Add(refusalLogInterval)
	_, _ = m.OpenConnection(network.DirInbound, true, a)
	if !m.lastLogAt["10.0.0.1"].Equal(now) {
		t.Errorf("source not logged again after the interval")
	}
	if _, kept := m.lastLogAt["10.0.0.2"]; kept {
		t.Errorf("a source silent for the whole interval is still remembered")
	}
}

func TestPerPeerLogLimiter(t *testing.T) {
	var l perPeerLogLimiter
	now := time.Unix(1_700_000_000, 0)
	p, q := peer.ID("peer-a"), peer.ID("peer-b")
	if !l.allow(p, now) || l.allow(p, now.Add(perPeerLogInterval-time.Second)) {
		t.Fatal("first line allowed once, then held for the interval")
	}
	if !l.allow(q, now) {
		t.Fatal("another peer is not held by the first")
	}
	if !l.allow(p, now.Add(perPeerLogInterval)) {
		t.Fatal("the peer is logged again after the interval")
	}
	if _, kept := l.lastAt[q]; kept {
		t.Fatal("a peer silent for the whole interval is still remembered")
	}
}

func TestEffectiveConnsPerSourceIP(t *testing.T) {
	if got := effectiveConnsPerSourceIP(0); got != defaultConnsPerSourceIP {
		t.Errorf("unset = %d, want libp2p's default %d", got, defaultConnsPerSourceIP)
	}
	if got := effectiveConnsPerSourceIP(64); got != 64 {
		t.Errorf("configured = %d, want 64", got)
	}
}
