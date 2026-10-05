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

// Package ratelimit bounds how often an individual peer may make a node or
// router do pre-authentication work.
package ratelimit

import (
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

const (
	// Rate limiting defaults for peers
	PeerRateLimit = 5
	PeerBurst     = 10
)

// PeerRateLimiter tracks rate limits per peer using an LRU cache.
type PeerRateLimiter struct {
	cache *lru.Cache[string, *rate.Limiter]
	limit rate.Limit
	burst int
	mu    sync.Mutex
}

// NewPeerRateLimiter creates a new PeerRateLimiter with specified cache size
// and the default pre-authentication peer rate limit and burst.
func NewPeerRateLimiter(size int) (*PeerRateLimiter, error) {
	return NewPeerRateLimiterWithRate(size, PeerRateLimit, PeerBurst)
}

// NewPeerRateLimiterWithRate creates a new PeerRateLimiter with specified cache
// size, rate limit (requests/sec), and burst size.
func NewPeerRateLimiterWithRate(size int, limit float64, burst int) (*PeerRateLimiter, error) {
	cache, err := lru.New[string, *rate.Limiter](size)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = PeerRateLimit
	}
	if burst <= 0 {
		burst = PeerBurst
	}
	return &PeerRateLimiter{
		cache: cache,
		limit: rate.Limit(limit),
		burst: burst,
	}, nil
}

// Allow checks if the peer is allowed to perform an action.
func (prl *PeerRateLimiter) Allow(peerID string) bool {
	prl.mu.Lock()
	defer prl.mu.Unlock()

	limiter, ok := prl.cache.Get(peerID)
	if !ok {
		limiter = rate.NewLimiter(prl.limit, prl.burst)
		prl.cache.Add(peerID, limiter)
		return limiter.Allow()
	}
	return limiter.Allow()
}
