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
	"fmt"
	"net/http"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
)

// Options holds configuration details for the sam-router.
type Options struct {
	ControlPlaneURL    string
	ListenAddrs        []string
	ExternalAddrs      []string
	KeysSyncInterval   time.Duration
	LeaseRenewInterval time.Duration
	OIDCProvider       string // For OIDC enrollment
	OIDCToken          string // OIDC JWT token for enrollment
	BootstrapToken     string // Pre-shared bootstrap token for enrollment
	BootstrapTokenPath string // File path containing pre-shared bootstrap token
	JWTPath            string // File path containing OIDC JWT token
	KeysDBPath         string // Path to save peer private key
	AllowLoopback      bool
	BiscuitTimeout     time.Duration
	LogVerbose         bool
	// DHTProviderAddrTTL is how long a provider record lives after its last
	// announcement; 0 is DefaultDHTProviderAddrTTL.
	DHTProviderAddrTTL time.Duration
	DHTMaxRecordAge    time.Duration
	LowWaterMark       int
	HighWaterMark      int
	// RelayLimitDuration / RelayLimitData cap each relayed connection; 0 is
	// no limit, so Default() leaves them alone.
	RelayLimitDuration time.Duration
	RelayLimitData     int64
	// RequiredRole restricts enrollment and startup to only accept tokens containing this role.
	RequiredRole string
	// HTTPFallbackHandler, when set, serves ordinary (non-WebSocket-upgrade)
	// HTTP requests arriving on the router's WebSocket listen addrs, letting a
	// single port carry both libp2p and REST traffic (single-port mode).
	HTTPFallbackHandler http.Handler
	// ConnsPerSourceIP overrides libp2p's per-source-IP inbound connection
	// cap (default: 8) when > 0. Raise it when the listener sits behind a
	// TLS-terminating proxy or NAT, where many peers share a few source IPs.
	ConnsPerSourceIP int
	// AllowInsecureControlPlane accepts a plaintext http:// ControlPlaneURL
	// to a non-loopback host. Off by default: whoever answers that URL is
	// the trust root.
	AllowInsecureControlPlane bool
	// MetricsAddr, when set, serves /metrics, /healthz and /readyz on a
	// plain HTTP listener separate from the libp2p ports. Off by default:
	// the listener is unauthenticated, so the operator names where it binds.
	MetricsAddr string
}

// Default sets default values for options.
func (o *Options) Default() {
	if o.ControlPlaneURL == "" {
		o.ControlPlaneURL = "http://127.0.0.1:8080"
	}
	if len(o.ListenAddrs) == 0 {
		o.ListenAddrs = []string{"/ip4/0.0.0.0/tcp/5001", "/ip6/::/tcp/5001"}
	}
	if o.KeysSyncInterval <= 0 {
		o.KeysSyncInterval = 5 * time.Minute
	}
	if o.LeaseRenewInterval <= 0 {
		o.LeaseRenewInterval = 30 * time.Second
	}
	if o.LowWaterMark <= 0 {
		o.LowWaterMark = 1000
	}
	if o.HighWaterMark <= 0 {
		o.HighWaterMark = 4000
	}
	if o.KeysDBPath == "" {
		o.KeysDBPath = "router.key"
	}
	if o.BiscuitTimeout <= 0 {
		o.BiscuitTimeout = identity.DefaultAuthorizerTimeout
	}
	if o.RequiredRole == "" {
		o.RequiredRole = api.RoleRouter
	}
}

// Validate ensures options are valid.
func (o *Options) Validate() error {
	if o.ControlPlaneURL == "" {
		return fmt.Errorf("ControlPlaneURL must be specified")
	}
	return api.ValidateControlPlaneTransport(o.ControlPlaneURL, o.AllowInsecureControlPlane)
}
