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

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/multiformats/go-multiaddr"
)

// DefaultShutdownLeaseTTL is the CLI default for Options.ShutdownLeaseTTL:
// about the time a pod takes to come back in place, and a pod's default
// termination grace period.
const DefaultShutdownLeaseTTL = 30 * time.Second

// DefaultAuthDeadline is the CLI default for Options.AuthDeadline: a
// member's first act on a connection is the handshake, which takes well
// under a second; a DHT query from a member attached elsewhere is done in
// less.
const DefaultAuthDeadline = time.Minute

// DefaultControlPlaneSyncInterval is how often a router talks to the control
// plane when nothing happens: the lease is renewed, and /info, /keys and
// /policies re-read, every five minutes. What has to be quick does not wait
// for it: a mesh event runs a pass at once, a new router reads /info on its
// own first pass and handshakes with every listed router, and a lookup that
// finds nothing re-reads /info (refederateIfStale).
const DefaultControlPlaneSyncInterval = 5 * time.Minute

// Options holds configuration details for the agentmesh-router.
type Options struct {
	ControlPlaneURL string
	ListenAddrs     []string
	ExternalAddrs   []string
	// ControlPlaneSyncInterval is how often the router's one pass over the
	// control plane runs: lease, /info, /keys, /policies, credential expiry.
	ControlPlaneSyncInterval time.Duration
	OIDCProvider             string // For OIDC enrollment
	OIDCToken                string // OIDC JWT token for enrollment
	BootstrapToken           string // Pre-shared bootstrap token for enrollment
	BootstrapTokenPath       string // File path containing pre-shared bootstrap token
	JWTPath                  string // File path containing OIDC JWT token
	KeysDBPath               string // Path to save peer private key
	AllowLoopback            bool
	BiscuitTimeout           time.Duration
	LogVerbose               bool
	LowWaterMark             int
	HighWaterMark            int
	// RelayLimitDuration / RelayLimitData cap each relayed connection; 0 is
	// no limit, so Default() leaves them alone.
	RelayLimitDuration time.Duration
	RelayLimitData     int64
	// RelayMaxReservations is how many members may hold a relay reservation,
	// which is what makes a member reachable through this router. Zero is
	// HighWaterMark: every connected member may be reachable.
	RelayMaxReservations int
	// RelayMaxCircuits is how many relayed connections one peer may hold at
	// once through this router. Zero is DefaultRelayMaxCircuits.
	RelayMaxCircuits int
	// ShutdownLeaseTTL is the lease the router asks for as it stops: how
	// long the control plane keeps listing it, which is the time the router
	// expects to be away. Zero sends no last lease and the entry expires on
	// the control plane's schedule. The CLIs default to
	// DefaultShutdownLeaseTTL.
	ShutdownLeaseTTL time.Duration
	// AuthDeadline is how long an inbound connection may stay open without
	// its peer passing the handshake before the router closes it. Members
	// hold a connection for their session; anyone else (a member attached
	// elsewhere whose DHT client queried here, a scanner) is done with the
	// connection long before, and would otherwise count against the
	// watermarks until a trim. Zero keeps every connection. The CLIs
	// default to DefaultAuthDeadline.
	AuthDeadline time.Duration
	// Labels the router declares at enrollment, the same labels as a
	// node's: the control plane signs them only if the router's role allows
	// them (PolicyRole.allowed_labels) and lists them on /info, where a
	// member selects or prefers routers by placement. Validated with
	// api.ValidateLabels.
	Labels map[string]string
	// RequiredRole restricts enrollment and startup to only accept tokens containing this role.
	RequiredRole string
	// HTTPFallbackHandler, when set, serves ordinary (non-WebSocket-upgrade)
	// HTTP requests arriving on the router's WebSocket listen addrs, letting a
	// single port carry both libp2p and REST traffic (single-port mode).
	HTTPFallbackHandler http.Handler
	// ConnsPerSourceIP is the inbound connection cap per source address,
	// and scales the per-address connection rate limit with it. Zero
	// derives it from HighWaterMark: one address may hold at most a
	// quarter of the router's inbound budget, so filling a router takes
	// at least four addresses. libp2p's own default is 8, sized for a
	// public DHT where one IP is one peer; members of a mesh share
	// addresses (pods behind a node's SNAT, a cluster behind a NAT, an
	// office), and the handshake, not this cap, is what keeps strangers
	// out.
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
	} else {
		o.ControlPlaneURL = api.NormalizeControlPlaneURL(o.ControlPlaneURL)
	}
	if len(o.ListenAddrs) == 0 {
		o.ListenAddrs = []string{"/ip4/0.0.0.0/tcp/5001", "/ip6/::/tcp/5001"}
	}
	if o.ControlPlaneSyncInterval <= 0 {
		o.ControlPlaneSyncInterval = DefaultControlPlaneSyncInterval
	}
	if o.HighWaterMark <= 0 {
		o.HighWaterMark = DefaultHighWaterMark
	}
	if o.LowWaterMark <= 0 {
		o.LowWaterMark = DefaultLowWaterMark(o.HighWaterMark)
	}
	if o.ConnsPerSourceIP <= 0 {
		o.ConnsPerSourceIP = DefaultConnsPerSourceIP(o.HighWaterMark)
	}
	if o.RelayMaxReservations <= 0 {
		o.RelayMaxReservations = o.HighWaterMark
	}
	if o.RelayMaxCircuits <= 0 {
		o.RelayMaxCircuits = DefaultRelayMaxCircuits
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
	if o.ShutdownLeaseTTL < 0 {
		return fmt.Errorf("ShutdownLeaseTTL must not be negative, got %s", o.ShutdownLeaseTTL)
	}
	if o.LowWaterMark >= o.HighWaterMark {
		return fmt.Errorf("LowWaterMark (%d) must be below HighWaterMark (%d)", o.LowWaterMark, o.HighWaterMark)
	}
	if err := api.ValidateLabels(o.Labels); err != nil {
		return fmt.Errorf("labels: %w", err)
	}
	for _, s := range o.ExternalAddrs {
		if _, err := multiaddr.NewMultiaddr(s); err != nil {
			return fmt.Errorf("external address %q: %w", s, err)
		}
	}
	return api.ValidateControlPlaneTransport(o.ControlPlaneURL, o.AllowInsecureControlPlane)
}
