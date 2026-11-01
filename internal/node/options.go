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
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
)

const (
	DefaultDiscoveryInterval    = "30s"
	DefaultConfigFile           = "agentmesh-node.yaml"
	DefaultRouterConnectTimeout = 5 * time.Second
	// A router pod that restarts is back in well under a minute; the first
	// redial waits a moment for it, and six doublings reach past where the
	// connection monitor's own interval takes over.
	DefaultRouterRedialDelay    = 2 * time.Second
	DefaultRouterRedialAttempts = 6
	// DefaultRouterAuthAttempts with DefaultRouterRedialDelay doubling
	// between them waits 14 s in all beyond the dials themselves: enough
	// for a router that is busy admitting a fleet, short enough that a
	// member with no router at all still reports it within a minute.
	DefaultRouterAuthAttempts = 4
	// DefaultRouters is how many routers a node keeps a session with: one
	// is enough to be on the mesh, the second is there for when the first
	// restarts. Every session costs a router a connection, so a node does
	// not keep one with every router it knows of.
	DefaultRouters = 2
	// DefaultRouterShunDuration is how long a node stays off a router that
	// sent it away or did not come back: past a rollout of the router, short
	// enough that one back for good is used again.
	DefaultRouterShunDuration = 5 * time.Minute
	// DefaultSocketName is the local API socket the node creates in its data directory.
	DefaultSocketName = "agentmesh.sock"
)

// Reachability is the value of Options.Reachability and of --reachability.
type Reachability string

const (
	ReachabilityPrivate Reachability = "private"
	ReachabilityAuto    Reachability = "auto"
)

// Options holds all configuration options for a AgentMeshNode.
type Options struct {
	PrivKey            crypto.PrivKey
	ControlPlanePubKey ed25519.PublicKey
	RouterAddrs        []multiaddr.Multiaddr
	Store              *Store

	DiscoveryInterval string
	ListenAddrs       []string
	EnableRelay       bool
	NodeConfig        *NodeConfigComplete
	KeyGracePeriod    time.Duration
	AllowLoopback     bool
	// AnnouncePrivateAddrs controls whether RFC1918/ULA addresses are published
	// to the mesh. Nil means true: private meshes reach each other over exactly
	// those addresses. Set false on nodes that are only reachable via routers or
	// public addresses, so peers do not learn the host's internal topology.
	AnnouncePrivateAddrs *bool
	// Reachability is how the node decides whether peers can dial it
	// directly. ReachabilityPrivate, the default, assumes they cannot: the
	// node always holds a relay reservation with the routers and is reached
	// through them, which works behind any NAT and needs nothing configured.
	// ReachabilityAuto lets AutoNAT v2 decide from dial-backs by the routers:
	// a node they can reach on a public address advertises that address and
	// holds no reservation, so direct dials replace relayed ones and the
	// routers carry only the members that need them. Auto is only right
	// where the routers sit on the public side of every NAT the node is
	// behind: a router in the same cluster or LAN can reach a node that the
	// rest of the mesh cannot, and would make it unreachable.
	Reachability         Reachability
	MonitorBootstrap     time.Duration
	MonitorInterval      time.Duration
	AutoRelayMinInterval time.Duration
	AutoRelayBootDelay   time.Duration
	AutoRelayBackoff     time.Duration
	// RouterConnectTimeout bounds each router address's dial (connect + stream open).
	RouterConnectTimeout time.Duration
	// RouterRedialDelay is how long after a router session drops the node
	// waits before dialing that router again; each further attempt waits
	// twice as long, up to RouterRedialAttempts of them. Zero uses the
	// default; negative disables the redial, leaving a dropped router to the
	// connection monitor.
	RouterRedialDelay    time.Duration
	RouterRedialAttempts int
	// RouterAuthAttempts is how many times Start, and the handshake after
	// an enrollment, dial the routers before giving up, RouterRedialDelay
	// doubling between attempts. Zero uses the default.
	RouterAuthAttempts int
	// Routers is how many routers the node keeps a session with, out of
	// those the control plane lists; every router when there are fewer.
	// Zero uses DefaultRouters. A session that drops is redialled, and a
	// router that does not come back is replaced from the list.
	Routers int
	// RouterSelector names labels a router must attest for the node to
	// attach to it, every pair; RouterPrefer names labels whose routers the
	// node attaches to first, the more pairs attested the earlier. Among
	// routers equal on preference the node takes the ones with the most
	// room. Both are matched against the labels /info lists for a router,
	// which are the ones the control plane attested at its enrollment.
	RouterSelector map[string]string
	RouterPrefer   map[string]string
	// RouterShunDuration is how long the node stays off a router that told
	// it to go away or that did not come back on redial. Zero uses the
	// default.
	RouterShunDuration time.Duration
	// BiscuitTimeout bounds Datalog evaluation when verifying biscuit tokens.
	BiscuitTimeout time.Duration
	// DHT Options
	DHTLookupLimit       int
	DiscoveryConcurrency int
	// RequiredRole restricts enrollment and startup to only accept tokens containing this role.
	RequiredRole string
	// ControlPlaneSyncInterval is how often the node pulls what it reads from
	// the control plane: signing keys, ban set and router addresses, mesh
	// policy. Zero uses the default; negative disables the loop.
	ControlPlaneSyncInterval time.Duration
	// ControlPlaneSyncJitter is the maximum random delay before a sync that a
	// gossip event asked for, so a fleet told at once does not pull at once.
	// Zero uses a tenth of ControlPlaneSyncInterval: the spread has to grow
	// with the fleet's cadence, or a policy update on a large mesh is a
	// stampede.
	ControlPlaneSyncJitter time.Duration
	// BootstrapTokenPath is the file the node's bootstrap (join) token is
	// read from. A node that has it can enroll again on its own when the
	// control plane answers 401 to an authenticated call, which is what a
	// control plane that lost its store (a new Cloud Run revision without a
	// database) does; the token is read again each time so a rotated token
	// is picked up. Empty leaves recovery to the renewal loop.
	BootstrapTokenPath string
	// BackendProbeTimeout bounds how long a command-spawned service backend
	// (agentmesh-node.yaml's `command`, spawned as a local subprocess) is given to
	// answer before the service is registered but withheld from
	// advertisement. Zero uses the library default (2s). Raise this for
	// backends with slower cold-start/import costs than that - the default
	// is tight enough that even simple interpreted-language MCP servers can
	// miss it on first spawn.
	BackendProbeTimeout time.Duration
	// SecretsDir is where the node resolves the credential names the control
	// plane assigns with egress destinations: one file per name, put there by
	// the platform (a Secret volume, a vault agent). Zero uses DefaultSecretsDir.
	SecretsDir string
	// CatalogReportInterval specifies how often the node self-reports its
	// locally registered services to the control plane (POST
	// /nodes/catalog), so an admin can see mesh-wide service topology
	// without the control plane needing DHT/P2P access to every node
	// itself. Zero uses the default.
	CatalogReportInterval time.Duration
	// CatalogReportInitialDelay is how long after Start the first catalog
	// report is sent, so services configured at startup have registered by
	// then. Zero uses the default.
	CatalogReportInitialDelay time.Duration
	// TokenSource is the optional live platform/OIDC token provider presented
	// as TokenRefreshRequest.jwt during RefreshEnrollment.
	TokenSource TokenSource
	// AllowInsecureControlPlane permits plaintext http:// control-plane and OIDC
	// URLs on non-loopback hosts for this node instance without mutating the
	// process-wide flag.
	AllowInsecureControlPlane bool
	// DisableFatalExit suppresses process-terminating logger.Fatalf calls on
	// router dropout when the node runs embedded inside a host Go application.
	DisableFatalExit bool
	// OnStreamRefused, when non-nil, is invoked whenever the libp2p auth gate
	// refuses an unauthenticated or non-router stream.
	OnStreamRefused func(scope, protocol string)
}

// Default applies default values to Options if they are not specified.
func (o *Options) Default() {
	if o.DiscoveryInterval == "" {
		o.DiscoveryInterval = "30s"
	}
	if o.MonitorBootstrap == 0 {
		o.MonitorBootstrap = 2 * time.Minute
	}
	if o.MonitorInterval == 0 {
		o.MonitorInterval = 1 * time.Minute
	}
	if o.AutoRelayMinInterval == 0 {
		o.AutoRelayMinInterval = 30 * time.Second
	}
	if o.AutoRelayBackoff == 0 {
		o.AutoRelayBackoff = 3 * time.Second
	}
	if o.KeyGracePeriod == 0 {
		o.KeyGracePeriod = 24 * time.Hour
	}
	if o.RouterConnectTimeout == 0 {
		o.RouterConnectTimeout = DefaultRouterConnectTimeout
	}
	if o.RouterRedialDelay == 0 {
		o.RouterRedialDelay = DefaultRouterRedialDelay
	}
	if o.RouterRedialAttempts <= 0 {
		o.RouterRedialAttempts = DefaultRouterRedialAttempts
	}
	if o.RouterAuthAttempts <= 0 {
		o.RouterAuthAttempts = DefaultRouterAuthAttempts
	}
	if o.Routers <= 0 {
		o.Routers = DefaultRouters
	}
	if o.RouterShunDuration <= 0 {
		o.RouterShunDuration = DefaultRouterShunDuration
	}
	if o.Reachability == "" {
		o.Reachability = ReachabilityPrivate
	}
	if o.BiscuitTimeout <= 0 {
		o.BiscuitTimeout = identity.DefaultAuthorizerTimeout
	}
	if o.DHTLookupLimit <= 0 {
		o.DHTLookupLimit = 20
	}
	if o.DiscoveryConcurrency <= 0 {
		o.DiscoveryConcurrency = 10
	}
	if len(o.ListenAddrs) == 0 {
		o.ListenAddrs = []string{"/ip4/0.0.0.0/udp/5001/quic-v1", "/ip4/0.0.0.0/tcp/5002"}
	}
	if o.AnnouncePrivateAddrs == nil {
		announce := true
		o.AnnouncePrivateAddrs = &announce
	}
	if o.RequiredRole == "" {
		o.RequiredRole = api.RoleNode
	}
	if o.ControlPlaneSyncInterval == 0 {
		o.ControlPlaneSyncInterval = DefaultControlPlaneSyncInterval
	}
	if o.SecretsDir == "" {
		o.SecretsDir = DefaultSecretsDir
	}
	if o.CatalogReportInterval <= 0 {
		o.CatalogReportInterval = 1 * time.Minute
	}
	if o.CatalogReportInitialDelay <= 0 {
		o.CatalogReportInitialDelay = 5 * time.Second
	}
	if o.ControlPlaneSyncJitter <= 0 && o.ControlPlaneSyncInterval > 0 {
		o.ControlPlaneSyncJitter = o.ControlPlaneSyncInterval / 10
	}
	if o.NodeConfig == nil {
		o.NodeConfig = &NodeConfigComplete{}
	}
	if o.BackendProbeTimeout <= 0 {
		o.BackendProbeTimeout = defaultDHTProbeTimeout
	}
}

// Validate verifies that the required options are provided and valid.
func (o *Options) Validate() error {
	if o.PrivKey == nil {
		return fmt.Errorf("private key is required")
	}
	if o.Store == nil {
		return fmt.Errorf("store is required")
	}
	if o.RequiredRole == "" {
		return fmt.Errorf("RequiredRole must be specified")
	}
	switch o.Reachability {
	case "", ReachabilityPrivate, ReachabilityAuto:
	default:
		return fmt.Errorf("reachability %q is not %q or %q", o.Reachability, ReachabilityPrivate, ReachabilityAuto)
	}
	if err := api.ValidateLabels(o.RouterSelector); err != nil {
		return fmt.Errorf("RouterSelector: %w", err)
	}
	if err := api.ValidateLabels(o.RouterPrefer); err != nil {
		return fmt.Errorf("RouterPrefer: %w", err)
	}
	// ed25519 verification panics on a wrong-size key, and this one comes
	// from a flag or FFI config.
	if len(o.ControlPlanePubKey) > 0 && len(o.ControlPlanePubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("control plane public key must be %d bytes, got %d", ed25519.PublicKeySize, len(o.ControlPlanePubKey))
	}
	return nil
}
