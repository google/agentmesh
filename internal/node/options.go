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

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
)

const (
	DefaultMeshName             = "public-mesh"
	DefaultDiscoveryInterval    = "30s"
	DefaultConfigFile           = "sam-node.yaml"
	DefaultRouterConnectTimeout = 5 * time.Second
	// DefaultSocketName is the local API socket the node creates in its data directory.
	DefaultSocketName = "sam.sock"
)

// Options holds all configuration options for a SamNode.
type Options struct {
	PrivKey            crypto.PrivKey
	ControlPlanePubKey ed25519.PublicKey
	RouterAddrs        []multiaddr.Multiaddr
	Store              *Store

	MeshID            string
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
	MonitorBootstrap     time.Duration
	MonitorInterval      time.Duration
	AutoRelayMinInterval time.Duration
	AutoRelayBootDelay   time.Duration
	AutoRelayBackoff     time.Duration
	// RouterConnectTimeout bounds each router address's dial (connect + stream open).
	RouterConnectTimeout time.Duration
	// BiscuitTimeout bounds Datalog evaluation when verifying biscuit tokens.
	BiscuitTimeout time.Duration
	// DHT Options
	DHTProviderAddrTTL   time.Duration
	DHTMaxRecordAge      time.Duration
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
	// BackendProbeTimeout bounds how long a command-spawned service backend
	// (sam-node.yaml's `command`, spawned as a local subprocess) is given to
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
}

// Default applies default values to Options if they are not specified.
func (o *Options) Default() {
	if o.MeshID == "" {
		o.MeshID = "public-mesh"
	}
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
	// ed25519 verification panics on a wrong-size key, and this one comes
	// from a flag or FFI config.
	if len(o.ControlPlanePubKey) > 0 && len(o.ControlPlanePubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("control plane public key must be %d bytes, got %d", ed25519.PublicKeySize, len(o.ControlPlanePubKey))
	}
	return nil
}
