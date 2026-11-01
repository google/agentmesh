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
	"math/rand"

	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	cpclient "github.com/google/agentmesh/internal/controlplane/client"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/p2plimits"
	"github.com/google/agentmesh/internal/ratelimit"
	lru "github.com/hashicorp/golang-lru/v2"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	gostream "github.com/libp2p/go-libp2p-gostream"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"
)

// PeerstoreKeyPrivateIPFailed is the key used in the libp2p Peerstore to track
// if a peer's private IP was previously found to be unreachable or slower than a relay.
// This allows the node to "try once and remember", avoiding a 15-second timeout on
// subsequent discovery or tool calls when dialing unroutable private networks.
const PeerstoreKeyPrivateIPFailed = "private_ip_failed"

const (
	// Cache sizes
	RateLimiterSize       = 1000
	RevocationCacheSize   = 10000
	VerificationCacheSize = 1000

	// Freshness checks
	FreshnessThreshold = 5 * time.Minute

	// Key pruning
	KeyPruningInterval = 1 * time.Hour
	// DefaultControlPlaneSyncInterval bounds how long a running node can lag
	// the control plane on keys, bans and policy when no gossip event reaches
	// it. It must sit well inside the control plane's --key-grace-period
	// (1h by default): a successor key can only be adopted while the key it
	// replaces still vouches for it, and one attempt per window is a race.
	// Four attempts per default window is the trade against load on large
	// meshes, where an operator raising the grace period can raise this too.
	DefaultControlPlaneSyncInterval = 15 * time.Minute

	// reprovideRetryInterval is the first retry after a backend was withheld,
	// doubling up to the mesh's reprovide interval. Backends commonly start
	// after the node does, and the full interval is far too long to wait for
	// one of those.
	reprovideRetryInterval = 5 * time.Second
)

var (
	// Renewal timing defaults
	DefaultRenewalFallback = (api.BiscuitTokenTTL * 8) / 10 // 80% of TTL (19.2h)
	RenewalBuffer          = api.BiscuitTokenTTL / 5        // 20% of TTL (4.8h)
	RenewalThreshold       = api.BiscuitTokenTTL / 4        // 25% of TTL (6h)
)

var ErrFatalAuth = errors.New("fatal authentication error")

type TrustedKey struct {
	Key        ed25519.PublicKey
	ReceivedAt time.Time
}

type nodeRelayACL struct {
	node *AgentMeshNode
}

func (a *nodeRelayACL) AllowReserve(p peer.ID, addr multiaddr.Multiaddr) bool {
	return a.node.isAdmitted(p)
}

func (a *nodeRelayACL) AllowConnect(src peer.ID, srcAddr multiaddr.Multiaddr, dest peer.ID) bool {
	// Both ends: an unauthenticated source could otherwise open circuits to
	// every admitted peer through this node.
	return a.node.isAdmitted(src) && a.node.isAdmitted(dest)
}

// isAdmitted reports whether a peer completed the auth handshake and its token
// has not lapsed since. The handshake only proves the token was valid at that
// instant, so without this the relay ACL would honour an admission forever.
func (n *AgentMeshNode) isAdmitted(p peer.ID) bool {
	return admissionHolds(&n.authPeers, p)
}

// isAdmittedRouter reports whether a peer completed the auth handshake with a
// credential carrying role("mesh:role:router") and that admission holds. It
// requires isAdmitted too, so dropping a peer from authPeers (a ban, an
// eviction) withdraws its router standing with it.
func (n *AgentMeshNode) isAdmittedRouter(p peer.ID) bool {
	return n.isAdmitted(p) && admissionHolds(&n.authRouters, p)
}

// admitPeer records a completed handshake: every admitted peer in authPeers,
// and a router additionally in authRouters. A peer re-admitted without the
// role loses it.
func (n *AgentMeshNode) admitPeer(p peer.ID, expiry time.Time, router bool) {
	n.authPeers.Store(p, expiry)
	if router {
		n.authRouters.Store(p, expiry)
	} else {
		n.authRouters.Delete(p)
	}
}

// forgetAdmission drops every record of p's handshake.
func (n *AgentMeshNode) forgetAdmission(p peer.ID) {
	n.authPeers.Delete(p)
	n.authRouters.Delete(p)
}

func admissionHolds(m *sync.Map, p peer.ID) bool {
	v, ok := m.Load(p)
	if !ok {
		return false
	}
	expiry, ok := v.(time.Time)
	if !ok || !time.Now().Before(expiry) {
		m.Delete(p)
		return false
	}
	return true
}

type AgentMeshNode struct {
	config Options
	// enrollBootstrapFn is EnrollBootstrap unless a test injects the step.
	enrollBootstrapFn func(ctx context.Context, controlPlaneURL, bootstrapToken string) error
	// lastReenroll is when recoverEnrollment last spent the bootstrap token.
	lastReenroll         time.Time
	reenrollMu           sync.Mutex
	Host                 host.Host
	Directory            Directory
	PubSub               *pubsub.PubSub
	Store                *Store
	RouterPeerID         peer.ID
	authenticatedRouters map[peer.ID]bool
	// redialing holds the routers a redialRouter goroutine is working on.
	redialing map[peer.ID]bool
	// handshaking holds the routers a handshake is in flight with; a second
	// caller waits for that one (authRouter).
	handshaking map[peer.ID]chan struct{}
	// routerCatalog is every router the node knows of; attached are the
	// Options.Routers of them it keeps a session with; shunned are the ones
	// it stays off until the time given, having been sent away or having
	// not come back. connMgr protects the attached ones from being trimmed.
	routerCatalog []routerCandidate
	// transitCatalogRefreshedAt is when a relay the catalog did not list
	// last made the node re-read /info (selectTransit).
	transitCatalogRefreshedAt time.Time
	attached                  map[peer.ID]bool
	shunned                   map[peer.ID]time.Time
	// directory is how the mesh keeps its DHT, as the control plane publishes
	// it on /info (syncMeshInfo); the api defaults until it has answered.
	directory             api.DirectorySettings
	connMgr               *connmgr.BasicConnMgr
	peerLastEventTime     map[string]int64
	mu                    sync.Mutex
	nodeConfig            *NodeConfigComplete
	revokedPeers          *lru.Cache[string, int64]
	revokedTokens         *lru.Cache[string, time.Time]
	delegatedBiscuitCache *lru.Cache[string, *api.TokenExchangeResponse]
	stsTokenCache         *lru.Cache[string, *api.STSTokenResponse]
	peerLabelGate         *lru.Cache[string, time.Time]
	// authPeers is every peer that completed the handshake with this node,
	// keyed by peer.ID, with the instant its admission lapses. authRouters
	// holds the subset whose credential carried mesh:role:router, with the
	// same instant, for the protocols only a router may open (routerHost).
	authPeers       sync.Map
	authRouters     sync.Map
	trustedKeys     []TrustedKey
	keysMu          sync.RWMutex
	MeshPolicyRules []biscuit.Rule
	meshPolicyTexts []string
	MeshPolicyMu    sync.RWMutex
	// pendingEgress holds assignments that arrived before Start created the
	// service registry (SyncControlPlane runs first); Start applies them.
	pendingEgress   []*api.EgressDestination
	pendingEgressMu sync.Mutex
	rateLimiter     *ratelimit.PeerRateLimiter
	// handshakeLimiter bounds /mesh/auth attempts per peer separately from
	// rateLimiter, so a peer's authenticated traffic cannot starve its own
	// re-authentication and vice versa.
	handshakeLimiter *ratelimit.PeerRateLimiter
	// externalIngressLimiter bounds /mesh/ingress requests per forwarding router
	// separately from peer-to-peer rateLimiter, because a single router
	// multiplexes external HTTP traffic for many external callers.
	externalIngressLimiter *ratelimit.PeerRateLimiter
	services               *ServiceRegistry
	BoundHTTPAddr          string
	BoundSocketPath        string
	AllowLoopback          bool

	authSuccess             chan struct{}
	authOnce                sync.Once
	currentRelays           []peer.AddrInfo
	reprovideTrigger        chan struct{}
	controlPlaneSyncTrigger chan struct{}
	// refreshMu serializes credential issuance: the control plane redeems
	// only the last biscuit it issued, so two refreshes in flight would
	// invalidate each other.
	refreshMu      sync.Mutex
	tokenSource    TokenSource
	BiscuitTimeout time.Duration
	cachedIdentity atomic.Value
	logger         *golog.ZapEventLogger

	// metricsRegistry holds this node's state collector; see metricsHandler.
	metricsOnce     sync.Once
	metricsRegistry *prometheus.Registry
}

// SetTokenSource configures the live platform/OIDC token source presented as
// TokenRefreshRequest.jwt during RefreshEnrollment.
func (n *AgentMeshNode) SetTokenSource(ts TokenSource) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tokenSource = ts
}

func (n *AgentMeshNode) getTokenSource() TokenSource {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.tokenSource
}

// UpdateRelays updates the current relays used by AutoRelay.
func (n *AgentMeshNode) UpdateRelays(addrs []multiaddr.Multiaddr) {
	newRelays := routerPeers(context.Background(), addrs)
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, relay := range newRelays {
		n.Host.Peerstore().AddAddrs(relay.ID, relay.Addrs, peerstore.PermanentAddrTTL)
	}
	n.currentRelays = newRelays
	logger.Infof("[Relay] Updated current relays for AutoRelay: %v", newRelays)
}

// GetIdentity returns the node's biscuit identity, caching it in memory.
func (n *AgentMeshNode) GetIdentity() []byte {
	if val := n.cachedIdentity.Load(); val != nil {
		b := val.([]byte)
		if len(b) > 0 {
			return b
		}
	}
	if n.Store != nil {
		if biscuitBytes, err := n.Store.LoadIdentity(); err == nil && len(biscuitBytes) > 0 {
			n.cachedIdentity.Store(biscuitBytes)
			return biscuitBytes
		}
	}
	return nil
}

// SetIdentityCache explicitly updates the cached identity.
func (n *AgentMeshNode) SetIdentityCache(b []byte) {
	if len(b) > 0 {
		n.cachedIdentity.Store(b)
	}
}

// RevokeBiscuitID records a Biscuit revocation ID (base64url- or hex-encoded) as revoked until expiry.
func (n *AgentMeshNode) RevokeBiscuitID(revocationID string, expiry time.Time) {
	if revocationID == "" {
		return
	}
	if n.revokedTokens == nil {
		n.mu.Lock()
		if n.revokedTokens == nil {
			n.revokedTokens, _ = lru.New[string, time.Time](RevocationCacheSize)
		}
		n.mu.Unlock()
	}
	if expiry.IsZero() {
		expiry = time.Now().Add(api.BiscuitTokenTTL)
	}
	if n.revokedTokens != nil {
		n.revokedTokens.Add(revocationID, expiry)
		if raw, err := hex.DecodeString(revocationID); err == nil && len(raw) > 0 {
			n.revokedTokens.Add(base64.RawURLEncoding.EncodeToString(raw), expiry)
		}
	}
}

// RevokeBiscuitToken revokes the outermost block of a Biscuit token locally.
// Revoking the final block's RevocationId invalidates that task token and any
// further attenuated descendants without revoking the parent token.
func (n *AgentMeshNode) RevokeBiscuitToken(rawToken []byte, expiry time.Time) (string, error) {
	b, _, err := identity.UnmarshalInbound(rawToken)
	if err != nil {
		return "", err
	}
	ids := b.RevocationIds()
	if len(ids) == 0 {
		return "", fmt.Errorf("biscuit has no revocation IDs")
	}
	revID := base64.RawURLEncoding.EncodeToString(ids[len(ids)-1])
	n.RevokeBiscuitID(revID, expiry)
	return revID, nil
}

// IsBiscuitRevoked checks whether any block of b has been revoked.
func (n *AgentMeshNode) IsBiscuitRevoked(b *biscuit.Biscuit) bool {
	if n == nil || n.revokedTokens == nil || b == nil {
		return false
	}
	now := time.Now()
	for _, id := range b.RevocationIds() {
		key := base64.RawURLEncoding.EncodeToString(id)
		if exp, ok := n.revokedTokens.Get(key); ok {
			if now.Before(exp) {
				return true
			}
			n.revokedTokens.Remove(key)
		}
	}
	return false
}

func stripP2pFromDnsaddr(addr multiaddr.Multiaddr) multiaddr.Multiaddr {
	_, err := addr.ValueForProtocol(multiaddr.P_DNSADDR)
	if err != nil {
		return addr
	}
	parts := multiaddr.Split(addr)
	var components []multiaddr.Multiaddrer
	for _, p := range parts {
		if _, err := p.ValueForProtocol(multiaddr.P_P2P); err != nil {
			components = append(components, multiaddr.Multiaddr{p})
		}
	}
	if len(components) > 0 {
		return multiaddr.Join(components...)
	}
	return addr
}

func resolveAddrIfNeeded(ctx context.Context, addr multiaddr.Multiaddr) ([]multiaddr.Multiaddr, error) {
	_, err := addr.ValueForProtocol(multiaddr.P_DNSADDR)
	if err != nil {
		return []multiaddr.Multiaddr{addr}, nil
	}
	return madns.DefaultResolver.Resolve(ctx, stripP2pFromDnsaddr(addr))
}

// routerPeers resolves router addresses and groups them by peer, in first-seen
// order. A router is advertised under one multiaddr per interface, and a
// dnsaddr entry resolves to every router behind the name, so the same peer
// arrives several times; it is one peer with all of its addresses, dialed
// once and handshaken once. An address that cannot be resolved is kept as
// written for libp2p to resolve at dial time.
func routerPeers(ctx context.Context, addrs []multiaddr.Multiaddr) []peer.AddrInfo {
	var order []peer.ID
	byPeer := map[peer.ID]*peer.AddrInfo{}
	for _, addr := range addrs {
		resolved, err := resolveAddrIfNeeded(ctx, addr)
		if err != nil {
			resolved = []multiaddr.Multiaddr{addr}
		}
		for _, r := range resolved {
			info, err := peer.AddrInfoFromP2pAddr(r)
			if err != nil || info.ID == "" {
				logger.Warnf("Failed to parse router addr %s: %v", r, err)
				continue
			}
			known, seen := byPeer[info.ID]
			if !seen {
				byPeer[info.ID] = info
				order = append(order, info.ID)
				continue
			}
			for _, a := range info.Addrs {
				if !slices.ContainsFunc(known.Addrs, a.Equal) {
					known.Addrs = append(known.Addrs, a)
				}
			}
		}
	}
	out := make([]peer.AddrInfo, 0, len(order))
	for _, id := range order {
		out = append(out, *byPeer[id])
	}
	return out
}

// NewAgentMeshNode creates a new Agent instance secured with the 4-layer pipeline.
// NewAgentMeshNode initializes options and structures without starting background tasks or network interfaces.
func NewAgentMeshNode(cfg Options) (*AgentMeshNode, error) {
	cfg.Default()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var trustedKeys []TrustedKey
	if cfg.Store != nil {
		if stored, err := cfg.Store.LoadTrustedKeys(); err != nil {
			logger.Warnf("Failed to load persisted trusted keys: %v", err)
		} else {
			for _, tk := range stored {
				// A corrupt entry must not reach ed25519 verification (panics
				// on wrong-size keys).
				if len(tk.Key) == ed25519.PublicKeySize {
					trustedKeys = append(trustedKeys, tk)
				} else {
					logger.Warnf("Ignoring persisted trusted key with invalid size %d", len(tk.Key))
				}
			}
		}
	}
	if len(cfg.ControlPlanePubKey) > 0 && !containsTrustedKey(trustedKeys, cfg.ControlPlanePubKey) {
		trustedKeys = append(trustedKeys, TrustedKey{Key: cfg.ControlPlanePubKey, ReceivedAt: time.Now()})
	}

	node := &AgentMeshNode{
		config:                  cfg,
		Store:                   cfg.Store,
		trustedKeys:             trustedKeys,
		peerLastEventTime:       make(map[string]int64),
		authenticatedRouters:    make(map[peer.ID]bool),
		directory:               api.DefaultDirectorySettings(),
		nodeConfig:              cfg.NodeConfig,
		AllowLoopback:           cfg.AllowLoopback,
		authSuccess:             make(chan struct{}),
		reprovideTrigger:        make(chan struct{}, 1),
		controlPlaneSyncTrigger: make(chan struct{}, 1),
		tokenSource:             cfg.TokenSource,
		BiscuitTimeout:          cfg.BiscuitTimeout,
		logger:                  golog.Logger("agentmesh-node"),
	}

	var err error
	node.rateLimiter, err = ratelimit.NewPeerRateLimiterWithRate(RateLimiterSize, 20, 30)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter: %w", err)
	}
	node.handshakeLimiter, err = ratelimit.NewPeerRateLimiter(RateLimiterSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create handshake rate limiter: %w", err)
	}
	node.externalIngressLimiter, err = ratelimit.NewPeerRateLimiterWithRate(RateLimiterSize, 200, 400)
	if err != nil {
		return nil, fmt.Errorf("failed to create external ingress rate limiter: %w", err)
	}
	node.revokedPeers, err = lru.New[string, int64](RevocationCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create revocation cache: %w", err)
	}
	node.revokedTokens, err = lru.New[string, time.Time](RevocationCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create token revocation cache: %w", err)
	}
	node.peerLabelGate, err = lru.New[string, time.Time](labelGateCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create label gate cache: %w", err)
	}

	return node, nil
}

// labels reports this node's operator-declared labels, validated at load.
// NewAgentMeshNode always leaves nodeConfig non-nil, but tests build AgentMeshNode
// literals directly, so the guard lives here rather than at each caller.
func (n *AgentMeshNode) labels() map[string]string {
	if n.nodeConfig == nil {
		return nil
	}
	return n.nodeConfig.Labels
}

// Start initializes the libp2p host, DHT, connects to the routers, and starts runtime components.
func (n *AgentMeshNode) Start(ctx context.Context) error {
	if biscuitBytes := n.GetIdentity(); len(biscuitBytes) > 0 {
		// The identity may be signed by any currently valid control plane
		// key, not only the newest: after a rotation the biscuit's key can
		// legitimately be in its grace period.
		n.keysMu.RLock()
		candidates := make([]ed25519.PublicKey, 0, len(n.trustedKeys))
		for _, tk := range n.trustedKeys {
			candidates = append(candidates, tk.Key)
		}
		n.keysMu.RUnlock()
		if len(candidates) == 0 {
			if pubKeyBytes, _, err := n.Store.LoadMeshConfig(); err == nil && len(pubKeyBytes) == ed25519.PublicKeySize {
				candidates = append(candidates, ed25519.PublicKey(pubKeyBytes))
			}
		}
		if len(candidates) > 0 {
			var roleErr error
			for _, key := range candidates {
				if roleErr = identity.VerifyBiscuitRole(biscuitBytes, key, n.config.RequiredRole, n.BiscuitTimeout); roleErr == nil {
					break
				}
			}
			if roleErr != nil {
				// Stale identity (e.g. signing key rotated past its grace
				// period while offline). Two silent recoveries are tried
				// before giving up: /refresh, which the control plane honours
				// on proof of possession alone if an operator opted this node
				// in to autonomous recovery (the only path a bootstrap node
				// has), then re-enrollment with the stored OIDC refresh token.
				logger.Warnf("Loaded identity fails role requirement %q: %v; attempting recovery", n.config.RequiredRole, roleErr)
				if refreshErr := n.RefreshEnrollment(ctx); refreshErr == nil {
					logger.Info("Identity recovered via autonomous refresh.")
				} else {
					logger.Warnf("Autonomous refresh refused (%v); attempting recovery via stored refresh token", refreshErr)
					if recErr := n.ReEnrollWithRefreshToken(ctx); recErr != nil {
						return fmt.Errorf("loaded identity fails role requirement %q (autonomous refresh: %v; refresh-token recovery: %v): %w", n.config.RequiredRole, refreshErr, recErr, roleErr)
					}
					logger.Info("Identity recovered via refresh-token re-enrollment.")
				}
				// Re-enrollment persisted the response's router addresses; adopt
				// them so the static relay setup below doesn't use stale ones.
				if _, storedAddrs, loadErr := n.Store.LoadMeshConfig(); loadErr == nil {
					var addrs []multiaddr.Multiaddr
					for _, addrStr := range storedAddrs {
						if ma, parseErr := multiaddr.NewMultiaddr(addrStr); parseErr == nil {
							addrs = append(addrs, ma)
						}
					}
					if len(addrs) > 0 {
						n.config.RouterAddrs = addrs
					}
				}
			}
		}
	}

	// Layer 2: Attach the Bouncer (Gater)
	gater := &nodeConnGate{node: n}

	// The routers, one entry per peer with every address it is known by.
	// SyncControlPlane may already have listed them with labels and load;
	// otherwise they are the stored addresses, which say nothing more.
	if len(n.routerCandidates()) == 0 {
		n.setRouterCatalog(candidatesFromAddrs(ctx, n.config.RouterAddrs))
	}
	staticRelays := n.routerCandidates()
	if n.RouterPeerID == "" && len(staticRelays) > 0 {
		n.RouterPeerID = staticRelays[0].ID
	}
	logger.Infof("Configured %d routers, attaching to %d: %v", len(staticRelays), n.wantRouters(), staticRelays)

	cm, err := connmgr.NewConnManager(ConnLowWaterMark, ConnHighWaterMark, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return fmt.Errorf("failed to create connection manager: %w", err)
	}
	n.connMgr = cm
	rm, err := newResourceManager()
	if err != nil {
		return fmt.Errorf("failed to create resource manager: %w", err)
	}

	// Layer 1: Transports & NAT Services. TLS first: Go peers and the
	// Node/Python SDKs land on it. Noise is what a browser can speak, and a
	// relayed connection from one is upgraded here, end to end; both bind
	// the connection to the peer ID.
	opts := []libp2p.Option{
		libp2p.Identity(n.config.PrivKey),
		libp2p.DefaultTransports,
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.ConnectionGater(gater),
		libp2p.ListenAddrStrings(n.config.ListenAddrs...),
		libp2p.EnableNATService(),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.ConnectionManager(cm),
		libp2p.ResourceManager(rm),
		libp2p.SwarmOpts(swarm.WithDialTimeout(15*time.Second), swarm.WithDialRanker(tcpFirstDialRanker)),
		libp2p.AddrsFactory(n.announceFilter),
	}
	// Private: the node holds a relay reservation whatever AutoNAT finds, so
	// it is reachable through the routers behind any NAT. Auto: AutoNAT v2
	// decides, and a node the routers can dial on a public address is
	// advertised there and skips the relay; see Options.Reachability.
	if n.config.Reachability == ReachabilityPrivate {
		opts = append(opts, libp2p.ForceReachabilityPrivate())
	}

	// If we have routers, configure them as our static fallback relays for NAT hole-punching
	if len(staticRelays) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithPeerSource(
			func(ctx context.Context, numPeers int) <-chan peer.AddrInfo {
				logger.Infof("[Relay] AutoRelay called PeerSource for %d peers", numPeers)
				n.mu.Lock()
				currentRelays := n.currentRelays
				n.mu.Unlock()

				c := make(chan peer.AddrInfo, len(currentRelays))
				go func() {
					defer close(c)
					select {
					case <-ctx.Done():
						logger.Infof("[Relay] PeerSource context done")
					case <-n.authSuccess:
						// The routers the node is attached to, which are the
						// ones that will grant it a reservation; shuffled so
						// a fleet spreads its reservations across them.
						n.mu.Lock()
						attachedRelays := n.currentRelays
						n.mu.Unlock()
						logger.Infof("[Relay] Yielding %d attached routers to AutoRelay", len(attachedRelays))
						shuffled := make([]peer.AddrInfo, len(attachedRelays))
						copy(shuffled, attachedRelays)
						rand.Shuffle(len(shuffled), func(i, j int) {
							shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
						})
						for _, r := range shuffled {
							c <- r
						}
					}
				}()
				return c
			},
			autorelay.WithNumRelays(n.config.Routers),
			autorelay.WithBootDelay(n.config.AutoRelayBootDelay),
			autorelay.WithBackoff(n.config.AutoRelayBackoff),
			autorelay.WithMinInterval(n.config.AutoRelayMinInterval),
		))
	}

	// If the user explicitly opts in, allow this node to serve as a relay for others
	if n.config.EnableRelay {
		logger.Infof("[Relay] Enabling Relay Service")
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return err
	}
	n.Host = h

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			remotePeer := c.RemotePeer()
			remoteAddr := c.RemoteMultiaddr()
			if hasCircuit(remoteAddr) || !isPrivateIP(remoteAddr) {
				if err := h.Peerstore().Put(remotePeer, PeerstoreKeyPrivateIPFailed, true); err != nil {
					logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", err)
				}
				logger.Debugf("[Discovery] Peer %s connected via relay/public IP (%s), marking private IP as failed", remotePeer, remoteAddr)
			}
		},
		// The router drops us from its authenticated set the moment our last
		// connection to it closes, so a stale entry here would report a
		// session that no longer exists and skip the re-handshake.
		DisconnectedF: func(_ network.Network, c network.Conn) {
			remotePeer := c.RemotePeer()
			// A router advertises several addresses: only the last connection closing ends the session.
			if len(h.Network().ConnsToPeer(remotePeer)) > 0 {
				return
			}
			n.mu.Lock()
			_, wasAuthenticated := n.authenticatedRouters[remotePeer]
			delete(n.authenticatedRouters, remotePeer)
			attached := n.attached[remotePeer]
			n.mu.Unlock()
			if wasAuthenticated {
				logger.Warnf("[AuthN] Router %s disconnected; clearing authenticated session so the next check re-handshakes", remotePeer)
				if attached {
					n.redialRouter(ctx, remotePeer)
				}
			}
		},
	})

	// Permanently add the router addresses to the peerstore so we can build relay paths later
	for _, pi := range staticRelays {
		h.Peerstore().AddAddrs(pi.ID, pi.Addrs, peerstore.PermanentAddrTTL)
	}

	if n.config.EnableRelay {
		logger.Infof("[Relay] Enabling Relay Service with ACL")
		_, err = relay.New(h, relay.WithACL(&nodeRelayACL{node: n}))
		if err != nil {
			return err
		}
	}

	// Gossip and the directory are served by, and serve, authenticated
	// peers only.
	gated := &meshHost{Host: h, n: n}

	// The directory: the routers this node is attached to answer for it.
	n.Directory = &routerDirectory{host: gated, routers: n.attachedRouters, addrs: h.Addrs}

	n.services = NewServiceRegistry(n.Directory, n.config.BackendProbeTimeout)
	n.services.reprovideNow = n.triggerReprovide
	n.services.onIngressRegistered = n.logIngressURLs
	n.applyPendingEgress(ctx)

	if _, err := n.admitByRouters(ctx); err != nil {
		return err
	}

	// Initialize pubsub for control plane events. StrictSign is the
	// library default; it is pinned because the event validator and the
	// per-author rate limit key on msg.GetFrom(), which only the signature
	// makes trustworthy.
	// A member is a leaf of the gossip: it speaks floodsub, so a router
	// delivers every event to it outright and it takes no part in the
	// routers' gossipsub mesh, its heartbeats, grafts and peer exchange.
	ps, err := pubsub.NewFloodSub(ctx, gated, pubsub.WithMessageSignaturePolicy(pubsub.StrictSign))
	if err != nil {
		return err
	}
	n.PubSub = ps
	// Validate control-plane events before pubsub accepts or re-forwards
	// them: one ed25519 verify per message, so a peer flooding the topic with
	// junk costs itself the verify and never reaches the subscriber or the
	// next hop. Without this the rate limit ran first, keyed on the
	// forwarding peer, and a flood via the router exhausted the router's
	// budget so real ban and rotation events were dropped.
	if err := ps.RegisterTopicValidator(api.GossipEvents, n.validateMeshEvent); err != nil {
		return fmt.Errorf("register mesh event validator: %w", err)
	}

	// Subscribe to local address updates to reprovide services and log
	sub, err := h.EventBus().Subscribe(new(event.EvtLocalAddressesUpdated))
	if err == nil {
		go func() {
			defer sub.Close() //nolint:errcheck
			for {
				select {
				case <-ctx.Done():
					return
				case e, ok := <-sub.Out():
					if !ok {
						return
					}
					evt, ok := e.(event.EvtLocalAddressesUpdated)
					if !ok {
						logger.Warnf("[Network] Unexpected event type received: %T", e)
						continue
					}

					var addrs []multiaddr.Multiaddr
					for _, a := range evt.Current {
						addrs = append(addrs, a.Address)
					}
					logger.Infof("[Network] Local addresses updated: %v", addrs)

					// Debounce and trigger unified reprovide loop
					go func() {
						time.Sleep(2 * time.Second) // Small debounce
						n.triggerReprovide()
					}()
				}
			}
		}()
	}

	// Listen for Network Evictions/Revocations from the control plane
	go n.listenForControlPlaneEvents(ctx)

	// Layer 3: Open the Lobby Door (Auth Protocol is bypassed by Layer 4)
	n.Host.SetStreamHandler(api.AuthProtocolID, recoverStreamHandler("AuthHandshake", n.HandleAuthHandshake))
	n.Host.SetStreamHandler(api.GoAwayProtocolID, recoverStreamHandler("GoAway", func(s network.Stream) { n.HandleGoAway(ctx, s) }))

	// Layer 3: Wire up MCP handler wrapped in middleware
	n.Host.SetStreamHandler(api.MCPProtocolID, recoverStreamHandler("MCP", n.WithBiscuitAuth(n.HandleMCPStream)))

	// Start key pruning
	n.startKeyPruning(ctx, n.config.KeyGracePeriod)

	// Start Ingress HTTP Server
	if err := n.StartIngressServer(ctx); err != nil {
		return fmt.Errorf("failed to start ingress server: %w", err)
	}
	if err := n.StartExternalIngressServer(ctx); err != nil {
		return fmt.Errorf("failed to start external ingress server: %w", err)
	}

	// Start connection monitor
	n.startConnectionMonitor(ctx, n.config.MonitorBootstrap, n.config.MonitorInterval, 3)
	go p2plimits.ObserveStreamPressure(n.Host.Network().Conns, busiestConnStreams, logger.Warnf).Run(ctx, streamPressureInterval)

	// Periodically and on-demand reprovide registered services to the DHT
	n.startReprovideLoop(ctx)

	// Everything read from the control plane (keys, bans, router addresses,
	// policy) in one loop; gossip events only bring the next pull forward.
	n.startControlPlaneSyncLoop(ctx, n.config.ControlPlaneSyncInterval)

	// Periodically self-report local services to the control plane, so an
	// admin can see mesh-wide service topology.
	n.startCatalogReportLoop(ctx, n.config.CatalogReportInitialDelay, n.config.CatalogReportInterval)

	return nil
}

// triggerReprovide asks the reprovide loop to run a cycle now, dropping the
// request when one is already pending.
func (n *AgentMeshNode) triggerReprovide() {
	select {
	case n.reprovideTrigger <- struct{}{}:
	default:
	}
}

// announceAll is one announcement pass: the node's services, then the
// node itself under its peer key, so a lookup of the node through a router
// that does not hold it finds it at the addresses its records carry. The
// peer record goes last so that, once it names an address, every service
// record of the pass does too. It returns how many services were withheld
// because their backend did not answer.
func (n *AgentMeshNode) announceAll(ctx context.Context) int {
	withheld := n.services.ReprovideAll(ctx)
	provideCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := n.Directory.Provide(provideCtx, api.PeerKey(n.Host.ID()), ""); err != nil && ctx.Err() == nil && !errors.Is(err, errNoDirectoryRouter) {
		// With no router attached the directory client has said so already.
		logger.Warnf("[Directory] Announcing where this node is reached: %v", err)
	}
	return withheld
}

// startReprovideLoop re-announces the node's services and its own record
// every reprovide interval of the mesh, read at each cycle so a control
// plane that changed it is followed at the next one.
func (n *AgentMeshNode) startReprovideLoop(ctx context.Context) {
	go func() {
		initialDelay := 5 * time.Second
		if n.config.DiscoveryInterval != "" {
			if d, err := time.ParseDuration(n.config.DiscoveryInterval); err == nil && d > 0 && d < initialDelay {
				initialDelay = d
			}
		}
		// Initial delay lets DHT bootstrap stabilize.
		timer := time.NewTimer(initialDelay)
		defer timer.Stop()

		retry := reprovideRetryInterval
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case <-n.reprovideTrigger:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}

			interval := n.directorySettings().Reprovide
			next := interval
			if n.announceAll(ctx) > 0 {
				// A backend that is not answering yet is usually one that is
				// still starting. Waiting the full interval would leave it
				// undiscoverable for minutes after it came up.
				next = retry
				retry = min(retry*2, interval)
			} else {
				retry = reprovideRetryInterval
			}
			timer.Reset(next)
		}
	}()
}

// directorySettings is how the mesh keeps its DHT, as last read from the
// control plane.
func (n *AgentMeshNode) directorySettings() api.DirectorySettings {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.directory
}

// adoptDirectory takes the directory parameters /info published. The
// reprovide interval applies from the next cycle; the record TTL is set
// when the DHT is built, so a change to it applies at the next start.
func (n *AgentMeshNode) adoptDirectory(p *api.DirectoryParameters) {
	settings := api.DirectorySettingsFrom(p)
	n.mu.Lock()
	changed := settings != n.directory
	n.directory = settings
	n.mu.Unlock()
	if changed {
		logger.Infof("[DHT] Directory parameters from the control plane: replication %d, reprovide every %s, records kept %s", settings.Replication, settings.Reprovide, settings.RecordTTL)
	}
}

func (n *AgentMeshNode) IsConnected() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.authenticatedRouters) == 0 {
		return false
	}
	for pid := range n.authenticatedRouters {
		if n.Host.Network().Connectedness(pid) == network.Connected {
			return true
		}
	}
	return false
}

// isAuthenticatedAndConnected reports whether this router was authenticated
// on a session that is still open. The router forgets a peer once its last
// connection drops, so a stale entry must not skip the handshake.
func (n *AgentMeshNode) isAuthenticatedAndConnected(router peer.ID) bool {
	n.mu.Lock()
	authed := n.authenticatedRouters[router]
	n.mu.Unlock()
	return authed && n.Host.Network().Connectedness(router) == network.Connected
}

// authenticatedRouterIDs lists the routers this node passed the handshake
// with and is still connected to: the relays that will open a circuit for it.
func (n *AgentMeshNode) authenticatedRouterIDs() []peer.ID {
	n.mu.Lock()
	defer n.mu.Unlock()
	ids := make([]peer.ID, 0, len(n.authenticatedRouters))
	for pid := range n.authenticatedRouters {
		if n.Host.Network().Connectedness(pid) == network.Connected {
			ids = append(ids, pid)
		}
	}
	return ids
}

func (n *AgentMeshNode) LoadMeshConfig() ([]byte, []string, error) {
	return n.Store.LoadMeshConfig()
}

func (n *AgentMeshNode) LoadControlPlaneURL() (string, error) {
	return n.Store.LoadControlPlaneURL()
}

func (n *AgentMeshNode) SaveMeshConfig(pubKey []byte, addrs []string) error {
	return n.Store.SaveMeshConfig(pubKey, addrs)
}

func (n *AgentMeshNode) startConnectionMonitor(ctx context.Context, bootstrapDuration, checkInterval time.Duration, maxFailures int) {
	go func() {
		// Wait for initial bootstrap to complete
		select {
		case <-ctx.Done():
			return
		case <-time.After(bootstrapDuration):
		}

		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		consecutiveFailures := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stable, reconnected := checkRouterConnection(ctx, n)

				if stable {
					if consecutiveFailures > 0 {
						logger.Infof("[Monitor] Connection to router is stable. Resetting failure count.")
						consecutiveFailures = 0
					}
					continue
				}

				if reconnected {
					logger.Infof("[Monitor] Reconnected successfully. Announcing services again...")
					n.announceAll(ctx)
					consecutiveFailures = 0
					continue
				}

				consecutiveFailures++
				logger.Errorf("[Monitor] Failed to reconnect to a router. Consecutive failures: %d/%d", consecutiveFailures, maxFailures)
				if consecutiveFailures >= maxFailures {
					logger.Fatalf("[Monitor] Failed to reconnect to a router for %d consecutive checks. Exiting to avoid network partition.", maxFailures)
				}
			}
		}
	}()
}

func (n *AgentMeshNode) RegisterStaticServices(ctx context.Context, services []api.ServiceConfig) error {
	// A router has to hold the node before a service can be announced, so
	// a registration right after enrollment waits for the first one.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(10 * time.Second)

attached:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for a router before registering static services")
		case <-ticker.C:
			if n.IsConnected() {
				break attached
			}
		}
	}

	var errs []error
	for _, sCfg := range services {
		req, err := buildRegisterRequest(sCfg)
		if err != nil {
			logger.Errorf("[ServiceRegistry] %v", err)
			errs = append(errs, err)
			continue
		}
		if err := n.RegisterService(ctx, req); err != nil {
			logger.Errorf("[ServiceRegistry] Failed to register static service %s: %v", sCfg.Name, err)
			errs = append(errs, fmt.Errorf("failed to register static service %s: %w", sCfg.Name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to register static services: %w", errors.Join(errs...))
	}
	logger.Infof("[ServiceRegistry] Successfully registered %d static services", len(services))
	return nil
}

// admitByRouters attaches the node to the routers it keeps and returns as
// soon as one has admitted it, retrying with RouterRedialDelay doubling
// between attempts, up to RouterAuthAttempts of them. Each attempt chooses
// afresh from the catalog, re-read from the control plane when it can be,
// so a router that is up but slow, as every router is while a fleet joins
// through it, admits the node on the next attempt, and a router that
// restarts with the labels a selector names is found when it is back. A
// router that refuses the credential ends it at once, and no router at all
// is reported as before. authenticated is false with a nil error only when
// the node knows of no router to admit it.
func (n *AgentMeshNode) admitByRouters(ctx context.Context) (authenticated bool, err error) {
	if len(n.routerCandidates()) == 0 {
		return false, nil
	}
	biscuitBytes, err := n.loadIdentityForAuth()
	if err != nil {
		return false, fmt.Errorf("fatal auth failure: %w", err)
	}
	delay := n.config.RouterRedialDelay
	for attempt := 1; ; attempt++ {
		if attempt > 1 {
			if refreshErr := n.refreshRouterCatalog(ctx); refreshErr != nil {
				logger.Debugf("[AuthN] Routers not re-read from the control plane: %v", refreshErr)
			}
		}
		targets := n.pickRouters(n.wantRouters())
		var fatal error
		if len(targets) > 0 {
			results := n.dialAndAttach(ctx, targets, biscuitBytes)
			for range targets {
				err := <-results
				if err == nil {
					return true, nil
				}
				if errors.Is(err, ErrFatalAuth) {
					fatal = err
				}
			}
		}
		if fatal != nil {
			return false, fmt.Errorf("fatal auth failure: %w", fatal)
		}
		if attempt >= n.config.RouterAuthAttempts || delay <= 0 {
			return false, errors.New("failed to authenticate with any router: all connection attempts failed")
		}
		logger.Warnf("[AuthN] No router admitted this node on attempt %d of %d; retrying in %s", attempt, n.config.RouterAuthAttempts, delay)
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// dialRouters runs authRouter against every router at once and delivers one
// outcome per router on the returned channel, in completion order. The
// channel is buffered for all of them, so a caller may stop reading early.
func (n *AgentMeshNode) dialRouters(ctx context.Context, routers []peer.AddrInfo, biscuitBytes []byte) <-chan error {
	results := make(chan error, len(routers))
	for _, router := range routers {
		go func() {
			err := n.authRouter(ctx, router, biscuitBytes)
			if err != nil {
				logger.Warnf("[AuthN] Failed to bootstrap and auth with router %s: %v", router.ID, err)
			}
			results <- err
		}()
	}
	return results
}

// redialRouter re-handshakes a router whose session just dropped, in the
// background, with a doubling delay between attempts. The connection monitor
// only acts once no router is left and only on its own interval, so without
// this a rollout that restarts the routers one after another, each faster
// than that interval, takes every session a member has before any is back;
// and a router that restarts alone is never re-handshaken at all, the
// member keeping one router fewer after each rollout. One redial per router
// runs at a time, and a router that stays away is left to the monitor.
func (n *AgentMeshNode) redialRouter(ctx context.Context, router peer.ID) {
	if n.config.RouterRedialDelay < 0 {
		return
	}
	n.mu.Lock()
	if n.redialing == nil {
		n.redialing = map[peer.ID]bool{}
	}
	if n.redialing[router] {
		n.mu.Unlock()
		logger.Debugf("[AuthN] Router %s dropped while a redial of it is running; that redial checks the session before it ends", router)
		return
	}
	n.redialing[router] = true
	n.mu.Unlock()

	go func() {
		if n.redialUntilUp(ctx, router) {
			return
		}
		n.mu.Lock()
		delete(n.redialing, router)
		n.mu.Unlock()
	}()
}

// redialUntilUp runs the redial attempts of redialRouter and reports whether
// it released the redial's in-flight mark. It releases it only on a live
// session, through releaseRedialIfUp; on every other exit the mark is left
// to the caller.
func (n *AgentMeshNode) redialUntilUp(ctx context.Context, router peer.ID) bool {
	biscuitBytes, err := n.loadIdentityForAuth()
	if err != nil {
		logger.Errorf("[AuthN] Cannot redial router %s without an identity: %v", router, err)
		return false
	}
	delay := n.config.RouterRedialDelay
	for attempt := 1; attempt <= n.config.RouterRedialAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(delay):
		}
		if n.releaseRedialIfUp(router) {
			logger.Debugf("[AuthN] Router %s session was restored while its redial waited", router)
			return true
		}
		if !n.isAttached(router) {
			return false
		}
		addrs := n.Host.Peerstore().Addrs(router)
		if len(addrs) == 0 {
			logger.Warnf("[AuthN] Router %s dropped and no address for it is known; replacing it", router)
			n.detach(router)
			return false
		}
		err := n.authRouter(ctx, peer.AddrInfo{ID: router, Addrs: addrs}, biscuitBytes)
		if err == nil {
			if n.releaseRedialIfUp(router) {
				logger.Infof("[AuthN] Router %s re-admitted this node on redial %d", router, attempt)
				// A router that restarted lost this node's records.
				n.triggerReprovide()
				return true
			}
			// A drop since the handshake found this redial's mark and left
			// the session to it, or came before the session was recorded.
			logger.Warnf("[AuthN] Router %s admitted this node on redial %d and dropped it again", router, attempt)
		} else {
			if errors.Is(err, ErrFatalAuth) {
				logger.Warnf("[AuthN] Router %s refused this node's credential on redial: %v", router, err)
				n.detach(router)
				n.shun(router, n.config.RouterShunDuration)
				return false
			}
			logger.Debugf("[AuthN] Redial %d of router %s failed: %v", attempt, router, err)
		}
		delay *= 2
	}
	// Given up: the monitor tops up from the other routers, and this one
	// is a candidate again once it is back on /info and the shun lapses.
	logger.Warnf("[AuthN] Router %s did not keep a session with this node within %d redials; replacing it", router, n.config.RouterRedialAttempts)
	n.detach(router)
	n.shun(router, n.config.RouterShunDuration)
	return false
}

// releaseRedialIfUp ends a redial of router on a live session: it clears the
// redial's in-flight mark only while the session is up, and reports whether
// it did. It holds n.mu, as the disconnect handler does to clear the
// session, so a drop either came first and is seen here, and the redial goes
// on, or comes after, finds no mark and starts a redial of its own. The
// connection is checked as well as the session flag, since a drop that
// lands before the handshake records the session clears nothing.
func (n *AgentMeshNode) releaseRedialIfUp(router peer.ID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.authenticatedRouters[router] || n.Host.Network().Connectedness(router) != network.Connected {
		return false
	}
	delete(n.redialing, router)
	return true
}

func (n *AgentMeshNode) loadIdentityForAuth() ([]byte, error) {
	if n.Store == nil {
		return nil, fmt.Errorf("%w: no identity store", ErrFatalAuth)
	}
	biscuitBytes, err := n.Store.LoadIdentity()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to load identity from store: %w", ErrFatalAuth, err)
	}
	if len(biscuitBytes) == 0 {
		return nil, fmt.Errorf("%w: no identity biscuit found in store", ErrFatalAuth)
	}
	return biscuitBytes, nil
}

// authRouter connects to one router over whichever of its addresses answers
// and runs the handshake, unless a live authenticated session to it already
// exists: Host.Connect is a no-op on an existing connection, but the
// handshake is not, and repeating it trips the router's per-peer handshake
// limiter. For the same reason two callers reaching for the same router at
// once, as the attach path and the directory path do when its connection
// comes up, run one handshake: the second waits for the first. The dial is
// bounded by RouterConnectTimeout so a router that is down does not hold
// its caller for long.
func (n *AgentMeshNode) authRouter(ctx context.Context, router peer.AddrInfo, biscuitBytes []byte) error {
	if n.isAuthenticatedAndConnected(router.ID) {
		return nil
	}
	n.mu.Lock()
	if done, inFlight := n.handshaking[router.ID]; inFlight {
		n.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		if n.isAuthenticatedAndConnected(router.ID) {
			return nil
		}
		return fmt.Errorf("router %s: the handshake in flight did not admit this node", router.ID)
	}
	if n.handshaking == nil {
		n.handshaking = map[peer.ID]chan struct{}{}
	}
	done := make(chan struct{})
	n.handshaking[router.ID] = done
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.handshaking, router.ID)
		n.mu.Unlock()
		close(done)
	}()

	routerCtx, cancel := context.WithTimeout(ctx, n.config.RouterConnectTimeout)
	defer cancel()
	if err := n.Host.Connect(routerCtx, router); err != nil {
		if strings.Contains(err.Error(), "peer id mismatch") {
			return fmt.Errorf("%w: %w", ErrFatalAuth, err)
		}
		return fmt.Errorf("failed to connect to router %s at %v: %w", router.ID, router.Addrs, err)
	}
	if err := n.authenticateRouterSession(routerCtx, router.ID, biscuitBytes); err != nil {
		return fmt.Errorf("router %s: %w", router.ID, err)
	}
	n.authOnce.Do(func() {
		close(n.authSuccess)
	})
	return nil
}

// ConnectAndAuthWithRouter connects to and authenticates with every router
// behind addr: one peer for a direct address, every router behind the name
// for a dnsaddr. They are dialed at once and all are waited for; it succeeds
// when at least one admitted this node.
func (n *AgentMeshNode) ConnectAndAuthWithRouter(ctx context.Context, addr multiaddr.Multiaddr) error {
	biscuitBytes, err := n.loadIdentityForAuth()
	if err != nil {
		return err
	}

	routers := routerPeers(ctx, []multiaddr.Multiaddr{addr})
	if len(routers) == 0 {
		return fmt.Errorf("no router peer behind %s", addr)
	}
	var connected bool
	var lastFatalErr error
	var errs []error
	results := n.dialRouters(ctx, routers, biscuitBytes)
	for range routers {
		err := <-results
		if err == nil {
			connected = true
			continue
		}
		errs = append(errs, err)
		if errors.Is(err, ErrFatalAuth) {
			lastFatalErr = err
		}
	}

	if connected {
		return nil
	}
	if lastFatalErr != nil {
		return lastFatalErr
	}
	return fmt.Errorf("failed to authenticate with any router addresses: %w", errors.Join(errs...))
}

// authenticateRouterSession runs the auth handshake with a router this host
// is connected to and records the session.
func (n *AgentMeshNode) authenticateRouterSession(ctx context.Context, router peer.ID, biscuitBytes []byte) error {
	s, err := n.Host.NewStream(ctx, router, api.AuthProtocolID)
	if err != nil {
		return fmt.Errorf("failed to open auth stream: %w", err)
	}
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := n.performRouterAuthHandshake(s, biscuitBytes, router); err != nil {
		_ = s.Reset()
		return fmt.Errorf("handshake failed: %w", err)
	}
	_ = s.Close()

	// A router that closes the connection right after admitting the node can
	// do so before the session is recorded, and the disconnect handler then
	// finds none to clear. Recorded anyway, it would outlive the connection,
	// and the next connection to the router, which AutoRelay opens within
	// milliseconds, would make it look live although the router never
	// authenticated it. The swarm closes a connection before it notifies
	// the handler, and the handler takes n.mu, so a close either came first
	// and is seen here or comes after and clears what is recorded now.
	n.mu.Lock()
	if s.Conn().IsClosed() {
		n.mu.Unlock()
		return fmt.Errorf("router %s closed the connection as it admitted this node", router)
	}
	n.authenticatedRouters[router] = true
	n.RouterPeerID = router
	n.mu.Unlock()
	logger.Infof("[AuthN] Successfully authenticated with router via libp2p: %s", router)
	return nil
}

// readmitRetryDelays spaces the retries of a re-admission a router refused.
// A credential refreshed right after a key rotation is signed by a key the
// router may not have synced yet; it has within a few seconds, so the node
// asks again instead of waiting a monitor interval with no router.
var readmitRetryDelays = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}

// readmitRouters presents the current credential to every router this node
// holds an authenticated session with. A router admits a peer until the
// biscuit it was shown expires, whatever the connection does, so a refreshed
// credential must be shown on the live session or relay circuits to this
// node are refused once the old one lapses. A router that still refuses
// after the retries is dropped from the authenticated set; the connection
// monitor then dials and handshakes afresh.
func (n *AgentMeshNode) readmitRouters(ctx context.Context) {
	if n.Host == nil {
		return
	}
	biscuitBytes := n.GetIdentity()
	if len(biscuitBytes) == 0 {
		return
	}
	for _, router := range n.authenticatedRouterIDs() {
		n.readmitRouter(ctx, router, biscuitBytes)
	}
}

func (n *AgentMeshNode) readmitRouter(ctx context.Context, router peer.ID, biscuitBytes []byte) {
	var err error
	for attempt := 0; ; attempt++ {
		routerCtx, cancel := context.WithTimeout(ctx, n.config.RouterConnectTimeout)
		err = n.authenticateRouterSession(routerCtx, router, biscuitBytes)
		cancel()
		if err == nil {
			if attempt > 0 {
				logger.Infow("[AuthN] Router accepted the refreshed credential on retry", "router", router, "attempt", attempt+1)
			}
			return
		}
		if attempt >= len(readmitRetryDelays) {
			break
		}
		logger.Warnw("[AuthN] Router did not accept the refreshed credential; retrying", "router", router, "attempt", attempt+1, "retry_in", readmitRetryDelays[attempt], "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(readmitRetryDelays[attempt]):
		}
	}
	logger.Warnw("[AuthN] Router did not accept the refreshed credential; the connection monitor will re-handshake", "router", router, "attempts", len(readmitRetryDelays)+1, "error", err)
	n.mu.Lock()
	delete(n.authenticatedRouters, router)
	n.mu.Unlock()
}

func (n *AgentMeshNode) performRouterAuthHandshake(s network.Stream, biscuitBytes []byte, expectedRouter peer.ID) (bool, error) {
	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: biscuitBytes}
	data, err := proto.Marshal(authFrame)
	if err != nil {
		return false, fmt.Errorf("marshal auth frame: %w", err)
	}
	if err := writer.WriteMsg(data); err != nil {
		return false, fmt.Errorf("write auth frame: %w", err)
	}

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		return false, fmt.Errorf("read auth response: %w", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		return false, fmt.Errorf("unmarshal auth response: %w", err)
	}

	if !resp.Success {
		return false, fmt.Errorf("%w: auth failed: %s", ErrFatalAuth, resp.Error)
	}

	// Mutual Auth: Verify server/router biscuit
	if len(resp.Biscuit) == 0 {
		return false, fmt.Errorf("%w: remote router returned empty biscuit", ErrFatalAuth)
	}

	trustedKeys := n.getTrustedPublicKeys()

	if len(trustedKeys) == 0 {
		return false, fmt.Errorf("%w: no trusted control plane keys loaded", ErrFatalAuth)
	}

	// Verify the router's biscuit using the control plane keys
	b, verifyingKey, err := identity.VerifyBiscuitAndGetKey(resp.Biscuit, expectedRouter, trustedKeys, n.BiscuitTimeout)
	if err != nil {
		return false, fmt.Errorf("%w: failed to verify router biscuit: %w", ErrFatalAuth, err)
	}

	// Enforce role("router") inside the biscuit, under the key that verified:
	// with several valid keys loaded (rotation grace) the first is not
	// necessarily the signer.
	if err := identity.RequireRole(b, verifyingKey, api.RoleRouter, n.BiscuitTimeout); err != nil {
		return false, fmt.Errorf("%w: remote peer lacks router authorization role: %w", ErrFatalAuth, err)
	}

	return true, nil
}

func (n *AgentMeshNode) StartRenewalLoop(ctx context.Context, issuerURL, clientID, clientSecret, jwtPath string) {
	src, continuous, err := ResolveTokenSource(ctx, TokenSourceConfig{
		Node:         n,
		IssuerURL:    issuerURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		JWTPath:      jwtPath,
	})
	if err != nil {
		logger.Warnf("Failed to resolve token source: %v", err)
		src = NewRefreshTokenSource(n, clientSecret)
	}
	if continuous && n.getTokenSource() == nil {
		n.SetTokenSource(src)
	}
	n.StartRenewalLoopWithSource(ctx, src)
}

func (n *AgentMeshNode) StartRenewalLoopWithSource(ctx context.Context, src TokenSource) {
	if src == nil {
		src = n.getTokenSource()
	}
	go func() {
		for {
			var renewAfter = DefaultRenewalFallback // Default fallback

			exp, err := n.Store.LoadIdentityExpiration()
			if err == nil && exp > 0 {
				expTime := time.Unix(exp, 0)
				duration := time.Until(expTime)
				if duration > RenewalThreshold {
					renewAfter = duration - RenewalBuffer
				} else if duration > 0 {
					renewAfter = duration / 2
					if renewAfter < 2*time.Second {
						renewAfter = 2 * time.Second
					}
				} else {
					renewAfter = 1 * time.Second
				}
			}

			fmt.Printf("[Auth] Next renewal in %v\n", renewAfter)
			timer := time.NewTimer(renewAfter)

			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				fmt.Println("Renewing enrollment...")

				// Try proactive biscuit token refresh first
				refreshErr := n.RefreshEnrollment(ctx)
				if refreshErr == nil {
					logger.Infof("Enrollment renewed successfully via proactive refresh.")
					continue
				}

				logger.Warnw("Proactive biscuit refresh failed, falling back to full OIDC/JWT re-enrollment", "error", refreshErr)

				var newJWT string
				var fetchErr error
				if src == nil {
					fetchErr = errors.New("no token source configured for renewal")
				} else {
					newJWT, fetchErr = src.FetchToken(ctx)
				}

				if fetchErr == nil {
					controlPlaneURL, loadErr := n.Store.LoadControlPlaneURL()
					if loadErr != nil {
						fetchErr = fmt.Errorf("failed to load control plane URL for renewal: %w", loadErr)
					} else {
						fetchErr = n.Enroll(ctx, controlPlaneURL, newJWT)
					}
				}

				if fetchErr != nil {
					logger.Errorf("Renewal failed: %v", fetchErr)

					// Check if we are already expired and if so, die to avoid a split brain
					exp, loadErr := n.Store.LoadIdentityExpiration()
					if loadErr == nil && exp > 0 {
						if time.Now().After(time.Unix(exp, 0)) {
							logger.Fatalf("Identity expired and renewal failed. Exiting to avoid network partition.")
						}
					}
				} else {
					logger.Infof("Enrollment renewed successfully.")
				}
			}
		}
	}()
}

type RefreshError struct {
	StatusCode int
	Message    string
}

func (e *RefreshError) Error() string {
	return e.Message
}

// RefreshEnrollment trades the expiring biscuit token for a new one using a cryptographic challenge.
func (n *AgentMeshNode) RefreshEnrollment(ctx context.Context) error {
	n.refreshMu.Lock()
	defer n.refreshMu.Unlock()

	// 1. Fetch current biscuit
	currentBiscuit, err := n.Store.LoadIdentity()
	if err != nil {
		return fmt.Errorf("failed to load current identity: %w", err)
	}

	// 2. Load private key
	privKeyBytes, err := n.Store.LoadKey()
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}
	privKey, err := crypto.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("corrupted private key: %w", err)
	}

	// 3. Derive peer ID from private key
	peerID, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to derive peer ID from private key: %w", err)
	}

	// 4. Construct request. peer_id lets the control plane find this node's
	// record when the biscuit's signing key has been retired and the biscuit
	// itself can no longer be verified (autonomous recovery, opt-in
	// server-side); it is cross-checked against the biscuit otherwise.
	var freshJWT string
	if ts := n.getTokenSource(); ts != nil {
		if tok, fetchErr := ts.FetchToken(ctx); fetchErr != nil {
			logger.Warnw("Failed to fetch fresh platform JWT for refresh attestation; attempting session-backed refresh", "error", fetchErr)
		} else {
			freshJWT = tok
		}
	}

	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil {
		return fmt.Errorf("failed to load control plane URL: %w", err)
	}

	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		return fmt.Errorf("control plane address must be an HTTP or HTTPS URL for renewal: %s", controlPlaneURL)
	}

	url := controlPlaneURL + "/refresh"
	b64Biscuit := base64.StdEncoding.EncodeToString(currentBiscuit)
	client := controlPlaneHTTPClient(30 * time.Second)
	resp, err := cpclient.DoWithChallenge(client, time.Now, func(timestamp int64) (*http.Request, error) {
		sig, err := privKey.Sign(api.RefreshChallenge(peerID.String(), timestamp))
		if err != nil {
			return nil, fmt.Errorf("failed to generate signature: %w", err)
		}
		req := &api.TokenRefreshRequest{
			ChallengeSignature: sig,
			ChallengeUnixMs:    timestamp,
			PeerId:             peerID.String(),
			Jwt:                freshJWT,
		}
		reqData, err := proto.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqData))
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		httpReq.Header.Set("Authorization", "Bearer "+b64Biscuit)
		return httpReq, nil
	})
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		// Not fatal on its own: a 403 is a claim by whoever answered, and
		// only a verified MeshEvent_BANNED is the control plane's word. The
		// node keeps serving on its current biscuit until that expires.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxControlPlaneBodyBytes))
		return &RefreshError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("refresh refused (403 Forbidden): %s", string(body)),
		}
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxControlPlaneBodyBytes))
		return &RefreshError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("refresh failed with status %s: %s", resp.Status, string(body)),
		}
	}

	respData, err := cpclient.ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("refresh response: %w", err)
	}

	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(respData, &refreshResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if refreshResp.ErrorMessage != "" {
		return fmt.Errorf("refresh error: %s", refreshResp.ErrorMessage)
	}

	// Same checks as enrollment: the token must be signed by a key this node
	// already trusts and carry the role it runs as, or a response from the
	// wrong party would replace a good identity with a useless one.
	if err := n.verifyOwnBiscuit(refreshResp.BiscuitToken); err != nil {
		return fmt.Errorf("refreshed biscuit rejected: %w", err)
	}

	// Save new biscuit and its expiration
	if err := n.Store.SaveIdentity(refreshResp.BiscuitToken); err != nil {
		return fmt.Errorf("failed to save refreshed identity: %w", err)
	}
	n.SetIdentityCache(refreshResp.BiscuitToken)
	if err := n.Store.SaveIdentityExpiration(expireUnix(refreshResp.ExpireTime)); err != nil {
		return fmt.Errorf("failed to save refreshed expiration: %w", err)
	}
	n.recordIdentityKeySet()
	n.readmitRouters(ctx)

	return nil
}

// verifyOwnBiscuit checks a token the control plane handed this node: signed
// by a trusted key, bound to this peer, and carrying the configured role.
func (n *AgentMeshNode) verifyOwnBiscuit(token []byte) error {
	if len(token) == 0 {
		return errors.New("empty biscuit token")
	}
	n.keysMu.RLock()
	trusted := publicKeysOf(n.trustedKeys)
	n.keysMu.RUnlock()
	if len(trusted) == 0 {
		return errors.New("no trusted control plane keys loaded")
	}
	var peerID peer.ID
	if n.Host != nil {
		peerID = n.Host.ID()
	} else {
		privBytes, err := n.Store.LoadKey()
		if err != nil {
			return fmt.Errorf("load node key: %w", err)
		}
		priv, err := crypto.UnmarshalPrivateKey(privBytes)
		if err != nil {
			return fmt.Errorf("corrupted node key: %w", err)
		}
		if peerID, err = peer.IDFromPrivateKey(priv); err != nil {
			return err
		}
	}
	_, key, err := identity.VerifyBiscuitAndGetKey(token, peerID, trusted, n.BiscuitTimeout)
	if err != nil {
		return err
	}
	if n.config.RequiredRole == "" {
		return nil
	}
	return identity.VerifyBiscuitRole(token, key, n.config.RequiredRole, n.BiscuitTimeout)
}

func (n *AgentMeshNode) renewWithRefreshToken(ctx context.Context, clientSecret string) (string, error) {
	if n.Store == nil {
		return "", fmt.Errorf("store is not initialized")
	}

	refreshToken, err := n.Store.LoadRefreshToken()
	if err != nil {
		return "", fmt.Errorf("no refresh token available for renewal: %w", err)
	}

	storedIssuer, storedClientID, _, err := n.Store.LoadOIDCConfig()
	if err != nil {
		return "", fmt.Errorf("failed to load OIDC configuration: %w", err)
	}
	if storedIssuer == "" || storedClientID == "" {
		return "", fmt.Errorf("OIDC configuration is incomplete (issuer or client ID is empty)")
	}

	tokenURL, err := n.DiscoverTokenURL(ctx, storedIssuer)
	if err != nil {
		return "", fmt.Errorf("failed to discover OIDC endpoints for renewal: %w", err)
	}

	newJWT, newRefreshToken, err := n.RefreshJWT(ctx, tokenURL, storedClientID, clientSecret, refreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to refresh JWT: %w", err)
	}

	if newRefreshToken != "" {
		if err := n.Store.SaveRefreshToken(newRefreshToken); err != nil {
			logger.Warnf("Failed to save updated refresh token: %v", err)
		}
	}

	return newJWT, nil
}

const (
	meshEventRateLimitDrop   = "rate_limit_drop"
	meshEventSpoofingAttempt = "spoofing_attempt"
	meshEventStaleEvent      = "stale_event"
	meshEventPolicyUpdate    = "policy_update"
	meshEventBanned          = "banned"
	meshEventKeyRotation     = "key_rotation"
)

// listenForControlPlaneEvents listens to the topic established by the control plane
func (n *AgentMeshNode) listenForControlPlaneEvents(ctx context.Context) {
	topic, err := n.PubSub.Join(api.GossipEvents)
	if err != nil {
		return
	}
	defer func() { _ = topic.Close() }()

	sub, err := topic.Subscribe()
	if err != nil {
		return
	}
	defer sub.Cancel()

	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return
		}

		// validateMeshEvent already rejected anything unsigned, misspelled or
		// stale; what arrives here is a genuine control-plane event. The limit
		// is on the author, so a burst from one control plane cannot be
		// blamed on the router that relayed it.
		if !n.rateLimiter.Allow(msg.GetFrom().String()) {
			logger.Warnw("[Mesh Event] rate limit exceeded, dropping message", "event", meshEventRateLimitDrop, "peer", msg.GetFrom().String())
			continue
		}

		var event api.MeshEvent
		if err := proto.Unmarshal(msg.Data, &event); err != nil {
			logger.Errorf("[Mesh Event] Failed to unmarshal event from %s: %v", msg.ReceivedFrom, err)
			continue
		}

		switch event.Type {
		case api.MeshEvent_BANNED:
			n.handleBannedEvent(&event)
		case api.MeshEvent_KEY_ROTATION:
			n.handleKeyRotationEvent(&event)
		case api.MeshEvent_POLICY_UPDATE:
			logger.Infow("[Mesh Event] policy update received, triggering sync", "event", meshEventPolicyUpdate, "peer", msg.ReceivedFrom.String())
			n.triggerControlPlaneSync()
		}
	}
}

func (n *AgentMeshNode) handleBannedEvent(event *api.MeshEvent) {
	p, err := peer.Decode(event.PeerId)
	if err != nil {
		logger.Warnf("[Mesh Event] Ignoring BANNED event with undecodable peer ID %q: %v", event.PeerId, err)
		return
	}
	canonicalID := p.String()

	eventMs := event.GetEventTime().AsTime().UnixMilli()
	n.mu.Lock()
	if n.peerLastEventTime == nil {
		n.peerLastEventTime = make(map[string]int64)
	}
	if eventMs < n.peerLastEventTime[canonicalID] {
		logger.Warnf("[Mesh Event] Dropping out-of-order BANNED event for peer %s (event time: %d, last processed: %d)", canonicalID, eventMs, n.peerLastEventTime[canonicalID])
		n.mu.Unlock()
		return
	}
	n.peerLastEventTime[canonicalID] = eventMs
	n.mu.Unlock()

	logger.Infow("[Mesh Event] peer banned", "event", meshEventBanned, "peer", canonicalID)
	// Not written to disk: a restarted node picks the ban back up from the
	// control plane's ban set in /info, which is also how an unban reaches it.
	n.banPeer(p, eventMs)
}

func containsTrustedKey(keys []TrustedKey, key ed25519.PublicKey) bool {
	for _, tk := range keys {
		if bytes.Equal(tk.Key, key) {
			return true
		}
	}
	return false
}

// addTrustedKey appends a control plane public key to the trust set (no-op
// on duplicates) and persists the updated set so it survives restarts.
func (n *AgentMeshNode) addTrustedKey(key ed25519.PublicKey) {
	n.keysMu.Lock()
	if containsTrustedKey(n.trustedKeys, key) {
		n.keysMu.Unlock()
		return
	}
	n.trustedKeys = append(n.trustedKeys, TrustedKey{Key: key, ReceivedAt: time.Now()})
	snapshot := append([]TrustedKey(nil), n.trustedKeys...)
	n.keysMu.Unlock()
	n.persistTrustedKeys(snapshot)
}

func (n *AgentMeshNode) persistTrustedKeys(keys []TrustedKey) {
	if n.Store == nil {
		return
	}
	if err := n.Store.SaveTrustedKeys(keys); err != nil {
		logger.Errorf("Failed to persist trusted keys: %v", err)
	}
}

func (n *AgentMeshNode) handleKeyRotationEvent(event *api.MeshEvent) {
	if len(event.NewPublicKey) != ed25519.PublicKeySize {
		logger.Errorf("[Mesh Event] Key rotation failed: invalid public key size %d, expected %d", len(event.NewPublicKey), ed25519.PublicKeySize)
		return
	}
	logger.Infow("[Mesh Event] key rotation received", "event", meshEventKeyRotation, "key", fmt.Sprintf("%x", event.NewPublicKey))
	n.addTrustedKey(ed25519.PublicKey(event.NewPublicKey))
	n.triggerControlPlaneSync()
}

// pruneTrustedKeys drops keys older than gracePeriod but always keeps the
// most recently received one: the current signing key has no successor until
// a rotation event arrives, so ageing it out would empty the trust set and
// leave the node unable to verify any peer or router.
func pruneTrustedKeys(keys []TrustedKey, now time.Time, gracePeriod time.Duration) []TrustedKey {
	if len(keys) == 0 {
		return keys
	}
	newest := 0
	for i, tk := range keys {
		if tk.ReceivedAt.After(keys[newest].ReceivedAt) {
			newest = i
		}
	}
	var active []TrustedKey
	for i, tk := range keys {
		if i == newest || now.Sub(tk.ReceivedAt) <= gracePeriod {
			active = append(active, tk)
		}
	}
	return active
}

func (n *AgentMeshNode) startKeyPruning(ctx context.Context, gracePeriod time.Duration) {
	if gracePeriod <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(KeyPruningInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				logger.Info("[KeyPruning] Pruning expired keys...")
				n.keysMu.Lock()
				pruned := pruneTrustedKeys(n.trustedKeys, time.Now(), gracePeriod)
				changed := len(pruned) != len(n.trustedKeys)
				n.trustedKeys = pruned
				snapshot := append([]TrustedKey(nil), pruned...)
				n.keysMu.Unlock()
				if changed {
					n.persistTrustedKeys(snapshot)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (n *AgentMeshNode) verifyEvent(event *api.MeshEvent) bool {
	sig := event.Signature
	event.Signature = nil
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	event.Signature = sig // Restore
	if err != nil {
		logger.Errorf("[Mesh Event] Failed to marshal event for verification: %v", err)
		return false
	}

	n.keysMu.RLock()
	keys := n.trustedKeys
	n.keysMu.RUnlock()

	for _, tk := range keys {
		if len(tk.Key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(tk.Key, data, sig) {
			return true
		}
	}
	return false
}

// validateMeshEvent is the GossipSub validator for api.GossipEvents. Reject
// means the message is dropped and not re-forwarded; the signature is checked
// against the trusted control-plane keys, so any peer whose libp2p key
// signed the pubsub envelope still cannot get an unsigned event past here. A
// stale event is ignored rather than rejected: it may be a genuine event
// that arrived late, and there is no reason to penalize its forwarder.
func (n *AgentMeshNode) validateMeshEvent(_ context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	var event api.MeshEvent
	if err := proto.Unmarshal(msg.Data, &event); err != nil {
		logger.Warnw("[Mesh Event] rejecting undecodable event", "event", meshEventSpoofingAttempt, "peer", from.String())
		return pubsub.ValidationReject
	}
	if !n.verifyEvent(&event) {
		logger.Warnw("[Mesh Event] potential spoofing attempt: invalid event signature", "event", meshEventSpoofingAttempt, "peer", from.String())
		return pubsub.ValidationReject
	}
	if event.EventTime == nil {
		logger.Warnw("[Mesh Event] dropping event without event_time", "event", meshEventStaleEvent, "peer", from.String())
		return pubsub.ValidationReject
	}
	eventTime := event.EventTime.AsTime()
	if time.Since(eventTime) > FreshnessThreshold || time.Until(eventTime) > FreshnessThreshold {
		logger.Warnw("[Mesh Event] dropping stale or future event", "event", meshEventStaleEvent, "peer", from.String(), "event_time", eventTime.UTC().Format(time.RFC3339))
		return pubsub.ValidationIgnore
	}
	return pubsub.ValidationAccept
}

func (n *AgentMeshNode) getTrustedPublicKeys() []ed25519.PublicKey {
	n.keysMu.RLock()
	defer n.keysMu.RUnlock()
	keys := make([]ed25519.PublicKey, 0, len(n.trustedKeys))
	for _, tk := range n.trustedKeys {
		keys = append(keys, tk.Key)
	}
	return keys
}

// authHandshakeTimeout bounds how long an unauthenticated peer may hold a
// /mesh/auth stream open: it has to send its frame and read the reply within
// it. Any internet peer can open these streams, so without a deadline each
// one is a goroutine held for as long as the peer likes. A var so tests can
// shorten it.
var authHandshakeTimeout = 10 * time.Second

// HandleAuthHandshake is the core libp2p stream handler for /mesh/auth/1.0.0.
// This is the "Admission Office" of the mesh node.
func (n *AgentMeshNode) HandleAuthHandshake(s network.Stream) {
	defer func() {
		if err := s.Close(); err != nil {
			logger.Errorf("[AuthN] Failed to close auth stream: %v", err)
		}
	}()
	remotePeer := s.Conn().RemotePeer()

	if n.revokedPeers != nil {
		if _, revoked := n.revokedPeers.Get(remotePeer.String()); revoked {
			logger.Warnf("[AuthN] Peer %s is revoked", remotePeer)
			return
		}
	}

	if n.handshakeLimiter != nil && !n.handshakeLimiter.Allow(remotePeer.String()) {
		logger.Warnf("[AuthN] Handshake rate limit exceeded for %s", remotePeer)
		_ = s.Reset()
		return
	}
	if err := s.SetDeadline(time.Now().Add(authHandshakeTimeout)); err != nil {
		logger.Debugf("[AuthN] Failed to set handshake deadline for %s: %v", remotePeer, err)
	}

	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		logger.Errorf("[AuthN] Failed to read handshake from %s: %v", remotePeer, err)
		return
	}
	defer reader.ReleaseMsg(msg)

	var exchange api.AuthFrame
	if err := proto.Unmarshal(msg, &exchange); err != nil {
		logger.Warnf("[AuthN] Invalid protobuf from %s", remotePeer)
		return
	}

	// One verifier call enforces signature, expiry and the authority-block peer
	// binding, and reports when the admission lapses, together with the key
	// that verified so the role can be read under that same key.
	b, verifyingKey, expiry, err := identity.VerifyBiscuitAdmission(exchange.Biscuit, remotePeer, n.getTrustedPublicKeys(), n.BiscuitTimeout)
	if err != nil {
		logger.Warnf("[AuthN] Authorization failed for %s: %v", remotePeer, err)
		return
	}

	// A router that connects to this node (to forward external ingress, for
	// one) is admitted like any peer, and additionally remembered as a router
	// so routerHost protocols can serve it and refuse everyone else.
	isRouter := identity.RequireRole(b, verifyingKey, api.RoleRouter, n.BiscuitTimeout) == nil
	n.admitPeer(remotePeer, expiry, isRouter)
	if isRouter {
		logger.Infof("[AuthN] Successfully authenticated peer %s as router", remotePeer)
	} else {
		logger.Infof("[AuthN] Successfully authenticated peer %s", remotePeer)
	}

	// Mutual response with our identity, mirroring the router handler, so
	// peers can verify this node's attested facts (e.g. region).
	writer := msgio.NewVarintWriter(s)
	respBytes, _ := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: n.GetIdentity()})
	if err := writer.WriteMsg(respBytes); err != nil {
		logger.Errorf("[AuthN] Failed to write mutual ACK to %s: %v", remotePeer, err)
	}
}

func (n *AgentMeshNode) RegisterService(ctx context.Context, req *api.RegisterServiceRequest) error {
	if req.Service == nil {
		return fmt.Errorf("service field is required")
	}
	if req.Service.Name == "" || req.Service.Type == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return fmt.Errorf("service name and type are required")
	}
	if req.Backend == nil {
		return fmt.Errorf("service backend is required")
	}
	svc, err := NewServiceFromRequest(req)
	if err != nil {
		return err
	}
	return n.services.Register(ctx, svc)
}

func (n *AgentMeshNode) UnregisterService(ctx context.Context, serviceName string) error {
	return n.services.Unregister(ctx, serviceName)
}

// withdrawTimeout bounds what a node leaving the mesh waits for its
// records to be withdrawn: a few round trips to the routers it holds.
const withdrawTimeout = 5 * time.Second

// Teardown withdraws the node's records from the directory, detaches all
// registered services and closes the libp2p host. Store is owned by the
// caller and is not closed here.
func (n *AgentMeshNode) Teardown() error {
	if n.services != nil && n.Directory != nil && n.Host != nil {
		ctx, cancel := context.WithTimeout(context.Background(), withdrawTimeout)
		n.services.WithdrawAll(ctx)
		if err := n.Directory.Withdraw(ctx, api.PeerKey(n.Host.ID())); err != nil && !errors.Is(err, errNoDirectoryRouter) {
			logger.Warnf("[Directory] Withdrawing this node's record: %v", err)
		}
		cancel()
	}
	if n.services != nil {
		n.services.TeardownAll()
	}
	var errs []error
	if n.Host != nil {
		if err := n.Host.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (n *AgentMeshNode) IsServiceRegistered(serviceName string) bool {
	_, ok := n.services.Get(serviceName)
	return ok
}

// Bound DHT lookups and per-peer catalog fan-out so a partially
// reachable mesh can't wedge a discovery call indefinitely.
const (
	dhtLookupTimeout       = 5 * time.Second
	discoveryFanoutTimeout = 40 * time.Second
)

// findProviders asks the directory who provides key and keeps their
// addresses for the dials that follow.
func (n *AgentMeshNode) findProviders(ctx context.Context, key []byte) ([]peer.AddrInfo, error) {
	if n.Directory == nil {
		return nil, fmt.Errorf("the directory is not up")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	found, err := n.Directory.FindProviders(lookupCtx, key, n.config.DHTLookupLimit)
	if errors.Is(err, errNoDirectoryRouter) {
		// A member not yet on the mesh knows of nobody; the lookup is
		// counted as failed, the caller sees an empty mesh.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	providers := make([]peer.AddrInfo, 0, len(found))
	for _, p := range found {
		// A revoked peer's record outlives its ban, so without this every
		// service lookup fans out a doomed dial and returns one fewer
		// usable provider.
		if n.peerIsRevoked(p.ID) {
			continue
		}
		logger.Debugf("[Discovery] Provider %s is reached at %v", p.ID, p.Addrs)
		rememberAddrs(n.Host.Peerstore(), p)
		providers = append(providers, p)
	}
	return providers, nil
}

// FindProvidersByName returns peers hosting a specific {type, name} service.
func (n *AgentMeshNode) FindProvidersByName(ctx context.Context, serviceType api.ServiceType, serviceName string) ([]peer.AddrInfo, error) {
	key, err := api.ServiceKey(serviceType, serviceName)
	if err != nil {
		return nil, err
	}
	return n.findProviders(ctx, key)
}

// FindProvidersByType returns peers hosting at least one service of the given type.
func (n *AgentMeshNode) FindProvidersByType(ctx context.Context, serviceType api.ServiceType) ([]peer.AddrInfo, error) {
	key, err := api.ServiceKey(serviceType, "")
	if err != nil {
		return nil, err
	}
	return n.findProviders(ctx, key)
}

// localProxyURL builds the loopback URL clients use to reach a remote service.
func (n *AgentMeshNode) localProxyURL(peerID peer.ID, typeStr, serviceName string) string {
	host := n.BoundHTTPAddr
	if host == "" {
		// Socket-only node: any host works once the caller dials the socket.
		host = "localhost"
	}
	return fmt.Sprintf("http://%s/mesh/%s/%s/%s",
		host, peerID.String(), typeStr, serviceName)
}

// DiscoverRemoteServices dispatches to the named or type-only path
// based on whether serviceName is provided.
func (n *AgentMeshNode) DiscoverRemoteServices(ctx context.Context, serviceType api.ServiceType, serviceName string) ([]*api.DiscoveredProvider, error) {
	typeStr, err := api.ServiceTypeToString(serviceType)
	if err != nil {
		return nil, err
	}
	if serviceName == "" {
		return n.discoverServicesByType(ctx, serviceType, typeStr)
	}
	return n.discoverServicesByName(ctx, serviceType, typeStr, serviceName)
}

// DiscoverRemoteServicesStream performs service discovery and streams results down the returned channel.
// The channel is closed automatically when discovery completes or the context is cancelled.
func (n *AgentMeshNode) DiscoverRemoteServicesStream(ctx context.Context, serviceType api.ServiceType, serviceName string) (<-chan *api.DiscoveredProvider, error) {
	typeStr, err := api.ServiceTypeToString(serviceType)
	if err != nil {
		return nil, err
	}

	out := make(chan *api.DiscoveredProvider, 16)

	go func() {
		defer close(out)

		if serviceName != "" {
			peers, err := n.FindProvidersByName(ctx, serviceType, serviceName)
			if err != nil {
				logger.Errorf("[Discovery] FindProvidersByName failed: %v", err)
				return
			}
			for _, p := range peers {
				if p.ID == n.Host.ID() {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case out <- &api.DiscoveredProvider{
					PeerId:        p.ID.String(),
					LocalProxyUrl: n.localProxyURL(p.ID, typeStr, serviceName),
					SrvName:       serviceName,
				}:
				}
			}
			return
		}

		peers, err := n.FindProvidersByType(ctx, serviceType)
		if err != nil {
			logger.Errorf("[Discovery] FindProvidersByType failed: %v", err)
			return
		}

		fanoutCtx, cancel := context.WithTimeout(ctx, discoveryFanoutTimeout)
		defer cancel()

		concurrency := n.config.DiscoveryConcurrency
		if concurrency <= 0 {
			concurrency = 10
		}
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, p := range peers {
			if p.ID == n.Host.ID() {
				continue
			}
			wg.Add(1)
			go func(peerID peer.ID) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-fanoutCtx.Done():
					return
				}
				services, err := n.fetchRemoteServiceCatalog(fanoutCtx, peerID, typeStr)
				if err != nil {
					logger.Warnf("[Discovery] catalog fetch from %s failed: %v", peerID, err)
					return
				}
				for _, info := range services {
					dp := &api.DiscoveredProvider{
						PeerId:         peerID.String(),
						LocalProxyUrl:  n.localProxyURL(peerID, typeStr, info.Name),
						SrvName:        info.Name,
						SrvDescription: info.Description,
					}
					select {
					case <-fanoutCtx.Done():
						return
					case out <- dp:
					}
				}
			}(p.ID)
		}
		wg.Wait()
	}()

	return out, nil
}

// discoverServicesByName: targeted DHT lookup, no fan-out.
func (n *AgentMeshNode) discoverServicesByName(ctx context.Context, serviceType api.ServiceType, typeStr, serviceName string) ([]*api.DiscoveredProvider, error) {
	peers, err := n.FindProvidersByName(ctx, serviceType, serviceName)
	if err != nil {
		return nil, err
	}
	discovered := []*api.DiscoveredProvider{}
	for _, p := range peers {
		if p.ID == n.Host.ID() {
			continue
		}
		discovered = append(discovered, &api.DiscoveredProvider{
			PeerId:        p.ID.String(),
			LocalProxyUrl: n.localProxyURL(p.ID, typeStr, serviceName),
			SrvName:       serviceName,
		})
	}
	return discovered, nil
}

// discoverServicesByType: rendezvous lookup → parallel list_local_services
// fan-out → flat catalog. Failed peers are dropped with a log line.
func (n *AgentMeshNode) discoverServicesByType(ctx context.Context, serviceType api.ServiceType, typeStr string) ([]*api.DiscoveredProvider, error) {
	peers, err := n.FindProvidersByType(ctx, serviceType)
	if err != nil {
		return nil, err
	}
	logger.Infof("[Discovery] FindProvidersByType returned %d peers", len(peers))

	fanoutCtx, cancel := context.WithTimeout(ctx, discoveryFanoutTimeout)
	defer cancel()

	type peerCatalog struct {
		peerID   peer.ID
		services []*api.ServiceInfo
	}
	results := make(chan peerCatalog, len(peers))
	concurrency := n.config.DiscoveryConcurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, p := range peers {
		if p.ID == n.Host.ID() {
			continue
		}
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-fanoutCtx.Done():
				return
			}
			services, err := n.fetchRemoteServiceCatalog(fanoutCtx, peerID, typeStr)
			if err != nil {
				logger.Warnf("[Discovery] catalog fetch from %s failed: %v", peerID, err)
				return
			}
			results <- peerCatalog{peerID: peerID, services: services}
		}(p.ID)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	discovered := []*api.DiscoveredProvider{}
	for r := range results {
		for _, info := range r.services {
			discovered = append(discovered, &api.DiscoveredProvider{
				PeerId:         r.peerID.String(),
				LocalProxyUrl:  n.localProxyURL(r.peerID, typeStr, info.Name),
				SrvName:        info.Name,
				SrvDescription: info.Description,
			})
		}
	}
	return discovered, nil
}

// ListLocalServices returns services registered on this node. If
// typeFilter is SERVICE_TYPE_UNSPECIFIED, all services are returned.
func (n *AgentMeshNode) ListLocalServices(typeFilter api.ServiceType) []*api.ServiceInfo {
	return n.services.List(typeFilter)
}

type readCloserWithCount struct {
	io.ReadCloser
	bytesRead atomic.Int64
}

func (rc *readCloserWithCount) Read(p []byte) (int, error) {
	n, err := rc.ReadCloser.Read(p)
	rc.bytesRead.Add(int64(n))
	return n, err
}

type responseWriterWithCount struct {
	http.ResponseWriter
	bytesWritten atomic.Int64
	statusCode   int
}

func (w *responseWriterWithCount) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten.Add(int64(n))
	return n, err
}

func (w *responseWriterWithCount) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriterWithCount) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseWriterWithCount) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (n *AgentMeshNode) StartIngressServer(ctx context.Context) error {
	listener, err := gostream.Listen(n.Host, "/libp2p-http")
	if err != nil {
		return err
	}

	server := &http.Server{
		// Bound header-read time only: proxied backend responses can stream.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := &readCloserWithCount{ReadCloser: r.Body}
			r.Body = rc
			wc := &responseWriterWithCount{ResponseWriter: w, statusCode: http.StatusOK}
			w = wc

			var remotePeer peer.ID
			var target string

			defer func() {
				peerIDStr := ""
				if remotePeer != "" {
					peerIDStr = remotePeer.String()
				}
				finalTarget := target
				if finalTarget == "" {
					finalTarget = "unauthenticated_or_failed"
				}
				logger.Infow("Stream Accounting",
					"peer_id", peerIDStr,
					"target", finalTarget,
					"protocol", "/libp2p-http",
					"bytes_read", rc.bytesRead.Load(),
					"bytes_written", wc.bytesWritten.Load(),
				)
			}()

			// The path is remote-controlled and the peer is not yet authorized:
			// it is logged only after VerifyBiscuitToken passes.
			path := r.URL.Path
			// Policy is decided on the /{type}/{name} prefix; a ".." segment in
			// what follows could resolve to a sibling service on a shared backend.
			if hasDotSegment(path) {
				http.Error(w, "Invalid path", http.StatusBadRequest)
				return
			}
			parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
			if len(parts) < 2 {
				http.Error(w, "Invalid path", http.StatusBadRequest)
				return
			}
			serviceTypeStr := parts[0]
			serviceName := parts[1]
			upstreamPath := ""
			if len(parts) > 2 {
				upstreamPath = parts[2]
			}

			serviceType, err := api.ParseServiceType(serviceTypeStr)
			if err != nil || serviceType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
				http.Error(w, "Invalid service type", http.StatusBadRequest)
				return
			}

			// Extract biscuit from X-Mesh-Biscuit header
			biscuitB64 := r.Header.Get(api.HeaderMeshBiscuit)
			if biscuitB64 == "" {
				http.Error(w, "Missing X-Mesh-Biscuit header", http.StatusUnauthorized)
				return
			}
			biscuitBytes, err := base64.StdEncoding.DecodeString(biscuitB64)
			if err != nil {
				http.Error(w, "Invalid X-Mesh-Biscuit encoding", http.StatusBadRequest)
				return
			}

			// Parse remote peer from RemoteAddr
			remotePeer, err = peer.Decode(r.RemoteAddr)
			if err != nil {
				http.Error(w, "Invalid remote peer", http.StatusBadRequest)
				return
			}
			if n.rateLimiter != nil && !n.rateLimiter.Allow(remotePeer.String()) {
				logger.Warnf("[Ingress] Rate limit exceeded for %s", remotePeer)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			target = strings.ToLower(serviceTypeStr) + "://" + serviceName
			reqCtx := RequestContext{
				PeerID:   remotePeer,
				User:     "", // Extracted implicitly if needed, or left empty
				Protocol: "/libp2p-http",
				Target:   target,
				// The path policy sees is the one the backend will see, decided
				// here so it can never be the routing prefix.
				HTTP: &HTTPRequestFacts{Method: r.Method, Path: "/" + upstreamPath},
			}
			if serviceType == api.ServiceType_SERVICE_TYPE_EGRESS {
				if svc, ok := n.services.GetTyped(serviceType, serviceName); ok {
					reqCtx.Egress = egressFactsFor(svc)
				}
				if strings.EqualFold(r.Header.Get("Upgrade"), HeaderMeshTunnelUpgrade) {
					reqPort, _ := strconv.Atoi(r.Header.Get(HeaderMeshEgressPort))
					reqCtx.HTTP = &HTTPRequestFacts{Method: http.MethodConnect, Path: ""}
					reqCtx.Egress = &EgressFacts{Host: serviceName, Port: reqPort}
				}
			}
			if serviceType == api.ServiceType_SERVICE_TYPE_MCP {
				preCtx := reqCtx
				preCtx.AllowMCPStreamInit = true
				if err := n.VerifyBiscuitToken(biscuitBytes, preCtx); err != nil {
					logger.Warnf("[Ingress] AuthZ Denied for %s: %v", remotePeer, err)
					refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusDenied)
					return
				}
				mcpTool, allowInit, err := inspectMCPHTTPRequestBody(r)
				if err != nil {
					refuse(w, http.StatusRequestEntityTooLarge, err.Error(), proxyStatusDenied)
					return
				}
				reqCtx.MCPTool = mcpTool
				reqCtx.AllowMCPStreamInit = allowInit
			}

			// Verify authorization
			if err := n.VerifyBiscuitToken(biscuitBytes, reqCtx); err != nil {
				logger.Warnf("[Ingress] AuthZ Denied for %s: %v", remotePeer, err)
				if serviceType == api.ServiceType_SERVICE_TYPE_EGRESS {
					recordEgressDecision(serviceName, egressOutcomeDeny)
				}
				refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusDenied)
				return
			}
			if serviceType == api.ServiceType_SERVICE_TYPE_EGRESS {
				recordEgressDecision(serviceName, egressOutcomeAllow)
			}

			// Strip the biscuit header and any caller-supplied X-Mesh-* headers so
			// only transport-verified identity attributes reach the backend service.
			for name := range r.Header {
				lower := strings.ToLower(name)
				if lower == "cookie" || strings.HasPrefix(lower, "x-mesh-") {
					delete(r.Header, name)
				}
			}
			r.Header.Set(api.HeaderPeerID, remotePeer.String())
			if claims, cErr := n.VerifyLocalBiscuit(biscuitBytes); cErr == nil && claims != nil {
				if p := claims.Principal(); p != "" {
					r.Header.Set(api.HeaderMeshPrincipal, p)
				}
				if len(claims.Roles) > 0 {
					r.Header.Set(api.HeaderMeshRoles, strings.Join(claims.Roles, ","))
				}
			}

			// Under the type the policy was evaluated on: a same-named service
			// of another type is not what the caller was granted.
			svc, ok := n.services.GetTyped(serviceType, serviceName)
			if !ok {
				logger.Errorf("[Ingress] Service not found: %s", truncateForLog(target))
				http.Error(w, "Service not found", http.StatusNotFound)
				return
			}
			if svc.Handler() == nil {
				logger.Errorf("[Ingress] Service %s has nil handler", serviceName)
				http.Error(w, "Service not found", http.StatusNotFound)
				return
			}
			logger.Infof("[Ingress] %s from %s: forwarding to service %s, upstreamPath: %q", r.Method, remotePeer, serviceName, truncateForLog(upstreamPath))

			if upstreamPath == "" {
				r.URL.Path = "/"
				if len(parts) == 2 {
					r.Header.Set(api.HeaderMeshNoTrailingSlash, "true")
				}
			} else {
				r.URL.Path = "/" + upstreamPath
			}
			r.URL.RawPath = ""

			svc.Handler().ServeHTTP(w, r.WithContext(WithCallerBiscuit(r.Context(), biscuitBytes)))
		}),
	}

	go func() {
		logger.Infof("[Ingress] Starting P2P HTTP server on protocol /libp2p-http")
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Errorf("[Ingress] Server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := server.Close(); err != nil {
			logger.Errorf("[Ingress] Failed to close server: %v", err)
		}
		if err := listener.Close(); err != nil {
			logger.Errorf("[Ingress] Failed to close listener: %v", err)
		}
	}()

	return nil
}

// announceFilter selects which of the host's addresses are published to the
// mesh (via Identify and DHT provider records). Relay addresses always pass:
// their IP belongs to the router, and dropping one would strand a node behind
// NAT. The routers the node holds a reservation on are added as circuit
// addresses: AutoRelay publishes those only for a router on a public IP, and
// a mesh on private or loopback addresses would otherwise publish no path to
// a node that is reachable through its routers alone.
func (n *AgentMeshNode) announceFilter(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	announcePrivate := n.config.AnnouncePrivateAddrs == nil || *n.config.AnnouncePrivateAddrs
	if !n.config.AllowLoopback || !announcePrivate {
		var filtered []multiaddr.Multiaddr
		for _, addr := range addrs {
			if hasCircuit(addr) {
				filtered = append(filtered, addr)
				continue
			}
			if !n.config.AllowLoopback && isLoopbackOrLinkLocal(addr) {
				continue
			}
			if !announcePrivate && isPrivateIP(addr) {
				continue
			}
			filtered = append(filtered, addr)
		}
		addrs = filtered
	}
	extra := n.reservedCircuitAddrs(addrs)
	if len(extra) == 0 {
		return addrs
	}
	out := make([]multiaddr.Multiaddr, 0, len(addrs)+len(extra))
	out = append(out, addrs...)
	return append(out, extra...)
}

// reservedCircuitAddrs is one <router>/p2p/<id>/p2p-circuit address per
// address of each router AutoRelay holds a reservation on, leaving out those
// already in have.
func (n *AgentMeshNode) reservedCircuitAddrs(have []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if n.connMgr == nil {
		return nil
	}
	seen := make(map[string]bool, len(have))
	for _, a := range have {
		seen[a.String()] = true
	}
	var out []multiaddr.Multiaddr
	for _, c := range n.routerCandidates() {
		if !n.connMgr.IsProtected(c.ID, autorelayTag) {
			continue
		}
		circuit := multiaddr.StringCast("/p2p/" + c.ID.String() + "/p2p-circuit")
		for _, addr := range c.Addrs {
			full := addr.Encapsulate(circuit)
			if !seen[full.String()] {
				seen[full.String()] = true
				out = append(out, full)
			}
		}
	}
	return out
}

func isLoopbackOrLinkLocal(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code != multiaddr.P_IP4 && proto.Code != multiaddr.P_IP6 {
			continue
		}
		value, err := addr.ValueForProtocol(proto.Code)
		if err != nil {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
	}
	return false
}

func isPrivateIP(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code != multiaddr.P_IP4 && proto.Code != multiaddr.P_IP6 {
			continue
		}
		value, err := addr.ValueForProtocol(proto.Code)
		if err != nil {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		if ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasCircuit(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code == multiaddr.P_CIRCUIT {
			return true
		}
	}
	return false
}

func (n *AgentMeshNode) syncMeshPolicy(ctx context.Context) error {
	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil || controlPlaneURL == "" {
		return fmt.Errorf("control plane URL not found in store")
	}

	token := n.GetIdentity()
	if len(token) == 0 {
		return fmt.Errorf("node has no identity token to fetch mesh policy")
	}

	policyResp, err := n.controlPlane(controlPlaneURL).FetchPolicy(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to fetch mesh policy: %w", err)
	}

	// The rendered text is the contract every member evaluates; a node does
	// not derive rules from roles and bindings itself. A control plane that
	// still sends those fields predates the contract.
	if len(policyResp.ProtoReflect().GetUnknown()) > 0 {
		return fmt.Errorf("control plane %s predates datalog_rules in its policy response; upgrade the control plane", controlPlaneURL)
	}
	rules, err := api.ParseDatalogRules(policyResp.DatalogRules)
	if err != nil {
		return fmt.Errorf("mesh policy carries an unparseable rule: %w", err)
	}

	n.MeshPolicyMu.Lock()
	changed := n.meshPolicyTexts != nil && !slices.Equal(n.meshPolicyTexts, policyResp.DatalogRules)
	n.MeshPolicyRules = rules
	n.meshPolicyTexts = policyResp.DatalogRules
	n.MeshPolicyMu.Unlock()

	logger.Infof("Successfully synchronized mesh policy (%d rules)", len(rules))
	if changed && n.reprovideTrigger != nil {
		// The policy decides what this node may publish; a record the
		// directory refused under the previous one is announced again now.
		logger.Info("Mesh policy changed; announcing this node's records again")
		n.triggerReprovide()
	}
	return nil
}

// reportNodeCatalog self-reports this node's local service list to the
// control plane (see internal/controlplane/catalog.go's HandleNodeCatalog),
// so an admin console can show mesh-wide service topology.
func (n *AgentMeshNode) reportNodeCatalog(ctx context.Context) error {
	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil || controlPlaneURL == "" {
		return fmt.Errorf("control plane URL not found in store")
	}

	token := n.GetIdentity()
	if len(token) == 0 {
		return fmt.Errorf("node has no identity token to report its catalog")
	}

	services := n.ListLocalServices(api.ServiceType_SERVICE_TYPE_UNSPECIFIED)
	if err := n.controlPlane(controlPlaneURL).ReportCatalog(ctx, token, services); err != nil {
		return fmt.Errorf("failed to report node catalog: %w", err)
	}
	return nil
}

// startCatalogReportLoop reports the local catalog once after initialDelay
// and then every interval, each wait stretched by up to a tenth of interval
// so a fleet started together does not hit the control plane in lockstep.
// A failure is logged at Warn once and at Debug while it persists: the
// usual causes (control plane unreachable, path not routed) do not change
// from one tick to the next.
func (n *AgentMeshNode) startCatalogReportLoop(ctx context.Context, initialDelay, interval time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	if initialDelay <= 0 {
		initialDelay = 5 * time.Second
	}

	go func() {
		wait := initialDelay
		failures := 0
		for {
			timer := time.NewTimer(wait + time.Duration(rand.Int63n(int64(interval/10)+1)))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			wait = interval

			err := n.reportNodeCatalog(ctx)
			switch {
			case err != nil && failures == 0:
				logger.Warnf("Node catalog report failed: %v", err)
			case err != nil:
				logger.Debugf("Node catalog report still failing (%d consecutive): %v", failures+1, err)
			case failures > 0:
				logger.Infof("Node catalog report recovered after %d failures", failures)
			}
			if err != nil {
				failures++
			} else {
				failures = 0
			}
		}
	}()
}
