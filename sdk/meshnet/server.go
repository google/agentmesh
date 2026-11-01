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

// Package meshnet embeds an Agent Mesh member directly inside a Go program
// (modeled on tailscale.com/tsnet), providing in-process A2A listeners
// (private P2P and public external HTTP ingress), a mesh-routing *http.Client,
// unspoofable WhoIs caller inspection, a local progressive-discovery MCP
// server, and a zero-secret OpenAI-compatible /v1 inference handler without an
// external agentmesh-node sidecar binary.
package meshnet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/ratelimit"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/libp2p/go-libp2p"
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
)

const (
	rateLimiterSize     = 1024
	revocationCacheSize = 4096
	withdrawTimeout     = 5 * time.Second
)

// Server is an embedded Agent Mesh node. Configure its exported fields and call
// Up (or ListenA2A after Up) to join the mesh in-process.
type Server struct {
	// StateDir persists identity.key and credential.json (0700/0600, byte-for-byte
	// compatible with sdk/js, sdk/python, and `agentmesh-node state export|import`).
	// When empty, Server runs with an ephemeral in-memory Ed25519 identity.
	StateDir string

	// ControlPlaneURL is the Agent Mesh hub URL (e.g. "https://bananas.sam-mesh.dev").
	// Optional when resuming from a populated StateDir that already records
	// control_plane_url.
	ControlPlaneURL string

	// BootstrapTokenPath reads a bootstrap enrollment token from disk when no
	// valid credential exists in StateDir. Preferred over BootstrapToken so
	// secrets stay in files rather than process arguments.
	BootstrapTokenPath string

	// BootstrapToken supplies an in-memory bootstrap enrollment token (for
	// example read from an environment variable or secret manager).
	BootstrapToken string

	// JWTPath reads a platform OIDC / Kubernetes ServiceAccount / SPIFFE JWT from
	// disk for POST /register enrollment and POST /refresh re-attestation.
	JWTPath string

	// TokenSource dynamically fetches a fresh platform JWT for POST /register
	// enrollment and proactive POST /refresh renewal.
	TokenSource func(ctx context.Context) (string, error)

	// Labels are operator-declared key=value pairs requested at enrollment time
	// (signed into Block 0 only when permitted by PolicyRole.allowed_labels).
	Labels map[string]string

	// EgressRequireLabels sets a consumer-side label floor enforced on every
	// outbound provider's Biscuit before request data leaves this Server.
	EgressRequireLabels map[string]string

	// Routers is the target number of mesh routers to stay attached to (default 2).
	Routers int

	// RouterSelector filters candidate routers to those attesting all key=value pairs.
	RouterSelector map[string]string

	// RouterPrefer ranks routers matching more key=value pairs first.
	RouterPrefer map[string]string

	// ListenAddrs overrides the libp2p listen multiaddrs. When empty, Server
	// binds ephemeral UDP QUIC and TCP ports on all interfaces so direct P2P and
	// hole-punching work alongside Circuit Relay v2.
	ListenAddrs []string

	// AllowInsecure opts into http:// control-plane URLs on loopback and keeps
	// loopback/private peer multiaddrs during local development and integration tests.
	AllowInsecure bool

	// Logger receives structured mesh events. Defaults to slog.Default().
	Logger *slog.Logger

	// Internal state initialized by Up.
	lifecycleMu sync.Mutex
	started     bool
	closed      bool
	bgCancel    context.CancelFunc
	addrSub     event.Subscription

	privKey      crypto.PrivKey
	privKeyBytes []byte
	peerID       peer.ID
	cpURL        string

	keysMu          sync.RWMutex
	trustedKeys     []trustedKey
	issuedUnderKeys []ed25519.PublicKey

	credMu            sync.RWMutex
	biscuit           []byte
	expireTime        time.Time
	storedRouterAddrs []string
	oidcSession       *api.OIDCSession

	refreshMu    sync.Mutex
	reenrollMu   sync.Mutex
	lastReenroll time.Time

	host    host.Host
	connMgr *connmgr.BasicConnMgr
	pubsub  *pubsub.PubSub
	dir     *routerDirectory

	mu                        sync.Mutex
	routerCatalog             []routerCandidate
	attached                  map[peer.ID]bool
	authenticatedRouters      map[peer.ID]bool
	shunned                   map[peer.ID]time.Time
	handshaking               map[peer.ID]chan struct{}
	redialing                 map[peer.ID]bool
	currentRelays             []peer.AddrInfo
	dirSettings               api.DirectorySettings
	peerLastEventTime         map[string]int64
	transitCatalogRefreshedAt time.Time

	authPeers   sync.Map
	authRouters sync.Map
	authSuccess chan struct{}
	authOnce    sync.Once

	policyMu        sync.RWMutex
	meshPolicyRules []biscuit.Rule
	meshPolicyTexts []string

	revokedPeers  *lru.Cache[string, int64]
	revokedTokens *lru.Cache[string, time.Time]
	peerLabelGate *lru.Cache[string, time.Time]

	rateLimiter            *ratelimit.PeerRateLimiter
	handshakeLimiter       *ratelimit.PeerRateLimiter
	externalIngressLimiter *ratelimit.PeerRateLimiter

	refusedMu      sync.Mutex
	refusedStreams map[string]uint64

	syncInterval     time.Duration
	syncTrigger      chan struct{}
	reprovideTrigger chan struct{}

	a2aMu       sync.RWMutex
	a2aServices map[string]*a2aEntry

	activeConns sync.Map
	nextConnSeq atomic.Uint64
}

// Status describes the live mesh connectivity and credential state of a Server.
type Status struct {
	PeerID          string
	ControlPlaneURL string
	AttachedRouters []string
	IngressURLs     []string
	ExpireTime      time.Time
}

// CallerInfo carries the cryptographically verified mesh identity of an inbound
// caller returned by Server.WhoIs.
type CallerInfo struct {
	PeerID    string
	Principal string
	Roles     []string
	Labels    map[string]string
	Task      string
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) biscuitTimeout() time.Duration {
	return identity.DefaultAuthorizerTimeout
}

// Up loads or enrolls the member credential, syncs mesh trust material and
// policy from the control plane, starts the gated libp2p host, authenticates
// with mesh routers, and starts background renewal, sync, and reprovide loops.
func (s *Server) Up(ctx context.Context) (*Status, error) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if s.closed {
		return nil, errors.New("meshnet: Server has been closed")
	}
	if s.started {
		st := s.Status()
		return &st, nil
	}

	if err := api.ValidateLabels(s.Labels); err != nil {
		return nil, fmt.Errorf("meshnet: invalid Labels: %w", err)
	}
	if err := api.ValidateLabels(s.EgressRequireLabels); err != nil {
		return nil, fmt.Errorf("meshnet: invalid EgressRequireLabels: %w", err)
	}
	if err := api.ValidateLabels(s.RouterSelector); err != nil {
		return nil, fmt.Errorf("meshnet: invalid RouterSelector: %w", err)
	}
	if err := api.ValidateLabels(s.RouterPrefer); err != nil {
		return nil, fmt.Errorf("meshnet: invalid RouterPrefer: %w", err)
	}

	if err := s.initCaches(); err != nil {
		return nil, err
	}

	if err := s.ensureCredential(ctx); err != nil {
		return nil, err
	}

	if err := s.syncControlPlane(ctx); err != nil {
		s.log().Warn("initial control plane sync completed with errors; falling back to cached state where available", "error", err)
	}
	if len(s.routerCandidates()) == 0 {
		s.credMu.RLock()
		stored := slices.Clone(s.storedRouterAddrs)
		s.credMu.RUnlock()
		if len(stored) > 0 {
			s.setRouterCatalog(candidatesFromAddrs(ctx, parseMultiaddrs(stored)))
		}
	}

	cm, err := connmgr.NewConnManager(connLowWaterMark, connHighWaterMark, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return nil, fmt.Errorf("create connection manager: %w", err)
	}
	s.connMgr = cm

	rm, err := s.newResourceManager()
	if err != nil {
		_ = cm.Close()
		return nil, fmt.Errorf("create resource manager: %w", err)
	}

	listenAddrs := s.ListenAddrs
	if len(listenAddrs) == 0 {
		listenAddrs = []string{
			"/ip4/0.0.0.0/udp/0/quic-v1",
			"/ip4/0.0.0.0/tcp/0",
			"/ip6/::/udp/0/quic-v1",
			"/ip6/::/tcp/0",
		}
	}

	numRelays := s.Routers
	if numRelays <= 0 {
		numRelays = 2
	}

	opts := []libp2p.Option{
		libp2p.Identity(s.privKey),
		libp2p.DefaultTransports,
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.ConnectionGater(&connGate{s: s}),
		libp2p.ListenAddrStrings(listenAddrs...),
		libp2p.EnableNATService(),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.ForceReachabilityPrivate(),
		libp2p.ConnectionManager(cm),
		libp2p.ResourceManager(rm),
		libp2p.SwarmOpts(swarm.WithDialTimeout(15*time.Second), swarm.WithDialRanker(tcpFirstDialRanker)),
		libp2p.AddrsFactory(s.announceFilter),
	}

	if len(s.routerCandidates()) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithPeerSource(
			func(pCtx context.Context, _ int) <-chan peer.AddrInfo {
				c := make(chan peer.AddrInfo, numRelays)
				go func() {
					defer close(c)
					select {
					case <-pCtx.Done():
						return
					case <-s.authSuccess:
					}
					s.mu.Lock()
					relays := slices.Clone(s.currentRelays)
					s.mu.Unlock()
					rand.Shuffle(len(relays), func(i, j int) {
						relays[i], relays[j] = relays[j], relays[i]
					})
					for _, r := range relays {
						select {
						case c <- r:
						case <-pCtx.Done():
							return
						}
					}
				}()
				return c
			},
			autorelay.WithNumRelays(numRelays),
			autorelay.WithBootDelay(0),
			autorelay.WithBackoff(5*time.Second),
			autorelay.WithMinInterval(5*time.Second),
		))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		_ = cm.Close()
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}
	s.host = h

	for _, c := range s.routerCandidates() {
		h.Peerstore().AddAddrs(c.ID, c.Addrs, peerstore.PermanentAddrTTL)
	}

	bgCtx, bgCancel := context.WithCancel(context.Background())
	s.bgCancel = bgCancel

	cleanupOnErr := func() {
		bgCancel()
		_ = h.Close()
		_ = cm.Close()
		s.host = nil
		s.connMgr = nil
	}

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			remoteAddr := c.RemoteMultiaddr()
			if hasCircuit(remoteAddr) || !isPrivateIP(remoteAddr) {
				_ = h.Peerstore().Put(c.RemotePeer(), peerstoreKeyPrivateIPFailed, true)
			}
		},
		DisconnectedF: func(_ network.Network, c network.Conn) {
			remotePeer := c.RemotePeer()
			if len(h.Network().ConnsToPeer(remotePeer)) > 0 {
				return
			}
			s.mu.Lock()
			_, wasAuth := s.authenticatedRouters[remotePeer]
			delete(s.authenticatedRouters, remotePeer)
			attached := s.attached[remotePeer]
			s.mu.Unlock()
			if wasAuth {
				s.log().Warn("router disconnected; clearing authenticated session", "router_peer_id", remotePeer.String())
				if attached {
					s.redialRouter(bgCtx, remotePeer)
				}
			}
		},
	})

	gated := &meshHost{Host: h, s: s}
	s.dir = &routerDirectory{
		host:    gated,
		routers: s.attachedRouters,
		addrs:   h.Addrs,
		log:     s.log,
	}

	// Register handshake and credential-gated stream handlers BEFORE dialing
	// routers so incoming streams during or immediately after router admission
	// find every protocol ready.
	h.SetStreamHandler(api.AuthProtocolID, s.recoverStream("auth", s.handleAuthHandshake))
	h.SetStreamHandler(api.GoAwayProtocolID, s.recoverStream("goaway", func(st network.Stream) {
		s.handleGoAway(bgCtx, st)
	}))
	h.SetStreamHandler(api.MCPProtocolID, s.recoverStream("mcp", s.handleMCPStream))

	if err := s.startHTTPServers(bgCtx); err != nil {
		cleanupOnErr()
		return nil, err
	}

	ps, err := pubsub.NewFloodSub(bgCtx, gated, pubsub.WithMessageSignaturePolicy(pubsub.StrictSign))
	if err != nil {
		cleanupOnErr()
		return nil, fmt.Errorf("init floodsub: %w", err)
	}
	if err := ps.RegisterTopicValidator(api.GossipEvents, s.validateMeshEvent); err != nil {
		cleanupOnErr()
		return nil, fmt.Errorf("register gossip validator: %w", err)
	}
	s.pubsub = ps
	go s.listenForControlPlaneEvents(bgCtx)

	if err := s.admitByRouters(ctx); err != nil {
		cleanupOnErr()
		return nil, err
	}

	if sub, subErr := h.EventBus().Subscribe(new(event.EvtLocalAddressesUpdated)); subErr == nil {
		s.addrSub = sub
		go func() {
			for {
				select {
				case <-bgCtx.Done():
					return
				case _, ok := <-sub.Out():
					if !ok {
						return
					}
					s.triggerReprovide()
				}
			}
		}()
	}

	s.startReprovideLoop(bgCtx)
	s.startControlPlaneSyncLoop(bgCtx)
	s.startRenewalLoop(bgCtx)

	s.started = true
	st := s.Status()
	return &st, nil
}

func (s *Server) initCaches() error {
	s.attached = make(map[peer.ID]bool)
	s.authenticatedRouters = make(map[peer.ID]bool)
	s.shunned = make(map[peer.ID]time.Time)
	s.handshaking = make(map[peer.ID]chan struct{})
	s.redialing = make(map[peer.ID]bool)
	s.peerLastEventTime = make(map[string]int64)
	s.dirSettings = api.DefaultDirectorySettings()
	s.authSuccess = make(chan struct{})
	s.syncTrigger = make(chan struct{}, 1)
	s.reprovideTrigger = make(chan struct{}, 1)
	s.refusedStreams = make(map[string]uint64)
	s.a2aServices = make(map[string]*a2aEntry)

	var err error
	if s.rateLimiter, err = ratelimit.NewPeerRateLimiterWithRate(rateLimiterSize, 20, 30); err != nil {
		return err
	}
	if s.handshakeLimiter, err = ratelimit.NewPeerRateLimiter(rateLimiterSize); err != nil {
		return err
	}
	if s.externalIngressLimiter, err = ratelimit.NewPeerRateLimiterWithRate(rateLimiterSize, 200, 400); err != nil {
		return err
	}
	if s.revokedPeers, err = lru.New[string, int64](revocationCacheSize); err != nil {
		return err
	}
	if s.revokedTokens, err = lru.New[string, time.Time](revocationCacheSize); err != nil {
		return err
	}
	if s.peerLabelGate, err = lru.New[string, time.Time](labelGateCacheSize); err != nil {
		return err
	}
	return nil
}

// Status returns a snapshot of the member's PeerID, control-plane URL,
// attached routers, public router ingress base URLs, and credential expiry.
func (s *Server) Status() Status {
	routers := s.attachedRouters()
	routerStrs := make([]string, 0, len(routers))
	for _, r := range routers {
		routerStrs = append(routerStrs, r.String())
	}
	sort.Strings(routerStrs)

	var peerIDStr string
	if s.peerID != "" {
		peerIDStr = s.peerID.String()
	}
	return Status{
		PeerID:          peerIDStr,
		ControlPlaneURL: s.cpURL,
		AttachedRouters: routerStrs,
		IngressURLs:     s.routerIngressURLs(),
		ExpireTime:      s.credentialExpireTime(),
	}
}

// Close withdraws directory records (bounded to 5s), closes all registered
// A2A listeners, stops background loops, and shuts down the libp2p host.
func (s *Server) Close() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	entries := s.listA2AEntries()
	for _, e := range entries {
		_ = e.privateLn.Close()
		if e.publicLn != nil {
			_ = e.publicLn.Close()
		}
	}

	if s.dir != nil && s.host != nil {
		wCtx, cancel := context.WithTimeout(context.Background(), withdrawTimeout)
		hasAnnouncedA2A := false
		for _, e := range entries {
			if e.noAnnounce {
				continue
			}
			hasAnnouncedA2A = true
			if nameKey, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, e.name); err == nil {
				_ = s.dir.withdraw(wCtx, nameKey)
			}
		}
		if hasAnnouncedA2A {
			if typeKey, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, ""); err == nil {
				_ = s.dir.withdraw(wCtx, typeKey)
			}
		}
		_ = s.dir.withdraw(wCtx, api.PeerKey(s.peerID))
		cancel()
	}

	if s.addrSub != nil {
		_ = s.addrSub.Close()
	}
	if s.bgCancel != nil {
		s.bgCancel()
	}

	var errs []error
	if s.host != nil {
		if err := s.host.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.connMgr != nil {
		if err := s.connMgr.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
