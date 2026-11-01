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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
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
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	coreconnmgr "github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	ws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	libp2pwebtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var logger = golog.Logger("agentmesh-router")

// DefaultLowWaterMark is the low watermark for a high one: TrimShare below
// it, so a trim sheds that share of the connections and no more.
func DefaultLowWaterMark(highWaterMark int) int {
	return max(1, int(float64(highWaterMark)*(1-TrimShare)))
}

const (
	DefaultHighWaterMark = 4000
	// TrimShare is the share of its connections a router sheds when it
	// crosses the high watermark: the low watermark it trims down to is
	// the high one less this. libp2p's own default trims from 4000 to 1000,
	// which on a hub whose every connection is a member session is most
	// of the mesh at once.
	TrimShare       = 0.15
	ConnGracePeriod = 1 * time.Minute
	// federationTag keeps a peer router's connection out of a trim: losing
	// it splits the DHT, losing a member's does not.
	federationTag = "agentmesh-federation"
	// memberTag marks the connection of a peer that authenticated; a trim
	// orders by tag value, lowest first, so the untagged go before members.
	memberTag      = "agentmesh-member"
	memberTagValue = 100
)

var _ coreconnmgr.ConnectionGater = (*routerConnGate)(nil)

type routerConnGate struct {
	r *Router
}

func (g *routerConnGate) InterceptPeerDial(p peer.ID) bool {
	if _, banned := g.r.bannedPeers.Load(p); banned {
		return false
	}
	return true
}

func (g *routerConnGate) InterceptAddrDial(peer.ID, multiaddr.Multiaddr) bool {
	return true
}

func (g *routerConnGate) InterceptAccept(network.ConnMultiaddrs) bool {
	return true
}

func (g *routerConnGate) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	if _, banned := g.r.bannedPeers.Load(p); banned {
		return false
	}
	return true
}

func (g *routerConnGate) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

type relayACL struct {
	r *Router
}

func (a *relayACL) AllowReserve(p peer.ID, addr multiaddr.Multiaddr) bool {
	if _, banned := a.r.bannedPeers.Load(p); banned {
		logger.Debugf("[Relay] Rejecting reservation for %s: peer is banned", p)
		return false
	}
	ok := a.r.isPeerAuthenticated(p)
	if !ok {
		logger.Debugf("[Relay] Rejecting reservation for %s: not authenticated", p)
		return false
	}
	a.r.recordReservation(p)
	return true
}

// recordReservation puts the addresses p is reached at through this router
// in the peerstore, so a DHT lookup for p that reaches this router gets
// them. A member tells its other routers about its reservations through
// identify, but not the router it reserved with: identify ran before the
// reservation, and an SDK member listens on nothing else. The entries last
// as long as the reservation, which the member renews through here;
// identify, which rewrites a peer's connected-TTL addresses whenever the
// peer announces new ones, leaves that TTL alone. forgetPeer drops them.
func (r *Router) recordReservation(p peer.ID) {
	if r.Host == nil {
		return
	}
	r.Host.Peerstore().AddAddrs(p, r.circuitAddrs(), r.reservationTTL())
}

// reservationTTL is the relay's reservation lifetime, which the recorded
// circuit addresses share.
func (r *Router) reservationTTL() time.Duration {
	return relay.DefaultResources().ReservationTTL
}

// advertisedAddrs are the addresses the router leases to the control plane
// and is reached at: the configured external ones, else what the host
// listens on.
func (r *Router) advertisedAddrs() []multiaddr.Multiaddr {
	if len(r.config.ExternalAddrs) == 0 {
		return r.Host.Addrs()
	}
	addrs := make([]multiaddr.Multiaddr, 0, len(r.config.ExternalAddrs))
	for _, s := range r.config.ExternalAddrs {
		if ma, err := multiaddr.NewMultiaddr(s); err == nil {
			addrs = append(addrs, ma)
		}
	}
	return addrs
}

// circuitAddrs are advertisedAddrs with /p2p/<router>/p2p-circuit appended:
// where a peer that reserved with this router is reached.
func (r *Router) circuitAddrs() []multiaddr.Multiaddr {
	via := multiaddr.StringCast("/p2p/" + r.Host.ID().String() + "/p2p-circuit")
	advertised := r.advertisedAddrs()
	addrs := make([]multiaddr.Multiaddr, 0, len(advertised))
	for _, a := range advertised {
		addrs = append(addrs, a.Encapsulate(via))
	}
	return addrs
}

func (a *relayACL) AllowConnect(src peer.ID, srcAddr multiaddr.Multiaddr, dest peer.ID) bool {
	if _, banned := a.r.bannedPeers.Load(src); banned {
		logger.Debugf("[Relay] Rejecting connect from %s to %s: src is banned", src, dest)
		return false
	}
	if _, banned := a.r.bannedPeers.Load(dest); banned {
		logger.Debugf("[Relay] Rejecting connect from %s to %s: dest is banned", src, dest)
		return false
	}
	// Both ends must have authenticated: every node authenticates to the
	// router on connect, so a source that has not is not a mesh member.
	if !a.r.isPeerAuthenticated(src) {
		logger.Debugf("[Relay] Rejecting connect from %s to %s: src not authenticated", src, dest)
		return false
	}
	ok := a.r.isPeerAuthenticated(dest)
	if !ok {
		logger.Debugf("[Relay] Rejecting connect from %s to %s: dest not authenticated", src, dest)
	}
	return ok
}

// isPeerAuthenticated reports whether p completed the auth handshake and its
// verified biscuit has not lapsed since.
func (r *Router) isPeerAuthenticated(p peer.ID) bool {
	v, ok := r.authenticatedPeers.Load(p)
	if !ok {
		return false
	}
	switch exp := v.(type) {
	case time.Time:
		if !time.Now().Before(exp) {
			r.forgetPeer(p)
			return false
		}
		return true
	case bool:
		return exp
	default:
		return false
	}
}

// admitPeer records that p proved membership until expiry and tags its
// connection for the connection manager: a trim takes the lowest tag
// first, so connections that never authenticated go before members.
func (r *Router) admitPeer(p peer.ID, expiry time.Time) {
	r.authenticatedPeers.Store(p, expiry)
	if r.Host != nil {
		r.Host.ConnManager().TagPeer(p, memberTag, memberTagValue)
	}
}

// memberCredential is a verified credential and the key that verified it.
type memberCredential struct {
	biscuit *biscuit.Biscuit
	key     ed25519.PublicKey
}

// forgetPeer is the reverse of admitPeer, and drops the circuit addresses
// recordReservation put in the peerstore: the relay drops the reservation
// with the connection.
func (r *Router) forgetPeer(p peer.ID) {
	r.authenticatedPeers.Delete(p)
	r.credentials.Delete(p)
	if r.Host != nil {
		r.Host.ConnManager().UntagPeer(p, memberTag)
		r.Host.Peerstore().UpdateAddrs(p, r.reservationTTL(), 0)
	}
	if r.DHT != nil {
		r.DHT.RoutingTable().RemovePeer(p)
	}
}

// AdmittedUntil reports when this router's admission of p lapses: the
// expiry of the biscuit p last presented on the auth handshake. A peer that
// never authenticated, or whose admission has lapsed, is not admitted.
func (r *Router) AdmittedUntil(p peer.ID) (until time.Time, admitted bool) {
	v, ok := r.authenticatedPeers.Load(p)
	if !ok {
		return time.Time{}, false
	}
	exp, isTime := v.(time.Time)
	return exp, isTime && time.Now().Before(exp)
}

// credential is the router's own mesh identity as the control plane issued
// it. issuedUnder is the trusted key set at issuance: a trusted key outside
// it is a rotation the biscuit predates, so the biscuit must be refreshed
// before that key's predecessor leaves its grace period. It is nil until the
// first /keys sync after enrollment pins it, since enrollment hands out one
// key and the sync learns the rest.
type credential struct {
	biscuit     []byte
	expiration  time.Time
	issuedUnder []ed25519.PublicKey
}

// newCredential builds the router's credential; an unset expire_time is an
// expired credential, so a control plane that sent none forces a refresh.
func newCredential(biscuit []byte, expireTime *timestamppb.Timestamp, issuedUnder []ed25519.PublicKey) credential {
	var expiration time.Time
	if expireTime != nil {
		expiration = expireTime.AsTime()
	}
	return credential{
		biscuit:     biscuit,
		expiration:  expiration,
		issuedUnder: append([]ed25519.PublicKey(nil), issuedUnder...),
	}
}

// pin records trusted as the issuance set of a biscuit that has none yet.
func (c *credential) pin(trusted []ed25519.PublicKey) {
	if len(c.biscuit) > 0 && c.issuedUnder == nil {
		c.issuedUnder = append([]ed25519.PublicKey(nil), trusted...)
	}
}

// predatesRotation reports whether trusted holds a key unknown at issuance.
func (c credential) predatesRotation(trusted []ed25519.PublicKey) bool {
	return len(c.biscuit) > 0 && c.issuedUnder != nil && !subsetOf(trusted, c.issuedUnder)
}

func subsetOf(keys, set []ed25519.PublicKey) bool {
	for _, key := range keys {
		known := false
		for _, candidate := range set {
			if key.Equal(candidate) {
				known = true
				break
			}
		}
		if !known {
			return false
		}
	}
	return true
}

// Router represents a libp2p bootstrap/relay node.
type Router struct {
	config             Options
	Host               host.Host
	DHT                *dht.IpfsDHT
	PubSub             *pubsub.PubSub
	EventTopic         *pubsub.Topic
	authenticatedPeers sync.Map
	// credentials is the credential each admitted member presented, as
	// memberCredential, for what the directory checks against it.
	credentials sync.Map
	// policy is the mesh policy as the control plane renders it
	// (PolicyConfigGetResponse.datalog_rules), what a member's credential is
	// evaluated with besides its own facts; nil until the first sync.
	policy      atomic.Pointer[meshPolicy]
	bannedPeers sync.Map
	// directory is how the mesh keeps its directory, read from /info at
	// start (syncDirectory); records is the records this router holds.
	directory api.DirectorySettings
	records   *recordStore
	// peerRouters is the other routers of the mesh, as /info lists them or as
	// a handshake proved them: held whatever the load and never sent away.
	peerRouters sync.Map
	// gated is the host the DHT, gossip and the directory run on: it serves
	// and reaches authenticated peers only (authGate).
	gated *authGate
	// listedRouters is the peer routers the control plane listed on the
	// last federation pass (*[]peer.AddrInfo), for ensureFederated.
	listedRouters  atomic.Value
	lastFederation atomic.Int64
	federateMu     sync.Mutex
	// handshakeLimiter bounds /mesh/auth attempts per peer; any internet peer
	// can open those streams.
	handshakeLimiter *ratelimit.PeerRateLimiter

	// trustedPublicKeys is what the control plane signs with now, the set
	// every peer credential is verified against; credential is this
	// router's own. Both are guarded by keysMu.
	trustedPublicKeys []ed25519.PublicKey
	credential        credential
	keysMu            sync.RWMutex
	enrollMu          sync.Mutex
	privKey           crypto.PrivKey
	// refreshMu serializes credential issuance: the control plane redeems
	// only the last biscuit it issued.
	refreshMu sync.Mutex

	// syncTrigger asks the control plane sync loop for a pass now; a mesh
	// event sends on it.
	syncTrigger chan struct{}

	// Control contexts
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	isReady  atomic.Bool
	shutdown atomic.Bool

	metricsServer *http.Server
	metricsAddr   net.Addr

	ingressServer  *http.Server
	ingressAddr    net.Addr
	ingressLimiter *ratelimit.PeerRateLimiter

	revokedTokens revocationSet

	// identityLoggedAt is when the "Router Online" line was last written.
	identityLoggedAt atomic.Pointer[time.Time]
	// leasedAddrs is the address list of the last accepted lease, joined.
	leasedAddrs    atomic.Pointer[string]
	authFailureLog perPeerLogLimiter
}

// NewRouter initializes the router.
func NewRouter(ctx context.Context, config Options) (*Router, error) {
	config.Default()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)

	handshakeLimiter, err := ratelimit.NewPeerRateLimiter(handshakeLimiterSize)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create handshake rate limiter: %w", err)
	}
	ingressLimiter, err := ratelimit.NewPeerRateLimiterWithRate(handshakeLimiterSize, ingressRateLimitPerIP, ingressRateBurstPerIP)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create ingress rate limiter: %w", err)
	}

	return &Router{
		config:           config,
		ctx:              ctx,
		cancel:           cancel,
		handshakeLimiter: handshakeLimiter,
		ingressLimiter:   ingressLimiter,
		syncTrigger:      make(chan struct{}, 1),
	}, nil
}

// transportOptions mirrors libp2p.DefaultTransports, attaching the HTTP
// fallback handler to the WebSocket transport in single-port mode. The
// explicit list is required because combining DefaultTransports with an
// extra Transport(websocket.New, ...) registers the WS transport twice and
// fails host construction.
func (r *Router) transportOptions() libp2p.Option {
	if r.config.HTTPFallbackHandler == nil {
		return libp2p.DefaultTransports
	}
	return libp2p.ChainOptions(
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(ws.New, ws.WithHTTPHandler(r.config.HTTPFallbackHandler)),
		libp2p.Transport(libp2pwebtransport.New),
		libp2p.Transport(libp2pwebrtc.New),
	)
}

// Start performs enrollment, syncs keys, launches libp2p host, and starts tasks.
func (r *Router) Start() (retErr error) {
	defer func() {
		if retErr != nil {
			_ = r.Close()
		}
	}()

	// The operator listener comes up first so /healthz answers while
	// enrollment is still in flight; /readyz turns 200 at the end.
	if r.config.MetricsAddr != "" {
		if err := r.serveMetrics(r.config.MetricsAddr); err != nil {
			return fmt.Errorf("failed to start metrics listener: %w", err)
		}
	}

	// 1. Load or Generate persistent identity key
	priv, err := getOrGeneratePeerKey(r.config.KeysDBPath)
	if err != nil {
		return fmt.Errorf("failed to load/generate peer identity: %w", err)
	}
	r.privKey = priv

	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return err
	}

	if err := r.enrollWithTokens(peerID); err != nil {
		if strings.Contains(err.Error(), "no enrollment token available") {
			logger.Warn("Router started without OIDCToken or BootstrapToken. Enrollment bypassed. Expecting local keys sync.")
		} else {
			return err
		}
	}

	// 3. Initial Keys Sync
	if err := r.syncKeys(); err != nil {
		return fmt.Errorf("failed initial keys sync: %w", err)
	}
	if err := r.syncDirectory(); err != nil {
		return err
	}

	// 4. Initialize libp2p host
	cm, err := connmgr.NewConnManager(r.config.LowWaterMark, r.config.HighWaterMark, connmgr.WithGracePeriod(ConnGracePeriod))
	if err != nil {
		return fmt.Errorf("failed to create connection manager: %w", err)
	}

	p2pOpts := []libp2p.Option{
		libp2p.Identity(r.privKey),
		r.transportOptions(),
		libp2p.ListenAddrStrings(r.config.ListenAddrs...),
		// TLS first: Go peers and the Node/Python SDKs land on it. Noise is
		// what a browser can speak; both bind the connection to the peer ID.
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.ConnectionManager(cm),
		libp2p.ConnectionGater(&routerConnGate{r: r}),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableNATService(),
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			var filtered []multiaddr.Multiaddr
			for _, addr := range addrs {
				if isLinkLocal(addr) {
					continue
				}
				if !r.config.AllowLoopback && isLoopbackOrLinkLocal(addr) {
					continue
				}
				filtered = append(filtered, addr)
			}
			return filtered
		}),
	}

	// Every refusal the resource manager makes is counted and logged with
	// its source; a refused dialer only sees its connection close before TLS.
	mgr, err := p2plimits.New(hubLimits(r.config.HighWaterMark, r.config.ConnsPerSourceIP, r.config.RelayMaxCircuits), r.config.ConnsPerSourceIP, inboundRefusedTotal, logger.Warnf, rcmgr.WithMetrics(countStreamRefusals()))
	if err != nil {
		return fmt.Errorf("failed to create resource manager: %w", err)
	}
	p2pOpts = append(p2pOpts, libp2p.ResourceManager(mgr))

	hostNode, err := libp2p.New(p2pOpts...)
	if err != nil {
		return err
	}
	r.Host = hostNode
	// The DHT, gossip and the directory serve, and are served by,
	// authenticated peers only.
	gated := &authGate{Host: hostNode, r: r}
	r.gated = gated

	// Setup DHT
	kadDHT, err := dht.New(gated, r.dhtOptions()...)
	if err != nil {
		return err
	}
	r.DHT = kadDHT
	r.records = newRecordStore(r.directory.RecordTTL)

	if err = kadDHT.Bootstrap(r.ctx); err != nil {
		return err
	}

	// Setup Relay. Its counters (reservations, circuits, refusals by
	// status) go to the default registry the metrics listener serves.
	_, err = relay.New(hostNode, relay.WithACL(&relayACL{r: r}),
		relay.WithResources(relayResources(r.config.RelayMaxReservations, r.config.RelayMaxCircuits, r.config.ConnsPerSourceIP)),
		relay.WithLimit(relayLimit(r.config.RelayLimitDuration, r.config.RelayLimitData)),
		relay.WithMetricsTracer(relay.NewMetricsTracer()))
	if err != nil {
		return err
	}

	// Setup PubSub. StrictSign is the default; pinned because the event
	// validator trusts msg.GetFrom().
	ps, err := pubsub.NewGossipSub(r.ctx, gated, pubsub.WithMessageSignaturePolicy(pubsub.StrictSign))
	if err != nil {
		return err
	}
	r.PubSub = ps
	// The router is the hub every node gossips through. Validating here
	// stops a junk event at the first hop instead of fanning it out to every
	// attached node, each of which would spend a verify on it.
	if err := ps.RegisterTopicValidator(api.GossipEvents, r.validateMeshEvent); err != nil {
		return fmt.Errorf("register mesh event validator: %w", err)
	}

	topic, err := ps.Join(api.GossipEvents)
	if err != nil {
		return err
	}
	r.EventTopic = topic

	// Setup authentication stream handler
	hostNode.SetStreamHandler(api.AuthProtocolID, recoverStreamHandler("AuthHandshake", r.HandleAuthHandshake))
	// The directory a member asks this router for, and routers place
	// records on each other through.
	gated.SetStreamHandler(api.DirectoryProtocolID, recoverStreamHandler("Directory", r.handleDirectory))

	// Clean authenticated status on peer disconnection
	hostNode.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, c network.Conn) {
			r.enforceAuthDeadline(c)
		},
		DisconnectedF: func(n network.Network, c network.Conn) {
			p := c.RemotePeer()
			if len(hostNode.Network().ConnsToPeer(p)) == 0 {
				r.forgetPeer(p)
			}
		},
	})

	if r.config.IngressAddr != "" {
		if err := r.serveIngress(r.config.IngressAddr); err != nil {
			return fmt.Errorf("failed to start ingress listener: %w", err)
		}
	}

	r.isReady.Store(true)

	// 5. Start background routines
	r.wg.Add(5)
	go r.runControlPlaneSyncLoop()
	go r.runShedLoop()
	go r.listenForControlPlaneEvents(r.ctx)
	go func() {
		defer r.wg.Done()
		r.records.runSweep(r.ctx, recordSweepInterval(r.directory.RecordTTL))
	}()
	go func() {
		defer r.wg.Done()
		p2plimits.ObserveStreamPressure(hostNode.Network().Conns, busiestConnStreams, logger.Warnf).Run(r.ctx, streamPressureInterval)
	}()

	logger.Infof("Router Online. PeerID: %s, ListenAddrs: %v", r.Host.ID(), r.Host.Addrs())
	return nil
}

func (r *Router) enroll(peerID peer.ID) error {
	pubKey := r.privKey.GetPublic()
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	client := r.controlPlaneClient(30 * time.Second)
	resp, err := cpclient.DoWithChallenge(client, time.Now, func(ts int64) (*http.Request, error) {
		sig, err := r.privKey.Sign(api.RegisterChallenge(peerID.String(), ts))
		if err != nil {
			return nil, fmt.Errorf("failed to sign registration challenge: %w", err)
		}
		req := &api.EnrollRequest{
			Jwt:                r.config.OIDCToken,
			PeerId:             peerID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      r.config.RequiredRole,
			Labels:             r.config.Labels,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		}
		data, err := proto.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(r.ctx, http.MethodPost, r.config.ControlPlaneURL+"/register", bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		return httpReq, nil
	})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := cpclient.ReadBody(resp.Body)
		return fmt.Errorf("enrollment response status %s: %s", resp.Status, string(body))
	}

	body, err := cpclient.ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("enrollment response: %w", err)
	}

	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollResp); err != nil {
		return err
	}

	r.keysMu.Lock()
	r.credential = newCredential(enrollResp.BiscuitToken, enrollResp.ExpireTime, nil)
	r.trustedPublicKeys = []ed25519.PublicKey{enrollResp.ControlPlanePublicKey}
	r.keysMu.Unlock()

	if err := identity.VerifyBiscuitRole(enrollResp.BiscuitToken, enrollResp.ControlPlanePublicKey, r.config.RequiredRole, r.config.BiscuitTimeout); err != nil {
		return fmt.Errorf("enrolled biscuit token lacks required role %q: %w", r.config.RequiredRole, err)
	}

	return nil
}

func (r *Router) enrollBootstrap(peerID peer.ID) error {
	pubKey := r.privKey.GetPublic()
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal router public key: %w", err)
	}

	client := r.controlPlaneClient(30 * time.Second)
	resp, err := cpclient.DoWithChallenge(client, time.Now, func(enrollTS int64) (*http.Request, error) {
		enrollSig, err := r.privKey.Sign(api.EnrollChallenge(peerID.String(), enrollTS))
		if err != nil {
			return nil, fmt.Errorf("failed to sign enrollment challenge: %w", err)
		}
		req := &api.BootstrapEnrollRequest{
			BootstrapToken:     r.config.BootstrapToken,
			PeerId:             peerID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      r.config.RequiredRole,
			Labels:             r.config.Labels,
			ChallengeUnixMs:    enrollTS,
			ChallengeSignature: enrollSig,
		}
		data, err := proto.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(r.ctx, http.MethodPost, r.config.ControlPlaneURL+"/enroll", bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		return httpReq, nil
	})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := cpclient.ReadBody(resp.Body)
		return fmt.Errorf("bootstrap enrollment request response status %s: %s", resp.Status, string(body))
	}

	respData, err := cpclient.ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("bootstrap enrollment response: %w", err)
	}

	enrollResp := &api.BootstrapEnrollResponse{}
	if err := proto.Unmarshal(respData, enrollResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if enrollResp.ErrorMessage != "" {
		return fmt.Errorf("enrollment failed: %s", enrollResp.ErrorMessage)
	}

	if enrollResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		logger.Infof("Enrollment is pending approval. Polling status...")

		u, err := url.Parse(r.config.ControlPlaneURL)
		if err != nil {
			return fmt.Errorf("invalid control plane URL: %w", err)
		}
		u = u.JoinPath("enroll", "status")
		q := u.Query()
		q.Set("peer_id", peerID.String())
		u.RawQuery = q.Encode()
		statusURL := u.String()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

	pollLoop:
		for {
			select {
			case <-r.ctx.Done():
				return r.ctx.Err()
			case <-ticker.C:
				// Prove possession of the enrollment key on every poll; the
				// control plane returns the biscuit only to the enrollee.
				statusResp, err := cpclient.DoWithChallenge(client, time.Now, func(ts int64) (*http.Request, error) {
					req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, statusURL, nil)
					if err != nil {
						return nil, fmt.Errorf("failed to create status request: %w", err)
					}
					if err := cpclient.SetChallengeHeaders(req, r.privKey, api.EnrollStatusChallenge(peerID.String(), ts), ts); err != nil {
						return nil, fmt.Errorf("failed to sign enrollment status challenge: %w", err)
					}
					return req, nil
				})
				if err != nil {
					logger.Warnf("failed to poll enrollment status: %v", err)
					continue
				}

				if statusResp.StatusCode != http.StatusOK {
					body, _ := cpclient.ReadBody(statusResp.Body)
					_ = statusResp.Body.Close()
					logger.Warnf("status poll returned code %s: %s", statusResp.Status, string(body))
					continue
				}

				statusBody, err := cpclient.ReadBody(statusResp.Body)
				_ = statusResp.Body.Close()
				if err != nil {
					logger.Warnf("enrollment status response: %v", err)
					continue
				}

				pollResp := &api.BootstrapEnrollResponse{}
				if err := proto.Unmarshal(statusBody, pollResp); err != nil {
					logger.Warnf("failed to unmarshal poll response: %v", err)
					continue
				}

				if pollResp.ErrorMessage != "" {
					return fmt.Errorf("enrollment rejected: %s", pollResp.ErrorMessage)
				}

				if pollResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
					enrollResp = pollResp
					break pollLoop
				}
				if pollResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
					return fmt.Errorf("enrollment rejected by administrator")
				}
				logger.Infof("Enrollment is still pending approval...")
			}
		}
	}

	if enrollResp.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
		return fmt.Errorf("enrollment not approved (status: %v)", enrollResp.Status)
	}

	r.keysMu.Lock()
	r.credential = newCredential(enrollResp.BiscuitToken, enrollResp.ExpireTime, nil)
	r.trustedPublicKeys = []ed25519.PublicKey{enrollResp.ControlPlanePublicKey}
	r.keysMu.Unlock()

	if err := identity.VerifyBiscuitRole(enrollResp.BiscuitToken, enrollResp.ControlPlanePublicKey, r.config.RequiredRole, r.config.BiscuitTimeout); err != nil {
		return fmt.Errorf("enrolled biscuit token lacks required role %q: %w", r.config.RequiredRole, err)
	}

	logger.Infof("Router bootstrap enrollment approved! Biscuit received.")
	return nil
}

func (r *Router) enrollWithTokens(peerID peer.ID) error {
	// Always read the token from disk if a path is specified to handle rotation
	if r.config.BootstrapTokenPath != "" {
		tokenData, err := os.ReadFile(r.config.BootstrapTokenPath)
		if err != nil {
			return fmt.Errorf("failed to read bootstrap token from path %s: %w", r.config.BootstrapTokenPath, err)
		}
		r.config.BootstrapToken = strings.TrimSpace(string(tokenData))
	}

	if r.config.BootstrapToken != "" {
		logger.Infof("Enrolling router %s with Control Plane at %s using Bootstrap Token...", peerID, r.config.ControlPlaneURL)
		if err := r.enrollBootstrap(peerID); err != nil {
			return fmt.Errorf("failed router bootstrap enrollment: %w", err)
		}
		return nil
	}

	// Fallback to OIDC token
	if src := r.tokenSource(); src != nil {
		tok, err := src.FetchToken(r.ctx)
		if err != nil {
			return fmt.Errorf("failed to read JWT from path %s: %w", r.config.JWTPath, err)
		}
		r.config.OIDCToken = tok
	}

	if r.config.OIDCToken != "" {
		logger.Infof("Enrolling router %s with Control Plane at %s using OIDC Token...", peerID, r.config.ControlPlaneURL)
		if err := r.enroll(peerID); err != nil {
			return fmt.Errorf("failed router enrollment: %w", err)
		}
		return nil
	}

	return fmt.Errorf("no enrollment token available")
}

func (r *Router) tokenSource() cpclient.TokenSource {
	if strings.TrimSpace(r.config.JWTPath) != "" {
		return cpclient.NewFileTokenSource(r.config.JWTPath)
	}
	return nil
}

func (r *Router) reEnroll() error {
	r.enrollMu.Lock()
	defer r.enrollMu.Unlock()

	if r.Host == nil {
		return fmt.Errorf("cannot re-enroll: router host is not initialized")
	}

	return r.enrollWithTokens(r.Host.ID())
}

// recoverAfterLease401 restores the router's standing with the control plane
// after a lease renewal was refused. A refresh goes first: it succeeds on
// proof of possession alone when the biscuit's signing key was retired and
// the operator opted this router in to autonomous recovery, and it already
// falls back to re-enrollment on a 401 of its own. Any other failure still
// ends in re-enrollment with the bootstrap token, the pre-existing contract.
func (r *Router) recoverAfterLease401() error {
	if r.privKey != nil && r.ctx != nil {
		err := r.RefreshEnrollment(r.ctx)
		if err == nil {
			return nil
		}
		logger.Warnf("Refresh after lease 401 failed (%v), re-enrolling", err)
	}
	return r.reEnroll()
}

func (r *Router) syncKeys() error {
	// Only a set signed by a key this router already trusts may replace
	// the trust set; anything else is whoever answered the URL.
	newKeys, err := r.controlPlane(10*time.Second).FetchKeys(r.ctx, r.getTrustedPublicKeys())
	if err != nil {
		return err
	}

	r.keysMu.Lock()
	changed := !samePublicKeys(r.trustedPublicKeys, newKeys)
	r.trustedPublicKeys = newKeys
	r.credential.pin(newKeys)
	refresh := r.credential.predatesRotation(newKeys)
	r.keysMu.Unlock()
	if changed {
		// The set a member's credential is verified against; a refusal
		// with "no valid key found" is read against this line.
		fps := make([]string, 0, len(newKeys))
		for _, k := range newKeys {
			sum := sha256.Sum256(k)
			fps = append(fps, hex.EncodeToString(sum[:8]))
		}
		logger.Infow("Control plane signing keys changed", "keys", len(newKeys), "fingerprints", fps, "credential_refresh", refresh)
	}

	if refresh {
		if err := r.RefreshEnrollment(r.ctx); err != nil {
			return fmt.Errorf("refresh enrollment after key rotation: %w", err)
		}
	}

	logger.Debugf("Synced %d valid public keys from control plane", len(newKeys))
	return nil
}

// controlPlane reads the pull endpoints of the control plane.
func (r *Router) controlPlane(timeout time.Duration) *cpclient.Client {
	c := cpclient.New(r.config.ControlPlaneURL, r.controlPlaneClient(timeout))
	if r != nil && r.privKey != nil {
		var pid peer.ID
		if r.Host != nil && r.Host.ID() != "" {
			pid = r.Host.ID()
		} else {
			pid, _ = peer.IDFromPrivateKey(r.privKey)
		}
		if pid != "" {
			c.WithIdentity(pid.String(), r.privKey)
		}
	}
	return c
}

// controlPlaneClient is the client for every request to the control plane;
// its transport re-checks the plaintext policy on each hop, redirects included.
func (r *Router) controlPlaneClient(timeout time.Duration) *http.Client {
	return cpclient.NewHTTPClient(timeout, func() bool { return r.config.AllowInsecureControlPlane }, "agentmesh-router")
}

func (r *Router) getTrustedPublicKeys() []ed25519.PublicKey {
	r.keysMu.RLock()
	defer r.keysMu.RUnlock()
	return append([]ed25519.PublicKey(nil), r.trustedPublicKeys...)
}

func (r *Router) verifyEvent(event *api.MeshEvent) bool {
	sig := event.Signature
	event.Signature = nil
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	event.Signature = sig
	if err != nil {
		logger.Errorf("[Router Event] Failed to marshal event for verification: %v", err)
		return false
	}

	keys := r.getTrustedPublicKeys()
	for _, pubKey := range keys {
		if len(pubKey) == ed25519.PublicKeySize && ed25519.Verify(pubKey, data, sig) {
			return true
		}
	}
	return false
}

// meshEventFreshness bounds how far an event's timestamp may be from now
// before it is treated as a replay (or a clock the router cannot trust).
const meshEventFreshness = 5 * time.Minute

// validateMeshEvent is the GossipSub validator for api.GossipEvents: reject
// (drop and do not forward) anything undecodable or not signed by a trusted
// control plane, ignore anything stale.
func (r *Router) validateMeshEvent(_ context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	var event api.MeshEvent
	if err := proto.Unmarshal(msg.Data, &event); err != nil {
		logger.Warnf("[Router Event] Rejecting undecodable event from %s", from)
		return pubsub.ValidationReject
	}
	if !r.verifyEvent(&event) {
		logger.Warnf("[Router Event] Potential spoofing attempt: invalid signature on event from %s", from)
		return pubsub.ValidationReject
	}
	if event.EventTime == nil {
		logger.Warnf("[Router Event] Dropping event without event_time from %s", from)
		return pubsub.ValidationReject
	}
	eventTime := event.EventTime.AsTime()
	if time.Since(eventTime) > meshEventFreshness || time.Until(eventTime) > meshEventFreshness {
		logger.Warnf("[Router Event] Dropping stale or future event from %s", from)
		return pubsub.ValidationIgnore
	}
	return pubsub.ValidationAccept
}

func (r *Router) listenForControlPlaneEvents(ctx context.Context) {
	defer r.wg.Done()
	if r.EventTopic == nil {
		return
	}
	sub, err := r.EventTopic.Subscribe()
	if err != nil {
		logger.Errorf("[Router Event] Failed to subscribe to GossipEvents topic: %v", err)
		return
	}
	defer sub.Cancel()

	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return
		}

		// validateMeshEvent already rejected anything unsigned or stale.
		var event api.MeshEvent
		if err := proto.Unmarshal(msg.Data, &event); err != nil {
			logger.Errorf("[Router Event] Failed to unmarshal event from %s: %v", msg.ReceivedFrom, err)
			continue
		}

		switch event.Type {
		case api.MeshEvent_BANNED:
			if event.PeerId != "" {
				if bannedPeer, err := peer.Decode(event.PeerId); err == nil {
					logger.Infof("[Router Event] Received BANNED event for peer %s, evicting from authenticated peers and adding to blocklist", bannedPeer)
					r.forgetPeer(bannedPeer)
					r.records.removePeer(bannedPeer)
					// The timestamp is what stops an /info answer that was
					// already in flight from undoing this (see
					// reconcileBannedPeers).
					r.bannedPeers.Store(bannedPeer, time.Now())
					if r.Host != nil {
						_ = r.Host.Network().ClosePeer(bannedPeer)
					}
				}
			}
		case api.MeshEvent_KEY_ROTATION:
			logger.Infof("[Router Event] Received KEY_ROTATION event, triggering control plane sync")
			r.triggerSync()
		case api.MeshEvent_POLICY_UPDATE:
			logger.Infof("[Router Event] Received POLICY_UPDATE event, triggering control plane sync")
			r.triggerSync()
		}
	}
}

func (r *Router) triggerSync() {
	select {
	case r.syncTrigger <- struct{}{}:
	default:
	}
}

// runControlPlaneSyncLoop is the router's one conversation with the control
// plane. Every ControlPlaneSyncInterval, and at once on a mesh event, a pass
// re-reads /keys, renews the lease, re-reads /info (the routers to federate
// with and the ban set), re-reads /policies and refreshes the router's own
// credential when it nears expiry. Between passes, while a listed router is
// not yet authenticated, the federation step alone is retried every
// federationCatchUp, so a router that cannot be reached costs the control
// plane nothing beyond the pass.
func (r *Router) runControlPlaneSyncLoop() {
	defer r.wg.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	var lastPass time.Time
	for {
		now := false
		select {
		case <-timer.C:
		case <-r.syncTrigger:
			now = true
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-r.ctx.Done():
			return
		}
		if now || time.Since(lastPass) >= r.config.ControlPlaneSyncInterval {
			r.syncControlPlane()
			lastPass = time.Now()
		} else {
			r.connectBootstrapRouters()
		}
		next := r.config.ControlPlaneSyncInterval - time.Since(lastPass)
		if listed, authenticated := r.peerRouterCounts(); authenticated < listed && federationCatchUp < next {
			next = federationCatchUp
		}
		timer.Reset(max(next, 0))
	}
}

// syncControlPlane is one pass of the sync loop. Keys come first: a lease
// or a policy read presented with a credential the control plane no longer
// signs for is refused until the rotation is learned and the credential
// refreshed (syncKeys).
func (r *Router) syncControlPlane() {
	if err := r.syncKeys(); err != nil && r.ctx.Err() == nil {
		logger.Errorf("Failed keys sync: %v", err)
	}
	r.renewLease()
	r.connectBootstrapRouters()
	if err := r.syncPolicy(); err != nil && r.ctx.Err() == nil {
		logger.Errorf("Failed policy sync: %v", err)
	}
	if err := r.syncRevocations(); err != nil && r.ctx.Err() == nil {
		logger.Errorf("Failed revocations sync: %v", err)
	}
	r.refreshExpiringCredential()
}

func (r *Router) syncRevocations() error {
	r.keysMu.RLock()
	tok := r.credential.biscuit
	r.keysMu.RUnlock()
	if len(tok) == 0 {
		return nil
	}
	fetchedAt := time.Now()
	resp, err := r.controlPlane(10*time.Second).FetchRevocations(r.ctx, tok)
	if errors.Is(err, cpclient.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	expiry := fetchedAt.Add(24 * time.Hour)
	for _, revID := range resp.GetRevocationIds() {
		r.recordRevokedBiscuitID(revID, expiry)
	}
	r.credentials.Range(func(k, v any) bool {
		pid, ok := k.(peer.ID)
		cred, credOK := v.(memberCredential)
		if ok && credOK && r.isBiscuitRevoked(cred.biscuit) {
			logger.Infof("[Revocations] Evicting peer %s with revoked biscuit", pid)
			r.forgetPeer(pid)
			if r.records != nil {
				r.records.removePeer(pid)
			}
			if r.Host != nil {
				_ = r.Host.Network().ClosePeer(pid)
			}
		}
		return true
	})
	if len(resp.GetBannedPeerIds()) > 0 {
		r.reconcileBannedPeers(resp.GetBannedPeerIds(), fetchedAt)
	}
	return nil
}

const revokedPruneMin = 64

// revocationSet holds active revoked Biscuit authority revocation IDs synced
// from the control plane. Entries expire by timestamp and are never evicted by
// capacity, so high-churn revocation cannot push live revocations out of the
// deny list. Zero-value safe for test routers constructed as &Router{}.
type revocationSet struct {
	mu      sync.Mutex
	entries map[string]time.Time
	pruneAt int
}

func normalizeRevocationKey(revID string) string {
	revID = strings.TrimSpace(revID)
	if revID == "" {
		return ""
	}
	if (len(revID) == 64 || len(revID) == 128) && isHexDigits(revID) {
		if raw, err := hex.DecodeString(revID); err == nil && len(raw) > 0 {
			return base64.RawURLEncoding.EncodeToString(raw)
		}
	}
	return revID
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isHexDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

func (s *revocationSet) add(revID string, expiry time.Time) {
	key := normalizeRevocationKey(revID)
	if key == "" {
		return
	}
	now := time.Now()
	if !now.Before(expiry) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[string]time.Time)
	}
	if len(s.entries) >= max(revokedPruneMin, s.pruneAt) {
		for k, exp := range s.entries {
			if !now.Before(exp) {
				delete(s.entries, k)
			}
		}
		s.pruneAt = max(revokedPruneMin, 2*len(s.entries))
	}
	if existing, ok := s.entries[key]; !ok || expiry.After(existing) {
		s.entries[key] = expiry
	}
}

func (s *revocationSet) isRevoked(b *biscuit.Biscuit, now time.Time) bool {
	if s == nil || b == nil {
		return false
	}
	ids := b.RevocationIds()
	if len(ids) == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 {
		return false
	}
	for _, id := range ids {
		key := base64.RawURLEncoding.EncodeToString(id)
		if exp, ok := s.entries[key]; ok {
			if now.Before(exp) {
				return true
			}
			delete(s.entries, key)
		}
	}
	return false
}

func (s *revocationSet) activeCount(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, exp := range s.entries {
		if now.Before(exp) {
			n++
		} else {
			delete(s.entries, k)
		}
	}
	return n
}

func (r *Router) recordRevokedBiscuitID(revID string, expiry time.Time) {
	if r == nil {
		return
	}
	r.revokedTokens.add(revID, expiry)
}

func (r *Router) isBiscuitRevoked(b *biscuit.Biscuit) bool {
	if r == nil || b == nil {
		return false
	}
	return r.revokedTokens.isRevoked(b, time.Now())
}

// refreshExpiringCredential refreshes the router's own credential once less
// than a fifth of its lifetime is left, so a credential is never presented
// close to its expiry.
func (r *Router) refreshExpiringCredential() {
	r.keysMu.RLock()
	expiration := r.credential.expiration
	r.keysMu.RUnlock()
	if expiration.IsZero() || time.Until(expiration) >= api.BiscuitTokenTTL/5 {
		return
	}
	logger.Infof("Router biscuit expiring in %v, triggering proactive refresh...", time.Until(expiration))
	if err := r.RefreshEnrollment(r.ctx); err != nil {
		logger.Errorf("Proactive router biscuit refresh failed: %v", err)
	}
}

// syncPolicy replaces the mesh policy rules with what the control plane
// renders now. The text is the contract: the router adds it to the
// authorizer and derives nothing from roles and bindings itself.
func (r *Router) syncPolicy() error {
	r.keysMu.RLock()
	biscuit := r.credential.biscuit
	r.keysMu.RUnlock()
	if len(biscuit) == 0 {
		return errors.New("router has no credential yet")
	}
	resp, err := r.controlPlane(10*time.Second).FetchPolicy(r.ctx, biscuit)
	if err != nil {
		return err
	}
	if len(resp.ProtoReflect().GetUnknown()) > 0 {
		return fmt.Errorf("control plane %s predates datalog_rules in its policy response; upgrade the control plane", r.config.ControlPlaneURL)
	}
	rules, err := api.ParseDatalogRules(resp.DatalogRules)
	if err != nil {
		return fmt.Errorf("mesh policy carries an unparseable rule: %w", err)
	}
	before := r.policy.Swap(&meshPolicy{rules: rules, texts: resp.DatalogRules})
	if before == nil || !slices.Equal(before.texts, resp.DatalogRules) {
		logger.Infof("Synced mesh policy (%d rules)", len(rules))
	} else {
		logger.Debugf("Synced mesh policy (%d rules, unchanged)", len(rules))
	}
	return nil
}

// meshPolicy is one synced rendering of the mesh policy: the rules the
// authorizer runs and the text they were parsed from, to tell a change.
type meshPolicy struct {
	rules []biscuit.Rule
	texts []string
}

// meshPolicyRules is the mesh policy as last synced; empty before the first
// sync, when only a credential's own facts decide.
func (r *Router) meshPolicyRules() []biscuit.Rule {
	if p := r.policy.Load(); p != nil {
		return p.rules
	}
	return nil
}

// renewLease extends the lease for the control plane's duration. Once the
// router is shutting down it does nothing: the withdrawal sent by Close is
// the last word, and a renewal racing it would re-advertise a router that
// is leaving.
func (r *Router) renewLease() {
	if r.shutdown.Load() {
		return
	}
	r.sendLease(r.ctx, nil, 2)
}

// withdrawLease is the router's last lease before it stops: one with the
// ttl the operator set for a shutdown, so the control plane keeps the
// router listed for as long as it expects to be away and no longer. Off
// when the ttl is zero. Its own context, since Close cancels the router's;
// a failure only means the lease expires as it always did.
func (r *Router) withdrawLease() {
	if r.config.ShutdownLeaseTTL <= 0 || r.Host == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ttl := r.config.ShutdownLeaseTTL
	logger.Infof("Withdrawing router lease (ttl %s)", ttl)
	r.sendLease(ctx, &ttl, 1)
}

// sendLease posts one lease to the control plane: the router's addresses
// and telemetry under proof of possession of its key, and the ttl it asks
// for when ttl is not nil. attempts allows one retry after a 401 for the
// credential recovery the renewal loop relies on.
func (r *Router) sendLease(ctx context.Context, ttl *time.Duration, attempts int) {
	for attempt := 0; attempt < attempts; attempt++ {
		r.keysMu.RLock()
		biscuit := r.credential.biscuit
		r.keysMu.RUnlock()

		if len(biscuit) == 0 {
			logger.Warn("Cannot renew lease: router is not enrolled (no biscuit)")
			return
		}

		var addrs []string
		for _, addr := range r.advertisedAddrs() {
			addrs = append(addrs, addr.String()+"/p2p/"+r.Host.ID().String())
		}

		var connectedPeers []string
		var inbound int32
		if r.Host != nil && r.Host.Network() != nil {
			for _, p := range r.Host.Network().Peers() {
				connectedPeers = append(connectedPeers, p.String())
			}
			for _, c := range r.Host.Network().Conns() {
				if c.Stat().Direction == network.DirInbound {
					inbound++
				}
			}
		}
		var dhtSize int32
		if r.DHT != nil && r.DHT.RoutingTable() != nil {
			dhtSize = int32(r.DHT.RoutingTable().Size())
		}

		// The biscuit identifies us; the signature proves it is us (peers we
		// authenticate hold a copy of the biscuit).
		client := r.controlPlaneClient(10 * time.Second)
		resp, err := cpclient.DoWithChallenge(client, time.Now, func(ts int64) (*http.Request, error) {
			sig, err := r.privKey.Sign(api.RouterLeaseChallenge(r.Host.ID().String(), ts))
			if err != nil {
				return nil, fmt.Errorf("failed to sign lease challenge: %w", err)
			}
			req := &api.RouterLeaseRequest{
				PeerId:             r.Host.ID().String(),
				Addresses:          addrs,
				Biscuit:            biscuit,
				ConnectedPeers:     connectedPeers,
				DhtSize:            dhtSize,
				ChallengeUnixMs:    ts,
				ChallengeSignature: sig,
				Connections:        inbound,
				ConnectionLimit:    int32(r.config.HighWaterMark),
				IngressUrl:         r.leasedIngressURL(),
			}
			if ttl != nil {
				req.Ttl = durationpb.New(*ttl)
			}
			data, err := proto.Marshal(req)
			if err != nil {
				return nil, err
			}
			httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.config.ControlPlaneURL+"/routers/lease", bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			httpReq.Header.Set("Content-Type", "application/x-protobuf")
			return httpReq, nil
		})
		if err != nil {
			logger.Errorf("Failed to renew lease with control plane: %v", err)
			leaseRenewalsTotal.WithLabelValues(leaseUnreachable).Inc()
			return
		}

		body, readErr := cpclient.ReadBody(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			logger.Errorf("Control plane lease renewal response: %v", readErr)
			leaseRenewalsTotal.WithLabelValues(leaseRejected).Inc()
			return
		}

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 && attempts > 1 {
			logger.Warnf("Control plane lease renewal rejected (401 Unauthorized: %s), attempting recovery...", string(body))
			leaseRenewalsTotal.WithLabelValues(leaseUnauthorized).Inc()
			if err := r.recoverAfterLease401(); err != nil {
				logger.Errorf("Recovery failed after 401 Unauthorized lease renewal: %v", err)
				return
			}
			logger.Info("Successfully recovered after 401 Unauthorized lease renewal, retrying lease renewal...")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			logger.Errorf("Control plane lease renewal rejected, status %s: %s", resp.Status, string(body))
			leaseRenewalsTotal.WithLabelValues(leaseRejected).Inc()
			return
		}

		var leaseResp api.RouterLeaseResponse
		if err := proto.Unmarshal(body, &leaseResp); err != nil {
			logger.Errorf("Failed to parse lease response: %v", err)
			leaseRenewalsTotal.WithLabelValues(leaseRejected).Inc()
			return
		}

		if !leaseResp.Success {
			logger.Errorf("Lease renewal failed: %s", leaseResp.Error)
			leaseRenewalsTotal.WithLabelValues(leaseRejected).Inc()
		} else {
			logger.Debugf("Lease renewed successfully. Expires at: %s", leaseResp.GetExpireTime().AsTime().Format(time.RFC3339))
			leaseRenewalsTotal.WithLabelValues(leaseOK).Inc()
			r.logLeasedAddrs(addrs)
			r.logIdentityPeriodically()
		}
		return
	}
}

// logLeasedAddrs writes the addresses the control plane now lists for this
// router each time they differ from the last lease: members and peer routers
// reach the router only through these, and a lease without any leaves it
// listed but unreachable.
func (r *Router) logLeasedAddrs(addrs []string) {
	joined := strings.Join(addrs, ",")
	if last := r.leasedAddrs.Swap(&joined); last != nil && *last == joined {
		return
	}
	if len(addrs) == 0 {
		logger.Warn("Lease advertises no addresses: the control plane lists this router but nothing can reach it")
		return
	}
	logger.Infof("Lease advertises %d address(es): %v", len(addrs), addrs)
}

// identityLogInterval is how often the router restates who it is. Container
// logs rotate, and the startup line is the first to go; an operator reading
// the log should still find the peer ID within the last hour of it.
const identityLogInterval = time.Hour

func (r *Router) logIdentityPeriodically() {
	now := time.Now()
	if last := r.identityLoggedAt.Load(); last != nil && now.Sub(*last) < identityLogInterval {
		return
	}
	r.identityLoggedAt.Store(&now)
	logger.Infof("Router Online. PeerID: %s, ListenAddrs: %v, ConnectedPeers: %d", r.Host.ID(), r.Host.Addrs(), len(r.Host.Network().Peers()))
}

// reconcileBannedPeers replaces the local blocklist with the control plane's
// ban set. It is a replacement rather than a merge: the control plane can
// unban a peer, and there is no event for that, so a peer that has dropped off
// the list has to drop out of the blocklist too.
//
// fetchedAt is when the request that produced peerIDs was issued, and it is
// what makes the replacement safe. A ban is written to the control plane's
// database before MeshEvent_BANNED is published, so a response *issued after*
// the ban is guaranteed to carry it, and its absence really does mean
// unbanned. A response issued before the ban cannot say anything about it, so
// bans recorded at or after fetchedAt are left alone -- otherwise an /info
// still in flight when an event arrived would immediately undo it, which is a
// race the router hits on startup, where the first poll overlaps live gossip.
//
// The boundary is inclusive because the answer has to be strictly newer than
// the ban to speak to it. A clock coarse enough to time the fetch and the ban
// in the same tick -- Windows readily does -- otherwise reads a simultaneous
// ban as the older of the two and drops it.
func (r *Router) reconcileBannedPeers(peerIDs []string, fetchedAt time.Time) {
	banned := make(map[peer.ID]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		p, err := peer.Decode(id)
		if err != nil {
			logger.Warnf("[Federation] Ignoring undecodable banned peer ID %q: %v", id, err)
			continue
		}
		banned[p] = struct{}{}
	}

	// Drop bans the control plane no longer holds, except any that landed at
	// or after the moment this answer was asked for.
	r.bannedPeers.Range(func(key, value any) bool {
		p, ok := key.(peer.ID)
		if !ok {
			return true
		}
		if _, still := banned[p]; still {
			return true
		}
		if bannedAt, ok := value.(time.Time); ok && !bannedAt.Before(fetchedAt) {
			return true
		}
		logger.Infof("[Federation] Peer %s is no longer banned, removing from blocklist", p)
		r.bannedPeers.Delete(p)
		return true
	})

	// Apply the ones it does, evicting anything already admitted.
	for p := range banned {
		if _, already := r.bannedPeers.Load(p); already {
			continue
		}
		logger.Infof("[Federation] Peer %s is banned, adding to blocklist", p)
		r.bannedPeers.Store(p, fetchedAt)
		r.forgetPeer(p)
		r.records.removePeer(p)
		if r.Host != nil {
			_ = r.Host.Network().ClosePeer(p)
		}
	}
}

// federationCatchUp is how often the sync loop retries the federation step
// alone while the control plane's list names a router this one has not
// authenticated with yet, which it does at start, when the other routers
// started at the same moment and leased after this one's first pass, and
// whenever a router joins.
const federationCatchUp = 2 * time.Second

func (r *Router) connectBootstrapRouters() {
	// Taken before the request: anything banned after this point cannot be
	// reflected in the answer, so reconciliation must not read its absence as
	// an unban (see reconcileBannedPeers).
	fetchedAt := time.Now()
	info, err := r.controlPlane(10 * time.Second).FetchInfo(r.ctx)
	if err != nil {
		logger.Errorf("[Federation] Failed to fetch router info: %v", err)
		return
	}

	// /info carries the whole ban set, so this is also where a router that
	// restarted or missed a MeshEvent_BANNED catches up.
	r.reconcileBannedPeers(info.GetBannedPeerIds(), fetchedAt)

	listed := map[peer.ID]bool{}
	var listedInfos []peer.AddrInfo
	for _, addrStr := range info.RouterAddresses {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			logger.Warnf("[Federation] Ignoring router address %q: %v", addrStr, err)
			continue
		}

		resolvedAddrs, err := madns.DefaultResolver.Resolve(r.ctx, ma)
		if err != nil {
			resolvedAddrs = []multiaddr.Multiaddr{ma}
		}

		for _, resolved := range resolvedAddrs {
			pi, err := peer.AddrInfoFromP2pAddr(resolved)
			if err != nil {
				logger.Warnf("[Federation] Ignoring router address %s: %v", resolved, err)
				continue
			}
			if pi.ID == r.Host.ID() {
				continue
			}
			listed[pi.ID] = true
			listedInfos = append(listedInfos, *pi)
			r.peerRouters.Store(pi.ID, true)
			r.Host.ConnManager().Protect(pi.ID, federationTag)
			if r.isPeerAuthenticated(pi.ID) {
				// Already admitted; make sure the table has it. kad-dht
				// drops a peer its filter refused, and a router that
				// authenticated while that was being decided would
				// otherwise stay out of the table until it authenticated
				// again.
				r.admitPeerRouter(pi.ID)
				continue
			}
			r.authenticatePeerRouter(*pi)
		}
	}
	r.listedRouters.Store(&listedInfos)
	r.lastFederation.Store(time.Now().UnixNano())
	r.forgetUnlistedRouters(listed)
}

// federationStaleAfter is how old the last federation pass may be before
// a directory lookup that found nothing runs one of its own: a router that
// leased since may hold the record.
const federationStaleAfter = time.Second

// refederateIfStale runs a federation pass when the last one is older than
// federationStaleAfter, one at a time, and reports whether one ran. A
// lookup that found nothing calls it before trying once more.
func (r *Router) refederateIfStale() bool {
	if time.Since(time.Unix(0, r.lastFederation.Load())) < federationStaleAfter {
		return false
	}
	r.federateMu.Lock()
	defer r.federateMu.Unlock()
	if time.Since(time.Unix(0, r.lastFederation.Load())) < federationStaleAfter {
		return true
	}
	logger.Infof("[Federation] A lookup found nothing; reading the control plane's router list again")
	r.connectBootstrapRouters()
	return true
}

// ensureFederated authenticates with every listed peer router this router
// has not authenticated with yet, at once, and returns when they are done
// or ctx ends. The federation pass does the same every 30 seconds; a
// directory request runs it first, so a lookup right after a router
// started, or right after another router joined, reaches every router's
// records instead of the ones in a table that is still filling. One run
// at a time: a second caller waits for the first.
func (r *Router) ensureFederated(ctx context.Context) {
	listed, _ := r.listedRouters.Load().(*[]peer.AddrInfo)
	if listed == nil {
		return
	}
	var missing []peer.AddrInfo
	for _, pi := range *listed {
		if !r.isPeerAuthenticated(pi.ID) {
			missing = append(missing, pi)
		}
	}
	if len(missing) == 0 {
		return
	}
	r.federateMu.Lock()
	defer r.federateMu.Unlock()
	logger.Infof("[Federation] %d listed router(s) not authenticated yet; authenticating before serving the directory", len(missing))
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for _, pi := range missing {
			if r.isPeerAuthenticated(pi.ID) {
				continue
			}
			wg.Add(1)
			go func(pi peer.AddrInfo) {
				defer wg.Done()
				r.authenticatePeerRouter(pi)
			}(pi)
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// forgetUnlistedRouters drops the peer routers the control plane no longer
// lists: a router that was replaced keeps its lease until it expires and
// nothing else would ever remove it, so it would stay listed and protected
// here for the life of the process. A router that proved its role in a
// handshake but is not listed is kept while that admission lasts; its
// lease is normally visible before it handshakes.
func (r *Router) forgetUnlistedRouters(listed map[peer.ID]bool) {
	r.peerRouters.Range(func(k, _ any) bool {
		p := k.(peer.ID)
		if listed[p] || r.isPeerAuthenticated(p) {
			return true
		}
		logger.Infof("[Federation] Peer router %s is no longer listed by the control plane, forgetting it", p)
		r.peerRouters.Delete(p)
		r.Host.ConnManager().Unprotect(p, federationTag)
		return true
	})
}

// authenticatePeerRouter runs the mutual handshake with a router the control
// plane lists, over the connection to it if one is open (the DHT commonly
// opens one first), dialling otherwise. Authentication is what decides, not
// the connection: a connection the DHT made is not an authenticated one,
// and an admission that expired is renewed on the next pass.
func (r *Router) authenticatePeerRouter(pi peer.AddrInfo) {
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	if len(r.Host.Network().ConnsToPeer(pi.ID)) == 0 {
		logger.Infof("[Federation] Connecting to peer router: %s via %v", pi.ID, pi.Addrs)
		if err := r.Host.Connect(ctx, pi); err != nil {
			logger.Errorf("[Federation] Failed to connect to %s: %v", pi.ID, err)
			return
		}
	} else {
		logger.Infof("[Federation] Authenticating with peer router %s over its open connection", pi.ID)
	}
	s, err := r.Host.NewStream(ctx, pi.ID, api.AuthProtocolID)
	if err != nil {
		logger.Errorf("[Federation] Failed to open auth stream to %s: %v", pi.ID, err)
		return
	}
	if err := r.performMutualAuth(s); err != nil {
		logger.Errorf("[Federation] Mutual auth handshake failed with %s: %v", pi.ID, err)
		_ = s.Reset()
		return
	}
	logger.Infof("[Federation] Mutually authenticated with peer router %s", pi.ID)
	_ = s.Close()
}

// peerRouterCounts is how many peer routers this router knows, from the
// control plane's list or a handshake that proved the router role, and how
// many of those hold a current authentication.
func (r *Router) peerRouterCounts() (listed, authenticated int) {
	r.peerRouters.Range(func(k, _ any) bool {
		listed++
		if r.isPeerAuthenticated(k.(peer.ID)) {
			authenticated++
		}
		return true
	})
	return listed, authenticated
}

// recoverStreamHandler isolates a panic while processing untrusted peer bytes
// to the single stream, resetting it instead of crashing the whole router.
func recoverStreamHandler(name string, next network.StreamHandler) network.StreamHandler {
	return func(s network.Stream) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Errorf("[%s] panic recovered from peer %s: %v\n%s", name, s.Conn().RemotePeer(), rec, debug.Stack())
				_ = s.Reset()
			}
		}()
		next(s)
	}
}

// authHandshakeTimeout bounds how long an unauthenticated peer may hold a
// /mesh/auth stream: it has to send its frame and read the reply within it.
// A var so tests can shorten it.
var authHandshakeTimeout = 10 * time.Second

// handshakeLimiterSize is how many distinct peers' handshake budgets are
// tracked at once (LRU beyond that).
const (
	handshakeLimiterSize  = 4096
	ingressRateLimitPerIP = 200
	ingressRateBurstPerIP = 400
)

// HandleAuthHandshake processes incoming auth connections.
// It is part of mutual auth:
// 1. Receives client's Biscuit.
// 2. Verifies it against CP public keys.
// 3. Responds with success and the router's own Biscuit.
func (r *Router) HandleAuthHandshake(s network.Stream) {
	defer func() { _ = s.Close() }()
	remotePeer := s.Conn().RemotePeer()

	if _, banned := r.bannedPeers.Load(remotePeer); banned {
		logger.Warnf("[AuthN] Rejecting authentication for banned peer %s", remotePeer)
		authHandshakesTotal.WithLabelValues(handshakeBanned).Inc()
		_ = s.Reset()
		return
	}

	if r.handshakeLimiter != nil && !r.handshakeLimiter.Allow(remotePeer.String()) {
		logger.Warnf("[AuthN] Handshake rate limit exceeded for %s", remotePeer)
		authHandshakesTotal.WithLabelValues(handshakeRateLimited).Inc()
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
		authHandshakesTotal.WithLabelValues(handshakeReadFailed).Inc()
		return
	}
	defer reader.ReleaseMsg(msg)

	var exchange api.AuthFrame
	if err := proto.Unmarshal(msg, &exchange); err != nil {
		logger.Warnf("[AuthN] Invalid protobuf from %s", remotePeer)
		authHandshakesTotal.WithLabelValues(handshakeInvalidFrame).Inc()
		return
	}

	// Verify Biscuit and record its expiration so relayACL drops the session on time.
	b, verifyingKey, expiry, err := identity.VerifyBiscuitAdmission(exchange.Biscuit, remotePeer, r.getTrustedPublicKeys(), r.config.BiscuitTimeout)
	if err != nil {
		// A peer stuck on a bad credential retries every few seconds for
		// days; one line a minute per peer keeps the log readable and the
		// counter carries the rate.
		if r.authFailureLog.allow(remotePeer, time.Now()) {
			logger.Warnf("[AuthN] Authorization failed for peer %s: %v (further failures from this peer are logged once per minute)", remotePeer, err)
		}
		authHandshakesTotal.WithLabelValues(handshakeUnauthorized).Inc()
		_ = s.Reset()
		return
	}
	if r.isBiscuitRevoked(b) {
		if r.authFailureLog.allow(remotePeer, time.Now()) {
			logger.Warnf("[AuthN] Rejecting revoked biscuit for peer %s", remotePeer)
		}
		authHandshakesTotal.WithLabelValues(handshakeUnauthorized).Inc()
		_ = s.Reset()
		return
	}

	r.admitPeer(remotePeer, expiry)
	r.credentials.Store(remotePeer, memberCredential{biscuit: b, key: verifyingKey})
	authHandshakesTotal.WithLabelValues(handshakeOK).Inc()
	logger.Infof("[AuthN] Successfully authenticated peer %s", remotePeer)
	// A router that proves the router role is a peer router from here on,
	// not from the next federation pass: it is never a member to shed.
	if identity.RequireRole(b, verifyingKey, api.RoleRouter, r.config.BiscuitTimeout) == nil {
		r.admitPeerRouter(remotePeer)
	}

	// Send mutual response (our biscuit)
	r.keysMu.RLock()
	ourBiscuit := r.credential.biscuit
	r.keysMu.RUnlock()

	writer := msgio.NewVarintWriter(s)
	resp := &api.AuthResponse{
		Success: true,
		Biscuit: ourBiscuit,
	}
	respBytes, _ := proto.Marshal(resp)
	if err := writer.WriteMsg(respBytes); err != nil {
		logger.Errorf("[AuthN] Failed to write mutual ACK to %s: %v", remotePeer, err)
	}
}

// performMutualAuth initiates client-side mutual authentication handshake.
func (r *Router) performMutualAuth(s network.Stream) error {
	remotePeer := s.Conn().RemotePeer()
	if _, banned := r.bannedPeers.Load(remotePeer); banned {
		return fmt.Errorf("peer %s is banned", remotePeer)
	}
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))

	// Send our biscuit
	r.keysMu.RLock()
	ourBiscuit := r.credential.biscuit
	r.keysMu.RUnlock()
	writer := msgio.NewVarintWriter(s)
	authFrame := &api.AuthFrame{Biscuit: ourBiscuit}
	data, _ := proto.Marshal(authFrame)
	if err := writer.WriteMsg(data); err != nil {
		return fmt.Errorf("write mutual auth frame: %w", err)
	}

	// Read response (success + remote biscuit)
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	respMsg, err := reader.ReadMsg()
	if err != nil {
		return fmt.Errorf("read mutual auth response: %w", err)
	}
	defer reader.ReleaseMsg(respMsg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(respMsg, &resp); err != nil {
		return fmt.Errorf("unmarshal mutual auth response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("mutual auth handshake rejected: %s", resp.Error)
	}

	trustedKeys := r.getTrustedPublicKeys()
	if len(trustedKeys) == 0 {
		return fmt.Errorf("no trusted control plane keys loaded")
	}

	// Verify remote biscuit
	b, verifyingKey, err := identity.VerifyBiscuitAndGetKey(resp.Biscuit, remotePeer, trustedKeys, r.config.BiscuitTimeout)
	if err != nil {
		return fmt.Errorf("failed to verify peer router biscuit: %w", err)
	}
	if r.isBiscuitRevoked(b) {
		return fmt.Errorf("peer router %s biscuit is revoked", remotePeer)
	}

	// Enforce required role inside the biscuit
	if err := identity.RequireRole(b, verifyingKey, r.config.RequiredRole, r.config.BiscuitTimeout); err != nil {
		return fmt.Errorf("remote peer lacks router authorization role: %w", err)
	}

	expiry, err := identity.VerifyBiscuitAndGetExpiry(resp.Biscuit, remotePeer, []ed25519.PublicKey{verifyingKey}, r.config.BiscuitTimeout)
	if err != nil {
		return fmt.Errorf("failed to extract peer router biscuit expiry: %w", err)
	}

	r.admitPeer(remotePeer, expiry)
	r.admitPeerRouter(remotePeer)
	return nil
}

// Close closes the underlying p2p host and keyring db.
func (r *Router) Close() error {
	r.isReady.Store(false)
	// Draining: no renewal may extend the lease past the withdrawal below,
	// which goes out while the host and the credential are still there.
	r.shutdown.Store(true)
	r.withdrawLease()
	r.drainMembers()
	r.cancel()

	var errs []error
	if r.ingressServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := r.ingressServer.Shutdown(shutdownCtx); err != nil {
			_ = r.ingressServer.Close()
			errs = append(errs, err)
		}
		shutdownCancel()
	}
	if r.metricsServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := r.metricsServer.Shutdown(shutdownCtx); err != nil {
			_ = r.metricsServer.Close()
			errs = append(errs, err)
		}
		shutdownCancel()
	}
	if r.DHT != nil {
		if err := r.DHT.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if r.Host != nil {
		if err := r.Host.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	r.wg.Wait()
	return errors.Join(errs...)
}

func getOrGeneratePeerKey(keyPath string) (crypto.PrivKey, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return nil, err
	}

	if _, err := os.Stat(keyPath); err == nil {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return crypto.UnmarshalPrivateKey(data)
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, err
	}
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return nil, err
	}
	return priv, nil
}

func isLinkLocal(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code == multiaddr.P_IP4 || proto.Code == multiaddr.P_IP6 {
			value, err := addr.ValueForProtocol(proto.Code)
			if err == nil {
				if ip := net.ParseIP(value); ip != nil {
					if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
						return true
					}
				}
			}
		}
	}
	return false
}

func isLoopbackOrLinkLocal(addr multiaddr.Multiaddr) bool {
	for _, proto := range addr.Protocols() {
		if proto.Code == multiaddr.P_IP4 || proto.Code == multiaddr.P_IP6 {
			value, err := addr.ValueForProtocol(proto.Code)
			if err == nil {
				ip := net.ParseIP(value)
				if ip != nil {
					if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
						return true
					}
				}
			}
		}
	}
	return false
}

// RefreshEnrollment trades the expiring biscuit token for a new one using a cryptographic challenge.
func (r *Router) RefreshEnrollment(ctx context.Context) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()

	r.keysMu.RLock()
	currentBiscuit := r.credential.biscuit
	r.keysMu.RUnlock()

	if len(currentBiscuit) == 0 {
		return fmt.Errorf("router not enrolled (no biscuit)")
	}

	// 1. Derive peer ID from private key
	peerID, err := peer.IDFromPrivateKey(r.privKey)
	if err != nil {
		return fmt.Errorf("failed to derive peer ID from private key: %w", err)
	}

	// 2. Construct request. peer_id lets the control plane find this
	// router's record when the biscuit's signing key has been retired and
	// the biscuit itself can no longer be verified (autonomous recovery,
	// opt-in server-side); it is cross-checked against the biscuit otherwise.
	var freshJWT string
	if src := r.tokenSource(); src != nil {
		if jwt, err := src.FetchToken(ctx); err == nil && jwt != "" {
			freshJWT = jwt
		} else if err != nil {
			logger.Warnf("Failed to fetch platform JWT for router refresh re-attestation, continuing with PoP-only refresh: %v", err)
		}
	}

	url := r.config.ControlPlaneURL + "/refresh"
	b64Biscuit := base64.StdEncoding.EncodeToString(currentBiscuit)
	client := r.controlPlaneClient(10 * time.Second)
	resp, err := cpclient.DoWithChallenge(client, time.Now, func(timestamp int64) (*http.Request, error) {
		sig, err := r.privKey.Sign(api.RefreshChallenge(peerID.String(), timestamp))
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

	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := cpclient.ReadBody(resp.Body)
		logger.Warnf("Proactive biscuit refresh rejected (401 Unauthorized: %s), attempting re-enrollment...", string(body))
		return r.reEnroll()
	}

	if resp.StatusCode == http.StatusForbidden {
		// A 403 is a claim by whoever answered; only a verified
		// MeshEvent_BANNED is the control plane's word. Keep serving on the
		// current biscuit until it expires.
		body, _ := cpclient.ReadBody(resp.Body)
		return fmt.Errorf("refresh refused (403 Forbidden): %s", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := cpclient.ReadBody(resp.Body)
		return fmt.Errorf("refresh failed with status %s: %s", resp.Status, string(body))
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

	// Same checks as enrollment: signed by a trusted key, bound to this
	// router, carrying the router role.
	if err := r.verifyOwnBiscuit(refreshResp.BiscuitToken, peerID); err != nil {
		return fmt.Errorf("refreshed biscuit rejected: %w", err)
	}

	// Update local biscuit token and expiration under lock
	r.keysMu.Lock()
	r.credential = newCredential(refreshResp.BiscuitToken, refreshResp.ExpireTime, r.trustedPublicKeys)
	r.keysMu.Unlock()

	logger.Infof("Router biscuit token refreshed successfully.")
	return nil
}

func (r *Router) verifyOwnBiscuit(token []byte, peerID peer.ID) error {
	trusted := r.getTrustedPublicKeys()
	if len(trusted) == 0 {
		return fmt.Errorf("no trusted control plane keys loaded")
	}
	_, key, err := identity.VerifyBiscuitAndGetKey(token, peerID, trusted, r.config.BiscuitTimeout)
	if err != nil {
		return err
	}
	return identity.VerifyBiscuitRole(token, key, r.config.RequiredRole, r.config.BiscuitTimeout)
}

// samePublicKeys reports whether a and b hold the same keys in any order.
func samePublicKeys(a, b []ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, k := range a {
		seen[string(k)] = true
	}
	for _, k := range b {
		if !seen[string(k)] {
			return false
		}
	}
	return true
}
