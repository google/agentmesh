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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/sam/api"
	cpclient "github.com/google/sam/internal/controlplane/client"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/ratelimit"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	records "github.com/libp2p/go-libp2p-kad-dht/records"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
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
	"github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	xrate "github.com/libp2p/go-libp2p/x/rate"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var logger = golog.Logger("sam-router")

const (
	DefaultLowWaterMark  = 1000
	DefaultHighWaterMark = 4000
	ConnGracePeriod      = 1 * time.Minute
)

type relayACL struct {
	r *Router
}

func (a *relayACL) AllowReserve(p peer.ID, addr multiaddr.Multiaddr) bool {
	if _, banned := a.r.bannedPeers.Load(p); banned {
		logger.Debugf("[Relay] Rejecting reservation for %s: peer is banned", p)
		return false
	}
	_, ok := a.r.authenticatedPeers.Load(p)
	if !ok {
		logger.Debugf("[Relay] Rejecting reservation for %s: not authenticated", p)
	}
	return ok
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
	if _, ok := a.r.authenticatedPeers.Load(src); !ok {
		logger.Debugf("[Relay] Rejecting connect from %s to %s: src not authenticated", src, dest)
		return false
	}
	_, ok := a.r.authenticatedPeers.Load(dest)
	if !ok {
		logger.Debugf("[Relay] Rejecting connect from %s to %s: dest not authenticated", src, dest)
	}
	return ok
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
	bannedPeers        sync.Map
	// handshakeLimiter bounds /sam/auth attempts per peer; any internet peer
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

	keysSyncTrigger chan struct{}

	// Control contexts
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	isReady  atomic.Bool
	shutdown bool

	metricsServer *http.Server
	metricsAddr   net.Addr

	// identityLoggedAt is when the "Router Online" line was last written.
	identityLoggedAt atomic.Pointer[time.Time]
	authFailureLog   perPeerLogLimiter
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

	return &Router{
		config:           config,
		ctx:              ctx,
		cancel:           cancel,
		handshakeLimiter: handshakeLimiter,
		keysSyncTrigger:  make(chan struct{}, 1),
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

// perIPConnResourceManager mirrors libp2p's default resource manager with the
// per-source-IP inbound connection cap, the per-subnet connection rate limit
// and the system/transient scopes scaled to carry limit connections; see
// Options.ConnsPerSourceIP. All three matter behind a proxy or NAT: every
// peer shares a few source IPs, so the default per-IP cap (8), the default
// per-IP rate (0.2 conns/s, burst 16) and the small transient scope each
// take down the whole listener under normal reconnect churn.
func perIPConnResourceManager(limit int) (network.ResourceManager, error) {
	limits := rcmgr.DefaultLimits
	libp2p.SetDefaultServiceLimits(&limits)
	scaled := limits.AutoScale()

	overrides := rcmgr.PartialLimitConfig{
		System: rcmgr.ResourceLimits{
			Conns:        rcmgr.LimitVal(2 * limit),
			ConnsInbound: rcmgr.LimitVal(limit),
			FD:           rcmgr.LimitVal(2 * limit),
		},
		Transient: rcmgr.ResourceLimits{
			Conns:        rcmgr.LimitVal(limit),
			ConnsInbound: rcmgr.LimitVal(limit),
			FD:           rcmgr.LimitVal(limit),
		},
	}

	// Same shape as the rcmgr default limiter (loopback exempt, no global
	// cap), with the per-subnet budget scaled by limit relative to the
	// default per-IP cap of 8.
	scale := float64(limit) / 8
	connRateLimiter := &xrate.Limiter{
		NetworkPrefixLimits: []xrate.PrefixLimit{
			{Prefix: netip.MustParsePrefix("127.0.0.0/8"), Limit: xrate.Limit{}},
			{Prefix: netip.MustParsePrefix("::1/128"), Limit: xrate.Limit{}},
		},
		SubnetRateLimiter: xrate.SubnetLimiter{
			IPv4SubnetLimits: []xrate.SubnetLimit{
				{PrefixLength: 32, Limit: xrate.Limit{RPS: 0.2 * scale, Burst: 2 * limit}},
			},
			IPv6SubnetLimits: []xrate.SubnetLimit{
				{PrefixLength: 56, Limit: xrate.Limit{RPS: 0.2 * scale, Burst: 2 * limit}},
			},
			GracePeriod: time.Minute,
		},
	}

	return rcmgr.NewResourceManager(
		rcmgr.NewFixedLimiter(overrides.Build(scaled)),
		rcmgr.WithLimitPerSubnet(
			[]rcmgr.ConnLimitPerSubnet{{PrefixLength: 32, ConnCount: limit}},
			[]rcmgr.ConnLimitPerSubnet{{PrefixLength: 56, ConnCount: limit}},
		),
		rcmgr.WithConnRateLimiters(connRateLimiter),
	)
}

// defaultResourceManager is what libp2p installs when none is given, built
// here so it can be wrapped.
func defaultResourceManager() (network.ResourceManager, error) {
	limits := rcmgr.DefaultLimits
	libp2p.SetDefaultServiceLimits(&limits)
	return rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limits.AutoScale()))
}

// Start performs enrollment, syncs keys, launches libp2p host, and starts tasks.
func (r *Router) Start() error {
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

	// 4. Initialize libp2p host
	low := r.config.LowWaterMark
	if low <= 0 {
		low = DefaultLowWaterMark
	}
	high := r.config.HighWaterMark
	if high <= 0 {
		high = DefaultHighWaterMark
	}
	cm, err := connmgr.NewConnManager(low, high, connmgr.WithGracePeriod(ConnGracePeriod))
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
	// its source, whether the per-IP cap is the configured one or libp2p's
	// default; a refused dialer only sees its connection close before TLS.
	var mgr network.ResourceManager
	if r.config.ConnsPerSourceIP > 0 {
		mgr, err = perIPConnResourceManager(r.config.ConnsPerSourceIP)
	} else {
		mgr, err = defaultResourceManager()
	}
	if err != nil {
		return fmt.Errorf("failed to create resource manager: %w", err)
	}
	p2pOpts = append(p2pOpts, libp2p.ResourceManager(observeResourceManager(mgr)))

	hostNode, err := libp2p.New(p2pOpts...)
	if err != nil {
		return err
	}
	r.Host = hostNode

	// Setup DHT
	dhtOpts := []dht.Option{
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix("/sam"),
	}
	var pmOpts []records.Option
	if r.config.DHTProviderAddrTTL > 0 {
		pmOpts = append(pmOpts, records.ProviderAddrTTL(r.config.DHTProviderAddrTTL))
		pmOpts = append(pmOpts, records.ProvideValidity(r.config.DHTProviderAddrTTL))
	}
	if len(pmOpts) > 0 {
		dhtOpts = append(dhtOpts, dht.ProviderManagerOpts(pmOpts...))
	}
	if r.config.DHTMaxRecordAge > 0 {
		dhtOpts = append(dhtOpts, dht.MaxRecordAge(r.config.DHTMaxRecordAge))
	}
	kadDHT, err := dht.New(hostNode, dhtOpts...)
	if err != nil {
		_ = hostNode.Close()
		return err
	}
	r.DHT = kadDHT

	if err = kadDHT.Bootstrap(r.ctx); err != nil {
		_ = hostNode.Close()
		return err
	}

	// Setup Relay
	_, err = relay.New(hostNode, relay.WithACL(&relayACL{r: r}),
		relay.WithLimit(relayLimit(r.config.RelayLimitDuration, r.config.RelayLimitData)))
	if err != nil {
		_ = hostNode.Close()
		return err
	}

	// Setup PubSub. StrictSign is the default; pinned because the event
	// validator trusts msg.GetFrom().
	ps, err := pubsub.NewGossipSub(r.ctx, hostNode, pubsub.WithMessageSignaturePolicy(pubsub.StrictSign))
	if err != nil {
		_ = hostNode.Close()
		return err
	}
	r.PubSub = ps
	// The router is the hub every node gossips through. Validating here
	// stops a junk event at the first hop instead of fanning it out to every
	// attached node, each of which would spend a verify on it.
	if err := ps.RegisterTopicValidator(api.GossipEvents, r.validateMeshEvent); err != nil {
		_ = hostNode.Close()
		return fmt.Errorf("register mesh event validator: %w", err)
	}

	topic, err := ps.Join(api.GossipEvents)
	if err != nil {
		_ = hostNode.Close()
		return err
	}
	r.EventTopic = topic

	// Setup authentication stream handler
	hostNode.SetStreamHandler(api.AuthProtocolID, recoverStreamHandler("AuthHandshake", r.HandleAuthHandshake))

	// Clean authenticated status on peer disconnection
	hostNode.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(n network.Network, c network.Conn) {
			p := c.RemotePeer()
			if len(hostNode.Network().ConnsToPeer(p)) == 0 {
				r.authenticatedPeers.Delete(p)
			}
		},
	})

	// 5. Start background routines
	r.wg.Add(5)
	go r.runLeaseRenewalLoop()
	go r.runKeysSyncLoop()
	go r.runFederationLoop()
	go r.runBiscuitRenewalLoop()
	go r.listenForControlPlaneEvents(r.ctx)

	r.isReady.Store(true)
	logger.Infof("Router Online. PeerID: %s, ListenAddrs: %v", r.Host.ID(), r.Host.Addrs())
	return nil
}

func (r *Router) enroll(peerID peer.ID) error {
	pubKey := r.privKey.GetPublic()
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	ts := time.Now().UnixMilli()
	sig, err := r.privKey.Sign(api.RegisterChallenge(peerID.String(), ts))
	if err != nil {
		return fmt.Errorf("failed to sign registration challenge: %w", err)
	}

	req := &api.EnrollRequest{
		Jwt:                r.config.OIDCToken,
		PeerId:             peerID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      r.config.RequiredRole,
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	client := r.controlPlaneClient(30 * time.Second)
	resp, err := client.Post(r.config.ControlPlaneURL+"/register", "application/x-protobuf", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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

	enrollTS := time.Now().UnixMilli()
	enrollSig, err := r.privKey.Sign(api.EnrollChallenge(peerID.String(), enrollTS))
	if err != nil {
		return fmt.Errorf("failed to sign enrollment challenge: %w", err)
	}

	req := &api.BootstrapEnrollRequest{
		BootstrapToken:     r.config.BootstrapToken,
		PeerId:             peerID.String(),
		PublicKey:          pubBytes,
		RequestedRole:      r.config.RequiredRole,
		ChallengeUnixMs:    enrollTS,
		ChallengeSignature: enrollSig,
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	client := r.controlPlaneClient(30 * time.Second)
	resp, err := client.Post(r.config.ControlPlaneURL+"/enroll", "application/x-protobuf", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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
				ts := time.Now().UnixMilli()
				sig, err := r.privKey.Sign(api.EnrollStatusChallenge(peerID.String(), ts))
				if err != nil {
					return fmt.Errorf("failed to sign enrollment status challenge: %w", err)
				}
				req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, statusURL, nil)
				if err != nil {
					return fmt.Errorf("failed to create status request: %w", err)
				}
				req.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(ts, 10))
				req.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(sig))
				statusResp, err := client.Do(req)
				if err != nil {
					logger.Warnf("failed to poll enrollment status: %v", err)
					continue
				}

				if statusResp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(statusResp.Body)
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
	r.trustedPublicKeys = newKeys
	r.credential.pin(newKeys)
	refresh := r.credential.predatesRotation(newKeys)
	r.keysMu.Unlock()

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
	return cpclient.New(r.config.ControlPlaneURL, r.controlPlaneClient(timeout))
}

// controlPlaneClient is the client for every request to the control plane;
// its transport re-checks the plaintext policy on each hop, redirects included.
func (r *Router) controlPlaneClient(timeout time.Duration) *http.Client {
	return cpclient.NewHTTPClient(timeout, func() bool { return r.config.AllowInsecureControlPlane }, "sam-router")
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
					r.authenticatedPeers.Delete(bannedPeer)
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
			logger.Infof("[Router Event] Received KEY_ROTATION event, triggering key sync")
			r.triggerKeysSync()
		}
	}
}

func (r *Router) triggerKeysSync() {
	select {
	case r.keysSyncTrigger <- struct{}{}:
	default:
	}
}

func (r *Router) runKeysSyncLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.config.KeysSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-r.keysSyncTrigger:
		case <-r.ctx.Done():
			return
		}
		if err := r.syncKeys(); err != nil {
			logger.Errorf("Failed keys sync: %v", err)
		}
	}
}

func (r *Router) runLeaseRenewalLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.config.LeaseRenewInterval)
	defer ticker.Stop()

	// Initial renewal after host is online
	r.renewLease()

	for {
		select {
		case <-ticker.C:
			r.renewLease()
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *Router) renewLease() {
	for attempt := 0; attempt < 2; attempt++ {
		r.keysMu.RLock()
		biscuit := r.credential.biscuit
		r.keysMu.RUnlock()

		if len(biscuit) == 0 {
			logger.Warn("Cannot renew lease: router is not enrolled (no biscuit)")
			return
		}

		var addrs []string
		if len(r.config.ExternalAddrs) > 0 {
			for _, addr := range r.config.ExternalAddrs {
				addrs = append(addrs, addr+"/p2p/"+r.Host.ID().String())
			}
		} else {
			for _, addr := range r.Host.Addrs() {
				addrs = append(addrs, addr.String()+"/p2p/"+r.Host.ID().String())
			}
		}

		var connectedPeers []string
		if r.Host != nil && r.Host.Network() != nil {
			for _, p := range r.Host.Network().Peers() {
				connectedPeers = append(connectedPeers, p.String())
			}
		}
		var dhtSize int32
		if r.DHT != nil && r.DHT.RoutingTable() != nil {
			dhtSize = int32(r.DHT.RoutingTable().Size())
		}

		// The biscuit identifies us; the signature proves it is us (peers we
		// authenticate hold a copy of the biscuit).
		ts := time.Now().UnixMilli()
		sig, err := r.privKey.Sign(api.RouterLeaseChallenge(r.Host.ID().String(), ts))
		if err != nil {
			logger.Errorf("Failed to sign lease challenge: %v", err)
			return
		}

		req := &api.RouterLeaseRequest{
			PeerId:             r.Host.ID().String(),
			Addresses:          addrs,
			Biscuit:            biscuit,
			ConnectedPeers:     connectedPeers,
			DhtSize:            dhtSize,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		}
		data, _ := proto.Marshal(req)

		client := r.controlPlaneClient(10 * time.Second)
		resp, err := client.Post(r.config.ControlPlaneURL+"/routers/lease", "application/x-protobuf", bytes.NewReader(data))
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

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
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
			r.logIdentityPeriodically()
		}
		return
	}
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
		r.authenticatedPeers.Delete(p)
		if r.Host != nil {
			_ = r.Host.Network().ClosePeer(p)
		}
	}
}

func (r *Router) runFederationLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	r.connectBootstrapRouters()

	for {
		select {
		case <-ticker.C:
			r.connectBootstrapRouters()
		case <-r.ctx.Done():
			return
		}
	}
}

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

	for _, addrStr := range info.RouterAddresses {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			continue
		}

		resolvedAddrs, err := madns.DefaultResolver.Resolve(r.ctx, ma)
		if err != nil {
			resolvedAddrs = []multiaddr.Multiaddr{ma}
		}

		for _, resolved := range resolvedAddrs {
			pi, err := peer.AddrInfoFromP2pAddr(resolved)
			if err != nil || pi.ID == r.Host.ID() {
				continue
			}

			if len(r.Host.Network().ConnsToPeer(pi.ID)) == 0 {
				logger.Infof("[Federation] Connecting to peer router: %s via %s", pi.ID, resolved)
				// Create a timeout context
				connectCtx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
				if err := r.Host.Connect(connectCtx, *pi); err == nil {
					// Initiate stream to perform mutual auth handshake
					s, err := r.Host.NewStream(connectCtx, pi.ID, api.AuthProtocolID)
					if err == nil {
						if err := r.performMutualAuth(s); err != nil {
							logger.Errorf("[Federation] Mutual auth handshake failed with %s: %v", pi.ID, err)
							_ = s.Reset()
						} else {
							logger.Infof("[Federation] Mutually authenticated with peer router %s", pi.ID)
							_ = s.Close()
						}
					} else {
						logger.Errorf("[Federation] Failed to open auth stream to %s: %v", pi.ID, err)
					}
				} else {
					logger.Errorf("[Federation] Failed to connect to %s: %v", pi.ID, err)
				}
				cancel()
			}
		}
	}
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
// /sam/auth stream: it has to send its frame and read the reply within it.
// A var so tests can shorten it.
var authHandshakeTimeout = 10 * time.Second

// handshakeLimiterSize is how many distinct peers' handshake budgets are
// tracked at once (LRU beyond that).
const handshakeLimiterSize = 4096

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

	// Verify Biscuit
	_, err = identity.VerifyBiscuit(exchange.Biscuit, remotePeer, r.getTrustedPublicKeys(), r.config.BiscuitTimeout)
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

	r.authenticatedPeers.Store(remotePeer, true)
	authHandshakesTotal.WithLabelValues(handshakeOK).Inc()
	logger.Infof("[AuthN] Successfully authenticated peer %s", remotePeer)

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

	// Enforce required role inside the biscuit
	if err := identity.RequireRole(b, verifyingKey, r.config.RequiredRole, r.config.BiscuitTimeout); err != nil {
		return fmt.Errorf("remote peer lacks router authorization role: %w", err)
	}

	r.authenticatedPeers.Store(remotePeer, true)
	return nil
}

// Close closes the underlying p2p host and keyring db.
func (r *Router) Close() error {
	r.shutdown = true
	r.cancel()

	var errs []error
	if r.metricsServer != nil {
		if err := r.metricsServer.Close(); err != nil {
			errs = append(errs, err)
		}
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

	// 1. Sign the peer-bound refresh challenge
	timestamp := time.Now().UnixMilli()
	peerID, err := peer.IDFromPrivateKey(r.privKey)
	if err != nil {
		return fmt.Errorf("failed to derive peer ID from private key: %w", err)
	}
	sig, err := r.privKey.Sign(api.RefreshChallenge(peerID.String(), timestamp))
	if err != nil {
		return fmt.Errorf("failed to generate signature: %w", err)
	}

	// 2. Construct request. peer_id lets the control plane find this
	// router's record when the biscuit's signing key has been retired and
	// the biscuit itself can no longer be verified (autonomous recovery,
	// opt-in server-side); it is cross-checked against the biscuit otherwise.
	req := &api.TokenRefreshRequest{
		ChallengeSignature: sig,
		ChallengeUnixMs:    timestamp,
		PeerId:             peerID.String(),
	}
	if src := r.tokenSource(); src != nil {
		if jwt, err := src.FetchToken(ctx); err == nil && jwt != "" {
			req.Jwt = jwt
		} else if err != nil {
			logger.Warnf("Failed to fetch platform JWT for router refresh re-attestation, continuing with PoP-only refresh: %v", err)
		}
	}
	reqData, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := r.config.ControlPlaneURL + "/refresh"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqData))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	b64Biscuit := base64.StdEncoding.EncodeToString(currentBiscuit)
	httpReq.Header.Set("Authorization", "Bearer "+b64Biscuit)

	client := r.controlPlaneClient(10 * time.Second)
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		logger.Warnf("Proactive biscuit refresh rejected (401 Unauthorized: %s), attempting re-enrollment...", string(body))
		return r.reEnroll()
	}

	if resp.StatusCode == http.StatusForbidden {
		// A 403 is a claim by whoever answered; only a verified
		// MeshEvent_BANNED is the control plane's word. Keep serving on the
		// current biscuit until it expires.
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("refresh refused (403 Forbidden): %s", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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

func (r *Router) runBiscuitRenewalLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(api.TokenRefreshCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.keysMu.RLock()
			expiration := r.credential.expiration
			r.keysMu.RUnlock()

			if !expiration.IsZero() && time.Until(expiration) < api.BiscuitTokenTTL/5 { // 80% elapsed lifespan of 24h (remaining time < 20% of TTL)
				logger.Infof("Router biscuit expiring in %v, triggering proactive refresh...", time.Until(expiration))
				if err := r.RefreshEnrollment(r.ctx); err != nil {
					logger.Errorf("Proactive router biscuit refresh failed: %v", err)
				}
			}
		case <-r.ctx.Done():
			return
		}
	}
}
