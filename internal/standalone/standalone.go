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

// Package standalone wires the control plane, the libp2p router and the
// shared SQL store into one process serving a single public port: the
// router's WebSocket listener carries libp2p upgrades while every other HTTP
// request falls through to the control-plane mux. The embedded router keeps
// its stock control-plane client, pointed at a loopback-only listener, so no
// component grows in-process shortcuts.
package standalone

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/console"
	"github.com/google/agentmesh/internal/controlplane"
	"github.com/google/agentmesh/internal/router"
	"github.com/google/agentmesh/internal/storage"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/protobuf/encoding/protojson"
)

var logger = golog.Logger("agentmesh-one")

const (
	joinTokenPrefix   = "mesh_tok_"
	adminTokenPrefix  = "mesh_adm_"
	deviceTokenPrefix = "mesh_dev_"

	joinTokenFile  = "join-token"
	adminTokenFile = "admin-token"
	routerKeyFile  = "router.key"

	consoleBasePath = "/console"

	// joinTokenTTL bounds the auto-generated join token; it is a development
	// credential, not a production secret rotation scheme.
	joinTokenTTL       = 10 * 365 * 24 * time.Hour
	joinTokenMaxUsages = 1 << 30

	// routerTokenTTL bounds the per-boot single-use token the embedded router
	// enrolls with; it never leaves the process.
	routerTokenTTL = time.Hour

	// DeviceTokenTTL bounds a device enrollment token: long enough to walk
	// over and scan the QR code, short enough that a screenshot of it goes
	// stale.
	DeviceTokenTTL = time.Hour
)

// Options configures the standalone all-in-one server.
type Options struct {
	// BindAddress is the host:port of the single public listener. The host
	// must be empty or an IP literal.
	BindAddress string
	// ExternalURL is the public URL nodes reach this server on; it is turned
	// into the ws/wss multiaddr the router advertises. Optional.
	ExternalURL string
	// P2PListen holds optional extra native libp2p listen multiaddrs.
	P2PListen []string
	// DataDir stores the SQLite database, the router identity key and the
	// generated token files.
	DataDir string
	// DBDriver selects "sqlite" (default) or "postgres".
	DBDriver string
	// DBDSN is the database connection string; defaults to
	// <DataDir>/agentmesh.db for sqlite.
	DBDSN string
	// JoinToken is the cluster join token; auto-generated and persisted in
	// DataDir when empty.
	JoinToken string
	// DisableJoinToken runs without any standing join token: devices then
	// enroll only with explicitly minted bootstrap tokens or through OIDC.
	// The right setting for a fleet; the default keeps `agentmesh-node join` on a
	// laptop zero-config.
	DisableJoinToken bool
	// AdminToken protects the admin REST API; auto-generated and persisted in
	// DataDir when empty.
	AdminToken string
	// PolicyFile optionally seeds the mesh policy on first boot from a
	// protojson PolicyConfig payload.
	PolicyFile string
	// OIDCIssuer optionally enables full OIDC enrollment.
	OIDCIssuer       string
	WorkloadIssuer   string
	AllowedAudiences []string
	// OIDCClientID is the OAuth client id advertised via /info.
	OIDCClientID string

	// ControlPlane and Router forward operator tunables to the embedded
	// components; zero values keep each component's defaults.
	ControlPlane ControlPlaneTunables
	Router       RouterTunables
}

// ControlPlaneTunables are the embedded control plane's operator knobs.
type ControlPlaneTunables struct {
	// LeaseDuration bounds how long a router lease stays valid.
	LeaseDuration time.Duration
	// KeyRotationInterval is how often the biscuit signing key rotates.
	KeyRotationInterval time.Duration
	// KeyGracePeriod keeps rotated-out keys valid for verification.
	KeyGracePeriod time.Duration
	// SigningKeyPath is the operator's PEM file of signing keys; see
	// controlplane.Options.SigningKeyPath. Empty lets the control plane
	// generate and rotate its own.
	SigningKeyPath string
	// DHTReplication and DHTReprovideInterval are the mesh's directory
	// parameters; see controlplane.Options.
	DHTReplication       int
	DHTReprovideInterval time.Duration
	// BiscuitTTL is the lifespan minted into issued biscuits.
	BiscuitTTL time.Duration
	// WorkloadSessionTTL is how long a workload-issuer enrollment stays
	// refreshable without presenting a fresh platform JWT on /refresh.
	WorkloadSessionTTL time.Duration
	// NodeRetention is how long a node record is kept after its session
	// expired, or after its last refresh for a bootstrap enrollment, before
	// the control plane deletes it.
	NodeRetention time.Duration
	// EphemeralNodeRetention is NodeRetention for a node an ephemeral
	// bootstrap token enrolled.
	EphemeralNodeRetention time.Duration
	// ManualEnrollment queues bootstrap enrollments for admin approval
	// instead of auto-approving them.
	ManualEnrollment bool
}

// RouterTunables are the embedded router's operator knobs.
type RouterTunables struct {
	// ControlPlaneSyncInterval is how often the router renews its lease and
	// pulls keys, routers, bans and policy from the control plane.
	ControlPlaneSyncInterval time.Duration
	// LowWaterMark / HighWaterMark bound the connection manager.
	LowWaterMark  int
	HighWaterMark int
	// ConnsPerSourceIP scales libp2p's per-source-IP budgets; defaults to
	// the connection manager high watermark (proxied deployments share
	// source IPs, so the global cap should be what binds).
	ConnsPerSourceIP int
	// RelayLimitDuration / RelayLimitData cap each relayed connection.
	RelayLimitDuration time.Duration
	RelayLimitData     router.ByteSize
	// ShutdownLeaseTTL is the lease the embedded router asks for as it stops;
	// see router.Options.ShutdownLeaseTTL.
	ShutdownLeaseTTL time.Duration
	// AuthDeadline closes inbound connections that do not pass the handshake
	// in time; see router.Options.AuthDeadline.
	AuthDeadline time.Duration
	// DisallowLoopback stops advertising loopback addresses (useful on
	// public deployments; the default keeps local development working).
	DisallowLoopback bool
}

// Default fills unset options with development-friendly values.
func (o *Options) Default() {
	if o.BindAddress == "" {
		// Port 0 picks a free port; the caller publishes it (banner/Addr),
		// like the generated tokens.
		o.BindAddress = "0.0.0.0:0"
	}
	if o.DataDir == "" {
		o.DataDir = "."
	}
	if o.DBDriver == "" {
		o.DBDriver = "sqlite"
	}
	if o.DBDSN == "" && o.DBDriver == "sqlite" {
		o.DBDSN = filepath.Join(o.DataDir, "agentmesh.db")
	}
	if len(o.AllowedAudiences) == 0 {
		o.AllowedAudiences = []string{api.DefaultAudience}
	}
	if o.Router.HighWaterMark == 0 {
		o.Router.HighWaterMark = router.DefaultHighWaterMark
	}
	if o.Router.ConnsPerSourceIP == 0 {
		o.Router.ConnsPerSourceIP = o.Router.HighWaterMark
	}
	if o.Router.RelayLimitDuration == 0 {
		o.Router.RelayLimitDuration = router.DefaultRelayLimitDuration
	}
}

// Validate rejects option combinations Start could not honor.
func (o *Options) Validate() error {
	if _, err := wsListenMultiaddr(o.BindAddress); err != nil {
		return fmt.Errorf("invalid bind address %q: %w", o.BindAddress, err)
	}
	if o.DisableJoinToken && o.JoinToken != "" {
		return fmt.Errorf("a join token was supplied together with DisableJoinToken")
	}
	if o.ExternalURL != "" {
		if _, err := externalMultiaddr(o.ExternalURL); err != nil {
			return fmt.Errorf("invalid external URL %q: %w", o.ExternalURL, err)
		}
	}
	if o.DBDSN == "" {
		return fmt.Errorf("a database DSN is required for driver %q", o.DBDriver)
	}
	for _, a := range o.P2PListen {
		if _, err := multiaddr.NewMultiaddr(a); err != nil {
			return fmt.Errorf("invalid p2p listen multiaddr %q: %w", a, err)
		}
	}
	return nil
}

// Server is the running all-in-one instance.
type Server struct {
	opts Options

	store      storage.Store
	cp         *controlplane.Server
	router     *router.Router
	mesh       *controlplane.P2PMeshAdapter
	adminToken string
	joinToken  string
	publicAddr string
}

// New validates the options and prepares a standalone server.
func New(opts Options) (*Server, error) {
	opts.Default()
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return &Server{opts: opts}, nil
}

// Start boots the store, the control plane on a loopback-only listener, and
// the router owning the single public port. It returns once the mesh accepts
// enrollments.
func (s *Server) Start(ctx context.Context) (retErr error) {
	defer func() {
		if retErr != nil {
			_ = s.Close()
		}
	}()

	if err := os.MkdirAll(s.opts.DataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data dir: %w", err)
	}

	store, err := storage.NewSQLStore(s.opts.DBDriver, s.opts.DBDSN)
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}
	s.store = store

	s.adminToken = s.opts.AdminToken
	if s.adminToken == "" {
		if s.adminToken, err = loadOrCreateTokenFile(filepath.Join(s.opts.DataDir, adminTokenFile), adminTokenPrefix); err != nil {
			return fmt.Errorf("failed to provision admin token: %w", err)
		}
	}

	// Loopback-only control plane listener: the embedded router (and any
	// other in-process client) bootstraps against it before the public port
	// exists. Public traffic reaches the same handlers via the router's
	// HTTP fallback mux.
	cp, err := controlplane.NewServer(controlplane.Options{
		ListenAddr:             "127.0.0.1:0",
		DriverName:             s.opts.DBDriver,
		DataSourceName:         s.opts.DBDSN,
		OIDCIssuer:             s.opts.OIDCIssuer,
		WorkloadIssuer:         s.opts.WorkloadIssuer,
		OIDCClientID:           s.opts.OIDCClientID,
		AllowedAudiences:       s.opts.AllowedAudiences,
		LeaseDuration:          s.opts.ControlPlane.LeaseDuration,
		KeyRotationInterval:    s.opts.ControlPlane.KeyRotationInterval,
		DHTReplication:         s.opts.ControlPlane.DHTReplication,
		DHTReprovideInterval:   s.opts.ControlPlane.DHTReprovideInterval,
		KeyGracePeriod:         s.opts.ControlPlane.KeyGracePeriod,
		SigningKeyPath:         s.opts.ControlPlane.SigningKeyPath,
		BiscuitTTL:             s.opts.ControlPlane.BiscuitTTL,
		WorkloadSessionTTL:     s.opts.ControlPlane.WorkloadSessionTTL,
		NodeRetention:          s.opts.ControlPlane.NodeRetention,
		EphemeralNodeRetention: s.opts.ControlPlane.EphemeralNodeRetention,
		BiscuitTimeout:         10 * time.Second,
		AdminToken:             s.adminToken,
		AutoApproveEnrollment:  !s.opts.ControlPlane.ManualEnrollment,
		STSIssuerURL:           s.opts.ExternalURL,
	}, store)
	if err != nil {
		return fmt.Errorf("failed to create control plane: %w", err)
	}
	if err := cp.Start(); err != nil {
		return fmt.Errorf("failed to start control plane: %w", err)
	}
	s.cp = cp

	if err := s.seedPolicyOnFirstBoot(ctx); err != nil {
		return err
	}

	if !s.opts.DisableJoinToken {
		s.joinToken = s.opts.JoinToken
		if s.joinToken == "" {
			if s.joinToken, err = loadOrCreateTokenFile(filepath.Join(s.opts.DataDir, joinTokenFile), joinTokenPrefix); err != nil {
				return fmt.Errorf("failed to provision join token: %w", err)
			}
		}
		if err := s.ensureBootstrapToken(ctx, s.joinToken, api.RoleNode, joinTokenMaxUsages, joinTokenTTL, "agentmesh-one join token"); err != nil {
			return fmt.Errorf("failed to register join token: %w", err)
		}
	}

	// Per-boot single-use credential for the embedded router's stock
	// enrollment flow; never persisted or displayed.
	routerToken, err := generateToken("mesh_rtr_")
	if err != nil {
		return err
	}
	if err := s.ensureBootstrapToken(ctx, routerToken, api.RoleRouter, 1, routerTokenTTL, "agentmesh-one embedded router token"); err != nil {
		return fmt.Errorf("failed to register router token: %w", err)
	}

	mux := http.NewServeMux()
	cp.RegisterRoutes(mux)

	// The console proxies /console/api/* to the loopback control plane and
	// serves the embedded frontend; it queries /info at construction, which is
	// already live on the loopback listener.
	consoleSrv, err := console.NewServer(console.Config{
		ControlPlaneURL: "http://" + cp.Addr(),
		AdminToken:      s.adminToken,
		StaticFS:        console.EmbeddedAssets(),
		BasePath:        consoleBasePath,
		ExternalURL:     s.opts.ExternalURL,
	})
	if err != nil {
		return fmt.Errorf("failed to create console: %w", err)
	}
	mux.Handle(consoleBasePath+"/", consoleSrv.Handler())

	// Mount external HTTP ingress directly onto the embedded router's ingress
	// handler so /ingress/* never flows through the control plane.
	var ingressHandler atomic.Pointer[http.Handler]
	mux.Handle("/ingress/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := ingressHandler.Load()
		if h == nil {
			http.Error(w, "Router ingress is not ready", http.StatusServiceUnavailable)
			return
		}
		(*h).ServeHTTP(w, r)
	}))

	wsAddr, err := wsListenMultiaddr(s.opts.BindAddress)
	if err != nil {
		return err
	}
	bindHost, _, err := net.SplitHostPort(s.opts.BindAddress)
	if err != nil {
		return err
	}
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	var externalAddrs []string
	var ingressURL string
	allowInsecureIngress := true
	if s.opts.ExternalURL != "" {
		ext, err := externalMultiaddr(s.opts.ExternalURL)
		if err != nil {
			return err
		}
		externalAddrs = []string{ext}
		ingressURL = strings.TrimRight(s.opts.ExternalURL, "/") + "/ingress"
		allowInsecureIngress = strings.HasPrefix(s.opts.ExternalURL, "http://")
	}

	routerKeyPath := filepath.Join(s.opts.DataDir, routerKeyFile)
	if err := ensureRouterKey(routerKeyPath, s.opts.AdminToken); err != nil {
		return fmt.Errorf("failed to provision router key: %w", err)
	}

	rtr, err := router.NewRouter(ctx, router.Options{
		ControlPlaneURL:          "http://" + cp.Addr(),
		ListenAddrs:              append([]string{wsAddr}, s.opts.P2PListen...),
		ExternalAddrs:            externalAddrs,
		AllowLoopback:            !s.opts.Router.DisallowLoopback,
		KeysDBPath:               routerKeyPath,
		BootstrapToken:           routerToken,
		ControlPlaneSyncInterval: s.opts.Router.ControlPlaneSyncInterval,
		LowWaterMark:             s.opts.Router.LowWaterMark,
		HighWaterMark:            s.opts.Router.HighWaterMark,
		RelayLimitDuration:       s.opts.Router.RelayLimitDuration,
		RelayLimitData:           int64(s.opts.Router.RelayLimitData),
		ShutdownLeaseTTL:         s.opts.Router.ShutdownLeaseTTL,
		AuthDeadline:             s.opts.Router.AuthDeadline,
		// Single-port deployments typically sit behind a TLS-terminating
		// proxy (Cloud Run, L7 LBs) or NAT where every peer shares a few
		// source IPs; libp2p's default 8-conns-per-IP cap would throttle
		// the whole listener.
		ConnsPerSourceIP:           s.opts.Router.ConnsPerSourceIP,
		HTTPFallbackHandler:        s.wrapPublicHTTPHandler(mux),
		IngressURL:                 ingressURL,
		AllowInsecureIngressHTTP:   allowInsecureIngress,
		AdvertiseSinglePortIngress: true,
		SinglePortBindHost:         bindHost,
	})
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}
	ingH := rtr.IngressHandler()
	ingressHandler.Store(&ingH)
	if err := rtr.Start(); err != nil {
		_ = rtr.Close()
		return fmt.Errorf("failed to start router: %w", err)
	}
	s.router = rtr
	// One process, one mesh peer: the control plane publishes its events on
	// the embedded router's own topic instead of dialing itself.
	mesh, err := controlplane.NewP2PMeshAdapter(rtr.Host, rtr.EventTopic, store)
	if err != nil {
		return fmt.Errorf("failed to attach control plane to the mesh: %w", err)
	}
	s.mesh = mesh
	cp.SetMeshAdapter(mesh)
	if s.publicAddr, err = s.resolvePublicAddr(); err != nil {
		return err
	}
	return nil
}

// Close shuts down the router, control plane and store.
func (s *Server) Close() error {
	var errs []string
	if s.mesh != nil {
		if err := s.mesh.Close(); err != nil {
			errs = append(errs, err.Error())
		}
		s.mesh = nil
	}
	if s.router != nil {
		if err := s.router.Close(); err != nil {
			errs = append(errs, err.Error())
		}
		s.router = nil
	}
	if s.cp != nil {
		if err := s.cp.Close(); err != nil {
			errs = append(errs, err.Error())
		}
		s.cp = nil
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			errs = append(errs, err.Error())
		}
		s.store = nil
	}
	if len(errs) > 0 {
		return fmt.Errorf("standalone shutdown: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Addr returns the public host:port actually bound (useful with port 0).
func (s *Server) Addr() string { return s.publicAddr }

// PublicURL is the base URL clients should reach this server on: the
// configured external URL, else the bound listener over plain HTTP.
func (s *Server) PublicURL() string {
	if s.opts.ExternalURL != "" {
		return strings.TrimRight(s.opts.ExternalURL, "/")
	}
	return "http://" + s.publicAddr
}

// IngressURL is the public base URL under which the embedded router serves
// external HTTP ingress on the single port.
func (s *Server) IngressURL() string {
	return s.PublicURL() + "/ingress"
}

// AdminToken returns the resolved admin API token.
func (s *Server) AdminToken() string { return s.adminToken }

// ReloadOperatorSigningKeys re-reads the operator's signing key file now
// instead of at the watcher's next tick. A no-op without --signing-key-path.
func (s *Server) ReloadOperatorSigningKeys() { s.cp.ReloadOperatorSigningKeys() }

// JoinToken returns the resolved cluster join token, or "" when the server
// runs with DisableJoinToken.
func (s *Server) JoinToken() string { return s.joinToken }

// JoinTokenPath is where an auto-generated join token is persisted, for
// `agentmesh-node join --bootstrap-token-path`.
func (s *Server) JoinTokenPath() string { return filepath.Join(s.opts.DataDir, joinTokenFile) }

// PeerID returns the embedded router's peer ID.
func (s *Server) PeerID() string { return s.router.Host.ID().String() }

// MintDeviceEnrollmentToken registers a fresh node bootstrap token good for
// maxUsages enrollments (1 = burned by the first device; more lets one code
// on a projector enroll a room) and returns its plaintext once. Unlike the
// join token it is never persisted; a device that missed the window simply
// gets a new one, and `agentmesh-one token revoke` ends a shared one early.
func (s *Server) MintDeviceEnrollmentToken(ctx context.Context, ttl time.Duration, maxUsages int) (string, error) {
	if ttl <= 0 {
		ttl = DeviceTokenTTL
	}
	if maxUsages <= 0 {
		maxUsages = 1
	}
	tok, err := generateToken(deviceTokenPrefix)
	if err != nil {
		return "", err
	}
	if err := s.ensureBootstrapToken(ctx, tok, api.RoleNode, maxUsages, ttl, "agentmesh-one device enrollment via "+s.PublicURL()); err != nil {
		return "", fmt.Errorf("failed to register device enrollment token: %w", err)
	}
	return tok, nil
}

// seedPolicyOnFirstBoot installs the mesh policy only when none exists; the
// database stays authoritative afterwards.
func (s *Server) seedPolicyOnFirstBoot(ctx context.Context) error {
	roles, _, err := s.store.GetMeshPolicy(ctx)
	if err != nil && err != storage.ErrNotFound {
		return fmt.Errorf("failed to inspect mesh policy: %w", err)
	}
	if len(roles) > 0 {
		if s.opts.PolicyFile != "" {
			logger.Warnf("Mesh policy already present; ignoring --policy-file %s (edit via POST /policies)", s.opts.PolicyFile)
		}
		return nil
	}

	var seed api.PolicyConfig
	if s.opts.PolicyFile != "" {
		data, err := os.ReadFile(s.opts.PolicyFile)
		if err != nil {
			return fmt.Errorf("failed to read policy file: %w", err)
		}
		if err := protojson.Unmarshal(data, &seed); err != nil {
			return fmt.Errorf("failed to parse policy file %s (expects protojson PolicyConfig): %w", s.opts.PolicyFile, err)
		}
		logger.Infof("Seeding mesh policy from %s", s.opts.PolicyFile)
	} else {
		seed.Roles = defaultDevPolicyRoles()
		logger.Warn("Seeding OPEN development mesh policy (enrolled nodes may declare any label and register any service); provide --policy-file to restrict")
	}
	if err := controlplane.ValidatePolicyConfig(&seed); err != nil {
		return fmt.Errorf("invalid seed mesh policy: %w", err)
	}
	// The whole document, as POST /policies stores it: a seed file that names
	// egress destinations must serve them too.
	if err := s.store.SavePolicyDocument(ctx, seed.Roles, seed.Bindings, seed.Egress); err != nil {
		return fmt.Errorf("failed to seed mesh policy: %w", err)
	}
	return nil
}

// defaultDevPolicyRoles mirrors the Helm bootstrap job's role set with the
// node role opened up for zero-config development use.
func defaultDevPolicyRoles() []*api.PolicyRole {
	devIngress := []*api.IngressGrant{{
		Services: []string{"*"},
		AllowedAuthModes: []api.IngressAuthMode{
			api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
			api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH,
		},
	}}
	return []*api.PolicyRole{
		{Name: "mesh-admin", AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}, AllowedIngress: devIngress},
		{Name: api.RoleRouter, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}},
		{Name: api.RoleNode, AllowedServices: []string{"*"}, AllowedPublish: []string{"*"}, AllowedTargets: []string{"*"}, AllowedLabels: []string{"*"}, AllowedIngress: devIngress},
	}
}

// ensureBootstrapToken stores the hashed token if absent (idempotent).
func (s *Server) ensureBootstrapToken(ctx context.Context, plaintext, role string, maxUsages int, ttl time.Duration, description string) error {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(plaintext)))
	now := time.Now()
	return s.store.SaveBootstrapToken(ctx, &storage.BootstrapToken{
		ID:          id,
		TokenHash:   id,
		Role:        role,
		MaxUsages:   maxUsages,
		Description: description,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	})
}

// resolvePublicAddr recovers the actually-bound port from the router's WS
// listen addr and pairs it with the configured bind host.
func (s *Server) resolvePublicAddr() (string, error) {
	host, _, err := net.SplitHostPort(s.opts.BindAddress)
	if err != nil {
		return "", err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	for _, a := range s.router.Host.Network().ListenAddresses() {
		if _, err := a.ValueForProtocol(multiaddr.P_WS); err != nil {
			continue
		}
		port, err := a.ValueForProtocol(multiaddr.P_TCP)
		if err != nil {
			continue
		}
		return net.JoinHostPort(host, port), nil
	}
	return "", fmt.Errorf("router reports no WebSocket listen address")
}

func generateToken(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

// AdminTokenFromDataDir reads the admin token a previous run persisted in
// dataDir, so CLI subcommands can authenticate without re-supplying it.
func AdminTokenFromDataDir(dataDir string) (string, error) {
	path := filepath.Join(dataDir, adminTokenFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return tok, nil
}

// loadOrCreateTokenFile reuses the token persisted at path, generating and
// saving a fresh one (0600) on first boot.
func loadOrCreateTokenFile(path, prefix string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		tok := strings.TrimSpace(string(data))
		if tok == "" {
			return "", fmt.Errorf("token file %s is empty", path)
		}
		return tok, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	tok, err := generateToken(prefix)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("failed to persist token: %w", err)
	}
	return tok, nil
}

// wsListenMultiaddr turns a host:port bind address into a WebSocket listen
// multiaddr.
func wsListenMultiaddr(bind string) (string, error) {
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return "", err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("bind host %q must be an IP literal", host)
	}
	if ip.To4() != nil {
		return fmt.Sprintf("/ip4/%s/tcp/%s/ws", ip, port), nil
	}
	return fmt.Sprintf("/ip6/%s/tcp/%s/ws", ip, port), nil
}

// externalMultiaddr turns a public http(s) URL into the ws/wss multiaddr the
// router advertises (http -> /ws, https -> /wss with TLS terminated at the
// platform edge).
func externalMultiaddr(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	var wsProto, defaultPort string
	switch u.Scheme {
	case "http":
		wsProto, defaultPort = "ws", "80"
	case "https":
		wsProto, defaultPort = "wss", "443"
	default:
		return "", fmt.Errorf("scheme %q not supported (use http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("URL has no host")
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	hostProto := "dns4"
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			hostProto = "ip4"
		} else {
			hostProto = "ip6"
		}
	}
	addr := fmt.Sprintf("/%s/%s/tcp/%s/%s", hostProto, host, port, wsProto)
	if _, err := multiaddr.NewMultiaddr(addr); err != nil {
		return "", err
	}
	return addr, nil
}

// ensureRouterKey seeds router.key deterministically from an operator-supplied
// adminToken when no router.key file exists on disk yet. On stateless
// single-container platforms (e.g. Cloud Run) where /data is ephemeral and
// AGENTMESH_ADMIN_TOKEN is pinned via environment variable, this keeps the embedded
// router's libp2p PeerID stable across container restarts without extra config.
func ensureRouterKey(keyPath, adminToken string) error {
	if _, err := os.Stat(keyPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if strings.TrimSpace(adminToken) == "" {
		return nil
	}
	seed := sha256.Sum256([]byte("agentmesh-one-router-ed25519-v1:" + strings.TrimSpace(adminToken)))
	priv, _, err := crypto.GenerateEd25519Key(bytes.NewReader(seed[:]))
	if err != nil {
		return err
	}
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(keyPath, data, 0o600)
}

// proxiedWithoutExternalURL counts requests that arrived through a reverse
// proxy (X-Forwarded-Proto or X-Forwarded-Host present) while no
// --external-url is configured. The router address and the OIDC issuer this
// instance advertises are then its own listener, which a member behind that
// proxy cannot reach.
var proxiedWithoutExternalURL = promauto.NewCounter(prometheus.CounterOpts{
	Name: "agentmesh_one_proxied_requests_without_external_url_total",
	Help: "Requests that arrived with X-Forwarded-* headers while --external-url is not set; the advertised router address and OIDC issuer are not reachable through that proxy",
})

// wrapPublicHTTPHandler makes a misconfiguration visible: what this instance
// advertises (the router multiaddr on /info and /enroll, the OIDC issuer in
// discovery and in the JWTs it signs) comes from --external-url, or from its
// own listener when the flag is absent. Nothing is derived from request
// headers; an address a member learns is a reachability hint, and the
// member verifies the peer's key and the router's control-plane-signed
// credential on connection. So a hub behind a TLS-terminating proxy that
// did not state its public URL is not unsafe, it is unreachable: the first
// proxied request logs that, and every one is counted.
func (s *Server) wrapPublicHTTPHandler(next http.Handler) http.Handler {
	if s.opts.ExternalURL != "" {
		return next
	}
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") != "" || r.Header.Get("X-Forwarded-Host") != "" {
			proxiedWithoutExternalURL.Inc()
			once.Do(func() {
				logger.Warnw("Requests arrive through a reverse proxy but --external-url is not set; the router address and the OIDC issuer this instance advertises are its own listener, which members behind the proxy cannot reach. Set --external-url to the public https URL",
					"forwarded_proto", r.Header.Get("X-Forwarded-Proto"), "forwarded_host", r.Header.Get("X-Forwarded-Host"), "host", r.Host)
			})
		}
		next.ServeHTTP(w, r)
	})
}
