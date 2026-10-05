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
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/console"
	"github.com/google/sam/internal/controlplane"
	"github.com/google/sam/internal/router"
	"github.com/google/sam/internal/storage"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var logger = golog.Logger("sam-one")

const (
	joinTokenPrefix   = "sam_tok_"
	adminTokenPrefix  = "sam_adm_"
	deviceTokenPrefix = "sam_dev_"

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
	// <DataDir>/sam.db for sqlite.
	DBDSN string
	// JoinToken is the cluster join token; auto-generated and persisted in
	// DataDir when empty.
	JoinToken string
	// DisableJoinToken runs without any standing join token: devices then
	// enroll only with explicitly minted bootstrap tokens or through OIDC.
	// The right setting for a fleet; the default keeps `sam-node join` on a
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
	// BiscuitTTL is the lifespan minted into issued biscuits.
	BiscuitTTL time.Duration
	// WorkloadSessionTTL is how long a workload-issuer enrollment stays
	// refreshable without presenting a fresh platform JWT on /refresh.
	WorkloadSessionTTL time.Duration
	// ManualEnrollment queues bootstrap enrollments for admin approval
	// instead of auto-approving them.
	ManualEnrollment bool
}

// RouterTunables are the embedded router's operator knobs.
type RouterTunables struct {
	// KeysSyncInterval is how often biscuit public keys are refreshed.
	KeysSyncInterval time.Duration
	// LeaseRenewInterval is how often the router renews its lease.
	LeaseRenewInterval time.Duration
	// LowWaterMark / HighWaterMark bound the connection manager.
	LowWaterMark  int
	HighWaterMark int
	// ConnsPerSourceIP scales libp2p's per-source-IP budgets; defaults to
	// the connection manager high watermark (proxied deployments share
	// source IPs, so the global cap should be what binds).
	ConnsPerSourceIP int
	// DHTProviderAddrTTL / DHTMaxRecordAge tune DHT record lifetimes.
	DHTProviderAddrTTL time.Duration
	DHTMaxRecordAge    time.Duration
	// RelayLimitDuration / RelayLimitData cap each relayed connection.
	RelayLimitDuration time.Duration
	RelayLimitData     router.ByteSize
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
		o.DBDSN = filepath.Join(o.DataDir, "sam.db")
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
func (s *Server) Start(ctx context.Context) error {
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
		ListenAddr:            "127.0.0.1:0",
		DriverName:            s.opts.DBDriver,
		DataSourceName:        s.opts.DBDSN,
		OIDCIssuer:            s.opts.OIDCIssuer,
		WorkloadIssuer:        s.opts.WorkloadIssuer,
		OIDCClientID:          s.opts.OIDCClientID,
		AllowedAudiences:      s.opts.AllowedAudiences,
		LeaseDuration:         s.opts.ControlPlane.LeaseDuration,
		KeyRotationInterval:   s.opts.ControlPlane.KeyRotationInterval,
		KeyGracePeriod:        s.opts.ControlPlane.KeyGracePeriod,
		BiscuitTTL:            s.opts.ControlPlane.BiscuitTTL,
		WorkloadSessionTTL:    s.opts.ControlPlane.WorkloadSessionTTL,
		BiscuitTimeout:        10 * time.Second,
		AdminToken:            s.adminToken,
		AutoApproveEnrollment: !s.opts.ControlPlane.ManualEnrollment,
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
		if err := s.ensureBootstrapToken(ctx, s.joinToken, api.RoleNode, joinTokenMaxUsages, joinTokenTTL, "sam-one join token"); err != nil {
			return fmt.Errorf("failed to register join token: %w", err)
		}
	}

	// Per-boot single-use credential for the embedded router's stock
	// enrollment flow; never persisted or displayed.
	routerToken, err := generateToken("sam_rtr_")
	if err != nil {
		return err
	}
	if err := s.ensureBootstrapToken(ctx, routerToken, api.RoleRouter, 1, routerTokenTTL, "sam-one embedded router token"); err != nil {
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

	wsAddr, err := wsListenMultiaddr(s.opts.BindAddress)
	if err != nil {
		return err
	}
	var externalAddrs []string
	if s.opts.ExternalURL != "" {
		ext, err := externalMultiaddr(s.opts.ExternalURL)
		if err != nil {
			return err
		}
		externalAddrs = []string{ext}
	}

	routerKeyPath := filepath.Join(s.opts.DataDir, routerKeyFile)
	if err := ensureRouterKey(routerKeyPath, s.opts.AdminToken); err != nil {
		return fmt.Errorf("failed to provision router key: %w", err)
	}

	rtr, err := router.NewRouter(ctx, router.Options{
		ControlPlaneURL:    "http://" + cp.Addr(),
		ListenAddrs:        append([]string{wsAddr}, s.opts.P2PListen...),
		ExternalAddrs:      externalAddrs,
		AllowLoopback:      !s.opts.Router.DisallowLoopback,
		KeysDBPath:         routerKeyPath,
		BootstrapToken:     routerToken,
		KeysSyncInterval:   s.opts.Router.KeysSyncInterval,
		LeaseRenewInterval: s.opts.Router.LeaseRenewInterval,
		LowWaterMark:       s.opts.Router.LowWaterMark,
		HighWaterMark:      s.opts.Router.HighWaterMark,
		DHTProviderAddrTTL: s.opts.Router.DHTProviderAddrTTL,
		DHTMaxRecordAge:    s.opts.Router.DHTMaxRecordAge,
		RelayLimitDuration: s.opts.Router.RelayLimitDuration,
		RelayLimitData:     int64(s.opts.Router.RelayLimitData),
		// Single-port deployments typically sit behind a TLS-terminating
		// proxy (Cloud Run, L7 LBs) or NAT where every peer shares a few
		// source IPs; libp2p's default 8-conns-per-IP cap would throttle
		// the whole listener.
		ConnsPerSourceIP:    s.opts.Router.ConnsPerSourceIP,
		HTTPFallbackHandler: s.wrapPublicHTTPHandler(mux),
	})
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}
	if err := rtr.Start(); err != nil {
		return fmt.Errorf("failed to start router: %w", err)
	}
	s.router = rtr
	// One process, one mesh peer: the control plane publishes its events on
	// the embedded router's own topic instead of dialing itself.
	mesh, err := controlplane.NewP2PMeshAdapter(rtr.Host, rtr.EventTopic, store)
	if err != nil {
		_ = rtr.Close()
		return fmt.Errorf("failed to attach control plane to the mesh: %w", err)
	}
	cp.SetMeshAdapter(mesh)
	if s.publicAddr, err = s.resolvePublicAddr(); err != nil {
		_ = rtr.Close()
		return err
	}
	return nil
}

// Close shuts down the router, control plane and store.
func (s *Server) Close() error {
	var errs []string
	if s.router != nil {
		if err := s.router.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if s.cp != nil {
		if err := s.cp.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			errs = append(errs, err.Error())
		}
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

// AdminToken returns the resolved admin API token.
func (s *Server) AdminToken() string { return s.adminToken }

// JoinToken returns the resolved cluster join token, or "" when the server
// runs with DisableJoinToken.
func (s *Server) JoinToken() string { return s.joinToken }

// JoinTokenPath is where an auto-generated join token is persisted, for
// `sam-node join --bootstrap-token-path`.
func (s *Server) JoinTokenPath() string { return filepath.Join(s.opts.DataDir, joinTokenFile) }

// PeerID returns the embedded router's peer ID.
func (s *Server) PeerID() string { return s.router.Host.ID().String() }

// MintDeviceEnrollmentToken registers a fresh node bootstrap token good for
// maxUsages enrollments (1 = burned by the first device; more lets one code
// on a projector enroll a room) and returns its plaintext once. Unlike the
// join token it is never persisted; a device that missed the window simply
// gets a new one, and `sam-one token revoke` ends a shared one early.
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
	if err := s.ensureBootstrapToken(ctx, tok, api.RoleNode, maxUsages, ttl, "sam-one device enrollment via "+s.PublicURL()); err != nil {
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
	return []*api.PolicyRole{
		{Name: "sam-admin", AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}},
		{Name: api.RoleRouter, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}},
		{Name: api.RoleNode, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}, AllowedLabels: []string{"*"}},
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
// SAM_ADMIN_TOKEN is pinned via environment variable, this keeps the embedded
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
	seed := sha256.Sum256([]byte("sam-one-router-ed25519-v1:" + strings.TrimSpace(adminToken)))
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

type responseRecorder struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{
		header: make(http.Header),
		code:   http.StatusOK,
	}
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.code = statusCode
}

// wrapPublicHTTPHandler augments control-plane endpoints that return
// RouterAddresses (/info, /enroll, /enroll/status, /enroll/oidc, /refresh) on
// the public listener when no explicit --external-url was configured: it
// derives the router's public ws/wss multiaddr from the incoming request's
// Host / X-Forwarded-Host and X-Forwarded-Proto headers so single-step PaaS
// deployments (Cloud Run, Fly.io, Render) advertise a dialable wss multiaddr
// without a second deploy pass.
func (s *Server) wrapPublicHTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.ExternalURL != "" || s.router == nil || !returnsRouterAddresses(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		inferredAddr, ok := inferredRequestMultiaddr(r, s.PeerID())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		rec := newResponseRecorder()
		next.ServeHTTP(rec, r)
		for k, vals := range rec.Header() {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		if rec.code != http.StatusOK {
			w.WriteHeader(rec.code)
			_, _ = w.Write(rec.body.Bytes())
			return
		}
		out, ok := prependInferredRouterAddr(r.URL.Path, rec.body.Bytes(), inferredAddr)
		if !ok {
			w.WriteHeader(rec.code)
			_, _ = w.Write(rec.body.Bytes())
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Header().Del("Content-Length")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	})
}

func returnsRouterAddresses(path string) bool {
	switch path {
	case "/info", "/enroll", "/enroll/status", "/enroll/oidc", "/refresh":
		return true
	default:
		return false
	}
}

func prependInferredRouterAddr(path string, body []byte, inferredAddr string) ([]byte, bool) {
	prepend := func(existing []string) []string {
		out := make([]string, 0, len(existing)+1)
		out = append(out, inferredAddr)
		for _, a := range existing {
			if a != inferredAddr {
				out = append(out, a)
			}
		}
		return out
	}
	switch path {
	case "/info":
		var msg api.ControlPlaneInfoResponse
		if err := proto.Unmarshal(body, &msg); err != nil {
			return nil, false
		}
		msg.RouterAddresses = prepend(msg.RouterAddresses)
		b, err := proto.Marshal(&msg)
		return b, err == nil
	case "/enroll", "/enroll/status":
		var msg api.BootstrapEnrollResponse
		if err := proto.Unmarshal(body, &msg); err != nil {
			return nil, false
		}
		msg.RouterAddresses = prepend(msg.RouterAddresses)
		b, err := proto.Marshal(&msg)
		return b, err == nil
	case "/enroll/oidc", "/refresh":
		var msg api.EnrollResponse
		if err := proto.Unmarshal(body, &msg); err != nil {
			return nil, false
		}
		msg.RouterAddresses = prepend(msg.RouterAddresses)
		b, err := proto.Marshal(&msg)
		return b, err == nil
	default:
		return nil, false
	}
}

// inferredRequestMultiaddr derives `/dns4/<host>/tcp/<port>/ws(s)/p2p/<peerID>`
// from an HTTP request when the request either arrived over HTTPS (TLS or
// X-Forwarded-Proto: https) or names a non-loopback host.
func inferredRequestMultiaddr(r *http.Request, peerID string) (string, bool) {
	if peerID == "" {
		return "", false
	}
	host := firstForwardedValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return "", false
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(firstForwardedValue(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	}
	if scheme == "http" && isLoopbackOrUnspecifiedHostPort(host) {
		return "", false
	}
	base, err := externalMultiaddr(scheme + "://" + host)
	if err != nil {
		return "", false
	}
	full := base + "/p2p/" + peerID
	if _, err := multiaddr.NewMultiaddr(full); err != nil {
		return "", false
	}
	return full, true
}

func firstForwardedValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

func isLoopbackOrUnspecifiedHostPort(hostport string) bool {
	h := hostport
	if splitHost, _, err := net.SplitHostPort(hostport); err == nil {
		h = splitHost
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") || h == "" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}
