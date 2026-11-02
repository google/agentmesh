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
//
// Internally, meshnet wraps internal/node.AgentMeshNode so embedded Go
// applications and the standalone agentmesh-node binary share a single Policy
// Enforcement Point (PEP), router attachment loop, directory client, and
// credential lifecycle implementation.
package meshnet

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/node"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrCredentialLapsed reports that the member's Biscuit credential has expired
// and background renewal failed. Background renewal continues retrying with
// exponential backoff until Close is called or renewal succeeds.
var ErrCredentialLapsed = errors.New("meshnet: member credential expired and renewal failed")

// Server is an embedded Agent Mesh node. Configure its exported fields and call
// Up (and then ListenA2A, HTTPClient, MCPHandler, or InferenceHandler) to join
// the mesh in-process.
type Server struct {
	// StateDir persists identity.key and credential.json (0700/0600, byte-for-byte
	// compatible with sdk/js, sdk/python, and `agentmesh-node state export|import`)
	// alongside the local bbolt store lock (agent.db), returning ErrStateDirLocked
	// if another Server or agentmesh-node instance already holds the directory.
	// When empty, Up creates an ephemeral Ed25519 identity in a temporary 0700
	// directory that is removed on Close (or if Up fails).
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
	// hole-punching work alongside Circuit Relay v2 without colliding across
	// multiple in-process Servers.
	ListenAddrs []string

	// AllowInsecure opts into http:// control-plane URLs and keeps
	// loopback/private peer multiaddrs during local development and integration tests.
	AllowInsecure bool

	// Registerer, when non-nil, registers per-Server state gauges and refusal
	// counters wrapped with peer_id="<id>" so multiple Servers can share one
	// Prometheus registry without colliding. Collectors are unregistered on
	// Close. When nil, no per-Server Prometheus collectors are registered.
	Registerer prometheus.Registerer

	// OnCredentialLapse, when non-nil, is invoked whenever a background renewal
	// attempt fails after the member's credential has expired. Background
	// renewal continues retrying with exponential backoff (2s up to 5m).
	OnCredentialLapse func(err error)

	// Logger receives structured meshnet lifecycle warnings and diagnostics.
	// Defaults to slog.Default().
	Logger *slog.Logger

	// Unexported test seams (zero values use production defaults).
	biscuitTimeout        time.Duration
	renewalInitialBackoff time.Duration
	renewalMaxBackoff     time.Duration

	lifecycleMu sync.Mutex
	started     bool
	closed      bool
	runCancel   context.CancelFunc

	privKey        crypto.PrivKey
	peerID         peer.ID
	cpURL          string
	store          *node.Store
	storeTmpDir    string
	stateDirSyncMu sync.Mutex
	node           *node.AgentMeshNode
	metrics        atomic.Pointer[serverMetrics]

	refusedMu      sync.Mutex
	refusedStreams map[string]uint64

	doneInitOnce     sync.Once
	doneCloseOnce    sync.Once
	doneCh           chan struct{}
	errMu            sync.RWMutex
	lapseErr         error
	credentialLapsed atomic.Bool

	mcpHandlerOnce sync.Once
	mcpHTTPHandler http.Handler
	infHandlerOnce sync.Once
	infHTTPHandler http.Handler

	activeConns sync.Map
	nextConnSeq atomic.Uint64
}

// Status describes the live mesh connectivity and credential state of a Server.
// Because Up returns as soon as the first router admits the member while
// remaining router dials finish in the background, AttachedRouters immediately
// after Up may list one router before reaching Server.Routers.
type Status struct {
	PeerID           string
	ControlPlaneURL  string
	AttachedRouters  []string
	IngressURLs      []string
	ExpireTime       time.Time
	CredentialLapsed bool
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

func (s *Server) ensureDoneCh() chan struct{} {
	s.doneInitOnce.Do(func() {
		s.doneCh = make(chan struct{})
	})
	return s.doneCh
}

func (s *Server) signalDone() {
	ch := s.ensureDoneCh()
	s.doneCloseOnce.Do(func() {
		close(ch)
	})
}

func (s *Server) handleCredentialLapse(peerID peer.ID, err error) {
	s.credentialLapsed.Store(true)
	if m := s.metrics.Load(); m != nil {
		m.credentialLapses.Inc()
	}
	wrapped := fmt.Errorf("%w: %w", ErrCredentialLapsed, err)
	s.errMu.Lock()
	s.lapseErr = wrapped
	s.errMu.Unlock()
	s.signalDone()
	s.log().Error("member credential expired and renewal failed; retrying with exponential backoff",
		"peer_id", peerID.String(),
		"error", err,
	)
	if s.OnCredentialLapse != nil {
		s.OnCredentialLapse(wrapped)
	}
}

func (s *Server) handleCredentialRenewed(peerID peer.ID) {
	s.credentialLapsed.Store(false)
	s.log().Info("member credential renewed", "peer_id", peerID.String())
}

// Done returns a channel that is closed when either the member's credential
// lapses (Err() wraps ErrCredentialLapsed) or Close is called (Err() is nil
// unless a lapse already occurred).
func (s *Server) Done() <-chan struct{} {
	return s.ensureDoneCh()
}

// Err returns nil while the Server's credential is healthy and after a clean
// Close, or an error wrapping ErrCredentialLapsed if the member's credential
// expired and background renewal failed. Check Status().CredentialLapsed to
// observe whether a subsequent backoff retry has recovered the credential.
func (s *Server) Err() error {
	s.errMu.RLock()
	defer s.errMu.RUnlock()
	return s.lapseErr
}

func (s *Server) runningNode() *node.AgentMeshNode {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if !s.started || s.closed || s.node == nil || s.node.Host == nil {
		return nil
	}
	return s.node
}

func (s *Server) stateSnapshot() (*node.AgentMeshNode, *node.Store, peer.ID, string) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.closed {
		return nil, nil, "", ""
	}
	return s.node, s.store, s.peerID, s.cpURL
}

func (s *Server) closeStoreLocked() error {
	var errs []error
	if s.store != nil {
		if s.started {
			if err := s.syncStateDir(s.store); err != nil {
				errs = append(errs, err)
			}
		}
		if err := s.store.Close(); err != nil {
			errs = append(errs, err)
		}
		s.store = nil
	}
	if s.storeTmpDir != "" {
		if err := os.RemoveAll(s.storeTmpDir); err != nil {
			errs = append(errs, err)
		}
		s.storeTmpDir = ""
	}
	return errors.Join(errs...)
}

// Up loads or enrolls the member credential, syncs mesh trust material and
// policy from the control plane, starts the gated libp2p host, authenticates
// with mesh routers, and starts background renewal, sync, and reprovide loops.
//
// Up returns as soon as at least one router admits the member while any
// remaining router dials up to Server.Routers complete in the background, so
// the returned Status.AttachedRouters may initially list a single router.
func (s *Server) Up(ctx context.Context) (*Status, error) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if s.closed {
		return nil, errors.New("meshnet: Server has been closed")
	}
	if s.started {
		st := s.statusLocked()
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

	s.ensureDoneCh()

	if err := s.ensureCredential(ctx); err != nil {
		return nil, err
	}

	if err := s.node.SyncControlPlane(ctx); err != nil {
		s.log().Warn("initial control plane sync completed with errors; falling back to cached state where available",
			"peer_id", s.peerID.String(),
			"error", err,
		)
	}

	if s.Registerer != nil {
		m, err := newServerMetrics(s, s.Registerer)
		if err != nil {
			_ = s.closeStoreLocked()
			s.node = nil
			return nil, fmt.Errorf("meshnet: register metrics: %w", err)
		}
		s.metrics.Store(m)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	stopAbort := context.AfterFunc(ctx, runCancel)
	startErr := s.node.Start(runCtx)
	abortedByCaller := !stopAbort()
	if startErr != nil {
		runCancel()
		if m := s.metrics.Swap(nil); m != nil {
			m.unregister()
		}
		_ = s.node.Teardown()
		_ = s.closeStoreLocked()
		s.node = nil
		if abortedByCaller && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, startErr
	}

	if err := s.syncStateDir(s.store); err != nil {
		s.log().Warn("failed to sync state directory after startup", "error", err)
	}
	s.startRenewalLoop(runCtx, s.node, s.store, s.peerID, s.cpURL)
	s.runCancel = runCancel
	s.started = true

	st := s.statusLocked()
	return &st, nil
}

// Status returns a snapshot of the member's PeerID, control-plane URL,
// currently attached routers, public router ingress base URLs, credential
// expiry, and live credential-lapse state. Because Up returns on the first
// router admission while additional router dials finish in the background,
// AttachedRouters may list fewer than Server.Routers immediately after Up.
func (s *Server) Status() Status {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.statusLocked()
}

func (s *Server) statusLocked() Status {
	var peerIDStr string
	if s.peerID != "" {
		peerIDStr = s.peerID.String()
	}

	var routerStrs []string
	var ingressURLs []string
	if s.node != nil && !s.closed {
		if s.node.Host != nil {
			routers := s.node.AttachedRouterIDs()
			routerStrs = make([]string, 0, len(routers))
			for _, r := range routers {
				routerStrs = append(routerStrs, r.String())
			}
			sort.Strings(routerStrs)
		}
		ingressURLs = s.node.RouterIngressURLs()
	}

	return Status{
		PeerID:           peerIDStr,
		ControlPlaneURL:  s.cpURL,
		AttachedRouters:  routerStrs,
		IngressURLs:      ingressURLs,
		ExpireTime:       credentialExpireTimeFromStore(s.store),
		CredentialLapsed: s.credentialLapsed.Load(),
	}
}

// Close withdraws directory records (bounded to 5s), closes all registered A2A
// listeners, unregisters per-Server Prometheus collectors, stops background
// loops, and shuts down the libp2p host and state store.
func (s *Server) Close() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	s.signalDone()

	if m := s.metrics.Swap(nil); m != nil {
		m.unregister()
	}

	if s.runCancel != nil {
		s.runCancel()
	}

	var errs []error
	if s.node != nil {
		if err := s.node.Teardown(); err != nil {
			errs = append(errs, err)
		}
		s.node = nil
	}
	if err := s.closeStoreLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Discover queries the mesh directory for providers offering serviceType (and
// optionally a specific serviceName; pass "" to browse all providers of that
// type via parallel catalog fan-out). Returned DiscoveredProvider.LocalProxyUrl
// values can be passed directly to Server.HTTPClient.
func (s *Server) Discover(ctx context.Context, serviceType api.ServiceType, serviceName string) ([]*api.DiscoveredProvider, error) {
	n := s.runningNode()
	if n == nil {
		return nil, errors.New("meshnet: Server is not running (call Up first)")
	}
	if serviceType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return nil, errors.New("meshnet: serviceType must not be SERVICE_TYPE_UNSPECIFIED")
	}
	if _, err := api.ServiceTypeToString(serviceType); err != nil {
		return nil, err
	}
	return n.DiscoverRemoteServices(ctx, serviceType, serviceName)
}

// MCPServer returns an in-process *mcp.Server exposing the 6 progressive mesh
// discovery and tool-invocation tools (get_mesh_info, list_local_services,
// discover_remote_services, find_remote_tools, describe_remote_tool,
// call_remote_tool). Returns nil if Up has not succeeded.
func (s *Server) MCPServer() *mcp.Server {
	n := s.runningNode()
	if n == nil {
		return nil
	}
	return node.NewMCPServer(n)
}

// MCPHandler returns a stateless StreamableHTTP handler serving Server.MCPServer
// at "/", "/mcp", and "/mcp/".
func (s *Server) MCPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := s.runningNode()
		if n == nil {
			http.Error(w, "meshnet: Server is not running", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "", "/", "/mcp", "/mcp/":
		default:
			http.NotFound(w, r)
			return
		}
		s.mcpHandlerOnce.Do(func() {
			s.mcpHTTPHandler = node.NewMCPHandler(n)
		})
		if r.URL.Path != "/mcp" {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/mcp"
			r2.URL.RawPath = ""
			r = r2
		}
		s.mcpHTTPHandler.ServeHTTP(w, r)
	})
}

// InferenceHandler returns a zero-secret OpenAI-compatible HTTP handler serving
// GET /v1/models, POST /v1/chat/completions, and POST /v1/completions backed by
// inference://* providers on the mesh.
func (s *Server) InferenceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := s.runningNode()
		if n == nil {
			http.Error(w, "meshnet: Server is not running", http.StatusServiceUnavailable)
			return
		}
		s.infHandlerOnce.Do(func() {
			s.infHTTPHandler = n.InferenceHandler()
		})
		s.infHTTPHandler.ServeHTTP(w, r)
	})
}

// AttenuateToken appends a validated TaskAuthorizationRule (tar_block fact,
// 0 Datalog rules, 0 checks) to the Server's current Biscuit in memory without
// a control-plane round trip, optionally sealing it so downstream holders
// cannot append further blocks.
func (s *Server) AttenuateToken(rule *api.TaskAuthorizationRule, ttl time.Duration, seal bool) (string, time.Time, error) {
	n, store, _, _ := s.stateSnapshot()
	if n == nil {
		return "", time.Time{}, errors.New("meshnet: Server is not running (call Up first)")
	}
	if rule == nil {
		return "", time.Time{}, errors.New("TaskAuthorizationRule is required")
	}
	raw := n.GetIdentity()
	if len(raw) == 0 {
		return "", time.Time{}, errors.New("no member credential loaded")
	}

	cloned := proto.Clone(rule).(*api.TaskAuthorizationRule)
	now := time.Now()
	exp := credentialExpireTimeFromStore(store)
	if exp.IsZero() {
		exp = now.Add(api.BiscuitTokenTTL)
	}
	if ttl > 0 {
		if candidate := now.Add(ttl); candidate.Before(exp) {
			exp = candidate
		}
	}
	if cloned.GetExpireTime() != nil {
		if ruleExp := cloned.GetExpireTime().AsTime(); ruleExp.Before(exp) {
			exp = ruleExp
		}
	}
	if !now.Before(exp) {
		return "", time.Time{}, errors.New("attenuated token expiration is in the past")
	}
	cloned.ExpireTime = timestamppb.New(exp)

	out, err := identity.AttenuateBiscuit(raw, cloned)
	if err != nil {
		return "", time.Time{}, err
	}
	if seal {
		out, err = identity.SealBiscuit(out)
		if err != nil {
			return "", time.Time{}, err
		}
	}
	return base64.RawURLEncoding.EncodeToString(out), exp, nil
}
