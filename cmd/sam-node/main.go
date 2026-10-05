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

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/node"
	"github.com/google/sam/internal/secrets"
	"github.com/google/sam/internal/version"
	golog "github.com/ipfs/go-log/v2"
	"github.com/mattn/go-isatty"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/spf13/cobra"
)

func init() {
	if dnsServer := os.Getenv("SAM_TEST_DNS_SERVER"); dnsServer != "" {
		customResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		net.DefaultResolver = customResolver
		madns.DefaultResolver, _ = madns.NewResolver(madns.WithDefaultResolver(customResolver))
	}
}

var (
	controlPlaneAddr             string
	joinFlag                     bool
	jwtFlag                      string
	jwtPathFlag                  string
	bootstrapTokenFlag           string
	clientIDFlag                 string
	clientSecretFlag             string
	controlPlanePublicKeyFlag    string
	bindAddrFlag                 string
	metricsAddrFlag              string
	socketPathFlag               string
	meshFlag                     string
	discoveryIntervalFlag        string
	listenAddrs                  []string
	enableRelayFlag              bool
	configFile                   string
	oidcIssuerFlag               string
	deviceAuthURLFlag            string
	audienceFlag                 string
	dataDirFlag                  string
	headlessFlag                 bool
	authModeFlag                 string
	insecureControlPlaneFlag     bool
	daemonizeFlag                bool
	resetAllFlag                 bool
	assumeYesFlag                bool
	offlineAccessFlag            bool
	logLevelFlag                 string
	keyGracePeriodFlag           time.Duration
	allowLoopbackFlag            bool
	announcePrivateFlag          bool
	monitorBootstrapFlag         time.Duration
	monitorCheckIntervalFlag     time.Duration
	autoRelayMinIntervalFlag     time.Duration
	autoRelayBootDelayFlag       time.Duration
	autoRelayBackoffFlag         time.Duration
	routerConnectTimeoutFlag     time.Duration
	apiTokenFlag                 string
	apiTokenPathFlag             string
	bootstrapTokenPathFlag       string
	clientSecretPathFlag         string
	tlsCertFlag                  string
	tlsKeyFlag                   string
	tlsCAFlag                    string
	dhtProviderAddrTTLFlag       time.Duration
	dhtMaxRecordAgeFlag          time.Duration
	dhtLookupLimitFlag           int
	discoveryConcurrencyFlag     int
	backendProbeTimeoutFlag      time.Duration
	secretsDirFlag               string
	controlPlaneSyncIntervalFlag time.Duration
	cloudProviderFlag            string
)

var logger = golog.Logger("sam-node-cli")

// resolveSecretFlag folds a --<name>-path file variant into its value flag
// and warns when the secret was passed on the command line, where it leaks
// via /proc/<pid>/cmdline, shell history, and pod specs.
func resolveSecretFlag(name, value, path string) string {
	if value != "" {
		logger.Warnf("--%s passes a secret on the command line; prefer --%s-path", name, name)
	}
	secret, err := secrets.Resolve(name, value, path)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	return secret
}

// resolveDaemonSecret resolves a secret that lives for the daemon's whole
// lifetime: file (recommended) or environment variable, never a flag value.
func resolveDaemonSecret(name, path, envVar string) string {
	secret, err := secrets.FromPathOrEnv(name, path, envVar)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	return secret
}

// isInteractiveTerminal reports whether stdin is a real terminal (not just a
// character device like /dev/null), so --join knows it can safely block on
// an interactive OIDC login prompt.
func isInteractiveTerminal() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// defaultControlPlane resolves which control plane to use when none was
// explicitly passed: the previously stored one, or "" when this node has
// never been pointed at a mesh (joining then requires --control-plane).
func defaultControlPlane(store *node.Store, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if h, err := store.LoadControlPlaneURL(); err == nil && h != "" {
		return h
	}
	return ""
}

// isYesResponse reports whether a raw prompt answer is an explicit "y"/"yes"
// (case/whitespace-insensitive). Anything else, including a blank answer, is
// a "no".
func isYesResponse(response string) bool {
	switch strings.ToLower(strings.TrimSpace(response)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// joinAction is the outcome of deciding what "--join" should do, given the
// node's current identity state and how it was invoked. Deciding this is
// pure/side-effect-free so it can be unit tested directly, instead of only
// through slow end-to-end runs of the CLI across every flag combination.
type joinAction int

const (
	// joinSkip: a usable identity is already stored; --join is a no-op.
	joinSkip joinAction = iota
	// joinFatalMismatchNoTTY: --control-plane conflicts with the stored
	// mesh and there's no terminal to confirm switching; must fail fast.
	joinFatalMismatchNoTTY
	// joinFallbackNoTTY: no usable identity and no terminal to run an
	// interactive login; fall back to the unauthenticated MCP sidecar.
	joinFallbackNoTTY
	// joinNeedsConfirmSwitch: --control-plane conflicts with the stored
	// mesh; an interactive terminal must confirm resetting and rejoining.
	joinNeedsConfirmSwitch
	// joinNeedsControlPlane: no explicit or stored control plane; the
	// user must pass --control-plane for the mesh this node should join.
	joinNeedsControlPlane
	// joinProceed: enough is known to go straight to interactiveJoin.
	joinProceed
)

// decideJoinAction is the decision table behind "--join": given the node's
// identity state (identityExists, hasPubKey), whether stdin is a real
// terminal, and the explicit vs. stored control planes, it picks exactly one
// of the joinAction outcomes above. It has no side effects.
func decideJoinAction(identityExists, hasPubKey, interactive bool, controlPlaneAddr, stored string) joinAction {
	mismatched := identityExists && controlPlaneAddr != "" && stored != "" &&
		normalizeControlPlaneURL(controlPlaneAddr) != normalizeControlPlaneURL(stored)
	hasUsableIdentity := identityExists && hasPubKey && !mismatched

	switch {
	case hasUsableIdentity:
		return joinSkip
	case mismatched && !interactive:
		return joinFatalMismatchNoTTY
	case !interactive:
		return joinFallbackNoTTY
	case mismatched:
		return joinNeedsConfirmSwitch
	case controlPlaneAddr == "" && stored == "":
		return joinNeedsControlPlane
	default:
		return joinProceed
	}
}

// normalizeControlPlaneURL adds the https:// scheme if missing and drops any
// trailing slash.
func normalizeControlPlaneURL(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	return strings.TrimSuffix(url, "/")
}

// parseRouterAddrs keeps the stored router addresses that still parse.
func parseRouterAddrs(addrs []string) []multiaddr.Multiaddr {
	out := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, s := range addrs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			logger.Warnf("Ignoring stored router address %q: %v", s, err)
			continue
		}
		out = append(out, ma)
	}
	return out
}

// interactiveJoin discovers a control plane's OIDC settings and completes an
// interactive browser/device-code login against it. Shared by "join" and
// "run --join"; targetControlPlane must already be a normalized URL. store is
// used to persist the OIDC refresh token when --offline-access is set.
func interactiveJoin(ctx context.Context, store *node.Store, targetControlPlane string) (string, *api.ControlPlaneInfoResponse, error) {
	dummyNode := &node.SamNode{Store: store}

	fmt.Printf("Discovering control plane info from %s...\n", targetControlPlane)
	info, err := node.FetchControlPlaneInfo(ctx, targetControlPlane)
	if err != nil {
		return "", nil, fmt.Errorf("failed to discover control plane info: %w", err)
	}

	fmt.Printf("OIDC Issuer discovered: %s\n", info.OidcIssuer)
	fmt.Printf("Client ID discovered: %s\n", info.ClientId)

	logger.Info("Discovering OIDC endpoints...")
	endpoints, err := dummyNode.DiscoverEndpointsWithDevice(ctx, info.OidcIssuer)
	if err != nil {
		return "", nil, fmt.Errorf("failed to discover OIDC endpoints: %w", err)
	}
	deviceAuthURL := endpoints.DeviceAuthURL
	if deviceAuthURLFlag != "" {
		deviceAuthURL = deviceAuthURLFlag
	}

	mode, err := node.ParseAuthMode(authModeFlag)
	if err != nil {
		return "", nil, fmt.Errorf("invalid --auth-mode: %w", err)
	}

	jwtStr, err := dummyNode.InteractiveLoginWithMode(ctx, endpoints.AuthURL, endpoints.TokenURL, deviceAuthURL, info.ClientId, info.Audience, offlineAccessFlag, headlessFlag, mode)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get token: %w", err)
	}
	return jwtStr, info, nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:     "sam-node",
		Short:   "Sovereign Agent Mesh Node",
		Version: version.String(),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			node.SetAllowInsecureControlPlane(insecureControlPlaneFlag)
			// The stored URL is checked at request time by the same policy;
			// this only turns a flag-supplied URL into an immediate error.
			if controlPlaneAddr != "" {
				return api.ValidateControlPlaneTransport(normalizeControlPlaneURL(controlPlaneAddr), insecureControlPlaneFlag)
			}
			return nil
		},
	}

	// RUN COMMAND: Start the Mesh
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Start the sovereign mesh node",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			if daemonizeFlag {
				if err := daemonizeRun(resolveSocketPath(cmd)); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				return
			}
			// Configure logging to duplicate to ring buffer
			cfg := golog.GetConfig()
			cfg.URL = "ringbuffer://"
			golog.SetupLogging(cfg)

			// Initialize logging
			golog.SetAllLoggers(golog.LevelInfo)
			if logLevelFlag != "" {
				lvl, err := golog.LevelFromString(logLevelFlag)
				if err == nil {
					golog.SetAllLoggers(lvl)
				}
			}

			// Suppress noisy DHT logs
			_ = golog.SetLogLevel("dht", "fatal")
			_ = golog.SetLogLevel("dht/RtRefreshManager", "fatal")

			apiTokenFlag = resolveDaemonSecret("api-token", apiTokenPathFlag, "SAM_API_TOKEN")
			bootstrapTokenFlag = resolveSecretFlag("bootstrap-token", bootstrapTokenFlag, bootstrapTokenPathFlag)
			clientSecretFlag = resolveDaemonSecret("client-secret", clientSecretPathFlag, "SAM_CLIENT_SECRET")
			if jwtFlag != "" {
				logger.Warn("--jwt passes a secret on the command line; prefer --jwt-path")
			}

			store, err := node.NewStore(resolveDataDir())
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}

			nodeConfig, err := node.LoadNodeConfig(configFile)
			if err != nil {
				logger.Fatalf("Failed to load node config: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("closing store: %v", err)
				}
			}()

			var controlPlanePubKey ed25519.PublicKey
			var routerAddrs []multiaddr.Multiaddr

			// What the last run left behind; the node itself pulls what the
			// control plane knows now before it starts (SyncControlPlane).
			storedPubKey, storedAddrs, err := store.LoadMeshConfig()
			if err != nil {
				logger.Warnf("Failed to load stored mesh config: %v", err)
			}
			if len(storedPubKey) > 0 {
				controlPlanePubKey = storedPubKey
				routerAddrs = parseRouterAddrs(storedAddrs)
			}

			if controlPlanePublicKeyFlag != "" {
				pubBytes, err := hex.DecodeString(strings.TrimSpace(controlPlanePublicKeyFlag))
				if err != nil {
					logger.Fatalf("Invalid control plane public key: %v", err)
				}
				controlPlanePubKey = pubBytes
			}

			var meshNode *node.SamNode

			var jwtStr string
			var controlPlaneInfo *api.ControlPlaneInfoResponse
			var liveTokenSource node.TokenSource

			if jwtFlag != "" {
				jwtStr = jwtFlag
			} else if jwtPathFlag != "" || oidcIssuerFlag != "" || cloudProviderFlag != "" {
				src, continuous, err := node.ResolveTokenSource(ctx, node.TokenSourceConfig{
					IssuerURL:     oidcIssuerFlag,
					ClientID:      clientIDFlag,
					ClientSecret:  clientSecretFlag,
					JWTPath:       jwtPathFlag,
					CloudProvider: cloudProviderFlag,
					Audience:      audienceFlag,
				})
				if err != nil {
					logger.Fatalf("Invalid token source configuration: %v", err)
				}
				if continuous {
					liveTokenSource = src
					jwtStr, err = src.FetchToken(ctx)
					if err != nil {
						logger.Fatalf("Failed to fetch platform JWT: %v", err)
					}
				}
			}

			if jwtStr == "" && bootstrapTokenFlag == "" && joinFlag {
				token, _ := store.LoadIdentity()
				identityExists := len(token) > 0
				stored, _ := store.LoadControlPlaneURL()
				mismatched := identityExists && controlPlaneAddr != "" && stored != "" && normalizeControlPlaneURL(controlPlaneAddr) != normalizeControlPlaneURL(stored)

				switch decideJoinAction(identityExists, len(controlPlanePubKey) > 0, isInteractiveTerminal(), controlPlaneAddr, stored) {
				case joinSkip:
					logger.Debug("--join set but a usable identity is already stored; ignoring")
				case joinFatalMismatchNoTTY:
					logger.Fatalf("--control-plane %q does not match the mesh this node is enrolled with (%s); switching meshes needs to be confirmed interactively. Run %q first, or re-run this interactively.", controlPlaneAddr, stored, "sam-node reset")
				case joinFallbackNoTTY:
					logger.Warn("--join set but no interactive terminal available; falling back to out-of-band enrollment via the unauthenticated MCP sidecar")
				case joinNeedsConfirmSwitch:
					fmt.Printf("This node is currently enrolled with %s. Switching to %s replaces its stored identity (keeping the same PeerID). Continue? [y/N]: ", stored, controlPlaneAddr)
					reader := bufio.NewReader(os.Stdin)
					resp, _ := reader.ReadString('\n')
					if !isYesResponse(resp) {
						logger.Fatal("Aborted: not switching meshes.")
					}
					if err := store.ResetMeshIdentity(); err != nil {
						logger.Fatalf("Failed to reset stored identity: %v", err)
					}
					fallthrough
				case joinNeedsControlPlane, joinProceed:
					if !mismatched && identityExists && len(controlPlanePubKey) == 0 {
						logger.Warn("Stored identity is missing its control plane public key; re-joining")
					}
					if controlPlaneAddr == "" && stored == "" {
						logger.Fatal("No control plane specified: pass --control-plane <url> for the mesh this node should join.")
					}
					targetControlPlane := normalizeControlPlaneURL(defaultControlPlane(store, controlPlaneAddr))
					jwtStr, controlPlaneInfo, err = interactiveJoin(ctx, store, targetControlPlane)
					if err != nil {
						logger.Fatalf("Failed to join: %v", err)
					}
					controlPlaneAddr = targetControlPlane
				}
			}

			if jwtStr == "" && bootstrapTokenFlag == "" {
				token, _ := store.LoadIdentity()
				if len(token) == 0 {
					// Explicit-or-stored only: never suggest the public testnet
					// as a join target without the user's explicit ack.
					displayControlPlane := controlPlaneAddr
					if displayControlPlane == "" {
						if h, err := store.LoadControlPlaneURL(); err == nil && h != "" {
							displayControlPlane = h
						}
					}
					logger.Infof("No identity found. Starting unauthenticated sidecar for enrollment over MCP...")
					unauthSrv, err := node.StartUnauthSidecarServer(displayControlPlane, bindAddrFlag, resolveSocketPath(cmd), tlsCertFlag, tlsKeyFlag)
					if err != nil {
						logger.Fatalf("Failed to start unauthenticated sidecar: %v", err)
					}
					defer func() {
						_ = unauthSrv.Close()
					}()
					<-ctx.Done()
					return
				}
				logger.Infoln("Using stored identity.")

				if controlPlaneAddr != "" {
					stored, _ := store.LoadControlPlaneURL()
					normalizedAddr := normalizeControlPlaneURL(controlPlaneAddr)
					if stored != "" && normalizedAddr != normalizeControlPlaneURL(stored) {
						logger.Fatalf("--control-plane %q does not match the mesh this node's stored identity was enrolled with (%s). A node's identity is only valid for the mesh that issued it: re-run with --join to switch interactively (%q clears it non-interactively), rather than pointing this one at a different mesh.", controlPlaneAddr, stored, "sam-node reset")
					}
				}

				if len(controlPlanePubKey) == 0 {
					logger.Fatal("Control plane public key not found in store and not provided. Re-run with --join to re-enroll, or pass --control-plane-public-key explicitly.")
				}
				priv := node.GetOrGenerateKey(store)
				meshNode, err = node.NewSamNode(node.Options{
					PrivKey:                  priv,
					ControlPlanePubKey:       controlPlanePubKey,
					RouterAddrs:              routerAddrs,
					Store:                    store,
					MeshID:                   meshFlag,
					DiscoveryInterval:        discoveryIntervalFlag,
					ListenAddrs:              listenAddrs,
					EnableRelay:              enableRelayFlag,
					NodeConfig:               nodeConfig,
					KeyGracePeriod:           keyGracePeriodFlag,
					AllowLoopback:            allowLoopbackFlag,
					AnnouncePrivateAddrs:     &announcePrivateFlag,
					MonitorBootstrap:         monitorBootstrapFlag,
					MonitorInterval:          monitorCheckIntervalFlag,
					AutoRelayMinInterval:     autoRelayMinIntervalFlag,
					AutoRelayBootDelay:       autoRelayBootDelayFlag,
					AutoRelayBackoff:         autoRelayBackoffFlag,
					RouterConnectTimeout:     routerConnectTimeoutFlag,
					RequiredRole:             api.RoleNode,
					ControlPlaneSyncInterval: controlPlaneSyncIntervalFlag,
					DHTProviderAddrTTL:       dhtProviderAddrTTLFlag,
					DHTMaxRecordAge:          dhtMaxRecordAgeFlag,
					DHTLookupLimit:           dhtLookupLimitFlag,
					DiscoveryConcurrency:     discoveryConcurrencyFlag,
					BackendProbeTimeout:      backendProbeTimeoutFlag,
					SecretsDir:               secretsDirFlag,
				})
				if err != nil {
					logger.Fatalf("Failed to initialize mesh node: %v", err)
				}
				if err := meshNode.SyncControlPlane(ctx); err != nil {
					logger.Warnf("Control plane sync before start failed (using stored config): %v", err)
				}
				if err := meshNode.Start(ctx); err != nil {
					logger.Fatalf("Failed to start mesh node: %v", err)
				}
			} else {
				// We have a new JWT (from flag or interactive login), need to enroll
				var initRouterAddrs []multiaddr.Multiaddr
				if !strings.HasPrefix(controlPlaneAddr, "http://") && !strings.HasPrefix(controlPlaneAddr, "https://") {
					ma, err := multiaddr.NewMultiaddr(controlPlaneAddr)
					if err == nil {
						initRouterAddrs = []multiaddr.Multiaddr{ma}
					} else {
						// Try parsing as host:port
						host, port, err := net.SplitHostPort(controlPlaneAddr)
						if err == nil {
							ip := net.ParseIP(host)
							var maddr multiaddr.Multiaddr
							var parseErr error
							if ip != nil {
								maddr, parseErr = multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", host, port))
							} else {
								maddr, parseErr = multiaddr.NewMultiaddr(fmt.Sprintf("/dns4/%s/tcp/%s", host, port))
							}
							if parseErr != nil {
								logger.Fatalf("Failed to parse multiaddr: %v", parseErr)
							}
							initRouterAddrs = []multiaddr.Multiaddr{maddr}
						} else {
							if len(routerAddrs) > 0 {
								initRouterAddrs = routerAddrs
							} else {
								logger.Fatalf("Invalid control plane address and no stored config: %v. Pass --control-plane <url> for the mesh this node should join", err)
							}
						}
					}
				}

				priv := node.GetOrGenerateKey(store)
				enrollCtx, enrollCancel := context.WithCancel(context.Background())
				meshNode, err = node.NewSamNode(node.Options{
					PrivKey:                  priv,
					RouterAddrs:              initRouterAddrs,
					Store:                    store,
					MeshID:                   meshFlag,
					DiscoveryInterval:        discoveryIntervalFlag,
					ListenAddrs:              listenAddrs,
					EnableRelay:              enableRelayFlag,
					NodeConfig:               nodeConfig,
					KeyGracePeriod:           keyGracePeriodFlag,
					AllowLoopback:            allowLoopbackFlag,
					AnnouncePrivateAddrs:     &announcePrivateFlag,
					MonitorBootstrap:         monitorBootstrapFlag,
					MonitorInterval:          monitorCheckIntervalFlag,
					AutoRelayMinInterval:     autoRelayMinIntervalFlag,
					AutoRelayBootDelay:       autoRelayBootDelayFlag,
					AutoRelayBackoff:         autoRelayBackoffFlag,
					RouterConnectTimeout:     routerConnectTimeoutFlag,
					RequiredRole:             api.RoleNode,
					ControlPlaneSyncInterval: controlPlaneSyncIntervalFlag,
					DHTProviderAddrTTL:       dhtProviderAddrTTLFlag,
					DHTMaxRecordAge:          dhtMaxRecordAgeFlag,
					DHTLookupLimit:           dhtLookupLimitFlag,
					DiscoveryConcurrency:     discoveryConcurrencyFlag,
					BackendProbeTimeout:      backendProbeTimeoutFlag,
					SecretsDir:               secretsDirFlag,
				})
				if err != nil {
					enrollCancel()
					logger.Fatalf("Failed to initialize node for enrollment: %v", err)
				}
				if err := meshNode.Start(enrollCtx); err != nil {
					enrollCancel()
					logger.Fatalf("Failed to start node for enrollment: %v", err)
				}

				if bootstrapTokenFlag != "" {
					err = meshNode.EnrollBootstrap(enrollCtx, controlPlaneAddr, bootstrapTokenFlag)
				} else {
					err = meshNode.Enroll(enrollCtx, controlPlaneAddr, jwtStr)
				}
				if err != nil {
					if teardownErr := meshNode.Teardown(); teardownErr != nil {
						logger.Errorf("Teardown failed during enrollment error cleanup: %v", teardownErr)
					}
					enrollCancel()
					logger.Fatalf("Enrollment failed: %v", err)
				}
				if err := store.SaveControlPlaneURL(controlPlaneAddr); err != nil {
					logger.Warnf("Failed to save control plane URL: %v", err)
				}
				if controlPlaneInfo != nil {
					if err := store.SaveOIDCConfig(controlPlaneInfo.OidcIssuer, controlPlaneInfo.ClientId, controlPlaneInfo.Audience); err != nil {
						logger.Warnf("Failed to save OIDC config: %v", err)
					}
				}

				if teardownErr := meshNode.Teardown(); teardownErr != nil {
					logger.Errorf("Failed to teardown enrollment node: %v", teardownErr)
				}
				enrollCancel()

				// Enrollment stored the control plane key and the router
				// addresses it answered with; the node built from them pulls
				// the rest before it starts.
				controlPlanePubKey, storedAddrs, err = store.LoadMeshConfig()
				if err != nil {
					logger.Fatalf("Failed to load mesh config after enrollment: %v", err)
				}

				logger.Debugf("listenAddrs: %v, allowLoopback: %v", listenAddrs, allowLoopbackFlag)
				meshNode, err = node.NewSamNode(node.Options{
					PrivKey:                  priv,
					ControlPlanePubKey:       controlPlanePubKey,
					RouterAddrs:              parseRouterAddrs(storedAddrs),
					Store:                    store,
					MeshID:                   meshFlag,
					DiscoveryInterval:        discoveryIntervalFlag,
					ListenAddrs:              listenAddrs,
					EnableRelay:              enableRelayFlag,
					NodeConfig:               nodeConfig,
					KeyGracePeriod:           keyGracePeriodFlag,
					AllowLoopback:            allowLoopbackFlag,
					AnnouncePrivateAddrs:     &announcePrivateFlag,
					MonitorBootstrap:         monitorBootstrapFlag,
					MonitorInterval:          monitorCheckIntervalFlag,
					AutoRelayMinInterval:     autoRelayMinIntervalFlag,
					AutoRelayBootDelay:       autoRelayBootDelayFlag,
					AutoRelayBackoff:         autoRelayBackoffFlag,
					RouterConnectTimeout:     routerConnectTimeoutFlag,
					RequiredRole:             api.RoleNode,
					ControlPlaneSyncInterval: controlPlaneSyncIntervalFlag,
					BackendProbeTimeout:      backendProbeTimeoutFlag,
					SecretsDir:               secretsDirFlag,
				})
				if err != nil {
					logger.Fatalf("Failed to initialize node after enrollment: %v", err)
				}
				if err := meshNode.SyncControlPlane(ctx); err != nil {
					logger.Warnf("Control plane sync after enrollment failed (using enrollment config): %v", err)
				}
				if err := meshNode.Start(ctx); err != nil {
					logger.Fatalf("Failed to start node after enrollment: %v", err)
				}
			}

			// Register static services from config
			if nodeConfig != nil && len(nodeConfig.Services) > 0 {
				if err := meshNode.RegisterStaticServices(context.Background(), nodeConfig.Services); err != nil {
					logger.Fatalf("Failed to register static services: %v", err)
				}
			}

			// Start renewal loop
			if liveTokenSource != nil {
				meshNode.SetTokenSource(liveTokenSource)
				meshNode.StartRenewalLoopWithSource(ctx, liveTokenSource)
			} else {
				meshNode.StartRenewalLoop(ctx, oidcIssuerFlag, clientIDFlag, clientSecretFlag, jwtPathFlag)
			}

			// Start Sidecar API Server (multiplexed with MCP)
			sidecarSrv, err := node.StartSidecarServer(meshNode, bindAddrFlag, resolveSocketPath(cmd), apiTokenFlag, tlsCertFlag, tlsKeyFlag, tlsCAFlag)
			if err != nil {
				logger.Fatalf("Failed to start sidecar server: %v", err)
			}
			defer func() {
				_ = sidecarSrv.Close()
				if err := meshNode.Teardown(); err != nil {
					logger.Warnf("Error during mesh node teardown: %v", err)
				}
			}()

			if metricsAddrFlag != "" {
				metricsSrv, err := node.StartMetricsServer(meshNode, metricsAddrFlag)
				if err != nil {
					logger.Fatalf("Failed to start metrics server: %v", err)
				}
				defer func() { _ = metricsSrv.Close() }()
			}

			fmt.Printf("SAM Node Online.\nPeerID: %s\nListening on: %v\n", meshNode.Host.ID(), meshNode.Host.Addrs())

			// Block forever
			<-ctx.Done()
			fmt.Println("Shutting down...")
		},
	}

	joinCmd := &cobra.Command{
		Use:   "join [control_plane_url]",
		Short: "Join the Sovereign Agent Mesh",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			targetControlPlane := ""
			if len(args) > 0 {
				targetControlPlane = args[0]
			}

			if targetControlPlane == "" {
				logger.Fatal("No control plane specified: sam-node join <control-plane-url>")
			}

			targetControlPlane = normalizeControlPlaneURL(targetControlPlane)

			bootstrapTokenFlag = resolveSecretFlag("bootstrap-token", bootstrapTokenFlag, bootstrapTokenPathFlag)

			store, err := node.NewStore(resolveDataDir())
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}

			nodeConfig, err := node.LoadNodeConfig(configFile)
			if err != nil {
				logger.Fatalf("Failed to load node config: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("closing store: %v", err)
				}
			}()

			var jwtStr string
			var controlPlaneInfo *api.ControlPlaneInfoResponse
			if bootstrapTokenFlag == "" {
				jwtStr, controlPlaneInfo, err = interactiveJoin(ctx, store, targetControlPlane)
				if err != nil {
					logger.Fatalf("Failed to join: %v", err)
				}
			}

			// Override global controlPlaneAddr with targetControlPlane for enrollment
			controlPlaneAddr = targetControlPlane

			// Connect to control plane and enroll
			var initRouterAddrs []multiaddr.Multiaddr
			if !strings.HasPrefix(controlPlaneAddr, "http://") && !strings.HasPrefix(controlPlaneAddr, "https://") {
				ma, err := multiaddr.NewMultiaddr(controlPlaneAddr)
				if err == nil {
					initRouterAddrs = []multiaddr.Multiaddr{ma}
				} else {
					host, port, err := net.SplitHostPort(controlPlaneAddr)
					if err == nil {
						ip := net.ParseIP(host)
						var maddr multiaddr.Multiaddr
						var parseErr error
						if ip != nil {
							maddr, parseErr = multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", host, port))
						} else {
							maddr, parseErr = multiaddr.NewMultiaddr(fmt.Sprintf("/dns4/%s/tcp/%s", host, port))
						}
						if parseErr != nil {
							logger.Fatalf("Failed to parse multiaddr: %v", parseErr)
						}
						initRouterAddrs = []multiaddr.Multiaddr{maddr}
					} else {
						logger.Fatalf("Invalid control plane address: %v", err)
					}
				}
			}

			priv := node.GetOrGenerateKey(store)
			meshNode, err := node.NewSamNode(node.Options{
				PrivKey:                  priv,
				RouterAddrs:              initRouterAddrs,
				Store:                    store,
				MeshID:                   meshFlag,
				DiscoveryInterval:        discoveryIntervalFlag,
				ListenAddrs:              []string{"/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"},
				EnableRelay:              enableRelayFlag,
				NodeConfig:               nodeConfig,
				KeyGracePeriod:           keyGracePeriodFlag,
				AllowLoopback:            allowLoopbackFlag,
				AnnouncePrivateAddrs:     &announcePrivateFlag,
				MonitorBootstrap:         2 * time.Minute,
				MonitorInterval:          1 * time.Minute,
				AutoRelayMinInterval:     30 * time.Second,
				AutoRelayBootDelay:       0 * time.Second,
				AutoRelayBackoff:         3 * time.Second,
				RouterConnectTimeout:     routerConnectTimeoutFlag,
				RequiredRole:             api.RoleNode,
				ControlPlaneSyncInterval: controlPlaneSyncIntervalFlag,
			})
			if err != nil {
				logger.Fatalf("Failed to initialize node for enrollment: %v", err)
			}
			if err := meshNode.Start(ctx); err != nil {
				logger.Fatalf("Failed to start node for enrollment: %v", err)
			}

			if bootstrapTokenFlag != "" {
				err = meshNode.EnrollBootstrap(ctx, targetControlPlane, bootstrapTokenFlag)
			} else {
				err = meshNode.Enroll(ctx, targetControlPlane, jwtStr)
			}
			if err != nil {
				logger.Fatalf("Enrollment failed: %v", err)
			}
			if err := store.SaveControlPlaneURL(targetControlPlane); err != nil {
				logger.Warnf("Failed to save control plane URL: %v", err)
			}
			if bootstrapTokenFlag == "" {
				if err := store.SaveOIDCConfig(controlPlaneInfo.OidcIssuer, controlPlaneInfo.ClientId, controlPlaneInfo.Audience); err != nil {
					logger.Warnf("Failed to save OIDC config: %v", err)
				}
			}

			fmt.Println("Successfully joined the Sovereign Agent Mesh!")
		},
	}

	resetCmd := &cobra.Command{
		Use:   "reset",
		Short: "Clear this node's stored mesh identity so it can join a different mesh",
		Long: "Clear this node's stored mesh identity so it can join a different mesh.\n" +
			"The node keeps its PeerID and any generated API token.\n\n" +
			"Use --all for a clean slate instead: it deletes every file the node keeps\n" +
			"in its data directory, including the key behind its PeerID, so the next\n" +
			"start behaves like a first start.",
		Run: func(cmd *cobra.Command, args []string) {
			dataDir := resolveDataDir()
			if resetAllFlag {
				if err := confirmPurge(dataDir); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				removed, err := purgeDataDir(dataDir)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				if len(removed) == 0 {
					fmt.Printf("No local node state found in %s.\n", dataDir)
					return
				}
				fmt.Println("Deleted all local node state:")
				for _, path := range removed {
					fmt.Printf("  %s\n", path)
				}
				fmt.Println("The next start generates a new PeerID and needs to enroll again.")
				return
			}
			store, err := node.NewStore(dataDir)
			if err != nil {
				logger.Fatalf("Failed to open store: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("closing store: %v", err)
				}
			}()
			if err := store.ResetMeshIdentity(); err != nil {
				logger.Fatalf("Failed to reset stored identity: %v", err)
			}
			fmt.Println("Cleared stored mesh identity (PeerID unchanged). Run 'sam-node join <control-plane-url>' or 'sam-node run --join' to enroll again.")
		},
	}
	resetCmd.Flags().BoolVar(&resetAllFlag, "all", false, "Delete every file the node keeps in its data directory, not just the mesh identity")
	resetCmd.Flags().BoolVar(&assumeYesFlag, "yes", false, "Skip the confirmation prompt for --all")

	// Configure Flags
	runCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/udp/5001/quic-v1", "/ip4/0.0.0.0/tcp/5002"}, "libp2p Listen Addrs")
	runCmd.Flags().StringVar(&jwtFlag, "jwt", "", "Pre-fetched JWT token")
	runCmd.Flags().StringVar(&jwtPathFlag, "jwt-path", "", "Path to file containing JWT token")
	runCmd.Flags().StringVar(&cloudProviderFlag, "cloud-provider", "", "Platform metadata identity provider for enrollment and renewal: gcp or auto")
	runCmd.Flags().BoolVar(&joinFlag, "join", false, "Enroll interactively on first run if no identity exists yet (requires --control-plane or a previously stored mesh); a no-op on later restarts")
	runCmd.Flags().StringVar(&bootstrapTokenFlag, "bootstrap-token", "", "Pre-shared bootstrap token for enrollment")
	runCmd.Flags().StringVar(&bootstrapTokenPathFlag, "bootstrap-token-path", "", "Path to file containing the bootstrap token (recommended over --bootstrap-token)")
	runCmd.Flags().StringVar(&clientIDFlag, "client-id", "", "OIDC Client ID for M2M")
	runCmd.Flags().StringVar(&clientSecretPathFlag, "client-secret-path", "", "Path to file containing the OIDC client secret (or env SAM_CLIENT_SECRET)")
	runCmd.Flags().StringVar(&controlPlanePublicKeyFlag, "control-plane-public-key", "", "Control plane public key (32-byte Hex)")
	runCmd.Flags().StringVar(&bindAddrFlag, "bind-addr", "127.0.0.1:8080", "Local TCP address for the HTTP server (MCP and Sidecar API); pass an empty value to serve only on the Unix socket")
	runCmd.Flags().StringVar(&socketPathFlag, "socket-path", "", "Unix socket serving the same API, where the socket's owner-only permissions replace the API token (defaults to <data-dir>/"+node.DefaultSocketName+"; pass an empty value to disable)")
	runCmd.Flags().StringVar(&metricsAddrFlag, "metrics-addr", "", "Serve Prometheus /metrics, /healthz and /readyz on this address without authentication (e.g. 0.0.0.0:9090), for scrapers and probes that hold no API token; off by default")
	runCmd.Flags().StringVar(&meshFlag, "mesh", node.DefaultMeshName, "Mesh federation name")
	runCmd.Flags().StringVar(&discoveryIntervalFlag, "discovery-interval", node.DefaultDiscoveryInterval, "Polling interval for DHT discovery")
	runCmd.Flags().DurationVar(&monitorBootstrapFlag, "monitor-bootstrap", 2*time.Minute, "Initial wait before monitoring router connection")
	runCmd.Flags().DurationVar(&monitorCheckIntervalFlag, "monitor-interval", 1*time.Minute, "Interval for checking router connection")
	runCmd.Flags().DurationVar(&autoRelayMinIntervalFlag, "autorelay-min-interval", 30*time.Second, "AutoRelay Min Interval")
	runCmd.Flags().DurationVar(&autoRelayBootDelayFlag, "autorelay-boot-delay", 0*time.Second, "AutoRelay Boot Delay")
	runCmd.Flags().DurationVar(&autoRelayBackoffFlag, "autorelay-backoff", 3*time.Second, "AutoRelay Backoff")
	runCmd.Flags().DurationVar(&routerConnectTimeoutFlag, "router-connect-timeout", node.DefaultRouterConnectTimeout, "Timeout for dialing each router address")
	runCmd.Flags().BoolVar(&enableRelayFlag, "enable-relay", false, "Allow this node to serve as a relay for others")
	runCmd.Flags().BoolVar(&daemonizeFlag, "daemonize", false, "Run the node in the background and return once its local API answers (writes sam-node.log and sam-node.pid to the data directory, and generates an API token there if none is configured)")
	runCmd.Flags().StringVar(&logLevelFlag, "log-level", "info", "Log level (debug, info, warn, error)")
	runCmd.Flags().DurationVar(&keyGracePeriodFlag, "key-grace-period", 24*time.Hour, "Key grace period for old keys (e.g. 24h)")
	runCmd.Flags().BoolVar(&allowLoopbackFlag, "allow-loopback", false, "Allow publishing and connecting to loopback/link-local addresses")
	runCmd.Flags().BoolVar(&announcePrivateFlag, "announce-private", true, "Publish this host's private (RFC1918/ULA) addresses to the mesh; keep enabled for LAN or on-premises meshes, disable when peers are only reachable through routers or public addresses")
	runCmd.Flags().BoolVar(&offlineAccessFlag, "offline-access", false, "With --join, request OIDC offline access/refresh token for automatic renewal")
	joinCmd.Flags().BoolVar(&allowLoopbackFlag, "allow-loopback", false, "Allow publishing and connecting to loopback/link-local addresses")
	joinCmd.Flags().BoolVar(&announcePrivateFlag, "announce-private", true, "Publish this host's private (RFC1918/ULA) addresses to the mesh; keep enabled for LAN or on-premises meshes, disable when peers are only reachable through routers or public addresses")
	joinCmd.Flags().DurationVar(&routerConnectTimeoutFlag, "router-connect-timeout", node.DefaultRouterConnectTimeout, "Timeout for dialing each router address")
	joinCmd.Flags().BoolVar(&offlineAccessFlag, "offline-access", false, "Request OIDC offline access/refresh token for automatic renewal")
	joinCmd.Flags().StringVar(&bootstrapTokenFlag, "bootstrap-token", "", "Pre-shared bootstrap token for enrollment")
	joinCmd.Flags().StringVar(&bootstrapTokenPathFlag, "bootstrap-token-path", "", "Path to file containing the bootstrap token (recommended over --bootstrap-token)")
	runCmd.Flags().StringVar(&apiTokenPathFlag, "api-token-path", "", "Path to file containing the static Bearer token for API authorization (or env SAM_API_TOKEN)")
	runCmd.Flags().StringVar(&tlsCertFlag, "tls-cert", "", "Path to TLS certificate for sidecar API")
	runCmd.Flags().StringVar(&tlsKeyFlag, "tls-key", "", "Path to TLS key for sidecar API")
	runCmd.Flags().StringVar(&tlsCAFlag, "tls-ca", "", "Path to TLS CA for sidecar API mTLS")
	runCmd.Flags().DurationVar(&dhtProviderAddrTTLFlag, "dht-provider-addr-ttl", 0, "Time-To-Live for DHT provider addresses (0s uses library default)")
	runCmd.Flags().DurationVar(&dhtMaxRecordAgeFlag, "dht-max-record-age", 0, "Maximum age for DHT records (0s uses library default)")
	runCmd.Flags().IntVar(&dhtLookupLimitFlag, "dht-lookup-limit", 0, "Maximum number of providers to query from the DHT (0 uses default 20)")
	runCmd.Flags().IntVar(&discoveryConcurrencyFlag, "discovery-concurrency", 0, "Max concurrent catalog fetches during discovery (0 uses default 10)")
	runCmd.Flags().DurationVar(&controlPlaneSyncIntervalFlag, "control-plane-sync-interval", node.DefaultControlPlaneSyncInterval, "How often signing keys, bans, router addresses and mesh policy are pulled from the control plane. Keep it well below the control plane's --key-grace-period; raise it on large meshes.")
	runCmd.Flags().DurationVar(&backendProbeTimeoutFlag, "backend-probe-timeout", 0, "Timeout for probing a command-spawned service backend before advertising it (0 uses default 2s); raise this for backends with slower cold-start times")
	runCmd.Flags().StringVar(&secretsDirFlag, "secrets-dir", node.DefaultSecretsDir, "Directory holding the credentials named by the control plane's egress destinations, one file per credential name")
	rootCmd.PersistentFlags().StringVar(&controlPlaneAddr, "control-plane", "", "Control plane URL")
	rootCmd.PersistentFlags().BoolVar(&insecureControlPlaneFlag, "insecure-control-plane", false, "Accept a plaintext http:// control plane URL to a non-loopback host (whoever answers it becomes this node's trust root; only for networks you already trust)")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", node.DefaultConfigFile, "Path to sam-node.yaml configuration file")
	rootCmd.PersistentFlags().StringVar(&oidcIssuerFlag, "oidc-issuer", "", "OIDC Issuer URL")
	rootCmd.PersistentFlags().StringVar(&deviceAuthURLFlag, "device-auth-url", "", "OIDC Device Authorization URL")
	rootCmd.PersistentFlags().StringVar(&audienceFlag, "audience", api.DefaultAudience, "OIDC Audience")
	rootCmd.PersistentFlags().StringVar(&dataDirFlag, "data-dir", "", "Override directory for the agent store (defaults to OS user config dir)")
	rootCmd.PersistentFlags().BoolVar(&headlessFlag, "headless", false, "Force headless out-of-band (OOB) authentication flow")
	rootCmd.PersistentFlags().StringVar(&authModeFlag, "auth-mode", "auto", "Interactive enrollment auth mode: auto, device, oob, or browser")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(joinCmd)
	rootCmd.AddCommand(resetCmd)
	rootCmd.AddCommand(newStateCmd())
	rootCmd.AddCommand(newSkillCmd())
	rootCmd.AddCommand(newDebugCmd())
	rootCmd.AddCommand(newForwardCmd())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[Signal] Received interrupt, shutting down...")
		cancel()
		signal.Stop(sigChan)
	}()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

// resolveDataDir honors --data-dir / $SAM_DATA_DIR if set, else falls back to GetDefaultDataDir().
func resolveDataDir() string {
	var dir string
	if dataDirFlag != "" {
		dir = dataDirFlag
	} else {
		d, err := node.GetDefaultDataDir()
		if err != nil {
			logger.Fatalf("Failed to get default data directory: %v", err)
		}
		dir = d
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Fatalf("Failed to create data directory: %v", err)
	}
	return dir
}

// resolveSocketPath places the local API socket in the data directory unless
// the operator names another path, or asks for no socket with --socket-path "".
func resolveSocketPath(cmd *cobra.Command) string {
	if cmd.Flags().Changed("socket-path") {
		return socketPathFlag
	}
	return filepath.Join(resolveDataDir(), node.DefaultSocketName)
}
