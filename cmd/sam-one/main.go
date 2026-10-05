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

// sam-one is the all-in-one SAM distribution: control plane, libp2p router
// and storage in a single binary serving a single public port.
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/standalone"
	"github.com/google/sam/internal/tunnel"
	golog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
)

var logger = golog.Logger("sam-one")

func main() {
	var (
		bindAddress          string
		port                 int
		externalURL          string
		p2pListen            []string
		dataDir              string
		dbDriver             string
		dbDSN                string
		joinTokenPath        string
		noJoinToken          bool
		adminTokenPath       string
		policyFile           string
		oidcIssuer           string
		workloadIssuer       string
		oidcClientID         string
		allowedAudiencesFlag string
		logLevel             string
		tunnelProvider       string
		tunnelTokenPath      string
		tunnelInstall        bool
		cloudflaredPath      string
		enrollQR             bool
		enrollQRMaxUsages    int
		cpTunables           standalone.ControlPlaneTunables
		routerTunables       standalone.RouterTunables
		routerAllowLoopback  bool
	)

	rootCmd := &cobra.Command{
		Use:   "sam-one",
		Short: "Sovereign Agent Mesh - all-in-one standalone server",
		Run: func(cmd *cobra.Command, args []string) {
			if os.Getenv("LOG_FORMAT") == "json" {
				_ = os.Setenv("GOLOG_LOG_FMT", "json")
			}
			lvl := golog.LevelInfo
			if logLevel != "" {
				if parsed, err := golog.LevelFromString(logLevel); err == nil {
					lvl = parsed
				}
			}
			golog.SetAllLoggers(lvl)
			// Same as sam-node: go-libp2p-kad-dht logs routine small-mesh
			// conditions (empty routing table, no closer peers) at INFO/ERROR,
			// the latter through a malformed zap call inside the library.
			// Only an explicit debug level keeps them.
			if lvl > golog.LevelDebug {
				_ = golog.SetLogLevel("dht", "fatal")
				_ = golog.SetLogLevel("dht/RtRefreshManager", "fatal")
			}

			// Secrets arrive through a file or the environment, never as a
			// flag value that would sit in `ps` and shell history. Env keeps
			// single-container platforms (Cloud Run) configurable.
			joinToken, err := secretFromPathOrEnv(joinTokenPath, "SAM_TOKEN")
			if err != nil {
				logger.Fatalf("Invalid --token-path: %v", err)
			}
			adminToken, err := secretFromPathOrEnv(adminTokenPath, "SAM_ADMIN_TOKEN")
			if err != nil {
				logger.Fatalf("Invalid --admin-token-path: %v", err)
			}
			tunnelToken, err := secretFromPathOrEnv(tunnelTokenPath, "SAM_TUNNEL_TOKEN")
			if err != nil {
				logger.Fatalf("Invalid --tunnel-token-path: %v", err)
			}
			if externalURL == "" {
				externalURL = os.Getenv("SAM_EXTERNAL_URL")
			}

			var auds []string
			for _, aud := range strings.Split(allowedAudiencesFlag, ",") {
				if aud = strings.TrimSpace(aud); aud != "" {
					auds = append(auds, aud)
				}
			}

			// The router advertises the external URL from its first lease, so
			// a tunnel must exist before it starts; that in turn needs the
			// port settled now rather than at bind time.
			var tun tunnel.Tunnel
			if tunnelProvider != "" {
				if tunnelToken == "" && externalURL != "" {
					logger.Fatal("--tunnel and --external-url are mutually exclusive unless --tunnel-token-path / SAM_TUNNEL_TOKEN is set")
				}
				if tunnelToken != "" && externalURL == "" {
					logger.Fatal("--tunnel-token-path / SAM_TUNNEL_TOKEN requires --external-url (the public https:// hostname routed to the tunnel)")
				}
				if port == 0 {
					var err error
					if port, err = freePort(bindAddress); err != nil {
						logger.Fatalf("Failed to pick a port for the tunnel target: %v", err)
					}
				}
				var err error
				if tun, err = openTunnel(cmd.Context(), tunnelOptions{
					provider:        tunnelProvider,
					bindAddress:     bindAddress,
					port:            port,
					dataDir:         dataDir,
					cloudflaredPath: cloudflaredPath,
					install:         tunnelInstall,
					token:           tunnelToken,
					externalURL:     externalURL,
				}); err != nil {
					logger.Fatalf("Failed to open tunnel: %v", err)
				}
				defer func() { _ = tun.Close() }()
				externalURL = tun.URL()
			}

			routerTunables.DisallowLoopback = !routerAllowLoopback
			srv, err := standalone.New(standalone.Options{
				BindAddress:      net.JoinHostPort(bindAddress, strconv.Itoa(port)),
				ExternalURL:      externalURL,
				P2PListen:        p2pListen,
				DataDir:          dataDir,
				DBDriver:         dbDriver,
				DBDSN:            dbDSN,
				JoinToken:        joinToken,
				DisableJoinToken: noJoinToken,
				AdminToken:       adminToken,
				PolicyFile:       policyFile,
				OIDCIssuer:       oidcIssuer,
				WorkloadIssuer:   workloadIssuer,
				OIDCClientID:     oidcClientID,
				AllowedAudiences: auds,
				ControlPlane:     cpTunables,
				Router:           routerTunables,
			})
			if err != nil {
				logger.Fatalf("Invalid configuration: %v", err)
			}
			if err := srv.Start(cmd.Context()); err != nil {
				logger.Fatalf("Failed to start: %v", err)
			}
			defer func() {
				if err := srv.Close(); err != nil {
					logger.Errorf("Shutdown: %v", err)
				}
			}()

			printBanner(srv, tun, bannerSecrets{adminSupplied: adminToken != "", joinSupplied: joinToken != ""})
			if enrollQR {
				if err := printBootEnrollQR(cmd.Context(), srv, enrollQRMaxUsages); err != nil {
					logger.Errorf("Device enrollment QR: %v", err)
				}
			}
			if tun != nil {
				go func() {
					<-tun.Done()
					if err := tun.Err(); err != nil {
						logger.Errorf("Tunnel %s closed: %v; remote devices can no longer reach %s", tunnelProvider, err, tun.URL())
					}
				}()
			}
			<-cmd.Context().Done()
		},
	}

	rootCmd.Flags().StringVar(&bindAddress, "bind-address", "0.0.0.0", "Host/IP to bind the single HTTP/WebSocket listener")
	rootCmd.Flags().IntVar(&port, "port", 0, "TCP port of the single listener; 0 picks a free port, published in the startup banner")
	rootCmd.Flags().StringVar(&externalURL, "external-url", "", "Public URL reachable by nodes (or env SAM_EXTERNAL_URL)")
	rootCmd.Flags().StringSliceVar(&p2pListen, "p2p-listen", nil, "Optional extra native libp2p listen multiaddrs")
	rootCmd.Flags().StringVar(&dataDir, "data-dir", ".", "Directory for the database, router key and generated tokens")
	rootCmd.Flags().StringVar(&dbDriver, "db-driver", "sqlite", "Database driver (sqlite or postgres)")
	rootCmd.Flags().StringVar(&dbDSN, "db-dsn", "", "Database DSN (default <data-dir>/sam.db for sqlite)")
	rootCmd.Flags().StringVar(&joinTokenPath, "token-path", "", "File containing the cluster join token (or env SAM_TOKEN; auto-generated and persisted in --data-dir if neither is set)")
	rootCmd.Flags().BoolVar(&noJoinToken, "no-join-token", false, "Run without a standing join token; devices enroll only with minted bootstrap tokens (token create/qr) or OIDC")
	rootCmd.Flags().StringVar(&adminTokenPath, "admin-token-path", "", "File containing the admin API bearer token (or env SAM_ADMIN_TOKEN; auto-generated and persisted in --data-dir if neither is set)")
	rootCmd.Flags().StringVar(&policyFile, "policy-file", "", "Path to a protojson PolicyConfig seeding the mesh policy on first boot only")
	rootCmd.Flags().StringVar(&oidcIssuer, "issuer", "", "Optional external OIDC issuer URL (comma-separated)")
	rootCmd.Flags().StringVar(&workloadIssuer, "workload-issuer", "", "Optional workload OIDC issuer URL or '<issuer>=<email-suffix>' (comma-separated); accepted at /register, /refresh and /token/exchange, refused at /user/* and /oauth/authorize")
	rootCmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "", "OAuth client id advertised via /info (defaults to the first allowed audience)")
	rootCmd.Flags().StringVar(&allowedAudiencesFlag, "allowed-audiences", api.DefaultAudience, "Comma-separated list of allowed OIDC audiences")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "", "Log level: debug, info, warn, error")
	rootCmd.Flags().StringVar(&tunnelProvider, "tunnel", "", "Publish the listener on a public URL through a tunnel provider ("+strings.Join(tunnel.Names(), ", ")+"); sets the external URL")
	rootCmd.Flags().StringVar(&tunnelTokenPath, "tunnel-token-path", "", "File containing the tunnel provider token (or env SAM_TUNNEL_TOKEN); use with --tunnel <provider> --external-url https://...")
	rootCmd.Flags().BoolVar(&tunnelInstall, "tunnel-install", false, "Download the pinned connector binary (cloudflared "+tunnel.CloudflaredVersion+", digest-verified) into <data-dir>/bin without asking; implies accepting its license")
	rootCmd.Flags().StringVar(&cloudflaredPath, "cloudflared-path", "", "Explicit cloudflared executable for --tunnel cloudflare (default: PATH, then <data-dir>/bin)")
	rootCmd.Flags().BoolVar(&enrollQR, "enroll-qr", stdoutIsTerminal(), "Print a device enrollment QR code at startup (default: when stdout is a terminal)")
	rootCmd.Flags().IntVar(&enrollQRMaxUsages, "enroll-qr-max-usages", 1, "How many devices the startup QR code admits (1 = single use; raise it to project one code to a room)")

	// Embedded control plane tunables.
	rootCmd.Flags().DurationVar(&cpTunables.LeaseDuration, "control-plane-lease-duration", 0, "Router lease validity (0 keeps the component default)")
	rootCmd.Flags().DurationVar(&cpTunables.KeyRotationInterval, "control-plane-key-rotation-interval", 0, "Biscuit signing key rotation interval (0 keeps the component default)")
	rootCmd.Flags().DurationVar(&cpTunables.KeyGracePeriod, "control-plane-key-grace-period", 0, "How long rotated-out keys stay valid for verification (0 keeps the component default)")
	rootCmd.Flags().DurationVar(&cpTunables.BiscuitTTL, "control-plane-biscuit-ttl", 0, "Lifespan minted into issued biscuits (0 keeps the component default)")
	rootCmd.Flags().DurationVar(&cpTunables.WorkloadSessionTTL, "control-plane-workload-session-ttl", 0, "How long a workload-issuer enrollment stays refreshable without presenting a fresh platform JWT on /refresh (0 keeps the component default)")
	rootCmd.Flags().BoolVar(&cpTunables.ManualEnrollment, "control-plane-manual-enrollment", false, "Queue bootstrap enrollments for admin approval instead of auto-approving")

	// Embedded router tunables.
	rootCmd.Flags().DurationVar(&routerTunables.KeysSyncInterval, "router-keys-sync-interval", 0, "Biscuit public key refresh interval (0 keeps the component default)")
	rootCmd.Flags().DurationVar(&routerTunables.LeaseRenewInterval, "router-lease-renew-interval", 0, "Lease renewal interval (0 keeps the component default)")
	rootCmd.Flags().IntVar(&routerTunables.LowWaterMark, "router-low-watermark", 0, "Connection manager low watermark (0 keeps the component default)")
	rootCmd.Flags().IntVar(&routerTunables.HighWaterMark, "router-high-watermark", 0, "Connection manager high watermark (0 keeps the component default)")
	rootCmd.Flags().IntVar(&routerTunables.ConnsPerSourceIP, "router-conns-per-source-ip", 0, "Per-source-IP connection budget (0 follows the high watermark; proxied peers share source IPs)")
	rootCmd.Flags().DurationVar(&routerTunables.DHTProviderAddrTTL, "router-dht-provider-addr-ttl", 0, "DHT provider address TTL (0 keeps the library default)")
	rootCmd.Flags().DurationVar(&routerTunables.DHTMaxRecordAge, "router-dht-max-record-age", 0, "DHT record max age (0 keeps the library default)")
	rootCmd.Flags().DurationVar(&routerTunables.RelayLimitDuration, "router-relay-limit-duration", 0, "Relayed connection lifetime (0 keeps the component default of 1h; use e.g. 24h for longer)")
	rootCmd.Flags().Var(&routerTunables.RelayLimitData, "router-relay-limit-data", "Bytes relayed per direction per connection, e.g. 512MiB (0 keeps the component default: no limit)")
	rootCmd.Flags().BoolVar(&routerAllowLoopback, "router-allow-loopback", true, "Advertise loopback addresses (disable on public deployments)")

	rootCmd.AddCommand(newAdminSubcommands()...)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

// bannerSecrets records which credentials the operator supplied (flag or
// env). Those are theirs already and stdout is often a log pipeline, so the
// banner names the source instead of echoing the value; tokens sam-one
// generated itself are shown, since this is where the operator learns them.
type bannerSecrets struct {
	adminSupplied bool
	joinSupplied  bool
}

func printBanner(srv *standalone.Server, tun tunnel.Tunnel, secrets bannerSecrets) {
	base := srv.PublicURL()
	adminShown := srv.AdminToken()
	if secrets.adminSupplied {
		adminShown = "(supplied via --admin-token-path / SAM_ADMIN_TOKEN)"
	}
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println("SAM standalone mesh is ready!")
	fmt.Println()
	fmt.Printf("API URL:      %s\n", base)
	if tun != nil {
		fmt.Printf("Tunnel:       %s -> http://%s\n", tun.URL(), srv.Addr())
	}
	fmt.Printf("Web Console:  %s/console\n", base)
	fmt.Printf("Router Peer:  %s\n", srv.PeerID())
	fmt.Printf("Admin Token:  %s\n", adminShown)
	switch {
	case srv.JoinToken() == "":
		fmt.Println("Join Token:   disabled (--no-join-token); enroll devices with `sam-one token qr` / `token create` or OIDC")
	case secrets.joinSupplied:
		fmt.Println("Join Token:   (supplied via --token-path / SAM_TOKEN)")
		fmt.Println()
		fmt.Println("To enroll a node:")
		fmt.Printf("  sam-node join %s --bootstrap-token-path <file with the join token>\n", base)
	default:
		fmt.Printf("Join Token:   %s\n", srv.JoinToken())
		fmt.Println()
		fmt.Println("To enroll a node:")
		// The token is persisted next to the database; a file beats a value
		// in the shell history, like sam-node's own help recommends.
		fmt.Printf("  sam-node join %s --bootstrap-token-path %s\n", base, srv.JoinTokenPath())
	}
	fmt.Println("══════════════════════════════════════════════════════════════════")
}

// printBootEnrollQR mints the per-boot device token and draws it under the
// banner; `sam-one token qr` produces further ones on demand. Without a
// public https URL there is nothing a device could trust, so no token is
// spent and a hint is printed instead.
func printBootEnrollQR(ctx context.Context, srv *standalone.Server, maxUsages int) error {
	if err := api.ValidateControlPlaneTransport(srv.PublicURL(), false); err != nil {
		fmt.Printf("\nDevice enrollment QR skipped: devices only trust an https control plane.\n"+
			"Run with --tunnel %s or --external-url https://... to enroll phones.\n", strings.Join(tunnel.Names(), "|"))
		return nil
	}
	tok, err := srv.MintDeviceEnrollmentToken(ctx, standalone.DeviceTokenTTL, maxUsages)
	if err != nil {
		return err
	}
	fmt.Println()
	return printEnrollQR(os.Stdout, srv.PublicURL(), tok, standalone.DeviceTokenTTL, maxUsages)
}

// tunnelOptions collects what openTunnel needs from the flags.
type tunnelOptions struct {
	provider        string
	bindAddress     string
	port            int
	dataDir         string
	cloudflaredPath string
	install         bool
	token           string
	externalURL     string
}

// openTunnel publishes the listener that Start is about to bind. The
// connector dials the bind host, or loopback when binding all interfaces.
func openTunnel(ctx context.Context, o tunnelOptions) (tunnel.Tunnel, error) {
	p, err := tunnel.Lookup(o.provider)
	if err != nil {
		return nil, err
	}
	if cf, ok := p.(*tunnel.Cloudflare); ok {
		cf.Binary = o.cloudflaredPath
		cf.InstallDir = filepath.Join(o.dataDir, "bin")
		cf.Consent = installConsent(o.install)
		cf.Token = o.token
		cf.ExternalURL = o.externalURL
	}
	host := o.bindAddress
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	target := "http://" + net.JoinHostPort(host, strconv.Itoa(o.port))
	logger.Infof("Opening %s tunnel to %s", p.Name(), target)
	return p.Open(ctx, target)
}

// installConsent decides whether a missing connector may be downloaded:
// --tunnel-install says yes up front; otherwise an interactive terminal is
// asked, and a non-interactive run is refused (a container or service must
// opt in explicitly rather than fetch binaries on its own).
func installConsent(preApproved bool) func(version, url string) bool {
	return func(version, url string) bool {
		fmt.Printf("cloudflared is not installed. sam-one can download release %s (SHA-256 verified) from\n  %s\ninto its data directory. Installing cloudflared means accepting Cloudflare's license:\n  %s\n",
			version, url, tunnel.CloudflaredLicenseURL)
		if preApproved {
			fmt.Println("Proceeding (--tunnel-install).")
			return true
		}
		if !stdinIsTerminal() {
			fmt.Println("Not a terminal: pass --tunnel-install to accept, or install cloudflared yourself.")
			return false
		}
		fmt.Print("Download and accept? [y/N] ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true
		}
		if err != nil {
			// /dev/null is a char device too; EOF is the tell.
			fmt.Println("\nNo answer: pass --tunnel-install to accept, or install cloudflared yourself.")
		}
		return false
	}
}

// freePort asks the kernel for an unused port on host; the listener is
// released immediately, so the port is only reserved by convention.
func freePort(host string) (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// secretFromPathOrEnv reads a credential from path when given, else from
// the named environment variable; "" means neither was set. A path that is
// set but unreadable or empty is an error, not a silent fallback.
func secretFromPathOrEnv(path, env string) (string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		secret := strings.TrimSpace(string(data))
		if secret == "" {
			return "", fmt.Errorf("%s is empty", path)
		}
		return secret, nil
	}
	return strings.TrimSpace(os.Getenv(env)), nil
}
