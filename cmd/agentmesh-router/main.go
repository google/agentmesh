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
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/logging"
	"github.com/google/agentmesh/internal/pprofserver"
	"github.com/google/agentmesh/internal/router"
	"github.com/google/agentmesh/internal/version"
	golog "github.com/ipfs/go-log/v2"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/spf13/cobra"
)

// The integration tests run a DNS server of their own for the dnsaddr
// addresses routers announce; the router resolves peer routers through it
// when told to, as agentmesh-node does.
func init() {
	if dnsServer := os.Getenv("AGENTMESH_TEST_DNS_SERVER"); dnsServer != "" {
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
	controlPlaneURL          string
	insecureControlPlane     bool
	listenAddrs              []string
	externalAddrs            []string
	controlPlaneSyncInterval time.Duration
	oidcToken                string
	bootstrapToken           string
	bootstrapTokenPath       string
	jwtPath                  string
	keysPath                 string
	allowLoopback            bool
	connsPerSourceIP         int
	logLevel                 string
	logFormat                string
	lowWaterMark             int
	highWaterMark            int
	metricsAddr              string
	pprofAddr                string
	relayLimitDuration       time.Duration
	relayLimitData           router.ByteSize
	relayMaxReservations     int
	relayMaxCircuits         int
	shutdownLeaseTTL         time.Duration
	authDeadline             time.Duration
	labelFlags               []string
	ingressAddr              string
	ingressURL               string
	ingressTLSCertPath       string
	ingressTLSKeyPath        string
	allowInsecureIngressHTTP bool
	publicControlPlaneURL    string
)

var logger = golog.Logger("agentmesh-router-cli")

func main() {
	rootCmd := &cobra.Command{
		Use:     "agentmesh-router",
		Short:   "Agent Mesh - libp2p Router Node",
		Version: version.String(),
		Run: func(cmd *cobra.Command, args []string) {
			logging.Setup(logging.Options{Level: logLevel, Format: logFormat})

			opts := router.Options{
				ControlPlaneURL:           controlPlaneURL,
				AllowInsecureControlPlane: insecureControlPlane,
				ListenAddrs:               listenAddrs,
				ExternalAddrs:             externalAddrs,
				ControlPlaneSyncInterval:  controlPlaneSyncInterval,
				OIDCToken:                 oidcToken,
				BootstrapToken:            bootstrapToken,
				BootstrapTokenPath:        bootstrapTokenPath,
				JWTPath:                   jwtPath,
				KeysDBPath:                keysPath,
				AllowLoopback:             allowLoopback,
				ConnsPerSourceIP:          connsPerSourceIP,
				LowWaterMark:              lowWaterMark,
				HighWaterMark:             highWaterMark,
				MetricsAddr:               metricsAddr,
				RelayLimitDuration:        relayLimitDuration,
				RelayLimitData:            int64(relayLimitData),
				RelayMaxReservations:      relayMaxReservations,
				RelayMaxCircuits:          relayMaxCircuits,
				ShutdownLeaseTTL:          shutdownLeaseTTL,
				AuthDeadline:              authDeadline,
				IngressAddr:               ingressAddr,
				IngressURL:                ingressURL,
				IngressTLSCertPath:        ingressTLSCertPath,
				IngressTLSKeyPath:         ingressTLSKeyPath,
				AllowInsecureIngressHTTP:  allowInsecureIngressHTTP,
				PublicControlPlaneURL:     publicControlPlaneURL,
			}
			labels, err := api.ParseLabelFlags(labelFlags)
			if err != nil {
				logger.Fatalf("Invalid --label: %v", err)
			}
			opts.Labels = labels

			r, err := router.NewRouter(cmd.Context(), opts)
			if err != nil {
				logger.Fatalf("Failed to initialize router: %v", err)
			}
			defer func() {
				if err := r.Close(); err != nil {
					logger.Errorf("Failed to stop router: %v", err)
				}
			}()

			if err := r.Start(); err != nil {
				_ = r.Close()
				logger.Fatalf("Failed to start router: %v", err)
			}
			if pprofAddr != "" {
				pprofSrv, err := pprofserver.Serve(pprofAddr)
				if err != nil {
					logger.Fatalf("Failed to serve profiles on %s: %v", pprofAddr, err)
				}
				defer func() { _ = pprofSrv.Close() }()
				logger.Infof("Profiles at http://%s/debug/pprof/", pprofSrv.Addr)
			}

			<-cmd.Context().Done()
		},
	}

	rootCmd.Flags().StringVar(&controlPlaneURL, "control-plane", "http://127.0.0.1:8080", "Control Plane web service URL")
	rootCmd.Flags().BoolVar(&insecureControlPlane, "insecure-control-plane", false, "Accept a plaintext http:// control plane URL to a non-loopback host (whoever answers it becomes this router's trust root; only for networks you already trust)")
	rootCmd.Flags().StringSliceVar(&listenAddrs, "listen", []string{"/ip4/0.0.0.0/tcp/5001", "/ip6/::/tcp/5001"}, "libp2p Listen Addresses")
	rootCmd.Flags().StringSliceVar(&externalAddrs, "external-addr", []string{}, "External addresses to announce to control plane")
	rootCmd.Flags().DurationVar(&controlPlaneSyncInterval, "control-plane-sync-interval", router.DefaultControlPlaneSyncInterval, "How often the lease is renewed and signing keys, the router list, bans and the mesh policy are pulled from the control plane; a mesh event pulls at once. Keep it well below the control plane's --lease-duration and --key-grace-period.")
	rootCmd.Flags().StringVar(&oidcToken, "oidc-token", "", "OIDC ID token for enrollment")
	rootCmd.Flags().StringVar(&bootstrapToken, "bootstrap-token", "", "Pre-shared bootstrap token for enrollment")
	rootCmd.Flags().StringVar(&bootstrapTokenPath, "bootstrap-token-path", "", "Path to file containing bootstrap token for enrollment")
	rootCmd.Flags().StringVar(&jwtPath, "jwt-path", "", "Path to file containing OIDC JWT token")
	rootCmd.Flags().StringVar(&keysPath, "keys-path", "router.key", "Path to save/load persistent private key")
	rootCmd.Flags().BoolVar(&allowLoopback, "allow-loopback", false, "Allow loopback and link-local addresses for discovery")
	rootCmd.Flags().IntVar(&connsPerSourceIP, "conns-per-source-ip", 0, "Max inbound connections per source IP; 0 is a quarter of --high-watermark, so filling the router takes at least four addresses. Raise it where more members share one address")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&logFormat, "log-format", "text", "Log format (text, json)")
	rootCmd.Flags().IntVar(&lowWaterMark, "low-watermark", 0, "Connections the router trims down to once it is over --high-watermark; 0 is 15% below the high watermark, so a trim sheds that share and no more")
	rootCmd.Flags().IntVar(&highWaterMark, "high-watermark", router.DefaultHighWaterMark, "Connections the router accepts before it trims; every member holds one, so this is the size of the mesh")
	rootCmd.Flags().StringVar(&metricsAddr, "metrics-addr", "", "Serve Prometheus /metrics, /healthz and /readyz on this address (e.g. 0.0.0.0:9090); unauthenticated, off by default")
	rootCmd.Flags().StringVar(&pprofAddr, "pprof-addr", "", "Serve Go runtime profiles under /debug/pprof/ on this address (e.g. 127.0.0.1:6060); unauthenticated and a heap profile is a memory dump, so bind it to loopback and reach it through a port-forward; off by default")
	rootCmd.Flags().DurationVar(&relayLimitDuration, "relay-limit-duration", router.DefaultRelayLimitDuration, "Lifetime of each relayed connection (0 = no limit)")
	rootCmd.Flags().Var(&relayLimitData, "relay-limit-data", "Bytes relayed per direction on each relayed connection, e.g. 512MiB (0 = no limit)")
	rootCmd.Flags().IntVar(&relayMaxReservations, "relay-max-reservations", 0, "Members that may hold a relay reservation, which is what makes a member reachable through this router; 0 is --high-watermark")
	rootCmd.Flags().IntVar(&relayMaxCircuits, "relay-max-circuits", 0, fmt.Sprintf("Relayed connections one peer may hold at once through this router, as caller or as destination; 0 is %d", router.DefaultRelayMaxCircuits))
	rootCmd.Flags().DurationVar(&shutdownLeaseTTL, "shutdown-lease-ttl", router.DefaultShutdownLeaseTTL, "Sent in this router's last lease when it stops: how long it expects to be away, which is how long the control plane keeps listing it. 0 sends nothing and the lease expires on the control plane's schedule")
	rootCmd.Flags().DurationVar(&authDeadline, "auth-deadline", router.DefaultAuthDeadline, "Close an inbound connection whose peer has not passed the mesh handshake within this time; members handshake at once, a DHT query from a member attached elsewhere is done long before. 0 keeps every connection")
	rootCmd.Flags().StringArrayVar(&labelFlags, "label", nil, "A key=value label declared at enrollment, repeatable; the control plane signs it only if the router's role allows it, and members select or prefer routers by it (e.g. region=eu, zone=us-central1-a)")
	rootCmd.Flags().StringVar(&ingressAddr, "ingress-addr", "", "Serve external HTTP ingress under /ingress/ on this address (e.g. 0.0.0.0:8080); off by default")
	rootCmd.Flags().StringVar(&ingressURL, "ingress-url", "", "Public base URL advertised for external HTTP ingress on this router (e.g. https://bananas.sam-mesh.dev/ingress)")
	rootCmd.Flags().StringVar(&ingressTLSCertPath, "ingress-tls-cert-path", "", "Path to TLS certificate file for --ingress-addr")
	rootCmd.Flags().StringVar(&ingressTLSKeyPath, "ingress-tls-key-path", "", "Path to TLS private key file for --ingress-addr")
	rootCmd.Flags().BoolVar(&allowInsecureIngressHTTP, "allow-insecure-ingress-http", false, "Allow --ingress-addr on a non-loopback interface without TLS and allow http:// in --ingress-url. Risk: every caller's bearer Biscuit and request body then cross the network in plaintext between the client and this router; set it only when a TLS-terminating L7 load balancer in front of the router is the only thing that can reach --ingress-addr")
	rootCmd.Flags().StringVar(&publicControlPlaneURL, "public-control-plane", "", "Optional public URL of the control plane advertised in RFC 9728 and A2A OAuth metadata when --control-plane uses a cluster-internal address")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
