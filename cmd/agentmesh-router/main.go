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
	"github.com/spf13/cobra"
)

var (
	controlPlaneURL      string
	insecureControlPlane bool
	listenAddrs          []string
	externalAddrs        []string
	keysSyncInterval     time.Duration
	leaseRenewInterval   time.Duration
	oidcToken            string
	bootstrapToken       string
	bootstrapTokenPath   string
	jwtPath              string
	keysPath             string
	allowLoopback        bool
	connsPerSourceIP     int
	logLevel             string
	dhtProviderAddrTTL   time.Duration
	dhtMaxRecordAge      time.Duration
	lowWaterMark         int
	highWaterMark        int
	metricsAddr          string
	pprofAddr            string
	relayLimitDuration   time.Duration
	relayLimitData       router.ByteSize
	relayMaxReservations int
	relayMaxCircuits     int
	shutdownLeaseTTL     time.Duration
	authDeadline         time.Duration
	labelFlags           []string
)

var logger = golog.Logger("agentmesh-router-cli")

func main() {
	rootCmd := &cobra.Command{
		Use:     "agentmesh-router",
		Short:   "Agent Mesh - libp2p Router Node",
		Version: version.String(),
		Run: func(cmd *cobra.Command, args []string) {
			logging.Setup(logLevel, "")

			opts := router.Options{
				ControlPlaneURL:           controlPlaneURL,
				AllowInsecureControlPlane: insecureControlPlane,
				ListenAddrs:               listenAddrs,
				ExternalAddrs:             externalAddrs,
				KeysSyncInterval:          keysSyncInterval,
				LeaseRenewInterval:        leaseRenewInterval,
				OIDCToken:                 oidcToken,
				BootstrapToken:            bootstrapToken,
				BootstrapTokenPath:        bootstrapTokenPath,
				JWTPath:                   jwtPath,
				KeysDBPath:                keysPath,
				AllowLoopback:             allowLoopback,
				ConnsPerSourceIP:          connsPerSourceIP,
				DHTProviderAddrTTL:        dhtProviderAddrTTL,
				DHTMaxRecordAge:           dhtMaxRecordAge,
				LowWaterMark:              lowWaterMark,
				HighWaterMark:             highWaterMark,
				MetricsAddr:               metricsAddr,
				RelayLimitDuration:        relayLimitDuration,
				RelayLimitData:            int64(relayLimitData),
				RelayMaxReservations:      relayMaxReservations,
				RelayMaxCircuits:          relayMaxCircuits,
				ShutdownLeaseTTL:          shutdownLeaseTTL,
				AuthDeadline:              authDeadline,
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
	rootCmd.Flags().DurationVar(&keysSyncInterval, "keys-sync-interval", 5*time.Minute, "Key synchronization polling interval")
	rootCmd.Flags().DurationVar(&leaseRenewInterval, "lease-renew-interval", 300*time.Second, "Lease renewal registration interval")
	rootCmd.Flags().StringVar(&oidcToken, "oidc-token", "", "OIDC ID token for enrollment")
	rootCmd.Flags().StringVar(&bootstrapToken, "bootstrap-token", "", "Pre-shared bootstrap token for enrollment")
	rootCmd.Flags().StringVar(&bootstrapTokenPath, "bootstrap-token-path", "", "Path to file containing bootstrap token for enrollment")
	rootCmd.Flags().StringVar(&jwtPath, "jwt-path", "", "Path to file containing OIDC JWT token")
	rootCmd.Flags().StringVar(&keysPath, "keys-path", "router.key", "Path to save/load persistent private key")
	rootCmd.Flags().BoolVar(&allowLoopback, "allow-loopback", false, "Allow loopback and link-local addresses for discovery")
	rootCmd.Flags().IntVar(&connsPerSourceIP, "conns-per-source-ip", 0, "Max inbound connections per source IP; 0 is a quarter of --high-watermark, so filling the router takes at least four addresses. Raise it where more members share one address")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().DurationVar(&dhtProviderAddrTTL, "dht-provider-addr-ttl", router.DefaultDHTProviderAddrTTL, "How long a DHT provider record lives after its last announcement")
	rootCmd.Flags().DurationVar(&dhtMaxRecordAge, "dht-max-record-age", 0, "Maximum age for DHT records (0s uses library default)")
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
