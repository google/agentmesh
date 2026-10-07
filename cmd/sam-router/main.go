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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/sam/internal/router"
	"github.com/google/sam/internal/version"
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
	relayLimitDuration   time.Duration
	relayLimitData       router.ByteSize
)

var logger = golog.Logger("sam-router-cli")

func main() {
	rootCmd := &cobra.Command{
		Use:     "sam-router",
		Short:   "Sovereign Agent Mesh - libp2p Router Node",
		Version: version.String(),
		Run: func(cmd *cobra.Command, args []string) {
			// Initialize logging
			if os.Getenv("LOG_FORMAT") == "json" {
				_ = os.Setenv("GOLOG_LOG_FMT", "json")
			}
			golog.SetAllLoggers(golog.LevelInfo)
			if logLevel != "" {
				lvl, err := golog.LevelFromString(logLevel)
				if err == nil {
					golog.SetAllLoggers(lvl)
				}
			}

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
			}

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
	rootCmd.Flags().IntVar(&connsPerSourceIP, "conns-per-source-ip", 0, "Max inbound connections per source IP (0 keeps libp2p's default of 8); raise behind TLS-terminating proxies or NAT where many peers share source IPs")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().DurationVar(&dhtProviderAddrTTL, "dht-provider-addr-ttl", router.DefaultDHTProviderAddrTTL, "How long a DHT provider record lives after its last announcement (0 = the default)")
	rootCmd.Flags().DurationVar(&dhtMaxRecordAge, "dht-max-record-age", 0, "Maximum age for DHT records (0s uses library default)")
	rootCmd.Flags().IntVar(&lowWaterMark, "low-watermark", 1000, "Connection manager low watermark limit")
	rootCmd.Flags().IntVar(&highWaterMark, "high-watermark", 4000, "Connection manager high watermark limit")
	rootCmd.Flags().StringVar(&metricsAddr, "metrics-addr", "", "Serve Prometheus /metrics, /healthz and /readyz on this address (e.g. 0.0.0.0:9090); unauthenticated, off by default")
	rootCmd.Flags().DurationVar(&relayLimitDuration, "relay-limit-duration", router.DefaultRelayLimitDuration, "Lifetime of each relayed connection (0 = no limit)")
	rootCmd.Flags().Var(&relayLimitData, "relay-limit-data", "Bytes relayed per direction on each relayed connection, e.g. 512MiB (0 = no limit)")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
