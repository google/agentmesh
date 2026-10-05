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
	"strings"
	"syscall"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/controlplane"
	"github.com/google/sam/internal/secrets"
	"github.com/google/sam/internal/storage"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"
)

var (
	bindAddress           string
	dbDriver              string
	dbDSN                 string
	dbDSNPath             string
	oidcIssuer            string
	workloadIssuer        string
	oidcClientID          string
	allowedAudiencesFlag  string
	keyRotationInterval   time.Duration
	keyGracePeriod        time.Duration
	leaseDuration         time.Duration
	biscuitTTL            time.Duration
	oidcSessionTTL        time.Duration
	workloadSessionTTL    time.Duration
	nodeRetention         time.Duration
	meshReconnectInterval time.Duration
	adminTokenPath        string
	insecureSkipTLSVerify bool
	logLevel              string
	autoApproveEnrollment bool
)

var logger = golog.Logger("sam-control-plane-cli")

func main() {
	rootCmd := &cobra.Command{
		Use:   "sam-control-plane",
		Short: "Sovereign Agent Mesh - Control Plane",
		// Resolve the DB DSN (may embed a password) before any subcommand runs.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := secrets.FromPathOrEnv("db-dsn", dbDSNPath, "SAM_DB_DSN")
			if err != nil {
				return err
			}
			if resolved != "" {
				dbDSN = resolved
			}
			return nil
		},
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

			if oidcIssuer == "" && workloadIssuer == "" {
				logger.Fatalf("OIDC issuer is required (use --issuer or --workload-issuer flag)")
			}

			adminToken, err := secrets.FromPathOrEnv("admin-token", adminTokenPath, "SAM_ADMIN_TOKEN")
			if err != nil {
				logger.Fatalf("%v", err)
			}

			var auds []string
			for _, aud := range strings.Split(allowedAudiencesFlag, ",") {
				aud = strings.TrimSpace(aud)
				if aud != "" {
					auds = append(auds, aud)
				}
			}
			if len(auds) == 0 {
				auds = []string{api.DefaultAudience}
			}

			// Open DB Store
			store, err := storage.NewSQLStore(dbDriver, dbDSN)
			if err != nil {
				logger.Fatalf("Failed to initialize database store: %v", err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					logger.Errorf("Failed to close database: %v", err)
				}
			}()

			opts := controlplane.Options{
				ListenAddr:            bindAddress,
				DriverName:            dbDriver,
				DataSourceName:        dbDSN,
				OIDCIssuer:            oidcIssuer,
				WorkloadIssuer:        workloadIssuer,
				OIDCClientID:          oidcClientID,
				AllowedAudiences:      auds,
				LeaseDuration:         leaseDuration,
				KeyRotationInterval:   keyRotationInterval,
				KeyGracePeriod:        keyGracePeriod,
				InsecureSkipTLSVerify: insecureSkipTLSVerify,
				BiscuitTimeout:        10 * time.Second,
				BiscuitTTL:            biscuitTTL,
				OIDCSessionTTL:        oidcSessionTTL,
				WorkloadSessionTTL:    workloadSessionTTL,
				NodeRetention:         nodeRetention,
				AdminToken:            adminToken,
				AutoApproveEnrollment: autoApproveEnrollment,
			}

			srv, err := controlplane.NewServer(opts, store)
			if err != nil {
				logger.Fatalf("Failed to create control plane server: %v", err)
			}
			defer func() {
				if err := srv.Close(); err != nil {
					logger.Errorf("Failed to stop control plane: %v", err)
				}
			}()

			// Bans, key rotations and policy updates reach the mesh as they
			// happen; every consumer also pulls, so this is speed, not truth.
			mesh, err := controlplane.NewMeshPublisher(cmd.Context(), store, meshReconnectInterval)
			if err != nil {
				logger.Fatalf("Failed to start mesh event publisher: %v", err)
			}
			defer func() {
				if err := mesh.Close(); err != nil {
					logger.Errorf("Failed to stop mesh event publisher: %v", err)
				}
			}()
			srv.SetMeshAdapter(mesh)

			if err := srv.Start(); err != nil {
				logger.Fatalf("Failed to start control plane: %v", err)
			}

			logger.Infof("SAM Control Plane Online on %s", bindAddress)
			<-cmd.Context().Done()
		},
	}

	rootCmd.Flags().StringVar(&bindAddress, "bind-address", "0.0.0.0:8080", "Address to listen on for web API services")
	rootCmd.PersistentFlags().StringVar(&dbDriver, "db-driver", "sqlite", "Database driver (sqlite or postgres)")
	rootCmd.PersistentFlags().StringVar(&dbDSN, "db-dsn", "control-plane.db", "Database DSN/Connection URL (avoid for postgres: embeds a password; prefer --db-dsn-path or SAM_DB_DSN)")
	rootCmd.PersistentFlags().StringVar(&dbDSNPath, "db-dsn-path", "", "Path to file containing the database DSN/Connection URL (overrides --db-dsn; or env SAM_DB_DSN)")
	rootCmd.Flags().StringVar(&oidcIssuer, "issuer", "", "OIDC Issuer URL (comma-separated)")
	rootCmd.Flags().StringVar(&workloadIssuer, "workload-issuer", "", "Workload OIDC Issuer URL or '<issuer>=<email-suffix>' (comma-separated); accepted at /register, /refresh and /token/exchange, refused at /user/* and /oauth/authorize")
	rootCmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "", "OAuth client ID advertised to joining nodes via /info (defaults to the first allowed audience)")
	rootCmd.Flags().StringVar(&allowedAudiencesFlag, "allowed-audiences", api.DefaultAudience, "Comma-separated list of allowed OIDC audiences")
	rootCmd.Flags().DurationVar(&keyRotationInterval, "key-rotation-interval", 24*time.Hour, "Key rotation interval (e.g. 24h). 0 disables rotation.")
	rootCmd.Flags().DurationVar(&keyGracePeriod, "key-grace-period", 1*time.Hour, "Key grace period for rotated keys.")
	rootCmd.Flags().DurationVar(&leaseDuration, "lease-duration", 15*time.Minute, "Router lease registration TTL.")
	rootCmd.Flags().DurationVar(&biscuitTTL, "biscuit-ttl", api.BiscuitTokenTTL, "Lifespan minted into every issued Biscuit's expiration fact. Capped to the OIDC token's own expiry when shorter.")
	rootCmd.Flags().DurationVar(&oidcSessionTTL, "oidc-session-ttl", api.OIDCSessionTTL, "How long an OIDC enrollment stays refreshable before the identity must re-authenticate with the OIDC provider. Shorter values keep the provider authoritative for offboarding at the cost of more frequent interactive re-enrollment.")
	rootCmd.Flags().DurationVar(&workloadSessionTTL, "workload-session-ttl", controlplane.DefaultWorkloadSessionTTL, "How long a workload-issuer enrollment stays refreshable without presenting a fresh platform JWT on /refresh.")
	rootCmd.Flags().DurationVar(&nodeRetention, "node-retention", controlplane.DefaultNodeRetention, "How long an enrolled node's record is kept after its session expired before it is deleted. Banned nodes are always kept. 0 keeps every record forever.")
	rootCmd.Flags().DurationVar(&meshReconnectInterval, "mesh-reconnect-interval", controlplane.DefaultMeshReconnectInterval, "How often the event publisher re-reads the router leases and dials any router it is not connected to.")
	rootCmd.Flags().StringVar(&adminTokenPath, "admin-token-path", "", "Path to file containing the token for authenticating policy REST API requests (or env SAM_ADMIN_TOKEN)")
	rootCmd.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS verification for OIDC providers")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().BoolVar(&autoApproveEnrollment, "auto-approve-enrollment", false, "Auto-approve valid bootstrap token enrollment requests")

	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrative operations",
	}

	var peerIDFlag string
	// setBan is the CLI counterpart of POST /admin/revoke and
	// POST /admin/nodes/{peer}/unban: same canonicalization, same node and
	// identity halves. A raw --peer used to match zero rows and still print
	// "Successfully banned".
	setBan := func(ctx context.Context, rawPeer string, banned bool) error {
		pID, err := peer.Decode(rawPeer)
		if err != nil {
			return fmt.Errorf("invalid peer ID %q: %w", rawPeer, err)
		}
		store, err := storage.NewSQLStore(dbDriver, dbDSN)
		if err != nil {
			return fmt.Errorf("failed to initialize database store: %w", err)
		}
		defer store.Close() //nolint:errcheck
		node, err := store.GetNode(ctx, pID.String())
		if err != nil {
			return fmt.Errorf("node %s: %w", pID, err)
		}
		return controlplane.SetNodeBan(ctx, store, node, banned)
	}
	banCmd := &cobra.Command{
		Use:   "ban",
		Short: "Ban a node peer ID and the identity that enrolled it",
		Run: func(cmd *cobra.Command, args []string) {
			if err := setBan(cmd.Context(), peerIDFlag, true); err != nil {
				logger.Fatalf("Failed to ban node: %v", err)
			}
			logger.Infof("Successfully banned node %s", peerIDFlag)
		},
	}
	banCmd.Flags().StringVar(&peerIDFlag, "peer", "", "Node Peer ID to ban")
	_ = banCmd.MarkFlagRequired("peer")

	unbanCmd := &cobra.Command{
		Use:   "unban",
		Short: "Unban a node peer ID and the identity that enrolled it",
		Run: func(cmd *cobra.Command, args []string) {
			if err := setBan(cmd.Context(), peerIDFlag, false); err != nil {
				logger.Fatalf("Failed to unban node: %v", err)
			}
			logger.Infof("Successfully unbanned node %s", peerIDFlag)
		},
	}
	unbanCmd.Flags().StringVar(&peerIDFlag, "peer", "", "Node Peer ID to unban")
	_ = unbanCmd.MarkFlagRequired("peer")

	adminCmd.AddCommand(banCmd, unbanCmd)
	rootCmd.AddCommand(adminCmd)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
