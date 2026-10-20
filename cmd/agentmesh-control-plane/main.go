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

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/controlplane"
	"github.com/google/agentmesh/internal/logging"
	"github.com/google/agentmesh/internal/pprofserver"
	"github.com/google/agentmesh/internal/secrets"
	"github.com/google/agentmesh/internal/storage"
	"github.com/google/agentmesh/internal/version"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"
)

var (
	bindAddress            string
	pprofAddr              string
	dbDriver               string
	dbDSN                  string
	dbDSNPath              string
	issuerFlags            controlplane.IssuerFlags
	oidcClientID           string
	allowedAudiencesFlag   string
	keyRotationInterval    time.Duration
	keyGracePeriod         time.Duration
	signingKeyPath         string
	leaseDuration          time.Duration
	dhtReplication         int
	dhtReprovideInterval   time.Duration
	biscuitTTL             time.Duration
	oidcSessionTTL         time.Duration
	workloadSessionTTL     time.Duration
	nodeRetention          time.Duration
	ephemeralNodeRetention time.Duration
	meshReconnectInterval  time.Duration
	adminTokenPath         string
	stsIssuerURL           string
	insecureSkipTLSVerify  bool
	logLevel               string
	logFormat              string
	autoApproveEnrollment  bool
)

var logger = golog.Logger("agentmesh-control-plane-cli")

func main() {
	rootCmd := &cobra.Command{
		Use:     "agentmesh-control-plane",
		Short:   "Agent Mesh - Control Plane",
		Version: version.String(),
		// Resolve the DB DSN (may embed a password) before any subcommand runs.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := secrets.FromPathOrEnv("db-dsn", dbDSNPath, "AGENTMESH_DB_DSN")
			if err != nil {
				return err
			}
			if resolved != "" {
				dbDSN = resolved
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			logging.Setup(logging.Options{Level: logLevel, Format: logFormat})

			if issuerFlags.Empty() {
				logger.Fatalf("OIDC issuer is required (use --issuer or --workload-issuer flag)")
			}
			if insecureSkipTLSVerify {
				logger.Warnf("--insecure-skip-tls-verify is set: identity provider TLS certificates are not verified, so anyone on the path to the provider can forge the identities this control plane admits. For development only.")
			}

			adminToken, err := secrets.FromPathOrEnv("admin-token", adminTokenPath, "AGENTMESH_ADMIN_TOKEN")
			if err != nil {
				logger.Fatalf("%v", err)
			}
			if stsIssuerURL == "" {
				stsIssuerURL = strings.TrimSpace(os.Getenv("AGENTMESH_STS_ISSUER_URL"))
			}
			// Options reads 0 as unset; the flag's 0 is a value the operator typed.
			if nodeRetention <= 0 {
				logger.Fatalf("--node-retention must be positive, got %s: node records are never kept forever", nodeRetention)
			}
			if ephemeralNodeRetention <= 0 {
				logger.Fatalf("--ephemeral-node-retention must be positive, got %s", ephemeralNodeRetention)
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
				ListenAddr:             bindAddress,
				DriverName:             dbDriver,
				DataSourceName:         dbDSN,
				OIDCIssuer:             issuerFlags.OIDCIssuer(),
				WorkloadIssuer:         issuerFlags.WorkloadIssuer(),
				OIDCClientID:           oidcClientID,
				AllowedAudiences:       auds,
				LeaseDuration:          leaseDuration,
				KeyRotationInterval:    keyRotationInterval,
				KeyGracePeriod:         keyGracePeriod,
				SigningKeyPath:         signingKeyPath,
				DHTReplication:         dhtReplication,
				DHTReprovideInterval:   dhtReprovideInterval,
				InsecureSkipTLSVerify:  insecureSkipTLSVerify,
				BiscuitTimeout:         10 * time.Second,
				BiscuitTTL:             biscuitTTL,
				OIDCSessionTTL:         oidcSessionTTL,
				WorkloadSessionTTL:     workloadSessionTTL,
				NodeRetention:          nodeRetention,
				EphemeralNodeRetention: ephemeralNodeRetention,
				AdminToken:             adminToken,
				AutoApproveEnrollment:  autoApproveEnrollment,
				STSIssuerURL:           stsIssuerURL,
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
			if pprofAddr != "" {
				pprofSrv, err := pprofserver.Serve(pprofAddr)
				if err != nil {
					logger.Fatalf("Failed to serve profiles on %s: %v", pprofAddr, err)
				}
				defer func() { _ = pprofSrv.Close() }()
				logger.Infof("Profiles at http://%s/debug/pprof/", pprofSrv.Addr)
			}

			logger.Infof("Agent Mesh Control Plane Online on %s", bindAddress)
			<-cmd.Context().Done()
		},
	}

	rootCmd.Flags().StringVar(&bindAddress, "bind-address", "0.0.0.0:8080", "Address to listen on for web API services")
	rootCmd.Flags().StringVar(&pprofAddr, "pprof-addr", "", "Serve Go runtime profiles under /debug/pprof/ on this address (e.g. 127.0.0.1:6060); unauthenticated and a heap profile is a memory dump, so bind it to loopback and reach it through a port-forward; off by default")
	rootCmd.PersistentFlags().StringVar(&dbDriver, "db-driver", "sqlite", "Database driver (sqlite or postgres)")
	rootCmd.PersistentFlags().StringVar(&dbDSN, "db-dsn", "control-plane.db", "Database DSN/Connection URL (avoid for postgres: embeds a password; prefer --db-dsn-path or AGENTMESH_DB_DSN)")
	rootCmd.PersistentFlags().StringVar(&dbDSNPath, "db-dsn-path", "", "Path to file containing the database DSN/Connection URL (overrides --db-dsn; or env AGENTMESH_DB_DSN)")
	issuerFlags.Register(rootCmd.Flags(), "")
	rootCmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "", "OAuth client ID advertised to joining nodes via /info (defaults to the first allowed audience)")
	rootCmd.Flags().StringVar(&allowedAudiencesFlag, "allowed-audiences", api.DefaultAudience, "Comma-separated list of allowed OIDC audiences")
	rootCmd.Flags().DurationVar(&keyRotationInterval, "key-rotation-interval", 24*time.Hour, "Key rotation interval (e.g. 24h). 0 means the default, 24h. --signing-key-path turns rotation off.")
	rootCmd.Flags().DurationVar(&keyGracePeriod, "key-grace-period", 1*time.Hour, "Key grace period for rotated keys.")
	rootCmd.Flags().StringVar(&signingKeyPath, "signing-key-path", "", "PEM file with the control plane's private signing keys (PKCS#8 or SEC 1): Ed25519 for Biscuits, P-256 for the ES256 JWTs; the first key of each kind signs, later ones only verify. Turns automatic key rotation off: rotate by publishing a new first key and keeping the previous one until every credential it signed has expired")
	rootCmd.Flags().DurationVar(&leaseDuration, "lease-duration", 15*time.Minute, "Router lease registration TTL.")
	rootCmd.Flags().IntVar(&dhtReplication, "dht-replication", api.DefaultDHTReplication, "How many routers closest to the key get a copy of each record a member announces, besides the router that keeps it. More replicas survive more routers down at once. Each replica is a copy more of every record. Members are not concerned and ask only the routers they hold. Published on /info for the whole mesh.")
	rootCmd.Flags().DurationVar(&dhtReprovideInterval, "dht-reprovide-interval", api.DefaultReprovideInterval, "How often a member re-announces each service it publishes. A provider that stopped without unpublishing stays listed for three intervals; the mesh pays providers / interval announcements a minute. Published on /info for the whole mesh.")
	rootCmd.Flags().DurationVar(&biscuitTTL, "biscuit-ttl", api.BiscuitTokenTTL, "Lifespan minted into every issued Biscuit's expiration fact. Capped to the OIDC token's own expiry when shorter.")
	rootCmd.Flags().DurationVar(&oidcSessionTTL, "oidc-session-ttl", api.OIDCSessionTTL, "How long an OIDC enrollment stays refreshable before the identity must re-authenticate with the OIDC provider. Shorter values keep the provider authoritative for offboarding at the cost of more frequent interactive re-enrollment.")
	rootCmd.Flags().DurationVar(&workloadSessionTTL, "workload-session-ttl", controlplane.DefaultWorkloadSessionTTL, "How long a workload-issuer enrollment stays refreshable without presenting a fresh platform JWT on /refresh.")
	rootCmd.Flags().DurationVar(&nodeRetention, "node-retention", controlplane.DefaultNodeRetention, "How long an enrolled node's record is kept after its session expired, or after its last refresh for a node enrolled with a bootstrap token, before it is deleted. Banned nodes are always kept. Must be positive: records are never kept forever.")
	rootCmd.Flags().DurationVar(&ephemeralNodeRetention, "ephemeral-node-retention", controlplane.DefaultEphemeralNodeRetention, "--node-retention for a node enrolled with an ephemeral bootstrap token: how long after its last refresh its record is kept. For members that come and go: a fleet in a scale test, a probe, a CI job.")
	rootCmd.Flags().DurationVar(&meshReconnectInterval, "mesh-reconnect-interval", controlplane.DefaultMeshReconnectInterval, "How often the event publisher re-reads the router leases and dials any router it is not connected to.")
	rootCmd.Flags().StringVar(&adminTokenPath, "admin-token-path", "", "Path to file containing the token for authenticating policy REST API requests (or env AGENTMESH_ADMIN_TOKEN)")
	rootCmd.Flags().StringVar(&stsIssuerURL, "sts-issuer-url", "", "Canonical external URL of this control plane for OIDC/STS issuer and discovery metadata (or env AGENTMESH_STS_ISSUER_URL)")
	rootCmd.Flags().BoolVar(&insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip TLS verification for OIDC providers")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&logFormat, "log-format", "text", "Log format (text, json)")
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
