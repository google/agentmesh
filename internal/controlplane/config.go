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

package controlplane

import (
	"fmt"
	"time"

	"github.com/google/sam/api"
)

// Options holds configuration for the control plane.
type Options struct {
	ListenAddr     string
	DriverName     string
	DataSourceName string
	OIDCIssuer     string
	// WorkloadIssuer is a comma-separated list of OIDC issuers (subset of or
	// addition to OIDCIssuer) that issue machine/workload tokens rather than
	// human user tokens. Tokens from a workload issuer are accepted at
	// /register, /refresh, and /token/exchange, and refused at /user/* and
	// /oauth/authorize.
	WorkloadIssuer        string
	OIDCClientID          string // OAuth client id advertised via /info; defaults to the first allowed audience
	AllowedAudiences      []string
	LeaseDuration         time.Duration
	KeyRotationInterval   time.Duration
	KeyGracePeriod        time.Duration
	InsecureSkipTLSVerify bool
	BiscuitTimeout        time.Duration
	BiscuitTTL            time.Duration // Lifespan minted into every issued Biscuit's expiration() fact; defaults to api.BiscuitTokenTTL
	OIDCSessionTTL        time.Duration // How long an OIDC enrollment stays refreshable before the identity must re-authenticate interactively; defaults to api.OIDCSessionTTL
	WorkloadSessionTTL    time.Duration // Session TTL for enrollments from a WorkloadIssuer; defaults to DefaultWorkloadSessionTTL (48h)
	// NodeRetention is how long an enrolled node's row is kept after its
	// session expired before being deleted; 0 keeps rows forever. Every
	// pod restart without a persistent data dir enrolls a fresh identity,
	// so without this the nodes table only ever grows.
	NodeRetention         time.Duration
	AdminToken            string // Optional: administrative bearer token for protecting policy and enrollment queue REST APIs
	AutoApproveEnrollment bool   // If true, valid bootstrap token enrollment requests are immediately approved without administrative manual gate
	// STSIssuerURL is the public issuer URL advertised in
	// /.well-known/openid-configuration and minted as the "iss" claim in
	// outbound /sts/token JWTs. If empty, derived from the incoming HTTP request.
	STSIssuerURL string
	// DelegatedBiscuitTTL bounds the lifespan of Delegated Session Biscuits
	// minted by POST /token/exchange and OAuth 2.1 flows (defaults to 1h).
	DelegatedBiscuitTTL time.Duration
	// STSTokenTTL is the default lifespan of short-lived ES256 border JWTs
	// minted by POST /sts/token (defaults to 5m, capped at 15m).
	STSTokenTTL time.Duration
	// OIDCSigner signs outbound border JWTs and serves /jwks. If nil, a
	// LocalES256Signer is initialized automatically.
	OIDCSigner OIDCSigner
	// STSRateLimit is the per-node request rate limit (requests/second) for
	// /token/exchange and /sts/token (defaults to STSRateLimitDefault).
	STSRateLimit float64
	// STSRateBurst is the per-node burst size for /token/exchange and
	// /sts/token (defaults to STSRateBurstDefault).
	STSRateBurst int
}

const (
	// STSRateLimitDefault sizes per-node STS throughput for workload JWT
	// rotation and egress border JWT minting.
	STSRateLimitDefault = 100
	// STSRateBurstDefault sizes per-node STS burst capacity.
	STSRateBurstDefault = 200
	// DefaultWorkloadSessionTTL is the default session TTL for workload OIDC
	// issuers (48h, twice BiscuitTokenTTL so a single missed refresh does not
	// sever the node).
	DefaultWorkloadSessionTTL = 48 * time.Hour
)

// Default sets default values for control plane options.
func (o *Options) Default() {
	if o.ListenAddr == "" {
		o.ListenAddr = "0.0.0.0:8080"
	}
	if o.DriverName == "" {
		o.DriverName = "sqlite"
		o.DataSourceName = "control-plane.db"
	}
	if o.LeaseDuration <= 0 {
		o.LeaseDuration = 15 * time.Minute
	}
	if o.KeyRotationInterval <= 0 {
		o.KeyRotationInterval = 24 * time.Hour
	}
	if o.KeyGracePeriod <= 0 {
		o.KeyGracePeriod = 1 * time.Hour
	}
	if o.BiscuitTTL <= 0 {
		o.BiscuitTTL = api.BiscuitTokenTTL
	}
	if o.OIDCSessionTTL <= 0 {
		o.OIDCSessionTTL = api.OIDCSessionTTL
	}
	if o.WorkloadSessionTTL <= 0 {
		o.WorkloadSessionTTL = DefaultWorkloadSessionTTL
	}
	if o.DelegatedBiscuitTTL <= 0 {
		o.DelegatedBiscuitTTL = 1 * time.Hour
	}
	if o.STSTokenTTL <= 0 {
		o.STSTokenTTL = 5 * time.Minute
	}
	if o.STSRateLimit <= 0 {
		o.STSRateLimit = STSRateLimitDefault
	}
	if o.STSRateBurst <= 0 {
		o.STSRateBurst = STSRateBurstDefault
	}
}

// Validate ensures options are valid.
func (o *Options) Validate() error {
	if o.DriverName == "" {
		return fmt.Errorf("DriverName must be specified")
	}
	if o.DataSourceName == "" {
		return fmt.Errorf("DataSourceName must be specified")
	}
	return nil
}
