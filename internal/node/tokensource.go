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

package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/sam/api"
	cpclient "github.com/google/sam/internal/controlplane/client"
)

const (
	defaultGCEMetadataIdentityEndpoint = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
	maxMetadataIdentityBytes           = 64 * 1024
)

// TokenSource fetches a fresh platform or OIDC JWT for enrollment, continuous
// attestation at POST /refresh, or fallback re-enrollment.
type TokenSource = cpclient.TokenSource

// FileTokenSource reads a JWT from a file path (e.g. a Kubernetes projected
// ServiceAccount token volume or a SPIRE spiffe-helper JWT-SVID file).
type FileTokenSource = cpclient.FileTokenSource

// NewFileTokenSource creates a TokenSource that reads path on every FetchToken call.
var NewFileTokenSource = cpclient.NewFileTokenSource

// ClientCredentialsTokenSource fetches a JWT via OAuth2 client_credentials
// against an OIDC issuer.
type ClientCredentialsTokenSource struct {
	node         *SamNode
	issuerURL    string
	clientID     string
	clientSecret string
}

// NewClientCredentialsTokenSource creates a TokenSource that exchanges client
// credentials at issuerURL's token endpoint.
func NewClientCredentialsTokenSource(n *SamNode, issuerURL, clientID, clientSecret string) *ClientCredentialsTokenSource {
	if n == nil {
		n = &SamNode{}
	}
	return &ClientCredentialsTokenSource{
		node:         n,
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// FetchToken discovers the OIDC token endpoint and fetches a fresh JWT.
func (s *ClientCredentialsTokenSource) FetchToken(ctx context.Context) (string, error) {
	tokenURL, err := s.node.DiscoverTokenURL(ctx, s.issuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to discover OIDC endpoints: %w", err)
	}
	tok, err := s.node.FetchJWT(ctx, tokenURL, s.clientID, s.clientSecret)
	if err != nil {
		return "", fmt.Errorf("failed to fetch JWT: %w", err)
	}
	return tok, nil
}

// RefreshTokenSource exchanges a stored OIDC refresh token for a fresh JWT.
type RefreshTokenSource struct {
	node         *SamNode
	clientSecret string
}

// NewRefreshTokenSource creates a TokenSource backed by the node's persisted
// OIDC refresh token.
func NewRefreshTokenSource(n *SamNode, clientSecret string) *RefreshTokenSource {
	return &RefreshTokenSource{
		node:         n,
		clientSecret: clientSecret,
	}
}

// FetchToken exchanges the stored refresh token for a new ID/access token.
func (s *RefreshTokenSource) FetchToken(ctx context.Context) (string, error) {
	if s.node == nil {
		return "", errors.New("node is required for refresh token source")
	}
	return s.node.renewWithRefreshToken(ctx, s.clientSecret)
}

// GCPMetadataTokenSource fetches a Google-signed OIDC ID token from the GCE or
// Cloud Run instance metadata server.
type GCPMetadataTokenSource struct {
	audience   string
	endpoint   string
	httpClient *http.Client
}

// NewGCPMetadataTokenSource creates a TokenSource targeting the GCE/Cloud Run
// service account identity metadata endpoint with format=full.
func NewGCPMetadataTokenSource(audience, endpoint string, httpClient *http.Client) *GCPMetadataTokenSource {
	if strings.TrimSpace(audience) == "" {
		audience = api.DefaultAudience
	}
	if strings.TrimSpace(endpoint) == "" {
		endpoint = defaultGCEMetadataIdentityEndpoint
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &GCPMetadataTokenSource{
		audience:   strings.TrimSpace(audience),
		endpoint:   strings.TrimSpace(endpoint),
		httpClient: httpClient,
	}
}

// FetchToken requests an OIDC identity token from the GCP metadata server.
func (s *GCPMetadataTokenSource) FetchToken(ctx context.Context) (string, error) {
	u, err := url.Parse(s.endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid GCP metadata endpoint %q: %w", s.endpoint, err)
	}
	q := u.Query()
	q.Set("audience", s.audience)
	q.Set("format", "full")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GCP metadata identity request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataIdentityBytes))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GCP metadata identity returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	tok := strings.TrimSpace(string(body))
	if tok == "" {
		return "", errors.New("GCP metadata identity returned an empty token")
	}
	return tok, nil
}

// ProbeGCPMetadata reports whether the GCE/Cloud Run metadata server is
// reachable and answers with Metadata-Flavor: Google.
func ProbeGCPMetadata(ctx context.Context, endpoint string, httpClient *http.Client) bool {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = defaultGCEMetadataIdentityEndpoint
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 1500 * time.Millisecond}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	probeURL := fmt.Sprintf("%s://%s/computeMetadata/v1/instance/service-accounts/default/email", u.Scheme, u.Host)
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode == http.StatusOK && strings.EqualFold(resp.Header.Get("Metadata-Flavor"), "Google")
}

// TokenSourceConfig configures how sam-node resolves its platform/OIDC JWT source.
type TokenSourceConfig struct {
	Node             *SamNode
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	JWTPath          string
	CloudProvider    string
	Audience         string
	MetadataEndpoint string
	HTTPClient       *http.Client
}

// ResolveTokenSource selects the TokenSource for enrollment and renewal based
// on the node's configuration. The returned continuousRefresh boolean is true
// when the source is a non-interactive workload credential (--jwt-path,
// --oidc-issuer, or GCP metadata) that should also be presented on every
// POST /refresh call via TokenRefreshRequest.jwt.
func ResolveTokenSource(ctx context.Context, cfg TokenSourceConfig) (TokenSource, bool, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.CloudProvider))
	if provider != "" && provider != "gcp" && provider != "auto" {
		return nil, false, fmt.Errorf("unsupported --cloud-provider %q (supported values: gcp, auto)", cfg.CloudProvider)
	}
	if strings.TrimSpace(cfg.JWTPath) != "" {
		return NewFileTokenSource(cfg.JWTPath), true, nil
	}
	if strings.TrimSpace(cfg.IssuerURL) != "" {
		return NewClientCredentialsTokenSource(cfg.Node, cfg.IssuerURL, cfg.ClientID, cfg.ClientSecret), true, nil
	}
	if provider == "gcp" {
		return NewGCPMetadataTokenSource(cfg.Audience, cfg.MetadataEndpoint, cfg.HTTPClient), true, nil
	}
	if provider == "auto" && ProbeGCPMetadata(ctx, cfg.MetadataEndpoint, cfg.HTTPClient) {
		return NewGCPMetadataTokenSource(cfg.Audience, cfg.MetadataEndpoint, cfg.HTTPClient), true, nil
	}
	return NewRefreshTokenSource(cfg.Node, cfg.ClientSecret), false, nil
}
