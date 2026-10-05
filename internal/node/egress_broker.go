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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/google/sam/api"
)

const (
	defaultGoogleSTSEndpoint            = "https://sts.googleapis.com/v1/token"
	defaultGoogleIAMCredentialsEndpoint = "https://iamcredentials.googleapis.com"
	defaultAWSSTSEndpoint               = "https://sts.amazonaws.com/"
	defaultGCEMetadataTokenEndpoint     = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	maxAWSSessionPolicyBytes            = 2048
)

// CloudTokenExchanger translates a verified SAM principal and its intersected
// TaskAuthorizationRule chain into a downscoped upstream credential.
type CloudTokenExchanger interface {
	Exchange(ctx context.Context, principal string, rules []*api.TaskAuthorizationRule) (bearerToken string, expiry time.Time, err error)
}

// BorderJWTMintFunc mints an outbound ES256 border JWT from the Control Plane
// (or a test double) for a destination and audience.
type BorderJWTMintFunc func(ctx context.Context, destination, audience string) (jwt string, expiry time.Time, err error)

type cachedBrokerToken struct {
	token  string
	expiry time.Time
}

// StaticSecretExchanger reads a static secret file from the node's secrets
// directory. A TaskAuthorizationRule cannot alter or replace a static secret.
type StaticSecretExchanger struct {
	secretsDir string
	secretName string
}

// NewStaticSecretExchanger constructs a StaticSecretExchanger for secretName in secretsDir.
func NewStaticSecretExchanger(secretsDir, secretName string) *StaticSecretExchanger {
	return &StaticSecretExchanger{
		secretsDir: secretsDir,
		secretName: secretName,
	}
}

// Exchange reads the secret from disk per request so platform secret rotations apply immediately.
func (e *StaticSecretExchanger) Exchange(_ context.Context, _ string, _ []*api.TaskAuthorizationRule) (string, time.Time, error) {
	if e.secretName == "" {
		return "", time.Time{}, nil
	}
	data, err := os.ReadFile(filepath.Join(e.secretsDir, e.secretName))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("credential %q: %w (put the file in %s)", e.secretName, errors.Unwrap(err), e.secretsDir)
	}
	cred := strings.TrimSpace(string(data))
	if cred == "" {
		return "", time.Time{}, fmt.Errorf("credential %q is empty", e.secretName)
	}
	return cred, time.Time{}, nil
}

// OIDCFederationExchanger exchanges a Control-Plane-issued ES256 JWT at a cloud
// or third-party RFC 8693 STS endpoint (e.g. Google Workload/Workforce Identity
// Federation or generic OAuth 2.0 token exchange), with optional Google Service
// Account impersonation and scope narrowing from the TAR chain.
type OIDCFederationExchanger struct {
	destName               string
	cfg                    *api.OIDCFederation
	mintJWT                BorderJWTMintFunc
	httpClient             *http.Client
	iamCredentialsEndpoint string

	mu    sync.Mutex
	cache *lru.Cache[string, cachedBrokerToken]
}

// NewOIDCFederationExchanger constructs an OIDCFederationExchanger for destName.
func NewOIDCFederationExchanger(destName string, cfg *api.OIDCFederation, mintJWT BorderJWTMintFunc, httpClient *http.Client) *OIDCFederationExchanger {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	cache, _ := lru.New[string, cachedBrokerToken](512)
	return &OIDCFederationExchanger{
		destName:               destName,
		cfg:                    cfg,
		mintJWT:                mintJWT,
		httpClient:             httpClient,
		iamCredentialsEndpoint: defaultGoogleIAMCredentialsEndpoint,
		cache:                  cache,
	}
}

// Exchange mints a border JWT and exchanges it at the configured STS endpoint,
// narrowing scopes by the TAR chain while never selecting a broker, audience,
// service account, or scope outside the destination policy.
func (e *OIDCFederationExchanger) Exchange(ctx context.Context, principal string, rules []*api.TaskAuthorizationRule) (string, time.Time, error) {
	if e.cfg == nil {
		return "", time.Time{}, errors.New("oidc_federation config is nil")
	}
	audience := strings.TrimSpace(e.cfg.GetAudience())
	if audience == "" {
		return "", time.Time{}, errors.New("oidc_federation.audience is required")
	}
	tokenEndpoint := strings.TrimSpace(e.cfg.GetTokenEndpoint())
	if tokenEndpoint == "" {
		tokenEndpoint = defaultGoogleSTSEndpoint
	}

	scopes, err := NarrowOIDCScopes(e.cfg.GetScopes(), e.destName, rules)
	if err != nil {
		return "", time.Time{}, err
	}
	_, resources, err := IntersectTaskPermissionsAndResources(e.destName, rules)
	if err != nil {
		return "", time.Time{}, err
	}

	cacheKey := brokerCacheKey(ctx, e.destName, principal, audience, e.cfg.GetImpersonate(), scopes, resources, rules)
	if e.cache != nil {
		e.mu.Lock()
		cached, ok := e.cache.Get(cacheKey)
		e.mu.Unlock()
		if ok && cached.token != "" && cached.expiry.After(time.Now().Add(10*time.Second)) {
			return cached.token, cached.expiry, nil
		}
	}

	if e.mintJWT == nil {
		return "", time.Time{}, errors.New("border JWT mint function is not configured")
	}
	borderJWT, jwtExpiry, err := e.mintJWT(ctx, e.destName, audience)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint border JWT for %s: %w", e.destName, err)
	}

	form := url.Values{}
	form.Set("grant_type", api.GrantTypeTokenExchange)
	form.Set("subject_token", borderJWT)
	form.Set("subject_token_type", api.TokenTypeJWT)
	form.Set("requested_token_type", api.TokenTypeAccessToken)
	form.Set("audience", audience)
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	for _, res := range resources {
		form.Add("resource", res)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("STS exchange at %s failed: %w", tokenEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read STS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("STS %s returned status %d: %s", tokenEndpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var stsResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &stsResp); err != nil || stsResp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("invalid STS response from %s", tokenEndpoint)
	}

	expiry := time.Now().Add(5 * time.Minute)
	if stsResp.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(stsResp.ExpiresIn) * time.Second)
	}
	if !jwtExpiry.IsZero() && jwtExpiry.Before(expiry) {
		expiry = jwtExpiry
	}

	finalToken := stsResp.AccessToken
	if sa := strings.TrimSpace(e.cfg.GetImpersonate()); sa != "" {
		impToken, impExpiry, err := e.impersonateServiceAccount(ctx, finalToken, sa, scopes)
		if err != nil {
			return "", time.Time{}, err
		}
		finalToken = impToken
		if !impExpiry.IsZero() && impExpiry.Before(expiry) {
			expiry = impExpiry
		}
	}

	if e.cache != nil {
		e.mu.Lock()
		e.cache.Add(cacheKey, cachedBrokerToken{token: finalToken, expiry: expiry})
		e.mu.Unlock()
	}
	return finalToken, expiry, nil
}

func (e *OIDCFederationExchanger) impersonateServiceAccount(ctx context.Context, federatedToken, serviceAccount string, scopes []string) (string, time.Time, error) {
	base := strings.TrimRight(e.iamCredentialsEndpoint, "/")
	if base == "" {
		base = defaultGoogleIAMCredentialsEndpoint
	}
	impURL := fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateAccessToken", base, url.PathEscape(serviceAccount))
	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}
	payload, err := json.Marshal(map[string]any{
		"scope":    scopes,
		"lifetime": "300s",
	})
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, impURL, bytes.NewReader(payload))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+federatedToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("service account impersonation failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes))
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("service account impersonation returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var impResp struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.Unmarshal(body, &impResp); err != nil || impResp.AccessToken == "" {
		return "", time.Time{}, errors.New("invalid generateAccessToken response")
	}
	var expiry time.Time
	if impResp.ExpireTime != "" {
		expiry, _ = time.Parse(time.RFC3339, impResp.ExpireTime)
	}
	return impResp.AccessToken, expiry, nil
}

// AWSAssumeRoleExchanger exchanges a Control-Plane-issued ES256 JWT at AWS STS
// AssumeRoleWithWebIdentity, compiling the intersected TAR chain into an inline
// IAM session policy intersected with the destination's session_policy template.
type AWSAssumeRoleExchanger struct {
	destName    string
	cfg         *api.AWSAssumeRole
	mintJWT     BorderJWTMintFunc
	httpClient  *http.Client
	stsEndpoint string

	mu    sync.Mutex
	cache *lru.Cache[string, cachedBrokerToken]
}

// NewAWSAssumeRoleExchanger constructs an AWSAssumeRoleExchanger for destName.
func NewAWSAssumeRoleExchanger(destName string, cfg *api.AWSAssumeRole, mintJWT BorderJWTMintFunc, httpClient *http.Client) *AWSAssumeRoleExchanger {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	cache, _ := lru.New[string, cachedBrokerToken](512)
	return &AWSAssumeRoleExchanger{
		destName:    destName,
		cfg:         cfg,
		mintJWT:     mintJWT,
		httpClient:  httpClient,
		stsEndpoint: defaultAWSSTSEndpoint,
		cache:       cache,
	}
}

// Exchange compiles the intersected session policy and calls AWS STS AssumeRoleWithWebIdentity.
func (e *AWSAssumeRoleExchanger) Exchange(ctx context.Context, principal string, rules []*api.TaskAuthorizationRule) (string, time.Time, error) {
	if e.cfg == nil || strings.TrimSpace(e.cfg.GetRoleArn()) == "" {
		return "", time.Time{}, errors.New("aws_assume_role.role_arn is required")
	}
	roleARN := strings.TrimSpace(e.cfg.GetRoleArn())

	sessionPolicy, err := CompileAWSSessionPolicy(e.cfg.GetSessionPolicy(), e.destName, rules)
	if err != nil {
		return "", time.Time{}, err
	}

	cacheKey := brokerCacheKey(ctx, e.destName, principal, roleARN, sessionPolicy, nil, nil, rules)
	if e.cache != nil {
		e.mu.Lock()
		cached, ok := e.cache.Get(cacheKey)
		e.mu.Unlock()
		if ok && cached.token != "" && cached.expiry.After(time.Now().Add(10*time.Second)) {
			return cached.token, cached.expiry, nil
		}
	}

	if e.mintJWT == nil {
		return "", time.Time{}, errors.New("border JWT mint function is not configured")
	}
	borderJWT, jwtExpiry, err := e.mintJWT(ctx, e.destName, "sts.amazonaws.com")
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint border JWT for AWS %s: %w", e.destName, err)
	}

	form := url.Values{}
	form.Set("Action", "AssumeRoleWithWebIdentity")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", roleARN)
	form.Set("RoleSessionName", sanitizeAWSSessionName(principal))
	form.Set("WebIdentityToken", borderJWT)
	if sessionPolicy != "" {
		form.Set("Policy", sessionPolicy)
	}

	endpoint := strings.TrimSpace(e.stsEndpoint)
	if endpoint == "" {
		endpoint = defaultAWSSTSEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("AWS STS AssumeRoleWithWebIdentity failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes))
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("AWS STS returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	token, expiry, err := parseAWSAssumeRoleResponse(body)
	if err != nil {
		return "", time.Time{}, err
	}
	if expiry.IsZero() {
		expiry = time.Now().Add(15 * time.Minute)
	}
	if !jwtExpiry.IsZero() && jwtExpiry.Before(expiry) {
		expiry = jwtExpiry
	}

	if e.cache != nil {
		e.mu.Lock()
		e.cache.Add(cacheKey, cachedBrokerToken{token: token, expiry: expiry})
		e.mu.Unlock()
	}
	return token, expiry, nil
}

func sanitizeAWSSessionName(principal string) string {
	if principal == "" {
		return "sam-session"
	}
	var b strings.Builder
	for _, r := range principal {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '=' || r == ',' || r == '.' || r == '@' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() < 2 {
		return "sam-session"
	}
	return b.String()
}

func parseAWSAssumeRoleResponse(body []byte) (string, time.Time, error) {
	var jsonResp struct {
		AssumeRoleWithWebIdentityResponse struct {
			AssumeRoleWithWebIdentityResult struct {
				Credentials struct {
					AccessKeyID     string `json:"AccessKeyId"`
					SecretAccessKey string `json:"SecretAccessKey"`
					SessionToken    string `json:"SessionToken"`
					Expiration      any    `json:"Expiration"`
				} `json:"Credentials"`
			} `json:"AssumeRoleWithWebIdentityResult"`
		} `json:"AssumeRoleWithWebIdentityResponse"`
		SessionToken string `json:"SessionToken"`
		AccessToken  string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &jsonResp); err == nil {
		creds := jsonResp.AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.Credentials
		if creds.SessionToken != "" {
			var exp time.Time
			switch v := creds.Expiration.(type) {
			case string:
				exp, _ = time.Parse(time.RFC3339, v)
			case float64:
				exp = time.Unix(int64(v), 0)
			}
			return creds.SessionToken, exp, nil
		}
		if jsonResp.SessionToken != "" {
			return jsonResp.SessionToken, time.Time{}, nil
		}
		if jsonResp.AccessToken != "" {
			return jsonResp.AccessToken, time.Time{}, nil
		}
	}

	var xmlResp struct {
		XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
		Result  struct {
			Credentials struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
				SessionToken    string `xml:"SessionToken"`
				Expiration      string `xml:"Expiration"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleWithWebIdentityResult"`
	}
	if err := xml.Unmarshal(body, &xmlResp); err == nil && xmlResp.Result.Credentials.SessionToken != "" {
		exp, _ := time.Parse(time.RFC3339, strings.TrimSpace(xmlResp.Result.Credentials.Expiration))
		return strings.TrimSpace(xmlResp.Result.Credentials.SessionToken), exp, nil
	}
	return "", time.Time{}, errors.New("unable to parse AWS AssumeRoleWithWebIdentity response")
}

// PlatformIdentityExchanger fetches an access token from the node's own cloud
// metadata server (e.g. GKE Workload Identity / GCE instance metadata).
type PlatformIdentityExchanger struct {
	destName         string
	cfg              *api.PlatformIdentity
	httpClient       *http.Client
	metadataEndpoint string
}

// NewPlatformIdentityExchanger constructs a PlatformIdentityExchanger.
func NewPlatformIdentityExchanger(destName string, cfg *api.PlatformIdentity, httpClient *http.Client) *PlatformIdentityExchanger {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &PlatformIdentityExchanger{
		destName:         destName,
		cfg:              cfg,
		httpClient:       httpClient,
		metadataEndpoint: defaultGCEMetadataTokenEndpoint,
	}
}

// Exchange queries the platform metadata server with scopes narrowed by the TAR chain.
func (e *PlatformIdentityExchanger) Exchange(ctx context.Context, _ string, rules []*api.TaskAuthorizationRule) (string, time.Time, error) {
	var policyScopes []string
	if e.cfg != nil {
		policyScopes = e.cfg.GetScopes()
	}
	scopes, err := NarrowOIDCScopes(policyScopes, e.destName, rules)
	if err != nil {
		return "", time.Time{}, err
	}
	endpoint := strings.TrimSpace(e.metadataEndpoint)
	if endpoint == "" {
		endpoint = defaultGCEMetadataTokenEndpoint
	}
	if len(scopes) > 0 {
		u, err := url.Parse(endpoint)
		if err == nil {
			q := u.Query()
			q.Set("scopes", strings.Join(scopes, ","))
			u.RawQuery = q.Encode()
			endpoint = u.String()
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("platform metadata request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes))
	if err != nil {
		return "", time.Time{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("platform metadata returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tokResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokResp); err != nil || tokResp.AccessToken == "" {
		return "", time.Time{}, errors.New("invalid platform metadata token response")
	}
	expiry := time.Now().Add(5 * time.Minute)
	if tokResp.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)
	}
	return tokResp.AccessToken, expiry, nil
}

// NarrowOIDCScopes computes the intersection of policyScopes with any OAuth
// scope constraints carried in the TaskAuthorizationRule chain for destName.
// It enforces the "TAR narrows, never selects" invariant:
//   - A TAR can shrink policyScopes to a subset.
//   - A TAR can never add a scope that is not in policyScopes.
//   - If a TAR specifies scope constraints that have an empty intersection with
//     policyScopes, NarrowOIDCScopes returns an error so the exchange fails closed.
func NarrowOIDCScopes(policyScopes []string, destName string, rules []*api.TaskAuthorizationRule) ([]string, error) {
	if len(policyScopes) == 0 {
		// Policy grants no OAuth scopes; a TAR can never select or add scopes.
		return nil, nil
	}
	current := slices.Clone(policyScopes)
	targetSvc := api.EgressServicePrefix + api.NormalizeMeshHost(strings.TrimPrefix(destName, api.EgressServicePrefix))

	for _, tar := range rules {
		if tar == nil {
			continue
		}
		var tarPerms []string
		for _, r := range tar.GetRules() {
			if !taskRuleMatchesService(r, targetSvc) {
				continue
			}
			for _, p := range r.GetOperation().GetAllowedPermissions() {
				p = strings.TrimSpace(p)
				if p != "" {
					tarPerms = append(tarPerms, p)
				}
			}
		}
		if len(tarPerms) == 0 {
			continue
		}
		// Distinguish fine-grained cloud IAM permissions (e.g.
		// "bigquery.googleapis.com/tables.getData") from OAuth scopes (e.g.
		// "https://www.googleapis.com/auth/bigquery.readonly" or "read:orders").
		// If every entry is a non-URL cloud IAM permission (host/resource.verb)
		// and none matches policyScopes, the TAR is constraining IAM permissions
		// rather than OAuth scopes; otherwise intersect with policyScopes.
		hasScopeCandidate := false
		for _, p := range tarPerms {
			if isOAuthScopeCandidate(p, policyScopes) {
				hasScopeCandidate = true
				break
			}
		}
		if !hasScopeCandidate {
			continue
		}
		var next []string
		for _, s := range current {
			if matchesAnyWildcard(s, tarPerms) {
				next = append(next, s)
			}
		}
		if len(next) == 0 {
			return nil, fmt.Errorf("task authorization rule %q narrows OAuth scopes to an empty intersection with policy scopes", tar.GetName())
		}
		current = next
	}
	return current, nil
}

func isOAuthScopeCandidate(perm string, policyScopes []string) bool {
	if matchesAnyWildcard(perm, policyScopes) {
		return true
	}
	for _, s := range policyScopes {
		if matchesWildcardPattern(perm, s) {
			return true
		}
	}
	if strings.HasPrefix(perm, "https://") || strings.HasPrefix(perm, "http://") {
		return true
	}
	// Cloud IAM permissions have the form "<service-host>/<resource>.<verb>" (e.g. "bigquery.googleapis.com/tables.getData")
	// whereas AWS actions have "<service>:<Action>" (no slash) and OAuth scopes have no slash or are URLs.
	if strings.Contains(perm, "/") && strings.Contains(perm, ".") {
		return false
	}
	return true
}

// IntersectTaskPermissionsAndResources computes the intersection of
// allowed_permissions and allowed_resources across all TaskAuthorizationRules
// in rules that match egress://<destName>. If two TARs in the chain specify
// disjoint permissions or disjoint resources, an error is returned.
func IntersectTaskPermissionsAndResources(destName string, rules []*api.TaskAuthorizationRule) (perms []string, resources []string, err error) {
	targetSvc := api.EgressServicePrefix + api.NormalizeMeshHost(strings.TrimPrefix(destName, api.EgressServicePrefix))
	hasPerms := false
	hasResources := false

	for _, tar := range rules {
		if tar == nil {
			continue
		}
		var rulePerms []string
		var ruleResources []string
		matchedRule := false
		for _, r := range tar.GetRules() {
			if !taskRuleMatchesService(r, targetSvc) {
				continue
			}
			matchedRule = true
			for _, p := range r.GetOperation().GetAllowedPermissions() {
				if p = strings.TrimSpace(p); p != "" && !slices.Contains(rulePerms, p) {
					rulePerms = append(rulePerms, p)
				}
			}
			for _, res := range r.GetAllowedResources() {
				if res = strings.TrimSpace(res); res != "" && !slices.Contains(ruleResources, res) {
					ruleResources = append(ruleResources, res)
				}
			}
		}
		if !matchedRule {
			return nil, nil, fmt.Errorf("task authorization rule %q does not allow service %s", tar.GetName(), targetSvc)
		}
		if len(rulePerms) > 0 {
			if !hasPerms {
				perms = rulePerms
				hasPerms = true
			} else {
				perms = intersectWildcardSets(perms, rulePerms)
				if len(perms) == 0 {
					return nil, nil, fmt.Errorf("task authorization rule %q has empty allowed_permissions intersection", tar.GetName())
				}
			}
		}
		if len(ruleResources) > 0 {
			if !hasResources {
				resources = ruleResources
				hasResources = true
			} else {
				resources = intersectWildcardSets(resources, ruleResources)
				if len(resources) == 0 {
					return nil, nil, fmt.Errorf("task authorization rule %q has empty allowed_resources intersection", tar.GetName())
				}
			}
		}
	}
	return perms, resources, nil
}

// CompileAWSSessionPolicy compiles an inline AWS IAM session policy JSON from
// the destination's session_policy template intersected with the TAR chain.
// It enforces the "TAR narrows, never selects" invariant: if templateJSON
// defines allowed Actions or Resources, the TAR chain can only narrow them to
// a subset, never add Actions or Resources outside the template.
func CompileAWSSessionPolicy(templateJSON, destName string, rules []*api.TaskAuthorizationRule) (string, error) {
	tarPerms, tarResources, err := IntersectTaskPermissionsAndResources(destName, rules)
	if err != nil {
		return "", err
	}

	var tmplActions []string
	var tmplResources []string
	hasTemplate := strings.TrimSpace(templateJSON) != ""
	if hasTemplate {
		var doc struct {
			Version   string `json:"Version"`
			Statement []struct {
				Effect   string `json:"Effect"`
				Action   any    `json:"Action"`
				Resource any    `json:"Resource"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(templateJSON), &doc); err != nil {
			return "", fmt.Errorf("invalid aws_assume_role.session_policy JSON: %w", err)
		}
		for _, st := range doc.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			tmplActions = append(tmplActions, stringOrSlice(st.Action)...)
			tmplResources = append(tmplResources, stringOrSlice(st.Resource)...)
		}
	}

	var actions []string
	switch {
	case hasTemplate && len(tarPerms) > 0:
		actions = intersectWildcardSets(tmplActions, tarPerms)
		if len(actions) == 0 {
			return "", errors.New("task allowed_permissions have empty intersection with AWS session_policy template Actions")
		}
	case hasTemplate:
		actions = tmplActions
	case len(tarPerms) > 0:
		actions = tarPerms
	}

	var resources []string
	switch {
	case hasTemplate && len(tarResources) > 0:
		resources = intersectWildcardSets(tmplResources, tarResources)
		if len(resources) == 0 {
			return "", errors.New("task allowed_resources have empty intersection with AWS session_policy template Resources")
		}
	case hasTemplate:
		resources = tmplResources
	case len(tarResources) > 0:
		resources = tarResources
	}

	if len(actions) == 0 && len(resources) == 0 {
		return "", nil
	}
	if len(actions) == 0 {
		actions = []string{"*"}
	}
	if len(resources) == 0 {
		resources = []string{"*"}
	}

	policyDoc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{
			{
				"Effect":   "Allow",
				"Action":   actions,
				"Resource": resources,
			},
		},
	}
	encoded, err := json.Marshal(policyDoc)
	if err != nil {
		return "", err
	}
	if len(encoded) > maxAWSSessionPolicyBytes {
		return "", fmt.Errorf("compiled AWS session policy (%d bytes) exceeds %d byte limit", len(encoded), maxAWSSessionPolicyBytes)
	}
	return string(encoded), nil
}

func stringOrSlice(v any) []string {
	switch val := v.(type) {
	case string:
		if strings.TrimSpace(val) != "" {
			return []string{strings.TrimSpace(val)}
		}
	case []any:
		var out []string
		for _, item := range val {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case []string:
		return val
	}
	return nil
}

func taskRuleMatchesService(r *api.TaskRule, targetSvc string) bool {
	if r == nil || len(r.GetAllowedServices()) == 0 {
		return true
	}
	return matchesAnyWildcard(targetSvc, r.GetAllowedServices())
}

func matchesAnyWildcard(val string, patterns []string) bool {
	for _, pat := range patterns {
		if matchesWildcardPattern(pat, val) {
			return true
		}
	}
	return false
}

func matchesWildcardPattern(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == "*" || pattern == value {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(value, prefix)
	}
	return false
}

// intersectWildcardSets computes the logical intersection of two sets of exact
// or prefix-wildcard strings (e.g. ["s3:*"] ∩ ["s3:GetObject"] = ["s3:GetObject"],
// and ["//bq/datasets/sales/*"] ∩ ["//bq/datasets/sales/tables/q1"] = ["//bq/datasets/sales/tables/q1"]).
func intersectWildcardSets(a, b []string) []string {
	var out []string
	addUnique := func(s string) {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for _, x := range a {
		for _, y := range b {
			switch {
			case matchesWildcardPattern(x, y):
				addUnique(y)
			case matchesWildcardPattern(y, x):
				addUnique(x)
			}
		}
	}
	return out
}

func brokerCacheKey(ctx context.Context, destName, principal, targetID, extra string, scopes, resources []string, rules []*api.TaskAuthorizationRule) string {
	h := sha256.New()
	if b := CallerBiscuitFromContext(ctx); len(b) > 0 {
		_, _ = h.Write(b)
	} else {
		_, _ = h.Write([]byte(principal))
		for _, r := range rules {
			if r != nil {
				_, _ = h.Write([]byte(r.GetName()))
			}
		}
	}
	_, _ = h.Write([]byte("|" + destName + "|" + targetID + "|" + extra + "|" + strings.Join(scopes, ",") + "|" + strings.Join(resources, ",")))
	return hex.EncodeToString(h.Sum(nil))
}
