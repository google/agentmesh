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

// Package client is how a mesh component reads from its control plane. Node
// and router share it, so the body cap, the status handling and the signature
// check on /keys are a single code path. It depends on api/ and build metadata:
// importing it pulls in none of the control plane server.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/version"
)

// MaxBodyBytes caps every response body read from a control plane: a
// misbehaving or impersonated server must not be able to make a client
// buffer arbitrary amounts of memory. It is sized for the largest legitimate
// answer, the ban set in /info at roughly 55 bytes per peer ID, so about
// 150k banned peers fit; the policy is bounded by the control plane's own
// 1 MiB cap on POST /policies, and /keys is a few hundred bytes.
const MaxBodyBytes = 8 << 20

// ErrBodyTooLarge marks an answer over MaxBodyBytes. It is an error, never a
// prefix: a protobuf message cut at a field boundary still decodes, so a
// truncated ban set or router list would be read as a smaller, valid one.
var ErrBodyTooLarge = errors.New("control plane answer exceeds the body cap")

// ErrNotFound marks a 404: the control plane does not serve the endpoint, as
// one predating it does not. Callers of an endpoint added after the first
// release check for it, so a newer node works against an older control plane.
var ErrNotFound = errors.New("control plane does not serve this endpoint")

// ReadBody reads a control plane response body of at most MaxBodyBytes and
// reports ErrBodyTooLarge for anything larger.
func ReadBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if len(body) > MaxBodyBytes {
		return nil, fmt.Errorf("%w (%d bytes)", ErrBodyTooLarge, MaxBodyBytes)
	}
	return body, nil
}

// transport applies api.ValidateControlPlaneTransport to every request,
// redirects included, so a plaintext hop is refused wherever the URL came
// from. allowInsecure is read per request: the node learns the operator's
// choice after its clients exist.
type transport struct {
	allowInsecure func() bool
	userAgent     string
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := api.ValidateControlPlaneTransport(req.URL.String(), t.allowInsecure()); err != nil {
		return nil, err
	}
	cloned := req.Clone(req.Context())
	cloned.Header.Set("User-Agent", t.userAgent)
	return http.DefaultTransport.RoundTrip(cloned)
}

// NewHTTPClient is the HTTP client for every request a mesh component makes
// to its control plane. A nil allowInsecure never allows plaintext.
func NewHTTPClient(timeout time.Duration, allowInsecure func() bool, component string) *http.Client {
	if allowInsecure == nil {
		allowInsecure = func() bool { return false }
	}
	return &http.Client{Timeout: timeout, Transport: transport{allowInsecure: allowInsecure, userAgent: component + "/" + version.String()}}
}

// Client reads the pull side of the mesh protocol from one control plane.
type Client struct {
	baseURL string
	http    *http.Client
}

// New normalizes baseURL, https:// when no scheme is given and no trailing
// slash, and speaks through httpClient, which the caller builds with
// NewHTTPClient so its own transport policy applies.
func New(baseURL string, httpClient *http.Client) *Client {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	return &Client{baseURL: strings.TrimSuffix(baseURL, "/"), http: httpClient}
}

// FetchInfo is GET /info: the router addresses, the ban set and the OIDC
// details a node needs to enroll.
func (c *Client) FetchInfo(ctx context.Context) (*api.ControlPlaneInfoResponse, error) {
	var info api.ControlPlaneInfoResponse
	if err := c.get(ctx, "/info", nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// FetchKeys is GET /keys: the control plane's currently valid signing keys.
// The set is accepted only if signed by a key in trusted
// (api.VerifyKeysResponse): whoever answers the URL must already be the
// control plane, not become it.
func (c *Client) FetchKeys(ctx context.Context, trusted []ed25519.PublicKey) ([]ed25519.PublicKey, error) {
	var resp api.KeysResponse
	if err := c.get(ctx, "/keys", nil, &resp); err != nil {
		return nil, err
	}
	keys, err := api.VerifyKeysResponse(&resp, trusted, time.Now())
	if err != nil {
		return nil, fmt.Errorf("/keys response rejected: %w", err)
	}
	return keys, nil
}

// FetchPolicy is GET /policies, authenticated with the caller's biscuit: the
// mesh policy as the Datalog rules a member adds to its authorizer.
func (c *Client) FetchPolicy(ctx context.Context, biscuit []byte) (*api.PolicyConfigGetResponse, error) {
	var policy api.PolicyConfigGetResponse
	if err := c.get(ctx, "/policies", biscuit, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// FetchEgress is GET /egress, authenticated with the caller's biscuit: the
// egress destinations the control plane assigned to this node.
func (c *Client) FetchEgress(ctx context.Context, biscuit []byte) (*api.EgressAssignmentsResponse, error) {
	var egress api.EgressAssignmentsResponse
	if err := c.get(ctx, "/egress", biscuit, &egress); err != nil {
		return nil, err
	}
	return &egress, nil
}

// FetchRevocations is GET /revocations, authenticated with the caller's biscuit:
// the revoked Biscuit IDs and banned peer IDs currently tracked by the control plane.
func (c *Client) FetchRevocations(ctx context.Context, biscuit []byte) (*api.RevocationsResponse, error) {
	var revocations api.RevocationsResponse
	if err := c.get(ctx, "/revocations", biscuit, &revocations); err != nil {
		return nil, err
	}
	return &revocations, nil
}

// ExchangeToken is POST /token/exchange, authenticated with the calling node's
// biscuit: verifies an external OIDC/K8s/SPIFFE JWT and mints a short-lived
// Delegated Session Biscuit bound to the calling node.
func (c *Client) ExchangeToken(ctx context.Context, biscuit []byte, req *api.TokenExchangeRequest) (*api.TokenExchangeResponse, error) {
	var resp api.TokenExchangeResponse
	if err := c.post(ctx, "/token/exchange", biscuit, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// MintSTSToken is POST /sts/token, authenticated with the egress node's
// biscuit: verifies a caller Biscuit for an egress destination and mints a
// short-lived ES256 JWT for cloud STS federation.
func (c *Client) MintSTSToken(ctx context.Context, biscuit []byte, req *api.STSTokenRequest) (*api.STSTokenResponse, error) {
	var resp api.STSTokenResponse
	if err := c.post(ctx, "/sts/token", biscuit, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) get(ctx context.Context, path string, biscuit []byte, msg proto.Message) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	if len(biscuit) > 0 {
		req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(biscuit))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane returned status %s: %s", resp.Status, string(body))
	}
	if err := proto.Unmarshal(body, msg); err != nil {
		return fmt.Errorf("failed to decode %s response: %w", path, err)
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, biscuit []byte, reqMsg, respMsg proto.Message) error {
	payload, err := proto.Marshal(reqMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal %s request: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	if len(biscuit) > 0 {
		req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(biscuit))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control plane returned status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if err := proto.Unmarshal(body, respMsg); err != nil {
		return fmt.Errorf("failed to decode %s response: %w", path, err)
	}
	return nil
}
