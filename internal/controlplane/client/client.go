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
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"google.golang.org/protobuf/proto"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/version"
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

// StatusError is a control plane answer other than success, with the status
// code a caller can act on (a 401 on an authenticated endpoint says the
// control plane does not know this node any more) and the body it sent.
type StatusError struct {
	Code   int
	Status string
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("control plane returned status %s: %s", e.Status, e.Body)
}

func newStatusError(resp *http.Response, body []byte) *StatusError {
	return &StatusError{Code: resp.StatusCode, Status: resp.Status, Body: strings.TrimSpace(string(body))}
}

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

// SetChallengeHeaders signs payload with priv and sets HeaderChallengeTimestamp
// and HeaderChallengeSignature on req.
func SetChallengeHeaders(req *http.Request, priv crypto.PrivKey, payload []byte, ts int64) error {
	sig, err := priv.Sign(payload)
	if err != nil {
		return fmt.Errorf("failed to sign challenge: %w", err)
	}
	req.Header.Set(api.HeaderChallengeTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(api.HeaderChallengeSignature, base64.RawURLEncoding.EncodeToString(sig))
	return nil
}

// DoWithChallenge executes a request built with the local clock's millisecond
// timestamp. If the control plane answers 401 with
// api.ErrStaleChallengeTimestampMessage and a valid HTTP Date header, it
// recomputes the timestamp from Date and retries once. No other 401 is retried.
func DoWithChallenge(httpClient *http.Client, now func() time.Time, build func(ts int64) (*http.Request, error)) (*http.Response, error) {
	if now == nil {
		now = time.Now
	}
	req, err := build(now().UnixMilli())
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	body, readErr := ReadBody(resp.Body)
	_ = resp.Body.Close()
	if readErr == nil && strings.Contains(string(body), api.ErrStaleChallengeTimestampMessage) {
		if dateHdr := resp.Header.Get("Date"); dateHdr != "" {
			if serverTime, parseErr := http.ParseTime(dateHdr); parseErr == nil {
				retryReq, buildErr := build(serverTime.UnixMilli())
				if buildErr != nil {
					return nil, buildErr
				}
				return httpClient.Do(retryReq)
			}
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
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
	peerID  string
	priv    crypto.PrivKey
	now     func() time.Time
}

// New normalizes baseURL, https:// when no scheme is given and no trailing
// slash via api.NormalizeControlPlaneURL, and speaks through httpClient, which the
// caller builds with NewHTTPClient so its own transport policy applies.
func New(baseURL string, httpClient *http.Client) *Client {
	return &Client{baseURL: api.NormalizeControlPlaneURL(baseURL), http: httpClient, now: time.Now}
}

// WithIdentity configures the peer ID and private key used to sign
// proof-of-possession challenges on authenticated requests.
func (c *Client) WithIdentity(peerID string, priv crypto.PrivKey) *Client {
	c.peerID = peerID
	c.priv = priv
	return c
}

// WithClock overrides the clock used for challenge timestamps.
func (c *Client) WithClock(now func() time.Time) *Client {
	if now != nil {
		c.now = now
	}
	return c
}

// FetchInfo is GET /info: the router addresses, the ban set and the OIDC
// details a node needs to enroll.
func (c *Client) FetchInfo(ctx context.Context) (*api.ControlPlaneInfoResponse, error) {
	var info api.ControlPlaneInfoResponse
	if err := c.get(ctx, "/info", nil, nil, &info); err != nil {
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
	if err := c.get(ctx, "/keys", nil, nil, &resp); err != nil {
		return nil, err
	}
	keys, err := api.VerifyKeysResponse(&resp, trusted, time.Now())
	if err != nil {
		return nil, fmt.Errorf("/keys response rejected: %w", err)
	}
	return keys, nil
}

// FetchPolicy is GET /policies, authenticated with the caller's biscuit and
// signed challenge: the mesh policy as the Datalog rules a member adds to its
// authorizer.
func (c *Client) FetchPolicy(ctx context.Context, biscuit []byte) (*api.PolicyConfigGetResponse, error) {
	var policy api.PolicyConfigGetResponse
	if err := c.get(ctx, "/policies", biscuit, api.PoliciesChallenge, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// FetchEgress is GET /egress, authenticated with the caller's biscuit and
// signed challenge: the egress destinations the control plane assigned to this
// node.
func (c *Client) FetchEgress(ctx context.Context, biscuit []byte) (*api.EgressAssignmentsResponse, error) {
	var egress api.EgressAssignmentsResponse
	if err := c.get(ctx, "/egress", biscuit, api.EgressChallenge, &egress); err != nil {
		return nil, err
	}
	return &egress, nil
}

// FetchRevocations is GET /revocations, authenticated with the caller's
// biscuit and signed challenge: the revoked Biscuit IDs and banned peer IDs
// currently tracked by the control plane.
func (c *Client) FetchRevocations(ctx context.Context, biscuit []byte) (*api.RevocationsResponse, error) {
	var revocations api.RevocationsResponse
	if err := c.get(ctx, "/revocations", biscuit, api.RevocationsChallenge, &revocations); err != nil {
		return nil, err
	}
	return &revocations, nil
}

// ReportCatalog is POST /nodes/catalog, authenticated with the calling node's
// biscuit and signed challenge: reports the services currently registered on
// the node.
func (c *Client) ReportCatalog(ctx context.Context, biscuit []byte, services []*api.ServiceInfo) error {
	payload, err := proto.Marshal(&api.NodeCatalogReport{Services: services})
	if err != nil {
		return fmt.Errorf("failed to encode catalog report: %w", err)
	}
	resp, err := DoWithChallenge(c.http, c.now, func(ts int64) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/nodes/catalog", bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		if len(biscuit) > 0 {
			req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(biscuit))
		}
		if c.priv != nil && c.peerID != "" {
			if err := SetChallengeHeaders(req, c.priv, api.NodesCatalogChallenge(c.peerID, ts), ts); err != nil {
				return nil, err
			}
		}
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := ReadBody(resp.Body)
		return newStatusError(resp, body)
	}
	return nil
}

// ExchangeToken is POST /token/exchange, authenticated with the calling node's
// biscuit: verifies an external OIDC/K8s/SPIFFE JWT and mints a short-lived
// Delegated Session Biscuit bound to the calling node.
func (c *Client) ExchangeToken(ctx context.Context, biscuit []byte, req *api.TokenExchangeRequest) (*api.TokenExchangeResponse, error) {
	var resp api.TokenExchangeResponse
	err := c.postWithChallenge(ctx, "/token/exchange", biscuit, func(ts int64) (proto.Message, error) {
		if c.priv == nil || c.peerID == "" {
			return req, nil
		}
		sig, err := c.priv.Sign(api.TokenExchangeChallenge(c.peerID, ts))
		if err != nil {
			return nil, fmt.Errorf("failed to sign token exchange challenge: %w", err)
		}
		cloned := proto.Clone(req).(*api.TokenExchangeRequest)
		cloned.ChallengeUnixMs = ts
		cloned.ChallengeSignature = sig
		return cloned, nil
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// MintSTSToken is POST /sts/token, authenticated with the egress node's
// biscuit: verifies a caller Biscuit for an egress destination and mints a
// short-lived ES256 JWT for cloud STS federation.
func (c *Client) MintSTSToken(ctx context.Context, biscuit []byte, req *api.STSTokenRequest) (*api.STSTokenResponse, error) {
	var resp api.STSTokenResponse
	err := c.postWithChallenge(ctx, "/sts/token", biscuit, func(ts int64) (proto.Message, error) {
		if c.priv == nil || c.peerID == "" {
			return req, nil
		}
		sig, err := c.priv.Sign(api.STSTokenChallenge(c.peerID, ts))
		if err != nil {
			return nil, fmt.Errorf("failed to sign STS token challenge: %w", err)
		}
		cloned := proto.Clone(req).(*api.STSTokenRequest)
		cloned.ChallengeUnixMs = ts
		cloned.ChallengeSignature = sig
		return cloned, nil
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) get(ctx context.Context, path string, biscuit []byte, challengeFn func(peerID string, ts int64) []byte, msg proto.Message) error {
	resp, err := DoWithChallenge(c.http, c.now, func(ts int64) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}
		if len(biscuit) > 0 {
			req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(biscuit))
		}
		if challengeFn != nil && c.priv != nil && c.peerID != "" {
			if err := SetChallengeHeaders(req, c.priv, challengeFn(c.peerID, ts), ts); err != nil {
				return nil, err
			}
		}
		return req, nil
	})
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
		return newStatusError(resp, body)
	}
	if err := proto.Unmarshal(body, msg); err != nil {
		return fmt.Errorf("failed to decode %s response: %w", path, err)
	}
	return nil
}

func (c *Client) postWithChallenge(ctx context.Context, path string, biscuit []byte, buildMsg func(ts int64) (proto.Message, error), respMsg proto.Message) error {
	resp, err := DoWithChallenge(c.http, c.now, func(ts int64) (*http.Request, error) {
		reqMsg, err := buildMsg(ts)
		if err != nil {
			return nil, err
		}
		payload, err := proto.Marshal(reqMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal %s request: %w", path, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		if len(biscuit) > 0 {
			req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(biscuit))
		}
		return req, nil
	})
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
		return newStatusError(resp, body)
	}
	if err := proto.Unmarshal(body, respMsg); err != nil {
		return fmt.Errorf("failed to decode %s response: %w", path, err)
	}
	return nil
}
