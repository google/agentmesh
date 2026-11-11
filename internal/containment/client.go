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

package containment

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/secrets"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CloudEvents and HTTP header constants.
const (
	HeaderCESpecVersion      = "ce-specversion"
	HeaderCEID               = "ce-id"
	HeaderCEType             = "ce-type"
	HeaderCESource           = "ce-source"
	HeaderCETime             = "ce-time"
	HeaderCESubject          = "ce-subject"
	HeaderContentType        = "Content-Type"
	HeaderUserAgent          = "User-Agent"
	HeaderAgentMeshTimestamp = "X-AgentMesh-Timestamp"
	HeaderAgentMeshSignature = "X-AgentMesh-Signature"

	ContentTypeJSON  = "application/json"
	DefaultUserAgent = "agentmesh-containment/1.0"
	MaxResponseBytes = 4096
)

// Client handles network delivery of security signals.
type Client interface {
	Send(ctx context.Context, event *api.SecuritySignalEvent) error
	Deliver(ctx context.Context, event *api.SecuritySignalEvent) error
	Close() error
}

// ClientConfig is an alias for EndpointConfig for backwards compatibility.
type ClientConfig = EndpointConfig

type singleClient struct {
	cfg          EndpointConfig
	httpClient   *http.Client
	requestURL   string
	isUnixSocket bool
	socketPath   string
	eventFilter  map[string]bool
	hasHMAC      bool
	hmacSecret   []byte
}

type multiClient struct {
	clients []Client
}

// NewClient creates a Client configured for one or more target endpoints.
func NewClient(endpoints ...EndpointConfig) (Client, error) {
	if len(endpoints) == 0 {
		return &multiClient{}, nil
	}

	var clients []Client
	for _, ep := range endpoints {
		if ep.URL == "" {
			continue
		}
		c, err := NewSingleClient(ep)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}

	if len(clients) == 1 {
		return clients[0], nil
	}
	return &multiClient{clients: clients}, nil
}

// NewSingleClient creates a Client for a single target endpoint.
func NewSingleClient(cfg EndpointConfig) (Client, error) {
	rawTarget := strings.TrimSpace(cfg.URL)
	if rawTarget == "" {
		return nil, errors.New("containment: target URL is required")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	c := &singleClient{
		cfg:     cfg,
		hasHMAC: false,
	}

	// 1. Resolve HMAC secret (direct bytes or file path)
	if len(cfg.HMACSecret) > 0 {
		c.hmacSecret = append([]byte(nil), cfg.HMACSecret...)
		c.hasHMAC = true
	} else if cfg.HMACSecretPath != "" {
		secretStr, err := secrets.FromPathOrEnv("containment-hmac-secret", cfg.HMACSecretPath, "AGENTMESH_CONTAINMENT_HMAC_SECRET")
		if err != nil {
			return nil, fmt.Errorf("containment: read hmac_secret_path %q: %w", cfg.HMACSecretPath, err)
		}
		if secretStr != "" {
			c.hmacSecret = []byte(secretStr)
			c.hasHMAC = true
		}
	}

	// 2. Setup event type filter
	if len(cfg.EventTypes) > 0 {
		c.eventFilter = make(map[string]bool, len(cfg.EventTypes))
		for _, et := range cfg.EventTypes {
			if trimmed := strings.TrimSpace(et); trimmed != "" {
				c.eventFilter[trimmed] = true
			}
		}
	}

	// 3. Configure transport based on scheme
	switch {
	case strings.HasPrefix(rawTarget, "unix:"):
		sockPath := strings.TrimPrefix(rawTarget, "unix:")
		sockPath = strings.TrimPrefix(sockPath, "//")
		if sockPath == "" {
			return nil, fmt.Errorf("containment: unix socket target %q contains empty path", rawTarget)
		}

		c.isUnixSocket = true
		c.socketPath = sockPath
		c.requestURL = "http://unix/events"

		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
			DisableKeepAlives: false,
			MaxIdleConns:      10,
			IdleConnTimeout:   90 * time.Second,
		}
		c.httpClient = &http.Client{
			Transport: tr,
			Timeout:   timeout,
		}

	case strings.HasPrefix(rawTarget, "https://"):
		u, err := url.Parse(rawTarget)
		if err != nil {
			return nil, fmt.Errorf("containment: invalid https target %q: %w", rawTarget, err)
		}
		c.requestURL = u.String()

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if cfg.CACertPath != "" {
			caBytes, err := os.ReadFile(cfg.CACertPath)
			if err != nil {
				return nil, fmt.Errorf("containment: read ca_cert_path %q: %w", cfg.CACertPath, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caBytes) {
				return nil, fmt.Errorf("containment: ca_cert_path %q contains no valid PEM certificates", cfg.CACertPath)
			}
			tlsConfig.RootCAs = pool
		}

		if cfg.ClientCertPath != "" || cfg.ClientKeyPath != "" {
			if cfg.ClientCertPath == "" || cfg.ClientKeyPath == "" {
				return nil, errors.New("containment: client_cert_path and client_key_path must both be provided for mTLS")
			}
			cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
			if err != nil {
				return nil, fmt.Errorf("containment: load mTLS client keypair (%s, %s): %w", cfg.ClientCertPath, cfg.ClientKeyPath, err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		if cfg.InsecureSkipTLS {
			tlsConfig.InsecureSkipVerify = true
		}

		tr := &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			MaxIdleConns:    10,
			IdleConnTimeout: 90 * time.Second,
		}
		c.httpClient = &http.Client{
			Transport: tr,
			Timeout:   timeout,
		}

	case strings.HasPrefix(rawTarget, "http://"):
		u, err := url.Parse(rawTarget)
		if err != nil {
			return nil, fmt.Errorf("containment: invalid http target %q: %w", rawTarget, err)
		}
		host := u.Hostname()
		ip := net.ParseIP(host)
		isLoopback := (ip != nil && ip.IsLoopback()) || strings.EqualFold(host, "localhost")
		if !isLoopback {
			return nil, fmt.Errorf("containment: insecure http scheme only permitted for loopback targets (127.0.0.1, localhost, ::1); got %q", rawTarget)
		}
		c.requestURL = u.String()

		tr := &http.Transport{
			DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			MaxIdleConns:    10,
			IdleConnTimeout: 90 * time.Second,
		}
		c.httpClient = &http.Client{
			Transport: tr,
			Timeout:   timeout,
		}

	default:
		return nil, fmt.Errorf("containment: unsupported scheme in URL %q: must start with https://, http://127.0.0.1, or unix:", rawTarget)
	}

	return c, nil
}

// NewClientFromProto constructs a Client directly from protobuf WebhookEndpointConfig.
func NewClientFromProto(cfg *api.WebhookEndpointConfig) (Client, error) {
	if cfg == nil {
		return nil, errors.New("containment: nil WebhookEndpointConfig")
	}
	epCfg, err := EndpointFromProto(cfg)
	if err != nil {
		return nil, err
	}
	return NewSingleClient(epCfg)
}

func (c *singleClient) Deliver(ctx context.Context, event *api.SecuritySignalEvent) error {
	return c.Send(ctx, event)
}

func (c *singleClient) Send(ctx context.Context, event *api.SecuritySignalEvent) error {
	if event == nil {
		return errors.New("containment: cannot send nil SecuritySignalEvent")
	}

	// 1. Check event type filter
	signalType := event.Type
	if signalType == "" {
		signalType = inferSignalType(event)
		event.Type = signalType
	}
	if len(c.eventFilter) > 0 && !c.eventFilter[signalType] {
		return nil
	}

	// 2. Ensure envelope fields are populated
	if event.Id == "" {
		event.Id = generateUUID()
	}
	if event.SpecVersion == "" {
		event.SpecVersion = "1.0"
	}
	if event.Source == "" {
		event.Source = "agentmesh://containment/dispatcher"
	}
	if event.EventTime == nil {
		event.EventTime = timestamppb.Now()
	}
	if event.DataContentType == "" {
		event.DataContentType = ContentTypeJSON
	}
	if event.Subject == "" {
		event.Subject = extractSubject(event)
	}

	// 3. Serialize via protojson with UseProtoNames: true
	bodyBytes, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}.Marshal(event)
	if err != nil {
		containmentDroppedTotal.WithLabelValues(event.Type, "marshal_error").Inc()
		return fmt.Errorf("containment: protojson marshal: %w", err)
	}

	// 4. Compute CloudEvents headers
	ceTime := event.EventTime.AsTime().UTC().Format(time.RFC3339Nano)

	// 5. Compute HMAC-SHA256 headers if configured
	var tsStr, sigHeader string
	if c.hasHMAC && len(c.hmacSecret) > 0 {
		tsMillis := time.Now().UnixMilli()
		tsStr = strconv.FormatInt(tsMillis, 10)
		sigHeader = ComputeSignature(c.hmacSecret, tsStr, bodyBytes)
	}

	maxRetries := c.cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = DefaultMaxRetries
	}

	var lastErr error
	totalAttempts := 1 + int(maxRetries)

	for attempt := 0; attempt < totalAttempts; attempt++ {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.requestURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("containment: create request: %w", err)
		}

		// CloudEvents 1.0 headers
		req.Header.Set(HeaderContentType, ContentTypeJSON)
		req.Header.Set(HeaderUserAgent, DefaultUserAgent)
		req.Header.Set(HeaderCESpecVersion, "1.0")
		req.Header.Set(HeaderCEID, event.Id)
		req.Header.Set(HeaderCEType, event.Type)
		req.Header.Set(HeaderCESource, event.Source)
		req.Header.Set(HeaderCETime, ceTime)
		if event.Subject != "" {
			req.Header.Set(HeaderCESubject, event.Subject)
		}

		// HMAC headers
		if sigHeader != "" {
			req.Header.Set(HeaderAgentMeshTimestamp, tsStr)
			req.Header.Set(HeaderAgentMeshSignature, sigHeader)
		}

		resp, err := c.httpClient.Do(req)
		duration := time.Since(start)
		containmentDeliveryDuration.WithLabelValues(event.Type).Observe(duration.Seconds())

		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponseBytes))
			resp.Body.Close()

			statusStr := strconv.Itoa(resp.StatusCode)
			containmentDeliveredTotal.WithLabelValues(event.Type, statusStr).Inc()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("webhook responded with status %d", resp.StatusCode)
			if resp.StatusCode < 500 {
				// Client 4xx error: do not retry
				break
			}
		} else {
			lastErr = err
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				containmentDroppedTotal.WithLabelValues(event.Type, "client_timeout").Inc()
				return err
			}
		}
	}

	containmentDroppedTotal.WithLabelValues(event.Type, "transport_error").Inc()
	logger.Warnw("Containment webhook delivery failed after retries",
		"url", c.cfg.URL,
		"type", event.Type,
		"err", lastErr,
	)
	return lastErr
}

func (c *singleClient) Close() error {
	if c.httpClient != nil {
		if tr, ok := c.httpClient.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	return nil
}

func (m *multiClient) Deliver(ctx context.Context, event *api.SecuritySignalEvent) error {
	return m.Send(ctx, event)
}

func (m *multiClient) Send(ctx context.Context, event *api.SecuritySignalEvent) error {
	if len(m.clients) == 0 {
		return nil
	}
	var errs []error
	for _, c := range m.clients {
		if err := c.Send(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *multiClient) Close() error {
	var errs []error
	for _, c := range m.clients {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ComputeSignature calculates the expected sha256=<hex> signature over timestamp + "." + body.
func ComputeSignature(secret []byte, timestamp string, body []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// VerifySignature verifies an incoming HMAC-SHA256 signature in constant time.
func VerifySignature(secret []byte, timestamp string, body []byte, signature string) bool {
	if len(secret) == 0 || timestamp == "" || signature == "" {
		return false
	}
	expectedSig := ComputeSignature(secret, timestamp, body)
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

func inferSignalType(event *api.SecuritySignalEvent) string {
	if event == nil {
		return ""
	}
	switch event.Data.(type) {
	case *api.SecuritySignalEvent_PolicyDenied:
		return "agentmesh.policy.denied"
	case *api.SecuritySignalEvent_TransportRefused:
		return "agentmesh.transport.refused"
	case *api.SecuritySignalEvent_IdentityRevoked:
		return "agentmesh.identity.revoked"
	case *api.SecuritySignalEvent_EnrollmentRejected:
		return "agentmesh.enrollment.rejected"
	}
	return ""
}
