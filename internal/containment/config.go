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
	"fmt"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/secrets"
)

// Default configurations per AGENTS.md §1 (Zero config, safe defaults).
const (
	DefaultQueueCapacity    = 1024
	DefaultWorkerCount      = 2
	DefaultTimeout          = 500 * time.Millisecond
	DefaultMaxRetries       = 3
	DefaultCoalescingWindow = time.Second
)

// Config specifies runtime configuration for containment webhook dispatch.
type Config struct {
	Enabled          bool
	QueueCapacity    int
	Workers          int
	WorkerCount      int // Alias for Workers
	CoalescingWindow time.Duration
	Endpoints        []EndpointConfig
}

// EffectiveWorkers returns the configured worker count, applying defaults.
func (c *Config) EffectiveWorkers() int {
	if c.Workers > 0 {
		return c.Workers
	}
	if c.WorkerCount > 0 {
		return c.WorkerCount
	}
	return DefaultWorkerCount
}

// EffectiveQueueCapacity returns the configured queue capacity, applying defaults.
func (c *Config) EffectiveQueueCapacity() int {
	if c.QueueCapacity > 0 {
		return c.QueueCapacity
	}
	return DefaultQueueCapacity
}

// EndpointConfig defines configuration for a single delivery target.
type EndpointConfig struct {
	URL             string
	Timeout         time.Duration
	MaxRetries      uint32
	EventTypes      []string
	HMACSecret      []byte
	HMACSecretPath  string
	CACertPath      string
	ClientCertPath  string
	ClientKeyPath   string
	InsecureSkipTLS bool
}

// FromProto translates an api.SecuritySignalsConfig message into an internal Config.
func FromProto(p *api.SecuritySignalsConfig) (*Config, error) {
	if p == nil {
		return &Config{
			Enabled:          false,
			QueueCapacity:    DefaultQueueCapacity,
			Workers:          DefaultWorkerCount,
			WorkerCount:      DefaultWorkerCount,
			CoalescingWindow: DefaultCoalescingWindow,
		}, nil
	}

	cfg := &Config{
		Enabled:       p.Enabled,
		QueueCapacity: int(p.QueueCapacity),
		Workers:       DefaultWorkerCount,
		WorkerCount:   DefaultWorkerCount,
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = DefaultQueueCapacity
	}

	if p.CoalescingWindow != nil {
		cfg.CoalescingWindow = p.CoalescingWindow.AsDuration()
	} else {
		cfg.CoalescingWindow = DefaultCoalescingWindow
	}

	var envSecret string
	for _, ep := range p.Endpoints {
		if ep != nil && ep.Url != "" && ep.HmacSecretPath == "" {
			resolved, err := secrets.FromPathOrEnv("containment-hmac-secret", "", "AGENTMESH_CONTAINMENT_HMAC_SECRET")
			if err != nil {
				return nil, fmt.Errorf("resolve AGENTMESH_CONTAINMENT_HMAC_SECRET: %w", err)
			}
			envSecret = strings.TrimSpace(resolved)
			break
		}
	}

	for _, ep := range p.Endpoints {
		if ep == nil || ep.Url == "" {
			continue
		}
		epCfg, err := EndpointFromProto(ep)
		if err != nil {
			return nil, err
		}
		if len(epCfg.HMACSecret) == 0 && epCfg.HMACSecretPath == "" && envSecret != "" {
			epCfg.HMACSecret = []byte(envSecret)
		}
		cfg.Endpoints = append(cfg.Endpoints, epCfg)
	}

	return cfg, nil
}

// EndpointFromProto translates an api.WebhookEndpointConfig message into an EndpointConfig.
func EndpointFromProto(ep *api.WebhookEndpointConfig) (EndpointConfig, error) {
	if ep == nil {
		return EndpointConfig{}, fmt.Errorf("nil WebhookEndpointConfig")
	}

	rawURL := strings.TrimSpace(ep.Url)
	if rawURL == "" {
		return EndpointConfig{}, fmt.Errorf("empty containment webhook URL")
	}

	if !strings.HasPrefix(rawURL, "unix:") &&
		!strings.HasPrefix(rawURL, "http://") &&
		!strings.HasPrefix(rawURL, "https://") {
		return EndpointConfig{}, fmt.Errorf("invalid containment webhook URL scheme: %s (must be unix:, http://, or https://)", rawURL)
	}

	epCfg := EndpointConfig{
		URL:            rawURL,
		MaxRetries:     ep.MaxRetries,
		EventTypes:     ep.EventTypes,
		HMACSecretPath: ep.HmacSecretPath,
		CACertPath:     ep.CaCertPath,
		ClientCertPath: ep.ClientCertPath,
		ClientKeyPath:  ep.ClientKeyPath,
	}

	if ep.Timeout != nil {
		epCfg.Timeout = ep.Timeout.AsDuration()
	} else {
		epCfg.Timeout = DefaultTimeout
	}

	if epCfg.MaxRetries == 0 {
		epCfg.MaxRetries = DefaultMaxRetries
	}

	secretStr, err := secrets.FromPathOrEnv("containment-hmac-secret", ep.HmacSecretPath, "AGENTMESH_CONTAINMENT_HMAC_SECRET")
	if err != nil && ep.HmacSecretPath != "" {
		return EndpointConfig{}, fmt.Errorf("endpoint %s hmac secret error: %w", rawURL, err)
	}
	if trimmed := strings.TrimSpace(secretStr); trimmed != "" {
		epCfg.HMACSecret = []byte(trimmed)
	}

	return epCfg, nil
}
