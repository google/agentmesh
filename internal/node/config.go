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
	"fmt"
	"os"
	"strings"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/google/agentmesh/api"
	"gopkg.in/yaml.v2"
)

type NodeConfigComplete struct {
	Policies []biscuit.Policy
	Checks   []biscuit.Check
	Rules    []biscuit.Rule
	Services []api.ServiceConfig
	Labels   map[string]string

	// EgressRequireLabels is the operator's egress floor (api.Egress). Nil
	// means no floor, so a caller's requirement — or the absence of one —
	// stands on its own, as it always has.
	EgressRequireLabels map[string]string
}

// LoadNodeConfig loads the node configuration from the specified path.
// If the file is missing, it returns an empty initialized config.
func LoadNodeConfig(path string) (*NodeConfigComplete, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &NodeConfigComplete{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config api.NodeConfig
	// Strict: a key this build does not recognise is either a typo or a newer
	// schema, and under attenuation either one silently weakens the node.
	if err := yaml.UnmarshalStrict(data, &config); err != nil {
		return nil, fmt.Errorf("invalid node config %s: %w", path, err)
	}

	if !api.SupportedNodeConfigVersions[config.Version] {
		return nil, fmt.Errorf("node config %s declares version %q, which this build does not support (supported: %s); upgrade agentmesh-node",
			path, config.Version, api.NodeConfigVersionV1Alpha1)
	}

	// A credential written into a file on disk is refused here, not in
	// CompleteNodeConfig: the mobile FFI builds its config in memory with a
	// per-launch token that is never written anywhere.
	for _, svc := range config.Services {
		if svc.TargetURL != "" {
			if err := rejectInlineBackendCredential(svc.TargetURL); err != nil {
				return nil, fmt.Errorf("node config %s, service %q: %w", path, svc.Name, err)
			}
		}
	}

	return CompleteNodeConfig(config)
}

// CompleteNodeConfig validates the services and labels and parses the Datalog
// of a decoded node config. Shared with the mobile FFI so both report the same
// errors.
func CompleteNodeConfig(config api.NodeConfig) (*NodeConfigComplete, error) {
	// The control plane attests this set at enrollment, so a malformed label
	// must stop the node here rather than surface as a refused enrollment.
	if err := api.ValidateLabels(config.Labels); err != nil {
		return nil, fmt.Errorf("invalid labels: %w", err)
	}

	complete := &NodeConfigComplete{
		Services: config.Services,
		Labels:   config.Labels,
	}

	// Rejected at load, not at first use: a floor that cannot compile would
	// otherwise fail open on the request that needed it, and an operator who
	// wrote one is entitled to find out at startup instead.
	if len(config.Egress.RequireLabels) > 0 {
		if err := api.ValidateLabels(config.Egress.RequireLabels); err != nil {
			return nil, fmt.Errorf("invalid egress.require_labels: %w", err)
		}
		if _, err := api.LabelCheck(config.Egress.RequireLabels); err != nil {
			return nil, fmt.Errorf("invalid egress.require_labels: %w", err)
		}
		complete.EgressRequireLabels = config.Egress.RequireLabels
	}

	for i, svc := range config.Services {
		if err := api.ValidateServiceFormat(svc.Type + "://" + svc.Name); err != nil {
			return nil, fmt.Errorf("invalid service config at index %d: %w", i, err)
		}
		// Nodes serve what the control plane assigns them; a destination
		// declared here would give one node a policy of its own.
		sType, typeErr := api.ParseServiceType(svc.Type)
		if typeErr == nil && sType == api.ServiceType_SERVICE_TYPE_EGRESS {
			return nil, fmt.Errorf("service %q: egress destinations are assigned by the control plane (PolicyConfig.egress), not declared in the node config", svc.Name)
		}
		if svc.Ingress != nil {
			if typeErr != nil {
				return nil, fmt.Errorf("service %q: %w", svc.Name, typeErr)
			}
			if _, err := api.ServiceIngressFromConfig(sType, svc.Ingress); err != nil {
				return nil, fmt.Errorf("service %q: %w", svc.Name, err)
			}
		}
		if svc.TargetAuthPath != "" && svc.TargetURL == "" {
			return nil, fmt.Errorf("service %q: target_auth_path needs a target_url", svc.Name)
		}
	}

	for _, pStr := range config.Attenuation.Policies {
		trimmed := strings.TrimRight(strings.TrimSpace(pStr), ";")
		p, err := parser.FromStringPolicy(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid local policy syntax %q: %w", pStr, err)
		}
		complete.Policies = append(complete.Policies, p)
	}

	for _, cStr := range config.Attenuation.Checks {
		trimmed := strings.TrimRight(strings.TrimSpace(cStr), ";")
		c, err := parser.FromStringCheck(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid local check syntax %q: %w", cStr, err)
		}
		complete.Checks = append(complete.Checks, c)
	}

	for _, rStr := range config.Attenuation.Rules {
		trimmed := strings.TrimRight(strings.TrimSpace(rStr), ";")
		r, err := parser.FromStringRule(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid local rule syntax %q: %w", rStr, err)
		}
		complete.Rules = append(complete.Rules, r)
	}

	return complete, nil
}
