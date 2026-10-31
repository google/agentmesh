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

package api

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// IngressAuthModeStringEdge is the canonical string form of INGRESS_AUTH_MODE_EDGE.
	IngressAuthModeStringEdge = "edge"

	// IngressAuthModeStringPassthrough is the canonical string form of INGRESS_AUTH_MODE_PASSTHROUGH.
	IngressAuthModeStringPassthrough = "passthrough"

	// MaxIngressAllowEntries bounds the number of caller principal patterns a
	// single ServiceIngress.allow list may carry in directory announcements.
	MaxIngressAllowEntries = 64
)

// IsInboundServiceType reports whether t is an inbound service type that a
// node can expose on external router HTTP ingress (a2a, mcp, or inference).
func IsInboundServiceType(t ServiceType) bool {
	switch t {
	case ServiceType_SERVICE_TYPE_A2A, ServiceType_SERVICE_TYPE_MCP, ServiceType_SERVICE_TYPE_INFERENCE:
		return true
	default:
		return false
	}
}

// EffectiveIngressAuthMode resolves UNSPECIFIED to the safe zero-trust default
// (INGRESS_AUTH_MODE_EDGE).
func EffectiveIngressAuthMode(ing *ServiceIngress) IngressAuthMode {
	if ing == nil || ing.AuthMode == IngressAuthMode_INGRESS_AUTH_MODE_UNSPECIFIED {
		return IngressAuthMode_INGRESS_AUTH_MODE_EDGE
	}
	return ing.AuthMode
}

// IngressAuthModeToString converts a resolved IngressAuthMode enum to its
// canonical Datalog and YAML string ("edge" or "passthrough").
func IngressAuthModeToString(m IngressAuthMode) (string, error) {
	switch m {
	case IngressAuthMode_INGRESS_AUTH_MODE_EDGE:
		return IngressAuthModeStringEdge, nil
	case IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH:
		return IngressAuthModeStringPassthrough, nil
	default:
		return "", fmt.Errorf("invalid or unspecified ingress auth mode: %v", m)
	}
}

// ParseIngressAuthMode parses a YAML/config string into an IngressAuthMode.
// An empty string defaults to INGRESS_AUTH_MODE_EDGE.
func ParseIngressAuthMode(s string) (IngressAuthMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", IngressAuthModeStringEdge:
		return IngressAuthMode_INGRESS_AUTH_MODE_EDGE, nil
	case IngressAuthModeStringPassthrough:
		return IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH, nil
	default:
		return IngressAuthMode_INGRESS_AUTH_MODE_UNSPECIFIED, fmt.Errorf("invalid ingress auth_mode %q (want %q or %q)", s, IngressAuthModeStringEdge, IngressAuthModeStringPassthrough)
	}
}

// ServiceIngressFromConfig converts a YAML IngressConfig into a validated
// protobuf ServiceIngress message.
func ServiceIngressFromConfig(svcType ServiceType, cfg *IngressConfig) (*ServiceIngress, error) {
	if cfg == nil {
		return nil, nil
	}
	mode, err := ParseIngressAuthMode(cfg.AuthMode)
	if err != nil {
		return nil, err
	}
	ing := &ServiceIngress{
		AuthMode: mode,
		Allow:    slices.Clone(cfg.Allow),
	}
	if err := ValidateServiceIngress(svcType, ing); err != nil {
		return nil, err
	}
	return ing, nil
}

// ValidateServiceIngress validates a ServiceIngress declaration on a service
// of type svcType. A nil ServiceIngress is always valid (internal-only).
func ValidateServiceIngress(svcType ServiceType, ing *ServiceIngress) error {
	if ing == nil {
		return nil
	}
	if !IsInboundServiceType(svcType) {
		return fmt.Errorf("ingress is only supported for inbound service types (a2a, mcp, inference), got %v", svcType)
	}
	mode := EffectiveIngressAuthMode(ing)
	if _, err := IngressAuthModeToString(mode); err != nil {
		return err
	}
	if mode == IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH && len(ing.Allow) > 0 {
		return fmt.Errorf("ingress.allow cannot be set when auth_mode is %q: caller identity is not verified at the edge", IngressAuthModeStringPassthrough)
	}
	if len(ing.Allow) > MaxIngressAllowEntries {
		return fmt.Errorf("ingress.allow has %d entries, max is %d", len(ing.Allow), MaxIngressAllowEntries)
	}
	for _, member := range ing.Allow {
		if err := ValidateBindingMember(member, "ingress.allow"); err != nil {
			return err
		}
		if prefix, val, ok := strings.Cut(member, ":"); ok && prefix == FactNode {
			if _, err := peer.Decode(val); err != nil {
				return fmt.Errorf("ingress.allow entry %q has invalid peer ID: %w", member, err)
			}
		}
	}
	return nil
}

// ValidateIngressGrant checks one PolicyRole.allowed_ingress entry.
func ValidateIngressGrant(g *IngressGrant, roleName string) error {
	if g == nil || len(g.Services) == 0 {
		return fmt.Errorf("allowed_ingress grant in role %q must list at least one service", roleName)
	}
	for _, svc := range g.Services {
		if err := ValidateServiceFormat(svc); err != nil {
			return fmt.Errorf("invalid service %q in allowed_ingress for role %q: %w", svc, roleName, err)
		}
		if svc == "*" {
			continue
		}
		svcTypeStr, _ := ParseServiceTarget(svc)
		svcType, err := ParseServiceType(svcTypeStr)
		if err != nil || !IsInboundServiceType(svcType) {
			return fmt.Errorf("service %q in allowed_ingress for role %q must target an inbound service type (a2a, mcp, inference)", svc, roleName)
		}
	}
	for _, m := range g.AllowedAuthModes {
		if _, err := IngressAuthModeToString(m); err != nil {
			return fmt.Errorf("invalid allowed_auth_modes value %v in allowed_ingress for role %q: %w", m, roleName, err)
		}
	}
	return nil
}

// ValidateIngressGrants checks all PolicyRole.allowed_ingress entries on a role.
func ValidateIngressGrants(grants []*IngressGrant, roleName string) error {
	for _, g := range grants {
		if err := ValidateIngressGrant(g, roleName); err != nil {
			return err
		}
	}
	return nil
}

// ValidateIngressURL validates and normalizes a router's public ingress base
// URL (e.g. "https://bananas.sam-mesh.dev/ingress"). An empty string disables
// ingress URL advertisement and returns "", nil.
func ValidateIngressURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid ingress_url %q: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("ingress_url %q must use http or https scheme", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("ingress_url %q must include a host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("ingress_url %q must not contain userinfo credentials", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("ingress_url %q must not contain query parameters or fragments", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// MatchIngressAllow reports whether a verified caller's attested identity
// claims (keyed by Datalog fact name: "user", "email", "group", "idp_role",
// "node") satisfy ServiceIngress.allow.
//
// When allow is empty, MatchIngressAllow returns true so mesh Datalog policy
// alone governs access. When allow is non-empty, the caller must have at least
// one attested claim matching at least one entry in allow.
func MatchIngressAllow(allow []string, claims map[string][]string) bool {
	if len(allow) == 0 {
		return true
	}
	hasAnyIdentity := false
	for _, k := range BindingMemberPrefixes() {
		if len(claims[k]) > 0 {
			hasAnyIdentity = true
			break
		}
	}
	if !hasAnyIdentity {
		return false
	}
	for _, entry := range allow {
		if entry == SystemAuthenticated {
			return true
		}
		prefix, pattern, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		if prefix == FactNode {
			id, err := peer.Decode(pattern)
			if err != nil {
				continue
			}
			if slices.Contains(claims[FactNode], id.String()) {
				return true
			}
			continue
		}
		if MatchBindingMemberValue(claims[prefix], pattern) {
			return true
		}
	}
	return false
}
