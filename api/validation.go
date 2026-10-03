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
	"slices"
	"strings"
)

// Caps for ServiceAnnounce fields: announcements are unsolicited gossip, so
// receivers bound every dimension before processing.
const (
	MaxAnnounceKeys      = 64
	MaxAnnounceLabels    = 16
	MaxAnnounceStringLen = 256
)

// ValidateServiceAnnounce bounds and sanity-checks a gossiped announcement.
// Origin authenticity and freshness are the receiver's responsibility.
func ValidateServiceAnnounce(a *ServiceAnnounce) error {
	if a == nil {
		return fmt.Errorf("announce is nil")
	}
	if a.GetPeerId() == "" || len(a.GetPeerId()) > MaxAnnounceStringLen {
		return fmt.Errorf("invalid peer_id")
	}
	if _, err := ServiceTypeToString(a.GetType()); err != nil {
		return fmt.Errorf("invalid type: %w", err)
	}
	if a.GetServiceName() == "" || len(a.GetServiceName()) > MaxAnnounceStringLen {
		return fmt.Errorf("invalid service_name")
	}
	if len(a.GetKeys()) == 0 || len(a.GetKeys()) > MaxAnnounceKeys {
		return fmt.Errorf("keys count %d out of range [1, %d]", len(a.GetKeys()), MaxAnnounceKeys)
	}
	for _, k := range a.GetKeys() {
		if k == "" || len(k) > MaxAnnounceStringLen {
			return fmt.Errorf("invalid key %q", k)
		}
	}
	if len(a.GetLabels()) > MaxAnnounceLabels {
		return fmt.Errorf("labels count %d exceeds %d", len(a.GetLabels()), MaxAnnounceLabels)
	}
	for k, v := range a.GetLabels() {
		if k == "" || len(k) > MaxAnnounceStringLen || len(v) > MaxAnnounceStringLen {
			return fmt.Errorf("invalid label %q", k)
		}
	}
	if a.GetAnnounceTime() == nil {
		return fmt.Errorf("missing announce_time")
	}
	return nil
}

// ValidateServiceFormat ensures the service string follows the explicit URI format.
func ValidateServiceFormat(svc string) error {
	if svc == "*" {
		return nil
	}

	matches := rfc3986URIRegex.FindStringSubmatch(svc)
	if len(matches) < 6 {
		return fmt.Errorf("invalid service format %q: must follow explicit URI format (e.g., mcp://name)", svc)
	}

	scheme := matches[2]
	hasAuthority := matches[3] != ""
	authority := matches[4]

	if scheme == "" || !hasAuthority {
		return fmt.Errorf("invalid service format %q: must follow explicit URI format (e.g., mcp://name)", svc)
	}

	if matches[6] != "" {
		return fmt.Errorf("invalid service format %q: query parameters are not allowed in service URIs", svc)
	}
	if matches[8] != "" {
		return fmt.Errorf("invalid service format %q: fragments are not allowed in service URIs", svc)
	}

	if strings.Contains(authority, "@") {
		return fmt.Errorf("invalid service format %q: userinfo is not allowed in service URIs", svc)
	}

	typ, val := ParseServiceTarget(svc)
	if typ == "" {
		return fmt.Errorf("invalid service format %q: type cannot be empty", svc)
	}
	if val == "" {
		return fmt.Errorf("invalid service format %q: value cannot be empty", svc)
	}

	if val == "*" {
		return nil
	}

	// Split val into host and path (if any)
	parts := strings.SplitN(val, "/", 2)
	host := parts[0]

	if !dnsNameRegex.MatchString(host) {
		return fmt.Errorf("invalid service format %q: %q is not a valid DNS name", svc, host)
	}

	return nil
}

// ValidateTargetFormat ensures the target string follows the explicit fact:value format.
func ValidateTargetFormat(target string) error {
	if target == "*" {
		return nil
	}
	parts := strings.SplitN(target, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid target format %q: must be fact:value (e.g., group:backend)", target)
	}
	fact, val := parts[0], parts[1]
	if fact == "" {
		return fmt.Errorf("invalid target format %q: fact cannot be empty", target)
	}
	if val == "" {
		return fmt.Errorf("invalid target format %q: value cannot be empty", target)
	}
	// "*" as the fact matches every target_fact (granted_target_all_facts).
	if fact != "*" && !slices.Contains(TargetFactNames(), fact) {
		return fmt.Errorf("invalid target %q: %q is not a target fact, so nothing would ever match it (want %s or \"*\")", target, fact, strings.Join(TargetFactNames(), ", "))
	}
	return nil
}
