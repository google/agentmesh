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
	"regexp"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
)

// credentialNameSyntax bounds a credential name to one safe file name: the
// serving node resolves it under its secrets directory, so it must not be
// able to name a path.
var credentialNameSyntax = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// EgressStaticSecret returns the static secret file name configured on d,
// whether specified via broker.static_secret or the shorthand credential field.
func EgressStaticSecret(d *EgressDestination) string {
	if s := d.GetBroker().GetStaticSecret(); s != "" {
		return s
	}
	return d.GetCredential()
}

// ValidateEgressDestination checks one PolicyConfig.egress entry. roleNames
// are the roles the same document defines, so served_by can be checked
// against them; a label entry is checked for form only.
func ValidateEgressDestination(d *EgressDestination, roleNames map[string]bool) error {
	if d == nil {
		return fmt.Errorf("egress entry is nil")
	}
	if err := ValidateEgressName(d.GetName()); err != nil {
		return err
	}
	if d.GetTargetUrl() != "" {
		if err := validateEgressTargetURL(d.GetTargetUrl()); err != nil {
			return fmt.Errorf("egress %q: %w", d.GetName(), err)
		}
	}
	if d.GetCredential() != "" && !credentialNameSyntax.MatchString(d.GetCredential()) {
		return fmt.Errorf("egress %q: credential %q must be a name of 1-64 chars of [a-zA-Z0-9_.-], not a path or a value", d.GetName(), d.GetCredential())
	}
	if b := d.GetBroker(); b != nil {
		if d.GetCredential() != "" && (b.GetStaticSecret() == "" || b.GetStaticSecret() != d.GetCredential()) {
			return fmt.Errorf("egress %q: cannot set both credential and broker", d.GetName())
		}
		switch kind := b.GetKind().(type) {
		case *CredentialBroker_StaticSecret:
			if kind.StaticSecret != "" && !credentialNameSyntax.MatchString(kind.StaticSecret) {
				return fmt.Errorf("egress %q: broker.static_secret %q must be a name of 1-64 chars of [a-zA-Z0-9_.-], not a path or a value", d.GetName(), kind.StaticSecret)
			}
		case *CredentialBroker_OidcFederation:
			if kind.OidcFederation == nil || strings.TrimSpace(kind.OidcFederation.GetAudience()) == "" {
				return fmt.Errorf("egress %q: broker.oidc_federation.audience is required", d.GetName())
			}
			if ep := kind.OidcFederation.GetTokenEndpoint(); ep != "" {
				if err := validateEgressTargetURL(ep); err != nil {
					return fmt.Errorf("egress %q: broker.oidc_federation.token_endpoint: %w", d.GetName(), err)
				}
			}
		case *CredentialBroker_AwsAssumeRole:
			if kind.AwsAssumeRole == nil || strings.TrimSpace(kind.AwsAssumeRole.GetRoleArn()) == "" {
				return fmt.Errorf("egress %q: broker.aws_assume_role.role_arn is required", d.GetName())
			}
		case *CredentialBroker_PlatformIdentity:
			// PlatformIdentity uses node metadata server; scopes are optional.
		}
	}
	if d.GetMode() == EgressMode_EGRESS_MODE_TCP && len(d.GetPorts()) == 0 {
		return fmt.Errorf("egress %q: mode EGRESS_MODE_TCP requires at least one port in ports", d.GetName())
	}
	for _, p := range d.GetPorts() {
		if p == 0 || p > 65535 {
			return fmt.Errorf("egress %q: port %d must be in 1..65535", d.GetName(), p)
		}
	}
	for i, ins := range d.GetInspection().GetInspectors() {
		if ins == nil {
			return fmt.Errorf("egress %q: inspector[%d] is nil", d.GetName(), i)
		}
		switch kind := ins.GetKind().(type) {
		case *Inspector_ModelArmor:
			if kind.ModelArmor == nil || strings.TrimSpace(kind.ModelArmor.GetTemplate()) == "" {
				return fmt.Errorf("egress %q: inspector[%d].model_armor.template is required", d.GetName(), i)
			}
		case *Inspector_ExtProc:
			if kind.ExtProc == nil || strings.TrimSpace(kind.ExtProc.GetTarget()) == "" {
				return fmt.Errorf("egress %q: inspector[%d].ext_proc.target is required", d.GetName(), i)
			}
			if ca := kind.ExtProc.GetCa(); ca != "" && !credentialNameSyntax.MatchString(ca) {
				return fmt.Errorf("egress %q: inspector[%d].ext_proc.ca %q must be a file name in the secrets directory", d.GetName(), i, ca)
			}
			if cc := kind.ExtProc.GetClientCertificate(); cc != "" && !credentialNameSyntax.MatchString(cc) {
				return fmt.Errorf("egress %q: inspector[%d].ext_proc.client_certificate %q must be a file name in the secrets directory", d.GetName(), i, cc)
			}
		default:
			return fmt.Errorf("egress %q: inspector[%d] must specify model_armor or ext_proc", d.GetName(), i)
		}
	}
	if len(d.GetServedBy()) == 0 {
		return fmt.Errorf("egress %q: served_by must select at least one role or label", d.GetName())
	}
	for _, sel := range d.GetServedBy() {
		if key, value, isLabel := strings.Cut(sel, "="); isLabel {
			if err := ValidateLabelKey(key); err != nil {
				return fmt.Errorf("egress %q: served_by %q: %w", d.GetName(), sel, err)
			}
			if err := ValidateLabelValue(value); err != nil {
				return fmt.Errorf("egress %q: served_by %q: %w", d.GetName(), sel, err)
			}
			continue
		}
		if !roleNames[sel] {
			return fmt.Errorf("egress %q: served_by %q is neither a role in this policy nor a key=value label", d.GetName(), sel)
		}
	}
	return nil
}

// ValidateEgressName checks a destination name: a lowercase hostname with no
// wildcard, port or path. It is the service name of egress://<name>, so it
// must also be valid there.
func ValidateEgressName(name string) error {
	if name == "" {
		return fmt.Errorf("egress entry has no name")
	}
	if name != NormalizeMeshHost(name) {
		return fmt.Errorf("egress name %q must be lowercase with no trailing dot", name)
	}
	if strings.ContainsAny(name, "*:/") {
		return fmt.Errorf("egress name %q must be one hostname: no wildcard, port or path", name)
	}
	if err := ValidateServiceFormat(EgressServicePrefix + name); err != nil {
		return err
	}
	return nil
}

// ValidateEgressServicePattern checks an egress entry of allowed_services or
// http.service. The generic service validator accepts a path and any case,
// which for the other types name a service that may exist; an egress name is
// a hostname, matched against a lowercase destination name, so a path, a
// port, uppercase or a trailing dot would compile to a grant that matches
// nothing. Entries of other types pass through unchanged.
func ValidateEgressServicePattern(svc string) error {
	svcType, name := ParseServiceTarget(svc)
	if svcType != ServiceTypeStringEgress {
		return nil
	}
	if err := ValidateServiceFormat(svc); err != nil {
		return err
	}
	if name == "*" {
		return nil
	}
	if strings.ContainsAny(name, ":/") {
		return fmt.Errorf("invalid egress pattern %q: a destination is a hostname, without a scheme, a port or a path (write the path in the role's http entry)", svc)
	}
	if name != NormalizeMeshHost(name) {
		return fmt.Errorf("invalid egress pattern %q: destination names are lowercase with no trailing dot", svc)
	}
	return nil
}

// validateEgressTargetURL accepts an http or https URL with a host and no
// credential; a credential is named by EgressDestination.credential and
// resolved on the serving node.
func validateEgressTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid target_url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target_url %q must use http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("target_url %q has no host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("target_url must not carry a credential; name one in credential instead")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("target_url %q must not carry a query or a fragment", raw)
	}
	return nil
}

// EgressTargetURL is where the serving node forwards requests for d:
// target_url when set, otherwise https on the destination name.
func EgressTargetURL(d *EgressDestination) string {
	if d.GetTargetUrl() != "" {
		return d.GetTargetUrl()
	}
	return "https://" + d.GetName()
}

// EgressServedBy reports whether a node with these roles and labels is
// selected to serve d.
func EgressServedBy(d *EgressDestination, roles []string, labels map[string]string) bool {
	for _, sel := range d.GetServedBy() {
		if key, value, isLabel := strings.Cut(sel, "="); isLabel {
			if labels[key] == value {
				return true
			}
			continue
		}
		for _, r := range roles {
			if r == sel {
				return true
			}
		}
	}
	return false
}

// BuildEgressServingRules grants each destination to the nodes that serve it:
// granted_service_exact("egress", name) <- role(r) or <- label(k, v) for every
// served_by entry. The serving node evaluates its own credential when a local
// client asks for the destination, so the grant has to reach it; the rules
// travel with the mesh policy like every other grant.
func BuildEgressServingRules(egress []*EgressDestination) []PolicyRule {
	var rules []PolicyRule
	for _, d := range egress {
		if d == nil || d.GetName() == "" {
			continue
		}
		head := biscuit.Predicate{Name: FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String(ServiceTypeStringEgress), biscuit.String(d.GetName())}}
		for _, sel := range d.GetServedBy() {
			var body biscuit.Predicate
			if key, value, isLabel := strings.Cut(sel, "="); isLabel {
				body = biscuit.Predicate{Name: FactLabel, IDs: []biscuit.Term{biscuit.String(key), biscuit.String(value)}}
			} else {
				body = biscuit.Predicate{Name: FactRole, IDs: []biscuit.Term{biscuit.String(sel)}}
			}
			r := biscuit.Rule{Head: head, Body: []biscuit.Predicate{body}}
			rules = append(rules, PolicyRule{Rule: r, Text: renderRule(r)})
		}
	}
	return rules
}
