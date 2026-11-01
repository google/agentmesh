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

package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
)

// DecodeBase64Biscuit decodes a base64 or unpadded base64url encoded Biscuit.
func DecodeBase64Biscuit(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("empty biscuit token")
	}
	if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(encoded)
}

// TargetFactsFromBiscuit queries api.TargetFactRules on a provider's own
// verified Biscuit to produce the target_fact(type, val) facts injected when
// evaluating BaselineTargetCheck against a caller.
func TargetFactsFromBiscuit(b *biscuit.Biscuit, trustedKeys []ed25519.PublicKey, timeout time.Duration) ([]biscuit.Fact, error) {
	var auth biscuit.Authorizer
	var lastErr error
	for _, pub := range trustedKeys {
		candidate, err := newAuthorizer(b, pub, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		candidate.AddPolicy(api.AllowIfTruePolicy)
		if err := candidate.Authorize(); err == nil {
			auth = candidate
			break
		} else {
			lastErr = err
		}
	}
	if auth == nil {
		return nil, fmt.Errorf("provider biscuit verification failed: %w", lastErr)
	}
	var out []biscuit.Fact
	for _, rule := range api.TargetFactRules {
		if factSet, err := auth.Query(rule); err == nil {
			for _, fact := range factSet {
				out = append(out, fact)
			}
		}
	}
	return out, nil
}

// IngressEvalParams configures Datalog + TAR + ServiceIngress.allow evaluation
// for an external HTTP ingress request in INGRESS_AUTH_MODE_EDGE.
type IngressEvalParams struct {
	ServiceType        string
	ServiceName        string
	Method             string
	Path               string
	MCPTool            string
	AllowMCPStreamInit bool
	TargetFacts        []biscuit.Fact
	EnforceTargetCheck bool
	MeshPolicyRules    []biscuit.Rule
	LocalPolicies      []biscuit.Policy
	LocalChecks        []biscuit.Check
	LocalRules         []biscuit.Rule
	Allow              []string
	Timeout            time.Duration
}

// IngressCallerResult describes an authorized external ingress caller.
type IngressCallerResult struct {
	Principal     string
	Roles         []string
	TaskName      string
	ActorNodeID   string
	IdentityFacts map[string][]string
}

func runIngressAuthorizer(authorizer biscuit.Authorizer, p IngressEvalParams) ([]string, error) {
	authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactService,
		IDs:  []biscuit.Term{biscuit.String(p.ServiceType), biscuit.String(p.ServiceName)},
	}})
	if p.Method != "" {
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactMethod,
			IDs:  []biscuit.Term{biscuit.String(p.Method)},
		}})
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactPath,
			IDs:  []biscuit.Term{biscuit.String(p.Path)},
		}})
	}
	EnforceExpiration(authorizer)
	for _, tf := range p.TargetFacts {
		authorizer.AddFact(tf)
	}
	if p.EnforceTargetCheck {
		authorizer.AddCheck(api.BaselineTargetCheck)
	}
	for _, pol := range p.LocalPolicies {
		authorizer.AddPolicy(pol)
	}
	for _, chk := range p.LocalChecks {
		authorizer.AddCheck(chk)
	}
	for _, r := range p.LocalRules {
		authorizer.AddRule(r)
	}
	for _, pol := range api.BaselinePolicies {
		authorizer.AddPolicy(pol)
	}
	for _, r := range api.BaselineRules {
		authorizer.AddRule(r)
	}
	for _, r := range api.BaselineHTTPRules {
		authorizer.AddRule(r)
	}
	for _, r := range p.MeshPolicyRules {
		authorizer.AddRule(r)
	}
	if err := authorizer.Authorize(); err != nil {
		return nil, err
	}

	var roles []string
	if facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_roles", IDs: []biscuit.Term{biscuit.Variable("r")}},
		Body: []biscuit.Predicate{{Name: api.FactRole, IDs: []biscuit.Term{biscuit.Variable("r")}}},
	}); err == nil {
		for _, f := range facts {
			if len(f.IDs) == 1 {
				if s, ok := f.IDs[0].(biscuit.String); ok {
					roles = append(roles, string(s))
				}
			}
		}
		sort.Strings(roles)
	}
	return roles, nil
}

// ValidateIngressCallerPreDial checks the caller's verified Biscuit claims,
// TAR attenuation chain, and ServiceIngress.allow ACL locally before opening a
// network connection or /mesh/auth handshake to the serving provider.
func ValidateIngressCallerPreDial(claims *VerifiedBiscuitClaims, p IngressEvalParams) (map[string][]string, error) {
	if claims == nil || claims.Biscuit == nil {
		return nil, fmt.Errorf("missing verified biscuit claims")
	}
	if slices.Contains(claims.Roles, api.RoleRouter) {
		return nil, fmt.Errorf("router biscuits cannot be used as HTTP edge bearer tokens")
	}
	if claims.NodePeerID != "" && len(claims.TaskRules) == 0 {
		return nil, fmt.Errorf("unattenuated transport member biscuits cannot be used as HTTP edge bearer tokens; exchange at /oauth/token")
	}
	if len(claims.TaskRules) > 0 {
		taskReq := api.TaskRequestContext{
			ServiceType:        p.ServiceType,
			ServiceName:        p.ServiceName,
			HasHTTP:            p.Method != "",
			Method:             p.Method,
			Path:               p.Path,
			MCPTool:            p.MCPTool,
			AllowMCPStreamInit: p.AllowMCPStreamInit,
		}
		if err := api.EvaluateTaskRules(claims.TaskRules, taskReq, time.Now()); err != nil {
			return nil, err
		}
	}
	idMap := claims.IdentityClaimsMap()
	if !api.MatchIngressAllow(p.Allow, idMap) {
		return nil, fmt.Errorf("caller does not satisfy service ingress allow list")
	}
	return idMap, nil
}

// AuthorizeIngressDelegatedBiscuit authorizes a verified Delegated Session
// Biscuit or task-attenuated Task Biscuit (minted via RFC 8693 /oauth/token,
// POST /token/exchange, or SDK task attenuation) against mesh Datalog policy,
// local node attenuation, TAR blocks, and ServiceIngress.allow. Unattenuated
// standing member/router transport Biscuits are rejected.
func AuthorizeIngressDelegatedBiscuit(claims *VerifiedBiscuitClaims, p IngressEvalParams) (*IngressCallerResult, error) {
	idMap, err := ValidateIngressCallerPreDial(claims, p)
	if err != nil {
		return nil, err
	}

	authorizer, err := newAuthorizer(claims.Biscuit, claims.VerifyingKey, p.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create biscuit authorizer: %w", err)
	}
	roles, err := runIngressAuthorizer(authorizer, p)
	if err != nil {
		return nil, err
	}

	actorNodeID := claims.ActorNodePeerID
	if actorNodeID == "" {
		actorNodeID = claims.NodePeerID
	}

	return &IngressCallerResult{
		Principal:     claims.Principal(),
		Roles:         roles,
		TaskName:      claims.InnermostTaskName(),
		ActorNodeID:   actorNodeID,
		IdentityFacts: idMap,
	}, nil
}
