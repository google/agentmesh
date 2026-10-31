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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
)

var (
	ephemeralOnce sync.Once
	ephemeralPub  ed25519.PublicKey
	ephemeralPriv ed25519.PrivateKey
)

func ephemeralEvalKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	ephemeralOnce.Do(func() {
		var err error
		ephemeralPub, ephemeralPriv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(fmt.Sprintf("failed to generate ephemeral evaluation key: %v", err))
		}
	})
	return ephemeralPub, ephemeralPriv
}

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

// OIDCFactsFromJWTClaims extracts standard Agent Mesh OIDC identity facts
// ("user", "email", "group", "idp_role") from verified JWT claims. FactRole and
// FactNode are never derived from OIDC claims.
func OIDCFactsFromJWTClaims(claims map[string]any) map[string][]string {
	out := make(map[string][]string)
	if len(claims) == 0 {
		return out
	}
	claimMap := api.OIDCClaimToFact()
	for claimKey, factName := range claimMap {
		raw, ok := claims[claimKey]
		if !ok || raw == nil {
			continue
		}
		seen := make(map[string]bool)
		for _, item := range toStringSlice(raw) {
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			out[factName] = append(out[factName], item)
		}
		sort.Strings(out[factName])
	}
	return out
}

func allowedOIDCFactNames() map[string]bool {
	allowed := make(map[string]bool)
	for _, factName := range api.OIDCClaimToFact() {
		allowed[factName] = true
	}
	return allowed
}

// SanitizeOIDCFacts returns a copy containing only permitted OIDC fact names
// ("user", "email", "group", "idp_role") and non-empty deduplicated values.
func SanitizeOIDCFacts(facts map[string][]string) map[string][]string {
	allowed := allowedOIDCFactNames()
	clean := make(map[string][]string)
	for k, vals := range facts {
		if !allowed[k] {
			continue
		}
		seen := make(map[string]bool)
		for _, v := range vals {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			clean[k] = append(clean[k], v)
		}
		if len(clean[k]) > 0 {
			sort.Strings(clean[k])
		}
	}
	return clean
}

// MarshalIngressClaimsHeader encodes verified OIDC fact claims for transport
// over IngressProtocolID from an authenticated router to the serving node.
func MarshalIngressClaimsHeader(facts map[string][]string) (string, error) {
	clean := SanitizeOIDCFacts(facts)
	raw, err := json.Marshal(clean)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// UnmarshalIngressClaimsHeader decodes and sanitizes verified OIDC fact claims
// received over IngressProtocolID from an authenticated router.
func UnmarshalIngressClaimsHeader(encoded string) (map[string][]string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("invalid base64url ingress claims header: %w", err)
	}
	var parsed map[string][]string
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("invalid json ingress claims header: %w", err)
	}
	return SanitizeOIDCFacts(parsed), nil
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

// AuthorizeIngressDelegatedBiscuit authorizes a verified Delegated Session
// Biscuit or task-attenuated Task Biscuit (minted via RFC 8693 /oauth/token or
// SDK task attenuation) against mesh Datalog policy, local node attenuation,
// TAR blocks, and ServiceIngress.allow. Unattenuated standing member/router
// transport Biscuits are rejected.
func AuthorizeIngressDelegatedBiscuit(claims *VerifiedBiscuitClaims, p IngressEvalParams) (*IngressCallerResult, error) {
	if claims == nil || claims.Biscuit == nil {
		return nil, fmt.Errorf("missing verified biscuit claims")
	}
	if slices.Contains(claims.Roles, api.RoleRouter) {
		return nil, fmt.Errorf("router biscuits cannot be used as HTTP edge bearer tokens")
	}
	if claims.NodePeerID != "" && len(claims.TaskRules) == 0 {
		return nil, fmt.Errorf("unattenuated transport member biscuits cannot be used as HTTP edge bearer tokens; exchange at /oauth/token")
	}

	authorizer, err := newAuthorizer(claims.Biscuit, claims.VerifyingKey, p.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create biscuit authorizer: %w", err)
	}
	roles, err := runIngressAuthorizer(authorizer, p)
	if err != nil {
		return nil, err
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

// AuthorizeIngressOIDCFacts authorizes verified OIDC JWT fact claims against
// mesh Datalog policy, local node attenuation, and ServiceIngress.allow using
// the exact same Biscuit Datalog authorizer as Delegated Session Biscuits.
func AuthorizeIngressOIDCFacts(oidcFacts map[string][]string, p IngressEvalParams) (*IngressCallerResult, error) {
	clean := SanitizeOIDCFacts(oidcFacts)
	if len(clean) == 0 {
		return nil, fmt.Errorf("verified OIDC token carries no identity claims")
	}

	pub, priv := ephemeralEvalKeys()
	builder := biscuit.NewBuilder(priv)
	if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(5 * time.Minute))},
	}}); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(clean))
	for k := range clean {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range clean[k] {
			if err := builder.AddAuthorityFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: k,
				IDs:  []biscuit.Term{biscuit.String(v)},
			}}); err != nil {
				return nil, err
			}
		}
	}
	tok, err := builder.Build()
	if err != nil {
		return nil, err
	}
	authorizer, err := tok.Authorizer(pub, AuthorizerOptions(p.Timeout)...)
	if err != nil {
		return nil, err
	}
	roles, err := runIngressAuthorizer(authorizer, p)
	if err != nil {
		return nil, err
	}

	if !api.MatchIngressAllow(p.Allow, clean) {
		return nil, fmt.Errorf("caller does not satisfy service ingress allow list")
	}

	var principal string
	if emails := clean[api.FactEmail]; len(emails) > 0 {
		principal = emails[0]
	} else if users := clean[api.FactUser]; len(users) > 0 {
		principal = users[0]
	}

	return &IngressCallerResult{
		Principal:     principal,
		Roles:         roles,
		IdentityFacts: clean,
	}, nil
}
