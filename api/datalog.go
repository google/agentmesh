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
	"maps"
	"sort"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
)

// ============================================================================
// SAM Datalog Authorization Concepts & Predicates
// ============================================================================
//
// SAM enforces security policies using Biscuit tokens containing Datalog facts,
// rules, and checks. Here are the core concepts used in our Datalog engine:
//
// 1. Replay Defense Facts:
//    - client_peer_id: The libp2p PeerID of the node that authenticated with the
//      control plane to request this token. Embedded in the token authority block.
//    - connection_peer_id: The libp2p PeerID of the caller initiating the connection
//      to the receiving node. Injected dynamically at runtime by the receiver.
//    - Replay Check: Verified using the check:
//      `check if client_peer_id($id), connection_peer_id($id)`
//      This guarantees that a token can only be used by its rightful owner.
//
// 2. Target Constraints & Resolution:
//    - target_fact(type, value): Standardized format representing an identity claim
//      (e.g., user, group, node ID) asserted by the caller. Derived dynamically at
//      runtime from OIDC claims or node authentication.
//    - allow_network_target: Derived fact generated on the receiver node by matching
//      target_fact against the token's allowed targets (e.g., granted_target_exact).
//    - target_unrestricted: Fact injected in the token by the control plane indicating that
//      the client has unrestricted network access and bypasses target constraints.
//    - Target Check: Verified using the check:
//      `check if allow_network_target($fact, $val) or target_unrestricted(true)`
//      If target_unrestricted is present, target checking succeeds immediately.
//      Otherwise, it requires a matching allow_network_target rule to succeed.
//
// 3. Marker Facts:
//    Facts that only signal presence (target_unrestricted, granted_service_all_types,
//    agent_authorized, ...) carry the single term `true`, see MarkerFact. The Biscuit
//    grammar requires at least one term per predicate; biscuit-go accepts an empty term
//    list but the Rust, Python and JavaScript implementations reject it, and the SDKs
//    evaluate this same Datalog.
//
// ============================================================================

// Biscuit fact names represent the Datalog predicates used in auth tokens and policy evaluation.
const (
	// FactExpiration defines the token expiration time.
	// Contains: biscuit.Date(expirationTime)
	// Example Datalog: check if time($time), expiration($exp), $time <= $exp
	FactExpiration = "expiration"

	// FactNode defines the PeerID of the node that this token belongs to.
	// Contains: biscuit.String(nodePeerID)
	// Example Datalog: allow if node("12D3KooWP2G8nJCLASp1Kb4TmQS4wCpMH2vpSUz8ug8DYEJiuf1i")
	FactNode = "node"

	// FactClientPeerID defines the client PeerID performing the request, used for replay defense.
	// Contains: biscuit.String(clientPeerID)
	// Example Datalog: check if client_peer_id($id), connection_peer_id($id)
	FactClientPeerID = "client_peer_id"

	// FactGroup defines the group claim extracted from the OIDC token.
	// Contains: biscuit.String(groupName)
	// Example Datalog: allow if group("data-science")
	FactGroup = "group"

	// FactRole defines a custom SAM role assigned to the user or node.
	// Contains: biscuit.String(roleName)
	// Example Datalog: allow if role("mesh-member")
	//
	// Only the control plane mints it, from mesh policy bindings. It must
	// never be derived from an OIDC claim: role("sam:role:router") is what
	// makes a router, and an issuer's "roles" claim is the issuer's word, not
	// the mesh operator's. See FactIdpRole.
	FactRole = "role"

	// FactIdpRole carries the OIDC "roles" claim as the issuer emitted it.
	// Contains: biscuit.String(roleName)
	// Example Datalog: allow if idp_role("platform-team")
	// Bind it to a mesh role in policy (member "idp_role:platform-team"),
	// or target it ("idp_role:platform-team"); it grants nothing by itself.
	FactIdpRole = "idp_role"

	// FactRight defines the cryptographically signed capability/right.
	// Contains: biscuit.String(rightName)
	// Example Datalog: allow if right("relay")
	FactRight = "right"

	// RightRelay defines the transport relaying/bridging right.
	RightRelay = "relay"

	// RightServiceInvoke defines the edge service invocation right.
	RightServiceInvoke = "service:invoke"

	// Standard role values
	RoleRouter = "sam:role:router"
	RoleNode   = "sam:role:node"

	// FactUser defines the subject (username/userID) claim extracted from the OIDC token.
	// Contains: biscuit.String(username)
	// Example Datalog: allow if user("alice")
	FactUser = "user"

	// FactEmail defines the email claim extracted from the OIDC token.
	// Contains: biscuit.String(emailAddress)
	// Example Datalog: allow if email("bob@example.com")
	FactEmail = "email"

	// FactGrantedServiceAllTypes allows access to all service types (e.g., mcp, inference) and all targets.
	// Contains: biscuit.Bool(true) (marker fact)
	// Example Datalog: allow if granted_service_all_types(true)
	FactGrantedServiceAllTypes = "granted_service_all_types"

	// FactGrantedServiceAll allows access to all targets under a specific service type.
	// Contains: biscuit.String(serviceType) (e.g., "mcp")
	// Example Datalog: allow if service("mcp", $target), granted_service_all("mcp")
	FactGrantedServiceAll = "granted_service_all"

	// FactGrantedServiceSuffix allows access to services matching a suffix pattern (e.g. *.service.local).
	// Contains: biscuit.String(serviceType), biscuit.String(suffixPattern)
	FactGrantedServiceSuffix = "granted_service_suffix"

	// FactGrantedServicePrefix allows access to services matching a prefix pattern (e.g. calculator.*).
	// Contains: biscuit.String(serviceType), biscuit.String(prefixPattern)
	FactGrantedServicePrefix = "granted_service_prefix"

	// FactGrantedServiceExact allows access to a specific service type and target.
	// Contains: biscuit.String(serviceType), biscuit.String(targetName)
	// Example Datalog: allow if service("mcp", "calculator"), granted_service_exact("mcp", "calculator")
	FactGrantedServiceExact = "granted_service_exact"

	// FactGrantedServiceSet allows access to a Set of exact service names under a specific service
	// type. This lets many exact grants for the same type be carried as a single Datalog fact instead
	// of one fact per entry, which keeps token/world fact counts flat regardless of list length.
	// Contains: biscuit.String(serviceType), biscuit.Set of biscuit.String(serviceName)
	// Example Datalog: allow if service("mcp", "calculator"), granted_service_set("mcp", $set), $set.contains("calculator")
	FactGrantedServiceSet = "granted_service_set"

	// FactGrantedTargetAllTypes allows target access to all network targets (unrestricted).
	// Contains: biscuit.Bool(true) (marker fact)
	FactGrantedTargetAllTypes = "granted_target_all_types"

	// FactGrantedTargetAll allows target access to all values of a specific fact.
	// Contains: biscuit.String(factName) (e.g., "group")
	FactGrantedTargetAll = "granted_target_all"

	// FactGrantedTargetSuffix allows target access to values matching a suffix pattern.
	// Contains: biscuit.String(factName), biscuit.String(suffixPattern)
	FactGrantedTargetSuffix = "granted_target_suffix"

	// FactGrantedTargetPrefix allows target access to values matching a prefix pattern.
	// Contains: biscuit.String(factName), biscuit.String(prefixPattern)
	FactGrantedTargetPrefix = "granted_target_prefix"

	// FactGrantedTargetExact allows target access to a specific fact name and value combination.
	// Contains: biscuit.String(factName), biscuit.String(factValue)
	// Example Datalog: allow_network_target("group", "backend") <- target_fact("group", "backend"), granted_target_exact("group", "backend")
	FactGrantedTargetExact = "granted_target_exact"

	// FactGrantedTargetAllFacts allows target access to any fact name and value combination.
	// Contains: biscuit.Bool(true) (marker fact)
	FactGrantedTargetAllFacts = "granted_target_all_facts"

	// FactGrantedTargetSet allows target access to a Set of exact values for a specific fact name.
	// This lets many exact target grants for the same fact name be carried as a single Datalog fact
	// instead of one fact per entry, which keeps token/world fact counts flat regardless of list length.
	// Contains: biscuit.String(factName), biscuit.Set of biscuit.String(factValue)
	FactGrantedTargetSet = "granted_target_set"

	// FactConnectionPeerID defines the actual PeerID of the remote peer making the connection.
	// Contains: biscuit.String(connectionPeerID)
	// Example Datalog: check if client_peer_id($id), connection_peer_id($id)
	FactConnectionPeerID = "connection_peer_id"

	// FactTargetFact normalizes identity assertions (claims, node, user) to a standardized target.
	// Contains: biscuit.String(factName), biscuit.String(factValue)
	// Example Datalog: target_fact("group", $val) <- group($val)
	FactTargetFact = "target_fact"

	// FactAllowNetworkTarget evaluates whether a target assertion meets the token access grants.
	// Contains: biscuit.String(factName), biscuit.String(factValue)
	// Example Datalog: allow_network_target("group", "backend")
	FactAllowNetworkTarget = "allow_network_target"

	// FactTargetUnrestricted indicates that target authorization checks are bypassed.
	// Contains: biscuit.Bool(true) (marker fact)
	// Example Datalog: check if allow_network_target($fact, $val) or target_unrestricted(true)
	FactTargetUnrestricted = "target_unrestricted"

	// FactTargetRestricted indicates that target authorization checks must be enforced.
	// Contains: biscuit.Bool(true) (marker fact)
	FactTargetRestricted = "target_restricted"

	// FactService represents the service target that a node is requesting access to.
	// Contains: biscuit.String(serviceType), biscuit.String(serviceName)
	// Example Datalog: service("mcp", "calculator")
	FactService = "service"

	// Request facts. The verifying node injects them from the request on the
	// wire, never from the token, so a holder cannot assert them. They are
	// present when the node handles the request as HTTP, and absent on a
	// stream that carries no HTTP request.

	// FactMethod is the HTTP method of the request as received, or "CONNECT"
	// for a tunnel the node opens without terminating HTTP.
	// Contains: biscuit.String(method)
	// Example Datalog: deny if method($m), !($m == "GET")
	FactMethod = "method"

	// FactPath is the request path as the backend sees it: leading slash, no
	// query, with the mesh routing prefix removed. A tunnel carries path("").
	// Contains: biscuit.String(path)
	// Example Datalog: deny if path($p), !$p.starts_with("/v2/public/")
	FactPath = "path"

	// FactHost is the destination hostname of an egress request, lowercase,
	// as authorized: the same string as the service name.
	// Contains: biscuit.String(host)
	// Example Datalog: deny if host("payroll.internal.example.com")
	FactHost = "host"

	// FactPort is the destination port of an egress request.
	// Contains: biscuit.Integer(port)
	// Example Datalog: deny if port($p), !($p == 443)
	FactPort = "port"

	// HTTP narrowing (PolicyRole.http). A narrowed allowed_services entry is
	// minted as an http_granted_service_* fact instead of the plain
	// granted_service_* one, together with the methods and paths it permits.
	// BaselineHTTPRules derive the plain grant only for a request whose
	// method() and path() facts match, so the ordinary allow policies apply
	// unchanged and a request without those facts matches nothing.
	//
	// Every fact below is keyed by ($type, $key), where $key is the term the
	// corresponding granted_service_* fact would carry: the exact name, the
	// suffix with its leading dot, the prefix with its trailing dot, or "*".

	// FactHTTPGrantedServiceExact is granted_service_exact, narrowed.
	// Contains: biscuit.String(serviceType), biscuit.String(serviceName)
	FactHTTPGrantedServiceExact = "http_granted_service_exact"

	// FactHTTPGrantedServiceSuffix is granted_service_suffix, narrowed.
	// Contains: biscuit.String(serviceType), biscuit.String(suffixPattern)
	FactHTTPGrantedServiceSuffix = "http_granted_service_suffix"

	// FactHTTPGrantedServicePrefix is granted_service_prefix, narrowed.
	// Contains: biscuit.String(serviceType), biscuit.String(prefixPattern)
	FactHTTPGrantedServicePrefix = "http_granted_service_prefix"

	// FactHTTPGrantedServiceAll is granted_service_all, narrowed. Its key is "*".
	// Contains: biscuit.String(serviceType)
	FactHTTPGrantedServiceAll = "http_granted_service_all"

	// FactHTTPGrantedServiceAllTypes is granted_service_all_types, narrowed.
	// Its type and key are both "*".
	// Contains: biscuit.Bool(true) (marker fact)
	FactHTTPGrantedServiceAllTypes = "http_granted_service_all_types"

	// FactGrantedMethod lists the methods a narrowed grant permits.
	// Contains: biscuit.String(serviceType), biscuit.String(key), biscuit.Set of biscuit.String(method)
	FactGrantedMethod = "granted_method"

	// FactGrantedMethodAny marks a narrowed grant that permits every method.
	// Contains: biscuit.String(serviceType), biscuit.String(key)
	FactGrantedMethodAny = "granted_method_any"

	// FactGrantedPathExact lists the exact paths a narrowed grant permits.
	// Contains: biscuit.String(serviceType), biscuit.String(key), biscuit.Set of biscuit.String(path)
	FactGrantedPathExact = "granted_path_exact"

	// FactGrantedPathPrefix permits every path under one prefix, one fact per prefix.
	// Contains: biscuit.String(serviceType), biscuit.String(key), biscuit.String(prefix)
	FactGrantedPathPrefix = "granted_path_prefix"

	// FactGrantedPathAny marks a narrowed grant that permits every path.
	// Contains: biscuit.String(serviceType), biscuit.String(key)
	FactGrantedPathAny = "granted_path_any"

	// FactHTTPMethodOK is derived when the request method satisfies a narrowed grant.
	// Contains: biscuit.String(serviceType), biscuit.String(key)
	FactHTTPMethodOK = "http_method_ok"

	// FactHTTPPathOK is derived when the request path satisfies a narrowed grant.
	// Contains: biscuit.String(serviceType), biscuit.String(key)
	FactHTTPPathOK = "http_path_ok"

	// FactLabel is a control-plane-attested key=value label on the token's
	// node (see api/labels.go). The control plane mints one fact per
	// declared label, so a requirement is a single exact match: a node
	// attested with region="us-east-1" carries label("region", "us-east-1"),
	// satisfying `check if label("region", "us-east-1")` only — composition
	// across values is left entirely to the operator (attest as many labels
	// as needed). Distinct from the unauthenticated gossip routing hint
	// carried in ServiceAnnounce.labels.
	// Contains: biscuit.String(key), biscuit.String(value)
	// Example Datalog: check if label("region", "us-east-1")
	FactLabel = "label"

	// FactTime defines the current system time injected during evaluation.
	// Contains: biscuit.Date(currentTime)
	// Example Datalog: check if time($time)
	FactTime = "time"
)

// MarkerTerm is the single term every marker fact carries, written `true` in
// Datalog text. See MarkerFact.
var MarkerTerm biscuit.Term = biscuit.Bool(true)

// MarkerFact returns the presence-only fact name(true). The Biscuit grammar
// requires at least one term per predicate, so a fact whose only meaning is
// "this grant exists" carries MarkerTerm and is matched as name(true).
func MarkerFact(name string) biscuit.Fact {
	return biscuit.Fact{Predicate: biscuit.Predicate{Name: name, IDs: []biscuit.Term{MarkerTerm}}}
}

var oidcClaimToFact = map[string]string{
	"sub":    FactUser,
	"email":  FactEmail,
	"groups": FactGroup,
	"roles":  FactIdpRole,
}

// BindingMemberPrefixes are the fact names a policy binding member or an
// allowed_targets entry may name: the peer itself plus every OIDC claim the
// control plane mints. FactRole is deliberately absent: a binding on it would
// grant a mesh role from a mesh role.
func BindingMemberPrefixes() []string {
	names := []string{FactNode}
	for _, fact := range OIDCClaimToFact() {
		names = append(names, fact)
	}
	sort.Strings(names)
	return names
}

// OIDCClaimToFact returns a copy of the OIDC claims to Biscuit facts map.
// This ensures that the global map is immutable and thread-safe for concurrent readers.
func OIDCClaimToFact() map[string]string {
	return maps.Clone(oidcClaimToFact)
}

// TargetFactNames returns the fact names an allowed_targets entry can use.
//
// It is derived from the same source as TargetFactRules, which is the point: a
// target naming any other fact mints a granted_target_* fact that no
// target_fact will ever match, so the grant silently denies instead of failing
// at config time. Deriving both from one place keeps them from drifting apart.
func TargetFactNames() []string {
	names := []string{FactNode}
	for _, fact := range OIDCClaimToFact() {
		names = append(names, fact)
	}
	sort.Strings(names)
	return names
}

var (
	// BaselinePolicies are the pre-compiled authorization policies for the node middleware.
	BaselinePolicies []biscuit.Policy

	// BaselineRules are the pre-compiled target evaluation rules for the node middleware.
	BaselineRules []biscuit.Rule

	// BaselineHTTPRules derive the plain granted_service_* facts from the
	// http_granted_service_* facts of a narrowed grant when the request's
	// method() and path() satisfy it. Added wherever BaselineRules are.
	BaselineHTTPRules []biscuit.Rule

	// BaselineReplayCheck verifies that the client peer ID matches the connection peer ID.
	BaselineReplayCheck biscuit.Check

	// BaselineTargetCheck verifies that the target matches one of the allowed network targets.
	BaselineTargetCheck biscuit.Check

	// TargetFactRules maps node and OIDC claims to target_fact datalog facts.
	TargetFactRules []biscuit.Rule

	// ControlPlaneStaticTimeCheck is the standard check for verifying a Biscuit's
	// own expiration() fact. Every path that admits a token must add it together
	// with a FactTime fact; see identity.EnforceExpiration.
	ControlPlaneStaticTimeCheck biscuit.Check

	// AllowIfTruePolicy is the static policy "allow if true" used during token verification.
	AllowIfTruePolicy biscuit.Policy

	// BaselineSources is the Datalog text every variable above is parsed from.
	// The SDKs embed this text (see hack/gen-sdk-datalog) so that a provider
	// written in another language evaluates the same authorizer as sam-node.
	BaselineSources DatalogSources
)

// DatalogSources is the source text of the baseline Datalog, one string per
// item, in the form every Biscuit implementation parses.
type DatalogSources struct {
	// Policies are the service allow policies (BaselinePolicies).
	Policies []string `json:"policies"`
	// Rules derive allow_network_target from target grants (BaselineRules).
	Rules []string `json:"rules"`
	// HTTPRules derive service grants from narrowed grants (BaselineHTTPRules).
	HTTPRules []string `json:"http_rules"`
	// TargetFactRules map identity facts to target_fact (TargetFactRules).
	TargetFactRules []string `json:"target_fact_rules"`
	// ReplayCheck is BaselineReplayCheck.
	ReplayCheck string `json:"replay_check"`
	// TargetCheck is BaselineTargetCheck.
	TargetCheck string `json:"target_check"`
	// TimeCheck is ControlPlaneStaticTimeCheck.
	TimeCheck string `json:"time_check"`
	// AllowIfTrue is AllowIfTruePolicy.
	AllowIfTrue string `json:"allow_if_true"`
}

func init() {
	// 1. Service Allow Policies
	BaselineSources.Policies = []string{
		// Exact Match: Allows access if the token possesses a granted_service_exact fact
		// that perfectly matches both the protocol type (e.g. "mcp") and the service name (e.g. "calculator").
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $name)`, FactService, FactGrantedServiceExact),

		// Exact Set Match: Allows access if the token possesses a granted_service_set fact for the given
		// protocol type whose Set of names contains the requested service name.
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $set), $set.contains($name)`, FactService, FactGrantedServiceSet),

		// Prefix Match: Allows access if the token possesses a granted_service_prefix fact
		// for the given protocol type, and the requested service name starts with that prefix.
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $prefix), $name.starts_with($prefix)`, FactService, FactGrantedServicePrefix),

		// Suffix Match: Allows access if the token possesses a granted_service_suffix fact
		// for the given protocol type, and the requested service name ends with that suffix.
		fmt.Sprintf(`allow if %s($type, $name), %s($type, $suffix), $name.ends_with($suffix)`, FactService, FactGrantedServiceSuffix),

		// Type Wildcard: Allows access if the token possesses a granted_service_all fact
		// for the given protocol type, granting access to ANY service name within that namespace.
		fmt.Sprintf(`allow if %s($type, $name), %s($type)`, FactService, FactGrantedServiceAll),

		// Global Wildcard: Allows access if the token possesses a granted_service_all_types fact,
		// granting access to literally any service in any namespace (equivalent to '*').
		fmt.Sprintf(`allow if %s($type, $name), %s(true)`, FactService, FactGrantedServiceAllTypes),
	}

	for i, pStr := range BaselineSources.Policies {
		p, err := parser.FromStringPolicy(pStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse baseline policy %d: %v", i, err))
		}
		BaselinePolicies = append(BaselinePolicies, p)
	}

	// 2. Target Evaluation Rules
	// These rules satisfy the check if allow_network_target($fact, $val) injected by the control plane.
	BaselineSources.Rules = []string{
		// Exact Match: Derives allow_network_target if the token has a granted_target_exact fact matching a target_fact exactly.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $val)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetExact),

		// Exact Set Match: Derives allow_network_target if the token has a granted_target_set fact for the
		// given fact name whose Set of values contains the target_fact value.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $set), $set.contains($val)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetSet),

		// Prefix Match: Derives allow_network_target if the token has a granted_target_prefix fact and the target_fact value starts with that prefix.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $prefix), $val.starts_with($prefix)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetPrefix),

		// Suffix Match: Derives allow_network_target if the token has a granted_target_suffix fact and the target_fact value ends with that suffix.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact, $suffix), $val.ends_with($suffix)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetSuffix),

		// Wildcard Fact Match: Derives allow_network_target if the token has a granted_target_all fact for a specific fact name (e.g. all values for "group").
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s($fact)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetAll),

		// Global Wildcard Match: Derives allow_network_target if the token has a granted_target_all_facts fact, unconditionally allowing any target_fact.
		fmt.Sprintf(`%s($fact, $val) <- %s($fact, $val), %s(true)`, FactAllowNetworkTarget, FactTargetFact, FactGrantedTargetAllFacts),
	}

	for i, rStr := range BaselineSources.Rules {
		r, err := parser.FromStringRule(rStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse baseline rule %d: %v", i, err))
		}
		BaselineRules = append(BaselineRules, r)
	}

	// 2b. HTTP Narrowing Rules (PolicyRole.http).
	// A narrowed grant yields the plain granted_service_* fact only when the
	// request's method and path match, so the allow policies above decide as
	// they do for any grant. Both axes must hold; an axis with no restriction
	// carries the *_any marker. The rules are positive, so a request with no
	// method() or path() fact derives nothing and a narrowed grant fails closed.
	BaselineSources.HTTPRules = []string{
		fmt.Sprintf(`%s($t, $k) <- %s($m), %s($t, $k, $set), $set.contains($m)`, FactHTTPMethodOK, FactMethod, FactGrantedMethod),
		fmt.Sprintf(`%s($t, $k) <- %s($t, $k)`, FactHTTPMethodOK, FactGrantedMethodAny),
		fmt.Sprintf(`%s($t, $k) <- %s($p), %s($t, $k, $set), $set.contains($p)`, FactHTTPPathOK, FactPath, FactGrantedPathExact),
		fmt.Sprintf(`%s($t, $k) <- %s($p), %s($t, $k, $prefix), $p.starts_with($prefix)`, FactHTTPPathOK, FactPath, FactGrantedPathPrefix),
		fmt.Sprintf(`%s($t, $k) <- %s($t, $k)`, FactHTTPPathOK, FactGrantedPathAny),
		fmt.Sprintf(`%s($t, $n) <- %s($t, $n), %s($t, $n), %s($t, $n), %s($t, $n)`, FactGrantedServiceExact, FactService, FactHTTPGrantedServiceExact, FactHTTPMethodOK, FactHTTPPathOK),
		fmt.Sprintf(`%s($t, $s) <- %s($t, $n), %s($t, $s), $n.ends_with($s), %s($t, $s), %s($t, $s)`, FactGrantedServiceSuffix, FactService, FactHTTPGrantedServiceSuffix, FactHTTPMethodOK, FactHTTPPathOK),
		fmt.Sprintf(`%s($t, $p) <- %s($t, $n), %s($t, $p), $n.starts_with($p), %s($t, $p), %s($t, $p)`, FactGrantedServicePrefix, FactService, FactHTTPGrantedServicePrefix, FactHTTPMethodOK, FactHTTPPathOK),
		fmt.Sprintf(`%s($t) <- %s($t, $n), %s($t), %s($t, "*"), %s($t, "*")`, FactGrantedServiceAll, FactService, FactHTTPGrantedServiceAll, FactHTTPMethodOK, FactHTTPPathOK),
		fmt.Sprintf(`%s(true) <- %s($t, $n), %s(true), %s("*", "*"), %s("*", "*")`, FactGrantedServiceAllTypes, FactService, FactHTTPGrantedServiceAllTypes, FactHTTPMethodOK, FactHTTPPathOK),
	}

	for i, rStr := range BaselineSources.HTTPRules {
		r, err := parser.FromStringRule(rStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse baseline http rule %d: %v", i, err))
		}
		BaselineHTTPRules = append(BaselineHTTPRules, r)
	}

	var err error

	// BaselineReplayCheck prevents token theft/replay by ensuring the client_peer_id fact (embedded by the control plane during issuance)
	// perfectly matches the connection_peer_id fact (provided by the local node verifying the incoming libp2p connection).
	BaselineSources.ReplayCheck = fmt.Sprintf(`check if %s($id), %s($id)`, FactClientPeerID, FactConnectionPeerID)
	BaselineReplayCheck, err = parser.FromStringCheck(BaselineSources.ReplayCheck)
	if err != nil {
		panic(fmt.Sprintf("failed to parse replay check: %v", err))
	}

	// BaselineTargetCheck enforces network target restrictions. The token must either have an unrestricted target,
	// or one of the Target Evaluation Rules must have successfully derived an allow_network_target fact.
	BaselineSources.TargetCheck = fmt.Sprintf(`check if %s($fact, $val) or %s(true)`, FactAllowNetworkTarget, FactTargetUnrestricted)
	BaselineTargetCheck, err = parser.FromStringCheck(BaselineSources.TargetCheck)
	if err != nil {
		panic(fmt.Sprintf("failed to parse target check: %v", err))
	}

	// OIDC Claims to Target Facts: Maps dynamically generated OIDC facts (like `user("alice")`)
	// into standard `target_fact("user", "alice")` facts for unified evaluation against network target policies.
	// Node PeerID Target Fact: Ensures the target node's PeerID is also evaluated as a standard target_fact.
	for _, name := range TargetFactNames() {
		BaselineSources.TargetFactRules = append(BaselineSources.TargetFactRules, fmt.Sprintf(`%s(%q, $val) <- %s($val)`, FactTargetFact, name, name))
	}
	for _, ruleStr := range BaselineSources.TargetFactRules {
		r, err := parser.FromStringRule(ruleStr)
		if err != nil {
			panic(fmt.Sprintf("failed to parse target fact rule: %v", err))
		}
		TargetFactRules = append(TargetFactRules, r)
	}

	// ControlPlaneStaticTimeCheck ensures the token is not expired at the time of evaluation.
	BaselineSources.TimeCheck = fmt.Sprintf(`check if %s($time), %s($exp), $time <= $exp`, FactTime, FactExpiration)
	ControlPlaneStaticTimeCheck, err = parser.FromStringCheck(BaselineSources.TimeCheck)
	if err != nil {
		panic(fmt.Sprintf("failed to parse static time check: %v", err))
	}

	// AllowIfTruePolicy is a permissive fallback policy used when explicit local node policies are omitted.
	// Note that this does NOT mean all requests are automatically allowed. Biscuit requires at least one policy
	// to evaluate to true AND all checks to pass. This simply satisfies the policy requirement, effectively
	// deferring entirely to the control plane's checks and granted facts without imposing extra local restrictions.
	BaselineSources.AllowIfTrue = "allow if true"
	AllowIfTruePolicy, err = parser.FromStringPolicy(BaselineSources.AllowIfTrue)
	if err != nil {
		panic(fmt.Sprintf("failed to parse static allow policy: %v", err))
	}
}

// BuildServiceDatalogFact translates a service pattern string into a Datalog Fact.
func BuildServiceDatalogFact(serviceStr string) biscuit.Fact {
	svcType, svcName := ParseServiceTarget(serviceStr)
	if svcType == "*" && svcName == "*" {
		return MarkerFact(FactGrantedServiceAllTypes)
	} else if svcName == "*" {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServiceAll,
			IDs:  []biscuit.Term{biscuit.String(svcType)},
		}}
	} else if strings.HasPrefix(svcName, "*.") {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServiceSuffix,
			IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(svcName[1:])},
		}}
	} else if strings.HasSuffix(svcName, ".*") {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServicePrefix,
			IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(svcName[:len(svcName)-1])},
		}}
	}
	return biscuit.Fact{Predicate: biscuit.Predicate{
		Name: FactGrantedServiceExact,
		IDs:  []biscuit.Term{biscuit.String(svcType), biscuit.String(svcName)},
	}}
}

// BuildTargetDatalogFact translates a target pattern string into a Datalog Fact.
func BuildTargetDatalogFact(targetStr string) biscuit.Fact {
	tFact, tVal := ParseServiceTarget(targetStr)
	if tFact == "" {
		tFact = FactNode
	}
	if tFact == "*" && tVal == "*" {
		return MarkerFact(FactGrantedTargetAllFacts)
	} else if tVal == "*" {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetAll,
			IDs:  []biscuit.Term{biscuit.String(tFact)},
		}}
	} else if strings.HasPrefix(tVal, "*.") {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetSuffix,
			IDs:  []biscuit.Term{biscuit.String(tFact), biscuit.String(tVal[1:])},
		}}
	} else if strings.HasSuffix(tVal, ".*") {
		return biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetPrefix,
			IDs:  []biscuit.Term{biscuit.String(tFact), biscuit.String(tVal[:len(tVal)-1])},
		}}
	}
	return biscuit.Fact{Predicate: biscuit.Predicate{
		Name: FactGrantedTargetExact,
		IDs:  []biscuit.Term{biscuit.String(tFact), biscuit.String(tVal)},
	}}
}

// LabelFacts materializes a label set as one Datalog fact per key=value
// pair (see FactLabel). Keys are sorted for deterministic fact ordering. An
// empty set returns nil.
func LabelFacts(labels map[string]string) []biscuit.Fact {
	if len(labels) == 0 {
		return nil
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	facts := make([]biscuit.Fact, 0, len(labels))
	for _, k := range keys {
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactLabel,
			IDs:  []biscuit.Term{biscuit.String(k), biscuit.String(labels[k])},
		}})
	}
	return facts
}

// LabelCheck compiles a required label set (canonical, pre-validated with
// ValidateLabels) into a single fail-closed check satisfied only when the
// token carries *every* pair: `check if label("jurisdiction", "eu"),
// label("compliance", "gdpr")`.
//
// The same rule serves a caller's requirement (X-Sam-Required-Labels, an
// SDK's required labels) and an operator's egress floor (Egress.RequireLabels).
// A map gives one value per key, so neither can spell an alternative, and
// listing several pairs narrows the set of acceptable peers, as it does in
// every label selector a reader is likely to know. A disjunction would let
// a peer attesting the most permissive pair stand in for the rest, and a
// caller who read the list as a conjunction would send data to a peer that
// lacks a property they required, with no error to tell them.
//
// A requirement and a floor are combined by adding one check each to the
// authorizer, which ANDs them; neither needs to know about the other.
func LabelCheck(required map[string]string) (biscuit.Check, error) {
	if len(required) == 0 {
		return biscuit.Check{}, fmt.Errorf("no required labels")
	}
	keys := make([]string, 0, len(required))
	for k := range required {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	clauses := make([]string, 0, len(required))
	for _, k := range keys {
		if err := ValidateLabelKey(k); err != nil {
			return biscuit.Check{}, err
		}
		v := required[k]
		if err := ValidateLabelValue(v); err != nil {
			return biscuit.Check{}, err
		}
		clauses = append(clauses, fmt.Sprintf("%s(%q, %q)", FactLabel, k, v))
	}
	return parser.FromStringCheck("check if " + strings.Join(clauses, ", "))
}

// LabelsSatisfy reports whether claimed carries every pair of required. It is
// the non-attested counterpart of LabelCheck, for the one provider class that
// has no Biscuit to check: a service local to this node, whose labels are its
// own configuration and so are complete. An empty requirement is satisfied by
// anything, so callers may pass one unconditionally.
func LabelsSatisfy(required, claimed map[string]string) bool {
	for k, v := range required {
		if claimed[k] != v {
			return false
		}
	}
	return true
}

// LabelsContradict reports whether claimed states a *different* value for
// some key required names.
//
// Absence is not contradiction, which is the whole distinction from
// LabelsSatisfy. Gossiped claims are a discovery hint and may carry only part
// of what a peer attests, so a peer silent on one pair may still satisfy all
// of them in its Biscuit. Only a conflicting value is grounds to skip such a
// peer before the gate has seen its attested facts; treating silence as
// failure would drop providers that are inside the boundary.
func LabelsContradict(required, claimed map[string]string) bool {
	for k, v := range required {
		if got, stated := claimed[k]; stated && got != v {
			return true
		}
	}
	return false
}

// isExactService reports whether serviceStr resolves to a plain exact-match grant, as opposed to a
// wildcard/prefix/suffix pattern which already collapses to a single, cheap fact via BuildServiceDatalogFact.
// The classification is asked of BuildServiceDatalogFact rather than repeated here: a new wildcard shape
// added to one and not the other would freeze a wildcard grant into a set, where only exact contains()
// matches it, and it would silently grant nothing.
func isExactService(serviceStr string) (svcType, svcName string, exact bool) {
	svcType, svcName = ParseServiceTarget(serviceStr)
	return svcType, svcName, BuildServiceDatalogFact(serviceStr).Name == FactGrantedServiceExact
}

// isExactTarget reports whether targetStr resolves to a plain exact-match grant, as opposed to a
// wildcard/prefix/suffix pattern which already collapses to a single, cheap fact via BuildTargetDatalogFact.
// See isExactService for why the classification is asked of the builder instead of repeated.
func isExactTarget(targetStr string) (tFact, tVal string, exact bool) {
	tFact, tVal = ParseServiceTarget(targetStr)
	if tFact == "" {
		tFact = FactNode
	}
	return tFact, tVal, BuildTargetDatalogFact(targetStr).Name == FactGrantedTargetExact
}

// BuildServiceDatalogFacts translates a list of service patterns into a minimal set of Datalog facts.
// Exact-match entries are grouped by service type into a single granted_service_set fact each, so
// token/world fact counts stay flat regardless of how many exact services a role grants. Wildcard,
// prefix and suffix entries keep their existing one-fact-per-entry representation via
// BuildServiceDatalogFact, since those already collapse to a single fact per entry.
func BuildServiceDatalogFacts(services []string) []biscuit.Fact {
	facts := make([]biscuit.Fact, 0, len(services))
	exactByType := make(map[string]map[string]bool)
	var types []string
	for _, svc := range services {
		svcType, svcName, exact := isExactService(svc)
		if !exact {
			facts = append(facts, BuildServiceDatalogFact(svc))
			continue
		}
		if _, ok := exactByType[svcType]; !ok {
			exactByType[svcType] = make(map[string]bool)
			types = append(types, svcType)
		}
		exactByType[svcType][svcName] = true
	}
	sort.Strings(types)
	for _, svcType := range types {
		names := make([]string, 0, len(exactByType[svcType]))
		for name := range exactByType[svcType] {
			names = append(names, name)
		}
		sort.Strings(names)
		bset := make(biscuit.Set, 0, len(names))
		for _, name := range names {
			bset = append(bset, biscuit.String(name))
		}
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedServiceSet,
			IDs:  []biscuit.Term{biscuit.String(svcType), bset},
		}})
	}
	return facts
}

// BuildTargetDatalogFacts translates a list of target patterns into a minimal set of Datalog facts.
// Exact-match entries are grouped by fact name into a single granted_target_set fact each, so
// token/world fact counts stay flat regardless of how many exact targets a role grants. Wildcard,
// prefix and suffix entries keep their existing one-fact-per-entry representation via
// BuildTargetDatalogFact, since those already collapse to a single fact per entry.
func BuildTargetDatalogFacts(targets []string) []biscuit.Fact {
	facts := make([]biscuit.Fact, 0, len(targets))
	exactByFact := make(map[string]map[string]bool)
	var factNames []string
	for _, t := range targets {
		tFact, tVal, exact := isExactTarget(t)
		if !exact {
			facts = append(facts, BuildTargetDatalogFact(t))
			continue
		}
		if _, ok := exactByFact[tFact]; !ok {
			exactByFact[tFact] = make(map[string]bool)
			factNames = append(factNames, tFact)
		}
		exactByFact[tFact][tVal] = true
	}
	sort.Strings(factNames)
	for _, tFact := range factNames {
		vals := make([]string, 0, len(exactByFact[tFact]))
		for val := range exactByFact[tFact] {
			vals = append(vals, val)
		}
		sort.Strings(vals)
		bset := make(biscuit.Set, 0, len(vals))
		for _, val := range vals {
			bset = append(bset, biscuit.String(val))
		}
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedTargetSet,
			IDs:  []biscuit.Term{biscuit.String(tFact), bset},
		}})
	}
	return facts
}
