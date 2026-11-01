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
	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

// MeshRequest is what a policy enforcement point knows about one request,
// whichever path it arrived on: a mesh stream from another member, the
// node's own sidecar, router external ingress, or the control plane's
// /sts/token. Every PEP turns its request into one of these and hands it to
// AuthorizeMeshRequest, so the facts and checks a credential is evaluated
// against are decided in one place and a rule added for one path reaches
// the others. The fields a path does not have stay at their zero value, and
// the zero value always means "not present", never "unrestricted".
type MeshRequest struct {
	// ServiceType and ServiceName are the service() fact: the service the
	// request targets, or (api.SystemNamespace, <protocol>) for a bare stream
	// that names no service.
	ServiceType string
	ServiceName string

	// HasHTTP reports whether Method and Path were carried on the wire. They
	// become method() and path() only then, so a grant narrowed to methods
	// and paths (PolicyRole.http) has nothing to match on a bare stream and
	// fails closed.
	HasHTTP bool
	Method  string
	Path    string

	// HasEgress reports whether the request is an egress call to
	// EgressHost:EgressPort, which become host() and port().
	HasEgress  bool
	EgressHost string
	EgressPort int64

	// Unrestricted adds target_unrestricted: the caller is this node's own
	// sidecar, or the verifier has no provider identity to match target
	// grants against (the control plane minting a border JWT).
	Unrestricted bool

	// ConnectionPeer, when set, is the libp2p peer the credential arrived
	// from: connection_peer_id() and BaselineReplayCheck then bind
	// client_peer_id to it, so an exfiltrated token cannot be replayed from
	// another peer. It stays empty for a bearer presented over HTTPS at the
	// border, where there is no libp2p connection to bind to
	// (security-architecture, section 5.2).
	ConnectionPeer peer.ID

	// MCPTool and AllowMCPStreamInit describe the MCP call for
	// TaskAuthorizationRule evaluation (TaskRequest).
	MCPTool            string
	AllowMCPStreamInit bool
}

// MeshPolicy is what the enforcement point adds to every evaluation on top
// of the credential: the provider's own target facts, its local attenuation,
// and the rules the control plane rendered from the mesh policy.
type MeshPolicy struct {
	// TargetFacts are target_fact(type, value) facts from the provider's own
	// credential (TargetFactsFromBiscuit); BaselineTargetCheck is always
	// added, so a caller whose grant names a target the provider does not
	// carry is refused, and so is every caller when the provider has none.
	TargetFacts []biscuit.Fact
	// LocalPolicies, LocalChecks and LocalRules are the enforcement point's
	// own attenuation (agentmesh-node.yaml, or a PEP's static rules).
	LocalPolicies []biscuit.Policy
	LocalChecks   []biscuit.Check
	LocalRules    []biscuit.Rule
	// MeshRules are PolicyConfigGetResponse.datalog_rules as parsed.
	MeshRules []biscuit.Rule
}

// AuthorizeMeshRequest loads req and pol into authorizer in the one order
// every enforcement point uses and runs it. The authorizer must already be
// built on the credential under the key that verified it; the caller
// checks revocation, bans and the authority-block binding before, and
// evaluates TaskAuthorizationRules (req.TaskRequest) after.
func AuthorizeMeshRequest(authorizer biscuit.Authorizer, req MeshRequest, pol MeshPolicy) error {
	authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactService,
		IDs:  []biscuit.Term{biscuit.String(req.ServiceType), biscuit.String(req.ServiceName)},
	}})
	if req.HasHTTP {
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactMethod,
			IDs:  []biscuit.Term{biscuit.String(req.Method)},
		}})
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactPath,
			IDs:  []biscuit.Term{biscuit.String(req.Path)},
		}})
	}
	if req.HasEgress {
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactHost,
			IDs:  []biscuit.Term{biscuit.String(req.EgressHost)},
		}})
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactPort,
			IDs:  []biscuit.Term{biscuit.Integer(req.EgressPort)},
		}})
	}
	if req.Unrestricted {
		authorizer.AddFact(api.MarkerFact(api.FactTargetUnrestricted))
	}
	if req.ConnectionPeer != "" {
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactConnectionPeerID,
			IDs:  []biscuit.Term{biscuit.String(req.ConnectionPeer.String())},
		}})
		authorizer.AddCheck(api.BaselineReplayCheck)
	}

	EnforceExpiration(authorizer)

	for _, f := range pol.TargetFacts {
		authorizer.AddFact(f)
	}
	authorizer.AddCheck(api.BaselineTargetCheck)

	for _, p := range pol.LocalPolicies {
		authorizer.AddPolicy(p)
	}
	for _, c := range pol.LocalChecks {
		authorizer.AddCheck(c)
	}
	for _, r := range pol.LocalRules {
		authorizer.AddRule(r)
	}

	for _, p := range api.BaselinePolicies {
		authorizer.AddPolicy(p)
	}
	for _, r := range api.BaselineRules {
		authorizer.AddRule(r)
	}
	for _, r := range api.BaselineHTTPRules {
		authorizer.AddRule(r)
	}
	for _, r := range pol.MeshRules {
		authorizer.AddRule(r)
	}

	return authorizer.Authorize()
}

// TaskRequest is req as TaskAuthorizationRule evaluation sees it, so the
// TAR intersection is computed from the same request on every path.
func (req MeshRequest) TaskRequest() api.TaskRequestContext {
	return api.TaskRequestContext{
		ServiceType:        req.ServiceType,
		ServiceName:        req.ServiceName,
		HasHTTP:            req.HasHTTP,
		Method:             req.Method,
		Path:               req.Path,
		MCPTool:            req.MCPTool,
		AllowMCPStreamInit: req.AllowMCPStreamInit,
	}
}
