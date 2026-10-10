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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/protocol"
)

// ============================================================================
// Libp2p Protocol & Network Constants
// ============================================================================

const (
	// EnrollProtocolID is the libp2p protocol identifier for node enrollment.
	EnrollProtocolID protocol.ID = "/mesh/enroll/1.0.0"

	// MCPProtocolID is the libp2p protocol identifier for Model Context Protocol streams.
	MCPProtocolID protocol.ID = "/mesh/mcp/1.0.0"

	// AuthProtocolID is the libp2p protocol identifier for the zero-trust auth handshake.
	AuthProtocolID protocol.ID = "/mesh/auth/1.0.0"

	// GossipEvents is the GossipSub topic used to broadcast mesh event updates (e.g., node bans).
	GossipEvents = "/mesh/events/v1"

	// GossipControlPlaneSync is the GossipSub topic used by the control plane to sync cluster state.
	GossipControlPlaneSync = "/mesh/control-plane/sync/v1"

	// DiscoveryTopicPrefix is the GossipSub topic namespace for interest-scoped
	// service announcements (ServiceAnnounce messages). Full topics are built
	// with DiscoveryTopic; the version segment allows wire evolution.
	DiscoveryTopicPrefix = "/mesh/discovery/v1"

	// DefaultAudience is the default audience string used in OIDC token validation.
	DefaultAudience = "agentmesh-audience"
)

// ============================================================================
// Token Lifespans & Session Constants
// ============================================================================

const (
	// BiscuitTokenTTL is the strict cryptographically enforced lifespan
	// of a minted Biscuit token (24 hours).
	// This is verified locally by each peer on every connection.
	BiscuitTokenTTL = 24 * time.Hour

	// OIDCSessionTTL is the default database-enforced lifespan of a node's OIDC
	// interactive enrollment session (90 days). After this period, the node
	// must re-authenticate with the OIDC provider to establish a new session.
	// Operators tune the cadence with the control plane's --oidc-session-ttl.
	OIDCSessionTTL = 90 * 24 * time.Hour

	// TokenRefreshCheckInterval is the frequency at which the node daemon and router check
	// if their current Biscuit token is close to expiration and needs to be proactively refreshed.
	TokenRefreshCheckInterval = 10 * time.Minute
)

// EnrollChallenge is the payload a bootstrap enrollee signs to prove
// possession of the private half of BootstrapEnrollRequest.public_key at
// POST /enroll, carried in that message's timestamp/challenge_signature
// fields. Binding the peer ID keeps a captured signature useless for any
// other peer; the domain prefix keeps it useless at any other endpoint.
func EnrollChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:enroll:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// EnrollStatusChallenge is the payload a bootstrap enrollee signs to prove
// possession of the key it submitted at /enroll when polling
// GET /enroll/status. ts is unix milliseconds; the signature travels in the
// HeaderChallengeSignature header (unpadded base64url) alongside
// HeaderChallengeTimestamp.
func EnrollStatusChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:enroll-status:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// RefreshChallenge is the payload an enrolled peer signs to prove possession
// of its identity key at POST /refresh, carried in TokenRefreshRequest's
// timestamp/challenge_signature fields alongside the expiring biscuit. Same
// shape as the other enrollment challenges: peer- and endpoint-bound, so a
// captured signature is useless anywhere else.
func RefreshChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:refresh:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// RegisterChallenge is the payload an OIDC enrollee signs to prove possession
// of EnrollRequest.public_key at POST /register, carried in that message's
// timestamp/challenge_signature fields. The JWT says who is asking; this says
// they hold the key they are binding.
func RegisterChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:register:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// RouterLeaseChallenge is the payload a router signs with its enrolled key at
// POST /routers/lease, carried in RouterLeaseRequest's
// timestamp/challenge_signature fields. The router's biscuit is not proof on
// its own: routers send it to every peer they authenticate.
func RouterLeaseChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:routers-lease:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// TokenExchangeChallenge is the payload an enrolled agentmesh-node signs with its
// identity key at POST /token/exchange to prove possession of the channel key
// that will carry the minted Delegated Session Biscuit.
func TokenExchangeChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:token-exchange:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// STSTokenChallenge is the payload an enrolled egress agentmesh-node signs with its
// identity key at POST /sts/token when asking the control plane to mint an
// ES256 border JWT for an outbound destination.
func STSTokenChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:sts-token:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// PoliciesChallenge is the payload an enrolled peer signs with its identity
// key at GET /policies in the HeaderChallengeTimestamp and
// HeaderChallengeSignature headers.
func PoliciesChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:policies:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// EgressChallenge is the payload an enrolled peer signs with its identity key
// at GET /egress in the HeaderChallengeTimestamp and HeaderChallengeSignature
// headers.
func EgressChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:egress:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// RevocationsChallenge is the payload an enrolled peer signs with its identity
// key at GET /revocations in the HeaderChallengeTimestamp and
// HeaderChallengeSignature headers.
func RevocationsChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:revocations:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// NodesCatalogChallenge is the payload an enrolled node signs with its
// identity key at POST /nodes/catalog in the HeaderChallengeTimestamp and
// HeaderChallengeSignature headers.
func NodesCatalogChallenge(peerID string, ts int64) []byte {
	return []byte("mesh:nodes-catalog:" + peerID + ":" + strconv.FormatInt(ts, 10))
}

// ErrStaleChallengeTimestampMessage is the stable substring returned in a 401
// response body when a signed challenge timestamp is outside the control
// plane's freshness window. Clients match this message to recompute
// challenge_unix_ms from the response's Date header and retry once.
const ErrStaleChallengeTimestampMessage = "stale or invalid challenge timestamp"

// ============================================================================
// OAuth 2.1 & RFC 8693 Token Exchange Constants
// ============================================================================

const (
	// GrantTypeTokenExchange is the RFC 8693 OAuth 2.0 Token Exchange grant type URI.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// GrantTypeAuthorizationCode is the standard OAuth 2.1 authorization_code grant type.
	GrantTypeAuthorizationCode = "authorization_code"

	// GrantTypeClientCredentials is the RFC 6749 client_credentials grant type.
	GrantTypeClientCredentials = "client_credentials"

	// GrantTypeJWTBearer is the RFC 7523 section 2.1 JWT authorization grant type URI.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// ClientAssertionTypeJWTBearer is the RFC 7523 section 2.2 client assertion type URI.
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// ClientAssertionTypeJWTSPIFFE is the client assertion type URI for a SPIFFE
	// JWT-SVID (draft-ietf-oauth-spiffe-client-auth).
	ClientAssertionTypeJWTSPIFFE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"

	// TokenTypeBiscuit is the token type URI identifying a Agent Mesh Biscuit token in RFC 8693 exchanges.
	TokenTypeBiscuit = "urn:agentmesh:params:oauth:token-type:biscuit"

	// TokenTypeJWT is the RFC 8693 JWT token type URI.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// TokenTypeIDToken is the RFC 8693 OIDC ID token type URI.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	// TokenTypeAccessToken is the RFC 8693 OAuth access token type URI.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// OAuthAuthorizationServerMetadata is the RFC 8414 document a token endpoint
// serves at /.well-known/oauth-authorization-server. Only the fields Agent Mesh
// populates are present; omitted RFC 8414 fields are optional there too.
type OAuthAuthorizationServerMetadata struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	RevocationEndpoint                     string   `json:"revocation_endpoint,omitempty"`
	JWKSURI                                string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported,omitempty"`
}

// OAuthProtectedResourceMetadata is the RFC 9728 document a resource server
// serves at /.well-known/oauth-protected-resource.
type OAuthProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
}

// ============================================================================
// Agent Mesh Custom HTTP Headers
// ============================================================================

const (
	// HeaderMeshBiscuit is the custom HTTP header used to carry the base64-encoded
	// Biscuit token containing the node's identity credentials when forwarding requests
	// over libp2p HTTP between nodes in the mesh.
	//
	// This header is internal to the Agent Mesh datapath and is stripped before requests
	// are forwarded to backend services.
	HeaderMeshBiscuit = "X-Mesh-Biscuit"

	// HeaderChallengeTimestamp and HeaderChallengeSignature carry the signed
	// freshness challenge on GET /enroll/status, GET /policies, GET /egress,
	// GET /revocations, and POST /nodes/catalog: unix milliseconds and an
	// unpadded base64url signature over the endpoint's challenge payload.
	// Headers rather than query parameters, so the signature never lands in
	// access logs, where it would be replayable for its freshness window.
	HeaderChallengeTimestamp = "X-Mesh-Challenge-Ts"
	HeaderChallengeSignature = "X-Mesh-Challenge-Sig"

	// HeaderPeerID carries the authenticated libp2p peer ID of the caller.
	// The mesh ingress handler stamps it after authorization succeeds,
	// overwriting any inbound value, so backend services get verified caller
	// attribution without parsing biscuits. The inference facade sets it the
	// same way for locally served requests.
	HeaderPeerID = "X-Peer-Id"

	// HeaderMeshAuthentication is the custom HTTP header used to authenticate a local
	// process to this node's sidecar API (the shared secret configured via
	// "--api-token-path" or the AGENTMESH_API_TOKEN environment variable). Using a
	// Agent Mesh-specific header name — instead of the standard
	// "Authorization" header — leaves "Authorization" free to always mean what
	// every HTTP client expects: the credential for the destination being called.
	// The sidecar strips this header before forwarding any request off-node, so
	// it never leaks to a remote peer or backend service.
	//
	// For compatibility with MCP clients that only support a plain "Authorization"
	// header, purely-local endpoints (that never forward it anywhere) also accept
	// "Authorization" as an alias. The egress/inference proxy does NOT: there,
	// "Authorization" is reserved exclusively for the destination's credential.
	HeaderMeshAuthentication = "X-Mesh-Authentication"

	// HeaderMeshNoTrailingSlash is the custom HTTP header set by the ingress handler
	// to indicate that the original request had no trailing slash.
	//
	// This helps backward-compatibility with services that strictly distinguish
	// between a root path "/" and an empty path "".
	HeaderMeshNoTrailingSlash = "X-Mesh-No-Trailing-Slash"

	// HeaderMeshRequiredLabels constrains an inference request on the sidecar's
	// OpenAI-compatible endpoints (/v1/*) to providers attested with every
	// pair of a comma-separated list of "key=value" label requirements (see
	// api/labels.go and LabelCheck); invalid entries are rejected with HTTP
	// 400. It can only narrow what mesh policy allows, never widen it. Absent
	// means any provider permitted by policy.
	//
	// Reserved as part of the sidecar contract; enforced by the provider
	// scorer. Label declarations are routing hints until attested via the
	// node's Biscuit (see api/labels.go).
	HeaderMeshRequiredLabels = "X-Mesh-Required-Labels"

	// HeaderMeshPrincipal, HeaderMeshRoles, HeaderMeshTask, and HeaderMeshTaskID carry
	// verified caller attribution injected by ext_authz or forwarded to an
	// operator inspection chain when forward_context is enabled.
	HeaderMeshPrincipal     = "X-Mesh-Principal"
	HeaderMeshRoles         = "X-Mesh-Roles"
	HeaderMeshTask          = "X-Mesh-Task"
	HeaderMeshTaskID        = "X-Mesh-Task-Id"
	HeaderMeshTargetService = "X-Mesh-Target-Service"
)

// ============================================================================
// Service Classification & Namespaces
// ============================================================================

const (
	// SystemNamespace is the namespace reserved for built-in mesh services and protocols.
	SystemNamespace = "mesh:system"

	// CatalogTarget is the special system service name used to retrieve tool catalogs.
	// In policy rules, it must be referred to explicitly as: system://mesh.catalog
	CatalogTarget = "mesh.catalog"

	// MCPServicePrefix is the scheme prefix for Model Context Protocol services.
	// Fully qualified MCP services use the URI format: mcp://<service-name>
	MCPServicePrefix = "mcp://"

	// InferenceServicePrefix is the scheme prefix for LLM Inference services.
	// Fully qualified inference services use the URI format: inference://<service-name>
	InferenceServicePrefix = "inference://"

	// EgressServicePrefix is the scheme prefix for destinations outside the
	// mesh, served by a node that enforces policy on them. The name is the
	// destination hostname: egress://api.github.com
	EgressServicePrefix = "egress://"
)

// ============================================================================
// Protocol Types & String Mappings
// ============================================================================

const (
	// ServiceTypeStringMCP is the string identifier for MCP services.
	ServiceTypeStringMCP = "mcp"

	// ServiceTypeStringInference is the string identifier for Inference services.
	ServiceTypeStringInference = "inference"

	// ServiceTypeStringA2A is the string identifier for A2A (Agent2Agent) services.
	ServiceTypeStringA2A = "a2a"

	// ServiceTypeStringEgress is the string identifier for egress destinations.
	ServiceTypeStringEgress = "egress"
)

// ParseServiceType converts a string identifier (e.g. from JSON or REST) to the ServiceType protobuf enum.
func ParseServiceType(s string) (ServiceType, error) {
	switch strings.ToLower(s) {
	case ServiceTypeStringMCP:
		return ServiceType_SERVICE_TYPE_MCP, nil
	case ServiceTypeStringInference:
		return ServiceType_SERVICE_TYPE_INFERENCE, nil
	case ServiceTypeStringA2A:
		return ServiceType_SERVICE_TYPE_A2A, nil
	case ServiceTypeStringEgress:
		return ServiceType_SERVICE_TYPE_EGRESS, nil
	default:
		return ServiceType_SERVICE_TYPE_UNSPECIFIED, fmt.Errorf("invalid service type: %s", s)
	}
}

// ServiceTypeToString converts a ServiceType protobuf enum back to its standard string identifier.
func ServiceTypeToString(t ServiceType) (string, error) {
	switch t {
	case ServiceType_SERVICE_TYPE_MCP:
		return ServiceTypeStringMCP, nil
	case ServiceType_SERVICE_TYPE_INFERENCE:
		return ServiceTypeStringInference, nil
	case ServiceType_SERVICE_TYPE_A2A:
		return ServiceTypeStringA2A, nil
	case ServiceType_SERVICE_TYPE_EGRESS:
		return ServiceTypeStringEgress, nil
	default:
		return "", fmt.Errorf("invalid or unspecified service type")
	}
}

// DiscoveryTopic returns the GossipSub topic for announcements about one
// routing key (a model ID for inference, a tool name for MCP). Keys are
// hashed so topic names stay bounded; consumers match exact keys from the
// ServiceAnnounce payload, so hash collisions only merge announcement
// streams, never routing decisions.
func DiscoveryTopic(t ServiceType, key string) (string, error) {
	typeStr, err := ServiceTypeToString(t)
	if err != nil {
		return "", err
	}
	if key == "" {
		return "", fmt.Errorf("discovery topic key cannot be empty")
	}
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s/%s/%s", DiscoveryTopicPrefix, typeStr, hex.EncodeToString(sum[:8])), nil
}

// ============================================================================
// Parsing & Routing Utilities
// ============================================================================

var (
	// rfc3986URIRegex is the exact regular expression provided by RFC 3986 Appendix B
	// for breaking down a well-formed URI reference into its components.
	// Reference: https://tools.ietf.org/html/rfc3986#appendix-B
	//
	// Breaking down the regex:
	//   ^(([^:/?#]+):)?   - Group 1 & 2: Scheme (optional, e.g. "mcp:")
	//   (//([^/?#]*))?    - Group 3 & 4: Authority (optional, e.g. "//my-service")
	//   ([^?#]*)          - Group 5: Path
	//   (\?([^#]*))?      - Group 6 & 7: Query (optional)
	//   (#(.*))?          - Group 8 & 9: Fragment (optional)
	rfc3986URIRegex = regexp.MustCompile(`^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?`)

	// dnsNameRegex is adapted from govalidator's DNSName pattern.
	// Reference: https://github.com/asaskevich/govalidator/blob/3dd3875e2b081a20d6eed935913a482fea14ecd0/patterns.go#L29
	// It is adapted to allow underscores and asterisks (wildcards).
	// The asterisk '*' can only be at the very beginning (e.g., "*.example.com") or at the very end (e.g., "example.*").
	dnsNameRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*(\.\*)?[\._]?$`)
)

// ParseServiceTarget parses a service target string into its type (scheme) and name components.
//
// Expected formats:
//   - Hierarchical service URIs: "scheme://name" (e.g., "mcp://my_service") or "scheme://name/path" (e.g., "mcp://my_service/tool").
//   - Target facts: "fact:value" (e.g., "group:backend" or "user:bob").
//   - Wildcards: "*" (maps type to "*" and name to "*").
//
// If no scheme/colon is present, it returns an empty string for the type and the full target as the name.
// No fallback namespace is applied; callers must be explicit.
func ParseServiceTarget(target string) (svcType, svcName string) {
	if target == "*" {
		return "*", "*"
	}

	if idx := strings.Index(target, "://"); idx >= 0 && !strings.Contains(target[:idx], ":") {
		matches := rfc3986URIRegex.FindStringSubmatch(target)
		if len(matches) < 6 {
			return "", target
		}
		scheme := matches[2]
		hasAuthority := matches[3] != ""
		authority := matches[4]
		path := matches[5]

		if scheme == "" || !hasAuthority {
			return "", target
		}
		name := authority
		if path != "" {
			name = authority + path
		}
		return scheme, name
	}

	parts := strings.SplitN(target, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", target
}

// SplitToolName splits a fully qualified MCP tool name into its target service URI
// and the original tool name.
//
// Expected format: "scheme://service/tool" (e.g., "mcp://my-service/my-tool").
// If the input is empty or invalid, it returns an error. No default fallback is applied.
func SplitToolName(toolName string) (targetService, originalToolName string, err error) {
	if toolName == "" {
		return "", "", fmt.Errorf("tool name cannot be empty")
	}

	matches := rfc3986URIRegex.FindStringSubmatch(toolName)
	if len(matches) < 6 {
		return "", "", fmt.Errorf("invalid namespaced tool name %q: must follow explicit URI format 'scheme://service/tool'", toolName)
	}

	scheme := matches[2]
	hasAuthority := matches[3] != ""
	authority := matches[4]
	path := matches[5]

	if scheme == "" || !hasAuthority || authority == "" || path == "" || path == "/" {
		return "", "", fmt.Errorf("invalid namespaced tool name %q: must follow explicit URI format 'scheme://service/tool'", toolName)
	}

	// Reject query parameters or fragments in the tool name
	if matches[6] != "" || matches[8] != "" {
		return "", "", fmt.Errorf("invalid namespaced tool name %q: queries and fragments are not allowed", toolName)
	}

	targetService = scheme + "://" + authority
	originalToolName = strings.TrimPrefix(path, "/")
	return targetService, originalToolName, nil
}
