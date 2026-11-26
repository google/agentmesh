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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/envoy"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// ExtProcMethodPath is the gRPC HTTP/2 path for Envoy ExternalProcessor.Process.
	ExtProcMethodPath = envoy.ExtProcMethodPath

	// upstreamCredentialTransportRule is the reason of a refused check: the
	// answer would carry the credential of an egress destination, and the
	// transport does not authenticate the caller as the gateway.
	upstreamCredentialTransportRule = "the upstream credential is returned only over the Unix socket (--socket-path) or to a verified client certificate (--tls-ca)"
)

type extAuthzCheckInput = envoy.CheckInput
type extAuthzCheckResult = envoy.CheckResult

// newNodeEnvoyGateway creates an Envoy ext_authz + ext_proc GatewayServer backed
// by this node's Biscuit PDP and credential broker.
func newNodeEnvoyGateway(node *AgentMeshNode) *envoy.GatewayServer {
	gw := envoy.NewGatewayServer(func(ctx context.Context, in envoy.CheckInput) envoy.CheckResult {
		return evaluateExtAuthz(ctx, node, in)
	})
	gw.TrustedTransport = fromTrustedTransport
	return gw
}

func handleExtAuthzHTTP(node *AgentMeshNode, w http.ResponseWriter, r *http.Request) {
	newNodeEnvoyGateway(node).HandleExtAuthzHTTP(w, r)
}

func inspectMCPHTTPRequestBody(r *http.Request) (string, bool, error) {
	return envoy.InspectMCPHTTPRequestBody(r)
}

func evaluateExtAuthz(ctx context.Context, node *AgentMeshNode, in extAuthzCheckInput) extAuthzCheckResult {
	if node == nil {
		return extAuthzCheckResult{
			Allowed:    false,
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "Service Unavailable: Node Not Initialized",
		}
	}

	rawBiscuit, status, err := extractAndVerifyExtAuthzBiscuit(ctx, node, in.Headers)
	if err != nil {
		return extAuthzCheckResult{
			Allowed:    false,
			HTTPStatus: status,
			Message:    err.Error(),
		}
	}

	claims, err := node.VerifyLocalBiscuit(rawBiscuit)
	if err != nil {
		return extAuthzCheckResult{
			Allowed:    false,
			HTTPStatus: http.StatusForbidden,
			Message:    fmt.Sprintf("Forbidden: %v", err),
		}
	}

	target, reqPath := resolveExtAuthzTarget(node, in)
	if target == "" {
		return extAuthzCheckResult{
			Allowed:    false,
			HTTPStatus: http.StatusForbidden,
			Message:    "Forbidden: unable to resolve target service",
		}
	}

	// Never trust an inbound X-Mesh-Peer-Id header. Unattenuated standing node
	// Biscuits (len(claims.TaskRules) == 0) must be bound to this local node's
	// peer ID; task-attenuated Biscuits (len(claims.TaskRules) > 0) presented
	// through an HTTP gateway PEP use the verified Block 0 client_peer_id.
	localPID, pErr := node.localPeerID()
	if pErr != nil || localPID == "" {
		return extAuthzCheckResult{
			Allowed:    false,
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "Service Unavailable: Node has no peer ID",
		}
	}
	callerPeer := localPID
	if len(claims.TaskRules) > 0 && claims.ClientPeerID != "" {
		pid, decErr := peer.Decode(claims.ClientPeerID)
		if decErr != nil {
			return extAuthzCheckResult{
				Allowed:    false,
				HTTPStatus: http.StatusBadRequest,
				Message:    "Invalid client_peer_id in token",
			}
		}
		callerPeer = pid
	}
	isLocal := callerPeer == localPID

	method := in.Method
	if method == "" {
		method = http.MethodGet
	}
	if reqPath == "" {
		reqPath = "/"
	}
	reqCtx := RequestContext{
		PeerID:             callerPeer,
		Protocol:           "ext_authz",
		Target:             target,
		MCPTool:            in.MCPTool,
		AllowMCPStreamInit: in.AllowMCPStreamInit,
		HTTP:               &HTTPRequestFacts{Method: method, Path: reqPath},
		Local:              isLocal,
	}
	if after, ok := strings.CutPrefix(target, api.EgressServicePrefix); ok {
		reqCtx.Egress = &EgressFacts{Host: after, Port: 443}
		if node.services != nil {
			if svc, ok := node.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, after); ok {
				if ef := egressFactsFor(svc); ef != nil {
					reqCtx.Egress = ef
				}
			}
		}
	}
	if err := node.VerifyBiscuitToken(rawBiscuit, reqCtx); err != nil {
		return extAuthzCheckResult{
			Allowed:    false,
			HTTPStatus: http.StatusForbidden,
			Message:    fmt.Sprintf("Forbidden: %v", err),
		}
	}

	respHeaders := map[string]string{
		api.HeaderMeshBiscuit:   base64.StdEncoding.EncodeToString(rawBiscuit),
		api.HeaderMeshPrincipal: claims.Principal(),
		api.HeaderMeshRoles:     strings.Join(claims.Roles, ","),
		api.HeaderMeshOrigin:    api.MeshOriginGateway,
	}
	if formattedClaims := api.FormatClaims(claims.Claims); formattedClaims != "" {
		respHeaders[api.HeaderMeshClaims] = formattedClaims
	}
	if formattedLabels := api.FormatLabels(claims.Labels); formattedLabels != "" {
		respHeaders[api.HeaderMeshLabels] = formattedLabels
	}
	actorNode := claims.ActorNodePeerID
	if actorNode == "" {
		actorNode = claims.NodePeerID
	}
	if actorNode == "" {
		actorNode = claims.ClientPeerID
	}
	if actorNode != "" {
		respHeaders[api.HeaderMeshActorNode] = actorNode
	}
	if len(claims.TaskRules) > 0 {
		lastRule := claims.TaskRules[len(claims.TaskRules)-1]
		if taskJSON, mErr := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(lastRule); mErr == nil {
			respHeaders[api.HeaderMeshTask] = string(taskJSON)
		}
		if lastRule.GetName() != "" {
			respHeaders[api.HeaderMeshTaskID] = lastRule.GetName()
		}
	}
	if after, ok := strings.CutPrefix(target, api.EgressServicePrefix); ok && node.services != nil {
		if svc, ok := node.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, after); ok {
			if es, ok := svc.(*EgressService); ok && es.exchanger != nil {
				// An application on the same host can send this check too.
				// Only the transport tells it from the gateway.
				if !in.TrustedTransport {
					logger.Warnf("[ExtAuthz] Check for %s by %s refused: %s", target, claims.Principal(), upstreamCredentialTransportRule)
					return extAuthzCheckResult{
						Allowed:    false,
						HTTPStatus: http.StatusForbidden,
						Message:    "Forbidden: " + upstreamCredentialTransportRule,
					}
				}
				authHdr, _, bErr := es.resolveAuthorization(WithCallerBiscuit(ctx, rawBiscuit))
				if bErr != nil {
					return extAuthzCheckResult{
						Allowed:    false,
						HTTPStatus: http.StatusBadGateway,
						Message:    fmt.Sprintf("egress credential broker failed: %v", bErr),
					}
				}
				if authHdr != "" {
					respHeaders["Authorization"] = authHdr
				}
			}
		}
	}

	return extAuthzCheckResult{
		Allowed:         true,
		HTTPStatus:      http.StatusOK,
		ResponseHeaders: respHeaders,
	}
}

func extractAndVerifyExtAuthzBiscuit(ctx context.Context, node *AgentMeshNode, headers map[string]string) ([]byte, int, error) {
	if rawB64 := strings.TrimSpace(headers[strings.ToLower(api.HeaderMeshBiscuit)]); rawB64 != "" {
		raw, err := decodeBiscuitToken(rawB64)
		if err != nil {
			return nil, http.StatusForbidden, fmt.Errorf("invalid %s header: %w", api.HeaderMeshBiscuit, err)
		}
		return raw, http.StatusOK, nil
	}

	var bearer string
	for _, h := range []string{strings.ToLower(api.HeaderMeshAuthentication), "authorization"} {
		val := strings.TrimSpace(headers[h])
		if val == "" {
			continue
		}
		parts := strings.SplitN(val, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			bearer = strings.TrimSpace(parts[1])
			break
		}
	}
	if bearer == "" {
		return nil, http.StatusUnauthorized, errors.New("unauthorized: missing Bearer token or X-Mesh-Biscuit header")
	}

	if raw, err := decodeBiscuitToken(bearer); err == nil {
		return raw, http.StatusOK, nil
	}
	if isLikelyJWT(bearer) {
		resp, err := node.ExchangeSubjectJWT(ctx, bearer, api.TokenTypeJWT, nil, false)
		if err != nil {
			return nil, http.StatusForbidden, fmt.Errorf("JWT token exchange failed: %w", err)
		}
		return resp.GetBiscuitToken(), http.StatusOK, nil
	}
	return nil, http.StatusForbidden, errors.New("forbidden: unrecognizable credential")
}

func isExtAuthzServiceScheme(scheme string) bool {
	switch scheme {
	case api.ServiceTypeStringMCP, api.ServiceTypeStringInference, api.ServiceTypeStringA2A, api.ServiceTypeStringEgress, "http":
		return true
	default:
		return false
	}
}

func resolveExtAuthzTarget(node *AgentMeshNode, in extAuthzCheckInput) (target, reqPath string) {
	path := in.Path
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if explicit := strings.TrimSpace(in.Headers[strings.ToLower(api.HeaderMeshTargetService)]); explicit != "" {
		scheme, name := api.ParseServiceTarget(explicit)
		scheme = strings.ToLower(scheme)
		if isExtAuthzServiceScheme(scheme) && name != "" {
			if scheme == api.ServiceTypeStringEgress {
				name = api.NormalizeMeshHost(name)
			}
			if name != "" {
				return scheme + "://" + name, path
			}
		}
		return "", path
	}
	trimmed := strings.TrimPrefix(path, "/mesh/")
	trimmed = strings.TrimPrefix(trimmed, "/")
	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) >= 2 {
		scheme := strings.ToLower(parts[0])
		if isExtAuthzServiceScheme(scheme) {
			name := parts[1]
			if scheme == api.ServiceTypeStringEgress {
				name = api.NormalizeMeshHost(name)
			}
			rest := "/"
			if len(parts) == 3 {
				rest = "/" + parts[2]
			}
			if name != "" {
				return scheme + "://" + name, rest
			}
		}
	}
	if strings.HasPrefix(path, "/mesh/") {
		if route, ok := parseEgressRoute(path); ok && isExtAuthzServiceScheme(route.serviceType) {
			up := "/" + route.upstreamPath
			return route.serviceType + "://" + route.serviceName, up
		}
	}
	if node != nil && node.services != nil && strings.TrimSpace(in.Host) != "" {
		normHost := api.NormalizeMeshHost(in.Host)
		if normHost != "" {
			if _, ok := node.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, normHost); ok {
				if path == "" {
					path = "/"
				}
				return api.EgressServicePrefix + normHost, path
			}
		}
	}
	return "", path
}
