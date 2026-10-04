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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// HeaderSamMCPTool lets an external proxy (or ext_proc filter) pass the
	// extracted MCP tool name during an ext_authz check.
	HeaderSamMCPTool = "X-Sam-Mcp-Tool"
)

type extAuthzCheckInput struct {
	Method  string
	Path    string
	Host    string
	Headers map[string]string
}

type extAuthzCheckResult struct {
	Allowed         bool
	HTTPStatus      int
	Message         string
	ResponseHeaders map[string]string
}

// handleExtAuthzHTTP implements Envoy's HTTP ext_authz check service on
// /ext_authz and /ext_authz/*.
func handleExtAuthzHTTP(node *SamNode, w http.ResponseWriter, r *http.Request) {
	headers := make(map[string]string, len(r.Header))
	for k, vals := range r.Header {
		if len(vals) > 0 {
			headers[strings.ToLower(k)] = vals[0]
		}
	}
	checkPath := strings.TrimPrefix(r.URL.Path, "/ext_authz")
	if origPath := headers["x-envoy-original-path"]; origPath != "" {
		checkPath = origPath
	} else if origPath := headers["x-original-path"]; origPath != "" {
		checkPath = origPath
	}
	if checkPath == "" {
		checkPath = "/"
	}
	method := r.Method
	if origMethod := headers["x-original-method"]; origMethod != "" {
		method = origMethod
	}

	res := evaluateExtAuthz(r.Context(), node, extAuthzCheckInput{
		Method:  method,
		Path:    checkPath,
		Host:    r.Host,
		Headers: headers,
	})
	if !res.Allowed {
		http.Error(w, res.Message, res.HTTPStatus)
		return
	}
	for k, v := range res.ResponseHeaders {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
}

// handleExtAuthzGRPC implements Envoy's gRPC ext_authz service
// (/envoy.service.auth.v3.Authorization/Check and v2) over HTTP/2 using
// standard protobuf wire encoding without external gRPC dependencies.
func handleExtAuthzGRPC(node *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer func() { _ = r.Body.Close() }()
	frame, err := readGRPCFrame(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err != nil {
		writeGRPCError(w, 3, fmt.Sprintf("invalid gRPC frame: %v", err)) // INVALID_ARGUMENT = 3
		return
	}
	in, err := unmarshalEnvoyCheckRequest(frame)
	if err != nil {
		writeGRPCError(w, 3, fmt.Sprintf("invalid CheckRequest: %v", err))
		return
	}
	res := evaluateExtAuthz(r.Context(), node, in)
	respPayload := marshalEnvoyCheckResponse(res)

	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(http.StatusOK)
	_ = writeGRPCFrame(w, respPayload)
	w.Header().Set("Grpc-Status", "0")
	w.Header().Set("Grpc-Message", "")
}

func evaluateExtAuthz(ctx context.Context, node *SamNode, in extAuthzCheckInput) extAuthzCheckResult {
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

	target, reqPath := resolveExtAuthzTarget(in)
	if target != "" {
		var callerPeer peer.ID
		var isLocal bool
		if peerHdr := in.Headers[strings.ToLower(api.HeaderPeerID)]; peerHdr != "" {
			if pid, pErr := peer.Decode(peerHdr); pErr == nil {
				callerPeer = pid
			}
		}
		if callerPeer == "" && claims.ActorNodePeerID != "" {
			if pid, pErr := peer.Decode(claims.ActorNodePeerID); pErr == nil {
				callerPeer = pid
			}
		}
		if callerPeer == "" && claims.NodePeerID != "" {
			if pid, pErr := peer.Decode(claims.NodePeerID); pErr == nil {
				callerPeer = pid
			}
		}
		if callerPeer == "" {
			if pid, pErr := node.localPeerID(); pErr == nil {
				callerPeer = pid
			}
			isLocal = true
		}
		if localPID, pErr := node.localPeerID(); pErr == nil && callerPeer == localPID {
			isLocal = true
		}

		method := in.Method
		if method == "" {
			method = http.MethodGet
		}
		if reqPath == "" {
			reqPath = "/"
		}
		reqCtx := RequestContext{
			PeerID:   callerPeer,
			Protocol: "ext_authz",
			Target:   target,
			MCPTool:  in.Headers[strings.ToLower(HeaderSamMCPTool)],
			HTTP:     &HTTPRequestFacts{Method: method, Path: reqPath},
			Local:    isLocal,
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
	}

	respHeaders := map[string]string{
		api.HeaderSamBiscuit:   base64.StdEncoding.EncodeToString(rawBiscuit),
		api.HeaderSamPrincipal: claims.Principal(),
		api.HeaderSamRoles:     strings.Join(claims.Roles, ","),
	}
	if len(claims.TaskRules) > 0 {
		lastRule := claims.TaskRules[len(claims.TaskRules)-1]
		if taskJSON, mErr := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(lastRule); mErr == nil {
			respHeaders[api.HeaderSamTask] = string(taskJSON)
		}
	}

	return extAuthzCheckResult{
		Allowed:         true,
		HTTPStatus:      http.StatusOK,
		ResponseHeaders: respHeaders,
	}
}

func extractAndVerifyExtAuthzBiscuit(ctx context.Context, node *SamNode, headers map[string]string) ([]byte, int, error) {
	if rawB64 := strings.TrimSpace(headers[strings.ToLower(api.HeaderSamBiscuit)]); rawB64 != "" {
		raw, err := decodeBiscuitToken(rawB64)
		if err != nil {
			return nil, http.StatusForbidden, fmt.Errorf("invalid %s header: %w", api.HeaderSamBiscuit, err)
		}
		return raw, http.StatusOK, nil
	}

	var bearer string
	for _, h := range []string{strings.ToLower(api.HeaderSamAuthentication), "authorization"} {
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
		return nil, http.StatusUnauthorized, errors.New("unauthorized: missing Bearer token or X-Sam-Biscuit header")
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

func resolveExtAuthzTarget(in extAuthzCheckInput) (target, reqPath string) {
	path := in.Path
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if explicit := strings.TrimSpace(in.Headers[strings.ToLower(api.HeaderSamTargetService)]); explicit != "" {
		return explicit, path
	}
	if strings.HasPrefix(path, "/sam/") {
		if route, ok := parseEgressRoute(path); ok {
			up := "/" + route.upstreamPath
			return route.serviceType + "://" + route.serviceName, up
		}
	}
	if after, ok := strings.CutPrefix(path, "/egress/"); ok {
		host, rest, _ := strings.Cut(after, "/")
		host = api.NormalizeMeshHost(host)
		if host != "" {
			return api.EgressServicePrefix + host, "/" + rest
		}
	}
	trimmed := strings.TrimPrefix(path, "/")
	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) >= 2 {
		scheme := strings.ToLower(parts[0])
		switch scheme {
		case api.ServiceTypeStringMCP, api.ServiceTypeStringInference, api.ServiceTypeStringA2A, api.ServiceTypeStringEgress, "http":
			rest := "/"
			if len(parts) == 3 {
				rest = "/" + parts[2]
			}
			return scheme + "://" + parts[1], rest
		}
	}
	return "", path
}

func readGRPCFrame(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0 {
		return nil, errors.New("compressed gRPC frames are not supported")
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length > maxRequestBodyBytes {
		return nil, fmt.Errorf("gRPC message length %d exceeds limit", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeGRPCFrame(w io.Writer, payload []byte) error {
	var hdr [5]byte
	hdr[0] = 0
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func writeGRPCError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", fmt.Sprintf("%d", code))
	w.Header().Set("Grpc-Message", msg)
	w.WriteHeader(http.StatusOK)
}

// unmarshalEnvoyCheckRequest decodes envoy.service.auth.v3.CheckRequest:
//
//	message CheckRequest {
//	  AttributeContext attributes = 1;
//	}
//	message AttributeContext {
//	  Request request = 4;
//	  message Request {
//	    HttpRequest http = 2;
//	  }
//	  message HttpRequest {
//	    string method = 2;
//	    map<string, string> headers = 3;
//	    string path = 4;
//	    string host = 5;
//	  }
//	}
func unmarshalEnvoyCheckRequest(b []byte) (extAuthzCheckInput, error) {
	out := extAuthzCheckInput{Headers: make(map[string]string)}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			attrBytes, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return out, protowire.ParseError(m)
			}
			b = b[m:]
			if err := parseAttributeContext(attrBytes, &out); err != nil {
				return out, err
			}
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return out, protowire.ParseError(m)
		}
		b = b[m:]
	}
	return out, nil
}

func parseAttributeContext(b []byte, out *extAuthzCheckInput) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if num == 4 && typ == protowire.BytesType {
			reqBytes, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return protowire.ParseError(m)
			}
			b = b[m:]
			if err := parseAttributeRequest(reqBytes, out); err != nil {
				return err
			}
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return protowire.ParseError(m)
		}
		b = b[m:]
	}
	return nil
}

func parseAttributeRequest(b []byte, out *extAuthzCheckInput) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if num == 2 && typ == protowire.BytesType {
			httpBytes, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return protowire.ParseError(m)
			}
			b = b[m:]
			if err := parseAttributeHTTPRequest(httpBytes, out); err != nil {
				return err
			}
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return protowire.ParseError(m)
		}
		b = b[m:]
	}
	return nil
}

func parseAttributeHTTPRequest(b []byte, out *extAuthzCheckInput) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if typ == protowire.BytesType {
			valBytes, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return protowire.ParseError(m)
			}
			b = b[m:]
			switch num {
			case 2:
				out.Method = string(valBytes)
			case 3:
				k, v, err := parseStringMapEntry(valBytes)
				if err != nil {
					return err
				}
				out.Headers[strings.ToLower(k)] = v
			case 4:
				out.Path = string(valBytes)
			case 5:
				out.Host = string(valBytes)
			}
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return protowire.ParseError(m)
		}
		b = b[m:]
	}
	return nil
}

func parseStringMapEntry(b []byte) (string, string, error) {
	var k, v string
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return "", "", protowire.ParseError(n)
		}
		b = b[n:]
		if typ == protowire.BytesType && (num == 1 || num == 2) {
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return "", "", protowire.ParseError(m)
			}
			b = b[m:]
			if num == 1 {
				k = string(val)
			} else {
				v = string(val)
			}
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return "", "", protowire.ParseError(m)
		}
		b = b[m:]
	}
	return k, v, nil
}

// marshalEnvoyCheckResponse encodes envoy.service.auth.v3.CheckResponse:
//
//	message CheckResponse {
//	  google.rpc.Status status = 1;
//	  oneof http_response {
//	    DeniedHttpResponse denied_response = 2;
//	    OkHttpResponse ok_response = 3;
//	  }
//	}
func marshalEnvoyCheckResponse(res extAuthzCheckResult) []byte {
	var out []byte
	if res.Allowed {
		// status = {code: 0}
		var statusBytes []byte
		statusBytes = protowire.AppendTag(statusBytes, 1, protowire.VarintType)
		statusBytes = protowire.AppendVarint(statusBytes, 0)
		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, statusBytes)

		// ok_response (field 3): repeated HeaderValueOption headers = 2
		var okBytes []byte
		for k, v := range res.ResponseHeaders {
			var hvBytes []byte
			hvBytes = protowire.AppendTag(hvBytes, 1, protowire.BytesType)
			hvBytes = protowire.AppendString(hvBytes, k)
			hvBytes = protowire.AppendTag(hvBytes, 2, protowire.BytesType)
			hvBytes = protowire.AppendString(hvBytes, v)

			var hvoBytes []byte
			hvoBytes = protowire.AppendTag(hvoBytes, 1, protowire.BytesType)
			hvoBytes = protowire.AppendBytes(hvoBytes, hvBytes)

			okBytes = protowire.AppendTag(okBytes, 2, protowire.BytesType)
			okBytes = protowire.AppendBytes(okBytes, hvoBytes)
		}
		out = protowire.AppendTag(out, 3, protowire.BytesType)
		out = protowire.AppendBytes(out, okBytes)
		return out
	}

	// Denied: google.rpc.Code PERMISSION_DENIED (7) or UNAUTHENTICATED (16)
	rpcCode := uint64(7)
	if res.HTTPStatus == http.StatusUnauthorized {
		rpcCode = 16
	}
	var statusBytes []byte
	statusBytes = protowire.AppendTag(statusBytes, 1, protowire.VarintType)
	statusBytes = protowire.AppendVarint(statusBytes, rpcCode)
	if res.Message != "" {
		statusBytes = protowire.AppendTag(statusBytes, 2, protowire.BytesType)
		statusBytes = protowire.AppendString(statusBytes, res.Message)
	}
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, statusBytes)

	// denied_response (field 2): HttpStatus status = 1 {code = res.HTTPStatus}, string body = 3
	var httpStatusBytes []byte
	httpStatusBytes = protowire.AppendTag(httpStatusBytes, 1, protowire.VarintType)
	httpStatusBytes = protowire.AppendVarint(httpStatusBytes, uint64(res.HTTPStatus))

	var deniedBytes []byte
	deniedBytes = protowire.AppendTag(deniedBytes, 1, protowire.BytesType)
	deniedBytes = protowire.AppendBytes(deniedBytes, httpStatusBytes)
	if res.Message != "" {
		deniedBytes = protowire.AppendTag(deniedBytes, 3, protowire.BytesType)
		deniedBytes = protowire.AppendString(deniedBytes, res.Message)
	}
	out = protowire.AppendTag(out, 2, protowire.BytesType)
	out = protowire.AppendBytes(out, deniedBytes)
	return out
}
