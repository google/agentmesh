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

// Package envoy implements Envoy ext_authz (HTTP and gRPC v3/v2) and ext_proc
// (gRPC v3 gateway server and outbound inspection callout client) using
// official google.golang.org/grpc and envoyproxy/go-control-plane bindings.
package envoy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/agentmesh/api"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	// HeaderMeshMCPTool lets an external proxy (or ext_proc filter) pass the
	// extracted MCP tool name during an ext_authz check.
	HeaderMeshMCPTool = "X-Mesh-Mcp-Tool"

	// ExtProcMethodPath is the gRPC HTTP/2 path for Envoy ExternalProcessor.Process.
	ExtProcMethodPath = "/envoy.service.ext_proc.v3.ExternalProcessor/Process"
	// ExtAuthzV3MethodPath is the gRPC HTTP/2 path for Envoy v3 Authorization.Check.
	ExtAuthzV3MethodPath = "/envoy.service.auth.v3.Authorization/Check"
	// ExtAuthzV2MethodPath is the gRPC HTTP/2 path for Envoy v2 Authorization.Check.
	ExtAuthzV2MethodPath = "/envoy.service.auth.v2.Authorization/Check"

	// MaxGRPCMessageBytes caps gRPC message sizes for ext_authz and ext_proc (16 MiB).
	MaxGRPCMessageBytes = 16 << 20
	// MaxHTTPBodyBytes caps HTTP ext_authz request bodies read into memory (1 MiB).
	MaxHTTPBodyBytes = 1 << 20
)

// CheckInput represents a normalized authorization check request from Envoy
// HTTP ext_authz, gRPC ext_authz, or gRPC ext_proc.
type CheckInput struct {
	Method             string
	Path               string
	Host               string
	Headers            map[string]string
	Body               []byte
	AllowMCPStreamInit bool
}

// CheckResult represents the policy decision and header mutations returned by
// an Evaluator for an ext_authz or ext_proc check.
type CheckResult struct {
	Allowed         bool
	HTTPStatus      int
	Message         string
	ResponseHeaders map[string]string
}

// Evaluator evaluates a normalized CheckInput against Agent Mesh's Datalog and TAR policy.
type Evaluator func(ctx context.Context, in CheckInput) CheckResult

// GatewayServer serves Envoy HTTP ext_authz, gRPC ext_authz (v3 and v2), and
// gRPC ext_proc over standard net/http and google.golang.org/grpc.
type GatewayServer struct {
	authv3.UnimplementedAuthorizationServer
	extprocv3.UnimplementedExternalProcessorServer

	eval       Evaluator
	grpcServer *grpc.Server
}

// NewGatewayServer constructs a GatewayServer backed by a google.golang.org/grpc
// server registered for both AuthorizationServer and ExternalProcessorServer.
func NewGatewayServer(eval Evaluator) *GatewayServer {
	s := &GatewayServer{
		eval: eval,
		grpcServer: grpc.NewServer(
			grpc.MaxRecvMsgSize(MaxGRPCMessageBytes),
			grpc.MaxSendMsgSize(MaxGRPCMessageBytes),
		),
	}
	authv3.RegisterAuthorizationServer(s.grpcServer, s)
	extprocv3.RegisterExternalProcessorServer(s.grpcServer, s)
	return s
}

// RegisterRoutes mounts the HTTP ext_authz, gRPC ext_authz (v3/v2), and gRPC
// ext_proc endpoints onto mux.
func (s *GatewayServer) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/ext_authz", s.HandleExtAuthzHTTP)
	mux.HandleFunc("/ext_authz/", s.HandleExtAuthzHTTP)
	mux.HandleFunc(ExtAuthzV3MethodPath, s.ServeGRPC)
	mux.HandleFunc(ExtAuthzV2MethodPath, s.ServeGRPC)
	mux.HandleFunc(ExtProcMethodPath, s.ServeGRPC)
}

// ServeGRPC dispatches an incoming HTTP/2 gRPC request to the underlying
// google.golang.org/grpc server, normalizing Envoy v2 ext_authz paths to v3.
func (s *GatewayServer) ServeGRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == ExtAuthzV2MethodPath {
		r2 := new(http.Request)
		*r2 = *r
		u2 := *r.URL
		u2.Path = ExtAuthzV3MethodPath
		r2.URL = &u2
		r = r2
	}
	s.grpcServer.ServeHTTP(w, r)
}

// HandleExtAuthzHTTP implements Envoy's HTTP ext_authz check service on
// /ext_authz and /ext_authz/*.
func (s *GatewayServer) HandleExtAuthzHTTP(w http.ResponseWriter, r *http.Request) {
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

	var bodyBytes []byte
	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(r.Body, MaxHTTPBodyBytes+1))
		_ = r.Body.Close()
		if err != nil || int64(len(b)) > MaxHTTPBodyBytes {
			http.Error(w, "request body exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}
		bodyBytes = b
	}
	allowInit := headers[strings.ToLower(HeaderMeshMCPTool)] == ""
	if len(bodyBytes) > 0 && headers[strings.ToLower(HeaderMeshMCPTool)] == "" {
		tool, isInit := InspectJSONRPCMCPBody(bodyBytes)
		if tool != "" {
			headers[strings.ToLower(HeaderMeshMCPTool)] = tool
		}
		allowInit = isInit
	}

	res := s.eval(r.Context(), CheckInput{
		Method:             method,
		Path:               checkPath,
		Host:               r.Host,
		Headers:            headers,
		Body:               bodyBytes,
		AllowMCPStreamInit: allowInit,
	})
	if !res.Allowed {
		status := res.HTTPStatus
		if status <= 0 {
			status = http.StatusForbidden
		}
		http.Error(w, res.Message, status)
		return
	}
	for k, v := range res.ResponseHeaders {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
}

// Check implements envoy.service.auth.v3.AuthorizationServer.
func (s *GatewayServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	headers := make(map[string]string, len(httpReq.GetHeaders()))
	for k, v := range httpReq.GetHeaders() {
		headers[strings.ToLower(k)] = v
	}
	var body []byte
	if len(httpReq.GetRawBody()) > 0 {
		body = httpReq.GetRawBody()
	} else if httpReq.GetBody() != "" {
		body = []byte(httpReq.GetBody())
	}

	allowInit := headers[strings.ToLower(HeaderMeshMCPTool)] == ""
	if len(body) > 0 && headers[strings.ToLower(HeaderMeshMCPTool)] == "" {
		tool, isInit := InspectJSONRPCMCPBody(body)
		if tool != "" {
			headers[strings.ToLower(HeaderMeshMCPTool)] = tool
		}
		allowInit = isInit
	}

	res := s.eval(ctx, CheckInput{
		Method:             httpReq.GetMethod(),
		Path:               httpReq.GetPath(),
		Host:               httpReq.GetHost(),
		Headers:            headers,
		Body:               body,
		AllowMCPStreamInit: allowInit,
	})
	if res.Allowed {
		var hdrs []*corev3.HeaderValueOption
		for k, v := range res.ResponseHeaders {
			hdrs = append(hdrs, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   k,
					Value: v,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{
					Headers: hdrs,
				},
			},
		}, nil
	}

	rpcCode := int32(codes.PermissionDenied)
	if res.HTTPStatus == http.StatusUnauthorized {
		rpcCode = int32(codes.Unauthenticated)
	}
	httpCode := typev3.StatusCode(res.HTTPStatus)
	if httpCode == 0 {
		httpCode = typev3.StatusCode_Forbidden
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{
			Code:    rpcCode,
			Message: res.Message,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpCode},
				Body:   res.Message,
			},
		},
	}, nil
}

// Process implements envoy.service.ext_proc.v3.ExternalProcessorServer.
func (s *GatewayServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	var capturedHeaders map[string]string
	var capturedMethod, capturedPath, capturedHost string
	var pendingCheck bool

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		var resp *extprocv3.ProcessingResponse
		switch phase := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			capturedHeaders = make(map[string]string)
			for _, hv := range phase.RequestHeaders.GetHeaders().GetHeaders() {
				k := strings.ToLower(hv.GetKey())
				val := hv.GetValue()
				if val == "" && len(hv.GetRawValue()) > 0 {
					val = string(hv.GetRawValue())
				}
				capturedHeaders[k] = val
			}
			capturedMethod = capturedHeaders[":method"]
			capturedPath = capturedHeaders[":path"]
			capturedHost = capturedHeaders[":authority"]
			if capturedHost == "" {
				capturedHost = capturedHeaders["host"]
			}

			targetHdr := strings.ToLower(capturedHeaders[strings.ToLower(api.HeaderMeshTargetService)])
			isMCPRoute := strings.HasPrefix(capturedPath, "/mcp") ||
				strings.Contains(capturedPath, "/mcp/") ||
				strings.HasPrefix(targetHdr, api.ServiceTypeStringMCP+"://")
			if !phase.RequestHeaders.GetEndOfStream() &&
				strings.EqualFold(capturedMethod, http.MethodPost) &&
				capturedHeaders[strings.ToLower(HeaderMeshMCPTool)] == "" &&
				isMCPRoute {
				preResp := s.evaluateExtProcDecision(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, false, true)
				if preResp.GetImmediateResponse() != nil {
					resp = preResp
				} else {
					pendingCheck = true
					resp = &extprocv3.ProcessingResponse{
						Response: &extprocv3.ProcessingResponse_RequestHeaders{
							RequestHeaders: &extprocv3.HeadersResponse{
								Response: &extprocv3.CommonResponse{
									Status: extprocv3.CommonResponse_CONTINUE,
								},
							},
						},
						ModeOverride: &extprocv3http.ProcessingMode{
							RequestBodyMode: extprocv3http.ProcessingMode_BUFFERED,
						},
					}
				}
			} else {
				resp = s.evaluateExtProcDecision(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, false, false)
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			var allowStreamInit bool
			if len(phase.RequestBody.GetBody()) > 0 && capturedHeaders != nil {
				tool, allowInit := InspectJSONRPCMCPBody(phase.RequestBody.GetBody())
				if tool != "" {
					capturedHeaders[strings.ToLower(HeaderMeshMCPTool)] = tool
				}
				allowStreamInit = allowInit
			}
			if pendingCheck {
				pendingCheck = false
				resp = s.evaluateExtProcDecision(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, true, allowStreamInit)
			} else {
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestBody{
						RequestBody: &extprocv3.BodyResponse{
							Response: &extprocv3.CommonResponse{
								Status: extprocv3.CommonResponse_CONTINUE,
							},
						},
					},
				}
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			if pendingCheck {
				pendingCheck = false
				if denyResp := s.evaluateExtProcDecision(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, false, false); denyResp.GetImmediateResponse() != nil {
					resp = denyResp
					break
				}
			}
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
						},
					},
				},
			}

		case *extprocv3.ProcessingRequest_ResponseBody:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
						},
					},
				},
			}

		case *extprocv3.ProcessingRequest_RequestTrailers:
			if pendingCheck {
				pendingCheck = false
				if denyResp := s.evaluateExtProcDecision(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, false, false); denyResp.GetImmediateResponse() != nil {
					resp = denyResp
					break
				}
			}
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestTrailers{
					RequestTrailers: &extprocv3.TrailersResponse{},
				},
			}

		case *extprocv3.ProcessingRequest_ResponseTrailers:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseTrailers{
					ResponseTrailers: &extprocv3.TrailersResponse{},
				},
			}
		}

		if resp != nil {
			if err := stream.Send(resp); err != nil {
				return err
			}
			if resp.GetImmediateResponse() != nil {
				return nil
			}
		}
	}
}

func (s *GatewayServer) evaluateExtProcDecision(ctx context.Context, method, path, host string, headers map[string]string, isBodyPhase, allowMCPStreamInit bool) *extprocv3.ProcessingResponse {
	res := s.eval(ctx, CheckInput{
		Method:             method,
		Path:               path,
		Host:               host,
		Headers:            headers,
		AllowMCPStreamInit: allowMCPStreamInit,
	})
	if !res.Allowed {
		status := typev3.StatusCode_Forbidden
		if res.HTTPStatus == http.StatusUnauthorized {
			status = typev3.StatusCode_Unauthorized
		}
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ImmediateResponse{
				ImmediateResponse: &extprocv3.ImmediateResponse{
					Status:  &typev3.HttpStatus{Code: status},
					Body:    []byte(res.Message),
					Details: "mesh_ext_proc_denied",
				},
			},
		}
	}

	var setHeaders []*corev3.HeaderValueOption
	for k, v := range res.ResponseHeaders {
		setHeaders = append(setHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:      k,
				RawValue: []byte(v),
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	var removeHeaders []string
	if _, hasUpstreamAuth := res.ResponseHeaders["Authorization"]; !hasUpstreamAuth {
		if headers["authorization"] != "" {
			removeHeaders = append(removeHeaders, "authorization")
		}
	}
	common := &extprocv3.CommonResponse{
		Status: extprocv3.CommonResponse_CONTINUE,
		HeaderMutation: &extprocv3.HeaderMutation{
			SetHeaders:    setHeaders,
			RemoveHeaders: removeHeaders,
		},
	}
	if isBodyPhase {
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: &extprocv3.BodyResponse{Response: common},
			},
		}
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: common},
		},
	}
}

// InspectJSONRPCMCPBody inspects a JSON-RPC 2.0 request body for MCP methods
// and extracts the bare tool name when present, or sets allowStreamInit for
// session handshake, capability discovery, and protocol notification methods.
func InspectJSONRPCMCPBody(body []byte) (mcpTool string, allowStreamInit bool) {
	var rpc struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return "", false
	}
	switch rpc.Method {
	case "initialize", "notifications/initialized", "server/discover", "ping",
		"tools/list", "resources/list", "prompts/list", "notifications/cancelled":
		return "", true
	case "tools/call":
		rawTool := strings.TrimSpace(rpc.Params.Name)
		if rawTool == "" {
			return "", false
		}
		if _, stripped, err := api.SplitToolName(rawTool); err == nil {
			return stripped, false
		}
		return rawTool, false
	default:
		return "", false
	}
}

// InspectMCPHTTPRequestBody buffers and restores r.Body up to MaxGRPCMessageBytes
// and extracts the MCP tool name and stream initialization flag.
func InspectMCPHTTPRequestBody(r *http.Request) (string, bool, error) {
	if r == nil {
		return "", false, nil
	}
	if strings.EqualFold(r.Method, http.MethodGet) || strings.EqualFold(r.Method, http.MethodDelete) {
		return "", true, nil
	}
	if r.Body == nil || !strings.EqualFold(r.Method, http.MethodPost) {
		return "", false, nil
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, MaxGRPCMessageBytes+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(bodyBytes)) > MaxGRPCMessageBytes {
		return "", false, fmt.Errorf("MCP request body exceeds maximum inspection size (%d bytes)", MaxGRPCMessageBytes)
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	tool, allowInit := InspectJSONRPCMCPBody(bodyBytes)
	return tool, allowInit, nil
}
