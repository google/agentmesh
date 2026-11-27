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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
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
	Method  string
	Path    string
	Host    string
	Headers map[string]string
	Body    []byte
	// MCPTool is the tool of an MCP tools/call, and AllowMCPStreamInit says
	// that the request is an MCP handshake. The server reads both from the
	// request body that Envoy sent, and from nothing else: a client can set
	// any request header, so no header names the tool.
	MCPTool            string
	AllowMCPStreamInit bool
	// TrustedTransport reports that the check arrived on a transport that
	// authenticates the caller as the gateway. The Evaluator returns an
	// upstream credential only when it is set.
	TrustedTransport bool
	// HeadersOnly is true during the ext_proc RequestHeaders pre-check when
	// the request has a body that has not yet been buffered.
	HeadersOnly bool
	// ExtProcMode records the Envoy ext_proc ProtocolConfig summary (for
	// audit logging) when invoked via ExternalProcessor.Process.
	ExtProcMode string
}

// CheckResult represents the policy decision and header mutations returned by
// an Evaluator for an ext_authz or ext_proc check.
type CheckResult struct {
	Allowed         bool
	HTTPStatus      int
	Message         string
	ResponseHeaders map[string]string
	// NeedsRequestBody signals to ext_proc RequestHeaders that the resolved
	// target requires buffering RequestBody (for example, an MCP service
	// resolved by Host/Authority rather than by a /mcp path prefix) before
	// finalizing the decision and mutating upstream headers.
	NeedsRequestBody bool
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

	// TrustedTransport reports whether a request arrived on a transport that
	// authenticates the caller as the gateway. Each entry point passes the
	// answer to the Evaluator in CheckInput.TrustedTransport. Set it before
	// the server handles requests. Nil trusts no transport.
	TrustedTransport func(*http.Request) bool
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

type trustedTransportKey struct{}

func (s *GatewayServer) trustedTransport(r *http.Request) bool {
	return s.TrustedTransport != nil && s.TrustedTransport(r)
}

// trustedTransportFromContext reads the transport fact that ServeGRPC stored.
// A context that did not pass through ServeGRPC is not trusted.
func trustedTransportFromContext(ctx context.Context) bool {
	trusted, _ := ctx.Value(trustedTransportKey{}).(bool)
	return trusted
}

// ServeGRPC dispatches an incoming HTTP/2 gRPC request to the underlying
// google.golang.org/grpc server, normalizing Envoy v2 ext_authz paths to v3.
func (s *GatewayServer) ServeGRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// grpc.Server.ServeHTTP derives the context of Check and Process from the
	// request context, so the transport fact travels in it.
	r = r.WithContext(context.WithValue(r.Context(), trustedTransportKey{}, s.trustedTransport(r)))
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
	mcpTool, allowInit := mcpCallOfBody(method, bodyBytes)

	res := s.eval(r.Context(), CheckInput{
		Method:             method,
		Path:               checkPath,
		Host:               r.Host,
		Headers:            headers,
		Body:               bodyBytes,
		MCPTool:            mcpTool,
		AllowMCPStreamInit: allowInit,
		TrustedTransport:   s.trustedTransport(r),
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
	mcpTool, allowInit := mcpCallOfBody(httpReq.GetMethod(), body)

	res := s.eval(ctx, CheckInput{
		Method:             httpReq.GetMethod(),
		Path:               httpReq.GetPath(),
		Host:               httpReq.GetHost(),
		Headers:            headers,
		Body:               body,
		MCPTool:            mcpTool,
		AllowMCPStreamInit: allowInit,
		TrustedTransport:   trustedTransportFromContext(ctx),
	})
	if res.Allowed {
		keys := make([]string, 0, len(res.ResponseHeaders))
		for k := range res.ResponseHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var hdrs []*corev3.HeaderValueOption
		for _, k := range keys {
			hdrs = append(hdrs, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   strings.ToLower(k),
					Value: res.ResponseHeaders[k],
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
		headersToRemove := spoofedMeshHeadersToRemove(headers, res.ResponseHeaders)
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{
					Headers:         hdrs,
					HeadersToRemove: headersToRemove,
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

func isFullDuplexBodyMode(mode extprocv3http.ProcessingMode_BodySendMode) bool {
	return mode == extprocv3http.ProcessingMode_FULL_DUPLEX_STREAMED
}

func formatExtProcMode(req *extprocv3.ProcessingRequest) string {
	pc := req.GetProtocolConfig()
	if pc == nil && req.GetFlowControlInit() == nil {
		return ""
	}
	if pc == nil {
		return "flow_control_init=true"
	}
	return fmt.Sprintf("req=%s,resp=%s,send_body_nowait=%t,flow_control=%t",
		pc.GetRequestBodyMode().String(),
		pc.GetResponseBodyMode().String(),
		pc.GetSendBodyWithoutWaitingForHeaderResponse(),
		req.GetFlowControlInit() != nil,
	)
}

func buildFullDuplexBodyResponse(isResponse bool, body []byte, endOfStream bool) *extprocv3.ProcessingResponse {
	bodyResp := &extprocv3.BodyResponse{
		Response: &extprocv3.CommonResponse{
			BodyMutation: &extprocv3.BodyMutation{
				Mutation: &extprocv3.BodyMutation_StreamedResponse{
					StreamedResponse: &extprocv3.StreamedBodyResponse{
						Body:        body,
						EndOfStream: endOfStream,
					},
				},
			},
		},
	}
	if isResponse {
		return &extprocv3.ProcessingResponse{
			Response: &extprocv3.ProcessingResponse_ResponseBody{
				ResponseBody: bodyResp,
			},
		}
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: bodyResp,
		},
	}
}

// Process implements envoy.service.ext_proc.v3.ExternalProcessorServer.
func (s *GatewayServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	var capturedHeaders map[string]string
	var capturedMethod, capturedPath, capturedHost, extProcMode string
	var pendingCheck, deferHeaderResponse bool
	var isFullDuplexReq, isFullDuplexResp, sendBodyNoWait bool
	var bodyBuf []byte

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		if pc := req.GetProtocolConfig(); pc != nil {
			isFullDuplexReq = isFullDuplexBodyMode(pc.GetRequestBodyMode())
			isFullDuplexResp = isFullDuplexBodyMode(pc.GetResponseBodyMode())
			sendBodyNoWait = pc.GetSendBodyWithoutWaitingForHeaderResponse()
		}
		if req.GetFlowControlInit() != nil && !isFullDuplexReq {
			isFullDuplexReq = true
		}
		if modeStr := formatExtProcMode(req); modeStr != "" {
			extProcMode = modeStr
		}

		var responses []*extprocv3.ProcessingResponse
		switch phase := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			pendingCheck = false
			deferHeaderResponse = false
			bodyBuf = nil
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

			// The tool of an MCP tools/call is in the body, so ext_proc asks
			// Envoy for the body of a POST to an MCP service and decides when
			// it arrives. A POST with a body is also pre-checked with
			// HeadersOnly=true so a host-resolved MCP service (without a /mcp
			// path prefix) can request body buffering via NeedsRequestBody.
			mcpRoute := isMCPRoute(capturedPath, capturedHeaders[strings.ToLower(api.HeaderMeshTargetService)])
			canBufferBody := !phase.RequestHeaders.GetEndOfStream() &&
				strings.EqualFold(capturedMethod, http.MethodPost)
			if canBufferBody {
				preRes := s.eval(stream.Context(), CheckInput{
					Method:             capturedMethod,
					Path:               capturedPath,
					Host:               capturedHost,
					Headers:            capturedHeaders,
					AllowMCPStreamInit: true,
					HeadersOnly:        true,
					TrustedTransport:   trustedTransportFromContext(stream.Context()),
					ExtProcMode:        extProcMode,
				})
				if !preRes.Allowed {
					responses = append(responses, buildExtProcResponse(preRes, capturedHeaders, false))
				} else if mcpRoute || preRes.NeedsRequestBody {
					pendingCheck = true
					if isFullDuplexReq {
						if sendBodyNoWait {
							// Envoy streams RequestBody without waiting for HeadersResponse;
							// defer header mutation until Phase 2 authorizes the MCP tool.
							deferHeaderResponse = true
						} else {
							// FULL_DUPLEX_STREAMED waits for HeadersResponse before streaming
							// RequestBody and applies HeaderMutation only on HeadersResponse.
							// Stamp verified provenance headers now (never backend secrets);
							// Phase 2 still blocks disallowed tools with ImmediateResponse
							// before any RequestBody bytes are forwarded upstream.
							responses = append(responses, buildExtProcResponse(preRes, capturedHeaders, false))
						}
					} else {
						responses = append(responses, &extprocv3.ProcessingResponse{
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
						})
					}
				} else {
					responses = append(responses, buildExtProcResponse(preRes, capturedHeaders, false))
				}
			} else {
				responses = append(responses, s.evaluateExtProcDecision(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, "", false, false, extProcMode))
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			if pendingCheck {
				chunk := phase.RequestBody.GetBody()
				if len(bodyBuf)+len(chunk) > MaxHTTPBodyBytes {
					pendingCheck = false
					deferHeaderResponse = false
					bodyBuf = nil
					responses = append(responses, &extprocv3.ProcessingResponse{
						Response: &extprocv3.ProcessingResponse_ImmediateResponse{
							ImmediateResponse: &extprocv3.ImmediateResponse{
								Status:  &typev3.HttpStatus{Code: typev3.StatusCode_PayloadTooLarge},
								Body:    []byte("request body exceeds inspection limit"),
								Details: "mesh_ext_proc_denied",
							},
						},
					})
					break
				}
				if !phase.RequestBody.GetEndOfStream() {
					if !isFullDuplexReq {
						// In half-duplex STREAMED mode, answering CONTINUE on a non-final
						// chunk releases those bytes upstream before the full JSON-RPC
						// body is inspected (and Envoy ignores HeaderMutation on
						// BodyResponse outside BUFFERED mode). Fail closed on chunk 1 so
						// zero unverified body bytes leave Envoy; MCP body authorization
						// requires BUFFERED (or allow_mode_override) or FULL_DUPLEX_STREAMED.
						pendingCheck = false
						deferHeaderResponse = false
						bodyBuf = nil
						responses = append(responses, &extprocv3.ProcessingResponse{
							Response: &extprocv3.ProcessingResponse_ImmediateResponse{
								ImmediateResponse: &extprocv3.ImmediateResponse{
									Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
									Body:    []byte("MCP body authorization requires BUFFERED or FULL_DUPLEX_STREAMED request body mode; partial STREAMED chunk rejected"),
									Details: "mesh_ext_proc_denied",
								},
							},
						})
						break
					}
					// FULL_DUPLEX_STREAMED buffers silently until EndOfStream (or
					// RequestTrailers) so zero bytes of a forbidden tool call leave Envoy.
					bodyBuf = append(bodyBuf, chunk...)
					break
				}
				bodyBuf = append(bodyBuf, chunk...)
				pendingCheck = false
				fullBody := bodyBuf
				bodyBuf = nil
				if isFullDuplexReq {
					res := s.evaluateExtProcBodyResult(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, fullBody, extProcMode)
					if !res.Allowed {
						deferHeaderResponse = false
						responses = append(responses, buildExtProcResponse(res, capturedHeaders, false))
					} else {
						if deferHeaderResponse {
							deferHeaderResponse = false
							responses = append(responses, buildExtProcResponse(res, capturedHeaders, false))
						}
						responses = append(responses, buildFullDuplexBodyResponse(false, fullBody, true))
					}
				} else {
					responses = append(responses, s.finalizeExtProcBodyCheck(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, fullBody, true, extProcMode))
				}
			} else if isFullDuplexReq {
				// Echo non-inspected request body chunks verbatim in FULL_DUPLEX_STREAMED
				// mode so Envoy does not strip the request body.
				responses = append(responses, buildFullDuplexBodyResponse(false, phase.RequestBody.GetBody(), phase.RequestBody.GetEndOfStream()))
			} else {
				responses = append(responses, &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestBody{
						RequestBody: &extprocv3.BodyResponse{
							Response: &extprocv3.CommonResponse{
								Status: extprocv3.CommonResponse_CONTINUE,
							},
						},
					},
				})
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			if pendingCheck {
				pendingCheck = false
				deferHeaderResponse = false
				fullBody := bodyBuf
				bodyBuf = nil
				if denyResp := s.finalizeExtProcBodyCheck(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, fullBody, false, extProcMode); denyResp.GetImmediateResponse() != nil {
					responses = append(responses, denyResp)
					break
				}
			}
			responses = append(responses, &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
						},
					},
				},
			})

		case *extprocv3.ProcessingRequest_ResponseBody:
			if isFullDuplexResp {
				responses = append(responses, buildFullDuplexBodyResponse(true, phase.ResponseBody.GetBody(), phase.ResponseBody.GetEndOfStream()))
			} else {
				responses = append(responses, &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_ResponseBody{
						ResponseBody: &extprocv3.BodyResponse{
							Response: &extprocv3.CommonResponse{
								Status: extprocv3.CommonResponse_CONTINUE,
							},
						},
					},
				})
			}

		case *extprocv3.ProcessingRequest_RequestTrailers:
			if pendingCheck {
				pendingCheck = false
				fullBody := bodyBuf
				bodyBuf = nil
				if isFullDuplexReq {
					res := s.evaluateExtProcBodyResult(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, fullBody, extProcMode)
					if !res.Allowed {
						deferHeaderResponse = false
						responses = append(responses, buildExtProcResponse(res, capturedHeaders, false))
						break
					}
					if deferHeaderResponse {
						deferHeaderResponse = false
						responses = append(responses, buildExtProcResponse(res, capturedHeaders, false))
					}
					responses = append(responses, buildFullDuplexBodyResponse(false, fullBody, false))
				} else if denyResp := s.finalizeExtProcBodyCheck(stream.Context(), capturedMethod, capturedPath, capturedHost, capturedHeaders, fullBody, false, extProcMode); denyResp.GetImmediateResponse() != nil {
					responses = append(responses, denyResp)
					break
				}
			}
			responses = append(responses, &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestTrailers{
					RequestTrailers: &extprocv3.TrailersResponse{},
				},
			})

		case *extprocv3.ProcessingRequest_ResponseTrailers:
			responses = append(responses, &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseTrailers{
					ResponseTrailers: &extprocv3.TrailersResponse{},
				},
			})
		}

		for _, resp := range responses {
			if resp == nil {
				continue
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
			if resp.GetImmediateResponse() != nil {
				return nil
			}
		}
	}
}

func (s *GatewayServer) evaluateExtProcBodyResult(ctx context.Context, method, path, host string, headers map[string]string, body []byte, extProcMode string) CheckResult {
	var mcpTool string
	var allowStreamInit bool
	if len(body) > 0 {
		mcpTool, allowStreamInit = InspectJSONRPCMCPBody(body)
	}
	return s.eval(ctx, CheckInput{
		Method:             method,
		Path:               path,
		Host:               host,
		Headers:            headers,
		Body:               body,
		MCPTool:            mcpTool,
		AllowMCPStreamInit: allowStreamInit,
		TrustedTransport:   trustedTransportFromContext(ctx),
		ExtProcMode:        extProcMode,
	})
}

func (s *GatewayServer) finalizeExtProcBodyCheck(ctx context.Context, method, path, host string, headers map[string]string, body []byte, isBodyPhase bool, extProcMode string) *extprocv3.ProcessingResponse {
	res := s.evaluateExtProcBodyResult(ctx, method, path, host, headers, body, extProcMode)
	return buildExtProcResponse(res, headers, isBodyPhase)
}

func (s *GatewayServer) evaluateExtProcDecision(ctx context.Context, method, path, host string, headers map[string]string, mcpTool string, isBodyPhase, allowMCPStreamInit bool, extProcMode string) *extprocv3.ProcessingResponse {
	res := s.eval(ctx, CheckInput{
		Method:             method,
		Path:               path,
		Host:               host,
		Headers:            headers,
		MCPTool:            mcpTool,
		AllowMCPStreamInit: allowMCPStreamInit,
		TrustedTransport:   trustedTransportFromContext(ctx),
		ExtProcMode:        extProcMode,
	})
	return buildExtProcResponse(res, headers, isBodyPhase)
}

func buildExtProcResponse(res CheckResult, headers map[string]string, isBodyPhase bool) *extprocv3.ProcessingResponse {
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

	keys := make([]string, 0, len(res.ResponseHeaders))
	for k := range res.ResponseHeaders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var setHeaders []*corev3.HeaderValueOption
	for _, k := range keys {
		setHeaders = append(setHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				// Envoy HTTP/2 HeaderMutation requires lowercase header names (RFC 9113).
				Key:      strings.ToLower(k),
				RawValue: []byte(res.ResponseHeaders[k]),
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	removeHeaders := spoofedMeshHeadersToRemove(headers, res.ResponseHeaders)
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

// callerInputMeshHeaders lists legitimate caller-supplied X-Mesh-* headers that
// Envoy filter chains (ext_authz -> ext_proc -> agentmesh-node sidecar) must
// preserve for target resolution, authentication, and label-floor routing.
// Every other inbound X-Mesh-* header (principal, roles, claims, labels,
// actor-node, origin, task, task-id, ingress, etc.) and X-Peer-Id is stripped
// unless freshly stamped by the PEP.
func isCallerInputMeshHeader(lower string) bool {
	return lower == strings.ToLower(api.HeaderMeshTargetService) ||
		lower == strings.ToLower(api.HeaderMeshAuthentication) ||
		lower == strings.ToLower(api.HeaderMeshRequiredLabels)
}

// spoofedMeshHeadersToRemove returns inbound X-Mesh-* and X-Peer-Id header
// names that were NOT freshly stamped in responseHeaders (excluding caller
// input routing/auth headers needed by downstream Envoy filters and the
// sidecar) so untrusted callers cannot smuggle forged provenance or task
// headers past Envoy ext_authz/ext_proc.
func spoofedMeshHeadersToRemove(inbound, responseHeaders map[string]string) []string {
	if len(inbound) == 0 {
		return nil
	}
	stamped := make(map[string]bool, len(responseHeaders))
	for k := range responseHeaders {
		stamped[strings.ToLower(k)] = true
	}
	peerHeaderLower := strings.ToLower(api.HeaderPeerID)
	var remove []string
	for k := range inbound {
		lower := strings.ToLower(k)
		if isCallerInputMeshHeader(lower) {
			continue
		}
		if (strings.HasPrefix(lower, "x-mesh-") || lower == peerHeaderLower) && !stamped[lower] {
			remove = append(remove, lower)
		}
	}
	sort.Strings(remove)
	return remove
}

// mcpCallOfBody reads the MCP call of an ext_authz check: the tool of a
// tools/call, or a handshake. The tool is in the body, and Envoy sends the
// body to ext_authz only when its filter sets with_request_body. A POST with
// no body names no tool and is not a handshake, so a task rule with
// allowed_tools refuses it. A GET opens a stream and a DELETE ends a session:
// they carry no call, as api.InspectMCPHTTPRequestBody also decides.
func mcpCallOfBody(method string, body []byte) (mcpTool string, allowStreamInit bool) {
	if len(body) == 0 {
		return "", strings.EqualFold(method, http.MethodGet) || strings.EqualFold(method, http.MethodDelete)
	}
	return InspectJSONRPCMCPBody(body)
}

// isMCPRoute reports whether a request is for an MCP service, by its path or
// by X-Mesh-Target-Service, so that ext_proc asks Envoy for the body. It
// ignores letter case, as the evaluator does when it resolves the service.
func isMCPRoute(path, targetService string) bool {
	path = strings.ToLower(path)
	target := strings.ToLower(strings.TrimSpace(targetService))
	return strings.HasPrefix(path, "/mcp") ||
		strings.Contains(path, "/mcp/") ||
		strings.HasPrefix(target, api.ServiceTypeStringMCP+"://")
}

// InspectJSONRPCMCPBody inspects a JSON-RPC 2.0 request body for MCP methods
// and extracts the tool name as the body states it, or sets allowStreamInit
// for a method that opens or keeps a session (api.MCPSessionMethod).
func InspectJSONRPCMCPBody(body []byte) (mcpTool string, allowStreamInit bool) {
	return api.InspectJSONRPCMCPBody(body)
}

// InspectMCPHTTPRequestBody buffers and restores r.Body up to MaxGRPCMessageBytes
// and extracts the MCP tool name and stream initialization flag.
func InspectMCPHTTPRequestBody(r *http.Request) (string, bool, error) {
	return api.InspectMCPHTTPRequestBody(r, MaxGRPCMessageBytes)
}
