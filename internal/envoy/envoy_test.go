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

package envoy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/agentmesh/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func startH2CGatewayTestServer(t *testing.T, gw *GatewayServer) string {
	t.Helper()
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Handler:   mux,
		Protocols: &protocols,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	return ln.Addr().String()
}

func TestGatewayServer_ExtAuthzHTTPAndGRPC(t *testing.T) {
	gw := NewGatewayServer(func(_ context.Context, in CheckInput) CheckResult {
		if in.Headers["authorization"] != "Bearer valid-token" {
			return CheckResult{
				Allowed:    false,
				HTTPStatus: http.StatusUnauthorized,
				Message:    "missing or invalid token",
			}
		}
		if in.Headers[strings.ToLower(HeaderMeshMCPTool)] == "merge_pr" {
			return CheckResult{
				Allowed:    false,
				HTTPStatus: http.StatusForbidden,
				Message:    "tool merge_pr is forbidden",
			}
		}
		return CheckResult{
			Allowed:    true,
			HTTPStatus: http.StatusOK,
			ResponseHeaders: map[string]string{
				api.HeaderMeshPrincipal: "alice@example.com",
				"X-Mesh-Task-Id":        "task-123",
			},
		}
	})

	addr := startH2CGatewayTestServer(t, gw)

	// 1. HTTP ext_authz allow & deny
	reqAllow := httptest.NewRequest(http.MethodPost, "/ext_authz/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"mcp://github/get_pr"}}`))
	reqAllow.Header.Set("Authorization", "Bearer valid-token")
	recAllow := httptest.NewRecorder()
	gw.HandleExtAuthzHTTP(recAllow, reqAllow)
	if recAllow.Code != http.StatusOK {
		t.Fatalf("HTTP ext_authz status = %d, want 200", recAllow.Code)
	}
	if recAllow.Header().Get(api.HeaderMeshPrincipal) != "alice@example.com" {
		t.Fatalf("X-Mesh-Principal = %q, want alice@example.com", recAllow.Header().Get(api.HeaderMeshPrincipal))
	}

	reqDeny := httptest.NewRequest(http.MethodPost, "/ext_authz/mcp/github", strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"merge_pr"}}`))
	reqDeny.Header.Set("Authorization", "Bearer valid-token")
	recDeny := httptest.NewRecorder()
	gw.HandleExtAuthzHTTP(recDeny, reqDeny)
	if recDeny.Code != http.StatusForbidden {
		t.Fatalf("HTTP ext_authz deny status = %d, want 403", recDeny.Code)
	}

	// 2. gRPC ext_authz Check via official AuthorizationClient over h2c
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer func() { _ = conn.Close() }()
	authClient := authv3.NewAuthorizationClient(conn)

	checkRespOK, err := authClient.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST",
					Path:   "/mcp/github",
					Host:   "localhost",
					Headers: map[string]string{
						"authorization": "Bearer valid-token",
					},
					Body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_pr"}}`,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("authClient.Check OK: %v", err)
	}
	if checkRespOK.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("Check status = %d, want 0", checkRespOK.GetStatus().GetCode())
	}
	if len(checkRespOK.GetOkResponse().GetHeaders()) == 0 {
		t.Fatalf("expected OkHttpResponse headers, got empty")
	}

	// 2b. gRPC ext_authz Check must strip spoofed inbound X-Mesh-* and X-Peer-Id headers not stamped in ResponseHeaders.
	checkSpoofed, err := authClient.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST",
					Path:   "/mcp/github",
					Host:   "localhost",
					Headers: map[string]string{
						"authorization":  "Bearer valid-token",
						"x-mesh-labels":  "device_trust=high",
						"x-mesh-origin":  "spoofed-local",
						"x-mesh-task":    "forged-task",
						"x-peer-id":      "forged-peer",
						"x-mesh-task-id": "forged-id",
					},
					Body: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_pr"}}`,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("authClient.Check spoofed: %v", err)
	}
	if checkSpoofed.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("Check spoofed status = %d, want 0", checkSpoofed.GetStatus().GetCode())
	}
	removed := checkSpoofed.GetOkResponse().GetHeadersToRemove()
	for _, wantRemoved := range []string{"x-mesh-labels", "x-mesh-origin", "x-mesh-task", "x-peer-id"} {
		found := false
		for _, h := range removed {
			if h == wantRemoved {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("HeadersToRemove = %v, missing spoofed header %q", removed, wantRemoved)
		}
	}
	for _, h := range removed {
		if h == "x-mesh-task-id" {
			t.Errorf("HeadersToRemove must not remove freshly stamped x-mesh-task-id: %v", removed)
		}
	}

	checkRespDeny, err := authClient.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST",
					Path:   "/mcp/github",
					Headers: map[string]string{
						"authorization": "Bearer valid-token",
					},
					RawBody: []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"merge_pr"}}`),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("authClient.Check Deny: %v", err)
	}
	if checkRespDeny.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("Check deny status = %d, want PermissionDenied", checkRespDeny.GetStatus().GetCode())
	}
	if checkRespDeny.GetDeniedResponse().GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("DeniedResponse HTTP code = %v, want Forbidden", checkRespDeny.GetDeniedResponse().GetStatus().GetCode())
	}

	// 3. Envoy v2 path normalization (/envoy.service.auth.v2.Authorization/Check)
	var v2Resp authv3.CheckResponse
	if err := conn.Invoke(context.Background(), ExtAuthzV2MethodPath, &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Path:    "/mcp/github",
					Headers: map[string]string{"authorization": "Bearer valid-token"},
				},
			},
		},
	}, &v2Resp); err != nil {
		t.Fatalf("Invoke v2 Check: %v", err)
	}
	if v2Resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("v2 Check status = %d, want 0", v2Resp.GetStatus().GetCode())
	}
}

func TestGatewayServer_ExtProcProcess(t *testing.T) {
	gw := NewGatewayServer(func(_ context.Context, in CheckInput) CheckResult {
		if in.Headers[strings.ToLower(HeaderMeshMCPTool)] == "merge_pr" {
			return CheckResult{
				Allowed:    false,
				HTTPStatus: http.StatusForbidden,
				Message:    "merge_pr denied",
			}
		}
		return CheckResult{
			Allowed:    true,
			HTTPStatus: http.StatusOK,
			ResponseHeaders: map[string]string{
				"X-Mesh-Task-Id": "task-extproc",
			},
		}
	})
	addr := startH2CGatewayTestServer(t, gw)

	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer func() { _ = conn.Close() }()
	procClient := extprocv3.NewExternalProcessorClient(conn)

	// 1. Allowed MCP tools/call buffers body and injects X-Mesh-Task-Id
	stream, err := procClient.Process(context.Background())
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				EndOfStream: false,
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", Value: "POST"},
						{Key: ":path", Value: "/mesh/mcp/github"},
						{Key: "authorization", Value: "Bearer tok"},
						{Key: "x-mesh-labels", Value: "device_trust=forged"},
						{Key: "x-peer-id", Value: "forged-peer"},
						{Key: "x-mesh-task-id", Value: "forged-task"},
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("Send RequestHeaders: %v", err)
	}
	r1, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv RequestHeaders: %v", err)
	}
	if r1.GetModeOverride().GetRequestBodyMode() != extprocv3http.ProcessingMode_BUFFERED {
		t.Fatalf("expected ModeOverride BUFFERED, got %+v", r1.GetModeOverride())
	}

	if err := stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_pr"}}`),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("Send RequestBody: %v", err)
	}
	r2, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv RequestBody: %v", err)
	}
	if r2.GetImmediateResponse() != nil {
		t.Fatalf("unexpected ImmediateResponse: %+v", r2.GetImmediateResponse())
	}
	extProcRemoved := r2.GetRequestBody().GetResponse().GetHeaderMutation().GetRemoveHeaders()
	for _, wantRemoved := range []string{"x-mesh-labels", "x-peer-id"} {
		found := false
		for _, h := range extProcRemoved {
			if h == wantRemoved {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ext_proc RemoveHeaders = %v, missing spoofed header %q", extProcRemoved, wantRemoved)
		}
	}
	for _, h := range extProcRemoved {
		if h == "x-mesh-task-id" {
			t.Errorf("ext_proc RemoveHeaders must not remove freshly stamped x-mesh-task-id: %v", extProcRemoved)
		}
	}

	// Also verify ResponseHeaders, ResponseBody, RequestTrailers, ResponseTrailers phases
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{},
		},
	})
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv ResponseHeaders: %v", err)
	}
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{},
		},
	})
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv ResponseBody: %v", err)
	}
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestTrailers{
			RequestTrailers: &extprocv3.HttpTrailers{},
		},
	})
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv RequestTrailers: %v", err)
	}
	_ = stream.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseTrailers{
			ResponseTrailers: &extprocv3.HttpTrailers{},
		},
	})
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv ResponseTrailers: %v", err)
	}
	_ = stream.CloseSend()
}

type referenceCalloutServer struct {
	extprocv3.UnimplementedExternalProcessorServer

	mu            sync.Mutex
	lastMeshAttrs map[string]*structpb.Value
	hadDeadline   bool
	sleepDuration time.Duration
}

func (s *referenceCalloutServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	_, hasDeadline := stream.Context().Deadline()
	s.mu.Lock()
	s.hadDeadline = hasDeadline
	sleep := s.sleepDuration
	s.mu.Unlock()

	if sleep > 0 {
		select {
		case <-time.After(sleep):
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		if meshAttrs := req.GetAttributes()["mesh"]; meshAttrs != nil {
			s.mu.Lock()
			s.lastMeshAttrs = meshAttrs.GetFields()
			s.mu.Unlock()
		}

		var resp *extprocv3.ProcessingResponse
		switch phase := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			var path string
			for _, hv := range phase.RequestHeaders.GetHeaders().GetHeaders() {
				if hv.GetKey() == ":path" {
					path = hv.GetValue()
				}
			}
			if path == "/trailers-only-error" {
				return status.Error(codes.PermissionDenied, "trailers-only rejection from grpc-go")
			}
			if path == "/immediate-deny" {
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_ImmediateResponse{
						ImmediateResponse: &extprocv3.ImmediateResponse{
							Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
							Body:    []byte("denied by service extensions callout"),
							Details: "service_extension_block",
						},
					},
				}
			} else {
				resp = &extprocv3.ProcessingResponse{
					Response: &extprocv3.ProcessingResponse_RequestHeaders{
						RequestHeaders: &extprocv3.HeadersResponse{
							Response: &extprocv3.CommonResponse{
								Status: extprocv3.CommonResponse_CONTINUE,
								HeaderMutation: &extprocv3.HeaderMutation{
									SetHeaders: []*corev3.HeaderValueOption{
										{
											Header:       &corev3.HeaderValue{Key: "X-Callout-Inspected", Value: "true"},
											Append:       wrapperspb.Bool(false),
											AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
										{
											Header:       &corev3.HeaderValue{Key: "Authorization", Value: "Bearer forged"},
											Append:       wrapperspb.Bool(false),
											AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
										},
									},
								},
							},
						},
					},
					ModeOverride: &extprocv3http.ProcessingMode{
						RequestBodyMode:  extprocv3http.ProcessingMode_BUFFERED,
						ResponseBodyMode: extprocv3http.ProcessingMode_BUFFERED,
					},
				}
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			mutated := bytes.ReplaceAll(phase.RequestBody.GetBody(), []byte("PII_SSN"), []byte("[REDACTED_SSN]"))
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_RequestBody{
					RequestBody: &extprocv3.BodyResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE_AND_REPLACE,
							BodyMutation: &extprocv3.BodyMutation{
								Mutation: &extprocv3.BodyMutation_Body{Body: mutated},
							},
						},
					},
				},
			}

		case *extprocv3.ProcessingRequest_ResponseHeaders:
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocv3.HeadersResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE,
							HeaderMutation: &extprocv3.HeaderMutation{
								SetHeaders: []*corev3.HeaderValueOption{
									{
										Header:       &corev3.HeaderValue{Key: "X-Callout-Response", Value: "verified"},
										Append:       wrapperspb.Bool(false),
										AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
									},
								},
							},
						},
					},
				},
			}

		case *extprocv3.ProcessingRequest_ResponseBody:
			mutated := bytes.ReplaceAll(phase.ResponseBody.GetBody(), []byte("RAW_OUTPUT"), []byte("SANITIZED_OUTPUT"))
			resp = &extprocv3.ProcessingResponse{
				Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{
						Response: &extprocv3.CommonResponse{
							Status: extprocv3.CommonResponse_CONTINUE_AND_REPLACE,
							BodyMutation: &extprocv3.BodyMutation{
								Mutation: &extprocv3.BodyMutation_Body{Body: mutated},
							},
						},
					},
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

func TestCalloutClient_UnixSocketAndMTLS(t *testing.T) {
	t.Run("unix_socket_4_phase_mutation_and_protected_headers", func(t *testing.T) {
		sockPath := filepath.Join(t.TempDir(), "callout.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("listen unix: %v", err)
		}
		callout := &referenceCalloutServer{}
		srv := grpc.NewServer()
		extprocv3.RegisterExternalProcessorServer(srv, callout)
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(srv.Stop)

		cfg := &api.ExtProc{
			Target:            "unix:" + sockPath,
			MessageTimeout:    durationpb.New(2 * time.Second),
			AllowModeOverride: true,
		}
		client, err := NewCalloutClient(cfg, t.TempDir())
		if err != nil {
			t.Fatalf("NewCalloutClient: %v", err)
		}

		meshStruct, _ := structpb.NewStruct(map[string]any{
			"destination": "vertex.googleapis.com",
			"principal":   "user:alice@example.com",
		})
		attrs := map[string]*structpb.Struct{"mesh": meshStruct}

		req := httptest.NewRequest(http.MethodPost, "https://vertex.googleapis.com/v1/models/gemini:generateContent", nil)
		session, imm, newReqBody, err := client.RunRequestPhase(req, cfg, "vertex.googleapis.com", []byte("prompt with PII_SSN inside"), attrs)
		if err != nil {
			t.Fatalf("RunRequestPhase: %v", err)
		}
		defer session.Close()
		if imm != nil {
			t.Fatalf("unexpected ImmediateResponse: %+v", imm)
		}
		if string(newReqBody) != "prompt with [REDACTED_SSN] inside" {
			t.Fatalf("newReqBody = %q", string(newReqBody))
		}
		if req.Header.Get("X-Callout-Inspected") != "true" {
			t.Fatalf("expected X-Callout-Inspected=true")
		}
		if req.Header.Get("Authorization") != "" {
			t.Fatalf("expected forged Authorization mutation to be ignored, got %q", req.Header.Get("Authorization"))
		}
		if !session.NeedsResponseBuffer() {
			t.Fatalf("expected NeedsResponseBuffer() == true after ModeOverride")
		}

		callout.mu.Lock()
		gotDest := callout.lastMeshAttrs["destination"].GetStringValue()
		hadDeadline := callout.hadDeadline
		callout.mu.Unlock()
		if gotDest != "vertex.googleapis.com" {
			t.Fatalf("callout destination = %q, want vertex.googleapis.com", gotDest)
		}
		if !hadDeadline {
			t.Fatalf("expected callout stream to have context deadline")
		}

		respHeader := make(http.Header)
		immResp, newRespBody, err := session.RunResponsePhase(http.StatusOK, respHeader, []byte("completion RAW_OUTPUT"))
		if err != nil {
			t.Fatalf("RunResponsePhase: %v", err)
		}
		if immResp != nil {
			t.Fatalf("unexpected response ImmediateResponse")
		}
		if string(newRespBody) != "completion SANITIZED_OUTPUT" {
			t.Fatalf("newRespBody = %q", string(newRespBody))
		}
		if respHeader.Get("X-Callout-Response") != "verified" {
			t.Fatalf("expected X-Callout-Response=verified")
		}
	})

	t.Run("tls_alpn_h2_trailers_only_rejection_and_timeout", func(t *testing.T) {
		secretsDir := t.TempDir()
		serverCert, caPEM, clientPEM := generateTestCerts(t)
		if err := os.WriteFile(filepath.Join(secretsDir, "ca.pem"), caPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(secretsDir, "client.pem"), clientPEM, 0o600); err != nil {
			t.Fatal(err)
		}

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		callout := &referenceCalloutServer{}

		// The test name promises mTLS, so the server must actually require
		// and verify a client certificate against the same CA the client
		// is configured with - otherwise this only exercises one-way TLS
		// and a regression that drops client-cert enforcement would pass
		// silently.
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			t.Fatalf("failed to parse CA cert for client-auth pool")
		}
		srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2"},
		})))
		extprocv3.RegisterExternalProcessorServer(srv, callout)
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(srv.Stop)

		cfg := &api.ExtProc{
			Target:            "https://" + ln.Addr().String(),
			Ca:                "ca.pem",
			ClientCertificate: "client.pem",
			MessageTimeout:    durationpb.New(100 * time.Millisecond),
			AllowModeOverride: true,
		}
		client, err := NewCalloutClient(cfg, secretsDir)
		if err != nil {
			t.Fatalf("NewCalloutClient TLS: %v", err)
		}

		// 1. Trailers-only PermissionDenied error
		reqErr := httptest.NewRequest(http.MethodPost, "https://vertex.googleapis.com/trailers-only-error", nil)
		_, _, _, err = client.RunRequestPhase(reqErr, cfg, "vertex.googleapis.com", nil, nil)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected codes.PermissionDenied, got %v", err)
		}

		// 2. ImmediateResponse deny
		reqDeny := httptest.NewRequest(http.MethodPost, "https://vertex.googleapis.com/immediate-deny", nil)
		sess, imm, _, err := client.RunRequestPhase(reqDeny, cfg, "vertex.googleapis.com", nil, nil)
		if err != nil {
			t.Fatalf("RunRequestPhase immediate-deny: %v", err)
		}
		sess.Close()
		if imm.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
			t.Fatalf("expected Forbidden ImmediateResponse, got %+v", imm)
		}

		// 3. Message timeout enforcement
		callout.mu.Lock()
		callout.sleepDuration = 500 * time.Millisecond
		callout.mu.Unlock()
		reqTimeout := httptest.NewRequest(http.MethodPost, "https://vertex.googleapis.com/slow", nil)
		_, _, _, err = client.RunRequestPhase(reqTimeout, cfg, "vertex.googleapis.com", nil, nil)
		if err == nil || !strings.Contains(err.Error(), "message_timeout") {
			t.Fatalf("expected message_timeout error, got %v", err)
		}
	})
}

func generateTestCerts(t *testing.T) (tls.Certificate, []byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return tlsCert, certPEM, append(append([]byte(nil), certPEM...), keyPEM...)
}
