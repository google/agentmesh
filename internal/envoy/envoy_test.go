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
	"strconv"
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
		if in.MCPTool == "merge_pr" {
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
						"authorization":          "Bearer valid-token",
						"x-mesh-target-service":  "inference://laptop-llm",
						"x-mesh-authentication":  "Bearer task-biscuit",
						"x-mesh-required-labels": "region=eu",
						"x-mesh-labels":          "device_trust=high",
						"x-mesh-origin":          "spoofed-local",
						"x-mesh-task":            "forged-task",
						"x-peer-id":              "forged-peer",
						"x-mesh-task-id":         "forged-id",
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
		if h == "x-mesh-task-id" || h == "x-mesh-target-service" || h == "x-mesh-authentication" || h == "x-mesh-required-labels" {
			t.Errorf("HeadersToRemove must not remove %q: %v", h, removed)
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

// The evaluator returns an upstream credential only to a caller that the
// transport authenticates as the gateway (GHSA-2g97-3v45-p9f4). Each entry
// point must hand it that fact from the connection of the request.
func TestGatewayServer_TrustedTransport(t *testing.T) {
	const seenHeader = "X-Test-Trusted-Transport"
	eval := func(_ context.Context, in CheckInput) CheckResult {
		return CheckResult{
			Allowed:         true,
			HTTPStatus:      http.StatusOK,
			ResponseHeaders: map[string]string{seenHeader: strconv.FormatBool(in.TrustedTransport)},
		}
	}
	seenIn := func(headers []*corev3.HeaderValueOption) string {
		for _, h := range headers {
			if h.GetHeader().GetKey() == seenHeader {
				return h.GetHeader().GetValue() + string(h.GetHeader().GetRawValue())
			}
		}
		return ""
	}
	verifiedClientCert := func(r *http.Request) bool {
		return r.TLS != nil && len(r.TLS.VerifiedChains) > 0
	}

	gw := NewGatewayServer(eval)
	gw.TrustedTransport = verifiedClientCert
	plainAddr := startH2CGatewayTestServer(t, gw)

	serverCert, caPEM, _ := generateTestCerts(t)
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse the test CA certificate")
	}
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)
	mtlsServer := httptest.NewUnstartedServer(mux)
	mtlsServer.EnableHTTP2 = true
	mtlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	mtlsServer.StartTLS()
	t.Cleanup(mtlsServer.Close)
	clientTLS := &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{serverCert}}

	transports := []struct {
		name       string
		addr       string
		baseURL    string
		httpClient *http.Client
		grpcCreds  credentials.TransportCredentials
		want       string
	}{
		{
			name:       "plain TCP",
			addr:       plainAddr,
			baseURL:    "http://" + plainAddr,
			httpClient: &http.Client{},
			grpcCreds:  insecure.NewCredentials(),
			want:       "false",
		},
		{
			name:       "verified client certificate",
			addr:       mtlsServer.Listener.Addr().String(),
			baseURL:    mtlsServer.URL,
			httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS, ForceAttemptHTTP2: true}},
			grpcCreds:  credentials.NewTLS(clientTLS),
			want:       "true",
		},
	}
	entryPoints := []struct {
		name string
		seen func(ctx context.Context, httpClient *http.Client, baseURL string, conn *grpc.ClientConn) (string, error)
	}{
		{"HTTP ext_authz", func(ctx context.Context, httpClient *http.Client, baseURL string, _ *grpc.ClientConn) (string, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/ext_authz/", nil)
			if err != nil {
				return "", err
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				return "", err
			}
			_ = resp.Body.Close()
			return resp.Header.Get(seenHeader), nil
		}},
		{"gRPC Check v3", func(ctx context.Context, _ *http.Client, _ string, conn *grpc.ClientConn) (string, error) {
			resp, err := authv3.NewAuthorizationClient(conn).Check(ctx, &authv3.CheckRequest{})
			if err != nil {
				return "", err
			}
			return seenIn(resp.GetOkResponse().GetHeaders()), nil
		}},
		{"gRPC Check v2", func(ctx context.Context, _ *http.Client, _ string, conn *grpc.ClientConn) (string, error) {
			var resp authv3.CheckResponse
			if err := conn.Invoke(ctx, ExtAuthzV2MethodPath, &authv3.CheckRequest{}, &resp); err != nil {
				return "", err
			}
			return seenIn(resp.GetOkResponse().GetHeaders()), nil
		}},
		{"gRPC ext_proc", func(ctx context.Context, _ *http.Client, _ string, conn *grpc.ClientConn) (string, error) {
			stream, err := extprocv3.NewExternalProcessorClient(conn).Process(ctx)
			if err != nil {
				return "", err
			}
			if err := stream.Send(&extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestHeaders{
					RequestHeaders: &extprocv3.HttpHeaders{EndOfStream: true},
				},
			}); err != nil {
				return "", err
			}
			resp, err := stream.Recv()
			if err != nil {
				return "", err
			}
			return seenIn(resp.GetRequestHeaders().GetResponse().GetHeaderMutation().GetSetHeaders()), nil
		}},
	}
	for _, tr := range transports {
		conn, err := grpc.NewClient("passthrough:///"+tr.addr, grpc.WithTransportCredentials(tr.grpcCreds))
		if err != nil {
			t.Fatalf("grpc.NewClient over %s: %v", tr.name, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		for _, ep := range entryPoints {
			t.Run(tr.name+"/"+ep.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				got, err := ep.seen(ctx, tr.httpClient, tr.baseURL, conn)
				if err != nil {
					t.Fatalf("%s over %s: %v", ep.name, tr.name, err)
				}
				if got != tr.want {
					t.Errorf("the evaluator saw TrustedTransport = %q, want %q", got, tr.want)
				}
			})
		}
	}

	t.Run("no transport is trusted when the server has no rule", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ext_authz/", nil)
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
		rec := httptest.NewRecorder()
		NewGatewayServer(eval).HandleExtAuthzHTTP(rec, req)
		if got := rec.Header().Get(seenHeader); got != "false" {
			t.Errorf("the evaluator saw TrustedTransport = %q, want %q", got, "false")
		}
	})
}

func TestGatewayServer_ExtProcProcess(t *testing.T) {
	gw := NewGatewayServer(func(_ context.Context, in CheckInput) CheckResult {
		if in.MCPTool == "merge_pr" {
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
						{Key: "x-mesh-target-service", Value: "mcp://github"},
						{Key: "x-mesh-authentication", Value: "Bearer task-biscuit"},
						{Key: "x-mesh-required-labels", Value: "region=eu"},
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
		if h == "x-mesh-task-id" || h == "x-mesh-target-service" || h == "x-mesh-authentication" || h == "x-mesh-required-labels" {
			t.Errorf("ext_proc RemoveHeaders must not remove %q: %v", h, extProcRemoved)
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

// The body names the tool of an MCP tools/call. A client can set any request
// header, so a header that names another tool must not change the decision of
// any of the three check services.
func TestGatewayServer_BodyDecidesMCPTool(t *testing.T) {
	// The evaluator stands for a task rule with allowed_tools: [get_pr].
	gw := NewGatewayServer(func(_ context.Context, in CheckInput) CheckResult {
		if in.MCPTool == "get_pr" || (in.MCPTool == "" && in.AllowMCPStreamInit) {
			return CheckResult{Allowed: true, HTTPStatus: http.StatusOK}
		}
		return CheckResult{Allowed: false, HTTPStatus: http.StatusForbidden, Message: "tool " + in.MCPTool + " is not allowed"}
	})
	addr := startH2CGatewayTestServer(t, gw)
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	procClient := extprocv3.NewExternalProcessorClient(conn)

	const clientHeader = "x-mesh-mcp-tool"

	// extProc sends one request through ext_proc. It reports whether the
	// processor asked Envoy for the body and whether it refused the request.
	extProc := func(t *testing.T, path, headerTool, body string) (buffered, denied bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stream, err := procClient.Process(ctx)
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
		hdrs := []*corev3.HeaderValue{{Key: ":method", Value: "POST"}, {Key: ":path", Value: path}}
		if headerTool != "" {
			hdrs = append(hdrs, &corev3.HeaderValue{Key: clientHeader, Value: headerTool})
		}
		if err := stream.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: hdrs}},
		}}); err != nil {
			t.Fatalf("Send RequestHeaders: %v", err)
		}
		r1, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv RequestHeaders: %v", err)
		}
		if r1.GetImmediateResponse() != nil {
			return false, true
		}
		if r1.GetModeOverride().GetRequestBodyMode() != extprocv3http.ProcessingMode_BUFFERED {
			// Envoy sends no body: the answer to the headers was the decision.
			return false, false
		}
		if err := stream.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: []byte(body), EndOfStream: true},
		}}); err != nil {
			t.Fatalf("Send RequestBody: %v", err)
		}
		r2, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv RequestBody: %v", err)
		}
		return true, r2.GetImmediateResponse() != nil
	}

	for _, tc := range []struct {
		name       string
		path       string
		headerTool string
		bodyTool   string
		wantDenied bool
	}{
		{name: "allowed tool in the body", path: "/mesh/mcp/github", bodyTool: "get_pr"},
		{name: "refused tool in the body", path: "/mesh/mcp/github", bodyTool: "merge_pr", wantDenied: true},
		{name: "refused tool in the body, allowed tool in a header", path: "/mesh/mcp/github", headerTool: "get_pr", bodyTool: "merge_pr", wantDenied: true},
		{name: "allowed tool in the body, refused tool in a header", path: "/mesh/mcp/github", headerTool: "merge_pr", bodyTool: "get_pr"},
		{name: "service type in upper case, refused tool in the body, allowed tool in a header", path: "/mesh/MCP/github", headerTool: "get_pr", bodyTool: "merge_pr", wantDenied: true},
		{name: "service type in upper case, allowed tool in the body", path: "/mesh/MCP/github", bodyTool: "get_pr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tc.bodyTool + `"}}`

			httpReq := httptest.NewRequest(http.MethodPost, "/ext_authz"+tc.path, strings.NewReader(body))
			if tc.headerTool != "" {
				httpReq.Header.Set(clientHeader, tc.headerTool)
			}
			rec := httptest.NewRecorder()
			gw.HandleExtAuthzHTTP(rec, httpReq)
			if denied := rec.Code != http.StatusOK; denied != tc.wantDenied {
				t.Errorf("HTTP ext_authz: status %d, denied = %v, want %v", rec.Code, denied, tc.wantDenied)
			}

			grpcHeaders := map[string]string{}
			if tc.headerTool != "" {
				grpcHeaders[clientHeader] = tc.headerTool
			}
			resp, err := gw.Check(context.Background(), &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
					Method: http.MethodPost, Path: tc.path, Headers: grpcHeaders, Body: body,
				}},
			}})
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if denied := resp.GetStatus().GetCode() != int32(codes.OK); denied != tc.wantDenied {
				t.Errorf("gRPC ext_authz: status code %d, denied = %v, want %v", resp.GetStatus().GetCode(), denied, tc.wantDenied)
			}

			buffered, denied := extProc(t, tc.path, tc.headerTool, body)
			if !buffered {
				t.Errorf("ext_proc: the processor did not ask Envoy for the request body")
			}
			if denied != tc.wantDenied {
				t.Errorf("ext_proc: denied = %v, want %v", denied, tc.wantDenied)
			}
		})
	}
}

// The tool of an MCP tools/call is in the body. An ext_authz check for a POST
// that carries no body names no tool and is not a handshake, so the evaluator
// refuses it for a rule with allowed_tools. A GET or a DELETE carries no call.
func TestGatewayServer_ExtAuthzWithoutBody(t *testing.T) {
	var got CheckInput
	gw := NewGatewayServer(func(_ context.Context, in CheckInput) CheckResult {
		got = in
		return CheckResult{Allowed: true, HTTPStatus: http.StatusOK}
	})
	for _, tc := range []struct {
		method        string
		wantHandshake bool
	}{
		{method: http.MethodPost, wantHandshake: false},
		{method: http.MethodGet, wantHandshake: true},
		{method: http.MethodDelete, wantHandshake: true},
	} {
		t.Run(tc.method, func(t *testing.T) {
			gw.HandleExtAuthzHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, "/ext_authz/mesh/mcp/github", nil))
			if got.MCPTool != "" || got.AllowMCPStreamInit != tc.wantHandshake {
				t.Errorf("HTTP ext_authz with no body: tool %q, handshake %v, want no tool and handshake %v", got.MCPTool, got.AllowMCPStreamInit, tc.wantHandshake)
			}
			if _, err := gw.Check(context.Background(), &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Method: tc.method, Path: "/mesh/mcp/github"}},
			}}); err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got.MCPTool != "" || got.AllowMCPStreamInit != tc.wantHandshake {
				t.Errorf("gRPC ext_authz with no body: tool %q, handshake %v, want no tool and handshake %v", got.MCPTool, got.AllowMCPStreamInit, tc.wantHandshake)
			}
		})
	}
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
