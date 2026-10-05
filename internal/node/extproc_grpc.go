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
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/sam/api"
	corev3 "github.com/google/sam/third_party/envoy/envoy/config/core/v3"
	extprocv3http "github.com/google/sam/third_party/envoy/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/google/sam/third_party/envoy/envoy/service/ext_proc/v3"
	typev3 "github.com/google/sam/third_party/envoy/envoy/type/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ExtProcMethodPath is the gRPC HTTP/2 path for Envoy ExternalProcessor.Process.
const ExtProcMethodPath = "/envoy.service.ext_proc.v3.ExternalProcessor/Process"

const maxGRPCFrameBytes = 16 << 20 // 16 MiB

func writeGRPCProtoFrame(w io.Writer, msg proto.Message) error {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = 0 // uncompressed
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	_, err = w.Write(frame)
	return err
}

func readGRPCProtoFrame(r io.Reader, msg proto.Message) error {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0 {
		return fmt.Errorf("compressed gRPC frame (flag=%d) is not supported", hdr[0])
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length > maxGRPCFrameBytes {
		return fmt.Errorf("gRPC frame size %d exceeds limit %d", length, maxGRPCFrameBytes)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return proto.Unmarshal(payload, msg)
}

func formatGRPCTimeout(d time.Duration) string {
	if d <= 0 {
		return "200m"
	}
	if ms := d.Milliseconds(); ms > 0 && ms < 100000 {
		return strconv.FormatInt(ms, 10) + "m"
	}
	if s := int64(d.Seconds()); s > 0 {
		return strconv.FormatInt(s, 10) + "S"
	}
	return "200m"
}

// extProcClientStream wraps a single HTTP/2 bidirectional gRPC stream to an
// ExternalProcessor server using the Go standard library net/http transport.
type extProcClientStream struct {
	cancel    context.CancelFunc
	pw        *io.PipeWriter
	respReady chan struct{}
	resp      *http.Response
	respErr   error
	writeMu   sync.Mutex
}

func dialExtProcStream(ctx context.Context, client *http.Client, endpoint string, timeout time.Duration) (*extProcClientStream, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()

	req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, endpoint, pr)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("TE", "trailers")
	if timeout > 0 {
		req.Header.Set("Grpc-Timeout", formatGRPCTimeout(timeout))
	}

	s := &extProcClientStream{
		cancel:    cancel,
		pw:        pw,
		respReady: make(chan struct{}),
	}
	go func() {
		defer close(s.respReady)
		s.resp, s.respErr = client.Do(req)
	}()
	return s, nil
}

func (s *extProcClientStream) Send(msg *extprocv3.ProcessingRequest) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeGRPCProtoFrame(s.pw, msg)
}

func (s *extProcClientStream) CloseSend() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.pw.Close()
}

func (s *extProcClientStream) Recv(msgTimeout time.Duration) (*extprocv3.ProcessingResponse, error) {
	type recvResult struct {
		resp *extprocv3.ProcessingResponse
		err  error
	}
	ch := make(chan recvResult, 1)
	go func() {
		<-s.respReady
		if s.respErr != nil {
			ch <- recvResult{err: s.respErr}
			return
		}
		if s.resp.StatusCode != http.StatusOK {
			ch <- recvResult{err: fmt.Errorf("ext_proc HTTP status %d", s.resp.StatusCode)}
			return
		}
		// Check trailers-only gRPC status in initial headers.
		if st := s.resp.Header.Get("Grpc-Status"); st != "" && st != "0" {
			ch <- recvResult{err: fmt.Errorf("ext_proc grpc-status %s: %s", st, s.resp.Header.Get("Grpc-Message"))}
			return
		}
		var out extprocv3.ProcessingResponse
		if err := readGRPCProtoFrame(s.resp.Body, &out); err != nil {
			if errors.Is(err, io.EOF) {
				if st := s.resp.Trailer.Get("Grpc-Status"); st != "" && st != "0" {
					ch <- recvResult{err: fmt.Errorf("ext_proc trailer grpc-status %s: %s", st, s.resp.Trailer.Get("Grpc-Message"))}
					return
				}
			}
			ch <- recvResult{err: err}
			return
		}
		ch <- recvResult{resp: &out}
	}()

	if msgTimeout <= 0 {
		msgTimeout = 200 * time.Millisecond
	}
	timer := time.NewTimer(msgTimeout)
	defer timer.Stop()

	select {
	case res := <-ch:
		return res.resp, res.err
	case <-timer.C:
		s.Close()
		return nil, fmt.Errorf("ext_proc message_timeout (%s) exceeded", msgTimeout)
	}
}

func (s *extProcClientStream) Close() {
	_ = s.pw.Close()
	s.cancel()
	select {
	case <-s.respReady:
		if s.resp != nil && s.resp.Body != nil {
			_ = s.resp.Body.Close()
		}
	default:
	}
}

// buildExtProcHTTPClient constructs an HTTP/2 client for an ExtProc target
// ("unix:/path", "host:port", "http://host:port", or "https://host:port") with
// optional mTLS credentials loaded from secretsDir.
func buildExtProcHTTPClient(cfg *api.ExtProc, secretsDir string) (*http.Client, string, error) {
	rawTarget := strings.TrimSpace(cfg.GetTarget())
	if rawTarget == "" {
		return nil, "", errors.New("ext_proc.target is required")
	}

	var protocols http.Protocols
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
	}

	if sockPath, ok := strings.CutPrefix(rawTarget, "unix:"); ok {
		sockPath = strings.TrimPrefix(sockPath, "//")
		protocols.SetUnencryptedHTTP2(true)
		tr.Protocols = &protocols
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sockPath)
		}
		return &http.Client{Transport: tr}, "http://localhost" + ExtProcMethodPath, nil
	}

	useTLS := strings.HasPrefix(rawTarget, "https://") || cfg.GetCa() != "" || cfg.GetClientCertificate() != ""
	endpointHost := strings.TrimPrefix(strings.TrimPrefix(rawTarget, "https://"), "http://")
	endpointHost = strings.TrimRight(endpointHost, "/")

	if useTLS {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2"},
		}
		if caFile := strings.TrimSpace(cfg.GetCa()); caFile != "" {
			pemBytes, err := os.ReadFile(filepath.Join(secretsDir, caFile))
			if err != nil {
				return nil, "", fmt.Errorf("ext_proc.ca %q: %w", caFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, "", fmt.Errorf("ext_proc.ca %q: failed to parse PEM certificates", caFile)
			}
			tlsCfg.RootCAs = pool
		}
		if certFile := strings.TrimSpace(cfg.GetClientCertificate()); certFile != "" {
			pemBytes, err := os.ReadFile(filepath.Join(secretsDir, certFile))
			if err != nil {
				return nil, "", fmt.Errorf("ext_proc.client_certificate %q: %w", certFile, err)
			}
			cert, err := tls.X509KeyPair(pemBytes, pemBytes)
			if err != nil {
				return nil, "", fmt.Errorf("ext_proc.client_certificate %q: %w", certFile, err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		protocols.SetHTTP2(true)
		tr.Protocols = &protocols
		tr.TLSClientConfig = tlsCfg
		return &http.Client{Transport: tr}, "https://" + endpointHost + ExtProcMethodPath, nil
	}

	protocols.SetUnencryptedHTTP2(true)
	tr.Protocols = &protocols
	return &http.Client{Transport: tr}, "http://" + endpointHost + ExtProcMethodPath, nil
}

// handleGatewayExtProc serves envoy.service.ext_proc.v3.ExternalProcessor/Process
// on sam-node so an existing gateway (agentgateway, Istio, Envoy) can delegate
// body-aware MCP tool authorization and upstream credential brokering over a
// single filter.
func handleGatewayExtProc(node *SamNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/grpc+proto")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()

	var capturedHeaders map[string]string
	var capturedMethod, capturedPath, capturedHost string
	var pendingCheck bool

	for {
		var req extprocv3.ProcessingRequest
		if err := readGRPCProtoFrame(r.Body, &req); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			w.Header().Set("Grpc-Status", "13")
			w.Header().Set("Grpc-Message", err.Error())
			return
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

			// If this is a POST with a body (e.g. MCP JSON-RPC tools/call) and no
			// X-Sam-Mcp-Tool header was pre-populated, request the buffered request
			// body before making the final authorization decision.
			targetHdr := strings.ToLower(capturedHeaders[strings.ToLower(api.HeaderSamTargetService)])
			isMCPRoute := strings.HasPrefix(capturedPath, "/mcp") ||
				strings.Contains(capturedPath, "/mcp/") ||
				strings.HasPrefix(targetHdr, api.ServiceTypeStringMCP+"://")
			if !phase.RequestHeaders.GetEndOfStream() &&
				strings.EqualFold(capturedMethod, http.MethodPost) &&
				capturedHeaders[strings.ToLower(HeaderSamMCPTool)] == "" &&
				isMCPRoute {
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
			} else {
				resp = evaluateGatewayExtProcDecision(r.Context(), node, capturedMethod, capturedPath, capturedHost, capturedHeaders, false)
			}

		case *extprocv3.ProcessingRequest_RequestBody:
			if len(phase.RequestBody.GetBody()) > 0 && capturedHeaders != nil {
				if tool := extractJSONRPCMCPTool(phase.RequestBody.GetBody()); tool != "" {
					capturedHeaders[strings.ToLower(HeaderSamMCPTool)] = tool
				}
			}
			if pendingCheck {
				pendingCheck = false
				resp = evaluateGatewayExtProcDecision(r.Context(), node, capturedMethod, capturedPath, capturedHost, capturedHeaders, true)
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
			if err := writeGRPCProtoFrame(w, resp); err != nil {
				return
			}
			_ = rc.Flush()
			if resp.GetImmediateResponse() != nil {
				break
			}
		}
	}

	w.Header().Set("Grpc-Status", "0")
	w.Header().Set("Grpc-Message", "")
}

func evaluateGatewayExtProcDecision(ctx context.Context, node *SamNode, method, path, host string, headers map[string]string, isBodyPhase bool) *extprocv3.ProcessingResponse {
	res := evaluateExtAuthz(ctx, node, extAuthzCheckInput{
		Method:  method,
		Path:    path,
		Host:    host,
		Headers: headers,
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
					Details: "sam_ext_proc_denied",
				},
			},
		}
	}

	var setHeaders []*corev3.HeaderValueOption
	for k, v := range res.ResponseHeaders {
		setHeaders = append(setHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   k,
				Value: v,
			},
			Append:       wrapperspb.Bool(false),
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	common := &extprocv3.CommonResponse{
		Status: extprocv3.CommonResponse_CONTINUE,
		HeaderMutation: &extprocv3.HeaderMutation{
			SetHeaders: setHeaders,
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

func extractJSONRPCMCPTool(body []byte) string {
	var rpc struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return ""
	}
	if rpc.Method == "tools/call" && strings.TrimSpace(rpc.Params.Name) != "" {
		rawTool := strings.TrimSpace(rpc.Params.Name)
		if _, stripped, err := api.SplitToolName(rawTool); err == nil {
			return stripped
		}
		return rawTool
	}
	return ""
}
