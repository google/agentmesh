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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/openai/openai-go"
)

// backendProbeTTL bounds backend capability probes (models, tools): the
// announcer ticks more often than backends change.
const backendProbeTTL = 30 * time.Second

// InferenceService provides intelligent LLM gateway features: traffic routing
// and token usage tracking for OpenAI-compatible endpoints.
type InferenceService struct {
	baseService
	backendURL  *url.URL
	backendAuth backendTarget
	engine      InferenceEngine
	active      atomic.Int64

	modelsMu      sync.Mutex
	cachedModels  []string
	modelsExpires time.Time
}

func (s *InferenceService) Init(ctx context.Context) error {
	switch x := s.backend.(type) {
	case *api.RegisterServiceRequest_TargetUrl:
		target, err := parseBackendTarget(x.TargetUrl)
		if err != nil {
			return fmt.Errorf("invalid inference backend URL: %w", err)
		}
		s.backendURL = target.url
		s.backendAuth = target
		s.engine = newOpenAIEngine(target.url, target.client())
		s.handler = s.trackActive(s.trackUsage(s.newInferenceProxy()))
	case *api.RegisterServiceRequest_Command:
		return fmt.Errorf("command-based backends are not supported for InferenceService")
	default:
		return fmt.Errorf("unsupported backend type %T for InferenceService", s.backend)
	}
	return nil
}

// Models returns the model IDs the backend serves, cached briefly since both
// the discovery announcer and the OpenAI facade call it repeatedly.
func (s *InferenceService) Models(ctx context.Context) ([]string, error) {
	if s.engine == nil {
		return nil, fmt.Errorf("inference service %q not initialized", s.info.GetName())
	}
	s.modelsMu.Lock()
	defer s.modelsMu.Unlock()
	if s.cachedModels != nil && time.Now().Before(s.modelsExpires) {
		return s.cachedModels, nil
	}
	models, err := s.engine.Models(ctx)
	if err != nil {
		return nil, err
	}
	s.cachedModels = models
	s.modelsExpires = time.Now().Add(backendProbeTTL)
	return models, nil
}

// ActiveRequests reports in-flight requests, a load hint for announcements.
func (s *InferenceService) ActiveRequests() uint32 {
	n := s.active.Load()
	if n < 0 {
		return 0
	}
	return uint32(n)
}

func (s *InferenceService) trackActive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.active.Add(1)
		defer s.active.Add(-1)
		next.ServeHTTP(w, r)
	})
}

func (s *InferenceService) trackUsage(next http.Handler) http.Handler {
	serviceName := "unknown"
	if s.info != nil && s.info.GetName() != "" {
		serviceName = s.info.GetName()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isDiscoveryProbe(r) {
			next.ServeHTTP(w, r)
			return
		}

		peerID := getPeerID(r)

		recordInferenceRequest(peerID, serviceName)

		var reqBytes atomic.Int64
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &countingReadCloser{
				ReadCloser: r.Body,
				count:      &reqBytes,
			}
		}

		cw := &countingResponseWriter{
			ResponseWriter: w,
		}

		defer func() {
			recordInferenceBytes(peerID, serviceName, reqBytes.Load(), cw.bytesWritten.Load())
		}()

		next.ServeHTTP(cw, r)
	})
}

func isDiscoveryProbe(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/v1/models" || strings.HasSuffix(r.URL.Path, "/v1/models") || r.URL.Path == "/models" || strings.HasSuffix(r.URL.Path, "/models"))
}

type countingReadCloser struct {
	io.ReadCloser
	count *atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.count.Add(int64(n))
	}
	return n, err
}

func (c *countingReadCloser) Close() error {
	return c.ReadCloser.Close()
}

type countingResponseWriter struct {
	http.ResponseWriter
	bytesWritten atomic.Int64
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.bytesWritten.Add(int64(n))
	}
	return n, err
}

func (w *countingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *countingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *InferenceService) newInferenceProxy() http.Handler {
	serviceName := "unknown"
	if s.info != nil && s.info.GetName() != "" {
		serviceName = s.info.GetName()
	}
	return &httputil.ReverseProxy{
		// The transport addresses the backend; the proxy itself strips the
		// inbound Forwarded and X-Forwarded-* headers and blanks a missing
		// User-Agent.
		Rewrite: func(*httputil.ProxyRequest) {},
		Transport: &inferenceTransport{
			service: serviceName,
			backend: s.backendURL,
			auth:    s.backendAuth,
			base:    http.DefaultTransport,
		},
	}
}

type inferenceTransport struct {
	service string
	backend *url.URL
	auth    backendTarget
	base    http.RoundTripper
}

func (t *inferenceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attemptReq := req.Clone(req.Context())
	attemptReq.Header.Del("Accept-Encoding") // Prevent gzipped response from breaking token tracking
	t.auth.apply(attemptReq.Header)

	attemptReq.URL.Scheme = t.backend.Scheme
	attemptReq.URL.Host = t.backend.Host
	attemptReq.URL.Path = singleJoiningSlash(t.backend.Path, req.URL.Path)
	if t.backend.RawQuery == "" || attemptReq.URL.RawQuery == "" {
		attemptReq.URL.RawQuery = t.backend.RawQuery + attemptReq.URL.RawQuery
	} else {
		attemptReq.URL.RawQuery = t.backend.RawQuery + "&" + attemptReq.URL.RawQuery
	}
	attemptReq.Host = t.backend.Host

	resp, err := t.base.RoundTrip(attemptReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		peerID := getPeerID(req)
		isSSE := strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
		resp.Body = newInterceptingReader(resp.Body, peerID, t.service, isSSE)
	}

	return resp, nil
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func getPeerID(r *http.Request) string {
	remoteAddr := r.RemoteAddr
	if remoteAddr != "" {
		if pID, err := peer.Decode(remoteAddr); err == nil {
			return pID.String()
		}
		if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
			if pID, err := peer.Decode(host); err == nil {
				return pID.String()
			}
			// Only trust X-Peer-Id if request comes from local loopback / trusted localhost source
			if host == "127.0.0.1" || host == "::1" || host == "localhost" {
				if peerHeader := r.Header.Get(api.HeaderPeerID); peerHeader != "" {
					if pID, err := peer.Decode(peerHeader); err == nil {
						return pID.String()
					}
				}
			}
		}
	}
	if fromLocalSocket(r) || remoteAddr == "@" {
		if peerHeader := r.Header.Get(api.HeaderPeerID); peerHeader != "" {
			if pID, err := peer.Decode(peerHeader); err == nil {
				return pID.String()
			}
		}
	}
	return "unknown"
}

type interceptingReader struct {
	body io.ReadCloser
	pw   *io.PipeWriter
	done chan struct{}
}

func newInterceptingReader(body io.ReadCloser, peerID, service string, isSSE bool) io.ReadCloser {
	pr, pw := io.Pipe()
	ir := &interceptingReader{
		body: body,
		pw:   pw,
		done: make(chan struct{}),
	}

	go func() {
		defer func() { _ = pr.Close() }()
		defer close(ir.done)
		parseResponseStream(pr, peerID, service, isSSE)
	}()

	return ir
}

func (ir *interceptingReader) Read(p []byte) (n int, err error) {
	n, err = ir.body.Read(p)
	if n > 0 {
		_, _ = ir.pw.Write(p[:n])
	}
	if err != nil {
		_ = ir.pw.CloseWithError(err)
	}
	return n, err
}

func (ir *interceptingReader) Close() error {
	_ = ir.pw.CloseWithError(io.EOF)
	<-ir.done
	return ir.body.Close()
}

func parseResponseStream(r io.Reader, peerID, service string, isSSE bool) {
	if isSSE {
		parseSSEResponse(r, peerID, service)
	} else {
		parseJSONResponse(r, peerID, service)
	}
}

func parseJSONResponse(r io.Reader, peerID, service string) {
	var resp openai.ChatCompletion
	if err := json.NewDecoder(io.LimitReader(r, maxInferenceBodyBytes)).Decode(&resp); err != nil {
		return
	}
	if resp.JSON.Usage.Valid() && (resp.Usage.PromptTokens > 0 || resp.Usage.CompletionTokens > 0) {
		recordTokens(peerID, service, resp.Model, int(resp.Usage.PromptTokens), int(resp.Usage.CompletionTokens))
	}
}

func parseSSEResponse(r io.Reader, peerID, service string) {
	reader := bufio.NewReader(io.LimitReader(r, maxInferenceBodyBytes*4))
	var model string
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			if err == io.EOF {
				break
			}
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			if err == io.EOF {
				break
			}
			continue
		}
		dataContent := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataContent == "[DONE]" {
			break
		}

		var chunk openai.ChatCompletionChunk
		if err := json.Unmarshal([]byte(dataContent), &chunk); err == nil {
			if chunk.Model != "" {
				model = chunk.Model
			}
			if chunk.JSON.Usage.Valid() && (chunk.Usage.PromptTokens > 0 || chunk.Usage.CompletionTokens > 0) {
				recordTokens(peerID, service, model, int(chunk.Usage.PromptTokens), int(chunk.Usage.CompletionTokens))
				break
			}
		}
		if err == io.EOF {
			break
		}
	}
}
