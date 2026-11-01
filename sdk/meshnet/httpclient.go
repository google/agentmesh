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

package meshnet

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

// HTTPClient returns an *http.Client whose Transport routes mesh URLs of the
// form http://<any-host>/mesh/<peer_id>/<type>/<name>[/<path>] directly over
// authenticated libp2p /libp2p-http streams via the underlying AgentMeshNode
// egress PEP (performing provider Biscuit, label, egress-floor, and
// publish-grant verification before sending request bytes, and rewriting A2A
// AgentCard interface URLs back onto the local mesh URL).
//
// No client-wide Timeout is set so Server-Sent Events (SSE) and streaming
// completions run unbounded; connection establishment and header reads are
// bounded by the underlying libp2p swarm and stream deadlines.
func (s *Server) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &meshRoundTripper{s: s},
	}
}

type meshRoundTripper struct {
	s *Server
}

func (rt *meshRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s := rt.s
	if !s.isRunning() {
		return nil, errors.New("meshnet: Server is not running (call Up first)")
	}
	if req.URL == nil {
		return nil, errors.New("meshnet: nil request URL")
	}

	path := req.URL.Path
	if api.HasDotSegment(path) {
		return httpErrorResponse(req, http.StatusBadRequest, "Invalid path"), nil
	}
	trimmed := strings.TrimPrefix(path, "/")
	if !strings.HasPrefix(trimmed, "mesh/") {
		return httpErrorResponse(req, http.StatusBadRequest, "meshnet HTTPClient expects /mesh/<peer_id>/<type>/<name> paths"), nil
	}
	parts := strings.SplitN(strings.TrimPrefix(trimmed, "mesh/"), "/", 4)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return httpErrorResponse(req, http.StatusBadRequest, "Invalid mesh path: expected /mesh/<peer_id>/<type>/<name>"), nil
	}
	if _, err := peer.Decode(parts[0]); err != nil {
		return httpErrorResponse(req, http.StatusBadRequest, "Invalid peer ID"), nil
	}
	svcType, err := api.ParseServiceType(strings.ToLower(parts[1]))
	if err != nil || svcType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return httpErrorResponse(req, http.StatusBadRequest, "Invalid service type"), nil
	}

	outReq := req.Clone(req.Context())
	outReq.Header = sanitizeCallerMeshHeaders(req.Header)
	hostHeader := req.Host
	if hostHeader == "" {
		hostHeader = req.URL.Host
	}
	if hostHeader == "" {
		hostHeader = "agentmesh.local"
	}
	outReq.Host = hostHeader

	pr, pw := io.Pipe()
	rw := newPipeResponseWriter(req, pw)
	handler := s.node.EgressHandler()

	go func() {
		defer rw.finish()
		handler.ServeHTTP(rw, outReq)
	}()

	return rw.waitResponse(pr), nil
}

func sanitizeCallerMeshHeaders(in http.Header) http.Header {
	out := in.Clone()
	if out == nil {
		out = make(http.Header)
	}
	for k := range out {
		lower := strings.ToLower(k)
		if lower == "cookie" || strings.EqualFold(k, api.HeaderPeerID) {
			delete(out, k)
			continue
		}
		if strings.HasPrefix(lower, "x-mesh-") &&
			!strings.EqualFold(k, api.HeaderMeshRequiredLabels) &&
			!strings.EqualFold(k, api.HeaderMeshAuthentication) &&
			!strings.EqualFold(k, api.HeaderMeshBiscuit) {
			delete(out, k)
		}
	}
	return out
}

type pipeResponseWriter struct {
	req        *http.Request
	pw         *io.PipeWriter
	hdr        http.Header
	once       sync.Once
	ready      chan struct{}
	statusCode int
	respHdr    http.Header
}

func newPipeResponseWriter(req *http.Request, pw *io.PipeWriter) *pipeResponseWriter {
	return &pipeResponseWriter{
		req:        req,
		pw:         pw,
		hdr:        make(http.Header),
		ready:      make(chan struct{}),
		statusCode: http.StatusOK,
	}
}

func (w *pipeResponseWriter) Header() http.Header {
	return w.hdr
}

func (w *pipeResponseWriter) WriteHeader(code int) {
	w.once.Do(func() {
		w.statusCode = code
		w.respHdr = w.hdr.Clone()
		close(w.ready)
	})
}

func (w *pipeResponseWriter) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.pw.Write(p)
}

func (w *pipeResponseWriter) Flush() {
	w.WriteHeader(http.StatusOK)
}

func (w *pipeResponseWriter) finish() {
	w.WriteHeader(http.StatusOK)
	_ = w.pw.Close()
}

func (w *pipeResponseWriter) waitResponse(pr *io.PipeReader) *http.Response {
	<-w.ready
	contentLen := int64(-1)
	if cl := w.respHdr.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n >= 0 {
			contentLen = n
		}
	}
	return &http.Response{
		StatusCode:    w.statusCode,
		Status:        fmt.Sprintf("%d %s", w.statusCode, http.StatusText(w.statusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        w.respHdr,
		Body:          pr,
		ContentLength: contentLen,
		Request:       w.req,
	}
}

func httpErrorResponse(req *http.Request, code int, msg string) *http.Response {
	body := msg + "\n"
	hdr := make(http.Header)
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		StatusCode:    code,
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
