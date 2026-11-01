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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/agentmesh/api"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// HTTPClient returns an *http.Client whose Transport routes mesh URLs of the
// form http://<any-host>/mesh/<peer_id>/<type>/<name>[/<path>] directly over
// authenticated libp2p /libp2p-http streams (performing provider Biscuit +
// label + publish-grant verification before sending request bytes, and
// rewriting A2A AgentCard interface URLs back onto the local mesh URL).
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
	if s.host == nil {
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

	peerIDStr := parts[0]
	svcTypeStr := strings.ToLower(parts[1])
	svcName := parts[2]
	upstreamPath := ""
	if len(parts) > 3 {
		upstreamPath = parts[3]
	}

	pid, err := peer.Decode(peerIDStr)
	if err != nil {
		return httpErrorResponse(req, http.StatusBadRequest, "Invalid peer ID"), nil
	}
	if s.isPeerBanned(pid) {
		return httpErrorResponse(req, http.StatusForbidden, "Target peer is banned"), nil
	}
	svcType, err := api.ParseServiceType(svcTypeStr)
	if err != nil || svcType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return httpErrorResponse(req, http.StatusBadRequest, "Invalid service type"), nil
	}

	required, err := parseRequiredLabels(req.Header.Get(api.HeaderMeshRequiredLabels))
	if err != nil {
		return httpErrorResponse(req, http.StatusBadRequest, fmt.Sprintf("Invalid %s header: %v", api.HeaderMeshRequiredLabels, err)), nil
	}

	// Verify provider identity, required labels, egress floor, and publish grant
	// BEFORE sending any request bytes.
	if err := s.verifyProvider(req.Context(), pid, required, svcTypeStr+"://"+svcName); err != nil {
		text, code := labelGateStatus(err, "Provider failed verification")
		s.log().Warn("outbound mesh HTTP provider verification failed",
			"peer_id", pid.String(),
			"service", svcTypeStr+"://"+svcName,
			"error", err,
		)
		return httpErrorResponse(req, code, text), nil
	}

	biscuitBytes := s.currentBiscuit()
	if len(biscuitBytes) == 0 {
		return nil, errors.New("meshnet: missing local member credential")
	}

	p2pTr := libp2phttp.NewTransport(s.host)
	ctx := network.WithAllowLimitedConn(req.Context(), "meshnet-egress")
	s.preparePeerAddrs(ctx, pid)

	if svcType == api.ServiceType_SERVICE_TYPE_A2A && req.Method == http.MethodGet &&
		(upstreamPath == "" || upstreamPath == a2aAgentCardPath) {
		return s.roundTripAgentCard(ctx, p2pTr, req, pid, svcTypeStr, svcName, biscuitBytes)
	}

	targetPath := fmt.Sprintf("/%s/%s", svcTypeStr, svcName)
	if upstreamPath != "" {
		targetPath += "/" + upstreamPath
	} else if strings.HasSuffix(path, "/") {
		targetPath += "/"
	}
	targetURL := "libp2p://" + pid.String() + targetPath
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}

	outReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, req.Body)
	if err != nil {
		return nil, err
	}
	outReq.ContentLength = req.ContentLength
	outReq.Header = sanitizeOutboundMeshHeaders(req.Header, biscuitBytes)
	outReq.Host = pid.String()

	resp, err := (&http.Client{Transport: p2pTr}).Do(outReq)
	if err != nil {
		_ = s.host.Peerstore().Put(pid, peerstoreKeyPrivateIPFailed, true)
		return httpErrorResponse(req, http.StatusBadGateway, fmt.Sprintf("Bad Gateway: %v", err)), nil
	}
	return resp, nil
}

func (s *Server) roundTripAgentCard(ctx context.Context, p2pTr http.RoundTripper, req *http.Request, pid peer.ID, svcTypeStr, svcName string, biscuitBytes []byte) (*http.Response, error) {
	cardURL := fmt.Sprintf("libp2p://%s/%s/%s/%s", pid.String(), svcTypeStr, svcName, a2aAgentCardPath)
	outReq, err := http.NewRequestWithContext(ctx, http.MethodGet, cardURL, nil)
	if err != nil {
		return nil, err
	}
	outReq.Header = sanitizeOutboundMeshHeaders(req.Header, biscuitBytes)
	outReq.Header.Del("Accept-Encoding")
	outReq.Header.Del("If-None-Match")
	outReq.Header.Del("If-Modified-Since")
	outReq.Host = pid.String()

	resp, err := (&http.Client{Transport: p2pTr}).Do(outReq)
	if err != nil {
		_ = s.host.Peerstore().Put(pid, peerstoreKeyPrivateIPFailed, true)
		return httpErrorResponse(req, http.StatusBadGateway, "Bad Gateway: agent card fetch failed"), nil
	}
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()

	var card a2a.AgentCard
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAgentCardBytes)).Decode(&card); err != nil {
		return httpErrorResponse(req, http.StatusBadGateway, "Bad Gateway: agent card is not valid JSON"), nil
	}

	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	hostHeader := req.Host
	if hostHeader == "" {
		hostHeader = req.URL.Host
	}
	if hostHeader == "" {
		hostHeader = "agentmesh.local"
	}
	base := fmt.Sprintf("%s://%s/mesh/%s/%s/%s", scheme, hostHeader, pid.String(), svcTypeStr, svcName)
	if err := regenerateAgentCardForMesh(&card, base); err != nil {
		return httpErrorResponse(req, http.StatusBadGateway, fmt.Sprintf("Bad Gateway: %v", err)), nil
	}
	out, err := json.Marshal(&card)
	if err != nil {
		return httpErrorResponse(req, http.StatusInternalServerError, "Internal Server Error"), nil
	}

	hdr := make(http.Header)
	for _, h := range []string{"Cache-Control", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			hdr.Set(h, v)
		}
	}
	etag := agentCardETag(out)
	hdr.Set("ETag", etag)
	if etagMatches(req.Header.Get("If-None-Match"), etag) {
		return &http.Response{
			StatusCode: http.StatusNotModified,
			Status:     fmt.Sprintf("%d %s", http.StatusNotModified, http.StatusText(http.StatusNotModified)),
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     hdr,
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}

	hdr.Set("Content-Type", "application/json")
	hdr.Set("Content-Length", strconv.Itoa(len(out)))
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(out)),
		ContentLength: int64(len(out)),
		Request:       req,
	}, nil
}

func regenerateAgentCardForMesh(card *a2a.AgentCard, base string) error {
	kept := make([]*a2a.AgentInterface, 0, len(card.SupportedInterfaces))
	for _, iface := range card.SupportedInterfaces {
		if iface == nil || !a2aBindingOverHTTP(iface.ProtocolBinding) {
			continue
		}
		iface.URL = meshInterfaceURL(base, iface.URL)
		kept = append(kept, iface)
	}
	if len(kept) == 0 {
		return errors.New("agent card advertises no HTTP interface (JSONRPC or HTTP+JSON)")
	}
	card.SupportedInterfaces = kept
	card.Signatures = nil
	if card.Skills == nil {
		card.Skills = []a2a.AgentSkill{}
	}
	if card.DefaultInputModes == nil {
		card.DefaultInputModes = []string{}
	}
	if card.DefaultOutputModes == nil {
		card.DefaultOutputModes = []string{}
	}
	return nil
}

func meshInterfaceURL(base, raw string) string {
	ref, err := url.Parse(raw)
	if err != nil || ref.Scheme != "" || ref.Host != "" || ref.User != nil || ref.Opaque != "" ||
		strings.HasPrefix(ref.Path, "/") || api.HasDotSegment(ref.Path) {
		return base
	}
	out := base
	if ref.Path != "" {
		out += "/" + ref.EscapedPath()
	}
	if ref.RawQuery != "" {
		out += "?" + ref.RawQuery
	}
	return out
}

func agentCardETag(card []byte) string {
	sum := sha256.Sum256(card)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}

func sanitizeOutboundMeshHeaders(in http.Header, biscuitBytes []byte) http.Header {
	out := in.Clone()
	if out == nil {
		out = make(http.Header)
	}
	for k := range out {
		lower := strings.ToLower(k)
		if lower == "cookie" || strings.HasPrefix(lower, "x-mesh-") || strings.EqualFold(k, api.HeaderPeerID) {
			delete(out, k)
		}
	}
	out.Set(api.HeaderMeshBiscuit, base64.StdEncoding.EncodeToString(biscuitBytes))
	return out
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
