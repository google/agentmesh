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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/envoy"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultExtProcMaxBufferBytes = envoy.DefaultMaxBufferBytes
	defaultModelArmorTimeout     = 5 * time.Second
)

// boundedResponseRecorder buffers an upstream HTTP response up to maxBytes+1
// so response inspection cannot consume unbounded memory on large or streaming
// upstream payloads.
type boundedResponseRecorder struct {
	header      http.Header
	body        bytes.Buffer
	code        int
	wroteHeader bool
	maxBytes    int64
	overflowed  bool
}

func newBoundedResponseRecorder(maxBytes int64) *boundedResponseRecorder {
	if maxBytes <= 0 {
		maxBytes = defaultExtProcMaxBufferBytes
	}
	return &boundedResponseRecorder{
		header:   make(http.Header),
		code:     http.StatusOK,
		maxBytes: maxBytes,
	}
}

func (r *boundedResponseRecorder) Header() http.Header {
	return r.header
}

func (r *boundedResponseRecorder) WriteHeader(statusCode int) {
	if r.wroteHeader {
		return
	}
	r.code = statusCode
	r.wroteHeader = true
}

func (r *boundedResponseRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	remaining := (r.maxBytes + 1) - int64(r.body.Len())
	if int64(len(p)) > remaining {
		if remaining > 0 {
			_, _ = r.body.Write(p[:remaining])
		}
		r.overflowed = true
		return 0, errors.New("response body exceeds max_buffered_bytes")
	}
	return r.body.Write(p)
}

func buildMeshAttributesStruct(destName string, ec egressCallerContext) map[string]*structpb.Struct {
	st, err := structpb.NewStruct(map[string]any{
		"principal":   ec.principal,
		"roles":       strings.Join(ec.roles, ","),
		"actor_node":  ec.actorNode,
		"task":        ec.task,
		"service":     api.EgressServicePrefix + destName,
		"destination": destName,
	})
	if err != nil {
		return nil
	}
	return map[string]*structpb.Struct{"mesh": st}
}

// writeImmediateResponse writes an ImmediateResponse from an ext_proc processor
// back to the HTTP caller with a Proxy-Status header identifying the block.
func writeImmediateResponse(w http.ResponseWriter, imm *extprocv3.ImmediateResponse, destName, task string) {
	status := http.StatusForbidden
	if code := int(imm.GetStatus().GetCode()); code >= 100 && code <= 599 {
		status = code
	}
	envoy.ApplySafeHeaderMutations(w.Header(), imm.GetHeaders())
	details := imm.GetDetails()
	if details == "" {
		details = "ext_proc_blocked"
	}
	w.Header().Set("Proxy-Status", fmt.Sprintf("agentmesh-node; error=%s; details=%q", proxyStatusDenied, details))
	logger.Infow("Egress Inspection Verdict",
		"destination", destName,
		"mesh_task", task,
		"tier", "ext_proc",
		"verdict", "block",
		"status", status,
		"details", details,
	)
	w.WriteHeader(status)
	if len(imm.GetBody()) > 0 {
		_, _ = w.Write(imm.GetBody())
	} else {
		_, _ = w.Write([]byte("Request blocked by ext_proc inspector\n"))
	}
}

// serveInspectedEgress executes the configured Inspection chain (ModelArmor and
// ExtProc) around the upstream ReverseProxy. Inspectors run BEFORE the
// credential broker resolves and injects Authorization, so a blocked prompt
// never triggers an upstream STS call and no inspector ever sees the caller's
// Biscuit or the destination's credential.
func (s *EgressService) serveInspectedEgress(w http.ResponseWriter, r *http.Request, proxy http.Handler) {
	inspectors := s.destination.GetInspection().GetInspectors()
	if len(inspectors) == 0 {
		auth, callerCtx, err := s.resolveAuthorization(r.Context())
		if err != nil {
			logger.Errorf("[Egress] %s: %v", s.info.Name, err)
			recordEgressDecision(s.info.Name, egressOutcomeCredentialUnavailable)
			refuse(w, http.StatusBadGateway, "egress credential unavailable", proxyStatusConfigurationError)
			return
		}
		reqCtx := context.WithValue(r.Context(), egressAuthKey{}, auth)
		reqCtx = context.WithValue(reqCtx, egressContextKey{}, callerCtx)
		proxy.ServeHTTP(w, r.WithContext(reqCtx))
		return
	}

	callerCtx := s.extractCallerContext(r.Context())

	maxBytes := int64(defaultExtProcMaxBufferBytes)
	hasExplicitMax := false
	hasModelArmor := false
	for _, ins := range inspectors {
		if ins.GetModelArmor() != nil {
			hasModelArmor = true
		}
		if ep := ins.GetExtProc(); ep != nil && ep.GetMaxBufferedBytes() > 0 {
			if !hasExplicitMax || int64(ep.GetMaxBufferedBytes()) > maxBytes {
				maxBytes = int64(ep.GetMaxBufferedBytes())
				hasExplicitMax = true
			}
		}
	}

	// Read and buffer the request body once if present so multiple inspectors can
	// inspect and optionally rewrite it before forwarding upstream.
	var reqBody []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		reqBody, err = io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
		_ = r.Body.Close()
		if err != nil {
			refuse(w, http.StatusBadRequest, "failed to read request body", proxyStatusDenied)
			return
		}
		if int64(len(reqBody)) > maxBytes {
			refuse(w, http.StatusRequestEntityTooLarge, "request body exceeds max_buffered_bytes", proxyStatusDenied)
			return
		}
	}

	if hasModelArmor && len(reqBody) > 0 {
		if ce := strings.TrimSpace(r.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
			if strings.EqualFold(ce, "gzip") {
				gz, gzErr := gzip.NewReader(bytes.NewReader(reqBody))
				if gzErr != nil {
					refuse(w, http.StatusBadRequest, "invalid gzip request body", proxyStatusDenied)
					return
				}
				decompressed, readErr := io.ReadAll(io.LimitReader(gz, maxBytes+1))
				_ = gz.Close()
				if readErr != nil || int64(len(decompressed)) > maxBytes {
					refuse(w, http.StatusRequestEntityTooLarge, "decompressed request body exceeds max_buffered_bytes", proxyStatusDenied)
					return
				}
				reqBody = decompressed
				r.Header.Del("Content-Encoding")
				r.Header.Del("Content-Length")
			} else {
				refuse(w, http.StatusUnsupportedMediaType, fmt.Sprintf("unsupported Content-Encoding %q with Model Armor inspection", ce), proxyStatusDenied)
				return
			}
		}
	}

	// Strip caller auth and X-Mesh-* headers on a working copy before any inspector sees them.
	for name := range r.Header {
		lower := strings.ToLower(name)
		if lower == "authorization" || lower == "cookie" || strings.HasPrefix(lower, "x-mesh-") || strings.HasPrefix(lower, "x-forwarded-") || strings.EqualFold(name, api.HeaderPeerID) {
			delete(r.Header, name)
		}
	}

	// Track active ext_proc streams that also want response headers/body.
	type activeExtProc struct {
		cfg     *api.ExtProc
		session *envoy.CalloutSession
	}
	var activeStreams []*activeExtProc
	defer func() {
		for _, as := range activeStreams {
			as.session.Close()
		}
	}()

	needResponseBuffer := false

	for _, ins := range inspectors {
		switch kind := ins.GetKind().(type) {
		case *api.Inspector_ModelArmor:
			if kind.ModelArmor == nil {
				continue
			}
			var blocked bool
			var err error
			reqBody, blocked, err = s.inspectModelArmorRequest(r.Context(), kind.ModelArmor, reqBody, callerCtx)
			if err != nil {
				if !kind.ModelArmor.GetFailOpen() {
					logger.Warnw("Egress Inspection Verdict",
						"destination", s.info.Name,
						"mesh_task", callerCtx.task,
						"tier", "model_armor",
						"verdict", "error_fail_closed",
						"error", err.Error(),
					)
					refuse(w, http.StatusBadGateway, "Model Armor inspection unavailable", proxyStatusConfigurationError)
					return
				}
				logger.Warnw("Egress Inspection Verdict",
					"destination", s.info.Name,
					"mesh_task", callerCtx.task,
					"tier", "model_armor",
					"verdict", "error_fail_open",
					"error", err.Error(),
				)
			} else if blocked {
				logger.Infow("Egress Inspection Verdict",
					"destination", s.info.Name,
					"mesh_task", callerCtx.task,
					"tier", "model_armor",
					"verdict", "block",
					"phase", "request",
				)
				s.emitInspectionDenied(r, callerCtx, "model_armor", "request", "prompt matched sanitization filter")
				w.Header().Set("Proxy-Status", fmt.Sprintf("agentmesh-node; error=%s; details=\"model_armor\"", proxyStatusDenied))
				http.Error(w, "Request blocked by Model Armor policy", http.StatusForbidden)
				return
			}
			if kind.ModelArmor.GetResponse() == api.ResponseInspection_RESPONSE_INSPECTION_BUFFERED {
				needResponseBuffer = true
			}

		case *api.Inspector_ExtProc:
			if kind.ExtProc == nil {
				continue
			}
			ep := kind.ExtProc
			client, err := s.getExtProcClient(ep)
			var session *envoy.CalloutSession
			var imm *extprocv3.ImmediateResponse
			var newBody []byte
			if err == nil {
				attrs := buildMeshAttributesStruct(s.info.Name, callerCtx)
				session, imm, newBody, err = client.RunRequestPhase(r, ep, s.info.Name, reqBody, attrs)
			}
			if err != nil {
				if !ep.GetFailureModeAllow() {
					logger.Warnw("Egress Inspection Verdict",
						"destination", s.info.Name,
						"mesh_task", callerCtx.task,
						"tier", "ext_proc",
						"verdict", "error_fail_closed",
						"error", err.Error(),
					)
					refuse(w, http.StatusBadGateway, "ext_proc inspector error", proxyStatusConfigurationError)
					return
				}
				logger.Warnw("Egress Inspection Verdict",
					"destination", s.info.Name,
					"mesh_task", callerCtx.task,
					"tier", "ext_proc",
					"verdict", "error_fail_open",
					"error", err.Error(),
				)
				continue
			}
			if imm != nil {
				if session != nil {
					session.Close()
				}
				s.emitInspectionDenied(r, callerCtx, "ext_proc", "request", imm.GetDetails())
				writeImmediateResponse(w, imm, s.info.Name, callerCtx.task)
				return
			}
			reqBody = newBody
			if session != nil {
				if session.NeedsResponseBuffer() {
					activeStreams = append(activeStreams, &activeExtProc{cfg: ep, session: session})
					needResponseBuffer = true
				} else {
					session.Close()
				}
			}
		}
	}

	auth, _, err := s.resolveAuthorization(r.Context())
	if err != nil {
		logger.Errorf("[Egress] %s: %v", s.info.Name, err)
		recordEgressDecision(s.info.Name, egressOutcomeCredentialUnavailable)
		refuse(w, http.StatusBadGateway, "egress credential unavailable", proxyStatusConfigurationError)
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(reqBody))
	r.ContentLength = int64(len(reqBody))
	if len(reqBody) > 0 {
		r.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))
	} else {
		r.Header.Del("Content-Length")
	}

	reqCtx := context.WithValue(r.Context(), egressAuthKey{}, auth)
	reqCtx = context.WithValue(reqCtx, egressContextKey{}, callerCtx)
	r = r.WithContext(reqCtx)

	if !needResponseBuffer {
		logger.Infow("Egress Inspection Verdict",
			"destination", s.info.Name,
			"mesh_task", callerCtx.task,
			"tier", "inspection_chain",
			"verdict", "allow",
		)
		proxy.ServeHTTP(w, r)
		return
	}

	// Request uncompressed responses from upstream when buffering for inspection.
	r.Header.Del("Accept-Encoding")

	rec := newBoundedResponseRecorder(maxBytes)
	proxy.ServeHTTP(rec, r)
	respStatus := rec.code
	respHeader := rec.Header().Clone()
	respBody := rec.body.Bytes()

	// Run response phase across active ext_proc streams and BUFFERED ModelArmor inspectors.
	for _, as := range activeStreams {
		imm, mutatedBody, err := as.session.RunResponsePhase(respStatus, respHeader, respBody)
		if err != nil {
			if !as.cfg.GetFailureModeAllow() {
				refuse(w, http.StatusBadGateway, "ext_proc response inspection error", proxyStatusConfigurationError)
				return
			}
			continue
		}
		if imm != nil {
			s.emitInspectionDenied(r, callerCtx, "ext_proc", "response", imm.GetDetails())
			writeImmediateResponse(w, imm, s.info.Name, callerCtx.task)
			return
		}
		respBody = mutatedBody
	}
	if rec.overflowed {
		refuse(w, http.StatusBadGateway, "upstream response exceeds max_buffered_bytes", proxyStatusDenied)
		return
	}

	for _, ins := range inspectors {
		ma := ins.GetModelArmor()
		if ma == nil || ma.GetResponse() != api.ResponseInspection_RESPONSE_INSPECTION_BUFFERED {
			continue
		}
		if ce := strings.TrimSpace(respHeader.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") && len(respBody) > 0 {
			if strings.EqualFold(ce, "gzip") {
				gz, gzErr := gzip.NewReader(bytes.NewReader(respBody))
				if gzErr != nil {
					if !ma.GetFailOpen() {
						refuse(w, http.StatusBadGateway, "invalid gzip upstream response body", proxyStatusDenied)
						return
					}
				} else {
					decompressed, readErr := io.ReadAll(io.LimitReader(gz, maxBytes+1))
					_ = gz.Close()
					if int64(len(decompressed)) > maxBytes {
						refuse(w, http.StatusBadGateway, "decompressed upstream response exceeds max_buffered_bytes", proxyStatusDenied)
						return
					}
					if readErr != nil {
						if !ma.GetFailOpen() {
							refuse(w, http.StatusBadGateway, "invalid gzip upstream response body", proxyStatusDenied)
							return
						}
					} else {
						respBody = decompressed
						respHeader.Del("Content-Encoding")
						respHeader.Del("Content-Length")
					}
				}
			} else if !ma.GetFailOpen() {
				refuse(w, http.StatusBadGateway, fmt.Sprintf("unsupported upstream Content-Encoding %q for Model Armor response inspection", ce), proxyStatusDenied)
				return
			}
		}
		var blocked bool
		var err error
		respBody, blocked, err = s.inspectModelArmorResponse(r.Context(), ma, respBody, callerCtx)
		if err != nil {
			if !ma.GetFailOpen() {
				refuse(w, http.StatusBadGateway, "Model Armor response inspection unavailable", proxyStatusConfigurationError)
				return
			}
		} else if blocked {
			logger.Infow("Egress Inspection Verdict",
				"destination", s.info.Name,
				"mesh_task", callerCtx.task,
				"tier", "model_armor",
				"verdict", "block",
				"phase", "response",
			)
			s.emitInspectionDenied(r, callerCtx, "model_armor", "response", "response matched sanitization filter")
			w.Header().Set("Proxy-Status", fmt.Sprintf("agentmesh-node; error=%s; details=\"model_armor_response\"", proxyStatusDenied))
			http.Error(w, "Response blocked by Model Armor policy", http.StatusForbidden)
			return
		}
	}

	logger.Infow("Egress Inspection Verdict",
		"destination", s.info.Name,
		"mesh_task", callerCtx.task,
		"tier", "inspection_chain",
		"verdict", "allow",
	)
	for k, vals := range respHeader {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(respStatus)
	_, _ = w.Write(respBody)
}

func extProcClientCacheKey(cfg *api.ExtProc) string {
	return strings.TrimSpace(cfg.GetTarget()) + "|" + strings.TrimSpace(cfg.GetCa()) + "|" + strings.TrimSpace(cfg.GetClientCertificate())
}

func (s *EgressService) initExtProcClients() {
	for _, ins := range s.destination.GetInspection().GetInspectors() {
		if ep := ins.GetExtProc(); ep != nil {
			_, _ = s.getExtProcClient(ep)
		}
	}
}

func (s *EgressService) getExtProcClient(cfg *api.ExtProc) (*envoy.CalloutClient, error) {
	key := extProcClientCacheKey(cfg)
	s.extProcMu.Lock()
	defer s.extProcMu.Unlock()
	if s.extProcClients == nil {
		s.extProcClients = make(map[string]*envoy.CalloutClient)
	}
	if c, ok := s.extProcClients[key]; ok {
		return c, nil
	}
	c, err := envoy.NewCalloutClient(cfg, s.secretsDir)
	if err != nil {
		return nil, err
	}
	s.extProcClients[key] = c
	return c, nil
}

func (s *EgressService) inspectModelArmorRequest(ctx context.Context, cfg *api.ModelArmor, body []byte, callerCtx egressCallerContext) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}
	promptText := extractInspectableText(body)
	if promptText == "" {
		return body, false, nil
	}
	blocked, replacement, err := s.callModelArmorAPI(ctx, cfg, "sanitizeUserPrompt", "userPromptData", promptText, callerCtx)
	if err != nil || blocked {
		return body, blocked, err
	}
	if replacement != "" && replacement != promptText {
		updated, err := replaceInspectableText(body, promptText, replacement)
		if err != nil {
			return body, false, err
		}
		body = updated
	}
	return body, false, nil
}

func (s *EgressService) inspectModelArmorResponse(ctx context.Context, cfg *api.ModelArmor, body []byte, callerCtx egressCallerContext) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}
	respText := extractInspectableText(body)
	if respText == "" {
		return body, false, nil
	}
	blocked, replacement, err := s.callModelArmorAPI(ctx, cfg, "sanitizeModelResponse", "modelResponseData", respText, callerCtx)
	if err != nil || blocked {
		return body, blocked, err
	}
	if replacement != "" && replacement != respText {
		updated, err := replaceInspectableText(body, respText, replacement)
		if err != nil {
			return body, false, err
		}
		body = updated
	}
	return body, false, nil
}

func (s *EgressService) callModelArmorAPI(ctx context.Context, cfg *api.ModelArmor, method, dataField, text string, callerCtx egressCallerContext) (blocked bool, replacement string, err error) {
	timeout := defaultModelArmorTimeout
	if cfg.GetTimeout().IsValid() && cfg.GetTimeout().AsDuration() > 0 {
		timeout = cfg.GetTimeout().AsDuration()
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint, authHdr, err := s.resolveModelArmorEndpoint(callCtx, cfg.GetTemplate())
	if err != nil {
		return false, "", err
	}
	urlStr := fmt.Sprintf("%s:%s", endpoint, method)
	payload, err := json.Marshal(map[string]any{
		dataField: map[string]any{
			"text": text,
		},
	})
	if err != nil {
		return false, "", err
	}
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, urlStr, bytes.NewReader(payload))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if authHdr != "" {
		req.Header.Set("Authorization", authHdr)
	}

	client := s.modelArmorClient
	if client == nil {
		client = &http.Client{
			Timeout:   timeout,
			Transport: s.newSafeModelArmorTransport(),
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes))
	if err != nil {
		return false, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("model armor %s returned %d: %s", method, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var result struct {
		SanitizationResult struct {
			FilterMatchState string `json:"filterMatchState"`
			FilterResults    map[string]struct {
				SdpFilterResult *struct {
					DeidentifyResult *struct {
						MatchState string `json:"matchState"`
						Data       struct {
							Text string `json:"text"`
						} `json:"data"`
					} `json:"deidentifyResult"`
					InspectResult *struct {
						MatchState string `json:"matchState"`
					} `json:"inspectResult"`
				} `json:"sdpFilterResult"`
			} `json:"filterResults"`
		} `json:"sanitizationResult"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return false, "", fmt.Errorf("invalid Model Armor response JSON: %w", err)
	}

	for _, fr := range result.SanitizationResult.FilterResults {
		if fr.SdpFilterResult != nil && fr.SdpFilterResult.DeidentifyResult != nil {
			if deid := fr.SdpFilterResult.DeidentifyResult.Data.Text; deid != "" {
				replacement = deid
			}
		}
	}

	if strings.EqualFold(result.SanitizationResult.FilterMatchState, "MATCH_FOUND") {
		// If the only match was an SDP de-identification transform that produced
		// a sanitized replacement text, allow the request with the de-identified text.
		if replacement != "" && len(result.SanitizationResult.FilterResults) == 1 {
			return false, replacement, nil
		}
		return true, "", nil
	}
	_ = callerCtx
	return false, replacement, nil
}

func (s *EgressService) newSafeModelArmorTransport() http.RoundTripper {
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialSafeEgressTCP(ctx, addr, s.allowsLocalTarget() || s.modelArmorBaseURL != "")
	}
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		cloned := dt.Clone()
		cloned.DialContext = dial
		return cloned
	}
	return &http.Transport{DialContext: dial}
}

func (s *EgressService) resolveModelArmorEndpoint(ctx context.Context, template string) (string, string, error) {
	tmpl := strings.TrimSpace(template)
	if tmpl == "" {
		return "", "", errors.New("model_armor.template is empty")
	}
	if s.modelArmorBaseURL != "" {
		return strings.TrimRight(s.modelArmorBaseURL, "/") + "/v1/" + strings.TrimLeft(tmpl, "/"), "", nil
	}
	if strings.HasPrefix(tmpl, "http://") || strings.HasPrefix(tmpl, "https://") {
		u, err := url.Parse(tmpl)
		if err != nil || u.Hostname() == "" {
			return "", "", fmt.Errorf("invalid model_armor.template URL %q", tmpl)
		}
		host := strings.TrimSpace(u.Hostname())
		if !s.allowsLocalTarget() && (strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost")) {
			return "", "", fmt.Errorf("model_armor.template URL host %q is in a forbidden local domain", host)
		}
		// Connect-time DNS resolution and IP validation against DNS rebinding
		// are enforced by dialSafeEgressTCP in newSafeModelArmorTransport().
		if ip, pErr := netip.ParseAddr(host); pErr == nil {
			if isForbiddenEgressAddr(ip, s.allowsLocalTarget()) {
				return "", "", fmt.Errorf("model_armor.template URL host %q is in a forbidden IP range", host)
			}
		}
		return tmpl, "", nil
	}
	// Parse location from projects/P/locations/L/templates/T
	location := "us-central1"
	parts := strings.Split(tmpl, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" && parts[i+1] != "" {
			location = parts[i+1]
			break
		}
	}
	maHost := fmt.Sprintf("modelarmor.%s.rep.googleapis.com", location)
	baseURL := "https://" + maHost
	var authHdr string
	if s.node != nil && s.node.services != nil {
		if svc, ok := s.node.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, maHost); ok {
			if maSvc, ok := svc.(*EgressService); ok {
				baseURL = strings.TrimRight(maSvc.target.String(), "/")
				authHdr, _, _ = maSvc.resolveAuthorization(ctx)
			}
		}
	}
	return baseURL + "/v1/" + strings.TrimLeft(tmpl, "/"), authHdr, nil
}

func extractInspectableText(body []byte) string {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return strings.TrimSpace(string(body))
	}
	// 1. OpenAI chat completions: messages[].content or choices[].message.content
	if msgs, ok := doc["messages"].([]any); ok {
		var sb strings.Builder
		for _, m := range msgs {
			if mm, ok := m.(map[string]any); ok {
				if c, ok := mm["content"].(string); ok && c != "" {
					if sb.Len() > 0 {
						sb.WriteByte('\n')
					}
					sb.WriteString(c)
				}
			}
		}
		if sb.Len() > 0 {
			return sb.String()
		}
	}
	if choices, ok := doc["choices"].([]any); ok {
		var sb strings.Builder
		for _, ch := range choices {
			if cm, ok := ch.(map[string]any); ok {
				if msg, ok := cm["message"].(map[string]any); ok {
					if c, ok := msg["content"].(string); ok && c != "" {
						sb.WriteString(c)
					}
				}
			}
		}
		if sb.Len() > 0 {
			return sb.String()
		}
	}
	// 2. Gemini generateContent: contents[].parts[].text or candidates[].content.parts[].text
	for _, topKey := range []string{"contents", "candidates"} {
		if items, ok := doc[topKey].([]any); ok {
			var sb strings.Builder
			for _, it := range items {
				im, ok := it.(map[string]any)
				if !ok {
					continue
				}
				if contentObj, ok := im["content"].(map[string]any); ok {
					im = contentObj
				}
				if parts, ok := im["parts"].([]any); ok {
					for _, p := range parts {
						if pm, ok := p.(map[string]any); ok {
							if txt, ok := pm["text"].(string); ok && txt != "" {
								sb.WriteString(txt)
							}
						}
					}
				}
			}
			if sb.Len() > 0 {
				return sb.String()
			}
		}
	}
	return strings.TrimSpace(string(body))
}

func replaceInspectableText(body []byte, original, replacement string) ([]byte, error) {
	if original == replacement {
		return body, nil
	}
	if original == "" {
		return nil, errors.New("cannot replace empty original inspectable text")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return bytes.ReplaceAll(body, []byte(original), []byte(replacement)), nil
	}

	// If messages[].content were joined by '\n' in extractInspectableText, split back
	// using each message's original line count; if the line count matches, map each
	// message back in-place.
	if msgs, ok := doc["messages"].([]any); ok {
		var contentMaps []map[string]any
		var lineCounts []int
		totalLines := 0
		for _, m := range msgs {
			if mm, ok := m.(map[string]any); ok {
				if c, ok := mm["content"].(string); ok && c != "" {
					contentMaps = append(contentMaps, mm)
					lc := strings.Count(c, "\n") + 1
					lineCounts = append(lineCounts, lc)
					totalLines += lc
				}
			}
		}
		if len(contentMaps) == 1 {
			contentMaps[0]["content"] = replacement
			return json.Marshal(doc)
		}
		if len(contentMaps) > 1 {
			parts := strings.Split(replacement, "\n")
			if len(parts) == totalLines {
				offset := 0
				for i, mm := range contentMaps {
					lc := lineCounts[i]
					mm["content"] = strings.Join(parts[offset:offset+lc], "\n")
					offset += lc
				}
				return json.Marshal(doc)
			}
		}
	}

	updated, modified := replaceStringInJSONValue(doc, original, replacement)
	if modified {
		return json.Marshal(updated)
	}
	if original != "" && bytes.Contains(body, []byte(original)) {
		return bytes.ReplaceAll(body, []byte(original), []byte(replacement)), nil
	}
	return nil, errors.New("failed to map inspection replacement back into structured JSON payload")
}

func replaceStringInJSONValue(v any, original, replacement string) (any, bool) {
	switch val := v.(type) {
	case string:
		if val == original {
			return replacement, true
		}
		if original != "" && strings.Contains(val, original) {
			return strings.ReplaceAll(val, original, replacement), true
		}
		return val, false
	case []any:
		anyMod := false
		for i, elem := range val {
			next, mod := replaceStringInJSONValue(elem, original, replacement)
			if mod {
				val[i] = next
				anyMod = true
			}
		}
		return val, anyMod
	case map[string]any:
		anyMod := false
		for k, elem := range val {
			next, mod := replaceStringInJSONValue(elem, original, replacement)
			if mod {
				val[k] = next
				anyMod = true
			}
		}
		return val, anyMod
	default:
		return v, false
	}
}

func (s *EgressService) emitInspectionDenied(r *http.Request, callerCtx egressCallerContext, tier, phase, detail string) {
	if s == nil || s.node == nil {
		return
	}
	dir := s.node.detectCallerDirection(r, nil)

	var op, res string
	if r != nil {
		op = r.Method
		if r.URL != nil {
			res = r.URL.Path
		}
	}

	var targetService string
	if s.info != nil && s.info.Name != "" {
		targetService = api.EgressServicePrefix + s.info.Name
	}

	s.node.EmitPolicyDenied(PolicyDeniedParams{
		Direction:          dir,
		Reason:             api.PolicyDenialReason_INSPECTION_FILTER_BLOCKED,
		Detail:             fmt.Sprintf("%s %s blocked: %s", tier, phase, detail),
		TargetService:      targetService,
		RequestedOperation: op,
		RequestedResource:  res,
		CallerPeerID:       callerCtx.actorNode,
		CallerSubject:      callerCtx.principal,
		CallerRoles:        callerCtx.roles,
		EventTime:          time.Now(),
	})
}
