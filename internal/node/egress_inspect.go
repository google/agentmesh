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
	"slices"
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

	blocked, replacement, err = evaluateModelArmorResponse(respBytes)
	if err != nil {
		return false, "", err
	}
	_ = callerCtx
	return blocked, replacement, nil
}

// evaluateModelArmorResponse parses a Model Armor SanitizationResult JSON body
// and decides whether the request/response must be blocked or rewritten with an
// SDP de-identification replacement. It fails closed whenever MATCH_FOUND is
// returned and any non-SDP filter did not explicitly report NO_MATCH_FOUND.
func evaluateModelArmorResponse(respBytes []byte) (blocked bool, replacement string, err error) {
	var result struct {
		SanitizationResult struct {
			FilterMatchState string                     `json:"filterMatchState"`
			FilterResults    map[string]json.RawMessage `json:"filterResults"`
		} `json:"sanitizationResult"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return false, "", fmt.Errorf("invalid Model Armor response JSON: %w", err)
	}

	nonDeidentifyMatch := len(result.SanitizationResult.FilterResults) == 0
	for filterName, rawEntry := range result.SanitizationResult.FilterResults {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(rawEntry, &entry); err != nil || len(entry) == 0 {
			logger.Warnw("Model Armor filter result malformed; failing closed", "filter", filterName, "error", err)
			nonDeidentifyMatch = true
			continue
		}
		for subKey, subRaw := range entry {
			if subKey == "sdpFilterResult" {
				var sdp struct {
					DeidentifyResult *struct {
						MatchState string `json:"matchState"`
						Data       struct {
							Text string `json:"text"`
						} `json:"data"`
					} `json:"deidentifyResult"`
					InspectResult *struct {
						MatchState string `json:"matchState"`
					} `json:"inspectResult"`
				}
				if err := json.Unmarshal(subRaw, &sdp); err != nil {
					logger.Warnw("Model Armor SDP filter result malformed; failing closed", "filter", filterName, "error", err)
					nonDeidentifyMatch = true
					continue
				}
				if sdp.InspectResult != nil && !strings.EqualFold(sdp.InspectResult.MatchState, "NO_MATCH_FOUND") && sdp.InspectResult.MatchState != "" {
					nonDeidentifyMatch = true
				}
				if sdp.DeidentifyResult != nil {
					if deid := sdp.DeidentifyResult.Data.Text; deid != "" {
						replacement = deid
					} else if strings.EqualFold(sdp.DeidentifyResult.MatchState, "MATCH_FOUND") {
						nonDeidentifyMatch = true
					}
				} else if sdp.InspectResult == nil {
					nonDeidentifyMatch = true
				}
				continue
			}

			// Any non-SDP filter (pi_and_jailbreak, rai, csam, malicious_uris,
			// or future filter types) must explicitly report NO_MATCH_FOUND to
			// permit an SDP-only de-identification pass-through.
			var filterState struct {
				MatchState string `json:"matchState"`
			}
			if err := json.Unmarshal(subRaw, &filterState); err != nil {
				logger.Warnw("Model Armor non-SDP filter result malformed; failing closed", "filter", filterName, "sub_filter", subKey, "error", err)
				nonDeidentifyMatch = true
				continue
			}
			if !strings.EqualFold(filterState.MatchState, "NO_MATCH_FOUND") {
				nonDeidentifyMatch = true
			}
		}
	}

	if strings.EqualFold(result.SanitizationResult.FilterMatchState, "MATCH_FOUND") {
		if replacement != "" && !nonDeidentifyMatch {
			return false, replacement, nil
		}
		return true, "", nil
	}
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

const maxInspectableJSONDepth = 64

// inspectableSlot references one non-empty text field inside a decoded JSON
// LLM payload so extraction and in-place SDP replacement walk the exact same
// fields in the same deterministic order.
type inspectableSlot struct {
	text  string
	write func(string)
}

func appendMapStringSlot(slots *[]inspectableSlot, m map[string]any, key string) {
	if s, ok := m[key].(string); ok && s != "" {
		*slots = append(*slots, inspectableSlot{
			text:  s,
			write: func(next string) { m[key] = next },
		})
	}
}

func collectJSONStringLeaves(slots *[]inspectableSlot, v any, write func(string), depth int) {
	if v == nil {
		return
	}
	if depth >= maxInspectableJSONDepth {
		if raw, err := json.Marshal(v); err == nil && len(raw) > 0 {
			// Preserve deep payloads for inspection; nil write causes SDP replacement to fail closed.
			*slots = append(*slots, inspectableSlot{text: string(raw)})
		}
		return
	}
	switch val := v.(type) {
	case string:
		if val != "" {
			*slots = append(*slots, inspectableSlot{text: val, write: write})
		}
	case []any:
		for i, elem := range val {
			idx := i
			collectJSONStringLeaves(slots, elem, func(next string) { val[idx] = next }, depth+1)
		}
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			key := k
			collectJSONStringLeaves(slots, val[key], func(next string) { val[key] = next }, depth+1)
		}
	}
}

func collectContentParts(slots *[]inspectableSlot, v any, write func(string), depth int) {
	if v == nil {
		return
	}
	if depth >= maxInspectableJSONDepth {
		if raw, err := json.Marshal(v); err == nil && len(raw) > 0 {
			*slots = append(*slots, inspectableSlot{text: string(raw)})
		}
		return
	}
	switch val := v.(type) {
	case string:
		if val != "" {
			*slots = append(*slots, inspectableSlot{text: val, write: write})
		}
	case []any:
		for i, item := range val {
			idx := i
			switch part := item.(type) {
			case string:
				if part != "" {
					*slots = append(*slots, inspectableSlot{
						text:  part,
						write: func(next string) { val[idx] = next },
					})
				}
			case map[string]any:
				collectPartObject(slots, part, depth+1)
			}
		}
	case map[string]any:
		collectPartObject(slots, val, depth+1)
	}
}

func collectPartObject(slots *[]inspectableSlot, pm map[string]any, depth int) {
	appendMapStringSlot(slots, pm, "text")
	appendMapStringSlot(slots, pm, "thinking")
	appendMapStringSlot(slots, pm, "refusal")
	appendMapStringSlot(slots, pm, "arguments")
	if c, ok := pm["content"]; ok {
		collectContentParts(slots, c, func(next string) { pm["content"] = next }, depth+1)
	}
	if in, ok := pm["input"]; ok {
		collectJSONStringLeaves(slots, in, func(next string) { pm["input"] = next }, depth+1)
	}
	if out, ok := pm["output"]; ok {
		collectContentParts(slots, out, func(next string) { pm["output"] = next }, depth+1)
	}
	if sum, ok := pm["summary"]; ok {
		collectContentParts(slots, sum, func(next string) { pm["summary"] = next }, depth+1)
	}
	if src, ok := pm["source"].(map[string]any); ok {
		if t, _ := src["type"].(string); t == "text" {
			appendMapStringSlot(slots, src, "data")
		}
	}
}

func collectToolCalls(slots *[]inspectableSlot, mm map[string]any) {
	if calls, ok := mm["tool_calls"].([]any); ok {
		for _, tc := range calls {
			if tcm, ok := tc.(map[string]any); ok {
				if fn, ok := tcm["function"].(map[string]any); ok {
					appendMapStringSlot(slots, fn, "arguments")
				}
			}
		}
	}
	if fc, ok := mm["function_call"].(map[string]any); ok {
		appendMapStringSlot(slots, fc, "arguments")
	}
}

func collectMessageObject(slots *[]inspectableSlot, mm map[string]any) {
	if c, ok := mm["content"]; ok {
		collectContentParts(slots, c, func(next string) { mm["content"] = next }, 0)
	}
	appendMapStringSlot(slots, mm, "refusal")
	collectToolCalls(slots, mm)
}

func collectGeminiContent(slots *[]inspectableSlot, container map[string]any) {
	if contentObj, ok := container["content"].(map[string]any); ok {
		container = contentObj
	}
	parts, ok := container["parts"].([]any)
	if !ok {
		return
	}
	for _, p := range parts {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		appendMapStringSlot(slots, pm, "text")
		for _, fcKey := range []string{"functionCall", "function_call"} {
			if fc, ok := pm[fcKey].(map[string]any); ok {
				if args, ok := fc["args"]; ok {
					collectJSONStringLeaves(slots, args, func(next string) { fc["args"] = next }, 0)
				}
			}
		}
		for _, frKey := range []string{"functionResponse", "function_response"} {
			if fr, ok := pm[frKey].(map[string]any); ok {
				if resp, ok := fr["response"]; ok {
					collectJSONStringLeaves(slots, resp, func(next string) { fr["response"] = next }, 0)
				}
			}
		}
	}
}

func collectInspectableSlots(doc map[string]any) []inspectableSlot {
	var slots []inspectableSlot

	// 1. Top-level system / instruction fields (Anthropic, OpenAI Responses, Gemini).
	if sys, ok := doc["system"]; ok {
		collectContentParts(&slots, sys, func(next string) { doc["system"] = next }, 0)
	}
	appendMapStringSlot(&slots, doc, "instructions")
	for _, sysKey := range []string{"systemInstruction", "system_instruction"} {
		switch sysVal := doc[sysKey].(type) {
		case string:
			appendMapStringSlot(&slots, doc, sysKey)
		case map[string]any:
			collectGeminiContent(&slots, sysVal)
		}
	}

	// 2. OpenAI / Anthropic messages[].
	if msgs, ok := doc["messages"].([]any); ok {
		for _, m := range msgs {
			if mm, ok := m.(map[string]any); ok {
				collectMessageObject(&slots, mm)
			}
		}
	}

	// 3. OpenAI Responses API input/output and legacy prompt.
	if in, ok := doc["input"]; ok {
		collectContentParts(&slots, in, func(next string) { doc["input"] = next }, 0)
	}
	if prompt, ok := doc["prompt"]; ok {
		collectContentParts(&slots, prompt, func(next string) { doc["prompt"] = next }, 0)
	}
	if out, ok := doc["output"]; ok {
		collectContentParts(&slots, out, func(next string) { doc["output"] = next }, 0)
	}
	appendMapStringSlot(&slots, doc, "output_text")

	// 4. OpenAI chat/completion choices[].
	if choices, ok := doc["choices"].([]any); ok {
		for _, ch := range choices {
			if cm, ok := ch.(map[string]any); ok {
				if msg, ok := cm["message"].(map[string]any); ok {
					collectMessageObject(&slots, msg)
				}
				if delta, ok := cm["delta"].(map[string]any); ok {
					collectMessageObject(&slots, delta)
				}
				appendMapStringSlot(&slots, cm, "text")
			}
		}
	}

	// 5. Anthropic top-level response content blocks.
	if content, ok := doc["content"]; ok {
		collectContentParts(&slots, content, func(next string) { doc["content"] = next }, 0)
	}

	// 6. Gemini contents[] and candidates[].
	for _, topKey := range []string{"contents", "candidates"} {
		if items, ok := doc[topKey].([]any); ok {
			for _, it := range items {
				if im, ok := it.(map[string]any); ok {
					collectGeminiContent(&slots, im)
				}
			}
		}
	}

	return slots
}

func extractSSEInspectableText(body []byte) (string, bool) {
	lines := strings.Split(string(body), "\n")
	var sb strings.Builder
	sawData := false
	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		sawData = true
		data = strings.TrimSpace(data)
		if data == "" || data == "[DONE]" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			sb.WriteString(data)
			continue
		}
		var evSlots []inspectableSlot
		// OpenAI Responses API delta string or Anthropic delta object.
		if d, ok := ev["delta"]; ok {
			switch dv := d.(type) {
			case string:
				if dv != "" {
					evSlots = append(evSlots, inspectableSlot{text: dv})
				}
			case map[string]any:
				appendMapStringSlot(&evSlots, dv, "text")
				appendMapStringSlot(&evSlots, dv, "partial_json")
				appendMapStringSlot(&evSlots, dv, "thinking")
			}
		}
		if cb, ok := ev["content_block"].(map[string]any); ok {
			collectPartObject(&evSlots, cb, 0)
		}
		evSlots = append(evSlots, collectInspectableSlots(ev)...)
		for _, sl := range evSlots {
			sb.WriteString(sl.text)
		}
	}
	if !sawData {
		return "", false
	}
	return strings.TrimSpace(sb.String()), true
}

func decodeInspectableObject(body []byte) (map[string]any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		return nil, false
	}
	_, err := decoder.Token()
	return doc, err == io.EOF
}

func extractInspectableText(body []byte) string {
	doc, ok := decodeInspectableObject(body)
	if !ok {
		if sseText, isSSE := extractSSEInspectableText(body); isSSE {
			if sseText != "" {
				return sseText
			}
			return strings.TrimSpace(string(body))
		}
		return strings.TrimSpace(string(body))
	}
	slots := collectInspectableSlots(doc)
	if len(slots) > 0 {
		var sb strings.Builder
		for i, sl := range slots {
			if i > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(sl.text)
		}
		return sb.String()
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
	doc, ok := decodeInspectableObject(body)
	if !ok {
		if !bytes.Contains(body, []byte(original)) {
			return nil, errors.New("failed to map inspection replacement back into non-JSON payload")
		}
		return bytes.ReplaceAll(body, []byte(original), []byte(replacement)), nil
	}

	// Walk the exact same inspectable slots that extractInspectableText collected.
	// When multiple slots were joined by '\n', map lines back using each slot's
	// original line count; fail closed if the line structure cannot be preserved
	// or if a modified slot is not writable.
	if slots := collectInspectableSlots(doc); len(slots) > 0 {
		if len(slots) == 1 {
			if slots[0].write == nil {
				return nil, errors.New("failed to map inspection replacement back into read-only JSON slot")
			}
			slots[0].write(replacement)
			return json.Marshal(doc)
		}
		lineCounts := make([]int, len(slots))
		totalLines := 0
		for i, sl := range slots {
			lc := strings.Count(sl.text, "\n") + 1
			lineCounts[i] = lc
			totalLines += lc
		}
		parts := strings.Split(replacement, "\n")
		if len(parts) == totalLines {
			offset := 0
			for i, sl := range slots {
				lc := lineCounts[i]
				nextVal := strings.Join(parts[offset:offset+lc], "\n")
				if nextVal != sl.text {
					if sl.write == nil {
						return nil, errors.New("failed to map inspection replacement back into read-only JSON slot")
					}
					sl.write(nextVal)
				}
				offset += lc
			}
			return json.Marshal(doc)
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
