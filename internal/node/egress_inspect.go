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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/google/sam/api"
	corev3 "github.com/google/sam/third_party/envoy/envoy/config/core/v3"
	extprocv3http "github.com/google/sam/third_party/envoy/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/google/sam/third_party/envoy/envoy/service/ext_proc/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultExtProcMessageTimeout = 200 * time.Millisecond
	defaultExtProcMaxBufferBytes = 1 << 20 // 1 MiB
	defaultModelArmorTimeout     = 5 * time.Second
)

// isProtectedEgressHeader reports whether a header name is off-limits to an
// ext_proc inspector. Inspectors may add/modify application headers, or block a
// request, but must never select or overwrite credentials, host routing, or
// SAM identity headers.
func isProtectedEgressHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "authorization", "host", ":authority", "cookie":
		return true
	}
	return strings.HasPrefix(lower, "x-sam-") || strings.HasPrefix(lower, "x-forwarded-")
}

func applySafeHeaderMutations(h http.Header, mut *extprocv3.HeaderMutation) {
	if mut == nil {
		return
	}
	for _, rem := range mut.GetRemoveHeaders() {
		if isProtectedEgressHeader(rem) {
			logger.Warnf("[EgressInspect] Refused ext_proc removal of protected header %q", rem)
			continue
		}
		h.Del(rem)
	}
	for _, opt := range mut.GetSetHeaders() {
		hv := opt.GetHeader()
		if hv == nil {
			continue
		}
		key := strings.TrimSpace(hv.GetKey())
		if key == "" || strings.HasPrefix(key, ":") {
			if strings.EqualFold(key, ":authority") {
				logger.Warnf("[EgressInspect] Refused ext_proc mutation of protected pseudo-header :authority")
			}
			continue
		}
		if isProtectedEgressHeader(key) {
			logger.Warnf("[EgressInspect] Refused ext_proc mutation of protected header %q", key)
			continue
		}
		val := hv.GetValue()
		if val == "" && len(hv.GetRawValue()) > 0 {
			val = string(hv.GetRawValue())
		}
		appendHdr := false
		if opt.GetAppend() != nil {
			appendHdr = opt.GetAppend().GetValue()
		} else if opt.GetAppendAction() == corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD {
			appendHdr = false // default to overwrite unless explicitly set
		}
		if opt.GetAppendAction() == corev3.HeaderValueOption_ADD_IF_ABSENT && h.Get(key) != "" {
			continue
		}
		if opt.GetAppendAction() == corev3.HeaderValueOption_OVERWRITE_IF_EXISTS && h.Get(key) == "" {
			continue
		}
		if appendHdr {
			h.Add(key, val)
		} else {
			h.Set(key, val)
		}
	}
}

func buildSamAttributesStruct(destName string, ec egressCallerContext) map[string]*structpb.Struct {
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
	return map[string]*structpb.Struct{"sam": st}
}

func httpHeadersToProto(r *http.Request, destName string) *corev3.HeaderMap {
	var list []*corev3.HeaderValue
	if r != nil {
		list = append(list,
			&corev3.HeaderValue{Key: ":method", Value: r.Method},
			&corev3.HeaderValue{Key: ":path", Value: r.URL.RequestURI()},
			&corev3.HeaderValue{Key: ":authority", Value: destName},
			&corev3.HeaderValue{Key: ":scheme", Value: "https"},
		)
		for k, vals := range r.Header {
			if isProtectedEgressHeader(k) {
				continue
			}
			list = append(list, &corev3.HeaderValue{
				Key:   strings.ToLower(k),
				Value: strings.Join(vals, ", "),
			})
		}
	}
	return &corev3.HeaderMap{Headers: list}
}

func responseHeadersToProto(status int, h http.Header) *corev3.HeaderMap {
	list := []*corev3.HeaderValue{
		{Key: ":status", Value: strconv.Itoa(status)},
	}
	for k, vals := range h {
		list = append(list, &corev3.HeaderValue{
			Key:   strings.ToLower(k),
			Value: strings.Join(vals, ", "),
		})
	}
	return &corev3.HeaderMap{Headers: list}
}

// writeImmediateResponse writes an ImmediateResponse from an ext_proc processor
// back to the HTTP caller with a Proxy-Status header identifying the block.
func writeImmediateResponse(w http.ResponseWriter, imm *extprocv3.ImmediateResponse, destName, task string) {
	status := http.StatusForbidden
	if code := int(imm.GetStatus().GetCode()); code >= 100 && code <= 599 {
		status = code
	}
	applySafeHeaderMutations(w.Header(), imm.GetHeaders())
	details := imm.GetDetails()
	if details == "" {
		details = "ext_proc_blocked"
	}
	w.Header().Set("Proxy-Status", fmt.Sprintf("sam-node; error=%s; details=%q", proxyStatusDenied, details))
	logger.Infow("Egress Inspection Verdict",
		"destination", destName,
		"sam_task", task,
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

	// Read and buffer the request body once if present so multiple inspectors can
	// inspect and optionally rewrite it before forwarding upstream.
	var reqBody []byte
	if r.Body != nil && r.Body != http.NoBody {
		maxBytes := int64(defaultExtProcMaxBufferBytes)
		for _, ins := range inspectors {
			if ep := ins.GetExtProc(); ep != nil && ep.GetMaxBufferedBytes() > 0 {
				if int64(ep.GetMaxBufferedBytes()) > maxBytes {
					maxBytes = int64(ep.GetMaxBufferedBytes())
				}
			}
		}
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

	// Strip caller auth and X-Sam-* headers on a working copy before any inspector sees them.
	r.Header.Del("Authorization")
	r.Header.Del("Cookie")
	for name := range r.Header {
		if strings.HasPrefix(name, "X-Sam-") || strings.HasPrefix(name, "X-Forwarded-") || name == api.HeaderPeerID {
			r.Header.Del(name)
		}
	}

	// Track active ext_proc streams that also want response headers/body.
	type activeExtProc struct {
		cfg    *api.ExtProc
		stream *extProcClientStream
		mode   *extprocv3http.ProcessingMode
	}
	var activeStreams []*activeExtProc
	defer func() {
		for _, as := range activeStreams {
			as.stream.Close()
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
						"sam_task", callerCtx.task,
						"tier", "model_armor",
						"verdict", "error_fail_closed",
						"error", err.Error(),
					)
					refuse(w, http.StatusBadGateway, "Model Armor inspection unavailable", proxyStatusConfigurationError)
					return
				}
				logger.Warnw("Egress Inspection Verdict",
					"destination", s.info.Name,
					"sam_task", callerCtx.task,
					"tier", "model_armor",
					"verdict", "error_fail_open",
					"error", err.Error(),
				)
			} else if blocked {
				logger.Infow("Egress Inspection Verdict",
					"destination", s.info.Name,
					"sam_task", callerCtx.task,
					"tier", "model_armor",
					"verdict", "block",
					"phase", "request",
				)
				w.Header().Set("Proxy-Status", fmt.Sprintf("sam-node; error=%s; details=\"model_armor\"", proxyStatusDenied))
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
			stream, mode, imm, newBody, err := s.runExtProcRequestPhase(r, ep, reqBody, callerCtx)
			if err != nil {
				if !ep.GetFailureModeAllow() {
					logger.Warnw("Egress Inspection Verdict",
						"destination", s.info.Name,
						"sam_task", callerCtx.task,
						"tier", "ext_proc",
						"verdict", "error_fail_closed",
						"error", err.Error(),
					)
					refuse(w, http.StatusBadGateway, "ext_proc inspector error", proxyStatusConfigurationError)
					return
				}
				logger.Warnw("Egress Inspection Verdict",
					"destination", s.info.Name,
					"sam_task", callerCtx.task,
					"tier", "ext_proc",
					"verdict", "error_fail_open",
					"error", err.Error(),
				)
				continue
			}
			if imm != nil {
				if stream != nil {
					stream.Close()
				}
				writeImmediateResponse(w, imm, s.info.Name, callerCtx.task)
				return
			}
			reqBody = newBody
			if stream != nil {
				if mode.GetResponseHeaderMode() != extprocv3http.ProcessingMode_SKIP || mode.GetResponseBodyMode() != extprocv3http.ProcessingMode_NONE {
					activeStreams = append(activeStreams, &activeExtProc{cfg: ep, stream: stream, mode: mode})
					needResponseBuffer = true
				} else {
					stream.Close()
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
	}

	reqCtx := context.WithValue(r.Context(), egressAuthKey{}, auth)
	reqCtx = context.WithValue(reqCtx, egressContextKey{}, callerCtx)
	r = r.WithContext(reqCtx)

	if !needResponseBuffer {
		logger.Infow("Egress Inspection Verdict",
			"destination", s.info.Name,
			"sam_task", callerCtx.task,
			"tier", "inspection_chain",
			"verdict", "allow",
		)
		proxy.ServeHTTP(w, r)
		return
	}

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, r)
	respStatus := rec.Code
	respHeader := rec.Header().Clone()
	respBody := rec.Body.Bytes()

	// Run response phase across active ext_proc streams and BUFFERED ModelArmor inspectors.
	for _, as := range activeStreams {
		imm, mutatedBody, err := s.runExtProcResponsePhase(as.cfg, as.stream, as.mode, respStatus, respHeader, respBody)
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

	for _, ins := range inspectors {
		ma := ins.GetModelArmor()
		if ma == nil || ma.GetResponse() != api.ResponseInspection_RESPONSE_INSPECTION_BUFFERED {
			continue
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
				"sam_task", callerCtx.task,
				"tier", "model_armor",
				"verdict", "block",
				"phase", "response",
			)
			w.Header().Set("Proxy-Status", fmt.Sprintf("sam-node; error=%s; details=\"model_armor_response\"", proxyStatusDenied))
			http.Error(w, "Response blocked by Model Armor policy", http.StatusForbidden)
			return
		}
	}

	logger.Infow("Egress Inspection Verdict",
		"destination", s.info.Name,
		"sam_task", callerCtx.task,
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

func initialExtProcMode(cfg *api.ExtProc) *extprocv3http.ProcessingMode {
	pm := cfg.GetProcessingMode()
	mode := &extprocv3http.ProcessingMode{
		RequestHeaderMode:   extprocv3http.ProcessingMode_SEND,
		ResponseHeaderMode:  extprocv3http.ProcessingMode_SEND,
		RequestBodyMode:     extprocv3http.ProcessingMode_NONE,
		ResponseBodyMode:    extprocv3http.ProcessingMode_NONE,
		RequestTrailerMode:  extprocv3http.ProcessingMode_SKIP,
		ResponseTrailerMode: extprocv3http.ProcessingMode_SKIP,
	}
	if pm == nil {
		return mode
	}
	if pm.GetRequestHeaderMode() == api.ExtProcProcessingMode_SKIP {
		mode.RequestHeaderMode = extprocv3http.ProcessingMode_SKIP
	}
	if pm.GetResponseHeaderMode() == api.ExtProcProcessingMode_SKIP {
		mode.ResponseHeaderMode = extprocv3http.ProcessingMode_SKIP
	}
	mode.RequestBodyMode = extprocv3http.ProcessingMode_BodySendMode(pm.GetRequestBodyMode())
	mode.ResponseBodyMode = extprocv3http.ProcessingMode_BodySendMode(pm.GetResponseBodyMode())
	if pm.GetRequestTrailerMode() == api.ExtProcProcessingMode_SEND {
		mode.RequestTrailerMode = extprocv3http.ProcessingMode_SEND
	}
	if pm.GetResponseTrailerMode() == api.ExtProcProcessingMode_SEND {
		mode.ResponseTrailerMode = extprocv3http.ProcessingMode_SEND
	}
	return mode
}

func (s *EgressService) runExtProcRequestPhase(r *http.Request, cfg *api.ExtProc, reqBody []byte, callerCtx egressCallerContext) (*extProcClientStream, *extprocv3http.ProcessingMode, *extprocv3.ImmediateResponse, []byte, error) {
	msgTimeout := defaultExtProcMessageTimeout
	if cfg.GetMessageTimeout().IsValid() && cfg.GetMessageTimeout().AsDuration() > 0 {
		msgTimeout = cfg.GetMessageTimeout().AsDuration()
	}
	client, endpoint, err := buildExtProcHTTPClient(cfg, s.secretsDir)
	if err != nil {
		return nil, nil, nil, reqBody, err
	}
	stream, err := dialExtProcStream(r.Context(), client, endpoint, msgTimeout*4)
	if err != nil {
		return nil, nil, nil, reqBody, err
	}

	mode := initialExtProcMode(cfg)
	attrs := buildSamAttributesStruct(s.info.Name, callerCtx)

	if mode.GetRequestHeaderMode() != extprocv3http.ProcessingMode_SKIP {
		endOfStream := len(reqBody) == 0 || mode.GetRequestBodyMode() == extprocv3http.ProcessingMode_NONE
		err := stream.Send(&extprocv3.ProcessingRequest{
			Attributes: attrs,
			Request: &extprocv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &extprocv3.HttpHeaders{
					Headers:     httpHeadersToProto(r, s.info.Name),
					EndOfStream: endOfStream,
				},
			},
		})
		if err != nil {
			stream.Close()
			return nil, nil, nil, reqBody, err
		}
		resp, err := stream.Recv(msgTimeout)
		if err != nil {
			stream.Close()
			return nil, nil, nil, reqBody, err
		}
		if cfg.GetAllowModeOverride() && resp.GetModeOverride() != nil {
			applyModeOverride(mode, resp.GetModeOverride())
		}
		if resp.GetOverrideMessageTimeout().IsValid() && resp.GetOverrideMessageTimeout().AsDuration() > 0 {
			msgTimeout = resp.GetOverrideMessageTimeout().AsDuration()
		}
		if imm := resp.GetImmediateResponse(); imm != nil {
			return stream, mode, imm, reqBody, nil
		}
		if hr := resp.GetRequestHeaders().GetResponse(); hr != nil {
			applySafeHeaderMutations(r.Header, hr.GetHeaderMutation())
			if bm := hr.GetBodyMutation(); bm != nil {
				if bm.GetClearBody() {
					reqBody = nil
				} else if bm.GetBody() != nil {
					reqBody = bm.GetBody()
				}
			}
		}
	}

	if len(reqBody) > 0 && mode.GetRequestBodyMode() != extprocv3http.ProcessingMode_NONE {
		err := stream.Send(&extprocv3.ProcessingRequest{
			Attributes: attrs,
			Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{
					Body:        reqBody,
					EndOfStream: true,
				},
			},
		})
		if err != nil {
			stream.Close()
			return nil, nil, nil, reqBody, err
		}
		resp, err := stream.Recv(msgTimeout)
		if err != nil {
			stream.Close()
			return nil, nil, nil, reqBody, err
		}
		if cfg.GetAllowModeOverride() && resp.GetModeOverride() != nil {
			applyModeOverride(mode, resp.GetModeOverride())
		}
		if imm := resp.GetImmediateResponse(); imm != nil {
			return stream, mode, imm, reqBody, nil
		}
		if br := resp.GetRequestBody().GetResponse(); br != nil {
			applySafeHeaderMutations(r.Header, br.GetHeaderMutation())
			if bm := br.GetBodyMutation(); bm != nil {
				if bm.GetClearBody() {
					reqBody = nil
				} else if bm.GetBody() != nil {
					reqBody = bm.GetBody()
				}
			}
		}
	}

	return stream, mode, nil, reqBody, nil
}

func (s *EgressService) runExtProcResponsePhase(cfg *api.ExtProc, stream *extProcClientStream, mode *extprocv3http.ProcessingMode, status int, respHeader http.Header, respBody []byte) (*extprocv3.ImmediateResponse, []byte, error) {
	msgTimeout := defaultExtProcMessageTimeout
	if cfg.GetMessageTimeout().IsValid() && cfg.GetMessageTimeout().AsDuration() > 0 {
		msgTimeout = cfg.GetMessageTimeout().AsDuration()
	}
	defer func() { _ = stream.CloseSend() }()

	if mode.GetResponseHeaderMode() != extprocv3http.ProcessingMode_SKIP {
		endOfStream := len(respBody) == 0 || mode.GetResponseBodyMode() == extprocv3http.ProcessingMode_NONE
		err := stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &extprocv3.HttpHeaders{
					Headers:     responseHeadersToProto(status, respHeader),
					EndOfStream: endOfStream,
				},
			},
		})
		if err != nil {
			return nil, respBody, err
		}
		resp, err := stream.Recv(msgTimeout)
		if err != nil {
			return nil, respBody, err
		}
		if cfg.GetAllowModeOverride() && resp.GetModeOverride() != nil {
			applyModeOverride(mode, resp.GetModeOverride())
		}
		if imm := resp.GetImmediateResponse(); imm != nil {
			return imm, respBody, nil
		}
		if hr := resp.GetResponseHeaders().GetResponse(); hr != nil {
			applySafeHeaderMutations(respHeader, hr.GetHeaderMutation())
			if bm := hr.GetBodyMutation(); bm != nil {
				if bm.GetClearBody() {
					respBody = nil
				} else if bm.GetBody() != nil {
					respBody = bm.GetBody()
				}
			}
		}
	}

	if len(respBody) > 0 && mode.GetResponseBodyMode() != extprocv3http.ProcessingMode_NONE {
		maxBytes := int(cfg.GetMaxBufferedBytes())
		if maxBytes <= 0 {
			maxBytes = defaultExtProcMaxBufferBytes
		}
		if len(respBody) > maxBytes {
			return nil, respBody, fmt.Errorf("response body (%d bytes) exceeds max_buffered_bytes (%d)", len(respBody), maxBytes)
		}
		err := stream.Send(&extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_ResponseBody{
				ResponseBody: &extprocv3.HttpBody{
					Body:        respBody,
					EndOfStream: true,
				},
			},
		})
		if err != nil {
			return nil, respBody, err
		}
		resp, err := stream.Recv(msgTimeout)
		if err != nil {
			return nil, respBody, err
		}
		if imm := resp.GetImmediateResponse(); imm != nil {
			return imm, respBody, nil
		}
		if br := resp.GetResponseBody().GetResponse(); br != nil {
			applySafeHeaderMutations(respHeader, br.GetHeaderMutation())
			if bm := br.GetBodyMutation(); bm != nil {
				if bm.GetClearBody() {
					respBody = nil
				} else if bm.GetBody() != nil {
					respBody = bm.GetBody()
				}
			}
		}
	}
	return nil, respBody, nil
}

func applyModeOverride(dst, override *extprocv3http.ProcessingMode) {
	if override.GetRequestHeaderMode() != extprocv3http.ProcessingMode_DEFAULT {
		dst.RequestHeaderMode = override.GetRequestHeaderMode()
	}
	if override.GetResponseHeaderMode() != extprocv3http.ProcessingMode_DEFAULT {
		dst.ResponseHeaderMode = override.GetResponseHeaderMode()
	}
	if override.GetRequestBodyMode() != extprocv3http.ProcessingMode_NONE {
		dst.RequestBodyMode = override.GetRequestBodyMode()
	}
	if override.GetResponseBodyMode() != extprocv3http.ProcessingMode_NONE {
		dst.ResponseBodyMode = override.GetResponseBodyMode()
	}
	if override.GetRequestTrailerMode() != extprocv3http.ProcessingMode_DEFAULT {
		dst.RequestTrailerMode = override.GetRequestTrailerMode()
	}
	if override.GetResponseTrailerMode() != extprocv3http.ProcessingMode_DEFAULT {
		dst.ResponseTrailerMode = override.GetResponseTrailerMode()
	}
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
		body = bytes.ReplaceAll(body, []byte(promptText), []byte(replacement))
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
		body = bytes.ReplaceAll(body, []byte(respText), []byte(replacement))
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
		client = &http.Client{Timeout: timeout}
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

func (s *EgressService) resolveModelArmorEndpoint(ctx context.Context, template string) (string, string, error) {
	tmpl := strings.TrimSpace(template)
	if tmpl == "" {
		return "", "", errors.New("model_armor.template is empty")
	}
	if s.modelArmorBaseURL != "" {
		return strings.TrimRight(s.modelArmorBaseURL, "/") + "/v1/" + strings.TrimLeft(tmpl, "/"), "", nil
	}
	if strings.HasPrefix(tmpl, "http://") || strings.HasPrefix(tmpl, "https://") {
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
