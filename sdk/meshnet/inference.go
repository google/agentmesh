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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/agentmesh/api"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	modelRegistryTTL        = 30 * time.Second
	remoteModelProbeTimeout = 10 * time.Second
	remoteProbeConcurrency  = 10
	maxInferenceBodyBytes   = 16 << 20 // 16 MiB
	providerBackoffDuration = 15 * time.Second
)

type modelProvider struct {
	peerID  string
	service string
}

type inferenceFacade struct {
	s      *Server
	client *http.Client

	mu      sync.Mutex
	models  map[string][]modelProvider
	expires time.Time

	backoffMu sync.Mutex
	backoff   map[string]time.Time
	rr        atomic.Uint64
}

// InferenceHandler returns an OpenAI-compatible http.Handler serving
// GET /v1/models, POST /v1/chat/completions, and POST /v1/completions backed by
// remote inference://* services across the mesh. Point any OpenAI SDK or coding
// harness at this handler over a local Unix socket or loopback listener so the
// sandbox needs zero upstream LLM API keys.
func (s *Server) InferenceHandler() http.Handler {
	f := &inferenceFacade{
		s:      s,
		client: s.HTTPClient(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", f.handleModels)
	mux.HandleFunc("/v1/chat/completions", f.handleCompletions)
	mux.HandleFunc("/v1/completions", f.handleCompletions)
	return mux
}

func (f *inferenceFacade) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is supported")
		return
	}
	type openAIModel struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}
	view := f.modelsView(r.Context())
	data := make([]openAIModel, 0, len(view))
	for id, providers := range view {
		ownedBy := "mesh"
		if len(providers) > 0 && providers[0].peerID != "" {
			ownedBy = providers[0].peerID
		}
		data = append(data, openAIModel{ID: id, Object: "model", OwnedBy: ownedBy})
	}
	sort.Slice(data, func(i, j int) bool { return data[i].ID < data[j].ID })

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
}

func (f *inferenceFacade) handleCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is supported")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxInferenceBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds limit")
			return
		}
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "failed to read request body")
		return
	}

	var reqBody struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &reqBody); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if reqBody.Model == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "missing required field: model")
		return
	}

	requiredLabels, err := parseRequiredLabels(r.Header.Get(api.HeaderMeshRequiredLabels))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	providers := f.providersFor(r.Context(), reqBody.Model)
	if len(providers) == 0 {
		writeOpenAIError(w, http.StatusNotFound, "model_not_found",
			fmt.Sprintf("model %q is not served by any provider on the mesh", reqBody.Model))
		return
	}

	ranked := f.rankProviders(providers)
	if len(ranked) == 0 {
		writeOpenAIError(w, http.StatusServiceUnavailable, "no_eligible_provider",
			fmt.Sprintf("model %q has no eligible provider", reqBody.Model))
		return
	}

	maxAttempts := min(3, len(ranked))
	verifiedAny := false
	for i := range maxAttempts {
		p := ranked[i]
		pid, err := peer.Decode(p.peerID)
		if err != nil {
			continue
		}
		if err := f.s.verifyProvider(r.Context(), pid, requiredLabels, api.ServiceTypeStringInference+"://"+p.service); err != nil {
			f.s.log().Warn("inference provider failed verification; trying next",
				"peer_id", p.peerID,
				"service", p.service,
				"error", err,
			)
			continue
		}
		verifiedAny = true

		targetURL := fmt.Sprintf("http://agentmesh.local/mesh/%s/%s/%s%s", p.peerID, api.ServiceTypeStringInference, p.service, r.URL.Path)
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}
		outReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			continue
		}
		outReq.ContentLength = int64(len(body))
		outReq.Header = r.Header.Clone()
		outReq.Header.Del(api.HeaderMeshAuthentication)
		outReq.Header.Del(api.HeaderMeshRequiredLabels)

		resp, err := f.client.Do(outReq)
		if err != nil {
			f.recordBackoff(p)
			f.s.log().Warn("inference request failed; trying next provider", "peer_id", p.peerID, "service", p.service, "error", err)
			continue
		}
		if retryableStatus(resp.StatusCode) {
			_ = resp.Body.Close()
			f.recordBackoff(p)
			f.s.log().Warn("inference provider returned retryable status; trying next",
				"peer_id", p.peerID,
				"service", p.service,
				"status", resp.StatusCode,
			)
			continue
		}

		copyResponse(w, resp)
		return
	}

	if !verifiedAny {
		writeOpenAIError(w, http.StatusServiceUnavailable, "no_eligible_provider",
			fmt.Sprintf("model %q has no provider satisfying required labels", reqBody.Model))
		return
	}
	writeOpenAIError(w, http.StatusServiceUnavailable, "no_available_provider",
		fmt.Sprintf("all providers for model %q are currently unavailable", reqBody.Model))
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	defer func() { _ = resp.Body.Close() }()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func (f *inferenceFacade) modelsView(ctx context.Context) map[string][]modelProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.models) == 0 || time.Now().After(f.expires) {
		f.models = f.collectModels(ctx)
		f.expires = time.Now().Add(modelRegistryTTL)
	}
	return f.models
}

func (f *inferenceFacade) providersFor(ctx context.Context, model string) []modelProvider {
	f.mu.Lock()
	refreshed := false
	if len(f.models) == 0 || time.Now().After(f.expires) {
		f.models = f.collectModels(ctx)
		f.expires = time.Now().Add(modelRegistryTTL)
		refreshed = true
	}
	if providers := f.models[model]; len(providers) > 0 {
		f.mu.Unlock()
		return providers
	}
	if !refreshed {
		f.models = f.collectModels(ctx)
		f.expires = time.Now().Add(modelRegistryTTL)
	}
	out := f.models[model]
	f.mu.Unlock()
	return out
}

func (f *inferenceFacade) collectModels(ctx context.Context) map[string][]modelProvider {
	models := map[string][]modelProvider{}
	providers, err := f.s.Discover(ctx, api.ServiceType_SERVICE_TYPE_INFERENCE, "")
	if err != nil {
		f.s.log().Debug("inference discovery failed", "error", err)
		return models
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, remoteProbeConcurrency)
	)
	for _, p := range providers {
		wg.Add(1)
		go func(peerID, srvName string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			ids, err := f.probeRemoteModels(ctx, peerID, srvName)
			if err != nil {
				f.s.log().Debug("remote model probe failed", "peer_id", peerID, "service", srvName, "error", err)
				return
			}
			mu.Lock()
			for _, id := range ids {
				models[id] = append(models[id], modelProvider{peerID: peerID, service: srvName})
			}
			mu.Unlock()
		}(p.GetPeerId(), p.GetSrvName())
	}
	wg.Wait()
	return models
}

func (f *inferenceFacade) probeRemoteModels(ctx context.Context, peerID, srvName string) ([]string, error) {
	if f.s.host == nil {
		return nil, errors.New("server not running")
	}
	pid, err := peer.Decode(peerID)
	if err != nil {
		return nil, err
	}
	biscuitBytes := f.s.currentBiscuit()
	if len(biscuitBytes) == 0 {
		return nil, errors.New("missing local credential")
	}
	if err := f.s.verifyProvider(ctx, pid, nil, api.ServiceTypeStringInference+"://"+srvName); err != nil {
		return nil, err
	}
	probeCtx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "openai-facade"), remoteModelProbeTimeout)
	defer cancel()
	f.s.preparePeerAddrs(probeCtx, pid)

	u := fmt.Sprintf("libp2p://%s/%s/%s/v1/models", pid.String(), api.ServiceTypeStringInference, srvName)
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(api.HeaderMeshBiscuit, base64.StdEncoding.EncodeToString(biscuitBytes))
	req.Host = pid.String()

	p2pClient := &http.Client{Transport: libp2phttp.NewTransport(f.s.host)}
	resp, err := p2pClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider %s/%s returned status %d for /v1/models", peerID, srvName, resp.StatusCode)
	}
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&list); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list.Data))
	for _, m := range list.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	return out, nil
}

func (f *inferenceFacade) rankProviders(providers []modelProvider) []modelProvider {
	var remotes []modelProvider
	for _, p := range providers {
		pid, err := peer.Decode(p.peerID)
		if err != nil || f.s.isPeerBanned(pid) || f.inBackoff(p) {
			continue
		}
		remotes = append(remotes, p)
	}
	if len(remotes) >= 2 {
		offset := int(f.rr.Add(1) % uint64(len(remotes)))
		head := append([]modelProvider(nil), remotes...)
		for i := range remotes {
			remotes[i] = head[(i+offset)%len(remotes)]
		}
	}
	return remotes
}

func (f *inferenceFacade) inBackoff(p modelProvider) bool {
	key := p.peerID + "|" + p.service
	f.backoffMu.Lock()
	defer f.backoffMu.Unlock()
	until, ok := f.backoff[key]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(f.backoff, key)
		return false
	}
	return true
}

func (f *inferenceFacade) recordBackoff(p modelProvider) {
	key := p.peerID + "|" + p.service
	f.backoffMu.Lock()
	if f.backoff == nil {
		f.backoff = map[string]time.Time{}
	}
	f.backoff[key] = time.Now().Add(providerBackoffDuration)
	f.backoffMu.Unlock()
}

func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func writeOpenAIError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": msg,
			"type":    "invalid_request_error",
			"code":    code,
		},
	})
}
