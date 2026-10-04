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

	"github.com/google/sam/api"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// modelRegistryTTL bounds how stale the mesh-wide model view can be.
	modelRegistryTTL = 30 * time.Second
	// remoteModelProbeTimeout bounds a single provider /v1/models probe.
	remoteModelProbeTimeout = 10 * time.Second
	// remoteProbeConcurrency bounds parallel provider probes during refresh.
	remoteProbeConcurrency = 10
	// maxInferenceBodyBytes caps buffered completion request bodies.
	maxInferenceBodyBytes = 16 << 20 // 16 MiB
)

// modelLister is implemented by local services that can report served models.
type modelLister interface {
	Models(ctx context.Context) ([]string, error)
}

// modelProvider locates one service able to serve a model.
// An empty peerID means the service runs on this node. labels and active
// are known only for gossip-observed providers; zero values mean unknown.
type modelProvider struct {
	peerID  string
	service string
	labels  map[string]string
	active  uint32
}

// openAIFacade exposes an OpenAI-compatible surface on the sidecar
// (/v1/models, /v1/chat/completions, /v1/completions): point any OpenAI SDK
// at the sidecar and the facade resolves the requested model to a local or
// mesh provider, preferring local. Function fields are seams so unit tests
// can fake discovery and probing.
type openAIFacade struct {
	forward       http.Handler // egress proxy handling /sam/<peer>/<type>/<name>/...
	localPeerID   func() string
	localServices func() []Service
	discover      func(ctx context.Context) ([]*api.DiscoveredProvider, error)
	remoteModels  func(ctx context.Context, peerID, srvName string) ([]string, error)
	// Gossip seams (may be nil): fresh provider knowledge without a probe,
	// and interest registration so announcements start flowing for a model.
	viewProviders  func(model string) []modelProvider
	ensureInterest func(model string)
	// Scorer seams (may be nil): revocation check and this node's labels.
	isRevoked   func(peerID string) bool
	localLabels func() map[string]string
	// peerLabels resolves a peer's gossip-observed labels for providers
	// discovered via the registry probe, which carries no labels.
	peerLabels func(peerID string) map[string]string
	// egressFloor (may be nil) is the operator's egress floor. Remotes are
	// held to it by the label gate, on attested facts; a local service has no
	// biscuit and no gate, so ranking is the only place its floor can be
	// applied at all.
	egressFloor func() map[string]string
	// Label gate seam (may be nil = enforcement unavailable, fail closed
	// when a requirement exists): verifies the provider's
	// control-plane-attested labels before any request data is sent
	// (see labels_gate.go).
	verifyPeerLabels func(ctx context.Context, peerID string, required map[string]string) error
	authorizeLocal   func(ctx context.Context, serviceName, method, path string) error

	ttl     time.Duration
	mu      sync.Mutex
	models  map[string][]modelProvider
	expires time.Time

	backoffMu sync.Mutex
	backoff   map[string]time.Time
}

func newOpenAIFacade(node *SamNode, egress http.Handler) *openAIFacade {
	client := &http.Client{Transport: libp2phttp.NewTransport(node.Host)}
	return &openAIFacade{
		forward:     egress,
		ttl:         modelRegistryTTL,
		localPeerID: func() string { return node.Host.ID().String() },
		localServices: func() []Service {
			var out []Service
			for _, info := range node.ListLocalServices(api.ServiceType_SERVICE_TYPE_INFERENCE) {
				if svc, ok := node.services.Get(info.GetName()); ok {
					out = append(out, svc)
				}
			}
			return out
		},
		discover: func(ctx context.Context) ([]*api.DiscoveredProvider, error) {
			return node.DiscoverRemoteServices(ctx, api.ServiceType_SERVICE_TYPE_INFERENCE, "")
		},
		remoteModels: func(ctx context.Context, peerID, srvName string) ([]string, error) {
			return fetchRemoteModels(ctx, node, client, peerID, srvName)
		},
		viewProviders: func(model string) []modelProvider {
			if node.Discovery == nil {
				return nil
			}
			var out []modelProvider
			for _, p := range node.Discovery.Providers(api.ServiceType_SERVICE_TYPE_INFERENCE, model) {
				out = append(out, modelProvider{
					peerID:  p.PeerID,
					service: p.Service,
					labels:  p.Labels,
					active:  p.Load.ActiveRequests,
				})
			}
			return out
		},
		ensureInterest: func(model string) {
			if node.Discovery != nil {
				node.Discovery.Ensure(api.ServiceType_SERVICE_TYPE_INFERENCE, model)
			}
		},
		isRevoked: func(peerID string) bool {
			return node.revokedPeers != nil && node.revokedPeers.Contains(peerID)
		},
		localLabels: node.labels,
		egressFloor: node.egressFloor,
		peerLabels: func(peerID string) map[string]string {
			if node.Discovery == nil {
				return nil
			}
			return node.Discovery.PeerLabels(peerID)
		},
		verifyPeerLabels: func(ctx context.Context, peerID string, required map[string]string) error {
			pid, err := peer.Decode(peerID)
			if err != nil {
				return fmt.Errorf("invalid peer ID %q: %w", peerID, err)
			}
			return node.VerifyPeerLabels(ctx, pid, required)
		},
		authorizeLocal: func(ctx context.Context, serviceName, method, path string) error {
			callerBiscuit := CallerBiscuitFromContext(ctx)
			if len(callerBiscuit) == 0 {
				return nil
			}
			pid, _ := node.localPeerID()
			return node.VerifyBiscuitToken(callerBiscuit, RequestContext{
				PeerID:   pid,
				Protocol: "local-api",
				Target:   api.InferenceServicePrefix + serviceName,
				HTTP:     &HTTPRequestFacts{Method: method, Path: path},
				Local:    true,
			})
		},
	}
}

// fetchRemoteModels probes a remote provider's backend /v1/models through its
// libp2p ingress, authenticating with this node's biscuit.
func fetchRemoteModels(ctx context.Context, node *SamNode, client *http.Client, peerID, srvName string) ([]string, error) {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return nil, fmt.Errorf("invalid peer ID %q: %w", peerID, err)
	}
	identity := node.GetRequestIdentity(ctx)
	if identity == nil {
		return nil, fmt.Errorf("missing node identity")
	}
	ctx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "openai-facade"), remoteModelProbeTimeout)
	defer cancel()
	if cond := node.Host.Network().Connectedness(pid); cond != network.Connected && cond != network.Limited {
		node.preparePeerAddrs(ctx, pid)
	}
	u := fmt.Sprintf("libp2p://%s/%s/%s/v1/models", peerID, api.ServiceTypeStringInference, srvName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(api.HeaderSamBiscuit, base64.StdEncoding.EncodeToString(identity))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider %s/%s returned status %d for /v1/models", peerID, srvName, resp.StatusCode)
	}
	return decodeModelIDs(resp.Body)
}

// providersFor resolves a model to its providers: registry first (locals
// preferred), then the gossip view (fresh knowledge without a mesh-wide
// probe), then one forced registry refresh so newly appeared providers are
// usable before the TTL lapses. Interest is registered so announcements for
// this model start flowing.
func (f *openAIFacade) providersFor(ctx context.Context, model string) []modelProvider {
	if f.ensureInterest != nil {
		f.ensureInterest(model)
	}
	f.mu.Lock()
	refreshed := false
	if f.staleLocked() {
		f.refreshLocked(ctx)
		refreshed = true
	}
	if providers := f.models[model]; len(providers) > 0 {
		f.mu.Unlock()
		return providers
	}
	f.mu.Unlock()

	if f.viewProviders != nil {
		if providers := f.viewProviders(model); len(providers) > 0 {
			return providers
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !refreshed {
		f.refreshLocked(ctx)
	}
	return f.models[model]
}

// modelsView returns the current model registry, refreshing when stale. The
// returned map is a snapshot: refreshes swap the pointer, never mutate.
func (f *openAIFacade) modelsView(ctx context.Context) map[string][]modelProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.staleLocked() {
		f.refreshLocked(ctx)
	}
	return f.models
}

// staleLocked reports whether the view needs a refresh. Empty views are never
// cached: providers may appear at any moment and discovery stays bounded.
func (f *openAIFacade) staleLocked() bool {
	return len(f.models) == 0 || time.Now().After(f.expires)
}

func (f *openAIFacade) refreshLocked(ctx context.Context) {
	f.models = f.collectModels(ctx)
	f.expires = time.Now().Add(f.ttl)
}

// collectModels aggregates model IDs from local services (first, so they are
// preferred) and mesh providers. Failed probes drop the provider with a log
// line rather than failing the whole view.
func (f *openAIFacade) collectModels(ctx context.Context) map[string][]modelProvider {
	models := map[string][]modelProvider{}
	for _, svc := range f.localServices() {
		lister, ok := svc.(modelLister)
		if !ok {
			continue
		}
		ids, err := lister.Models(ctx)
		if err != nil {
			logger.Warnf("[OpenAIFacade] local model probe for %q failed: %v", svc.Info().GetName(), err)
			continue
		}
		for _, id := range ids {
			models[id] = append(models[id], modelProvider{service: svc.Info().GetName()})
		}
	}

	providers, err := f.discover(ctx)
	if err != nil {
		logger.Warnf("[OpenAIFacade] mesh discovery failed: %v", err)
		return models
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, remoteProbeConcurrency)
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
			ids, err := f.remoteModels(ctx, peerID, srvName)
			if err != nil {
				logger.Warnf("[OpenAIFacade] model probe for %s/%s failed: %v", peerID, srvName, err)
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

// facadeRR spreads load across equally ranked remote providers.
var facadeRR atomic.Uint64

func (f *openAIFacade) handleModels(w http.ResponseWriter, r *http.Request) {
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
		ownedBy := "local"
		if providers[0].peerID != "" {
			ownedBy = providers[0].peerID
		}
		data = append(data, openAIModel{ID: id, Object: "model", OwnedBy: ownedBy})
	}
	sort.Slice(data, func(i, j int) bool { return data[i].ID < data[j].ID })

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data}); err != nil {
		logger.Errorf("[OpenAIFacade] failed to encode models response: %v", err)
	}
}

func (f *openAIFacade) handleCompletions(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if req.Model == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "missing required field: model")
		return
	}

	requiredLabels, err := parseRequiredLabels(r.Header.Get(api.HeaderSamRequiredLabels))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	providers := f.providersFor(r.Context(), req.Model)
	if len(providers) == 0 {
		writeOpenAIError(w, http.StatusNotFound, "model_not_found",
			fmt.Sprintf("model %q is not served by any provider on the mesh", req.Model))
		return
	}

	ranked := f.rankProviders(providers, requiredLabels)
	if len(ranked) == 0 {
		recordFacadeRejection(reasonNoEligible)
		writeOpenAIError(w, http.StatusServiceUnavailable, "no_eligible_provider",
			fmt.Sprintf("model %q has no provider satisfying the request constraints", req.Model))
		return
	}

	// The gate already stripped the credential it consumed; a surviving
	// Authorization header is the destination backend's own credential and
	// passes through, mirroring the egress path. X-Sam-Authentication is
	// local-only, and the label requirement is an instruction to this
	// sidecar, not to the provider.
	r.Header.Del(api.HeaderSamAuthentication)
	r.Header.Del(api.HeaderSamRequiredLabels)

	maxAttempts := min(3, len(ranked))
	for i := range maxAttempts {
		p := ranked[i]
		logger.Debugf("[OpenAIFacade] model %q attempt %d/%d -> provider peer=%q service=%q (%d eligible)",
			req.Model, i+1, maxAttempts, p.peerID, p.service, len(ranked))

		attempt := r.Clone(r.Context())
		attempt.Body = io.NopCloser(bytes.NewReader(body))
		attempt.ContentLength = int64(len(body))
		aw := newAttemptWriter(w)

		if p.peerID == "" {
			f.serveLocal(aw, attempt, p.service)
		} else {
			// Every provider is verified before the request body leaves this
			// node: a discovered peer is only a provider once it has shown a
			// control-plane-signed biscuit bound to it. The caller's label
			// requirement and the operator's floor are extra checks on that
			// same token (VerifyPeerLabels ANDs both).
			if f.verifyPeerLabels == nil {
				recordFacadeRejection(reasonLabelUnattested)
				writeOpenAIError(w, http.StatusServiceUnavailable, "label_unattested",
					"provider verification is unavailable on this node")
				return
			}
			// No backoff on failure: the verdict is requirement-scoped,
			// the provider stays eligible for unconstrained requests.
			if err := f.verifyPeerLabels(r.Context(), p.peerID, requiredLabels); err != nil {
				// With no caller requirement what failed is the floor or the
				// peer's own identity; attribute it so the operator can tell
				// their floor apart from a caller's requirement.
				if len(requiredLabels) == 0 {
					recordFacadeRejection(reasonEgressFloorMismatch)
				} else {
					recordFacadeRejection(reasonLabelUnattested)
				}
				logger.Warnf("[OpenAIFacade] provider peer=%q service=%q failed verification for %v (egress floor %v): %v; trying next",
					p.peerID, p.service, requiredLabels, f.floor(), err)
				continue
			}
			attempt.URL.Path = fmt.Sprintf("/sam/%s/%s/%s%s", p.peerID, api.ServiceTypeStringInference, p.service, r.URL.Path)
			attempt.URL.RawPath = ""
			f.forward.ServeHTTP(aw, attempt)
		}
		if !aw.retryable {
			return // response delivered (success or non-retryable error)
		}
		recordFacadeRetry()
		f.recordBackoff(p)
		logger.Warnf("[OpenAIFacade] provider peer=%q service=%q returned %d for model %q; trying next",
			p.peerID, p.service, aw.status, req.Model)
	}
	recordFacadeRejection(reasonAttemptsExceeded)
	writeOpenAIError(w, http.StatusServiceUnavailable, "no_available_provider",
		fmt.Sprintf("all providers for model %q are currently unavailable", req.Model))
}

func (f *openAIFacade) serveLocal(w http.ResponseWriter, r *http.Request, serviceName string) {
	if f.authorizeLocal != nil {
		if err := f.authorizeLocal(r.Context(), serviceName, r.Method, r.URL.Path); err != nil {
			writeOpenAIError(w, http.StatusForbidden, "permission_denied", fmt.Sprintf("authorization failed: %v", err))
			return
		}
	}
	for _, svc := range f.localServices() {
		if svc.Info().GetName() != serviceName || svc.Handler() == nil {
			continue
		}
		// Attribute locally served tokens to this node in usage metrics.
		if id := f.localPeerID(); id != "" {
			r.Header.Set(api.HeaderPeerID, id)
		}
		svc.Handler().ServeHTTP(w, r)
		return
	}
	writeOpenAIError(w, http.StatusServiceUnavailable, "service_unavailable",
		fmt.Sprintf("local service %q is no longer available", serviceName))
}

// writeOpenAIError emits an OpenAI-style error body so SDKs surface it cleanly.
func writeOpenAIError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": "invalid_request_error", "code": code},
	})
	if err != nil {
		logger.Errorf("[OpenAIFacade] failed to encode error response: %v", err)
	}
}
