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

package bench

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/controlplane"
	cpclient "github.com/google/sam/internal/controlplane/client"
	"github.com/google/sam/internal/identity"
	"github.com/google/sam/internal/node"
	"github.com/google/sam/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// STSOptions configures a Control Plane and Node STS benchmark run.
type STSOptions struct {
	Requests          int
	Concurrency       int
	Warmup            int
	Workloads         int
	RequestsPerMinute int
}

// STSPhaseReport records throughput, latency distribution, and cache behavior
// for one STS benchmark phase.
type STSPhaseReport struct {
	Requests          int          `json:"requests"`
	Succeeded         int          `json:"succeeded"`
	Failed            int          `json:"failed"`
	Elapsed           float64      `json:"elapsed_seconds"`
	Throughput        float64      `json:"requests_per_second"`
	Latency           Distribution `json:"latency_ms"`
	ControlPlaneCalls int          `json:"control_plane_calls"`
	CacheHits         int          `json:"cache_hits"`
	CacheHitRate      float64      `json:"cache_hit_rate"`
}

// STSReport summarizes all STS benchmark phases (uncached Control Plane
// endpoints and cached SamNode paths under 5-minute JWT-SVID and 1-hour
// projected token rotation schedules).
type STSReport struct {
	Concurrency           int            `json:"concurrency"`
	Requests              int            `json:"requests"`
	Workloads             int            `json:"workloads"`
	RequestsPerMinute     int            `json:"requests_per_minute"`
	TokenExchangeUncached STSPhaseReport `json:"token_exchange_uncached"`
	STSTokenUncached      STSPhaseReport `json:"sts_token_uncached"`
	TokenExchangeSVID5m   STSPhaseReport `json:"token_exchange_svid_5m"`
	TokenExchangeK8s1h    STSPhaseReport `json:"token_exchange_k8s_1h"`
	STSTokenCached        STSPhaseReport `json:"sts_token_cached"`
}

// RunSTS executes the STS benchmark suite against an in-process Control Plane
// and enrolled SamNode, measuring uncached mint throughput/latency as well as
// node-cached throughput and hit rates for 5-minute JWT-SVIDs and 1-hour
// Kubernetes projected tokens.
func RunSTS(ctx context.Context, opts STSOptions) (*STSReport, error) {
	if opts.Requests <= 0 {
		return nil, errors.New("bench: requests must be > 0")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.Workloads <= 0 {
		opts.Workloads = 8
	}
	if opts.RequestsPerMinute <= 0 {
		opts.RequestsPerMinute = 60
	}

	env, err := newSTSEnv(ctx)
	if err != nil {
		return nil, err
	}
	defer env.Close()

	report := &STSReport{
		Concurrency:       opts.Concurrency,
		Requests:          opts.Requests,
		Workloads:         opts.Workloads,
		RequestsPerMinute: opts.RequestsPerMinute,
	}

	// Pre-mint a subject JWT and a task-attenuated Biscuit for uncached CP calls.
	baseJWT, err := env.mintSubjectJWT("workload-0", 1)
	if err != nil {
		return nil, err
	}
	taskBiscuit, err := identity.AttenuateBiscuit(env.nodeBiscuit, &api.TaskAuthorizationRule{
		Name: "tasks/bench-sts",
		Rules: []*api.TaskRule{
			{
				AllowedServices: []string{"egress://bigquery.googleapis.com"},
				Operation: &api.TaskOperation{
					AllowedMethods:     []string{"GET"},
					AllowedPermissions: []string{"bigquery.googleapis.com/tables.getData"},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("attenuate task biscuit: %w", err)
	}

	// Phase 1: Uncached Control Plane POST /token/exchange
	cpClient := cpclient.New(env.cpURL, env.httpClient)
	report.TokenExchangeUncached = runSTSPhase(ctx, opts.Concurrency, opts.Warmup, opts.Requests, &env.exchangeCalls, func(i int) error {
		nowMs := time.Now().UnixMilli()
		sig, err := env.nodePriv.Sign([]byte(api.TokenExchangeChallenge(env.nodePeerID.String(), nowMs)))
		if err != nil {
			return err
		}
		_, err = cpClient.ExchangeToken(ctx, env.nodeBiscuit, &api.TokenExchangeRequest{
			SubjectToken:       baseJWT,
			ChallengeUnixMs:    nowMs,
			ChallengeSignature: sig,
		})
		return err
	})

	// Phase 2: Uncached Control Plane POST /sts/token
	report.STSTokenUncached = runSTSPhase(ctx, opts.Concurrency, opts.Warmup, opts.Requests, &env.stsCalls, func(i int) error {
		nowMs := time.Now().UnixMilli()
		sig, err := env.nodePriv.Sign([]byte(api.STSTokenChallenge(env.nodePeerID.String(), nowMs)))
		if err != nil {
			return err
		}
		_, err = cpClient.MintSTSToken(ctx, env.nodeBiscuit, &api.STSTokenRequest{
			Biscuit:            taskBiscuit,
			Destination:        "bigquery.googleapis.com",
			Audience:           "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sam/providers/cp",
			ChallengeUnixMs:    nowMs,
			ChallengeSignature: sig,
		})
		return err
	})

	// Phase 3: Cached SamNode.ExchangeSubjectJWT with 5-minute SPIFFE JWT-SVID rotation.
	// A workload issuing RequestsPerMinute requests/min makes (5 * RequestsPerMinute)
	// requests per 5-minute SVID lifetime before its token rotates.
	reqsPerSVID := 5 * opts.RequestsPerMinute
	svidTokens, err := env.precomputeWorkloadTokens(opts.Workloads, opts.Requests, reqsPerSVID, "svid")
	if err != nil {
		return nil, err
	}
	report.TokenExchangeSVID5m = runSTSPhase(ctx, opts.Concurrency, 0, opts.Requests, &env.exchangeCalls, func(i int) error {
		wIdx := i % opts.Workloads
		rotEpoch := (i / opts.Workloads) / reqsPerSVID
		tok := svidTokens[wIdx][rotEpoch]
		_, err := env.samNode.ExchangeSubjectJWT(ctx, tok, api.TokenTypeJWT, nil, false)
		return err
	})

	// Phase 4: Cached SamNode.ExchangeSubjectJWT with 1-hour Kubernetes projected token rotation.
	// A workload issuing RequestsPerMinute requests/min makes (60 * RequestsPerMinute)
	// requests per 1-hour projected token lifetime before its token rotates.
	reqsPerK8s := 60 * opts.RequestsPerMinute
	k8sTokens, err := env.precomputeWorkloadTokens(opts.Workloads, opts.Requests, reqsPerK8s, "k8s")
	if err != nil {
		return nil, err
	}
	report.TokenExchangeK8s1h = runSTSPhase(ctx, opts.Concurrency, 0, opts.Requests, &env.exchangeCalls, func(i int) error {
		wIdx := i % opts.Workloads
		rotEpoch := (i / opts.Workloads) / reqsPerK8s
		tok := k8sTokens[wIdx][rotEpoch]
		_, err := env.samNode.ExchangeSubjectJWT(ctx, tok, api.TokenTypeJWT, nil, false)
		return err
	})

	// Phase 5: Cached SamNode.MintBorderJWT across active task Biscuits (15m border JWT lifetime).
	reqsPerTask := 15 * opts.RequestsPerMinute
	taskBiscuits, err := env.precomputeTaskBiscuits(opts.Workloads, opts.Requests, reqsPerTask)
	if err != nil {
		return nil, err
	}
	report.STSTokenCached = runSTSPhase(ctx, opts.Concurrency, 0, opts.Requests, &env.stsCalls, func(i int) error {
		wIdx := i % opts.Workloads
		rotEpoch := (i / opts.Workloads) / reqsPerTask
		tb := taskBiscuits[wIdx][rotEpoch]
		_, err := env.samNode.MintBorderJWT(
			ctx,
			tb,
			"bigquery.googleapis.com",
			"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sam/providers/cp",
		)
		return err
	})

	return report, nil
}

func runSTSPhase(ctx context.Context, concurrency, warmup, total int, cpCounter *atomic.Int64, fn func(i int) error) STSPhaseReport {
	if warmup > 0 {
		for i := range warmup {
			_ = fn(i)
		}
	}
	cpCounter.Store(0)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		durations = make([]time.Duration, 0, total)
		succeeded int
		failed    int
		idx       atomic.Int64
	)

	start := time.Now()
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(idx.Add(1) - 1)
				if i >= total {
					return
				}
				if ctx.Err() != nil {
					return
				}
				t0 := time.Now()
				err := fn(i)
				dt := time.Since(t0)
				mu.Lock()
				if err != nil {
					failed++
				} else {
					succeeded++
					durations = append(durations, dt)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	cpCalls := int(cpCounter.Load())
	hits := succeeded - cpCalls
	if hits < 0 {
		hits = 0
	}
	var hitRate float64
	if succeeded > 0 {
		hitRate = float64(hits) / float64(succeeded)
	}
	var throughput float64
	if elapsed > 0 {
		throughput = float64(succeeded+failed) / elapsed
	}
	return STSPhaseReport{
		Requests:          total,
		Succeeded:         succeeded,
		Failed:            failed,
		Elapsed:           elapsed,
		Throughput:        throughput,
		Latency:           summarise(durations),
		ControlPlaneCalls: cpCalls,
		CacheHits:         hits,
		CacheHitRate:      hitRate,
	}
}

type stsBenchEnv struct {
	tempDir       string
	oidcSrv       *httptest.Server
	rsaKey        *rsa.PrivateKey
	cpSrv         *controlplane.Server
	cpProxySrv    *httptest.Server
	store         storage.Store
	cpURL         string
	httpClient    *http.Client
	nodePriv      crypto.PrivKey
	nodePeerID    peer.ID
	nodeBiscuit   []byte
	samNode       *node.SamNode
	exchangeCalls atomic.Int64
	stsCalls      atomic.Int64
}

func newSTSEnv(ctx context.Context) (*stsBenchEnv, error) {
	tempDir, err := os.MkdirTemp("", "sam-bench-sts-*")
	if err != nil {
		return nil, err
	}
	env := &stsBenchEnv{
		tempDir:    tempDir,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		env.Close()
		return nil, err
	}
	env.rsaKey = rsaKey

	oidcMux := http.NewServeMux()
	env.oidcSrv = httptest.NewServer(oidcMux)
	issuer := env.oidcSrv.URL
	oidcMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   issuer,
			"jwks_uri": issuer + "/keys",
		})
	})
	oidcMux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "bench-key",
					"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
				},
			},
		})
	})

	dbPath := filepath.Join(tempDir, "cp.db")
	store, err := storage.NewSQLStore("sqlite", dbPath)
	if err != nil {
		env.Close()
		return nil, err
	}
	env.store = store

	roles := []*api.PolicyRole{
		{
			Name:            api.RoleNode,
			AllowedServices: []string{"egress://bigquery.googleapis.com"},
			AllowedTargets:  []string{"*"},
		},
	}
	bindings := []*api.PolicyBinding{
		{
			Role:    api.RoleNode,
			Members: []string{api.SystemAuthenticated},
		},
	}
	egress := []*api.EgressDestination{
		{
			Name:     "bigquery.googleapis.com",
			ServedBy: []string{api.RoleNode},
			Broker: &api.CredentialBroker{
				Kind: &api.CredentialBroker_OidcFederation{
					OidcFederation: &api.OIDCFederation{
						TokenEndpoint: "https://sts.googleapis.com/v1/token",
						Audience:      "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sam/providers/cp",
					},
				},
			},
		},
	}
	if err := store.SavePolicyDocument(ctx, roles, bindings, egress); err != nil {
		env.Close()
		return nil, err
	}

	cpSrv, err := controlplane.NewServer(controlplane.Options{
		ListenAddr:            "127.0.0.1:0",
		DriverName:            "sqlite",
		DataSourceName:        dbPath,
		OIDCIssuer:            issuer,
		AllowedAudiences:      []string{"sam-mesh-audience"},
		LeaseDuration:         time.Minute,
		KeyRotationInterval:   12 * time.Hour,
		KeyGracePeriod:        10 * time.Minute,
		InsecureSkipTLSVerify: true,
		BiscuitTimeout:        10 * time.Second,
		STSRateLimit:          100000,
		STSRateBurst:          100000,
	}, store)
	if err != nil {
		env.Close()
		return nil, err
	}
	if err := cpSrv.Start(); err != nil {
		env.Close()
		return nil, err
	}
	env.cpSrv = cpSrv
	rawCPURL := "http://" + cpSrv.Addr()

	// Wrap CP with an observer proxy that counts /token/exchange and /sts/token requests.
	env.cpProxySrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token/exchange":
			env.exchangeCalls.Add(1)
		case "/sts/token":
			env.stsCalls.Add(1)
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, rawCPURL+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := env.httpClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	env.cpURL = env.cpProxySrv.URL

	// Enroll a benchmark SamNode.
	priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		env.Close()
		return nil, err
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		env.Close()
		return nil, err
	}
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		env.Close()
		return nil, err
	}
	nodeJWT, err := env.mintSubjectJWT("bench-node", 1)
	if err != nil {
		env.Close()
		return nil, err
	}
	ts := time.Now().UnixMilli()
	sig, err := priv.Sign(api.RegisterChallenge(pid.String(), ts))
	if err != nil {
		env.Close()
		return nil, err
	}
	enrollBytes, err := proto.Marshal(&api.EnrollRequest{
		Jwt:                nodeJWT,
		PeerId:             pid.String(),
		PublicKey:          pubBytes,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	})
	if err != nil {
		env.Close()
		return nil, err
	}
	resp, err := env.httpClient.Post(env.cpURL+"/register", "application/x-protobuf", bytes.NewReader(enrollBytes))
	if err != nil {
		env.Close()
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		env.Close()
		return nil, fmt.Errorf("enroll failed (%d): %s", resp.StatusCode, string(body))
	}
	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(body, &enrollResp); err != nil {
		env.Close()
		return nil, err
	}
	env.nodePriv = priv
	env.nodePeerID = pid
	env.nodeBiscuit = enrollResp.BiscuitToken

	nodeDir := filepath.Join(tempDir, "node")
	nodeStore, err := node.NewStore(nodeDir)
	if err != nil {
		env.Close()
		return nil, err
	}
	if err := nodeStore.SaveIdentity(env.nodeBiscuit); err != nil {
		env.Close()
		return nil, err
	}
	if err := nodeStore.SaveMeshConfig(enrollResp.ControlPlanePublicKey, nil); err != nil {
		env.Close()
		return nil, err
	}
	if err := nodeStore.SaveControlPlaneURL(env.cpURL); err != nil {
		env.Close()
		return nil, err
	}

	samNode, err := node.NewSamNode(node.Options{
		PrivKey:        priv,
		Store:          nodeStore,
		BiscuitTimeout: 5 * time.Second,
	})
	if err != nil {
		env.Close()
		return nil, err
	}
	env.samNode = samNode
	return env, nil
}

func (e *stsBenchEnv) mintSubjectJWT(sub string, epoch int) (string, error) {
	claims := jwt.MapClaims{
		"iss":   e.oidcSrv.URL,
		"sub":   sub,
		"email": sub + "@example.com",
		"aud":   "sam-mesh-audience",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"jti":   fmt.Sprintf("%s-%d", sub, epoch),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "bench-key"
	return tok.SignedString(e.rsaKey)
}

func (e *stsBenchEnv) precomputeWorkloadTokens(workloads, totalRequests, reqsPerToken int, prefix string) ([][]string, error) {
	if reqsPerToken <= 0 {
		reqsPerToken = 1
	}
	maxEpochs := ((totalRequests/workloads)+1)/reqsPerToken + 2
	out := make([][]string, workloads)
	for w := range workloads {
		out[w] = make([]string, maxEpochs)
		for ep := range maxEpochs {
			tok, err := e.mintSubjectJWT(fmt.Sprintf("%s-workload-%d", prefix, w), ep)
			if err != nil {
				return nil, err
			}
			out[w][ep] = tok
		}
	}
	return out, nil
}

func (e *stsBenchEnv) precomputeTaskBiscuits(workloads, totalRequests, reqsPerTask int) ([][][]byte, error) {
	if reqsPerTask <= 0 {
		reqsPerTask = 1
	}
	maxEpochs := ((totalRequests/workloads)+1)/reqsPerTask + 2
	out := make([][][]byte, workloads)
	for w := range workloads {
		out[w] = make([][]byte, maxEpochs)
		for ep := range maxEpochs {
			tb, err := identity.AttenuateBiscuit(e.nodeBiscuit, &api.TaskAuthorizationRule{
				Name: fmt.Sprintf("tasks/workload-%d-epoch-%d", w, ep),
				Rules: []*api.TaskRule{
					{
						AllowedServices: []string{"egress://bigquery.googleapis.com"},
					},
				},
			})
			if err != nil {
				return nil, err
			}
			out[w][ep] = tb
		}
	}
	return out, nil
}

func (e *stsBenchEnv) Close() {
	if e.cpProxySrv != nil {
		e.cpProxySrv.Close()
	}
	if e.cpSrv != nil {
		_ = e.cpSrv.Close()
	}
	if e.store != nil {
		_ = e.store.Close()
	}
	if e.oidcSrv != nil {
		e.oidcSrv.Close()
	}
	if e.tempDir != "" {
		_ = os.RemoveAll(e.tempDir)
	}
}
