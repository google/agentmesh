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

// demo-server runs local loopback services for the device-posture and
// workload-isolation example:
//  1. A primary RS256 OIDC Identity Provider (--idp-addr) emitting signed JWTs
//     carrying device posture, amr, and workload environment claims.
//  2. A secondary partner RS256 OIDC IdP (--partner-idp-addr) to demonstrate
//     cross-issuer protection via "iss" matching in PolicyBinding.claims.
//  3. A loopback workstation A2A agent backend (--agent-addr) reporting the
//     verified X-Mesh-* provenance headers it received.
//  4. A loopback approved external API backend (--api-addr, target of
//     egress://api.tools.example) reporting credential injection and forwarded
//     caller context.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	idpAddr := flag.String("idp-addr", "127.0.0.1:18881", "Loopback address for the primary corporate OIDC IdP")
	partnerIdpAddr := flag.String("partner-idp-addr", "127.0.0.1:18884", "Loopback address for the secondary partner OIDC IdP")
	agentAddr := flag.String("agent-addr", "127.0.0.1:18882", "Loopback address for the workstation A2A agent backend")
	apiAddr := flag.String("api-addr", "127.0.0.1:18883", "Loopback address for the approved external tool API")
	expectedSecret := flag.String("expected-secret", "demo-tools-api-secret", "Expected bearer credential injected by the egress gateway")
	flag.Parse()

	corpMux := newMockOIDCHandler("http://"+*idpAddr, "corp-idp-key-1")
	partnerMux := newMockOIDCHandler("http://"+*partnerIdpAddr, "partner-idp-key-1")

	agentMux := http.NewServeMux()
	agentMux.HandleFunc("/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":        "dev-agent",
			"description": "Loopback workstation coding agent with posture enforcement",
			"version":     "1.0.0",
			"supportedInterfaces": []map[string]any{
				{
					"url":             "http://" + *agentAddr + "/tasks/run",
					"protocolBinding": "HTTP+JSON",
					"protocolVersion": "1.0",
				},
			},
		})
	})
	agentMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"backend":    "workstation-dev-agent",
			"mode":       "safe-sandboxed-only",
			"method":     r.Method,
			"path":       r.URL.Path,
			"provenance": collectMeshHeaders(r.Header),
		})
	})

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authOK := r.Header.Get("Authorization") == "Bearer "+*expectedSecret
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"backend":             "approved-tools-api",
			"path":                r.URL.Path,
			"credential_injected": authOK,
			"forwarded_context":   collectMeshHeaders(r.Header),
		})
	})

	servers := []*http.Server{
		{Addr: *idpAddr, Handler: corpMux, ReadHeaderTimeout: 5 * time.Second},
		{Addr: *partnerIdpAddr, Handler: partnerMux, ReadHeaderTimeout: 5 * time.Second},
		{Addr: *agentAddr, Handler: agentMux, ReadHeaderTimeout: 5 * time.Second},
		{Addr: *apiAddr, Handler: apiMux, ReadHeaderTimeout: 5 * time.Second},
	}

	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func(srv *http.Server) {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("%s: %w", srv.Addr, err)
			}
		}(s)
	}
	log.Printf("demo-server listening: idp=http://%s partner=http://%s agent=http://%s api=http://%s", *idpAddr, *partnerIdpAddr, *agentAddr, *apiAddr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		log.Fatalf("server error: %v", err)
	case <-sigCh:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
}

func newMockOIDCHandler(issuer, kid string) http.Handler {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate rsa key: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"jwks_uri":               issuer + "/jwks",
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": kid,
					"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				},
			},
		})
	})
	mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
		profile := r.URL.Query().Get("profile")
		claims, ok := profileClaims(profile, issuer)
		if !ok {
			http.Error(w, fmt.Sprintf("unknown profile %q", profile), http.StatusBadRequest)
			return
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		signed, err := tok.SignedString(privKey)
		if err != nil {
			http.Error(w, "failed to sign token", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(signed))
	})
	return mux
}

func profileClaims(profile, issuer string) (jwt.MapClaims, bool) {
	now := time.Now()
	base := func(sub, email string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss":            issuer,
			"aud":            "agentmesh-audience",
			"sub":            sub,
			"email":          email,
			"email_verified": true,
			"iat":            now.Unix(),
			"exp":            now.Add(time.Hour).Unix(),
		}
	}
	switch profile {
	case "workstation":
		c := base("alice", "alice@corp.example")
		c["amr"] = []any{"hwk", "mfa"}
		c["device"] = map[string]any{
			"trust_tier": "high",
			"type":       "managed_workstation",
		}
		c["workload"] = map[string]any{"env": "workstation"}
		return c, true
	case "gateway":
		c := base("egress-gateway", "egress-gateway@bots.workloads.corp.example")
		c["workload"] = map[string]any{"env": "gateway"}
		return c, true
	case "mobile-managed":
		c := base("alice", "alice@corp.example")
		c["amr"] = []any{"hwk", "mfa"}
		c["device"] = map[string]any{
			"trust_tier": "high",
			"type":       "managed_mobile",
			"management": "fully_managed",
		}
		return c, true
	case "mobile-work-profile":
		c := base("alice", "alice@corp.example")
		c["device"] = map[string]any{
			"trust_tier": "high",
			"type":       "managed_mobile",
			"management": "work_profile",
		}
		return c, true
	case "mobile-unmanaged":
		c := base("alice", "alice@corp.example")
		c["device"] = map[string]any{
			"trust_tier": "basic",
			"type":       "unmanaged_mobile",
		}
		return c, true
	case "sandbox":
		c := base("bot-alice", "bot-alice@bots.workloads.corp.example")
		c["workload"] = map[string]any{"env": "sandbox"}
		return c, true
	default:
		return nil, false
	}
}

func collectMeshHeaders(h http.Header) map[string]string {
	keys := []string{
		"X-Mesh-Principal",
		"X-Mesh-Roles",
		"X-Mesh-Claims",
		"X-Mesh-Labels",
		"X-Mesh-Actor-Node",
		"X-Mesh-Origin",
		"X-Mesh-Task",
		"X-Mesh-Task-Id",
		"X-Mesh-Spoofed",
		"X-Peer-Id",
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}
