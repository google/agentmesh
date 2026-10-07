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

package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/version"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
)

type Config struct {
	ControlPlaneURL string
	AdminToken      string
	// StaticDir serves frontend assets from disk (live-editable, used by the
	// ui-dev workflow). It takes precedence over StaticFS.
	StaticDir string
	// StaticFS serves frontend assets from an fs.FS, e.g. EmbeddedAssets().
	StaticFS fs.FS
	BasePath string

	// ExternalURL is the origin browsers reach this console on, e.g.
	// "https://console.example". When set it decides the OIDC redirect_uri and
	// whether session cookies are marked Secure, instead of the Host and
	// X-Forwarded-Proto headers, which a client controls and a proxy may drop.
	ExternalURL string
}

// NormalizeBasePath makes a base-path flag value safe to concatenate: no trailing
// slash (else cookie paths become /console//) and a guaranteed leading slash.
func NormalizeBasePath(p string) string {
	if p == "" {
		return ""
	}
	p = path.Clean("/" + p)
	if p == "/" {
		return ""
	}
	return p
}

// origin returns the scheme and host to build absolute URLs with.
//
// A configured ExternalURL wins. Falling back to the request means trusting
// Host and X-Forwarded-Proto, which the client sets: a proxy that terminates
// TLS but drops the header leaves session cookies without Secure, and the
// redirect_uri is only kept honest by the provider's own exact-match list.
func (s *Server) origin(r *http.Request) (scheme, host string) {
	if s.external != nil {
		return s.external.Scheme, s.external.Host
	}
	scheme = "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme, r.Host
}

// redirectURI is the OIDC callback this console is reachable at. It must match
// byte for byte between the authorization request and the token exchange.
func (s *Server) redirectURI(r *http.Request) string {
	scheme, host := s.origin(r)
	return fmt.Sprintf("%s://%s%s/auth/callback", scheme, host, s.cfg.BasePath)
}

// secureCookies reports whether session cookies may carry the Secure attribute.
func (s *Server) secureCookies(r *http.Request) bool {
	scheme, _ := s.origin(r)
	return scheme == "https"
}

type Server struct {
	cfg      Config
	mux      *http.ServeMux
	provider *oidc.Provider
	clientID string
	// external is the parsed Config.ExternalURL, nil when unset.
	external *url.URL
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.ControlPlaneURL == "" {
		return nil, fmt.Errorf("ControlPlaneURL is required")
	}

	var assets fs.FS
	switch {
	case cfg.StaticDir != "":
		assets = os.DirFS(cfg.StaticDir)
	case cfg.StaticFS != nil:
		assets = cfg.StaticFS
	default:
		return nil, fmt.Errorf("static assets are required: set StaticDir or StaticFS")
	}

	controlPlaneURL, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ControlPlaneURL: %w", err)
	}

	var external *url.URL
	if cfg.ExternalURL != "" {
		// Fail at startup: a redirect_uri built from a malformed value would be
		// rejected by the provider on every login instead.
		u, err := url.Parse(cfg.ExternalURL)
		if err != nil {
			return nil, fmt.Errorf("invalid ExternalURL: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("invalid ExternalURL %q: scheme must be http or https", cfg.ExternalURL)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("invalid ExternalURL %q: missing host", cfg.ExternalURL)
		}
		external = u
	}

	var provider *oidc.Provider
	var clientID string

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(cfg.ControlPlaneURL + "/info")
	if err != nil {
		return nil, fmt.Errorf("failed to query control-plane info for OIDC discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read control-plane info body: %w", err)
		}
		var info api.ControlPlaneInfoResponse
		if err := proto.Unmarshal(body, &info); err != nil {
			return nil, fmt.Errorf("failed to unmarshal control plane info: %w", err)
		}

		if info.OidcIssuer != "" && info.ClientId != "" {
			// Bound the discovery client so an unresponsive issuer can't hang startup.
			oidcClient := &http.Client{Timeout: 10 * time.Second}
			discoveryCtx := oidc.ClientContext(context.Background(), oidcClient)
			provider, err = discoverProviderWithRetry(discoveryCtx, info.OidcIssuer, oidcDiscoveryMaxAttempts, oidcDiscoveryBaseDelay, oidcDiscoveryMaxDelay)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed OIDC discovery on %s: %v\n", info.OidcIssuer, err)
			} else if provider.Endpoint().AuthURL != "" && provider.Endpoint().TokenURL != "" {
				clientID = info.ClientId
			} else {
				fmt.Fprintf(os.Stderr, "Info: discovered issuer %s does not support authorization flow (M2M only)\n", info.OidcIssuer)
				provider = nil // Disable console interactive endpoints
			}
		}
	}

	s := &Server{
		cfg:      cfg,
		mux:      http.NewServeMux(),
		provider: provider,
		clientID: clientID,
		external: external,
	}
	// Create reverse proxy to the control plane
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(controlPlaneURL)
			r.Out.Host = r.In.Host
			// If Authorization header is not set, inject from sam_session cookie
			if r.Out.Header.Get("Authorization") == "" {
				if cookie, err := r.In.Cookie("sam_session"); err == nil && cookie.Value != "" {
					r.Out.Header.Set("Authorization", "Bearer "+cookie.Value)
				}
			}
		},
	}

	routes := http.NewServeMux()

	// Proxy all API requests to the control plane, guarding cookie-backed
	// state-mutating calls against cross-origin form submissions (CSRF).
	apiProxy := http.StripPrefix("/api", proxy)
	routes.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if !s.checkCookieCSRF(w, r) {
			return
		}
		apiProxy.ServeHTTP(w, r)
	})

	// Serve static files
	fileServer := http.FileServerFS(assets)
	routes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "."
		}
		if name == "." || name == "index.html" {
			serveIndex(w, r, assets)
			return
		}
		if _, err := fs.Stat(assets, name); err != nil {
			// SPA fallback: return index.html for unknown paths (useful for flutter/react router)
			serveIndex(w, r, assets)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	// OIDC login endpoints
	if s.provider != nil {
		routes.HandleFunc("/auth/login", s.HandleLogin)
		routes.HandleFunc("/auth/callback", s.HandleCallback)
		routes.HandleFunc("/auth/session", s.HandleSession)
	}
	routes.HandleFunc("/auth/logout", s.HandleLogout)
	// Available without OIDC: the admin bearer token uses the same exchange.
	routes.HandleFunc("/auth/token", s.HandleTokenLogin)
	routes.HandleFunc("/info", s.HandleInfo)

	// Serve under BasePath too, so the links this server emits resolve without the proxy
	// stripping the prefix. Still served at the root for proxies that do strip it.
	if s.cfg.BasePath != "" {
		s.mux.Handle(s.cfg.BasePath+"/", http.StripPrefix(s.cfg.BasePath, routes))
	}
	s.mux.Handle("/", routes)

	return s, nil
}

// checkCookieCSRF blocks cross-site state-mutating requests to /api/* that rely
// on the ambient sam_session cookie rather than an explicit Authorization header.
func (s *Server) checkCookieCSRF(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if r.Header.Get("Authorization") != "" {
		return true
	}
	if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" && sfs != "same-origin" && sfs != "none" {
		http.Error(w, "cross-origin cookie request rejected", http.StatusForbidden)
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		_, expectedHost := s.origin(r)
		if err != nil || u.Host == "" || !strings.EqualFold(u.Host, expectedHost) {
			http.Error(w, "cross-origin cookie request rejected", http.StatusForbidden)
			return false
		}
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct == "application/x-www-form-urlencoded" || ct == "multipart/form-data" || ct == "text/plain" {
		http.Error(w, "HTML form content types are not accepted on /api/*", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

// Defaults for discoverProviderWithRetry; matches sam-control-plane's
// discoverProviders so a transient hiccup during rollout (e.g. Dex still
// starting up) doesn't permanently disable console OIDC login, since the
// console's /info reports healthy either way and Kubernetes won't restart it.
const (
	oidcDiscoveryMaxAttempts = 5
	oidcDiscoveryBaseDelay   = 1 * time.Second
	oidcDiscoveryMaxDelay    = 8 * time.Second
)

// discoverProviderWithRetry retries OIDC discovery with exponential backoff so a
// transient upstream hiccup (e.g. the identity provider mid-rollout) doesn't
// permanently disable the console's OIDC login endpoints.
func discoverProviderWithRetry(ctx context.Context, issuer string, maxAttempts int, baseDelay, maxDelay time.Duration) (*oidc.Provider, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if delay > maxDelay {
				delay = maxDelay
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		provider, err := oidc.NewProvider(ctx, issuer)
		if err == nil {
			return provider, nil
		}
		lastErr = err
		fmt.Fprintf(os.Stderr, "Warning: OIDC discovery attempt %d/%d for %s failed: %v\n", attempt+1, maxAttempts, issuer, err)
	}
	return nil, lastErr
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sam_session",
		Value:    "",
		Path:     s.cfg.BasePath + "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	redirectURI := s.redirectURI(r)

	verifier, challenge, err := generatePKCE()
	if err != nil {
		http.Error(w, "Failed to generate PKCE components", http.StatusInternalServerError)
		return
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "Internal state generator error", http.StatusInternalServerError)
		return
	}
	state := fmt.Sprintf("%x", stateBytes)

	http.SetCookie(w, &http.Cookie{
		Name:     "sam_oidc_state",
		Value:    state,
		Path:     s.cfg.BasePath + "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sam_oidc_verifier",
		Value:    verifier,
		Path:     s.cfg.BasePath + "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteLaxMode,
	})

	oauth2Config := &oauth2.Config{
		ClientID:    s.clientID,
		Endpoint:    s.provider.Endpoint(),
		RedirectURL: redirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	authURL := oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("sam_oidc_state")
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state (CSRF verification failed)", http.StatusBadRequest)
		return
	}

	verifierCookie, err := r.Cookie("sam_oidc_verifier")
	if err != nil || verifierCookie.Value == "" {
		http.Error(w, "Missing verifier cookie", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "sam_oidc_state", Value: "", Path: s.cfg.BasePath + "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies(r), SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "sam_oidc_verifier", Value: "", Path: s.cfg.BasePath + "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies(r), SameSite: http.SameSiteLaxMode})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	// Must match the value sent in HandleLogin byte for byte.
	redirectURI := s.redirectURI(r)

	oauth2Config := &oauth2.Config{
		ClientID:    s.clientID,
		Endpoint:    s.provider.Endpoint(),
		RedirectURL: redirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	exchangeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	oauth2Token, err := oauth2Config.Exchange(exchangeCtx, code,
		oauth2.SetAuthURLParam("code_verifier", verifierCookie.Value),
	)
	if err != nil {
		http.Error(w, "Failed to exchange auth code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "No id_token field in OAuth2 token response", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "sam_session",
		Value:    rawIDToken,
		Path:     s.cfg.BasePath + "/",
		MaxAge:   24 * 3600,
		HttpOnly: true,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
}

// HandleSession reports whether a session cookie is present. It deliberately
// does not return the cookie's value: the credential is stored HttpOnly so an
// XSS in the console cannot exfiltrate mesh admin rights, and handing the raw
// token back to any same-origin fetch would undo exactly that. The SPA never
// needs it, since the reverse proxy injects the cookie as Authorization for
// /api/ calls.
func (s *Server) HandleSession(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("sam_session")
	if err != nil || sessionCookie.Value == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "No active session"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]bool{
		"authenticated": true,
	})
}

func (s *Server) HandleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"oidc_enabled": s.provider != nil,
	})
}

// maxTokenLoginBody bounds the login body; a JWT with generous claims stays well
// under this, and cookies larger than this would be dropped by browsers anyway.
const maxTokenLoginBody = 16 << 10

// HandleTokenLogin exchanges a token the operator pasted into the console for an
// httpOnly session cookie, so the credential is never reachable from JavaScript
// and an XSS in the console cannot exfiltrate mesh admin rights.
func (s *Server) HandleTokenLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// An HTML form cannot produce this content type, so a cross-origin POST is
	// forced through a CORS preflight this server never approves. Blocks an
	// attacker from planting their own session cookie in a victim's browser.
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		http.Error(w, "expected Content-Type: application/json", http.StatusUnsupportedMediaType)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxTokenLoginBody)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	token := strings.TrimSpace(req.Token)
	// Operators routinely paste the whole "Bearer <token>" header value.
	if fields := strings.Fields(token); len(fields) > 0 && strings.EqualFold(fields[0], "bearer") {
		token = strings.Join(fields[1:], " ")
	}
	if token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}
	// net/http silently drops a cookie whose value needs quoting, which would
	// fail as a confusing 401 later. Reject it here instead.
	if !isValidCookieValue(token) {
		http.Error(w, "token contains characters that are not valid in a cookie", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "sam_session",
		Value:    token,
		Path:     s.cfg.BasePath + "/",
		MaxAge:   24 * 3600,
		HttpOnly: true,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// isValidCookieValue reports whether v can be sent verbatim as a cookie value,
// per the cookie-octet rule in RFC 6265 section 4.1.1.
func isValidCookieValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == ',' || c == ';' || c == '\\' {
			return false
		}
	}
	return true
}

func generatePKCE() (string, string, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

// versionPlaceholder in index.html is replaced with the build version on every page load.
const versionPlaceholder = "__SAM_VERSION__"

// serveIndex reads index.html per request so a StaticDir stays live-editable.
func serveIndex(w http.ResponseWriter, r *http.Request, assets fs.FS) {
	page, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	page = bytes.ReplaceAll(page, []byte(versionPlaceholder), []byte(html.EscapeString(version.String())))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}
