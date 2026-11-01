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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mattn/go-isatty"
	"golang.org/x/oauth2/clientcredentials"
)

// generatePKCE generates a PKCE code verifier and challenge.
func generatePKCE() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

// FetchJWT fetches a JWT token using the Client Credentials flow.
func (n *AgentMeshNode) FetchJWT(ctx context.Context, tokenURL, clientID, clientSecret string) (string, error) {
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}
	token, err := config.Token(ctx)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// AuthMode selects how interactive enrollment authenticates the user.
type AuthMode string

const (
	// AuthModeAuto prefers device flow in headless environments (when the
	// provider advertises one) and the loopback browser flow otherwise, with an
	// automatic device fallback when the browser can't be opened.
	AuthModeAuto AuthMode = "auto"
	// AuthModeDevice forces the OAuth 2.0 Device Authorization Grant (RFC 8628).
	AuthModeDevice AuthMode = "device"
	// AuthModeOOB forces the out-of-band code-paste flow.
	AuthModeOOB AuthMode = "oob"
	// AuthModeBrowser forces the loopback browser (authorization code) flow.
	AuthModeBrowser AuthMode = "browser"
)

// ParseAuthMode validates a user-provided --auth-mode value. An empty string
// maps to AuthModeAuto.
func ParseAuthMode(s string) (AuthMode, error) {
	switch AuthMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", AuthModeAuto:
		return AuthModeAuto, nil
	case AuthModeDevice:
		return AuthModeDevice, nil
	case AuthModeOOB:
		return AuthModeOOB, nil
	case AuthModeBrowser:
		return AuthModeBrowser, nil
	default:
		return "", fmt.Errorf("invalid auth mode %q (want auto, device, oob, or browser)", s)
	}
}

// InteractiveLogin prompts the user to go to a URL and enter a code.
func (n *AgentMeshNode) InteractiveLogin(ctx context.Context, authURL, tokenURL, clientID, audience string, requestRefresh bool, headless bool) (string, error) {
	return n.InteractiveLoginWithDeviceAuth(ctx, authURL, tokenURL, "", clientID, audience, requestRefresh, headless)
}

// InteractiveLoginWithDeviceAuth authenticates using AuthModeAuto: it prefers
// the OAuth Device Authorization Grant in headless mode when the provider
// exposes a device authorization endpoint, and otherwise uses the loopback
// browser flow with a device fallback.
func (n *AgentMeshNode) InteractiveLoginWithDeviceAuth(ctx context.Context, authURL, tokenURL, deviceAuthURL, clientID, audience string, requestRefresh bool, headless bool) (string, error) {
	return n.InteractiveLoginWithMode(ctx, authURL, tokenURL, deviceAuthURL, clientID, audience, requestRefresh, headless, AuthModeAuto)
}

// InteractiveLoginWithMode authenticates the user using an explicit AuthMode,
// letting callers (e.g. CUJ harnesses) force a deterministic flow instead of
// relying on headless environment detection.
func (n *AgentMeshNode) InteractiveLoginWithMode(ctx context.Context, authURL, tokenURL, deviceAuthURL, clientID, audience string, requestRefresh bool, headless bool, mode AuthMode) (string, error) {
	if tokenURL == "" {
		return "", fmt.Errorf("token URL is required")
	}
	if clientID == "" {
		return "", fmt.Errorf("client ID is required")
	}

	isHeadless := headless || os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != ""

	switch mode {
	case AuthModeDevice:
		if deviceAuthURL == "" {
			return "", fmt.Errorf("auth-mode=device requested but the OIDC provider does not advertise a device_authorization_endpoint")
		}
		return n.DeviceLogin(ctx, deviceAuthURL, tokenURL, clientID, audience, requestRefresh)
	case AuthModeOOB:
		// Force out-of-band paste; disable any device fallback.
		isHeadless = true
		deviceAuthURL = ""
	case AuthModeBrowser:
		// Force the loopback browser flow; disable device fallback.
		isHeadless = false
		deviceAuthURL = ""
	case AuthModeAuto:
		if isHeadless && deviceAuthURL != "" {
			logger.Info("Headless mode detected and device authorization endpoint available; using device flow")
			return n.DeviceLogin(ctx, deviceAuthURL, tokenURL, clientID, audience, requestRefresh)
		}
	default:
		return "", fmt.Errorf("invalid auth mode %q", mode)
	}

	if authURL == "" {
		return "", fmt.Errorf("authorization URL is required")
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE: %w", err)
	}

	var redirectURI string
	var listener net.Listener

	if isHeadless {
		if !stdinIsInteractive() {
			logger.Warn("Headless OOB flow requires pasting a code, but stdin is non-interactive and no device endpoint is configured; auth may block")
		}
		redirectURI = "urn:ietf:wg:oauth:2.0:oob"
	} else {
		var err error
		// Try a few known ports to satisfy Dex which doesn't support RFC 8252 dynamic loopback
		// Since Dex strictly matches redirect URIs (Dex Issue #4836), we can't use `localhost:0`.
		// Instead, we try a small set of pre-registered fixed ports.
		for _, p := range []string{"13000", "13001", "13002"} {
			listener, err = net.Listen("tcp", "127.0.0.1:"+p)
			if err == nil {
				break
			}
		}
		if listener == nil {
			if deviceAuthURL != "" {
				logger.Warn("Could not bind local OIDC listener (ports 13000-13002 busy); falling back to device authorization flow.")
				return n.DeviceLogin(ctx, deviceAuthURL, tokenURL, clientID, audience, requestRefresh)
			}
			logger.Warn("Could not bind local OIDC listener (ports 13000-13002 busy). Falling back to headless (OOB) authorization.")
			isHeadless = true
			redirectURI = "urn:ietf:wg:oauth:2.0:oob"
		} else {
			defer func() { _ = listener.Close() }()
			port := listener.Addr().(*net.TCPAddr).Port
			redirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback", port)
		}
	}

	authReq, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth request: %w", err)
	}
	q := authReq.URL.Query()
	q.Add("response_type", "code")
	q.Add("client_id", clientID)
	q.Add("redirect_uri", redirectURI)
	scope := "openid email profile"
	if requestRefresh {
		scope += " offline_access"
		q.Add("access_type", "offline")
		q.Add("prompt", "consent")
	}
	q.Add("scope", scope)
	q.Add("state", state)
	q.Add("code_challenge", challenge)
	q.Add("code_challenge_method", "S256")
	if audience != "" {
		q.Add("audience", audience)
	}
	authReq.URL.RawQuery = q.Encode()
	targetURL := authReq.URL.String()

	// In an interactive (loopback) flow, try to open the browser up front. If it
	// can't be opened, nothing will complete the redirect, so when the provider
	// advertises a device authorization endpoint we fall back to device flow
	// rather than forcing the user (or a CUJ harness) to paste a callback code
	// back. Headless flows open the browser only best-effort (after the banner),
	// since they already print a URL to complete elsewhere.
	if !isHeadless {
		if err := openBrowserFunc(targetURL); err != nil {
			if deviceAuthURL != "" {
				logger.Warnf("Could not open a browser (%v); falling back to device authorization flow.", err)
				return n.DeviceLogin(ctx, deviceAuthURL, tokenURL, clientID, audience, requestRefresh)
			}
			logger.Warnf("Could not open a browser (%v); open the URL below manually or paste the callback code.", err)
		}
	}

	fmt.Println("------------------------------------------------------------")
	fmt.Println("OAuth Authorization Flow")
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("To authenticate, please go to the following URL in your browser:\n\n")
	fmt.Printf("  %s\n\n", targetURL)
	if isHeadless {
		fmt.Println("After authorizing, paste the authorization code below:")
	} else {
		fmt.Println("Waiting for authorization... (If your browser fails, you can paste the callback URL or code here)")
	}
	fmt.Println("------------------------------------------------------------")

	if isHeadless {
		// Best-effort: some headless setups still have a usable browser.
		_ = openBrowserFunc(targetURL)
	}

	loginCtx, loginCancel := context.WithCancel(ctx)
	defer loginCancel()

	codeChan := make(chan string)
	errChan := make(chan error)

	var srv *http.Server
	if !isHeadless {
		mux := http.NewServeMux()
		mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			if query.Get("state") != state {
				http.Error(w, "Invalid state parameter", http.StatusBadRequest)
				select {
				case errChan <- fmt.Errorf("invalid state parameter received"):
				case <-loginCtx.Done():
				}
				return
			}
			if errStr := query.Get("error"); errStr != "" {
				desc := query.Get("error_description")
				http.Error(w, "Authorization failed: "+errStr, http.StatusBadRequest)
				select {
				case errChan <- fmt.Errorf("authorization failed: %s - %s", errStr, desc):
				case <-loginCtx.Done():
				}
				return
			}
			code := query.Get("code")
			if code == "" {
				http.Error(w, "No code in request", http.StatusBadRequest)
				select {
				case errChan <- fmt.Errorf("no code received"):
				case <-loginCtx.Done():
				}
				return
			}

			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>Authorization successful!</h1><p>You can close this window and return to the CLI.</p></body></html>"))

			select {
			case codeChan <- code:
			case <-loginCtx.Done():
			}
		})

		srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
				select {
				case errChan <- fmt.Errorf("local server error: %w", err):
				case <-loginCtx.Done():
				}
			}
		}()
	}

	// Also allow manual code entry via stdin
	go func() {
		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			return
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return
		}
		if parsed, err := url.Parse(input); err == nil && parsed.Query().Get("code") != "" {
			input = parsed.Query().Get("code")
		}
		select {
		case codeChan <- input:
		case <-loginCtx.Done():
		}
	}()

	shutdownSrv := func() {
		if srv != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(shutdownCtx)
			cancel()
		}
	}

	var code string
	select {
	case <-ctx.Done():
		shutdownSrv()
		return "", ctx.Err()
	case err := <-errChan:
		shutdownSrv()
		return "", err
	case code = <-codeChan:
		shutdownSrv()
	}

	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("client_id", clientID)
	tokenData.Set("code", code)
	tokenData.Set("redirect_uri", redirectURI)
	tokenData.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	jwt, refreshToken, err := parseTokenResponse(resp)
	if err != nil {
		return "", err
	}
	if refreshToken != "" && n.Store != nil {
		if err := n.Store.SaveRefreshToken(refreshToken); err != nil {
			logger.Warnf("Failed to save refresh token: %v", err)
		}
	}
	return jwt, nil
}

func stdinIsInteractive() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// bodySnippet renders a response body for error messages, bounded so a
// misbehaving server can't flood logs.
func bodySnippet(body []byte) string {
	if len(body) > 256 {
		return strings.TrimSpace(string(body[:256])) + "..."
	}
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "(empty response body)"
	}
	return s
}

// DeviceLogin performs OAuth 2.0 Device Authorization Grant (RFC 8628).
func (n *AgentMeshNode) DeviceLogin(ctx context.Context, deviceAuthURL, tokenURL, clientID, audience string, requestRefresh bool) (string, error) {
	if deviceAuthURL == "" {
		return "", fmt.Errorf("device authorization URL is required")
	}
	if tokenURL == "" {
		return "", fmt.Errorf("token URL is required")
	}
	if clientID == "" {
		return "", fmt.Errorf("client ID is required")
	}

	deviceData := url.Values{}
	deviceData.Set("client_id", clientID)
	scope := "openid email profile"
	if requestRefresh {
		scope += " offline_access"
	}
	deviceData.Set("scope", scope)
	if audience != "" {
		deviceData.Set("audience", audience)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", deviceAuthURL, strings.NewReader(deviceData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create device authorization request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("device authorization request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxControlPlaneBodyBytes)).Decode(&errResp)
		return "", fmt.Errorf("device authorization failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var deviceResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
		Message                 string `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxControlPlaneBodyBytes)).Decode(&deviceResp); err != nil {
		return "", fmt.Errorf("failed to decode device authorization response: %w", err)
	}
	if deviceResp.DeviceCode == "" {
		return "", fmt.Errorf("device authorization response missing device_code")
	}

	verificationURL := deviceResp.VerificationURI
	if deviceResp.VerificationURIComplete != "" {
		verificationURL = deviceResp.VerificationURIComplete
	}

	fmt.Println("------------------------------------------------------------")
	fmt.Println("OAuth Device Authorization Flow")
	fmt.Println("------------------------------------------------------------")
	if deviceResp.Message != "" {
		fmt.Println(deviceResp.Message)
		fmt.Println()
	} else {
		if verificationURL != "" {
			fmt.Printf("Open this URL in a browser:\n\n  %s\n\n", verificationURL)
		}
		if deviceResp.UserCode != "" {
			fmt.Printf("Enter code: %s\n\n", deviceResp.UserCode)
		}
	}
	fmt.Println("Waiting for authorization...")
	fmt.Println("------------------------------------------------------------")

	pollInterval := 5 * time.Second
	if deviceResp.Interval > 0 {
		pollInterval = time.Duration(deviceResp.Interval) * time.Second
	}
	var expiresAt time.Time
	if deviceResp.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		if !expiresAt.IsZero() && time.Now().After(expiresAt) {
			return "", fmt.Errorf("device authorization expired before completion")
		}

		tokenData := url.Values{}
		tokenData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		tokenData.Set("device_code", deviceResp.DeviceCode)
		tokenData.Set("client_id", clientID)

		tokenReq, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(tokenData.Encode()))
		if err != nil {
			return "", fmt.Errorf("failed to create token polling request: %w", err)
		}
		tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		tokenResp, err := client.Do(tokenReq)
		if err != nil {
			// Transient network errors shouldn't abort the whole device flow: log
			// and keep polling until the context is cancelled or the code expires.
			logger.Warnf("Token polling request failed: %v. Retrying in %v...", err, pollInterval)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(pollInterval):
			}
			continue
		}

		// Cap the read: the poll target comes from discovery and a misbehaving
		// server must not be able to exhaust memory.
		body, readErr := io.ReadAll(io.LimitReader(tokenResp.Body, 1<<20))
		if closeErr := tokenResp.Body.Close(); closeErr != nil {
			logger.Errorf("Failed to close response body: %v", closeErr)
		}
		if readErr != nil {
			return "", fmt.Errorf("failed to read token polling response: %w", readErr)
		}

		if tokenResp.StatusCode == http.StatusOK {
			var tokenData struct {
				AccessToken  string `json:"access_token"`
				IdToken      string `json:"id_token"`
				RefreshToken string `json:"refresh_token"`
			}
			if err := json.Unmarshal(body, &tokenData); err != nil {
				return "", fmt.Errorf("failed to decode token response: %w", err)
			}
			jwt := tokenData.AccessToken
			if tokenData.IdToken != "" {
				jwt = tokenData.IdToken
			}
			if jwt == "" {
				return "", fmt.Errorf("token response did not contain an access_token or id_token")
			}
			if tokenData.RefreshToken != "" && n.Store != nil {
				if saveErr := n.Store.SaveRefreshToken(tokenData.RefreshToken); saveErr != nil {
					logger.Warnf("Failed to save refresh token: %v", saveErr)
				}
			}
			return jwt, nil
		}

		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		// Best-effort: non-JSON bodies (proxy HTML, empty) leave Error empty
		// and are reported raw via bodySnippet below.
		_ = json.Unmarshal(body, &errResp)
		pending := errResp.Error == "authorization_pending" || errResp.Error == "slow_down"

		// RFC 8628 §3.5 delivers polling errors as HTTP 400 with an OAuth error
		// body. Known exception: dex returns the pending/slow_down signals with
		// HTTP 401. Anything else is a real failure and is surfaced verbatim.
		rfcError := tokenResp.StatusCode == http.StatusBadRequest && errResp.Error != ""
		dexPending := tokenResp.StatusCode == http.StatusUnauthorized && pending
		if !rfcError && !dexPending {
			if errResp.Error != "" {
				msg := errResp.Error
				if errResp.ErrorDescription != "" {
					msg += " - " + errResp.ErrorDescription
				}
				return "", fmt.Errorf("token request failed with status %s: %s", tokenResp.Status, msg)
			}
			return "", fmt.Errorf("token request failed with status %s: %s", tokenResp.Status, bodySnippet(body))
		}

		switch errResp.Error {
		case "authorization_pending":
			// keep polling
		case "slow_down":
			pollInterval += 5 * time.Second
		case "access_denied":
			return "", fmt.Errorf("device authorization denied by user")
		case "expired_token":
			return "", fmt.Errorf("device authorization expired")
		default:
			return "", fmt.Errorf("device token polling failed: %s - %s", errResp.Error, errResp.ErrorDescription)
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func parseTokenResponse(resp *http.Response) (jwt string, refreshToken string, err error) {
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Errorf("Failed to close response body: %v", closeErr)
		}
	}()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxControlPlaneBodyBytes))
	if readErr != nil {
		return "", "", readErr
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if unmarshalErr := json.Unmarshal(body, &errResp); unmarshalErr == nil && errResp.Error != "" {
			return "", "", fmt.Errorf("token request failed: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return "", "", fmt.Errorf("token request failed with status: %s", resp.Status)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IdToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", "", err
	}

	jwt = tokenResp.AccessToken
	if tokenResp.IdToken != "" {
		jwt = tokenResp.IdToken
	}
	if jwt == "" {
		return "", "", fmt.Errorf("token response did not contain an access_token or id_token")
	}
	return jwt, tokenResp.RefreshToken, nil
}

// oidcDiscoveryTimeout bounds a single OIDC discovery HTTP call so an
// unresponsive issuer can't hang "join"/"run --join" indefinitely. A var
// (not const) so tests can shrink it instead of waiting out the real value.
var oidcDiscoveryTimeout = 10 * time.Second

// DiscoverTokenURL discovers the token URL from the OIDC issuer.
func (n *AgentMeshNode) DiscoverTokenURL(ctx context.Context, issuerURL string) (string, error) {
	client := &http.Client{Timeout: oidcDiscoveryTimeout}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	var claims struct {
		TokenURL string `json:"token_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return "", fmt.Errorf("failed to extract claims: %w", err)
	}
	if claims.TokenURL == "" {
		return "", fmt.Errorf("token_endpoint not found in discovery document")
	}
	return claims.TokenURL, nil
}

// DiscoverEndpoints discovers both token and authorization endpoints.
func (n *AgentMeshNode) DiscoverEndpoints(ctx context.Context, issuerURL string) (tokenURL, authURL string, err error) {
	endpoints, err := n.DiscoverEndpointsWithDevice(ctx, issuerURL)
	if err != nil {
		return "", "", err
	}
	return endpoints.TokenURL, endpoints.AuthURL, nil
}

// OIDCEndpoints contains discovered OIDC endpoint URLs.
type OIDCEndpoints struct {
	TokenURL      string
	AuthURL       string
	DeviceAuthURL string
}

// DiscoverEndpointsWithDevice discovers token, authorization and device authorization endpoints.
func (n *AgentMeshNode) DiscoverEndpointsWithDevice(ctx context.Context, issuerURL string) (*OIDCEndpoints, error) {
	client := &http.Client{Timeout: oidcDiscoveryTimeout}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	var claims struct {
		TokenURL      string `json:"token_endpoint"`
		AuthURL       string `json:"authorization_endpoint"`
		DeviceAuthURL string `json:"device_authorization_endpoint"`
	}
	if err := provider.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}
	return &OIDCEndpoints{
		TokenURL:      claims.TokenURL,
		AuthURL:       claims.AuthURL,
		DeviceAuthURL: claims.DeviceAuthURL,
	}, nil
}

var openBrowserFunc = openBrowser

func openBrowser(targetURL string) error {
	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return fmt.Errorf("invalid or unsafe URL scheme %q", targetURL)
	}
	var cmdErr error
	switch runtime.GOOS {
	case "linux":
		cmdErr = exec.Command("xdg-open", targetURL).Start()
	case "darwin":
		cmdErr = exec.Command("open", targetURL).Start()
	case "windows":
		cmdErr = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start()
	default:
		cmdErr = fmt.Errorf("unsupported platform")
	}
	if cmdErr != nil {
		logger.Debugf("Failed to open browser: %v", cmdErr)
		return cmdErr
	}
	return nil
}

// RefreshJWT refreshes the OIDC token using the stored refresh token.
func (n *AgentMeshNode) RefreshJWT(ctx context.Context, tokenURL, clientID, clientSecret, refreshToken string) (string, string, error) {
	tokenData := url.Values{}
	tokenData.Set("grant_type", "refresh_token")
	tokenData.Set("client_id", clientID)
	tokenData.Set("refresh_token", refreshToken)
	if clientSecret != "" {
		tokenData.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxControlPlaneBodyBytes)).Decode(&errResp); err == nil && errResp.Error != "" {
			return "", "", fmt.Errorf("refresh token request failed (status %s): %s - %s", resp.Status, errResp.Error, errResp.ErrorDescription)
		}
		return "", "", fmt.Errorf("refresh token request failed with status: %s", resp.Status)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IdToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxControlPlaneBodyBytes)).Decode(&tokenResp); err != nil {
		return "", "", err
	}

	jwtStr := tokenResp.AccessToken
	if tokenResp.IdToken != "" {
		jwtStr = tokenResp.IdToken
	}
	if jwtStr == "" {
		return "", "", fmt.Errorf("token response did not contain an access_token or id_token")
	}
	return jwtStr, tokenResp.RefreshToken, nil
}
