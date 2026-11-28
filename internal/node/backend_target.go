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
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// backendTarget is a service's target_url split into the address the node
// dials and the credential it presents there. A target_url may carry that
// credential as URL userinfo: "http://:token@host" sends "Bearer token",
// "http://user:pass@host" sends HTTP Basic. Nothing else in the node sees
// the userinfo: it is not advertised, logged or forwarded to callers.
type backendTarget struct {
	url  *url.URL // userinfo stripped
	auth string   // Authorization header value, or ""
}

func parseBackendTarget(raw string) (backendTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// Not %w: url.Error prints the raw URL, userinfo included.
		return backendTarget{}, errors.New("invalid target URL")
	}
	t := backendTarget{url: u}
	if u.User == nil {
		return t, nil
	}
	pass, _ := u.User.Password()
	t.auth = authorizationFor(u.User.Username(), pass)
	clean := *u
	clean.User = nil
	t.url = &clean
	return t, nil
}

// authorizationFor turns decoded userinfo into an Authorization header value:
// a password with no user is a bearer token, user and password are Basic.
func authorizationFor(user, pass string) string {
	if user == "" {
		return "Bearer " + pass
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// rejectInlineBackendCredential refuses a credential written into a config
// file's target_url; target_auth_path is the channel for that. Userinfo is
// still honoured on the wire (parseBackendTarget) so an in-process caller,
// e.g. the mobile app, can pass a per-launch token without ever writing it.
func rejectInlineBackendCredential(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid target_url")
	}
	if u.User != nil {
		return errors.New("target_url must not carry a credential; put it in a file and set target_auth_path")
	}
	return nil
}

// withBackendAuthFile composes the in-memory target URL for a service whose
// credential lives in a file: the file's content becomes the URL userinfo,
// which parseBackendTarget turns into the Authorization header and strips
// before dialling. The credential never returns to disk or to any log.
func withBackendAuthFile(targetURL, authPath string) (string, error) {
	data, err := os.ReadFile(authPath)
	if err != nil {
		return "", fmt.Errorf("read target_auth_path: %w", err)
	}
	cred := strings.TrimSpace(string(data))
	if cred == "" {
		return "", fmt.Errorf("target_auth_path %s is empty", authPath)
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", errors.New("invalid target_url")
	}
	if user, pass, ok := strings.Cut(cred, ":"); ok {
		u.User = url.UserPassword(user, pass)
	} else {
		u.User = url.UserPassword("", cred)
	}
	return u.String(), nil
}

// apply sets the backend credential on an outbound request. The operator's
// configured credential wins over anything a caller sent: the caller's
// Authorization was for the node, this one is the node's for the backend.
func (t backendTarget) apply(h http.Header) {
	if t.auth != "" {
		h.Set("Authorization", t.auth)
	}
}

// client returns an HTTP client that presents the backend credential on
// every request, for backends dialled through an SDK rather than a proxy.
func (t backendTarget) client() *http.Client {
	return t.clientWithHeaders(nil)
}

// clientWithHeaders returns an HTTP client that presents extra headers (e.g. verified identity headers)
// and the backend credential on every outbound request.
func (t backendTarget) clientWithHeaders(extraHeaders http.Header) *http.Client {
	if len(extraHeaders) == 0 && t.auth == "" {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: mcpHeaderTransport{
			target:  t,
			headers: extraHeaders.Clone(),
			base:    http.DefaultTransport,
		},
	}
}

type mcpHeaderTransport struct {
	target  backendTarget
	headers http.Header
	base    http.RoundTripper
}

func (m mcpHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	stripMeshIdentityHeaders(req.Header)
	for k, vv := range m.headers {
		req.Header[k] = vv
	}
	m.target.apply(req.Header)
	base := m.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
