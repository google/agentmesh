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

// Package webapp serves Agent Mesh Connect, the web app that puts a browser on the mesh.
package webapp

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/google/agentmesh/internal/version"
)

//go:embed all:public
var embedded embed.FS

var bundleFiles = []string{"sdk/index.js", "sdk/biscuit_bg.wasm", "sdk/webmcp-polyfill.js", "sdk/webmcp-relay.js", "sdk/agentmesh-relay.mjs"}

// contentTypes is a fixed table, not mime.TypeByExtension: the Windows
// registry can map .js to text/plain, and nosniff then blocks the module.
var contentTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".json": "application/json",
	".wasm": "application/wasm",
	".png":  "image/png",
	".mjs":  "text/javascript; charset=utf-8",
}

// connect-src allows any ws/wss/https host because the person names the control
// plane and the control plane names the routers; WebTransport dials a router as
// https://<ip>:<port>. Plain http reaches only a control plane on this computer;
// CSP has no source for an IPv6 literal, so the page takes localhost and 127.0.0.1 only.
// no-cache plus the ETag makes a phone revalidate instead of running stale JS after an upgrade.
var securityHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
		"img-src 'self'; connect-src 'self' ws: wss: https: http://localhost:* http://127.0.0.1:*; manifest-src 'self'; base-uri 'none'; " +
		"form-action 'none'; frame-ancestors 'none'",
	"X-Content-Type-Options":     "nosniff",
	"Referrer-Policy":            "no-referrer",
	"X-Frame-Options":            "DENY",
	"Cross-Origin-Opener-Policy": "same-origin",
	"Cache-Control":              "no-cache",
}

const versionPlaceholder = "__AGENTMESH_VERSION__"

// Handler serves the app at /. A name not in the embedded tree is a 404,
// with no SPA fallback, so a missing SDK bundle is a failed import the page can
// report rather than HTML parsed as JavaScript.
func Handler() http.Handler {
	h, err := newHandler(public(), version.String())
	if err != nil {
		panic(err)
	}
	return h
}

// MissingBundle names the SDK bundle files this binary lacks, nil when it
// was built with `make all` (or `make app` before go build).
func MissingBundle() []string {
	return missingBundle(public())
}

func public() fs.FS {
	sub, err := fs.Sub(embedded, "public")
	if err != nil {
		panic(err)
	}
	return sub
}

func missingBundle(files fs.FS) []string {
	var missing []string
	for _, name := range bundleFiles {
		if _, err := fs.Stat(files, name); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}

type asset struct {
	body        []byte
	contentType string
	etag        string
}

type handler struct {
	assets map[string]asset
}

func newHandler(files fs.FS, buildVersion string) (*handler, error) {
	h := &handler{assets: map[string]asset{}}
	err := fs.WalkDir(files, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		contentType, known := contentTypes[path.Ext(name)]
		if entry.IsDir() || !known {
			return nil
		}
		body, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		if name == "index.html" {
			body = bytes.ReplaceAll(body, []byte(versionPlaceholder), []byte(html.EscapeString(buildVersion)))
		}
		sum := sha256.Sum256(body)
		h.assets[name] = asset{body: body, contentType: contentType, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
		return nil
	})
	return h, err
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for name, value := range securityHeaders {
		w.Header().Set(name, value)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed: the app serves GET and HEAD only", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	a, ok := h.assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("ETag", a.etag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(a.body))
}
