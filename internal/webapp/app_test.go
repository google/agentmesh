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

package webapp

import (
	"encoding/json"
	"fmt"
	"image/png"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func testFiles() fstest.MapFS {
	return fstest.MapFS{
		"index.html":              {Data: []byte(`<html><footer>Agent Mesh __AGENTMESH_VERSION__</footer></html>`)},
		"app.js":                  {Data: []byte(`import "./model.js";`)},
		"model.js":                {Data: []byte(`export {};`)},
		"style.css":               {Data: []byte(`body {}`)},
		"manifest.json":           {Data: []byte(`{}`)},
		"icon-192.png":            {Data: []byte("\x89PNG")},
		"app.js.map":              {Data: []byte(`{}`)},
		"sdk/index.js":            {Data: []byte(`export const sdk = 1;`)},
		"sdk/biscuit_bg.wasm":     {Data: []byte("\x00asm")},
		"sdk/webmcp-polyfill.js":  {Data: []byte(`export {};`)},
		"sdk/webmcp-relay.js":     {Data: []byte(`(function(){})();`)},
		"sdk/agentmesh-relay.mjs": {Data: []byte(`export {};`)},
	}
}

func newTestHandler(t *testing.T, files fstest.MapFS) *handler {
	t.Helper()
	h, err := newHandler(files, "v1.2.3")
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	return h
}

func serve(h http.Handler, method, target string, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for name, values := range header {
		req.Header[name] = values
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandlerSetsSecurityHeadersOnEveryResponse(t *testing.T) {
	h := newTestHandler(t, testFiles())
	for _, target := range []string{"/", "/app.js", "/missing.js"} {
		rec := serve(h, http.MethodGet, target, nil)
		csp := rec.Header().Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self' 'wasm-unsafe-eval'", "connect-src 'self' ws: wss: https: http://localhost:* http://127.0.0.1:*;", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("GET %s Content-Security-Policy = %q, want it to contain %q", target, csp, want)
			}
		}
		for name, want := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-cache"} {
			if got := rec.Header().Get(name); got != want {
				t.Errorf("GET %s %s = %q, want %q", target, name, got, want)
			}
		}
	}
}

func TestHandlerContentTypes(t *testing.T) {
	h := newTestHandler(t, testFiles())
	for target, want := range map[string]string{
		"/":                        "text/html; charset=utf-8",
		"/app.js":                  "text/javascript; charset=utf-8",
		"/style.css":               "text/css; charset=utf-8",
		"/manifest.json":           "application/json",
		"/sdk/biscuit_bg.wasm":     "application/wasm",
		"/sdk/agentmesh-relay.mjs": "text/javascript; charset=utf-8",
		"/icon-192.png":            "image/png",
	} {
		rec := serve(h, http.MethodGet, target, nil)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != want {
			t.Errorf("GET %s = %d %q, want 200 %q", target, rec.Code, rec.Header().Get("Content-Type"), want)
		}
	}
}

func TestHandlerAnswersRevalidationWith304(t *testing.T) {
	h := newTestHandler(t, testFiles())
	first := serve(h, http.MethodGet, "/sdk/index.js", nil)
	etag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || !strings.HasPrefix(etag, `"`) {
		t.Fatalf("GET /sdk/index.js = %d with ETag %q, want 200 with a strong ETag", first.Code, etag)
	}
	again := serve(h, http.MethodGet, "/sdk/index.js", http.Header{"If-None-Match": {etag}})
	if again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Errorf("revalidating with If-None-Match %s = %d with %d bytes, want 304 with none", etag, again.Code, again.Body.Len())
	}
}

func TestHandlerServesOnlyEmbeddedFiles(t *testing.T) {
	h := newTestHandler(t, testFiles())
	for _, target := range []string{"/sdk/", "/../go.mod", "/app.js.map", "/unknown", "/node/"} {
		rec := serve(h, http.MethodGet, target, nil)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<html") {
			t.Errorf("GET %s = %d %q, want a plain 404", target, rec.Code, rec.Body.String())
		}
	}
}

func TestHandlerWithoutBundleStillServesTheApp(t *testing.T) {
	files := testFiles()
	for _, name := range bundleFiles {
		delete(files, name)
	}
	h := newTestHandler(t, files)
	if rec := serve(h, http.MethodGet, "/", nil); rec.Code != http.StatusOK {
		t.Errorf("GET / without the bundle = %d, want 200: the page explains what is missing", rec.Code)
	}
	if rec := serve(h, http.MethodGet, "/sdk/index.js", nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET /sdk/index.js without the bundle = %d, want 404 so the page's import fails", rec.Code)
	}
	if got := missingBundle(files); !slices.Equal(got, bundleFiles) {
		t.Errorf("missingBundle without the bundle = %v, want %v", got, bundleFiles)
	}
	if got := missingBundle(testFiles()); got != nil {
		t.Errorf("missingBundle with the bundle = %v, want nil", got)
	}
}

func TestHandlerStampsTheVersion(t *testing.T) {
	rec := serve(newTestHandler(t, testFiles()), http.MethodGet, "/", nil)
	if body := rec.Body.String(); !strings.Contains(body, "Agent Mesh v1.2.3") || strings.Contains(body, versionPlaceholder) {
		t.Errorf("GET / = %q, want the version stamped in place of %s", body, versionPlaceholder)
	}
	other, err := newHandler(testFiles(), "v1.2.4")
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	if rec.Header().Get("ETag") == serve(other, http.MethodGet, "/", nil).Header().Get("ETag") {
		t.Errorf("index.html has the same ETag under two versions, so a phone would keep the old page")
	}
}

func TestHandlerRejectsOtherMethods(t *testing.T) {
	rec := serve(newTestHandler(t, testFiles()), http.MethodPost, "/", nil)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST / = %d with Allow %q, want 405 with Allow: GET, HEAD", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestEmbeddedAppIsComplete(t *testing.T) {
	files := public()
	for _, name := range []string{"index.html", "app.js", "model.js", "style.css", "manifest.json", "apple-touch-icon.png", "favicon.png"} {
		if _, err := fs.Stat(files, name); err != nil {
			t.Errorf("embedded app lacks %s: %v", name, err)
		}
	}
	raw, err := fs.ReadFile(files, "manifest.json")
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var manifest struct {
		Name          string `json:"name"`
		StartURL      string `json:"start_url"`
		Display       string `json:"display"`
		LaunchHandler struct {
			ClientMode string `json:"client_mode"`
		} `json:"launch_handler"`
		Icons []struct {
			Src   string `json:"src"`
			Sizes string `json:"sizes"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("manifest.json does not parse: %v", err)
	}
	if manifest.Name == "" || manifest.StartURL != "./" || manifest.Display != "standalone" || manifest.LaunchHandler.ClientMode != "navigate-existing" {
		t.Errorf("manifest = %+v, want a name, start_url ./, display standalone and launch_handler navigate-existing", manifest)
	}
	if len(manifest.Icons) == 0 {
		t.Fatalf("manifest lists no icons, so browsers offer no install")
	}
	for _, icon := range manifest.Icons {
		f, err := files.Open(icon.Src)
		if err != nil {
			t.Errorf("manifest icon %s is not embedded: %v", icon.Src, err)
			continue
		}
		config, err := png.DecodeConfig(f)
		_ = f.Close()
		if err != nil {
			t.Errorf("manifest icon %s is not a PNG: %v", icon.Src, err)
			continue
		}
		if got := fmt.Sprintf("%dx%d", config.Width, config.Height); got != icon.Sizes {
			t.Errorf("manifest icon %s is %s, manifest says %s", icon.Src, got, icon.Sizes)
		}
	}
}
