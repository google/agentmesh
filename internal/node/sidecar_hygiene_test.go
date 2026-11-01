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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/agentmesh/api"
)

// L32: a ".." after the authorized /{type}/{name} prefix travelled to the
// backend verbatim, where a server that resolves dot segments could serve a
// sibling service the caller was not granted.
func TestHasDotSegment(t *testing.T) {
	for path, want := range map[string]bool{
		"/mcp/a/tools":         false,
		"/mcp/a/../b/tools":    true,
		"/mcp/a/./tools":       true,
		"/mcp/a/..":            true,
		"/mcp/a/x..y/tools":    false, // ".." inside a segment is just a name
		"/mcp/a/tools/...":     false,
		"/mesh/p/mcp/a/../b/x": true,
		// A backslash reaches the backend percent-encoded; a backend that
		// treats it as a separator would see a traversal, so it is one here.
		"/mcp/a/..\\b/tools":  true,
		"/mcp/a\\..\\b/tools": true,
		"/mcp/a/x\\y/tools":   false,
	} {
		if got := api.HasDotSegment(path); got != want {
			t.Errorf("HasDotSegment(%q) = %v, want %v", path, got, want)
		}
	}
}

// L30: an OpenAI SDK pointed at the sidecar with api_key=<sidecar token> plus
// X-Mesh-Authentication as a default header sends the token twice. The gate
// stripped only the header it consumed and forwarded the other copy to the
// remote inference provider.
func TestWithAuthStripsDuplicateSidecarToken(t *testing.T) {
	const token = "sidecar-token"
	var seen http.Header
	h := withAuth(token, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))

	cases := map[string]struct {
		samAuth, authorization string
		wantAuthorization      string
	}{
		"token in both headers": {
			samAuth: "Bearer " + token, authorization: "Bearer " + token, wantAuthorization: "",
		},
		"token via X-Mesh, provider key in Authorization": {
			samAuth: "Bearer " + token, authorization: "Bearer provider-key", wantAuthorization: "Bearer provider-key",
		},
		"token via Authorization only": {
			samAuth: "", authorization: "Bearer " + token, wantAuthorization: "",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			seen = nil
			req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			if tc.samAuth != "" {
				req.Header.Set(api.HeaderMeshAuthentication, tc.samAuth)
			}
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			if got := seen.Get("Authorization"); got != tc.wantAuthorization {
				t.Errorf("Authorization reaching the handler = %q, want %q", got, tc.wantAuthorization)
			}
			if seen.Get(api.HeaderMeshAuthentication) != "" {
				t.Error("X-Mesh-Authentication reached the handler")
			}
		})
	}
}
