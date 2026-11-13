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

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/version"
)

func writeProto(t *testing.T, w http.ResponseWriter, msg proto.Message) {
	t.Helper()
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Errorf("proto.Marshal(%T): %v", msg, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	if _, err := w.Write(data); err != nil {
		t.Errorf("write %T: %v", msg, err)
	}
}

func TestNewBaseURLNormalization(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		"   ":                           "",
		"hub.sam-mesh.dev":              "https://hub.sam-mesh.dev",
		"http://127.0.0.1:8080":         "http://127.0.0.1:8080",
		"https://hub.sam-mesh.dev/":     "https://hub.sam-mesh.dev",
		"https://hub.sam-mesh.dev//":    "https://hub.sam-mesh.dev",
		"  https://hub.sam-mesh.dev/  ": "https://hub.sam-mesh.dev",
	}
	for in, want := range cases {
		c := New(in, nil)
		if c.baseURL != want {
			t.Errorf("New(%q).baseURL = %q, want %q", in, c.baseURL, want)
		}
	}
}

func TestHTTPClientUserAgent(t *testing.T) {
	for _, component := range []string{"agentmesh-node", "agentmesh-router"} {
		t.Run(component, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if got, want := request.UserAgent(), component+"/"+version.String(); got != want {
					t.Errorf("User-Agent = %q, want %q", got, want)
				}
				if request.Header.Get("Authorization") != "Bearer test" {
					t.Error("transport changed the authentication header")
				}
				if request.URL.Path == "/redirect" {
					http.Redirect(w, request, "/final", http.StatusTemporaryRedirect)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			request, err := http.NewRequest(http.MethodGet, server.URL+"/redirect", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer test")
			request.Header.Set("User-Agent", "original")
			response, err := NewHTTPClient(time.Second, nil, component).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if request.UserAgent() != "original" {
				t.Fatal("transport mutated the caller's request")
			}
		})
	}
}

func TestFetchInfo(t *testing.T) {
	want := &api.ControlPlaneInfoResponse{
		RouterAddresses: []string{"/ip4/10.0.0.1/tcp/4501"},
		BannedPeerIds:   []string{"12D3KooWBanned"},
	}
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writeProto(t, w, want)
	}))
	defer srv.Close()

	// A trailing slash on the base URL must not double up in the path.
	c := New(srv.URL+"/", NewHTTPClient(time.Second, nil, "agentmesh-node"))
	info, err := c.FetchInfo(context.Background())
	if err != nil {
		t.Fatalf("FetchInfo: %v", err)
	}
	if gotPath != "/info" {
		t.Errorf("request path = %q, want /info", gotPath)
	}
	if !proto.Equal(info, want) {
		t.Errorf("FetchInfo = %v, want %v", info, want)
	}
}

func TestFetchKeys(t *testing.T) {
	trustedPub, trustedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	successorPub, successorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	strangerPub, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serve := func(t *testing.T, pubs []ed25519.PublicKey, privs []ed25519.PrivateKey) *Client {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := &api.KeysResponse{}
			for _, p := range pubs {
				resp.PublicKeys = append(resp.PublicKeys, p)
			}
			if privs != nil {
				if err := api.SignKeysResponse(resp, privs, time.Now()); err != nil {
					t.Errorf("SignKeysResponse: %v", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			writeProto(t, w, resp)
		}))
		t.Cleanup(srv.Close)
		return New(srv.URL, NewHTTPClient(time.Second, nil, "agentmesh-node"))
	}

	t.Run("a set vouched for by a trusted key is adopted whole", func(t *testing.T) {
		c := serve(t, []ed25519.PublicKey{trustedPub, successorPub}, []ed25519.PrivateKey{trustedPriv, successorPriv})
		keys, err := c.FetchKeys(context.Background(), []ed25519.PublicKey{trustedPub})
		if err != nil {
			t.Fatalf("FetchKeys: %v", err)
		}
		if len(keys) != 2 || !keys[0].Equal(trustedPub) || !keys[1].Equal(successorPub) {
			t.Errorf("FetchKeys = %d keys, want trusted then successor", len(keys))
		}
	})

	t.Run("a set signed only by a stranger is rejected", func(t *testing.T) {
		c := serve(t, []ed25519.PublicKey{strangerPub}, []ed25519.PrivateKey{strangerPriv})
		if _, err := c.FetchKeys(context.Background(), []ed25519.PublicKey{trustedPub}); err == nil {
			t.Fatal("FetchKeys accepted a set no trusted key signed")
		}
	})

	t.Run("an unsigned set is rejected", func(t *testing.T) {
		c := serve(t, []ed25519.PublicKey{trustedPub, strangerPub}, nil)
		if _, err := c.FetchKeys(context.Background(), []ed25519.PublicKey{trustedPub}); err == nil {
			t.Fatal("FetchKeys accepted an unsigned set")
		}
	})
}

func TestErrors(t *testing.T) {
	t.Run("non-200 carries the status and body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "store down", http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		c := New(srv.URL, NewHTTPClient(time.Second, nil, "agentmesh-node"))
		_, err := c.FetchInfo(context.Background())
		if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "store down") {
			t.Fatalf("FetchInfo error = %v, want status and body", err)
		}
	})

	t.Run("a body that is not the message is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := w.Write([]byte("not protobuf")); err != nil {
				t.Errorf("write: %v", err)
			}
		}))
		defer srv.Close()
		c := New(srv.URL, NewHTTPClient(time.Second, nil, "agentmesh-node"))
		if _, err := c.FetchInfo(context.Background()); err == nil || !strings.Contains(err.Error(), "decode /info") {
			t.Fatalf("FetchInfo error = %v, want a decode error naming the path", err)
		}
	})

	t.Run("an oversized body is an error, not a shorter message", func(t *testing.T) {
		// A ban set cut at an entry boundary would decode as a valid, smaller
		// ban set; the client must refuse the answer instead.
		big := &api.ControlPlaneInfoResponse{}
		for len(big.BannedPeerIds) < 200_000 {
			big.BannedPeerIds = append(big.BannedPeerIds, "12D3KooWL7xNnc7bdzPGobhPxvunLC1uNhHfSCK8ZTXjR1YSTG9T")
		}
		data, err := proto.Marshal(big)
		if err != nil {
			t.Fatalf("proto.Marshal: %v", err)
		}
		if len(data) <= MaxBodyBytes {
			t.Fatalf("test answer is %d bytes, need more than %d", len(data), MaxBodyBytes)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-protobuf")
			// The client stops reading at MaxBodyBytes+1 and closes the
			// body, which resets the connection before the tail of data is
			// written.
			_, _ = w.Write(data)
		}))
		defer srv.Close()
		c := New(srv.URL, NewHTTPClient(5*time.Second, nil, "agentmesh-node"))
		info, err := c.FetchInfo(context.Background())
		if !errors.Is(err, ErrBodyTooLarge) {
			t.Fatalf("FetchInfo = (%d bans, %v), want ErrBodyTooLarge", len(info.GetBannedPeerIds()), err)
		}
	})
}

// The cap must never cut a legitimate answer: a large ban set well inside it
// arrives whole, and a body of exactly the cap still decodes.
func TestLargeAnswersArriveWhole(t *testing.T) {
	const bans = 100_000
	big := &api.ControlPlaneInfoResponse{RouterAddresses: []string{"/ip4/10.0.0.1/tcp/4501"}}
	for i := 0; i < bans; i++ {
		big.BannedPeerIds = append(big.BannedPeerIds, "12D3KooWL7xNnc7bdzPGobhPxvunLC1uNhHfSCK8ZTXjR1YSTG9T")
	}
	if n := proto.Size(big); n >= MaxBodyBytes {
		t.Fatalf("%d bans is %d bytes, over the %d cap: the cap is too small for a mesh this size", bans, n, MaxBodyBytes)
	}

	t.Run("large ban set", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeProto(t, w, big)
		}))
		defer srv.Close()
		info, err := New(srv.URL, NewHTTPClient(5*time.Second, nil, "agentmesh-node")).FetchInfo(context.Background())
		if err != nil {
			t.Fatalf("FetchInfo: %v", err)
		}
		if got := len(info.BannedPeerIds); got != bans {
			t.Fatalf("FetchInfo returned %d bans, want %d: the answer was cut", got, bans)
		}
	})

	t.Run("body of exactly the cap", func(t *testing.T) {
		// Pad the router address so the encoded message is exactly MaxBodyBytes.
		exact := &api.ControlPlaneInfoResponse{RouterAddresses: []string{""}}
		pad := MaxBodyBytes - proto.Size(exact) - 3 // 3: the length prefix grows to three bytes
		exact.RouterAddresses[0] = strings.Repeat("a", pad)
		for proto.Size(exact) < MaxBodyBytes {
			exact.RouterAddresses[0] += "a"
		}
		if n := proto.Size(exact); n != MaxBodyBytes {
			t.Fatalf("test body is %d bytes, want exactly %d", n, MaxBodyBytes)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeProto(t, w, exact)
		}))
		defer srv.Close()
		info, err := New(srv.URL, NewHTTPClient(5*time.Second, nil, "agentmesh-node")).FetchInfo(context.Background())
		if err != nil {
			t.Fatalf("FetchInfo at exactly the cap: %v", err)
		}
		if len(info.RouterAddresses) != 1 || len(info.RouterAddresses[0]) != len(exact.RouterAddresses[0]) {
			t.Fatal("body of exactly the cap did not arrive whole")
		}
	})
}

func TestFetchPolicy(t *testing.T) {
	want := &api.PolicyConfigGetResponse{
		DatalogRules: []string{`role("developer") <- group("eng")`, `granted_service_all("mcp") <- role("developer")`},
	}
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/policies" {
			http.NotFound(w, r)
			return
		}
		writeProto(t, w, want)
	}))
	defer srv.Close()

	policy, err := New(srv.URL, NewHTTPClient(time.Second, nil, "agentmesh-node")).FetchPolicy(context.Background(), []byte("biscuit"))
	if err != nil {
		t.Fatalf("FetchPolicy: %v", err)
	}
	if !proto.Equal(policy, want) {
		t.Errorf("FetchPolicy = %v, want %v", policy, want)
	}
	if gotAuth != "Bearer "+base64.StdEncoding.EncodeToString([]byte("biscuit")) {
		t.Errorf("Authorization = %q, want the biscuit as a base64 bearer token", gotAuth)
	}
}

// The control plane is the trust root, so a plaintext hop to it is refused
// unless the operator opted in; loopback is the standalone case and is fine.
// The choice is read per request, since the node learns it after its clients
// exist.
func TestHTTPClientTransportPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProto(t, w, &api.ControlPlaneInfoResponse{})
	}))
	defer srv.Close()
	// httptest binds 127.0.0.1; spell it as a non-loopback name that the
	// transport must refuse before any connection is attempted.
	nonLoopbackURL := strings.Replace(srv.URL, "127.0.0.1", "agentmesh-control-plane.invalid", 1)

	allow := false
	httpClient := NewHTTPClient(time.Second, func() bool { return allow }, "agentmesh-node")

	if _, err := New(srv.URL, httpClient).FetchInfo(context.Background()); err != nil {
		t.Fatalf("loopback plaintext must be accepted: %v", err)
	}
	_, err := New(nonLoopbackURL, httpClient).FetchInfo(context.Background())
	if !errors.Is(err, api.ErrInsecureControlPlaneURL) {
		t.Fatalf("plaintext to a non-loopback host: err = %v, want %v", err, api.ErrInsecureControlPlaneURL)
	}

	// With the opt-in the request is attempted; the name does not resolve,
	// which is a dial error, not the policy error.
	allow = true
	_, err = New(nonLoopbackURL, httpClient).FetchInfo(context.Background())
	if err == nil || errors.Is(err, api.ErrInsecureControlPlaneURL) {
		t.Fatalf("with the opt-in the policy must not be what fails: %v", err)
	}
}
