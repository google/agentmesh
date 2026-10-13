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

package ffi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/node"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

// mockMesh is a fake control plane plus a router that accepts any auth, so
// the FFI can enroll and start against it in-process. It records the last
// request seen on each enrollment endpoint.
type mockMesh struct {
	url              string
	registerRequest  api.EnrollRequest
	bootstrapRequest api.BootstrapEnrollRequest
}

func newMockMesh(t *testing.T) *mockMesh {
	t.Helper()
	routerHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routerHost.Close() })

	routerDHT, err := dht.New(routerHost, dht.Mode(dht.ModeServer), dht.ProtocolPrefix("/mesh"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = routerDHT.Close() })

	// Generate key-pair for Mock Control Plane signing
	cpPubKey, cpPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	routerHost.SetStreamHandler(api.AuthProtocolID, func(s network.Stream) {
		println("--- MOCK ROUTER: received auth stream connection")
		defer func() { _ = s.Close() }()

		biscuitBytes := mintMockBiscuit(t, routerHost.ID().String(), cpPrivKey, api.RoleRouter)

		resp := &api.AuthResponse{
			Success: true,
			Biscuit: biscuitBytes,
		}
		data, _ := proto.Marshal(resp)
		writer := msgio.NewVarintWriter(s)
		if err := writer.WriteMsg(data); err != nil {
			println("--- MOCK ROUTER: failed to write AuthResponse:", err.Error())
			return
		}
		println("--- MOCK ROUTER: wrote AuthResponse success with valid biscuit")
	})

	mesh := &mockMesh{}
	routerAddrs := []string{routerHost.Addrs()[0].String() + "/p2p/" + routerHost.ID().String()}
	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = proto.Unmarshal(body, &mesh.registerRequest)
		writeProto(w, &api.EnrollResponse{
			BiscuitToken:          mintMockBiscuit(t, mesh.registerRequest.PeerId, cpPrivKey, api.RoleNode),
			ControlPlanePublicKey: cpPubKey,
			RouterAddresses:       routerAddrs,
		})
	})
	mux.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = proto.Unmarshal(body, &mesh.bootstrapRequest)
		writeProto(w, &api.BootstrapEnrollResponse{
			Status:                api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED,
			BiscuitToken:          mintMockBiscuit(t, mesh.bootstrapRequest.PeerId, cpPrivKey, api.RoleNode),
			ControlPlanePublicKey: cpPubKey,
			RouterAddresses:       routerAddrs,
		})
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		writeProto(w, &api.ControlPlaneInfoResponse{
			OidcIssuer: "http://mock-issuer",
			ClientId:   "mock-client",
			Audience:   "mock-audience",
		})
	})

	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	mesh.url = httpServer.URL
	return mesh
}

func writeProto(w http.ResponseWriter, message proto.Message) {
	data, _ := proto.Marshal(message)
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(data)
}

func TestMobileFFILifecycle(t *testing.T) {
	mesh := newMockMesh(t)

	// Mobile Enrollment
	tmpDir := t.TempDir()
	err := EnrollNode(tmpDir, mesh.url, "dummy-jwt", true, `{"region":"eu-west-1"}`, "")
	if err != nil {
		t.Fatalf("EnrollNode failed: %v", err)
	}
	if mesh.registerRequest.Labels["region"] != "eu-west-1" {
		t.Fatalf("Expected label region=eu-west-1 in enroll request, got %v", mesh.registerRequest.Labels)
	}

	// Mobile Node Start
	cfg := MobileConfig{
		DataDir:         tmpDir,
		ControlPlaneURL: mesh.url,
		MeshID:          "test-mesh",
		BindAddr:        "127.0.0.1:0", // random free port
		ApiToken:        "test-token",
		AllowLoopback:   true,
		Labels:          map[string]string{"region": "eu-west-1"},
		// A valid floor must not stop startup; enforcement is internal/node's.
		Egress: api.Egress{RequireLabels: map[string]string{"jurisdiction": "eu"}},
	}
	cfgBytes, _ := json.Marshal(cfg)

	err = StartNode(string(cfgBytes))
	if err != nil {
		t.Fatalf("StartNode failed: %v", err)
	}

	if GetNodeID() == "" || GetNodeID() == "unauthenticated" {
		t.Fatalf("Expected valid peer ID, got %q", GetNodeID())
	}

	// Stop Node
	err = StopNode()
	if err != nil {
		t.Fatalf("StopNode failed: %v", err)
	}
}

func TestEnrollNodeBootstrap(t *testing.T) {
	mesh := newMockMesh(t)
	dir := t.TempDir()
	if err := EnrollNodeBootstrap(dir, mesh.url, " mesh_dev_join-token\n", true, `{"region":"eu-west-1"}`); err != nil {
		t.Fatalf("EnrollNodeBootstrap failed: %v", err)
	}
	if mesh.bootstrapRequest.BootstrapToken != "mesh_dev_join-token" {
		t.Fatalf("bootstrap token not sent (trimmed) to /enroll, got %q", mesh.bootstrapRequest.BootstrapToken)
	}
	if mesh.bootstrapRequest.Labels["region"] != "eu-west-1" {
		t.Fatalf("Expected label region=eu-west-1 in bootstrap request, got %v", mesh.bootstrapRequest.Labels)
	}
	if mesh.registerRequest.PeerId != "" {
		t.Fatal("bootstrap enrollment must not call /register")
	}
	if IsEnrolled(dir) != 1 {
		t.Fatal("expected node to be enrolled after bootstrap enrollment")
	}
}

func TestEnrollNodeBootstrapRequiresToken(t *testing.T) {
	if err := EnrollNodeBootstrap(t.TempDir(), "http://127.0.0.1:1", "  ", true, `{}`); err == nil {
		t.Fatal("expected an empty bootstrap token to be rejected before any network call")
	}
}

func TestStartNodeRejectsInvalidLabels(t *testing.T) {
	if err := StartNode(`{"labels": {"bad key!": "x"}}`); err == nil {
		_ = StopNode()
		t.Fatal("expected StartNode to reject invalid labels")
	}
}

func mintMockBiscuit(t *testing.T, peerID string, priv ed25519.PrivateKey, role string) []byte {
	builder := biscuit.NewBuilder(priv)
	if err := builder.AddAuthorityFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: "node",
			IDs:  []biscuit.Term{biscuit.String(peerID)},
		},
	}); err != nil {
		t.Fatalf("failed to add node fact: %v", err)
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactRole,
			IDs:  []biscuit.Term{biscuit.String(role)},
		},
	}); err != nil {
		t.Fatalf("failed to add role fact: %v", err)
	}
	if err := builder.AddAuthorityFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactExpiration,
			IDs:  []biscuit.Term{biscuit.Date(time.Now().Add(time.Hour))},
		},
	}); err != nil {
		t.Fatalf("failed to add expiration fact: %v", err)
	}
	b, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build biscuit: %v", err)
	}
	biscuitBytes, err := b.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize biscuit: %v", err)
	}
	return biscuitBytes
}

// api.Attenuation carries only yaml tags; this pins the case-insensitive JSON
// match, since a silent miss would drop the node's local limits.
func TestMobileConfigDecodesAttenuation(t *testing.T) {
	var config MobileConfig
	if err := json.Unmarshal([]byte(`{"attenuation":{"rules":["r"],"policies":["p"],"checks":["c"]}}`), &config); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(config.Attenuation.Rules) != 1 || len(config.Attenuation.Policies) != 1 || len(config.Attenuation.Checks) != 1 {
		t.Fatalf("got %+v, want one statement of each kind", config.Attenuation)
	}
}

// Same pin for the egress floor: it rides the yaml-tagged api.Egress, so the
// JSON spelling is requireLabels. A silent miss here would start the node
// with no floor while the operator believes one is set.
func TestMobileConfigDecodesEgressFloor(t *testing.T) {
	var config MobileConfig
	if err := json.Unmarshal([]byte(`{"egress":{"requireLabels":{"jurisdiction":"eu"}}}`), &config); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if config.Egress.RequireLabels["jurisdiction"] != "eu" {
		t.Fatalf("got %+v, want the floor pair decoded", config.Egress)
	}
}

// Re-enrollment buys a JWT with the stored refresh token and re-attests the
// new labels under the same PeerID, with no browser involved.
func TestReEnrollNodeUsesStoredRefreshToken(t *testing.T) {
	cpPubKey, cpPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var registered api.EnrollRequest
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "token_endpoint": srv.URL + "/token"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("grant_type") != "refresh_token" || r.FormValue("refresh_token") != "stored" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": "fresh-jwt", "refresh_token": "rotated"})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = proto.Unmarshal(body, &registered)
		resp := &api.EnrollResponse{
			BiscuitToken:          mintMockBiscuit(t, registered.PeerId, cpPrivKey, api.RoleNode),
			ControlPlanePublicKey: cpPubKey,
			RouterAddresses:       []string{"/ip4/127.0.0.1/tcp/1"},
		}
		data, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(data)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	store, err := node.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveControlPlaneURL(srv.URL); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRefreshToken("stored"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveOIDCConfig(srv.URL, "mock-client", ""); err != nil {
		t.Fatal(err)
	}
	want, err := peer.IDFromPublicKey(node.GetOrGenerateKey(store).GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	if err := ReEnrollNode(dir, `{"region":"us-east-1"}`); err != nil {
		t.Fatalf("ReEnrollNode failed: %v", err)
	}
	if registered.Jwt != "fresh-jwt" || registered.PeerId != want.String() || registered.Labels["region"] != "us-east-1" {
		t.Fatalf("unexpected enroll request: jwt=%q peer=%q labels=%v", registered.Jwt, registered.PeerId, registered.Labels)
	}
	store, err = node.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if tok, err := store.LoadRefreshToken(); err != nil || tok != "rotated" {
		t.Fatalf("expected rotated refresh token saved, got %q, %v", tok, err)
	}

	// Nothing saved means nothing to re-enroll with; the app opens the browser.
	if err := ReEnrollNode(t.TempDir(), `{"region":"us-east-1"}`); err == nil {
		t.Fatal("expected re-enrollment without a refresh token to fail")
	}
}

func TestDecodeLabels(t *testing.T) {
	if got, err := decodeLabels(""); err != nil || got != nil {
		t.Fatalf("empty string should mean no labels, got %v, %v", got, err)
	}
	if got, err := decodeLabels(`{"region":"eu-west-1"}`); err != nil || got["region"] != "eu-west-1" {
		t.Fatalf("unexpected labels %v, %v", got, err)
	}
	for _, bad := range []string{`not json`, `{"bad key!":"x"}`} {
		if _, err := decodeLabels(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}
