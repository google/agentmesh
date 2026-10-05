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

package router

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
)

func getBody(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestRouterMetricsListener(t *testing.T) {
	ctx := context.Background()
	r, err := NewRouter(ctx, Options{BiscuitTimeout: time.Second, RequiredRole: api.RoleRouter})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.serveMetrics("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	base := "http://" + r.metricsAddr.String()

	// Before Start completes: alive, not ready, and nothing read from a host
	// that does not exist yet.
	if code, _ := getBody(t, base+"/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d before ready", code)
	}
	if code, _ := getBody(t, base+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d before ready, want 503", code)
	}
	code, body := getBody(t, base+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics = %d: %s", code, body)
	}
	if !strings.Contains(body, "sam_router_ready 0") {
		t.Error("/metrics missing sam_router_ready 0 before start")
	}
	if strings.Contains(body, "sam_router_authenticated_peers") {
		t.Error("/metrics exported host state before the host existed")
	}

	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	kad, err := dht.New(host, dht.Mode(dht.ModeServer))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kad.Close() }()

	r.Host = host
	r.DHT = kad
	r.authenticatedPeers.Store(peer.ID("peer-a"), true)
	r.authenticatedPeers.Store(peer.ID("peer-b"), true)
	r.bannedPeers.Store(peer.ID("peer-x"), true)
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	r.keysMu.Lock()
	r.credential.expiration = expiry
	r.keysMu.Unlock()
	r.isReady.Store(true)

	if code, _ := getBody(t, base+"/readyz"); code != http.StatusOK {
		t.Errorf("/readyz = %d once ready", code)
	}
	_, body = getBody(t, base+"/metrics")
	for _, want := range []string{
		"sam_router_ready 1",
		`sam_router_info{peer_id="` + host.ID().String() + `"} 1`,
		"sam_router_conns_per_source_ip_limit 8",
		"sam_router_inbound_connections_refused_total",
		"sam_router_authenticated_peers 2",
		"sam_router_banned_peers 1",
		"sam_router_connected_peers 0",
		"sam_router_dht_routing_table_size 0",
		// The text format renders values with strconv 'g', so a unix time
		// comes out in scientific notation.
		"sam_router_biscuit_expiry_timestamp_seconds " + strconv.FormatFloat(float64(expiry.Unix()), 'g', -1, 64),
		// libp2p registers into the default registry, which the listener
		// serves alongside the router's own state.
		"libp2p_",
		"sam_router_auth_handshakes_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get(base + "/healthz"); err == nil {
		t.Error("metrics listener still answering after Close")
	}
}
