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
	"bufio"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	gostream "github.com/libp2p/go-libp2p-gostream"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// streamingPeers starts a server peer whose /stream handler sends one line and
// then waits for its request to end, reporting that on the returned channel.
func streamingPeers(t *testing.T) (client, server host.Host, ended <-chan struct{}) {
	t.Helper()
	newHost := func() host.Host {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}
	server, client = newHost(), newHost()

	listener, err := gostream.Listen(server, libp2phttp.DefaultP2PProtocol)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first\n"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(done)
		case <-time.After(30 * time.Second):
		}
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	if err := client.Connect(context.Background(), peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatal(err)
	}
	return client, server, done
}

func TestLibp2pHTTPTransportResetsStreamOnCancel(t *testing.T) {
	client, server, ended := streamingPeers(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "libp2p://"+server.ID().String()+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newLibp2pHTTPTransport(client).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if line, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil || line != "first\n" {
		t.Fatalf("first line = %q, %v", line, err)
	}

	cancel()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("remote handler still running 5s after the caller cancelled")
	}
}

func TestLibp2pHTTPTransportKeepsStreamUntilCancel(t *testing.T) {
	client, server, ended := streamingPeers(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "libp2p://"+server.ID().String()+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newLibp2pHTTPTransport(client).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if line, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil || line != "first\n" {
		t.Fatalf("first line = %q, %v", line, err)
	}
	select {
	case <-ended:
		t.Fatal("remote handler ended although the caller kept the request open")
	case <-time.After(500 * time.Millisecond):
	}
}
