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
	"fmt"
	"net"
	"net/http"

	gostream "github.com/libp2p/go-libp2p-gostream"
	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// newLibp2pHTTPTransport returns a transport for libp2p:// URLs whose host is a
// peer ID. Requests go through net/http's Transport over a gostream connection
// to the peer's /libp2p-http protocol, as the router's ingress transport does,
// so net/http closes the stream when the request's context ends.
//
// go-libp2p-http's own transport uses the request context only to open the
// stream, which left the stream, and the remote handler behind it, open after
// the caller cancelled a long or streaming request.
//
// Keep-alives are disabled so each request gets its own stream, as it did with
// go-libp2p-http. A pooled stream over a limited (relayed) connection can be
// closed by the relay while idle, and net/http does not retry a request with a
// body, such as an A2A POST, on a reused connection.
func newLibp2pHTTPTransport(h host.Host) http.RoundTripper {
	return libp2pSchemeTransport{&http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			hostPart, _, err := net.SplitHostPort(addr)
			if err != nil {
				hostPart = addr
			}
			pid, err := peer.Decode(hostPart)
			if err != nil {
				return nil, fmt.Errorf("invalid target peer %q: %w", hostPart, err)
			}
			return gostream.Dial(ctx, h, pid, libp2phttp.DefaultP2PProtocol)
		},
		DisableKeepAlives: true,
	}}
}

// libp2pSchemeTransport sends libp2p:// requests through next as http://, so
// callers keep libp2p:// URLs, which an ordinary client refuses.
type libp2pSchemeTransport struct{ next http.RoundTripper }

func (t libp2pSchemeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "libp2p" {
		return nil, fmt.Errorf("unsupported scheme %q", req.URL.Scheme)
	}
	out := req.Clone(req.Context())
	out.URL.Scheme = "http"
	return t.next.RoundTrip(out)
}
