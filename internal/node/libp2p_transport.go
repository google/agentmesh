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

	libp2phttp "github.com/libp2p/go-libp2p-http"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// newLibp2pHTTPTransport returns the go-libp2p-http transport over h, with
// each request's stream reset when the request's context ends.
//
// go-libp2p-http uses the request context only to open the stream. A caller
// that cancels a long or streaming request would otherwise leave the stream,
// and the remote handler behind it, open until the remote side finishes.
func newLibp2pHTTPTransport(h host.Host) *libp2phttp.RoundTripper {
	return libp2phttp.NewTransport(cancelableStreamHost{h})
}

// cancelableStreamHost resets a stream opened by NewStream when the context
// passed to NewStream ends before the stream is closed.
type cancelableStreamHost struct {
	host.Host
}

func (h cancelableStreamHost) NewStream(ctx context.Context, p peer.ID, pids ...protocol.ID) (network.Stream, error) {
	s, err := h.Host.NewStream(ctx, p, pids...)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Reset() })
	return &cancelableStream{Stream: s, stop: stop}, nil
}

type cancelableStream struct {
	network.Stream
	stop func() bool
}

func (s *cancelableStream) Close() error {
	s.stop()
	return s.Stream.Close()
}

func (s *cancelableStream) Reset() error {
	s.stop()
	return s.Stream.Reset()
}

func (s *cancelableStream) ResetWithError(code network.StreamErrorCode) error {
	s.stop()
	return s.Stream.ResetWithError(code)
}
