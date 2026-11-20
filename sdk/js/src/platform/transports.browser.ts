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

// A browser reaches a router over WebSocket or WebTransport. WebTransport works
// by IP: the browser checks the router's certificate against the certhash in
// its address. A browser can't run libp2p's TLS, so it secures both with Noise.

import { noise } from "@chainsafe/libp2p-noise";
import { webSockets } from "@libp2p/websockets";
import { webTransport } from "@libp2p/webtransport";
import type { Libp2pOptions } from "libp2p";

export function transports(): NonNullable<Libp2pOptions["transports"]> {
  return [webSockets(), webTransport()];
}

export function connectionEncrypters(): NonNullable<Libp2pOptions["connectionEncrypters"]> {
  return [noise()];
}
