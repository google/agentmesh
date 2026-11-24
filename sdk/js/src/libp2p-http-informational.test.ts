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

import assert from "node:assert/strict";
import { test } from "node:test";
import type { Connection } from "@libp2p/interface";
import { fetchOverStream } from "./libp2p-http.ts";

test("a mesh fetch returns the final response after informational responses", { timeout: 5000 }, async () => {
  for (const prefix of ["", "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n"]) {
    let sent = false;
    const stream = Object.assign(new EventTarget(), {
      send() { return true; },
      pause() {},
      resume() {
        if (sent) return;
        sent = true;
        queueMicrotask(() => stream.dispatchEvent(Object.assign(new Event("message"), {
          data: new TextEncoder().encode(prefix + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        })));
      },
      abort() { stream.dispatchEvent(new Event("close")); },
      async close() { stream.dispatchEvent(new Event("close")); },
    });
    const connection = { remotePeer: "peer", async newStream() { return stream; } } as unknown as Connection;
    const response = await fetchOverStream(
      connection, new Uint8Array(), new Request("http://mesh/mesh/peer/a2a/agent/message"),
    );
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "ok");
    assert.equal(response.headers.has("link"), false);
  }
});
