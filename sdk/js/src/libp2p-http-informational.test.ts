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
import { HTTPParseError } from "./http1.ts";
import { fetchOverStream } from "./libp2p-http.ts";

// A connection whose one stream answers any request with the given bytes.
function answering(response: string): { connection: Connection; aborted: () => boolean } {
  let sent = false;
  let aborted = false;
  const stream = Object.assign(new EventTarget(), {
    send() { return true; },
    pause() {},
    resume() {
      if (sent) return;
      sent = true;
      queueMicrotask(() => stream.dispatchEvent(Object.assign(new Event("message"), {
        data: new TextEncoder().encode(response),
      })));
    },
    abort() {
      aborted = true;
      stream.dispatchEvent(new Event("close"));
    },
    async close() { stream.dispatchEvent(new Event("close")); },
  });
  const connection = { remotePeer: "peer", async newStream() { return stream; } } as unknown as Connection;
  return { connection, aborted: () => aborted };
}

const request = () => new Request("http://mesh/mesh/peer/a2a/agent/message");
const continued = (n: number) => "HTTP/1.1 100 Continue\r\n\r\n".repeat(n);
const final = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

test("a mesh fetch returns the final response after informational responses", { timeout: 5000 }, async () => {
  const earlyHints = "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n";
  for (const prefix of ["", earlyHints + continued(1), continued(10)]) {
    const { connection } = answering(prefix + final);
    const response = await fetchOverStream(connection, new Uint8Array(), request());
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "ok");
    assert.equal(response.headers.has("link"), false);
  }
});

test("a mesh fetch refuses a peer that keeps sending informational responses", { timeout: 5000 }, async () => {
  const { connection, aborted } = answering(continued(11) + final);
  await assert.rejects(fetchOverStream(connection, new Uint8Array(), request()), HTTPParseError);
  assert.equal(aborted(), true, "the stream is aborted");
});
