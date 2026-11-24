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

test("a mesh fetch releases any stream opened for an unreadable request body", async () => {
  let streams = 0;
  let aborted = 0;
  const stream = Object.assign(new EventTarget(), {
    abort() { aborted++; },
  });
  const connection = {
    remotePeer: "peer",
    async newStream() { streams++; return stream; },
  } as unknown as Connection;
  const request = new Request("http://mesh/mesh/peer/a2a/agent/message", { method: "POST", body: "fixture" });
  assert.equal(await request.text(), "fixture");
  await assert.rejects(fetchOverStream(connection, new Uint8Array(), request), TypeError);
  assert.equal(streams - aborted, 0, "request body failure leaked the libp2p stream");
});
