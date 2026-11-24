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

test("an already aborted mesh fetch leaves the connection untouched", async () => {
  for (const source of ["options", "request"] as const) {
    const reason = new Error("caller cancelled");
    const signal = AbortSignal.abort(reason);
    let streams = 0;
    const connection = {
      remotePeer: "peer",
      async newStream() {
        streams++;
        throw new Error("opened a stream");
      },
    } as unknown as Connection;
    const request = new Request(
      "http://mesh/mesh/peer/a2a/agent/message",
      source === "request" ? { signal } : undefined,
    );
    const error = await fetchOverStream(
      connection, new Uint8Array(), request, source === "options" ? { signal } : {},
    ).catch((err: unknown) => err);
    assert.equal(streams, 0, `${source} signal opened a stream`);
    assert.equal(error, reason);
  }
});
