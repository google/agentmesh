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
import { MeshSession } from "./session.ts";

test("SDK passes cancellation to a remote tool call", async () => {
  for (const abort of [false, true]) {
    const controller = new AbortController();
    const reason = new Error("caller cancelled");
    let closed = 0;
    const session = {
      async openMCP() {
        return {
          client: {
            async callTool(_params: unknown, _schema: unknown, options?: { signal?: AbortSignal }) {
              if (abort) controller.abort(reason);
              options?.signal?.throwIfAborted();
              return { content: [{ type: "text", text: "result" }] };
            },
          },
          async close() { closed++; },
        };
      },
    } as unknown as MeshSession;
    const result = MeshSession.prototype.callTool.call(
      session, "peer", "mcp://catalog", "read", {}, { signal: controller.signal },
    );
    if (abort) {
      await assert.rejects(result, reason);
    } else {
      assert.deepEqual((await result).text, ["result"]);
    }
    assert.equal(closed, 1);
  }
});
