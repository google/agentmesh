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

test("SDK lists all remote tool pages", async () => {
  for (const cursor of [undefined, "next"]) {
    const calls: (string | undefined)[] = [];
    let closed = 0;
    const session = {
      async openMCP() {
        return {
          client: {
            async listTools(params?: { cursor?: string }) {
              calls.push(params?.cursor);
              return params?.cursor === undefined
                ? { tools: [{ name: "first" }], nextCursor: cursor }
                : { tools: [{ name: "second", description: "Second tool" }] };
            },
          },
          async close() { closed++; },
        };
      },
    } as unknown as MeshSession;
    const tools = await MeshSession.prototype.listTools.call(session, "peer", "mcp://catalog");
    assert.equal(closed, 1);
    if (cursor === undefined) {
      assert.deepEqual(tools, [{ name: "first" }]);
      assert.deepEqual(calls, [undefined]);
    } else {
      assert.deepEqual(tools, [{ name: "first" }, { name: "second", description: "Second tool" }]);
      assert.deepEqual(calls, [undefined, "next"]);
    }
  }
});

test("SDK rejects a remote tool catalog that never ends", async () => {
  for (const [name, next, wantCalls] of [
    ["a repeated cursor", () => "loop", 2],
    ["a new cursor on every page", (n: number) => `page-${n}`, 257],
  ] as const) {
    let calls = 0;
    let closed = 0;
    const session = {
      async openMCP() {
        return {
          client: {
            async listTools() {
              return { tools: [], nextCursor: next(calls++) };
            },
          },
          async close() { closed++; },
        };
      },
    } as unknown as MeshSession;
    await assert.rejects(
      MeshSession.prototype.listTools.call(session, "peer", "mcp://catalog"),
      /provider returned an unbounded tool catalog/,
      name,
    );
    assert.equal(calls, wantCalls, `${name}: listTools calls`);
    assert.equal(closed, 1, `${name}: sessions closed`);
  }
});
