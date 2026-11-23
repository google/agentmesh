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
import { peerIdFromString } from "@libp2p/peer-id";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Identity } from "../src/identity.ts";
import { createMeshMCPServer, meshTools } from "../src/mcp-server.ts";
import { CallVerifier, signCall, type PairedAgent } from "./pairing.ts";
import { registerWebMCPTools, type CallLog, type ModelContext } from "./webmcp.ts";

type Registered = Parameters<ModelContext["registerTool"]>[0];

const agent: PairedAgent = { key_id: "k1", name: "Test Agent", key: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url"), paired_time: "2026-11-23T00:00:00Z" };

function recorder(): CallLog & { lines: string[] } {
  const lines: string[] = [];
  return { lines, called: (tool, by) => { lines.push(`${by.name} called ${tool}`); }, refused: (tool) => { lines.push(`refused ${tool}`); } };
}

test("WebMCP offers the stdio server's five tools, with the same schemas, to signed calls only, until the signal aborts", async (t) => {
  const self = Identity.generate().peerId;
  const peer = Identity.generate().peerId;
  const session = {
    peerId: self, routers: [], isHeldRouter: () => false,
    node: { getPeers: () => [peerIdFromString(peer)] },
    async discover() { return []; },
    async openMCP(): Promise<never> { throw new Error("no remote peers in this test"); },
  };
  const registered: Registered[] = [];
  const signals: AbortSignal[] = [];
  const modelContext: ModelContext = { registerTool(tool, options) { registered.push(tool); signals.push(options.signal); } };
  const controller = new AbortController();
  const log = recorder();

  await registerWebMCPTools(modelContext, meshTools(session), new CallVerifier(() => [agent]), log, controller.signal);

  const [a, b] = InMemoryTransport.createLinkedPair();
  const stdio = createMeshMCPServer(session, "1");
  const client = new Client({ name: "test", version: "1" });
  await stdio.connect(a);
  await client.connect(b);
  t.after(async () => { await client.close(); });
  const listed = (await client.listTools()).tools;
  assert.deepEqual(
    registered.map((tool) => ({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema })),
    listed.map((tool) => ({ name: tool.name, description: tool.description, inputSchema: tool.inputSchema })),
  );
  assert.equal(registered.length, 5);
  assert.ok(signals.every((signal) => signal === controller.signal), "every registration ends with the caller's signal");

  const info = registered.find((tool) => tool.name === "get_mesh_info")!;
  const unsigned = await info.execute({});
  assert.deepEqual(unsigned, { isError: true, content: [{ type: "text", text: "This node accepts calls only from a paired agent. Press Connect a local agent on the page and paste the prompt into your agent." }] });
  const result = await info.execute(await signCall(agent, "get_mesh_info", {}));
  assert.deepEqual(JSON.parse((result.content[0] as { text: string }).text), { peer_id: self, connected_peers: [peer], attached_routers: [], router_peer_id: "" });
  const invalid = await registered.find((tool) => tool.name === "call_remote_tool")!.execute(await signCall(agent, "call_remote_tool", { tool_name: "mcp://calc/add" }));
  assert.equal(invalid.isError, true, "input that fails the schema is a tool error, not a call");
  assert.deepEqual(log.lines, ["refused get_mesh_info", "Test Agent called get_mesh_info", "Test Agent called call_remote_tool"]);

  controller.abort();
  assert.equal((await info.execute(await signCall(agent, "get_mesh_info", {}))).isError, true, "a tool held past the abort no longer reaches the session");
});

test("an agent's cancel stops that call on the mesh", async () => {
  let reached = () => {};
  const reachedMesh = new Promise<void>((resolve) => { reached = resolve; });
  const session = {
    peerId: Identity.generate().peerId, routers: [], isHeldRouter: () => false,
    node: { getPeers: () => [] },
    async discover() { return []; },
    openMCP(_peer: string, _service: string, options: { signal?: AbortSignal }): Promise<never> {
      reached();
      return new Promise((_resolve, reject) => { options.signal?.addEventListener("abort", () => { reject(options.signal?.reason); }, { once: true }); });
    },
  };
  const registered: Registered[] = [];
  await registerWebMCPTools({ registerTool(tool) { registered.push(tool); } }, meshTools(session), new CallVerifier(() => [agent]), recorder(), new AbortController().signal);
  const cancel = new AbortController();

  const input = await signCall(agent, "describe_remote_tool", { peer_id: Identity.generate().peerId, tool_name: "mcp://calc/add" });
  const pending = registered.find((tool) => tool.name === "describe_remote_tool")!.execute(input, { signal: cancel.signal });
  await reachedMesh;
  cancel.abort(new Error("the agent cancelled"));

  assert.deepEqual((await pending).content, [{ type: "text", text: "the agent cancelled" }]);
});
