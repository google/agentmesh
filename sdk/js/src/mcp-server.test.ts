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
import { test, type TestContext } from "node:test";
import { once } from "node:events";
import { createServer } from "node:http";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { peerIdFromString } from "@libp2p/peer-id";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolRequestSchema, CallToolResultSchema, ListToolsRequestSchema, type Tool } from "@modelcontextprotocol/sdk/types.js";
import { createMeshMCPServer } from "./mcp-server.ts";
import { Identity } from "./identity.ts";
import { AuthRejectedError } from "./auth.ts";
import type { MCPSessionOptions, MCPSession } from "./mcp.ts";

// Protocol-level fixture: real MCP client/server transports, a stub mesh
// session. Authentication and persisted enrollment are tested with Go nodes
// in TestNativeSDKMCPStdio, not simulated here.
async function fixture(t: TestContext, mode = "normal") {
  const peerId = Identity.generate().peerId;
  const self = Identity.generate().peerId;
  const stalled = Identity.generate().peerId;
  const calls: { service: string; name: string; args: unknown; labels: unknown }[] = [];
  let opened = 0, closed = 0;
  let markStarted!: () => void, markFinished!: () => void;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  const finished = new Promise<void>((resolve) => { markFinished = resolve; });
  const tool: Tool = { name: "add", description: "add numbers", inputSchema: { type: "object", properties: { a: { type: "number" } } }, outputSchema: { type: "object", properties: { answer: { type: "number" } } } };
  const session = {
    peerId: self, routers: [], isHeldRouter: () => false,
    node: { getPeers: () => [peerIdFromString(peerId)] },
    async discover() { return mode === "stalled" ? [{ peerId: stalled, addrs: [] }, { peerId, addrs: [] }] : [{ peerId, addrs: [] }]; },
    async openMCP(peer: unknown, service: string, options: MCPSessionOptions = {}): Promise<MCPSession> {
      if ((peer as { peerId?: string }).peerId === stalled) {
        // A provider that never answers; only the caller's deadline ends it.
        return new Promise<never>((_resolve, reject) => { options.signal?.addEventListener("abort", () => { reject(options.signal!.reason); }, { once: true }); });
      }
      if (service === "mcp://denied") throw new AuthRejectedError(peerId, "not granted");
      opened++;
      const remote = new Server({ name: "fixture", version: "1" }, { capabilities: { tools: {} } });
      remote.setRequestHandler(ListToolsRequestSchema, async (req) => {
        if (mode === "loop") return { tools: [], nextCursor: "again" };
        if (req.params?.cursor === undefined) return { tools: [{ ...tool, name: "first" }], nextCursor: "second" };
        return { tools: [tool] };
      });
      remote.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
        if (mode === "hang") {
          markStarted();
          await new Promise<void>((resolve) => { extra.signal.addEventListener("abort", () => { resolve(); }, { once: true }); });
        }
        calls.push({ service, name: req.params.name, args: req.params.arguments, labels: options.requiredLabels });
        if (service === "system://mesh.catalog") return { content: [{ type: "text", text: JSON.stringify([{ type: 1, name: "calc", description: "calculator" }, { type: 1, name: "denied" }]) }] };
        return { content: [{ type: "text", text: "3" }, { type: "image", data: "AA==", mimeType: "image/png" }], structuredContent: { answer: 3 }, isError: mode === "error" };
      });
      const [a, b] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: "fixture-client", version: "1" });
      await remote.connect(a);
      await client.connect(b);
      return {
        client, provider: {} as MCPSession["provider"],
        async close() { closed++; await client.close(); await remote.close(); markFinished(); },
      };
    },
  };
  const server = createMeshMCPServer(session, "1");
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "1" });
  await server.connect(a);
  await client.connect(b);
  t.after(async () => { await client.close(); await server.close(); assert.equal(closed, opened, "every remote session closes"); });
  return { client, calls, peerId, self, stalled, tool, started, finished };
}

function payload(result: unknown): unknown {
  const content = CallToolResultSchema.parse(result).content[0];
  assert.equal(content?.type, "text");
  return JSON.parse((content as { text: string }).text);
}

test("stdio surface exposes exactly the five caller tools and their parameter contracts", async (t) => {
  const { client } = await fixture(t);
  const expected: Record<string, string[]> = {
    get_mesh_info: [], discover_remote_services: ["type", "name", "limit", "offset"],
    find_remote_tools: ["intent", "peer_id", "service_name", "tool_name"],
    describe_remote_tool: ["peer_id", "tool_name"],
    call_remote_tool: ["peer_id", "tool_name", "arguments", "required_labels"],
  };
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((x) => x.name).sort(), Object.keys(expected).sort());
  for (const tool of tools) assert.deepEqual(Object.keys(tool.inputSchema.properties ?? {}).sort(), expected[tool.name]!.sort());
});

test("remote calls preserve structured/non-text results and pass required labels to authenticated open", async (t) => {
  const { client, calls, peerId } = await fixture(t);
  const result = await client.callTool({ name: "call_remote_tool", arguments: { peer_id: peerId, tool_name: "mcp://calc/add", arguments: { a: 1, b: 2 }, required_labels: "region=eu,team=platform" } });
  assert.deepEqual(result.structuredContent, { answer: 3 });
  assert.equal((result.content as { type: string }[])[1]?.type, "image");
  assert.deepEqual(calls[0]?.args, { a: 1, b: 2 });
  assert.deepEqual({ ...calls[0]?.labels as object }, { region: "eu", team: "platform" });
  assert.equal(calls[0]?.service, "mcp://calc");
  assert.equal(calls[0]?.name, "add");
});

test("remote isError stays an MCP tool failure", async (t) => {
  const { client, peerId } = await fixture(t, "error");
  const result = await client.callTool({ name: "call_remote_tool", arguments: { peer_id: peerId, tool_name: "mcp://calc/add" } });
  assert.equal(result.isError, true);
});

test("invalid names, stringified arguments and malformed labels never invoke a remote tool", async (t) => {
  const { client, calls, peerId } = await fixture(t);
  for (const args of [
    { peer_id: peerId, tool_name: "system://catalog/list_local_services" },
    { peer_id: peerId, tool_name: "mcp://calc/add", arguments: "{}" },
    { peer_id: peerId, tool_name: "mcp://calc/add", required_labels: "region" },
    { peer_id: peerId, tool_name: "mcp://calc/add", required_labels: "region=eu,region=us" },
    { peer_id: peerId, tool_name: "mcp://calc?scope=all/add" },
    { peer_id: peerId, tool_name: "mcp://calc/" },
    { peer_id: "not-a-peer", tool_name: "mcp://calc/add" },
  ]) {
    const result = await client.callTool({ name: "call_remote_tool", arguments: args });
    assert.equal(result.isError, true, JSON.stringify(args));
  }
  assert.equal(calls.length, 0);
});

test("describe follows pagination and preserves both schemas", async (t) => {
  const { client, peerId, tool } = await fixture(t);
  assert.deepEqual(payload(await client.callTool({ name: "describe_remote_tool", arguments: { peer_id: peerId, tool_name: "mcp://calc/add" } })), {
    peer_id: peerId, tool_name: "mcp://calc/add", description: tool.description,
    input_schema: tool.inputSchema, output_schema: tool.outputSchema,
  });
});

test("looping pagination fails and closes the remote session", async (t) => {
  const { client, peerId } = await fixture(t, "loop");
  const result = await client.callTool({ name: "describe_remote_tool", arguments: { peer_id: peerId, tool_name: "mcp://calc/add" } });
  assert.equal(result.isError, true);
  assert.match(JSON.stringify(result), /unbounded tool catalog/);
});

test("find confirms tools, applies filters, omits unauthorized services and rejects self", async (t) => {
  const { client, peerId, self } = await fixture(t);
  const result = await client.callTool({ name: "find_remote_tools", arguments: { tool_name: "add", intent: "accepted but ignored" } });
  assert.deepEqual(payload(result), [{ peer_id: peerId, tool_name: "mcp://calc/add", description: "add numbers" }]);
  assert.deepEqual(payload(await client.callTool({ name: "find_remote_tools", arguments: { service_name: "missing" } })), []);
  assert.equal((await client.callTool({ name: "find_remote_tools", arguments: { peer_id: self } })).isError, true);
});

test("discovery returns service metadata without inventing an HTTP proxy", async (t) => {
  const { client, calls, peerId } = await fixture(t);
  // A named lookup is answered by the directory alone, as in agentmesh-node.
  assert.deepEqual(payload(await client.callTool({ name: "discover_remote_services", arguments: { type: "MCP", name: "calc" } })), [{ peer_id: peerId, srv_name: "mcp://calc", srv_description: "" }]);
  assert.equal(calls.length, 0);
  assert.deepEqual(payload(await client.callTool({ name: "discover_remote_services", arguments: { type: "mcp" } })), [
    { peer_id: peerId, srv_name: "mcp://calc", srv_description: "calculator" },
    { peer_id: peerId, srv_name: "mcp://denied", srv_description: "" },
  ]);
  assert.deepEqual(payload(await client.callTool({ name: "discover_remote_services", arguments: { type: "mcp", offset: 99 } })), []);
  assert.equal((await client.callTool({ name: "discover_remote_services", arguments: { type: "invalid" } })).isError, true);
});

test("CLI configuration failures and help write no non-MCP stdout", async () => {
  for (const args of [[], ["--help"], ["--token", "must-not-appear"]]) {
    const env = { ...process.env };
    for (const key of Object.keys(env)) if (key.startsWith("AGENTMESH_")) delete env[key];
    const child = spawn(process.execPath, [fileURLToPath(new URL("./cli.js", import.meta.url)), ...args], { env });
    let stdout = "", stderr = "";
    child.stdout.on("data", (data) => { stdout += String(data); });
    child.stderr.on("data", (data) => { stderr += String(data); });
    child.stdin.end();
    const code = await new Promise<number | null>((resolve, reject) => { child.once("exit", resolve); child.once("error", reject); });
    assert.equal(code, args[0] === "--help" ? 0 : 1);
    assert.equal(stdout, "");
    assert.ok(stderr.includes("AGENTMESH_"));
    assert.ok(!stderr.includes("must-not-appear"));
  }
});


test("CLI rejects relative credential and identity paths", async () => {
  for (const name of ["AGENTMESH_BOOTSTRAP_TOKEN_PATH", "AGENTMESH_JWT_PATH", "AGENTMESH_STATE_DIR"]) {
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const key of Object.keys(env)) if (key.startsWith("AGENTMESH_")) delete env[key];
    Object.assign(env, { AGENTMESH_CONTROL_PLANE_URL: "http://127.0.0.1:9", [name]: "relative/path" });
    const child = spawn(process.execPath, [fileURLToPath(new URL("./cli.js", import.meta.url))], { env });
    let stdout = "", stderr = "";
    child.stdout.on("data", (data) => { stdout += String(data); });
    child.stderr.on("data", (data) => { stderr += String(data); });
    child.stdin.end();
    const code = await new Promise<number | null>((resolve, reject) => { child.once("exit", resolve); child.once("error", reject); });
    assert.equal(code, 1, name);
    assert.equal(stdout, "");
    assert.match(stderr, new RegExp(`${name} must be an absolute path`));
  }
});

test("tool names retain path segments after the service name", async (t) => {
  const { client, calls, peerId } = await fixture(t);
  await client.callTool({ name: "call_remote_tool", arguments: { peer_id: peerId, tool_name: "mcp://calc/math/add" } });
  assert.equal(calls[0]?.service, "mcp://calc");
  assert.equal(calls[0]?.name, "math/add");
});

test("tool names may contain query and fragment characters", async (t) => {
  const { client, calls, peerId } = await fixture(t);
  await client.callTool({ name: "call_remote_tool", arguments: { peer_id: peerId, tool_name: "mcp://calc/add?x#y" } });
  assert.equal(calls[0]?.service, "mcp://calc");
  assert.equal(calls[0]?.name, "add?x#y");
});

test("a stalled provider costs only its own row in mesh-wide discovery", { timeout: 15_000 }, async (t) => {
  const { client, peerId, stalled } = await fixture(t, "stalled");
  const rows = payload(await client.callTool({ name: "find_remote_tools", arguments: {} })) as { peer_id: string; tool_name?: string; error?: string }[];
  assert.deepEqual(rows.filter((row) => !row.error).map((row) => [row.peer_id, row.tool_name]), [[peerId, "mcp://calc/add"], [peerId, "mcp://calc/first"]]);
  assert.equal(rows.find((row) => row.peer_id === stalled)?.error !== undefined, true);
  assert.deepEqual(payload(await client.callTool({ name: "discover_remote_services", arguments: { type: "mcp" } })), [
    { peer_id: peerId, srv_name: "mcp://calc", srv_description: "calculator" },
    { peer_id: peerId, srv_name: "mcp://denied", srv_description: "" },
  ]);
});

test("cancelling a remote call closes its mesh session", { timeout: 2000 }, async (t) => {
  const { client, peerId, started, finished } = await fixture(t, "hang");
  const abort = new AbortController();
  const result = client.callTool({ name: "call_remote_tool", arguments: { peer_id: peerId, tool_name: "mcp://calc/add" } }, undefined, { signal: abort.signal });
  const rejected = assert.rejects(result);
  await started;
  abort.abort();
  await rejected;
  await finished;
});

test("EOF and SIGTERM abort enrollment without leaving a process running", { timeout: 5000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "agentmesh-stdio-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const token = join(directory, "token");
  await writeFile(token, "test-bootstrap-token", { mode: 0o600 });
  for (const stop of ["eof", "signal"]) {
    let markRequested!: () => void;
    const requested = new Promise<void>((resolve) => { markRequested = resolve; });
    const controlPlane = createServer((_req, _res) => { markRequested(); });
    controlPlane.listen(0, "127.0.0.1");
    await once(controlPlane, "listening");
    t.after(() => { controlPlane.closeAllConnections(); controlPlane.close(); });
    const address = controlPlane.address();
    assert.ok(address && typeof address !== "string");
    const env = { ...process.env };
    for (const key of Object.keys(env)) if (key.startsWith("AGENTMESH_")) delete env[key];
    Object.assign(env, {
      AGENTMESH_CONTROL_PLANE_URL: `http://127.0.0.1:${address.port}`,
      AGENTMESH_STATE_DIR: join(directory, stop), AGENTMESH_BOOTSTRAP_TOKEN_PATH: token,
    });
    const child = spawn(process.execPath, [fileURLToPath(new URL("./cli.js", import.meta.url))], { env });
    t.after(() => { if (child.exitCode === null) child.kill("SIGKILL"); });
    let stdout = "", stderr = "";
    child.stdout.on("data", (data) => { stdout += String(data); });
    child.stderr.on("data", (data) => { stderr += String(data); });
    const closed = once(child, "close");
    await requested;
    if (stop === "eof") child.stdin.end();
    else child.kill("SIGTERM");
    const [code, signal] = await closed;
    assert.equal(code, 0, stderr);
    assert.equal(signal, null);
    assert.equal(stdout, "");
  }
});
