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
import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer, type AddressInfo, type Socket } from "node:net";
import { test } from "node:test";
import { RelayBridgeServer } from "@mcp-b/webmcp-local-relay";
import { requestToolsAfterJoin } from "./relay-join.ts";

const TOOLS = {
  tools: [{ name: "get_mesh_info", inputSchema: { type: "object", properties: {} } }],
  sources: [{ sourceId: "page", tabId: "tab", connectedAt: 0, lastSeenAt: 0, toolCount: 1 }],
  toolSourceMap: { get_mesh_info: ["page"] },
};

/** One WebSocket text frame as a server sends it: not masked. */
function frame(message: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(message));
  assert.ok(payload.length < 0x10000, "a test message fits a 16-bit length");
  const header = payload.length < 126 ? Buffer.from([0x81, payload.length]) : Buffer.from([0x81, 126, payload.length >> 8, payload.length & 0xff]);
  return Buffer.concat([header, payload]);
}

/** The text messages of the complete client frames at the start of data, and the bytes left after them. */
function clientMessages(data: Buffer): { messages: { type?: string }[]; closed: boolean; rest: Buffer } {
  const messages: { type?: string }[] = [];
  let closed = false;
  let at = 0;
  for (;;) {
    if (data.length - at < 2) break;
    const opcode = data.readUInt8(at) & 0x0f;
    let length = data.readUInt8(at + 1) & 0x7f;
    let header = 2;
    if (length === 126) {
      if (data.length - at < 4) break;
      length = data.readUInt16BE(at + 2);
      header = 4;
    }
    assert.notEqual(length, 127, "a relay client message fits a 16-bit length");
    // A client masks every frame: four key bytes come before the payload.
    if (data.length - at < header + 4 + length) break;
    const key = data.subarray(at + header, at + header + 4);
    const payload = Buffer.from(data.subarray(at + header + 4, at + header + 4 + length));
    for (let i = 0; i < payload.length; i++) payload[i] = payload.readUInt8(i) ^ key.readUInt8(i % 4);
    if (opcode === 0x1) messages.push(JSON.parse(payload.toString()) as { type?: string });
    if (opcode === 0x8) closed = true;
    at += header + 4 + length;
  }
  return { messages, closed, rest: data.subarray(at) };
}

/**
 * A relay in server mode, reduced to what a joining relay needs. It answers
 * the first relay/list-tools with its hello and the tool list in one write, so
 * the client reads the two together, as it does on a loaded machine. It
 * answers each later relay/list-tools with the tool list.
 */
async function startRelayServer(): Promise<{ port: number; listRequests: () => number; close: () => Promise<void> }> {
  let listRequests = 0;
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    let upgraded = false;
    let pending: Buffer = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      if (!upgraded) {
        const end = pending.indexOf("\r\n\r\n");
        if (end < 0) return;
        const request = pending.subarray(0, end).toString();
        pending = pending.subarray(end + 4);
        const key = /^sec-websocket-key:\s*(\S+)/im.exec(request)?.[1] ?? "";
        const protocol = /^sec-websocket-protocol:\s*([^\s,]+)/im.exec(request)?.[1] ?? "";
        const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
        socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: ${protocol}\r\n\r\n`);
        upgraded = true;
      }
      const { messages, closed, rest } = clientMessages(pending);
      pending = rest;
      for (const message of messages) {
        if (message.type !== "relay/list-tools") continue;
        listRequests++;
        const tools = frame({ type: "relay/tools", ...TOOLS });
        if (listRequests === 1) {
          const hello = frame({ type: "server-hello", service: "webmcp-local-relay", version: 1, host: "127.0.0.1", instanceId: "test-relay", port: (server.address() as AddressInfo).port });
          socket.write(Buffer.concat([hello, tools]));
        } else {
          socket.write(tools);
        }
      }
      if (closed) socket.end();
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    port: (server.address() as AddressInfo).port,
    listRequests: () => listRequests,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      server.close();
      await once(server, "close");
    },
  };
}

// Without requestToolsAfterJoin the relay stays with no tool here: the tool list
// that comes with the hello is lost, and this server sends no other one.
test("a relay that joins another relay has the page's tools when the hello and the tool list arrive together", async (t) => {
  const server = await startRelayServer();
  t.after(() => server.close());
  const bridge = new RelayBridgeServer({ host: "127.0.0.1", port: server.port });
  const logged: string[] = [];
  requestToolsAfterJoin(bridge, (line) => logged.push(line));
  t.after(() => bridge.stop());

  await bridge.start();
  assert.equal(bridge.mode, "client", "the port is held, so the relay joins the relay that holds it");

  const deadline = AbortSignal.timeout(5_000);
  try {
    while (bridge.listToolsFromRelay().length === 0) await once(bridge, "stateChanged", { signal: deadline });
  } catch {
    assert.fail(`the relay has no tool after it joined: list requests = ${server.listRequests()}, logged = ${JSON.stringify(logged)}`);
  }
  assert.deepEqual(
    bridge.listToolsFromRelay().map((tool) => tool.name),
    ["get_mesh_info"],
  );
  assert.equal(server.listRequests(), 2, "one request of the relay's own handshake and one after the listener is attached");
  assert.deepEqual(logged, []);
});
