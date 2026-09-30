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

// The A2A ingress in one process: this SDK's /libp2p-http handler for one
// agent behind a js-libp2p host, called with this SDK's clients, including
// the fetch a session hands to clients built on fetch. The real sam-node as
// a caller is exercised by tests/integration.

import { yamux } from "@chainsafe/libp2p-yamux";
import { identify } from "@libp2p/identify";
import type { Connection, Libp2p } from "@libp2p/interface";
import { tcp } from "@libp2p/tcp";
import { tls } from "@libp2p/tls";
import { createLibp2p } from "libp2p";
import assert from "node:assert/strict";
import http from "node:http";
import { after, before, test } from "node:test";
import { loadBiscuit } from "./biscuit.ts";
import { ROLE_NODE } from "./controlplane.ts";
import {
  AGENT_CARD_PATH,
  HTTP_PROTOCOL,
  a2aEndpoint,
  admitIngress,
  fetchOverStream,
  httpIngressHandler,
  httpRequestOverStream,
  meshHTTPTarget,
  meshURL,
  rewriteAgentCard,
  splitMeshURL,
  type ProviderOptions,
} from "./libp2p-http.ts";
import { nodeIngressHandler, streamToNodeDuplex } from "./libp2p-http-node.ts";

type Wasm = Awaited<ReturnType<typeof loadBiscuit>>;

let wasm: Wasm;
let cpKeyPair: InstanceType<Wasm["KeyPair"]>;
let cpKey: Uint8Array;
let agent: Libp2p;
let listenerAgent: Libp2p;
let handlerAgent: Libp2p;
let caller: Libp2p;
let callerBiscuit: Uint8Array;
let guestBiscuit: Uint8Array;
let backend: http.Server;
let backendURL: string;
const backendSeen: { method: string; url: string; peer: string | undefined; body: string; encoding: string | undefined }[] = [];
const listenerSeen: { url: string; peer: string | undefined; biscuit: string | undefined }[] = [];
const authorized: string[] = [];

function mint(peerId: string, role: string, extra: string[] = []): Uint8Array {
  const b = wasm.Biscuit.builder();
  b.addFact(wasm.Fact.fromString(`node(${JSON.stringify(peerId)})`));
  b.addFact(wasm.Fact.fromString(`client_peer_id(${JSON.stringify(peerId)})`));
  b.addFact(wasm.Fact.fromString("expiration(2035-01-01T00:00:00Z)"));
  b.addFact(wasm.Fact.fromString(`role(${JSON.stringify(role)})`));
  for (const f of extra) {
    b.addFact(wasm.Fact.fromString(f));
  }
  return b.build(cpKeyPair.getPrivateKey()).toBytes();
}

function newHost(): Promise<Libp2p> {
  return createLibp2p({
    addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
    transports: [tcp()],
    connectionEncrypters: [tls()],
    streamMuxers: [yamux()],
    services: { identify: identify() },
  });
}

// What the control plane renders for a policy granting the node role every
// A2A service on any target, and nothing else.
const POLICY_RULES = [
  `granted_service_all("a2a") <- role("sam:role:node")`,
  `granted_service_all("sam:system") <- role("sam:role:node")`,
  `target_unrestricted(true) <- role("sam:role:node")`,
];

function providerOptions(biscuit: Uint8Array): ProviderOptions {
  return {
    trustedKeys: () => [cpKey],
    ownBiscuit: () => biscuit,
    policyRules: () => POLICY_RULES,
    onAuthorized: (peerId, _v, service) => authorized.push(`${peerId} ${service}`),
  };
}

const STOCK_CARD = {
  name: "echo-agent",
  version: "1.0.0",
  capabilities: { streaming: true, pushNotifications: false },
  supportedInterfaces: [
    { url: "http://127.0.0.1:7777/", protocolBinding: "JSONRPC", protocolVersion: "1.0" },
    { url: "127.0.0.1:50051", protocolBinding: "GRPC", protocolVersion: "1.0" },
  ],
  signatures: [{ protected: "eyJhbGciOiJFUzI1NiJ9", signature: "c3RhbGU" }],
  skills: [],
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain"],
};

// Stands in for an A2A server beside the agent: echoes the request and, on
// /stream, answers with three SSE events as message/stream would.
function fakeA2AServer(req: http.IncomingMessage, res: http.ServerResponse): void {
  let body = "";
  req.on("data", (c: Buffer) => (body += c.toString()));
  req.on("end", () => {
    backendSeen.push({ method: req.method ?? "", url: req.url ?? "", peer: req.headers["x-peer-id"] as string | undefined, body, encoding: req.headers["accept-encoding"] as string | undefined });
    assert.equal(req.headers["x-sam-biscuit"], undefined, "biscuit leaked to the backend");
    if (req.url === `/${AGENT_CARD_PATH}` && req.headers["x-card"] === "missing") {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("no card");
      return;
    }
    if (req.url === `/${AGENT_CARD_PATH}`) {
      const grpcOnly = req.headers["x-card"] === "grpc-only";
      const supportedInterfaces = STOCK_CARD.supportedInterfaces.filter((i) => !grpcOnly || i.protocolBinding === "GRPC");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ...STOCK_CARD, supportedInterfaces }));
      return;
    }
    if (req.url === "/stream") {
      res.writeHead(200, { "content-type": "text/event-stream" });
      let i = 0;
      const tick = () => {
        res.write(`data: ${JSON.stringify({ event: i })}\n\n`);
        if (++i < 3) {
          setTimeout(tick, 10);
        } else {
          res.end();
        }
      };
      tick();
      return;
    }
    res.writeHead(200, { "content-type": "application/json", "x-backend": "fake" });
    res.end(JSON.stringify({ path: req.url, echo: body }));
  });
}

before(async () => {
  wasm = await loadBiscuit();
  cpKeyPair = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
  cpKey = new Uint8Array(Buffer.from(cpKeyPair.getPublicKey().toString().replace(/^ed25519\//, ""), "hex"));

  backend = http.createServer(fakeA2AServer);
  await new Promise<void>((resolve) => backend.listen(0, "127.0.0.1", resolve));
  backendURL = `http://127.0.0.1:${(backend.address() as { port: number }).port}`;

  // An agent forwarding to a server beside it.
  agent = await newHost();
  await agent.handle(HTTP_PROTOCOL, httpIngressHandler(a2aEndpoint({ url: backendURL }), providerOptions(mint(agent.peerId.toString(), ROLE_NODE))), {
    runOnLimitedConnection: true,
  });

  // An agent answering with a Node request listener in the process, as an
  // Express app carrying the A2A SDK's handlers would.
  listenerAgent = await newHost();
  const listener = (req: http.IncomingMessage, res: http.ServerResponse) => {
    listenerSeen.push({ url: req.url ?? "", peer: req.headers["x-peer-id"] as string | undefined, biscuit: req.headers["x-sam-biscuit"] as string | undefined });
    res.writeHead(202, { "content-type": "text/plain" });
    res.end(`listener ${req.method} ${req.url}`);
  };
  await listenerAgent.handle(
    HTTP_PROTOCOL,
    nodeIngressHandler(a2aEndpoint({ name: "worker", listener }), providerOptions(mint(listenerAgent.peerId.toString(), ROLE_NODE))),
    { runOnLimitedConnection: true },
  );

  // An agent answering with a fetch handler, the shape a browser member uses:
  // echoes what it was given and, on /stream, writes three SSE events one at
  // a time into a streaming body.
  handlerAgent = await newHost();
  const handler = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.pathname === "/stream") {
      const encoder = new TextEncoder();
      let i = 0;
      const body = new ReadableStream<Uint8Array>({
        async pull(controller) {
          await new Promise((r) => setTimeout(r, 10));
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ event: i })}\n\n`));
          if (++i === 3) {
            controller.close();
          }
        },
      });
      return new Response(body, { headers: { "content-type": "text/event-stream" } });
    }
    if (url.pathname === "/sized") {
      // An agent that declares its length, as a static file server would.
      return new Response(request.method === "HEAD" ? null : "x".repeat(42), { headers: { "content-type": "text/plain", "content-length": "42" } });
    }
    return Response.json({ path: url.pathname + url.search, method: request.method, peer: request.headers.get("x-peer-id"), biscuit: request.headers.get("x-sam-biscuit"), echo: await request.text() });
  };
  await handlerAgent.handle(HTTP_PROTOCOL, httpIngressHandler(a2aEndpoint({ handler }), providerOptions(mint(handlerAgent.peerId.toString(), ROLE_NODE))), {
    runOnLimitedConnection: true,
  });

  caller = await newHost();
  callerBiscuit = mint(caller.peerId.toString(), ROLE_NODE);
  guestBiscuit = mint(caller.peerId.toString(), "sam:role:guest");
});

after(async () => {
  await caller.stop();
  await agent.stop();
  await listenerAgent.stop();
  await handlerAgent.stop();
  await new Promise<void>((resolve) => backend.close(() => resolve()));
});

async function dial(to: Libp2p = agent): Promise<Connection> {
  return caller.dial(to.getMultiaddrs()[0] as Parameters<typeof caller.dial>[0]);
}

test("the agent is forwarded the request with the caller's identity and without its biscuit", async () => {
  const conn = await dial();
  const res = await httpRequestOverStream(conn, callerBiscuit, "a2a://agent", "/card?x=1", { headers: { "x-sam-biscuit": "spoof" } });
  assert.equal(res.status, 200);
  assert.equal(res.headers["x-backend"], "fake");
  assert.deepEqual(JSON.parse(res.text()), { path: "/card?x=1", echo: "" });
  assert.equal(backendSeen.at(-1)?.peer, caller.peerId.toString());
  assert.ok(authorized.includes(`${caller.peerId.toString()} a2a://agent`));

  const post = await httpRequestOverStream(conn, callerBiscuit, "a2a://agent", "/", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0" }),
  });
  assert.equal(post.status, 200);
  assert.equal(JSON.parse(post.text()).echo, JSON.stringify({ jsonrpc: "2.0" }));
});

test("a fetch over the stream delivers an SSE body event by event", async () => {
  const conn = await dial();
  const url = meshURL(agent.peerId.toString(), "a2a://agent", "/stream");
  assert.equal(url, `http://mesh/sam/${agent.peerId.toString()}/a2a/agent/stream`);
  const response = await fetchOverStream(conn, callerBiscuit, new Request(url));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/event-stream");
  const chunks: string[] = [];
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  for (let next = await reader.read(); !next.done; next = await reader.read()) {
    chunks.push(new TextDecoder().decode(next.value));
  }
  // Three events, each flushed by the server before the next one was written.
  assert.ok(chunks.length >= 3, `want at least three chunks, got ${JSON.stringify(chunks)}`);
  assert.deepEqual(
    chunks
      .join("")
      .split("\n")
      .filter((l) => l.startsWith("data:")),
    ['data: {"event":0}', 'data: {"event":1}', 'data: {"event":2}'],
  );
});

test("the card of an agent behind a node comes back rewritten for the mesh, as sam-node serves it", async () => {
  const conn = await dial();
  const base = meshURL(agent.peerId.toString(), "a2a://agent");
  const response = await fetchOverStream(conn, callerBiscuit, new Request(`${base}/${AGENT_CARD_PATH}`));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json");
  const card = (await response.json()) as Record<string, unknown>;
  assert.deepEqual(card.supportedInterfaces, [{ url: base, protocolBinding: "JSONRPC", protocolVersion: "1.0" }]);
  assert.deepEqual(card.capabilities, { streaming: true, pushNotifications: false });
  assert.equal("signatures" in card, false);
  assert.equal(card.name, "echo-agent");
  assert.deepEqual(card.skills, []);
  assert.equal(backendSeen[backendSeen.length - 1]?.url, `/${AGENT_CARD_PATH}`);

  // The bare service root serves the card too, the way a2a-go resolves a pathful base URL.
  assert.deepEqual(await (await fetchOverStream(conn, callerBiscuit, new Request(base))).json(), card);
  assert.equal(backendSeen[backendSeen.length - 1]?.url, `/${AGENT_CARD_PATH}`);
  await fetchOverStream(conn, callerBiscuit, new Request(`${base}/${AGENT_CARD_PATH}`, { headers: { "accept-encoding": "x-test-only" } }));
  assert.notEqual(backendSeen[backendSeen.length - 1]?.encoding, "x-test-only", "the client's accept-encoding reached the agent");

  const missing = await fetchOverStream(conn, callerBiscuit, new Request(`${base}/${AGENT_CARD_PATH}`, { headers: { "x-card": "missing" } }));
  assert.equal(missing.status, 404);
  assert.equal(await missing.text(), "no card");

  const raw = await httpRequestOverStream(conn, callerBiscuit, "a2a://agent", `/${AGENT_CARD_PATH}`);
  assert.deepEqual(JSON.parse(raw.text()), card);

  const refused = await fetchOverStream(conn, callerBiscuit, new Request(`${base}/${AGENT_CARD_PATH}`, { headers: { "x-card": "grpc-only" } }));
  assert.equal(refused.status, 502);
  assert.match(await refused.text(), /no supported interface the mesh can carry/);

  const other = await fetchOverStream(conn, callerBiscuit, new Request(`${base}/card`));
  assert.deepEqual(await other.json(), { path: "/card", echo: "" });
});

test("rewriteAgentCard keeps only what the mesh carries", () => {
  assert.throws(() => rewriteAgentCard([], "http://mesh/x"), /not a JSON object/);
  assert.throws(() => rewriteAgentCard({ supportedInterfaces: [] }, "http://mesh/x"), /no supported interface/);
  assert.deepEqual(rewriteAgentCard({ supportedInterfaces: [{ url: "x", protocolBinding: "http+json" }] }, "http://mesh/x"), {
    supportedInterfaces: [{ url: "http://mesh/x", protocolBinding: "http+json" }],
  });
});

test("a fetch handler sees the caller and the path, and its streaming body goes out as it is written", async () => {
  const conn = await dial(handlerAgent);
  const res = await httpRequestOverStream(conn, callerBiscuit, "a2a://agent", "/tasks?x=1", { method: "POST", headers: { "x-sam-biscuit": "spoof", "content-type": "text/plain" }, body: "hello" });
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.text()), { path: "/tasks?x=1", method: "POST", peer: caller.peerId.toString(), biscuit: null, echo: "hello" });

  // HEAD: the head a GET would get, the declared length kept, no body sent.
  const sized = await httpRequestOverStream(conn, callerBiscuit, "a2a://agent", "/sized");
  assert.equal(sized.text(), "x".repeat(42));
  const head = await httpRequestOverStream(conn, callerBiscuit, "a2a://agent", "/sized", { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(head.headers["content-length"], "42");
  assert.equal(head.headers["content-type"], "text/plain");
  assert.equal(head.body.length, 0);
  // A handler that built a body for HEAD anyway: no length is invented.
  const headJson = await httpRequestOverStream(conn, callerBiscuit, "a2a://agent", "/card", { method: "HEAD" });
  assert.equal(headJson.status, 200);
  assert.equal(headJson.headers["content-length"], undefined);
  assert.equal(headJson.body.length, 0);

  const response = await fetchOverStream(conn, callerBiscuit, new Request(meshURL(handlerAgent.peerId.toString(), "a2a://agent", "/stream")));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/event-stream");
  const chunks: string[] = [];
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  for (let next = await reader.read(); !next.done; next = await reader.read()) {
    chunks.push(new TextDecoder().decode(next.value));
  }
  assert.ok(chunks.length >= 3, `want at least three chunks, got ${JSON.stringify(chunks)}`);
  assert.deepEqual(chunks.join("").split("\n").filter((l) => l.startsWith("data:")), ['data: {"event":0}', 'data: {"event":1}', 'data: {"event":2}']);

  // Node's own client reads the chunked response the ingress writes.
  const stream = await conn.newStream(HTTP_PROTOCOL, { runOnLimitedConnection: true });
  const socket = streamToNodeDuplex(stream, handlerAgent.peerId.toString());
  const viaNode = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = http.request(
      { method: "GET", path: "/a2a/agent/card", headers: { host: handlerAgent.peerId.toString(), "x-sam-biscuit": Buffer.from(callerBiscuit).toString("base64") }, createConnection: () => socket },
      (r) => {
        let body = "";
        r.on("data", (c: Buffer) => (body += c.toString()));
        r.on("end", () => resolve({ status: r.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    req.end();
  });
  socket.destroy();
  assert.equal(viaNode.status, 200);
  assert.equal(JSON.parse(viaNode.body).path, "/card");
});

test("a Node request listener sees the path relative to the agent and the verified caller", async () => {
  const conn = await dial(listenerAgent);
  const res = await httpRequestOverStream(conn, callerBiscuit, "a2a://worker", "/tasks/1?q=1", { method: "POST", headers: { "x-sam-biscuit": "spoof" }, body: "{}" });
  assert.equal(res.status, 202);
  assert.equal(res.text(), "listener POST /tasks/1?q=1");
  assert.deepEqual(listenerSeen.at(-1), { url: "/tasks/1?q=1", peer: caller.peerId.toString(), biscuit: undefined });
  // The listener answers only its own name.
  assert.equal((await httpRequestOverStream(conn, callerBiscuit, "a2a://agent", "/")).status, 404);
});

test("what the policy does not grant is refused before the agent is reached", async () => {
  const conn = await dial();
  const before = backendSeen.length;
  assert.equal((await httpRequestOverStream(conn, guestBiscuit, "a2a://agent", "/card")).status, 403);
  // The node role is granted a2a only.
  assert.equal((await httpRequestOverStream(conn, callerBiscuit, "inference://agent", "/")).status, 403);
  assert.equal(backendSeen.length, before);
  // Granted, but not this agent: 404 after authorization.
  assert.equal((await httpRequestOverStream(conn, callerBiscuit, "a2a://other", "/card")).status, 404);
});

test("the ingress rejects a request without a biscuit and a dotted path", async () => {
  const conn = await dial();
  // An empty biscuit encodes to an empty header, which the server treats as missing.
  assert.equal((await httpRequestOverStream(conn, new Uint8Array(), "a2a://agent", "/card")).status, 401);
  // The fetch client normalizes a dot segment away before it leaves, so the
  // server's own check is reached with a raw request.
  const stream = await conn.newStream(HTTP_PROTOCOL, { runOnLimitedConnection: true });
  const socket = streamToNodeDuplex(stream, agent.peerId.toString());
  const status = await new Promise<number>((resolve, reject) => {
    const req = http.request(
      { method: "GET", path: "/a2a/agent/../other/x", headers: { host: agent.peerId.toString(), "x-sam-biscuit": Buffer.from(callerBiscuit).toString("base64") }, createConnection: () => socket },
      (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      },
    );
    req.on("error", reject);
    req.end();
  });
  socket.destroy();
  assert.equal(status, 400);
});

test("a dot segment is refused however it is spelled", async () => {
  const endpoint = a2aEndpoint({ handler: () => new Response() });
  // Nothing in options is consulted before the path check.
  const options = providerOptions(new Uint8Array());
  for (const target of ["/a2a/agent/../x", "/a2a/agent/./x", "/a2a/agent/%2e%2e/x", "/a2a/agent/%2E%2E/x", "/a2a/agent/.%2e/x", "/a2a/agent/%2e/x", "/a2a/%2e%2e/other/x?q=1"]) {
    assert.deepEqual(await admitIngress({ method: "GET", target, headers: new Headers(), remotePeer: "peer" }, endpoint, options), { status: 400, text: "Invalid path" }, target);
  }
  // Not dot segments: the request reaches the next check, the missing biscuit.
  for (const target of ["/a2a/agent/%2e%2ex/x", "/a2a/agent/..x/x", "/a2a/agent/x?p=../y"]) {
    assert.deepEqual(await admitIngress({ method: "GET", target, headers: new Headers(), remotePeer: "peer" }, endpoint, options), { status: 401, text: "Missing X-Sam-Biscuit header" }, target);
  }
});

test("mesh URLs name a peer and a service", () => {
  const peer = "12D3KooWJ2Yhy3CKwVPDw7AnkxN5HbZbb65xDoRif54hdXXUzh1U";
  assert.deepEqual(splitMeshURL(new URL(`http://mesh/sam/${peer}/a2a/agent`)), { peerId: peer, target: "/a2a/agent" });
  assert.deepEqual(splitMeshURL(new URL(`http://anything:1/sam/${peer}/inference/llm/v1/models?x=1`)), { peerId: peer, target: "/inference/llm/v1/models?x=1" });
  for (const bad of ["http://mesh/a2a/agent", `http://mesh/sam/${peer}`, `http://mesh/sam/${peer}/a2a`, "http://mesh/sam//a2a/agent"]) {
    assert.throws(() => splitMeshURL(new URL(bad)), TypeError);
  }
  assert.equal(meshHTTPTarget("a2a://agent"), "/a2a/agent");
  assert.equal(meshHTTPTarget("a2a://agent", "card"), "/a2a/agent/card");
  assert.equal(meshHTTPTarget("egress://api.github.com", "/repos/acme/x"), "/egress/api.github.com/repos/acme/x");
  assert.throws(() => meshHTTPTarget("ftp://agent", "/"));
  assert.throws(() => a2aEndpoint({}), /exactly one/);
  assert.throws(() => a2aEndpoint({ url: "http://x", handler: () => new Response() }), /exactly one/);
});
