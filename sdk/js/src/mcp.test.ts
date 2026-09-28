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

// A provider in one process: a js-libp2p host that serves /sam/mcp/1.0.0
// the way sam-node does (AuthFrame in, AuthResponse out, then MCP over the
// stream) with the official MCP server behind it. The real sam-node is
// exercised by tests/integration/sdk_mesh_test.go.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { yamux } from "@chainsafe/libp2p-yamux";
import { identify } from "@libp2p/identify";
import type { Connection, Libp2p, Stream } from "@libp2p/interface";
import { tcp } from "@libp2p/tcp";
import { tls } from "@libp2p/tls";
import { lpStream } from "@libp2p/utils";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createLibp2p } from "libp2p";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { z } from "zod";
import { AuthRejectedError, MAX_AUTH_FRAME_BYTES, MCP_PROTOCOL } from "./auth.ts";
import { loadBiscuit, verifyPeerBiscuit } from "./biscuit.ts";
import { ROLE_NODE } from "./controlplane.ts";
import { parseServiceTarget, serviceCID } from "./discovery.ts";
import { AuthFrameSchema, AuthResponseSchema } from "./gen/sam_pb.ts";
import { Identity } from "./identity.ts";
import { LabelsNotSatisfiedError, StreamTransport, openMCPSession, requireEgressLabels, requireLabels } from "./mcp.ts";

type Wasm = Awaited<ReturnType<typeof loadBiscuit>>;

let wasm: Wasm;
let cpKeyPair: InstanceType<Wasm["KeyPair"]>;
let cpKey: Uint8Array;
let provider: Libp2p;
let providerBiscuit: Uint8Array;
let caller: Libp2p;
let callerBiscuit: Uint8Array;
const servedTargets: string[] = [];

function mint(peerId: string, role: string, labels: Record<string, string> = {}): Uint8Array {
  const b = wasm.Biscuit.builder();
  b.addFact(wasm.Fact.fromString(`node(${JSON.stringify(peerId)})`));
  b.addFact(wasm.Fact.fromString("expiration(2035-01-01T00:00:00Z)"));
  b.addFact(wasm.Fact.fromString(`role(${JSON.stringify(role)})`));
  for (const [k, v] of Object.entries(labels)) {
    b.addFact(wasm.Fact.fromString(`label(${JSON.stringify(k)}, ${JSON.stringify(v)})`));
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

/** sam-node's WithBiscuitAuth(HandleMCPStream) in miniature. */
async function serveMCP(stream: Stream, connection: Connection): Promise<void> {
  const auth = lpStream(stream, { maxDataLength: MAX_AUTH_FRAME_BYTES });
  const frame = fromBinary(AuthFrameSchema, (await auth.read()).subarray());
  try {
    await verifyPeerBiscuit(frame.biscuit, connection.remotePeer.toString(), [cpKey]);
  } catch {
    await stream.close();
    return;
  }
  const { type, name } = parseServiceTarget(frame.targetService);
  if (type !== "" && name !== "calc") {
    // An unknown service closes the stream after the frame, as sam-node does.
    await auth.write(toBinary(AuthResponseSchema, create(AuthResponseSchema, { success: true, biscuit: providerBiscuit })));
    await stream.close();
    return;
  }
  servedTargets.push(frame.targetService);
  await auth.write(toBinary(AuthResponseSchema, create(AuthResponseSchema, { success: true, biscuit: providerBiscuit })));

  const server = new McpServer({ name: type === "" ? "catalog" : "calc", version: "0.0.1" });
  if (type === "") {
    server.tool("list_local_services", async () => ({ content: [{ type: "text", text: JSON.stringify([{ type: "mcp", name: "calc" }]) }] }));
  } else {
    server.tool("add", { a: z.number(), b: z.number() }, async ({ a, b }) => ({ content: [{ type: "text", text: String(a + b) }] }));
  }
  await server.connect(new StreamTransport(stream));
}

before(async () => {
  wasm = await loadBiscuit();
  cpKeyPair = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
  cpKey = new Uint8Array(Buffer.from(cpKeyPair.getPublicKey().toString().replace(/^ed25519\//, ""), "hex"));
  provider = await newHost();
  providerBiscuit = mint(provider.peerId.toString(), ROLE_NODE, { region: "eu" });
  await provider.handle(MCP_PROTOCOL, (stream, connection) => void serveMCP(stream, connection), { runOnLimitedConnection: true });
  caller = await newHost();
  callerBiscuit = mint(caller.peerId.toString(), ROLE_NODE);
});

after(async () => {
  await caller.stop();
  await provider.stop();
});

function frame(target: string, biscuit = callerBiscuit): Uint8Array {
  return toBinary(AuthFrameSchema, create(AuthFrameSchema, { biscuit, targetService: target }));
}

test("service keys match internal/node/service.go", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../testdata/service_keys.json", import.meta.url), "utf8")) as {
    services: Array<{ type: "mcp" | "inference" | "a2a"; name: string; cid: string; multihash: string }>;
  };
  for (const s of fixture.services) {
    const cid = await serviceCID(s.type, s.name);
    assert.equal(cid.toString(), s.cid, `${s.type}:${s.name}`);
    assert.equal(Buffer.from(cid.multihash.bytes).toString("hex"), s.multihash);
  }
  assert.deepEqual(parseServiceTarget("mcp://calc"), { type: "mcp", name: "calc" });
  assert.deepEqual(parseServiceTarget("egress://api.github.com"), { type: "egress", name: "api.github.com" });
  assert.deepEqual(parseServiceTarget(""), { type: "", name: "" });
  assert.throws(() => parseServiceTarget("calc"), /must look like/);
});

test("a tool is listed and called over the mesh stream, and the provider is verified", async () => {
  const conn = await caller.dial(provider.getMultiaddrs()[0] as Parameters<typeof caller.dial>[0]);
  const mcp = await openMCPSession(conn, frame("mcp://calc"), [cpKey]);
  try {
    assert.equal(mcp.provider.peerId, provider.peerId.toString());
    assert.deepEqual(mcp.provider.labels, { region: "eu" });
    const { tools } = await mcp.client.listTools();
    assert.deepEqual(tools.map((t) => t.name), ["add"]);
    const result = await mcp.client.callTool({ name: "add", arguments: { a: 2, b: 3 } });
    assert.deepEqual(result.content, [{ type: "text", text: "5" }]);
  } finally {
    await mcp.close();
  }
  assert.ok(servedTargets.includes("mcp://calc"));
});

test("the empty target is the provider's own catalog", async () => {
  const conn = await caller.dial(provider.getMultiaddrs()[0] as Parameters<typeof caller.dial>[0]);
  const mcp = await openMCPSession(conn, frame(""), [cpKey]);
  try {
    const result = await mcp.client.callTool({ name: "list_local_services", arguments: {} });
    assert.match(JSON.stringify(result.content), /calc/);
  } finally {
    await mcp.close();
  }
});

test("required labels are checked on the provider's credential", async () => {
  const conn = await caller.dial(provider.getMultiaddrs()[0] as Parameters<typeof caller.dial>[0]);
  const ok = await openMCPSession(conn, frame("mcp://calc"), [cpKey], { requiredLabels: { region: "eu" } });
  await ok.close();
  await assert.rejects(openMCPSession(conn, frame("mcp://calc"), [cpKey], { requiredLabels: { region: "us" } }), LabelsNotSatisfiedError);
  assert.throws(() => requireLabels({ peerId: "p", expiration: new Date(), verifyingKey: cpKey, roles: [], labels: {} }, { team: "x" }), /team=x/);
});

test("a requirement of several labels is met by any one of them, as sam-node's checkPeerLabels", () => {
  // The cases of internal/node/labels_gate_test.go, run through the SDK's predicate.
  const attesting = (labels: Record<string, string>) => ({ peerId: "p", expiration: new Date(), verifyingKey: cpKey, roles: [], labels });
  // exact match
  requireLabels(attesting({ region: "us-east-1" }), { region: "us-east-1" });
  // any-of requirement matches one key
  requireLabels(attesting({ region: "na-us", team: "platform" }), { region: "eu", team: "platform" });
  // no built-in hierarchy: coarser requirement fails a finer claim
  assert.throws(() => requireLabels(attesting({ region: "us-east-1" }), { region: "us" }), LabelsNotSatisfiedError);
  // disjoint labels fail
  assert.throws(() => requireLabels(attesting({ region: "na-us" }), { region: "eu" }), LabelsNotSatisfiedError);
  // unattested token fails closed, naming every pair the caller asked for
  assert.throws(() => requireLabels(attesting({}), { region: "eu", team: "platform" }), /region=eu, team=platform/);
  // an empty requirement is no requirement
  requireLabels(attesting({}), {});
});

test("the egress floor is met only by every one of its pairs, as sam-node's api.LabelFloorCheck", () => {
  const attesting = (labels: Record<string, string>) => ({ peerId: "p", expiration: new Date(), verifyingKey: cpKey, roles: [], labels });
  requireEgressLabels(attesting({ region: "eu", team: "platform" }), { region: "eu" });
  requireEgressLabels(attesting({ region: "eu", team: "platform" }), { region: "eu", team: "platform" });
  // one pair short is a refusal that names the whole floor
  assert.throws(() => requireEgressLabels(attesting({ region: "eu" }), { region: "eu", team: "platform" }), /peer p does not attest the egress floor: region=eu, team=platform/);
  assert.throws(() => requireEgressLabels(attesting({ region: "us" }), { region: "eu" }), LabelsNotSatisfiedError);
  // no floor is no floor
  requireEgressLabels(attesting({}), {});
  requireEgressLabels(attesting({}), undefined);
});

test("the egress floor is held on the MCP path beside the caller's requirement", async () => {
  const conn = await caller.dial(provider.getMultiaddrs()[0] as Parameters<typeof caller.dial>[0]);
  const ok = await openMCPSession(conn, frame("mcp://calc"), [cpKey], {}, { region: "eu" });
  await ok.close();
  await assert.rejects(openMCPSession(conn, frame("mcp://calc"), [cpKey], {}, { region: "eu", team: "platform" }), LabelsNotSatisfiedError);
  // Both apply when both are set: neither one's pairs stand in for the other's.
  await assert.rejects(openMCPSession(conn, frame("mcp://calc"), [cpKey], { requiredLabels: { region: "eu" } }, { team: "platform" }), LabelsNotSatisfiedError);
  await assert.rejects(openMCPSession(conn, frame("mcp://calc"), [cpKey], { requiredLabels: { team: "platform" } }, { region: "eu" }), LabelsNotSatisfiedError);
});

test("a caller the provider cannot verify gets no session", async () => {
  const conn = await caller.dial(provider.getMultiaddrs()[0] as Parameters<typeof caller.dial>[0]);
  const forged = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
  const fb = wasm.Biscuit.builder();
  fb.addFact(wasm.Fact.fromString(`node(${JSON.stringify(caller.peerId.toString())})`));
  fb.addFact(wasm.Fact.fromString("expiration(2035-01-01T00:00:00Z)"));
  await assert.rejects(openMCPSession(conn, frame("mcp://calc", fb.build(forged.getPrivateKey()).toBytes()), [cpKey], { signal: AbortSignal.timeout(3000) }));
});

test("a provider whose credential the caller does not trust is rejected", async () => {
  const conn = await caller.dial(provider.getMultiaddrs()[0] as Parameters<typeof caller.dial>[0]);
  const other = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
  const otherKey = new Uint8Array(Buffer.from(other.getPublicKey().toString().replace(/^ed25519\//, ""), "hex"));
  await assert.rejects(openMCPSession(conn, frame("mcp://calc"), [otherKey]), AuthRejectedError);
});

test("a service the provider does not have ends the session before MCP starts", async () => {
  const conn = await caller.dial(provider.getMultiaddrs()[0] as Parameters<typeof caller.dial>[0]);
  await assert.rejects(openMCPSession(conn, frame("mcp://no-such-service"), [cpKey], { signal: AbortSignal.timeout(3000) }));
});
