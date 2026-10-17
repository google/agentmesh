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

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { yamux } from "@chainsafe/libp2p-yamux";
import type { Connection, Libp2p } from "@libp2p/interface";
import { tcp } from "@libp2p/tcp";
import { tls } from "@libp2p/tls";
import { lpStream } from "@libp2p/utils";
import { createLibp2p } from "libp2p";
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { DIRECTORY_PROTOCOL, DirectoryError, request, serviceKey } from "./discovery.ts";
import { DirectoryRequestSchema, DirectoryResponseSchema, PeerRecordSchema, type DirectoryResponse } from "./gen/agentmesh_pb.ts";

const PROVIDER = "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB";

let member: Libp2p;
let routerA: Libp2p;
let routerB: Libp2p;
const asked: string[] = [];
// What each router answers a find with; an announcement is always taken.
const answers = new Map<string, () => DirectoryResponse>();

async function node(): Promise<Libp2p> {
  return createLibp2p({ addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] }, transports: [tcp()], connectionEncrypters: [tls()], streamMuxers: [yamux()] });
}

function serve(router: Libp2p, name: string): Promise<void> {
  return router.handle(DIRECTORY_PROTOCOL, (stream) => {
    void (async () => {
      const lp = lpStream(stream, { maxDataLength: 64 * 1024 });
      const req = fromBinary(DirectoryRequestSchema, (await lp.read()).subarray());
      asked.push(name);
      const resp = req.request.case === "provide" ? create(DirectoryResponseSchema, {}) : (answers.get(name) ?? (() => create(DirectoryResponseSchema, {})))();
      await lp.write(toBinary(DirectoryResponseSchema, resp));
      await stream.close();
    })();
  });
}

before(async () => {
  [member, routerA, routerB] = await Promise.all([node(), node(), node()]);
  await Promise.all([serve(routerA, "a"), serve(routerB, "b")]);
  await member.dial(routerA.getMultiaddrs());
  await member.dial(routerB.getMultiaddrs());
});

after(async () => {
  await Promise.all([member.stop(), routerA.stop(), routerB.stop()]);
});

function held(router: Libp2p) {
  return { peerId: router.peerId.toString(), connection: (): Connection | undefined => member.getConnections(router.peerId)[0] };
}

const found = () => create(DirectoryResponseSchema, { providers: [create(PeerRecordSchema, { peerId: PROVIDER, addrs: [`/ip4/10.0.0.9/tcp/4001/p2p/${PROVIDER}`] })] });
const nothing = () => create(DirectoryResponseSchema, {});

test("a lookup one router answers with nothing is put to the next; an announcement is not", async () => {
  // A router cut off from the routers closest to the key answers from what
  // it can reach; the member holds another that may not be.
  const key = await serviceKey("mcp", "calculator");
  const find = create(DirectoryRequestSchema, { request: { case: "findProviders", value: { key, limit: 20 } } });

  answers.set("a", nothing);
  answers.set("b", found);
  asked.length = 0;
  let resp = await request([held(routerA), held(routerB)], find);
  assert.equal(resp.providers[0]?.peerId, PROVIDER);
  assert.deepEqual(asked, ["a", "b"]);

  answers.set("b", nothing);
  asked.length = 0;
  resp = await request([held(routerA), held(routerB)], find);
  assert.equal(resp.providers.length, 0, "nobody has a record: the answer is empty, not an error");
  assert.deepEqual(asked, ["a", "b"]);

  answers.set("a", found);
  asked.length = 0;
  resp = await request([held(routerA), held(routerB)], find);
  assert.equal(resp.providers[0]?.peerId, PROVIDER);
  assert.deepEqual(asked, ["a"], "the first router answered");

  asked.length = 0;
  await request([held(routerA), held(routerB)], create(DirectoryRequestSchema, { request: { case: "provide", value: { key, addrs: [] } } }));
  assert.deepEqual(asked, ["a"], "an announcement one router took is not repeated");

  await assert.rejects(request([{ peerId: "nobody", connection: () => undefined }], find), DirectoryError);
});

test("a request no router answered names every router and what each said", async () => {
  const key = await serviceKey("mcp", "calculator");
  const find = create(DirectoryRequestSchema, { request: { case: "findProviders", value: { key, limit: 20 } } });
  answers.set("a", () => create(DirectoryResponseSchema, { error: "routing table empty" }));
  answers.set("b", () => create(DirectoryResponseSchema, { error: "rate limited" }));
  try {
    await assert.rejects(request([held(routerA), held(routerB)], find), (err: Error) => {
      assert.ok(err instanceof DirectoryError, `got ${err.name}, want DirectoryError`);
      for (const [router, said] of [
        [routerA, "routing table empty"],
        [routerB, "rate limited"],
      ] as const) {
        assert.ok(err.message.includes(`${router.peerId.toString()}: ${said}`), `got ${JSON.stringify(err.message)}, want ${router.peerId.toString()} and what it said`);
      }
      return true;
    });
  } finally {
    answers.delete("a");
    answers.delete("b");
  }
});
