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

// What a joined member keeps in step with the control plane: a fake control
// plane behind fetch rotates its key and bans a peer; the member learns both
// from a pull, refreshes its credential under the new key, and refuses the
// banned peer at the gate and at the handshake. The real control plane and
// router are exercised by tests/integration/sdk_mesh_test.go.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { yamux } from "@chainsafe/libp2p-yamux";
import { circuitRelayServer, circuitRelayTransport } from "@libp2p/circuit-relay-v2";
import { privateKeyFromProtobuf } from "@libp2p/crypto/keys";
import { identify } from "@libp2p/identify";
import type { Libp2p } from "@libp2p/interface";
import { peerIdFromString } from "@libp2p/peer-id";
import { tcp } from "@libp2p/tcp";
import { tls } from "@libp2p/tls";
import { createLibp2p } from "libp2p";
import assert from "node:assert/strict";
import { after, before, test, type TestContext } from "node:test";
import { AUTH_PROTOCOL, authenticateWithPeer, authStreamHandler } from "./auth.ts";
import { ROLE_ROUTER, loadBiscuit, verifyPeerBiscuit } from "./biscuit.ts";
import { ROLE_NODE } from "./controlplane.ts";
import { credentialPredatesRotation } from "./credential.ts";
import {
  AuthFrameSchema,
  BootstrapEnrollRequestSchema,
  BootstrapEnrollResponseSchema,
  ControlPlaneInfoResponseSchema,
  EnrollmentStatus,
  KeysResponseSchema,
  MeshEvent_Type,
  MeshEventSchema,
  PolicyConfigGetResponseSchema,
  TokenRefreshResponseSchema,
} from "./gen/agentmesh_pb.ts";
import { Identity } from "./identity.ts";
import { AgentMesh } from "./mesh.ts";
import type { MeshSession } from "./session.ts";
import { BanSet, EVENT_FRESHNESS_MS, verifyMeshEvent } from "./sync.ts";

type Wasm = Awaited<ReturnType<typeof loadBiscuit>>;

let wasm: Wasm;
let router: Libp2p;
let routerAddr: string;

/** One ed25519 key usable both as a biscuit root and for plain signatures. */
class SigningKey {
  readonly biscuit: InstanceType<Wasm["KeyPair"]>;
  readonly identity: Identity;
  constructor() {
    this.biscuit = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
    this.identity = Identity.fromSeed(new Uint8Array(Buffer.from(this.biscuit.getPrivateKey().toString().replace(/^ed25519-private\//, ""), "hex")));
  }
  get pub(): Uint8Array {
    return this.identity.publicKeyRaw;
  }
  mint(peerId: string, role: string): Uint8Array {
    const b = wasm.Biscuit.builder();
    b.addFact(wasm.Fact.fromString(`node(${JSON.stringify(peerId)})`));
    b.addFact(wasm.Fact.fromString("expiration(2035-01-01T00:00:00Z)"));
    b.addFact(wasm.Fact.fromString(`role(${JSON.stringify(role)})`));
    return b.build(this.biscuit.getPrivateKey()).toBytes();
  }
}

/** A control plane whose key set, ban set and issuing key the test changes. */
class FakeControlPlane {
  keys: SigningKey[];
  banned: string[] = [];
  refreshes = 0;
  /** The /policies reads so far, one per pull; the hook may hold an answer. */
  policyReads = 0;
  onPolicyRead: ((reads: number) => Promise<void>) | undefined;
  constructor(initial: SigningKey) {
    this.keys = [initial];
  }
  /** The key credentials are minted with: the newest. */
  get current(): SigningKey {
    return this.keys[this.keys.length - 1] as SigningKey;
  }
  get fetch(): typeof fetch {
    return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const req = new Request(input, init);
      const path = new URL(req.url).pathname;
      const proto = (bytes: Uint8Array) => new Response(Buffer.from(bytes), { status: 200, headers: { "Content-Type": "application/x-protobuf" } });
      if (req.method === "POST" && path === "/enroll") {
        const enroll = fromBinary(BootstrapEnrollRequestSchema, new Uint8Array(await req.arrayBuffer()));
        return proto(
          toBinary(
            BootstrapEnrollResponseSchema,
            create(BootstrapEnrollResponseSchema, {
              status: EnrollmentStatus.APPROVED,
              biscuitToken: this.current.mint(enroll.peerId, ROLE_NODE),
              controlPlanePublicKey: this.current.pub,
              routerAddresses: [routerAddr],
              expireTime: timestampFromMs(Date.now() + 3600_000),
            }),
          ),
        );
      }
      if (req.method === "GET" && path === "/keys") {
        // Signed as api.VerifyKeysResponse expects: each key over the set with signatures cleared.
        const unsigned = create(KeysResponseSchema, { publicKeys: this.keys.map((k) => k.pub), signTime: timestampFromMs(Date.now()) });
        const payload = toBinary(KeysResponseSchema, unsigned);
        return proto(toBinary(KeysResponseSchema, create(KeysResponseSchema, { ...unsigned, signatures: this.keys.map((k) => k.identity.sign(payload)) })));
      }
      if (req.method === "GET" && path === "/info") {
        return proto(
          toBinary(
            ControlPlaneInfoResponseSchema,
            create(ControlPlaneInfoResponseSchema, {
              routerAddresses: [routerAddr],
              bannedPeerIds: this.banned,
            }),
          ),
        );
      }
      if (req.method === "GET" && path === "/policies") {
        this.policyReads++;
        await this.onPolicyRead?.(this.policyReads);
        return proto(toBinary(PolicyConfigGetResponseSchema, create(PolicyConfigGetResponseSchema, { datalogRules: ['granted_publish_all_types(true) <- role("mesh:role:node")'] })));
      }
      if (req.method === "POST" && path === "/refresh") {
        this.refreshes++;
        // The peer is whoever the presented biscuit is bound to; every valid key is tried.
        const presented = new Uint8Array(Buffer.from((req.headers.get("Authorization") ?? "").replace(/^Bearer /, ""), "base64"));
        let peerId: string | undefined;
        for (const key of this.keys) {
          try {
            const token = wasm.Biscuit.fromBytes(presented, wasm.PublicKey.fromBytes(key.pub, wasm.SignatureAlgorithm.Ed25519));
            const b = new wasm.AuthorizerBuilder();
            b.addPolicy(wasm.Policy.fromString("allow if true"));
            const facts = b.buildAuthenticated(token).query(wasm.Rule.fromString("p($p) <- node($p)"));
            peerId = facts[0]?.terms()[0] as string;
            break;
          } catch {
            // try the next key
          }
        }
        if (peerId === undefined) {
          return new Response("unverifiable biscuit", { status: 401 });
        }
        return proto(
          toBinary(
            TokenRefreshResponseSchema,
            create(TokenRefreshResponseSchema, { biscuitToken: this.current.mint(peerId, ROLE_NODE), expireTime: timestampFromMs(Date.now() + 7200_000) }),
          ),
        );
      }
      return new Response(`no route for ${req.method} ${path}`, { status: 404 });
    }) as typeof fetch;
  }
}

let cp: FakeControlPlane;

before(async () => {
  wasm = await loadBiscuit();
  cp = new FakeControlPlane(new SigningKey());
  router = await createLibp2p({
    addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
    transports: [tcp()],
    connectionEncrypters: [tls()],
    streamMuxers: [yamux()],
    services: { identify: identify(), relay: circuitRelayServer() },
    // Every member in these tests dials from 127.0.0.1; libp2p's default of
    // five inbound connections per host per second would refuse later joins.
    connectionManager: { inboundConnectionThreshold: 1_000 },
  });
  const routerBiscuit = cp.current.mint(router.peerId.toString(), ROLE_ROUTER);
  await router.handle(AUTH_PROTOCOL, authStreamHandler({ ownBiscuit: () => routerBiscuit, trustedKeys: () => cp.keys.map((k) => k.pub) }));
  routerAddr = router.getMultiaddrs()[0]!.toString();
});

after(async () => {
  await router.stop();
});

test("a ban learned after the answer was requested survives an answer that omits it", () => {
  const bans = new BanSet();
  const t0 = new Date("2026-09-24T10:00:00Z");
  const t1 = new Date(t0.getTime() + 1000);
  assert.deepEqual(bans.reconcile(["A", "B"], t0), { banned: ["A", "B"], unbanned: [] });
  // A gossip event bans C after t1's request went out; t1's answer cannot speak to it.
  assert.ok(bans.add("C", t1.getTime() + 500));
  assert.deepEqual(bans.reconcile(["A"], t1), { banned: [], unbanned: ["B"] });
  assert.deepEqual(bans.peers(), ["A", "C"]);
  // A later answer without C lifts it.
  assert.deepEqual(bans.reconcile(["A"], new Date(t1.getTime() + 2000)), { banned: [], unbanned: ["C"] });
  assert.ok(!bans.add("A", 1), "an existing ban is not re-added");
});

test("a ban repeated after the answer was requested survives an answer that omits it", () => {
  const bans = new BanSet();
  const t0 = new Date("2026-09-24T10:00:00Z");
  const t1 = new Date(t0.getTime() + 1000);
  assert.ok(bans.add("X", t0.getTime()));
  // The ban was lifted, which publishes no event, and set again after t1's request went out.
  assert.ok(!bans.add("X", t1.getTime() + 500), "a repeated ban is not a new ban");
  assert.deepEqual(bans.reconcile([], t1), { banned: [], unbanned: [] });
  assert.deepEqual(bans.peers(), ["X"]);
});

test("a repeated ban with an earlier time does not move the ban time back", () => {
  const bans = new BanSet();
  const t0 = new Date("2026-09-24T10:00:00Z");
  const t1 = new Date(t0.getTime() + 1000);
  assert.ok(bans.add("X", t1.getTime() + 500));
  assert.ok(!bans.add("X", t0.getTime()), "a repeated ban is not a new ban");
  assert.deepEqual(bans.reconcile([], t1), { banned: [], unbanned: [] });
  assert.deepEqual(bans.peers(), ["X"]);
});

test("a mesh event verifies only under a trusted key and only when fresh", () => {
  const key = new SigningKey();
  const sign = (event: ReturnType<typeof create<typeof MeshEventSchema>>) => {
    const unsigned = toBinary(MeshEventSchema, { ...event, signature: new Uint8Array() });
    return toBinary(MeshEventSchema, { ...event, signature: key.identity.sign(unsigned) });
  };
  const now = new Date();
  const target = Identity.generate().peerId;
  const banned = sign(create(MeshEventSchema, { type: MeshEvent_Type.BANNED, peerId: target, eventTime: timestampFromMs(now.getTime()) }));
  assert.equal(verifyMeshEvent(banned, [key.pub], now)?.peerId, target);
  assert.equal(verifyMeshEvent(banned, [new SigningKey().pub], now), undefined, "untrusted key");
  const tampered = new Uint8Array(banned);
  tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
  assert.equal(verifyMeshEvent(tampered, [key.pub], now), undefined, "tampered signature");
  const stale = sign(create(MeshEventSchema, { type: MeshEvent_Type.BANNED, peerId: target, eventTime: timestampFromMs(now.getTime() - EVENT_FRESHNESS_MS - 1) }));
  assert.equal(verifyMeshEvent(stale, [key.pub], now), undefined, "stale");
  assert.equal(verifyMeshEvent(new Uint8Array([1, 2, 3]), [key.pub], now), undefined, "garbage");

  // The ban set is keyed on the base58 form; an event naming the peer in
  // its CIDv1 form bans the same peer, and one naming no peer bans nobody.
  const cidForm = peerIdFromString(target).toCID().toString();
  assert.notEqual(cidForm, target);
  const bannedByCID = sign(create(MeshEventSchema, { type: MeshEvent_Type.BANNED, peerId: cidForm, eventTime: timestampFromMs(now.getTime()) }));
  assert.equal(verifyMeshEvent(bannedByCID, [key.pub], now)?.peerId, target);
  const bannedNobody = sign(create(MeshEventSchema, { type: MeshEvent_Type.BANNED, peerId: "not-a-peer", eventTime: timestampFromMs(now.getTime()) }));
  assert.equal(verifyMeshEvent(bannedNobody, [key.pub], now), undefined, "not a peer id");
});

test("a pull learns a key rotation and refreshes the credential under the new key", async () => {
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: cp.fetch });
  const session = await mesh.join({ refreshLeadMs: 0, controlPlaneSyncIntervalMs: 0 });
  try {
    const issuer = cp.current;
    assert.equal(mesh.credential.controlPlaneKeys.length, 1);

    // Nothing changed: a pull is a no-op that spends no refresh.
    let result = await session.sync();
    assert.deepEqual(result.errors, []);
    assert.equal(result.keysChanged, false);
    assert.equal(result.refreshed, false);
    assert.equal(cp.refreshes, 0);

    // The control plane rotates: a new key joins the set and mints from now on.
    cp.keys.push(new SigningKey());
    result = await session.sync();
    assert.deepEqual(result.errors, []);
    assert.equal(result.keysChanged, true);
    assert.equal(result.refreshed, true, "credential predating the rotation was not refreshed");
    assert.equal(cp.refreshes, 1);
    assert.equal(mesh.credential.controlPlaneKeys.length, 2);
    assert.ok(!credentialPredatesRotation(mesh.credential));
    // The new credential is signed by the new key and no longer by the retiring one.
    const verified = await verifyPeerBiscuit(mesh.credential.biscuit, mesh.peerId, [cp.current.pub]);
    assert.equal(verified.peerId, mesh.peerId);
    await assert.rejects(verifyPeerBiscuit(mesh.credential.biscuit, mesh.peerId, [issuer.pub]));

    // The retiring key leaves the set: the member follows without another refresh.
    cp.keys.shift();
    result = await session.sync();
    assert.equal(result.keysChanged, true);
    assert.equal(result.refreshed, false);
    assert.equal(mesh.credential.controlPlaneKeys.length, 1);
    // The router's credential was minted under the first key; keep it valid for the next test.
    cp.keys.unshift(issuer);
  } finally {
    await session.close();
  }
});

test("a banned peer is hung up on and refused at the gate and the handshake", async () => {
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: cp.fetch });
  const session = await mesh.join({ refreshLeadMs: 0, controlPlaneSyncIntervalMs: 0 });
  const peerIdentity = Identity.generate();
  const peerBiscuit = cp.current.mint(peerIdentity.peerId, ROLE_NODE);
  const peer = await createLibp2p({
    privateKey: privateKeyFromProtobuf(peerIdentity.toLibp2pPrivateKey()),
    transports: [tcp(), circuitRelayTransport()],
    connectionEncrypters: [tls()],
    streamMuxers: [yamux()],
    services: { identify: identify() },
  });
  try {
    const relayed = session.relayAddresses[0];
    assert.ok(relayed !== undefined, "no relayed address");
    const frame = toBinary(AuthFrameSchema, create(AuthFrameSchema, { biscuit: peerBiscuit }));
    const conn = await peer.dial(relayed);
    await authenticateWithPeer(conn, frame, [cp.current.pub]);
    assert.ok(session.authenticatedPeers.has(peerIdentity.peerId));

    // The control plane bans the peer; the next pull evicts it.
    cp.banned = [peerIdentity.peerId];
    const result = await session.sync();
    assert.deepEqual(result.errors, []);
    assert.deepEqual(session.banned.peers(), [peerIdentity.peerId]);
    assert.ok(!session.authenticatedPeers.has(peerIdentity.peerId), "admission survived the ban");
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(session.node.getConnections(peer.peerId).length, 0, "connection survived the ban");

    // Its token still verifies, and it is still refused: a new connection at the gate ...
    await assert.rejects(peer.dial(relayed).then((c) => authenticateWithPeer(c, frame, [cp.current.pub])));
    // ... and outbound, before any dial, however the peer is named.
    const cidForm = peerIdFromString(peerIdentity.peerId).toCID().toString();
    await assert.rejects(session.connect(`${routerAddr}/p2p-circuit/p2p/${peerIdentity.peerId}`), /banned/);
    await assert.rejects(session.connect(`${routerAddr}/p2p-circuit/p2p/${cidForm}`), /banned/);
    await assert.rejects(session.connect(cidForm), /banned/);
    await assert.rejects(session.connect({ peerId: cidForm, addrs: [] }), /banned/);

    // Lifted by the control plane: the next pull unbans it. A ban list that
    // names the peer in its CIDv1 form bans the same peer.
    cp.banned = [];
    await session.sync();
    assert.deepEqual(session.banned.peers(), []);
    cp.banned = [cidForm, "not-a-peer"];
    await session.sync();
    assert.deepEqual(session.banned.peers(), [peerIdentity.peerId]);
    cp.banned = [];
    await session.sync();
  } finally {
    await peer.stop();
    await session.close();
  }
});

test("an event that arrives while a pull is in flight is followed by another pull", async () => {
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: cp.fetch });
  // No jitter, so a triggered pull is due at once; no periodic pull within the test.
  const session = await mesh.join({ refreshLeadMs: 0, controlPlaneSyncIntervalMs: 3_600_000, controlPlaneSyncJitterMs: 0 });
  const start = cp.policyReads;
  let secondPull!: () => void;
  const pulledAgain = new Promise<void>((resolve) => (secondPull = resolve));
  // The first triggered pull holds its /policies answer (it has read the
  // control plane) while a second event triggers. The answer is released
  // from a timer queued after the second trigger's, so that trigger comes
  // due while the first pull is still in flight.
  cp.onPolicyRead = (reads) => {
    if (reads === start + 2) {
      secondPull();
    }
    if (reads !== start + 1) {
      return Promise.resolve();
    }
    return new Promise<void>((release) => {
      session.triggerSync();
      setTimeout(release, 0);
    });
  };
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    session.triggerSync();
    await Promise.race([pulledAgain, new Promise<void>((resolve) => (deadline = setTimeout(resolve, 5_000)))]);
    assert.equal(cp.policyReads, start + 2, "the event that came during the pull was not followed by a pull of its own");
  } finally {
    clearTimeout(deadline);
    cp.onPolicyRead = undefined;
    await session.close();
  }
});

/** Triggers a pull whose random delay is half the jitter; Math.random is mocked for this call only. */
function triggerAtHalfJitter(t: TestContext, session: MeshSession): void {
  const random = t.mock.method(Math, "random", () => 0.5);
  try {
    session.triggerSync();
  } finally {
    random.mock.restore();
  }
}

test("a burst of events does not push back the pull the first one asked for", async (t) => {
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: cp.fetch });
  const session = await mesh.join({ refreshLeadMs: 0, controlPlaneSyncIntervalMs: 3_600_000, controlPlaneSyncJitterMs: 200 });
  const start = cp.policyReads;
  let pulled!: () => void;
  const pulledOnce = new Promise<void>((resolve) => (pulled = resolve));
  let burst: ReturnType<typeof setInterval> | undefined;
  cp.onPolicyRead = (reads) => {
    if (reads === start + 1) {
      clearInterval(burst);
      pulled();
    }
    return Promise.resolve();
  };
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    // Every event asks for a pull 100 ms after it, and they keep coming
    // every 20 ms for well past the first one's delay.
    triggerAtHalfJitter(t, session);
    burst = setInterval(() => triggerAtHalfJitter(t, session), 20);
    const outcome = await Promise.race([
      pulledOnce.then(() => "pulled"),
      new Promise<string>((resolve) => (deadline = setTimeout(() => resolve("burst over"), 5_000))),
    ]);
    assert.equal(outcome, "pulled", "the burst kept moving the triggered pull back");
  } finally {
    clearInterval(burst);
    clearTimeout(deadline);
    cp.onPolicyRead = undefined;
    await session.close();
  }
});

test("a pull that ends while a triggered one is still due leaves that one's timer alone", async (t) => {
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: cp.fetch });
  const session = await mesh.join({ refreshLeadMs: 0, controlPlaneSyncIntervalMs: 3_600_000, controlPlaneSyncJitterMs: 200 });
  const start = cp.policyReads;
  let secondPull!: () => void;
  const pulledAgain = new Promise<void>((resolve) => (secondPull = resolve));
  // The second event arrives while the first pull is reading /policies, and
  // that pull ends long before the second event's timer fires.
  cp.onPolicyRead = (reads) => {
    if (reads === start + 1) {
      triggerAtHalfJitter(t, session);
    }
    if (reads === start + 2) {
      secondPull();
    }
    return Promise.resolve();
  };
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    // A triggered pull comes due 100 ms after its event.
    triggerAtHalfJitter(t, session);
    await Promise.race([pulledAgain, new Promise<void>((resolve) => (deadline = setTimeout(resolve, 5_000)))]);
    assert.equal(cp.policyReads, start + 2, "the first pull's end replaced the pending triggered pull with a periodic one");
  } finally {
    clearTimeout(deadline);
    cp.onPolicyRead = undefined;
    await session.close();
  }
});

test("a pull queued behind another does not let the first one schedule a periodic pull", async () => {
  const intervalMs = 200;
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: cp.fetch });
  const session = await mesh.join({ refreshLeadMs: 0, controlPlaneSyncIntervalMs: intervalMs, controlPlaneSyncJitterMs: 0 });
  const start = cp.policyReads;
  let releasedAt = 0;
  let thirdPull!: (at: number) => void;
  const pulledThird = new Promise<number>((resolve) => (thirdPull = resolve));
  cp.onPolicyRead = (reads) => {
    if (reads === start + 1) {
      // As in the test above: a second event comes due while this pull is
      // in flight, so its pull is queued behind this one.
      return new Promise<void>((release) => {
        session.triggerSync();
        setTimeout(release, 0);
      });
    }
    if (reads === start + 2) {
      // The queued pull is slower than the periodic interval.
      return new Promise<void>((release) =>
        setTimeout(() => {
          releasedAt = performance.now();
          release();
        }, 2 * intervalMs),
      );
    }
    if (reads === start + 3) {
      thirdPull(performance.now());
    }
    return Promise.resolve();
  };
  let deadline: ReturnType<typeof setTimeout> | undefined;
  try {
    session.triggerSync();
    const at = await Promise.race([pulledThird, new Promise<number>((resolve) => (deadline = setTimeout(() => resolve(-1), 5_000)))]);
    assert.notEqual(at, -1, "no periodic pull followed the queued one");
    // The next periodic pull is scheduled when the queued one ends, not by
    // the first pull while the queued one is still running.
    assert.ok(at - releasedAt >= intervalMs / 2, `a pull started ${Math.round(at - releasedAt)} ms after the queued one, want about ${intervalMs} ms`);
  } finally {
    clearTimeout(deadline);
    cp.onPolicyRead = undefined;
    await session.close();
  }
});
