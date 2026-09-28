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

// A mesh in one process: a fake control plane behind fetch, a fake router
// (js-libp2p with a relay server and the auth handshake) and a peer that
// reaches the member through the router. The real router and control
// plane are exercised by tests/integration/sdk_join_test.go.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { yamux } from "@chainsafe/libp2p-yamux";
import { circuitRelayServer, circuitRelayTransport } from "@libp2p/circuit-relay-v2";
import { privateKeyFromProtobuf } from "@libp2p/crypto/keys";
import { identify } from "@libp2p/identify";
import type { Libp2p } from "@libp2p/interface";
import { tcp } from "@libp2p/tcp";
import { tls } from "@libp2p/tls";
import { multiaddr } from "@multiformats/multiaddr";
import { createLibp2p } from "libp2p";
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { AUTH_HANDLER_OPTIONS, AUTH_PROTOCOL, AuthRejectedError, authenticateWithPeer, authStreamHandler } from "./auth.ts";
import { BiscuitVerificationError, ROLE_ROUTER, loadBiscuit, verifyPeerBiscuit } from "./biscuit.ts";
import { ROLE_NODE } from "./controlplane.ts";
import { BootstrapEnrollRequestSchema, BootstrapEnrollResponseSchema, EnrollmentStatus, KeysResponseSchema, AuthFrameSchema } from "./gen/sam_pb.ts";
import { Identity } from "./identity.ts";
import { HTTP_HANDLER_OPTIONS, HTTP_PROTOCOL, a2aEndpoint, httpIngressHandler } from "./libp2p-http.ts";
import { LabelsNotSatisfiedError } from "./mcp.ts";
import { AgentMesh } from "./mesh.ts";
import { MeshSession, type JoinOptions } from "./session.ts";

type Wasm = Awaited<ReturnType<typeof loadBiscuit>>;

let wasm: Wasm;
let cpKeyPair: InstanceType<Wasm["KeyPair"]>;
let cpKey: Uint8Array;
let router: Libp2p;
let routerAddr: string;
let routerBiscuit: Uint8Array;

function mint(peerId: string, role: string, expiration = "2035-01-01T00:00:00Z", labels: Record<string, string> = {}): Uint8Array {
  const b = wasm.Biscuit.builder();
  b.addFact(wasm.Fact.fromString(`node(${JSON.stringify(peerId)})`));
  b.addFact(wasm.Fact.fromString(`client_peer_id(${JSON.stringify(peerId)})`));
  b.addFact(wasm.Fact.fromString(`expiration(${expiration})`));
  b.addFact(wasm.Fact.fromString(`role(${JSON.stringify(role)})`));
  for (const [k, v] of Object.entries(labels)) {
    b.addFact(wasm.Fact.fromString(`label(${JSON.stringify(k)}, ${JSON.stringify(v)})`));
  }
  return b.build(cpKeyPair.getPrivateKey()).toBytes();
}

// What the control plane renders for a policy granting the node role every
// A2A service on any target, and nothing else.
const POLICY_RULES = [
  `granted_service_all("a2a") <- role("sam:role:node")`,
  `granted_service_all("sam:system") <- role("sam:role:node")`,
  `target_unrestricted(true) <- role("sam:role:node")`,
];

function proto(bytes: Uint8Array): Response {
  return new Response(Buffer.from(bytes), { status: 200, headers: { "Content-Type": "application/x-protobuf" } });
}

/** Approves every enrollment with a biscuit bound to the requesting peer. */
function fakeControlPlane(routerAddresses: string[]): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const req = new Request(input, init);
    const path = new URL(req.url).pathname;
    if (req.method === "POST" && path === "/enroll") {
      const enroll = fromBinary(BootstrapEnrollRequestSchema, new Uint8Array(await req.arrayBuffer()));
      return proto(
        toBinary(
          BootstrapEnrollResponseSchema,
          create(BootstrapEnrollResponseSchema, {
            status: EnrollmentStatus.APPROVED,
            biscuitToken: mint(enroll.peerId, ROLE_NODE),
            controlPlanePublicKey: cpKey,
            routerAddresses,
            expireTime: timestampFromMs(Date.now() + 3600_000),
          }),
        ),
      );
    }
    if (req.method === "GET" && path === "/keys") {
      // Unsigned: the client keeps the enrollment key when /keys cannot be verified.
      return proto(toBinary(KeysResponseSchema, create(KeysResponseSchema, { publicKeys: [cpKey], signTime: timestampFromMs(Date.now()) })));
    }
    return new Response(`no route for ${req.method} ${path}`, { status: 404 });
  }) as typeof fetch;
}

before(async () => {
  wasm = await loadBiscuit();
  cpKeyPair = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
  cpKey = new Uint8Array(Buffer.from(cpKeyPair.getPublicKey().toString().replace(/^ed25519\//, ""), "hex"));

  router = await createLibp2p({
    addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
    transports: [tcp()],
    connectionEncrypters: [tls()],
    streamMuxers: [yamux()],
    services: { identify: identify(), relay: circuitRelayServer() },
    // Every member here dials from loopback; the per-host inbound rate limit would refuse the later ones.
    connectionManager: { inboundConnectionThreshold: Infinity },
  });
  routerBiscuit = mint(router.peerId.toString(), ROLE_ROUTER);
  await router.handle(
    AUTH_PROTOCOL,
    authStreamHandler({ ownBiscuit: () => routerBiscuit, trustedKeys: () => [cpKey] }),
  );
  routerAddr = `${(router.getMultiaddrs()[0] as ReturnType<typeof multiaddr>).toString()}`;
  assert.match(routerAddr, /\/p2p\/12D3Koo/);
});

after(async () => {
  await router.stop();
});

test("join authenticates with the router, reserves a relay slot and answers peers", async () => {
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane([routerAddr]) });
  const session = await mesh.join({ refreshLeadMs: 0 });
  try {
    assert.equal(session.routers.length, 1);
    assert.equal(session.routers[0]?.peerId, router.peerId.toString());
    assert.ok(session.routers[0]?.credential.roles.includes(ROLE_ROUTER));
    assert.ok(session.relayAddresses.length > 0, "no relayed address after the reservation");
    const relayed = session.relayAddresses.find((ma) => ma.toString().startsWith(routerAddr));
    assert.ok(relayed, `relayed address ${session.relayAddresses.map(String).join(",")} does not go through ${routerAddr}`);

    // A peer reaches the member through the router and both sides verify each other.
    const peerIdentity = Identity.generate();
    const peerBiscuit = mint(peerIdentity.peerId, ROLE_NODE);
    const peer = await createLibp2p({
      privateKey: privateKeyFromProtobuf(peerIdentity.toLibp2pPrivateKey()),
      transports: [tcp(), circuitRelayTransport()],
      connectionEncrypters: [tls()],
      streamMuxers: [yamux()],
      services: { identify: identify() },
    });
    try {
      const conn = await peer.dial(relayed);
      assert.equal(conn.remotePeer.toString(), mesh.peerId);
      const frame = toBinary(AuthFrameSchema, create(AuthFrameSchema, { biscuit: peerBiscuit }));
      const memberCredential = await authenticateWithPeer(conn, frame, [cpKey]);
      assert.equal(memberCredential.peerId, mesh.peerId);
      assert.deepEqual(memberCredential.roles, [ROLE_NODE]);
      assert.equal(session.authenticatedPeers.get(peerIdentity.peerId)?.toISOString(), "2035-01-01T00:00:00.000Z");

      // A forged credential gets no answer, only a closed stream.
      const forged = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
      const fb = wasm.Biscuit.builder();
      fb.addFact(wasm.Fact.fromString(`node(${JSON.stringify(peerIdentity.peerId)})`));
      fb.addFact(wasm.Fact.fromString("expiration(2035-01-01T00:00:00Z)"));
      const forgedFrame = toBinary(AuthFrameSchema, create(AuthFrameSchema, { biscuit: fb.build(forged.getPrivateKey()).toBytes() }));
      await assert.rejects(authenticateWithPeer(conn, forgedFrame, [cpKey]));
    } finally {
      await peer.stop();
    }
  } finally {
    await session.close();
  }
});

test("a router handed out as /dnsaddr still relays to peers", async () => {
  // The testnets advertise their routers as /dnsaddr/<host>/p2p/<id>, one
  // TXT lookup away from the addresses. A stub resolver answers with the
  // real router's addresses, as the records would.
  const dnsaddr = `/dnsaddr/router.test/p2p/${router.peerId.toString()}`;
  const dns = {
    query: async (domain: string) => {
      assert.equal(domain, "_dnsaddr.router.test");
      return { Answer: router.getMultiaddrs().map((ma) => ({ name: domain, type: 16, TTL: 60, data: `dnsaddr=${ma.toString()}` })) };
    },
  } as unknown as NonNullable<Parameters<typeof createLibp2p>[0]>["dns"];

  const agent = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane([routerAddr]) });
  const agentSession = await agent.join({ refreshLeadMs: 0 });
  const caller = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane([dnsaddr]) });
  const callerSession = await caller.join({ refreshLeadMs: 0, dns });
  try {
    // The router is known by the address the connection was made on: the
    // relay address for a peer is dialable as it stands.
    const routerAddrs = callerSession.routers.map((r) => r.addr.toString());
    assert.deepEqual(routerAddrs, [routerAddr]);
    assert.ok(callerSession.relayAddresses.some((ma) => ma.toString().startsWith(routerAddr)), `reserved on ${callerSession.relayAddresses.map(String).join(",")}`);
    const targets = callerSession.dialTargets(agent.peerId).addrs.map(String);
    assert.deepEqual(targets, [`${routerAddr}/p2p-circuit/p2p/${agent.peerId}`]);

    const verified = await callerSession.authenticate(agent.peerId);
    assert.equal(verified.peerId, agent.peerId);
  } finally {
    await callerSession.close();
    await agentSession.close();
  }
});

test("a dropped router connection is authenticated and reserved again", async () => {
  // A router that restarts or trims the connection forgets the admission
  // and drops the reservation with it; js-libp2p does not ask a configured
  // relay again. The member notices within the check interval, runs the
  // handshake again and holds a relayed address once more.
  const handshakes: string[] = [];
  const strict = await createLibp2p({
    addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
    transports: [tcp()],
    connectionEncrypters: [tls()],
    streamMuxers: [yamux()],
    services: { identify: identify(), relay: circuitRelayServer() },
  });
  try {
    const strictBiscuit = mint(strict.peerId.toString(), ROLE_ROUTER);
    await strict.handle(
      AUTH_PROTOCOL,
      authStreamHandler({ ownBiscuit: () => strictBiscuit, trustedKeys: () => [cpKey], onAuthenticated: (peerId) => handshakes.push(peerId) }),
    );
    const addr = (strict.getMultiaddrs()[0] as ReturnType<typeof multiaddr>).toString();
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane([addr]) });
    const session = await mesh.join({ refreshLeadMs: 0, relayCheckIntervalMs: 200 });
    try {
      assert.deepEqual(handshakes, [mesh.peerId]);
      const reserved = session.relayAddresses.map(String);
      assert.equal(reserved.length, 1);

      await strict.hangUp(session.node.peerId);
      const deadline = Date.now() + 10_000;
      while (session.relayAddresses.length > 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.equal(session.relayAddresses.length, 0, "the reservation should go with the connection");

      while ((session.relayAddresses.length === 0 || handshakes.length < 2) && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 50));
      }
      assert.deepEqual(session.relayAddresses.map(String), reserved, "the relayed address is back");
      // Once on the connection js-libp2p reopened, once ahead of the new
      // reservation; both are the member, and both after the drop.
      assert.ok(handshakes.length >= 2, "the member authenticated again before reserving");
      assert.ok(handshakes.every((p) => p === mesh.peerId));

      // And a peer reaches the member through the router as before.
      const peer = await createLibp2p({
        transports: [tcp(), circuitRelayTransport()],
        connectionEncrypters: [tls()],
        streamMuxers: [yamux()],
        services: { identify: identify() },
      });
      try {
        const conn = await peer.dial(multiaddr(reserved[0] as string));
        assert.equal(conn.remotePeer.toString(), mesh.peerId);
      } finally {
        await peer.stop();
      }
    } finally {
      await session.close();
    }
  } finally {
    await strict.stop();
  }
});

test("a member on one router reaches a member on another", async () => {
  // The caller joined through router A only and the agent reserved on router
  // B only; the credential lists both, as the control plane's does. The
  // caller must not depend on having joined through the agent's router:
  // it admits B on the way and dials the circuit.
  const routerB = await createLibp2p({
    addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
    transports: [tcp()],
    connectionEncrypters: [tls()],
    streamMuxers: [yamux()],
    services: { identify: identify(), relay: circuitRelayServer() },
  });
  try {
    const routerBBiscuit = mint(routerB.peerId.toString(), ROLE_ROUTER);
    const handshakesB: string[] = [];
    await routerB.handle(AUTH_PROTOCOL, authStreamHandler({ ownBiscuit: () => routerBBiscuit, trustedKeys: () => [cpKey], onAuthenticated: (p) => handshakesB.push(p) }));
    const routerBAddr = (routerB.getMultiaddrs()[0] as ReturnType<typeof multiaddr>).toString();
    const both = [routerAddr, routerBAddr];

    const agent = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane(both) });
    const agentSession = await agent.join({ refreshLeadMs: 0, routerAddresses: [routerBAddr] });
    const caller = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane(both) });
    const callerSession = await caller.join({ refreshLeadMs: 0, routerAddresses: [routerAddr], reserveRelay: false });
    try {
      assert.deepEqual(agentSession.routers.map((r) => r.peerId), [routerB.peerId.toString()]);
      assert.deepEqual(callerSession.routers.map((r) => r.peerId), [router.peerId.toString()]);
      assert.deepEqual(handshakesB, [agent.peerId]);

      const verified = await callerSession.authenticate(agent.peerId, AbortSignal.timeout(15_000));
      assert.equal(verified.peerId, agent.peerId);
      // Router B admitted the caller on the way and stays admitted.
      assert.deepEqual(handshakesB, [agent.peerId, caller.peerId]);
      assert.deepEqual(callerSession.routers.map((r) => r.peerId).sort(), [router.peerId.toString(), routerB.peerId.toString()].sort());
    } finally {
      await callerSession.close();
      await agentSession.close();
    }
  } finally {
    await routerB.stop();
  }
});

test("join fails closed when the router is not a router", async () => {
  // A relay whose credential lacks the router role must not admit us to the mesh.
  const impostor = await createLibp2p({
    addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
    transports: [tcp()],
    connectionEncrypters: [tls()],
    streamMuxers: [yamux()],
    services: { identify: identify(), relay: circuitRelayServer() },
  });
  try {
    const impostorBiscuit = mint(impostor.peerId.toString(), ROLE_NODE);
    await impostor.handle(AUTH_PROTOCOL, authStreamHandler({ ownBiscuit: () => impostorBiscuit, trustedKeys: () => [cpKey] }));
    const addr = (impostor.getMultiaddrs()[0] as ReturnType<typeof multiaddr>).toString();
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane([addr]) });
    await assert.rejects(mesh.join(), /lacks expected role "sam:role:router"/);
  } finally {
    await impostor.stop();
  }
});

test("join reports a router that refuses the handshake", async () => {
  const strict = await createLibp2p({
    addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
    transports: [tcp()],
    connectionEncrypters: [tls()],
    streamMuxers: [yamux()],
    services: { identify: identify() },
  });
  try {
    // Trusts a different control plane, so our credential never verifies.
    const otherKey = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
    const other = new Uint8Array(Buffer.from(otherKey.getPublicKey().toString().replace(/^ed25519\//, ""), "hex"));
    await strict.handle(AUTH_PROTOCOL, authStreamHandler({ ownBiscuit: () => routerBiscuit, trustedKeys: () => [other] }));
    const addr = (strict.getMultiaddrs()[0] as ReturnType<typeof multiaddr>).toString();
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane([addr]) });
    await assert.rejects(mesh.join(), /no router admitted this member/);
  } finally {
    await strict.stop();
  }
});

test("an explicit rejection is reported with its reason", async () => {
  const reason = new AuthRejectedError("12D3KooWtest", "peer is revoked");
  assert.match(reason.message, /12D3KooWtest.*peer is revoked/);
  // The verifier does not depend on libp2p; a token for another peer is refused before any network I/O.
  await assert.rejects(verifyPeerBiscuit(routerBiscuit, "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB", [cpKey]), /not bound to peer/);
});

test("an egress floor stated at join is held on the HTTP path, and the provider is verified with or without one", async () => {
  // A provider answering /sam/auth and /libp2p-http as a member does, with
  // whatever credential mintFor gives it; the handshakes it answers are counted.
  const handshakes: string[] = [];
  const serve = async (mintFor: (peerId: string) => Uint8Array): Promise<Libp2p> => {
    const identity = Identity.generate();
    const biscuit = mintFor(identity.peerId);
    const host = await createLibp2p({
      privateKey: privateKeyFromProtobuf(identity.toLibp2pPrivateKey()),
      addresses: { listen: ["/ip4/127.0.0.1/tcp/0"] },
      transports: [tcp()],
      connectionEncrypters: [tls()],
      streamMuxers: [yamux()],
      services: { identify: identify() },
    });
    await host.handle(AUTH_PROTOCOL, authStreamHandler({ ownBiscuit: () => biscuit, trustedKeys: () => [cpKey], onAuthenticated: (peerId) => handshakes.push(peerId) }), AUTH_HANDLER_OPTIONS);
    await host.handle(HTTP_PROTOCOL, httpIngressHandler(a2aEndpoint({ handler: () => Response.json({ ok: true }) }), { ownBiscuit: () => biscuit, trustedKeys: () => [cpKey], policyRules: () => POLICY_RULES }), HTTP_HANDLER_OPTIONS);
    return host;
  };
  const provider = await serve((peerId) => mint(peerId, ROLE_NODE, undefined, { region: "eu" }));
  // Enrolled nowhere: a credential no trusted key signed.
  const forged = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
  const impostor = await serve((peerId) => {
    const b = wasm.Biscuit.builder();
    b.addFact(wasm.Fact.fromString(`node(${JSON.stringify(peerId)})`));
    b.addFact(wasm.Fact.fromString("expiration(2035-01-01T00:00:00Z)"));
    return b.build(forged.getPrivateKey()).toBytes();
  });
  // Enrolled and attesting the floor, but not a node: a router hosts no service.
  const notANode = await serve((peerId) => mint(peerId, ROLE_ROUTER, undefined, { region: "eu" }));
  const addrOf = (host: Libp2p) => (host.getMultiaddrs()[0] as ReturnType<typeof multiaddr>).toString();
  const sessions: MeshSession[] = [];
  const join = async (options: JoinOptions): Promise<MeshSession> => {
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt", fetch: fakeControlPlane([routerAddr]) });
    const session = await mesh.join({ refreshLeadMs: 0, reserveRelay: false, ...options });
    sessions.push(session);
    return session;
  };
  try {
    const held = await join({ egressRequireLabels: { region: "eu" } });
    const missed = await join({ egressRequireLabels: { region: "eu", team: "platform" } });
    const plain = await join({});
    const card = MeshSession.meshURL(provider.peerId.toString(), "a2a://agent", "/card");
    // Met: one handshake verifies the provider; the verdict is kept for the next calls.
    assert.equal((await held.request(addrOf(provider), "a2a://agent", "/card")).status, 200);
    assert.equal((await held.request(addrOf(provider), "a2a://agent", "/card")).status, 200);
    assert.equal((await held.fetch()(card)).status, 200);
    assert.deepEqual(handshakes, [held.peerId]);

    // Missed: every path refuses, and a refusal is not kept: each call asks again.
    await assert.rejects(missed.request(addrOf(provider), "a2a://agent", "/card"), LabelsNotSatisfiedError);
    await assert.rejects(missed.fetch()(card), LabelsNotSatisfiedError);
    assert.deepEqual(handshakes, [held.peerId, missed.peerId, missed.peerId]);

    // No floor: no gate, but the provider is verified all the same.
    assert.equal((await plain.request(addrOf(provider), "a2a://agent", "/card")).status, 200);
    await assert.rejects(plain.request(addrOf(impostor), "a2a://agent", "/card"), BiscuitVerificationError);
    // A banned provider is refused before any handshake.
    plain.banned.add(provider.peerId.toString(), Date.now());
    await assert.rejects(plain.request(addrOf(provider), "a2a://agent", "/card"), /banned/);
    // Only nodes host services, as sam-node's checkPeerLabels requires.
    await assert.rejects(held.request(addrOf(notANode), "a2a://agent", "/card"), /lacks expected role "sam:role:node"/);
  } finally {
    await Promise.all([...sessions.map((s) => s.close()), provider.stop(), impostor.stop(), notANode.stop()]);
  }
});
