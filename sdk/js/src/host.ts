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

// The libp2p host a member joins the mesh with, configured the way
// agentmesh-node's is (internal/node/node.go): yamux the muxer, circuit relay v2
// for reachability through the routers. Transports and the security
// protocol come from the runtime (platform/transports.ts): on Node TCP and
// WebSocket with TLS, in a browser WebSocket and WebTransport with Noise.

import { yamux } from "@chainsafe/libp2p-yamux";
import { circuitRelayTransport } from "@libp2p/circuit-relay-v2";
import { privateKeyFromProtobuf } from "@libp2p/crypto/keys";
import { gossipsub, type GossipSub, type GossipSubComponents } from "@libp2p/gossipsub";
import { identify, identifyPush } from "@libp2p/identify";
import type { Libp2p, PeerId } from "@libp2p/interface";
import { ping } from "@libp2p/ping";
import type { Multiaddr } from "@multiformats/multiaddr";
import { createLibp2p, type Libp2pOptions } from "libp2p";
import type { Identity } from "./identity.ts";
import { connectionEncrypters, transports } from "./platform/transports.ts";

export interface MeshHostOptions {
  /**
   * Addresses to accept direct connections on, e.g. "/ip4/0.0.0.0/tcp/0"
   * or "/ip4/0.0.0.0/tcp/0/ws". Empty by default: an agent is reached
   * through a router's relay.
   */
  listenAddrs?: string[];
  /**
   * Peers the control plane has banned. Consulted for every dial and every
   * inbound connection, as agentmesh-node's connection gater; the session keeps
   * it current from /info and the gossip events.
   */
  banned?: { has(peerId: string): boolean };
  /** The resolver for `/dnsaddr` and `/dns*` addresses; the system's by default. */
  dns?: Libp2pOptions["dns"];
}

/** The floodsub protocol, the one a member speaks (see leafPubsub). */
const FLOODSUB_PROTOCOL = "/floodsub/1.0.0";

/**
 * A member is a leaf of the gossip: it speaks floodsub only, so a router
 * delivers every control plane event to it outright and it takes no part
 * in the routers' gossipsub mesh, its heartbeats, grafts and peer exchange.
 * The gossipsub implementation serves as the floodsub one, told to register
 * that protocol alone; the message envelope is the same.
 */
function leafPubsub(): (components: GossipSubComponents) => GossipSub {
  // StrictSign, as every Go component pins it: the pubsub envelope is
  // signed by the author, and the event inside by the control plane.
  const build = gossipsub({ globalSignaturePolicy: "StrictSign", allowPublishToZeroTopicPeers: true, emitSelf: false });
  return (components) => {
    const ps = build(components);
    ps.protocols = [FLOODSUB_PROTOCOL];
    return ps;
  };
}

/** The services a mesh host runs; `services.pubsub` carries the control plane's events. */
export type MeshHost = Libp2p<{ pubsub: GossipSub }>;

export async function createMeshHost(identity: Identity, options: MeshHostOptions = {}): Promise<MeshHost> {
  const banned = options.banned ?? { has: () => false };
  const denyBanned = (peerId: PeerId) => banned.has(peerId.toString());
  return createLibp2p({
    privateKey: privateKeyFromProtobuf(identity.toLibp2pPrivateKey()),
    addresses: { listen: options.listenAddrs ?? [] },
    ...(options.dns !== undefined ? { dns: options.dns } : {}),
    transports: [...transports(), circuitRelayTransport()],
    connectionEncrypters: connectionEncrypters(),
    streamMuxers: [yamux()],
    connectionManager: {
      inboundConnectionThreshold: Infinity,
    },
    connectionGater: {
      denyDialPeer: denyBanned,
      denyInboundEncryptedConnection: denyBanned,
      denyInboundRelayedConnection: (_relay, remotePeer) => denyBanned(remotePeer),
      // The addresses dialled are the routers' as the control plane
      // published them, and every connection is authenticated by peer ID
      // whatever the address, so no address is refused for its shape. In a
      // browser js-libp2p would otherwise skip loopback and plain ws://
      // addresses, which is what agentmesh-one on the same machine advertises; a
      // page on https cannot open ws:// anyway, the browser sees to that.
      denyDialMultiaddr: () => false,
    },
    services: {
      identify: identify(),
      // A member's addresses change after it connects: the relay address
      // arrives with the reservation, which follows the auth handshake.
      // Identify alone tells a router the addresses at connect time; push
      // tells the routers already connected, the reservation's own among
      // them, where the member is reached now, as agentmesh-node does.
      identifyPush: identifyPush(),
      ping: ping(),
      // The control plane's events reach members through the routers.
      pubsub: leafPubsub(),
    },
  });
}

/** The relay listener a member holds, to ask for its reservation again. */
export interface RelayListener {
  listen(addr: Multiaddr): Promise<void>;
}

/**
 * Starts listening on a relay after the caller has authenticated with it,
 * and returns the listener. js-libp2p reserves a relay slot when it starts
 * listening on `<relay>/p2p-circuit`; a router refuses that until the peer
 * has passed the auth handshake, so the listen cannot be part of the host's
 * config. The transport manager is not on the public Libp2p interface.
 *
 * The reservation goes with the connection it was made on: a router that
 * restarts or trims the connection drops it, and js-libp2p does not ask a
 * configured relay again. Calling `listen` on the returned listener does,
 * without registering a second listener.
 *
 * Upstream: libp2p/js-libp2p#3645 (listen after start), #3601 (re-reserve).
 */
export async function listenThroughRelay(node: Libp2p, relayAddr: Multiaddr): Promise<RelayListener> {
  const internals = node as unknown as { components: { transportManager: { listen(addrs: Multiaddr[]): Promise<void>; getListeners(): RelayListener[] } } };
  const manager = internals.components.transportManager;
  const before = new Set(manager.getListeners());
  await manager.listen([relayAddr.encapsulate("/p2p-circuit")]);
  const listener = manager.getListeners().find((l) => !before.has(l));
  if (listener === undefined) {
    throw new Error("libp2p registered no listener for the relay address");
  }
  return listener;
}
