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

import type { MessageInitShape } from "@bufbuild/protobuf";
import type { Connection } from "@libp2p/interface";
import { timestampMs } from "@bufbuild/protobuf/wkt";
import { TopicValidatorResult } from "@libp2p/gossipsub";
import { peerIdFromString } from "@libp2p/peer-id";
import { isMultiaddr, multiaddr, type Multiaddr } from "@multiformats/multiaddr";
import {
  AUTH_HANDLER_OPTIONS,
  AUTH_PROTOCOL,
  GOAWAY_PROTOCOL,
  ROUTER_SHUN_DURATION_MS,
  authenticateWithPeer,
  authStreamHandler,
  goAwayReasonName,
  goAwayStreamHandler,
} from "./auth.ts";
import { ROLE_ROUTER, attenuateBiscuit, requirePublish, requireRole, sealBiscuit, type VerifiedBiscuit } from "./biscuit.ts";
import { ROLE_NODE } from "./controlplane.ts";
import { encodeAuthFrame } from "./credential.ts";
import { canonicalPeerId } from "./identity.ts";
import { findPeer, findProviders, isServiceType, parseServiceTarget, peerKey, provide, serviceKey, withdraw, type DirectoryRouter } from "./discovery.ts";
import type { PeerRecord, RouterGoAway, RouterInfo, TaskAuthorizationRuleSchema } from "./gen/agentmesh_pb.ts";
import { createMeshHost, listenThroughRelay, type MeshHost, type MeshHostOptions, type RelayListener } from "./host.ts";
import { openMCPSession, requireEgressLabels, type MCPSession, type MCPSessionOptions } from "./mcp.ts";
import type { AgentMesh, ControlPlaneSync } from "./mesh.ts";
import {
  HTTP_HANDLER_OPTIONS,
  HTTP_PROTOCOL,
  a2aEndpoint,
  fetchOverStream,
  httpRequestOverStream,
  meshURL,
  splitMeshURL,
  type A2AEndpoint,
  type A2AEndpointSpec,
  type HTTPRequestOptions,
  type HTTPResponse,
  type ProviderOptions,
} from "./libp2p-http.ts";
import { ingressHandler } from "./platform/ingress.ts";
import { BanSet, GOSSIP_EVENTS_TOPIC, MeshEvent_Type, verifyMeshEvent } from "./sync.ts";

/** Default number of routers a member attaches to and reserves on at join. */
export const DEFAULT_ROUTERS = 2;
/** Default backoff delays before replacing a dropped held router. */
export const ROUTER_REDIAL_BACKOFFS_MS: readonly number[] = [2_000, 4_000, 8_000];

export interface JoinOptions extends MeshHostOptions {
  /**
   * The routers to join through, `/…/p2p/<router>` multiaddrs, instead of
   * the ones the credential lists. A peer behind a router not named here is
   * still reached: connect() finds it through the routers' DHT and
   * authenticates with the router that relays for it.
   */
  routerAddresses?: string[];
  /**
   * Number of routers to hold and reserve on at a time (agentmesh-node's --routers).
   * Defaults to DEFAULT_ROUTERS (2).
   */
  routers?: number;
  /**
   * Required router labels (agentmesh-node's --router-selector): every pair must
   * match the router's labels in ControlPlaneInfoResponse.routers.
   */
  routerSelector?: Record<string, string>;
  /**
   * Preferred router labels (agentmesh-node's --router-prefer): routers matching
   * more pairs are chosen ahead of others before comparing load.
   */
  routerPrefer?: Record<string, string>;
  /**
   * Backoff delays (ms) when redialing a held router whose connection dropped
   * before shunning it and failing over to another router from the catalog.
   * Defaults to ROUTER_REDIAL_BACKOFFS_MS ([2000, 4000, 8000]).
   */
  routerRedialBackoffsMs?: readonly number[];
  /**
   * Reserve a relay slot on each held router that admits us, so peers can
   * reach this member through the routers. On by default; a member that
   * only calls out can turn it off.
   */
  reserveRelay?: boolean;
  /** Refresh the credential this long before it expires. */
  refreshLeadMs?: number;
  /** Retry a failed refresh after this long. */
  refreshRetryMs?: number;
  /** How often the mesh policy is re-read from the control plane while accepting callers. */
  policySyncIntervalMs?: number;
  /**
   * How often keys, bans and router addresses are pulled from the control
   * plane (agentmesh-node's --control-plane-sync-interval). Gossip events bring a
   * pull forward; 0 disables the loop.
   */
  controlPlaneSyncIntervalMs?: number;
  /** Upper bound of the random delay before a pull an event triggered. */
  controlPlaneSyncJitterMs?: number;
  /**
   * How often the relay reservation is checked while reserveRelay is on: a
   * router that restarted or trimmed the connection dropped it, and this is
   * how long the member is unreachable at most before it reserves again.
   */
  relayCheckIntervalMs?: number;
  /**
   * How often this member announces where it is reached under its peer
   * key (default 5 minutes, agentmesh-node's reprovide interval).
   */
  announceIntervalMs?: number;
  /**
   * agentmesh-node's egress.require_labels for an SDK member: every provider this
   * session calls must attest all of these pairs, on top of a call's
   * requiredLabels. Held on every call, MCP and HTTP alike; no call waives it.
   */
  egressRequireLabels?: Record<string, string>;
  /**
   * Bounds the whole join: the control plane sync, and the dial, auth
   * handshake and relay reservation with every router tried. Without one the
   * join is bounded by JOIN_TIMEOUT_MS (60s). A join that stops throws an
   * error naming each router tried and the step it was in.
   */
  signal?: AbortSignal;
}

export interface AdmittedRouter {
  peerId: string;
  /**
   * The address the connection to the router was made on, resolved: a
   * `/ip4` or `/ip6` address ending in `/p2p/<router>`. Relay addresses
   * are built on it. The control plane may hand a router out as
   * `/dnsaddr/<host>/p2p/<router>`; js-libp2p resolves such an address to
   * the TXT records themselves and drops what follows it, so a
   * `/dnsaddr/.../p2p-circuit/p2p/<peer>` address reaches nobody.
   */
  addr: Multiaddr;
  credential: VerifiedBiscuit;
}

/** One router candidate from the control plane's /info catalog. */
export interface RouterCandidate {
  peerId: string;
  addresses: Multiaddr[];
  labels: Record<string, string>;
  connections: number;
  connectionLimit: number;
}

/** A peer the DHT names as offering a service. */
export interface DiscoveredProvider {
  peerId: string;
  /** Addresses the provider advertised; may be empty when the record carried none. */
  addrs: string[];
}

/**
 * How a caller names the peer it wants to reach: a provider `discover`
 * returned, a peer id, or a multiaddr. For a provider or a peer id the SDK
 * dials the addresses the peer advertised and the relayed path through
 * every router that admitted this member, so the caller never assembles a
 * `/p2p-circuit` address. A multiaddr is dialed as given.
 */
export type Peer = DiscoveredProvider | string | Multiaddr;

/** A tool call's outcome, as MCP reports it. */
export interface ToolCallResult {
  isError: boolean;
  /** Text content blocks, in order; other block types are left out. */
  text: string[];
  /** The raw MCP result. */
  raw: unknown;
}

const DISCOVERY_TIMEOUT_MS = 5_000;
/** Bounds the DHT walk connect() falls back to for a peer no admitted router relays. */
const PEER_ROUTING_TIMEOUT_MS = 10_000;

const DEFAULT_REFRESH_LEAD_MS = 60 * 60 * 1000;
const DEFAULT_REFRESH_RETRY_MS = 30 * 1000;
const MIN_REFRESH_DELAY_MS = 2_000;
/** agentmesh-node's --control-plane-sync-interval default. */
const DEFAULT_POLICY_SYNC_MS = 15 * 60 * 1000;
/** agentmesh-node's --control-plane-sync-interval default, and its 2s first pull. */
const DEFAULT_CONTROL_PLANE_SYNC_MS = 15 * 60 * 1000;
const FIRST_CONTROL_PLANE_SYNC_MS = 2_000;
const DEFAULT_CONTROL_PLANE_SYNC_JITTER_MS = 2_000;
const DEFAULT_RELAY_CHECK_MS = 30 * 1000;
/**
 * How often a member announces where it is reached: agentmesh-node's default
 * reprovide interval, a third of the mesh's default record TTL.
 */
const DEFAULT_ANNOUNCE_MS = 5 * 60 * 1000;
/** What close() waits for the member's record to be withdrawn. */
const WITHDRAW_TIMEOUT_MS = 2 * 1000;
/**
 * Bounds a join whose caller passed no signal: each step has a timeout of
 * its own, but a join tries them in turn over every router it is offered.
 */
export const JOIN_TIMEOUT_MS = 60_000;
/**
 * Bounds the control plane sync a join starts with. The sync is best effort,
 * so a control plane that does not answer in time leaves the join to go on
 * with the stored credential instead of using up the whole join.
 */
export const JOIN_SYNC_TIMEOUT_MS = 5_000;
/** How long a provider's positive egress verdict is kept; agentmesh-node's labelGateTTL. */
const EGRESS_VERDICT_TTL_MS = 5 * 60 * 1000;

/**
 * A member that is on the mesh: a libp2p host authenticated with at least
 * one router, answering the auth handshake for peers that dial it, and
 * keeping its credential fresh. Close it to leave.
 */
export class MeshSession {
  readonly mesh: AgentMesh;
  readonly node: MeshHost;
  readonly routers: AdmittedRouter[];
  /** Peers that passed the inbound auth handshake, with their credential's expiration. */
  readonly authenticatedPeers: Map<string, Date>;
  /** Peers the control plane has banned; connections to and from them are refused. */
  readonly banned: BanSet;
  /** Count of /mesh/goaway/1.0.0 frames received from held routers, keyed by reason name (DRAINING, OVERLOADED, REASON_UNSPECIFIED). */
  readonly goAwayReceived: Map<string, number>;
  /** Routers currently shunned (after a go-away or failed redial), mapped to the unix ms when the shun expires. */
  readonly shunnedRouters: Map<string, number>;
  /** This member's agent, once acceptA2A was called. */
  endpoint: A2AEndpoint | undefined;
  #refreshTimer: ReturnType<typeof setTimeout> | undefined;
  #policyTimer: ReturnType<typeof setInterval> | undefined;
  #syncTimer: ReturnType<typeof setTimeout> | undefined;
  #relayTimer: ReturnType<typeof setInterval> | undefined;
  #announceTimer: ReturnType<typeof setInterval> | undefined;
  /** The addresses of the record last announced under this member's peer key. */
  #announced: string[] = [];
  #syncing: Promise<ControlPlaneSync> | undefined;
  #keepingRelay: Promise<void> | undefined;
  #keepRelayPending = false;
  readonly #heldRouterIds: Set<string>;
  readonly #relayListeners: Map<string, RelayListener>;
  readonly #freeRelayListeners: RelayListener[];
  readonly #reserveRelay: boolean;
  readonly #targetRouters: number;
  readonly #routerSelector: Record<string, string> | undefined;
  readonly #routerPrefer: Record<string, string> | undefined;
  readonly #pinnedRouterAddresses: string[] | undefined;
  readonly #redialBackoffsMs: readonly number[];
  readonly #refreshLeadMs: number;
  readonly #refreshRetryMs: number;
  readonly #policySyncMs: number;
  readonly #syncIntervalMs: number;
  readonly #syncJitterMs: number;
  #policyRules: string[] | undefined;
  readonly #egressRequireLabels: Record<string, string> | undefined;
  /** Peers verified as enrolled and holding the floor, until when; misses are never kept. */
  readonly #egressVerdicts = new Map<string, Date>();
  readonly #taskBiscuit: Uint8Array | undefined;
  readonly #isTaskView: boolean;
  #closed = false;

  constructor(
    mesh: AgentMesh,
    node: MeshHost,
    routers: AdmittedRouter[],
    authenticatedPeers: Map<string, Date>,
    banned: BanSet,
    options: JoinOptions,
    relayListeners?: Map<string, RelayListener>,
    taskBiscuit?: Uint8Array,
    sharedState?: {
      heldRouterIds: Set<string>;
      freeRelayListeners: RelayListener[];
      goAwayReceived: Map<string, number>;
      shunnedRouters: Map<string, number>;
    },
  ) {
    this.mesh = mesh;
    this.node = node;
    this.routers = routers;
    this.authenticatedPeers = authenticatedPeers;
    this.banned = banned;
    this.goAwayReceived = sharedState?.goAwayReceived ?? new Map<string, number>();
    this.shunnedRouters = sharedState?.shunnedRouters ?? new Map<string, number>();
    this.#heldRouterIds = sharedState?.heldRouterIds ?? new Set(routers.map((r) => r.peerId));
    this.#relayListeners = relayListeners ?? new Map<string, RelayListener>();
    this.#freeRelayListeners = sharedState?.freeRelayListeners ?? [];
    this.#reserveRelay = options.reserveRelay ?? true;
    this.#targetRouters = options.routers !== undefined && options.routers > 0 ? options.routers : DEFAULT_ROUTERS;
    this.#routerSelector = options.routerSelector;
    this.#routerPrefer = options.routerPrefer;
    this.#pinnedRouterAddresses = options.routerAddresses;
    this.#redialBackoffsMs = options.routerRedialBackoffsMs ?? ROUTER_REDIAL_BACKOFFS_MS;
    this.#refreshLeadMs = options.refreshLeadMs ?? DEFAULT_REFRESH_LEAD_MS;
    this.#refreshRetryMs = options.refreshRetryMs ?? DEFAULT_REFRESH_RETRY_MS;
    this.#policySyncMs = options.policySyncIntervalMs ?? DEFAULT_POLICY_SYNC_MS;
    this.#syncIntervalMs = options.controlPlaneSyncIntervalMs ?? DEFAULT_CONTROL_PLANE_SYNC_MS;
    this.#syncJitterMs = options.controlPlaneSyncJitterMs ?? DEFAULT_CONTROL_PLANE_SYNC_JITTER_MS;
    this.#egressRequireLabels = options.egressRequireLabels;
    this.#taskBiscuit = taskBiscuit;
    this.#isTaskView = taskBiscuit !== undefined;
    if (!this.#isTaskView) {
      this.#scheduleRefresh();
      this.#listenForEvents();
      this.#keepRouterAdmissions();
      if (this.#syncIntervalMs > 0) {
        this.#scheduleSync(Math.min(FIRST_CONTROL_PLANE_SYNC_MS, this.#syncIntervalMs));
      }
      this.#relayTimer = setInterval(() => void this.keepRelay().catch(() => {}), options.relayCheckIntervalMs ?? DEFAULT_RELAY_CHECK_MS);
      this.#relayTimer.unref?.();
      this.#announceTimer = setInterval(() => void this.announce().catch(() => {}), options.announceIntervalMs ?? DEFAULT_ANNOUNCE_MS);
      this.#announceTimer.unref?.();
    }
  }

  get peerId(): string {
    return this.node.peerId.toString();
  }

  /** The Biscuit presented on outbound service calls (task-attenuated when derived via attenuate()). */
  get biscuit(): Uint8Array {
    return this.#taskBiscuit ?? this.mesh.credential.biscuit;
  }

  /**
   * Returns a task-scoped MeshSession view sharing the underlying libp2p host
   * whose outbound MCP and HTTP service calls carry a Biscuit attenuated offline
   * in memory with rule.
   */
  async attenuate(rule: MessageInitShape<typeof TaskAuthorizationRuleSchema>): Promise<MeshSession> {
    const nextBiscuit = await attenuateBiscuit(this.biscuit, rule, this.mesh.credential.controlPlaneKeys);
    return this.#deriveWithBiscuit(nextBiscuit);
  }

  /**
   * Returns a MeshSession view whose outbound Biscuit is sealed so downstream
   * holders cannot append any further blocks.
   */
  async seal(): Promise<MeshSession> {
    const sealed = await sealBiscuit(this.biscuit, this.mesh.credential.controlPlaneKeys);
    return this.#deriveWithBiscuit(sealed);
  }

  #deriveWithBiscuit(taskBiscuit: Uint8Array): MeshSession {
    const opts: JoinOptions = {
      refreshLeadMs: this.#refreshLeadMs,
      refreshRetryMs: this.#refreshRetryMs,
      policySyncIntervalMs: this.#policySyncMs,
      controlPlaneSyncIntervalMs: 0,
      controlPlaneSyncJitterMs: this.#syncJitterMs,
      reserveRelay: this.#reserveRelay,
      routers: this.#targetRouters,
      routerRedialBackoffsMs: this.#redialBackoffsMs,
      ...(this.#routerSelector !== undefined ? { routerSelector: this.#routerSelector } : {}),
      ...(this.#routerPrefer !== undefined ? { routerPrefer: this.#routerPrefer } : {}),
      ...(this.#pinnedRouterAddresses !== undefined ? { routerAddresses: this.#pinnedRouterAddresses } : {}),
      ...(this.#egressRequireLabels !== undefined ? { egressRequireLabels: this.#egressRequireLabels } : {}),
    };
    return new MeshSession(this.mesh, this.node, this.routers, this.authenticatedPeers, this.banned, opts, this.#relayListeners, taskBiscuit, {
      heldRouterIds: this.#heldRouterIds,
      freeRelayListeners: this.#freeRelayListeners,
      goAwayReceived: this.goAwayReceived,
      shunnedRouters: this.shunnedRouters,
    });
  }

  /**
   * The URL a fetch bound to this session (fetch()) takes for a service on a
   * peer: http://mesh/mesh/<peer-id>/<type>/<name>/<path>, the shape of
   * agentmesh-node's egress proxy and of an agent card it rewrote.
   */
  static meshURL(peerId: string, targetService: string, path = ""): string {
    return meshURL(peerId, targetService, path);
  }

  /** The mesh URL of this member's own agent, once acceptA2A was called. */
  get agentURL(): string | undefined {
    return this.endpoint === undefined ? undefined : meshURL(this.peerId, this.endpoint.service);
  }

  /** Addresses peers can dial this member on, including relayed ones. */
  get addresses(): Multiaddr[] {
    return this.node.getMultiaddrs();
  }

  /** The `.../p2p-circuit/p2p/<self>` addresses reserved on held routers. */
  get relayAddresses(): Multiaddr[] {
    return this.node
      .getMultiaddrs()
      .filter((ma) => {
        const s = ma.toString();
        return s.includes("/p2p-circuit") && [...this.#heldRouterIds].some((id) => s.includes(`/p2p/${id}/p2p-circuit`));
      });
  }

  /**
   * Announces where this member is reached, its relayed addresses on the
   * routers it holds, under its peer key, so that a peer attached to other
   * routers finds it by ID. Runs after join, when the addresses change and
   * every announceIntervalMs; the record outlives its last announcement by
   * the mesh's record TTL. A member with no relayed address announces
   * nothing: there is nothing to reach it at.
   */
  async announce(signal?: AbortSignal): Promise<void> {
    if (this.#closed || this.#isTaskView) {
      return;
    }
    const addrs = this.relayAddresses.map(String).sort();
    if (addrs.length === 0) {
      return;
    }
    await provide(this.#directoryRouters(), await peerKey(this.peerId), addrs, signal);
    this.#announced = addrs;
  }

  /** Whether peerId is currently one of the routers this member holds. */
  isHeldRouter(peerId: string): boolean {
    try {
      return this.#heldRouterIds.has(canonicalPeerId(peerId));
    } catch {
      return false;
    }
  }

  /** Handles a /mesh/goaway/1.0.0 message from a held router: shuns it, detaches it, and tops up from the catalog. */
  async handleGoAway(peerId: string, msg: RouterGoAway, retryAfterMs: number): Promise<void> {
    let canonical: string;
    try {
      canonical = canonicalPeerId(peerId);
    } catch {
      return;
    }
    if (!this.#heldRouterIds.has(canonical)) {
      return;
    }
    const reason = goAwayReasonName(msg.reason);
    this.goAwayReceived.set(reason, (this.goAwayReceived.get(reason) ?? 0) + 1);
    this.#shunRouter(canonical, retryAfterMs);
    await this.#detachRouter(canonical);
    await this.keepRelay().catch(() => {});
  }

  #shunRouter(peerId: string, durationMs: number): void {
    this.shunnedRouters.set(peerId, Date.now() + durationMs);
  }

  #isRouterShunned(peerId: string, nowMs = Date.now()): boolean {
    const expiry = this.shunnedRouters.get(peerId);
    if (expiry === undefined) {
      return false;
    }
    if (expiry <= nowMs) {
      this.shunnedRouters.delete(peerId);
      return false;
    }
    return true;
  }

  async #detachRouter(peerId: string): Promise<void> {
    this.#heldRouterIds.delete(peerId);
    const idx = this.routers.findIndex((r) => r.peerId === peerId);
    if (idx !== -1) {
      this.routers.splice(idx, 1);
    }
    const listener = this.#relayListeners.get(peerId);
    if (listener !== undefined) {
      this.#relayListeners.delete(peerId);
      this.#freeRelayListeners.push(listener);
    }
    try {
      await this.node.hangUp(peerIdFromString(peerId));
    } catch {
      // Already disconnected.
    }
  }

  async #reserveOnRouter(peerId: string, addr: Multiaddr): Promise<void> {
    const existing = this.#relayListeners.get(peerId);
    if (existing !== undefined) {
      await existing.listen(addr.encapsulate("/p2p-circuit"));
      return;
    }
    const free = this.#freeRelayListeners.pop();
    if (free !== undefined) {
      await free.listen(addr.encapsulate("/p2p-circuit"));
      this.#relayListeners.set(peerId, free);
      return;
    }
    const listener = await listenThroughRelay(this.node, addr);
    this.#relayListeners.set(peerId, listener);
  }

  #upsertHeldRouter(router: AdmittedRouter): void {
    this.#heldRouterIds.add(router.peerId);
    const idx = this.routers.findIndex((r) => r.peerId === router.peerId);
    if (idx !== -1) {
      this.routers[idx] = router;
    } else {
      this.routers.push(router);
    }
  }

  #candidatesForHolding(): RouterCandidate[] {
    if (this.#pinnedRouterAddresses !== undefined) {
      return candidatesFromRouterInfos([], this.#pinnedRouterAddresses, this.mesh.routers);
    }
    return candidatesFromRouterInfos(this.mesh.routers, this.mesh.credential.routerAddresses);
  }

  #wantRouters(): number {
    const candidates = this.#candidatesForHolding();
    let matched = 0;
    for (const c of candidates) {
      if (matchesLabels(c.labels, this.#routerSelector)) {
        matched++;
      }
    }
    if (matched > 0 && matched < this.#targetRouters) {
      return matched;
    }
    return this.#targetRouters;
  }

  #candidateAddressesFor(peerId: string, fallback: Multiaddr): Multiaddr[] {
    for (const c of candidatesFromRouterInfos(this.mesh.routers, this.mesh.credential.routerAddresses)) {
      if (c.peerId === peerId && c.addresses.length > 0) {
        return c.addresses;
      }
    }
    const listed = this.mesh.credential.routerAddresses
      .map((a) => {
        try {
          return multiaddr(a);
        } catch {
          return undefined;
        }
      })
      .filter((ma): ma is Multiaddr => ma !== undefined && targetPeerOf(ma) === peerId);
    return listed.length > 0 ? listed : [fallback];
  }

  /**
   * A router forgets the admission with the connection it came on, and
   * js-libp2p reconnects to a relay on its own, so every new connection to a
   * router runs the handshake again: the relay's own renewal of the
   * reservation then still passes the router's check.
   */
  #keepRouterAdmissions(): void {
    this.node.addEventListener("connection:open", (evt) => {
      const conn = evt.detail;
      if (this.#closed || !this.routers.some((r) => r.peerId === conn.remotePeer.toString())) {
        return;
      }
      void this.#authenticateRouter(conn).catch(() => {});
    });
  }

  /** Handshakes in flight by connection id: one per connection, whoever asks first. */
  readonly #routerHandshakes = new Map<string, Promise<VerifiedBiscuit>>();

  /**
   * Runs the handshake on a router connection once: the connection:open
   * listener and an explicit admission both call this, and the second waits
   * for the first instead of running a second handshake. The signal applies
   * to a handshake this call starts; one already running keeps its own.
   */
  #authenticateRouter(conn: Connection, signal?: AbortSignal): Promise<VerifiedBiscuit> {
    const pending = this.#routerHandshakes.get(conn.id);
    if (pending !== undefined) {
      return pending;
    }
    const run = authenticateWithPeer(conn, this.mesh.authFrame(), this.mesh.credential.controlPlaneKeys, signal).finally(() => {
      this.#routerHandshakes.delete(conn.id);
    });
    this.#routerHandshakes.set(conn.id, run);
    return run;
  }

  /** The held routers as the directory client asks them, each with its open connection. */
  #directoryRouters(): DirectoryRouter[] {
    return this.routers.map((r) => ({
      peerId: r.peerId,
      connection: () => this.node.getConnections(peerIdFromString(r.peerId)).find((c) => c.status === "open"),
    }));
  }

  /**
   * Maintains held routers and relay reservations: when a held router's
   * connection or reservation drops, redials it first (2s, 4s, 8s by default)
   * using its current address from the catalog; if it does not recover or
   * refuses auth, shuns it and tops up from the catalog. Runs on
   * relayCheckIntervalMs and immediately after a /mesh/goaway/1.0.0 frame.
   */
  keepRelay(): Promise<void> {
    if (this.#keepingRelay !== undefined) {
      this.#keepRelayPending = true;
      return this.#keepingRelay;
    }
    const run = async (): Promise<void> => {
      do {
        this.#keepRelayPending = false;
        await this.#keepRelayOnce();
      } while (this.#keepRelayPending && !this.#closed);
    };
    this.#keepingRelay = run().finally(() => {
      this.#keepingRelay = undefined;
    });
    return this.#keepingRelay;
  }

  async #keepRelayOnce(): Promise<void> {
    if (this.#closed) {
      return;
    }
    try {
      await this.#maintainRouters();
    } finally {
      const addrs = this.relayAddresses.map(String).sort();
      if (!this.#closed && addrs.length > 0 && addrs.join(" ") !== this.#announced.join(" ")) {
        await this.announce().catch(() => {});
      }
    }
  }

  async #maintainRouters(): Promise<void> {
    const held = this.routers.filter((r) => this.#heldRouterIds.has(r.peerId));
    for (const r of held) {
      if (this.#closed) {
        return;
      }
      if (this.#isRouterShunned(r.peerId)) {
        await this.#detachRouter(r.peerId);
        continue;
      }
      const isConnected = this.node
        .getConnections(peerIdFromString(r.peerId))
        .some((c) => c.status === "open" && !c.remoteAddr.toString().includes("/p2p-circuit"));
      const hasRelay = !this.#reserveRelay || this.relayAddresses.some((ma) => ma.toString().includes(`/p2p/${r.peerId}/p2p-circuit`));
      if (isConnected && hasRelay) {
        continue;
      }
      let reconnected = false;
      for (const backoffMs of [0, ...this.#redialBackoffsMs]) {
        if (this.#closed || this.#isRouterShunned(r.peerId)) {
          break;
        }
        if (backoffMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, backoffMs));
        }
        if (this.#closed || this.#isRouterShunned(r.peerId)) {
          break;
        }
        const addrs = this.#candidateAddressesFor(r.peerId, r.addr);
        let conn: Connection;
        try {
          conn = await this.node.dial(addrs);
        } catch {
          continue;
        }
        try {
          const credential = await this.#authenticateRouter(conn);
          requireRole(credential, ROLE_ROUTER);
          const addr = connectedAddress(conn, r.peerId);
          if (this.#reserveRelay) {
            await this.#reserveOnRouter(r.peerId, addr);
          }
          this.#upsertHeldRouter({ peerId: r.peerId, addr, credential });
          reconnected = true;
          break;
        } catch {
          // Router refused auth or reservation after connecting; fail over immediately.
          break;
        }
      }
      if (!reconnected && !this.#closed) {
        this.#shunRouter(r.peerId, ROUTER_SHUN_DURATION_MS);
        await this.#detachRouter(r.peerId);
      }
    }

    if (!this.#closed && this.#heldRouterIds.size < this.#wantRouters()) {
      await this.topUpRouters();
    }
  }

  /**
   * Attaches and reserves on additional routers from the catalog until this
   * session holds wantRouters() routers or no more eligible candidates remain.
   */
  async topUpRouters(signal?: AbortSignal): Promise<string[]> {
    const failures: string[] = [];
    // A function, not a narrowed value: the signal aborts across the awaits below.
    const aborted = () => signal?.aborted === true;
    const want = this.#wantRouters();
    const candidates = this.#candidatesForHolding();
    const tried = new Set<string>();
    while (!this.#closed && this.#heldRouterIds.size < want) {
      const need = want - this.#heldRouterIds.size;
      const exclude = new Set<string>([...this.#heldRouterIds, ...tried]);
      const picks = selectRouters(candidates, need, {
        ...(this.#routerSelector !== undefined ? { selector: this.#routerSelector } : {}),
        ...(this.#routerPrefer !== undefined ? { prefer: this.#routerPrefer } : {}),
        attached: exclude,
        shunned: this.shunnedRouters,
      });
      if (picks.length === 0) {
        break;
      }
      let progress = false;
      for (const cand of picks) {
        // A router not dialed yet is not tried under a signal that has
        // already aborted: it would fail at once and be shunned for nothing.
        if (aborted()) {
          return failures;
        }
        tried.add(cand.peerId);
        // Each step has a timeout of its own; the failure names the one the
        // router was in, so a join that hangs says where.
        let step = `dial ${cand.addresses.map(String).join(", ")}`;
        try {
          const conn = await this.node.dial(cand.addresses, signal !== undefined ? { signal } : {});
          step = "auth handshake";
          const credential = await this.#authenticateRouter(conn, signal);
          requireRole(credential, ROLE_ROUTER);
          const addr = connectedAddress(conn, cand.peerId);
          if (this.#reserveRelay) {
            step = "relay reservation";
            await this.#reserveOnRouter(cand.peerId, addr);
          }
          this.#upsertHeldRouter({ peerId: cand.peerId, addr, credential });
          progress = true;
        } catch (err) {
          failures.push(`${cand.peerId}: ${step}: ${errorText(err)}`);
          await this.node.hangUp(peerIdFromString(cand.peerId)).catch(() => {});
          // A router cut off by the signal did not fail on its own, so it is
          // not shunned.
          if (aborted()) {
            return failures;
          }
          this.#shunRouter(cand.peerId, ROUTER_SHUN_DURATION_MS);
        }
      }
      if (!progress && picks.length < need) {
        break;
      }
    }
    return failures;
  }

  /**
   * Connects to a peer; see Peer for how it is named. Returns the
   * connection, reused if one is already open. A banned peer is refused
   * here and by the connection gater. A peer named by ID that no admitted
   * router relays for is looked up in the routers' DHT, and failing that
   * tried through every router the control plane lists that this member
   * has not joined through; a relay opens a circuit only for a source it
   * authenticated, so each such router is admitted first. Which router each
   * side joined through does not decide whether they can talk.
   */
  async connect(peer: Peer, signal?: AbortSignal): Promise<Connection> {
    const { peerId, addrs } = this.dialTargets(peer);
    if (peerId !== undefined && this.banned.has(peerId)) {
      throw new Error(`peer ${peerId} is banned by the control plane`);
    }
    const options = signal !== undefined ? { signal } : {};
    try {
      return await this.node.dial(addrs, options);
    } catch (err) {
      if (peerId === undefined || (typeof peer === "string" && peer.startsWith("/")) || isMultiaddr(peer) || signal?.aborted === true) {
        throw err;
      }
      for (const more of [() => this.#routedAddresses(peerId, signal), () => this.#unjoinedRouterAddresses(peerId, signal)]) {
        const routed = await more();
        if (routed.length === 0) {
          continue;
        }
        try {
          return await this.node.dial(routed, options);
        } catch (routedErr) {
          err = routedErr;
        }
      }
      throw err;
    }
  }

  /**
   * The relayed paths to a peer through the routers the control plane lists
   * that this member has not joined through, each admitted first. The list
   * is the one the credential carries, refreshed by every control plane
   * pull, so a router that came up after join is tried too.
   */
  async #unjoinedRouterAddresses(peerId: string, signal?: AbortSignal): Promise<Multiaddr[]> {
    const out: Multiaddr[] = [];
    for (const text of this.mesh.credential.routerAddresses) {
      let addr: Multiaddr;
      try {
        addr = multiaddr(text);
      } catch {
        continue;
      }
      const router = targetPeerOf(addr);
      if (router === undefined || router === peerId || this.banned.has(router) || this.routers.some((r) => r.peerId === router)) {
        continue;
      }
      try {
        out.push((await this.#admitRouter(addr, signal)).addr.encapsulate(`/p2p-circuit/p2p/${peerId}`));
      } catch {
        continue;
      }
    }
    return out;
  }

  /**
   * The addresses the directory knows for a peer, its relayed ones through
   * routers this member has admitted by then: a relay opens a circuit only
   * for a source it authenticated, so a router met this way is dialed and
   * passed the handshake first, and joins the admitted set.
   */
  async #routedAddresses(peerId: string, signal?: AbortSignal): Promise<Multiaddr[]> {
    const lookup = signal ?? AbortSignal.timeout(PEER_ROUTING_TIMEOUT_MS);
    let found: PeerRecord | undefined;
    try {
      found = await findPeer(this.#directoryRouters(), peerId, lookup);
    } catch {
      return [];
    }
    if (found === undefined) {
      return [];
    }
    const out: Multiaddr[] = [];
    for (const text of found.addrs) {
      const ma = multiaddr(text);
      const circuit = text.indexOf("/p2p-circuit");
      if (circuit === -1) {
        out.push(targetPeerOf(ma) === undefined ? ma.encapsulate(`/p2p/${peerId}`) : ma);
        continue;
      }
      const relayAddr = multiaddr(text.slice(0, circuit));
      const relay = targetPeerOf(relayAddr);
      if (relay === undefined || this.banned.has(relay)) {
        continue;
      }
      if (!this.routers.some((r) => r.peerId === relay)) {
        try {
          await this.#admitRouter(relayAddr, signal);
        } catch {
          continue;
        }
      }
      out.push(relayAddr.encapsulate(`/p2p-circuit/p2p/${peerId}`));
    }
    return out;
  }

  /** Dials a router, runs the handshake and, its role verified, adds it to the admitted set. */
  async #admitRouter(addr: Multiaddr, signal?: AbortSignal): Promise<AdmittedRouter> {
    const conn = await this.node.dial(addr, signal !== undefined ? { signal } : {});
    const credential = await this.#authenticateRouter(conn);
    requireRole(credential, ROLE_ROUTER);
    const peerId = conn.remotePeer.toString();
    const router = { peerId, addr: connectedAddress(conn, peerId), credential };
    if (!this.routers.some((r) => r.peerId === peerId)) {
      this.routers.push(router);
    }
    return router;
  }

  /** The addresses connect() dials for a peer, in the order libp2p tries them. */
  dialTargets(peer: Peer): { peerId: string | undefined; addrs: Multiaddr[] } {
    if (typeof peer === "string" && !peer.startsWith("/")) {
      const peerId = canonicalPeerId(peer);
      return { peerId, addrs: this.relayedAddresses(peerId) };
    }
    if (typeof peer === "string" || isMultiaddr(peer)) {
      const ma = typeof peer === "string" ? multiaddr(peer) : peer;
      return { peerId: targetPeerOf(ma), addrs: [ma] };
    }
    const peerId = canonicalPeerId(peer.peerId);
    const advertised = peer.addrs.map((text) => {
      const ma = multiaddr(text);
      return targetPeerOf(ma) === undefined ? ma.encapsulate(`/p2p/${peerId}`) : ma;
    });
    return { peerId, addrs: [...advertised, ...this.relayedAddresses(peerId)] };
  }

  /** `<router>/p2p-circuit/p2p/<peer>` through every router that admitted this member. */
  relayedAddresses(peerId: string): Multiaddr[] {
    return this.routers.map((r) => r.addr.encapsulate(`/p2p-circuit/p2p/${peerId}`));
  }

  /** Connects to a peer and runs the mutual auth handshake, returning its verified credential. */
  async authenticate(peer: Peer, signal?: AbortSignal): Promise<VerifiedBiscuit> {
    const conn = await this.connect(peer, signal);
    return authenticateWithPeer(conn, this.mesh.authFrame(), this.mesh.credential.controlPlaneKeys);
  }

  /**
   * Asks the directory for peers offering a service: `"mcp://calc"`, the
   * same string callTool and request take, or a type alone (`"mcp"`) for
   * every service of that type, or (type, name). A router this member holds
   * answers; bounded by the timeout.
   */
  async discover(service: string, name?: string, options: { timeoutMs?: number; limit?: number } = {}): Promise<DiscoveredProvider[]> {
    const target = service.includes("://") ? parseServiceTarget(service) : { type: service, name };
    if (!isServiceType(target.type)) {
      throw new Error(`service type must be mcp, inference, a2a or egress, got ${JSON.stringify(target.type)}`);
    }
    const key = await serviceKey(target.type, target.name);
    const signal = AbortSignal.timeout(options.timeoutMs ?? DISCOVERY_TIMEOUT_MS);
    const limit = options.limit ?? 20;
    const found = new Map<string, DiscoveredProvider>();
    for (const record of await findProviders(this.#directoryRouters(), key, limit, signal)) {
      if (record.peerId === this.peerId) {
        continue;
      }
      const entry = found.get(record.peerId) ?? { peerId: record.peerId, addrs: [] };
      for (const text of record.addrs) {
        if (!entry.addrs.includes(text)) {
          entry.addrs.push(text);
        }
      }
      found.set(record.peerId, entry);
    }
    return [...found.values()].slice(0, limit);
  }

  /**
   * Opens an MCP session with a provider for targetService ("mcp://<name>",
   * or "" for the provider's own catalog tools).
   */
  async openMCP(peer: Peer, targetService: string, options: MCPSessionOptions = {}): Promise<MCPSession> {
    const conn = await this.connect(peer, options.signal);
    return openMCPSession(conn, encodeAuthFrame(this.biscuit, targetService), this.mesh.credential.controlPlaneKeys, { ...options, policyRules: this.policyRules }, this.#egressRequireLabels);
  }

  /** Lists the tools a provider serves for a service. */
  async listTools(peer: Peer, targetService: string, options: MCPSessionOptions = {}): Promise<{ name: string; description?: string }[]> {
    const mcp = await this.openMCP(peer, targetService, options);
    try {
      const { tools } = await mcp.client.listTools();
      return tools.map((t) => (t.description !== undefined ? { name: t.name, description: t.description } : { name: t.name }));
    } finally {
      await mcp.close();
    }
  }

  /** Calls one tool on a provider's service. */
  async callTool(peer: Peer, targetService: string, tool: string, args: Record<string, unknown> = {}, options: MCPSessionOptions = {}): Promise<ToolCallResult> {
    const mcp = await this.openMCP(peer, targetService, options);
    try {
      const result = await mcp.client.callTool({ name: tool, arguments: args });
      const content = Array.isArray(result.content) ? (result.content as Array<{ type: string; text?: string }>) : [];
      return {
        isError: result.isError === true,
        text: content.filter((c) => c.type === "text" && typeof c.text === "string").map((c) => c.text as string),
        raw: result,
      };
    } finally {
      await mcp.close();
    }
  }

  /** Refreshes now and reschedules; exposed so a caller can force it. */
  async refresh(): Promise<void> {
    await this.#refreshCredential();
    this.#scheduleRefresh();
  }

  /**
   * Trades the credential for a fresh one and shows it to every router this
   * member is connected to. A router admits a peer until the biscuit it was
   * shown expires, whatever the connection does; a refreshed credential it
   * never sees leaves it refusing relay circuits to this member once the
   * old one lapses, with every connection still open.
   */
  async #refreshCredential(): Promise<void> {
    await this.mesh.refresh();
    await this.#readmitRouters();
  }

  /**
   * Runs the handshake again on the open connection to each admitted
   * router; the router records the expiry of the credential it is shown.
   * A router without an open connection is left to keepRelay and the
   * connection:open listener, which handshake on the next connection.
   */
  async #readmitRouters(): Promise<void> {
    await Promise.all(
      this.routers.map(async (r) => {
        const conn = this.node.getConnections(peerIdFromString(r.peerId)).find((c) => c.status === "open");
        if (conn === undefined) {
          return;
        }
        try {
          await this.#authenticateRouter(conn);
        } catch {
          // The router keeps the admission it has until the old credential lapses.
        }
      }),
    );
  }

  /**
   * Pulls keys, bans and router addresses from the control plane now, and
   * the mesh policy when accepting callers, then applies them: a newly
   * banned peer is hung up on and dropped from the admitted set. Concurrent
   * calls share one pull. Errors of individual parts are in the result, not
   * thrown.
   */
  sync(): Promise<ControlPlaneSync> {
    this.#syncing ??= this.#syncOnce().finally(() => {
      this.#syncing = undefined;
    });
    return this.#syncing;
  }

  async #syncOnce(): Promise<ControlPlaneSync> {
    const result = await this.mesh.syncControlPlane();
    if (result.refreshed) {
      await this.#readmitRouters();
    }
    if (result.bannedPeerIds !== undefined) {
      const { banned } = this.banned.reconcile(canonicalPeerIds(result.bannedPeerIds), result.fetchedAt);
      await Promise.all(banned.map((peerId) => this.#evict(peerId)));
    }
    if (!this.#closed && this.#heldRouterIds.size < this.#wantRouters()) {
      await this.topUpRouters().catch(() => {});
    }
    if (!this.#closed) {
      void this.keepRelay().catch(() => {});
    }
    // Callers evaluate the policy too: it is what grants a provider the
    // service it serves (requirePublish), not only what an A2A endpoint
    // authorizes its callers with.
    try {
      await this.syncPolicy();
    } catch (err) {
      result.errors.push(`policy: ${err instanceof Error ? err.message : String(err)}`);
    }
    return result;
  }

  /** Asks for a pull soon, after a random delay so a fleet told at once does not pull at once. */
  triggerSync(): void {
    if (this.#closed) {
      return;
    }
    this.#scheduleSync(Math.floor(Math.random() * (this.#syncJitterMs + 1)));
  }

  #scheduleSync(delayMs: number): void {
    clearTimeout(this.#syncTimer);
    this.#syncTimer = setTimeout(() => {
      this.sync()
        .catch(() => {})
        .finally(() => {
          if (!this.#closed && this.#syncIntervalMs > 0) {
            // Stretched by up to a tenth so a fleet started together does not pull together.
            this.#scheduleSync(this.#syncIntervalMs + Math.floor(Math.random() * (this.#syncIntervalMs / 10 + 1)));
          }
        });
    }, delayMs);
    this.#syncTimer.unref?.();
  }

  /** Drops a banned peer: its admission and its connections. */
  async #evict(peerId: string): Promise<void> {
    this.authenticatedPeers.delete(peerId);
    try {
      await this.node.hangUp(peerIdFromString(peerId));
    } catch {
      // Not connected, or already gone.
    }
  }

  /**
   * The control plane's gossip events, relayed by the routers. The topic
   * validator drops anything not signed by a trusted control plane key, so
   * a peer whose libp2p key signed the envelope still cannot get an
   * unsigned event through; a stale event is ignored, not penalized.
   */
  #listenForEvents(): void {
    const pubsub = this.node.services.pubsub;
    pubsub.topicValidators.set(GOSSIP_EVENTS_TOPIC, (_peer, message) => {
      if (message.type !== "signed") {
        return TopicValidatorResult.Reject;
      }
      return verifyMeshEvent(message.data, this.mesh.credential.controlPlaneKeys) !== undefined ? TopicValidatorResult.Accept : TopicValidatorResult.Reject;
    });
    pubsub.addEventListener("message", (evt) => {
      if (evt.detail.topic !== GOSSIP_EVENTS_TOPIC) {
        return;
      }
      const event = verifyMeshEvent(evt.detail.data, this.mesh.credential.controlPlaneKeys);
      if (event === undefined) {
        return;
      }
      switch (event.type) {
        case MeshEvent_Type.BANNED:
          // Not persisted: a restarted member picks the ban back up from /info.
          if (this.banned.add(event.peerId, timestampMs(event.eventTime))) {
            void this.#evict(event.peerId);
          }
          break;
        case MeshEvent_Type.KEY_ROTATION:
          if (event.newPublicKey.length === 32) {
            this.mesh.addTrustedKey(event.newPublicKey);
          }
          this.triggerSync();
          break;
        case MeshEvent_Type.POLICY_UPDATE:
          this.triggerSync();
          break;
      }
    });
    pubsub.subscribe(GOSSIP_EVENTS_TOPIC);
  }

  /**
   * The mesh policy rules this member evaluates for callers, as the control
   * plane rendered them (PolicyConfigGetResponse.datalog_rules). Empty until
   * the first control plane sync, acceptA2A() or syncPolicy().
   */
  get policyRules(): string[] {
    return this.#policyRules ?? [];
  }

  /** Re-reads the mesh policy from the control plane. */
  async syncPolicy(): Promise<void> {
    this.#policyRules = await this.mesh.controlPlane.policyRules(this.mesh.identity, this.mesh.credential.biscuit);
  }

  /**
   * Calls an inference or A2A service on a provider over /libp2p-http, the
   * way agentmesh-node's egress proxy does for /mesh/<peer>/<type>/<name>/<path>.
   */
  async request(peer: Peer, targetService: string, path: string, options: HTTPRequestOptions = {}): Promise<HTTPResponse> {
    const conn = await this.#egressConnection(peer, targetService, options.signal);
    return httpRequestOverStream(conn, this.biscuit, targetService, path, options);
  }

  /**
   * The connection an HTTP call goes out on, its peer verified as an enrolled
   * node holding the floor and granted the service before anything is sent
   * (agentmesh-node's VerifyProvider).
   */
  async #egressConnection(peer: Peer, targetService: string, signal?: AbortSignal): Promise<Connection> {
    const conn = await this.connect(peer, signal);
    const verdict = `${conn.remotePeer.toString()}|${targetService}`;
    const until = this.#egressVerdicts.get(verdict);
    if (until !== undefined && until.getTime() > Date.now()) {
      return conn;
    }
    const provider = await authenticateWithPeer(conn, this.mesh.authFrame(), this.mesh.credential.controlPlaneKeys);
    // Only nodes host services; a router's or an admin's credential is a member, not a provider.
    requireRole(provider, ROLE_NODE);
    await requirePublish(provider, targetService, this.policyRules);
    requireEgressLabels(provider, this.#egressRequireLabels);
    this.#egressVerdicts.set(verdict, new Date(Date.now() + EGRESS_VERDICT_TTL_MS));
    return conn;
  }

  /**
   * A `fetch` bound to the mesh, for clients built on fetch such as the A2A
   * SDK's (`fetchImpl`): a request to http://mesh/mesh/<peer-id>/<type>/<name>/<path>
   * is carried to that peer over /libp2p-http with this member's credential.
   * Response bodies stream, so message/stream works. See MeshSession.meshURL.
   */
  fetch(): typeof fetch {
    return async (input, init) => {
      const request = new Request(input, init);
      const { peerId, target } = splitMeshURL(new URL(request.url));
      const [svcType = "", svcName = ""] = target.slice(1).split("/");
      const conn = await this.#egressConnection(peerId, `${svcType}://${svcName}`, request.signal);
      const streamOptions: { signal?: AbortSignal } = {};
      if (init?.signal !== undefined && init.signal !== null) {
        streamOptions.signal = init.signal;
      }
      return fetchOverStream(conn, this.biscuit, request, streamOptions);
    };
  }

  /**
   * Makes this member's agent reachable: other members call it as
   * `a2a://<name>` by peer ID, through a router, and the SDK answers
   * /libp2p-http with the spec's url (an A2A server beside this process),
   * handler or listener (in this process; an Express app with the A2A SDK's
   * handlers is a listener). Nothing is announced: no DHT record, no
   * catalog entry. A tool, a model or a service others should find by name
   * is published by a agentmesh-node. Fetches the mesh policy first and keeps it
   * current; a policy that cannot be read fails the call, since an agent
   * without it could only authorize what callers carry in their own tokens.
   * Returns the service target callers use. One agent per session.
   */
  async acceptA2A(spec: A2AEndpointSpec): Promise<string> {
    if (this.endpoint !== undefined) {
      throw new Error(`this session already accepts ${this.endpoint.service}`);
    }
    const endpoint = a2aEndpoint(spec);
    await this.syncPolicy();
    const providerOptions: ProviderOptions = {
      trustedKeys: () => this.mesh.credential.controlPlaneKeys,
      ownBiscuit: () => this.mesh.credential.biscuit,
      policyRules: () => this.policyRules,
      isBanned: (peerId) => this.banned.has(peerId),
      onAuthorized: (peerId, verified) => this.authenticatedPeers.set(peerId, verified.expiration),
    };
    await this.node.handle(HTTP_PROTOCOL, ingressHandler(endpoint, providerOptions), HTTP_HANDLER_OPTIONS);
    this.#policyTimer = setInterval(() => void this.syncPolicy().catch(() => {}), this.#policySyncMs);
    this.#policyTimer.unref?.();
    this.endpoint = endpoint;
    return endpoint.service;
  }

  #scheduleRefresh(): void {
    if (this.#closed) {
      return;
    }
    clearTimeout(this.#refreshTimer);
    const dueMs = this.mesh.credential.expiration * 1000 - this.#refreshLeadMs - Date.now();
    const delay = Math.max(MIN_REFRESH_DELAY_MS, dueMs);
    this.#refreshTimer = setTimeout(() => {
      this.#refreshCredential().then(
        () => this.#scheduleRefresh(),
        () => {
          if (!this.#closed) {
            this.#refreshTimer = setTimeout(() => this.#scheduleRefresh(), this.#refreshRetryMs);
            this.#refreshTimer.unref?.();
          }
        },
      );
    }, delay);
    // A pending refresh must not keep an otherwise finished process alive.
    this.#refreshTimer.unref?.();
  }

  async close(): Promise<void> {
    const announced = this.#announced.length > 0 && !this.#closed && !this.#isTaskView;
    this.#closed = true;
    clearTimeout(this.#refreshTimer);
    clearTimeout(this.#syncTimer);
    clearInterval(this.#policyTimer);
    clearInterval(this.#relayTimer);
    clearInterval(this.#announceTimer);
    if (announced) {
      // Best effort: the record expires on its own within the record TTL.
      await withdraw(this.#directoryRouters(), await peerKey(this.peerId), AbortSignal.timeout(WITHDRAW_TIMEOUT_MS)).catch(() => {});
      this.#announced = [];
    }
    if (!this.#isTaskView) {
      await this.node.stop();
    }
  }
}

export interface SelectRoutersOptions {
  selector?: Record<string, string>;
  prefer?: Record<string, string>;
  attached?: ReadonlySet<string>;
  shunned?: ReadonlyMap<string, number>;
  nowMs?: number;
  random?: () => number;
}

/**
 * Builds router candidates from ControlPlaneInfoResponse.routers, falling back
 * to router_addresses when routers is empty (an older control plane). When
 * routerMetadata is provided alongside explicit fallbackAddresses, labels and
 * load from routerMetadata are attached by peerId.
 */
export function candidatesFromRouterInfos(
  routers: readonly RouterInfo[],
  fallbackAddresses: readonly string[],
  routerMetadata: readonly RouterInfo[] = [],
): RouterCandidate[] {
  if (routers.length > 0) {
    const out: RouterCandidate[] = [];
    for (const r of routers) {
      let peerId: string | undefined;
      if (r.peerId !== "") {
        try {
          peerId = canonicalPeerId(r.peerId);
        } catch {
          peerId = undefined;
        }
      }
      const addrs: Multiaddr[] = [];
      for (const raw of r.addresses) {
        let ma: Multiaddr;
        try {
          ma = multiaddr(raw);
        } catch {
          continue;
        }
        const target = targetPeerOf(ma);
        if (peerId === undefined && target !== undefined) {
          peerId = target;
        }
        if (peerId !== undefined && (target === undefined || target === peerId)) {
          addrs.push(target === undefined ? ma.encapsulate(`/p2p/${peerId}`) : ma);
        }
      }
      if (peerId === undefined || addrs.length === 0) {
        continue;
      }
      out.push({
        peerId,
        addresses: addrs,
        labels: { ...r.labels },
        connections: r.connections,
        connectionLimit: r.connectionLimit,
      });
    }
    return out;
  }

  const metaByPeer = new Map<string, RouterInfo>();
  for (const r of routerMetadata) {
    if (r.peerId !== "") {
      try {
        metaByPeer.set(canonicalPeerId(r.peerId), r);
      } catch {
        // Ignore malformed peer IDs.
      }
    }
  }

  const byId = new Map<string, RouterCandidate>();
  for (const raw of fallbackAddresses) {
    let ma: Multiaddr;
    try {
      ma = multiaddr(raw);
    } catch {
      continue;
    }
    const peerId = targetPeerOf(ma);
    if (peerId === undefined) {
      continue;
    }
    const existing = byId.get(peerId);
    if (existing !== undefined) {
      existing.addresses.push(ma);
    } else {
      const meta = metaByPeer.get(peerId);
      byId.set(peerId, {
        peerId,
        addresses: [ma],
        labels: meta !== undefined ? { ...meta.labels } : {},
        connections: meta?.connections ?? 0,
        connectionLimit: meta?.connectionLimit ?? 0,
      });
    }
  }
  return [...byId.values()];
}

function matchesLabels(routerLabels: Record<string, string>, selector: Record<string, string> | undefined): boolean {
  if (selector === undefined) {
    return true;
  }
  for (const [k, v] of Object.entries(selector)) {
    if (routerLabels[k] !== v) {
      return false;
    }
  }
  return true;
}

function countMatchingLabels(routerLabels: Record<string, string>, prefer: Record<string, string> | undefined): number {
  if (prefer === undefined) {
    return 0;
  }
  let n = 0;
  for (const [k, v] of Object.entries(prefer)) {
    if (routerLabels[k] === v) {
      n++;
    }
  }
  return n;
}

function routerLoad(c: RouterCandidate): number {
  if (c.connectionLimit <= 0) {
    return 0.5;
  }
  const load = c.connections / c.connectionLimit;
  if (load < 0) {
    return 0;
  }
  if (load > 1) {
    return 1;
  }
  return load;
}

/**
 * Picks up to k routers from candidates, mirroring agentmesh-node's selectRouters:
 * filters by selector, excludes already-attached and currently-shunned routers,
 * and orders by matching prefer labels (descending) then load + jitter (ascending).
 */
export function selectRouters(candidates: readonly RouterCandidate[], k: number, options: SelectRoutersOptions = {}): RouterCandidate[] {
  if (k <= 0) {
    return [];
  }
  const nowMs = options.nowMs ?? Date.now();
  const rand = options.random ?? Math.random;
  const scored: Array<{ candidate: RouterCandidate; preferScore: number; load: number }> = [];
  for (const c of candidates) {
    if (options.attached?.has(c.peerId) === true) {
      continue;
    }
    const shunExpiry = options.shunned?.get(c.peerId);
    if (shunExpiry !== undefined && shunExpiry > nowMs) {
      continue;
    }
    if (!matchesLabels(c.labels, options.selector)) {
      continue;
    }
    scored.push({
      candidate: c,
      preferScore: countMatchingLabels(c.labels, options.prefer),
      load: routerLoad(c) + rand() * 0.05,
    });
  }
  scored.sort((a, b) => {
    if (a.preferScore !== b.preferScore) {
      return b.preferScore - a.preferScore;
    }
    return a.load - b.load;
  });
  return scored.slice(0, k).map((s) => s.candidate);
}

/**
 * Implements AgentMesh.join(); lives here to keep mesh.ts free of libp2p.
 * timeoutMs bounds a join whose caller passed no signal.
 */
export async function joinMesh(mesh: AgentMesh, options: JoinOptions = {}, timeoutMs = JOIN_TIMEOUT_MS): Promise<MeshSession> {
  const signal = options.signal ?? AbortSignal.timeout(timeoutMs);
  // Why the join stopped: the caller's reason, or its own timeout.
  const stopReason = () => (options.signal !== undefined ? errorText(signal.reason) : `timed out after ${timeoutMs}ms`);
  // The pull agentmesh-node makes before it starts: a member resuming from its
  // state directory after a key rotation would otherwise verify the routers,
  // which already hold credentials under the new key, against the keys it
  // persisted, and the sync that would have brought the new key runs only
  // once joined. Best effort; the stored credential serves when the control
  // plane cannot be reached.
  try {
    await mesh.syncControlPlane(AbortSignal.any([signal, AbortSignal.timeout(JOIN_SYNC_TIMEOUT_MS)]));
  } catch {
    // Joining goes on with what the credential holds, unless the caller
    // stopped the join while the control plane kept it waiting.
    if (signal.aborted) {
      throw new Error(`join stopped while syncing with the control plane: ${stopReason()}`);
    }
  }
  const rawAddrs = options.routerAddresses ?? mesh.credential.routerAddresses;
  if (rawAddrs.length === 0 && mesh.routers.length === 0) {
    throw new Error(options.routerAddresses === undefined ? "credential lists no router addresses; the control plane had no active router at enrollment" : "routerAddresses names no router");
  }
  // Validate explicit routerAddresses up front so malformed multiaddrs fail fast.
  for (const a of rawAddrs) {
    multiaddr(a);
  }

  const banned = new BanSet();
  const node = await createMeshHost(mesh.identity, { ...options, banned });
  const authenticatedPeers = new Map<string, Date>();
  let session: MeshSession | undefined;
  try {
    await node.handle(
      AUTH_PROTOCOL,
      authStreamHandler({
        ownBiscuit: () => mesh.credential.biscuit,
        trustedKeys: () => mesh.credential.controlPlaneKeys,
        isBanned: (peerId) => banned.has(peerId),
        onAuthenticated: (peerId, verified) => authenticatedPeers.set(peerId, verified.expiration),
      }),
      AUTH_HANDLER_OPTIONS,
    );
    await node.handle(
      GOAWAY_PROTOCOL,
      goAwayStreamHandler({
        isHeldRouter: (peerId) => session?.isHeldRouter(peerId) === true,
        onGoAway: (peerId, msg, retryAfterMs) => session?.handleGoAway(peerId, msg, retryAfterMs),
      }),
      AUTH_HANDLER_OPTIONS,
    );

    session = new MeshSession(mesh, node, [], authenticatedPeers, banned, options);
    const failures = await session.topUpRouters(signal);
    // One admitted router is enough to be on the mesh; only the caller's own
    // signal turns that into a failure.
    if (options.signal?.aborted === true || session.routers.length === 0) {
      const detail = failures.length > 0 ? `:\n  ${failures.join("\n  ")}` : "";
      throw new Error(signal.aborted ? `join stopped: ${stopReason()}${detail}` : `no router admitted this member${detail}`);
    }
    // Best effort: a router that does not take the record is a warning the
    // next announcement retries; the member is on the mesh regardless. Under
    // the caller's signal only: a join that ran out of its own time still
    // announces the routers it holds.
    await session.announce(options.signal).catch(() => {});
    return session;
  } catch (err) {
    if (session !== undefined) {
      await session.close().catch(() => {});
    } else {
      await Promise.resolve(node.stop()).catch(() => {});
    }
    throw err;
  }
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** The peer a multiaddr ends at, in canonical form: its trailing `/p2p/<id>`, or undefined for a relay address with no target yet. */
function targetPeerOf(ma: Multiaddr): string | undefined {
  const last = ma.getComponents().at(-1);
  return last?.name === "p2p" && last.value !== undefined ? canonicalPeerId(last.value) : undefined;
}

/** The remote address of a connection, ending in `/p2p/<peerId>`. */
function connectedAddress(conn: Connection, peerId: string): Multiaddr {
  return targetPeerOf(conn.remoteAddr) === undefined ? conn.remoteAddr.encapsulate(`/p2p/${peerId}`) : conn.remoteAddr;
}

/** Canonicalizes a list from the control plane, dropping entries that are not peer IDs. */
function canonicalPeerIds(ids: string[]): string[] {
  const out: string[] = [];
  for (const id of ids) {
    try {
      out.push(canonicalPeerId(id));
    } catch {
      // Not a peer ID; it can match nothing, so it bans nothing.
    }
  }
  return out;
}
