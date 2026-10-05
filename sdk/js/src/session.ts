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
import { AUTH_HANDLER_OPTIONS, AUTH_PROTOCOL, authenticateWithPeer, authStreamHandler } from "./auth.ts";
import { ROLE_ROUTER, attenuateBiscuit, requireRole, sealBiscuit, type VerifiedBiscuit } from "./biscuit.ts";
import { ROLE_NODE } from "./controlplane.ts";
import { encodeAuthFrame } from "./credential.ts";
import { canonicalPeerId } from "./identity.ts";
import { isServiceType, parseServiceTarget, serviceCID } from "./discovery.ts";
import type { TaskAuthorizationRuleSchema } from "./gen/sam_pb.ts";
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

export interface JoinOptions extends MeshHostOptions {
  /**
   * The routers to join through, `/…/p2p/<router>` multiaddrs, instead of
   * the ones the credential lists. A peer behind a router not named here is
   * still reached: connect() finds it through the routers' DHT and
   * authenticates with the router that relays for it.
   */
  routerAddresses?: string[];
  /**
   * Reserve a relay slot on the first router that admits us, so peers can
   * reach this member through the router. On by default; a member that
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
   * plane (sam-node's --control-plane-sync-interval). Gossip events bring a
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
   * sam-node's egress.require_labels for an SDK member: every provider this
   * session calls must attest all of these pairs, on top of a call's
   * requiredLabels. Held on every call, MCP and HTTP alike; no call waives it.
   */
  egressRequireLabels?: Record<string, string>;
  /** Bounds the whole join. */
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
/** sam-node's --control-plane-sync-interval default. */
const DEFAULT_POLICY_SYNC_MS = 15 * 60 * 1000;
/** sam-node's --control-plane-sync-interval default, and its 2s first pull. */
const DEFAULT_CONTROL_PLANE_SYNC_MS = 15 * 60 * 1000;
const FIRST_CONTROL_PLANE_SYNC_MS = 2_000;
const DEFAULT_CONTROL_PLANE_SYNC_JITTER_MS = 2_000;
const DEFAULT_RELAY_CHECK_MS = 30 * 1000;
/** How long a provider's positive egress verdict is kept; sam-node's labelGateTTL. */
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
  /** This member's agent, once acceptA2A was called. */
  endpoint: A2AEndpoint | undefined;
  #refreshTimer: ReturnType<typeof setTimeout> | undefined;
  #policyTimer: ReturnType<typeof setInterval> | undefined;
  #syncTimer: ReturnType<typeof setTimeout> | undefined;
  #relayTimer: ReturnType<typeof setInterval> | undefined;
  #syncing: Promise<ControlPlaneSync> | undefined;
  #keepingRelay: Promise<void> | undefined;
  readonly #relayListener: RelayListener | undefined;
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
    relayListener?: RelayListener,
    taskBiscuit?: Uint8Array,
  ) {
    this.mesh = mesh;
    this.node = node;
    this.routers = routers;
    this.authenticatedPeers = authenticatedPeers;
    this.banned = banned;
    this.#relayListener = relayListener;
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
      if (relayListener !== undefined) {
        this.#relayTimer = setInterval(() => void this.keepRelay().catch(() => {}), options.relayCheckIntervalMs ?? DEFAULT_RELAY_CHECK_MS);
        this.#relayTimer.unref?.();
      }
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
      ...(this.#egressRequireLabels !== undefined ? { egressRequireLabels: this.#egressRequireLabels } : {}),
    };
    return new MeshSession(this.mesh, this.node, this.routers, this.authenticatedPeers, this.banned, opts, this.#relayListener, taskBiscuit);
  }

  /**
   * The URL a fetch bound to this session (fetch()) takes for a service on a
   * peer: http://mesh/sam/<peer-id>/<type>/<name>/<path>, the shape of
   * sam-node's egress proxy and of an agent card it rewrote.
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

  /** The `.../p2p-circuit/p2p/<self>` addresses reserved on routers. */
  get relayAddresses(): Multiaddr[] {
    return this.node.getMultiaddrs().filter((ma) => ma.toString().includes("/p2p-circuit"));
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
      void authenticateWithPeer(conn, this.mesh.authFrame(), this.mesh.credential.controlPlaneKeys).catch(() => {});
    });
  }

  /**
   * Makes sure this member holds a relay reservation when it asked for one
   * at join: a router that restarted or trimmed the connection dropped it
   * and with it the relayed address peers reach this member on. Routers are
   * tried in order, each dialed and authenticated again first, since the
   * router forgot the admission with the connection. A router rescheduled
   * keeps its key and comes back on another address; the list the control
   * plane hands out, refreshed by every pull, names the current one, so the
   * router is dialed at what that list says and keeps the address the
   * connection was made on. Runs on relayCheckIntervalMs; exposed so a
   * caller can force it. Concurrent calls share one attempt. Upstream:
   * libp2p/js-libp2p#3601.
   */
  keepRelay(): Promise<void> {
    this.#keepingRelay ??= this.#keepRelayOnce().finally(() => {
      this.#keepingRelay = undefined;
    });
    return this.#keepingRelay;
  }

  async #keepRelayOnce(): Promise<void> {
    if (this.#relayListener === undefined || this.#closed || this.relayAddresses.length > 0) {
      return;
    }
    const failures: string[] = [];
    for (const [i, r] of this.routers.entries()) {
      const listed = this.mesh.credential.routerAddresses.map((a) => multiaddr(a)).filter((ma) => targetPeerOf(ma) === r.peerId);
      try {
        const conn = await this.node.dial(listed.length > 0 ? listed : r.addr);
        await authenticateWithPeer(conn, this.mesh.authFrame(), this.mesh.credential.controlPlaneKeys);
        const addr = connectedAddress(conn, r.peerId);
        this.routers[i] = { ...r, addr };
        await this.#relayListener.listen(addr.encapsulate("/p2p-circuit"));
        return;
      } catch (err) {
        failures.push(`${r.peerId}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    throw new Error(`no router granted a relay reservation:\n  ${failures.join("\n  ")}`);
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
   * The addresses the routers' DHT knows for a peer, its relayed ones
   * through routers this member has admitted by then: a relay opens a
   * circuit only for a source it authenticated, so a router met this way is
   * dialed and passed the handshake first, and joins the admitted set.
   */
  async #routedAddresses(peerId: string, signal?: AbortSignal): Promise<Multiaddr[]> {
    const lookup = signal ?? AbortSignal.timeout(PEER_ROUTING_TIMEOUT_MS);
    let found: { multiaddrs: Multiaddr[] };
    try {
      found = await this.node.peerRouting.findPeer(peerIdFromString(peerId), { signal: lookup });
    } catch {
      return [];
    }
    const out: Multiaddr[] = [];
    for (const ma of found.multiaddrs) {
      const text = ma.toString();
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
    const credential = await authenticateWithPeer(conn, this.mesh.authFrame(), this.mesh.credential.controlPlaneKeys);
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
   * Looks the DHT up for peers offering a service: `"mcp://calc"`, the
   * same string callTool and request take, or a type alone (`"mcp"`) for
   * every service of that type, or (type, name). Bounded by the timeout;
   * the DHT walk itself is what sam-node's discover does.
   */
  async discover(service: string, name?: string, options: { timeoutMs?: number; limit?: number } = {}): Promise<DiscoveredProvider[]> {
    const target = service.includes("://") ? parseServiceTarget(service) : { type: service, name };
    if (!isServiceType(target.type)) {
      throw new Error(`service type must be mcp, inference, a2a or egress, got ${JSON.stringify(target.type)}`);
    }
    const cid = await serviceCID(target.type, target.name);
    const signal = AbortSignal.timeout(options.timeoutMs ?? DISCOVERY_TIMEOUT_MS);
    const found = new Map<string, DiscoveredProvider>();
    try {
      for await (const provider of this.node.contentRouting.findProviders(cid, { signal })) {
        const peerId = provider.id.toString();
        if (peerId === this.peerId) {
          continue;
        }
        const entry = found.get(peerId) ?? { peerId, addrs: [] };
        for (const ma of provider.multiaddrs) {
          const text = ma.toString();
          if (!entry.addrs.includes(text)) {
            entry.addrs.push(text);
          }
        }
        found.set(peerId, entry);
        if (found.size >= (options.limit ?? 20)) {
          break;
        }
      }
    } catch (err) {
      // The lookup ended on its deadline; what was found so far is the answer.
      if (!(err instanceof Error && err.name === "TimeoutError") && !signal.aborted) {
        throw err;
      }
    }
    return [...found.values()];
  }

  /**
   * Opens an MCP session with a provider for targetService ("mcp://<name>",
   * or "" for the provider's own catalog tools).
   */
  async openMCP(peer: Peer, targetService: string, options: MCPSessionOptions = {}): Promise<MCPSession> {
    const conn = await this.connect(peer, options.signal);
    return openMCPSession(conn, encodeAuthFrame(this.biscuit, targetService), this.mesh.credential.controlPlaneKeys, options, this.#egressRequireLabels);
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
    await this.mesh.refresh();
    this.#scheduleRefresh();
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
    if (result.bannedPeerIds !== undefined) {
      const { banned } = this.banned.reconcile(canonicalPeerIds(result.bannedPeerIds), result.fetchedAt);
      await Promise.all(banned.map((peerId) => this.#evict(peerId)));
    }
    if (this.endpoint !== undefined) {
      try {
        await this.syncPolicy();
      } catch (err) {
        result.errors.push(`policy: ${err instanceof Error ? err.message : String(err)}`);
      }
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
   * acceptA2A() or syncPolicy().
   */
  get policyRules(): string[] {
    return this.#policyRules ?? [];
  }

  /** Re-reads the mesh policy from the control plane. */
  async syncPolicy(): Promise<void> {
    this.#policyRules = await this.mesh.controlPlane.policyRules(this.mesh.credential.biscuit);
  }

  /**
   * Calls an inference or A2A service on a provider over /libp2p-http, the
   * way sam-node's egress proxy does for /sam/<peer>/<type>/<name>/<path>.
   */
  async request(peer: Peer, targetService: string, path: string, options: HTTPRequestOptions = {}): Promise<HTTPResponse> {
    const conn = await this.#egressConnection(peer, options.signal);
    return httpRequestOverStream(conn, this.biscuit, targetService, path, options);
  }

  /**
   * The connection an HTTP call goes out on, its peer verified as an enrolled
   * node holding the floor before anything is sent (sam-node's VerifyPeerLabels).
   */
  async #egressConnection(peer: Peer, signal?: AbortSignal): Promise<Connection> {
    const conn = await this.connect(peer, signal);
    const peerId = conn.remotePeer.toString();
    const until = this.#egressVerdicts.get(peerId);
    if (until !== undefined && until.getTime() > Date.now()) {
      return conn;
    }
    const provider = await authenticateWithPeer(conn, this.mesh.authFrame(), this.mesh.credential.controlPlaneKeys);
    // Only nodes host services; a router's or an admin's credential is a member, not a provider.
    requireRole(provider, ROLE_NODE);
    requireEgressLabels(provider, this.#egressRequireLabels);
    this.#egressVerdicts.set(peerId, new Date(Date.now() + EGRESS_VERDICT_TTL_MS));
    return conn;
  }

  /**
   * A `fetch` bound to the mesh, for clients built on fetch such as the A2A
   * SDK's (`fetchImpl`): a request to http://mesh/sam/<peer-id>/<type>/<name>/<path>
   * is carried to that peer over /libp2p-http with this member's credential.
   * Response bodies stream, so message/stream works. See MeshSession.meshURL.
   */
  fetch(): typeof fetch {
    return async (input, init) => {
      const request = new Request(input, init);
      const { peerId } = splitMeshURL(new URL(request.url));
      const conn = await this.#egressConnection(peerId, request.signal);
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
   * is published by a sam-node. Fetches the mesh policy first and keeps it
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
      this.mesh.refresh().then(
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
    this.#closed = true;
    clearTimeout(this.#refreshTimer);
    clearTimeout(this.#syncTimer);
    clearInterval(this.#policyTimer);
    clearInterval(this.#relayTimer);
    if (!this.#isTaskView) {
      await this.node.stop();
    }
  }
}

/** Implements AgentMesh.join(); lives here to keep mesh.ts free of libp2p. */
export async function joinMesh(mesh: AgentMesh, options: JoinOptions = {}): Promise<MeshSession> {
  // The pull sam-node makes before it starts: a member resuming from its
  // state directory after a key rotation would otherwise verify the routers,
  // which already hold credentials under the new key, against the keys it
  // persisted, and the sync that would have brought the new key runs only
  // once joined. Best effort; the stored credential serves when the control
  // plane cannot be reached.
  try {
    await mesh.syncControlPlane();
  } catch {
    // Joining goes on with what the credential holds.
  }
  const routerAddrs = (options.routerAddresses ?? mesh.credential.routerAddresses).map((a) => multiaddr(a));
  if (routerAddrs.length === 0) {
    throw new Error(options.routerAddresses === undefined ? "credential lists no router addresses; the control plane had no active router at enrollment" : "routerAddresses names no router");
  }

  const banned = new BanSet();
  const node = await createMeshHost(mesh.identity, { ...options, banned });
  const admitted: AdmittedRouter[] = [];
  const authenticatedPeers = new Map<string, Date>();
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

    const failures: string[] = [];
    for (const addr of routerAddrs) {
      const routerPeer = targetPeerOf(addr);
      if (routerPeer === undefined) {
        failures.push(`${addr.toString()}: no /p2p/<peer id> component`);
        continue;
      }
      try {
        const conn = await node.dial(addr, options.signal !== undefined ? { signal: options.signal } : {});
        const credential = await authenticateWithPeer(conn, mesh.authFrame(), mesh.credential.controlPlaneKeys);
        // Enforced under the key that verified the token; a relay that is
        // not a router must not become our way onto the mesh.
        requireRole(credential, ROLE_ROUTER);
        admitted.push({ peerId: routerPeer, addr: connectedAddress(conn, routerPeer), credential });
      } catch (err) {
        failures.push(`${addr.toString()}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (admitted.length === 0) {
      throw new Error(`no router admitted this member:\n  ${failures.join("\n  ")}`);
    }

    let relayListener: RelayListener | undefined;
    if (options.reserveRelay ?? true) {
      relayListener = await listenThroughRelay(node, (admitted[0] as AdmittedRouter).addr);
    }
    return new MeshSession(mesh, node, admitted, authenticatedPeers, banned, options, relayListener);
  } catch (err) {
    await Promise.resolve(node.stop()).catch(() => {});
    throw err;
  }
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
