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

// What a member keeps in step with the control plane while it runs, as
// agentmesh-node's controlplane_sync.go: the ban set, reconciled from /info, and
// the gossip events that bring the next pull forward.

import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { timestampMs, type Timestamp } from "@bufbuild/protobuf/wkt";
import { canonicalPeerId, verifyEd25519 } from "./identity.ts";
import { MeshEvent_Type, MeshEventSchema, type MeshEvent } from "./gen/agentmesh_pb.ts";

/** The GossipSub topic the control plane publishes mesh events on (api.GossipEvents). */
export const GOSSIP_EVENTS_TOPIC = "/mesh/events/v1";

/** How far an event's timestamp may be from now; older or later ones are ignored. */
export const EVENT_FRESHNESS_MS = 5 * 60 * 1000;

/**
 * The peers the control plane has banned, with when each ban was learned.
 * A ban recorded at or after the instant a /info answer was requested is
 * kept when that answer omits it: the answer predates the ban and cannot
 * speak to it.
 */
export class BanSet {
  readonly #bannedAt = new Map<string, number>();

  has(peerId: string): boolean {
    return this.#bannedAt.has(peerId);
  }

  get size(): number {
    return this.#bannedAt.size;
  }

  peers(): string[] {
    return [...this.#bannedAt.keys()].sort();
  }

  /**
   * Records a ban; returns false when the peer was already in the set. The
   * set then keeps the later of the stored time and atMs: a ban time never
   * moves back. A second event for a peer can be a new ban, because the
   * control plane publishes no event when it lifts one.
   */
  add(peerId: string, atMs: number): boolean {
    const known = this.#bannedAt.get(peerId);
    if (known === undefined || atMs > known) {
      this.#bannedAt.set(peerId, atMs);
    }
    return known === undefined;
  }

  /**
   * Makes the set match the control plane's ban set as of fetchedAt.
   * Returns the peers newly banned and the peers whose ban was lifted.
   */
  reconcile(bannedPeerIds: string[], fetchedAt: Date): { banned: string[]; unbanned: string[] } {
    const fetchedAtMs = fetchedAt.getTime();
    const current = new Set(bannedPeerIds);
    const unbanned: string[] = [];
    for (const [peerId, at] of this.#bannedAt) {
      if (current.has(peerId) || at >= fetchedAtMs) {
        continue;
      }
      this.#bannedAt.delete(peerId);
      unbanned.push(peerId);
    }
    const banned: string[] = [];
    for (const peerId of current) {
      if (this.add(peerId, fetchedAtMs)) {
        banned.push(peerId);
      }
    }
    return { banned, unbanned };
  }
}

/** A MeshEvent that verified: signed by a trusted key and carrying a fresh event_time. */
/** A MeshEvent that verified: signed by a trusted key, carrying a fresh event_time, its peer id in canonical form. */
export type VerifiedMeshEvent = MeshEvent & { eventTime: Timestamp };

/**
 * Verifies a MeshEvent as agentmesh-node's verifyEvent does: the signature covers
 * the deterministic encoding of the event with the signature cleared, under
 * any trusted control plane key. Returns the event, or undefined when it
 * does not verify, is not fresh, or bans something that is not a peer ID.
 */
export function verifyMeshEvent(data: Uint8Array, trustedKeys: Uint8Array[], now: Date = new Date()): VerifiedMeshEvent | undefined {
  let event: MeshEvent;
  try {
    event = fromBinary(MeshEventSchema, data);
  } catch {
    return undefined;
  }
  const signature = event.signature;
  const unsigned = toBinary(MeshEventSchema, { ...event, signature: new Uint8Array() });
  if (!trustedKeys.some((key) => verifyEd25519(key, unsigned, signature))) {
    return undefined;
  }
  if (event.eventTime === undefined) {
    return undefined;
  }
  const skew = Math.abs(now.getTime() - timestampMs(event.eventTime));
  if (skew > EVENT_FRESHNESS_MS) {
    return undefined;
  }
  if (event.type === MeshEvent_Type.BANNED) {
    // Canonicalized after the signature check, which covers the bytes as sent.
    try {
      return { ...event, peerId: canonicalPeerId(event.peerId) } as VerifiedMeshEvent;
    } catch {
      return undefined;
    }
  }
  return event as VerifiedMeshEvent;
}

export { MeshEvent_Type };
