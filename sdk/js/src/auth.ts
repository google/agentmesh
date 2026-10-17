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

// The /mesh/auth/1.0.0 handshake, both sides. One varint-length-prefixed
// AuthFrame, one AuthResponse back; go-msgio framing on the Go side is
// the same unsigned varint prefix lpStream uses.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import type { Connection, Stream, StreamHandler } from "@libp2p/interface";
import { lpStream } from "@libp2p/utils";
import { BiscuitVerificationError, verifyPeerBiscuit, type VerifiedBiscuit } from "./biscuit.ts";
import { decodeAuthResponse } from "./credential.ts";
import {
  AuthFrameSchema,
  AuthResponseSchema,
  RouterGoAwaySchema,
  RouterGoAway_Reason,
  type RouterGoAway,
} from "./gen/agentmesh_pb.ts";

export const AUTH_PROTOCOL = "/mesh/auth/1.0.0";
export const MCP_PROTOCOL = "/mesh/mcp/1.0.0";
export const GOAWAY_PROTOCOL = "/mesh/goaway/1.0.0";

/** The first frame on a stream is capped, as msgio.NewVarintReaderSize(s, 64 KiB). */
export const MAX_AUTH_FRAME_BYTES = 64 * 1024;
/** How long either side waits for the other's frame. */
export const AUTH_HANDSHAKE_TIMEOUT_MS = 10_000;

/** The go-away message on /mesh/goaway/1.0.0 is capped at 1 KiB, with a 5s read timeout. */
export const MAX_GOAWAY_MESSAGE_BYTES = 1024;
export const GOAWAY_STREAM_TIMEOUT_MS = 5_000;
/** Default duration a router is shunned when retry_after is unset or non-positive (5 minutes). */
export const ROUTER_SHUN_DURATION_MS = 5 * 60_000;
/** Maximum duration a router go-away retry_after can shun a router (1 hour). */
export const GOAWAY_MAX_RETRY_AFTER_MS = 60 * 60_000;

export class AuthRejectedError extends Error {
  constructor(peerId: string, reason: string) {
    super(`peer ${peerId} rejected the auth handshake: ${reason}`);
    this.name = "AuthRejectedError";
  }
}

function framed(stream: Stream) {
  return lpStream(stream, { maxDataLength: MAX_AUTH_FRAME_BYTES });
}

/**
 * Client side: presents frame on a new /mesh/auth/1.0.0 stream and returns
 * the peer's verified credential. trustedKeys are the control plane keys.
 * The handshake has a timeout of its own; outer, when given, can end it sooner.
 */
export async function authenticateWithPeer(conn: Connection, frame: Uint8Array, trustedKeys: Uint8Array[], outer?: AbortSignal): Promise<VerifiedBiscuit> {
  const signal = outer === undefined ? AbortSignal.timeout(AUTH_HANDSHAKE_TIMEOUT_MS) : AbortSignal.any([outer, AbortSignal.timeout(AUTH_HANDSHAKE_TIMEOUT_MS)]);
  // A peer behind a router is reached over a relayed, limited connection.
  const stream = await conn.newStream(AUTH_PROTOCOL, { signal, runOnLimitedConnection: true });
  try {
    const lp = framed(stream);
    await lp.write(frame, { signal });
    const resp = decodeAuthResponse((await lp.read({ signal })).subarray());
    if (!resp.success) {
      throw new AuthRejectedError(conn.remotePeer.toString(), resp.error || "no reason given");
    }
    if (resp.biscuit.length === 0) {
      throw new AuthRejectedError(conn.remotePeer.toString(), "empty credential in the mutual response");
    }
    // Discovery names whoever answered; only this says the peer is enrolled.
    return await verifyPeerBiscuit(resp.biscuit, conn.remotePeer.toString(), trustedKeys);
  } finally {
    await stream.close().catch(() => stream.abort(new Error("auth stream close failed")));
  }
}

export interface AuthServerOptions {
  /** This member's current biscuit, read per handshake so a refresh takes effect. */
  ownBiscuit(): Uint8Array;
  trustedKeys(): Uint8Array[];
  /** Peers the control plane has banned; a banned peer's frame gets no answer. */
  isBanned?(peerId: string): boolean;
  /** Called with every peer that passes; the session keeps the admitted set. */
  onAuthenticated?(peerId: string, verified: VerifiedBiscuit): void;
}

/** Options for libp2p.handle() so the handshake also runs over relayed connections. */
export const AUTH_HANDLER_OPTIONS = { runOnLimitedConnection: true };

/**
 * Server side of /mesh/auth/1.0.0, mirroring agentmesh-node's HandleAuthHandshake:
 * verify the caller's biscuit against the control plane keys and its
 * connection peer ID, then answer with our own. A failed verification gets
 * no answer, only a closed stream, as on the Go side.
 */
export function authStreamHandler(options: AuthServerOptions): StreamHandler {
  return async (stream: Stream, connection: Connection) => {
    const peerId = connection.remotePeer.toString();
    const signal = AbortSignal.timeout(AUTH_HANDSHAKE_TIMEOUT_MS);
    try {
      const lp = framed(stream);
      const frame = fromBinary(AuthFrameSchema, (await lp.read({ signal })).subarray());
      if (options.isBanned?.(peerId) === true) {
        stream.log?.("auth handshake from %s refused: peer is revoked", peerId);
        return;
      }
      let verified: VerifiedBiscuit;
      try {
        verified = await verifyPeerBiscuit(frame.biscuit, peerId, options.trustedKeys());
      } catch (err) {
        if (err instanceof BiscuitVerificationError) {
          stream.log?.("auth handshake from %s refused: %s", peerId, err.message);
          return;
        }
        throw err;
      }
      options.onAuthenticated?.(peerId, verified);
      await lp.write(toBinary(AuthResponseSchema, create(AuthResponseSchema, { success: true, biscuit: options.ownBiscuit() })), { signal });
    } finally {
      await stream.close().catch(() => stream.abort(new Error("auth stream close failed")));
    }
  };
}

/** Returns the canonical proto enum name for a RouterGoAway_Reason value. */
export function goAwayReasonName(reason: RouterGoAway_Reason): string {
  switch (reason) {
    case RouterGoAway_Reason.DRAINING:
      return "DRAINING";
    case RouterGoAway_Reason.OVERLOADED:
      return "OVERLOADED";
    default:
      return "REASON_UNSPECIFIED";
  }
}

/**
 * Computes the shun duration in milliseconds from a RouterGoAway message:
 * defaults to ROUTER_SHUN_DURATION_MS (5m) when retry_after <= 0, capped at
 * GOAWAY_MAX_RETRY_AFTER_MS (1h).
 */
export function clampGoAwayRetryAfterMs(msg: RouterGoAway): number {
  let ms = 0;
  if (msg.retryAfter !== undefined) {
    ms = Number(msg.retryAfter.seconds) * 1000 + Math.floor(msg.retryAfter.nanos / 1_000_000);
  }
  if (ms <= 0) {
    return ROUTER_SHUN_DURATION_MS;
  }
  if (ms > GOAWAY_MAX_RETRY_AFTER_MS) {
    return GOAWAY_MAX_RETRY_AFTER_MS;
  }
  return ms;
}

export interface GoAwayServerOptions {
  /** Whether peerId is currently a router this member holds. */
  isHeldRouter(peerId: string): boolean;
  /** Called once a held router's RouterGoAway message has been read and the stream closed. */
  onGoAway(peerId: string, msg: RouterGoAway, retryAfterMs: number): void | Promise<void>;
}

/**
 * Server side of /mesh/goaway/1.0.0, mirroring agentmesh-node's HandleGoAway:
 * reads one varint-prefixed RouterGoAway message (1024 B cap, 5s timeout) only
 * from a router the member currently holds, closes the stream, and notifies
 * the session to shun the router and top up from the catalog.
 */
export function goAwayStreamHandler(options: GoAwayServerOptions): StreamHandler {
  return async (stream: Stream, connection: Connection) => {
    const peerId = connection.remotePeer.toString();
    if (!options.isHeldRouter(peerId)) {
      stream.abort(new Error(`ignoring go-away from unattached peer ${peerId}`));
      return;
    }
    const signal = AbortSignal.timeout(GOAWAY_STREAM_TIMEOUT_MS);
    let msg: RouterGoAway;
    try {
      const lp = lpStream(stream, { maxDataLength: MAX_GOAWAY_MESSAGE_BYTES });
      msg = fromBinary(RouterGoAwaySchema, (await lp.read({ signal })).subarray());
    } catch (err) {
      stream.abort(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    await stream.close().catch(() => stream.abort(new Error("goaway stream close failed")));
    const retryAfterMs = clampGoAwayRetryAfterMs(msg);
    await options.onGoAway(peerId, msg, retryAfterMs);
  };
}

