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

// MCP over a mesh stream, the client side of sam-node's /sam/mcp/1.0.0
// (internal/node/gate.go): an AuthFrame naming the service, the provider's
// AuthResponse, then JSON-RPC messages each with a varint length prefix.

import type { Connection, Stream } from "@libp2p/interface";
import { lpStream } from "@libp2p/utils";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { JSONRPCMessageSchema, type JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { AUTH_HANDSHAKE_TIMEOUT_MS, AuthRejectedError, MAX_AUTH_FRAME_BYTES, MCP_PROTOCOL } from "./auth.ts";
import { BiscuitVerificationError, requireRole, verifyPeerBiscuit, type VerifiedBiscuit } from "./biscuit.ts";
import { ROLE_NODE } from "./controlplane.ts";
import { decodeAuthResponse } from "./credential.ts";

/** go-msgio's default message cap, which sam-node's StreamTransport uses. */
export const MAX_MCP_MESSAGE_BYTES = 8 * 1024 * 1024;

/** The MCP client the SDK identifies itself as. */
export const MCP_CLIENT_INFO = { name: "agent-mesh-sdk", version: "0.1.0" };

/**
 * A Transport for @modelcontextprotocol/sdk over a libp2p stream that has
 * already passed the auth handshake.
 */
export class StreamTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;
  readonly #lp: ReturnType<typeof lpStream>;
  readonly #stream: Stream;
  #closed = false;

  constructor(stream: Stream) {
    this.#stream = stream;
    this.#lp = lpStream(stream, { maxDataLength: MAX_MCP_MESSAGE_BYTES });
  }

  async start(): Promise<void> {
    void this.#readLoop();
  }

  async #readLoop(): Promise<void> {
    const decoder = new TextDecoder();
    try {
      while (!this.#closed) {
        const frame = await this.#lp.read();
        const message = JSONRPCMessageSchema.parse(JSON.parse(decoder.decode(frame.subarray())));
        this.onmessage?.(message);
      }
    } catch (err) {
      if (!this.#closed) {
        this.onerror?.(err instanceof Error ? err : new Error(String(err)));
      }
    } finally {
      if (!this.#closed) {
        this.#closed = true;
        this.onclose?.();
      }
    }
  }

  async send(message: JSONRPCMessage): Promise<void> {
    await this.#lp.write(new TextEncoder().encode(JSON.stringify(message)));
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    await this.#stream.close().catch(() => this.#stream.abort(new Error("mcp stream close failed")));
    this.onclose?.();
  }
}

export interface MCPSessionOptions {
  /** Labels the provider's credential must carry, e.g. { region: "eu" }. */
  requiredLabels?: Record<string, string>;
  /** The agent this call is made for; attribution beside the token, as in sam-node. */
  agent?: string;
  signal?: AbortSignal;
}

/** An open MCP session with a provider on the mesh. */
export interface MCPSession {
  client: Client;
  /** The provider's verified credential. */
  provider: VerifiedBiscuit;
  close(): Promise<void>;
}

/**
 * The provider's credential lacks what the caller requires (any one pair) or
 * what the session's egress floor requires (every pair), as checkPeerLabels refuses.
 */
export class LabelsNotSatisfiedError extends Error {
  constructor(peerId: string, required: string[], what = "carries none of the required labels") {
    super(`peer ${peerId} ${what}: ${required.join(", ")}`);
    this.name = "LabelsNotSatisfiedError";
  }
}

/**
 * A caller's requirement is satisfied by any one pair, as sam-node's
 * api.LabelCheck (`check if label(k1, v1) or label(k2, v2)`): several pairs
 * mean "any of these will do". The egress floor (requireEgressLabels) is the
 * conjunction.
 */
export function requireLabels(provider: VerifiedBiscuit, required: Record<string, string> | undefined): void {
  if (!required) {
    return;
  }
  const pairs = Object.entries(required);
  if (pairs.length === 0 || pairs.some(([k, v]) => provider.labels[k] === v)) {
    return;
  }
  throw new LabelsNotSatisfiedError(
    provider.peerId,
    pairs.map(([k, v]) => `${k}=${v}`),
  );
}

/**
 * The egress floor is met only by every one of its pairs, as sam-node's
 * api.LabelFloorCheck (`check if label(k1, v1), label(k2, v2)`) for
 * egress.require_labels: a floor takes no alternatives. Empty is no floor.
 */
export function requireEgressLabels(provider: VerifiedBiscuit, required: Record<string, string> | undefined): void {
  if (!required) {
    return;
  }
  const pairs = Object.entries(required);
  if (pairs.every(([k, v]) => provider.labels[k] === v)) {
    return;
  }
  throw new LabelsNotSatisfiedError(
    provider.peerId,
    pairs.map(([k, v]) => `${k}=${v}`),
    "does not attest the egress floor",
  );
}

/**
 * Opens /sam/mcp/1.0.0 to a connected provider for targetService ("" is the
 * provider's own catalog), verifies the provider, and returns a connected
 * MCP client. frame is this member's AuthFrame for that service; egressRequireLabels
 * is the session's, not the caller's (requireEgressLabels).
 */
export async function openMCPSession(
  conn: Connection,
  frame: Uint8Array,
  trustedKeys: Uint8Array[],
  options: MCPSessionOptions = {},
  egressRequireLabels?: Record<string, string>,
): Promise<MCPSession> {
  const signal = options.signal ?? AbortSignal.timeout(AUTH_HANDSHAKE_TIMEOUT_MS);
  const stream = await conn.newStream(MCP_PROTOCOL, { signal, runOnLimitedConnection: true });
  let provider: VerifiedBiscuit;
  try {
    // The handshake frames are small; the MCP messages after them are not.
    const auth = lpStream(stream, { maxDataLength: MAX_AUTH_FRAME_BYTES });
    await auth.write(frame, { signal });
    const resp = decodeAuthResponse((await auth.read({ signal })).subarray());
    if (!resp.success) {
      throw new AuthRejectedError(conn.remotePeer.toString(), resp.error || "no reason given");
    }
    provider = await verifyPeerBiscuit(resp.biscuit, conn.remotePeer.toString(), trustedKeys);
    // Only nodes host services; a router's or an admin's credential is a member, not a provider.
    requireRole(provider, ROLE_NODE);
    requireLabels(provider, options.requiredLabels);
    requireEgressLabels(provider, egressRequireLabels);
  } catch (err) {
    await stream.close().catch(() => stream.abort(err instanceof Error ? err : new Error(String(err))));
    if (err instanceof BiscuitVerificationError) {
      throw new AuthRejectedError(conn.remotePeer.toString(), `provider credential rejected: ${err.message}`);
    }
    throw err;
  }

  const transport = new StreamTransport(stream);
  const client = new Client(MCP_CLIENT_INFO);
  await client.connect(transport, { signal });
  return {
    client,
    provider,
    close: async () => {
      await client.close();
      await transport.close();
    },
  };
}
