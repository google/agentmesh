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

// The mesh's directory as a member uses it, as agentmesh-node does
// (internal/node/directory_client.go): the member keeps no DHT and asks the
// routers it holds over /mesh/directory/1.0.0, one DirectoryRequest per
// stream, one DirectoryResponse back. A request goes to one held router and
// to the next when it fails. The routers run the lookup across their own
// DHT. A key is the sha256 multihash of "mesh:service:<type>[:<name>]" for
// a service and of "mesh:peer:<peer_id>" for a member.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import type { Connection } from "@libp2p/interface";
import { lpStream } from "@libp2p/utils";
import { sha256 } from "multiformats/hashes/sha2";
import {
  DirectoryRequestSchema,
  DirectoryResponseSchema,
  type DirectoryRequest,
  type DirectoryResponse,
  type PeerRecord,
} from "./gen/agentmesh_pb.ts";

/** api.DirectoryProtocolID. */
export const DIRECTORY_PROTOCOL = "/mesh/directory/1.0.0";

const REQUEST_TIMEOUT_MS = 10_000;
const MAX_DIRECTORY_MESSAGE_BYTES = 64 * 1024;
export const DEFAULT_LIMIT = 20;

export type ServiceType = "mcp" | "inference" | "a2a" | "egress";

export function isServiceType(value: unknown): value is ServiceType {
  return value === "mcp" || value === "inference" || value === "a2a" || value === "egress";
}

/** The sha256 multihash of a name: the two-byte header and the digest. */
async function directoryKey(name: string): Promise<Uint8Array> {
  return (await sha256.digest(new TextEncoder().encode(name))).bytes;
}

/** The directory key of a service type, or of one named service of that type (api.ServiceKey). */
export async function serviceKey(type: ServiceType, name?: string): Promise<Uint8Array> {
  return directoryKey(["mesh:service", type, ...(name !== undefined && name !== "" ? [name] : [])].join(":"));
}

/** The directory key a member announces where it is reached under (api.PeerKey). */
export async function peerKey(peerId: string): Promise<Uint8Array> {
  return directoryKey(`mesh:peer:${peerId}`);
}

/** Splits "mcp://calculator" into its type and name; "" is the node's own catalog. */
export function parseServiceTarget(target: string): { type: ServiceType | ""; name: string } {
  if (target === "") {
    return { type: "", name: "" };
  }
  const m = /^(mcp|inference|a2a|egress):\/\/(.+)$/.exec(target);
  if (!m) {
    throw new Error(`service target must look like mcp://<name>, got ${JSON.stringify(target)}`);
  }
  return { type: m[1] as ServiceType, name: m[2] as string };
}

/** No held router answered a directory request. */
export class DirectoryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DirectoryError";
  }
}

/** A router connection a request goes over. */
export interface DirectoryRouter {
  peerId: string;
  connection(): Connection | undefined;
}

/** One request to one router, answered or thrown. */
async function ask(conn: Connection, req: DirectoryRequest, signal: AbortSignal): Promise<DirectoryResponse> {
  const stream = await conn.newStream(DIRECTORY_PROTOCOL, { signal });
  try {
    const lp = lpStream(stream, { maxDataLength: MAX_DIRECTORY_MESSAGE_BYTES });
    await lp.write(toBinary(DirectoryRequestSchema, req), { signal });
    const resp = fromBinary(DirectoryResponseSchema, (await lp.read({ signal })).subarray());
    if (resp.error !== "") {
      throw new DirectoryError(resp.error);
    }
    return resp;
  } finally {
    await stream.close().catch(() => stream.abort(new Error("directory stream not closed")));
  }
}

/**
 * Sends req to the held routers in turn until one answers. A router that
 * is restarting costs the request a timeout, not an answer. A lookup one
 * router answers with nothing is put to the next as well: a router cut
 * off from the routers closest to the key answers from what it can reach.
 */
export async function request(routers: DirectoryRouter[], req: DirectoryRequest, signal?: AbortSignal): Promise<DirectoryResponse> {
  const lookup = req.request.case === "findProviders" || req.request.case === "findPeer";
  const failures: string[] = [];
  let asked = 0;
  let empty: DirectoryResponse | undefined;
  for (const router of routers) {
    const conn = router.connection();
    if (conn === undefined) {
      continue;
    }
    asked++;
    const bounded = signal === undefined ? AbortSignal.timeout(REQUEST_TIMEOUT_MS) : AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]);
    try {
      const resp = await ask(conn, req, bounded);
      if (lookup && resp.providers.length === 0 && resp.peer === undefined) {
        empty = resp;
        continue;
      }
      return resp;
    } catch (err) {
      failures.push(`${router.peerId}: ${err instanceof Error ? err.message : String(err)}`);
      if (signal?.aborted === true) {
        break;
      }
    }
  }
  if (empty !== undefined) {
    return empty;
  }
  if (asked === 0) {
    throw new DirectoryError("no held router to ask");
  }
  throw new DirectoryError(`no held router answered: ${failures.join("; ")}`);
}

/**
 * Announces this member as a provider of key, reached at addrs, to a held
 * router; the router keeps the record and places it on the routers closest
 * to the key.
 */
export async function provide(routers: DirectoryRouter[], key: Uint8Array, addrs: string[], signal?: AbortSignal): Promise<void> {
  await request(routers, create(DirectoryRequestSchema, { request: { case: "provide", value: { key, addrs } } }), signal);
}

/**
 * Removes this member's record under key from the held router and from the
 * routers it was placed on.
 */
export async function withdraw(routers: DirectoryRouter[], key: Uint8Array, signal?: AbortSignal): Promise<void> {
  await request(routers, create(DirectoryRequestSchema, { request: { case: "withdraw", value: { key } } }), signal);
}

/** Who provides key, up to limit, with their addresses; empty when nobody does. */
export async function findProviders(routers: DirectoryRouter[], key: Uint8Array, limit = DEFAULT_LIMIT, signal?: AbortSignal): Promise<PeerRecord[]> {
  const resp = await request(routers, create(DirectoryRequestSchema, { request: { case: "findProviders", value: { key, limit: Math.max(limit, 1) } } }), signal);
  return resp.providers.slice(0, limit);
}

/**
 * Where a peer is reached: its addresses, each ending in its peer ID,
 * relayed ones included. Undefined when nobody knows the peer.
 */
export async function findPeer(routers: DirectoryRouter[], peerId: string, signal?: AbortSignal): Promise<PeerRecord | undefined> {
  const resp = await request(routers, create(DirectoryRequestSchema, { request: { case: "findPeer", value: { peerId } } }), signal);
  if (resp.peer === undefined || resp.peer.peerId !== peerId) {
    return undefined;
  }
  return resp.peer;
}
