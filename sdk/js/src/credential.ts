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

import { create, fromBinary, fromJson, toBinary, toJson, type MessageInitShape } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import { attenuateBiscuit, sealBiscuit } from "./biscuit.ts";
import { toHex } from "./bytes.ts";
import {
  AuthFrameSchema,
  AuthResponseSchema,
  MemberCredentialSchema,
  TaskAuthorizationRuleSchema,
  type AuthResponse,
  type OIDCSession,
} from "./gen/sam_pb.ts";

/** What a member holds after enrolling: its biscuit and what it trusts. */
export interface MeshCredential {
  controlPlaneUrl: string;
  /** The biscuit the control plane minted for this identity. */
  biscuit: Uint8Array;
  /** Unix seconds at which the biscuit expires. */
  expiration: number;
  /** Every control plane signing key currently trusted (rotation keeps several valid). */
  controlPlaneKeys: Uint8Array[];
  /**
   * The trusted set when the biscuit was issued. A key trusted now that was
   * not in this set means a rotation happened since: the biscuit is signed
   * by a retiring key and must be refreshed before that key leaves its
   * grace period (sam-node's identityPredatesRotation).
   */
  issuedUnderKeys: Uint8Array[];
  /** Router multiaddrs, `/p2p/<peer id>` suffixed, as handed out at enrollment. */
  routerAddresses: string[];
  /**
   * What other implementations persist in the same file and this SDK does
   * not use: key receipt times and sam-node's OIDC session. Carried through
   * so a state directory survives a round trip untouched.
   */
  extra?: { receiveTime: Map<string, Timestamp>; oidcSession?: OIDCSession };
  /** Returns a new credential whose biscuit is attenuated in memory with rule. */
  attenuate?: (rule: MessageInitShape<typeof TaskAuthorizationRuleSchema>) => Promise<MeshCredential>;
  /** Returns a new credential whose biscuit is sealed against further attenuation. */
  seal?: () => Promise<MeshCredential>;
}

/** Attaches .attenuate() and .seal() convenience methods to a MeshCredential object. */
export function withCredentialMethods(c: MeshCredential): MeshCredential {
  const out: MeshCredential = {
    ...c,
    attenuate: (rule) => attenuateCredential(out, rule),
    seal: () => sealCredential(out),
  };
  return out;
}

/**
 * Returns a new MeshCredential with a tar_block appended offline in memory.
 * If the rule sets expire_time earlier than the credential's expiration,
 * the returned credential's expiration is narrowed to match.
 */
export async function attenuateCredential(
  c: MeshCredential,
  ruleInput: MessageInitShape<typeof TaskAuthorizationRuleSchema>,
): Promise<MeshCredential> {
  const rule = create(TaskAuthorizationRuleSchema, ruleInput);
  const biscuit = await attenuateBiscuit(c.biscuit, rule, c.controlPlaneKeys);
  let expiration = c.expiration;
  if (rule.expireTime !== undefined) {
    const ruleExp = Math.floor(timestampDate(rule.expireTime).getTime() / 1000);
    if (ruleExp < expiration) {
      expiration = ruleExp;
    }
  }
  return withCredentialMethods({
    ...c,
    biscuit,
    expiration,
  });
}

/** Returns a new MeshCredential whose biscuit is sealed so no further blocks can be appended. */
export async function sealCredential(c: MeshCredential): Promise<MeshCredential> {
  const biscuit = await sealBiscuit(c.biscuit, c.controlPlaneKeys);
  return withCredentialMethods({
    ...c,
    biscuit,
  });
}

/** Whether a key trusted now was unknown when the credential was issued. */
export function credentialPredatesRotation(c: MeshCredential): boolean {
  const issued = new Set(c.issuedUnderKeys.map((k) => toHex(k)));
  return c.controlPlaneKeys.some((k) => !issued.has(toHex(k)));
}

/** Seconds of validity left on the biscuit; negative once expired. */
export function credentialTimeToLiveSeconds(c: MeshCredential, nowMs = Date.now()): number {
  return c.expiration - Math.floor(nowMs / 1000);
}

/**
 * The first frame on every mesh stream (/sam/auth/1.0.0, /sam/mcp/1.0.0):
 * the caller's biscuit and the service it wants.
 * Framing (varint length prefix) is the transport's job.
 */
export function encodeAuthFrame(biscuit: Uint8Array, targetService = ""): Uint8Array {
  return toBinary(AuthFrameSchema, create(AuthFrameSchema, { biscuit, targetService }));
}

/** The peer's answer to an AuthResponse, carrying its own biscuit on success. */
export function decodeAuthResponse(bytes: Uint8Array): AuthResponse {
  return fromBinary(AuthResponseSchema, bytes);
}

/**
 * credential.json is the api.MemberCredential message as protojson with
 * proto field names, the layout `sam-node state export` writes and every
 * SDK reads. An unknown field is an error, as on every SAM surface.
 */
export function credentialToJSON(c: MeshCredential): string {
  const message = create(MemberCredentialSchema, {
    controlPlaneUrl: c.controlPlaneUrl,
    biscuit: c.biscuit,
    expireTime: timestampFromDate(new Date(c.expiration * 1000)),
    trustedKeys: c.controlPlaneKeys.map((k) => {
      const receiveTime = c.extra?.receiveTime.get(toHex(k));
      return receiveTime !== undefined ? { publicKey: k, receiveTime } : { publicKey: k };
    }),
    issuedUnderKeys: c.issuedUnderKeys,
    routerAddresses: c.routerAddresses,
    ...(c.extra?.oidcSession !== undefined ? { oidcSession: c.extra.oidcSession } : {}),
  });
  return JSON.stringify(toJson(MemberCredentialSchema, message, { useProtoFieldName: true }), null, 2) + "\n";
}

export function credentialFromJSON(text: string): MeshCredential {
  const message = fromJson(MemberCredentialSchema, JSON.parse(text));
  if (message.controlPlaneUrl === "" || message.biscuit.length === 0 || message.expireTime === undefined) {
    throw new Error("malformed credential file: control_plane_url, biscuit and expire_time are required");
  }
  const controlPlaneKeys = message.trustedKeys.map((k) => k.publicKey);
  const receiveTime = new Map<string, Timestamp>();
  for (const k of message.trustedKeys) {
    if (k.receiveTime !== undefined) {
      receiveTime.set(toHex(k.publicKey), k.receiveTime);
    }
  }
  return withCredentialMethods({
    controlPlaneUrl: message.controlPlaneUrl,
    biscuit: message.biscuit,
    expiration: Math.floor(timestampDate(message.expireTime).getTime() / 1000),
    controlPlaneKeys,
    // A file that recorded no issuance set: the keys trusted then are the best answer.
    issuedUnderKeys: message.issuedUnderKeys.length > 0 ? message.issuedUnderKeys : controlPlaneKeys,
    routerAddresses: message.routerAddresses,
    extra: { receiveTime, ...(message.oidcSession !== undefined ? { oidcSession: message.oidcSession } : {}) },
  });
}
