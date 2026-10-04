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

// Verification of a peer's biscuit, mirroring internal/identity.verifyBiscuit:
// signed by a trusted control plane key, authority block + validated tar_block
// chain, unexpired, and bound to the peer at the other end of the connection.

import type { MessageInitShape } from "@bufbuild/protobuf";
import { BASELINE_DATALOG } from "./gen/datalog.ts";
import { TaskAuthorizationRuleSchema, type TaskAuthorizationRule } from "./gen/sam_pb.ts";
import { loadBiscuitWasm, type BiscuitWasm } from "./platform/wasm.ts";
import { effectiveTARExpiration, encodeTARBlockFact, parseTARBlockSource } from "./tar.ts";

let loading: Promise<BiscuitWasm> | undefined;

/** The biscuit-wasm module, loaded once, the way the runtime loads it. */
export function loadBiscuit(): Promise<BiscuitWasm> {
  loading ??= loadBiscuitWasm();
  return loading;
}

/** Datalog evaluation budget, as in internal/identity.AuthorizerOptions. */
export const AUTHORIZER_LIMITS = { max_facts: 1000, max_iterations: 100, max_time_micro: 1_000_000 };

/**
 * Runs an authorize or query call under AUTHORIZER_LIMITS. biscuit-wasm
 * applies the limits it is passed to the checks and policies only; the
 * fact-generation pass runs under the builder's own limits, 1 ms of wall
 * clock, which it does not let a caller change. A paused event loop or a
 * throttled CPU then answers a valid request with RunLimit Timeout. The
 * facts derived before that deadline stay in the authorizer and the next
 * call resumes from them, so the pass is driven to completion here until
 * the budget above is spent.
 */
export function withinLimits<T>(run: () => T): T {
  const deadline = performance.now() + AUTHORIZER_LIMITS.max_time_micro / 1000;
  for (;;) {
    try {
      return run();
    } catch (err) {
      if (!isTimeout(err) || performance.now() >= deadline) {
        throw err;
      }
    }
  }
}

function isTimeout(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { RunLimit?: unknown }).RunLimit === "Timeout";
}

export const ROLE_ROUTER = "sam:role:router";

export class BiscuitVerificationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BiscuitVerificationError";
  }
}

/** What a verified peer biscuit says about its holder. */
export interface VerifiedBiscuit {
  /** The peer the token is bound to (its node() or actor_node()/client_peer_id() fact). */
  peerId: string;
  /** The origin node channel when the token is a delegated session biscuit (actor_node()). */
  actorNode?: string;
  /** When the token lapses; the minimum of authority expiration() and any tar_block expire_time. */
  expiration: Date;
  /** The trusted key that verified the signature. */
  verifyingKey: Uint8Array;
  roles: string[];
  labels: Record<string, string>;
  /** Verified TaskAuthorizationRule chain from blocks 1..N (empty for unattenuated tokens). */
  taskRules: TaskAuthorizationRule[];
}

function describe(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

type QueriedFact = { terms(): unknown[] };

function parseWithTrustedKeys(
  wasm: BiscuitWasm,
  biscuitBytes: Uint8Array,
  trustedKeys: Uint8Array[],
): { token: ReturnType<BiscuitWasm["Biscuit"]["fromBytes"]>; verifyingKey: Uint8Array } {
  if (trustedKeys.length === 0) {
    throw new BiscuitVerificationError("no trusted control plane key to verify against");
  }
  let token: ReturnType<BiscuitWasm["Biscuit"]["fromBytes"]> | undefined;
  let verifyingKey: Uint8Array | undefined;
  let lastErr: unknown;
  for (const key of trustedKeys) {
    try {
      token = wasm.Biscuit.fromBytes(biscuitBytes, wasm.PublicKey.fromBytes(key, wasm.SignatureAlgorithm.Ed25519));
      verifyingKey = key;
      break;
    } catch (err) {
      lastErr = err;
    }
  }
  if (!token || !verifyingKey) {
    throw new BiscuitVerificationError(`biscuit is not signed by a trusted control plane key: ${describe(lastErr)}`);
  }
  return { token, verifyingKey };
}

function extractTARChain(token: ReturnType<BiscuitWasm["Biscuit"]["fromBytes"]>): TaskAuthorizationRule[] {
  const appendedCount = token.countBlocks() - 1;
  if (appendedCount > BASELINE_DATALOG.max_attenuation_blocks) {
    throw new BiscuitVerificationError(
      `biscuit carries ${appendedCount} appended blocks; maximum is ${BASELINE_DATALOG.max_attenuation_blocks}`,
    );
  }
  const taskRules: TaskAuthorizationRule[] = [];
  for (let i = 1; i <= appendedCount; i++) {
    try {
      taskRules.push(parseTARBlockSource(token.getBlockSource(i)));
    } catch (err) {
      throw new BiscuitVerificationError(`biscuit block ${i}: ${describe(err)}`);
    }
  }
  return taskRules;
}

/**
 * Verifies a biscuit received from expectedPeerId over an authenticated
 * connection. Every trusted key is tried, so a token minted under a
 * retiring key still verifies during rotation.
 *
 * By default (peer handshakes on /sam/auth/1.0.0), the authority block must
 * carry node(expectedPeerId). When allowDelegated is true (request tokens in
 * authorizeCaller), the authority block may alternatively carry both
 * actor_node(expectedPeerId) and client_peer_id(expectedPeerId) without node().
 */
export async function verifyPeerBiscuit(
  biscuitBytes: Uint8Array,
  expectedPeerId: string,
  trustedKeys: Uint8Array[],
  now: Date = new Date(),
  options?: { allowDelegated?: boolean },
): Promise<VerifiedBiscuit> {
  const wasm = await loadBiscuit();
  const { token, verifyingKey } = parseWithTrustedKeys(wasm, biscuitBytes, trustedKeys);
  const taskRules = extractTARChain(token);

  const builder = new wasm.AuthorizerBuilder();
  builder.addFact(wasm.Fact.fromString(`time(${now.toISOString().replace(/\.\d{3}Z$/, "Z")})`));
  builder.addCheck(wasm.Check.fromString("check if time($t), expiration($e), $t <= $e"));
  builder.addPolicy(wasm.Policy.fromString("allow if true"));
  const authorizer = builder.buildAuthenticated(token);
  try {
    withinLimits(() => authorizer.authorizeWithLimits(AUTHORIZER_LIMITS));
  } catch (err) {
    throw new BiscuitVerificationError(`biscuit is expired or fails its checks: ${describe(err)}`);
  }

  const query = (rule: string) => withinLimits(() => authorizer.queryWithLimits(wasm.Rule.fromString(rule), AUTHORIZER_LIMITS) as QueriedFact[]);
  const strings = (facts: QueriedFact[]) => facts.map((f) => f.terms()[0]).filter((t): t is string => typeof t === "string");

  const bound = strings(query("p($p) <- node($p)"));
  const actorNodes = strings(query("a($a) <- actor_node($a)"));
  const clientPeers = strings(query("c($c) <- client_peer_id($c)"));
  const isBoundNode = bound.includes(expectedPeerId);
  const isBoundDelegated =
    options?.allowDelegated === true &&
    actorNodes.includes(expectedPeerId) &&
    clientPeers.includes(expectedPeerId);
  if (!isBoundNode && !isBoundDelegated) {
    throw new BiscuitVerificationError(`biscuit is not bound to peer ${expectedPeerId}`);
  }

  const expirations = query("e($e) <- expiration($e)")
    .map((f) => f.terms()[0])
    .filter((t): t is Date => t instanceof Date && !Number.isNaN(t.getTime()));
  if (expirations.length === 0) {
    throw new BiscuitVerificationError("biscuit carries no expiration fact");
  }
  const authorityExpiration = new Date(Math.min(...expirations.map((d) => d.getTime())));
  const expiration = effectiveTARExpiration(authorityExpiration, taskRules);
  if (now.getTime() > expiration.getTime()) {
    throw new BiscuitVerificationError(
      `biscuit is expired at ${now.toISOString()} (effective expiration ${expiration.toISOString()})`,
    );
  }

  const labels: Record<string, string> = {};
  for (const f of query("l($k, $v) <- label($k, $v)")) {
    const [k, v] = f.terms();
    if (typeof k === "string" && typeof v === "string") {
      labels[k] = v;
    }
  }

  return {
    peerId: expectedPeerId,
    ...(actorNodes[0] !== undefined ? { actorNode: actorNodes[0] } : {}),
    expiration,
    verifyingKey,
    roles: strings(query("r($r) <- role($r)")),
    labels,
    taskRules,
  };
}

/**
 * Appends a non-authority block carrying a single tar_block("<base64url-proto>")
 * fact to an existing Biscuit token in memory without contacting the control plane.
 */
export async function attenuateBiscuit(
  biscuitBytes: Uint8Array,
  ruleInput: MessageInitShape<typeof TaskAuthorizationRuleSchema>,
  trustedKeys: Uint8Array[],
): Promise<Uint8Array> {
  const wasm = await loadBiscuit();
  const { token } = parseWithTrustedKeys(wasm, biscuitBytes, trustedKeys);
  const appendedCount = token.countBlocks() - 1;
  if (appendedCount >= BASELINE_DATALOG.max_attenuation_blocks) {
    throw new BiscuitVerificationError(
      `biscuit already has ${appendedCount} appended blocks (maximum ${BASELINE_DATALOG.max_attenuation_blocks})`,
    );
  }
  extractTARChain(token);
  const factStr = encodeTARBlockFact(ruleInput);
  const block = wasm.Biscuit.block_builder();
  block.addFact(wasm.Fact.fromString(factStr));
  try {
    return token.appendBlock(block).toBytes();
  } catch (err) {
    throw new BiscuitVerificationError(`failed to append tar_block to biscuit: ${describe(err)}`);
  }
}

/**
 * Seals a Biscuit token so no further blocks can be appended by downstream holders.
 */
export async function sealBiscuit(biscuitBytes: Uint8Array, trustedKeys: Uint8Array[]): Promise<Uint8Array> {
  const wasm = await loadBiscuit();
  const { token } = parseWithTrustedKeys(wasm, biscuitBytes, trustedKeys);
  extractTARChain(token);
  try {
    return token.sealToken().toBytes();
  } catch (err) {
    throw new BiscuitVerificationError(`failed to seal biscuit: ${describe(err)}`);
  }
}

/** Requires role(<role>) on an already verified token, as identity.RequireRole. */
export function requireRole(verified: VerifiedBiscuit, role: string): void {
  if (!verified.roles.includes(role)) {
    throw new BiscuitVerificationError(`biscuit lacks expected role ${JSON.stringify(role)}`);
  }
}

