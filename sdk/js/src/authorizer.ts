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

// The provider-side authorizer, mirroring internal/node.(*SamNode).Authorize.
// Every piece of Datalog it evaluates is text: the baseline generated from
// api/datalog.go (gen/datalog.ts) and the mesh policy rules the control
// plane renders (GET /policies). Nothing here derives rules from roles.

import { AUTHORIZER_LIMITS, BiscuitVerificationError, loadBiscuit, verifyPeerBiscuit, withinLimits, type VerifiedBiscuit } from "./biscuit.ts";
import { parseServiceTarget } from "./discovery.ts";
import { BASELINE_DATALOG } from "./gen/datalog.ts";

/** What a caller asks for, as sam-node's RequestContext. */
export interface AuthorizeRequest {
  /** The caller's biscuit, as it arrived in the AuthFrame or X-Sam-Biscuit. */
  biscuit: Uint8Array;
  /** The peer at the other end of the authenticated connection. */
  peerId: string;
  /** "mcp://<name>", or "" for the protocol itself (the provider's own catalog). */
  targetService: string;
  /** The stream protocol; names the service when targetService is "". */
  protocol: string;
  /**
   * The HTTP method and the path as the backend sees it, when the request is
   * HTTP. Both are injected together; a request without them (a stream that
   * carries no HTTP request) does not match a grant narrowed by
   * PolicyRole.http.
   */
  method?: string;
  path?: string;
}

export interface ProviderAuthorizerOptions {
  /** Control plane keys, read per request so a rotation takes effect. */
  trustedKeys(): Uint8Array[];
  /** This provider's own biscuit; its identity facts are what target grants match. */
  ownBiscuit(): Uint8Array;
  /** The mesh policy as PolicyConfigGetResponse.datalog_rules. */
  policyRules(): string[];
  now?(): Date;
}

export class AuthorizationError extends Error {
  constructor(peerId: string, reason: string) {
    super(`caller ${peerId} is not authorized: ${reason}`);
    this.name = "AuthorizationError";
  }
}

// biscuit-wasm throws plain objects ({ FailedLogic: ... }, { RunLimit: ... }).
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

function timeFact(now: Date): string {
  return `${BASELINE_DATALOG.fact_time}(${now.toISOString().replace(/\.\d{3}Z$/, "Z")})`;
}

/**
 * Authorizes one request from a caller. Returns the caller's verified
 * credential when every check holds and a policy allows; throws
 * AuthorizationError otherwise. Every trusted key is tried, as
 * VerifyBiscuitToken does.
 */
export async function authorizeCaller(req: AuthorizeRequest, options: ProviderAuthorizerOptions): Promise<VerifiedBiscuit> {
  const wasm = await loadBiscuit();
  const now = options.now?.() ?? new Date();
  const keys = options.trustedKeys();
  if (keys.length === 0) {
    throw new AuthorizationError(req.peerId, "no trusted control plane key");
  }

  // Signature under a trusted key, authority block only, expiry and binding
  // to the connection peer: RequireAuthorityBinding and EnforceExpiration.
  let caller: VerifiedBiscuit;
  try {
    caller = await verifyPeerBiscuit(req.biscuit, req.peerId, keys, now);
  } catch (err) {
    throw new AuthorizationError(req.peerId, describe(err));
  }
  const token = wasm.Biscuit.fromBytes(req.biscuit, wasm.PublicKey.fromBytes(caller.verifyingKey, wasm.SignatureAlgorithm.Ed25519));

  const b = new wasm.AuthorizerBuilder();
  const fact = (source: string, params: Record<string, unknown> = {}) => {
    const f = wasm.Fact.fromString(source);
    for (const [k, v] of Object.entries(params)) {
      f.set(k, v);
    }
    b.addFact(f);
  };

  // The action: service(type, name). An empty target is the protocol itself
  // in the system namespace, as sam-node scopes its own catalog.
  let svcType: string;
  let svcName: string;
  if (req.targetService === "") {
    svcType = BASELINE_DATALOG.system_namespace;
    svcName = req.protocol;
  } else {
    let parsed: { type: string; name: string };
    try {
      parsed = parseServiceTarget(req.targetService);
    } catch (err) {
      throw new AuthorizationError(req.peerId, describe(err));
    }
    svcType = parsed.type;
    svcName = parsed.name;
  }
  fact(`${BASELINE_DATALOG.fact_service}({t}, {n})`, { t: svcType, n: svcName });
  fact(`${BASELINE_DATALOG.fact_connection_peer_id}({p})`, { p: req.peerId });
  fact(timeFact(now));

  // The request as the wire carried it, never as the caller describes it.
  if (req.method !== undefined) {
    fact(`${BASELINE_DATALOG.fact_method}({m})`, { m: req.method });
    fact(`${BASELINE_DATALOG.fact_path}({p})`, { p: req.path ?? "" });
  }

  b.addCheck(wasm.Check.fromString(BASELINE_DATALOG.replay_check));
  b.addCheck(wasm.Check.fromString(BASELINE_DATALOG.time_check));

  // This provider's identity as target_fact facts, so the caller's target
  // grants have something to match (injectIdentityFacts).
  for (const f of await identityTargetFacts(options.ownBiscuit(), keys, now)) {
    b.addFact(f);
  }

  b.addCheck(wasm.Check.fromString(BASELINE_DATALOG.target_check));
  for (const p of BASELINE_DATALOG.policies) {
    b.addPolicy(wasm.Policy.fromString(p));
  }
  for (const r of BASELINE_DATALOG.rules) {
    b.addRule(wasm.Rule.fromString(r));
  }
  for (const r of BASELINE_DATALOG.http_rules) {
    b.addRule(wasm.Rule.fromString(r));
  }
  for (const r of options.policyRules()) {
    b.addRule(wasm.Rule.fromString(r));
  }

  const authorizer = b.buildAuthenticated(token);
  try {
    withinLimits(() => authorizer.authorizeWithLimits(AUTHORIZER_LIMITS));
  } catch (err) {
    throw new AuthorizationError(req.peerId, describe(err));
  }
  return caller;
}

type WasmFact = ReturnType<Awaited<ReturnType<typeof loadBiscuit>>["Fact"]["fromString"]>;

/**
 * Evaluates this provider's own biscuit and returns its identity as
 * target_fact facts, one per target_fact rule of the baseline.
 */
async function identityTargetFacts(ownBiscuit: Uint8Array, keys: Uint8Array[], now: Date): Promise<WasmFact[]> {
  const wasm = await loadBiscuit();
  if (ownBiscuit.length === 0) {
    return [];
  }
  let own: VerifiedBiscuit;
  try {
    own = await verifyPeerBiscuit(ownBiscuit, await boundPeer(ownBiscuit, keys), keys, now);
  } catch (err) {
    throw new BiscuitVerificationError(`own credential does not verify: ${describe(err)}`, { cause: err });
  }
  const token = wasm.Biscuit.fromBytes(ownBiscuit, wasm.PublicKey.fromBytes(own.verifyingKey, wasm.SignatureAlgorithm.Ed25519));
  const b = new wasm.AuthorizerBuilder();
  b.addFact(wasm.Fact.fromString(timeFact(now)));
  b.addPolicy(wasm.Policy.fromString(BASELINE_DATALOG.allow_if_true));
  const authorizer = b.buildAuthenticated(token);
  withinLimits(() => authorizer.authorizeWithLimits(AUTHORIZER_LIMITS));
  const facts: WasmFact[] = [];
  for (const r of BASELINE_DATALOG.target_fact_rules) {
    facts.push(...withinLimits(() => authorizer.queryWithLimits(wasm.Rule.fromString(r), AUTHORIZER_LIMITS) as WasmFact[]));
  }
  return facts;
}

/** The peer a biscuit binds itself to: its node() fact. */
async function boundPeer(biscuit: Uint8Array, keys: Uint8Array[]): Promise<string> {
  const wasm = await loadBiscuit();
  let lastErr: unknown;
  for (const key of keys) {
    try {
      const token = wasm.Biscuit.fromBytes(biscuit, wasm.PublicKey.fromBytes(key, wasm.SignatureAlgorithm.Ed25519));
      const b = new wasm.AuthorizerBuilder();
      b.addPolicy(wasm.Policy.fromString(BASELINE_DATALOG.allow_if_true));
      const authorizer = b.buildAuthenticated(token);
      const bound = withinLimits(() => authorizer.queryWithLimits(wasm.Rule.fromString("p($p) <- node($p)"), AUTHORIZER_LIMITS) as WasmFact[])
        .map((f) => f.terms()[0])
        .find((t): t is string => typeof t === "string");
      if (bound === undefined) {
        throw new Error("biscuit carries no node() fact");
      }
      return bound;
    } catch (err) {
      lastErr = err;
    }
  }
  throw new BiscuitVerificationError(`biscuit is not signed by a trusted control plane key: ${describe(lastErr)}`);
}
