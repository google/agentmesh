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

// Client for the control plane's mesh-protocol surface: protobuf over HTTP
// (api/sam.proto). The operator plane (/admin/*, JSON) is out of scope.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { timestampMs, type Timestamp } from "@bufbuild/protobuf/wkt";
import { enrollChallenge, enrollStatusChallenge, refreshChallenge, registerChallenge } from "./challenges.ts";
import {
  BootstrapEnrollRequestSchema,
  BootstrapEnrollResponseSchema,
  ControlPlaneInfoResponseSchema,
  EnrollRequestSchema,
  EnrollResponseSchema,
  EnrollmentStatus,
  KeysResponseSchema,
  PolicyConfigGetResponseSchema,
  TokenRefreshRequestSchema,
  TokenRefreshResponseSchema,
  type BootstrapEnrollResponse,
  type ControlPlaneInfoResponse,
  type KeysResponse,
} from "./gen/sam_pb.ts";
import type { Identity } from "./identity.ts";
import { bytesEqual, toBase64, toBase64Url } from "./bytes.ts";
import { verifyEd25519 } from "./identity.ts";

export const PROTOBUF_CONTENT_TYPE = "application/x-protobuf";
export const HEADER_CHALLENGE_TIMESTAMP = "X-Sam-Challenge-Ts";
export const HEADER_CHALLENGE_SIGNATURE = "X-Sam-Challenge-Sig";

/** The role a plain mesh member enrolls with (api.RoleNode). */
export const ROLE_NODE = "sam:role:node";

/** How far a signed /keys response's timestamp may drift from our clock. */
export const KEYS_RESPONSE_FRESHNESS_MS = 5 * 60 * 1000;

const ED25519_PUBLIC_KEY_SIZE = 32;
const MAX_RESPONSE_BYTES = 1024 * 1024;

/** A non-2xx answer from the control plane. */
export class ControlPlaneError extends Error {
  readonly status: number;
  readonly body: string;

  constructor(path: string, status: number, body: string) {
    super(`control plane ${path}: HTTP ${status}${body ? `: ${body.trim()}` : ""}`);
    this.name = "ControlPlaneError";
    this.status = status;
    this.body = body;
  }
}

/** The control plane answered, and the answer is a refusal. */
export class EnrollmentRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnrollmentRejectedError";
  }
}

/**
 * The /keys answer is signed by no key this member trusts: every key it
 * holds has left the control plane's set, so its credential cannot be
 * verified or refreshed either.
 */
export class KeysNotTrustedError extends Error {
  constructor() {
    super("keys response is not signed by any trusted control plane key");
    this.name = "KeysNotTrustedError";
  }
}

/** Plaintext http:// to a host that is not loopback; see api.ValidateControlPlaneTransport. */
export class InsecureControlPlaneURLError extends Error {
  constructor(url: string) {
    super(`plaintext http:// control plane URL to a non-loopback host: ${url} (use https://, or set allowInsecure for a network you trust)`);
    this.name = "InsecureControlPlaneURLError";
  }
}

export interface ControlPlaneClientOptions {
  /** Base URL, e.g. https://mesh.example.com. */
  url: string;
  /** Accept plaintext http:// to a non-loopback host. Off by default. */
  allowInsecure?: boolean;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** Injection point for tests. Defaults to the global fetch. */
  fetch?: typeof fetch;
}

/** What an approved enrollment hands the caller. */
export interface Enrollment {
  biscuit: Uint8Array;
  /** Unix seconds at which the biscuit expires. */
  expiration: number;
  controlPlanePublicKey: Uint8Array;
  routerAddresses: string[];
}

export interface EnrollBootstrapParams {
  identity: Identity;
  bootstrapToken: string;
  /** Must equal the role the bootstrap token was minted for. Defaults to ROLE_NODE. */
  role?: string;
  labels?: Record<string, string>;
  /** Overrides the control plane's suggested poll interval while pending. */
  pollIntervalMs?: number;
  /** Bounds the wait for an operator to approve a pending enrollment. */
  signal?: AbortSignal;
}

export interface RegisterParams {
  identity: Identity;
  jwt: string;
  role?: string;
  labels?: Record<string, string>;
}

export interface RefreshParams {
  identity: Identity;
  /** The biscuit currently held; only the last one issued is redeemable. */
  biscuit: Uint8Array;
  /** Optional fresh platform/OIDC JWT for continuous attestation on refresh. */
  jwt?: string | undefined;
}

export interface RefreshResult {
  biscuit: Uint8Array;
  /** Unix seconds. */
  expiration: number;
}

function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "");
  return h.toLowerCase() === "localhost" || h === "127.0.0.1" || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
}

/** Mirrors api.ValidateControlPlaneTransport: https, or http to loopback only. */
export function validateControlPlaneURL(rawUrl: string, allowInsecure = false): URL {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new Error(`invalid control plane URL ${JSON.stringify(rawUrl)}`);
  }
  if (u.protocol === "https:") {
    return u;
  }
  if (u.protocol === "http:") {
    if (allowInsecure || isLoopbackHost(u.hostname)) {
      return u;
    }
    throw new InsecureControlPlaneURLError(rawUrl);
  }
  throw new Error(`control plane URL ${JSON.stringify(rawUrl)} must use http:// or https://`);
}

/**
 * Returns the key set if it is fresh and at least one listed key is already
 * trusted and its signature verifies. Mirrors api.VerifyKeysResponse.
 */
export function verifyKeysResponse(resp: KeysResponse, trusted: Uint8Array[], nowMs = Date.now()): Uint8Array[] {
  if (trusted.length === 0) {
    throw new Error("no trusted control plane key to verify /keys against");
  }
  if (resp.signatures.length !== resp.publicKeys.length) {
    throw new Error(`keys response carries ${resp.signatures.length} signatures for ${resp.publicKeys.length} keys`);
  }
  if (resp.signTime === undefined) {
    throw new Error("keys response carries no sign_time");
  }
  const issued = timestampMs(resp.signTime);
  if (Math.abs(nowMs - issued) > KEYS_RESPONSE_FRESHNESS_MS) {
    throw new Error(`keys response sign_time ${new Date(issued).toISOString()} is outside the freshness window`);
  }
  // Each signature covers the set and the signing time, deterministically
  // encoded with the signatures cleared.
  const payload = toBinary(KeysResponseSchema, create(KeysResponseSchema, { publicKeys: resp.publicKeys, signTime: resp.signTime }));
  const keys: Uint8Array[] = [];
  let verified = false;
  resp.publicKeys.forEach((pub, i) => {
    if (pub.length !== ED25519_PUBLIC_KEY_SIZE) {
      return;
    }
    keys.push(pub);
    if (verified) {
      return;
    }
    const sig = resp.signatures[i];
    if (sig && trusted.some((t) => bytesEqual(t, pub)) && verifyEd25519(pub, payload, sig)) {
      verified = true;
    }
  });
  if (!verified) {
    throw new KeysNotTrustedError();
  }
  return keys;
}

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error("aborted");
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError(signal));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortError(signal as AbortSignal));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export class ControlPlaneClient {
  readonly url: URL;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(options: ControlPlaneClientOptions) {
    this.url = validateControlPlaneURL(options.url, options.allowInsecure ?? false);
    // Unbound: a browser's fetch refuses to run as a method of anything else.
    const f = options.fetch ?? globalThis.fetch;
    this.#fetch = (input, init) => f(input, init);
    this.#timeoutMs = options.timeoutMs ?? 30_000;
  }

  /** GET /info: OIDC settings, router addresses and the ban list. Unauthenticated. */
  async info(): Promise<ControlPlaneInfoResponse> {
    const body = await this.#request("GET", "/info");
    return fromBinary(ControlPlaneInfoResponseSchema, body);
  }

  /**
   * GET /keys: every signing key the control plane currently trusts,
   * verified against a key the caller already trusts (the enrollment key).
   */
  async keys(trusted: Uint8Array[]): Promise<Uint8Array[]> {
    const body = await this.#request("GET", "/keys");
    return verifyKeysResponse(fromBinary(KeysResponseSchema, body), trusted);
  }

  /**
   * POST /enroll with a bootstrap token, then GET /enroll/status until an
   * operator approves the request if the mesh is not on auto-approve.
   */
  async enrollBootstrap(params: EnrollBootstrapParams): Promise<Enrollment> {
    const { identity, signal } = params;
    const role = params.role ?? ROLE_NODE;
    const ts = Date.now();
    const req = create(BootstrapEnrollRequestSchema, {
      bootstrapToken: params.bootstrapToken,
      peerId: identity.peerId,
      publicKey: identity.libp2pPublicKey,
      requestedRole: role,
      labels: params.labels ?? {},
      challengeUnixMs: BigInt(ts),
      challengeSignature: identity.sign(enrollChallenge(identity.peerId, ts)),
    });
    let resp = fromBinary(BootstrapEnrollResponseSchema, await this.#request("POST", "/enroll", toBinary(BootstrapEnrollRequestSchema, req)));

    while (resp.status === EnrollmentStatus.PENDING) {
      const waitMs = params.pollIntervalMs ?? Math.max(1, resp.pollIntervalSeconds) * 1000;
      await sleep(waitMs, signal);
      resp = await this.#enrollStatus(identity);
    }
    return enrollmentFromBootstrapResponse(resp);
  }

  async #enrollStatus(identity: Identity): Promise<BootstrapEnrollResponse> {
    const ts = Date.now();
    const sig = identity.sign(enrollStatusChallenge(identity.peerId, ts));
    const body = await this.#request("GET", `/enroll/status?peer_id=${encodeURIComponent(identity.peerId)}`, undefined, {
      [HEADER_CHALLENGE_TIMESTAMP]: String(ts),
      [HEADER_CHALLENGE_SIGNATURE]: toBase64Url(sig),
    });
    return fromBinary(BootstrapEnrollResponseSchema, body);
  }

  /** POST /register with an OIDC ID token. */
  async register(params: RegisterParams): Promise<Enrollment> {
    const { identity } = params;
    const ts = Date.now();
    const req = create(EnrollRequestSchema, {
      jwt: params.jwt,
      peerId: identity.peerId,
      publicKey: identity.libp2pPublicKey,
      requestedRole: params.role ?? ROLE_NODE,
      labels: params.labels ?? {},
      challengeUnixMs: BigInt(ts),
      challengeSignature: identity.sign(registerChallenge(identity.peerId, ts)),
    });
    const resp = fromBinary(EnrollResponseSchema, await this.#request("POST", "/register", toBinary(EnrollRequestSchema, req)));
    if (resp.errorMessage) {
      throw new EnrollmentRejectedError(`enrollment failed: ${resp.errorMessage}`);
    }
    return checkedEnrollment({
      biscuit: resp.biscuitToken,
      controlPlanePublicKey: resp.controlPlanePublicKey,
      routerAddresses: resp.routerAddresses,
    }, resp.expireTime);
  }

  /**
   * POST /refresh: trades the biscuit for a fresh one. The old one is
   * spent by this call; callers must persist the result before using it.
   */
  async refresh(params: RefreshParams): Promise<RefreshResult> {
    const { identity } = params;
    const ts = Date.now();
    const req = create(TokenRefreshRequestSchema, {
      challengeUnixMs: BigInt(ts),
      challengeSignature: identity.sign(refreshChallenge(identity.peerId, ts)),
      peerId: identity.peerId,
      ...(params.jwt ? { jwt: params.jwt } : {}),
    });
    const body = await this.#request("POST", "/refresh", toBinary(TokenRefreshRequestSchema, req), {
      Authorization: `Bearer ${toBase64(params.biscuit)}`,
    });
    const resp = fromBinary(TokenRefreshResponseSchema, body);
    if (resp.errorMessage) {
      throw new EnrollmentRejectedError(`refresh failed: ${resp.errorMessage}`);
    }
    if (resp.biscuitToken.length === 0) {
      throw new Error("refresh returned an empty biscuit");
    }
    return { biscuit: resp.biscuitToken, expiration: expirationSeconds(resp.expireTime, "refresh") };
  }

  /**
   * GET /policies: the mesh policy as the Datalog rules a provider adds to
   * its authorizer, one per entry, rendered by the control plane. The text
   * is the contract; nothing here derives rules from roles and bindings.
   */
  async policyRules(biscuit: Uint8Array): Promise<string[]> {
    const body = await this.#request("GET", "/policies", undefined, {
      Authorization: `Bearer ${toBase64(biscuit)}`,
    });
    const resp = fromBinary(PolicyConfigGetResponseSchema, body);
    if (resp.$unknown !== undefined && resp.$unknown.length > 0) {
      throw new Error("control plane predates datalog_rules in its policy response; upgrade the control plane");
    }
    return resp.datalogRules;
  }

  async #request(method: "GET" | "POST", path: string, body?: Uint8Array, headers: Record<string, string> = {}): Promise<Uint8Array> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`control plane ${path}: timed out after ${this.#timeoutMs}ms`)), this.#timeoutMs);
    try {
      const init: RequestInit = {
        method,
        headers: { Accept: PROTOBUF_CONTENT_TYPE, ...headers },
        signal: controller.signal,
      };
      if (body !== undefined) {
        init.body = new Uint8Array(body);
        init.headers = { ...init.headers, "Content-Type": PROTOBUF_CONTENT_TYPE };
      }
      const resp = await this.#fetch(new URL(path, this.url), init);
      const buf = new Uint8Array(await resp.arrayBuffer());
      if (buf.length > MAX_RESPONSE_BYTES) {
        throw new Error(`control plane ${path}: response of ${buf.length} bytes exceeds the ${MAX_RESPONSE_BYTES} byte limit`);
      }
      if (!resp.ok) {
        throw new ControlPlaneError(path, resp.status, new TextDecoder().decode(buf));
      }
      return buf;
    } finally {
      clearTimeout(timer);
    }
  }
}

function enrollmentFromBootstrapResponse(resp: BootstrapEnrollResponse): Enrollment {
  switch (resp.status) {
    case EnrollmentStatus.APPROVED:
      return checkedEnrollment({
        biscuit: resp.biscuitToken,
        controlPlanePublicKey: resp.controlPlanePublicKey,
        routerAddresses: resp.routerAddresses,
      }, resp.expireTime);
    case EnrollmentStatus.REJECTED:
      throw new EnrollmentRejectedError(`enrollment rejected: ${resp.errorMessage || "no reason given"}`);
    default:
      throw new Error(`unexpected enrollment status ${resp.status}: ${resp.errorMessage}`);
  }
}

function checkedEnrollment(e: Omit<Enrollment, "expiration">, expireTime: Timestamp | undefined): Enrollment {
  if (e.biscuit.length === 0) {
    throw new Error("received empty biscuit token");
  }
  if (e.controlPlanePublicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(`received invalid control plane public key size: ${e.controlPlanePublicKey.length} bytes (expected ${ED25519_PUBLIC_KEY_SIZE})`);
  }
  return { ...e, expiration: expirationSeconds(expireTime, "enrollment") };
}

/** A biscuit of unknown lifetime cannot be kept fresh; the control plane must say when it expires. */
function expirationSeconds(expireTime: Timestamp | undefined, what: string): number {
  if (expireTime === undefined) {
    throw new Error(`${what} response carries no expire_time`);
  }
  return Math.floor(timestampMs(expireTime) / 1000);
}
