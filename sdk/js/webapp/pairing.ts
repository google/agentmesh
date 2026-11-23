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

// A page that offers tools through the WebMCP local relay accepts calls only from
// a relay it paired with: any program on the computer can reach the relay's port.
// WebCrypto only, so the page and the relay launcher share this file.

/** The tool a page offers so an agent can pair its relay with a token from the page. */
export const PAIR_TOOL = "pair_agent";
/** The argument a paired relay puts in place of a call's arguments. */
export const CALL_FIELD = "_agentmesh";
/** How far a call's clock may be from the page's. The page remembers nonces for twice this, while a call can still pass. */
export const CALL_WINDOW_MS = 60_000;

/** A call signed by a paired relay. The arguments travel as the exact text the relay signed. */
export interface SignedCall { key_id: string; call_unix_ms: number; nonce: string; body: string; mac: string }
/** The relay's half of pairing, sent as the pair tool's arguments. */
export interface PairRequest { name: string; relay_nonce: string; proof: string }
/** The page's answer, returned as the pair tool's text result. */
export interface PairResponse { key_id: string; page_nonce: string; proof: string }
/** An agent the page trusts. */
export interface PairedAgent { key_id: string; name: string; key: string; paired_time: string }

const encoder = new TextEncoder();

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64url(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

/** A random value in base64url; 16 bytes is a pairing token. */
export function randomToken(bytes = 16): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function hmacKey(secret: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function mac(key: CryptoKey, text: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(text))));
}

async function macMatches(key: CryptoKey, text: string, expected: string): Promise<boolean> {
  try {
    return await crypto.subtle.verify("HMAC", key, fromBase64url(expected), encoder.encode(text));
  } catch {
    return false;
  }
}

async function deriveKey(token: string, relayNonce: string, pageNonce: string): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(token), "HKDF", false, ["deriveBits"]);
  const salt = encoder.encode(`${relayNonce}|${pageNonce}`);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: encoder.encode("agentmesh-webapp-relay") }, material, 256);
  return new Uint8Array(bits);
}

/** The relay side of pairing: a request that proves it holds the token, then the key from the page's answer. */
export async function startPairing(token: string, name: string): Promise<{
  request: PairRequest;
  finish(response: PairResponse): Promise<{ key_id: string; key: string }>;
}> {
  const tokenKey = await hmacKey(encoder.encode(token));
  const relayNonce = randomToken();
  return {
    request: { name, relay_nonce: relayNonce, proof: await mac(tokenKey, `pair|${relayNonce}|${name}`) },
    async finish(response) {
      if (!(await macMatches(tokenKey, `paired|${relayNonce}|${response.page_nonce}|${response.key_id}`, response.proof))) {
        throw new Error("The page did not prove it holds the pairing token. Copy a fresh prompt from the page.");
      }
      return { key_id: response.key_id, key: base64url(await deriveKey(token, relayNonce, response.page_nonce)) };
    },
  };
}

/** The page side of pairing: checks the relay's proof of the token and answers with a proof of its own. */
export async function answerPairing(token: string, request: PairRequest): Promise<{ response: PairResponse; agent: PairedAgent }> {
  const tokenKey = await hmacKey(encoder.encode(token));
  if (!(await macMatches(tokenKey, `pair|${request.relay_nonce}|${request.name}`, request.proof))) {
    throw new Error("The pairing token is wrong, expired or already used. Copy a fresh prompt from the page.");
  }
  const pageNonce = randomToken();
  const keyId = randomToken(8);
  return {
    response: { key_id: keyId, page_nonce: pageNonce, proof: await mac(tokenKey, `paired|${request.relay_nonce}|${pageNonce}|${keyId}`) },
    agent: {
      key_id: keyId,
      name: request.name,
      key: base64url(await deriveKey(token, request.relay_nonce, pageNonce)),
      paired_time: new Date().toISOString(),
    },
  };
}

// No version field: agentmesh-webapp serves the page and the relay from one build, and a saved relay
// that no longer matches fails with a wrong signature, which tells the user to download it again.
function callText(tool: string, call: Omit<SignedCall, "mac">): string {
  return `call|${tool}|${call.key_id}|${call.call_unix_ms}|${call.nonce}|${call.body}`;
}

/** The relay side of a call: the arguments a paired relay sends in place of args. */
export async function signCall(agent: { key_id: string; key: string }, tool: string, args: Record<string, unknown>): Promise<{ [CALL_FIELD]: SignedCall }> {
  const call = { key_id: agent.key_id, call_unix_ms: Date.now(), nonce: randomToken(), body: JSON.stringify(args) };
  return { [CALL_FIELD]: { ...call, mac: await mac(await hmacKey(fromBase64url(agent.key)), callText(tool, call)) } };
}

/** The page side of a call: accepts each signed call once, from a paired agent, within CALL_WINDOW_MS. */
export class CallVerifier {
  readonly #agents: () => readonly PairedAgent[];
  readonly #seen = new Map<string, number>();
  // Seen nonces live in memory, so a call signed before this verifier existed may be one it already ran.
  readonly #since: number;

  constructor(agents: () => readonly PairedAgent[], now = Date.now()) {
    this.#agents = agents;
    this.#since = now;
  }

  /** Returns the caller and its arguments, or throws an Error whose message the agent sees. */
  async verify(tool: string, input: Record<string, unknown>, now = Date.now()): Promise<{ agent: PairedAgent; args: Record<string, unknown> }> {
    const call = input[CALL_FIELD] as Partial<SignedCall> | undefined;
    if (typeof call !== "object" || call === null || typeof call.body !== "string" || typeof call.mac !== "string") {
      throw new Error("This node accepts calls only from a paired agent. Press Connect a local agent on the page and paste the prompt into your agent.");
    }
    const agent = this.#agents().find((candidate) => candidate.key_id === call.key_id);
    if (agent === undefined) throw new Error("This agent is no longer paired with the node. Copy a fresh prompt from the page.");
    for (const [nonce, at] of this.#seen) if (now - at > 2 * CALL_WINDOW_MS) this.#seen.delete(nonce);
    if (typeof call.call_unix_ms !== "number" || call.call_unix_ms < this.#since || Math.abs(now - call.call_unix_ms) > CALL_WINDOW_MS || typeof call.nonce !== "string" || this.#seen.has(call.nonce)) {
      throw new Error("Rejected a replayed or delayed call.");
    }
    const signed = { key_id: agent.key_id, call_unix_ms: call.call_unix_ms, nonce: call.nonce, body: call.body };
    if (!(await macMatches(await hmacKey(fromBase64url(agent.key)), callText(tool, signed), call.mac))) {
      throw new Error("Rejected a call with a wrong signature. If the mesh was updated, download the relay again with the command from the page's prompt.");
    }
    // Checked again after the await and spent in the same step, so two copies sent together run once.
    if (this.#seen.has(call.nonce)) throw new Error("Rejected a replayed or delayed call.");
    this.#seen.set(call.nonce, now);
    const args: unknown = JSON.parse(call.body);
    if (typeof args !== "object" || args === null || Array.isArray(args)) throw new Error("A signed call's arguments must be an object.");
    return { agent, args: args as Record<string, unknown> };
  }
}
