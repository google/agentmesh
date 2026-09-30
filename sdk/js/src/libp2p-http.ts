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

// The /libp2p-http protocol (go-libp2p-http): the client that calls inference
// and A2A services on the mesh, and the ingress that accepts A2A requests for
// this member's own agent, gated by the authorizer the way sam-node gates its
// ingress (StartIngressServer in internal/node). Requests and responses are
// framed by the codec in http1.ts on the libp2p stream itself, so bodies
// stream in both directions, an A2A message/stream (SSE) works, and none of
// it needs Node: a member in a browser calls and answers the same way. A
// Node request listener (an Express app) is served by libp2p-http-node.ts.

import type { Connection, Stream, StreamHandler } from "@libp2p/interface";
import { AUTH_HANDSHAKE_TIMEOUT_MS } from "./auth.ts";
import { AuthorizationError, authorizeCaller, type ProviderAuthorizerOptions } from "./authorizer.ts";
import type { VerifiedBiscuit } from "./biscuit.ts";
import { fromBase64, toBase64 } from "./bytes.ts";
import {
  ByteReader,
  HTTPParseError,
  LAST_CHUNK,
  bodyStream,
  encodeChunk,
  encodeRequestHead,
  encodeResponseHead,
  readBody,
  readRequestHead,
  readResponseHead,
  requestBodyFraming,
  responseBodyFraming,
  sendAll,
  streamSource,
} from "./http1.ts";
import { canonicalPeerId } from "./identity.ts";

/** go-libp2p-http's protocol: plain HTTP/1.1 on a stream, one request per stream. */
export const HTTP_PROTOCOL = "/libp2p-http";

/** Headers of the mesh HTTP datapath (api/network.go). */
export const HEADER_SAM_BISCUIT = "x-sam-biscuit";
export const HEADER_SAM_AGENT = "x-sam-agent";
export const HEADER_PEER_ID = "x-peer-id";
export const HEADER_SAM_NO_TRAILING_SLASH = "x-sam-no-trailing-slash";

/** Options for libp2p.handle() so the agent is reachable over relayed connections. */
export const HTTP_HANDLER_OPTIONS = { runOnLimitedConnection: true };

/** The service name an agent answers under unless it picks another. */
export const DEFAULT_A2A_NAME = "agent";

/**
 * The path prefix of a mesh URL, http://mesh/sam/<peer-id>/<type>/<name>/<path>:
 * the shape of sam-node's egress proxy and of an agent card rewritten for the
 * mesh, by sam-node or by this SDK. The host is ignored; the peer ID is in the
 * path because URL parsers lowercase the host and a peer ID is case-sensitive.
 */
export const MESH_PATH_PREFIX = "/sam/";

/** The well-known agent card location (A2A spec / RFC 8615). */
export const AGENT_CARD_PATH = ".well-known/agent-card.json";

const MAX_AGENT_CARD_BYTES = 1 << 20;

/** Largest request body the ingress reads whole for a handler or url target. */
export const MAX_INGRESS_BODY_BYTES = 8 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 60_000;

/** A fetch-style handler in this process. */
export type HTTPHandler = (request: Request, caller: VerifiedBiscuit) => Promise<Response> | Response;

/**
 * A request listener of the runtime's own HTTP server, such as an Express
 * app with the A2A SDK's handlers mounted. On Node it is
 * (req: http.IncomingMessage, res: http.ServerResponse) => void, served by
 * libp2p-http-node.ts; a browser has no such server and answers 501.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type NodeRequestListener = (req: any, res: any) => void;

/**
 * This member's agent as other members reach it: `a2a://<name>`, answered by
 * exactly one of url (an A2A server beside this process), handler or
 * listener (in this process). Authorized requests arrive with the biscuit and
 * agent headers stripped, X-Peer-Id naming the verified caller and the path
 * relative to /a2a/<name>, as sam-node forwards them. The endpoint is not
 * announced anywhere; a caller reaches it by peer ID.
 */
export interface A2AEndpointSpec {
  name?: string;
  url?: string;
  handler?: HTTPHandler;
  listener?: NodeRequestListener;
}

export interface A2AEndpoint {
  name: string;
  service: string;
  target: { url: string } | { handler: HTTPHandler } | { listener: NodeRequestListener };
}

export function a2aEndpoint(spec: A2AEndpointSpec): A2AEndpoint {
  const name = spec.name ?? DEFAULT_A2A_NAME;
  const given = [spec.url, spec.handler, spec.listener].filter((t) => t !== undefined).length;
  if (given !== 1) {
    throw new Error("an A2A endpoint is exactly one of url, handler or listener");
  }
  const target = spec.url !== undefined ? { url: spec.url } : spec.handler !== undefined ? { handler: spec.handler } : { listener: spec.listener as NodeRequestListener };
  return { name, service: `a2a://${name}`, target };
}

export interface ProviderOptions extends ProviderAuthorizerOptions {
  /** Peers the control plane has banned; refused before their token is looked at. */
  isBanned?(peerId: string): boolean;
  /** Called after a caller is authorized, e.g. for the session's admitted set. */
  onAuthorized?(peerId: string, verified: VerifiedBiscuit, targetService: string): void;
}

// A URL parser reads %2e as a dot too (WHATWG URL, path state), so the check
// sees what the parser and the backend will see.
function hasDotSegment(path: string): boolean {
  return path.split("/").some((seg) => {
    const s = seg.replace(/%2e/gi, ".");
    return s === "." || s === "..";
  });
}

/** What the ingress looks at before anything reaches the agent. */
export interface IngressRequest {
  /** The request method as it came off the wire. */
  method: string;
  /** The request target as it came off the wire, path and query. */
  target: string;
  headers: Headers;
  remotePeer: string;
}

/** A refusal, with the text the caller gets. */
export interface IngressRefusal {
  status: number;
  text: string;
}

/** An authorized request for the endpoint, with what the agent may see. */
export interface IngressAdmission {
  verified: VerifiedBiscuit;
  /** The path relative to the service, query included. */
  path: string;
  noTrailingSlash: boolean;
}

/**
 * Server-side admission of /libp2p-http, as sam-node's StartIngressServer:
 * the path is /<type>/<name>[/<upstream>], the caller's biscuit is
 * X-Sam-Biscuit, and the request is authorized for <type>://<name> before
 * anything is forwarded. Only the agent's own endpoint is answered; anything
 * else is 404 after authorization, so an unauthorized caller learns nothing
 * about it.
 */
export async function admitIngress(req: IngressRequest, endpoint: A2AEndpoint, options: ProviderOptions): Promise<IngressRefusal | IngressAdmission> {
  // Policy is decided on the /<type>/<name> prefix; a dot segment in what
  // follows could resolve to a sibling path on the backend. Checked on the
  // raw path, before URL parsing normalizes it away.
  if (hasDotSegment(req.target.split("?")[0] as string)) {
    return { status: 400, text: "Invalid path" };
  }
  const url = new URL(req.target, "http://mesh.invalid");
  const parts = url.pathname.replace(/^\//, "").split("/");
  if (parts.length < 2 || parts[0] === "" || parts[1] === "") {
    return { status: 400, text: "Invalid path" };
  }
  const [serviceType, serviceName, ...rest] = parts as [string, string, ...string[]];
  if (serviceType !== "inference" && serviceType !== "a2a" && serviceType !== "mcp" && serviceType !== "egress") {
    return { status: 400, text: "Invalid service type" };
  }
  const upstreamPath = rest.join("/");

  const biscuitB64 = req.headers.get(HEADER_SAM_BISCUIT);
  if (biscuitB64 === null || biscuitB64 === "") {
    return { status: 401, text: "Missing X-Sam-Biscuit header" };
  }
  let biscuit: Uint8Array;
  try {
    biscuit = fromBase64(biscuitB64);
    if (biscuit.length === 0) {
      throw new Error("empty");
    }
  } catch {
    return { status: 400, text: "Invalid X-Sam-Biscuit encoding" };
  }

  const targetService = `${serviceType}://${serviceName}`;
  if (options.isBanned?.(req.remotePeer) === true) {
    return { status: 403, text: "Authorization failed" };
  }
  let verified: VerifiedBiscuit;
  try {
    verified = await authorizeCaller(
      {
        biscuit,
        peerId: req.remotePeer,
        targetService,
        protocol: HTTP_PROTOCOL,
        agent: req.headers.get(HEADER_SAM_AGENT) ?? "",
        // The path as the backend sees it, decided before authorization so
        // path() is what policy meant, never the routing prefix.
        method: req.method,
        path: "/" + upstreamPath,
      },
      options,
    );
  } catch (err) {
    if (err instanceof AuthorizationError) {
      return { status: 403, text: "Authorization failed" };
    }
    throw err;
  }
  options.onAuthorized?.(req.remotePeer, verified, targetService);

  // Under the type the policy was evaluated on.
  if (targetService !== endpoint.service) {
    return { status: 404, text: "Service not found" };
  }
  return { verified, path: "/" + upstreamPath + url.search, noTrailingSlash: upstreamPath === "" && rest.length === 0 };
}

/** Headers of the mesh datapath and of the hop itself, not passed on to the agent. */
const HOP_HEADERS = new Set([HEADER_SAM_BISCUIT, HEADER_SAM_AGENT, HEADER_SAM_NO_TRAILING_SLASH, HEADER_PEER_ID, "host", "connection", "transfer-encoding", "content-length", "keep-alive"]);

/**
 * The headers the agent sees: the request's own, less the datapath's, with
 * X-Peer-Id set (not added) to the verified caller so an inbound value
 * cannot pose as the peer.
 */
export function agentHeaders(inbound: Headers, remotePeer: string, noTrailingSlash: boolean): Headers {
  const headers = new Headers();
  inbound.forEach((value, name) => {
    if (!HOP_HEADERS.has(name)) {
      headers.append(name, value);
    }
  });
  headers.set(HEADER_PEER_ID, remotePeer);
  if (noTrailingSlash) {
    headers.set(HEADER_SAM_NO_TRAILING_SLASH, "true");
  }
  return headers;
}

/** A plain-text refusal, as sam-node's ingress writes one. */
export function refusalResponse(refusal: IngressRefusal): Response {
  return new Response(refusal.text + "\n", { status: refusal.status, headers: { "content-type": "text/plain; charset=utf-8" } });
}

async function writeResponse(stream: Stream, response: Response, headOnly: boolean): Promise<void> {
  const headers = new Headers();
  response.headers.forEach((value, name) => {
    if (name !== "content-length" && name !== "transfer-encoding" && name !== "connection") {
      headers.set(name, value);
    }
  });
  headers.set("connection", "close");
  if (headOnly) {
    // The same head a GET would get (RFC 9110 section 9.3.2): the length the
    // agent declared, if any; the body it may have built is not sent.
    const declared = response.headers.get("content-length");
    if (declared !== null) {
      headers.set("content-length", declared);
    }
    void response.body?.cancel().catch(() => {});
    await sendAll(stream, encodeResponseHead(response.status, response.statusText, headers));
    return;
  }
  const body = response.body;
  if (body === null) {
    headers.set("content-length", "0");
    await sendAll(stream, encodeResponseHead(response.status, response.statusText, headers));
    return;
  }
  // The length is not known up front, so each piece goes as a chunk as soon
  // as the agent writes it; an SSE event reaches the caller before the next.
  headers.set("transfer-encoding", "chunked");
  await sendAll(stream, encodeResponseHead(response.status, response.statusText, headers));
  const reader = body.getReader();
  try {
    for (let next = await reader.read(); !next.done; next = await reader.read()) {
      if (next.value.length > 0) {
        await sendAll(stream, encodeChunk(next.value));
      }
    }
  } finally {
    reader.releaseLock();
  }
  await sendAll(stream, LAST_CHUNK);
}

async function serveIngress(stream: Stream, remotePeer: string, endpoint: A2AEndpoint, options: ProviderOptions): Promise<void> {
  const reader = new ByteReader(streamSource(stream));
  const headTimer = setTimeout(() => stream.abort(new Error(`no request head from ${remotePeer} within ${AUTH_HANDSHAKE_TIMEOUT_MS}ms`)), AUTH_HANDSHAKE_TIMEOUT_MS);
  let response: Response;
  let headOnly = false;
  try {
    let head;
    try {
      head = await readRequestHead(reader);
    } finally {
      clearTimeout(headTimer);
    }
    if (head === null) {
      return;
    }
    headOnly = head.method === "HEAD";
    const admission = await admitIngress({ method: head.method, target: head.target, headers: head.headers, remotePeer }, endpoint, options);
    if ("status" in admission) {
      response = refusalResponse(admission);
    } else if ("listener" in endpoint.target) {
      response = refusalResponse({ status: 501, text: "A request listener is not served in this runtime" });
    } else {
      const headers = agentHeaders(head.headers, remotePeer, admission.noTrailingSlash);
      const init: RequestInit = { method: head.method, headers };
      if (head.method !== "GET" && head.method !== "HEAD") {
        init.body = await readBody(reader, requestBodyFraming(head), MAX_INGRESS_BODY_BYTES);
      }
      if ("url" in endpoint.target) {
        const base = endpoint.target.url.replace(/\/$/, "");
        response = await fetch(base + admission.path, { ...init, redirect: "manual" });
      } else {
        response = await endpoint.target.handler(new Request("http://" + endpoint.name + admission.path, init), admission.verified);
      }
    }
  } catch (err) {
    if (err instanceof HTTPParseError) {
      response = refusalResponse({ status: 400, text: `Bad request: ${err.message}` });
    } else {
      response = refusalResponse({ status: 500, text: `ingress error: ${err instanceof Error ? err.message : String(err)}` });
    }
  }
  await writeResponse(stream, response, headOnly);
}

/**
 * Server side of /libp2p-http for an endpoint answered by a handler in this
 * process or an A2A server at a URL. One request per stream; the stream is
 * closed once the response has been written.
 */
export function httpIngressHandler(endpoint: A2AEndpoint, options: ProviderOptions): StreamHandler {
  return (stream: Stream, connection: Connection) => {
    void serveIngress(stream, connection.remotePeer.toString(), endpoint, options)
      .then(() => stream.close())
      .catch((err: unknown) => stream.abort(err instanceof Error ? err : new Error(String(err))));
  };
}

/** The request target for a service on a peer: /<type>/<name>/<path>. */
export function meshHTTPTarget(targetService: string, path = ""): string {
  const m = /^(inference|a2a|mcp|egress):\/\/(.+)$/.exec(targetService);
  if (m === null) {
    throw new Error(`service target must look like inference://<name>, got ${JSON.stringify(targetService)}`);
  }
  if (path === "") {
    return `/${m[1]}/${m[2]}`;
  }
  return `/${m[1]}/${m[2]}${path.startsWith("/") ? path : "/" + path}`;
}

/**
 * The URL a fetch bound to a session (session.fetch()) takes for a service
 * on a peer: http://mesh/sam/<peer-id>/<type>/<name>/<path>.
 */
export function meshURL(peerId: string, targetService: string, path = ""): string {
  return "http://mesh" + MESH_PATH_PREFIX + canonicalPeerId(peerId) + meshHTTPTarget(targetService, path);
}

/** (peer ID, request target) of a mesh URL; the target is what the peer's ingress takes. */
export function splitMeshURL(url: URL): { peerId: string; target: string } {
  if (!url.pathname.startsWith(MESH_PATH_PREFIX)) {
    throw new TypeError(`a mesh URL looks like http://mesh${MESH_PATH_PREFIX}<peer-id>/<type>/<name>/..., got ${url.toString()}`);
  }
  const [peerId = "", ...rest] = url.pathname.slice(MESH_PATH_PREFIX.length).split("/");
  if (peerId === "" || rest.length < 2 || rest[0] === "" || rest[1] === "") {
    throw new TypeError(`a mesh URL names a peer, a service type and a name, got ${url.toString()}`);
  }
  return { peerId, target: "/" + rest.join("/") + url.search };
}

/** The bare service root counts too: a2a-go treats a pathful base URL as the card location. */
function agentCardService(method: string, target: string): string | undefined {
  const m = /^\/a2a\/([^/?]+)(?:\/(?:\.well-known\/agent-card\.json)?)?(?:\?.*)?$/.exec(target);
  return method === "GET" && m !== null ? `a2a://${m[1]}` : undefined;
}

/**
 * An agent card rebuilt for the mesh, as sam-node's egress proxy serves it:
 * HTTP interfaces point at base, gRPC ones go, signatures no longer match.
 * Streaming stays as declared, this transport streams. Throws when no interface remains.
 */
export function rewriteAgentCard(card: unknown, base: string): Record<string, unknown> {
  if (typeof card !== "object" || card === null || Array.isArray(card)) {
    throw new Error("agent card is not a JSON object");
  }
  const out = { ...(card as Record<string, unknown>) };
  delete out.signatures;
  const interfaces = Array.isArray(out.supportedInterfaces) ? (out.supportedInterfaces as unknown[]) : [];
  const kept = interfaces.filter(carriedOverHTTP).map((iface) => ({ ...(iface as Record<string, unknown>), url: base }));
  if (kept.length === 0) {
    throw new Error("agent card advertises no supported interface the mesh can carry (JSONRPC or HTTP+JSON); is the agent serving a pre-1.0 A2A card?");
  }
  return { ...out, supportedInterfaces: kept };
}

/** Whether an interface's binding can traverse the mesh; gRPC needs its own connection. */
function carriedOverHTTP(iface: unknown): boolean {
  const binding = typeof iface === "object" && iface !== null ? (iface as { protocolBinding?: unknown }).protocolBinding : undefined;
  return typeof binding === "string" && ["JSONRPC", "HTTP+JSON"].includes(binding.toUpperCase());
}

/**
 * Impersonates the agent's card endpoint as sam-node's egress proxy does: holds
 * the client's request, fetches the card itself with identity encoding, and
 * answers with it regenerated; the agent's own non-200 is relayed as it is.
 */
async function serveAgentCard(conn: Connection, biscuit: Uint8Array, request: Request, options: HTTPStreamOptions, service: string): Promise<Response> {
  const base = meshURL(conn.remotePeer.toString(), service);
  const headers = new Headers(request.headers);
  headers.delete("accept-encoding");
  let response: Response;
  try {
    response = await sendOverStream(conn, biscuit, new Request(`${base}/${AGENT_CARD_PATH}`, { headers, signal: request.signal }), options);
  } catch (err) {
    return badGateway(`agent card fetch failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (response.status !== 200) {
    return response;
  }
  let card: unknown;
  try {
    card = JSON.parse(new TextDecoder().decode(await readLimited(response.body, MAX_AGENT_CARD_BYTES)));
  } catch {
    return badGateway("agent card is not valid JSON");
  }
  try {
    return new Response(JSON.stringify(rewriteAgentCard(card, base)), { status: 200, headers: { "content-type": "application/json" } });
  } catch (err) {
    return badGateway(err instanceof Error ? err.message : String(err));
  }
}

function badGateway(reason: string): Response {
  return new Response(`Bad Gateway: ${reason}`, { status: 502, headers: { "content-type": "text/plain" } });
}

/** The first limit bytes of a body, the rest dropped, as io.LimitReader bounds the node. */
async function readLimited(body: ReadableStream<Uint8Array> | null, limit: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let n = 0;
  if (body !== null) {
    const reader = body.getReader();
    for (let next = await reader.read(); !next.done && n < limit; next = await reader.read()) {
      const chunk = next.value.subarray(0, limit - n);
      chunks.push(chunk);
      n += chunk.length;
    }
    await reader.cancel();
  }
  const out = new Uint8Array(n);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

export interface HTTPStreamOptions {
  /** The agent this request is made for. */
  agent?: string;
  /** Bounds the whole exchange; without one, the response headers must arrive within a minute and the body is unbounded. */
  signal?: AbortSignal;
}

/**
 * Client side of /libp2p-http, as go-libp2p-http's RoundTripper: one stream
 * per request, plain HTTP/1.1 with Host set to the peer ID and the biscuit in
 * X-Sam-Biscuit. Resolves once the response headers are in; the body streams
 * after, so an SSE response is consumed as the peer sends it. An agent card
 * is served rewritten for the mesh (rewriteAgentCard), as sam-node serves one.
 */
export async function fetchOverStream(conn: Connection, biscuit: Uint8Array, request: Request, options: HTTPStreamOptions = {}): Promise<Response> {
  const { target } = splitMeshURL(new URL(request.url));
  const service = agentCardService(request.method, target);
  return service === undefined ? sendOverStream(conn, biscuit, request, options) : serveAgentCard(conn, biscuit, request, options, service);
}

async function sendOverStream(conn: Connection, biscuit: Uint8Array, request: Request, options: HTTPStreamOptions): Promise<Response> {
  const { target } = splitMeshURL(new URL(request.url));
  const peerId = conn.remotePeer.toString();
  // One controller ends the exchange: the caller's signal at any time, the
  // headers timeout only until the response headers are in.
  const ctl = new AbortController();
  let headersIn = false;
  const forward = (s: AbortSignal | undefined) => s?.addEventListener("abort", () => ctl.abort(s.reason), { once: true });
  forward(options.signal);
  forward(request.signal);
  if (options.signal === undefined) {
    const timer = setTimeout(() => {
      if (!headersIn) {
        ctl.abort(new DOMException(`no response headers from ${peerId} within ${REQUEST_TIMEOUT_MS}ms`, "TimeoutError"));
      }
    }, REQUEST_TIMEOUT_MS);
    (timer as { unref?: () => void }).unref?.();
  }
  const signal = ctl.signal;
  const stream = await conn.newStream(HTTP_PROTOCOL, { signal, runOnLimitedConnection: true });
  const asError = (reason: unknown) => (reason instanceof Error ? reason : new Error(String(reason)));
  const abortStream = () => stream.abort(asError(signal.reason));
  signal.addEventListener("abort", abortStream, { once: true });

  const headers = new Headers();
  request.headers.forEach((value, name) => {
    if (name !== "host" && name !== "content-length" && name !== "transfer-encoding" && name !== HEADER_SAM_BISCUIT && name !== HEADER_PEER_ID) {
      headers.set(name, value);
    }
  });
  headers.set("host", peerId);
  headers.set(HEADER_SAM_BISCUIT, toBase64(biscuit));
  if (options.agent) {
    headers.set(HEADER_SAM_AGENT, options.agent);
  }
  const body = request.body === null ? new Uint8Array(0) : new Uint8Array(await request.arrayBuffer());
  headers.set("content-length", String(body.length));

  try {
    await sendAll(stream, encodeRequestHead(request.method, target, headers));
    await sendAll(stream, body);
    const reader = new ByteReader(streamSource(stream));
    const head = await readResponseHead(reader);
    headersIn = true;
    signal.throwIfAborted();
    const framing = responseBodyFraming(request.method, head);
    const done = (err?: Error) => {
      signal.removeEventListener("abort", abortStream);
      if (err !== undefined) {
        stream.abort(err);
      } else {
        void stream.close().catch(() => {});
      }
    };
    let responseBody: ReadableStream<Uint8Array> | null = null;
    if (framing.kind === "none") {
      done();
    } else {
      responseBody = bodyStream(reader, framing, done);
    }
    return new Response(responseBody, { status: head.status, statusText: head.statusText, headers: head.headers });
  } catch (err) {
    stream.abort(asError(err));
    throw signal.aborted ? (signal.reason ?? err) : err;
  }
}

export interface HTTPRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string;
  /** The agent this request is made for. */
  agent?: string;
  signal?: AbortSignal;
}

export interface HTTPResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
  text(): string;
}

/** One request to /<type>/<name>/<path> on a peer, body read whole. */
export async function httpRequestOverStream(
  conn: Connection,
  biscuit: Uint8Array,
  targetService: string,
  path: string,
  options: HTTPRequestOptions = {},
): Promise<HTTPResponse> {
  const signal = options.signal ?? AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  const init: RequestInit = { method: options.method ?? "GET", headers: options.headers ?? {}, signal };
  if (options.body !== undefined) {
    init.body = options.body as BodyInit;
  }
  const request = new Request(meshURL(conn.remotePeer.toString(), targetService, path), init);
  const streamOptions: HTTPStreamOptions = { signal };
  if (options.agent !== undefined) {
    streamOptions.agent = options.agent;
  }
  const response = await fetchOverStream(conn, biscuit, request, streamOptions);
  const buf = new Uint8Array(await response.arrayBuffer());
  if (buf.length > MAX_INGRESS_BODY_BYTES) {
    throw new Error("response body too large");
  }
  const flat: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    flat[key] = value;
  });
  return { status: response.status, headers: flat, body: buf, text: () => new TextDecoder().decode(buf) };
}
