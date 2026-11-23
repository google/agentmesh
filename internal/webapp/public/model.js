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

/**
 * An enrollment token, or the ID token a sign-in returned, for the control plane at server.
 * The token is memory only: never persisted, never logged.
 * @typedef {{ server: string, token: string } | { server: string, jwt: string }} Offer
 */

/**
 * expires is the credential's expiry in unix seconds.
 * @typedef {{ peers: number, routers: number, expires: number }} Stats
 */

/**
 * @typedef {"insecure" | "elsewhere" | "bundle" | "storage"} BlockedWhy
 */

/**
 * @typedef {{ kind: "boot", steal?: boolean }
 *   | { kind: "blocked", why: BlockedWhy, detail?: string }
 *   | { kind: "welcome", offer?: Offer, status?: string }
 *   | { kind: "enrolling", offer: Offer }
 *   | { kind: "stopped", peerId: string, refused?: boolean, offer?: Offer, status?: string }
 *   | { kind: "joining", peerId: string, attempt: number, offer?: Offer }
 *   | { kind: "online", peerId: string, stats: Stats, emptySince?: number, status?: string }
 *   | { kind: "reconnecting", peerId: string, attempt: number, offer?: Offer, status: string }
 *   | { kind: "forgetting", peerId?: string, keepIdentity: boolean }
 * } AppState
 */

/**
 * @typedef {"transient" | "refused" | "banned" | "notEnrolled" | "aborted"} Failure
 */

/**
 * @typedef {{ type: "blocked", why: BlockedWhy, detail?: string }
 *   | { type: "booted", peerId?: string, online: boolean, offer?: Offer }
 *   | { type: "useHere" }
 *   | { type: "offer", offer: Offer }
 *   | { type: "dismiss" } | { type: "confirm" } | { type: "cancel" }
 *   | { type: "enrolled", peerId: string }
 *   | { type: "start" } | { type: "stop" }
 *   | { type: "joined", stats: Stats }
 *   | { type: "failed", failure: Failure, message: string }
 *   | { type: "stats", stats: Stats, at: number }
 *   | { type: "lost", message: string }
 *   | { type: "retry" }
 *   | { type: "unenroll", keepIdentity: boolean }
 *   | { type: "forgotten", keepIdentity: boolean }
 *   | { type: "stolen" }
 * } AppEvent
 */

const ALREADY_ENROLLED = "This device is already enrolled; the enrollment code was not used.";

// session.routers drops a router only after the SDK's own redials (2 + 4 + 8 s,
// ROUTER_REDIAL_BACKOFFS_MS); waiting as long again lets its catalog top-up finish.
export const ROUTER_LOSS_GRACE_MS = 14_000;

/**
 * Returns state itself for an event that does not apply, so no effect runs:
 * that is how a join that finishes after Stop, or a second click, is dropped.
 * @param {AppState} state
 * @param {AppEvent} event
 * @returns {AppState}
 */
export function reduce(state, event) {
  if (event.type === "stolen") return { kind: "blocked", why: "elsewhere" };

  switch (state.kind) {
    case "boot":
      if (event.type === "blocked") return { kind: "blocked", why: event.why, detail: event.detail };
      if (event.type === "booted") {
        // The person pressed Sign in on this page, so the ID token joins without a second confirmation.
        if (event.offer !== undefined && "jwt" in event.offer) return { kind: "enrolling", offer: event.offer };
        if (event.peerId === undefined) return { kind: "welcome", offer: event.offer };
        // A scanned code is intent to be on the mesh; the offer rides along in
        // case the control plane refuses the saved credential.
        if (event.online || event.offer) return { kind: "joining", peerId: event.peerId, attempt: 1, offer: event.offer };
        return { kind: "stopped", peerId: event.peerId };
      }
      return state;

    case "blocked":
      return state.why === "elsewhere" && event.type === "useHere" ? { kind: "boot", steal: true } : state;

    case "welcome":
      if (event.type === "offer") return { kind: "welcome", offer: event.offer };
      if (event.type === "dismiss" && state.offer) return { kind: "welcome" };
      if (event.type === "confirm" && state.offer) return { kind: "enrolling", offer: state.offer };
      // A key kept from an earlier enrollment may be banned, so the welcome view can still reset it.
      if (event.type === "unenroll" && !event.keepIdentity) return { kind: "forgetting", keepIdentity: false };
      return state;

    case "enrolling":
      if (event.type === "enrolled") return { kind: "joining", peerId: event.peerId, attempt: 1 };
      if (event.type === "failed" && event.failure !== "aborted") return { kind: "welcome", status: `Enrollment failed: ${event.message}` };
      if (event.type === "cancel") return { kind: "welcome", status: "Enrollment cancelled." };
      return state;

    case "stopped":
      if (event.type === "start") return { kind: "joining", peerId: state.peerId, attempt: 1 };
      // Only a refused device takes a new code: the rejoin that keeps the Node ID.
      if (event.type === "offer") return state.refused ? { ...state, offer: event.offer } : { ...state, status: ALREADY_ENROLLED };
      if (event.type === "dismiss" && state.offer) return { ...state, offer: undefined };
      if (event.type === "confirm" && state.offer) return { kind: "enrolling", offer: state.offer };
      if (event.type === "unenroll") return forgetting(state, event);
      return state;

    case "joining":
      if (event.type === "joined")
        return { kind: "online", peerId: state.peerId, stats: event.stats, status: state.offer ? ALREADY_ENROLLED : undefined };
      if (event.type === "failed") {
        if (event.failure === "aborted") return state;
        if (event.failure === "transient")
          return { kind: "reconnecting", peerId: state.peerId, attempt: state.attempt, offer: state.offer, status: event.message };
        return { kind: "stopped", peerId: state.peerId, refused: true, offer: state.offer, status: refusal(event) };
      }
      if (event.type === "stop") return { kind: "stopped", peerId: state.peerId };
      if (event.type === "offer") return { ...state, offer: event.offer };
      if (event.type === "unenroll") return forgetting(state, event);
      return state;

    case "online":
      if (event.type === "stats") {
        if (event.stats.routers > 0) return { ...state, stats: event.stats, emptySince: undefined };
        const emptySince = state.emptySince ?? event.at;
        if (event.at - emptySince >= ROUTER_LOSS_GRACE_MS)
          return { kind: "reconnecting", peerId: state.peerId, attempt: 1, status: "No router holds this device any more." };
        return { ...state, stats: event.stats, emptySince };
      }
      if (event.type === "lost") return { kind: "reconnecting", peerId: state.peerId, attempt: 1, status: event.message };
      if (event.type === "stop") return { kind: "stopped", peerId: state.peerId };
      if (event.type === "offer") return { ...state, status: ALREADY_ENROLLED };
      if (event.type === "unenroll") return forgetting(state, event);
      return state;

    case "reconnecting":
      if (event.type === "retry") return { kind: "joining", peerId: state.peerId, attempt: state.attempt + 1, offer: state.offer };
      if (event.type === "stop") return { kind: "stopped", peerId: state.peerId };
      if (event.type === "offer") return { ...state, offer: event.offer };
      if (event.type === "unenroll") return forgetting(state, event);
      return state;

    case "forgetting":
      if (event.type === "forgotten") return { kind: "welcome", status: event.keepIdentity ? "Unenrolled; the Node ID is kept." : "Device identity reset." };
      if (event.type === "failed" && event.failure !== "aborted") {
        const status = `Could not unenroll: ${event.message}`;
        return state.peerId === undefined ? { kind: "welcome", status } : { kind: "stopped", peerId: state.peerId, status };
      }
      return state;
  }
  return state;
}

/** @param {{ peerId: string }} state @param {{ keepIdentity: boolean }} event @returns {AppState} */
function forgetting(state, event) {
  return { kind: "forgetting", peerId: state.peerId, keepIdentity: event.keepIdentity };
}

/** @param {{ failure: Failure, message: string }} event */
function refusal(event) {
  return event.failure === "banned"
    ? `This device is banned from the mesh (${event.message}).`
    : `The mesh no longer accepts this device (${event.message}). Rejoin below; the Node ID stays the same.`;
}

/**
 * A new kind's effect starts only after the old one, aborted, settled and
 * leave() returned, so a refresh still landing cannot save a forgotten credential.
 * @param {AppState} initial
 * @param {{
 *   enter: (state: AppState, signal: AbortSignal) => Promise<void> | void,
 *   leave: (prev: AppState, next: AppState) => Promise<void> | void,
 *   changed: (prev: AppState, event: AppEvent, next: AppState) => void,
 * }} hooks
 */
export function createMachine(initial, { enter, leave, changed }) {
  let state = initial;
  let controller = new AbortController();
  /** @type {Promise<void>} */
  let running = Promise.resolve();
  let transitions = Promise.resolve();
  /** @param {AppState} next @param {AbortSignal} signal */
  const start = (next, signal) => {
    running = Promise.resolve()
      .then(() => enter(next, signal))
      .catch((err) => console.error(`[agentmesh-app] ${next.kind} effect failed`, err));
  };
  start(initial, controller.signal);

  return {
    get state() {
      return state;
    },
    /** @param {AppEvent} event */
    dispatch(event) {
      const prev = state;
      const next = reduce(prev, event);
      if (next === prev) return;
      state = next;
      if (next.kind !== prev.kind) {
        controller.abort();
        const { signal } = (controller = new AbortController());
        transitions = transitions.then(async () => {
          await running;
          try {
            await leave(prev, next);
          } catch (err) {
            console.error(`[agentmesh-app] leaving ${prev.kind} failed`, err);
          }
          if (!signal.aborted) start(next, signal);
        });
      }
      changed(prev, event, next);
    },
  };
}

/**
 * The control plane's base URL: https, or http to this computer, because whoever answers it becomes this
 * device's trust root. Plain http is narrower than api.ValidateControlPlaneTransport: only the loopback
 * hosts the page's CSP can name.
 * @param {string} text
 * @returns {{ server: string } | { error: string }}
 */
export function parseServer(text) {
  const trimmed = text.trim();
  if (trimmed === "") return { error: "Enter the mesh address, for example https://mesh.example.com." };
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return { error: "The mesh address is not a valid URL." };
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    return { error: "The mesh address must start with https:// (http:// only for this computer)." };
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    return { error: "The mesh address is the control plane's address only, with no user name, query or fragment." };
  }
  return { server: url.origin + url.pathname.replace(/\/+$/, "") };
}

/**
 * The offer in a join link's fragment, #server=…&token=…, which never reaches a server.
 * Without server= the link joins the mesh this device belongs to; with server= alone it names the mesh.
 * @param {string} hash
 * @param {string | undefined} lockedServer the control plane this device's identity belongs to
 * @returns {{ offer: Offer } | { server: string } | { error: string } | undefined} undefined when the fragment names neither
 */
export function takeFragmentOffer(hash, lockedServer) {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const server = params.get("server");
  if (!params.get("token")?.trim() && server !== null) return serverFor(server, lockedServer);
  return fragmentOffer(params, lockedServer ?? "", lockedServer);
}

/** @param {URLSearchParams} params @param {string} serverText @param {string | undefined} lockedServer */
function fragmentOffer(params, serverText, lockedServer) {
  const token = params.get("token")?.trim();
  return token ? offerFor(params.get("server") ?? serverText, token, lockedServer) : undefined;
}

/**
 * One identity per page origin: the browser keeps one key here, so a device joins one mesh until its identity is reset.
 * @param {string} serverText @param {string | undefined} lockedServer
 * @returns {{ server: string } | { error: string }}
 */
function serverFor(serverText, lockedServer) {
  const parsed = parseServer(serverText);
  if ("error" in parsed) return parsed;
  const refused = lockRefusal(parsed.server, lockedServer);
  return refused === undefined ? parsed : { error: refused };
}

/**
 * Why an offer for server cannot join a device whose identity belongs to lockedServer, or undefined when it can.
 * @param {string} server @param {string | undefined} lockedServer
 */
export function lockRefusal(server, lockedServer) {
  if (lockedServer === undefined || server === lockedServer) return undefined;
  return `This device belongs to the mesh at ${new URL(lockedServer).host}. Reset device identity to join another mesh.`;
}

/** @param {string} serverText @param {string} token @param {string | undefined} lockedServer @returns {{ offer: Offer } | { error: string }} */
function offerFor(serverText, token, lockedServer) {
  const found = serverFor(serverText, lockedServer);
  return "error" in found ? found : { offer: { server: found.server, token } };
}

/**
 * What the provider sent back to the page after a sign-in, from the address's query.
 * Anyone can craft this address, so nothing in it is trusted before state matches the sign-in this tab started.
 * @param {string} search
 * @returns {{ code: string, state: string } | { error: string, state: string } | undefined}
 */
export function takeSignInReturn(search) {
  const params = new URLSearchParams(search);
  const state = params.get("state") ?? "";
  const error = params.get("error");
  if (error !== null) return { error: params.get("error_description") || error, state };
  const code = params.get("code");
  return code && state ? { code, state } : undefined;
}

/**
 * The provider's sign-in page: the authorization code flow with PKCE, back to the page itself.
 * @param {{ authorizationEndpoint: string, clientId: string, audience: string }} provider
 * @param {string} appUrl the page's own address, which the provider must list as a redirect URI
 * @param {string} state @param {string} challenge
 */
export function signInUrl(provider, appUrl, state, challenge) {
  const url = new URL(provider.authorizationEndpoint);
  const params = { response_type: "code", client_id: provider.clientId, redirect_uri: appUrl, scope: "openid email profile", state, code_challenge: challenge, code_challenge_method: "S256" };
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  if (provider.audience !== "") url.searchParams.set("audience", provider.audience);
  return url.href;
}

/**
 * What the person pasted: a mesh://enroll code (api.EnrollURI), a link to this page with #server=…&token=…,
 * or a bare token for the mesh address they entered.
 * @param {string} text
 * @param {string} serverText the mesh address field
 * @param {string | undefined} lockedServer the control plane this device's identity belongs to
 * @param {string} origin this page's origin
 * @returns {{ offer: Offer } | { error: string }}
 */
export function parseOffer(text, serverText, lockedServer, origin) {
  const trimmed = text.trim();
  if (trimmed === "") return { error: "Paste the enrollment link, code or token." };
  const serverOrLocked = lockedServer ?? serverText;
  if (/^(mesh|https?):\/\//i.test(trimmed)) {
    let url;
    try {
      url = new URL(trimmed);
    } catch {
      return { error: "That link is not a valid URL." };
    }
    if (url.protocol === "mesh:") {
      const token = url.searchParams.get("token")?.trim();
      if (url.host !== "enroll" || !token) return { error: "That code is not a mesh://enroll?server=…&token=… enrollment code." };
      return offerFor(url.searchParams.get("server") ?? "", token, lockedServer);
    }
    // Another page's storage holds another identity, so its link opens there.
    if (url.origin !== origin) return { error: `This link is for the page at ${url.host}. Open the link itself.` };
    return fragmentOffer(new URLSearchParams(url.hash.replace(/^#/, "")), serverOrLocked, lockedServer) ?? { error: "The link carries no token." };
  }
  if (/\s|:\/\//.test(trimmed)) return { error: "Paste an enrollment link, a mesh://enroll code or a token." };
  return offerFor(serverOrLocked, trimmed, lockedServer);
}

/**
 * Only the shape is checked here; api.ValidateLabels on the control plane judges the rest.
 * @param {string} text
 * @returns {{ labels: Record<string, string> } | { error: string }}
 */
export function parseLabels(text) {
  /** @type {Record<string, string>} */
  const labels = {};
  for (const part of text.split(",")) {
    const pair = part.trim();
    if (pair === "") continue;
    const eq = pair.indexOf("=");
    const key = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (eq < 0 || key === "" || value === "") return { error: `Label "${pair}" is not key=value.` };
    if (Object.hasOwn(labels, key)) return { error: `Label "${key}" is set twice.` };
    labels[key] = value;
  }
  return { labels };
}

/**
 * Matches err.name and err.status only, so this module needs no SDK import.
 * @param {unknown} err
 * @returns {Failure}
 */
export function classify(err) {
  const { name, status } = /** @type {{ name?: unknown, status?: unknown }} */ (err ?? {});
  switch (name) {
    case "NotEnrolledError":
      return "notEnrolled";
    case "AbortError":
      return "aborted";
    case "EnrollmentRejectedError":
    case "CredentialRetiredError":
      return "refused";
    case "ControlPlaneError":
      if (status === 403) return "banned";
      if (status === 400 || status === 401) return "refused";
      return "transient";
  }
  return "transient";
}

/**
 * Refresh when the credential lapses, and once on attempt 2, because only /refresh
 * says the mesh forgot this device. Not on every retry: each refresh spends the last biscuit.
 * @param {number} expires
 * @param {number} nowMs
 * @param {number} attempt
 */
export function shouldRefreshBeforeJoin(expires, nowMs, attempt) {
  return attempt === 2 || expires * 1000 - nowMs < 5 * 60_000;
}

/**
 * @param {number} attempt
 */
export function retryDelayMs(attempt) {
  return Math.min(60_000, 2_000 * 2 ** (attempt - 1));
}

/** Where the page serves the relay, relative to the page: one file with its dependencies, which sdk/js bundles. */
export const RELAY_FILE = "sdk/agentmesh-relay.mjs";
const RELAY_DIRS = [".local", "share", "agentmesh", "webapp-relay"];
/** Where the relay is saved once, so an agent start runs that copy and fetches nothing. One relay serves one page per computer. */
export const RELAY_SCRIPT = ["~", ...RELAY_DIRS, "relay.mjs"].join("/");
/** The relay's argument the agent replaces with its own name, which the page shows in the call log. */
export const AGENT_NAME_PLACEHOLDER = "YOUR NAME";

/**
 * Saves, or updates, the relay this page serves. Node itself downloads it, so the command needs nothing but
 * Node on any system; no "!", which bash expands.
 * @param {string} appUrl the page's own address, ending in "/"
 */
export function relayInstallCommand(appUrl) {
  const script = [
    `const p=require('path'),f=require('fs'),d=p.join(require('os').homedir(),${RELAY_DIRS.map((dir) => `'${dir}'`).join(",")});`,
    `fetch('${appUrl}${RELAY_FILE}').then(r=>r.ok?r.arrayBuffer():Promise.reject(new Error('HTTP '+r.status)))`,
    `.then(b=>{f.mkdirSync(d,{recursive:true});f.writeFileSync(p.join(d,'relay.mjs'),Buffer.from(b))})`,
  ].join("");
  return `node -e "${script}"`;
}

/** The saved relay's MCP server: a program and its arguments, paired with this app's origin only. */
export function relayServer(origin) {
  return {
    command: "node",
    args: [RELAY_SCRIPT, "--widget-origin", origin, "--agent-name", AGENT_NAME_PLACEHOLDER],
  };
}

/** The relay's MCP server in the mcpServers form most agents' configuration files take. */
export function relayServerConfig(origin) {
  return JSON.stringify({ mcpServers: { "agentmesh-webapp": relayServer(origin) } }, null, 2);
}

/**
 * What a person pastes into any MCP agent so it installs the relay with their approval, pairs it with this page and checks it.
 * @param {string} appUrl the page's own address, ending in "/" @param {string} token single-use pairing token @param {string} until when the token expires, as the page shows it
 */
export function agentPrompt(appUrl, token, until) {
  const server = relayServer(new URL(appUrl).origin);
  const command = [server.command, ...server.args.map((arg) => (arg.includes(" ") ? `"${arg}"` : arg))].join(" ");
  return [
    `Connect yourself to my Agent Mesh node. It runs in my browser at ${appUrl} and offers its tools to agents on this computer through a local relay.`,
    "Show me steps 1 and 2 together and ask me once to approve them. Then do every step without asking again. Keep your messages short: say only what you need from me, and the result at the end.",
    "",
    `1. Save the relay, one JavaScript file from ${appUrl}${RELAY_FILE} that needs Node.js 22 or later, as ${RELAY_SCRIPT} with this command:`,
    `   ${relayInstallCommand(appUrl)}`,
    `2. Add a local stdio MCP server named "agentmesh-webapp" that runs this command. Write ~ as the absolute path of my home folder, and replace ${AGENT_NAME_PLACEHOLDER} with your product name, such as Claude Code or Cursor:`,
    `   ${command}`,
    "   If my default node is older than 22, run it with npx -y node@22 in place of node.",
    "   If you cannot change your MCP configuration yourself, tell me exactly what to add and where, and stop until I say it is done.",
    "3. If you load new MCP servers only when you start, tell me to restart you and come back to this conversation, and stop until I do.",
    `4. Call pair_agent from agentmesh-webapp with the token ${token}. It works once, until ${until}. If pair_agent is not listed yet, wait 10 seconds and list your tools again.`,
    "5. Call get_mesh_info from agentmesh-webapp and show me its peer_id. It must match the Node ID my browser shows.",
    "",
    "Then use find_remote_tools, describe_remote_tool and call_remote_tool from agentmesh-webapp to use tools on my mesh. Your calls run as my node, and only while that browser tab stays open.",
  ].join("\n");
}

/**
 * The pair call the page checks with the open pairing's token, or why the page refuses it before any crypto.
 * @param {{ token: string, expires: number } | undefined} pairing the open pairing; a used token leaves none
 * @param {Record<string, unknown>} input @param {number} nowMs
 * @returns {{ token: string, request: { name: string, relay_nonce: string, proof: string } } | { refused: string }}
 */
export function pairingRequest(pairing, input, nowMs) {
  if (pairing === undefined) return { refused: "No pairing is open on the page. Press Pair another agent and paste the new prompt." };
  if (pairing.expires <= nowMs) return { refused: "The pairing token expired. Copy a fresh prompt from the page." };
  const { name, relay_nonce, proof } = input;
  if (typeof name !== "string" || typeof relay_nonce !== "string" || typeof proof !== "string") {
    return { refused: "This relay cannot pair. Download the relay and add the MCP server with the commands from the page's prompt." };
  }
  return { token: pairing.token, request: { name, relay_nonce, proof } };
}

/**
 * Pairs one agent through the open pairing: answer proves the request, then the token is spent in the same
 * synchronous step as the check that no other request spent it meanwhile, so one token never pairs two agents.
 * @template T
 * @param {{ read(): { token: string, expires: number } | undefined, spend(): void }} pairing
 * @param {Record<string, unknown>} input @param {number} nowMs
 * @param {(token: string, request: { name: string, relay_nonce: string, proof: string }) => Promise<T>} answer
 * @returns {Promise<T>}
 */
export async function pairWithToken(pairing, input, nowMs, answer) {
  const checked = pairingRequest(pairing.read(), input, nowMs);
  if ("refused" in checked) throw new Error(checked.refused);
  const answered = await answer(checked.token, checked.request);
  if (pairing.read()?.token !== checked.token) throw new Error("The pairing token was already used or replaced. Copy a fresh prompt from the page.");
  pairing.spend();
  return answered;
}

/**
 * The paired agents after one more pairs: pairing again under a name replaces that agent's key.
 * @template {{ name: string }} A @param {A[]} agents @param {A} agent
 */
export function withPairedAgent(agents, agent) {
  return [...agents.filter((known) => known.name !== agent.name), agent];
}

/**
 * What a local agent's tool call aims at, for the page's call log. Never the call's
 * arguments, which may carry the agent's data.
 * @param {string} tool
 * @param {Record<string, unknown>} input
 */
export function agentCallTarget(tool, input) {
  /** @param {unknown} value */
  const text = (value) => (typeof value === "string" ? value.trim() : "");
  const peerId = text(input.peer_id);
  const on = peerId === "" ? "" : `on ${peerId.length > 16 ? `${peerId.slice(0, 8)}…${peerId.slice(-4)}` : peerId}`;
  switch (tool) {
    case "call_remote_tool":
    case "describe_remote_tool":
      return [text(input.tool_name), on].filter(Boolean).join(" ");
    case "find_remote_tools":
      return [text(input.tool_name) || text(input.service_name), on].filter(Boolean).join(" ");
    case "discover_remote_services":
      return [text(input.type), text(input.name)].filter(Boolean).join(" ");
    default:
      return "";
  }
}

export const NODE_TITLE = {
  stopped: "Node is Stopped",
  joining: "Node is Starting…",
  online: "Node is Running",
  reconnecting: "Reconnecting…",
  forgetting: "Unenrolling…",
};

export const NODE_SHORT_TITLE = {
  stopped: "Stopped",
  joining: "Starting",
  online: "Running",
  reconnecting: "Reconnecting",
  forgetting: "Unenrolling",
};
