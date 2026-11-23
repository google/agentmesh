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

// Strings from the network reach the DOM through textContent only.
import { NODE_SHORT_TITLE, NODE_TITLE, classify, createMachine, lockRefusal, parseLabels, parseOffer, parseServer, agentCallTarget, agentPrompt, pairWithToken, relayInstallCommand, relayServerConfig, withPairedAgent, retryDelayMs, shouldRefreshBeforeJoin, signInUrl, takeFragmentOffer, takeSignInReturn } from "./model.js";

// The provider's answer to a sign-in arrives in the query; strip it as the token below.
let signInReturn = takeSignInReturn(location.search);
if (signInReturn !== undefined) history.replaceState(history.state, "", location.pathname + location.hash);

// Read before the first await.
let fragment = takeFragment();

/** Reads and strips the fragment: replaceState rewrites this history entry, so the address bar, Back and an install no longer carry its token. */
function takeFragment() {
  const hash = location.hash;
  if (hash !== "") history.replaceState(history.state, "", location.pathname + location.search);
  return hash;
}

const STATE_DIR = "app";
const LOCK_NAME = "agentmesh-app";
const PREFS_KEY = "agentmesh-app.prefs";
const AGENTS_KEY = "agentmesh-app.agents";
const PAIRING_KEY = "agentmesh-app.pairing";
const SIGN_IN_KEY = "agentmesh-app.sign-in";
const SIGN_IN_TIMEOUT_MS = 15_000;
const PAIRING_TTL_MS = 10 * 60_000;
// The relay's page script probes a closed relay every 2 min only; an agent restarts in less.
const RELAY_WAKE_MS = 5_000;
const POLL_MS = 3_000;
// The page may be served under a prefix, so its own files resolve from its address.
const APP_URL = new URL(".", location.href).href;
// A phone has no local agent to serve.
const AGENT_CAPABLE = matchMedia("(any-pointer: fine)").matches;
const serverInput = /** @type {HTMLInputElement} */ (document.getElementById("server-input"));

/** @type {any} */
let sdk;
/** @type {any} */
let mesh;
/** @type {any} */
let session;
/** @type {AbortController | undefined} */
let agentTools;
/** @type {Promise<void> | undefined} */
let agentBridge;
// Every call from a paired agent runs here, signed with its key.
/** @type {{ tool: string, agent: string, target: string, at: number }[]} */
let agentCalls = [];
let agentCallCount = 0;
/** @type {any} */
let agentVerifier;
/** @type {ReturnType<typeof setTimeout> | undefined} */
let pairingTimer;
/** @type {boolean | undefined} */
let storagePersisted;
// The mesh's sign-in provider, once /info names one and its discovery document loads.
/** @type {{ server: string, host: string, authorizationEndpoint: string, tokenEndpoint: string, clientId: string, audience: string } | undefined} */
let signIn;
/** @type {AbortController | undefined} */
let signInLookup;
/** @type {string | undefined} */
let signInError;
let selectedTab = "dashboard";

const machine = createMachine({ kind: "boot" }, { enter, leave, changed });
/** @param {import("./model.js").AppEvent} event */
const dispatch = (event) => machine.dispatch(event);

/** @param {import("./model.js").AppState} state @param {AbortSignal} signal */
function enter(state, signal) {
  /** @param {import("./model.js").AppEvent} event */
  const send = (event) => {
    if (!signal.aborted) dispatch(event);
  };
  switch (state.kind) {
    case "boot":
      return boot(state.steal === true, send);
    // Only the welcome and rejoin views offer Sign in, so only they ask the provider.
    // Not awaited: the machine waits for an effect before it leaves a view, and a silent provider must not hold a join.
    case "welcome":
      return void lookUpSignIn();
    case "stopped":
      return void (state.refused && lookUpSignIn());
    case "enrolling":
      return enroll(state.offer, signal, send);
    case "joining":
      return join(state.attempt, signal, send);
    case "online":
      return poll(signal);
    case "reconnecting":
      return wait(retryDelayMs(state.attempt), signal).then(() => send({ type: "retry" }));
    case "forgetting":
      return forget(state.keepIdentity, send);
  }
}

/** @param {import("./model.js").AppState} prev @param {import("./model.js").AppState} next */
async function leave(prev, next) {
  signInLookup?.abort();
  if (prev.kind === "online") {
    const closing = session;
    session = undefined;
    syncAgentTools();
    await closing?.close();
  }
  if (!("peerId" in next)) mesh = undefined;
}

/** @param {boolean} steal @param {(event: import("./model.js").AppEvent) => void} send */
async function boot(steal, send) {
  if (!isSecureContext) return send({ type: "blocked", why: "insecure" });
  if (!(await holdLock(steal))) return send({ type: "blocked", why: "elsewhere" });
  // zod in the bundle probes eval with new Function, which this page's CSP
  // refuses; jitless is zod's own setting, kept where z.config() keeps it.
  globalThis.__zod_globalConfig = { ...globalThis.__zod_globalConfig, jitless: true };
  try {
    sdk ??= await import("./sdk/index.js");
  } catch (err) {
    console.error("[agentmesh-app] the SDK bundle did not load", err);
    return send({ type: "blocked", why: "bundle" });
  }
  let loaded;
  try {
    loaded = await sdk.AgentMesh.load({ stateDir: STATE_DIR });
  } catch (err) {
    if (classify(err) !== "notEnrolled") return send({ type: "blocked", why: "storage", detail: messageOf(err) });
  }
  mesh = loaded;
  if (loaded !== undefined) {
    keepStorage();
    // The saved credential names its control plane, so the lock follows it, and a link is checked against it below.
    writePrefs({ keyKept: true, server: loaded.credential.controlPlaneUrl });
  }
  let offer = linkOffer(fragment);
  fragment = "";
  if (signInReturn !== undefined) {
    const returned = signInReturn;
    signInReturn = undefined;
    try {
      offer = await finishSignIn(returned);
    } catch (err) {
      signInError = messageOf(err);
    }
  }
  send({ type: "booted", peerId: loaded?.peerId, online: readPrefs().online, offer });
}

function holdLock(steal) {
  return new Promise((resolve) => {
    navigator.locks
      .request(LOCK_NAME, steal ? { steal: true } : { ifAvailable: true }, (lock) => {
        resolve(lock !== null);
        // Held for the life of the page, unless another window steals it.
        return lock === null ? undefined : new Promise(() => {});
      })
      .catch(() => dispatch({ type: "stolen" }));
  });
}

/** @param {import("./model.js").Offer} offer @param {AbortSignal} signal @param {(event: import("./model.js").AppEvent) => void} send */
async function enroll(offer, signal, send) {
  // An offer taken while the device was not yet locked, such as during a cancelled sign-in, is checked again here.
  const refused = lockRefusal(offer.server, readPrefs().server);
  if (refused !== undefined) return send({ type: "failed", failure: "refused", message: refused });
  const parsed = parseLabels(readPrefs().labels);
  if ("error" in parsed) return send({ type: "failed", failure: "refused", message: `${parsed.error} Fix the labels, then join again.` });
  try {
    // enroll() resumes a still-valid saved credential and ignores the token.
    await sdk.AgentMesh.forget(STATE_DIR, { keepIdentity: true });
    const enrolled = await sdk.AgentMesh.enroll({
      controlPlaneUrl: offer.server,
      stateDir: STATE_DIR,
      ...("token" in offer ? { bootstrapToken: offer.token } : { jwt: offer.jwt }),
      labels: parsed.labels,
      signal,
    });
    // The SDK saves the credential even after Cancel once the control plane has answered, so the lock follows it,
    // and a cancelled view shows the fixed address and Reset.
    writePrefs({ keyKept: true, server: offer.server });
    render(machine.state);
    if (signal.aborted) return;
    mesh = enrolled;
    writePrefs({ online: true });
    send({ type: "enrolled", peerId: enrolled.peerId });
  } catch (err) {
    send({ type: "failed", failure: classify(err), message: messageOf(err) });
  }
}

/**
 * A join link's offer. A link with only #server=… fills in the mesh address, so that mesh's Sign in shows.
 * @param {string} hash @returns {import("./model.js").Offer | undefined}
 */
function linkOffer(hash) {
  const taken = takeFragmentOffer(hash, readPrefs().server);
  if (taken === undefined) return undefined;
  if ("error" in taken) showOfferError(taken.error);
  if ("server" in taken) serverInput.value = taken.server;
  if (!("offer" in taken)) return undefined;
  // A failed join keeps the link's mesh in the field, for the next token.
  serverInput.value = taken.offer.server;
  return taken.offer;
}

/** The mesh this device belongs to, or else the valid address in the field. */
function currentServer() {
  const parsed = parseServer(readPrefs().server ?? serverInput.value);
  return "server" in parsed ? parsed.server : undefined;
}

/** Asks the current mesh for its sign-in provider; a new address or leaving the view cancels the last ask. */
function lookUpSignIn() {
  signInLookup?.abort();
  signInLookup = new AbortController();
  signIn = undefined;
  const server = currentServer();
  return server === undefined ? undefined : findSignIn(server, signInLookup.signal);
}

/**
 * Shows Sign in when the control plane names a provider whose discovery document this page can read.
 * Asked again on every entry, so a provider the operator changed or removed is not offered.
 * @param {string} server @param {AbortSignal} signal
 */
async function findSignIn(server, signal) {
  /** @type {typeof signIn} */
  let found;
  try {
    const info = await new sdk.ControlPlaneClient({ url: server }).info(signal);
    if (info.oidcIssuer === "") return;
    // Bounded as the token request is, so a provider that stops answering is no longer offered.
    const res = await fetch(`${info.oidcIssuer.replace(/\/$/, "")}/.well-known/openid-configuration`, { signal: AbortSignal.any([signal, AbortSignal.timeout(SIGN_IN_TIMEOUT_MS)]) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const discovery = await res.json();
    // OIDC Discovery 1.0 section 4.3: the document must name the issuer that was asked.
    if (discovery.issuer !== info.oidcIssuer || typeof discovery.authorization_endpoint !== "string" || typeof discovery.token_endpoint !== "string") {
      throw new Error("the discovery document does not name this issuer's endpoints");
    }
    found = {
      server,
      host: new URL(info.oidcIssuer).host,
      authorizationEndpoint: discovery.authorization_endpoint,
      tokenEndpoint: discovery.token_endpoint,
      clientId: info.clientId,
      audience: info.audience,
    };
  } catch (err) {
    if (signal.aborted) return;
    // Most often the provider does not allow this origin (CORS); enrollment tokens still work.
    console.warn("[agentmesh-app] Sign in is not offered: the sign-in provider did not answer this page", err);
  } finally {
    if (!signal.aborted) {
      signIn = found;
      render(machine.state);
    }
  }
}

/** 32 random bytes, base64url. */
const randomText = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

/** @param {Uint8Array} bytes */
function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Leaves for the provider's sign-in page; the PKCE verifier waits in this tab's storage. */
async function startSignIn() {
  if (signIn === undefined) return;
  keepStorage();
  const verifier = randomText();
  const state = randomText();
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  try {
    sessionStorage.setItem(SIGN_IN_KEY, JSON.stringify({ state, verifier, server: signIn.server, tokenEndpoint: signIn.tokenEndpoint, clientId: signIn.clientId }));
  } catch (err) {
    signInError = `This browser did not keep the sign-in: ${messageOf(err)}`;
    return render(machine.state);
  }
  location.assign(signInUrl(signIn, APP_URL, state, challenge));
}

/**
 * Trades the provider's code for an ID token, only for a sign-in this tab started.
 * @param {{ code: string, state: string } | { error: string, state: string }} returned @returns {Promise<import("./model.js").Offer>}
 */
async function finishSignIn(returned) {
  let pending;
  try {
    pending = JSON.parse(sessionStorage.getItem(SIGN_IN_KEY) ?? "null");
    sessionStorage.removeItem(SIGN_IN_KEY);
  } catch {
    pending = null;
  }
  if (pending?.state !== returned.state) throw new Error("This sign-in did not start in this tab. Press Sign in again.");
  // A failed sign-in comes back to the same mesh, so Sign in shows again.
  serverInput.value = pending.server;
  if ("error" in returned) throw new Error(`The sign-in failed: ${returned.error}`);
  let res;
  try {
    // Bounded, because boot waits for it before it reports booted.
    res = await fetch(pending.tokenEndpoint, {
      method: "POST",
      body: new URLSearchParams({ grant_type: "authorization_code", code: returned.code, redirect_uri: APP_URL, client_id: pending.clientId, code_verifier: pending.verifier }),
      signal: AbortSignal.timeout(SIGN_IN_TIMEOUT_MS),
    });
  } catch (err) {
    console.warn("[agentmesh-app] the sign-in provider's token endpoint did not answer", err);
    throw new Error("The sign-in provider did not answer this page. Press Sign in again, or join with a token.");
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok || typeof body.id_token !== "string") throw new Error(`The sign-in provider refused the code (HTTP ${res.status}${body.error ? `, ${body.error}` : ""}).`);
  return { server: pending.server, jwt: body.id_token };
}

/** @param {number} attempt @param {AbortSignal} signal @param {(event: import("./model.js").AppEvent) => void} send */
async function join(attempt, signal, send) {
  try {
    if (shouldRefreshBeforeJoin(mesh.credential.expiration, Date.now(), attempt)) {
      try {
        await mesh.refresh();
      } catch (err) {
        // The control plane did not answer: the saved credential may still join.
        if (classify(err) !== "transient") throw err;
        console.warn("[agentmesh-app] refresh failed; joining with the saved credential", err);
      }
    }
    signal.throwIfAborted();
    const joined = await mesh.join({ signal });
    if (signal.aborted) return void (await joined.close());
    session = joined;
    syncAgentTools();
    send({ type: "joined", stats: statsOf(joined) });
  } catch (err) {
    send({ type: "failed", failure: classify(err), message: messageOf(err) });
  }
}

/** @param {AbortSignal} signal */
async function poll(signal) {
  while (!signal.aborted) {
    if (document.visibilityState === "visible") report();
    await wait(POLL_MS, signal);
  }
}

function report() {
  if (session !== undefined) dispatch({ type: "stats", stats: statsOf(session), at: Date.now() });
}

/** @param {boolean} keepIdentity @param {(event: import("./model.js").AppEvent) => void} send */
async function forget(keepIdentity, send) {
  try {
    await sdk.AgentMesh.forget(STATE_DIR, { keepIdentity });
    // The mesh stays with the key: only a new identity may join another mesh.
    if (!keepIdentity) writePrefs({ keyKept: false, server: undefined });
    mesh = undefined;
    signInError = undefined;
    writeAgents([]);
    setPairing(false);
    send({ type: "forgotten", keepIdentity });
  } catch (err) {
    send({ type: "failed", failure: classify(err), message: messageOf(err) });
  }
}

/** @returns {import("./model.js").Stats} */
function statsOf(joined) {
  return { peers: joined.node.getPeers().length, routers: joined.routers.length, expires: joined.mesh.credential.expiration };
}

function wait(ms, signal) {
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve(undefined);
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done);
  });
}

function messageOf(err) {
  return err instanceof Error ? err.message : String(err);
}

function keepStorage() {
  navigator.storage?.persist?.().then(
    (granted) => {
      storagePersisted = granted;
      render(machine.state);
    },
    () => {},
  );
}

/**
 * keyKept: this browser holds a key from an earlier enrollment, which the welcome view offers to reset.
 * server: the control plane that key belongs to.
 * @returns {{ labels: string, online: boolean, agent: boolean, keyKept: boolean, server: string | undefined }}
 */
function readPrefs() {
  try {
    const saved = JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}");
    return {
      labels: typeof saved.labels === "string" ? saved.labels : "",
      online: saved.online !== false,
      agent: saved.agent === true,
      keyKept: saved.keyKept === true,
      server: typeof saved.server === "string" ? saved.server : undefined,
    };
  } catch {
    return { labels: "", online: true, agent: false, keyKept: false, server: undefined };
  }
}

/** @param {Partial<{ labels: string, online: boolean, agent: boolean, keyKept: boolean, server: string | undefined }>} patch */
function writePrefs(patch) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify({ ...readPrefs(), ...patch }));
  } catch (err) {
    console.warn("[agentmesh-app] preferences not saved", err);
  }
}

/** @typedef {{ key_id: string, name: string, key: string, paired_time: string }} PairedAgent */

/** The agents paired with this page. Only their signed calls run. @returns {PairedAgent[]} */
function readAgents() {
  try {
    const saved = JSON.parse(localStorage.getItem(AGENTS_KEY) ?? "[]");
    return Array.isArray(saved) ? saved : [];
  } catch {
    return [];
  }
}

/** @param {PairedAgent[]} agents */
function writeAgents(agents) {
  try {
    localStorage.setItem(AGENTS_KEY, JSON.stringify(agents));
  } catch (err) {
    console.warn("[agentmesh-app] paired agents not saved", err);
  }
}

/** The open pairing and its single-use token, kept for this tab across reloads. @returns {{ token: string, expires: number } | undefined} */
function readPairing() {
  try {
    const saved = JSON.parse(sessionStorage.getItem(PAIRING_KEY) ?? "null");
    return typeof saved?.token === "string" && typeof saved.expires === "number" ? saved : undefined;
  } catch {
    return undefined;
  }
}

/** 128 random bits, in hex so an agent copies it without surprises. */
const newPairingToken = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");

/** Opens a pairing with a fresh token, or closes it. */
function setPairing(/** @type {boolean} */ open) {
  try {
    if (open) sessionStorage.setItem(PAIRING_KEY, JSON.stringify({ token: newPairingToken(), expires: Date.now() + PAIRING_TTL_MS }));
    else sessionStorage.removeItem(PAIRING_KEY);
  } catch (err) {
    console.warn("[agentmesh-app] pairing not saved", err);
  }
  renewPairingOnExpiry();
}

/** Replaces an unused token when it expires, so the prompt on screen always works. */
function renewPairingOnExpiry() {
  clearTimeout(pairingTimer);
  const pairing = readPairing();
  if (pairing === undefined) return;
  pairingTimer = setTimeout(() => {
    setPairing(true);
    render(machine.state);
  }, Math.max(0, pairing.expires - Date.now()));
}

/** @param {string} text */
const toolFailure = (text) => ({ isError: true, content: [{ type: "text", text }] });

/** Answers a relay that proves it holds the open pairing's token, and trusts its key from then on. @param {Record<string, unknown>} input */
async function pairAgent(input) {
  try {
    const { response, agent } = await pairWithToken({ read: readPairing, spend: () => setPairing(false) }, input, Date.now(), sdk.answerPairing);
    writeAgents(withPairedAgent(readAgents(), agent));
    console.info(`[agentmesh-app] paired the local agent "${agent.name}"`);
    render(machine.state);
    return { content: [{ type: "text", text: JSON.stringify(response) }] };
  } catch (err) {
    console.warn(`[agentmesh-app] refused to pair a local agent: ${messageOf(err)}`);
    return toolFailure(messageOf(err));
  }
}

/** Offers the node's tools to a local agent while it is connected and the node is online. */
function syncAgentTools() {
  if (!(AGENT_CAPABLE && readPrefs().agent && session !== undefined)) {
    agentTools?.abort();
    agentTools = undefined;
    return;
  }
  if (agentTools !== undefined) return;
  const controller = (agentTools = new AbortController());
  const joined = session;
  agentVerifier ??= new sdk.CallVerifier(readAgents);
  if (readAgents().length === 0 && readPairing() === undefined) setPairing(true);
  const modelContext = () => /** @type {any} */ (document).modelContext;
  const log = {
    /** @param {string} tool @param {{ name: string }} agent @param {Record<string, unknown>} args */
    called: (tool, agent, args) => agentCalled(tool, agent.name, args),
    /** @param {string} tool @param {string} reason */
    refused: (tool, reason) => console.warn(`[agentmesh-app] refused a call to ${tool}: ${reason}`),
  };
  const pairTool = {
    name: sdk.PAIR_TOOL,
    description: "Pairs this agent with the Agent Mesh node in the browser, using the single-use token from the page's prompt. Call it once; the agent then stays paired.",
    inputSchema: { type: "object", properties: { token: { type: "string", description: "The token from the prompt." } }, required: ["token"] },
    execute: (/** @type {any} */ input) => pairAgent(input ?? {}),
  };
  loadAgentBridge()
    .then(async () => {
      await modelContext().registerTool(pairTool, { signal: controller.signal });
      await sdk.registerWebMCPTools(modelContext(), sdk.meshTools(joined), agentVerifier, log, controller.signal);
      // The page script reconnects on this message, sent as its parent window: the page itself.
      const wake = setInterval(() => window.postMessage({ type: "webmcp.connect" }, location.origin), RELAY_WAKE_MS);
      controller.signal.addEventListener("abort", () => clearInterval(wake), { once: true });
    })
    .catch((err) => {
      if (!controller.signal.aborted) console.warn("[agentmesh-app] the tools were not offered to a local agent", err);
    });
}

/** @param {string} tool @param {string} agent @param {Record<string, unknown>} input */
function agentCalled(tool, agent, input) {
  const target = agentCallTarget(tool, input);
  agentCallCount++;
  agentCalls = [{ tool, agent, target, at: Date.now() }, ...agentCalls].slice(0, 5);
  console.info(`[agentmesh-app] the local agent "${agent}" called ${tool} ${target}`.trimEnd());
  render(machine.state);
}

/** Loads the WebMCP polyfill, for browsers without WebMCP, and the relay's page script. Neither loads before the agent is connected. */
function loadAgentBridge() {
  agentBridge ??= import("./sdk/webmcp-polyfill.js").then(() => {
    // The relay script reads this; without its embed frame, the page itself is the "parent" it serves.
    /** @type {any} */ (globalThis).__WEBMCP_RELAY_CONFIG = { hostOrigin: location.origin, hostTitle: document.title, hostUrl: location.origin + location.pathname };
    const script = document.createElement("script");
    script.src = "./sdk/webmcp-relay.js";
    document.head.append(script);
  });
  return agentBridge;
}

/** @param {import("./model.js").AppState} prev @param {import("./model.js").AppEvent} event @param {import("./model.js").AppState} next */
function changed(prev, event, next) {
  // Any enrollment, by token, link or sign-in, replaces an earlier sign-in error.
  if (next.kind === "enrolling") signInError = undefined;
  if (prev.kind !== next.kind) {
    const why = event.type === "failed" || event.type === "lost" ? `: ${event.message}` : "";
    console.info(`[agentmesh-app] ${prev.kind} --${event.type}--> ${next.kind}${why}`);
  }
  render(next);
}

/** @param {number} unixSeconds */
function clock(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

const BLOCKED = {
  insecure: "Open this page over https. Put agentmesh-webapp behind an https proxy, Gateway or tunnel.",
  elsewhere: "Agent Mesh is open in another tab or window.",
  bundle: "This server was built without the app. Rebuild it with make all.",
  storage: "This browser does not let the page keep its identity. Leave private browsing and open the link again.",
};

/** @param {import("./model.js").AppState} s */
function render(s) {
  const enrolled = "peerId" in s;
  // Before enrollment the welcome view is the whole app, labels included.
  const tab = enrolled ? selectedTab : "dashboard";

  for (const name of ["dashboard", "config"]) {
    $(`tab-${name}`).hidden = name !== tab;
  }
  $("nav").hidden = !enrolled;
  $("nav").dataset.kind = s.kind;
  for (const button of document.querySelectorAll("#nav button")) {
    button.toggleAttribute("aria-current", button.dataset.tab === tab);
  }
  $("tab-dashboard").dataset.kind = s.kind;
  $("bar-status").hidden = !enrolled;
  $("bar-status").dataset.kind = s.kind;
  $("bar-status-text").textContent = NODE_SHORT_TITLE[s.kind] ?? "";

  $("view-boot").hidden = s.kind !== "boot";
  $("view-blocked").hidden = s.kind !== "blocked";
  if (s.kind === "blocked") {
    $("blocked-message").textContent = s.why === "storage" && s.detail ? `${BLOCKED.storage} (${s.detail})` : BLOCKED[s.why];
    $("use-here").hidden = s.why !== "elsewhere";
    $("blocked-icon").setAttribute("href", s.why === "elsewhere" ? "#i-windows" : "#i-alert");
  }

  // A refused device rejoins with a new token, keeping its key and the labels on record.
  const rejoin = s.kind === "stopped" && s.refused === true;
  $("view-welcome").hidden = s.kind !== "welcome" && s.kind !== "enrolling" && !rejoin;
  $("welcome-title").textContent = rejoin ? "Rejoin the mesh" : "Welcome to Agent Mesh";
  $("welcome-text").textContent =
    rejoin ? `${signIn ? "Sign in again, paste" : "Paste"} a new enrollment link or token, or clear this device's identity.`
    : signIn ? "Sign in with your account, or join with the enrollment link or token the mesh's operator gave you."
    : "Enter the mesh's address, then join with the enrollment link or token its operator gave you.";
  const locked = readPrefs().server;
  if (locked !== undefined) serverInput.value = locked;
  serverInput.readOnly = locked !== undefined;
  $("sign-in-block").hidden = signIn === undefined || s.kind === "enrolling";
  $("sign-in-label").textContent = signIn ? `Sign in with ${signIn.host}` : "";
  $("sign-in-error").hidden = signInError === undefined;
  $("sign-in-error").textContent = signInError ?? "";
  $("labels-field").hidden = rejoin;
  $("labels-hint").hidden = rejoin;
  // A banned key cannot rejoin, so the rejoin view keeps the way out the dashboard has.
  $("rejoin-unenroll").hidden = !rejoin;
  $("welcome-reset").hidden = s.kind !== "welcome" || !readPrefs().keyKept;
  const enrolling = s.kind === "enrolling";
  $("offer-input").toggleAttribute("disabled", enrolling);
  serverInput.toggleAttribute("disabled", enrolling);
  $("join-button").toggleAttribute("disabled", enrolling);
  $("join-label").textContent = enrolling ? "Joining…" : "Join with token";
  $("cancel-enroll").hidden = !enrolling;

  $("view-node").hidden = !enrolled || rejoin;
  if (enrolled) renderNode(s);

  const status =
    s.kind === "enrolling"
      ? `Enrolling with ${new URL(s.offer.server).host}… If this mesh needs approval, an operator approves this device in the console.`
      : "status" in s
        ? s.status
        : undefined;
  $("status").hidden = status === undefined;
  $("status").classList.toggle("error", s.kind === "stopped" && s.refused === true);
  $("status-text").textContent = status ?? "";

  const offer = (s.kind === "welcome" || s.kind === "stopped") && s.offer !== undefined ? s.offer : undefined;
  const dialog = /** @type {HTMLDialogElement} */ ($("join-dialog"));
  if (offer !== undefined) {
    $("join-server").textContent = offer.server;
    $("join-token").textContent = `${offer.token.slice(0, 12)}…`;
    if (!dialog.open) {
      dialog.showModal();
      // Opened by a page load, not a tap: focusing Cancel would draw its keyboard focus ring.
      dialog.focus();
    }
  } else if (dialog.open) {
    dialog.close();
  }

  const labels = /** @type {HTMLInputElement} */ ($("labels"));
  if (document.activeElement !== labels) labels.value = readPrefs().labels;
  labels.toggleAttribute("disabled", enrolling);
  $("labels-line").hidden = !enrolled;
  $("labels-line").textContent = `Labels: ${readPrefs().labels.trim() || "none"}. To change them, unenroll with Reset device identity, then join again.`;
  $("storage-line").textContent =
    storagePersisted === undefined
      ? ""
      : storagePersisted
        ? "Storage: kept by the browser."
        : "Storage: the browser may clear it. Install the app (Add to Home Screen) to keep this device's identity.";
  const agent = AGENT_CAPABLE && readPrefs().agent;
  $("agent-card").hidden = !AGENT_CAPABLE;
  $("agent-toggle-label").textContent = agent ? "Disconnect local agent" : "Connect a local agent";
  $("agent-toggle").classList.toggle("primary", !agent);
  $("agent-toggle").classList.toggle("secondary", agent);
  const paired = agent ? readAgents() : [];
  const pairing = agent ? readPairing() : undefined;
  $("agent-paired").hidden = paired.length === 0;
  $("agent-paired").replaceChildren(...paired.map((known) => {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = `${known.name}, paired ${new Date(known.paired_time).toLocaleString()}`;
    const forget = document.createElement("button");
    forget.className = "btn quiet";
    forget.type = "button";
    forget.dataset.keyId = known.key_id;
    forget.textContent = "Forget";
    forget.setAttribute("aria-label", `Forget ${known.name}`);
    item.append(label, forget);
    return item;
  }));
  $("agent-pair-another").hidden = !agent || pairing !== undefined;
  $("agent-pair-another").textContent = paired.length === 0 ? "Pair an agent" : "Pair another agent";
  $("agent-setup").hidden = pairing === undefined;
  $("agent-prompt").textContent = pairing === undefined ? "" : agentPrompt(APP_URL, pairing.token, clock(Math.floor(pairing.expires / 1000)));
  $("agent-install").textContent = relayInstallCommand(APP_URL);
  $("agent-config").textContent = relayServerConfig(location.origin);
  const used = agent && agentCallCount > 0;
  const lastCall = used ? `last call ${agentCalls[0].tool} at ${clock(Math.floor(agentCalls[0].at / 1000))}` : "";
  $("agent-status").hidden = !agent;
  $("agent-status").textContent =
    s.kind !== "online" ? "The tools are offered while the node is running."
    : used ? `${agentCalls[0].agent}: ${lastCall}, ${agentCallCount} ${agentCallCount === 1 ? "call" : "calls"} so far.`
    : pairing !== undefined ? "Waiting for your agent. Paste the prompt into it and follow the instructions."
    : "Waiting for a call from a paired agent.";
  $("agent-calls").hidden = !used;
  $("agent-calls").replaceChildren(...agentCalls.map((call) => {
    const item = document.createElement("li");
    item.textContent = `${new Date(call.at).toLocaleTimeString()} ${call.agent}: ${call.tool} ${call.target}`.trimEnd();
    return item;
  }));
  $("agent-line").hidden = !used;
  $("agent-line-text").textContent = used ? `Local agent ${agentCalls[0].agent} connected, ${lastCall}` : "";
  $("credential-line").hidden = s.kind !== "online";
  if (s.kind === "online") {
    $("credential-line").textContent = `Credential renews automatically; valid until ${clock(s.stats.expires)}.`;
  }
}

/** @param {Extract<import("./model.js").AppState, { peerId: string }>} s */
function renderNode(s) {
  const online = s.kind === "online";
  $("node-dot").dataset.kind = s.kind;
  $("node-title").textContent = NODE_TITLE[s.kind];
  const server = readPrefs().server;
  $("mesh-host").textContent = server === undefined ? "" : new URL(server).host;
  $("stat-peers").textContent = online ? String(s.stats.peers) : "–";
  $("stat-routers").textContent = online ? String(s.stats.routers) : "–";
  $("node-id").textContent = s.peerId;
  $("start").hidden = s.kind !== "stopped";
  $("stop").hidden = s.kind === "stopped";
  $("stop").toggleAttribute("disabled", s.kind === "forgetting");
  $("unenroll").toggleAttribute("disabled", s.kind === "forgetting");
}

// The nav's tab buttons.
for (const button of document.querySelectorAll("[data-tab]")) {
  button.addEventListener("click", () => {
    selectedTab = /** @type {HTMLElement} */ (button).dataset.tab ?? "dashboard";
    render(machine.state);
  });
}

$("use-here").addEventListener("click", () => dispatch({ type: "useHere" }));

for (const button of document.querySelectorAll("[data-copy]")) {
  const label = button.getAttribute("aria-label") ?? "";
  const icon = /** @type {SVGUseElement} */ (button.querySelector("use"));
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let reset;
  /** @param {boolean} copied */
  const show = (copied) => {
    button.classList.toggle("done", copied);
    button.setAttribute("aria-label", copied ? "Copied" : label);
    icon.setAttribute("href", copied ? "#i-check" : "#i-copy");
  };
  button.addEventListener("click", async () => {
    const source = $(/** @type {HTMLElement} */ (button).dataset.copy ?? "");
    clearTimeout(reset);
    try {
      await navigator.clipboard.writeText(source.textContent ?? "");
    } catch (err) {
      // Selected, so the person can copy it by hand.
      console.warn("[agentmesh-app] copy to the clipboard failed", err);
      show(false);
      getSelection()?.selectAllChildren(source);
      return;
    }
    show(true);
    reset = setTimeout(() => show(false), 1600);
  });
}

/** @param {string | undefined} message */
function showOfferError(message) {
  $("offer-error").hidden = message === undefined;
  $("offer-error").textContent = message ?? "";
}

serverInput.addEventListener("change", () => {
  const parsed = parseServer(serverInput.value);
  $("server-error").hidden = !("error" in parsed) || serverInput.value.trim() === "";
  $("server-error").textContent = "error" in parsed ? parsed.error : "";
  lookUpSignIn();
  render(machine.state);
});

$("manual-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = /** @type {HTMLInputElement} */ ($("offer-input"));
  const parsed = parseOffer(input.value, serverInput.value, readPrefs().server, location.origin);
  showOfferError("error" in parsed ? parsed.error : undefined);
  if ("offer" in parsed) {
    input.value = "";
    dispatch({ type: "offer", offer: parsed.offer });
  }
});
$("cancel-enroll").addEventListener("click", () => dispatch({ type: "cancel" }));
$("sign-in").addEventListener("click", () => {
  signInError = undefined;
  startSignIn().catch((err) => {
    signInError = messageOf(err);
    render(machine.state);
  });
});

$("join-cancel").addEventListener("click", () => dispatch({ type: "dismiss" }));
$("join-confirm").addEventListener("click", () => {
  keepStorage();
  dispatch({ type: "confirm" });
});
$("join-dialog").addEventListener("cancel", (event) => {
  event.preventDefault();
  dispatch({ type: "dismiss" });
});

$("start").addEventListener("click", () => {
  writePrefs({ online: true });
  dispatch({ type: "start" });
});
$("stop").addEventListener("click", () => {
  writePrefs({ online: false });
  dispatch({ type: "stop" });
});

const unenrollDialog = /** @type {HTMLDialogElement} */ ($("unenroll-dialog"));
$("unenroll").addEventListener("click", () => unenrollDialog.showModal());
$("rejoin-unenroll").addEventListener("click", () => unenrollDialog.showModal());
$("welcome-reset").addEventListener("click", () => dispatch({ type: "unenroll", keepIdentity: false }));
$("unenroll-cancel").addEventListener("click", () => unenrollDialog.close());
$("unenroll-reset").addEventListener("click", () => {
  unenrollDialog.close();
  dispatch({ type: "unenroll", keepIdentity: false });
});
$("unenroll-confirm").addEventListener("click", () => {
  unenrollDialog.close();
  dispatch({ type: "unenroll", keepIdentity: true });
});

$("agent-toggle").addEventListener("click", () => {
  const agent = !readPrefs().agent;
  writePrefs({ agent });
  if (!agent) {
    agentCalls = [];
    agentCallCount = 0;
    setPairing(false);
  }
  syncAgentTools();
  render(machine.state);
});

$("agent-pair-another").addEventListener("click", () => {
  setPairing(true);
  render(machine.state);
});

$("agent-paired").addEventListener("click", (event) => {
  const keyId = /** @type {HTMLElement} */ (event.target).closest("button")?.dataset.keyId;
  if (keyId === undefined) return;
  writeAgents(readAgents().filter((known) => known.key_id !== keyId));
  console.info("[agentmesh-app] forgot a paired local agent");
  render(machine.state);
});

$("labels").addEventListener("input", (event) => {
  const text = /** @type {HTMLInputElement} */ (event.target).value;
  const parsed = parseLabels(text);
  $("labels-error").hidden = !("error" in parsed);
  $("labels-error").textContent = "error" in parsed ? parsed.error : "";
  writePrefs({ labels: text });
});

// An installed app receives a scanned link as a fragment-only navigation.
addEventListener("hashchange", () => {
  const hash = takeFragment();
  if (hash === "") return;
  if (machine.state.kind === "boot" || machine.state.kind === "blocked") return void (fragment = hash);
  const offer = linkOffer(hash);
  if (offer !== undefined) dispatch({ type: "offer", offer });
  else if (machine.state.kind === "welcome") {
    lookUpSignIn();
    render(machine.state);
  }
});
renewPairingOnExpiry();

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") return;
  if (machine.state.kind === "online") {
    // A frozen page's relay check is overdue; run the SDK's own recovery now.
    session?.keepRelay().catch(() => {});
    report();
  }
  if (machine.state.kind === "reconnecting") dispatch({ type: "retry" });
});
addEventListener("online", () => {
  if (machine.state.kind === "reconnecting") dispatch({ type: "retry" });
});
addEventListener("pagehide", () => {
  if (machine.state.kind === "online") dispatch({ type: "lost", message: "The page was closed; rejoining." });
});

navigator.storage?.persisted?.().then(
  (persisted) => {
    storagePersisted = persisted;
    render(machine.state);
  },
  () => {},
);

Object.defineProperty(window, "agentmeshApp", { value: Object.freeze({ get state() { return machine.state; } }) });

render(machine.state);
