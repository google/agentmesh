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

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AGENT_NAME_PLACEHOLDER,
  RELAY_FILE,
  RELAY_SCRIPT,
  ROUTER_LOSS_GRACE_MS,
  classify,
  createMachine,
  parseLabels,
  parseOffer,
  parseServer,
  lockRefusal,
  reduce,
  agentCallTarget,
  agentPrompt,
  pairingRequest,
  pairWithToken,
  withPairedAgent,
  relayInstallCommand,
  relayServer,
  relayServerConfig,
  retryDelayMs,
  shouldRefreshBeforeJoin,
  signInUrl,
  takeFragmentOffer,
  takeSignInReturn,
} from "./public/model.js";

const server = "https://cp.example.com";
const offer = { server, token: "mesh_dev_ab" };
const signedIn = { server, jwt: "eyJ.id.token" };
const stats = { peers: 2, routers: 1, expires: 2_000_000_000 };
const noRouters = { ...stats, routers: 0 };
const peerId = "12D3KooWPeer";

test("the call log names what a local agent's call aims at, never its arguments", () => {
  const peer = "12D3KooWPeerIdThatIsLong1234";
  assert.equal(agentCallTarget("call_remote_tool", { peer_id: peer, tool_name: "mcp://calc/add", arguments: { secret: "x" } }), "mcp://calc/add on 12D3KooW…1234");
  assert.equal(agentCallTarget("describe_remote_tool", { peer_id: "short", tool_name: "mcp://calc/add" }), "mcp://calc/add on short");
  assert.equal(agentCallTarget("find_remote_tools", { service_name: "calc" }), "calc");
  assert.equal(agentCallTarget("find_remote_tools", {}), "");
  assert.equal(agentCallTarget("discover_remote_services", { type: "mcp", name: "calc" }), "mcp calc");
  assert.equal(agentCallTarget("get_mesh_info", {}), "");
  assert.equal(agentCallTarget("call_remote_tool", { peer_id: 7, tool_name: null }), "");
});

test("the prompt saves the relay this page serves with Node alone, runs that copy for the page's origin and carries the pairing token", () => {
  const origin = "https://mesh.example.com";
  const appUrl = `${origin}/node/`;
  assert.equal(RELAY_FILE, "sdk/agentmesh-relay.mjs");
  assert.equal(RELAY_SCRIPT, "~/.local/share/agentmesh/webapp-relay/relay.mjs");
  const install = relayInstallCommand(appUrl);
  assert.ok(install.startsWith('node -e "') && install.endsWith('"'), install);
  assert.ok(install.includes("fetch('https://mesh.example.com/node/sdk/agentmesh-relay.mjs')"), install);
  assert.ok(install.includes("homedir(),'.local','share','agentmesh','webapp-relay')"), install);
  assert.ok(install.includes("r.arrayBuffer()"), "saved byte for byte");
  assert.ok(!/[!$`"]/.test(install.slice('node -e "'.length, -1)), "the script survives bash, PowerShell and cmd quoting");
  assert.deepEqual(relayServer(origin), {
    command: "node",
    args: [RELAY_SCRIPT, "--widget-origin", origin, "--agent-name", AGENT_NAME_PLACEHOLDER],
  });
  assert.deepEqual(JSON.parse(relayServerConfig(origin)).mcpServers["agentmesh-webapp"], relayServer(origin));

  const prompt = agentPrompt(appUrl, "tok_abc", "23:52");
  assert.ok(prompt.includes(`It runs in my browser at ${appUrl} and`), prompt);
  assert.ok(relayInstallCommand(`${origin}/console/node/`).includes("fetch('https://mesh.example.com/console/node/sdk/agentmesh-relay.mjs')"), "a page under a prefix downloads its own copy");
  assert.ok(prompt.includes(`   ${install}\n`), prompt);
  assert.ok(prompt.includes(`   node ${RELAY_SCRIPT} --widget-origin ${origin} --agent-name "${AGENT_NAME_PLACEHOLDER}"\n`), prompt);
  assert.ok(prompt.includes("Show me steps 1 and 2 together and ask me once to approve them. Then do every step without asking again."), prompt);
  assert.ok(prompt.includes("Call pair_agent from agentmesh-webapp with the token tok_abc. It works once, until 23:52."), prompt);
  assert.ok(!relayServerConfig(origin).includes("tok_abc"), "the MCP server's configuration carries no secret");
});

test("the page pairs only through an open, unexpired pairing, and pairing again under a name replaces that agent", () => {
  const request = { name: "Claude Code", relay_nonce: "n", proof: "p" };
  const open = { token: "tok", expires: 1_000 };
  assert.deepEqual(pairingRequest(open, request, 999), { token: "tok", request });
  assert.match(pairingRequest(open, request, 1_000).refused, /token expired/);
  assert.match(pairingRequest(undefined, request, 0).refused, /No pairing is open/);
  assert.match(pairingRequest(open, { token: "tok" }, 0).refused, /cannot pair/);
  assert.deepEqual(pairingRequest(open, { ...request, extra: 1 }, 0), { token: "tok", request });

  const cursor = { name: "Cursor", key_id: "c" };
  const agents = withPairedAgent(withPairedAgent([], { name: "Claude Code", key_id: "old" }), cursor);
  assert.deepEqual(withPairedAgent(agents, { name: "Claude Code", key_id: "new" }), [cursor, { name: "Claude Code", key_id: "new" }]);
});

test("parseServer accepts https, or http to this computer, as the control plane's base URL", () => {
  assert.deepEqual(parseServer(" https://cp.example.com/ "), { server });
  assert.deepEqual(parseServer("https://cp.example.com/mesh/"), { server: "https://cp.example.com/mesh" });
  assert.deepEqual(parseServer("http://localhost:8080"), { server: "http://localhost:8080" });
  assert.deepEqual(parseServer("http://127.0.0.1:8080/"), { server: "http://127.0.0.1:8080" });
  // The page's CSP can name only these two loopback hosts.
  assert.match(parseServer("http://[::1]:8080").error, /https/);
  assert.match(parseServer("http://127.0.0.2:8080").error, /https/);
  assert.match(parseServer("http://cp.example.com").error, /https/);
  assert.match(parseServer("http://127.0.0.1.evil.example").error, /https/);
  assert.match(parseServer("ftp://cp.example.com").error, /https/);
  assert.match(parseServer("https://cp.example.com/?x=1").error, /query/);
  assert.match(parseServer("https://user@cp.example.com").error, /user name/);
  assert.match(parseServer("cp.example.com").error, /not a valid URL/);
  assert.match(parseServer("").error, /Enter the mesh address/);
});

test("takeFragmentOffer reads #server=…&token=…, or the token alone for the mesh this device belongs to", () => {
  assert.deepEqual(takeFragmentOffer(`#server=${encodeURIComponent(server)}&token=mesh_dev_ab`, undefined), { offer });
  assert.deepEqual(takeFragmentOffer("#server=https://cp.example.com&token=a%2Bb%3Dc", undefined), { offer: { server, token: "a+b=c" } });
  assert.deepEqual(takeFragmentOffer("#token=mesh_dev_ab", server), { offer });
  assert.match(takeFragmentOffer("#token=mesh_dev_ab", undefined).error, /Enter the mesh address/);
  assert.match(takeFragmentOffer("#server=http://cp.example.com&token=x", undefined).error, /https/);
  assert.match(takeFragmentOffer("#server=https://other.example.com&token=x", server).error, /belongs to the mesh at cp\.example\.com/);
  assert.equal(takeFragmentOffer("#other=1", server), undefined);
  assert.equal(takeFragmentOffer("", server), undefined);
});

test("takeSignInReturn reads the provider's code and state, or its error, from the query", () => {
  assert.deepEqual(takeSignInReturn("?code=c1&state=s1"), { code: "c1", state: "s1" });
  assert.deepEqual(takeSignInReturn("?error=access_denied&error_description=The+user+said+no&state=s1"), { error: "The user said no", state: "s1" });
  assert.deepEqual(takeSignInReturn("?error=access_denied"), { error: "access_denied", state: "" });
  assert.equal(takeSignInReturn("?code=c1"), undefined);
  assert.equal(takeSignInReturn(""), undefined);
});

test("signInUrl asks for a code with PKCE back to the page, for the audience the control plane accepts", () => {
  const provider = { authorizationEndpoint: "https://auth.example/auth?prompt=login", clientId: "agentmesh-audience", audience: "agentmesh-audience" };
  const url = new URL(signInUrl(provider, "https://mesh.example/node/", "s1", "ch1"));
  assert.equal(url.origin + url.pathname, "https://auth.example/auth");
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    prompt: "login",
    response_type: "code",
    client_id: "agentmesh-audience",
    redirect_uri: "https://mesh.example/node/",
    scope: "openid email profile",
    state: "s1",
    code_challenge: "ch1",
    code_challenge_method: "S256",
    audience: "agentmesh-audience",
  });
  const none = new URL(signInUrl({ ...provider, audience: "" }, "https://mesh.example/node/", "s1", "ch1"));
  assert.equal(none.searchParams.has("audience"), false);
});

test("lockRefusal lets a device join only the mesh it belongs to, or any mesh when it belongs to none", () => {
  assert.equal(lockRefusal(server, undefined), undefined);
  assert.equal(lockRefusal(server, server), undefined);
  assert.equal(lockRefusal("https://other.example.com", server), "This device belongs to the mesh at cp.example.com. Reset device identity to join another mesh.");
});

test("a link with only #server=… names the mesh, under the same rules and lock as a join link", () => {
  assert.deepEqual(takeFragmentOffer("#server=https://cp.example.com/", undefined), { server });
  assert.deepEqual(takeFragmentOffer("#server=https://cp.example.com&token=", undefined), { server });
  assert.match(takeFragmentOffer("#server=http://cp.example.com", undefined).error, /https/);
  assert.match(takeFragmentOffer("#server=https://other.example.com", server).error, /belongs to the mesh at cp\.example\.com/);
  assert.equal(takeFragmentOffer("#token=", undefined), undefined);
});

test("parseOffer takes a mesh://enroll code, a link to this page, or a bare token for the mesh address entered", () => {
  const origin = "https://app.example.com";
  const code = `mesh://enroll?server=${encodeURIComponent(server)}&token=mesh_dev_ab`;
  assert.deepEqual(parseOffer(code, "", undefined, origin), { offer });
  assert.deepEqual(parseOffer(code, "https://typed.example.com", undefined, origin), { offer });
  assert.deepEqual(parseOffer("  mesh_dev_ab \n", "https://cp.example.com/", undefined, origin), { offer });
  assert.deepEqual(parseOffer(`https://app.example.com/#server=${server}&token=mesh_dev_ab`, "", undefined, origin), { offer });
  assert.deepEqual(parseOffer("https://app.example.com/#token=mesh_dev_ab", server, undefined, origin), { offer });
  assert.match(parseOffer("https://other.example.com/#token=mesh_dev_ab", server, undefined, origin).error, /other\.example\.com/);
  assert.match(parseOffer("https://app.example.com/", server, undefined, origin).error, /no token/);
  assert.match(parseOffer("mesh_dev_ab", "", undefined, origin).error, /Enter the mesh address/);
  assert.match(parseOffer("mesh_dev_ab", "http://cp.example.com", undefined, origin).error, /https/);
  assert.match(parseOffer("mesh://enroll?server=http%3A%2F%2Fcp.example.com&token=x", "", undefined, origin).error, /https/);
  assert.match(parseOffer("mesh://enroll?token=x", server, undefined, origin).error, /Enter the mesh address/);
  assert.match(parseOffer("mesh://other?server=https%3A%2F%2Fcp.example.com&token=x", "", undefined, origin).error, /enrollment code/);
  assert.match(parseOffer("", server, undefined, origin).error, /Paste/);
  assert.match(parseOffer("mesh dev ab", server, undefined, origin).error, /token/);
});

test("a device that belongs to a mesh takes offers for that mesh only, whatever the address field says", () => {
  const origin = "https://app.example.com";
  assert.deepEqual(parseOffer("mesh_dev_ab", "https://typed.example.com", server, origin), { offer });
  assert.deepEqual(parseOffer(`mesh://enroll?server=${encodeURIComponent(server)}&token=mesh_dev_ab`, "", server, origin), { offer });
  const other = "mesh://enroll?server=https%3A%2F%2Fother.example.com&token=x";
  assert.match(parseOffer(other, "", server, origin).error, /belongs to the mesh at cp\.example\.com\. Reset device identity/);
  assert.match(parseOffer("https://app.example.com/#server=https://other.example.com&token=x", "", server, origin).error, /belongs to/);
});

test("parseLabels checks the key=value shape and leaves the rest to the control plane", () => {
  assert.deepEqual(parseLabels(" region=eu-west-1, tier=a "), { labels: { region: "eu-west-1", tier: "a" } });
  assert.deepEqual(parseLabels(""), { labels: {} });
  for (const bad of ["x", "=v", "k=", "a=1,a=2"]) {
    assert.ok("error" in parseLabels(bad), `parseLabels(${JSON.stringify(bad)}) accepted a malformed label`);
  }
});

test("classify maps errors by name and status", () => {
  const cp = (status) => ({ name: "ControlPlaneError", status });
  const cases = [
    [{ name: "NotEnrolledError" }, "notEnrolled"],
    [{ name: "AbortError" }, "aborted"],
    [cp(400), "refused"],
    [cp(401), "refused"],
    [cp(403), "banned"],
    [cp(500), "transient"],
    [cp(503), "transient"],
    [{ name: "EnrollmentRejectedError" }, "refused"],
    [new TypeError("Failed to fetch"), "transient"],
    [new Error("no router admitted this member"), "transient"],
    [undefined, "transient"],
  ];
  for (const [err, want] of cases) {
    assert.equal(classify(err), want, `classify(${JSON.stringify(err)})`);
  }
});

test("shouldRefreshBeforeJoin refreshes a lapsing credential and probes once, on attempt 2", () => {
  const now = 1_000_000_000_000;
  const fresh = now / 1000 + 3600;
  assert.equal(shouldRefreshBeforeJoin(fresh, now, 1), false);
  assert.equal(shouldRefreshBeforeJoin(now / 1000 + 4 * 60, now, 1), true);
  assert.equal(shouldRefreshBeforeJoin(now / 1000 - 86_400, now, 1), true);
  assert.equal(shouldRefreshBeforeJoin(fresh, now, 2), true);
  assert.equal(shouldRefreshBeforeJoin(fresh, now, 3), false);
});

test("retryDelayMs backs off from 2 s to a 60 s cap", () => {
  assert.deepEqual([1, 2, 3, 10].map(retryDelayMs), [2_000, 4_000, 8_000, 60_000]);
});

const transitions = [
  ["boot", { kind: "boot" }, { type: "blocked", why: "bundle" }, { kind: "blocked", why: "bundle", detail: undefined }],
  ["first launch", { kind: "boot" }, { type: "booted", online: true }, { kind: "welcome", offer: undefined }],
  ["first launch from a scanned link", { kind: "boot" }, { type: "booted", online: true, offer }, { kind: "welcome", offer }],
  ["launch, left running", { kind: "boot" }, { type: "booted", peerId, online: true }, { kind: "joining", peerId, attempt: 1, offer: undefined }],
  ["launch, left stopped", { kind: "boot" }, { type: "booted", peerId, online: false }, { kind: "stopped", peerId }],
  ["back from a sign-in", { kind: "boot" }, { type: "booted", online: true, offer: signedIn }, { kind: "enrolling", offer: signedIn }],
  ["back from a sign-in on a refused device", { kind: "boot" }, { type: "booted", peerId, online: false, offer: signedIn }, { kind: "enrolling", offer: signedIn }],
  ["launch, left stopped, from a scanned link", { kind: "boot" }, { type: "booted", peerId, online: false, offer }, { kind: "joining", peerId, attempt: 1, offer }],
  ["use here", { kind: "blocked", why: "elsewhere" }, { type: "useHere" }, { kind: "boot", steal: true }],
  ["pasted code", { kind: "welcome" }, { type: "offer", offer }, { kind: "welcome", offer }],
  ["dialog cancelled", { kind: "welcome", offer }, { type: "dismiss" }, { kind: "welcome" }],
  ["dialog confirmed", { kind: "welcome", offer }, { type: "confirm" }, { kind: "enrolling", offer }],
  ["enrolled", { kind: "enrolling", offer }, { type: "enrolled", peerId }, { kind: "joining", peerId, attempt: 1 }],
  ["enrollment refused", { kind: "enrolling", offer }, { type: "failed", failure: "refused", message: "HTTP 401" }, { kind: "welcome", status: "Enrollment failed: HTTP 401" }],
  ["enrollment cancelled", { kind: "enrolling", offer }, { type: "cancel" }, { kind: "welcome", status: "Enrollment cancelled." }],
  ["start", { kind: "stopped", peerId }, { type: "start" }, { kind: "joining", peerId, attempt: 1 }],
  ["code on a refused device", { kind: "stopped", peerId, refused: true }, { type: "offer", offer }, { kind: "stopped", peerId, refused: true, offer }],
  ["rejoin confirmed", { kind: "stopped", peerId, refused: true, offer }, { type: "confirm" }, { kind: "enrolling", offer }],
  ["rejoin cancelled", { kind: "stopped", peerId, refused: true, offer }, { type: "dismiss" }, { kind: "stopped", peerId, refused: true, offer: undefined }],
  ["joined", { kind: "joining", peerId, attempt: 1 }, { type: "joined", stats }, { kind: "online", peerId, stats, status: undefined }],
  ["join fails on the network", { kind: "joining", peerId, attempt: 2 }, { type: "failed", failure: "transient", message: "offline" }, { kind: "reconnecting", peerId, attempt: 2, offer: undefined, status: "offline" }],
  ["stop while joining", { kind: "joining", peerId, attempt: 1 }, { type: "stop" }, { kind: "stopped", peerId }],
  ["stats", { kind: "online", peerId, stats }, { type: "stats", stats, at: 1 }, { kind: "online", peerId, stats, emptySince: undefined }],
  ["page hidden and restored", { kind: "online", peerId, stats }, { type: "lost", message: "left the page" }, { kind: "reconnecting", peerId, attempt: 1, status: "left the page" }],
  ["stop", { kind: "online", peerId, stats }, { type: "stop" }, { kind: "stopped", peerId }],
  ["retry", { kind: "reconnecting", peerId, attempt: 1, status: "x" }, { type: "retry" }, { kind: "joining", peerId, attempt: 2, offer: undefined }],
  ["stop while reconnecting", { kind: "reconnecting", peerId, attempt: 3, status: "x" }, { type: "stop" }, { kind: "stopped", peerId }],
  ["unenroll", { kind: "online", peerId, stats }, { type: "unenroll", keepIdentity: true }, { kind: "forgetting", peerId, keepIdentity: true }],
  ["reset while joining", { kind: "joining", peerId, attempt: 1 }, { type: "unenroll", keepIdentity: false }, { kind: "forgetting", peerId, keepIdentity: false }],
  ["unenroll while stopped", { kind: "stopped", peerId }, { type: "unenroll", keepIdentity: true }, { kind: "forgetting", peerId, keepIdentity: true }],
  ["unenroll while reconnecting", { kind: "reconnecting", peerId, attempt: 1, status: "x" }, { type: "unenroll", keepIdentity: true }, { kind: "forgetting", peerId, keepIdentity: true }],
  ["unenrolled", { kind: "forgetting", peerId, keepIdentity: true }, { type: "forgotten", keepIdentity: true }, { kind: "welcome", status: "Unenrolled; the Node ID is kept." }],
  ["reset", { kind: "forgetting", peerId, keepIdentity: false }, { type: "forgotten", keepIdentity: false }, { kind: "welcome", status: "Device identity reset." }],
  ["unenroll fails", { kind: "forgetting", peerId, keepIdentity: true }, { type: "failed", failure: "transient", message: "quota" }, { kind: "stopped", peerId, status: "Could not unenroll: quota" }],
  ["reset a kept key from the welcome view", { kind: "welcome" }, { type: "unenroll", keepIdentity: false }, { kind: "forgetting", keepIdentity: false }],
  ["no unenroll that keeps the key from the welcome view", { kind: "welcome" }, { type: "unenroll", keepIdentity: true }, { kind: "welcome" }],
  ["reset from the welcome view", { kind: "forgetting", keepIdentity: false }, { type: "forgotten", keepIdentity: false }, { kind: "welcome", status: "Device identity reset." }],
  ["reset from the welcome view fails", { kind: "forgetting", keepIdentity: false }, { type: "failed", failure: "transient", message: "quota" }, { kind: "welcome", status: "Could not unenroll: quota" }],
];

test("reduce: one row per transition", () => {
  for (const [name, state, event, want] of transitions) {
    assert.deepEqual(reduce(state, event), want, name);
  }
});

const states = [
  { kind: "boot" },
  { kind: "blocked", why: "bundle" },
  { kind: "blocked", why: "elsewhere" },
  { kind: "welcome" },
  { kind: "welcome", offer },
  { kind: "enrolling", offer },
  { kind: "stopped", peerId },
  { kind: "stopped", peerId, refused: true, offer },
  { kind: "joining", peerId, attempt: 1 },
  { kind: "online", peerId, stats },
  { kind: "reconnecting", peerId, attempt: 1, status: "x" },
  { kind: "forgetting", peerId, keepIdentity: true },
  { kind: "forgetting", keepIdentity: false },
];
const events = [
  { type: "blocked", why: "storage" },
  { type: "booted", peerId, online: true },
  { type: "useHere" },
  { type: "offer", offer },
  { type: "dismiss" },
  { type: "confirm" },
  { type: "cancel" },
  { type: "enrolled", peerId },
  { type: "start" },
  { type: "stop" },
  { type: "joined", stats },
  { type: "failed", failure: "transient", message: "x" },
  { type: "failed", failure: "aborted", message: "x" },
  { type: "stats", stats, at: 1 },
  { type: "lost", message: "x" },
  { type: "retry" },
  { type: "unenroll", keepIdentity: true },
  { type: "unenroll", keepIdentity: false },
  { type: "forgotten", keepIdentity: true },
];

const takes = {
  boot: ["blocked", "booted"],
  blocked: [],
  welcome: ["offer", "dismiss", "confirm", "unenroll"],
  enrolling: ["enrolled", "failed", "cancel"],
  stopped: ["start", "offer", "dismiss", "confirm", "unenroll"],
  joining: ["joined", "failed", "stop", "offer", "unenroll"],
  online: ["stats", "lost", "stop", "offer", "unenroll"],
  reconnecting: ["retry", "stop", "offer", "unenroll"],
  forgetting: ["forgotten", "failed"],
};

function taken(state, event) {
  if (state.kind === "blocked") return state.why === "elsewhere" && event.type === "useHere";
  if (event.type === "failed" && event.failure === "aborted") return false;
  if ((event.type === "confirm" || event.type === "dismiss") && !state.offer) return false;
  // The welcome view only resets a kept key; there is no credential to unenroll.
  if (state.kind === "welcome" && event.type === "unenroll") return !event.keepIdentity;
  return takes[state.kind].includes(event.type);
}

test("reduce returns the same object for every event a state does not take", () => {
  for (const state of states) {
    for (const event of events) {
      const next = reduce(state, event);
      if (taken(state, event)) {
        assert.notEqual(next, state, `${state.kind} ignored ${JSON.stringify(event)}`);
      } else {
        assert.equal(next, state, `${JSON.stringify(state)} took ${JSON.stringify(event)} and became ${JSON.stringify(next)}`);
      }
    }
  }
});

test("losing the Web Lock ends whatever this window was doing", () => {
  for (const state of states) {
    assert.deepEqual(reduce(state, { type: "stolen" }), { kind: "blocked", why: "elsewhere" }, state.kind);
  }
});

test("a join that finishes after Stop is dropped", () => {
  const stopped = reduce({ kind: "joining", peerId, attempt: 1 }, { type: "stop" });
  assert.equal(reduce(stopped, { type: "joined", stats }), stopped);
});

test("a scanned code on an enrolled device rides along and is reported unused when the join works", () => {
  const joining = reduce({ kind: "boot" }, { type: "booted", peerId, online: true, offer });
  const online = reduce(joining, { type: "joined", stats });
  assert.equal(online.kind, "online");
  assert.match(online.status, /already enrolled/);
  assert.match(reduce({ kind: "online", peerId, stats }, { type: "offer", offer }).status, /already enrolled/);
});

test("a refusal while joining with a scanned code opens the dialog for it", () => {
  const stopped = reduce({ kind: "joining", peerId, attempt: 2, offer }, { type: "failed", failure: "refused", message: "HTTP 401" });
  assert.deepEqual(stopped, { kind: "stopped", peerId, refused: true, offer, status: stopped.status });
  assert.match(stopped.status, /Rejoin below; the Node ID stays the same/);
  assert.equal(reduce(stopped, { type: "confirm" }).kind, "enrolling");
  const banned = reduce({ kind: "joining", peerId, attempt: 1 }, { type: "failed", failure: "banned", message: "HTTP 403" });
  assert.match(banned.status, /banned/);
});

test("online reports a lost session only after the SDK's recovery window passed with no router", () => {
  let state = { kind: "online", peerId, stats };
  state = reduce(state, { type: "stats", stats: noRouters, at: 1_000 });
  assert.equal(state.kind, "online");
  state = reduce(state, { type: "stats", stats: noRouters, at: 1_000 + ROUTER_LOSS_GRACE_MS - 1 });
  assert.equal(state.kind, "online", "reported lost while the SDK could still re-admit a router");
  state = reduce(state, { type: "stats", stats, at: 1_000 + ROUTER_LOSS_GRACE_MS });
  assert.equal(state.emptySince, undefined, "a router coming back resets the window");
  state = reduce(state, { type: "stats", stats: noRouters, at: 50_000 });
  state = reduce(state, { type: "stats", stats: noRouters, at: 50_000 + ROUTER_LOSS_GRACE_MS });
  assert.deepEqual(state, { kind: "reconnecting", peerId, attempt: 1, status: "No router holds this device any more." });
});

function recordingMachine(initial, held = {}) {
  const log = [];
  const machine = createMachine(initial, {
    async enter(state, signal) {
      log.push(`enter ${state.kind}`);
      if (held[state.kind]) await held[state.kind];
      log.push(`settled ${state.kind}${signal.aborted ? " (aborted)" : ""}`);
    },
    leave(prev) {
      log.push(`leave ${prev.kind}`);
    },
    changed() {},
  });
  return { machine, log };
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

test("unenroll waits for the join's refresh to settle before it forgets", async () => {
  let refreshLands;
  const { machine, log } = recordingMachine({ kind: "joining", peerId, attempt: 1 }, { joining: new Promise((resolve) => (refreshLands = resolve)) });
  await flush();
  machine.dispatch({ type: "unenroll", keepIdentity: true });
  await flush();
  assert.equal(machine.state.kind, "forgetting");
  assert.deepEqual(log, ["enter joining"], "forget started while the refresh could still save the credential");
  refreshLands();
  await flush();
  assert.deepEqual(log, ["enter joining", "settled joining (aborted)", "leave joining", "enter forgetting", "settled forgetting"]);
});

test("a kind left before its effect started never runs it", async () => {
  let refreshLands;
  const { machine, log } = recordingMachine({ kind: "joining", peerId, attempt: 1 }, { joining: new Promise((resolve) => (refreshLands = resolve)) });
  await flush();
  machine.dispatch({ type: "stop" });
  machine.dispatch({ type: "start" });
  refreshLands();
  await flush();
  assert.deepEqual(log, ["enter joining", "settled joining (aborted)", "leave joining", "leave stopped", "enter joining", "settled joining"]);
});

test("one pairing token pairs one agent, even when two requests overlap while the page checks them", async () => {
  let open = { token: "tok", expires: 1_000 };
  const pairing = { read: () => open, spend: () => (open = undefined) };
  const answer = async (_token, request) => {
    await new Promise((resolve) => setTimeout(resolve, 5));
    return request.name;
  };
  const results = await Promise.allSettled([
    pairWithToken(pairing, { name: "Claude Code", relay_nonce: "a", proof: "p" }, 0, answer),
    pairWithToken(pairing, { name: "Cursor", relay_nonce: "b", proof: "p" }, 0, answer),
  ]);
  assert.deepEqual(results.map((result) => result.status), ["fulfilled", "rejected"]);
  assert.equal(results[0].value, "Claude Code");
  assert.match(results[1].reason.message, /already used or replaced/);
  await assert.rejects(pairWithToken(pairing, { name: "Cursor", relay_nonce: "c", proof: "p" }, 0, answer), /No pairing is open/);
});
