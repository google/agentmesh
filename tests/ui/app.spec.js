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

const { test, expect, chromium } = require('@playwright/test');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const stack = require('./lib/agentmesh-one');
const { startMockOIDC } = require('./lib/mock-oidc');

test.use({ ignoreHTTPSErrors: true });
test.describe.configure({ mode: 'serial' });
test.setTimeout(120_000);

// The page comes from agentmesh-webapp, on an origin apart from every mesh it joins.
let app;
test.beforeAll(async () => {
  if (!stack.missing().startsWith('bin/')) app = await stack.startWebapp();
});
test.afterAll(() => app?.stop());

/** The page with a join link for mesh: #server=…&token=…, or #server=… alone when token is null. */
const linkTo = (mesh, token = mesh.joinToken) =>
  `${app.url}#server=${encodeURIComponent(mesh.publicUrl)}${token === null ? '' : `&token=${encodeURIComponent(token)}`}`;

async function watchCSP(page) {
  await page.addInitScript(() => {
    window.__cspViolations = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
}

async function noViolations(page) {
  expect(await page.evaluate(() => window.__cspViolations)).toEqual([]);
}

const nodeTitle = (page) => page.locator('#node-title');
const nodeId = async (page) => (await page.locator('#node-id').textContent()).trim();

async function joinFromDialog(page, token) {
  const dialog = page.locator('#join-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('#join-token')).toHaveText(`${token.slice(0, 12)}…`);
  await dialog.getByRole('button', { name: 'Join' }).click();
  await expect(nodeTitle(page)).toHaveText('Node is Running', { timeout: 30_000 });
}

/** Types the mesh address the way a person does; leaving the field asks that mesh for its Sign in. */
async function enterServer(page, url) {
  await page.locator('#server-input').fill(url);
  await page.locator('#server-input').blur();
}

async function pasteCode(page, text) {
  await page.locator('#offer-input').fill(text);
  await page.getByRole('button', { name: 'Join with token' }).click();
}

const topologies = [
  { name: 'direct', edge: false },
  { name: 'behind a TLS edge', edge: true },
];

for (const topology of topologies) {
  test(`a scanned link enrolls, joins and resumes after a reload (${topology.name})`, async ({ page }) => {
    const why = stack.missing({ app: true });
    test.skip(why !== '', why);

    const stops = [];
    try {
      let samOne;
      if (topology.edge) {
        const cert = stack.selfSignedCert('localhost');
        test.skip(cert === null, 'openssl is not installed');
        const edgePort = await stack.freePort();
        samOne = await stack.startSamOne({ externalUrl: `https://localhost:${edgePort}` });
        stops.push(() => samOne.stop());
        const edge = await stack.startTLSEdge({ host: 'localhost', origin: samOne.localUrl.replace('http://', ''), cert: cert.cert, key: cert.key, port: edgePort });
        stops.push(() => edge.stop());
      } else {
        samOne = await stack.startSamOne();
        stops.push(() => samOne.stop());
      }
      await watchCSP(page);

      await page.goto(linkTo(samOne));
      const historyLength = await page.evaluate(() => history.length);
      await expect(page.locator('#join-server')).toHaveText(samOne.publicUrl);
      expect(page.url(), 'the token stayed in the address bar').toBe(app.url);
      await joinFromDialog(page, samOne.joinToken);
      expect(await page.evaluate(() => history.length), 'stripping the token added a history entry').toBe(historyLength);

      const peer = await nodeId(page);
      expect(peer).toMatch(/^12D3Koo/);
      // The config grants the clipboard permissions.
      await page.locator('#copy-id').click();
      await expect(page.locator('#copy-id')).toHaveAccessibleName('Copied');
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(peer);
      await expect(page.locator('#stat-routers')).toHaveText('1');
      // The router is counted once, under Routers, not again as a peer.
      await expect(page.locator('#stat-peers')).toHaveText('0');
      await expect(page.locator('#mesh-host')).toHaveText(new URL(samOne.publicUrl).host);

      // The address follows the saved credential, even when the page never saved it.
      await page.evaluate(() => {
        const prefs = JSON.parse(localStorage.getItem('agentmesh-app.prefs'));
        delete prefs.server;
        localStorage.setItem('agentmesh-app.prefs', JSON.stringify(prefs));
      });
      // The page loads again from a link for another mesh, which the lock from the credential refuses.
      // A goto that changes only the fragment does not load the page again.
      await page.goto('about:blank');
      await page.goto(`${app.url}#server=${encodeURIComponent('https://other.example.com')}&token=mesh_dev_x`);
      await expect(nodeTitle(page)).toHaveText('Node is Running', { timeout: 30_000 });
      expect(await nodeId(page)).toBe(peer);
      await expect(page.locator('#mesh-host')).toHaveText(new URL(samOne.publicUrl).host);
      await expect(page.locator('#offer-error')).toHaveText(`This device belongs to the mesh at ${new URL(samOne.publicUrl).host}. Reset device identity to join another mesh.`);
      await expect(page.locator('#join-dialog')).toBeHidden();
      await noViolations(page);
    } finally {
      for (const stop of stops.reverse()) {
        await stop();
      }
    }
  });
}

test('a local agent pairs with the node through the relay, and only its signed calls run', async ({ browser }) => {
  const why = stack.missing({ app: true });
  test.skip(why !== '', why);
  const stops = [];
  // Every relay of this test. A relay says on stderr which mode and port it took, and a failure prints that.
  const relays = [];
  const configHome = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-relay-keys-'));
  stops.push(() => fs.rmSync(configHome, { recursive: true, force: true }));
  try {
    const samOne = await stack.startSamOne();
    stops.push(() => samOne.stop());
    const origin = new URL(app.url).origin;
    await stack.assertRelayPortFree();
    let relay;
    stops.push(() => relay?.stop());
    const startRelay = async (label, options) => {
      const started = await stack.startAgentRelay(origin, options);
      relays.push({ label, started });
      return started;
    };
    const tools = async () => (await relay.client.listTools()).tools.map((tool) => tool.name);
    const callRaw = (name, args) => relay.client.callTool({ name, arguments: args });
    const call = async (name, args) => {
      const result = await callRaw(name, args);
      expect(result.isError, result.content[0].text).toBeFalsy();
      return JSON.parse(result.content[0].text);
    };

    const context = await browser.newContext({ permissions: ['local-network-access', 'clipboard-read', 'clipboard-write'] });
    stops.push(() => context.close());
    const page = await context.newPage();
    await watchCSP(page);
    await page.goto(linkTo(samOne));
    await joinFromDialog(page, samOne.joinToken);
    await page.getByRole('button', { name: 'Config' }).click();
    await page.getByRole('button', { name: 'Connect a local agent' }).click();
    await expect(page.locator('#agent-status')).toHaveText('Waiting for your agent. Paste the prompt into it and follow the instructions.');
    await expect(page.locator('#agent-config')).toContainText('~/.local/share/agentmesh/webapp-relay/relay.mjs');
    // The prompt's install step, run as printed with this test's home folder: Node alone saves the relay.
    const install = await page.locator('#agent-install').textContent();
    execFileSync('sh', ['-c', install], { env: { ...process.env, HOME: configHome }, stdio: 'pipe' });
    const cli = path.join(configHome, '.local', 'share', 'agentmesh', 'webapp-relay', 'relay.mjs');
    relay = await startRelay('first', { agentName: 'Claude Code', configHome, cli });
    await page.locator('#copy-agent-prompt').click();
    const prompt = await page.evaluate(() => navigator.clipboard.readText());
    const token = /with the token ([0-9a-f]{32})\./.exec(prompt)?.[1];
    expect(token, prompt).toBeTruthy();
    expect(prompt).toContain(install);

    await expect.poll(tools, { timeout: 20_000, message: 'the relay lists the page tools' }).toEqual(expect.arrayContaining(['pair_agent', 'get_mesh_info']));
    expect((await callRaw('get_mesh_info', {})).content[0].text).toContain('not paired yet');
    expect((await callRaw('pair_agent', { token: '0'.repeat(32) })).content[0].text).toContain('token is wrong, expired or already used');
    expect((await callRaw('pair_agent', { token })).content[0].text).toContain('Paired with the Agent Mesh page as "Claude Code"');
    await expect(page.locator('#agent-paired li')).toHaveCount(1);
    await expect(page.locator('#agent-paired li')).toContainText('Claude Code, paired');
    await expect(page.locator('#agent-setup')).toBeHidden();
    const keyFile = path.join(configHome, 'agentmesh', 'webapp-relay', encodeURIComponent(new URL(origin).host), 'Claude%20Code.json');
    expect(fs.statSync(keyFile).mode & 0o777).toBe(0o600);
    expect((await callRaw('pair_agent', { token })).content[0].text).toContain('No pairing is open');

    // The page answers from its own mesh session: its peer ID and the router it holds.
    const info = await call('get_mesh_info', {});
    expect(info.peer_id).toBe(await nodeId(page));
    expect(info.attached_routers).toHaveLength(1);
    await expect(page.locator('#agent-status')).toContainText('Claude Code: last call get_mesh_info at');
    await expect(page.locator('#agent-status')).toContainText('1 call so far');
    await call('discover_remote_services', { type: 'a2a', name: 'agent' });
    await expect(page.locator('#agent-calls li').first()).toContainText('Claude Code: discover_remote_services a2a agent');
    await expect(page.locator('#agent-calls li').nth(1)).toContainText('Claude Code: get_mesh_info');
    await page.getByRole('button', { name: 'Dashboard' }).click();
    await expect(page.locator('#agent-line')).toContainText('Local agent Claude Code connected, last call discover_remote_services');
    await page.getByRole('button', { name: 'Config' }).click();

    // A restarted agent stays paired, and the open page finds its relay again without a reload.
    await relay.stop();
    relay = await startRelay('restarted', { agentName: 'Claude Code', configHome, cli });
    await expect.poll(tools, { timeout: 15_000, message: 'the page reconnects to the restarted relay' }).toContain('get_mesh_info');
    expect((await call('get_mesh_info', {})).peer_id).toBe(await nodeId(page));

    // Another program starts the upstream relay, with no pairing. The agent's relay holds the port, so this one
    // joins it. It starts before the reload, because a relay that joins learns the tools for certain only from the
    // update that the other relay sends when the page's tools change: it can lose the list that it asks for at
    // its own start (sdk/js/webapp/relay-join.ts).
    const plain = await startRelay('plain', { plain: true });
    stops.push(() => plain.stop());
    const plainTools = async () => (await plain.client.listTools()).tools.map((tool) => tool.name);
    await expect.poll(() => plain.output, { timeout: 5_000, message: 'the plain relay joins the relay that holds the port' }).toContain('client mode');

    // A reloaded page stays paired too.
    await page.reload();
    await page.getByRole('button', { name: 'Config' }).click();
    await expect.poll(tools, { timeout: 20_000, message: 'the reloaded page offers its tools again' }).toContain('get_mesh_info');
    expect((await call('get_mesh_info', {})).peer_id).toBe(await nodeId(page));

    // The program with no pairing reaches the page through the agent's relay, but its calls are refused:
    // the agent's relay signs its own calls only.
    await expect.poll(plainTools, { timeout: 20_000, message: 'the plain relay lists the page tools' }).toContain('get_mesh_info');
    expect((await plain.client.callTool({ name: 'get_mesh_info', arguments: {} })).content[0].text).toContain('accepts calls only from a paired agent');

    await page.getByRole('button', { name: 'Forget Claude Code' }).click();
    await expect(page.locator('#agent-paired')).toBeHidden();
    expect((await callRaw('get_mesh_info', {})).content[0].text).toContain('no longer paired');

    await page.getByRole('button', { name: 'Disconnect local agent' }).click();
    await expect.poll(tools, { timeout: 10_000, message: 'disconnecting withdraws the tools' }).not.toContain('get_mesh_info');
    await expect(page.locator('#agent-line')).toBeHidden();
    await noViolations(page);
  } catch (err) {
    for (const { label, started } of relays) {
      console.log(`-- stderr of the ${label} relay --\n${started.output}`);
    }
    throw err;
  } finally {
    for (const stop of stops.reverse()) {
      await stop();
    }
  }
});

test('Chromium can install the app without a service worker', async () => {
  const why = stack.missing({ app: true });
  test.skip(why !== '', why);
  const samOne = await stack.startSamOne();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-app-profile-'));
  // The headless shell has no install checks and reports none; full Chromium
  // reports them, and only outside incognito, hence a persistent profile.
  const context = await chromium.launchPersistentContext(profile, { channel: 'chromium' });
  try {
    const page = context.pages()[0] ?? (await context.newPage());
    await page.goto(app.url);
    await expect(page.locator('#view-welcome')).toBeVisible({ timeout: 30_000 });
    const cdp = await context.newCDPSession(page);
    const { installabilityErrors } = await cdp.send('Page.getInstallabilityErrors');
    expect(installabilityErrors).toEqual([]);
  } finally {
    await context.close();
    fs.rmSync(profile, { recursive: true, force: true });
    await samOne.stop();
  }
});

test('a lapsed credential is refreshed at launch', async ({ context }) => {
  const why = stack.missing({ app: true });
  test.skip(why !== '', why);
  // The router's own credential also lives 15 s; its default 5 min pass would present it expired.
  const samOne = await stack.startSamOne({ args: ['--control-plane-biscuit-ttl', '15s', '--router-control-plane-sync-interval', '2s'] });
  try {
    const page = await context.newPage();
    await watchCSP(page);
    await page.goto(linkTo(samOne));
    await joinFromDialog(page, samOne.joinToken);
    const peer = await nodeId(page);
    const expires = await page.evaluate(() => window.agentmeshApp.state.stats.expires);
    await page.close();

    await expect.poll(() => Date.now() / 1000 > expires + 1, { timeout: 30_000 }).toBe(true);
    const later = await context.newPage();
    await watchCSP(later);
    await later.goto(app.url);
    await expect(nodeTitle(later)).toHaveText('Node is Running', { timeout: 30_000 });
    expect(await nodeId(later)).toBe(peer);
    expect(await later.evaluate(() => window.agentmeshApp.state.stats.expires)).toBeGreaterThan(expires);
    await noViolations(later);
  } finally {
    await samOne.stop();
  }
});

test('a mesh that forgot this device takes a new code and keeps the Node ID', async ({ page }) => {
  const why = stack.missing({ app: true });
  test.skip(why !== '', why);
  let samOne = await stack.startSamOne();
  try {
    await watchCSP(page);
    await page.goto(linkTo(samOne));
    await joinFromDialog(page, samOne.joinToken);
    const peer = await nodeId(page);

    await samOne.stop();
    samOne = await stack.startSamOne({ port: samOne.port });
    await page.reload();
    await expect(page.locator('#status')).toContainText('The mesh no longer accepts this device', { timeout: 30_000 });
    await expect(page.locator('#welcome-title')).toHaveText('Rejoin the mesh');
    await expect(page.locator('#labels-field')).toBeHidden();
    // A banned key cannot rejoin, so the rejoin view keeps the way out.
    await expect(page.locator('#rejoin-unenroll')).toBeVisible();

    await pasteCode(page, samOne.joinToken);
    await joinFromDialog(page, samOne.joinToken);
    expect(await nodeId(page)).toBe(peer);
    await noViolations(page);
  } finally {
    await samOne.stop();
  }
});

test('Sign in shows only when the provider answers the page with its own issuer, refuses a forged return, survives a silent provider, follows a provider change, and joins and rejoins with one Node ID', async ({ page, browser }) => {
  const why = stack.missing({ app: true });
  test.skip(why !== '', why);
  const tls = stack.selfSignedCert('localhost');
  test.skip(tls === null, 'openssl is not installed');
  const stops = [() => fs.rmSync(tls.dir, { recursive: true, force: true })];
  // The control plane trusts the mock provider's certificate through SSL_CERT_FILE, the page through ignoreHTTPSErrors.
  const startMesh = (issuer, port, ...extra) =>
    stack.startSamOne({ port, args: ['--issuer', issuer, ...extra], env: { SSL_CERT_FILE: tls.certFile } });
  // 15 s credentials, so the page renews one at once while the test watches; the router's own credential also lives 15 s.
  const shortCredentials = ['--control-plane-biscuit-ttl', '15s', '--router-control-plane-sync-interval', '2s'];
  const signInButton = (provider) => page.getByRole('button', { name: `Sign in with ${new URL(provider.issuer).host}` });
  try {
    await watchCSP(page);
    const plain = await stack.startSamOne();
    stops.push(() => plain.stop());
    await page.goto(app.url);
    await expect(page.locator('#welcome-title')).toHaveText('Welcome to Agent Mesh');
    await expect(page.locator('#server-input')).toBeEditable();
    const asked = page.waitForResponse((res) => res.url() === `${plain.localUrl}/info`);
    await enterServer(page, plain.localUrl);
    await asked;
    await expect(page.locator('#sign-in-block')).toBeHidden();

    const closed = await startMockOIDC({ tls, cors: false });
    stops.push(() => closed.stop());
    const closedMesh = await startMesh(closed.issuer);
    stops.push(() => closedMesh.stop());
    const gaveUp = page.waitForEvent('console', (msg) => msg.text().includes('Sign in is not offered'));
    await enterServer(page, closedMesh.localUrl);
    await gaveUp;
    await expect(page.locator('#sign-in-block')).toBeHidden();
    await expect(page.locator('#offer-input')).toBeVisible();

    const provider = await startMockOIDC({ tls });
    stops.push(() => provider.stop());
    let samOne = await startMesh(provider.issuer);
    stops.push(() => samOne.stop());
    // Enrollment by sign-in needs the node role bound to the identity, as the testnets bind it.
    const bindNodeRole = async () => {
      const admin = { Authorization: `Bearer ${samOne.adminToken}` };
      const current = await fetch(`${samOne.localUrl}/admin/policy`, { headers: admin });
      expect(current.status, 'GET /admin/policy').toBe(200);
      const policy = await current.json();
      policy.bindings = [...(policy.bindings ?? []), { role: 'mesh:role:node', members: ['mesh:system:authenticated'] }];
      const saved = await fetch(`${samOne.localUrl}/policies`, { method: 'POST', headers: { ...admin, 'Content-Type': 'application/json' }, body: JSON.stringify(policy) });
      expect(saved.status, await saved.text()).toBe(200);
    };
    await bindNodeRole();
    // A page that names no mesh offers no Sign in; the mesh's address brings it.
    await page.goto(app.url);
    await expect(page.locator('#view-welcome')).toBeVisible();
    await expect(page.locator('#sign-in-block')).toBeHidden();
    await enterServer(page, samOne.localUrl);
    await expect(signInButton(provider)).toBeVisible();
    // A link with only #server=… fills in the address, so the mesh's Sign in shows at once.
    const meshPage = linkTo(samOne, null);

    // With discovery hanging, a token join still works, and any enrollment clears a sign-in error; the 10 s refusal step below pins that a hung lookup holds no join.
    provider.hangDiscovery = true;
    const other = await browser.newContext({ ignoreHTTPSErrors: true });
    stops.push(() => other.close());
    const fallback = await other.newPage();
    await fallback.goto(`${app.url}?code=forged&state=forged`);
    await expect(fallback.locator('#sign-in-error')).toBeVisible();
    await fallback.evaluate((server) => {
      location.hash = `server=${encodeURIComponent(server)}&token=mesh_not_a_token`;
    }, samOne.localUrl);
    await fallback.locator('#join-dialog').getByRole('button', { name: 'Join' }).click();
    await expect(fallback.locator('#status')).toContainText('Enrollment failed', { timeout: 10_000 });
    await expect(fallback.locator('#sign-in-error')).toBeHidden();
    await pasteCode(fallback, samOne.joinToken);
    await joinFromDialog(fallback, samOne.joinToken);
    await other.close();
    provider.hangDiscovery = false;

    // OIDC Discovery 1.0 section 4.3: a document for another issuer, or without a token endpoint, offers no Sign in.
    for (const pageDiscovery of [{ issuer: 'https://elsewhere.example' }, { token_endpoint: undefined }]) {
      provider.pageDiscovery = pageDiscovery;
      const refused = page.waitForEvent('console', (msg) => msg.text().includes('Sign in is not offered'));
      await page.goto(meshPage);
      await refused;
      await expect(page.locator('#sign-in-block')).toBeHidden();
      await expect(page.locator('#offer-input')).toBeVisible();
    }
    provider.pageDiscovery = undefined;

    // Anyone can craft a return address, so the page shows its own words, never the provider's.
    for (const forged of ['?error=access_denied&error_description=Call+this+number&state=forged', '?code=forged&state=forged']) {
      await page.goto(app.url + forged);
      await expect(page.locator('#sign-in-error')).toHaveText('This sign-in did not start in this tab. Press Sign in again.');
      expect(page.url(), 'the forged return stayed in the address bar').toBe(app.url);
      await expect(page.locator('#welcome-title')).toHaveText('Welcome to Agent Mesh');
    }

    // A token endpoint that never answers costs the page 15 s, not the app: it shows why and offers Sign in again.
    provider.hangToken = true;
    await page.goto(meshPage);
    await signInButton(provider).click();
    await expect(page.locator('#sign-in-error')).toHaveText('The sign-in provider did not answer this page. Press Sign in again, or join with a token.', { timeout: 30_000 });
    await expect(signInButton(provider)).toBeVisible();
    provider.hangToken = false;

    // Cancel during /register, which the SDK cannot abort: the credential is saved, so the address locks to this mesh.
    let releaseRegister;
    await page.route(`${samOne.localUrl}/register`, async (route) => {
      await new Promise((resolve) => (releaseRegister = resolve));
      await route.continue();
    });
    await signInButton(provider).click();
    await expect.poll(() => releaseRegister !== undefined, { timeout: 30_000 }).toBe(true);
    await page.locator('#cancel-enroll').click();
    await expect(page.locator('#status')).toContainText('Enrollment cancelled.');
    // A code for another mesh taken before the lock exists opens its dialog, and the join checks the lock again.
    await pasteCode(page, 'mesh://enroll?server=https%3A%2F%2Fother.example.com&token=mesh_dev_x');
    await expect(page.locator('#join-dialog')).toBeVisible();
    // A provider that is slow to answer holds the view's Sign in lookup for 15 s, so within 5 s only the lock write shows Reset.
    provider.hangDiscovery = true;
    const registered = page.waitForResponse((res) => res.url() === `${samOne.localUrl}/register`);
    releaseRegister();
    await registered;
    await page.unroute(`${samOne.localUrl}/register`);
    await expect(page.locator('#welcome-reset')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('#server-input')).not.toBeEditable();
    await page.locator('#join-dialog').getByRole('button', { name: 'Join' }).click();
    await expect(page.locator('#status-text')).toHaveText(`Enrollment failed: This device belongs to the mesh at ${new URL(samOne.localUrl).host}. Reset device identity to join another mesh.`, { timeout: 10_000 });
    await pasteCode(page, 'mesh://enroll?server=https%3A%2F%2Fother.example.com&token=mesh_dev_x');
    await expect(page.locator('#offer-error')).toHaveText(`This device belongs to the mesh at ${new URL(samOne.localUrl).host}. Reset device identity to join another mesh.`);
    // A failed join enters the view again, and the provider, answering now, brings Sign in back.
    provider.hangDiscovery = false;
    await pasteCode(page, 'mesh_not_a_token');
    await page.locator('#join-dialog').getByRole('button', { name: 'Join' }).click();
    await expect(page.locator('#status')).toContainText('Enrollment failed', { timeout: 10_000 });

    await signInButton(provider).click();
    await expect(nodeTitle(page)).toHaveText('Node is Running', { timeout: 30_000 });
    expect(page.url(), 'the code stayed in the address bar').toBe(app.url);
    const peer = await nodeId(page);

    // The saved credential joins again: a reload needs no second sign-in.
    await page.reload();
    await expect(nodeTitle(page)).toHaveText('Node is Running', { timeout: 30_000 });
    expect(await nodeId(page)).toBe(peer);

    await samOne.stop();
    samOne = await startMesh(provider.issuer, samOne.port);
    await bindNodeRole();
    await page.reload();
    await expect(page.locator('#welcome-title')).toHaveText('Rejoin the mesh', { timeout: 30_000 });
    await expect(signInButton(provider)).toBeVisible();

    // Without a reload, the page follows the operator: no provider, no Sign in; the provider back, Sign in back.
    const failToken = async () => {
      await pasteCode(page, 'mesh_not_a_token');
      await page.locator('#join-dialog').getByRole('button', { name: 'Join' }).click();
      await expect(page.locator('#status')).toContainText('Enrollment failed', { timeout: 10_000 });
    };
    await samOne.stop();
    samOne = await stack.startSamOne({ port: samOne.port });
    await failToken();
    await expect(page.locator('#sign-in-block')).toBeHidden();
    await samOne.stop();
    samOne = await startMesh(provider.issuer, samOne.port, ...shortCredentials);
    await bindNodeRole();
    await failToken();
    await expect(signInButton(provider)).toBeVisible();
    // A provider that stops answering is dropped after 15 s, not offered for as long as the view stays open.
    provider.hangDiscovery = true;
    await failToken();
    await expect(page.locator('#sign-in-block')).toBeHidden({ timeout: 30_000 });
    provider.hangDiscovery = false;
    await failToken();
    const issued = page.waitForResponse((res) => res.url() === `${provider.issuer}/token`);
    await signInButton(provider).click();
    await expect(nodeTitle(page)).toHaveText('Node is Running', { timeout: 30_000 });
    expect(await nodeId(page)).toBe(peer);
    const idToken = (await (await issued).json()).id_token;

    // The credential renews by proof of possession: the page keeps no ID token to send.
    const refresh = await page.waitForRequest((req) => req.url() === `${samOne.localUrl}/refresh`, { timeout: 30_000 });
    expect(refresh.postDataBuffer().includes(Buffer.from(idToken)), 'the refresh carried the ID token').toBe(false);
    expect((await refresh.response()).status()).toBe(200);

    // The control plane spends the old credential when it answers /refresh, so the page saves the new one before it asks
    // for /keys. Held there, a reload still joins with the saved credential.
    let refreshed = false;
    page.on('response', (res) => {
      if (res.url() === `${samOne.localUrl}/refresh` && res.status() === 200) refreshed = true;
    });
    let hold;
    const held = new Promise((resolve) => (hold = resolve));
    await page.route(`${samOne.localUrl}/keys`, (route) => {
      // Only the first /keys after a refresh answer, and never released: the reload drops it.
      if (!refreshed || hold === undefined) return route.continue();
      hold();
      hold = undefined;
    });
    await held;
    await page.reload();
    await expect(nodeTitle(page)).toHaveText('Node is Running', { timeout: 30_000 });
    expect(await nodeId(page)).toBe(peer);
    await noViolations(page);
  } finally {
    for (const stop of stops.reverse()) {
      await stop();
    }
  }
});

test('a banned browser keeps a way to reset its identity, whatever it tries first', async ({ page }) => {
  const why = stack.missing({ app: true });
  test.skip(why !== '', why);
  const samOne = await stack.startSamOne();
  try {
    await watchCSP(page);
    await page.goto(linkTo(samOne));
    await joinFromDialog(page, samOne.joinToken);
    const peer = await nodeId(page);
    execFileSync(path.join(__dirname, '..', '..', 'bin', 'agentmesh-one'), ['admin', 'ban', peer, '--server', samOne.localUrl, '--data-dir', samOne.dataDir], { stdio: 'pipe' });

    await page.reload();
    await expect(page.locator('#welcome-title')).toHaveText('Rejoin the mesh', { timeout: 30_000 });
    await expect(page.locator('#rejoin-unenroll')).toBeVisible();
    // The token the page asks for cannot help a banned key, and the reset stays in reach.
    await pasteCode(page, samOne.joinToken);
    await page.locator('#join-dialog').getByRole('button', { name: 'Join' }).click();
    await expect(page.locator('#status')).toContainText('Enrollment failed', { timeout: 30_000 });
    await expect(page.locator('#welcome-reset')).toBeVisible();
    await page.reload();
    await expect(page.locator('#welcome-reset')).toBeVisible({ timeout: 30_000 });

    await page.locator('#welcome-reset').click();
    await expect(page.locator('#status')).toContainText('Device identity reset.');
    await expect(page.locator('#welcome-reset')).toBeHidden();
    await pasteCode(page, samOne.joinToken);
    await joinFromDialog(page, samOne.joinToken);
    expect(await nodeId(page)).not.toBe(peer);
    await noViolations(page);
  } finally {
    await samOne.stop();
  }
});

test('Unenroll keeps the Node ID, Reset device identity replaces it', async ({ page }) => {
  const why = stack.missing({ app: true });
  test.skip(why !== '', why);
  const samOne = await stack.startSamOne();
  try {
    await watchCSP(page);
    await page.goto(linkTo(samOne));
    await joinFromDialog(page, samOne.joinToken);
    const peer = await nodeId(page);

    await page.getByRole('button', { name: 'Unenroll / Clear Identity' }).click();
    await page.locator('#unenroll-dialog').getByRole('button', { name: 'Unenroll', exact: true }).click();
    await expect(page.locator('#view-welcome')).toBeVisible();
    await expect(page.locator('#status')).toContainText('Node ID is kept');
    // The kept key stays with its mesh: the address is fixed, and a code for another mesh is refused.
    await expect(page.locator('#server-input')).toHaveValue(samOne.localUrl);
    await expect(page.locator('#server-input')).not.toBeEditable();
    await pasteCode(page, 'mesh://enroll?server=https%3A%2F%2Fother.example.com&token=mesh_dev_x');
    await expect(page.locator('#offer-error')).toHaveText(`This device belongs to the mesh at ${new URL(samOne.localUrl).host}. Reset device identity to join another mesh.`);
    await pasteCode(page, linkTo(samOne));
    await joinFromDialog(page, samOne.joinToken);
    expect(await nodeId(page)).toBe(peer);

    await page.getByRole('button', { name: 'Unenroll / Clear Identity' }).click();
    await page.locator('#unenroll-dialog').getByRole('button', { name: 'Reset device identity' }).click();
    await expect(page.locator('#view-welcome')).toBeVisible();
    await page.reload();
    await expect(page.locator('#view-welcome')).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('#nav'), 'a device that has not enrolled has only the welcome view').toBeHidden();
    // A new identity may join any mesh, so the address is open again.
    await expect(page.locator('#server-input')).toBeEditable();
    await expect(page.locator('#server-input')).toHaveValue('');
    await enterServer(page, samOne.localUrl);
    await page.locator('#labels').fill('region=eu');
    await pasteCode(page, samOne.joinToken);
    await joinFromDialog(page, samOne.joinToken);
    const fresh = await nodeId(page);
    expect(fresh).toMatch(/^12D3Koo/);
    expect(fresh).not.toBe(peer);
    await page.getByRole('button', { name: 'Config' }).click();
    await expect(page.locator('#labels-line')).toHaveText(/^Labels: region=eu\./);
    await noViolations(page);
  } finally {
    await samOne.stop();
  }
});

test('a second window yields the identity', async ({ context }) => {
  const why = stack.missing({ app: true });
  test.skip(why !== '', why);
  const samOne = await stack.startSamOne();
  try {
    const first = await context.newPage();
    await first.goto(linkTo(samOne));
    await joinFromDialog(first, samOne.joinToken);
    const peer = await nodeId(first);

    const second = await context.newPage();
    await second.goto(app.url);
    await expect(second.locator('#blocked-message')).toHaveText('Agent Mesh is open in another tab or window.');
    await second.getByRole('button', { name: 'Use here' }).click();
    await expect(nodeTitle(second)).toHaveText('Node is Running', { timeout: 30_000 });
    expect(await nodeId(second)).toBe(peer);
    await expect(first.locator('#blocked-message')).toHaveText('Agent Mesh is open in another tab or window.');
  } finally {
    await samOne.stop();
  }
});

test('a binary without the SDK bundle says so and spends no token', async ({ page }) => {
  const why = stack.missing();
  test.skip(why.startsWith('bin/'), why);
  const samOne = await stack.startSamOne();
  try {
    const enrollments = [];
    page.on('request', (req) => {
      if (new URL(req.url()).pathname.startsWith('/enroll')) enrollments.push(req.url());
    });
    await page.route('**/sdk/index.js', (route) => route.fulfill({ status: 404 }));
    await page.goto(linkTo(samOne));
    await expect(page.locator('#blocked-message')).toHaveText(/built without the app.*make all/);
    await expect(page.locator('#join-dialog')).toBeHidden();
    expect(enrollments).toEqual([]);
  } finally {
    await samOne.stop();
  }
});
