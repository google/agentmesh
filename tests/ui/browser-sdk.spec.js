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

// The JS SDK in a browser page (sdk/js/examples/browser) as a member of a
// agentmesh-one mesh: the page enrolls with the join token from an origin of its
// own, joins the router over WebSocket and Noise, answers A2A requests from
// a Node member, calls a Node agent, and after a reload resumes the saved
// enrollment without a token. Once against agentmesh-one directly and once behind
// a TLS-terminating edge reached by name, the topology `agentmesh-one --tunnel`
// leaves the page in, where the router is advertised as wss. A last test adds
// a router that the page reaches by IP over WebTransport.

const { test, expect } = require('@playwright/test');
const stack = require('./lib/agentmesh-one');

test.use({ ignoreHTTPSErrors: true });
test.describe.configure({ mode: 'serial' });
test.setTimeout(120_000);

const topologies = [
  { name: 'direct', edge: false },
  { name: 'behind a TLS edge', edge: true },
];

for (const topology of topologies) {
  test(`a browser page is a member of a agentmesh-one mesh (${topology.name})`, async ({ page }) => {
    const why = stack.missing();
    test.skip(why !== '', why);

    const stops = [];
    try {
      let samOne;
      let caFile;
      if (topology.edge) {
        const cert = stack.selfSignedCert('localhost');
        test.skip(cert === null, 'openssl is not installed');
        caFile = cert.certFile;
        // The edge's port must be known before agentmesh-one starts, since agentmesh-one
        // advertises it; the edge then proxies to wherever agentmesh-one bound.
        const edgePort = await stack.freePort();
        samOne = await stack.startSamOne({ externalUrl: `https://localhost:${edgePort}` });
        stops.push(() => samOne.stop());
        const edge = await stack.startTLSEdge({ host: 'localhost', origin: samOne.localUrl.replace('http://', ''), cert: cert.cert, key: cert.key, port: edgePort });
        stops.push(() => edge.stop());
      } else {
        samOne = await stack.startSamOne();
        stops.push(() => samOne.stop());
      }
      const site = await stack.serveStatic(stack.PAGE_DIR);
      stops.push(() => site.stop());

      // Enroll and join from the page, on an origin of its own.
      const query = new URLSearchParams({ controlPlaneUrl: samOne.publicUrl, bootstrapToken: samOne.joinToken, allowInsecure: 'true' });
      await page.goto(`${site.url}/?${query}`);
      await page.getByRole('button', { name: 'Join' }).click();
      await expect(page.locator('#status')).toContainText('accepting a2a://agent', { timeout: 30_000 });
      const browserPeer = (await page.locator('#peer-id').textContent()).trim();
      expect(browserPeer).toMatch(/^12D3Koo/);

      // A Node member calls the page's agent through the router.
      const nodeEnv = stack.exampleEnv({ publicUrl: samOne.publicUrl, joinToken: samOne.joinToken, caFile }, 'caller');
      const callOut = await stack.runExample('a2a-call', nodeEnv, [browserPeer, 'hello from node']);
      const nodePeer = /on the mesh as (\S+)/.exec(callOut)?.[1];
      expect(nodePeer, callOut).toBeTruthy();
      expect(callOut).toContain('agent: Echo agent (browser)');
      expect(callOut).toContain(`${nodePeer} said: hello from node`);
      await expect(page.locator('#log')).toContainText(`message from ${nodePeer}: hello from node`);

      // The page calls a Node agent.
      const agent = await stack.startExampleAgent('a2a-agent', stack.exampleEnv({ publicUrl: samOne.publicUrl, joinToken: samOne.joinToken, caFile }, 'agent'));
      stops.push(() => agent.stop());
      await page.locator('#target-peer').fill(agent.peerId);
      await page.locator('#message').fill('hello from a browser');
      await page.getByRole('button', { name: 'Call' }).click();
      await expect(page.locator('#answer')).toContainText(`Echo agent: ${browserPeer} said: hello from a browser`, { timeout: 30_000 });

      // A reload resumes the saved enrollment: same peer, no token.
      const resume = new URLSearchParams({ controlPlaneUrl: samOne.publicUrl, allowInsecure: 'true' });
      await page.goto(`${site.url}/?${resume}`);
      await page.getByRole('button', { name: 'Join' }).click();
      await expect(page.locator('#status')).toContainText('accepting a2a://agent', { timeout: 30_000 });
      expect((await page.locator('#peer-id').textContent()).trim()).toBe(browserPeer);
    } finally {
      for (const stop of stops.reverse()) {
        stop();
      }
    }
  });
}

// The router announces a QUIC address by IP and listens on WebTransport on
// the same port; it has no WebSocket listener and no CA certificate. The page
// reads the router's WebTransport address from the control plane, dials it,
// and completes the mesh handshake with the router on that connection.
test('a browser page reaches a router by IP over WebTransport', async ({ page }) => {
  const why = stack.missing();
  test.skip(why !== '', why);

  const stops = [];
  try {
    const samOne = await stack.startSamOne();
    stops.push(() => samOne.stop());
    const router = await stack.startWebTransportRouter(samOne);
    stops.push(() => router.stop());
    expect(router.leased.filter((addr) => addr.startsWith(`${router.externalAddr}/webtransport/certhash/`)), `leased: ${router.leased}`).toHaveLength(1);
    const site = await stack.serveStatic(stack.PAGE_DIR);
    stops.push(() => site.stop());

    const query = new URLSearchParams({ controlPlaneUrl: samOne.publicUrl, bootstrapToken: samOne.joinToken, allowInsecure: 'true' });
    await page.goto(`${site.url}/?${query}`);
    await page.getByRole('button', { name: 'Join' }).click();
    await expect(page.locator('#status')).toContainText('accepting a2a://agent', { timeout: 30_000 });

    // The page's open connections to the router, then "admitted" once the
    // router passed the mesh handshake.
    const toRouter = () =>
      page.evaluate((routerPeer) => {
        const { node, routers } = window.agentmesh.session;
        const open = node.getConnections().filter((c) => c.remotePeer.toString() === routerPeer && c.status === 'open');
        return [...open.map((c) => c.remoteAddr.toString()), routers.some((r) => r.peerId === routerPeer) ? 'admitted' : 'not admitted'].join(' ');
      }, router.peerId);
    await expect.poll(toRouter, { timeout: 30_000 }).toMatch(/^\S+\/webtransport\/certhash\/\S+ admitted$/);
    expect((await toRouter()).startsWith(`${router.externalAddr}/webtransport/certhash/`)).toBe(true);
  } finally {
    for (const stop of stops.reverse()) {
      stop();
    }
  }
});
