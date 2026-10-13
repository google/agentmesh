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

const { test, expect } = require('@playwright/test');

const ADMIN_TOKEN = process.env.AGENTMESH_ADMIN_TOKEN || 'ui-test-admin-token';

// Tests run serially with a single worker, so one collector is enough.
let jsFailures = [];

// The landing page deliberately probes an authenticated endpoint before login,
// so a 401 and its handler's console.error are expected, not defects.
const EXPECTED_NOISE = [
  'Unauthorized. Please login again.',
  'Failed to load resource: the server responded with a status of 401',
];

// The console is hand-written vanilla JS with no build step, so a renamed element
// id or a typo only surfaces at runtime. Fail the test on any uncaught error.
test.beforeEach(async ({ page }) => {
  jsFailures = [];
  page.on('pageerror', (err) => jsFailures.push(`uncaught: ${err.message}`));
  page.on('console', (msg) => {
    if (msg.type() !== 'error') {
      return;
    }
    const text = msg.text();
    if (EXPECTED_NOISE.some((allowed) => text.includes(allowed))) {
      return;
    }
    jsFailures.push(`console.error: ${text}`);
  });
});

test.afterEach(async () => {
  expect(jsFailures, 'console reported JavaScript errors').toEqual([]);
});

async function login(page) {
  await page.goto('/');
  await page.fill('#admin-token-input', ADMIN_TOKEN);
  await page.click('button:has-text("Login as Admin")');
  await expect(page.locator('#app-container')).toBeVisible();
}

test('admin can log in and reach the bootstrap token form', async ({ page }) => {
  await login(page);

  await page.click('.nav-item[data-target="bootstrap"]');
  await expect(page.locator('#view-bootstrap')).toBeVisible();
  await expect(page.locator('#form-generate-token')).toBeVisible();

  // Owner ID is admin-only and optional.
  await expect(page.locator('#token-owner')).toBeVisible();
  const required = await page.locator('#token-owner').evaluate((el) => el.required);
  expect(required).toBe(false);
});

test('generating a token shows a copyable value and lists it', async ({ page }) => {
  await login(page);
  await page.click('.nav-item[data-target="bootstrap"]');

  await expect(page.locator('#token-result')).toBeHidden();

  await page.selectOption('#token-role', 'mesh:role:node');
  await page.fill('#token-desc', 'playwright smoke');
  await page.click('#form-generate-token button[type="submit"]');

  const tokenField = page.locator('#token-result-value');
  await expect(page.locator('#token-result')).toBeVisible();
  await expect(tokenField).toHaveValue(/^mesh-bt-[0-9a-f]{32}$/);

  const token = await tokenField.inputValue();
  await expect(page.locator('#token-result-owner')).toHaveText('none');
  await expect(page.locator('#token-result-cmd')).toContainText(token);

  // The copy affordance is the whole point of the panel; prove it works.
  await page.click('#token-copy-btn');
  await expect(page.locator('#token-copy-btn')).toHaveText('Copied');
  const clipboard = await page.evaluate(() => navigator.clipboard.readText());
  expect(clipboard).toBe(token);

  // The new token must appear in the active token list after the refresh.
  await expect(page.locator('#table-bootstrap')).toContainText('mesh:role:node');
});

// The admin token has no users row to own a token, so the token is unowned.
test('omitting the owner as the root admin leaves the token unowned', async ({ page }) => {
  await login(page);
  await page.click('.nav-item[data-target="bootstrap"]');

  await expect(page.locator('#token-owner')).toHaveValue('');
  await page.click('#form-generate-token button[type="submit"]');

  await expect(page.locator('#token-result-owner')).toHaveText('none');
});

// The console holds mesh admin credentials. If they were reachable from JS, a
// single XSS in this hand-written page would hand over the whole mesh.
test('the session credential is never exposed to JavaScript', async ({ page, context }) => {
  await login(page);

  const storage = await page.evaluate(() => JSON.stringify(window.localStorage));
  expect(storage).not.toContain(ADMIN_TOKEN);
  expect(await page.evaluate(() => document.cookie)).not.toContain(ADMIN_TOKEN);

  const session = (await context.cookies()).find((c) => c.name === 'agentmesh_session');
  expect(session, 'agentmesh_session cookie was not set').toBeTruthy();
  expect(session.httpOnly).toBe(true);
});

test('views are deep-linkable via the URL hash', async ({ page }) => {
  await login(page);

  await page.click('.nav-item[data-target="routers"]');
  await expect(page).toHaveURL(/#routers$/);

  // A reload must land back on the same view rather than resetting to Overview.
  await page.reload();
  await expect(page.locator('#view-routers')).toBeVisible();
  await expect(page.locator('#view-overview')).toBeHidden();
  await expect(page.locator('.nav-item[data-target="routers"]')).toHaveAttribute('aria-current', 'page');

  // Back returns to the previously selected view.
  await page.goBack();
  await expect(page.locator('#view-overview')).toBeVisible();
});

test('an unknown hash falls back to the overview', async ({ page }) => {
  await login(page);

  await page.goto('/#not-a-view');
  await expect(page.locator('#view-overview')).toBeVisible();
});

test('the search box filters rendered rows', async ({ page }) => {
  await login(page);
  await page.click('.nav-item[data-target="bootstrap"]');

  // Guarantee at least one row to filter, independent of test ordering. Wait
  // for the result panel before typing anywhere else: showing it moves focus
  // to the token field, and a fill() that races that focus change inserts
  // its text there instead of into the search box.
  await page.click('#form-generate-token button[type="submit"]');
  await expect(page.locator('#token-result')).toBeVisible();
  await expect(page.locator('#table-bootstrap')).toContainText('mesh:role:node');

  await page.fill('#resource-search', 'mesh:role:node');
  await expect(page.locator('#table-bootstrap tr:visible')).not.toHaveCount(0);
  await expect(page.locator('#table-bootstrap tr[data-filter-empty]')).toHaveCount(0);

  await page.fill('#resource-search', 'zzz-no-such-resource');
  await expect(page.locator('#table-bootstrap tr[data-filter-empty]')).toContainText('No rows match');

  await page.fill('#resource-search', '');
  await expect(page.locator('#table-bootstrap tr[data-filter-empty]')).toHaveCount(0);
  await expect(page.locator('#table-bootstrap')).toContainText('mesh:role:node');
});

// The policy textarea is the one place in the console where a stray click can
// destroy work that exists nowhere else.
test('leaving the policy view warns about unsaved edits', async ({ page }) => {
  await login(page);
  await page.click('.nav-item[data-target="policy"]');
  await page.fill('#policy-yaml', '# unsaved edit\n');

  let message = '';
  const dismissed = new Promise((resolve) => {
    page.once('dialog', async (d) => {
      message = d.message();
      await d.dismiss();
      resolve();
    });
  });
  await page.click('.nav-item[data-target="overview"]');
  await dismissed;
  expect(message).toContain('unsaved policy changes');
  await expect(page.locator('#view-policy')).toBeVisible();

  page.once('dialog', (d) => d.accept());
  await page.click('.nav-item[data-target="overview"]');
  await expect(page.locator('#view-overview')).toBeVisible();
});

test('an unedited policy view navigates away without prompting', async ({ page }) => {
  await login(page);
  await page.click('.nav-item[data-target="policy"]');

  let prompted = false;
  page.once('dialog', async (d) => {
    prompted = true;
    await d.dismiss();
  });
  await page.click('.nav-item[data-target="overview"]');
  await expect(page.locator('#view-overview')).toBeVisible();
  expect(prompted).toBe(false);
});

test('navigation is keyboard operable and refreshes are announced', async ({ page }) => {
  await login(page);

  // Real hrefs, so keyboard activation and open-in-new-tab work without JS.
  await expect(page.locator('.nav-item[data-target="nodes"]')).toHaveAttribute('href', '#nodes');

  await page.locator('.nav-item[data-target="routers"]').press('Enter');
  await expect(page.locator('#view-routers')).toBeVisible();
  await expect(page).toHaveURL(/#routers$/);

  await expect(page.locator('#live-status')).toHaveText(/nodes, .* routers/);
});

// A blocking alert() would also stall the refresh timer, so feedback must not
// come from a native dialog.
test('action feedback is a dismissible toast, not a native dialog', async ({ page }) => {
  await login(page);
  await page.click('.nav-item[data-target="policy"]');

  let dialogs = 0;
  page.on('dialog', async (d) => {
    dialogs += 1;
    await d.dismiss();
  });

  await page.fill('#policy-yaml', 'roles:\n  - name: dev\n    allowed_services: ["mcp://git"]\n    allowed_targets: ["group:eng"]\nbindings:\n  - role: dev\n    members: ["user:bob"]\n');
  await page.click('#policy-save');

  const toast = page.locator('#toast-container .toast');
  await expect(toast).toHaveClass(/toast-success/);
  await expect(toast).toContainText('Mesh policy updated');
  expect(dialogs).toBe(0);

  await toast.locator('.toast-dismiss').click();
  await expect(toast).toHaveCount(0);

  // Saving cleared the dirty flag, so leaving must not prompt.
  await page.click('.nav-item[data-target="overview"]');
  await expect(page.locator('#view-overview')).toBeVisible();
  expect(dialogs).toBe(0);
});

// The editor is YAML for readability, but the API speaks protojson. The console
// converts, so a saved policy must come back as the same document.
test('the policy editor round-trips through the API', async ({ page }) => {
  await login(page);
  await page.click('.nav-item[data-target="policy"]');

  const policy = 'roles:\n  - name: reviewer\n    allowed_services: ["mcp://code-reviewer"]\n    allowed_targets: ["group:eng"]\n    custom_datalog: [\'right("data:read");\']\nbindings:\n  - role: reviewer\n    members: ["user:carol"]\n';
  await page.fill('#policy-yaml', policy);

  const posted = page.waitForRequest((r) => r.url().endsWith('/policies') && r.method() === 'POST');
  await page.click('#policy-save');

  // It must go over the wire as protojson, not as the YAML in the textarea.
  const request = await posted;
  expect(request.headers()['content-type']).toContain('application/json');
  const body = JSON.parse(request.postData());
  expect(body.roles[0].name).toBe('reviewer');
  expect(body.roles[0].custom_datalog).toEqual(['right("data:read");']);

  await expect(page.locator('#toast-container .toast')).toHaveClass(/toast-success/);

  // Reload and confirm the stored policy renders back into the editor, with the
  // custom_datalog that earlier renderers silently dropped.
  await page.reload();
  await page.click('.nav-item[data-target="policy"]');
  const reloaded = await page.locator('#policy-yaml').inputValue();
  expect(reloaded).toContain('reviewer');
  expect(reloaded).toContain('custom_datalog');
  expect(reloaded).toContain('mcp://code-reviewer');
});

test('invalid YAML is reported inline and blocks saving', async ({ page }) => {
  await login(page);
  await page.click('.nav-item[data-target="policy"]');

  await expect(page.locator('#policy-error')).toBeHidden();
  await expect(page.locator('#policy-save')).toBeEnabled();

  await page.fill('#policy-yaml', 'roles:\n  - name: dev\n   bad indentation here\n');

  const error = page.locator('#policy-error');
  await expect(error).toBeVisible();
  await expect(page.locator('#policy-save')).toBeDisabled();
  await expect(page.locator('#policy-yaml')).toHaveAttribute('aria-invalid', 'true');

  // Recovering must re-enable the button rather than requiring a reload.
  await page.fill('#policy-yaml', 'roles: []\nbindings: []\n');
  await expect(error).toBeHidden();
  await expect(page.locator('#policy-save')).toBeEnabled();
});

test('stat cards link to the view that lists what they count', async ({ page }) => {
  await login(page);

  await page.click('.stat-card[href="#routers"]');
  await expect(page.locator('#view-routers')).toBeVisible();
  await expect(page).toHaveURL(/#routers$/);
});

// Styling belongs in the stylesheet: a style attribute in the markup would need
// style-src 'unsafe-inline' to survive any strict CSP. Styles the scripts set at
// runtime go through the CSSOM, which CSP allows, so check what is served rather
// than the live DOM.
test('the served markup carries no inline style attribute', async ({ request }) => {
  const html = await (await request.get('/index.html')).text();
  expect(html).not.toMatch(/<[^>]+\sstyle=/);
});

// The Services view has no admin flow to seed it from the browser alone (a
// real node has to self-report), so this only pins what is reachable without
// one: the nav item routes there and the empty state renders without a JS
// error. TestHandleNodeCatalog in internal/controlplane covers the reporting
// endpoint itself, and TestReportNodeCatalog in internal/node covers the
// node-side push.
test('the Services view is reachable and renders its empty state', async ({ page }) => {
  await login(page);

  await page.click('.nav-item[data-target="services"]');
  await expect(page).toHaveURL(/#services$/);
  await expect(page.locator('#view-services')).toBeVisible();
  await expect(page.locator('#table-services')).toContainText('No nodes have reported any services yet');
});

// A reload must survive on this view too, same as the other deep-linkable
// views already covered above for #routers.
test('the Services view is deep-linkable via the URL hash', async ({ page }) => {
  await login(page);

  await page.goto('/#services');
  await expect(page.locator('#view-services')).toBeVisible();
  await expect(page.locator('.nav-item[data-target="services"]')).toHaveAttribute('aria-current', 'page');
});

// Seeding the Services view for real needs an enrolled node self-reporting, so
// render it from an intercepted /admin/status instead: the real response with
// node_catalog and a labelled node spliced in, shaped exactly like
// catalogViewFor in internal/controlplane/catalog.go emits it.
test('reported services render with type, labels and report time', async ({ page }) => {
  const PEER = '12D3KooWServicesViewFixturePeer';
  await page.route('**/api/admin/status', async (route) => {
    const response = await route.fetch();
    const status = await response.json();
    status.enrolled_nodes = [...(status.enrolled_nodes || []), {
      peer_id: PEER,
      role: 'mesh:role:node',
      owner_id: 'root-admin',
      labels: { component: 'stvv', region: 'eu-west' },
    }];
    status.node_catalog = {
      [PEER]: {
        services: [
          { name: 'compliance-docs', type: 'SERVICE_TYPE_MCP', description: 'doc lookup' },
          // Reported names and descriptions are node-controlled input to an
          // admin page; markup in them must render inert.
          { name: 'llama', type: 'SERVICE_TYPE_INFERENCE', description: '<img src=x onerror="window.svcXSS=1">' },
        ],
        report_time: '2026-09-15T08:00:00Z',
      },
    };
    await route.fulfill({ response, json: status });
  });

  await login(page);
  await page.click('.nav-item[data-target="services"]');

  const rows = page.locator('#table-services tr');
  await expect(rows).toHaveCount(2);

  const first = rows.nth(0);
  await expect(first).toContainText('compliance-docs');
  await expect(first).toContainText('mcp');
  await expect(first).toContainText('doc lookup');
  await expect(first).toContainText(PEER);
  // The node's labels ride along as the mnemonic under the peer ID.
  await expect(first.locator('.cell-subtext')).toHaveText('component=stvv, region=eu-west');
  // report_time renders as a local time, not the raw RFC 3339 string.
  await expect(first.locator('td').nth(4)).not.toHaveText(/2026-09-15T08:00:00Z|-/);

  await expect(rows.nth(1)).toContainText('inference');
  // The description shows as text; nothing was injected into the DOM.
  await expect(rows.nth(1)).toContainText('onerror');
  expect(await page.locator('#table-services img').count()).toBe(0);
  expect(await page.evaluate(() => window.svcXSS)).toBeUndefined();

  // The same labels also annotate the peer ID in the Nodes table.
  await page.click('.nav-item[data-target="nodes"]');
  const nodeRow = page.locator('#table-nodes tr', { hasText: PEER });
  await expect(nodeRow.locator('.cell-subtext')).toHaveText('component=stvv, region=eu-west');
});

// Revoking a node bans its record rather than deleting it, so /admin/status
// keeps returning it; the console must not keep showing it as enrolled.
test('revoked nodes disappear from the Nodes view and the node count', async ({ page }) => {
  const LIVE = '12D3KooWLiveNodeFixturePeer';
  const REVOKED = '12D3KooWRevokedNodeFixturePeer';
  await page.route('**/api/admin/status', async (route) => {
    const response = await route.fetch();
    const status = await response.json();
    status.enrolled_nodes = [
      { peer_id: LIVE, role: 'mesh:role:node', owner_id: 'root-admin' },
      { peer_id: REVOKED, role: 'mesh:role:node', owner_id: 'root-admin', banned: true },
    ];
    await route.fulfill({ response, json: status });
  });

  await login(page);
  await page.click('.nav-item[data-target="nodes"]');

  await expect(page.locator('#table-nodes')).toContainText(LIVE);
  await expect(page.locator('#table-nodes')).not.toContainText(REVOKED);
  await expect(page.locator('#stat-nodes')).toHaveText('1');
});

// A revoke only bans the record, so the console offers the way back.
test('an admin restores a revoked node from the Nodes view', async ({ page }) => {
  const REVOKED = '12D3KooWRevokedNodeFixturePeer';
  await page.route('**/api/admin/status', async (route) => {
    const response = await route.fetch();
    const status = await response.json();
    status.enrolled_nodes = [{ peer_id: REVOKED, role: 'mesh:role:node', owner_id: 'root-admin', banned: true }];
    await route.fulfill({ response, json: status });
  });
  let unban = '';
  await page.route('**/api/admin/nodes/*/unban', async (route) => {
    unban = `${route.request().method()} ${new URL(route.request().url()).pathname}`;
    await route.fulfill({ status: 204 });
  });

  await login(page);
  await page.click('.nav-item[data-target="nodes"]');
  page.once('dialog', (d) => d.accept());
  await page.locator('#table-revoked-nodes tr', { hasText: REVOKED }).locator('button:has-text("Restore")').click();
  await expect.poll(() => unban).toBe(`POST /api/admin/nodes/${REVOKED}/unban`);
});

// Expired nodes are not in /admin/status: the section fetches them only when
// opened, a page at a time, and a revoke there drops the row in place.
test('expired nodes load on open, page on demand and revoke in place', async ({ page }) => {
  const FIRST = '12D3KooWExpiredFirstFixturePeer';
  const SECOND = '12D3KooWExpiredSecondFixturePeer';
  const requested = [];
  await page.route((url) => url.pathname.endsWith('/api/user/nodes'), async (route) => {
    const params = new URL(route.request().url()).searchParams;
    requested.push(`${params.getAll('state')}:${params.get('page_token') || ''}`);
    const expired = { role: 'mesh:role:node', expire_time: '2026-09-15T08:00:00Z' };
    const json = params.get('page_token') === 'next'
      // The owner is server data on an admin page; markup in it must render inert.
      ? { nodes: [{ ...expired, peer_id: SECOND, owner_id: '<img src=x onerror="window.expiredXSS=1">' }] }
      : { nodes: [{ ...expired, peer_id: FIRST, owner_id: 'alice' }], next_page_token: 'next' };
    await route.fulfill({ json });
  });
  let revoked = '';
  await page.route((url) => url.pathname.endsWith('/api/user/revoke'), async (route) => {
    revoked = `${route.request().method()} ${new URL(route.request().url()).searchParams.get('id')}`;
    await route.fulfill({ status: 200, contentType: 'text/plain', body: 'Node revoked successfully' });
  });

  await login(page);
  await page.click('.nav-item[data-target="nodes"]');
  expect(requested, 'the list is fetched only when opened').toEqual([]);

  await page.click('#expired-nodes summary');
  const rows = page.locator('#table-expired-nodes tr');
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0)).toContainText(FIRST);
  await expect(rows.nth(0).locator('td').nth(3)).not.toHaveText(/2026-09-15T08:00:00Z|-/);

  await page.click('#expired-nodes-more');
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(1)).toContainText(SECOND);
  await expect(page.locator('#expired-nodes-more')).toBeHidden();
  expect(await page.locator('#table-expired-nodes img').count()).toBe(0);
  expect(await page.evaluate(() => window.expiredXSS)).toBeUndefined();
  expect(requested).toEqual(['expired:', 'expired:next']);

  page.once('dialog', (d) => d.accept());
  await rows.filter({ hasText: FIRST }).locator('button:has-text("Revoke")').click();
  await expect.poll(() => revoked).toBe(`POST ${FIRST}`);
  await expect(rows).toHaveCount(1);
  await expect(page.locator('#table-expired-nodes')).not.toContainText(FIRST);
});

// The landing page hides the app without a reload, so the next identity to log
// in must not see the expired rows fetched for the previous one.
test('returning to the landing page clears the expired nodes list', async ({ page }) => {
  await page.route((url) => url.pathname.endsWith('/api/user/nodes'), async (route) => {
    await route.fulfill({ json: { nodes: [{
      peer_id: '12D3KooWExpiredResetFixturePeer', role: 'mesh:role:node', owner_id: 'bob', expire_time: '2026-09-15T08:00:00Z',
    }] } });
  });

  await login(page);
  await page.click('.nav-item[data-target="nodes"]');
  await page.click('#expired-nodes summary');
  const rows = page.locator('#table-expired-nodes tr');
  await expect(rows).toHaveCount(1);

  await page.evaluate(() => showLandingPage());
  await expect(page.locator('#expired-nodes')).toHaveJSProperty('open', false);
  await expect(rows).toHaveCount(0);
});
