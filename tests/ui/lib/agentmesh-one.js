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

// The pieces the browser tests stand up around Chromium: agentmesh-one from
// bin/, agentmesh-webapp from bin/ on an origin of its own, a TLS-terminating edge in front of it that routes by name the way
// `agentmesh-one --tunnel` puts one there, a static server for the page, and the
// Node example programs from sdk/js as the other members, agentmesh-router
// from bin/ as a second router that a page reaches over WebTransport, and the
// WebMCP local relay that gives a page's tools to an agent.

const { spawn, spawnSync } = require('node:child_process');
const dgram = require('node:dgram');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const tls = require('node:tls');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const SDK_JS = path.join(REPO_ROOT, 'sdk', 'js');
const PAGE_DIR = path.join(SDK_JS, 'build', 'browser-example');

/** Why the test cannot run here, or '' when everything is in place. */
function missing({ app = false } = {}) {
  if (!fs.existsSync(path.join(REPO_ROOT, 'bin', 'agentmesh-one'))) {
    return 'bin/agentmesh-one is not built (make build)';
  }
  if (!fs.existsSync(path.join(REPO_ROOT, 'bin', 'agentmesh-router'))) {
    return 'bin/agentmesh-router is not built (make build)';
  }
  if (!fs.existsSync(path.join(REPO_ROOT, 'bin', 'agentmesh-webapp'))) {
    return 'bin/agentmesh-webapp is not built (make build)';
  }
  if (app) {
    const built = ['index.js', 'agentmesh-relay.mjs'].every((name) => fs.existsSync(path.join(REPO_ROOT, 'internal', 'webapp', 'public', 'sdk', name)));
    return built ? '' : 'the app bundle is not built (make app)';
  }
  if (!fs.existsSync(path.join(PAGE_DIR, 'index.html')) || !fs.existsSync(path.join(SDK_JS, 'build', 'examples', 'a2a-call.js'))) {
    return 'the sdk/js browser example is not built (tests/ui/run.sh builds it)';
  }
  return '';
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

// The page under test connects to the first relay that answers from 9333 up, so a real relay there would capture it.
function assertRelayPortFree() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', () => reject(new Error('port 9333 is in use, perhaps by a WebMCP relay; stop it before this test')));
    srv.listen(9333, '127.0.0.1', () => srv.close(resolve));
  });
}

function freeUDPPort() {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.on('error', reject);
    sock.bind(0, '127.0.0.1', () => {
      const { port } = sock.address();
      sock.close(() => resolve(port));
    });
  });
}

async function waitFor(url, what, tries = 100) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        return;
      }
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what} at ${url}`);
}

/** Runs bin/agentmesh-webapp on a free loopback port: a page origin apart from every mesh it joins. */
async function startWebapp() {
  const port = await freePort();
  const proc = spawn(path.join(REPO_ROOT, 'bin', 'agentmesh-webapp'), ['--bind-addr', `127.0.0.1:${port}`], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  proc.stdout.on('data', (d) => (output += d));
  proc.stderr.on('data', (d) => (output += d));
  const url = `http://127.0.0.1:${port}/`;
  try {
    await waitFor(url, 'agentmesh-webapp');
  } catch (err) {
    proc.kill();
    throw new Error(`${err.message}\n${output}`);
  }
  return { url, stop: () => proc.kill() };
}

/** Runs bin/agentmesh-one on port, or a free loopback port; externalUrl is what it advertises, and args and env go to it as given. */
async function startSamOne({ externalUrl, port, args: extra = [], env = {} } = {}) {
  port ??= await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-one-ui-'));
  const args = ['--bind-address', '127.0.0.1', '--port', String(port), '--data-dir', dataDir, '--log-level', 'warn', ...extra];
  if (externalUrl) {
    args.push('--external-url', externalUrl);
  }
  const proc = spawn(path.join(REPO_ROOT, 'bin', 'agentmesh-one'), args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
  let output = '';
  proc.stdout.on('data', (d) => (output += d));
  proc.stderr.on('data', (d) => (output += d));
  const localUrl = `http://127.0.0.1:${port}`;
  try {
    await waitFor(`${localUrl}/readyz`, 'agentmesh-one');
  } catch (err) {
    proc.kill();
    throw new Error(`${err.message}\n${output}`);
  }
  return {
    port,
    localUrl,
    dataDir,
    publicUrl: externalUrl ?? localUrl,
    joinToken: fs.readFileSync(path.join(dataDir, 'join-token'), 'utf8').trim(),
    // agentmesh-one persists a token in the data dir only when AGENTMESH_ADMIN_TOKEN is unset or blank; tests/ui/run.sh sets it.
    get adminToken() {
      return (env.AGENTMESH_ADMIN_TOKEN ?? process.env.AGENTMESH_ADMIN_TOKEN ?? '').trim() || fs.readFileSync(path.join(dataDir, 'admin-token'), 'utf8').trim();
    },
    get output() {
      return output;
    },
    stop() {
      const exited = proc.exitCode !== null || proc.signalCode !== null ? Promise.resolve() : new Promise((resolve) => proc.once('exit', resolve));
      proc.kill();
      fs.rmSync(dataDir, { recursive: true, force: true });
      return exited;
    },
  };
}

/**
 * Runs bin/agentmesh-router against samOne with QUIC and WebTransport on one
 * loopback UDP port, announced by --external-addr as an operator announces a
 * public address. Resolves once the router has leased its addresses.
 */
async function startWebTransportRouter(samOne) {
  const minted = spawnSync(path.join(REPO_ROOT, 'bin', 'agentmesh-one'), ['token', 'create', '--role', 'mesh:role:router', '--data-dir', samOne.dataDir, '--server', samOne.localUrl], { encoding: 'utf8' });
  const token = /^Token:\s+(\S+)/m.exec(minted.stdout ?? '')?.[1];
  if (minted.status !== 0 || !token) {
    throw new Error(`agentmesh-one token create exited with ${minted.status}: ${minted.stderr}`);
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentmesh-router-ui-'));
  fs.writeFileSync(path.join(dir, 'token'), token + '\n', { mode: 0o600 });
  const externalAddr = `/ip4/127.0.0.1/udp/${await freeUDPPort()}/quic-v1`;
  const args = ['--control-plane', samOne.localUrl, '--bootstrap-token-path', path.join(dir, 'token'), '--keys-path', path.join(dir, 'router.key'), '--listen', externalAddr, '--listen', `${externalAddr}/webtransport`, '--external-addr', externalAddr];
  const proc = spawn(path.join(REPO_ROOT, 'bin', 'agentmesh-router'), args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  proc.stdout.on('data', (d) => (output += d));
  proc.stderr.on('data', (d) => (output += d));
  const stop = () => {
    proc.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  };
  for (let i = 0; i < 300; i++) {
    const leased = /Lease advertises \d+ address\(es\): \[(.*)\]/.exec(output)?.[1];
    if (leased) {
      return { externalAddr, leased: leased.split(' '), peerId: /\/p2p\/(12D3Koo\w+)/.exec(leased)[1], stop };
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  stop();
  throw new Error(`agentmesh-router did not lease its addresses:\n${output}`);
}

/** A self-signed certificate for host, from openssl; null when openssl is not installed. */
function selfSignedCert(host) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sam-edge-'));
  const cert = path.join(dir, 'cert.pem');
  const key = path.join(dir, 'key.pem');
  const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', `/CN=${host}`, '-addext', `subjectAltName=DNS:${host}`], { stdio: 'pipe' });
  if (r.error || r.status !== 0) {
    fs.rmSync(dir, { recursive: true, force: true });
    return null;
  }
  return { certFile: cert, cert: fs.readFileSync(cert), key: fs.readFileSync(key), dir };
}

function hostOf(req) {
  const h = req.headers.host ?? '';
  return h.includes(':') ? h.slice(0, h.lastIndexOf(':')) : h;
}

/**
 * Terminates TLS for host and proxies to origin, HTTP and WebSocket
 * upgrades alike. A handshake for another server name fails and a request
 * for another host gets 403, as an edge that routes by name treats a client
 * that reached it by IP.
 */
async function startTLSEdge({ host, origin, cert, key, port = 0 }) {
  const [originHost, originPort] = origin.split(':');
  const context = tls.createSecureContext({ cert, key });
  const server = https.createServer(
    {
      cert,
      key,
      SNICallback: (name, cb) => (name.toLowerCase() === host ? cb(null, context) : cb(new Error(`edge: unknown server name ${name}`))),
    },
    (req, res) => {
      if (hostOf(req).toLowerCase() !== host) {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end(`403 Forbidden (edge: unknown host ${req.headers.host})\n`);
        return;
      }
      const upstream = http.request({ host: originHost, port: Number(originPort), method: req.method, path: req.url, headers: { ...req.headers, host: origin } }, (ur) => {
        res.writeHead(ur.statusCode, ur.headers);
        ur.pipe(res);
      });
      upstream.on('error', () => {
        res.writeHead(502);
        res.end();
      });
      req.pipe(upstream);
    },
  );
  server.on('upgrade', (req, socket, head) => {
    if (hostOf(req).toLowerCase() !== host) {
      socket.end('HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n');
      return;
    }
    const upstream = net.connect(Number(originPort), originHost, () => {
      const lines = [`${req.method} ${req.url} HTTP/1.1`];
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const name = req.rawHeaders[i];
        lines.push(`${name}: ${name.toLowerCase() === 'host' ? origin : req.rawHeaders[i + 1]}`);
      }
      upstream.write(lines.join('\r\n') + '\r\n\r\n');
      if (head.length > 0) {
        upstream.write(head);
      }
      socket.pipe(upstream).pipe(socket);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  });
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  return { url: `https://${host}:${server.address().port}`, port: server.address().port, stop: () => server.close() };
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.map': 'application/json', '.wasm': 'application/wasm' };

/** Serves a directory of static files on a free loopback port. */
async function serveStatic(dir) {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '') || 'index.html';
    const file = path.join(dir, rel);
    if (!file.startsWith(dir) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, stop: () => server.close() };
}

/** Runs one of sdk/js's built examples to completion and returns its output. */
function runExample(name, env, args = []) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [path.join(SDK_JS, 'build', 'examples', `${name}.js`), ...args], { cwd: REPO_ROOT, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    proc.stdout.on('data', (d) => (out += d));
    proc.stderr.on('data', (d) => (out += d));
    const timer = setTimeout(() => proc.kill(), 30_000);
    proc.on('close', (code) => {
      clearTimeout(timer);
      code === 0 ? resolve(out) : reject(new Error(`${name} exited with ${code}:\n${out}`));
    });
  });
}

/** Starts one of sdk/js's built example agents and waits for the line that names its peer. */
function startExampleAgent(name, env, ready = /accepting a2a:\/\/agent as (\S+)/) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [path.join(SDK_JS, 'build', 'examples', `${name}.js`)], { cwd: REPO_ROOT, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error(`${name} did not come up:\n${out}`));
    }, 30_000);
    const onData = (d) => {
      out += d;
      const m = ready.exec(out);
      if (m) {
        clearTimeout(timer);
        resolve({ peerId: m[1], stop: () => proc.kill(), get output() { return out; } });
      }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', onData);
    proc.on('close', () => {
      clearTimeout(timer);
      reject(new Error(`${name} exited:\n${out}`));
    });
  });
}

/**
 * Starts a relay for pages of origin, connected to an MCP client as an agent would be: the paired relay
 * the app serves, run from cli as agentName with its keys under configHome, or with plain the unpaired upstream relay.
 */
async function startAgentRelay(origin, { agentName = 'UI Test Agent', configHome, plain = false, cli = path.join(REPO_ROOT, 'internal', 'webapp', 'public', 'sdk', 'agentmesh-relay.mjs') } = {}) {
  const sdkRequire = require('node:module').createRequire(path.join(SDK_JS, 'package.json'));
  const { Client } = sdkRequire('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = sdkRequire('@modelcontextprotocol/sdk/client/stdio.js');
  const client = new Client({ name: 'ui-test-agent', version: '1' });
  const transport = plain
    ? new StdioClientTransport({ command: path.join(SDK_JS, 'node_modules', '.bin', 'webmcp-local-relay'), args: ['--widget-origin', origin], stderr: 'pipe' })
    : new StdioClientTransport({
        command: process.execPath,
        args: [cli, '--widget-origin', origin, '--agent-name', agentName],
        env: { ...process.env, XDG_CONFIG_HOME: configHome },
        stderr: 'pipe',
      });
  let log = '';
  transport.stderr?.on('data', (d) => (log += d));
  await client.connect(transport);
  return { client, stop: () => client.close(), get output() { return log; } };
}

/** The environment the Node examples take to join agentmesh-one at publicUrl. */
function exampleEnv({ publicUrl, joinToken, caFile }, stateName) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `sam-${stateName}-`));
  fs.writeFileSync(path.join(dir, 'join-token'), joinToken + '\n', { mode: 0o600 });
  return {
    AGENTMESH_CONTROL_PLANE_URL: publicUrl,
    AGENTMESH_BOOTSTRAP_TOKEN_PATH: path.join(dir, 'join-token'),
    AGENTMESH_STATE_DIR: path.join(dir, 'state'),
    ...(caFile ? { NODE_EXTRA_CA_CERTS: caFile } : {}),
  };
}

module.exports = { PAGE_DIR, missing, freePort, assertRelayPortFree, startSamOne, startWebapp, startWebTransportRouter, selfSignedCert, startTLSEdge, serveStatic, runExample, startExampleAgent, startAgentRelay, exampleEnv };
