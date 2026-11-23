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

const crypto = require('node:crypto');
const https = require('node:https');

const b64url = (data) => Buffer.from(data).toString('base64url');

/**
 * An OIDC provider on https://localhost, under tls from selfSignedCert, for
 * one user: its sign-in page approves at once, and its token endpoint trades a
 * code only for the PKCE verifier the sign-in started with. It allows any
 * origin, as a provider configured for the page does, unless cors is false.
 * A test misbehaves it through the returned handle: pageDiscovery replaces
 * fields of the discovery document a browser (a request with an Origin) gets,
 * hangDiscovery makes the browser's discovery request never answer, and
 * hangToken makes the token endpoint never answer.
 */
async function startMockOIDC({ tls, cors = true, subject = 'alice', email = 'alice@example.com' }) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'ui-test';
  const codes = new Map();
  let issuer;
  const idToken = (clientId) => {
    const now = Math.floor(Date.now() / 1000);
    const head = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid }));
    const body = b64url(JSON.stringify({ iss: issuer, sub: subject, aud: clientId, email, email_verified: true, iat: now, exp: now + 600 }));
    return `${head}.${body}.${b64url(crypto.sign('sha256', Buffer.from(`${head}.${body}`), privateKey))}`;
  };
  const handle = { issuer: '', pageDiscovery: undefined, hangDiscovery: false, hangToken: false };
  const server = https.createServer({ cert: tls.cert, key: tls.key }, async (req, res) => {
    if (cors) res.setHeader('Access-Control-Allow-Origin', '*');
    const url = new URL(req.url, issuer);
    const json = (status, value) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(value));
    };
    if (url.pathname === '/.well-known/openid-configuration') {
      if (handle.hangDiscovery && req.headers.origin) return;
      const discovery = { issuer, authorization_endpoint: `${issuer}/auth`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/keys`, id_token_signing_alg_values_supported: ['RS256'] };
      return json(200, req.headers.origin ? { ...discovery, ...handle.pageDiscovery } : discovery);
    }
    if (url.pathname === '/keys') {
      return json(200, { keys: [{ ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' }] });
    }
    if (url.pathname === '/auth') {
      const code = b64url(crypto.randomBytes(16));
      codes.set(code, { challenge: url.searchParams.get('code_challenge'), clientId: url.searchParams.get('client_id'), redirectUri: url.searchParams.get('redirect_uri') });
      const back = new URL(url.searchParams.get('redirect_uri'));
      back.searchParams.set('code', code);
      back.searchParams.set('state', url.searchParams.get('state'));
      res.writeHead(302, { Location: back.href });
      return res.end();
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      if (handle.hangToken) return;
      let text = '';
      for await (const chunk of req) text += chunk;
      const form = new URLSearchParams(text);
      const pending = codes.get(form.get('code'));
      codes.delete(form.get('code'));
      const verifier = form.get('code_verifier') ?? '';
      if (pending === undefined || pending.redirectUri !== form.get('redirect_uri') || pending.challenge !== b64url(crypto.createHash('sha256').update(verifier).digest())) {
        return json(400, { error: 'invalid_grant' });
      }
      return json(200, { access_token: 'unused', token_type: 'Bearer', expires_in: 600, id_token: idToken(pending.clientId) });
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = handle.issuer = `https://localhost:${server.address().port}`;
  handle.stop = () => {
    const closed = new Promise((resolve) => server.close(resolve));
    server.closeAllConnections();
    return closed;
  };
  return handle;
}

module.exports = { startMockOIDC };
