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

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import { cp as copyDir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { credentialTimeToLiveSeconds, decodeAuthResponse } from "./credential.ts";
import {
  AuthFrameSchema,
  AuthResponseSchema,
  BootstrapEnrollResponseSchema,
  EnrollRequestSchema,
  EnrollResponseSchema,
  EnrollmentStatus,
  KeysResponseSchema,
  TokenRefreshRequestSchema,
  TokenRefreshResponseSchema,
} from "./gen/agentmesh_pb.ts";
import { Identity } from "./identity.ts";
import { AgentMesh, CredentialRetiredError, NotEnrolledError } from "./mesh.ts";

const cpKey = Identity.generate();
const text = (s: string) => new TextEncoder().encode(s);

function proto(bytes: Uint8Array): Response {
  return new Response(Buffer.from(bytes), { status: 200, headers: { "Content-Type": "application/x-protobuf" } });
}

/** A control plane that approves everything and hands out numbered biscuits. */
function fakeControlPlane(
  keysOk = true,
  opts: { strictRefresh?: boolean; refreshDelayMs?: number; rejectNextRefresh?: boolean } = {},
): { fetch: typeof fetch; issued: number; lastRefreshJwt: string; keys: Identity[]; keysOk: boolean; onKeys: (() => Promise<void>) | undefined } {
  // keys is what /keys serves and signs with; a test rotates by replacing it. onKeys runs when /keys is asked.
  const state = { issued: 0, lastRefreshJwt: "", keys: [cpKey], keysOk, onKeys: undefined as (() => Promise<void>) | undefined };
  const current = () => (state.keys[state.keys.length - 1] as Identity).publicKeyRaw;
  const signedKeys = () => {
    const unsigned = create(KeysResponseSchema, { publicKeys: state.keys.map((k) => k.publicKeyRaw), signTime: timestampFromMs(Date.now()) });
    const payload = toBinary(KeysResponseSchema, unsigned);
    return create(KeysResponseSchema, { ...unsigned, signatures: state.keys.map((k) => k.sign(payload)) });
  };
  const fetch: typeof globalThis.fetch = (async (input: Parameters<typeof globalThis.fetch>[0], init?: RequestInit) => {
    const req = new Request(input, init);
    const path = new URL(req.url).pathname;
    switch (`${req.method} ${path}`) {
      case "POST /enroll":
        state.issued++;
        return proto(
          toBinary(
            BootstrapEnrollResponseSchema,
            create(BootstrapEnrollResponseSchema, {
              status: EnrollmentStatus.APPROVED,
              biscuitToken: text(`biscuit-${state.issued}`),
              controlPlanePublicKey: current(),
              routerAddresses: ["/dns4/router.example/tcp/4001/p2p/12D3KooWP8iKhDf3iCMo2H3butNVfdTUtYwYWYQ75jTGnynXPFMp"],
              expireTime: timestampFromMs(Date.now() + 3600_000),
            }),
          ),
        );
      case "POST /refresh": {
        const refreshReq = fromBinary(TokenRefreshRequestSchema, new Uint8Array(await req.arrayBuffer()));
        if (opts.rejectNextRefresh) {
          opts.rejectNextRefresh = false;
          return new Response("control plane unavailable", { status: 503 });
        }
        if (opts.strictRefresh) {
          // The real control plane redeems only the last biscuit it issued.
          const presented = Buffer.from(req.headers.get("Authorization")?.replace(/^Bearer /, "") ?? "", "base64").toString();
          if (presented !== `biscuit-${state.issued}`) {
            return new Response(`stale biscuit ${presented}`, { status: 401 });
          }
        }
        if (opts.refreshDelayMs) {
          await new Promise((resolve) => setTimeout(resolve, opts.refreshDelayMs));
        }
        state.lastRefreshJwt = refreshReq.jwt;
        state.issued++;
        return proto(
          toBinary(
            TokenRefreshResponseSchema,
            create(TokenRefreshResponseSchema, {
              biscuitToken: text(refreshReq.jwt ? `biscuit-for-${refreshReq.jwt}` : `biscuit-${state.issued}`),
              expireTime: timestampFromMs(Date.now() + 7200_000),
            }),
          ),
        );
      }
      case "POST /register": {
        // The biscuit names the JWT that was presented, so a test can see which.
        const jwt = fromBinary(EnrollRequestSchema, new Uint8Array(await req.arrayBuffer())).jwt;
        state.issued++;
        return proto(
          toBinary(
            EnrollResponseSchema,
            create(EnrollResponseSchema, {
              biscuitToken: text(`biscuit-for-${jwt}`),
              controlPlanePublicKey: current(),
              routerAddresses: ["/dns4/router.example/tcp/4001/p2p/12D3KooWP8iKhDf3iCMo2H3butNVfdTUtYwYWYQ75jTGnynXPFMp"],
              expireTime: timestampFromMs(Date.now() + 3600_000),
            }),
          ),
        );
      }
      case "GET /keys":
        await state.onKeys?.();
        return state.keysOk ? proto(toBinary(KeysResponseSchema, signedKeys())) : new Response("boom", { status: 500 });
      default:
        return new Response(`no route for ${req.method} ${path}`, { status: 404 });
    }
  }) as typeof globalThis.fetch;
  return {
    fetch,
    get issued() {
      return state.issued;
    },
    get lastRefreshJwt() {
      return state.lastRefreshJwt;
    },
    get keys() {
      return state.keys;
    },
    set keys(keys: Identity[]) {
      state.keys = keys;
    },
    get keysOk() {
      return state.keysOk;
    },
    set keysOk(ok: boolean) {
      state.keysOk = ok;
    },
    get onKeys() {
      return state.onKeys;
    },
    set onKeys(hook: (() => Promise<void>) | undefined) {
      state.onKeys = hook;
    },
  };
}

test("refresh saves the new biscuit before it asks for /keys, so a process stopped in between can still refresh", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentmesh-sdk-"));
  try {
    const cp = fakeControlPlane(true, { strictRefresh: true });
    const stateDir = join(dir, "state");
    const stopped = join(dir, "stopped");
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, bootstrapToken: "sbt_secret", fetch: cp.fetch });
    // What a process stopped while /keys is asked leaves on disk.
    cp.onKeys = () => copyDir(stateDir, stopped, { recursive: true });
    await mesh.refresh();
    cp.onKeys = undefined;

    const restarted = await AgentMesh.load({ stateDir: stopped, fetch: cp.fetch });
    await restarted.refresh();
    assert.deepEqual(restarted.credential.biscuit, text("biscuit-3"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("enroll persists identity and credential, load resumes them, refresh rotates", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentmesh-sdk-"));
  try {
    const cp = fakeControlPlane();
    const tokenPath = join(dir, "bootstrap.token");
    await writeFile(tokenPath, "sbt_secret\n");

    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir: join(dir, "state"), bootstrapTokenPath: tokenPath, fetch: cp.fetch });
    assert.deepEqual(mesh.credential.biscuit, text("biscuit-1"));
    assert.deepEqual(mesh.credential.controlPlaneKeys, [cpKey.publicKeyRaw]);
    assert.equal(mesh.credential.routerAddresses.length, 1);
    assert.ok(credentialTimeToLiveSeconds(mesh.credential) > 3500);

    // Secrets on disk are owner-only.
    for (const f of ["identity.key", "credential.json"]) {
      assert.equal((await stat(join(dir, "state", f))).mode & 0o777, 0o600, f);
    }
    assert.equal((await stat(join(dir, "state"))).mode & 0o777, 0o700);

    const resumed = await AgentMesh.load({ stateDir: join(dir, "state"), fetch: cp.fetch });
    assert.equal(resumed.peerId, mesh.peerId);
    assert.deepEqual(resumed.credential.biscuit, text("biscuit-1"));
    assert.equal(resumed.controlPlane.url.toString(), "http://127.0.0.1:1/");

    await resumed.refresh();
    assert.deepEqual(resumed.credential.biscuit, text("biscuit-2"));
    const onDisk = JSON.parse(await readFile(join(dir, "state", "credential.json"), "utf8")) as Record<string, unknown>;
    assert.equal(Buffer.from(onDisk.biscuit as string, "base64").toString(), "biscuit-2");
    // The file is api.MemberCredential as protojson: proto field names, RFC 3339 instants.
    assert.deepEqual(Object.keys(onDisk).sort(), ["biscuit", "control_plane_url", "expire_time", "issued_under_keys", "router_addresses", "trusted_keys"]);
    assert.match(onDisk.expire_time as string, /^\d{4}-\d{2}-\d{2}T.*Z$/);

    // Enrolling again from the same directory resumes the saved credential
    // without a token; another control plane or an expiring credential
    // enrolls afresh with the same identity.
    const issuedBefore = cp.issued;
    const again = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir: join(dir, "state"), fetch: cp.fetch });
    assert.equal(again.peerId, mesh.peerId);
    assert.deepEqual(again.credential.biscuit, text("biscuit-2"));
    assert.equal(cp.issued, issuedBefore);

    await assert.rejects(AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.2:1", stateDir: join(dir, "state"), fetch: cp.fetch }), /no credential to resume/);
    const elsewhere = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.2:1", stateDir: join(dir, "state"), bootstrapToken: "sbt_secret", fetch: cp.fetch });
    assert.equal(elsewhere.peerId, mesh.peerId);
    assert.equal(cp.issued, issuedBefore + 1);
    assert.equal(elsewhere.credential.controlPlaneUrl, "http://127.0.0.2:1");

    const expiring = JSON.parse(await readFile(join(dir, "state", "credential.json"), "utf8")) as { expire_time: string };
    expiring.expire_time = new Date(Date.now() + 60_000).toISOString();
    await writeFile(join(dir, "state", "credential.json"), JSON.stringify(expiring));
    await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.2:1", stateDir: join(dir, "state"), bootstrapToken: "sbt_secret", fetch: cp.fetch });
    assert.equal(cp.issued, issuedBefore + 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("enroll resumes only a credential the control plane still vouches for", async () => {
  // A member off across a rotation comes back with a credential and a trust
  // set from before it. Within the grace period the retiring key still signs
  // /keys, so the credential is resumed and the new key adopted. Past it, the
  // control plane serves only keys the member never saw: the credential is
  // dead, and the member enrolls again with the token it has, or says so.
  const dir = await mkdtemp(join(tmpdir(), "agentmesh-sdk-"));
  try {
    const cp = fakeControlPlane();
    const stateDir = join(dir, "state");
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, bootstrapToken: "sbt_secret", fetch: cp.fetch });
    const issued = cp.issued;
    const hex = (keys: Uint8Array[]) => keys.map((k) => Buffer.from(k).toString("hex")).sort();

    // Within the grace period: resumed, both keys trusted, and persisted so.
    const rotated = Identity.generate();
    cp.keys = [cpKey, rotated];
    const within = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, fetch: cp.fetch });
    assert.deepEqual(within.credential.biscuit, mesh.credential.biscuit);
    assert.equal(cp.issued, issued);
    assert.deepEqual(hex(within.credential.controlPlaneKeys), hex([cpKey.publicKeyRaw, rotated.publicKeyRaw]));
    const onDisk = JSON.parse(await readFile(join(stateDir, "credential.json"), "utf8")) as { trusted_keys: unknown[] };
    assert.equal(onDisk.trusted_keys.length, 2);

    // The control plane cannot be reached: resumed as saved; join tries again.
    cp.keysOk = false;
    assert.deepEqual((await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, fetch: cp.fetch })).credential.biscuit, mesh.credential.biscuit);
    cp.keysOk = true;

    // Past the grace period, from the state as it was before the rotation.
    await writeFile(join(stateDir, "credential.json"), JSON.stringify({ ...onDisk, trusted_keys: [{ public_key: Buffer.from(cpKey.publicKeyRaw).toString("base64") }] }));
    cp.keys = [rotated];
    await assert.rejects(AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, fetch: cp.fetch }), CredentialRetiredError);
    const again = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, bootstrapToken: "sbt_secret", fetch: cp.fetch });
    assert.equal(again.peerId, mesh.peerId);
    assert.notDeepEqual(again.credential.biscuit, mesh.credential.biscuit);
    assert.equal(cp.issued, issued + 1);
    assert.deepEqual(hex(again.credential.controlPlaneKeys), hex([rotated.publicKeyRaw]));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("load needs both the identity and the credential", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentmesh-sdk-"));
  try {
    await assert.rejects(AgentMesh.load({ stateDir: dir }), (err: Error) => err instanceof NotEnrolledError && /no identity/.test(err.message));
    await writeFile(join(dir, "identity.key"), Identity.generate().toLibp2pPrivateKey());
    await assert.rejects(AgentMesh.load({ stateDir: dir }), (err: Error) => err.name === "NotEnrolledError" && /no credential/.test(err.message));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("forget keeps the identity when asked, so the next enroll presents the same peer", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentmesh-sdk-"));
  try {
    const cp = fakeControlPlane();
    const stateDir = join(dir, "state");
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, bootstrapToken: "sbt_secret", fetch: cp.fetch });

    await AgentMesh.forget(stateDir, { keepIdentity: true });
    await assert.rejects(AgentMesh.load({ stateDir }), NotEnrolledError);
    await assert.rejects(AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, fetch: cp.fetch }), /no credential to resume/);
    const again = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, bootstrapToken: "sbt_secret", fetch: cp.fetch });
    assert.equal(again.peerId, mesh.peerId);
    assert.equal(cp.issued, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("forget without keepIdentity removes both; forgetting an empty state directory is not an error", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentmesh-sdk-"));
  try {
    const cp = fakeControlPlane();
    const stateDir = join(dir, "state");
    await AgentMesh.forget(stateDir);
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, bootstrapToken: "sbt_secret", fetch: cp.fetch });

    await AgentMesh.forget(stateDir);
    await assert.rejects(AgentMesh.load({ stateDir }), /no identity/);
    await assert.rejects(stat(join(stateDir, "identity.key")), { code: "ENOENT" });
    await assert.rejects(stat(join(stateDir, "credential.json")), { code: "ENOENT" });
    const fresh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", stateDir, bootstrapToken: "sbt_secret", fetch: cp.fetch });
    assert.notEqual(fresh.peerId, mesh.peerId);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("enroll works without a state directory and keeps the enrollment key when /keys fails", async () => {
  const cp = fakeControlPlane(false);
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt_secret", fetch: cp.fetch });
  assert.deepEqual(mesh.credential.controlPlaneKeys, [cpKey.publicKeyRaw]);
  await mesh.save();
  await mesh.refresh();
  assert.deepEqual(mesh.credential.biscuit, text("biscuit-2"));
});

// A session refreshes on its own schedule while a pull from the control
// plane may refresh too. The control plane redeems only the last biscuit it
// issued and both write the same state file, so refreshes must run one
// after another (agentmesh-node's refreshMu, the Python SDK's lock).
test("concurrent refreshes run one after the other", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentmesh-sdk-"));
  try {
    const opts = { strictRefresh: true, refreshDelayMs: 10, rejectNextRefresh: false };
    const cp = fakeControlPlane(true, opts);
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt_secret", stateDir: join(dir, "state"), fetch: cp.fetch });

    const results = await Promise.allSettled(Array.from({ length: 8 }, () => mesh.refresh()));
    const failures = results.filter((r) => r.status === "rejected");
    assert.deepEqual(failures, []);
    assert.deepEqual(mesh.credential.biscuit, text("biscuit-9"));
    const onDisk = JSON.parse(await readFile(join(dir, "state", "credential.json"), "utf8")) as Record<string, unknown>;
    assert.equal(Buffer.from(onDisk.biscuit as string, "base64").toString(), "biscuit-9");

    // A failed refresh does not block the one queued behind it.
    opts.rejectNextRefresh = true;
    const [failed, next] = await Promise.allSettled([mesh.refresh(), mesh.refresh()]);
    assert.equal(failed?.status, "rejected");
    assert.equal(next?.status, "fulfilled");
    assert.deepEqual(mesh.credential.biscuit, text("biscuit-10"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("enroll refuses ambiguous credentials", async () => {
  const cp = fakeControlPlane();
  await assert.rejects(AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", fetch: cp.fetch }), /exactly one of/);
  await assert.rejects(AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "a", jwt: "b", fetch: cp.fetch }), /exactly one of/);
  await assert.rejects(AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", jwt: "a", jwtPath: "/nonexistent", fetch: cp.fetch }), /exactly one of/);
  assert.equal(cp.issued, 0);
});

test("enroll reads a workload identity token from jwtPath and re-reads on refresh", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agentmesh-sdk-"));
  try {
    const cp = fakeControlPlane();
    const jwtPath = join(dir, "token");
    await writeFile(jwtPath, "eyJ.projected.token.1\n");
    const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", jwtPath, fetch: cp.fetch });
    assert.deepEqual(mesh.credential.biscuit, text("biscuit-for-eyJ.projected.token.1"));

    await writeFile(jwtPath, "eyJ.projected.token.2\n");
    await mesh.refresh();
    assert.equal(cp.lastRefreshJwt, "eyJ.projected.token.2");
    assert.deepEqual(mesh.credential.biscuit, text("biscuit-for-eyJ.projected.token.2"));

    await assert.rejects(AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", jwtPath: join(dir, "missing"), fetch: cp.fetch }), /ENOENT/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("enroll accepts a jwt callback and invokes it on refresh", async () => {
  const cp = fakeControlPlane();
  let seq = 0;
  let shouldFail = false;
  const mesh = await AgentMesh.enroll({
    controlPlaneUrl: "http://127.0.0.1:1",
    jwt: async () => {
      if (shouldFail) {
        throw new Error("metadata server temporarily unavailable");
      }
      seq++;
      return `  eyJ.callback.${seq} \n`;
    },
    fetch: cp.fetch,
  });
  assert.deepEqual(mesh.credential.biscuit, text("biscuit-for-eyJ.callback.1"));

  await mesh.refresh();
  assert.equal(cp.lastRefreshJwt, "eyJ.callback.2");
  assert.deepEqual(mesh.credential.biscuit, text("biscuit-for-eyJ.callback.2"));

  // Best-effort fallback when the callback fails during refresh.
  shouldFail = true;
  await mesh.refresh();
  assert.equal(cp.lastRefreshJwt, "");
});

test("authFrame is the AuthFrame protobuf with this member's biscuit", async () => {
  const cp = fakeControlPlane();
  const mesh = await AgentMesh.enroll({ controlPlaneUrl: "http://127.0.0.1:1", bootstrapToken: "sbt_secret", fetch: cp.fetch });
  const frame = fromBinary(AuthFrameSchema, mesh.authFrame("mcp://calculator"));
  assert.deepEqual(frame.biscuit, text("biscuit-1"));
  assert.equal(frame.targetService, "mcp://calculator");

  const resp = decodeAuthResponse(toBinary(AuthResponseSchema, create(AuthResponseSchema, { success: false, error: "denied" })));
  assert.equal(resp.success, false);
  assert.equal(resp.error, "denied");
});
