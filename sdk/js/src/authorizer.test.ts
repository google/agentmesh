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

// The provider authorizer against tokens minted the way the control plane
// mints them and policy rules rendered the way it renders them. The
// decisions here are the ones internal/node/middleware_test.go pins.

import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, test } from "node:test";
import { AuthorizationError, authorizeCaller, type AuthorizeRequest } from "./authorizer.ts";
import { BiscuitVerificationError, attenuateBiscuit, loadBiscuit, sealBiscuit } from "./biscuit.ts";
import { BASELINE_DATALOG } from "./gen/datalog.ts";

type Wasm = Awaited<ReturnType<typeof loadBiscuit>>;

let wasm: Wasm;
let cpKeyPair: InstanceType<Wasm["KeyPair"]>;
let otherKeyPair: InstanceType<Wasm["KeyPair"]>;
let cpKey: Uint8Array;

const PROVIDER = "12D3KooWProvider00000000000000000000000000000000000";
const CALLER = "12D3KooWCaller0000000000000000000000000000000000000";

function mint(facts: string[], keyPair = cpKeyPair, expiration = "2035-01-01T00:00:00Z"): Uint8Array {
  const b = wasm.Biscuit.builder();
  b.addFact(wasm.Fact.fromString(`expiration(${expiration})`));
  for (const f of facts) {
    b.addFact(wasm.Fact.fromString(f));
  }
  return b.build(keyPair.getPrivateKey()).toBytes();
}

/** A token as the control plane mints it for a node bound to peerId. */
function nodeToken(peerId: string, extra: string[] = [], keyPair = cpKeyPair): Uint8Array {
  return mint([`node(${JSON.stringify(peerId)})`, `client_peer_id(${JSON.stringify(peerId)})`, `role("sam:role:node")`, ...extra], keyPair);
}

before(async () => {
  wasm = await loadBiscuit();
  cpKeyPair = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
  otherKeyPair = new wasm.KeyPair(wasm.SignatureAlgorithm.Ed25519);
  cpKey = new Uint8Array(Buffer.from(cpKeyPair.getPublicKey().toString().replace(/^ed25519\//, ""), "hex"));
});

function options(policyRules: string[], ownBiscuit?: Uint8Array) {
  return {
    trustedKeys: () => [cpKey],
    ownBiscuit: () => ownBiscuit ?? nodeToken(PROVIDER, [`granted_service_all_types(true)`, `target_unrestricted(true)`]),
    policyRules: () => policyRules,
  };
}

function request(biscuit: Uint8Array, targetService = "mcp://calc"): AuthorizeRequest {
  return { biscuit, peerId: CALLER, targetService, protocol: "/sam/mcp/1.0.0" };
}

// The role grants the service through the mesh policy rules, exactly as the
// control plane renders them; the token itself carries only the role.
const NODE_ROLE_GRANTS = [
  `granted_service_set("mcp", ["calc"]) <- role("sam:role:node")`,
  `target_unrestricted(true) <- role("sam:role:node")`,
];

test("a role granted the service by the mesh policy is allowed", async () => {
  const verified = await authorizeCaller(request(nodeToken(CALLER)), options(NODE_ROLE_GRANTS));
  assert.equal(verified.peerId, CALLER);
  assert.deepEqual(verified.roles, ["sam:role:node"]);
});

test("grants minted into the token are enough on their own", async () => {
  const token = nodeToken(CALLER, [`granted_service_exact("mcp", "calc")`, `target_unrestricted(true)`]);
  await authorizeCaller(request(token), options([]));
});

test("the empty target is the protocol in the system namespace", async () => {
  const token = nodeToken(CALLER, [`granted_service_all("sam:system")`, `target_unrestricted(true)`]);
  await authorizeCaller(request(token, ""), options([]));
  await assert.rejects(authorizeCaller(request(token, "mcp://calc"), options([])), AuthorizationError);
});

test("a service the role was not granted is denied, and the refusal names the check", async () => {
  await assert.rejects(
    authorizeCaller(request(nodeToken(CALLER), "mcp://other"), options(NODE_ROLE_GRANTS)),
    (err: unknown) => err instanceof AuthorizationError && /FailedLogic/.test(err.message) && !/\[object Object\]/.test(err.message),
  );
});

test("a role with no grants at all is denied", async () => {
  const guest = mint([`node(${JSON.stringify(CALLER)})`, `client_peer_id(${JSON.stringify(CALLER)})`, `role("sam:role:guest")`]);
  await assert.rejects(authorizeCaller(request(guest), options(NODE_ROLE_GRANTS)), AuthorizationError);
});

test("a token presented by a peer it is not bound to is denied", async () => {
  // Minted for someone else, replayed by CALLER over CALLER's connection.
  const stolen = nodeToken("12D3KooWVictim000000000000000000000000000000000000", [`granted_service_all_types(true)`, `target_unrestricted(true)`]);
  await assert.rejects(authorizeCaller(request(stolen), options([])), AuthorizationError);
});

test("client_peer_id must match the connection peer", async () => {
  // node() binds to CALLER but client_peer_id names another peer: the replay check fails.
  const token = mint([
    `node(${JSON.stringify(CALLER)})`,
    `client_peer_id("12D3KooWSomeoneElse000000000000000000000000000000")`,
    `granted_service_all_types(true)`,
    `target_unrestricted(true)`,
  ]);
  await assert.rejects(authorizeCaller(request(token), options([])), AuthorizationError);
});

test("an expired token is denied", async () => {
  const token = mint([`node(${JSON.stringify(CALLER)})`, `client_peer_id(${JSON.stringify(CALLER)})`, `granted_service_all_types(true)`, `target_unrestricted(true)`], cpKeyPair, "2020-01-01T00:00:00Z");
  await assert.rejects(authorizeCaller(request(token), options([])), AuthorizationError);
});

test("a token under an untrusted key is denied", async () => {
  const token = nodeToken(CALLER, [`granted_service_all_types(true)`, `target_unrestricted(true)`], otherKeyPair);
  await assert.rejects(authorizeCaller(request(token), options([])), AuthorizationError);
});

test("target grants are matched against the provider's own identity", async () => {
  const provider = nodeToken(PROVIDER, [`group("backend")`]);
  const rules = [`granted_service_all_types(true) <- role("sam:role:node")`, `target_restricted(true) <- role("sam:role:node")`];
  // Granted group:backend, which the provider carries: allowed.
  await authorizeCaller(request(nodeToken(CALLER, [`granted_target_set("group", ["backend"])`])), options(rules, provider));
  // Granted group:frontend only: the provider is not an intended target.
  await assert.rejects(
    authorizeCaller(request(nodeToken(CALLER, [`granted_target_set("group", ["frontend"])`])), options(rules, provider)),
    AuthorizationError,
  );
  // No target grant and no target_unrestricted: denied.
  await assert.rejects(authorizeCaller(request(nodeToken(CALLER)), options(rules, provider)), AuthorizationError);
});

test("a grant narrowed by PolicyRole.http follows the request's method and path", async () => {
  // Rendered as the control plane renders a role with
  // http: [{service: "mcp://calc", methods: ["GET"], paths: ["/v1/*"]}]:
  // the plain grant is withheld, the narrowed facts take its place.
  const rules = [
    `http_granted_service_exact("mcp", "calc") <- role("sam:role:node")`,
    `granted_method("mcp", "calc", ["GET"]) <- role("sam:role:node")`,
    `granted_path_prefix("mcp", "calc", "/v1/") <- role("sam:role:node")`,
    `target_unrestricted(true) <- role("sam:role:node")`,
  ];
  const http = (method: string, path: string): AuthorizeRequest => ({ ...request(nodeToken(CALLER)), method, path });
  await authorizeCaller(http("GET", "/v1/models"), options(rules));
  await assert.rejects(authorizeCaller(http("POST", "/v1/models"), options(rules)), AuthorizationError);
  await assert.rejects(authorizeCaller(http("GET", "/v2/models"), options(rules)), AuthorizationError);
  // A tunnel, and a stream that carries no HTTP request: neither matches.
  await assert.rejects(authorizeCaller(http("CONNECT", ""), options(rules)), AuthorizationError);
  await assert.rejects(authorizeCaller(request(nodeToken(CALLER)), options(rules)), AuthorizationError);
});

test("every baseline item parses in biscuit-wasm", () => {
  for (const c of [BASELINE_DATALOG.time_check, BASELINE_DATALOG.replay_check, BASELINE_DATALOG.target_check]) {
    wasm.Check.fromString(c);
  }
  for (const r of [...BASELINE_DATALOG.rules, ...BASELINE_DATALOG.http_rules, ...BASELINE_DATALOG.target_fact_rules]) {
    wasm.Rule.fromString(r);
  }
  for (const p of [...BASELINE_DATALOG.policies, BASELINE_DATALOG.allow_if_true]) {
    wasm.Policy.fromString(p);
  }
});

interface TARConformanceVector {
  name: string;
  biscuit_b64: string;
  target_service: string;
  protocol: string;
  method?: string;
  path?: string;
  mcp_tool?: string;
  allow: boolean;
  expected_effective_expiration?: string;
}

const tarSuite = JSON.parse(readFileSync(new URL("../../testdata/tar_conformance.json", import.meta.url), "utf8")) as {
  public_key_b64: string;
  caller_peer_id: string;
  provider_biscuit_b64: string;
  evaluation_time: string;
  policy_datalog_rules: string[];
  vectors: TARConformanceVector[];
};

for (const vec of tarSuite.vectors) {
  test(`tar conformance: ${vec.name}`, async () => {
    const rootPub = new Uint8Array(Buffer.from(tarSuite.public_key_b64, "base64"));
    const providerBiscuit = new Uint8Array(Buffer.from(tarSuite.provider_biscuit_b64, "base64"));
    const biscuitBytes = new Uint8Array(Buffer.from(vec.biscuit_b64, "base64"));
    const evalNow = new Date(tarSuite.evaluation_time);
    const req: AuthorizeRequest = {
      biscuit: biscuitBytes,
      peerId: tarSuite.caller_peer_id,
      targetService: vec.target_service,
      protocol: vec.protocol,
      ...(vec.method !== undefined ? { method: vec.method, path: vec.path ?? "" } : {}),
      ...(vec.mcp_tool !== undefined ? { mcpTool: vec.mcp_tool } : {}),
    };
    const opts = {
      trustedKeys: () => [rootPub],
      ownBiscuit: () => providerBiscuit,
      policyRules: () => tarSuite.policy_datalog_rules,
      now: () => evalNow,
    };
    if (!vec.allow) {
      await assert.rejects(authorizeCaller(req, opts), AuthorizationError);
      return;
    }
    const verified = await authorizeCaller(req, opts);
    assert.equal(verified.peerId, tarSuite.caller_peer_id);
    if (vec.expected_effective_expiration !== undefined) {
      assert.equal(verified.expiration.getTime(), new Date(vec.expected_effective_expiration).getTime());
    }
  });
}

test("attenuateBiscuit and sealBiscuit narrow authority across hops", async () => {
  const root = nodeToken(CALLER, [`granted_service_all_types(true)`, `target_unrestricted(true)`]);
  const hop1Exp = new Date("2034-05-01T00:00:00Z");
  const hop2Exp = new Date("2034-02-01T00:00:00Z");

  const att1 = await attenuateBiscuit(
    root,
    {
      name: "hop-1",
      expireTime: timestampFromDate(hop1Exp),
      rules: [
        {
          allowedServices: ["mcp://calc"],
          operation: { allowedTools: ["add", "multiply"] },
        },
      ],
    },
    [cpKey],
  );
  const att2 = await attenuateBiscuit(
    att1,
    {
      name: "hop-2",
      expireTime: timestampFromDate(hop2Exp),
      rules: [
        {
          allowedServices: ["mcp://calc"],
          operation: { allowedTools: ["add"] },
        },
      ],
    },
    [cpKey],
  );
  const sealed = await sealBiscuit(att2, [cpKey]);

  const verified = await authorizeCaller({ ...request(sealed, "mcp://calc"), mcpTool: "add" }, options([]));
  assert.equal(verified.expiration.getTime(), hop2Exp.getTime());
  assert.equal(verified.taskRules.length, 2);

  await assert.rejects(
    authorizeCaller({ ...request(sealed, "mcp://calc"), mcpTool: "multiply" }, options([])),
    AuthorizationError,
  );
  await assert.rejects(
    attenuateBiscuit(
      sealed,
      {
        name: "hop-3",
        rules: [{ allowedServices: ["mcp://calc"] }],
      },
      [cpKey],
    ),
    BiscuitVerificationError,
  );
});

