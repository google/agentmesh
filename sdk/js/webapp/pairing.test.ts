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
import { CALL_FIELD, CALL_WINDOW_MS, CallVerifier, answerPairing, randomToken, signCall, startPairing, type PairedAgent } from "./pairing.ts";

async function pair(name = "Claude Code"): Promise<{ relay: { key_id: string; key: string }; agent: PairedAgent }> {
  const token = randomToken();
  const pairing = await startPairing(token, name);
  const { response, agent } = await answerPairing(token, pairing.request);
  return { relay: await pairing.finish(response), agent };
}

test("pairing gives the relay and the page the same key under the page's key ID", async () => {
  const { relay, agent } = await pair("Cursor");
  assert.equal(relay.key_id, agent.key_id);
  assert.equal(relay.key, agent.key);
  assert.equal(agent.name, "Cursor");
});

test("the page refuses a pairing request made with another token", async () => {
  const pairing = await startPairing(randomToken(), "Claude Code");
  await assert.rejects(answerPairing(randomToken(), pairing.request), /pairing token is wrong, expired or already used/);
});

test("the relay refuses an answer from a page without the token", async () => {
  const pairing = await startPairing(randomToken(), "Claude Code");
  const other = randomToken();
  const { response } = await answerPairing(other, (await startPairing(other, "Claude Code")).request);
  await assert.rejects(pairing.finish(response), /did not prove it holds the pairing token/);
});

test("the page accepts a signed call once and hands back the arguments the relay signed", async () => {
  const { relay, agent } = await pair();
  const verifier = new CallVerifier(() => [agent]);
  const input = await signCall(relay, "call_remote_tool", { peer_id: "12D3KooW", tool: "add" });

  const { agent: caller, args } = await verifier.verify("call_remote_tool", input);
  assert.equal(caller.name, "Claude Code");
  assert.deepEqual(args, { peer_id: "12D3KooW", tool: "add" });
  await assert.rejects(verifier.verify("call_remote_tool", input), /replayed or delayed/);
});

test("two copies of one signed call sent together run once", async () => {
  const { relay, agent } = await pair();
  const verifier = new CallVerifier(() => [agent]);
  const input = await signCall(relay, "call_remote_tool", { peer_id: "12D3KooW", tool: "transfer" });

  const results = await Promise.allSettled([verifier.verify("call_remote_tool", input), verifier.verify("call_remote_tool", input)]);

  assert.deepEqual(results.map((result) => result.status).sort(), ["fulfilled", "rejected"]);
});

test("the page rejects calls that are unsigned, unpaired, stale, altered or aimed at another tool", async () => {
  const { relay, agent } = await pair();
  const verifier = new CallVerifier(() => [agent]);
  const signed = async () => (await signCall(relay, "get_mesh_info", { a: 1 }))[CALL_FIELD];

  await assert.rejects(verifier.verify("get_mesh_info", { a: 1 }), /only from a paired agent/);
  await assert.rejects(new CallVerifier(() => []).verify("get_mesh_info", { [CALL_FIELD]: await signed() }), /no longer paired/);
  await assert.rejects(verifier.verify("get_mesh_info", { [CALL_FIELD]: await signed() }, Date.now() + CALL_WINDOW_MS + 1_000), /replayed or delayed/);
  await assert.rejects(verifier.verify("get_mesh_info", { [CALL_FIELD]: { ...(await signed()), body: '{"a":2}' } }), /wrong signature/);
  await assert.rejects(verifier.verify("call_remote_tool", { [CALL_FIELD]: await signed() }), /wrong signature/);
});

test("a page reload does not run a call again: a new verifier refuses calls signed before it started", async () => {
  const { relay, agent } = await pair();
  const page = new CallVerifier(() => [agent]);
  const input = await signCall(relay, "call_remote_tool", { peer_id: "12D3KooW", tool: "transfer" });
  await page.verify("call_remote_tool", input);

  const reloaded = new CallVerifier(() => [agent], input[CALL_FIELD].call_unix_ms + 1);
  await assert.rejects(reloaded.verify("call_remote_tool", input), /replayed or delayed/);
});
