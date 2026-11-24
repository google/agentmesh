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
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { openState } from "./state.ts";

test("overlapping state writes publish their own bytes", { timeout: 5000 }, async (t) => {
  const dir = await fs.mkdtemp(join(tmpdir(), "agentmesh-state-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const state = openState(dir);
  await state.write("credential", Uint8Array.of(0));
  assert.deepEqual(await state.read("credential"), Uint8Array.of(0));
  console.log("CONTROL OK");
  const rename = fs.rename;
  let signalReady!: () => void;
  let allowRename!: () => void;
  const ready = new Promise<void>((resolve) => { signalReady = resolve; });
  const release = new Promise<void>((resolve) => { allowRename = resolve; });
  let paused = false;
  const intercepted = t.mock.method(fs, "rename", async (...paths: Parameters<typeof rename>) => {
    if (!paused) {
      paused = true;
      signalReady();
      await release;
    }
    await rename(...paths);
  });
  syncBuiltinESMExports();
  t.after(() => {
    allowRename();
    intercepted.mock.restore();
    syncBuiltinESMExports();
  });

  const first = state.write("credential", Uint8Array.of(1));
  await ready;
  try {
    await openState(dir).write("credential", Uint8Array.of(2));
    assert.deepEqual(await state.read("credential"), Uint8Array.of(2));
  } finally {
    allowRename();
    await first;
  }
  assert.deepEqual(await state.read("credential"), Uint8Array.of(1));
  assert.deepEqual(await fs.readdir(dir), ["credential"]);
});

test("state write can replace an existing value with empty bytes", async (t) => {
  const dir = await fs.mkdtemp(join(tmpdir(), "agentmesh-state-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const state = openState(dir);
  await state.write("credential", Uint8Array.of(1));
  await state.write("credential", new Uint8Array());
  assert.deepEqual(await state.read("credential"), new Uint8Array());
  assert.deepEqual(await fs.readdir(dir), ["credential"]);
});

test("state write removes its temporary file if publish fails", async (t) => {
  const dir = await fs.mkdtemp(join(tmpdir(), "agentmesh-state-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  await fs.mkdir(join(dir, "credential"));
  await assert.rejects(openState(dir).write("credential", Uint8Array.of(1)));
  assert.deepEqual(await fs.readdir(dir), ["credential"]);
});
