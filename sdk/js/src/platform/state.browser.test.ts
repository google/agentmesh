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
import { openState } from "./state.browser.ts";

for (const outcome of ["commit", "abort", "abort without a reason"] as const) {
  test(`browser state write waits for transaction ${outcome}`, { timeout: 5000 }, async (t) => {
    const opened = { result: { transaction: () => transaction }, onsuccess: () => {} };
    const stored = { onsuccess: () => {} };
    let signalPut!: () => void;
    const queued = new Promise<void>((resolve) => { signalPut = resolve; });
    const failure = new DOMException("commit failed", "QuotaExceededError");
    const transaction = {
      objectStore: () => ({
        put: () => {
          signalPut();
          return stored;
        },
      }),
      error: outcome === "abort" ? failure : null,
      oncomplete: () => {},
      onabort: () => {},
    };
    Object.defineProperty(globalThis, "indexedDB", {
      configurable: true,
      value: { open: () => opened },
    });
    t.after(() => Reflect.deleteProperty(globalThis, "indexedDB"));

    let settled = false;
    const result = openState("test").write("credential", Uint8Array.of(1)).then(
      () => { settled = true; },
      (error: unknown) => {
        settled = true;
        return error;
      },
    );
    opened.onsuccess();
    await queued;
    console.log("CONTROL OK");
    stored.onsuccess();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(settled, false, "write settled before the transaction finished");
    if (outcome === "commit") {
      transaction.oncomplete();
    } else {
      transaction.onabort();
    }
    const error = await result;
    if (outcome === "abort without a reason") {
      assert.match(String(error), /IndexedDB write transaction aborted/);
    } else {
      assert.equal(error, outcome === "abort" ? failure : undefined);
    }
  });
}

test("browser state retries an unsuccessful database open", async (t) => {
  const failure = new DOMException("database temporarily unavailable", "UnknownError");
  const data = Uint8Array.of(5);
  const db = {
    transaction: () => ({
      objectStore: () => ({
        get: () => {
          const request = { result: data, onsuccess: () => {} };
          queueMicrotask(() => request.onsuccess());
          return request;
        },
      }),
    }),
  };
  let opens = 0;
  Object.defineProperty(globalThis, "indexedDB", {
    configurable: true,
    value: {
      open: () => {
        const request = { result: db, error: failure, onsuccess: () => {}, onerror: () => {} };
        opens++;
        const fail = opens === 2;
        queueMicrotask(() => {
          if (fail) {
            request.onerror();
          } else {
            request.onsuccess();
          }
        });
        return request;
      },
    },
  });
  t.after(() => Reflect.deleteProperty(globalThis, "indexedDB"));

  const working = openState("working");
  assert.deepEqual(await working.read("credential"), data);
  assert.deepEqual(await working.read("credential"), data);
  assert.equal(opens, 1);
  console.log("CONTROL OK");

  const recovering = openState("recovering");
  await assert.rejects(recovering.read("credential"), failure);
  const retried = await Promise.allSettled([
    recovering.read("credential"),
    recovering.read("credential"),
  ]);
  assert.equal(opens, 3, "database open was not retried once");
  assert.deepEqual(retried, [
    { status: "fulfilled", value: data },
    { status: "fulfilled", value: data },
  ]);
  assert.deepEqual(await recovering.read("credential"), data);
  assert.equal(opens, 3);
});
