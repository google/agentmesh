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
  test(`browser state write waits for transaction ${outcome}`, async (t) => {
    const opened = { result: { transaction: () => transaction }, onsuccess: () => {} };
    const stored = { onsuccess: () => {} };
    let queued = false;
    const failure = new DOMException("commit failed", "QuotaExceededError");
    const transaction = {
      objectStore: () => ({
        put: () => {
          queued = true;
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
    await Promise.resolve(); // let write queue its put request
    assert.equal(queued, true);
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
