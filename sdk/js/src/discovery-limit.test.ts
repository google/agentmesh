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
import { findProviders } from "./discovery.ts";

test("directory validates the provider limit before contacting routers", async () => {
  const key = new Uint8Array();
  assert.deepEqual(await findProviders([], key, 0), []);
  await assert.rejects(findProviders([], key, -1), RangeError);
  await assert.rejects(findProviders([], key, 0.5), RangeError);
  await assert.rejects(findProviders([], key, 0xffffffff + 1), RangeError);
  await assert.rejects(findProviders([], key, Number.NaN), RangeError);
});

test("directory rejects an already aborted provider lookup", async () => {
  const reason = new Error("caller gave up");
  await assert.rejects(findProviders([], new Uint8Array(), 0, AbortSignal.abort(reason)), reason);
});
