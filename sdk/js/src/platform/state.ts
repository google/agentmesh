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

// State on Node: a directory, one file per name, owner-only, written to a
// temporary name and renamed into place. Where a token file is read from.

import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { StateStore } from "./types.ts";

/** The store for a state location: a directory, created on first write. */
export function openState(location: string): StateStore {
  return {
    async read(name) {
      try {
        return new Uint8Array(await readFile(join(location, name)));
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          return undefined;
        }
        throw err;
      }
    },
    async write(name, data) {
      await mkdir(location, { recursive: true, mode: 0o700 });
      const dir = await mkdtemp(join(location, ".write-"));
      const tmp = join(dir, "value");
      try {
        await writeFile(tmp, data, { mode: 0o600 });
        await rename(tmp, join(location, name));
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    },
    async remove(name) {
      await rm(join(location, name), { force: true });
    },
  };
}

/** A text file, for a token an operator or a platform placed on disk. */
export async function readTextFile(path: string): Promise<string> {
  return readFile(path, "utf8");
}
