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

// State in a browser: an IndexedDB database per state location, one record
// per name, kept by the browser for the page's origin. A put replaces the
// record in one transaction, so a reader sees the old or the new value.

import type { StateStore } from "./types.ts";

const STORE = "state";

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB request failed"));
  });
}

function openDatabase(name: string): Promise<IDBDatabase> {
  const req = indexedDB.open(`agentmesh:${name}`, 1);
  req.onupgradeneeded = () => {
    req.result.createObjectStore(STORE);
  };
  return request(req);
}

/** The store for a state location: a database named after it. */
export function openState(location: string): StateStore {
  let db: Promise<IDBDatabase> | undefined;
  const open = () => (db ??= openDatabase(location));
  return {
    async read(name) {
      const tx = (await open()).transaction(STORE, "readonly");
      const value = await request(tx.objectStore(STORE).get(name));
      return value instanceof Uint8Array ? value : undefined;
    },
    async write(name, data) {
      const tx = (await open()).transaction(STORE, "readwrite");
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onabort = () => reject(tx.error ?? new Error("IndexedDB write transaction aborted"));
        tx.objectStore(STORE).put(new Uint8Array(data), name);
      });
    },
    async remove(name) {
      const tx = (await open()).transaction(STORE, "readwrite");
      await request(tx.objectStore(STORE).delete(name));
    },
  };
}

/** A browser has no file system a page may read; give the token itself. */
export async function readTextFile(path: string): Promise<string> {
  throw new Error(`cannot read ${path}: a browser has no files to read a token from; pass the value instead`);
}
