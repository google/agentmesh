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

// What differs between Node and a browser, as the rest of the SDK sees it.
// Each concern has a Node module and a .browser.ts twin with the same
// exports; package.json's "browser" field points a bundler at the twin.

/** Where a member keeps its identity and credential between runs. */
export interface StateStore {
  /** The bytes under a name, or undefined when nothing was written yet. */
  read(name: string): Promise<Uint8Array | undefined>;
  /** Writes the bytes under a name so that a reader sees the old or the new value, never a mix. */
  write(name: string, data: Uint8Array): Promise<void>;
  /** Deletes the bytes under a name; deleting a name never written is not an error. */
  remove(name: string): Promise<void>;
}
