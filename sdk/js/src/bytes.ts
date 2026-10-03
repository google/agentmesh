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

// Text encodings of bytes as the Go side reads them, for any JavaScript
// runtime. The names say which alphabet and whether the text is padded:
// a biscuit travels as padded standard base64 (Go base64.StdEncoding), a
// challenge signature as unpadded base64url (Go base64.RawURLEncoding).

import { fromString } from "uint8arrays/from-string";
import { toString } from "uint8arrays/to-string";

export function toHex(bytes: Uint8Array): string {
  return toString(bytes, "hex");
}

export function fromHex(text: string): Uint8Array {
  return fromString(text, "hex");
}

/** Padded standard base64 (RFC 4648 section 4), what Go base64.StdEncoding decodes. */
export function toBase64(bytes: Uint8Array): string {
  return toString(bytes, "base64pad");
}

export function fromBase64(text: string): Uint8Array {
  return fromString(text, "base64pad");
}

/** Unpadded base64url (RFC 4648 section 5), what Go base64.RawURLEncoding decodes. */
export function toBase64Url(bytes: Uint8Array): string {
  return toString(bytes, "base64url");
}

export function fromBase64Url(text: string): Uint8Array {
  return fromString(text, "base64url");
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
