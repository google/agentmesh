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

// Conformance runner driven by tests/integration/sdk_enroll_test.go: enrolls
// against a real control plane, refreshes, reloads from disk and reports
// what it holds as JSON on stdout for the Go side to verify. The Python SDK
// ships the same runner (python -m agent_mesh.conformance) with the same
// environment and output, so one Go test checks both.
//
//   SAM_CONTROL_PLANE_URL      base URL of the control plane
//   SAM_BOOTSTRAP_TOKEN_PATH   file holding a bootstrap token
//   SAM_SDK_STATE_DIR          directory for identity and credential
//   SAM_INSECURE_CONTROL_PLANE "1" to accept plaintext http:// off loopback

import { AgentMesh } from "./mesh.ts";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    throw new Error(`${name} is required`);
  }
  return v;
}

async function main(): Promise<void> {
  const controlPlaneUrl = requireEnv("SAM_CONTROL_PLANE_URL");
  const bootstrapTokenPath = requireEnv("SAM_BOOTSTRAP_TOKEN_PATH");
  const stateDir = requireEnv("SAM_SDK_STATE_DIR");
  const allowInsecure = process.env.SAM_INSECURE_CONTROL_PLANE === "1";

  const mesh = await AgentMesh.enroll({ controlPlaneUrl, allowInsecure, stateDir, bootstrapTokenPath, pollIntervalMs: 200 });
  const enrolled = mesh.credential;

  const reloaded = await AgentMesh.load({ allowInsecure, stateDir });
  const refreshed = await reloaded.refresh();

  process.stdout.write(
    JSON.stringify({
      sdk: "js",
      peer_id: mesh.peerId,
      public_key: hex(mesh.identity.publicKeyRaw),
      biscuit: b64(enrolled.biscuit),
      expiration: enrolled.expiration,
      control_plane_keys: enrolled.controlPlaneKeys.map(hex),
      router_addresses: enrolled.routerAddresses,
      reloaded_peer_id: reloaded.peerId,
      refreshed_biscuit: b64(refreshed.biscuit),
      refreshed_expiration: refreshed.expiration,
      auth_frame: b64(reloaded.authFrame("mcp://echo")),
    }) + "\n",
  );
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
