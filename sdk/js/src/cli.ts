#!/usr/bin/env node
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

import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { AgentMesh, type EnrollOptions } from "./mesh.ts";
import { createMeshMCPServer } from "./mcp-server.ts";
import type { MeshSession } from "./session.ts";

function options(): EnrollOptions {
  const env = process.env;
  const controlPlaneUrl = env.AGENTMESH_CONTROL_PLANE_URL?.trim();
  if (!controlPlaneUrl) throw new Error("AGENTMESH_CONTROL_PLANE_URL is required");
  if (env.AGENTMESH_BOOTSTRAP_TOKEN_PATH && env.AGENTMESH_JWT_PATH) {
    throw new Error("set only one of AGENTMESH_BOOTSTRAP_TOKEN_PATH and AGENTMESH_JWT_PATH");
  }
  if (env.AGENTMESH_INSECURE_CONTROL_PLANE && !["true", "false"].includes(env.AGENTMESH_INSECURE_CONTROL_PLANE)) {
    throw new Error("AGENTMESH_INSECURE_CONTROL_PLANE must be true or false");
  }
  // A client launches this from any working directory; a relative path would
  // silently read credentials or enrol an identity somewhere unexpected.
  for (const name of ["AGENTMESH_BOOTSTRAP_TOKEN_PATH", "AGENTMESH_JWT_PATH", "AGENTMESH_STATE_DIR"] as const) {
    if (env[name] && !isAbsolute(env[name])) throw new Error(`${name} must be an absolute path`);
  }
  return {
    controlPlaneUrl,
    bootstrapTokenPath: env.AGENTMESH_BOOTSTRAP_TOKEN_PATH || undefined,
    jwtPath: env.AGENTMESH_JWT_PATH || undefined,
    stateDir: env.AGENTMESH_STATE_DIR || join(homedir(), ".config", "agentmesh", "mcp"),
    allowInsecure: env.AGENTMESH_INSECURE_CONTROL_PLANE === "true",
  };
}

async function main(): Promise<void> {
  if (process.argv.length > 2) {
    if (process.argv.length !== 3 || !["--help", "-h"].includes(process.argv[2]!)) {
      throw new Error("agentmesh accepts no arguments other than --help; configure it through AGENTMESH_* environment variables");
    }
    console.error("agentmesh: MCP over stdio\n" +
      "AGENTMESH_CONTROL_PLANE_URL      Mesh control plane URL (required)\n" +
      "AGENTMESH_BOOTSTRAP_TOKEN_PATH   Bootstrap token file for first enrollment\n" +
      "AGENTMESH_JWT_PATH               OIDC/workload token file, read again on refresh\n" +
      "AGENTMESH_STATE_DIR              Identity directory (default: ~/.config/agentmesh/mcp)\n" +
      "AGENTMESH_INSECURE_CONTROL_PLANE  true permits plaintext HTTP beyond loopback (default: false)");
    return;
  }
  const config = options();
  const { version } = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
  const abort = new AbortController();
  let stop!: () => void;
  const stopped = new Promise<void>((resolve) => { stop = () => { abort.abort(); resolve(); }; });
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  process.stdin.once("end", stop);
  let session: MeshSession | undefined;
  const ready = AgentMesh.enroll({
    ...config,
    signal: abort.signal,
    // EnrollOptions.signal bounds pending approval, not every HTTP request.
    // The executable owns this client: shutdown must also cancel enrollment,
    // credential resume and key fetches while the control plane is silent.
    fetch: (input, init) => fetch(input, {
      ...init,
      signal: AbortSignal.any([abort.signal, ...(init?.signal ? [init.signal] : [])]),
    }),
  }).then(async (mesh) => {
    session = await mesh.join({ signal: abort.signal });
    return session;
  });
  // Handle startup failure immediately, including before a client calls a tool.
  void ready.catch((err: unknown) => {
    if (!abort.signal.aborted) {
      console.error(`agentmesh: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    stop();
  });
  const server = createMeshMCPServer(ready, version);
  server.server.onclose = stop;
  try {
    await server.connect(new StdioServerTransport());
    await stopped;
  } finally {
    stop();
    try {
      await server.close();
    } finally {
      await ready.catch(() => undefined);
      try {
        await session?.close();
      } finally {
        process.removeListener("SIGINT", stop);
        process.removeListener("SIGTERM", stop);
        process.stdin.removeListener("end", stop);
      }
    }
  }
}

void main().catch((err: unknown) => {
  console.error(`agentmesh: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
