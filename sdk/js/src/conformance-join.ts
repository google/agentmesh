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

// Mesh member driven by tests/integration/sdk_mesh_test.go: enrolls, joins
// the mesh through a real router, prints one JSON line describing the
// session, then takes JSON commands on stdin, one per line, until stdin
// closes:
//
//   {"cmd": "auth", "addr": "<multiaddr>"}  connect (through a relay when the
//                                            address says /p2p-circuit) and
//                                            run the auth handshake
//   {"cmd": "discover", "type": "mcp", "name": "calc"}
//                                            DHT lookup for a service's providers
//   {"cmd": "tools", "addr": "<multiaddr>", "service": "mcp://calc",
//    "required_labels": {"region": "eu"}}   list a provider's tools; the labels,
//                                            if given, must be on its credential
//   {"cmd": "call", "addr": "<multiaddr>", "service": "mcp://calc",
//    "tool": "add", "args": {...}, "required_labels": {...}}
//                                            call one tool
//   {"cmd": "accept", "name": "agent", "target": "<url>"}
//                                            accept A2A requests for this
//                                            member's agent; without target,
//                                            a handler in this process answers
//   {"cmd": "http", "addr": "<multiaddr>", "service": "a2a://agent",
//    "path": "/card", "method": "GET", "body": "..."}
//                                            call an HTTP service over the mesh
//   {"cmd": "peers"}                          peers that authenticated to us
//   {"cmd": "sync"}                           pull keys, bans and routers from
//                                            the control plane now
//   {"cmd": "banned"}                         peers banned by the control plane
//   {"cmd": "quit"}                           leave the mesh and exit
//
// Each command gets one JSON line back. Same environment as conformance.ts;
// the Python SDK ships the same runner (python -m agent_mesh.conformance_join).

import { createInterface } from "node:readline";
import type { ServiceType } from "./discovery.ts";
import { DEFAULT_A2A_NAME, type A2AEndpointSpec } from "./libp2p-http.ts";
import { AgentMesh } from "./mesh.ts";
import type { MeshSession } from "./session.ts";

interface Command {
  cmd?: string;
  addr?: string;
  type?: string;
  name?: string;
  service?: string;
  tool?: string;
  args?: Record<string, unknown>;
  target?: string;
  path?: string;
  method?: string;
  body?: string;
  headers?: Record<string, string>;
  required_labels?: Record<string, string>;
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    throw new Error(`${name} is required`);
  }
  return v;
}

function emit(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

/** Labels from an environment variable written "k=v,k2=v2". */
function labelsFromEnv(name: string): Record<string, string> {
  return Object.fromEntries(
    (process.env[name] ?? "")
      .split(",")
      .filter((pair) => pair.includes("="))
      .map((pair) => pair.split("=", 2) as [string, string]),
  );
}

function failure(cmd: string | undefined, err: unknown): unknown {
  return { cmd, ok: false, error: err instanceof Error ? `${err.name}: ${err.message}` : String(err) };
}

function requiredLabelsOf(command: Command): { requiredLabels?: Record<string, string> } {
  return command.required_labels !== undefined ? { requiredLabels: command.required_labels } : {};
}

async function handle(session: MeshSession, command: Command): Promise<unknown> {
  try {
    switch (command.cmd) {
      case "auth": {
        const verified = await session.authenticate(command.addr ?? "", AbortSignal.timeout(15_000));
        return {
          cmd: "auth",
          ok: true,
          peer_id: verified.peerId,
          roles: verified.roles,
          labels: verified.labels,
          expiration: Math.floor(verified.expiration.getTime() / 1000),
        };
      }
      case "discover": {
        const providers = await session.discover((command.type ?? "mcp") as ServiceType, command.name);
        return { cmd: "discover", ok: true, providers: providers.map((p) => ({ peer_id: p.peerId, addrs: p.addrs })) };
      }
      case "tools": {
        const tools = await session.listTools(command.addr ?? "", command.service ?? "", { signal: AbortSignal.timeout(15_000), ...requiredLabelsOf(command) });
        return { cmd: "tools", ok: true, tools: tools.map((t) => t.name) };
      }
      case "call": {
        const result = await session.callTool(command.addr ?? "", command.service ?? "", command.tool ?? "", command.args ?? {}, {
          signal: AbortSignal.timeout(15_000),
          ...requiredLabelsOf(command),
        });
        return { cmd: "call", ok: true, is_error: result.isError, text: result.text };
      }
      case "peers":
        return { cmd: "peers", authenticated_peers: [...session.authenticatedPeers.keys()].sort() };
      case "routers":
        return { cmd: "routers", ok: true, routers: session.routers.map((r) => r.peerId), relay_addresses: session.relayAddresses.map((ma) => ma.toString()) };
      case "sync": {
        const result = await session.sync();
        return {
          cmd: "sync",
          ok: result.errors.length === 0,
          error: result.errors.join("; "),
          keys_changed: result.keysChanged,
          refreshed: result.refreshed,
          trusted_keys: session.mesh.credential.controlPlaneKeys.map((k) => Buffer.from(k).toString("hex")),
          biscuit: Buffer.from(session.mesh.credential.biscuit).toString("base64"),
          banned: session.banned.peers(),
          router_addresses: session.mesh.credential.routerAddresses,
        };
      }
      case "banned":
        return { cmd: "banned", ok: true, banned: session.banned.peers(), authenticated_peers: [...session.authenticatedPeers.keys()].sort() };
      case "accept": {
        const spec: A2AEndpointSpec =
          command.target !== undefined
            ? { url: command.target }
            : {
                handler: (request, caller) =>
                  new Response(JSON.stringify({ sdk: "js", peer: caller.peerId, method: request.method, path: new URL(request.url).pathname }), {
                    headers: { "content-type": "application/json" },
                  }),
              };
        spec.name = command.name ?? DEFAULT_A2A_NAME;
        const service = await session.acceptA2A(spec);
        return { cmd: "accept", ok: true, service };
      }
      case "http": {
        const res = await session.request(command.addr ?? "", command.service ?? "", command.path ?? "/", {
          method: command.method ?? "GET",
          ...(command.headers !== undefined ? { headers: command.headers } : {}),
          ...(command.body !== undefined ? { body: command.body } : {}),
          signal: AbortSignal.timeout(15_000),
        });
        return { cmd: "http", ok: true, status: res.status, headers: res.headers, body: res.text() };
      }
      default:
        return failure(command.cmd, new Error(`unknown command ${JSON.stringify(command.cmd)}`));
    }
  } catch (err) {
    return failure(command.cmd, err);
  }
}

async function main(): Promise<void> {
  const controlPlaneUrl = requireEnv("SAM_CONTROL_PLANE_URL");
  const bootstrapTokenPath = requireEnv("SAM_BOOTSTRAP_TOKEN_PATH");
  const stateDir = requireEnv("SAM_SDK_STATE_DIR");
  const allowInsecure = process.env.SAM_INSECURE_CONTROL_PLANE === "1";
  const listenAddrs = (process.env.SAM_SDK_LISTEN_ADDRS ?? "").split(",").filter((a) => a !== "");
  // Labels this member declares at enrollment; the policy's allowed_labels
  // decide whether the control plane attests them. SAM_SDK_EGRESS_REQUIRE_LABELS
  // is the floor every provider this member calls must attest.
  const labels = labelsFromEnv("SAM_SDK_LABELS");
  const egressRequireLabels = labelsFromEnv("SAM_SDK_EGRESS_REQUIRE_LABELS");

  const mesh = await AgentMesh.enroll({
    controlPlaneUrl,
    allowInsecure,
    stateDir,
    bootstrapTokenPath,
    pollIntervalMs: 200,
    ...(Object.keys(labels).length > 0 ? { labels } : {}),
  });
  // The test drives every pull itself; only gossip events bring one forward.
  // SAM_SDK_ROUTERS, peer IDs, joins through those routers only, so the test
  // can put two members on different routers.
  const only = new Set((process.env.SAM_SDK_ROUTERS ?? "").split(",").filter((id) => id !== ""));
  const routerAddresses = only.size === 0 ? undefined : mesh.credential.routerAddresses.filter((a) => [...only].some((id) => a.endsWith(`/p2p/${id}`)));
  const session = await mesh.join({
    listenAddrs,
    ...(routerAddresses !== undefined ? { routerAddresses } : {}),
    ...(Object.keys(egressRequireLabels).length > 0 ? { egressRequireLabels } : {}),
    signal: AbortSignal.timeout(20_000),
    controlPlaneSyncIntervalMs: 0,
    controlPlaneSyncJitterMs: 0,
  });

  emit({
    sdk: "js",
    peer_id: session.peerId,
    routers: session.routers.map((r) => ({ peer_id: r.peerId, addr: r.addr.toString(), roles: r.credential.roles })),
    relay_addresses: session.relayAddresses.map((ma) => ma.toString()),
    direct_addresses: session.addresses.filter((ma) => !ma.toString().includes("/p2p-circuit")).map((ma) => ma.toString()),
    biscuit: Buffer.from(mesh.credential.biscuit).toString("base64"),
    trusted_keys: mesh.credential.controlPlaneKeys.map((k) => Buffer.from(k).toString("hex")),
  });

  for await (const line of createInterface({ input: process.stdin })) {
    if (line.trim() === "") {
      continue;
    }
    let command: Command;
    try {
      command = JSON.parse(line) as Command;
    } catch (err) {
      emit({ ok: false, error: `not JSON: ${err instanceof Error ? err.message : String(err)}` });
      continue;
    }
    if (command.cmd === "quit") {
      emit({ cmd: "quit", ok: true });
      break;
    }
    emit(await handle(session, command));
  }
  // Leaving must not depend on every peer closing its side promptly.
  await Promise.race([session.close(), new Promise((resolve) => setTimeout(resolve, 5_000).unref())]);
  process.exit(0);
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
