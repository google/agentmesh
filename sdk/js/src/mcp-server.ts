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

// The local MCP surface for SDK members. All remote operations use the
// session's authenticated streams and the member's own credential.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import { CallToolResultSchema, type CallToolResult, type Tool } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { BASELINE_DATALOG } from "./gen/datalog.ts";
import { AuthRejectedError } from "./auth.ts";
import { canonicalPeerId } from "./identity.ts";
import type { MeshSession, Peer } from "./session.ts";
import type { MCPSessionOptions } from "./mcp.ts";

type Session = Pick<MeshSession, "peerId" | "routers" | "isHeldRouter" | "discover" | "openMCP"> & {
  node: Pick<MeshSession["node"], "getPeers">;
};

const MAX_PROVIDERS = 64;
const MAX_SERVICES = 256;
const MAX_TOOLS = 256;
const MAX_RESULTS = 1024;
// Bounds enrollment, directory lookups and single-peer queries.
const REQUEST_TIMEOUT_MS = 10_000;
// Match agentmesh-node: each provider in a mesh-wide fan-out gets its own
// deadline, at most 8 at a time, and a slow one only costs its own row.
const PEER_TIMEOUT_MS = 5_000;
const FANOUT = 8;
// Opening a call stream is bounded like the node's dial; the call itself is
// bounded by the MCP client's cancellation, as tools may run for minutes.
const OPEN_TIMEOUT_MS = 15_000;
const CALL_TIMEOUT_MS = 30 * 60_000;
const serviceSchema = z.object({
  type: z.number().int(), name: z.string().min(1), description: z.string().optional(),
});
type Service = z.infer<typeof serviceSchema>;
type ToolRow = { peer_id: string; tool_name?: string; description?: string; error?: string };
const types: Record<string, number> = { mcp: 1, inference: 2, a2a: 3 };

function text(value: unknown): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value) }] };
}

function serviceTarget(name: string, type = "mcp"): string {
  const target = name.includes("://") ? name : `${type}://${name}`;
  if (!target.startsWith(`${type}://`) || target.slice(type.length + 3).length === 0) {
    throw new Error(`expected a ${type} service name`);
  }
  return target;
}

function toolTarget(name: string): { service: string; tool: string } {
  // Split at the first path slash: MCP tool names themselves can contain '/',
  // '?' or '#'. Only the service name is a path segment on the wire.
  const match = /^mcp:\/\/([^/?#]+)\/(.+)$/s.exec(name);
  if (!match) throw new Error("tool_name must be mcp://<service>/<tool>");
  return { service: `mcp://${match[1]}`, tool: match[2]! };
}

function requiredLabels(value: string): Record<string, string> {
  const labels: Record<string, string> = Object.create(null) as Record<string, string>;
  if (value.trim() === "") return labels;
  for (const pair of value.split(",")) {
    if (pair.trim() === "") continue;
    const parts = pair.trim().split("=");
    if (parts.length !== 2 || !parts[0]?.trim() || !parts[1]?.trim()) {
      throw new Error("required_labels must contain comma-separated key=value pairs");
    }
    const key = parts[0].trim(), val = parts[1].trim();
    // Match api.ValidateLabelKey / ValidateLabelValue and the node parser.
    if (!/^[a-zA-Z0-9_.-]{1,63}$/.test(key) || new TextEncoder().encode(val).length > 255 || /[\p{Cc}"\\]/u.test(val)) {
      throw new Error("invalid required label key or value");
    }
    if (Object.hasOwn(labels, key)) throw new Error(`duplicate required label: ${key}`);
    labels[key] = val;
  }
  if (Object.keys(labels).length === 0) throw new Error("expected at least one required label");
  return labels;
}

async function call(session: Session, peer: Peer, service: string, name: string, args: Record<string, unknown>, options: MCPSessionOptions & { signal: AbortSignal }, request: RequestOptions = { signal: options.signal }): Promise<CallToolResult> {
  const remote = await session.openMCP(peer, service, options);
  try {
    return CallToolResultSchema.parse(await remote.client.callTool({ name, arguments: args }, undefined, request));
  } finally {
    await remote.close();
  }
}

async function catalog(session: Session, peer: Peer, type: string, signal: AbortSignal): Promise<Service[]> {
  const result = await call(session, peer, `system://${BASELINE_DATALOG.catalog_target}`, "list_local_services", { type }, { signal });
  const content = result.content[0];
  if (result.isError || content?.type !== "text") throw new Error("provider refused its service catalog");
  return z.array(serviceSchema).max(MAX_SERVICES).parse(JSON.parse(content.text)).filter((s) => s.type === types[type]);
}

// Follow MCP cursors, but never accept an unbounded or looping catalog.
async function tools(session: Session, peer: Peer, service: string, signal: AbortSignal): Promise<Tool[]> {
  const remote = await session.openMCP(peer, service, { signal });
  try {
    const result: Tool[] = [];
    const cursors = new Set<string>();
    let cursor: string | undefined;
    do {
      signal.throwIfAborted();
      const page = await remote.client.listTools(cursor === undefined ? {} : { cursor }, { signal });
      result.push(...page.tools);
      if (result.length > MAX_TOOLS) throw new Error(`provider exceeds ${MAX_TOOLS} tools per service`);
      cursor = page.nextCursor;
      if (cursor !== undefined) {
        if (cursors.has(cursor) || cursors.size >= MAX_TOOLS) throw new Error("provider returned an unbounded tool catalog");
        cursors.add(cursor);
      }
    } while (cursor !== undefined);
    return result;
  } finally {
    await remote.close();
  }
}

// Do not keep a cancelled MCP request waiting for enrollment or directory lookup.
async function withSignal<T>(value: T | Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    const abort = () => { reject(signal.reason); };
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve(value).then(resolve, reject).finally(() => { signal.removeEventListener("abort", abort); });
  });
}

class ResultLimitError extends Error {
  constructor() { super("too many tools; narrow the search by peer or service"); }
}

// Runs fn for each peer, FANOUT at a time, each under its own deadline. Only
// the caller's cancellation aborts the whole fan-out.
async function fanOut<P extends Peer, R>(peers: P[], signal: AbortSignal, fn: (peer: P, signal: AbortSignal) => Promise<R>): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = [];
  let next = 0;
  const worker = async () => {
    for (let i = next++; i < peers.length; i = next++) {
      signal.throwIfAborted();
      try {
        results[i] = { status: "fulfilled", value: await fn(peers[i]!, AbortSignal.any([signal, AbortSignal.timeout(PEER_TIMEOUT_MS)])) };
      } catch (reason) {
        results[i] = { status: "rejected", reason };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(FANOUT, peers.length) }, worker));
  signal.throwIfAborted();
  return results;
}

/** The same five caller tools as agentmesh-node; an SDK member hosts no services. */
export function createMeshMCPServer(ready: Session | Promise<Session>, version: string): McpServer {
  const server = new McpServer({ name: "agentmesh", version }, { instructions:
    "Use find_remote_tools, then describe_remote_tool to learn the input schema, then call_remote_tool. " +
    "Calls use this SDK member's identity and mesh policy. This stdio server exposes no local HTTP proxy, inference endpoint or hosted services.",
  });

  server.registerTool("get_mesh_info", { description: "Get information about the mesh network", inputSchema: {} }, async (_args, extra) => {
    const signal = AbortSignal.any([extra.signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]);
    const s = await withSignal(ready, signal);
    const routers = s.routers.filter((r) => s.isHeldRouter(r.peerId)).map((r) => r.peerId).sort();
    return text({ peer_id: s.peerId, connected_peers: s.node.getPeers().map((p) => p.toString()).sort(), attached_routers: routers, router_peer_id: routers[0] ?? "" });
  });

  server.registerTool("discover_remote_services", {
    description: "Discover remote services by type and optional name. Returns peer_id, srv_name and srv_description. This SDK member has no local_proxy_url; inference and A2A services require an SDK client or an agentmesh-node HTTP proxy.",
    inputSchema: {
      type: z.string().describe("Required. One of: mcp, inference, a2a."),
      name: z.string().optional().describe("Optional service name. Omit to list all services of the given type."),
      limit: z.number().int().optional().describe("Optional limit for pagination. Defaults to 20."),
      offset: z.number().int().optional().describe("Optional offset for pagination. Defaults to 0."),
    },
  }, async (args, extra) => {
    const setup = AbortSignal.any([extra.signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]);
    const s = await withSignal(ready, setup);
    const type = args.type.toLowerCase();
    if (types[type] === undefined) throw new Error("type must be mcp, inference or a2a");
    const name = args.name ? serviceTarget(args.name, type).slice(type.length + 3) : undefined;
    const peers = await withSignal(s.discover(type, name, { limit: MAX_PROVIDERS }), setup);
    const rows: { peer_id: string; srv_name: string; srv_description: string }[] = [];
    if (name !== undefined) {
      // As in agentmesh-node, a named lookup is answered by the directory
      // alone; no provider is contacted, so none can fail or stall it.
      for (const peer of peers) rows.push({ peer_id: peer.peerId, srv_name: `${type}://${name}`, srv_description: "" });
    } else {
      // A provider that fails or stalls is dropped, as in agentmesh-node.
      const catalogs = await fanOut(peers, extra.signal, (peer, signal) => catalog(s, peer, type, signal));
      catalogs.forEach((result, i) => {
        if (result.status === "rejected") {
          console.error(`agentmesh: catalog from ${peers[i]!.peerId} failed: ${JSON.stringify(String(result.reason))}`);
          return;
        }
        for (const svc of result.value) {
          rows.push({ peer_id: peers[i]!.peerId, srv_name: serviceTarget(svc.name, type), srv_description: svc.description ?? "" });
          if (rows.length > MAX_RESULTS) throw new Error("too many services; narrow the discovery by name");
        }
      });
    }
    rows.sort((a, b) => a.peer_id.localeCompare(b.peer_id) || a.srv_name.localeCompare(b.srv_name));
    const offset = Math.max(0, args.offset ?? 0), limit = (args.limit ?? 0) > 0 ? args.limit! : 20;
    return text(rows.slice(offset, offset + limit));
  });

  server.registerTool("find_remote_tools", {
    description: "Discover MCP tools available on hosted services across the mesh. Optionally narrow by peer_id, service_name, or exact tool_name. intent is accepted but ignored, as in agentmesh-node.",
    inputSchema: {
      intent: z.string().optional().describe("Natural-language description of what the caller is looking for. Reserved for future semantic ranking; currently accepted but ignored."),
      peer_id: z.string().optional().describe("Restrict the search to a single peer. Empty means search the whole mesh."),
      service_name: z.string().optional().describe("Restrict results to tools whose name starts with this service prefix (e.g. 'code-reviewer'). Empty means no service filter."),
      tool_name: z.string().optional().describe("Exact (non-namespaced) tool name to locate across the mesh, e.g. 'review_pr'. Empty means list all tools."),
    },
  }, async (args, extra) => {
    const setup = AbortSignal.any([extra.signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]);
    const s = await withSignal(ready, setup);
    const filter = args.service_name ? serviceTarget(args.service_name) : undefined;
    const peerId = args.peer_id ? canonicalPeerId(args.peer_id) : undefined;
    if (peerId === s.peerId) throw new Error("cross-mesh discovery cannot target self");
    const peers = peerId ? [{ peerId, addrs: [] }] : await withSignal(s.discover("mcp", undefined, { limit: MAX_PROVIDERS }), setup);
    const rows: ToolRow[] = [];
    const append = (row: ToolRow) => {
      if (rows.length >= MAX_RESULTS) throw new ResultLimitError();
      rows.push(row);
    };
    const results = await fanOut(peers, extra.signal, async (peer, signal) => {
      const found: ToolRow[] = [];
      for (const svc of await catalog(s, peer, "mcp", signal)) {
        const target = serviceTarget(svc.name);
        if (filter !== undefined && target !== filter) continue;
        try {
          for (const tool of await tools(s, peer, target, signal)) {
            if (!args.tool_name || tool.name === args.tool_name) {
              found.push({ peer_id: peer.peerId, tool_name: `${target}/${tool.name}`, description: tool.description ?? "" });
              if (found.length > MAX_RESULTS) throw new ResultLimitError();
            }
          }
        } catch (err) {
          // The peer's deadline ends the peer, not just this service.
          signal.throwIfAborted();
          if (err instanceof ResultLimitError) throw err;
          if (err instanceof AuthRejectedError) console.error(`agentmesh: discovery refused: ${JSON.stringify(err.message)}`);
          else found.push({ peer_id: peer.peerId, tool_name: target, error: String(err) });
        }
      }
      return found;
    });
    results.forEach((result, i) => {
      if (result.status === "fulfilled") {
        result.value.forEach(append);
        return;
      }
      const err: unknown = result.reason;
      if (err instanceof ResultLimitError) throw err;
      if (peerId !== undefined) throw err;
      if (err instanceof AuthRejectedError) console.error(`agentmesh: discovery refused: ${JSON.stringify(err.message)}`);
      else append({ peer_id: peers[i]!.peerId, error: String(err) });
    });
    return text(rows.filter((row) => !args.tool_name || !row.error).sort((a, b) => a.peer_id.localeCompare(b.peer_id) || (a.tool_name ?? "").localeCompare(b.tool_name ?? "")));
  });

  server.registerTool("describe_remote_tool", {
    description: "Return the description, input schema, and output schema for a specific MCP tool on a specific peer.",
    inputSchema: {
      peer_id: z.string().describe("Peer ID of the node hosting the server. Required."),
      tool_name: z.string().describe("Namespaced server name as returned by find_remote_tools (e.g. 'mcp://code-reviewer/review_pr'). Required."),
    },
  }, async (args, extra) => {
    const signal = AbortSignal.any([extra.signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]);
    const s = await withSignal(ready, signal), peer = canonicalPeerId(args.peer_id), target = toolTarget(args.tool_name);
    const tool = (await tools(s, peer, target.service, signal)).find((t) => t.name === target.tool);
    if (tool === undefined) throw new Error("tool not found on peer");
    return text({ peer_id: peer, tool_name: args.tool_name, description: tool.description ?? "", input_schema: tool.inputSchema, ...(tool.outputSchema ? { output_schema: tool.outputSchema } : {}) });
  });

  server.registerTool("call_remote_tool", {
    description: "Call an MCP tool on a remote agent",
    inputSchema: {
      peer_id: z.string().describe("The Peer ID of the target agent"),
      tool_name: z.string().describe("The name of the server to call"),
      arguments: z.record(z.string(), z.unknown()).optional().describe("Server arguments as a JSON object whose keys match the target server's input_schema. Call describe_remote_tool first to learn the schema."),
      required_labels: z.string().optional().describe("Comma-separated key=value pairs (e.g. 'region=us-east-1,team=platform'). Fails closed: the call is rejected unless the peer attests every one of them. Empty means no requirement."),
    },
  }, async (args, extra) => {
    const s = await withSignal(ready, AbortSignal.any([extra.signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]));
    const peer = canonicalPeerId(args.peer_id), target = toolTarget(args.tool_name);
    const open = AbortSignal.any([extra.signal, AbortSignal.timeout(OPEN_TIMEOUT_MS)]);
    return call(s, peer, target.service, target.tool, args.arguments ?? {}, { signal: open, requiredLabels: requiredLabels(args.required_labels ?? "") },
      { signal: extra.signal, timeout: CALL_TIMEOUT_MS, resetTimeoutOnProgress: true });
  });
  return server;
}
