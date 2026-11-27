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

// The WebMCP local relay, paired with one Agent Mesh web app: upstream's relay and
// MCP server, with every call signed by a key only this agent and the page hold.
// Bundled as one ESM file, whose banner gives its CommonJS dependencies a require (sdk/js/package.json).
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { LocalRelayMcpServer, RelayBridgeServer, parseCliOptions, type RelayBridgeServerOptions, type RelayCallToolResult, type RelayInvokeArgs } from "@mcp-b/webmcp-local-relay";
import { PAIR_TOOL, signCall, startPairing, type PairResponse } from "./pairing.ts";
import { requestToolsAfterJoin } from "./relay-join.ts";

const log = (line: string) => process.stderr.write(`[agentmesh-webapp-relay] ${line}\n`);
const failure = (text: string): RelayCallToolResult => {
  log(`refused: ${text}`);
  return { isError: true, content: [{ type: "text", text }] };
};

/** The key this agent shares with one page, in a file only its user reads. */
class KeyStore {
  readonly #dir: string;
  readonly #file: string;

  constructor(origin: string, name: string) {
    // Percent-encoding keeps distinct names distinct; "*" is the one character it keeps that Windows refuses.
    const safe = (text: string) => encodeURIComponent(text).replaceAll("*", "%2A");
    this.#dir = join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "agentmesh", "webapp-relay", safe(new URL(origin).host));
    this.#file = join(this.#dir, `${safe(name)}.json`);
  }

  async load(): Promise<{ key_id: string; key: string } | undefined> {
    try {
      return JSON.parse(await readFile(this.#file, "utf8")) as { key_id: string; key: string };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw err;
    }
  }

  async save(key: { key_id: string; key: string }): Promise<void> {
    await mkdir(this.#dir, { recursive: true, mode: 0o700 });
    // writeFile's mode applies only to a new file, so an existing one is narrowed before the key lands in it.
    await chmod(this.#file, 0o600).catch((err: NodeJS.ErrnoException) => {
      if (err.code !== "ENOENT") throw err;
    });
    await writeFile(this.#file, JSON.stringify(key), { mode: 0o600 });
    log(`paired; key ${key.key_id} saved to ${this.#file}`);
  }
}

/** Pairs on the pair tool and signs every other call, so the page can tell this agent from any other program. */
class SigningBridge extends RelayBridgeServer {
  readonly #name: string;
  readonly #keys: KeyStore;

  constructor(options: RelayBridgeServerOptions, name: string, keys: KeyStore) {
    super(options);
    this.#name = name;
    this.#keys = keys;
    // Another agent's relay can hold the port: this one then joins it, and must not miss the page's tools.
    requestToolsAfterJoin(this, log);
  }

  override async invokeTool(toolName: string, args: RelayInvokeArgs, options?: { signal?: AbortSignal }): Promise<RelayCallToolResult> {
    if (toolName === PAIR_TOOL) return this.#pair(args, options);
    const key = await this.#keys.load();
    if (key === undefined) return failure(`This relay is not paired yet. Call ${PAIR_TOOL} with the token from the Agent Mesh page's Local agent card.`);
    return super.invokeTool(toolName, await signCall(key, toolName, args), options);
  }

  async #pair(args: RelayInvokeArgs, options?: { signal?: AbortSignal }): Promise<RelayCallToolResult> {
    const token = typeof args.token === "string" ? args.token.trim() : "";
    if (token === "") return failure(`${PAIR_TOOL} needs the token from the prompt.`);
    const pairing = await startPairing(token, this.#name);
    const result = await super.invokeTool(PAIR_TOOL, { ...pairing.request }, options);
    if (result.isError) {
      log(`the page refused to pair: ${result.content.find((part) => part.type === "text")?.text ?? ""}`);
      return result;
    }
    const text = result.content.find((part) => part.type === "text")?.text ?? "";
    try {
      await this.#keys.save(await pairing.finish(JSON.parse(text) as PairResponse));
    } catch (err) {
      return failure(err instanceof Error ? err.message : String(err));
    }
    return { content: [{ type: "text", text: `Paired with the Agent Mesh page as "${this.#name}". Its tools now run as that node.` }] };
  }
}

const argv = process.argv.slice(2);
const rest: string[] = [];
let name = "";
for (let i = 0; i < argv.length; i++) {
  const arg = argv[i] ?? "";
  if (arg === "--agent-name") name = argv[++i] ?? "";
  else if (arg.startsWith("--agent-name=")) name = arg.slice("--agent-name=".length);
  else rest.push(arg);
}
name = name.trim();
const options = parseCliOptions(rest);
const origin = options.allowedOrigins.length === 1 ? options.allowedOrigins[0] : undefined;
if (name === "" || origin === undefined || origin === "*") {
  log("usage: agentmesh-webapp-relay --widget-origin <the page's origin> --agent-name <a name for this agent>");
  process.exit(2);
}

const relay = new LocalRelayMcpServer({ bridge: new SigningBridge(options, name, new KeyStore(origin, name)), serverName: "agentmesh-webapp" });
await relay.start();
await relay.startStdio();
log(`${relay.bridge.mode} mode on 127.0.0.1:${relay.bridge.port}, for ${origin} as "${name}"`);
const shutdown = () => void relay.stop().finally(() => process.exit(0));
process.stdin.on("end", shutdown);
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
