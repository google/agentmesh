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

// WebMCP gives the web app's tools to an agent on the same computer through the
// local relay. Any program there can reach the relay, so a call runs only when a
// paired agent signed it. Built into the page's bundle only; npm does not ship it.
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod";
import type { MeshTool } from "../src/mcp-server.ts";
import type { CallVerifier, PairedAgent } from "./pairing.ts";

/** The part of document.modelContext this module uses. */
export interface ModelContext {
  registerTool(tool: {
    name: string;
    description: string;
    inputSchema: object;
    execute(input: Record<string, unknown>, options?: { signal: AbortSignal }): Promise<CallToolResult>;
  }, options: { signal: AbortSignal }): unknown;
}

/** What the page records about the calls: each one it ran, and each one it refused. */
export interface CallLog {
  called(tool: string, agent: PairedAgent, args: Record<string, unknown>): void;
  refused(tool: string, reason: string): void;
}

const failure = (text: string): CallToolResult => ({ isError: true, content: [{ type: "text", text }] });
const messageOf = (err: unknown) => (err instanceof Error ? err.message : String(err));

/** Registers the tools with modelContext until signal aborts, which also cancels their calls. */
export async function registerWebMCPTools(modelContext: ModelContext, tools: MeshTool[], verifier: CallVerifier, log: CallLog, signal: AbortSignal): Promise<void> {
  for (const tool of tools) {
    signal.throwIfAborted();
    const schema = z.object(tool.inputSchema);
    await modelContext.registerTool({
      name: tool.name,
      description: tool.description,
      // The JSON Schema the stdio server lists for the same tool.
      inputSchema: z.toJSONSchema(schema, { target: "draft-7", io: "input" }),
      // The agent cancels one call through options; signal withdraws every tool.
      async execute(input, options) {
        let call;
        try {
          call = await verifier.verify(tool.name, input);
        } catch (err) {
          log.refused(tool.name, messageOf(err));
          return failure(messageOf(err));
        }
        log.called(tool.name, call.agent, call.args);
        try {
          return await tool.run(schema.parse(call.args), { signal: options === undefined ? signal : AbortSignal.any([signal, options.signal]) });
        } catch (err) {
          return failure(messageOf(err));
        }
      },
    }, { signal });
  }
}
