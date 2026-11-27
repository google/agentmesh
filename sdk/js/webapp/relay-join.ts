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

// A workaround for a defect of @mcp-b/webmcp-local-relay 6.2.0 in client mode.
// It is apart from relay.ts, which starts a relay when it loads, so that a test can import it.
import type { RelayBridgeServer } from "@mcp-b/webmcp-local-relay";

/** The part of the relay's client mode that the workaround wraps. Upstream declares it private. */
interface ClientMode {
  setupClientHandlers(socket: { send(data: string): void }, buffered?: unknown[]): void;
}

/**
 * Makes bridge ask for the tool list again each time it joins another relay.
 *
 * A relay that finds its port held by another relay joins that relay in
 * client mode. It sends relay/hello and relay/list-tools, waits for the first
 * message of the server, and only then attaches the listener that handles the
 * messages. The server sends its hello first. When the hello and the tool
 * list arrive in one read, the tool list comes while no listener is attached
 * and is lost: the relay offers no tool of the page until the page changes
 * its tools. A relay on a loaded machine reads the two together.
 *
 * The request that this function adds goes out after the listener is
 * attached, so its answer is not lost. A second copy of the list does no
 * harm: it replaces the first one.
 */
export function requestToolsAfterJoin(bridge: RelayBridgeServer, log: (line: string) => void): void {
  const client = bridge as unknown as ClientMode;
  const setup = client.setupClientHandlers;
  if (typeof setup !== "function") {
    // A silent no-op here would bring the defect back with the next version of the relay.
    throw new Error("@mcp-b/webmcp-local-relay has no setupClientHandlers: its client mode changed, review requestToolsAfterJoin");
  }
  client.setupClientHandlers = function (this: ClientMode, socket, buffered) {
    setup.call(this, socket, buffered);
    try {
      socket.send(JSON.stringify({ type: "relay/list-tools" }));
    } catch (err) {
      // The relay reconnects when its socket closes, and that join asks again.
      log(`could not ask the relay it joined for its tool list: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
}
