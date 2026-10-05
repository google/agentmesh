---
title: "Native SDKs"
linkTitle: "Native SDKs"
weight: 6
---

An agent written in JavaScript or Python can be a member of the mesh itself,
with no `sam-node` beside it. The SDK enrolls with the control plane, joins
through a router, finds services, calls MCP tools and inference or A2A
endpoints, and answers A2A requests for the agent itself. Every caller of
the agent is checked against the mesh policy before anything reaches your
code.

This guide takes you from nothing to two programs on a mesh: an agent that
other members can call, and a caller that reaches a service by name and the
agent by its peer ID. Both programs are in the repository under
[`sdk/js/examples`](https://github.com/google/sam/tree/main/sdk/js/examples)
and
[`sdk/python/examples`](https://github.com/google/sam/tree/main/sdk/python/examples),
and the repository's tests run them against a real mesh, so what you read
here is what runs.

An SDK member calls what the mesh offers and accepts A2A requests for its
own agent. It does not publish services. A tool, a model or an agent that
others should find by name runs behind a `sam-node`, which publishes it and
enforces the policy; see [Your own mesh](../../getting-started/your-own-mesh/).
The reasons are in the
[SDK README](https://github.com/google/sam/blob/main/sdk/README.md#agents-not-services).

## 1. Get a mesh

A program needs the URL of a control plane and a token that lets it enroll.
You get them in one of two ways.

### Run your own

`sam-one` runs a control plane, a router and a web console in one process.
The [install script](../../getting-started/quickstart/#1-install) provides
it. Start it with a directory for its state:

```bash
sam-one --data-dir ~/sam-one
```

The banner it prints has the URL, and the token is written to
`~/sam-one/join-token`:

```text
API URL:      http://0.0.0.0:33775
Join Token:   sam_tok_…
```

On first boot `sam-one` seeds an open development policy, so any enrolled
member may publish and call any service. That is right for trying the
programs below on your laptop. Before you share the mesh, replace it, as
[Your own mesh](../../getting-started/your-own-mesh/#5-before-you-share-it)
explains.

This mesh is reachable from your machine only. To let programs on other
machines join, start `sam-one` with `--tunnel cloudflare`, which publishes
the port on a temporary public `https` hostname and prints that URL in the
banner instead. Use that URL as the control plane URL everywhere below. [Your
own mesh](../../getting-started/your-own-mesh/) covers the tunnel, a real
hostname and the console.

### Join a mesh someone else runs

Ask the operator for the control plane URL and a bootstrap token. Operators
mint tokens in the console or with `sam-one token create`; a mesh with an
identity provider lets you mint your own from the console after logging in.
Save the token in a file that only you can read. Do not put it on a command
line: it would sit in `ps` output and shell history.

### Tell the programs about it

The programs below read the mesh from two environment variables. Set them in
every terminal you use:

```bash
export SAM_CONTROL_PLANE_URL=http://127.0.0.1:33775   # the API URL from the banner
export SAM_BOOTSTRAP_TOKEN_PATH=~/sam-one/join-token
```

A plain `http://` URL is accepted only for a control plane on the same
machine. Anything else needs `https://`, because the control plane is the
trust root of every member and the SDK refuses to fetch it over plaintext
from a remote address. Inside a network you already trust, such as a
Kubernetes cluster where the control plane is a cluster-local service, set
`SAM_INSECURE_CONTROL_PLANE=true` (`allowInsecure` in code), the same choice
as `sam-node --insecure-control-plane`.

On a platform that issues workload identity tokens, a program needs no
bootstrap token. A mesh whose control plane trusts the platform's issuer
enrolls the program from that token instead; on Kubernetes that is a
projected service account token, as [Headless enrollment](../headless-enrollment/)
shows for `sam-node`. Set `SAM_JWT_PATH` (`jwtPath` / `jwt_path`) to the
token file rather than `SAM_BOOTSTRAP_TOKEN_PATH`, or pass a `jwt` callback
(`() => string | Promise<string>` in JS, `Callable[[], str]` in Python) that
fetches a fresh token (for example, from a cloud metadata server). On every
credential refresh, the SDK re-reads `jwtPath` or invokes the `jwt` callback
and sends the fresh token in `TokenRefreshRequest.jwt` so the control plane
re-attests the member in place. That is how the public testnets run these
same programs as canaries beside the `sam-node` ones.

## 2. Install the SDK

```bash
npm install @sam-mesh/sdk          # Node.js 22 or later
```

```bash
pip install sam-mesh               # Python 3.11 or later
```

The Python package is imported as `agent_mesh`. It runs on trio, because
py-libp2p does; under asyncio, use it through `anyio` with the trio backend.

The JS package also runs in a browser page; see
[In a browser](#in-a-browser) below.

## 3. Be an agent

This program joins the mesh and answers A2A requests for `a2a://agent`
until you stop it. It publishes nothing: there is no name to look up. A
caller reaches it by the peer ID it prints, through a router. Without an
argument the handler in the program answers; with the URL of an A2A server
running beside it, requests are forwarded there, which is how an agent
written with an A2A SDK joins the mesh.

JavaScript, `agent.js`:

<!-- embed: sdk/js/examples/agent.ts -->
```ts
// An agent on the mesh: joins, then answers A2A requests from other members
// until stopped. It publishes nothing. There is no service name to look up; a
// caller reaches the agent by its peer ID, through a router, as a2a://agent.
// The mesh policy decides which members may call; the SDK turns the others
// away before anything reaches this code.
//
//   node agent.js                        # answered by the handler below
//   node agent.js http://127.0.0.1:9999  # forwarded to an A2A server beside it
//
// SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
// SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or
// SAM_JWT_PATH (a workload identity token your platform issues, such as a
// Kubernetes projected service account token), and keeps the identity and
// credential in SAM_STATE_DIR; later runs resume from there, as the same
// peer, without it.
import { homedir } from "node:os";
import { AgentMesh } from "@sam-mesh/sdk";

const [backendURL] = process.argv.slice(2);

const mesh = await AgentMesh.enroll({
  controlPlaneUrl: process.env.SAM_CONTROL_PLANE_URL ?? "https://mesh.example.com",
  bootstrapTokenPath: process.env.SAM_BOOTSTRAP_TOKEN_PATH,
  jwtPath: process.env.SAM_JWT_PATH,
  stateDir: process.env.SAM_STATE_DIR ?? `${homedir()}/.config/sam-mesh/agent`,
  // A plaintext http:// control plane is otherwise accepted only on loopback.
  allowInsecure: process.env.SAM_INSECURE_CONTROL_PLANE === "true",
});
const session = await mesh.join();

// Answers every path with who was asked and who asked; a real agent runs an
// A2A server here, or beside this process at backendURL.
const target = await session.acceptA2A(
  backendURL !== undefined
    ? { url: backendURL }
    : { handler: (request, caller) => Response.json({ name: "agent", path: new URL(request.url).pathname, caller: caller.peerId }) },
);
console.log(`accepting ${target} as ${session.peerId}`);

const stop = () => void session.close().then(() => process.exit(0));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
```
<!-- /embed -->

Python, `agent.py`:

<!-- embed: sdk/python/examples/agent.py -->
```python
"""An agent on the mesh: joins, then answers A2A requests from other members
until stopped. It publishes nothing. There is no service name to look up; a
caller reaches the agent by its peer ID, through a router, as `a2a://agent`.
The mesh policy decides which members may call; the SDK turns the others away
before anything reaches this code.

    python agent.py                        # answered by the handler below
    python agent.py http://127.0.0.1:9999  # forwarded to an A2A server beside it

SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or SAM_JWT_PATH
(a workload identity token your platform issues, such as a Kubernetes
projected service account token), and keeps the identity and credential in
SAM_STATE_DIR; later runs resume from there, as the same peer, without it.
"""

import json
import os
import sys

import trio
from agent_mesh import AgentMesh, HTTPRequest, HTTPResponse, VerifiedBiscuit

backend_url = sys.argv[1] if len(sys.argv) > 1 else None

mesh = AgentMesh.enroll(
    os.environ.get("SAM_CONTROL_PLANE_URL", "https://mesh.example.com"),
    bootstrap_token_path=os.environ.get("SAM_BOOTSTRAP_TOKEN_PATH"),
    jwt_path=os.environ.get("SAM_JWT_PATH"),
    state_dir=os.environ.get("SAM_STATE_DIR", "~/.config/sam-mesh/agent"),
    # A plaintext http:// control plane is otherwise accepted only on loopback.
    allow_insecure=os.environ.get("SAM_INSECURE_CONTROL_PLANE") == "true",
)


async def card(request: HTTPRequest, caller: VerifiedBiscuit) -> HTTPResponse:
    """Answers every path with who was asked and who asked; a real agent runs
    an A2A server here, or beside this process at backend_url."""
    body = json.dumps({"name": "agent", "path": request.path, "caller": caller.peer_id})
    return HTTPResponse(status=200, headers={"content-type": "application/json"}, body=body.encode())


async def main() -> None:
    async with mesh.join() as session:
        target = await session.accept_a2a(backend_url or card)
        print(f"accepting {target} as {session.peer_id}", flush=True)
        await trio.sleep_forever()


trio.run(main)
```
<!-- /embed -->

Run one of them:

```bash
node agent.js
# or
python agent.py
```

```text
accepting a2a://agent as 12D3KooWQmB5…
```

The program spent the token, saved its identity and credential under
`~/.config/sam-mesh/agent`, joined through the router and started answering.
Run it again and it resumes from that directory, as the same peer; the token
is no longer needed. Keep the peer ID: it is how the agent is reached, from
another program written with an SDK, a `sam-node` on any machine, or a
phone.

## 4. Call it

This program calls something on the mesh: a tool or a path of a service
someone published, found by name, or an agent that published nothing,
reached by its peer ID.

JavaScript, `call.js`:

<!-- embed: sdk/js/examples/call.ts -->
```ts
// Calls something on the mesh: a tool of an MCP service or a path of an
// inference or A2A service someone published, found by name, or an agent that
// published nothing, reached by its peer ID.
//
//   node call.js mcp://everything echo '{"message": "hi"}'
//   node call.js inference://ollama /v1/models
//   node call.js 12D3KooW... a2a://agent /card
//
// SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
// SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or
// SAM_JWT_PATH (a workload identity token your platform issues, such as a
// Kubernetes projected service account token), and keeps the identity and
// credential in SAM_STATE_DIR; later runs resume from there without it.
import { homedir } from "node:os";
import { AgentMesh, type DiscoveredProvider } from "@sam-mesh/sdk";

let argv = process.argv.slice(2);
// A first argument that is not a service target is the peer ID of an agent.
let peerId: string | undefined;
if (argv[0] !== undefined && !argv[0].includes("://")) {
  [peerId, ...argv] = argv as [string, ...string[]];
}
const [service = peerId !== undefined ? "a2a://agent" : "mcp://everything", toolOrPath = peerId !== undefined ? "/card" : "echo", args = '{"message": "hi"}'] = argv;

const mesh = await AgentMesh.enroll({
  controlPlaneUrl: process.env.SAM_CONTROL_PLANE_URL ?? "https://mesh.example.com",
  bootstrapTokenPath: process.env.SAM_BOOTSTRAP_TOKEN_PATH,
  jwtPath: process.env.SAM_JWT_PATH,
  stateDir: process.env.SAM_STATE_DIR ?? `${homedir()}/.config/sam-mesh/caller`,
  // A plaintext http:// control plane is otherwise accepted only on loopback.
  allowInsecure: process.env.SAM_INSECURE_CONTROL_PLANE === "true",
});
const session = await mesh.join();
console.log(`on the mesh as ${session.peerId}`);

// The peer to call: an agent named by ID, or a provider of a published service.
let provider: DiscoveredProvider = { peerId: peerId ?? "", addrs: [] };
if (peerId !== undefined) {
  // An agent is not in the discovery table; the SDK finds the path to its
  // peer ID through the routers.
  await session.connect(peerId);
} else {
  const providers = await session.discover(service);
  if (providers.length === 0) {
    throw new Error(`no member of the mesh serves ${service}`);
  }
  // A provider record can outlive its member; the first that answers is used.
  let reached = false;
  for (const candidate of providers) {
    try {
      await session.connect(candidate);
      provider = candidate;
      reached = true;
      break;
    } catch (err) {
      console.error(`${candidate.peerId}: ${(err as Error).message}`);
    }
  }
  if (!reached) {
    throw new Error(`no provider of ${service} is reachable`);
  }
}
console.log(`${service} is served by ${provider.peerId}`);

if (service.startsWith("mcp://")) {
  const tools = await session.listTools(provider, service);
  console.log(`tools: ${tools.map((t) => t.name).join(", ")}`);
  const result = await session.callTool(provider, service, toolOrPath, JSON.parse(args));
  console.log(result.text.join("\n"));
} else {
  const response = await session.request(provider, service, toolOrPath);
  console.log(response.status, response.text());
}

await session.close();
```
<!-- /embed -->

Python, `call.py`:

<!-- embed: sdk/python/examples/call.py -->
```python
"""Calls something on the mesh: a tool of an MCP service or a path of an
inference or A2A service someone published, found by name, or an agent that
published nothing, reached by its peer ID.

    python call.py mcp://everything echo '{"message": "hi"}'
    python call.py inference://ollama /v1/models
    python call.py 12D3KooW... a2a://agent /card

SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or SAM_JWT_PATH
(a workload identity token your platform issues, such as a Kubernetes
projected service account token), and keeps the identity and credential in
SAM_STATE_DIR; later runs resume from there without it.
"""

import json
import os
import sys

import trio
from agent_mesh import AgentMesh

argv = sys.argv[1:]
# A first argument that is not a service target is the peer ID of an agent.
peer_id = None
if argv and "://" not in argv[0]:
    peer_id, argv = argv[0], argv[1:]
service = argv[0] if len(argv) > 0 else ("a2a://agent" if peer_id else "mcp://everything")
tool_or_path = argv[1] if len(argv) > 1 else ("/card" if peer_id else "echo")
args = json.loads(argv[2]) if len(argv) > 2 else {"message": "hi"}

mesh = AgentMesh.enroll(
    os.environ.get("SAM_CONTROL_PLANE_URL", "https://mesh.example.com"),
    bootstrap_token_path=os.environ.get("SAM_BOOTSTRAP_TOKEN_PATH"),
    jwt_path=os.environ.get("SAM_JWT_PATH"),
    state_dir=os.environ.get("SAM_STATE_DIR", "~/.config/sam-mesh/caller"),
    # A plaintext http:// control plane is otherwise accepted only on loopback.
    allow_insecure=os.environ.get("SAM_INSECURE_CONTROL_PLANE") == "true",
)


async def main() -> None:
    async with mesh.join() as session:
        print(f"on the mesh as {session.peer_id}")

        if peer_id:
            # An agent is not in the discovery table; the SDK finds the path
            # to its peer ID through the routers.
            await session.connect(peer_id)
            provider = peer_id
        else:
            providers = await session.discover(service)
            if not providers:
                raise SystemExit(f"no member of the mesh serves {service}")
            # A provider record can outlive its member; the first that answers is used.
            for provider in providers:
                try:
                    await session.connect(provider)
                    break
                except (ConnectionError, PermissionError) as err:
                    print(f"{provider.peer_id}: {err}", file=sys.stderr)
            else:
                raise SystemExit(f"no provider of {service} is reachable")
        print(f"{service} is served by {peer_id or provider.peer_id}")

        if service.startswith("mcp://"):
            tools = await session.list_tools(provider, service)
            print("tools:", ", ".join(t.name for t in tools))
            result = await session.call_tool(provider, service, tool_or_path, args)
            print("\n".join(result.text))
        else:
            response = await session.request(provider, service, tool_or_path)
            print(response.status, response.text)


trio.run(main)
```
<!-- /embed -->

In a second terminal, with the same two environment variables set, call the
agent by the peer ID it printed. Either language reaches an agent written
with the other:

```bash
python call.py 12D3KooWQmB5… a2a://agent /card
```

```text
on the mesh as 12D3KooWHZ2M…
a2a://agent is served by 12D3KooWQmB5…
200 {"name": "agent", "path": "/card", "caller": "12D3KooWHZ2M…"}
```

A service a `sam-node` publishes is found by name instead. On a mesh with
the `everything` canary of the public testnets, or your own `sam-node` with
an MCP server behind it:

```bash
node call.js mcp://everything echo '{"message": "hi"}'
```

```text
on the mesh as 12D3KooWHZ2M…
mcp://everything is served by 12D3KooWAb3d…
tools: echo, add, …
Echo: hi
```

The caller and the agent are two identities on the mesh with their own
state directories, `caller` and `agent`. Each spent a token on its first
run; the standing join token of `sam-one` admits any number of members.

## 5. Agents that speak A2A

The two programs above answer and call HTTP paths by hand. An agent you
write with an [A2A SDK](https://a2a-protocol.org/) speaks the protocol:
an agent card, `message/send`, tasks, streaming. It joins the mesh the same
way, and needs to know two things: the URL it has on the mesh, and how to
plug the mesh in as its transport.

- An agent on the mesh has the URL `http://mesh/sam/<peer-id>/a2a/agent`
  (`MeshSession.meshURL(peerId, "a2a://agent")`,
  `MeshSession.mesh_url(peer_id, "a2a://agent")`). That is what goes in its
  agent card, and what an A2A client on the mesh is given. The peer ID is in
  the path because URL parsers lowercase the host and a peer ID is
  case-sensitive.
- An agent behind a `sam-node` serves a card naming its own address. The
  SDK hands the client that card rewritten for the mesh, as `sam-node`'s
  egress proxy does, so a stock A2A client given the mesh URL bootstraps
  from it unchanged.
- The A2A JavaScript SDK takes a `fetch` for its client and mounts its server
  as Express handlers. `session.fetch()` is the fetch;
  `acceptA2A({ listener: app })` runs the Express app on the mesh, with
  nothing listening on a port.
- The A2A Python SDK takes an `httpx.AsyncClient` for its client and runs its
  server as a Starlette app. `httpx.AsyncClient(transport=MeshTransport(session))`
  is the client; the server runs under uvicorn on a loopback port, in a
  thread since the A2A SDK is asyncio and the mesh SDK trio, and
  `accept_a2a("http://127.0.0.1:<port>")` forwards to it.

Install the A2A SDK next to the mesh SDK:

```bash
npm install @a2a-js/sdk express
```

```bash
pip install 'a2a-sdk[http-server]' uvicorn
```

The agent, an echo: it answers every message with what was said and who
said it. Who said it is the peer the mesh verified, which the SDK sets as
`X-Peer-Id` after authorizing the request and before it reaches the A2A
server, so the agent reads the header rather than a name in the message.

JavaScript, `a2a-agent.js`:

<!-- embed: sdk/js/examples/a2a-agent.ts -->
```ts
// An agent written with the A2A SDK, on the mesh. The A2A SDK builds the agent
// card and the JSON-RPC handler as an Express app; instead of listening on a
// port, the app answers requests the mesh SDK accepts for a2a://agent. Other
// members reach it by peer ID through a router; the mesh policy decides which
// ones, and the SDK turns the rest away before a request reaches the app.
//
//   node a2a-agent.js
//
// SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
// SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or
// SAM_JWT_PATH (a workload identity token your platform issues, such as a
// Kubernetes projected service account token), and keeps the identity and
// credential in SAM_STATE_DIR; later runs resume from there, as the same
// peer, without it.
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import express from "express";
import { A2A_PROTOCOL_VERSION, AGENT_CARD_PATH, Role, type AgentCard, type Message } from "@a2a-js/sdk";
import { AgentEvent, DefaultRequestHandler, InMemoryTaskStore, type AgentExecutor, type ExecutionEventBus, type RequestContext } from "@a2a-js/sdk/server";
import { UserBuilder, agentCardHandler, jsonRpcHandler } from "@a2a-js/sdk/server/express";
import { AgentMesh, MeshSession } from "@sam-mesh/sdk";

const mesh = await AgentMesh.enroll({
  controlPlaneUrl: process.env.SAM_CONTROL_PLANE_URL ?? "https://mesh.example.com",
  bootstrapTokenPath: process.env.SAM_BOOTSTRAP_TOKEN_PATH,
  jwtPath: process.env.SAM_JWT_PATH,
  stateDir: process.env.SAM_STATE_DIR ?? `${homedir()}/.config/sam-mesh/a2a-agent`,
  // A plaintext http:// control plane is otherwise accepted only on loopback.
  allowInsecure: process.env.SAM_INSECURE_CONTROL_PLANE === "true",
});
const session = await mesh.join();

// The card names the agent as the mesh reaches it: the URL an A2A client on
// the mesh gives its fetch, http://mesh/sam/<peer-id>/a2a/agent.
const url = MeshSession.meshURL(session.peerId, "a2a://agent");
const card: AgentCard = {
  name: "Echo agent",
  description: "Answers every message with what it said and who sent it.",
  version: "1.0.0",
  supportedInterfaces: [{ url, protocolBinding: "JSONRPC", tenant: "", protocolVersion: A2A_PROTOCOL_VERSION }],
  provider: undefined,
  documentationUrl: "",
  capabilities: { streaming: true, pushNotifications: false, extendedAgentCard: false, extensions: [] },
  securitySchemes: {},
  securityRequirements: [],
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain"],
  skills: [{ id: "echo", name: "Echo", description: "Repeats the message.", tags: ["echo"], examples: ["hello"], inputModes: [], outputModes: [], securityRequirements: [] }],
  signatures: [],
  iconUrl: "",
};

// The agent's logic: one message in, one message out. The user on the call
// context is the caller the mesh verified, built from X-Peer-Id below.
class EchoExecutor implements AgentExecutor {
  async execute(context: RequestContext, eventBus: ExecutionEventBus): Promise<void> {
    const said = context.userMessage.parts.map((p) => (p.content?.$case === "text" ? p.content.value : "")).join("");
    const caller = context.context.user?.userName ?? "someone";
    const reply: Message = {
      messageId: randomUUID(),
      contextId: context.contextId,
      taskId: "",
      role: Role.ROLE_AGENT,
      parts: [{ content: { $case: "text", value: `${caller} said: ${said}` }, filename: "", mediaType: "text/plain", metadata: undefined }],
      metadata: undefined,
      extensions: [],
      referenceTaskIds: [],
    };
    eventBus.publish(AgentEvent.message(reply));
    eventBus.finished();
  }

  async cancelTask(): Promise<void> {}
}

const requestHandler = new DefaultRequestHandler(card, new InMemoryTaskStore(), new EchoExecutor());
const app = express();
app.use(`/${AGENT_CARD_PATH}`, agentCardHandler({ agentCardProvider: requestHandler }));
// The SDK sets X-Peer-Id to the peer it verified and authorized, after
// stripping anything the caller sent under that name.
const verifiedPeer: UserBuilder = async (req) => ({ isAuthenticated: true, userName: String(req.headers["x-peer-id"] ?? "") });
app.use(jsonRpcHandler({ requestHandler, userBuilder: verifiedPeer }));

const target = await session.acceptA2A({ listener: app });
console.log(`accepting ${target} as ${session.peerId}`);
console.log(`agent card at ${session.agentURL}/${AGENT_CARD_PATH}`);

const stop = () => void session.close().then(() => process.exit(0));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
```
<!-- /embed -->

Python, `a2a_agent.py`:

<!-- embed: sdk/python/examples/a2a_agent.py -->
```python
"""An agent written with the A2A SDK, on the mesh. The A2A SDK's server runs
as it always does, a Starlette app under uvicorn on a loopback port; the mesh
SDK accepts requests for a2a://agent and forwards them to it. Other members
reach the agent by peer ID through a router; the mesh policy decides which
ones, and the SDK turns the rest away before a request reaches the app.

    python a2a_agent.py

SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or SAM_JWT_PATH
(a workload identity token your platform issues, such as a Kubernetes
projected service account token), and keeps the identity and credential in
SAM_STATE_DIR; later runs resume from there, as the same peer, without it.
"""

import os
import socket
import threading

import trio
import uvicorn
from a2a.helpers import get_message_text, new_text_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill, Role
from agent_mesh import AgentMesh, MeshSession
from starlette.applications import Starlette

mesh = AgentMesh.enroll(
    os.environ.get("SAM_CONTROL_PLANE_URL", "https://mesh.example.com"),
    bootstrap_token_path=os.environ.get("SAM_BOOTSTRAP_TOKEN_PATH"),
    jwt_path=os.environ.get("SAM_JWT_PATH"),
    state_dir=os.environ.get("SAM_STATE_DIR", "~/.config/sam-mesh/a2a-agent"),
    # A plaintext http:// control plane is otherwise accepted only on loopback.
    allow_insecure=os.environ.get("SAM_INSECURE_CONTROL_PLANE") == "true",
)


class EchoExecutor(AgentExecutor):
    """One message in, one message out. X-Peer-Id is the caller the mesh
    verified; the SDK sets it after authorizing the request."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        caller = context.call_context.state["headers"].get("x-peer-id", "someone") if context.call_context else "someone"
        said = get_message_text(context.message) if context.message else ""
        await event_queue.enqueue_event(new_text_message(f"{caller} said: {said}", role=Role.ROLE_AGENT, context_id=context.context_id))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass


def a2a_app(agent_url: str) -> Starlette:
    """The A2A SDK's server, as its samples build it. The card names the agent
    as the mesh reaches it: http://mesh/sam/<peer-id>/a2a/agent."""
    card = AgentCard(
        name="Echo agent",
        description="Answers every message with what it said and who sent it.",
        version="1.0.0",
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        capabilities=AgentCapabilities(streaming=True),
        supported_interfaces=[AgentInterface(protocol_binding="JSONRPC", url=agent_url, protocol_version="1.0")],
        skills=[AgentSkill(id="echo", name="Echo", description="Repeats the message.", tags=["echo"], examples=["hello"])],
    )
    handler = DefaultRequestHandler(agent_executor=EchoExecutor(), task_store=InMemoryTaskStore(), agent_card=card)
    return Starlette(routes=[*create_agent_card_routes(card), *create_jsonrpc_routes(handler, "/")])


def serve_locally(app: Starlette) -> str:
    """Runs uvicorn on a free loopback port in a thread and returns its URL.
    The A2A SDK runs on asyncio, the mesh SDK on trio; a thread keeps them apart."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    return f"http://127.0.0.1:{port}"


async def main() -> None:
    backend_url = serve_locally(a2a_app(MeshSession.mesh_url(mesh.identity.peer_id, "a2a://agent")))
    async with mesh.join() as session:
        target = await session.accept_a2a(backend_url)
        print(f"accepting {target} as {session.peer_id}", flush=True)
        print(f"agent card at {session.agent_url}/.well-known/agent-card.json", flush=True)
        await trio.sleep_forever()


trio.run(main)
```
<!-- /embed -->

```bash
node a2a-agent.js
# or
python a2a_agent.py
```

```text
accepting a2a://agent as 12D3KooWQmB5…
agent card at http://mesh/sam/12D3KooWQmB5…/a2a/agent/.well-known/agent-card.json
```

The caller, with the A2A SDK's client: it fetches the card, sends one
message and prints the answer.

JavaScript, `a2a-call.js`:

<!-- embed: sdk/js/examples/a2a-call.ts -->
```ts
// Talks to an agent on the mesh with the A2A SDK's client. The mesh SDK hands
// the A2A client a `fetch` bound to the mesh; the client fetches the agent
// card and sends messages as it would to any A2A server, and every request
// travels to the peer through a router with this member's credential.
//
//   node a2a-call.js 12D3KooW... "hello"
//
// SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
// SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or
// SAM_JWT_PATH (a workload identity token your platform issues, such as a
// Kubernetes projected service account token), and keeps the identity and
// credential in SAM_STATE_DIR; later runs resume from there without it.
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { Message, Role, type SendMessageRequest } from "@a2a-js/sdk";
import { ClientFactory, DefaultAgentCardResolver, JsonRpcTransportFactory } from "@a2a-js/sdk/client";
import { AgentMesh, MeshSession } from "@sam-mesh/sdk";

const [peerId, text = "hello"] = process.argv.slice(2);
if (peerId === undefined) {
  throw new Error("usage: a2a-call.js <peer-id> [text]");
}

const mesh = await AgentMesh.enroll({
  controlPlaneUrl: process.env.SAM_CONTROL_PLANE_URL ?? "https://mesh.example.com",
  bootstrapTokenPath: process.env.SAM_BOOTSTRAP_TOKEN_PATH,
  jwtPath: process.env.SAM_JWT_PATH,
  stateDir: process.env.SAM_STATE_DIR ?? `${homedir()}/.config/sam-mesh/a2a-caller`,
  // A plaintext http:// control plane is otherwise accepted only on loopback.
  allowInsecure: process.env.SAM_INSECURE_CONTROL_PLANE === "true",
});
const session = await mesh.join();
console.log(`on the mesh as ${session.peerId}`);

// The agent's URL on the mesh, and a fetch that carries requests to it.
const agentURL = MeshSession.meshURL(peerId, "a2a://agent");
const fetchImpl = session.fetch();
const factory = new ClientFactory({
  transports: [new JsonRpcTransportFactory({ fetchImpl })],
  cardResolver: new DefaultAgentCardResolver({ fetchImpl }),
});
// The card lives under the agent's URL; the trailing slash keeps the last segment when the resolver appends the well-known path.
const client = await factory.createFromUrl(agentURL + "/");
const card = await client.getAgentCard();
console.log(`agent: ${card.name}, ${card.description}`);

const request: SendMessageRequest = {
  tenant: "",
  message: Message.fromJSON({ messageId: randomUUID(), role: Role[Role.ROLE_USER], parts: [{ text }] }),
  configuration: undefined,
  metadata: undefined,
};
const answer = await client.sendMessage(request);
const parts = "parts" in answer ? answer.parts : (answer.status?.message?.parts ?? []);
console.log(parts.map((p) => (p.content?.$case === "text" ? p.content.value : "")).join(""));

await session.close();
```
<!-- /embed -->

Python, `a2a_call.py`:

<!-- embed: sdk/python/examples/a2a_call.py -->
```python
"""Talks to an agent on the mesh with the A2A SDK's client. The mesh SDK is an
httpx transport; the A2A client fetches the agent card and sends messages as
it would to any A2A server, and every request travels to the peer through a
router with this member's credential.

    python a2a_call.py 12D3KooW... "hello"

SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or SAM_JWT_PATH
(a workload identity token your platform issues, such as a Kubernetes
projected service account token), and keeps the identity and credential in
SAM_STATE_DIR; later runs resume from there without it.
"""

import os
import sys

import httpx
import trio
from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.helpers import get_message_text, new_text_message
from a2a.types import Role, SendMessageRequest
from agent_mesh import AgentMesh, MeshSession, MeshTransport

if len(sys.argv) < 2:
    raise SystemExit("usage: a2a_call.py <peer-id> [text]")
peer_id = sys.argv[1]
text = sys.argv[2] if len(sys.argv) > 2 else "hello"

mesh = AgentMesh.enroll(
    os.environ.get("SAM_CONTROL_PLANE_URL", "https://mesh.example.com"),
    bootstrap_token_path=os.environ.get("SAM_BOOTSTRAP_TOKEN_PATH"),
    jwt_path=os.environ.get("SAM_JWT_PATH"),
    state_dir=os.environ.get("SAM_STATE_DIR", "~/.config/sam-mesh/a2a-caller"),
    # A plaintext http:// control plane is otherwise accepted only on loopback.
    allow_insecure=os.environ.get("SAM_INSECURE_CONTROL_PLANE") == "true",
)


async def main() -> None:
    async with mesh.join() as session:
        print(f"on the mesh as {session.peer_id}")

        # The agent's URL on the mesh, and an httpx client that carries requests to it.
        agent_url = MeshSession.mesh_url(peer_id, "a2a://agent")
        async with httpx.AsyncClient(transport=MeshTransport(session), timeout=60) as http:
            card = await A2ACardResolver(http, agent_url).get_agent_card()
            print(f"agent: {card.name}, {card.description}")

            client = await create_client(card, ClientConfig(httpx_client=http, streaming=False))
            request = SendMessageRequest(message=new_text_message(text, role=Role.ROLE_USER))
            async for response in client.send_message(request):
                if response.HasField("message"):
                    print(get_message_text(response.message))
                elif response.HasField("task") and response.task.status.HasField("message"):
                    print(get_message_text(response.task.status.message))
            await client.close()


trio.run(main)
```
<!-- /embed -->

In a second terminal, call the agent from the other language:

```bash
python a2a_call.py 12D3KooWQmB5… "hello from python"
```

```text
on the mesh as 12D3KooWHZ2M…
agent: Echo agent, Answers every message with what it said and who sent it.
12D3KooWHZ2M… said: hello from python
```

The A2A client did what it does against any A2A server; the mesh carried
each request to the peer through a router, with the caller's credential,
and the agent's server received it with the caller already verified.
`message/stream` works the same way: response bodies stream through both
SDKs.

Treat what another agent sends as input from outside your control. The
mesh verifies the peer's identity and credential; it does not inspect the
content the peer sends. An agent card's `description` or a skill's text
pasted into a prompt is a prompt injection path like any other.

The public testnets run these programs: an agent written with each SDK
and, every fifteen minutes, a caller written with the other that sends it a
message and checks the answer names the caller.

## What happened

`enroll` sent the token and the program's public key to the control plane
and received a credential: a signed token that names the member, its role
and the routers it may use. The identity key and the credential live in the
state directory, so the next run resumes without a token, and the SDK
renews the credential before it expires. Delete the directory to enroll
afresh, for instance with other labels. The directory has the same layout
in both SDKs and in `sam-node`: a program in one language resumes a
directory written by the other, and `sam-node state import` runs the same
identity as a node (see the [sam-node reference](../../reference/sam-node/#state)).

`join` connected to the routers named in the credential, proved the
program's identity to each and verified the router's own credential, and
reserved a relay slot so that other members reach the program through the
router. The program opens no port of its own. While the session is open,
the SDK follows the control plane: keys, bans and router addresses on
`sam-node`'s schedule, and sooner when the control plane announces a change
over the mesh.

`discover` looked a service up by name in a table the routers host. An
agent is not in that table; given its peer ID, `connect` dials the path
through every router that admitted the caller, and the router opens a
circuit because it admitted the agent too. Either way the SDK verifies the
peer's credential before sending anything, and `requiredLabels`
(`required_labels` in Python) refuses a peer whose control-plane-attested
labels do not carry every pair you ask for, as `X-Sam-Required-Labels` does
on a `sam-node`. A floor uses the same rule for the whole session:
`join({ egressRequireLabels })` (`join(egress_require_labels=)`) names
labels every peer the session calls must attest, as `egress.require_labels`
does for a `sam-node`. It is stated once at `join` and held for the
session, on every call and however the peer was named; the agent's calls
cannot waive or widen it. The floor belongs to the program that calls
`join`; no configuration outside the process sets it.

`acceptA2A` (`accept_a2a`) fetched the mesh policy and started answering.
Every caller must present a credential signed by a trusted control plane
key, bound to the connection's peer and unexpired, and its role must be
granted `a2a://agent` by the policy. The check runs on the same Datalog
text a `sam-node` evaluates. A caller the policy does not admit is turned
away before the request reaches your handler or your A2A server. Your
handler sees the verified caller as `caller.peerId` (`caller.peer_id`) and
a forwarded server as the `X-Peer-Id` header; the caller's credential is
never forwarded. The connection is encrypted end to end between the two
peers; the router forwards ciphertext.

Under the open development policy of `sam-one`, every member holds the
`node` role and that role may call any service. On a shared mesh the policy
grants a role the services it may call (`allowed_services: ["a2a://agent"]`
or a pattern) and the members it may reach; see
[Mesh policy](../../reference/policy/). A refused caller receives `403`.

## Beyond the examples

- **Naming a peer.** `callTool`, `listTools`, `request`, `authenticate` and
  `connect` accept a provider from `discover`, a peer id, or a multiaddr.
  With a peer id alone the SDK goes through the routers.
- **Every service of a type.** `discover("mcp")` lists every MCP provider
  on the mesh; `discover("mcp://everything")` those of one service.
- **A member's own catalog.** `listTools(peer, "")` returns a `sam-node`'s
  `list_local_services` tool.
- **Another agent name.** `acceptA2A({ name: "reviewer", ... })` and
  `accept_a2a(target, name="reviewer")` answer as `a2a://reviewer`; callers
  use that target and the matching mesh URL.
- **Reading the policy.** `session.policyRules` (`session.policy_rules`)
  holds the Datalog the session enforces, for logging or tests.

## In a browser

The JS SDK is the same package in a page. `AgentMesh.enroll`, `join`,
`acceptA2A`, `fetch()` and the rest work as above; what differs is how
the page reaches the mesh and where it keeps its state:

- The page connects to a router over WebSocket and secures the connection
  with Noise. Routers and nodes offer TLS first and accept Noise, so a
  Node, Python or Go member reached through a relay meets the page on
  Noise, end to end. `sam-one` listens on WebSocket by default; behind
  `--tunnel` or any TLS-terminating proxy it advertises the router as
  `wss`, which a page served over `https` needs.
- The control plane answers the page's requests from any origin. Enrollment
  and refresh authenticate by the token or biscuit the request carries, so a
  page on another origin sends nothing a program could not send already.
- `stateDir` names an IndexedDB database instead of a directory; a reload
  resumes the saved enrollment without a token. `bootstrapTokenPath` and
  `jwtPath` are refused, a browser has no files: pass `bootstrapToken` or
  `jwt`.
- `acceptA2A` takes a `handler` (a function from `Request` to `Response`) or
  a `url`; a Node `listener` has no HTTP server to run on in a page.

The example `sdk/js/examples/browser` is the Echo agent above in a page,
answering with the A2A SDK's `JsonRpcTransportHandler` behind a handler.
Bundle it with the page's own bundler, or with the script the repository
uses:

```bash
cd sdk/js && npm run build
node scripts/bundle-browser.mjs examples/browser/app.js build/browser-example
```

and serve `build/browser-example`. The `browser` field of `package.json`
tells a bundler which files to swap for the browser; `@biscuit-auth/biscuit-wasm`
imports its `.wasm` as a module, which webpack (`asyncWebAssembly`), Vite
(`vite-plugin-wasm`) and the script above resolve. `tests/ui/browser-sdk.spec.js`
runs the page in Chromium against `sam-one`, once directly and once behind
a TLS-terminating edge, with Node members calling it and being called.

## What the SDKs do not do

- They do not publish services. An MCP server, a model or an agent that
  others should find by name runs behind a `sam-node`, which publishes it
  to the discovery table and reports it to the console.
- They do not run a local HTTP/gRPC gateway or credential broker. A workload
  that needs `ext_authz`, `ext_proc`, RFC 8693 `/oauth/token`, or cloud egress
  credential brokering runs beside a `sam-node`.
- They do not serve the discovery table. A member is a client of it; the
  routers hold the records.
- The Python SDK does not run in a browser; the JS SDK does, see
  [In a browser](#in-a-browser).

The wire contract and the interoperability facts the tests pin are in
[`sdk/README.md`](https://github.com/google/sam/blob/main/sdk/README.md).
