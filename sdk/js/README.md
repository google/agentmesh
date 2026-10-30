# @agentmesh-p2p/sdk

Native JavaScript SDK for joining an Agent Mesh from inside the agent
process. It replaces the `agentmesh-node` sidecar for agents written for Node.js
or running in a browser page:
the agent enrolls with the control plane, joins the mesh through a router,
finds services and calls them, answers A2A requests for the agent itself,
and follows the control plane's keys, bans and policy while it runs. It
publishes no service; a tool or a model others should find by name runs
behind a `agentmesh-node`.

Guide: [google.github.io/agentmesh/docs/guides/native-sdks](https://google.github.io/agentmesh/docs/guides/native-sdks/),
from an empty machine to two programs on a mesh.
Source: [github.com/google/agentmesh/tree/main/sdk/js](https://github.com/google/agentmesh/tree/main/sdk/js).

## Install

```bash
npm install @agentmesh-p2p/sdk @modelcontextprotocol/sdk zod
```

Requires Node.js 22.18 or later. In a browser, bundle it with the page
(the package's `browser` field selects the browser files); the guide's
[In a browser](https://google.github.io/agentmesh/docs/guides/native-sdks/#in-a-browser)
section has the details and an example page.

## MCP client over stdio

The package's `agentmesh` executable joins as its own mesh member and exposes
five MCP tools: `get_mesh_info`, `discover_remote_services`, `find_remote_tools`,
`describe_remote_tool` and `call_remote_tool`. A stdio-capable MCP client starts
and stops the process; no node daemon is needed for this caller. Providers still
publish their services through `agentmesh-node`.

To try the executable from a source checkout:

```bash
cd sdk/js
npm ci
npm run build
```

Use absolute paths in your MCP client's configuration:

```json
{
  "mcpServers": {
    "agentmesh": {
      "command": "node",
      "args": ["/absolute/path/to/agentmesh/sdk/js/dist/cli.js"],
      "env": {
        "AGENTMESH_CONTROL_PLANE_URL": "https://your-control-plane.example",
        "AGENTMESH_BOOTSTRAP_TOKEN_PATH": "/absolute/path/to/join-token",
        "AGENTMESH_STATE_DIR": "/absolute/path/to/this-client-identity"
      }
    }
  }
}
```

Get the control plane URL and token file from your mesh operator or
[`agentmesh-one`](https://google.github.io/agentmesh/docs/guides/native-sdks/).
Alternatively, set `AGENTMESH_JWT_PATH` to a workload/OIDC token file; do not set
both token paths. Credentials are read from files, never command-line values.

The first run enrolls and saves its identity; later runs resume from the state
directory without the bootstrap token. JWT enrollment rereads the token file
when refreshing. Use a distinct state directory for each client identity and
mesh; do not run multiple processes against the same directory. The default is
`~/.config/agentmesh/mcp`. Plain HTTP is allowed on loopback only unless
`AGENTMESH_INSECURE_CONTROL_PLANE=true` explicitly permits it elsewhere.

Stdout contains only MCP messages; diagnostics go to stderr. Closing stdin or
sending SIGINT/SIGTERM shuts down the mesh session. Tool calls use the member's
existing authenticated streams and policy, including provider label checks.
Remote tool results retain text, non-text content, structured output and errors.
Discovery follows tool pagination, rejects looping catalogs and bounds each
search to 64 providers, 256 services per provider, 256 tools per service and
1024 results. Requests have a 10-second deadline; narrow a large search by peer
or service. `intent` is accepted but ignored, matching the node's current tool.

This member publishes no services, so it has no `list_local_services` tool.
Inference and A2A discovery return metadata, but this executable provides no
HTTP proxy, `/v1` endpoint, local socket or `local_proxy_url`. Use an SDK client
or an `agentmesh-node` HTTP proxy to invoke those protocols.

This source implementation is the executable portion of
[#544](https://github.com/google/agentmesh/issues/544). Official MCP registry
registration and release automation are separate work; this configuration does
not depend on a published registry entry.

## Use

Both programs below are in
[`examples/`](https://github.com/google/agentmesh/tree/main/sdk/js/examples) and
run against a real mesh in the repository's tests. They read the mesh from
`AGENTMESH_CONTROL_PLANE_URL` and the enrollment token from
`AGENTMESH_BOOTSTRAP_TOKEN_PATH`; the guide shows how to get both from `agentmesh-one`
or from the operator of an existing mesh.

Find a service and call it:

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
// AGENTMESH_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
// AGENTMESH_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or
// AGENTMESH_JWT_PATH (a workload identity token your platform issues, such as a
// Kubernetes projected service account token), and keeps the identity and
// credential in AGENTMESH_STATE_DIR; later runs resume from there without it.
import { homedir } from "node:os";
import { AgentMesh, type DiscoveredProvider } from "@agentmesh-p2p/sdk";

let argv = process.argv.slice(2);
// A first argument that is not a service target is the peer ID of an agent.
let peerId: string | undefined;
if (argv[0] !== undefined && !argv[0].includes("://")) {
  [peerId, ...argv] = argv as [string, ...string[]];
}
const [service = peerId !== undefined ? "a2a://agent" : "mcp://everything", toolOrPath = peerId !== undefined ? "/card" : "echo", args = '{"message": "hi"}'] = argv;

const mesh = await AgentMesh.enroll({
  controlPlaneUrl: process.env.AGENTMESH_CONTROL_PLANE_URL ?? "https://mesh.example.com",
  bootstrapTokenPath: process.env.AGENTMESH_BOOTSTRAP_TOKEN_PATH,
  jwtPath: process.env.AGENTMESH_JWT_PATH,
  stateDir: process.env.AGENTMESH_STATE_DIR ?? `${homedir()}/.config/agentmesh/caller`,
  // A plaintext http:// control plane is otherwise accepted only on loopback.
  allowInsecure: process.env.AGENTMESH_INSECURE_CONTROL_PLANE === "true",
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

Be an agent others can call. Nothing is published; a caller reaches the
agent by its peer ID, the one it prints, through a router:

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
// AGENTMESH_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
// AGENTMESH_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or
// AGENTMESH_JWT_PATH (a workload identity token your platform issues, such as a
// Kubernetes projected service account token), and keeps the identity and
// credential in AGENTMESH_STATE_DIR; later runs resume from there, as the same
// peer, without it.
import { homedir } from "node:os";
import { AgentMesh } from "@agentmesh-p2p/sdk";

const [backendURL] = process.argv.slice(2);

const mesh = await AgentMesh.enroll({
  controlPlaneUrl: process.env.AGENTMESH_CONTROL_PLANE_URL ?? "https://mesh.example.com",
  bootstrapTokenPath: process.env.AGENTMESH_BOOTSTRAP_TOKEN_PATH,
  jwtPath: process.env.AGENTMESH_JWT_PATH,
  stateDir: process.env.AGENTMESH_STATE_DIR ?? `${homedir()}/.config/agentmesh/agent`,
  // A plaintext http:// control plane is otherwise accepted only on loopback.
  allowInsecure: process.env.AGENTMESH_INSECURE_CONTROL_PLANE === "true",
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

`enroll` reuses the identity and credential saved in `stateDir` when they
are still valid for that control plane, and needs exactly one of
`bootstrapTokenPath`, `bootstrapToken`, `jwtPath` or `jwt` (a token string or
a `() => string | Promise<string>` callback invoked at enrollment and on every
refresh) otherwise. Read tokens from a file, a callback or the environment; do
not put them on a command line. `labels` are attested at enrollment;
`join({ egressRequireLabels })` is the floor every peer the session calls must
attest, all of it, held for the session.

A plaintext `http://` control plane is accepted only on loopback. Pass
`allowInsecure: true` for a network you trust.

## License

Apache-2.0. Issues and contributions at
[github.com/google/agentmesh](https://github.com/google/agentmesh).
