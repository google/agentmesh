# @sam-mesh/sdk

Native JavaScript SDK for joining a SAM agent mesh from inside the agent
process. It replaces the `sam-node` sidecar for agents written for Node.js
or running in a browser page:
the agent enrolls with the control plane, joins the mesh through a router,
finds services and calls them, answers A2A requests for the agent itself,
and follows the control plane's keys, bans and policy while it runs. It
publishes no service; a tool or a model others should find by name runs
behind a `sam-node`.

Guide: [sam-mesh.dev/docs/guides/native-sdks](https://sam-mesh.dev/docs/guides/native-sdks/),
from an empty machine to two programs on a mesh.
Source: [github.com/google/sam/tree/main/sdk/js](https://github.com/google/sam/tree/main/sdk/js).

## Install

```bash
npm install @sam-mesh/sdk @modelcontextprotocol/sdk zod
```

Requires Node.js 22.18 or later. In a browser, bundle it with the page
(the package's `browser` field selects the browser files); the guide's
[In a browser](https://sam-mesh.dev/docs/guides/native-sdks/#in-a-browser)
section has the details and an example page.

## Use

Both programs below are in
[`examples/`](https://github.com/google/sam/tree/main/sdk/js/examples) and
run against a real mesh in the repository's tests. They read the mesh from
`SAM_CONTROL_PLANE_URL` and the enrollment token from
`SAM_BOOTSTRAP_TOKEN_PATH`; the guide shows how to get both from `sam-one`
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
[github.com/google/sam](https://github.com/google/sam).
