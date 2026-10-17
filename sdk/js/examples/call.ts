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
