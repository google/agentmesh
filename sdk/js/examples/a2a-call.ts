// Talks to an agent on the mesh with the A2A SDK's client. The mesh SDK hands
// the A2A client a `fetch` bound to the mesh; the client fetches the agent
// card and sends messages as it would to any A2A server, and every request
// travels to the peer through a router with this member's credential.
//
//   node a2a-call.js 12D3KooW... "hello"
//
// AGENTMESH_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
// AGENTMESH_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or
// AGENTMESH_JWT_PATH (a workload identity token your platform issues, such as a
// Kubernetes projected service account token), and keeps the identity and
// credential in AGENTMESH_STATE_DIR; later runs resume from there without it.
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { Message, Role, type SendMessageRequest } from "@a2a-js/sdk";
import { ClientFactory, DefaultAgentCardResolver, JsonRpcTransportFactory } from "@a2a-js/sdk/client";
import { AgentMesh, MeshSession } from "@agentmesh-p2p/sdk";

const [peerId, text = "hello"] = process.argv.slice(2);
if (peerId === undefined) {
  throw new Error("usage: a2a-call.js <peer-id> [text]");
}

// Each stage goes to stderr as it is reached, so a run that hangs shows the
// last one it got to; stdout carries only what callers parse.
const controlPlaneUrl = process.env.AGENTMESH_CONTROL_PLANE_URL ?? "https://mesh.example.com";
console.error(`enrolling with ${controlPlaneUrl}`);
const mesh = await AgentMesh.enroll({
  controlPlaneUrl,
  bootstrapTokenPath: process.env.AGENTMESH_BOOTSTRAP_TOKEN_PATH,
  jwtPath: process.env.AGENTMESH_JWT_PATH,
  stateDir: process.env.AGENTMESH_STATE_DIR ?? `${homedir()}/.config/agentmesh/a2a-caller`,
  // A plaintext http:// control plane is otherwise accepted only on loopback.
  allowInsecure: process.env.AGENTMESH_INSECURE_CONTROL_PLANE === "true",
});
console.error(`enrolled ${mesh.peerId}`);
const session = await mesh.join();
console.error(`joined via ${session.routers.map((r) => r.peerId).join(", ")}`);
console.log(`on the mesh as ${session.peerId}`);

// The agent's URL on the mesh, and a fetch that carries requests to it.
const agentURL = MeshSession.meshURL(peerId, "a2a://agent");
const fetchImpl = session.fetch();
const factory = new ClientFactory({
  transports: [new JsonRpcTransportFactory({ fetchImpl })],
  cardResolver: new DefaultAgentCardResolver({ fetchImpl }),
});
// The card lives under the agent's URL; the trailing slash keeps the last segment when the resolver appends the well-known path.
console.error(`dialing ${peerId}`);
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
