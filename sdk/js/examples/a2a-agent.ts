// An agent written with the A2A SDK, on the mesh. The A2A SDK builds the agent
// card and the JSON-RPC handler as an Express app; instead of listening on a
// port, the app answers requests the mesh SDK accepts for a2a://agent. Other
// members reach it by peer ID through a router; the mesh policy decides which
// ones, and the SDK turns the rest away before a request reaches the app.
//
//   node a2a-agent.js
//
// AGENTMESH_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
// AGENTMESH_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or
// AGENTMESH_JWT_PATH (a workload identity token your platform issues, such as a
// Kubernetes projected service account token), and keeps the identity and
// credential in AGENTMESH_STATE_DIR; later runs resume from there, as the same
// peer, without it.
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import express from "express";
import { A2A_PROTOCOL_VERSION, AGENT_CARD_PATH, Role, type AgentCard, type Message } from "@a2a-js/sdk";
import { AgentEvent, DefaultRequestHandler, InMemoryTaskStore, type AgentExecutor, type ExecutionEventBus, type RequestContext } from "@a2a-js/sdk/server";
import { UserBuilder, agentCardHandler, jsonRpcHandler } from "@a2a-js/sdk/server/express";
import { AgentMesh, MeshSession } from "@agentmesh-p2p/sdk";

const mesh = await AgentMesh.enroll({
  controlPlaneUrl: process.env.AGENTMESH_CONTROL_PLANE_URL ?? "https://mesh.example.com",
  bootstrapTokenPath: process.env.AGENTMESH_BOOTSTRAP_TOKEN_PATH,
  jwtPath: process.env.AGENTMESH_JWT_PATH,
  stateDir: process.env.AGENTMESH_STATE_DIR ?? `${homedir()}/.config/agentmesh/a2a-agent`,
  // A plaintext http:// control plane is otherwise accepted only on loopback.
  allowInsecure: process.env.AGENTMESH_INSECURE_CONTROL_PLANE === "true",
});
const session = await mesh.join();

// The card names the agent as the mesh reaches it: the URL an A2A client on
// the mesh gives its fetch, http://mesh/mesh/<peer-id>/a2a/agent.
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
