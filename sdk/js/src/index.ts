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

export { AgentMesh, type AgentMeshOptions, type ControlPlaneSync, type EnrollOptions } from "./mesh.ts";
export { Identity, canonicalPeerId, peerIdFromPublicKey, libp2pPublicKey, verifyEd25519 } from "./identity.ts";
export {
  ControlPlaneClient,
  ControlPlaneError,
  EnrollmentRejectedError,
  InsecureControlPlaneURLError,
  ROLE_NODE,
  validateControlPlaneURL,
  verifyKeysResponse,
  type ControlPlaneClientOptions,
  type Enrollment,
  type EnrollBootstrapParams,
  type RegisterParams,
  type RefreshParams,
  type RefreshResult,
} from "./controlplane.ts";
export {
  credentialFromJSON,
  credentialTimeToLiveSeconds,
  credentialToJSON,
  decodeAuthResponse,
  encodeAuthFrame,
  type MeshCredential,
} from "./credential.ts";
export { enrollChallenge, enrollStatusChallenge, refreshChallenge, registerChallenge } from "./challenges.ts";
export { MeshSession, type AdmittedRouter, type DiscoveredProvider, type JoinOptions, type Peer, type ToolCallResult } from "./session.ts";
export { BiscuitVerificationError, ROLE_ROUTER, requireRole, verifyPeerBiscuit, type VerifiedBiscuit } from "./biscuit.ts";
export { AUTH_HANDLER_OPTIONS, AUTH_PROTOCOL, MCP_PROTOCOL, AuthRejectedError, authenticateWithPeer, authStreamHandler } from "./auth.ts";
export { createMeshHost, type MeshHost, type MeshHostOptions } from "./host.ts";
export { DHT_PROTOCOL, isServiceType, parseServiceTarget, serviceCID, type ServiceType } from "./discovery.ts";
export { LabelsNotSatisfiedError, StreamTransport, openMCPSession, requireEgressLabels, requireLabels, type MCPSession, type MCPSessionOptions } from "./mcp.ts";
export { AuthorizationError, authorizeCaller, type AuthorizeRequest, type ProviderAuthorizerOptions } from "./authorizer.ts";
export {
  DEFAULT_A2A_NAME,
  AGENT_CARD_PATH,
  HTTP_HANDLER_OPTIONS,
  HTTP_PROTOCOL,
  MESH_PATH_PREFIX,
  a2aEndpoint,
  admitIngress,
  fetchOverStream,
  httpIngressHandler,
  httpRequestOverStream,
  meshHTTPTarget,
  meshURL,
  rewriteAgentCard,
  splitMeshURL,
  type A2AEndpoint,
  type A2AEndpointSpec,
  type HTTPHandler,
  type HTTPRequestOptions,
  type HTTPResponse,
  type HTTPStreamOptions,
  type NodeRequestListener,
  type ProviderOptions,
} from "./libp2p-http.ts";
export { ingressHandler } from "./platform/ingress.ts";
export type { StateStore } from "./platform/types.ts";
export { BASELINE_DATALOG } from "./gen/datalog.ts";
export { BanSet, EVENT_FRESHNESS_MS, GOSSIP_EVENTS_TOPIC, verifyMeshEvent, type VerifiedMeshEvent } from "./sync.ts";
