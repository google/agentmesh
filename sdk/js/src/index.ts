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

export { AgentMesh, CredentialRetiredError, type AgentMeshOptions, type ControlPlaneSync, type EnrollOptions, type JwtSource } from "./mesh.ts";
export { Identity, canonicalPeerId, peerIdFromPublicKey, libp2pPublicKey, verifyEd25519 } from "./identity.ts";
export {
  ControlPlaneClient,
  ControlPlaneError,
  EnrollmentRejectedError,
  InsecureControlPlaneURLError,
  KeysNotTrustedError,
  ROLE_NODE,
  validateControlPlaneURL,
  verifyKeysResponse,
  type ControlPlaneClientOptions,
  type Enrollment,
  type EnrollBootstrapParams,
  type PolicyRulesParams,
  type RegisterParams,
  type RefreshParams,
  type RefreshResult,
} from "./controlplane.ts";
export {
  attenuateCredential,
  credentialFromJSON,
  credentialTimeToLiveSeconds,
  credentialToJSON,
  decodeAuthResponse,
  encodeAuthFrame,
  sealCredential,
  withCredentialMethods,
  type MeshCredential,
} from "./credential.ts";
export {
  egressChallenge,
  enrollChallenge,
  enrollStatusChallenge,
  nodesCatalogChallenge,
  policiesChallenge,
  refreshChallenge,
  registerChallenge,
  revocationsChallenge,
} from "./challenges.ts";
export {
  DEFAULT_ROUTERS,
  JOIN_TIMEOUT_MS,
  MeshSession,
  ROUTER_REDIAL_BACKOFFS_MS,
  candidatesFromRouterInfos,
  selectRouters,
  type AdmittedRouter,
  type DiscoveredProvider,
  type JoinOptions,
  type Peer,
  type RouterCandidate,
  type SelectRoutersOptions,
  type ToolCallResult,
} from "./session.ts";
export {
  BiscuitVerificationError,
  ROLE_ROUTER,
  attenuateBiscuit,
  requireRole,
  sealBiscuit,
  verifyPeerBiscuit,
  type VerifiedBiscuit,
} from "./biscuit.ts";
export {
  decodeTARBlockPayload,
  effectiveTARExpiration,
  encodeTARBlockFact,
  encodeTARBlockPayload,
  evaluateTaskRules,
  matchHTTPPath,
  matchServicePattern,
  matchTaskRule,
  parseTARBlockSource,
  validateHTTPGrantPath,
  validateServicePattern,
  validateTaskAuthorizationRule,
  validateTaskRule,
  type TaskRequestContext,
} from "./tar.ts";
export {
  AUTH_HANDLER_OPTIONS,
  AUTH_PROTOCOL,
  GOAWAY_MAX_RETRY_AFTER_MS,
  GOAWAY_PROTOCOL,
  GOAWAY_STREAM_TIMEOUT_MS,
   MAX_GOAWAY_MESSAGE_BYTES,
  MCP_PROTOCOL,
  ROUTER_SHUN_DURATION_MS,
  AuthRejectedError,
  authenticateWithPeer,
  authStreamHandler,
  clampGoAwayRetryAfterMs,
  goAwayReasonName,
  goAwayStreamHandler,
  type GoAwayServerOptions,
} from "./auth.ts";
export { createMeshHost, type MeshHost, type MeshHostOptions } from "./host.ts";
export { DIRECTORY_PROTOCOL, DirectoryError, isServiceType, parseServiceTarget, peerKey, serviceKey, type ServiceType } from "./discovery.ts";
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
