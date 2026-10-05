---
title: "Agent architecture"
linkTitle: "Agent architecture"
weight: 2
aliases:
  - /docs/agent-architecture/
---

This page explains how SAM authenticates workloads and users, scopes authority
to individual tasks and sub-agent hops, integrates with existing gateways and
sandbox runtimes, and brokers short-lived credentials to external cloud APIs
without placing standing cloud credentials inside the agent environment.

## A courier network for tasks

![The Agent Mesh as a courier network](/images/agent-mesh-courier.svg)

SAM moves tasks between environments that trust nothing on arrival, the way a
courier network moves parcels between post offices:

| In the picture | In SAM |
|---|---|
| **Parcel** | One request: an MCP tool call, a chat completion, a BigQuery query, an A2A message. |
| **Sender** | The agent wherever it runs: a developer laptop, Kubernetes on premises or in a cloud, a SaaS platform, or a sandbox runtime. |
| **Local post office** | The `sam-node` next to the agent, or the native SDK (`@sam-mesh/sdk`, `sam-mesh`) inside its process. It verifies the sender's platform credential and obtains a task waybill from the control plane. |
| **Your gateway** | Istio, `agentgateway`, Envoy AI Gateway, or `kgateway` where a cluster already runs one. It stays in the data path and consults `sam-node` over Envoy `ext_proc`, `ext_authz`, or RFC 8693 `/oauth/token`. |
| **Waybill** | The SAM Biscuit credential: who the subject is, through which actor node it travels, which roles it holds, and when it expires. |
| **Stamp** | An offline attenuation block (`tar_block`) appended at a task or sub-agent hop. Each stamp carries a serialized `TaskAuthorizationRule` and can only narrow authority. |
| **Sealed bag** | The mutually authenticated, encrypted libp2p stream between two nodes. Routers relay ciphertext across NATs, clusters, and clouds and cannot inspect it. |
| **Registry** | `sam-control-plane`: verifies identities, issues Biscuits (`POST /token/exchange`), distributes Datalog policy, and acts as an OIDC issuer (`POST /sts/token`, `/.well-known/openid-configuration`, `/jwks`) for outbound cloud federation. |
| **Destination office** | The serving or egress `sam-node` for `mcp://`, `inference://`, `a2a://`, or `egress://`: verifies the Biscuit and every `tar_block` stamp, runs content inspection, brokers the upstream credential, and delivers the request. |
| **Customs** | Content inspection at the egress node: built-in policy facts, Google Cloud Model Armor, and Envoy `ext_proc` callout processors. |
| **Permit** | The upstream destination credential: a federated cloud token exchanged via `CloudTokenExchanger` or a secret from the node's vault, never held by the agent. |
| **Receipts** | Structured audit logs at the control plane, the origin and egress nodes, and the cloud provider, joined by principal and `sam_task`. |

## Why workload identity alone is not enough

In cloud and service-mesh architectures, permissions are granted ambiently to a
workload identity (a Kubernetes Service Account, a cloud service account, or a
SPIFFE SVID). Workload identity is necessary, but insufficient for AI agents:

1. **One workload, many tasks.** A single agent service executes concurrent or
   sequential tasks with different least-privilege boundaries (for example,
   read-only access to `dataset_A` in one session and schema updates on
   `dataset_B` in another). Workload identity proves *which container* is
   calling, not *which task boundary* applies to this request.
2. **Prompt injection and confused deputy.** If a session exercises the full
   standing privileges of its workload or user identity, a prompt injection
   during a narrow task can touch unrelated tools or datasets.
3. **Multi-hop sub-agent delegation.** When an orchestrator delegates a
   narrower sub-task to a sub-agent, it needs offline, progressive attenuation
   (`Token_2 = Attenuate(Token_1, TaskRule)`) without minting a new identity at
   the identity provider on every hop.

SAM separates the two layers:

| Layer | Question answered | Primitive |
|---|---|---|
| **Subject & channel attestation** | *Which user or workload initiated this request, and through which node?* | OIDC ID token, Kubernetes projected SA JWT, SPIFFE JWT-SVID, or Istio mTLS identity (`source.principal` / XFCC), exchanged into a Biscuit bound to the channel (`client_peer_id`, `actor_node`). |
| **Task authorization (TAR)** | *What subset of standing permissions may this task or sub-agent hop exercise?* | Appended `tar_block` blocks carrying `api.TaskAuthorizationRule`, intersected across hops and translated into downscoped cloud credentials at egress. |

## Separation of responsibilities

OS and container confinement belongs to the sandbox platform (**Kubernetes
`agent-sandbox`**, **NVIDIA OpenShell**, **Docker Sandbox `docker sbx`**).
Local traffic interception belongs to the proxy (**`agentgateway`**, **Istio**,
**Envoy**, or **`sam-node`**). SAM provides:

- **`sam-control-plane`**: the mesh authority, Datalog policy distributor,
  OAuth 2.1 Authorization Server, stateless token exchanger
  (`POST /token/exchange`), and OIDC issuer (`POST /sts/token`) for cloud
  federation.
- **`sam-node`**: the Policy Decision Point (PDP), RFC 8693 Security Token
  Service (`POST /oauth/token`), Envoy `ext_authz` and `ext_proc` server, mesh
  router client, and egress credential broker.
- **Native SDKs (`@sam-mesh/sdk`, `sam-mesh`)**: in-process mesh clients for
  TypeScript and Python that enroll, open authenticated streams, verify peers,
  and attenuate and seal task credentials in memory (`session.attenuate(rule)`,
  `session.seal()`).

## The two-token model: Biscuit inside, JWT at both borders

Inside the mesh, every credential is a Biscuit. External identity providers and
cloud APIs speak standard JWTs and OAuth 2.1 / RFC 8693. SAM translates at both
borders:

1. **Inbound border (`POST /token/exchange` on the control plane, `POST /oauth/token` on the node):**
   The origin `sam-node` presents its own node Biscuit, a proof-of-possession
   signature over `sam:token-exchange:<peer_id>:<challenge_unix_ms>`, and the
   caller's `subject_token` (an OIDC JWT, Kubernetes projected SA token, or
   SPIFFE JWT-SVID). The control plane verifies both, resolves the caller's
   roles from the mesh policy, and mints a short-lived **Delegated Session
   Biscuit** with zero database writes:
   - `client_peer_id("<origin_peer_id>")` and `actor_node("<origin_peer_id>")`
     bind the token to the origin node's transport channel without granting the
     origin node's own `node:<peer_id>` roles to the caller.
   - `user(...)`, `email(...)`, `group(...)`, `idp_role(...)`, and `role(...)`
     carry the caller's verified identity and resolved roles.
2. **In-mesh hops (offline `tar_block` attenuation):**
   Before handing a token to a task runner or sub-agent, the holder appends a
   `TaskAuthorizationRule` block (`tar_block("<base64url-proto>")`) offline and
   optionally seals the token (`Seal()`) so downstream leaf processes cannot
   append further blocks.
3. **Outbound border (`POST /sts/token` + `CloudTokenExchanger`):**
   When a request reaches an egress `sam-node` (`egress://<destination>`), the
   node verifies the Biscuit signature, channel binding, standing Datalog
   policy, and every appended `TaskAuthorizationRule`. On a cache miss for the
   Biscuit digest, it calls `POST /sts/token` on the control plane, which
   re-verifies the token and mints a short-lived **ES256 JWT** (`iss` = control
   plane, `sub` = caller principal, `act.sub` = egress node peer ID, `aud` =
   destination audience, `sam_roles` = caller roles, `sam_task` = innermost
   task name). The egress node's `CloudTokenExchanger` exchanges that JWT at
   the cloud provider's STS endpoint.

## Safe Biscuit attenuation (`tar_block`)

SAM never evaluates holder-authored Datalog rules or checks. In `biscuit-go`,
Datalog `check if` queries are not bounded by rule-iteration limits, and
allowing both Datalog checks and a serialized protobuf in an appended block
would let a crafted token make the mesh PEP and the cloud STS adapter disagree.

Instead, every appended block (`block_idx >= 1`, up to `MaxAttenuationBlocks = 8`)
must contain:

- **0 Datalog rules**
- **0 Datalog checks**
- **Exactly 1 fact:** `tar_block("<base64url-encoded api.TaskAuthorizationRule>")`

All three verifiers (Go, TypeScript, and Python) enforce this structure before
building the Datalog authorizer, decode the `TaskAuthorizationRule` chain in a
single pass, and evaluate the rules directly in host code.

### Positive allow-lists and intersection semantics

`TaskAuthorizationRule` uses strictly positive allow-lists:

- Within a single `TaskAuthorizationRule`, a request is permitted if it matches
  **at least one** `TaskRule`. An empty `rules` list denies everything.
- Across appended blocks `1..k`, semantics are **strict intersection (logical
  AND)**: the request must be permitted by Block 0's standing Datalog policy,
  arrive before every block's `expire_time`, and match at least one `TaskRule`
  in **every** appended `TaskAuthorizationRule` block.

Each `TaskRule` scopes:

- `allowed_services`: service patterns (`mcp://bigquery`, `inference://gemini.*`,
  `egress://bigquery.googleapis.com`).
- `operation.allowed_tools`: MCP tool names enforced on `tools/call`.
- `operation.allowed_methods` and `operation.allowed_paths`: HTTP methods and
  exact or prefix (`/prefix/*`) paths.
- `operation.allowed_permissions` and `allowed_resources`: cloud IAM
  permissions and resource prefixes intersected across all hops and consumed by
  `CloudTokenExchanger` at egress.

## Gateway integration (`agentgateway`, Istio, Envoy)

Where a cluster already runs Envoy, Istio, or `agentgateway`, `sam-node` acts
as their external Policy Decision Point and Token Service over three standard
interfaces:

1. **Envoy `ext_authz` (`--ext-authz-addr`):** evaluates standing policy and
   `tar_block` chains on incoming `CheckRequest` calls, accepts verified
   SPIFFE principals from `AttributeContext.Source.Principal` or
   `X-Forwarded-Client-Cert` (XFCC) on trusted proxy listeners, and injects
   brokered upstream credentials (`Authorization: Bearer ...`,
   `X-Sam-Principal`, `X-Sam-Task-Id`).
2. **Envoy `ext_proc` (`envoy.service.ext_proc.v3.ExternalProcessor`):** the
   body-aware counterpart to `ext_authz`. Because MCP tool names travel inside
   the JSON-RPC request body (`params.name`), `ext_proc` inspects the buffered
   body to enforce `operation.allowed_tools` and injects the brokered
   credential only after the payload passes inspection.
3. **RFC 8693 Token Exchange (`POST /oauth/token`) & OAuth 2.1:** accepts
   `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with a JWT or
   Biscuit `subject_token` and optional `TaskAuthorizationRule` (in `options`,
   `scope`, or `resource`), returning a delegated or attenuated Task Biscuit.
   Unauthenticated MCP clients receive RFC 9728 Protected Resource Metadata
   (`/.well-known/oauth-protected-resource`) pointing to the control plane's
   OAuth 2.1 Authorization Server (`/oauth/authorize`, `/oauth/token` with
   PKCE).

## Egress credential brokering, inspection, and TCP tunnels

An `EgressDestination` in the mesh policy configures how selected egress nodes
reach an external service:

- **Credential brokers (`broker`):**
  - `static_secret`: reads a secret file from `--secrets-dir` (`Bearer` token
    or `user:pass` Basic auth).
  - `oidc_federation`: mints a control-plane ES256 border JWT via
    `POST /sts/token` and exchanges it at an RFC 8693 STS endpoint such as
    Google Cloud Workload/Workforce Identity Federation
    (`https://sts.googleapis.com/v1/token`), optionally impersonating a service
    account (`impersonate`) with scopes narrowed by the TAR chain.
  - `aws_assume_role`: exchanges the control-plane border JWT via AWS
    `AssumeRoleWithWebIdentity`, compiling the intersected TAR permissions and
    resources into an inline AWS session policy intersected with the configured
    `session_policy` template.
  - `platform_identity`: uses the egress node's ambient cloud identity (such as
    GKE Workload Identity metadata tokens) narrowed by scopes.
- **Content inspection (`inspection.inspectors`):**
  Runs at the egress node *before* the broker injects the destination
  credential, so inspectors never see upstream secrets:
  - **Model Armor (`model_armor`):** calls `sanitizeUserPrompt` and (in
    `BUFFERED` mode) `sanitizeModelResponse` for Gemini, OpenAI chat, MCP
    `tools/call`, and A2A payloads, blocking findings with `403` and replacing
    SDP de-identified text.
  - **Envoy `ext_proc` (`ext_proc`):** streams headers, bodies, and trailers to
    an external gRPC processor with `ProcessingRequest.attributes["sam"]`
    populated (`principal`, `roles`, `actor_node`, `task`, `service`,
    `destination`), while refusing any processor mutation to `Authorization`,
    `Host`, `:authority`, or `X-Sam-*`.
  - **Operator inspection chain (`preserve_host`, `forward_context`):** routes
    through an explicit outbound proxy while preserving the destination `Host`
    header and optionally forwarding `X-Sam-Principal`, `X-Sam-Roles`, and
    `X-Sam-Task`.
- **Named TCP tunnels (`mode: EGRESS_MODE_TCP`):**
  For non-HTTP TLS protocols (PostgreSQL, Cloud SQL, AlloyDB, Redis, SSH), the
  egress node exposes named `CONNECT host:port` tunnels and the local
  `sam-node forward egress://<name>:<port> <local-addr>` port forwarder. The
  egress node enforces the destination's `ports` allow-list and inspects the
  TLS `ClientHello` before splicing, refusing connections whose SNI does not
  match the authorized destination name or that hide the SNI with Encrypted
  Client Hello (ECH).

## Control-plane STS sizing

`sam-node` caches exchanged Delegated Biscuits by `SHA-256(subject_jwt + tar)`
and caches minted border JWTs and upstream cloud tokens by Biscuit digest,
keeping the control plane off the per-request hot path. You can measure raw
control-plane mint throughput and node cache hit rates on your hardware with:

```bash
sam-bench sts --requests 200 --concurrency 8 --warmup 10
```

On a standard development workstation (8 concurrent workers, SQLite store):

| Phase | Throughput (req/s) | p50 Latency | p99 Latency | Cache Hit Rate |
|---|---|---|---|---|
| Uncached `POST /token/exchange` | ~2,090 req/s | 3.6 ms | 7.8 ms | 0% (uncached baseline) |
| Uncached `POST /sts/token` (Datalog + TAR + ES256) | ~130 req/s | 61.0 ms | 68.4 ms | 0% (uncached baseline) |
| Cached `ExchangeSubjectJWT` (5m SPIFFE JWT-SVIDs) | ~18,500 req/s | 0.02 ms | 7.7 ms | >91% (99.7% steady-state) |
| Cached `ExchangeSubjectJWT` (1h K8s SA tokens) | ~19,500 req/s | 0.02 ms | 6.7 ms | >92% (99.97% steady-state) |
| Cached `MintBorderJWT` (15m task Biscuits) | ~1,980 req/s | 0.002 ms | 54.7 ms | >92% |
