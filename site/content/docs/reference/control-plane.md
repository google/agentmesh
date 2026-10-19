---
title: "agentmesh-control-plane"
linkTitle: "agentmesh-control-plane"
weight: 2
aliases:
  - /docs/user/control-plane-configuration/
---

`agentmesh-control-plane` admits nodes, mints credentials, holds the mesh policy
and tracks routers. It is an HTTP server over SQLite or PostgreSQL.

```text
agentmesh-control-plane [flags]                     run the server
agentmesh-control-plane admin ban   --peer <id>     ban a node directly in the database
agentmesh-control-plane admin unban --peer <id>     lift a ban
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--issuer` | | OIDC issuer URL(s), repeatable or comma-separated. At least one of `--issuer` or `--workload-issuer` is required. The first issuer is advertised to enrolling nodes on `/info`. |
| `--workload-issuer` | | Workload OIDC issuer(s), repeatable or comma-separated (`<issuer>` or `<issuer>=<email-suffix>`, such as `https://accounts.google.com=.gserviceaccount.com`). Automatically added to `--issuer`. Workload tokens can enroll, refresh, and exchange credentials (`/register`, `/refresh`, `/token/exchange`), and are refused at `/user/*` and `/oauth/authorize`. A workload issuer that does not answer its discovery document at start-up does not stop the control plane: it keeps retrying in the background (backoff up to 5 minutes), refuses tokens from that issuer with `401` and a message naming it until it does, and reports it as `agentmesh_control_plane_workload_issuer_ready{issuer}` = 0. An `--issuer` that does not answer is still fatal. |
| `--allowed-audiences` | `agentmesh-audience` | Audiences accepted in OIDC tokens, comma-separated. |
| `--oidc-client-id` | first audience | OAuth client ID advertised on `/info`, for providers where it differs from the audience. |
| `--insecure-skip-tls-verify` | `false` | Skip TLS verification when fetching issuer metadata and keys. For a cluster issuer served with the cluster CA, or a local development issuer. |
| `--bind-address` | `0.0.0.0:8080` | HTTP listen address. |
| `--pprof-addr` | off | Serve Go runtime profiles under `/debug/pprof/` on this address. Unauthenticated, and a heap profile is a dump of process memory, which holds the signing keys and the admin token: bind it to loopback, never to the API address. |
| `--db-driver` | `sqlite` | `sqlite` or `postgres`. |
| `--db-dsn` | `control-plane.db` | Database DSN. A PostgreSQL DSN contains a password, so the next two options are preferred for PostgreSQL. |
| `--db-dsn-path` | | File containing the DSN. Overrides `--db-dsn`. Can also be set with `AGENTMESH_DB_DSN`. |
| `--admin-token-path` | | File containing the bearer token for `/admin/*` and `POST /policies`. Can also be set with `AGENTMESH_ADMIN_TOKEN`. Without a token, the admin API cannot be used. |
| `--auto-approve-enrollment` | `false` | Issue credentials for valid bootstrap-token enrollments immediately instead of queueing them for approval. |
| `--biscuit-ttl` | `24h` | Lifetime of each credential. If the OIDC token expires sooner, the credential expires with it. |
| `--oidc-session-ttl` | `2160h` (90 days) | How long a human OIDC enrollment may keep refreshing before the identity must log in again. |
| `--signing-key-path` | | PEM file with the control plane's private signing keys (PKCS#8 or SEC 1): Ed25519 for Biscuits, P-256 for the ES256 JWTs behind `/sts/token` and `/jwks`. At least one key of each kind is required. The first key of each kind signs, later ones verify for as long as they are listed; a key the control plane generated earlier, or one dropped from the file, stays valid for `--key-grace-period`. Verifiers learn the set from `/keys` and `/jwks` as after any rotation. Turns automatic rotation off; the file is re-read every 30s, so rotation is publishing a new first key and keeping the previous one until every credential it signed has expired. `agentmesh_control_plane_operator_signing_keys{algorithm}` counts the keys loaded. |
| `--workload-session-ttl` | `48h` | How long a workload OIDC enrollment (`--workload-issuer`) may refresh without presenting a fresh platform JWT in `TokenRefreshRequest.jwt`. |
| `--key-rotation-interval` | `24h` | How often a new signing key is generated. `0` means the default, `24h`. To turn rotation off, use `--signing-key-path`. |
| `--key-grace-period` | `1h` | How long a rotated-out key stays accepted. Credentials signed by a retired key cannot be verified or refreshed. Nodes and routers must pull `/keys` well within this window (`agentmesh-node --control-plane-sync-interval`, `agentmesh-router --control-plane-sync-interval`). |
| `--lease-duration` | `15m` | How long a router lease lasts without renewal. |
| `--dht-replication` | `3` | How many routers each record a member announces is placed on: the router it announced to keeps it, and places a copy on this many routers closest to the key. A record on three routers survives two of them down at once; each replica more is a copy more of every record. Members are not concerned: they ask the routers they hold. Published on `/info`; every router of the mesh runs on it. |
| `--dht-reprovide-interval` | `5m` | How often a member re-announces each service it publishes. A provider that stopped without unpublishing stays listed for three intervals, which is how long routers keep a record after its last announcement; the mesh pays its providers divided by the interval in announcements a minute. Published on `/info`. |
| `--node-retention` | `720h` (30 days) | How long the record of an enrolled node is kept after its session expires, or, for a node enrolled with a bootstrap token, after its last refresh. Banned nodes are kept forever. Must be positive; records are never kept forever. |
| `--ephemeral-node-retention` | `1h` | `--node-retention` for a node enrolled with an ephemeral bootstrap token (`BootstrapTokenCreateRequest.ephemeral`): how long after its last refresh its record is kept. For members that come and go: a fleet in a scale test, a probe, a CI job. |
| `--mesh-reconnect-interval` | `30s` | How often the event publisher re-reads the router leases and dials any router it is not connected to. On each router it runs the mesh handshake with a credential it mints for its own peer under the signing key, with the role `mesh:role:control-plane`, so the router holds its connection as a member's. |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`. |
| `--log-format` | `text` | `text` or `json`. |

## HTTP API

Every request and response is a message in `api/agentmesh.proto`, in one of two
encodings. Routes that mesh components call use binary protobuf
(`application/x-protobuf`). Routes for operators and the console use
protojson of the same messages, with proto field names; unknown fields are
rejected. `POST /policies` accepts either and answers in the encoding of the
request.

Responses that carry credentials are sent with `Cache-Control: no-store`.

### Unauthenticated

| Route | Purpose |
|---|---|
| `GET /healthz` | Liveness. |
| `GET /readyz` | Readiness. Returns `503` when the database is unreachable. |
| `GET /metrics` | Prometheus metrics. |
| `GET /info` | `ControlPlaneInfoResponse`: the OIDC issuer, client ID and audience, the routers with live leases (`routers`: peer ID, addresses, the labels attested at the router's enrollment, and its connections against its limit as of its last lease; `router_addresses` is the same routers flattened), the list of banned peer IDs, and the directory parameters of the mesh (`directory`: `replication`, `reprovide_interval`, and the `record_ttl` derived from them). This is what a node needs before it can enroll, what it chooses its routers from, and what it runs its DHT on. |
| `GET /keys` | The current set of signing public keys, signed by every key in the set. A caller accepts the set only if one signature verifies under a key it already trusts. |
| `GET /.well-known/openid-configuration`, `GET /.well-known/oauth-authorization-server` | OIDC Discovery and OAuth 2.1 Authorization Server metadata for outbound STS federation and MCP OAuth 2.1 clients. |
| `GET /jwks` | JSON Web Key Set (`ES256` public keys) for verifying border JWTs minted by `POST /sts/token`. |
| `GET /oauth/authorize`, `POST /oauth/token` | OAuth 2.1 Authorization Code + PKCE endpoints (honouring RFC 8707 `resource` indicators to scope the issued Task Biscuit). Tokens from `--workload-issuer` are refused at `/oauth/authorize` with `403`. |

### Enrollment, refresh, and STS

Every request below carries a `challenge_unix_ms` and a `challenge_signature`.
The enrollee signs `mesh:<endpoint>:<peer_id>:<challenge_unix_ms>` with its
key, and the control plane accepts the signature within five minutes of that
instant. This proves that the caller holds the key behind the peer ID it
names. Every instant in a response (`expire_time` and the like) is a
`google.protobuf.Timestamp`, an RFC 3339 string in JSON.

Enrollment is admitted at 10 requests a second for the whole mesh, with a
burst of 20. A request over that is answered `429` with a `Retry-After`
header. `agentmesh-node` waits for it and sends the request again, with
jitter, for up to three minutes before it reports the failure, so a fleet of
up to about 1500 members that starts at once joins over its first minutes
instead of losing the members the limiter turned away. A larger fleet starts
in waves; the [scalability guide](../../guides/scalability/) has the
arithmetic. A client of your own should retry the same way.

| Route | Body | Purpose |
|---|---|---|
| `POST /register` | `EnrollRequest` (OIDC token, public key, requested role, labels) | OIDC enrollment. Returns `EnrollResponse`: the credential, the control plane public key, router addresses and expiry. |
| `POST /enroll` | `BootstrapEnrollRequest` (bootstrap token, public key, requested role, labels) | Bootstrap enrollment. Returns `BootstrapEnrollResponse` with status `APPROVED` and the credential, or with status `PENDING`. For a peer that is already approved, a new credential is minted directly. |
| `GET /enroll/status?peer_id=` | headers `X-Mesh-Challenge-Ts`, `X-Mesh-Challenge-Sig` | Poll a pending enrollment. Any authentication failure answers `401`, so the credential is released only to the enrollee. |
| `POST /refresh` | `TokenRefreshRequest` (optional `jwt`), current credential as `Authorization: Bearer <base64>` | Exchange a credential for a new one. When `jwt` is present and its `iss|sub` matches the enrolled node record, re-attests the node in place, updates stored claims and extends the session. Refuses a replayed (superseded) credential, a banned node, an expired session without a matching `jwt`, and a credential signed by a retired key unless the node has `autonomous_recovery`. |
| `POST /token/exchange` | `TokenExchangeRequest` (`subject_token`, optional `task_rule` and `seal`, challenge signature), node credential as bearer | Stateless JWT-to-Biscuit exchange. Mints a Delegated Session Biscuit bound to the calling node (`actor_node`, `client_peer_id`) with zero database writes. |
| `POST /sts/token` | `STSTokenRequest` (`biscuit`, `destination`, optional `audience`, challenge signature), node credential as bearer | Stateless Biscuit-to-JWT minting. Verifies the Biscuit and `tar_block` chain against `egress://<destination>` and mints a short-lived ES256 border JWT (`sub`, `act.sub`, `aud`, `mesh_roles`, `mesh_task`). |
| `GET /revocations` | credential as `Authorization: Bearer <base64>` | `RevocationsResponse`: revoked root Biscuit revocation IDs (`revocation_ids`) and banned peer IDs (`banned_peer_ids`). |
| `POST /routers/lease` | `RouterLeaseRequest` (credential, addresses, telemetry: connected peers, DHT size, open connections against the connection limit) | Register or renew a router lease. Requires `role("mesh:role:router")`. Announced addresses must end in the router's own peer ID. The load is what `/info` lists for the router. |
| `GET /policies` | credential as `Authorization: Bearer <base64>` | The mesh policy as `PolicyConfigGetResponse`: the Datalog rules a member adds to its authorizer, one per entry. Operators read the document at `GET /admin/policy`. |
| `GET /egress` | credential as `Authorization: Bearer <base64>` | `EgressAssignmentsResponse`: the [egress destinations](../policy/#egress-destinations) whose `served_by` selects the calling node, by its roles or labels. A node registers and serves what it receives here. |
| `POST /nodes/catalog` | `NodeCatalogReport`, credential as bearer | A node's report of the services it publishes, for the console. Display only. Never used for authorization. |

### Admin

All routes require `Authorization: Bearer <admin-token>`. Request and
response bodies are protojson of the messages named below, with proto field
names; unknown fields are rejected.

| Route | Purpose |
|---|---|
| `GET /admin/status` | `AdminStatusResponse`: everything the console shows: routers, nodes, enrollment requests, tokens, users, the policy and the node service catalog. Nodes whose session expired are left out; `GET /user/nodes?state=expired` lists them. |
| `GET /admin/policy` | The mesh policy as `PolicyConfig`, the same document `POST /policies` takes. |
| `POST /policies`, `PUT /policies` | Replace the mesh policy. The body is `PolicyConfig`, so a misspelt grant fails instead of being dropped. |
| `GET /admin/bootstrap-tokens` | `BootstrapTokenListResponse`: every token, including revoked and expired ones. |
| `POST /admin/bootstrap-tokens` | Mint a token. Body `BootstrapTokenCreateRequest`: `role` (required), `ttl_hours` (default 24), `max_usages` (default 1), `description`, `autonomous_recovery` (default false), `ephemeral` (default false: nodes enrolled with the token are kept for `--ephemeral-node-retention` after their last refresh instead of `--node-retention`). Returns `201` with `BootstrapTokenCreateResponse`: `id`, `token` (shown once), `role`, `expire_time`. |
| `DELETE /admin/bootstrap-tokens/{id}` | Revoke a token. Can be repeated. The token stays in the list with `revoke_time` set. |
| `GET /admin/enrollments` | `EnrollmentRequestListResponse`: bootstrap enrollment requests, pending and decided. |
| `POST /admin/enrollments/{id}/approve` | Approve. Spends a token usage. Checks the token again, and checks the labels against the role's `allowed_labels`. |
| `POST /admin/enrollments/{id}/reject` | Reject. |
| `POST /admin/revoke` | Body `{"peer_id": "..."}`. Ban the node and, for an OIDC enrollment, the identity behind it. |
| `POST /admin/nodes/{peer_id}/unban` | Lift both bans. |
| `POST /admin/nodes/{peer_id}/autonomous-recovery` | Body `{"enabled": true}`. Toggle the flag on an enrolled node. |

### User

For a human OIDC user acting on their own nodes, authenticated with an ID token
from a configured human issuer (tokens matching `--workload-issuer` are refused
with `403`). The console uses these routes.

| Route | Purpose |
|---|---|
| `GET /user/status` | `UserStatusResponse`: the caller, their enrolled nodes and tokens. For an administrator it also carries the routers and the policy. Nodes whose session expired are left out. |
| `GET /user/nodes` | `NodeListResponse`: one page of enrolled nodes, most recent enrollment first. `state` (`admitted`, `expired` or `banned`, repeatable) and `role` narrow the list. An expired OIDC enrollment can renew in place, so the console pages `state=expired` to keep those nodes revocable. An administrator sees every owner's nodes and may pick one with `owner_id`; a user sees only their own. Query `page_size` (default 50, at most 200) and `page_token`, the `next_page_token` of the previous page. |
| `POST /user/bootstrap-tokens` | Mint a token owned by the caller; body and response as on the admin route. `role` defaults to `mesh:role:node`. Banning the owner disables the tokens they minted. |
| `POST /user/revoke` | Ban one of the caller's own nodes. |

## Notes

- **A new control plane grants nothing.** With no policy in the database,
  enrollment succeeds only for identities bound to the requested role, and
  with no bindings there are none. A policy must be posted first.
- **Bootstrap tokens are spent atomically.** `max_usages` holds under
  concurrent enrollments, and a pending request is resolved exactly once.
- **An approved peer that enrolls again gets a new credential without
  approval**, as long as the token is valid, the role matches the record and
  the peer is not banned. This is how a bootstrap node recovers from a
  retired signing key.
- **Bans propagate in two ways.** `/info` lists banned peer IDs for nodes and
  routers that start or restart. A signed mesh event reaches the ones that
  are already running.
- **The rotation deadline is in the database.** The first rotation is due
  one `--key-rotation-interval` after the first start, each rotation sets
  the next, and every replica checks the deadline at least once a minute.
  A control plane that restarts more often than it rotates still rotates on
  time, and one that was down when a rotation was due rotates on its first
  check. `agentmesh_control_plane_next_key_rotation_timestamp_seconds` is
  the deadline; a value in the past is a rotation that is not happening.
- **Node records are garbage-collected.** A node whose session has expired is
  deleted after `--node-retention`. A node enrolled with a bootstrap token
  has no session; its record is deleted once it has not refreshed its
  credential for `--node-retention`, or for `--ephemeral-node-retention`
  when the token was ephemeral, and a node that comes back after that
  enrolls again. A node without a persistent data directory enrolls a new
  identity on every restart, so without this the node table would only grow.
  `agentmesh_control_plane_nodes_deleted_total{reason}` counts the deletions:
  `session`, `silent`, `ephemeral`.
- **The records around an enrollment are garbage-collected with it.** The
  same sweep deletes enrollment requests resolved, or left pending, for
  `--node-retention` (for `--ephemeral-node-retention` when an ephemeral
  token made them), bootstrap tokens that expired `--node-retention` ago and
  that no remaining request refers to, and router leases that expired
  `--node-retention` ago. It also drops the service report held in memory
  for every node that is no longer admitted.
  `agentmesh_control_plane_storage_rows_deleted_total{table}` counts these
  deletions; `agentmesh_control_plane_storage_rows{table}` is the size of
  each table, and a table that keeps growing past its retention is a sweep
  that is failing, which the log says.

## Metrics

`/metrics` exposes `agentmesh_control_plane_*` counters and gauges: enrolled nodes
by role and state, active routers, mesh-connected peers as reported by
router leases, rows per store table, service reports held in memory,
per-route request counts and latencies, and the Go runtime.

A member whose request on a mesh endpoint (`/policies`, `/egress`,
`/revocations`, `/token/exchange`, `/sts/token`, ...) is answered 401 is
counted in `agentmesh_control_plane_member_auth_refusals_total{reason}` and
logged with the same reason: `malformed` (not a base64 credential),
`invalid_biscuit` (not signed by a key this control plane trusts, or
expired), `unknown_node` (the credential verifies but the store has no
enrollment record for the node: the store was reset, or the node was
removed), `banned`, `session_expired`. `unknown_node` is the one to look
at after a control plane restart on an empty store: every node then
refused is a node that needs a bootstrap token
(`--bootstrap-token-path`) to enroll again on its own.
