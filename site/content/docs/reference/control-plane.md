---
title: "sam-control-plane"
linkTitle: "sam-control-plane"
weight: 2
aliases:
  - /docs/user/control-plane-configuration/
---

`sam-control-plane` admits nodes, mints credentials, holds the mesh policy
and tracks routers. It is an HTTP server over SQLite or PostgreSQL.

```text
sam-control-plane [flags]                     run the server
sam-control-plane admin ban   --peer <id>     ban a node directly in the database
sam-control-plane admin unban --peer <id>     lift a ban
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--issuer` | required | OIDC issuer URL(s), comma-separated. The first is advertised to enrolling nodes on `/info`. Can also be set with `SAM_OIDC_ISSUER`. |
| `--allowed-audiences` | `sam-mesh-audience` | Audiences accepted in OIDC tokens, comma-separated. |
| `--oidc-client-id` | first audience | OAuth client ID advertised on `/info`, for providers where it differs from the audience. |
| `--insecure-skip-tls-verify` | `false` | Skip TLS verification when fetching issuer metadata and keys. For a cluster issuer served with the cluster CA, or a local development issuer. |
| `--bind-address` | `0.0.0.0:8080` | HTTP listen address. |
| `--db-driver` | `sqlite` | `sqlite` or `postgres`. |
| `--db-dsn` | `control-plane.db` | Database DSN. A PostgreSQL DSN contains a password, so the next two options are preferred for PostgreSQL. |
| `--db-dsn-path` | | File containing the DSN. Overrides `--db-dsn`. Can also be set with `SAM_DB_DSN`. |
| `--admin-token-path` | | File containing the bearer token for `/admin/*` and `POST /policies`. Can also be set with `SAM_ADMIN_TOKEN`. Without a token, the admin API cannot be used. |
| `--auto-approve-enrollment` | `false` | Issue credentials for valid bootstrap-token enrollments immediately instead of queueing them for approval. |
| `--biscuit-ttl` | `24h` | Lifetime of each credential. If the OIDC token expires sooner, the credential expires with it. |
| `--oidc-session-ttl` | `2160h` (90 days) | How long an OIDC enrollment may keep refreshing before the identity must log in again. |
| `--key-rotation-interval` | `24h` | How often a new signing key is generated. `0` disables rotation. |
| `--key-grace-period` | `1h` | How long a rotated-out key stays accepted. Credentials signed by a retired key cannot be verified or refreshed. Nodes and routers must pull `/keys` well within this window (`sam-node --control-plane-sync-interval`, `sam-router --keys-sync-interval`). |
| `--lease-duration` | `15m` | How long a router lease lasts without renewal. |
| `--node-retention` | `720h` (30 days) | How long the record of an enrolled node is kept after its session expires. Banned nodes are kept forever. `0` keeps every record. |
| `--mesh-reconnect-interval` | `30s` | How often the event publisher re-reads the router leases and dials any router it is not connected to. |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`. `LOG_FORMAT=json` selects JSON output. |

## HTTP API

Every request and response is a message in `api/sam.proto`, in one of two
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
| `GET /info` | `ControlPlaneInfoResponse`: the OIDC issuer, client ID and audience, the addresses of routers with live leases, and the list of banned peer IDs. This is what a node needs before it can enroll. |
| `GET /keys` | The current set of signing public keys, signed by every key in the set. A caller accepts the set only if one signature verifies under a key it already trusts. |
| `GET /.well-known/openid-configuration`, `GET /.well-known/oauth-authorization-server` | OIDC Discovery and OAuth 2.1 Authorization Server metadata for outbound STS federation and MCP OAuth 2.1 clients. |
| `GET /jwks` | JSON Web Key Set (`ES256` public keys) for verifying border JWTs minted by `POST /sts/token`. |
| `GET /oauth/authorize`, `POST /oauth/token` | OAuth 2.1 Authorization Code + PKCE endpoints (honouring RFC 8707 `resource` indicators to scope the issued Task Biscuit). |

### Enrollment, refresh, and STS

Every request below carries a `challenge_unix_ms` and a `challenge_signature`.
The enrollee signs `sam:<endpoint>:<peer_id>:<challenge_unix_ms>` with its
key, and the control plane accepts the signature within five minutes of that
instant. This proves that the caller holds the key behind the peer ID it
names. Every instant in a response (`expire_time` and the like) is a
`google.protobuf.Timestamp`, an RFC 3339 string in JSON.

| Route | Body | Purpose |
|---|---|---|
| `POST /register` | `EnrollRequest` (OIDC token, public key, requested role, labels) | OIDC enrollment. Returns `EnrollResponse`: the credential, the control plane public key, router addresses and expiry. |
| `POST /enroll` | `BootstrapEnrollRequest` (bootstrap token, public key, requested role, labels) | Bootstrap enrollment. Returns `BootstrapEnrollResponse` with status `APPROVED` and the credential, or with status `PENDING`. For a peer that is already approved, a new credential is minted directly. |
| `GET /enroll/status?peer_id=` | headers `X-Sam-Challenge-Ts`, `X-Sam-Challenge-Sig` | Poll a pending enrollment. Any authentication failure answers `401`, so the credential is released only to the enrollee. |
| `POST /refresh` | `TokenRefreshRequest`, current credential as `Authorization: Bearer <base64>` | Exchange a credential for a new one. Refuses a replayed (superseded) credential, a banned node, an expired session, and a credential signed by a retired key unless the node has `autonomous_recovery`. |
| `POST /token/exchange` | `TokenExchangeRequest` (`subject_token`, optional `task_rule` and `seal`, challenge signature), node credential as bearer | Stateless JWT-to-Biscuit exchange. Mints a Delegated Session Biscuit bound to the calling node (`actor_node`, `client_peer_id`) with zero database writes. |
| `POST /sts/token` | `STSTokenRequest` (`biscuit`, `destination`, optional `audience`, challenge signature), node credential as bearer | Stateless Biscuit-to-JWT minting. Verifies the Biscuit and `tar_block` chain against `egress://<destination>` and mints a short-lived ES256 border JWT (`sub`, `act.sub`, `aud`, `sam_roles`, `sam_task`). |
| `GET /revocations` | credential as `Authorization: Bearer <base64>` | `RevocationsResponse`: revoked root Biscuit revocation IDs (`revocation_ids`) and banned peer IDs (`banned_peer_ids`). |
| `POST /routers/lease` | `RouterLeaseRequest` (credential, addresses, telemetry) | Register or renew a router lease. Requires `role("sam:role:router")`. Announced addresses must end in the router's own peer ID. |
| `GET /policies` | credential as `Authorization: Bearer <base64>` | The mesh policy as `PolicyConfigGetResponse`: the Datalog rules a member adds to its authorizer, one per entry. Operators read the document at `GET /admin/policy`. |
| `GET /egress` | credential as `Authorization: Bearer <base64>` | `EgressAssignmentsResponse`: the [egress destinations](../policy/#egress-destinations) whose `served_by` selects the calling node, by its roles or labels. A node registers and serves what it receives here. |
| `POST /nodes/catalog` | `NodeCatalogReport`, credential as bearer | A node's report of the services it publishes, for the console. Display only. Never used for authorization. |

### Admin

All routes require `Authorization: Bearer <admin-token>` and use JSON.

| Route | Purpose |
|---|---|
| `GET /admin/status` | Everything the console shows: routers, nodes, enrollment requests, tokens, users, and the policy as JSON. |
| `GET /admin/policy` | The mesh policy as protojson of `PolicyConfig`, the same document `POST /policies` takes. |
| `POST /policies`, `PUT /policies` | Replace the mesh policy. The JSON body is protojson of `PolicyConfig`. Unknown fields are rejected, so a misspelt grant fails instead of being dropped. |
| `POST /admin/bootstrap-tokens` | Mint a token. Body: `role` (required), `ttl_hours` (default 24), `max_usages` (default 1), `description`, `autonomous_recovery` (default false). Returns `201` with `id`, `token` (shown once), `role`, `expires_at`. |
| `DELETE /admin/bootstrap-tokens/{id}` | Revoke a token. Can be repeated. The token stays in the list, marked as revoked. |
| `GET /admin/enrollments` | Pending bootstrap enrollment requests. |
| `POST /admin/enrollments/{id}/approve` | Approve. Spends a token usage. Checks the token again, and checks the labels against the role's `allowed_labels`. |
| `POST /admin/enrollments/{id}/reject` | Reject. |
| `POST /admin/revoke` | Body `{"peer_id": "..."}`. Ban the node and, for an OIDC enrollment, the identity behind it. |
| `POST /admin/nodes/{peer_id}/unban` | Lift both bans. |
| `POST /admin/nodes/{peer_id}/autonomous-recovery` | Body `{"enabled": true}`. Toggle the flag on an enrolled node. |

### User

For an OIDC user acting on their own nodes, authenticated with an ID token
from the configured issuer. The console uses these routes.

| Route | Purpose |
|---|---|
| `GET /user/status` | The caller's enrolled nodes and tokens. |
| `POST /user/bootstrap-tokens` | Mint a token owned by the caller. `role` defaults to `sam:role:node`. Banning the owner disables the tokens they minted. |
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
- **Node records are garbage-collected.** A node whose session has expired is
  deleted after `--node-retention`. A node without a persistent data
  directory enrolls a new identity on every restart, so without this the
  node table would only grow.

## Metrics

`/metrics` exposes `sam_control_plane_*` counters and gauges: enrolled nodes
by role and state, active routers, mesh-connected peers as reported by
router leases, per-route request counts and latencies, and the Go runtime.
