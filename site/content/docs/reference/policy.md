---
title: "Mesh policy"
linkTitle: "Mesh policy"
weight: 6
aliases:
  - /docs/development/policy/
---

The mesh policy is one document held by the control plane: a list of roles,
a list of bindings and a list of egress destinations. It is posted as JSON
(protojson of `PolicyConfig` in `api/agentmesh.proto`) to `POST /policies`, read
back from `GET /admin/policy`, edited in the console, or given to
`agentmesh-one --policy-file` for first boot.

```json
{
  "roles": [
    {
      "name": "mesh:role:node",
      "allowed_services": ["system://mesh.catalog"],
      "allowed_publish": ["mcp://code-reviewer", "mcp://build-runner.*", "inference://*"],
      "allowed_labels": ["region=*", "team=platform"]
    },
    {
      "name": "developer",
      "allowed_services": ["mcp://code-reviewer", "mcp://build-runner.*", "inference://*"],
      "allowed_targets": ["group:dev-nodes", "node:12D3KooWSpecialNode"],
      "custom_datalog": ["tier(\"standard\");"]
    },
    {
      "name": "analyst",
      "allowed_services": ["egress://bigquery.googleapis.com"],
      "allowed_targets": ["*"],
      "http": [
        { "service": "egress://bigquery.googleapis.com", "methods": ["GET", "POST"], "paths": ["/bigquery/v2/projects/my-proj/datasets/*"] }
      ]
    }
  ],
  "bindings": [
    { "role": "mesh:role:node", "members": ["group:engineering", "user:system:serviceaccount:agentmesh-nodes:calc-mcp-agentmesh-node"] },
    { "role": "developer",     "members": ["group:engineering"] },
    { "role": "analyst",       "members": ["group:analytics"] }
  ],
  "egress": [
    {
      "name": "bigquery.googleapis.com",
      "served_by": ["site=eu"],
      "broker": {
        "oidc_federation": {
          "token_endpoint": "https://sts.googleapis.com/v1/token",
          "audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/agentmesh/providers/agentmesh-cp",
          "scopes": ["https://www.googleapis.com/auth/bigquery.readonly"]
        }
      }
    }
  ]
}
```

The whole document is replaced on every post. Unknown fields are rejected,
so a misspelt key fails the request instead of dropping a grant without
notice.

## Roles

| Field | Type | Meaning |
|---|---|---|
| `name` | string, required, unique | The role name. `mesh:role:node` and `mesh:role:router` are the roles that the two binaries request at enrollment. Any other name is an ordinary role. |
| `allowed_services` | list of service patterns | Services that holders may call. |
| `allowed_publish` | list of service patterns | Services that holders may serve. A router keeps a member's directory record only for a service its credential grants here, and a caller sends a request to a provider it reached by name only when the provider's credential does. If absent, holders may publish nothing. See [Publishing](#publishing). |
| `allowed_ingress` | list of ingress grants | Inbound services (`a2a`, `mcp`, `inference`, or `*`) that holders may expose on router HTTP ingress. Each entry has `services` (required) and optional `allowed_auth_modes` (`INGRESS_AUTH_MODE_EDGE`, `INGRESS_AUTH_MODE_PASSTHROUGH`; empty grants `EDGE` only). See the [external ingress guide](../../guides/external-ingress/). |
| `allowed_targets` | list of target patterns | Nodes that holders may call. `*` means any node. If absent, holders may call no node. |
| `allowed_labels` | list of label patterns | Labels that a node holding this role may declare at enrollment. If absent, no labels may be declared. |
| `custom_datalog` | list of Datalog statements | Facts are minted into the credentials of holders. Rules are distributed to nodes and applied when a holder is verified. |
| `http` | list of HTTP grants | Narrows an `allowed_services` entry to HTTP methods and paths. See [HTTP grants](#http-grants). |

### Service patterns

`type://name`. The types are `mcp`, `inference`, `a2a`, `egress` and
`system`. The control plane checks the form of an entry and not the type, so
a type outside this list passes too. `name` is dot-separated labels, each 1
to 63 characters of `[a-zA-Z0-9_-]` with no leading `-`. A `/path` after the
name is part of the name. For `egress` the name is the hostname of a
destination outside the mesh. It is lowercase, with no scheme, port or path.
The control plane rejects `egress://api.github.com/v3`, because the path
belongs in the role's `http` entry or a `TaskAuthorizationRule`. See
[Egress destinations](#egress-destinations).

| Pattern | Compiles to | Matches |
|---|---|---|
| `mcp://calculator` | `granted_service_set("mcp", ["calculator"])`. All exact entries of one type share one `granted_service_set` fact. | that service |
| `mcp://*.internal` | `granted_service_suffix("mcp", ".internal")` | `a.internal` and `b.c.internal`, but not `xinternal` |
| `mcp://build.*` | `granted_service_prefix("mcp", "build.")` | `build.runner`, but not `builder` |
| `mcp://*` | `granted_service_all("mcp")` | every MCP service |
| `*` | `granted_service_all_types(true)` | every service |

A fact whose only meaning is that a grant exists carries the single term
`true`, because the Biscuit grammar requires at least one term per predicate.
The same holds for `target_unrestricted(true)` below.

`system://mesh.catalog` is the built-in discovery service that every node
runs. A role that should be able to list the tools of a node needs it.

### Publishing

`allowed_publish` takes the same patterns and compiles them to
`granted_publish_*` facts: `granted_publish_set("mcp", ["calculator"])`,
`granted_publish_all("mcp")`, `granted_publish_all_types(true)` and so on.
They say what a member may serve, where `allowed_services` says what it may
call, and the two are independent: a role that may call `mcp://calc` may
not serve it unless granted here.

Two parties check the grant, on the holder's own credential. The router a
member announces a record to refuses a record for a service the grant does
not cover (`agentmesh_router_directory_requests_total{op="provide",result="denied"}`),
so a member cannot put itself in the directory under a name it may not
serve. A caller that reaches a provider by name, from the directory or by
peer ID, verifies the provider's credential before sending the request and
refuses a provider the grant does not cover, so a record that reached the
directory some other way is still not called. `agentmesh-node` and both
SDKs make the check; a member's own record under its peer ID, and a node's
catalog (`system://mesh.catalog`), name no service and need no grant.

An egress destination needs no entry: `served_by` selects the nodes that
serve it, and the control plane mints `granted_publish_set("egress", ["<name>"])`
into their credentials with the destination.

A change to `allowed_publish` takes effect without a new credential. The
grant is also rendered into the policy text as
`granted_publish_*(...) <- role("<role>")` (and `<- label(...)` for
`served_by`), and every verifier adds that text to its authorizer: the
router at its next `--control-plane-sync-interval` pass, a node and an SDK
member at their next sync, all of them at once on the `POLICY_UPDATE` event
the control plane publishes. A node whose policy text changed announces its
services again, so a record the router refused under the previous policy is
in the directory within the sync interval; until then the router answers
`credential does not grant serving <service>`, which the node logs.

### Target patterns

`fact:value`, where `fact` is one of the identity facts that a node's
credential can carry: `node` (peer ID), `user`, `email`, `group`,
`idp_role`. The values come from the destination node's own credential, so
`group:dev-nodes` means "nodes whose enrolling identity is in group
`dev-nodes`".

| Pattern | Matches |
|---|---|
| `node:12D3KooW...` | one node |
| `group:dev-nodes` | nodes enrolled by a member of that group |
| `email:*.acme.example` | suffix match on the email of the enrolling identity |
| `group:*` | any node with a `group` fact |
| `*` | any node |

Exact entries of one fact are merged into one `granted_target_set` fact.

### Label patterns

| Pattern | Permits |
|---|---|
| `key=value` | exactly that pair |
| `key=*` | any value for that key |
| `*` | any label |

Keys match `[a-zA-Z0-9_.-]{1,63}`. Values are up to 255 characters with no
`,`, `=`, `"`, `\` or control characters. Every label that a node declares
must be permitted by a role it holds, or enrollment fails. Manual approval of a
bootstrap enrollment does not bypass this check.

### HTTP grants

An entry of `http` narrows one `allowed_services` entry of the same role to
HTTP methods and paths. The service must be written exactly as it appears in
`allowed_services`; at least one of `methods` and `paths` must be set.

| Field | Meaning |
|---|---|
| `service` | The `allowed_services` entry this narrows. |
| `methods` | Methods the holder may use, uppercase, such as `GET`. Empty means any method. |
| `paths` | Paths the holder may request, as the backend sees them. `/user` matches that path only; `/v2/public/*` matches every path under the prefix. Empty means any path. |

```json
{ "service": "egress://api.github.com", "methods": ["GET", "HEAD"], "paths": ["/repos/acme/*", "/user"] }
```

The control plane compiles the entry into facts in the holder's credential
and withholds the plain service grant for that entry:

```datalog
http_granted_service_exact("egress", "api.github.com")
granted_method("egress", "api.github.com", ["GET", "HEAD"])
granted_path_prefix("egress", "api.github.com", "/repos/acme/")
granted_path_exact("egress", "api.github.com", ["/user"])
```

Baseline rules on every node derive `granted_service_exact("egress",
"api.github.com")` from these facts only when the request's `method()` and
`path()` facts satisfy them. The ordinary allow policies then decide as they
do for any grant. The rules are positive, so a request that carries no HTTP
method (a tunnel, a non-HTTP stream) derives nothing and a narrowed grant
denies it. A role that holds the same service plainly, through another
entry or another role, is not narrowed: grants are a union.

### `custom_datalog`

Each entry is one Biscuit Datalog fact or rule. A **fact**
(`tier("standard");`) is minted into the credential of every holder, where
`attenuation` statements on any node can refer to it. A **rule**
(`head($x) <- body($x);`) is compiled into the node-side rule set and
applied when a holder is verified. `allow` and `deny` policies are not
accepted here. They belong in a node's `attenuation.policies`. An entry that
parses as neither a fact nor a rule fails validation.

## Bindings

| Field | Meaning |
|---|---|
| `role` | A role name from `roles`. A binding to an undefined role is rejected. |
| `members` | Identities that receive the role. At least one is required. |

A member is one of:

| Member | Matches |
|---|---|
| `user:<sub>` | the OIDC subject. For a Kubernetes service account: `user:system:serviceaccount:<namespace>:<name>`. For a SPIFFE workload: `user:spiffe://<trust-domain>/<path>`. |
| `email:<address>` | a verified email claim |
| `group:<name>` | an entry of the `groups` claim |
| `idp_role:<name>` | an entry of the issuer's `roles` claim |
| `node:<peer-id>` | one node, by key (exact peer ID only; wildcards are not permitted on `node:`) |
| `mesh:system:authenticated` | every holder of a valid credential, including members enrolled with a bootstrap token and delegated sessions |

Each claim-backed member (`user:`, `email:`, `group:`, `idp_role:`) may carry
a single trailing `*` (prefix match, compiled to `$v.starts_with("<prefix>")`)
or a single leading `*` (suffix match, compiled to `$v.ends_with("<suffix>")`),
for example:

- `user:system:serviceaccount:agentmesh-nodes:*`
- `user:spiffe://acme.example/ns/prod/*`
- `email:*@my-project.iam.gserviceaccount.com`

Bare `<prefix>:*` (such as `user:*` or `email:*`) and interior wildcards
(`a*b`) are rejected; use `mesh:system:authenticated` when any authenticated
identity is intended. Role names and binding member values may contain spaces
and UTF-8 (for example `group:Engineering Team`), and may not contain `"`,
`\`, or control characters.

`role:` is not a member, because a role cannot grant a role. A bootstrap
token enrollment carries no OIDC claims. Such a node receives the token's
role and the roles bound to `mesh:system:authenticated` or to its
`node:<peer-id>`. A binding on claims adds nothing to such a node.

## Egress destinations

An entry of `egress` is a destination outside the mesh that selected nodes
serve as `egress://<name>`. The admin writes it once; each selected node
receives it at `GET /egress`, registers the service, announces it to the
directory and forwards requests to it. Nodes hold no egress configuration of
their own, and `type: egress` in `agentmesh-node.yaml` is refused.

| Field | Meaning |
|---|---|
| `name` | Required and unique in the policy. The destination hostname, lowercase, without a port or a path. It is the service name in grants (`egress://<name>`) and in the `service()` fact. One hostname; no wildcard. |
| `target_url` | Where the serving node forwards HTTP requests. Optional; `https://<name>` when empty. `http` or `https`, no credential, no query. |
| `served_by` | Role names or `key=value` labels selecting the serving nodes. At least one entry is required. A node matches when any entry names one of its roles or attested labels. |
| `credential` | Shorthand for `broker.static_secret`: name of a file in `<--secrets-dir>/<credential>`. Cannot be combined with `broker`, unless `broker.static_secret` names the same file. |
| `broker` | `CredentialBroker` configuring how the egress node obtains the upstream credential. See [Credential brokers](#credential-brokers). |
| `inspection` | `Inspection` pipeline executed at the egress node before the upstream credential is injected. See [Content inspection](#content-inspection). |
| `mode` | `EGRESS_MODE_HTTP` (default) or `EGRESS_MODE_TCP` (named `CONNECT` tunnel). |
| `ports` | Allowed TCP destination ports when `mode` is `EGRESS_MODE_TCP` (for example, `[5432]`). Required in that mode. Each port is from 1 to 65535. |
| `preserve_host` | Keep the destination hostname (`name`) in the `Host` header when `target_url` points at an operator inspection chain. |
| `forward_context` | Forward `X-Mesh-Principal`, `X-Mesh-Roles` and `X-Mesh-Task` to `target_url` when `target_url` is an operator inspection chain. |

### Credential brokers

None of the fields in `broker` is a secret value:

- **`static_secret`** (`string`): name of a file in the node's `--secrets-dir`
  (default `/etc/agentmesh/secrets`). `TOKEN` is sent as `Authorization: Bearer TOKEN`,
  `user:pass` as HTTP Basic. Read on every request so file rotations apply
  immediately.
- **`oidc_federation`** (`OIDCFederation`): mints a short-lived ES256 border
  JWT at the control plane (`POST /sts/token`) and exchanges it at an RFC 8693
  token endpoint:
  - `token_endpoint`: STS URL (for example, `https://sts.googleapis.com/v1/token`).
  - `audience`: required. Provider audience (for example, a Google Workload or
    Workforce Identity Pool provider resource name).
  - `impersonate`: optional Google Cloud service account email or resource URL
    for `iamcredentials.generateAccessToken`.
  - `scopes`: OAuth scopes requested for the upstream token; a
    `TaskAuthorizationRule` can narrow them further, never widen them.
- **`aws_assume_role`** (`AWSAssumeRole`): mints a border JWT at the control
  plane and calls AWS STS `AssumeRoleWithWebIdentity`:
  - `role_arn`: required. IAM role ARN to assume.
  - `session_policy`: optional IAM session policy JSON template intersected with
    the caller's `TaskAuthorizationRule` (`allowed_permissions` $\rightarrow$
    `Action`, `allowed_resources` $\rightarrow$ `Resource`).
- **`platform_identity`** (`PlatformIdentity`): uses the egress node's own
  ambient cloud identity (such as the GCE/GKE metadata server) narrowed by
  `scopes`.

### Content inspection

`inspection.inspectors` runs in order before the broker injects the upstream
credential:

- **`model_armor`**: calls Google Cloud Model Armor `sanitizeUserPrompt` and
  (when `response` is `RESPONSE_INSPECTION_BUFFERED`) `sanitizeModelResponse`
  for Gemini, OpenAI chat, MCP `tools/call`, and A2A payloads:
  - `template`: required. `projects/<P>/locations/<L>/templates/<T>`.
  - `response`: `RESPONSE_INSPECTION_BUFFERED` (default) or
    `RESPONSE_INSPECTION_REQUEST_ONLY`.
  - `fail_open`: default `false`.
  - `timeout`: per-call timeout (`google.protobuf.Duration`).
- **`ext_proc`**: streams the request and response to an Envoy external
  processor (`envoy.service.ext_proc.v3.ExternalProcessor`) over HTTP/2 gRPC:
  - `target`: required. `host:port` or `unix:/path/to.sock`.
  - `ca`, `client_certificate`: optional file names in `--secrets-dir` for TLS /
    mTLS to the processor.
  - `processing_mode`: `request_header_mode`, `response_header_mode`,
    `request_body_mode`, `response_body_mode`, `request_trailer_mode`,
    `response_trailer_mode`.
  - `allow_mode_override`, `message_timeout` (default `200ms`),
    `failure_mode_allow` (default `false`), `max_buffered_bytes`.

## Task-scoped attenuation (`TaskAuthorizationRule`)

Holders narrow a Biscuit for a task or sub-agent hop by appending a block with
a single `tar_block("<base64url-proto>")` fact encoding `TaskAuthorizationRule`:

```json
{
  "name": "tasks/bq-read-sales",
  "expire_time": "2026-10-05T12:00:00Z",
  "rules": [
    {
      "allowed_services": ["egress://bigquery.googleapis.com"],
      "operation": {
        "allowed_methods": ["GET", "POST"],
        "allowed_paths": ["/bigquery/v2/projects/my-proj/datasets/sales_2026/*"],
        "allowed_permissions": ["bigquery.googleapis.com/tables.getData"]
      },
      "allowed_resources": [
        "//bigquery.googleapis.com/projects/my-proj/datasets/sales_2026/*"
      ]
    }
  ]
}
```

Across appended blocks `1..k` (up to `MaxAttenuationBlocks = 8`), evaluation is
strict intersection: a request must pass Block 0 Datalog policy, be before
every block's `expire_time`, and match at least one `TaskRule` in every
appended `TaskAuthorizationRule` block.

## Evaluation

At enrollment, refresh, and token exchange, the control plane resolves the
identity's roles from the bindings and mints into the credential one `role()`
fact per role and the compiled `granted_*` facts of every role. The control
plane also renders the policy as Datalog rules served as `datalog_rules` at
`GET /policies`. Nodes, routers and SDK members fetch this text
(`--control-plane-sync-interval`, 15 minutes for a node, 5 for a router) and
add it to their authorizer as it arrives.

At the destination node, in this order:

1. Structural check on appended blocks (`1..k`): each must contain 0 rules, 0
   checks, and 1 `tar_block("<base64url-proto>")` fact.
2. Facts for the request: `service($type, $name)`, `connection_peer_id($id)`,
   `time($now)`. On an HTTP request, `method($m)` and `path($p)`; on an egress
   request, `host($h)` and `port($n)`.
3. Checks that always apply: `client_peer_id($id), connection_peer_id($id)` and
   `time($t), expiration($e), $t <= $e`.
4. The node's own identity as `target_fact($name, $value)` facts.
5. The node's `attenuation` rules, checks and policies.
6. Baseline policies and the synced mesh policy rules.
7. `TaskAuthorizationRule` intersection across all appended `tar_block` blocks.

## Datalog vocabulary

Every fact name used by Agent Mesh, for writing `custom_datalog` or `attenuation`
statements.

| Fact | Terms | Minted by |
|---|---|---|
| `node` | peer ID | control plane (Member Biscuits) |
| `actor_node` | peer ID | control plane (Delegated Session Biscuits) |
| `client_peer_id` | peer ID | control plane |
| `expiration` | date | control plane |
| `role` | name | control plane |
| `user`, `email`, `group`, `idp_role` | string | control plane, from OIDC claims |
| `label` | key, value | control plane |
| `right` | `relay` | control plane, for routers |
| `target_unrestricted` | `true` | control plane, for routers. Node rules, for a role with `allowed_targets: ["*"]`. The destination node, for a request from its local API to a service it serves itself. |
| `target_restricted` | `true` | node rules, for a role with an `allowed_targets` entry other than `*` |
| `granted_service_exact`, `_set`, `_prefix`, `_suffix`, `_all`, `_all_types` | type, name/set/pattern | control plane and node rules |
| `granted_publish_exact`, `_set`, `_prefix`, `_suffix`, `_all`, `_all_types` | type, name/set/pattern | control plane and node rules, from `allowed_publish` and `served_by` |
| `granted_target_exact`, `_set`, `_prefix`, `_suffix`, `_all`, `_all_facts` | fact, value/set/pattern | control plane and node rules |
| `http_granted_service_exact`, `_prefix`, `_suffix`, `_all`, `_all_types` | type, name/pattern | control plane and node rules, for an `http` entry |
| `granted_method` | type, key, set | control plane and node rules, for an `http` entry |
| `granted_path_exact`, `granted_path_prefix` | type, key, set/prefix | control plane and node rules, for an `http` entry |
| `granted_method_any`, `granted_path_any` | type, key | control plane and node rules, for an `http` entry with no `methods` or no `paths` |
| `tar_block` | base64url `TaskAuthorizationRule` | holder, in appended blocks `1..k` |
| `service` | type, name | destination node, per request |
| `publish` | type, name | the router before it keeps a directory record, and a caller before it sends to a provider reached by name |
| `connection_peer_id` | peer ID | destination node, per request |
| `time` | date | destination node, per request |
| `method` | string | destination node, on an HTTP request: the method as received; `CONNECT` on a tunnel |
| `path` | string | destination node, on an HTTP request: the path as the backend sees it, leading slash, no query; empty on a tunnel |
| `host` | hostname | destination node, on an egress request |
| `port` | integer | destination node, on an egress request |
| `target_fact` | fact, value | destination node, from its own credential |
| `allow_network_target` | fact, value | derived by baseline rules |
| `http_method_ok`, `http_path_ok` | type, key | derived by baseline rules |

A node's `attenuation` can refer to the request facts. The Datalog dialect
has no `!=`; a negation is written with `!`:

```yaml
attenuation:
  policies:
    - 'deny if method($m), !($m == "GET");'
    - 'deny if path($p), $p.starts_with("/admin/");'
    - 'deny if port($p), !($p == 443);'
    - 'deny if host("payroll.internal.example.com");'
```
