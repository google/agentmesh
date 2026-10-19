---
title: "Authorization"
linkTitle: "Authorization"
weight: 3
---

Authorization in Agent Mesh answers one question: may this caller perform this
operation on this service on this node right now? Four sources contribute to
the answer, and the destination node combines them:

1. **The caller's credential** (Block 0 authority facts signed by the control
   plane).
2. **The standing mesh policy** (roles, bindings, HTTP narrowings, and egress
   destinations distributed by the control plane as Datalog rules).
3. **Any appended `TaskAuthorizationRule` blocks (`tar_block`)** on the
   credential, which narrow authority for a specific task or sub-agent hop.
4. **The hosting node's local `attenuation` configuration**.

The credential and the standing policy say what the caller is granted. A
task block can only narrow those grants. The node's local
[`attenuation`](../../reference/node-config/#attenuation) can narrow them or
widen them, because its policies run before the baseline policies and the
first match wins. A local `deny` overrides a mesh grant. A local `allow`
admits a caller that the mesh did not grant. No layer admits a caller that
fails a check, such as the target check, or an appended task block.

## Services and task operations

A node publishes services, each with a type and a name: `mcp://calculator`,
`inference://vllm-eu`, `a2a://triage`, `egress://bigquery.googleapis.com`, and
the built-in `system://mesh.catalog` that answers discovery queries.

Standing mesh roles grant access to services by name (`allowed_services`),
grant the right to serve them (`allowed_publish`) and can narrow HTTP
methods and paths (`http`). On top of standing roles, a
holder can append `TaskAuthorizationRule` blocks (`tar_block`) to scope a
token for a single task or sub-agent hop—narrowing which services, MCP tools
(`operation.allowed_tools`), HTTP methods and paths
(`operation.allowed_methods`, `operation.allowed_paths`), and upstream cloud
IAM permissions and resources (`operation.allowed_permissions`,
`allowed_resources`) that token may use.

## Mesh policy: roles and bindings

The mesh policy is a document held by the control plane. You edit it through
`POST /policies` or the console. `agentmesh-one` can also seed it on first boot
from a file (`--policy-file`).

**Roles** name a set of standing permissions:

```json
{
  "name": "developer",
  "allowed_services": ["mcp://code-reviewer", "mcp://build-runner.*", "inference://*"],
  "allowed_publish": ["mcp://build-runner.*"],
  "allowed_targets": ["group:dev-nodes"],
  "allowed_labels": ["region=*"],
  "http": [
    { "service": "mcp://code-reviewer", "methods": ["POST"], "paths": ["/mcp"] }
  ],
  "custom_datalog": []
}
```

- `allowed_services`: the services holders may call, as `type://name`. `*`
  can stand for the whole name, for a leading component (`mcp://*.internal`)
  or for a trailing one (`mcp://build-runner.*`). A bare `*` means every
  service.
- `allowed_publish`: the services holders may serve, in the same syntax.
  A member announces a service to the directory, and is accepted as its
  provider by callers, only when its own credential grants it here. If
  absent, holders may publish nothing. Calling and serving are granted
  separately: a role that may call `mcp://calculator` does not serve it.
- `allowed_targets`: the nodes holders may call, as facts about the
  destination node's identity: `node:<peer-id>`, `user:<sub>`,
  `email:<addr>`, `group:<name>`, `idp_role:<name>`, or `*`. If absent,
  holders may call no node.
- `allowed_labels`: the labels a node with this role may declare at
  enrollment: `key=value`, `key=*` or `*`. If absent, the node may declare
  no labels.
- `http`: optional method and path restrictions for entries in
  `allowed_services`.
- `custom_datalog`: extra Datalog facts or rules for holders of the role.

**Bindings** attach roles to identities:

```json
{ "role": "developer", "members": ["group:eng", "email:alice@example.com"] }
```

A member is one of: `user:`, `email:`, `group:` or `idp_role:` followed by a
value from the identity's OIDC claims; `node:` followed by a peer ID; or the
special value `mesh:system:authenticated`, which matches every holder of a
valid credential. That includes members that enrolled with a bootstrap token
and delegated sessions, not only the identities that the identity provider
authenticates. Be careful with this member. On a public identity provider
it means everyone, so bind it only to roles with few grants.

Roles are never members and never claims. `role:x` is not a valid member,
and an identity provider cannot give out a mesh role by putting it in a
`roles` claim. Such a claim becomes an `idp_role` fact, and a binding can
choose to honour it. The two built-in roles, `mesh:role:node` and
`mesh:role:router`, follow the same rule. A binary that enrolls with an
OIDC identity gets the role only if a binding gives the role to that
identity. A binary that enrolls with a bootstrap token gets the token's
role without a binding.

The control plane validates a policy when it is posted. It rejects a policy
that references an undefined role, uses an unknown member prefix, or would
give a single identity more grants than the Biscuit authorizer can
evaluate.

## From policy to facts

At enrollment, refresh, and token exchange (`POST /token/exchange`), the
control plane resolves the identity's roles from the bindings and writes the
result into the credential's authority block as Datalog facts: one `role(...)`
fact per role, plus the grants compiled from the lists of every role. For
example, `allowed_services: ["mcp://calculator"]` becomes
`granted_service_set("mcp", ["calculator"])`, `mcp://*` becomes
`granted_service_all("mcp")`, and `mcp://*.internal` becomes
`granted_service_suffix("mcp", ".internal")`. Wildcards keep their dot, so
`*.acme.example` matches `svc.acme.example` but not `evil-acme.example`.

The control plane also renders the policy as Datalog rules such as
`role("developer") <- group("eng")` and
`granted_service_set("mcp", ["calculator"]) <- role("developer")`. Nodes
fetch this text every `--control-plane-sync-interval` (15 minutes by default,
sooner when a policy update event reaches them) and add it to their
authorizer as it arrives. When a node verifies a credential, these rules run
against the identity facts in it. A grant added to the policy therefore
reaches every node within the sync interval, with no need to reissue
credentials. Removing a grant takes effect through the credential instead:
the facts already in a token stay valid until the token is refreshed or
expires.

## What the hosting node checks

When a request for service `S` arrives from peer `P`, the node validates the
Biscuit structure and runs two enforcement stages:

### Stage 1: Standing Datalog policy (Block 0)

The node builds a Biscuit authorizer over Block 0 and adds, in this order:

1. **The request facts**: `service("mcp", "calculator")` for the requested
   service, and `connection_peer_id(P)` from the authenticated connection.
   When the node handles the request as HTTP it adds `method("GET")` and
   `path("/v1/models")`, the path as the backend will see it; for a
   destination outside the mesh (`egress://`) it adds `host(...)` and
   `port(...)`.
2. **The baseline checks**: `client_peer_id($id), connection_peer_id($id)`
   (the token belongs to the peer that presents it), and the expiration
   check against the current time.
3. **The node's own identity facts**, taken from its own credential, as
   `target_fact("group", "dev-nodes")` and similar. The caller's
   `allowed_targets` are matched against these facts.
4. **The node's local rules**, from the `attenuation` block of its
   configuration file: extra facts, extra checks, and `allow` and `deny`
   policies.
5. **The baseline policies**: `allow if service($t,$n), granted_service_exact($t,$n)`
   and the equivalent policies for sets, prefixes, suffixes, per-type and
   global wildcards, plus the target check
   `allow_network_target(...) or target_unrestricted(true)`, and the rules
   that turn an [HTTP grant](../../reference/policy/#http-grants) into a
   service grant when the request's method and path match it.
6. **The synced mesh policy rules** described above.

Biscuit evaluates every `check` and requires all of them to pass. It then
walks the policies in order and applies the first `allow` or `deny` that
matches.

### Stage 2: Task authorization rules (`tar_block` 1..k)

If the Biscuit carries appended blocks (`1..k`, up to `MaxAttenuationBlocks = 8`),
`UnmarshalInbound` verifies before building the authorizer that every appended
block has **0 rules, 0 checks, and 1 `tar_block("<base64url-proto>")` fact**.
After Stage 1 succeeds, the verifier evaluates the decoded
`TaskAuthorizationRule` chain against the request:

- The current time must be strictly before every block's `expire_time` (when
  set).
- In **every** appended `TaskAuthorizationRule` block, at least one `TaskRule`
  must match the request's `service`, HTTP `method` and `path` (when
  `allowed_methods` or `allowed_paths` are non-empty), and MCP tool name on
  `tools/call` (when `allowed_tools` is non-empty).

Because every block must match, appending a new `tar_block` at a sub-agent hop
computes the **intersection** ($\text{Standing Policy} \cap \text{TAR}_1 \cap \dots \cap \text{TAR}_k$)
and can never widen authority.

## Why a caller cannot forge a fact or smuggle Datalog

Two kinds of Datalog fact meet in the authorizer. The facts in the
credential's authority block were written and signed by the control plane:
roles, grants, labels, and `client_peer_id`. The facts about the request
(`service`, `method`, `path`, `host`, `port`, `connection_peer_id`, `time`)
are added by the node that received the request, from what arrived on the
wire. A caller writes neither.

When a holder attenuates a token by appending a block, Agent Mesh never evaluates
holder-authored Datalog rules or checks. Appended blocks are restricted to a
single `tar_block("<base64url-proto>")` fact, which is invisible to Block 0's
Datalog rules and is evaluated by the verifier's own `TaskAuthorizationRule`
matcher. This guarantees that:

1. An untrusted holder cannot trigger expensive Datalog backtracking via
   crafted `check if` queries.
2. The `TaskAuthorizationRule` enforced by the mesh PEP is byte-for-byte
   identical to the rule intersected by `CloudTokenExchanger` at egress.

## Workloads and agents acting through a node or gateway

When multiple workloads, users, or sandboxed agents share a `agentmesh-node` (or
call through `agentgateway` / Istio), they do not share the node's own
permissions:

- On `/mcp` and `/v1/*` (or via RFC 8693 `POST /oauth/token` and Envoy
  `ext_authz` / `ext_proc`), the caller presents its own platform JWT (OIDC ID
  token, Kubernetes projected SA JWT, or SPIFFE JWT-SVID) or a task-attenuated
  Biscuit.
- `agentmesh-node` exchanges platform JWTs via `POST /token/exchange` into a
  **Delegated Session Biscuit** carrying the caller's own `user()`, `email()`,
  `group()`, and `role()` facts, bound to the node via `client_peer_id()` and
  `actor_node()`.
- The destination node authorizes the request against the caller's delegated
  Biscuit and its `tar_block` chain, never the origin node's own roles.

## Local rules

The `attenuation` block in `agentmesh-node.yaml` gives the hosting node the final
say. Use it for constraints that the operator of that node wants regardless
of what the mesh policy grants:

```yaml
attenuation:
  rules:
    - 'maintenance(true) <- time($t), $t > 2026-12-31T00:00:00Z;'
  checks:
    - 'check if label("jurisdiction", "eu");'        # every caller must carry this label
  policies:
    - 'deny if service("mcp", "db-writer"), group("contractors");'
    - 'deny if maintenance(true);'
```

`rules` derive new facts, `checks` must all hold, and `policies` are
evaluated before the baseline policies. Every predicate in Datalog carries at
least one term (presence-only facts are written `name(true)`). A syntax error
in any statement stops the node at start, so a broken rule cannot weaken the
node without notice.

## Labels

Labels are `key=value` pairs. A node declares them in its configuration, and
the control plane writes them into the node's credential as `label(k, v)`
facts, one per label, if a role the node holds allows them. Labels let
policy describe where a node is or what it is for. Agent Mesh does not define a
fixed set of keys: `region`, `jurisdiction`, `team`, `compliance`, or
whatever the operator needs. A router declares labels the same way
(`agentmesh-router --label`), under the same `allowed_labels` of its role,
and carries them in its credential the same way.

Labels are used in four places:

- **A provider restricting callers** adds `check if label("region", "eu")`
  to its `attenuation.checks`. Every caller's credential must then carry
  that label.
- **A caller choosing providers** sends `X-Mesh-Required-Labels: region=eu`
  on the node's `/v1` inference endpoints or on a proxied A2A request, or
  passes `required_labels` to `call_remote_tool`. Before it sends any request
  data, the calling node fetches the provider's credential through the
  mutual handshake, verifies it, and confirms that every label named is
  attested in it. A provider that cannot show them all is skipped.
- **An operator drawing a boundary** sets `egress.require_labels` in the
  node configuration. Every provider this node talks to must attest all of
  those labels, whether or not the caller asked for any. The caller can add
  further requirements but cannot remove the operator's.
- **A node choosing routers** sets `--router-selector key=value` to attach
  only to routers that attest every pair, and `--router-prefer key=value`
  to attach to routers that attest more of those pairs before routers that
  attest fewer. The control plane lists on `/info` the labels it attested
  in each router's credential, and the node chooses from that list before
  it connects. The handshake checks that the router's credential is valid
  and holds the router role, but it does not check the labels again. This
  places a node on routers; it grants the routers nothing, and a call still
  reaches any peer on any router.

The header, the operator floor and the router selector follow the same
matching rule: a map of `key=value` pairs, one value per key, and the peer
must attest every pair. Listing more pairs narrows the set of acceptable
peers, as it does in a Kubernetes label selector or a Prometheus matcher.
Labels seen in discovery results are only used to rank candidates. The only
labels that authorize anything are the signed ones in a credential.

## See also

- [Policy reference](../../reference/policy/): every field, pattern and fact
  name.
- [Agent architecture](../../preview/agent-architecture/): `TaskAuthorizationRule`
  (`tar_block`), `CloudTokenExchanger`, and gateway integration.
- [Node configuration reference](../../reference/node-config/): the
  `attenuation`, `labels` and `egress` blocks.
- [Reaching services outside the mesh](../../guides/egress-destinations/):
  the node as a policy enforcement point and credential broker for outbound
  API calls.
