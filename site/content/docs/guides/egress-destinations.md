---
title: "Reaching services outside the mesh"
linkTitle: "Egress destinations"
weight: 3
---

An agentic application calls APIs that are not on the mesh: a source
forge, a ticketing system, an internal REST service, a model provider. This
guide puts a `sam-node` in front of such a destination as a policy
enforcement point. The application changes one base URL. The admin writes
one policy document. The node decides every request on the method, the
path and the caller, holds the credential the destination needs, and keeps
it out of the application.

You need a control plane you administer, one enrolled node that will serve
the destination, and the credential the destination expects (an API token)
available to that node's host as a file.

## What the admin writes

Everything is in the mesh policy. The `egress` section names the
destination, the credential and the nodes that serve it. A role narrows who
may call it and how.

```json
{
  "roles": [
    {
      "name": "sam:role:node",
      "allowed_services": ["system://sam.catalog"],
      "allowed_targets": ["*"]
    },
    {
      "name": "pep",
      "allowed_targets": ["*"]
    },
    {
      "name": "contractor",
      "allowed_services": ["egress://api.github.com"],
      "allowed_targets": ["*"],
      "http": [
        { "service": "egress://api.github.com", "methods": ["GET"], "paths": ["/repos/acme/*"] }
      ]
    }
  ],
  "bindings": [
    { "role": "sam:role:node", "members": ["group:platform", "group:external"] },
    { "role": "pep",           "members": ["group:platform"] },
    { "role": "contractor",    "members": ["group:external"] }
  ],
  "egress": [
    { "name": "api.github.com", "credential": "github-eu", "served_by": ["pep"] }
  ]
}
```

- `egress[].name` is the destination hostname. It is the service name in
  grants (`egress://api.github.com`) and the name a caller looks up.
- `egress[].credential` is a name, never a value. The serving node reads
  the file `/etc/sam/secrets/github-eu` (or under `--secrets-dir`) and
  presents its content as `Authorization: Bearer <content>`; `user:pass`
  is sent as HTTP Basic. Whatever puts secrets in files on the host, a
  Kubernetes Secret volume, a vault agent, a secrets-store CSI driver,
  delivers it; the control plane never sees it.
- `egress[].served_by` selects the serving nodes by role or by attested
  label (`site=eu`). The control plane grants the destination to those
  nodes, so a serving node authorizes local requests on its own credential.
- `roles[].http` narrows a grant to methods and paths. Here a contractor may
  `GET` under `/repos/acme/` and nothing else. The other fields of a role
  are unchanged; see the [policy reference](../../reference/policy/).

Post it:

```bash
curl -sS -X POST "$CONTROL_PLANE/policies" \
  -H "Authorization: Bearer $(cat admin-token)" \
  -H 'Content-Type: application/json' \
  --data @policy.json
```

## What the node does

Nothing in `sam-node.yaml` changes, and `type: egress` is refused there. A
node holding the `pep` role pulls its assignments from the control plane on
the same schedule as the mesh policy, and sooner when the policy changes.
For each destination that selects it, the node registers the service,
announces `egress://api.github.com` on the mesh, and checks that the named
credential is readable. Its log shows:

```text
[Egress] Serving egress://api.github.com -> https://api.github.com (assigned by the control plane)
[Egress] Assignments: 1 assigned, 1 registered, 0 unchanged, 0 withdrawn, 0 refused
```

A destination whose credential is not in the secrets directory is refused
and logged; the node keeps serving the others. When the admin removes a
destination or its `served_by` no longer selects the node, the node
withdraws the service on its next sync. Every sync that changes or refuses
something logs the summary line above; the control plane, for its part,
warns when a posted destination selects no enrolled node at all.

## What the application does

The application on the serving node's host is configured with the node's
API as the base URL of the destination and the node's API token as its
bearer, in the place it would hold a provider key:

```bash
export GITHUB_API_URL=http://127.0.0.1:8080/egress/api.github.com
export GITHUB_TOKEN=$(cat /etc/sam/api-token)
```

A request then travels like this:

```text
app        GET /egress/api.github.com/repos/acme/dubbing/pulls?state=open
           Authorization: Bearer <api token>
node       accepts the API token; drops it
           facts: service("egress","api.github.com") method("GET")
                  path("/repos/acme/dubbing/pulls") host("api.github.com") port(443)
           authorizes on its own credential, with its attenuation
           GET https://api.github.com/repos/acme/dubbing/pulls?state=open
           Authorization: Bearer <content of /etc/sam/secrets/github-eu>
```

The destination sees the node's credential and none of the application's
headers (`Authorization`, `Cookie`, `X-*`). A `403` is a policy decision; a
`404` is a destination this node was not assigned. Both carry
`Proxy-Status: sam-node; error=...`, so your client can tell them from an
answer the destination sent.

Every decision, allowed or denied, is one `Audit Traceability` line in the
node's log with the peer, the role, the method, the path, the host and the
port policy saw, and the decision. That line is the audit trail of the PEP;
the destination's own logs see the brokered credential (or the federated
principal when `oidc_federation` or `aws_assume_role` is configured).

The node's `/metrics` endpoint counts the same events, so you can alert
without reading logs:

| Metric | Labels | Counts |
|---|---|---|
| `sam_node_egress_decisions_total` | `destination`, `outcome` | requests for a destination, by outcome: `allow`, `deny`, `not_assigned` (the node does not serve that name) and `credential_unavailable` (the credential file could not be read when the request arrived) |
| `sam_node_egress_assignments_total` | `outcome` | assignments applied from the control plane: `registered`, `withdrawn` and `refused` |

`sam_node_services_registered{type="egress"}` is the number of destinations
the node serves right now. A `refused` assignment or a `credential_unavailable`
decision means the platform did not deliver a credential the policy names.

A caller that wants to narrow a request to a single task presents a
task-attenuated Biscuit (`tar_block`), which the egress node evaluates after
standing Datalog policy.

## What another mesh member does

A member whose role grants `egress://api.github.com` reaches the same
destination through its own node, which finds the serving node by name:

```bash
curl -sS -H "X-Sam-Authentication: Bearer $TOKEN" \
  "http://127.0.0.1:8080/sam/$PEP_PEER_ID/egress/api.github.com/repos/acme/dubbing/pulls"
```

The serving node evaluates the member's credential. With the policy above a
member in `group:external` gets `204` on that request, `403` on a `POST` to
the same path, and `403` on `GET /user`.

## Narrowing on the node

The serving node's operator can refuse what the mesh policy allows, in
`sam-node.yaml`. The request facts are available there. The dialect has no
`!=`; a negation is `!`:

```yaml
attenuation:
  policies:
    - 'deny if path($p), $p.starts_with("/repos/acme/vault/");'
    - 'deny if group("external"), method($m), !($m == "GET");'
    - 'deny if port($p), !($p == 443);'
```

## Limits

- The node is the HTTP origin for `EGRESS_MODE_HTTP` destinations. A method
  and path decision needs the request in the clear, which is the case here
  because the application talks plain HTTP to the node. A TCP tunnel
  (`mode: EGRESS_MODE_TCP`) carries `method("CONNECT")` and an empty path, so
  a grant narrowed to HTTP methods or paths denies it.
- The path is a prefix under the destination. A client that follows
  absolute URLs returned by the destination (a `Link` header, a URL in a
  body) leaves the node. Use a client that takes a base URL, or point it
  back at the prefix.
- One destination is one hostname. Wildcard egress destinations are not
  supported.
