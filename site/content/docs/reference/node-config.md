---
title: "Node configuration file"
linkTitle: "Node configuration"
weight: 5
aliases:
  - /docs/user/node-configuration/
---

`agentmesh-node.yaml` declares what a node is (labels), what it publishes
(services), what it requires from callers (attenuation) and what it requires
from providers (egress). Both `agentmesh-node join` and `agentmesh-node run` read it from
`--config`, by default `./agentmesh-node.yaml`. A missing file means an empty
configuration. Unknown keys are an error, because a typo under `attenuation`
would otherwise weaken the node without notice.

```yaml
version: "v1alpha1"

labels:
  region: eu-west-1
  team: platform

services:
  - type: mcp
    name: code-reviewer
    description: "Reviews diffs"
    target_url: "http://127.0.0.1:7777/mcp"
  - type: mcp
    name: filesystem
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/docs"]
    env:
      NODE_OPTIONS: "--max-old-space-size=256"
  - type: inference
    name: vllm
    target_url: "http://127.0.0.1:8000"
    target_auth_path: /etc/agentmesh/vllm-key
  - type: a2a
    name: triage
    target_url: "http://127.0.0.1:9999"

attenuation:
  rules:
    - 'maintenance(true) <- time($t), $t > 2026-12-31T00:00:00Z;'
  checks:
    - 'check if label("team", "platform");'
  policies:
    - 'deny if service("mcp", "filesystem"), group("contractors");'
    - 'deny if maintenance(true);'

egress:
  require_labels:
    jurisdiction: eu
```

## `version`

`"v1alpha1"`, or omitted (read as `v1alpha1`). A node refuses a version it
does not know.

## `labels`

A map of `key: value`, at most 64 entries. Keys are 1 to 63 characters from
`[a-zA-Z0-9_.-]`. Values are non-empty and at most 255 characters. Values
contain no `,` or `=`, because the wire form is a comma-separated `key=value`
list. Values also contain no `"`, `\` or control characters, because the
control plane writes the value into Datalog. A malformed label, or more than
64 labels, stops the node at start.

Labels are sent at enrollment. The control plane writes them into the node's
credential as `label(key, value)` facts, but only if a role the node holds
allows them through `allowed_labels`. A label that the role does not permit
fails the enrollment. Changing labels requires a new enrollment. Matching is
exact and case-sensitive.

## `services`

A list. Each entry has these keys:

| Key | Required | Meaning |
|---|---|---|
| `type` | yes | `mcp`, `inference` or `a2a`. `egress` is refused here: a destination outside the mesh is assigned to nodes by the control plane, in the [egress section](../policy/#egress-destinations) of the mesh policy. |
| `name` | yes | Dot-separated labels, each 1 to 63 characters of `[a-zA-Z0-9_-]` with no leading `-` (`db-reader`, `build.runner`). The node checks the name as a [service pattern](../policy/#service-patterns), so a wildcard form or a `/path` suffix passes too. A name serves one type. The node refuses a second type under the same name. A later entry with the same name and type replaces the earlier one. Policy grants refer to `type://name`. |
| `description` | no | Shown in discovery results and in the console. |
| `target_url` | `mcp`: this or `command`; `inference` and `a2a`: yes | Backend URL that the node proxies to. Embedded credentials (`http://user:pass@`) are refused. |
| `command` | `mcp` only: this or `target_url` | Argument vector of a subprocess that speaks MCP over stdio. The node starts and supervises it. |
| `env` | no | `command` only. Environment for the subprocess. |
| `target_auth_path` | no | `target_url` only. File whose contents the node presents to the backend: a bare token as `Authorization: Bearer <token>`, or `user:pass` as HTTP Basic. Read once at start, never logged or advertised. It overrides any `Authorization` header that a caller sent. |
| `ingress` | no | Exposes an `a2a`, `mcp` or `inference` service on router HTTP ingress (`<ingress_url>/<peer_id>/<type>/<name>`), subject to the node's `allowed_ingress` role ceiling. Subkeys: `auth_mode` (`edge`, the default, or `passthrough`) and `allow` (optional list of `PolicyBinding.members` patterns narrowing `edge` callers). See the [external ingress guide](../../guides/external-ingress/). |

Rules by type:

- **`mcp`**: `command` or `target_url`. When both are set, the node uses
  `target_url` and ignores `command` and `env`. A `target_url` must be a
  Streamable HTTP MCP endpoint.
- **`inference`**: `target_url` only. It must be the root URL of the backend
  without `/v1`. The node adds the prefix. Callers reach the service through
  the node's `/v1` endpoint or at `/mesh/<peer>/inference/<name>/v1/...`.
- **`a2a`**: `target_url` only. The agent card is fetched from
  `/.well-known/agent-card.json` on the backend and served again with mesh
  URLs. The card must use the A2A 1.0 format.

Before an MCP or A2A service is advertised, the node probes the backend
(`--backend-probe-timeout`, 2 seconds). A backend that does not answer is
not advertised, and the log records this. An inference service is
advertised without a probe.

Services exist only through this file and through the control plane's
egress assignments. There is no runtime API that adds a service. An agent
with access to the node's API therefore cannot point the mesh at a new
backend.

## `attenuation`

Biscuit Datalog that the node adds to every authorization decision for
requests it receives. Each entry is one statement. A trailing `;` is
optional. A statement that does not parse stops the node at start.

| Key | Meaning |
|---|---|
| `rules` | Derive new facts from existing ones: `head(...) <- body(...)`. |
| `checks` | Conditions that must all hold: `check if ...`. A failing check denies the request regardless of any policy. |
| `policies` | `allow if ...` and `deny if ...`, evaluated before the baseline policies. The first matching policy wins. A `deny` here overrides a mesh grant. An `allow` here admits a caller that the mesh did not grant, but never a caller that fails a check. |

Facts available:

| Fact | Source |
|---|---|
| `service($type, $name)` | The request: which service is being called. |
| `time($now)` | Injected at evaluation. |
| `connection_peer_id($id)` | The authenticated peer. |
| `user($sub)`, `email($e)`, `group($g)`, `idp_role($r)` | The caller's OIDC claims, from its credential. |
| `role($r)` | The caller's mesh roles. |
| `label($k, $v)` | The caller's attested labels. |
| `node($id)`, `client_peer_id($id)`, `expiration($t)` | The caller's credential binding and expiry. |
| `granted_*`, `http_granted_service_*` | The caller's grants. [Datalog vocabulary](../policy/#datalog-vocabulary) lists them. |
| `target_fact($name, $value)` | This node's own identity facts, for target matching. |
| `method($m)`, `path($p)` | The request, when it is HTTP: the method as received and the path as the backend sees it. On a tunnel, `CONNECT` and an empty path. Absent on a stream that carries no HTTP request. |
| `host($h)`, `port($n)` | The destination of a request for an egress destination. |

The dialect has no `!=`; write a negation with `!`, as in
`deny if method($m), !($m == "GET")`.

The mobile app has the same three lists in its settings, with the same
syntax and the same errors.

## `egress`

| Key | Meaning |
|---|---|
| `require_labels` | A map of `key: value`. Every remote provider that this node sends a request to must have all of these labels attested in its credential, whether or not the caller asked for labels. Same syntax rules as `labels`. |

This is the operator's floor. A caller's `X-Mesh-Required-Labels` header is
checked separately, with the same rule: every pair it names must be attested.
It can add requirements but cannot remove or relax the floor. A floor that
names a label which no provider carries makes the node unable to reach any
provider, which can serve as an egress kill switch. Omit the block for no
floor.

## Kubernetes

The `agentmesh-node` Helm chart renders its `config:` value as this file and
restarts the pod when it changes. Because the backend runs in the same pod,
`target_url` there is always `http://127.0.0.1:<port>`.
