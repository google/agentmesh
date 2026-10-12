---
title: "Exposing services"
linkTitle: "Exposing services"
weight: 1
aliases:
  - /docs/integrations/openrouter/
---

A node does not publish any service by default. You declare the services it
offers in `agentmesh-node.yaml`. This guide covers the three kinds of service a
node can serve and what the mesh policy must contain before anyone can reach
them.

## The configuration file

`agentmesh-node` reads `agentmesh-node.yaml` from the working directory, or the file
named by `--config`. Both `join` and `run` read it, because labels are
declared at enrollment. A minimal file with one service:

```yaml
version: "v1alpha1"
services:
  - type: mcp
    name: calculator
    description: "Arithmetic tools"
    target_url: "http://127.0.0.1:7779/mcp"
```

Services exist only through this file. There is no runtime API for adding
one, so an agent with access to the node cannot make it publish a new
backend. To change the services, edit the file and restart the node. The
[node configuration reference](../../reference/node-config/) lists every key.

A `name` must be a valid DNS-style label sequence (`db-reader`,
`build.runner`), because the mesh uses it in URLs and in policy. A policy
grant refers to the pair `type://name`, so `mcp://calculator` in the policy
means this service and no other.

## MCP servers

[MCP](https://modelcontextprotocol.io/) (Model Context Protocol) is the
standard that agents use to call tools. An MCP server is a program that
offers tools over that protocol. There are two ways to serve an MCP backend.

**A subprocess that speaks stdio.** The node starts it, keeps it running, and
translates between the mesh and its stdin and stdout:

```yaml
  - type: mcp
    name: filesystem
    description: "Read-only access to the docs tree"
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/docs"]
    env:
      NODE_OPTIONS: "--max-old-space-size=256"
```

**A Streamable HTTP server that is already running.** The node proxies to it
and does not manage it:

```yaml
  - type: mcp
    name: code-reviewer
    description: "Reviews diffs"
    target_url: "http://127.0.0.1:7777/mcp"
```

`command` and `target_url` are mutually exclusive. Before the node advertises
a service of either kind, it probes the backend. A subprocess that needs more
than two seconds to answer its first request is not advertised unless you
raise `--backend-probe-timeout`.

Callers see the whole tool list of the server. If a third-party server
bundles tools that you do not want to offer, put a small MCP server in front
of it that exposes only the tools you want to publish, or split the tools
into several services with different names and grant them to different
roles.

## Inference backends

Any OpenAI-compatible HTTP server can be an `inference` service: vLLM,
Ollama, LiteLLM, or a proxy in front of a hosted API. Register the root URL
without `/v1`. The node adds the prefix.

```yaml
  - type: inference
    name: local-llama
    description: "Llama 3 on this workstation"
    target_url: "http://127.0.0.1:11434"
```

Every model that the backend lists on `/v1/models` becomes available on
`/v1/models` of every authorized node, and a `chat/completions` request for
that model may be routed here. Give backends distinct names when they serve
different models or run in different places, because policy and label rules
work on the name.

### A hosted API behind a proxy

To share a commercial API without sharing its key, run a proxy that holds the
key next to the node and register the proxy. For example, with LiteLLM in the
same pod or on the same host:

```yaml
  - type: inference
    name: openrouter
    description: "OpenRouter via LiteLLM"
    target_url: "http://127.0.0.1:4000"
```

```bash
OPENROUTER_API_KEY=... \
  LITELLM_DANGEROUSLY_PERMIT_WEAK_OR_UNSET_MASTER_KEY=true \
  litellm --host 127.0.0.1 --model openrouter/auto --port 4000
```

The key never leaves the proxy. Callers on the mesh authenticate with their
credential, the node checks the policy, and the proxy adds the key on the way
out. If the backend itself requires a credential, put it in a file and name
the file in `target_auth_path`. A bare token is sent as
`Authorization: Bearer`, and a `user:pass` pair as HTTP Basic. This is a
file and not an inline value because `agentmesh-node.yaml` is copied into
ConfigMaps and repositories. For the same reason, a URL with embedded
credentials is refused.

## A2A agents

An agent that speaks the [A2A protocol](https://a2a-protocol.org) is served
by URL only:

```yaml
  - type: a2a
    name: triage
    description: "Ticket triage agent"
    target_url: "http://127.0.0.1:9999"
```

Remote callers reach it at `/mesh/<peer-id>/a2a/triage/` on their own node.
The agent card gets special treatment. The caller's node fetches
`/.well-known/agent-card.json` from the agent and serves a regenerated card
whose interface URLs point at the mesh path. An interface served below the
`target_url`, such as a JSON-RPC endpoint at `/invoke` or an HTTP+JSON
binding under `/rest`, keeps that path below the mesh path. Bindings that the
mesh cannot carry (gRPC) are removed, and the original signatures are dropped because the
content changed. Standard A2A client SDKs then work without changes. Cards
must use the A2A 1.0 format. Older formats are refused. The
[A2A chat use case](../../use-cases/chat-a2a/) runs one end to end.

## Making it reachable

Declaring a service publishes it, but nobody can call it until the mesh
policy grants access. Two conditions must hold:

1. The caller's identity resolves to a role whose `allowed_services`
   includes `mcp://calculator`, or a pattern that covers it.
2. If that role has `allowed_targets`, one of them matches this node's
   identity: its peer ID as `node:<id>`, or a claim from the identity it
   enrolled with.

A policy that grants the service to a role bound to your users:

```json
{
  "roles": [
    { "name": "mesh:role:node", "allowed_labels": ["region=*"] },
    { "name": "calc-users", "allowed_services": ["mcp://calculator"] }
  ],
  "bindings": [
    { "role": "mesh:role:node", "members": ["group:engineering"] },
    { "role": "calc-users",    "members": ["group:engineering"] }
  ]
}
```

Post it to the control plane, or paste it into the console's policy editor:

```bash
curl -fsS -X POST https://mesh.example.com/policies \
  -H "Authorization: Bearer $AGENTMESH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data @policy.json
```

Discovery (`system://mesh.catalog`) follows the same rule. A role that should
be able to browse what a node offers needs `system://mesh.catalog` in its
grants. On a mesh where everyone may browse, grant it to `mesh:role:node`.

## Labels

If the node should be identifiable by where it is or what it is for, declare
labels:

```yaml
labels:
  region: eu-west-1
  team: platform
```

Labels are attested at enrollment, so the role the node enrolls with must
permit them (`allowed_labels: ["region=*", "team=platform"]`, or `["*"]`).
Enrollment is refused if a label is not allowed by the role. Once attested,
callers can require the labels (`X-Mesh-Required-Labels: region=eu-west-1`;
several pairs must all be attested), and the node can require labels from
its callers:

```yaml
attenuation:
  checks:
    - 'check if label("team", "platform");'
```

## Restricting callers locally

The `attenuation` block adds your own conditions on top of the policy. All
checks must hold, and `deny` policies override grants:

```yaml
attenuation:
  policies:
    - 'deny if service("mcp", "calculator"), group("contractors");'
  checks:
    - 'check if time($t), $t < 2027-01-01T00:00:00Z;'
```

The syntax is Biscuit Datalog. Your rules can use the facts from the
caller's credential (`user`, `email`, `group`, `idp_role`, `role`, `label`
and the `granted_*` facts), plus `service($type, $name)` for the request and
`time($now)`. A syntax error stops the node at start.

## Checking that it worked

From another enrolled node:

```bash
mcp-client -url http://127.0.0.1:8080/mcp -token "$TOKEN" \
  -tool discover_remote_services -args '{"type":"mcp","name":"calculator"}'
```

If the service is missing, check these causes in order:

1. The backend did not answer the probe. Look for "Withholding" in the
   node log.
2. The caller's role lacks `system://mesh.catalog`.
3. The two nodes have not exchanged discovery state yet. Wait a few seconds
   and try again.

If the service is listed but a call returns a policy error, the grant or the
target is wrong. The node's log names the check that failed.

## Kubernetes

On Kubernetes a service is a pod with your backend container and a
`agentmesh-node` sidecar, deployed with the `charts/agentmesh-node` Helm chart; the
`config:` value is this file. The [Kubernetes guide](../kubernetes/) covers
it.
