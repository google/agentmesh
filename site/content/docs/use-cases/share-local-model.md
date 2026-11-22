---
title: "Share a Local Model"
linkTitle: "Share a Local Model"
weight: 6
---

One node serves a model that runs on its own machine, on loopback. Another
member of the mesh asks for it and is refused, because nothing is reachable
by default. The operator grants that one service by name, and the same
request goes through. Agents that use node B then find the model through
node B's MCP server. The recording runs the control plane and both nodes on
one machine.

<video autoplay loop muted playsinline controls style="width: 100%; border-radius: 8px;">
  <source src="../../../demo-share-local-model.mp4" type="video/mp4">
</video>

Source: [`development/examples/share-local-model/`](https://github.com/google/agentmesh/tree/main/development/examples/share-local-model).
The scenes, the captions and the recording recipe are in its
[`SCRIPT.md`](https://github.com/google/agentmesh/blob/main/development/examples/share-local-model/SCRIPT.md).

## The idea

A model on a workstation is useful to more people than the one who runs it,
but opening its port lets anyone who reaches the port use it. Here the model
stays on 127.0.0.1. The node next to it publishes it under a name,
`inference://laptop-llm`, and the policy decides who may call that name.

## The pieces

**One policy** ([`mesh-policy.json`](https://github.com/google/agentmesh/blob/main/development/examples/share-local-model/mesh-policy.json)).
Members hold the role `mesh:role:node`: they may publish `inference://*` but
may call only `system://mesh.catalog`.

**Node A** ([`node-a.yaml`](https://github.com/google/agentmesh/blob/main/development/examples/share-local-model/node-a.yaml))
publishes Ollama at `http://127.0.0.1:11434` as `laptop-llm`.

**Node B** offers the agents on its machine an OpenAI-compatible API
(`/v1/chat/completions`) and an MCP server (`/mcp`).

**[`audit.py`](https://github.com/google/agentmesh/blob/main/development/examples/share-local-model/audit.py)**
filters each node's log to one line per authorization decision, plus a line
when the node loads a changed policy.

## What happens

1. Node B asks its own socket for `gemma3:1b`. Node A checks node B's
   credential against the policy and refuses: `DENY`.
2. The operator adds `inference://laptop-llm` to the node role through the
   admin API (`POST /policies`). Both nodes load the new policy within
   seconds: the demo pulls every 5 seconds (`--control-plane-sync-interval 5s`,
   15 minutes by default), and a policy event brings the pull forward.
3. The same request: `ALLOW`, and the answer comes from the model on node A
   over an authenticated peer-to-peer link.
4. Antigravity CLI and OpenCode, pointed at node B's MCP server, find the
   model and the node that serves it.
