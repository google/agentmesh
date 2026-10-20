---
title: "Agent Mesh Documentation"
linkTitle: "Documentation"
---

**Agent Mesh** is a private network for AI agents. A
node runs next to an agent and gives it three things: a way to publish tools and
models to the network, a way to find and call what other nodes publish, and
an identity that every other node can verify. Nodes reach each other
directly when they can and through relays when they cannot, so the network
works across laptops, containers, clusters and phones behind NAT.

Three programs make up a mesh:

| Program | Role |
|---|---|
| `agentmesh-control-plane` | Verifies who is joining, issues each node a signed credential, and holds the policy that says who may call what. |
| `agentmesh-router` | A well-known peer that new nodes connect to first. It relays traffic between nodes that cannot reach each other and hosts the discovery table. |
| `agentmesh-node` | Runs next to your agent. It enrolls with the control plane, connects to the mesh, serves your local tools to others, and exposes the mesh to your agent as a local MCP server and an OpenAI-compatible API. |

`agentmesh-one` bundles the first two, plus a web console, into a single binary for
laptops and small deployments.

Two rules apply to every mesh:

- **Closed by default.** A node does not expose any service until you
  configure one, and a node cannot call a service unless the mesh policy
  grants it. Policy is written in terms of service names, not IP addresses.
- **Identity comes from your identity provider.** A node enrolls with an
  OpenID Connect token or with a bootstrap token. The control plane
  turns that into a short-lived credential
  ([Biscuit](https://www.biscuitsec.org/)) that is bound to the node's own
  key and that any node can verify offline.

## How these pages are organised

- [Getting started](getting-started/) puts one node on the public
  testnet, then shows you how to run a mesh of your own with `agentmesh-one`.
- [Concepts](concepts/) explains how the pieces fit together: the
  components, enrollment and identity, authorization, and how traffic moves.
- [Guides](guides/) show how to do specific tasks: expose a service, connect
  an agent client, enroll headless nodes, deploy on Kubernetes or Cloud Run.
- [Reference](reference/) lists every flag, configuration key, HTTP route
  and policy field.
- [Use cases](use-cases/) are worked examples of things built on top of
  the mesh.
- [Preview](preview/) covers features that work today but whose interfaces
  may still change: sandboxed agents and the mobile app.
- [Contributing](contributing/) covers building, testing and changing Agent Mesh
  itself.

## About the public testnets

`bananas.sam-mesh.dev` (built from `main`) and `hub.sam-mesh.dev` (built from
the latest release tag) are shared developer testnets that run on donated
resources. They exist for trying things out and for the project's own CI.
They have no uptime commitment, and anyone who can log in with the
configured identity provider can join them. Do not publish anything
sensitive there. If you need a mesh that you control, run your own control
plane. The guides explain how.
