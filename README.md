# Agent Mesh

<p align="center">
  <img alt="Agent Mesh" src="site/content/docs/agentmesh_logo.png" width="480" />
</p>

**Agent Mesh** is a private network for AI agents. A
node runs next to an agent and gives it three things: a way to publish tools
and models to the network, a way to find and call what other nodes publish,
and an identity every other node can verify. Nodes connect directly when they
can and through relays when they cannot, so the network works across laptops,
containers, clusters and phones behind NAT.

> **Note:** We have updated the name to **Agent Mesh** to better align with the goals of the project in the ecosystem.

Two properties hold everywhere:

- **Nothing is reachable by default.** A node exposes no services until its
  configuration says so, and no node may call a service the mesh policy has
  not granted. Grants are evaluated on service names, never on addresses.
- **Identity comes from your identity provider.** A node enrolls with an
  OpenID Connect token or a bootstrap token, and the control plane
  turns that into a short-lived, offline-verifiable credential bound to the
  node's own key.

## Try it

```bash
curl -sL https://google.github.io/agentmesh/install.sh | bash  # agentmesh-node, mcp-client and friends
agentmesh-node join https://bananas.sam-mesh.dev               # one-time login
agentmesh-node run --daemonize                                 # local MCP server on 127.0.0.1:8080
agentmesh-node skill install                                   # teach your agent to use it
```

Your agent now has tools that discover and call services across the mesh,
and an OpenAI-compatible endpoint that routes model requests to whoever
serves the model. `bananas.sam-mesh.dev` is a shared developer testnet with
no uptime promise; the [quick start](https://google.github.io/agentmesh/docs/getting-started/quickstart/)
walks through it, and [your own mesh](https://google.github.io/agentmesh/docs/getting-started/your-own-mesh/)
runs a control plane on your laptop in one command.

To run a control plane of your own without installing anything, open a
GitHub codespace with the released binaries and run `make testnet`. It
starts on a public `https` URL that your laptop and phone can enroll into,
on your GitHub account's free quota:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/google/agentmesh?quickstart=1&devcontainer_path=.devcontainer%2Ftestnet%2Fdevcontainer.json)

The [Codespaces guide](https://google.github.io/agentmesh/docs/guides/codespaces/) has the
steps, what persists and what stops.

## What is in a mesh

| Program | Role |
|---|---|
| `agentmesh-control-plane` | Verifies who is joining, issues each node a signed credential, and holds the policy that says who may call what. |
| `agentmesh-router` | A well-known peer that nodes connect to first. Relays traffic between nodes that cannot reach each other and hosts the discovery table. |
| `agentmesh-node` | Runs next to your agent or service. Enrolls, connects, serves your local backends to the mesh, and exposes the mesh to your agent as a local MCP server and OpenAI-compatible API. |
| `agentmesh-one` | The control plane, a router and a web console in one binary, for laptops and small deployments. |

## Documentation

[google.github.io/agentmesh/docs](https://google.github.io/agentmesh/docs/) is built from `site/`.

- [Getting started](https://google.github.io/agentmesh/docs/getting-started/): one node on the testnet, then a mesh of your own.
- [Concepts](https://google.github.io/agentmesh/docs/concepts/): architecture, identity and enrollment, authorization, networking.
- [Guides](https://google.github.io/agentmesh/docs/guides/): exposing services, connecting agent clients, headless enrollment, Kubernetes, Cloud Run.
- [Reference](https://google.github.io/agentmesh/docs/reference/): every flag, configuration key, HTTP route and policy field.
- [Preview](https://google.github.io/agentmesh/docs/preview/): sandboxed agents and the mobile app, which work but are still settling.
- [Contributing](https://google.github.io/agentmesh/docs/contributing/): building, testing and the local kind environment.

The repository has a dev container with the Go, Node and Python toolchains
and Docker, so you can build and test in a codespace or in VS Code without
installing anything:

[![Develop in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/google/agentmesh?quickstart=1)

## Status

Agent Mesh is pre-1.0. The node, routers, control plane, identity and policy model
are stable in shape and exercised by the test suite and two public testnets;
see [ROADMAP.md](ROADMAP.md) for the release plan. Sandboxed agent blueprints
and the mobile app are in preview.

## License and disclaimer

Apache-2.0; see [LICENSE](LICENSE). This is not an officially supported
Google product, and it is not eligible for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).
