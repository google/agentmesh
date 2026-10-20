---
title: "Quick start"
linkTitle: "Quick start"
weight: 1
aliases:
  - /docs/quickstart/
---

This page installs `agentmesh-node`, enrolls it in the public `bananas.sam-mesh.dev`
testnet, and calls a tool hosted by another node. It takes a few minutes.

The testnet is a shared developer playground with no uptime commitment. See
[About the public testnets](../../#about-the-public-testnets). The steps are
the same for any mesh: replace the URL with your own control plane.

## 1. Install

On Linux and macOS, the install script downloads the latest release and
places the binaries in `/usr/local/bin`:

```bash
curl -sL https://google.github.io/agentmesh/install.sh | bash
```

With a Go toolchain, you can build from source instead:

```bash
go install github.com/google/agentmesh/cmd/agentmesh-node@latest
go install github.com/google/agentmesh/cmd/mcp-client@latest
```

On Windows, download `agentmesh_Windows_x86_64.zip` from the
[releases page](https://github.com/google/agentmesh/releases) and put `agentmesh-node.exe`
on your `PATH`.

## 2. Enroll with a control plane

Every node joins a mesh by enrolling with a running **control plane** at its
**URL**:

- **Shared public testnet (used below)**: `https://bananas.sam-mesh.dev` is an already-running control plane open to any developer; it authenticates in your browser.
- **Your own control plane**: start your own control plane with `agentmesh-one` on your workstation or in the cloud ([Your own mesh](../your-own-mesh/), [Cloud Run](../../guides/cloud-run/), or [SkyPilot](../../guides/skypilot/)) and copy the `API URL` and `agentmesh-node join` command printed in the `agentmesh-one` startup banner.

Enroll your node against the public testnet control plane:

```bash
agentmesh-node join https://bananas.sam-mesh.dev
```

The command opens a browser for the login. If no browser is available, it
prints a URL and a code to enter on another device. (When joining your own
`agentmesh-one` server before setting up OIDC, pass `--bootstrap-token-path <join-token-file>`
as shown in the `agentmesh-one` banner instead of logging in through a browser.)
When enrollment completes, the credential is stored under `~/.config/agentmesh/`.
You do this once per machine. Later starts reuse the stored identity and renew
it automatically.

## 3. Run the node

```bash
agentmesh-node run --daemonize
```

The node starts in the background, connects to the mesh, and prints where its
local API is:

```text
agentmesh-node is running in the background.
  PID       48213
  Endpoint  http://127.0.0.1:8080/mcp
  Socket    /home/you/.config/agentmesh/agentmesh.sock
  Token     /home/you/.config/agentmesh/api-token
  Logs      /home/you/.config/agentmesh/agentmesh-node.log
  Stop      kill 48213
```

The local API is served on two listeners. The TCP port requires the token
from the file shown. The Unix socket requires no token, because only your
user can open it. `--daemonize` generates the token on first use. To choose
the token yourself, set `AGENTMESH_API_TOKEN` or pass `--api-token-path`. Run the
command without `--daemonize` to keep the node in the foreground.

You can run `agentmesh-node run --daemonize` again at any time. If a node is
already running, the command does not start a second one. It prints the
address of the running node and exits.

## 4. Call a tool on the mesh

The node's local API is an MCP server. `mcp-client` is installed together
with `agentmesh-node` and is the quickest way to talk to it. `mcp-client`
reads the token from `AGENTMESH_API_TOKEN` or from the file named by
`-token-path`. Export the token once:

```bash
export AGENTMESH_API_TOKEN=$(cat ~/.config/agentmesh/api-token)
```

List the tools the node itself offers:

```bash
mcp-client -url http://127.0.0.1:8080/mcp -list
```

Find MCP services other nodes are publishing:

```bash
mcp-client -url http://127.0.0.1:8080/mcp \
  -tool discover_remote_services -args '{"type":"mcp"}'
```

Each result carries a `peer_id`. Ask one of them which tools it hosts:

```bash
mcp-client -url http://127.0.0.1:8080/mcp \
  -tool find_remote_tools -args '{"peer_id":"<peer-id>"}'
```

Then call one. The testnet runs the MCP reference `everything` server as a
demo. Its `add` tool adds two numbers:

```bash
mcp-client -url http://127.0.0.1:8080/mcp \
  -tool call_remote_tool \
  -args '{"peer_id":"<peer-id>","tool_name":"mcp://everything/add","arguments":{"a":2,"b":3}}'
```

The call left your machine over an authenticated peer-to-peer connection.
The node that hosts the service checked the mesh policy, ran the tool, and
returned the result the same way. Any MCP client can make the same calls.

MCP is one of three service types. The testnet also publishes `inference`
services, and the same node offers their models on an OpenAI-compatible
endpoint. The Unix socket needs no token:

```bash
curl -s --unix-socket ~/.config/agentmesh/agentmesh.sock http://localhost/v1/models
```

A completion request to `/v1/chat/completions` for one of those models is
routed to the node that serves it. The third type, `a2a`, is an agent that
speaks the A2A protocol; [Your own mesh](../your-own-mesh/) publishes a
model from your laptop and shows where each type fits.

## 5. Give your agent the skill

The MCP tools tell an agent what it can do. The Agent Mesh skill tells it when and
how to use them: start a node, discover services, describe a tool before
calling it, reach a mesh inference model. Install it once:

```bash
agentmesh-node skill install
```

This writes `SKILL.md` into the directories that the common agent harnesses
read: `~/.claude/skills/agentmesh/` for Claude Code and Claude Desktop, and
`~/.gemini/config/skills/agentmesh/` for Antigravity. Then register the node's
MCP endpoint with your agent. [Connecting agents](../../guides/connecting-agents/)
has the configuration for each client.

With the skill installed, you can ask an agent to "connect to the mesh" and
it brings a node online by itself. The one step it cannot do for you is the
`agentmesh-node join` login, which requires a person.

## Starting over

The node reuses whatever is in its data directory. To forget the mesh
identity but keep the node's key:

```bash
agentmesh-node reset
```

To delete everything the node stores, including its key (the node gets a new
peer ID and must enroll again):

```bash
agentmesh-node reset --all
```

Both commands refuse to run while a node is up. Stop the node first with the
`kill` command from the `--daemonize` output.

## Next

- [Your own mesh](../your-own-mesh/) runs a control plane and router on your
  laptop in one command.
- [Exposing services](../../guides/exposing-services/) publishes a tool or a
  model from your node.
- [Architecture](../../concepts/architecture/) explains what just happened.
