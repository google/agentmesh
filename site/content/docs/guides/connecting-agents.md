---
title: "Connecting agents"
linkTitle: "Connecting agents"
weight: 2
aliases:
  - /docs/user/agent-usage/
  - /docs/integrations/claude-code/
  - /docs/integrations/claude-desktop/
  - /docs/integrations/antigravity/
  - /docs/integrations/gemini/
  - /docs/integrations/openclaw/
  - /docs/integrations/vscode-copilot/
---

An MCP client can join Agent Mesh as its own member and call remote MCP tools
through the published **`dev.sam-mesh/mesh`** server. The server runs locally
over stdio. It enrolls directly with your mesh control plane, so it does not
need an `agentmesh-node` process beside it.

## Install from the MCP registry

The official registry server entry is **`dev.sam-mesh/mesh`**. Its npm package
is **`@agentmesh-p2p/sdk`**; the registry name and npm package name serve
different purposes. After the first registry release is available, configure
your client to run the published package version:

```json
{
  "command": "npx",
  "args": ["--yes", "@agentmesh-p2p/sdk@<published-version>"],
  "env": {
    "AGENTMESH_CONTROL_PLANE_URL": "https://mesh.example.com",
    "AGENTMESH_BOOTSTRAP_TOKEN_PATH": "/absolute/path/to/join-token",
    "AGENTMESH_STATE_DIR": "/absolute/path/to/this-client-identity"
  }
}
```

Replace `<published-version>` with the version shown for `dev.sam-mesh/mesh`
in the MCP registry. The first registry release must include the package's
`agentmesh` command, so use a version published after that release. Node.js
22.18 or later is required. Use absolute paths: MCP clients do not expand `~`
in environment-variable values.

Ask your mesh operator for the HTTPS control-plane URL and a bootstrap-token
file that only your account can read. The executable reads the credential from
that file; do not put token contents into client configuration, command-line
arguments or shell history. Alternatively, use
`AGENTMESH_JWT_PATH` for a workload/OIDC token file. Set exactly one credential
path for first enrollment. The client saves its member identity and resumes
from `AGENTMESH_STATE_DIR` on later launches, so it can omit the credential
path after enrollment. JWT enrollment rereads the token file when refreshing.

Each client identity and mesh needs its own state directory. Do not launch two
copies against one directory. If you omit `AGENTMESH_STATE_DIR`, the executable
uses `~/.config/agentmesh/mcp`.

Plain HTTP is accepted only for a loopback control plane. To permit plaintext
HTTP to another address, set `AGENTMESH_INSECURE_CONTROL_PLANE=true`; this
disables TLS protection for the control-plane connection and should only be
used on a network you trust. Its default is `false`.

## Configure a client

The registry entry declares a stdio transport and the environment variables
above. Most MCP clients accept this `mcpServers` shape:

```json
{
  "mcpServers": {
    "agentmesh": {
      "command": "npx",
      "args": ["--yes", "@agentmesh-p2p/sdk@<published-version>"],
      "env": {
        "AGENTMESH_CONTROL_PLANE_URL": "https://mesh.example.com",
        "AGENTMESH_BOOTSTRAP_TOKEN_PATH": "/absolute/path/to/join-token",
        "AGENTMESH_STATE_DIR": "/absolute/path/to/this-client-identity"
      }
    }
  }
}
```

VS Code uses a `servers` object in `.vscode/mcp.json` instead:

```json
{
  "servers": {
    "agentmesh": {
      "type": "stdio",
      "command": "npx",
      "args": ["--yes", "@agentmesh-p2p/sdk@<published-version>"],
      "env": {
        "AGENTMESH_CONTROL_PLANE_URL": "https://mesh.example.com",
        "AGENTMESH_BOOTSTRAP_TOKEN_PATH": "/absolute/path/to/join-token",
        "AGENTMESH_STATE_DIR": "/absolute/path/to/this-client-identity"
      }
    }
  }
}
```

The process writes MCP messages only to stdout and diagnostics to stderr.
Closing stdin or stopping the client shuts down the mesh session.

## What the server provides

The stdio server exposes five caller tools:

| Tool | Purpose |
|---|---|
| `get_mesh_info` | Return this member's peer ID, connected peers and attached routers. |
| `discover_remote_services` | Find services published by other mesh members. |
| `find_remote_tools` | Find tools offered by remote MCP services. |
| `describe_remote_tool` | Read the input schema for a remote tool. |
| `call_remote_tool` | Call a remote tool using the member's authenticated mesh session. |

The server is a caller, not a service host, so it does not expose
`list_local_services`. Calls follow the member's mesh identity and policy.
Discovery is bounded and follows tool pagination. Inference and A2A discovery
return service metadata, but this stdio executable does not create an HTTP
proxy, `/v1` endpoint, local socket or `local_proxy_url`. To publish a local
service, share a node identity, or invoke inference and A2A over HTTP, use
[the agentmesh-node setup](../deploying-node-mcp/).

## Try the source checkout before registry release

Until the first package version with its executable is published, you can run
the same server from a checkout:

```bash
git clone https://github.com/google/agentmesh.git
cd agentmesh/sdk/js
npm ci
npm run build
```

Use `node` and the absolute path to `dist/cli.js` in place of `npx` in the
client configuration:

```json
{
  "command": "node",
  "args": ["/absolute/path/to/agentmesh/sdk/js/dist/cli.js"],
  "env": {
    "AGENTMESH_CONTROL_PLANE_URL": "https://mesh.example.com",
    "AGENTMESH_BOOTSTRAP_TOKEN_PATH": "/absolute/path/to/join-token",
    "AGENTMESH_STATE_DIR": "/absolute/path/to/this-client-identity"
  }
}
```

The source checkout needs Node.js 22.18 or later and the same mesh settings
described above. See the
[JavaScript SDK README](https://github.com/google/agentmesh/tree/main/sdk/js#mcp-client-over-stdio)
for implementation limits and troubleshooting.

## The node HTTP server

The `agentmesh-node` also exposes an MCP server over authenticated HTTP. Use it
when you want a node to publish services or several clients to share one
member identity. Its HTTP setup and client-specific configuration live in
[Connect through an agentmesh-node](../deploying-node-mcp/).
