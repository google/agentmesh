---
title: "mcp-client"
linkTitle: "mcp-client"
weight: 9
---

`mcp-client` is a command-line MCP client for trying a node from a shell. It
lists the tools of an MCP server, calls one tool, or streams a service
discovery from the node's local API.

```text
mcp-client -url <url> -list                               list the server's tools
mcp-client -url <url> -tool <name> [-args <json>]         call a tool and print its text content
mcp-client -url <url> -stream -args '{"type":"mcp"}'      stream a service discovery
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-url` | | URL of the MCP server, such as `http://127.0.0.1:8080/mcp` or `http://127.0.0.1:8080/mesh/<peer-id>/mcp/<name>`. With `-stream`, the node's base URL or its `/mcp` URL. Required. |
| `-list` | `false` | List the tools and exit. The client also lists them when `-tool` is absent. |
| `-tool` | | Tool to call. |
| `-args` | `{}` | JSON object with the tool's arguments. With `-stream`, the discovery parameters: `type` (required) and `name`. |
| `-stream` | `false` | Call `GET /mesh/service/discover?stream=true` on the node instead of an MCP server, and print each event as it arrives. |
| `-timeout` | `10` | Seconds before the client gives up. With `-stream`, also sent as the `timeout` of the discovery. |
| `-token-path` | | File containing the node's API token, sent as `X-Mesh-Authentication: Bearer <token>`. Can also be set with `AGENTMESH_API_TOKEN`. |
| `-token` | | The token as a value. Deprecated, because the value is visible in process listings. `-token-path` and the variable are preferred. |
| `-version` | | Print the version and exit. |

The client speaks the streamable HTTP transport and tries to connect up to
five times, 500 ms apart, before it reports the failure.
