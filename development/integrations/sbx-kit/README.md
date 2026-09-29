# SAM kit for Docker sandboxes

A [Docker sandbox kit](https://github.com/docker/sandbox-kit-spec) that puts a
SAM mesh node inside the sandbox, next to the agent, and registers it with the
agent as an MCP server. The agent reaches the mesh's tools and models by name,
under the mesh's policy and audit, and the admin can revoke it without touching
the sandbox.

Docker's host proxy stays the sandbox's internet boundary. The kit adds one
allow entry, the control plane host; the mesh rides on that connection.

## Requirements

- `sbx` 0.45 or later (the first release with v3 kits).
- A v3 workload such as `docker/sbx-kit-claude`. The built-in names such as
  `sbx run claude` select v2 kits, which refuse v3 mixins.
- A control plane reachable over HTTPS on a hostname, and a single-use
  bootstrap token for the sandbox. [Your own
  mesh](https://sam-mesh.dev/docs/getting-started/your-own-mesh/) covers both;
  `sam-one --tunnel cloudflare` gives a hostname in one command. A standalone
  router advertised only by IP address does not work yet.

## Files

| | |
| --- | --- |
| `sam.yaml` | The kit: args, the one allow entry, the startup hook. |
| `sam.dockerfile` | Copies `sam-node` from `ghcr.io/google/sam-node` and the hooks into an overlay. |
| `hooks/startup.sh` | Every boot: registers the node with every supported agent CLI present, enrolls on the first boot, then runs `sam-node run --daemonize`. |
| `sam-kit-args.example` | The two values the kit needs. |

## Run

1. Copy `sam-kit-args.example` to `sam-kit-args` and fill in the control plane
   host (no `https://`) and the token. Keep the file out of version control.

2. Start the agent with the kit, from a checkout of this repository:

   ```sh
   sbx run docker/sbx-kit-claude --kit ./development/integrations/sbx-kit \
     --kit-args-file sam-kit-args --name sam-demo
   ```

   `sbx` asks you to approve one network allow entry, the control plane host.

3. Ask the agent to list the tools on the SAM mesh. They arrive through the
   `sam-mesh` MCP server, and calls to them are decided by the mesh's policy.

Arguments can also go on the command line, `--kit-arg controlPlane=<host>`,
and a flag overrides the file. Keep the token in the file: a flag value lands
in shell history and in `ps` output.

## Notes

- **The token is single-use.** The first boot spends it and the node keeps
  its identity in `~/.sam`, so restarts need nothing. A recreated sandbox
  needs a fresh token.
- **The node is the agent's identity.** The mesh sees one member per sandbox,
  with the role the token grants.
- **Logs.** Inside the sandbox, `~/.sam/sam-node.log` for the node and
  `~/.sam/hooks.log` for the registration. On the host, `sbx
  policy log` shows what the proxy refused.
- **A project `.mcp.json` pointing at `127.0.0.1:8080`** is loaded too,
  since the workspace is mounted, and reaches this node with your host node's
  token, so it fails with `401`. The kit's own server is `sam-mesh`. Disable the
  other one inside the sandbox only, by adding its name to
  `disabledMcpjsonServers` in the sandbox's `~/.claude/settings.json`.
- **Other agents.** The startup hook registers `sam-mesh` with whichever of
  these the workload ships: Claude Code, Codex, Gemini CLI, Antigravity,
  OpenCode, Devin, Cursor, Copilot, Droid and Kiro. Swap the workload, for example
  `sbx run docker/sbx-kit-codex --kit …`. Any other MCP client can use
  `http://127.0.0.1:8080/mcp` with the header
  `X-Sam-Authentication: Bearer $(cat ~/.sam/api-token)`.
