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
- A control plane reachable over HTTPS on a hostname. `sam-one --tunnel`
  works. A standalone router advertised only by IP address does not yet.

## Files

| | |
| --- | --- |
| `sam.yaml` | The kit: args, the one allow entry, the startup hook. |
| `sam.dockerfile` | Copies `sam-node` from `ghcr.io/google/sam-node` and the hooks into an overlay. |
| `hooks/startup.sh` | Every boot: registers the node with every supported agent CLI present, enrolls on the first boot, then runs `sam-node run --daemonize`. |
| `policy.json`, `pep.yaml` | The walkthrough's mesh: one node serving `mcp://tools`, one `agent` role allowed to call it. |
| `kit-args.example` | The two values the kit needs. |

## Walkthrough

**Admin**, in a checkout of this repository, with `sam-one`, `sam-node` and
`npx` on the path. Each server runs in the foreground in its own terminal.

1. Start a tool server for the mesh to serve:

   ```sh
   npx -y @modelcontextprotocol/server-everything streamableHttp
   ```

2. Start the mesh on a public URL:

   ```sh
   cd development/examples/sbx-kit
   sam-one --data-dir ~/.sam-sbx/one --tunnel cloudflare --tunnel-install \
     --policy-file policy.json --no-join-token --enroll-qr=false
   ```

   Note the `https://` URL in the banner; below it is `$URL`, and its host
   is `$HOST`.

3. Admit the node that serves the tools, and start it:

   ```sh
   sam-one token create --server "$URL" --data-dir ~/.sam-sbx/one \
     --max-usages 1 | awk '/^Token:/ {print $2}' > ~/.sam-sbx/pep-token
   sam-node run --control-plane "$URL" --bootstrap-token-path ~/.sam-sbx/pep-token \
     --config pep.yaml --data-dir ~/.sam-sbx/pep --bind-addr=
   ```

4. Mint the sandbox's token:

   ```sh
   sam-one token create --server "$URL" --data-dir ~/.sam-sbx/one \
     --role agent --max-usages 1
   ```

**Developer**, on the machine running Docker sandboxes, in a checkout of this
repository.

5. Copy `kit-args.example` to `kit-args`, and fill in `$HOST` (no
   `https://`) and the token from step 4. Keep the file out of version control: the token must
   not appear on a command line.

6. Start Claude Code with the kit:

   ```sh
   sbx run docker/sbx-kit-claude --kit ./development/examples/sbx-kit \
     --kit-args-file kit-args --name sam-demo
   ```

   `sbx` asks you to approve one network allow entry, the control plane host.

7. Ask Claude: *"List the tools on the SAM mesh and call echo with hello."* It
   finds `mcp://tools` through the `sam-mesh` MCP server and calls it.

**Admin** again.

8. Take the tools away from the agent role:

   ```sh
   jq '(.roles[] | select(.name == "agent") | .allowed_services) = []' policy.json \
     | curl -sS -X POST "$URL/policies" \
         -H "Authorization: Bearer $(cat ~/.sam-sbx/one/admin-token)" \
         -H 'Content-Type: application/json' --data @-
   ```

9. Ask Claude to call the tool again. The mesh refuses it by policy. The
   sandbox and the agent were not restarted.

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
