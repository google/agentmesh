---
name: sam-mesh
description: "Use when local tools cannot provide a needed capability and a SAM agent mesh can: inspect mesh state, discover reachable services/tools, describe and call namespaced remote MCP tools, reach OpenAI-compatible inference models hosted by mesh peers, and hand work to A2A agents on the mesh through the official a2a CLI. Also use to set up, join, or reconnect a sam-node when its MCP tools are not callable yet."
---

# SAM Agent Skill

Use this skill when local tools cannot satisfy the task and the SAM mesh can.
Prefer local tools first. Reach into the SAM mesh only for the capability needed
to complete the task.

Pick the path that matches the need:

- The `sam-node` MCP tools are not callable yet:
  [Bootstrap A Node](#bootstrap-a-node).
- The task needs a plain HTTP call to the node, such as inference or a
  `local_proxy_url`: [Talk To The Node Over HTTP](#talk-to-the-node-over-http).
- The node is up but the mesh seems broken:
  [Diagnose The Node](#diagnose-the-node).
- The task needs a remote tool or capability:
  [Inspect The Mesh](#inspect-the-mesh).
- The task needs a model completion:
  [Use Mesh Inference](#use-mesh-inference).
- The task needs a remote A2A agent: [Call A2A Agents](#call-a2a-agents).

## Bootstrap A Node

The mesh is reached through a local `sam-node`. When its MCP tools are missing,
guide the user through these steps. Propose each shell command and let the user
approve it before running anything.

1. Check the CLI: `sam-node --help`. If it is missing, install it with
   `curl -sL https://sam-mesh.dev/install.sh | bash` or
   `go install github.com/google/sam/cmd/sam-node@latest`.
2. Start the node in the background: `sam-node run --daemonize`. It returns as
   soon as the node answers, and prints the endpoint, the API token file, the
   log file, and how to stop it. It is idempotent, so run it again whenever you
   need to confirm a node is up.
3. If step 2 reports that the node is not enrolled, run the command it prints,
   `sam-node join --headless <control-plane-url>`. In headless mode SAM now
   prefers OAuth device flow automatically when the OIDC provider supports it,
   so no pasted callback code is required: it prints a verification URL/code
   and polls until login completes. If the provider does not expose a device
   endpoint, SAM falls back to OOB code-paste flow; show the URL/code to the
   user, wait for completion, then repeat step 2. For deterministic automation,
   force the flow with `--auth-mode device` (also `oob`, `browser`, or the
   default `auto`); `--auth-mode device` fails fast if the provider has no
   device endpoint. Enrollment is a one-time step per machine.
4. Read the node API token from the file named in step 2, then register the MCP
   endpoint `http://127.0.0.1:8080/mcp` with the header
   `X-Sam-Authentication: Bearer <token>`. Claude Code:
   `claude mcp add --transport http sam-mesh http://127.0.0.1:8080/mcp --header "X-Sam-Authentication: Bearer <token>"`.
   Antigravity: add the same URL as `serverUrl` with the same header to
   `~/.gemini/config/mcp_config.json`.
5. Tell the user to restart the agent session, since MCP tools load at startup.

MCP clients need that HTTP endpoint. For everything else — shell commands and
direct HTTP calls to the node — see
[Talk To The Node Over HTTP](#talk-to-the-node-over-http): the Unix socket gets
you in without a token.

If setup is stuck in a half-configured state, ask the user before starting over:
stop the node, run `sam-node reset --all --yes` for a clean slate, then go back
to step 2. That deletes the node's identity and its PeerID, and enrolling again
needs another login, so never do it to work around an unexplained error.

Put the node API token only in the agent's MCP configuration. Do not echo it
into the transcript, and do not commit it.

## Talk To The Node Over HTTP

The MCP tools need none of this. It applies when a task needs a plain HTTP
request to the node: the OpenAI-compatible `/v1` endpoints, or a
`local_proxy_url` returned by `discover_remote_services`.

There are two ways in. Try them in this order.

**1. The Unix socket, whenever there is one.** `get_mesh_info` reports it as
`local_api_socket`, by default `~/.config/sam-mesh/sam.sock`. It serves the same
API and takes no token at all: only the user who owns the socket can connect to
it, so the filesystem has already done the authenticating. Prefer it, because no
secret reaches a command line, the shell history, or the transcript.

```bash
curl --unix-socket ~/.config/sam-mesh/sam.sock http://localhost/v1/models
```

The host in the URL is a placeholder that curl ignores once it dials a socket.

**2. The TCP endpoint, with the node API token.** Use this when `get_mesh_info`
reports no `local_api_socket`, or when that path is not reachable from where you
run, for example a node inside a container. Do not read your MCP client
configuration to recover it: those files hold the headers of every other server
you are connected to, and reading them puts all of those secrets into the
transcript. A daemonized node writes its token to
`~/.config/sam-mesh/api-token`; let curl read that file itself so the value
never appears in an argument, the shell history, or your output:

```bash
curl http://127.0.0.1:8080/v1/models -H @<(printf 'X-Sam-Authentication: Bearer %s' "$(cat ~/.config/sam-mesh/api-token)")
```

`<(...)` needs bash or zsh; in a plain `sh`, write the header line to a file
with mode 0600 and pass `-H @that-file` instead.

If the node was started with `--api-token-path` or `SAM_API_TOKEN`, ask the
user where the token lives rather than searching for it.

Never print the token or echo it into the transcript. `Authorization` is not the
node's credential: send it only when the destination service needs its own, and
it passes through to that service untouched.

## Diagnose The Node

Operator diagnostics are not MCP tools, so they never appear in the tool list.
A running node serves them under `/debug`, and the `sam-node` CLI wraps each
endpoint over the node's Unix socket — no token involved:

```bash
sam-node debug mesh-info                 # connected peers, DHT size, router peer ID
sam-node debug connectivity [peer-id]    # ping the SAM router, or a specific peer
sam-node debug network-info              # listen and observed addresses
sam-node debug token-info                # local auth token expiration and status
sam-node debug logs                      # recent log lines
sam-node debug connect-peer <multiaddr>  # manually dial a peer
```

Each command prints the endpoint's raw JSON, so it composes with `jq`. The same
data is one `curl` away when the CLI is not at hand:

```bash
curl --unix-socket ~/.config/sam-mesh/sam.sock http://localhost/debug/mesh-info
```

These endpoints answer even while the mesh is unreachable — that is the state
they exist to diagnose. When the node runs but mesh tools fail, check
`debug connectivity` for `router_error_msg` and `debug token-info` for an
expired token before restarting or re-enrolling anything.

## Inspect The Mesh

Start by understanding the local node and mesh state:

- Use `get_mesh_info` with `{}` to inspect `connected_peers`, `dht_size`, and
  `router_peer_id`.
- Use `list_local_services` with `{}` to see services registered on the local
  node.

## Discover Remote Capabilities

Use service discovery when you need to inventory reachable service providers:

- Use `discover_remote_services` with `{"type":"mcp"}`,
  `{"type":"inference"}`, or `{"type":"a2a"}`. Add `name` only when narrowing
  by service name.
- Treat `discover_remote_services` as service inventory. Non-MCP service types
  are not callable with `call_remote_tool`. For `inference://` services see
  [Use Mesh Inference](#use-mesh-inference), for `a2a://` services
  [Call A2A Agents](#call-a2a-agents).

Use tool discovery when you need remote MCP tools:

- Use `find_remote_tools` to discover reachable aggregated MCP tools advertised
  by remote SAM services.
- Narrow `find_remote_tools` with `service_name` or `peer_id` when you already
  know the target.
- Mesh-wide searches fetch each peer's catalog on a best-effort basis and may
  return an empty array when no reachable aggregated tools are found. Discovery
  failures or explicit `peer_id` lookup failures are returned as errors.

## Describe Before Calling

All tools returned by `find_remote_tools` are namespaced. Always call
`describe_remote_tool` before calling them with `call_remote_tool`.

Remote MCP tools returned by `find_remote_tools` are namespaced as:

```text
<scheme>://<service_name>/<tool_name>
```

For example `mcp://everything/get-sum`. Pass the name exactly as returned to
`describe_remote_tool` and `call_remote_tool`; do not reassemble it.

Entries may carry an `error` field instead of a `description` when a peer
advertises a service whose backend did not answer. Discovery is best-effort per
peer, so a partly broken mesh yields a partly populated array rather than a
failed call. Check for `error` before treating a tool as available.

Use the input schema from `describe_remote_tool` to build the call arguments.
Do not guess arguments if a tool cannot be described.

After `describe_remote_tool`, inspect the tool name, description, and schema
for side effects and required data. Only call read-only, low-risk tools
autonomously. Ask the user before calls that may mutate state, execute code,
access files, contact external services, spend money, or transmit sensitive or
private data. Pass only task-required data, and never include secrets unless
explicitly authorized.

## Call Remote Tools

Use `call_remote_tool` with:

- `peer_id`: the peer hosting the tool
- `tool_name`: the discovered namespaced tool name, such as
  `mcp://everything/get-sum`
- `arguments`: a JSON object whose keys match the described input schema

`arguments` must be a JSON object, not a string containing JSON.

## Use Mesh Inference

The mesh also carries `inference://` services: OpenAI-compatible model
endpoints. They are plain HTTP and are never invoked with `call_remote_tool`.

The node exposes them through an OpenAI-compatible facade on its own address:

- Base URL `http://localhost:8080/v1`, usable as `base_url` for any OpenAI SDK
  or a direct `curl`.
- `GET /v1/models` lists the models reachable across the mesh.
- `POST /v1/chat/completions` routes to a provider of the requested `model`,
  preferring a local one, and fails over between providers.
- Add `X-Sam-Required-Labels: key=value` (comma-separated; every pair must
  be attested) to accept only providers whose labels the control plane
  attested, for example `region=eu`. Enforcement is fail-closed: unattested
  providers are rejected before any request data leaves the node.

To pin one specific provider instead of letting the facade choose, call
`discover_remote_services` with `{"type":"inference"}` and send the request to
the returned `local_proxy_url` (append `/v1/chat/completions`).

Authenticate as described in
[Talk To The Node Over HTTP](#talk-to-the-node-over-http): over the socket when
there is one, otherwise with the token from your own MCP configuration. The
`/v1` endpoints also accept that token as `Authorization`, so an OpenAI SDK can
pass it as its `api_key`.

```bash
curl --unix-socket ~/.config/sam-mesh/sam.sock \
  http://localhost/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model": "<model>", "messages": [{"role": "user", "content": "..."}]}'
```

Ask the user before sending private or sensitive content to a mesh model, and
say which provider will receive it.

## Call A2A Agents

The mesh also carries `a2a://` services: agents that speak the A2A protocol.
They are plain HTTP behind the node's proxy path and are never invoked with
`call_remote_tool`. Drive them with the official `a2a` CLI
(github.com/a2aproject/a2a-cli, v0.3.0 or later). It ships its own agent
skill, which covers the protocol side: cards, messages, tasks and streaming.
This section only adds what the mesh needs.

Check for the CLI with `a2a version`. If it is missing, propose the install
from its README (`go install github.com/a2aproject/a2a-cli@latest` names the
binary `a2a-cli`; rename it to `a2a`) and its skill with
`npx skills add https://github.com/a2aproject/a2a-cli --skill a2a-cli`, and
let the user approve each command.

1. Call `discover_remote_services` with `{"type":"a2a"}` and take the
   `local_proxy_url` of the provider you want.
2. Point the CLI at the agent card under that URL. The node regenerates the
   card so its interface URL is the proxy path itself; every later request
   then goes through the mesh with no further SAM-specific setup.
3. The CLI speaks TCP only, so it needs the node API token from
   [Talk To The Node Over HTTP](#talk-to-the-node-over-http) as a service
   parameter. Pass it through the CLI's environment, never as a flag, so the
   value stays out of the process arguments and the shell history:

```bash
A2ACLI_SVC_PARAM="X-Sam-Authentication=Bearer $(cat ~/.config/sam-mesh/api-token)" \
  a2a card get <local_proxy_url>/.well-known/agent-card.json
```

Every other `a2a` command takes the same card URL through `-a` and the same
environment. To accept only a provider whose labels the control plane
attested, append `,X-Sam-Required-Labels=region=eu` to that variable: the
node then refuses fail-closed with `403` before any data leaves it. That
refusal is the feature: report it, never retry with weaker labels on your
own. A `--svc-param` flag replaces the whole variable, and the variable is
split on commas, so several label pairs need a `--config` YAML file with
both entries under `svc-param` instead.

Ask the user before sending private or sensitive content to a mesh agent, and
say which peer will receive it.

## Minimal Workflow

1. Confirm no local tool can satisfy the task.
2. If the `sam-node` MCP tools are unavailable, follow
   [Bootstrap A Node](#bootstrap-a-node) and stop until the user restarts the
   agent session.
3. Call `get_mesh_info` with `{}`.
4. If a local SAM service may be
   relevant, call `list_local_services` with `{}`.
5. Call `find_remote_tools` with `service_name` or `peer_id` when known. Use
   `{}` only when the user asked to inventory the mesh or no narrower target
   exists.
6. Call `describe_remote_tool` with
   `{"peer_id":"...","tool_name":"service.tool"}`.
7. Call `call_remote_tool` only when the described tool is read-only and
   low-risk, or after the user approves the exact `peer_id`, `tool_name`, side
   effects, and task-required data being sent:
   `{"peer_id":"...","tool_name":"service.tool","arguments":{...}}`.

For a model completion rather than a tool, skip steps 5-7 and follow
[Use Mesh Inference](#use-mesh-inference) instead; for an A2A agent,
[Call A2A Agents](#call-a2a-agents).

## Safety And Reliability

- Do not call mesh tools when a local tool is sufficient.
- Do not guess remote tool names or arguments.
- Ask before side-effecting or sensitive remote calls.
- Do not send secrets or private data through SAM unless the user explicitly
  approves the data and destination.
- Treat remote capabilities as networked and potentially unavailable.
- Surface peer, service, discovery, schema, and tool-call errors clearly.
