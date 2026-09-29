---
title: "Node API"
linkTitle: "Node API"
weight: 7
aliases:
  - /docs/development/testnet-validation/
---

The local API that `sam-node run` serves to agents and scripts on the same
machine. It is available on TCP (`--bind-addr`, default `127.0.0.1:8080`)
and on a Unix socket (`--socket-path`, default `<data-dir>/sam.sock`).

## Authentication

| Listener | Requirement |
|---|---|
| TCP | `X-Sam-Authentication: Bearer <api-token>` on every request, or a client certificate when `--tls-ca` is set. |
| Unix socket | None. The socket has mode `0600`. Being able to open it is the credential. |

`Authorization` is reserved for the credential of the service that is being
called through the node, and the proxy path forwards it. The endpoints that
never forward anything (`/mcp`, `/v1/*`, `/sam/service/*`, `/metrics`,
`/sam/identity`, `/sam/peer/*`, `/debug/*`) also accept the API token in
`Authorization: Bearer`, for clients that cannot set custom headers. The
proxy path does not accept it there.

## Routes

| Route | Auth | Purpose |
|---|---|---|
| `GET /healthz`, `GET /readyz` | none | `200` while the process is up. Every other route except `/debug/*` answers `503` until the node is connected to the mesh, so a `503` on `/mcp` is the practical readiness signal. |
| `GET /metrics` | token | Prometheus metrics (`sam_node_*`). |
| `POST /mcp` | token | The MCP server (Streamable HTTP, sessionless: no `Mcp-Session-Id`, `GET` answers `405`). `/` is an alias. |
| `GET /v1/models` | token | Models served by every reachable inference provider. |
| `POST /v1/chat/completions`, `POST /v1/completions` | token | OpenAI-compatible inference, routed to a provider of the requested model. |
| `GET /sam/service/discover` | token | Discover services on the mesh. |
| `ANY /sam/{peer-id}/{type}/{name}[/{path}]` | token | Reverse proxy to one service on one peer. |
| `ANY /egress/{destination}[/{path}]` | token | A destination outside the mesh that this node serves, for local clients. See [Egress](#egress). |
| `GET /sam/identity` | token, socket or mTLS only | This node's credential and the key it verifies under. |
| `GET /sam/peer/{peer-id}/evidence` | token, socket or mTLS only | A peer's credential as this node last verified it. |
| `GET /debug/*` | token | Operator diagnostics. These answer even when the mesh is unreachable. |

`--metrics-addr` serves `/metrics`, `/healthz` and `/readyz` on a second
listener without authentication, for scrapers that hold no token.

## MCP tools

The `/mcp` endpoint speaks Streamable HTTP. The older SSE transport is
refused with `400`. The server's instructions field tells a client how the
tools fit together. The tools are:

### `get_mesh_info`

No parameters. Returns `router_peer_id`, `connected_peers`, `dht_size` and
`local_api_socket`. `connected_peers` and `dht_size` count different things
(transport connections and routing-table entries), so a small `dht_size`
next to a long peer list is normal.

### `list_local_services`

| Parameter | Meaning |
|---|---|
| `type` | Optional filter: `mcp`, `inference`, `a2a`. |

Services this node publishes.

### `discover_remote_services`

| Parameter | Meaning |
|---|---|
| `type` | Required: `mcp`, `inference` or `a2a`. |
| `name` | Optional service name. Omit to list every reachable service of the type. |
| `limit`, `offset` | Pagination. Defaults are 20 and 0. |

Each result has `peer_id`, `srv_name`, `srv_description` and, when the
provider declared them, `labels`. Service names are not unique across the
mesh. The peer ID identifies the provider. For `type: inference` the
response adds a `local_proxy_url` per provider and a note that inference is
called over HTTP and not with `call_remote_tool`.

### `find_remote_tools`

| Parameter | Meaning |
|---|---|
| `peer_id` | Restrict the search to one peer. |
| `service_name` | Restrict the search to one service, bare (`code-reviewer`) or namespaced (`mcp://code-reviewer`). |
| `tool_name` | Exact tool name to locate across the mesh (`review_pr`). Answered from gossip announcements when they are fresh. |
| `intent` | Accepted and ignored. Reserved for later use. |

Returns one row per tool with `peer_id`, `tool_name` (namespaced as
`mcp://service/tool`), `description` and `labels`. A peer that could not be
queried appears as a row with an `error` field. The call itself does not
fail.

### `describe_remote_tool`

| Parameter | Meaning |
|---|---|
| `peer_id` | Required. |
| `tool_name` | Required, namespaced as returned by `find_remote_tools`. |

Returns `description`, `input_schema` and `output_schema`.

### `call_remote_tool`

| Parameter | Meaning |
|---|---|
| `peer_id` | Required. |
| `tool_name` | Required, namespaced. |
| `arguments` | Object matching the tool's `input_schema`. |
| `required_labels` | `key=value[,key=value]`. The call is refused unless the peer's credential attests every one of them. |

Returns the tool's result content. A policy denial comes back as a tool
error that the caller can read, not as a transport failure.

### When the node has no credential

A node that starts without a credential and without a way to enroll serves
a reduced MCP server with one tool, `get_login_instructions`, and one
prompt, `help_user_login`. Both tell the client to run `sam-node join`.

## Service discovery over HTTP

`GET /sam/service/discover?type=mcp[&name=calculator][&limit=20&offset=0][&timeout=10s]`
returns the same JSON array as `discover_remote_services`. With
`&stream=true` or `Accept: text/event-stream`, results arrive as
server-sent events as they are found, and the stream ends with
`event: done`.

## The proxy path

```text
/sam/<peer-id>/<type>/<name>/<path...>
```

The node verifies the peer's credential and, if set, the operator's
`egress.require_labels`. It then opens an authenticated stream and forwards
the request to `/<type>/<name>/<path>` on the peer, which proxies it to the
backend. Headers pass through, including `Authorization`. Paths that contain
`..` are refused. For an `mcp` service, `<path>` is empty and the request
body is the JSON-RPC message. For `inference`, `<path>` is `v1/models` or
`v1/chat/completions`. For `a2a`, `<path>` is whatever the agent serves, and
`.well-known/agent-card.json` is rewritten for the mesh.

Two headers modify a proxied request:

| Header | Effect |
|---|---|
| `X-Sam-Required-Labels: k=v[,k=v]` | Forward only to a peer whose credential attests every listed pair. Otherwise `403`. Removed before forwarding. Also honoured on `/v1/*`. |
| `X-Sam-Agent: <agent-id>` | Name the agent for which this request is made. Only meaningful when sent by a `sam-box`. See the [preview](../../preview/sandboxed-agents/). |

### Talking MCP through the proxy

An MCP session with a remote service, without using the node's own tools:

```bash
SOCK=~/.config/sam-mesh/sam.sock
URL=http://localhost/sam/<peer-id>/mcp/everything

# initialize; the Mcp-Session-Id response header identifies the session
curl -si --unix-socket $SOCK $URL \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'

# subsequent calls carry the session id
curl -s --unix-socket $SOCK $URL \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'Mcp-Session-Id: <id from above>' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

Over TCP, add `-H "X-Sam-Authentication: Bearer $TOKEN"` and use
`http://127.0.0.1:8080` as the base URL.

### Talking A2A through the proxy

An A2A client starts from the agent card. Fetched through the proxy path,
the card comes back regenerated: its interface URL is the proxy path
itself, so a stock client sends `message/send` there without changes:

```bash
curl -s --unix-socket $SOCK \
  http://localhost/sam/<peer-id>/a2a/triage/.well-known/agent-card.json
```

The official [`a2a` CLI](https://github.com/a2aproject/a2a-cli) (v0.3.0 or
later) is such a client. It speaks TCP only, so the token travels as a
service parameter, set through the environment to keep it off the command
line; `X-Sam-Required-Labels` goes in the same variable, comma-separated:

```bash
CARD=http://127.0.0.1:8080/sam/<peer-id>/a2a/triage/.well-known/agent-card.json
export A2ACLI_SVC_PARAM="X-Sam-Authentication=Bearer $TOKEN"
a2a card get $CARD
a2a send -a $CARD "hello"
```

## Inference

`/v1/models` collects the model list of every reachable `inference` provider
(cached for 30 seconds) and returns the union. `owned_by` on each entry is
the peer that serves the model. A completion request names a model, and the
node picks a provider that serves it. It prefers a local provider, and ranks
remote providers by the labels the caller required, the operator's floor,
and load. A model that no provider lists answers `404`.

```bash
curl -s --unix-socket $SOCK http://localhost/v1/models

curl -s --unix-socket $SOCK http://localhost/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"<model-id>","messages":[{"role":"user","content":"hi"}]}'
```

Any OpenAI SDK works with `base_url` set to `http://127.0.0.1:8080/v1` and
the API token as `api_key`. The node accepts the token in `Authorization`
here because nothing on this path forwards that header. Streaming responses
are passed through. One provider can also be addressed directly, at
`/sam/<peer-id>/inference/<name>/v1/chat/completions`.

## Egress

`/egress/<destination>/<path>` reaches a destination outside the mesh that
the control plane assigned to this node (an entry of the
[egress section](../policy/#egress-destinations) of the mesh policy whose
`served_by` selects it). The node is the HTTP origin: it authorizes the
request on its own credential, with the request's method and path and the
destination's host and port as facts, forwards it to the destination's
`target_url` with the credential the policy names, and returns the answer.

```bash
curl -s --unix-socket $SOCK "http://localhost/egress/api.github.com/repos/acme/dubbing/pulls?state=open"
```

An application that takes a base URL for the API it calls points it at the
node, `http://127.0.0.1:8080/egress/api.github.com`, and sends the API
token as its bearer, the way it would send a provider key. The node accepts
the token in `Authorization` on this path and never forwards that header:
the destination sees the node's credential and none of the client's
headers. A client may name the agent it acts for in `X-Sam-Agent`; the
claim is checked against the node's `allowed_agents` grant and is visible
to policy as `agent()`.

`403` is a policy decision: the node's role lacks the destination, an
`http` narrowing excludes the method or path, or the node's `attenuation`
refuses the request. `404` is a destination the control plane did not
assign to this node. Both carry a `Proxy-Status` header (RFC 9209) naming
the node as the source, `sam-node; error=http_request_denied` or
`error=destination_not_found`, so a client can tell them from a `403` or
`404` the destination itself sent, which carries none. A destination whose
credential file went missing after registration answers `502` with
`error=proxy_configuration_error`. The same destination is reachable from
another mesh member at `/sam/<peer-id>/egress/<destination>/<path>` on that
member's node, authorized on the member's credential.

The path is a prefix under the destination, so a client that follows
absolute URLs returned by the destination (a `Link` header, a URL in a
body) leaves the node. Point it back at the prefix, or use a client that
takes a base URL.

## Identity evidence

`GET /sam/identity` returns the node's credential (base64), the control
plane public key it verifies under (SPKI DER), the peer ID, roles, labels
and expiry. `GET /sam/peer/{peer-id}/evidence` returns the same for a peer
that the node has authenticated. Both refuse plain TCP. They are reachable
only over the Unix socket or over an mTLS-verified connection, because this
material is meant for the node's owner and for auditors, not for agents.

## Debug

`GET /debug/mesh-info`, `GET /debug/connectivity`, `GET /debug/network-info`,
`GET /debug/token-info`, `GET /debug/logs` and `POST /debug/connect-peer`
report and probe the node's view of the mesh for troubleshooting, and answer
even while the mesh is unreachable. `sam-node debug` on the command line
wraps them. Their output is not stable across releases.
