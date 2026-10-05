---
title: "Node API"
linkTitle: "Node API"
weight: 7
aliases:
  - /docs/development/testnet-validation/
---

The local API that `sam-node run` serves to agents, gateways, and scripts on
the same machine or cluster. It is available on TCP (`--bind-addr`, default
`127.0.0.1:8080`), on a Unix socket (`--socket-path`, default
`<data-dir>/sam.sock`), and optionally on a dedicated Envoy `ext_authz` /
`ext_proc` listener (`--ext-authz-addr`).

## Authentication

| Listener | Requirement |
|---|---|
| TCP (`--bind-addr`) | `X-Sam-Authentication: Bearer <token>` on every request, or `Authorization: Bearer <token>` on non-proxy endpoints (`/mcp`, `/v1/*`, `/egress/*`, `/oauth/*`), or a client certificate when `--tls-ca` is set. |
| Unix socket (`--socket-path`) | None required for node-level access (the socket has mode `0600`). A caller may still pass a SAM Task Biscuit or platform JWT in `X-Sam-Authentication` or `Authorization` to scope the request to that caller's identity and task rules. |

The bearer `<token>` accepted by `sam-node` can be:

1. **The node's static API token** (`--api-token-path` or `SAM_API_TOKEN`),
   which exercises the node's own enrolled credential.
2. **A SAM Biscuit** (a Member Biscuit, a Delegated Session Biscuit, or a
   task-attenuated Biscuit with `tar_block` blocks), base64-encoded.
3. **An external platform JWT** (an OIDC ID token, Kubernetes projected service
   account token, or SPIFFE JWT-SVID). On `/mcp`, `/v1/*`, `/sam/*` (via
   `X-Sam-Authentication`), and `/egress/*`, `sam-node` exchanges the JWT via
   the control plane's stateless `POST /token/exchange` endpoint (cached until
   expiry) and forwards the resulting Delegated Session Biscuit.

On `/sam/{peer-id}/{type}/{name}/...`, the `Authorization` header is reserved
exclusively for the destination service's own credential and passes through
untouched; callers of `/sam/...` pass their SAM token or platform JWT in
`X-Sam-Authentication: Bearer <token>`.

When a request on TCP fails authentication with `401 Unauthorized`, `sam-node`
includes `WWW-Authenticate: Bearer resource_metadata="http://<host>/.well-known/oauth-protected-resource"`
per RFC 9728 so standard MCP OAuth 2.1 clients can discover the control plane
Authorization Server.

## Routes

| Route | Auth | Purpose |
|---|---|---|
| `GET /healthz`, `GET /readyz` | none | `200` while the process is up. Every other route except `/debug/*` and `/.well-known/*` answers `503` until the node is connected to the mesh. |
| `GET /.well-known/oauth-protected-resource` | none | RFC 9728 OAuth 2.1 Protected Resource Metadata naming the SAM control plane in `authorization_servers`. |
| `POST /oauth/token` | token | RFC 8693 Token Exchange: exchanges a platform JWT or Biscuit into a Delegated or Task-Attenuated Biscuit. See [Token exchange (`/oauth/token`)](#token-exchange-oauthtoken). |
| `POST /oauth/revoke` | token | RFC 7009 Token Revocation: revokes a task Biscuit in this node's local revocation cache. |
| `GET /metrics` | token | Prometheus metrics (`sam_node_*`). |
| `POST /mcp` | token | The MCP server (Streamable HTTP, sessionless: no `Mcp-Session-Id`, `GET` answers `405`). `/` is an alias. |
| `GET /v1/models` | token | Models served by every reachable inference provider. |
| `POST /v1/chat/completions`, `POST /v1/completions` | token | OpenAI-compatible inference, routed to a provider of the requested model. |
| `GET /sam/service/discover` | token | Discover services on the mesh. |
| `ANY /sam/{peer-id}/{type}/{name}[/{path}]` | token | Reverse proxy to one service on one peer. |
| `ANY /egress/{destination}[/{path}]` | token | HTTP proxy to an external destination assigned to this node. See [Egress](#egress). |
| `CONNECT {destination}:{port}` | token | Named TCP tunnel to an `EGRESS_MODE_TCP` destination assigned to this node. |
| `GET /sam/identity` | token, socket or mTLS only | This node's credential and the key it verifies under. |
| `GET /sam/peer/{peer-id}/evidence` | token, socket or mTLS only | A peer's credential as this node last verified it. |
| `GET /debug/*` | token | Operator diagnostics. These answer even when the mesh is unreachable. |

`--metrics-addr` serves `/metrics`, `/healthz` and `/readyz` on a second
listener without authentication, for scrapers that hold no token.

## Token exchange (`/oauth/token`) and revocation (`/oauth/revoke`)

`POST /oauth/token` implements RFC 8693 (`application/x-www-form-urlencoded`):

| Parameter | Meaning |
|---|---|
| `grant_type` | Required: `urn:ietf:params:oauth:grant-type:token-exchange`. |
| `subject_token` | The input JWT or base64 Biscuit. If omitted when authenticated with the node's API token, defaults to the node's own Biscuit. |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt`, `id_token`, `access_token`, or `urn:sam-mesh:params:oauth:token-type:biscuit`. |
| `options` (or `scope` / `resource`) | Optional `TaskAuthorizationRule` as protojson (or space-separated service patterns in `scope`) to append as a `tar_block`. |
| `seal` | Optional (`true` / `1`): seal the returned Biscuit so downstream holders cannot append further blocks. |

Returns standard RFC 8693 JSON (`access_token`,
`issued_token_type: "urn:sam-mesh:params:oauth:token-type:biscuit"`,
`token_type: "Bearer"`, `expires_in`).

`POST /oauth/revoke` accepts `token=<base64-biscuit>` and records its leaf
revocation ID in the node's local revocation cache until the token expires.

## Envoy `ext_authz` and `ext_proc` gateway integration

When `--ext-authz-addr` (`host:port` or `unix:/path`) is set (or on the local
API listener), `sam-node` serves:

- **Envoy HTTP `ext_authz` (`/ext_authz`, `/ext_authz/*`)** and **gRPC
  `envoy.service.auth.v3.Authorization/Check`**: evaluates standing Datalog
  policy and any `tar_block` chain on the request. On a trusted `--ext-authz-addr`
  listener, if no Bearer token is present, `sam-node` extracts the caller's
  verified SPIFFE principal from `AttributeContext.Source.Principal` or
  `X-Forwarded-Client-Cert` (XFCC) and exchanges it into a Delegated Session
  Biscuit. On `OK`, it injects `Authorization: Bearer <upstream-token>`,
  `X-Sam-Principal`, and `X-Sam-Task-Id`.
- **Envoy gRPC `envoy.service.ext_proc.v3.ExternalProcessor/Process`**: the
  body-aware gateway processor. It inspects JSON-RPC bodies on MCP `tools/call`
  requests to enforce `operation.allowed_tools` in `TaskAuthorizationRule`
  blocks before injecting the upstream credential.

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

Returns the tool's result content. If the caller authenticated with a
Delegated or Task-Attenuated Biscuit, `sam-node` forwards that Biscuit on the
mesh stream so the provider enforces the caller's roles and `tar_block` tool
restrictions. A policy denial comes back as a tool error that the caller can
read, not as a transport failure.

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
`egress.require_labels`. It then opens an authenticated stream (presenting the
caller's Task Biscuit when one was supplied in `X-Sam-Authentication`) and
forwards the request to `/<type>/<name>/<path>` on the peer, which proxies it
to the backend. Headers pass through, including `Authorization`. Paths that
contain `..` are refused. For an `mcp` service, `<path>` is empty and the
request body is the JSON-RPC message. For `inference`, `<path>` is `v1/models`
or `v1/chat/completions`. For `a2a`, `<path>` is whatever the agent serves,
and `.well-known/agent-card.json` is rewritten for the mesh.

| Header | Effect |
|---|---|
| `X-Sam-Required-Labels: k=v[,k=v]` | Forward only to a peer whose credential attests every listed pair. Otherwise `403`. Removed before forwarding. Also honoured on `/v1/*`. |

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
the API token, Task Biscuit, or platform JWT as `api_key`. The node accepts
the token in `Authorization` here because nothing on this path forwards that
header. Streaming responses are passed through. One provider can also be
addressed directly, at `/sam/<peer-id>/inference/<name>/v1/chat/completions`.

## Egress

`/egress/<destination>/<path>` reaches an external HTTP destination that the
control plane assigned to this node (an entry of the
[egress section](../policy/#egress-destinations) of the mesh policy whose
`served_by` selects it). The node is the HTTP origin:

1. It authorizes the request against the caller's Biscuit (or the node's own
   credential for local socket calls), evaluating standing Datalog policy and
   any appended `TaskAuthorizationRule` (`tar_block`) chain against `service`,
   `method`, `path`, `host`, and `port`.
2. It strips the caller's `Authorization`, `Cookie`, `X-Sam-*`, and
   `X-Forwarded-*` headers (unless `forward_context` is set for an operator
   inspection chain).
3. It runs any configured [content inspectors](../policy/#content-inspection)
   (`model_armor`, `ext_proc`) before injecting secrets.
4. It brokers the upstream credential via `CloudTokenExchanger` (`static_secret`,
   `oidc_federation` via `POST /sts/token`, `aws_assume_role`, or
   `platform_identity`), injects `Authorization: Bearer ...`, and forwards the
   request to `target_url` (preserving `Host: <destination>` when
   `preserve_host` is enabled).

```bash
curl -s --unix-socket $SOCK "http://localhost/egress/api.github.com/repos/acme/dubbing/pulls?state=open"
```

`403` is a policy or inspection decision (`Proxy-Status: sam-node; error=http_request_denied`).
`404` is a destination the control plane did not assign to this node
(`error=destination_not_found`). A destination whose broker cannot obtain a
credential answers `502` with `error=proxy_configuration_error`. The same
destination is reachable from another mesh member at
`/sam/<peer-id>/egress/<destination>/<path>` on that member's node, authorized
on the caller's Biscuit.

### Named TCP tunnels (`CONNECT` and `sam-node forward`)

For destinations with `mode: EGRESS_MODE_TCP` and an allowed `ports` list, the
node accepts HTTP `CONNECT <destination>:<port>` on its local listener and
verifies that the TLS `ClientHello` SNI matches `<destination>` (and does not
use Encrypted Client Hello) before splicing the stream to the remote egress
node. Clients that do not speak `CONNECT` can use `sam-node forward`:

```bash
sam-node forward egress://pg.internal.example:5432 127.0.0.1:15432
```

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
