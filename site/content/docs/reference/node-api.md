---
title: "Node API"
linkTitle: "Node API"
weight: 7
aliases:
  - /docs/development/testnet-validation/
---

The local API that `agentmesh-node run` serves to agents, gateways, and scripts on
the same machine or cluster. It is available on TCP (`--bind-addr`, default
`127.0.0.1:8080`) and on a Unix socket (`--socket-path`, default
`<data-dir>/agentmesh.sock`). The Envoy `ext_authz` and `ext_proc` endpoints are
served on the same listeners.

## Authentication

| Listener | Requirement |
|---|---|
| TCP (`--bind-addr`) | `X-Mesh-Authentication: Bearer <token>` on every request, or `Authorization: Bearer <token>` on non-proxy endpoints (`/mcp`, `/v1/*`, `/egress/*`, `/oauth/*`), or a client certificate when `--tls-ca` is set. |
| Unix socket (`--socket-path`) | None required for node-level access (the socket has mode `0600`). A caller may still pass an Agent Mesh Task Biscuit or platform JWT in `X-Mesh-Authentication` or `Authorization` to scope the request to that caller's identity and task rules. |

The bearer `<token>` accepted by `agentmesh-node` can be:

1. **The node's static API token** (`--api-token-path` or `AGENTMESH_API_TOKEN`),
   which exercises the node's own enrolled credential.
2. **An Agent Mesh Biscuit** (a Member Biscuit, a Delegated Session Biscuit, or a
   task-attenuated Biscuit with `tar_block` blocks), base64-encoded.
3. **An external platform JWT** (an OIDC ID token, Kubernetes projected service
   account token, or SPIFFE JWT-SVID). On `/mcp`, `/v1/*`, `/mesh/*` (via
   `X-Mesh-Authentication`), and `/egress/*`, `agentmesh-node` exchanges the JWT via
   the control plane's stateless `POST /token/exchange` endpoint (cached until
   expiry) and forwards the resulting Delegated Session Biscuit.

On `/mesh/{peer-id}/{type}/{name}/...`, the `Authorization` header is reserved
exclusively for the destination service's own credential and passes through
untouched; callers of `/mesh/...` pass their Agent Mesh token or platform JWT in
`X-Mesh-Authentication: Bearer <token>`.

When a request on TCP fails authentication with `401 Unauthorized`, `agentmesh-node`
includes `WWW-Authenticate: Bearer resource_metadata="http://<host>/.well-known/oauth-protected-resource"`
per RFC 9728 so standard MCP OAuth 2.1 clients can discover the control plane
Authorization Server.

## Routes

| Route | Auth | Purpose |
|---|---|---|
| `GET /healthz`, `GET /readyz` | none | `200` while the process is up. Every other route except `/debug/*` and `/.well-known/*` answers `503` until the node is connected to the mesh. |
| `GET /.well-known/oauth-protected-resource` | none | RFC 9728 OAuth 2.1 Protected Resource Metadata naming the Agent Mesh control plane in `authorization_servers`. |
| `GET /.well-known/oauth-authorization-server` | none | RFC 8414 metadata for this node's token endpoint: the grant types and client authentication methods it accepts. |
| `POST /oauth/token` | token or client assertion | Token endpoint: RFC 8693 token exchange, RFC 7523 client assertion and JWT authorization grants. Every grant returns a Delegated or Task-Attenuated Biscuit. See [Token endpoint (`/oauth/token`)](#token-endpoint-oauthtoken). |
| `POST /oauth/revoke` | token | RFC 7009 Token Revocation: revokes a task Biscuit in this node's local revocation cache. |
| `GET /metrics` | token | Prometheus metrics (`agentmesh_node_*`). |
| `POST /mcp` | token | The MCP server (Streamable HTTP, sessionless: no `Mcp-Session-Id`, `GET` answers `405`). `/` is an alias. |
| `GET /v1/models` | token | Models served by every reachable inference provider. |
| `POST /v1/chat/completions`, `POST /v1/completions` | token | OpenAI-compatible inference, routed to a provider of the requested model. |
| `GET /mesh/service/discover` | token | Discover services on the mesh. |
| `ANY /mesh/{peer-id}/{type}/{name}[/{path}]` | token | Reverse proxy to one service on one peer. |
| `ANY /egress/{destination}[/{path}]` | token | HTTP proxy to an external destination assigned to this node. See [Egress](#egress). |
| `CONNECT {destination}:{port}` | token | Named TCP tunnel to an `EGRESS_MODE_TCP` destination assigned to this node. |
| `GET /mesh/identity` | token, socket or mTLS only | This node's credential and the key it verifies under. |
| `GET /mesh/peer/{peer-id}/evidence` | token, socket or mTLS only | A peer's credential as this node last verified it. |
| `GET /debug/*` | token | Operator diagnostics. These answer even when the mesh is unreachable. |

`--metrics-addr` serves `/metrics`, `/healthz` and `/readyz` on a second
listener without authentication, for scrapers that hold no token.

## Token endpoint (`/oauth/token`) and revocation (`/oauth/revoke`)

`POST /oauth/token` takes `application/x-www-form-urlencoded` and accepts
three grant types. Each one ends in a Biscuit: a platform JWT is exchanged at
the control plane's `POST /token/exchange`, a Biscuit is attenuated locally.

| `grant_type` | Subject | Standard |
|---|---|---|
| `urn:ietf:params:oauth:grant-type:token-exchange` | `subject_token` with `subject_token_type` | RFC 8693 token exchange. |
| `client_credentials` | `client_assertion` with `client_assertion_type` | RFC 7523 section 2.2 client authentication. The assertion both authenticates the client and names the subject. |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | `assertion` | RFC 7523 section 2.1 JWT authorization grant, as produced by OAuth identity chaining. |

| Parameter | Meaning |
|---|---|
| `subject_token` | Token exchange: the input JWT or base64 Biscuit. If omitted when the caller is authenticated (API token, local socket, or `client_assertion`), defaults to that caller's Biscuit, or to the node's own Biscuit. |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt`, `id_token`, `access_token`, or `urn:agentmesh:params:oauth:token-type:biscuit`. |
| `client_assertion`, `client_assertion_type` | A JWT with type `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` or `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe` (a SPIFFE JWT-SVID). Required for `client_credentials`; on any other grant it authenticates the caller. The control plane verifies the JWT against its `--issuer`, `--workload-issuer` and `--allowed-audiences`, so a JWT-SVID must carry one of those audiences. A rejected assertion answers `401 invalid_client`. |
| `assertion` | The JWT authorization grant for `jwt-bearer`. |
| `options` (or `scope` / `resource`) | Optional `TaskAuthorizationRule` as protojson (or space-separated service patterns in `scope`) to append as a `tar_block`. |
| `seal` | Optional (`true` / `1`): seal the returned Biscuit so downstream holders cannot append further blocks. |

Returns standard RFC 8693 JSON (`access_token`,
`issued_token_type: "urn:agentmesh:params:oauth:token-type:biscuit"`,
`token_type: "Bearer"`, `expires_in`).

`GET /.well-known/oauth-authorization-server` lists these grant types in
`grant_types_supported` and `none`, `private_key_jwt` and `spiffe_jwt` in
`token_endpoint_auth_methods_supported`, so an OAuth client that discovers its
token endpoint can pick the client assertion type it holds.

An OpenShell provider profile that acquires its credential with a
`client_credentials` token grant posts exactly this shape:

```yaml
token_grant:
  grant_type: client_credentials
  token_endpoint: https://agentmesh-node.internal:8080/oauth/token
  client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt-spiffe
  jwt_svid_audience: agentmesh-audience
  scopes: ["mcp://github", "inference://*"]
```

`POST /oauth/revoke` accepts `token=<base64-biscuit>` and records its leaf
revocation ID in the node's local revocation cache until the token expires.

## Envoy `ext_authz` and `ext_proc` gateway integration

On the local API listeners, `agentmesh-node` serves:

- **Envoy HTTP `ext_authz` (`/ext_authz`, `/ext_authz/*`)** and **gRPC
  `envoy.service.auth.v3.Authorization/Check`**: evaluates standing Datalog
  policy and any `tar_block` chain on the request. The credential is read
  from `X-Mesh-Biscuit`, or from a Bearer value in `X-Mesh-Authentication` or
  `Authorization`. A Bearer value that is a platform JWT is exchanged at the
  control plane (`POST /token/exchange`) into a delegated Biscuit before
  evaluation; a request with no credential is refused with `401`. The target
  service is taken from `X-Mesh-Target-Service` or from the `/mesh/<peer>/<type>/<name>`
  request path. On `OK`, the response carries `X-Mesh-Biscuit`,
  `X-Mesh-Principal`, `X-Mesh-Roles`, and, when the token is task-attenuated,
  `X-Mesh-Task` (the last `TaskAuthorizationRule` as protojson) and
  `X-Mesh-Task-Id`. For an `egress://` target with a configured credential
  broker it also carries the brokered `Authorization` header for the upstream.
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
Delegated or Task-Attenuated Biscuit, `agentmesh-node` forwards that Biscuit on the
mesh stream so the provider enforces the caller's roles and `tar_block` tool
restrictions. A policy denial comes back as a tool error that the caller can
read, not as a transport failure.

### When the node has no credential

A node that starts without a credential and without a way to enroll serves
a reduced MCP server with one tool, `get_login_instructions`, and one
prompt, `help_user_login`. Both tell the client to run `agentmesh-node join`.

## Service discovery over HTTP

`GET /mesh/service/discover?type=mcp[&name=calculator][&limit=20&offset=0][&timeout=10s]`
returns the same JSON array as `discover_remote_services`. With
`&stream=true` or `Accept: text/event-stream`, results arrive as
server-sent events as they are found, and the stream ends with
`event: done`.

## The proxy path

```text
/mesh/<peer-id>/<type>/<name>/<path...>
```

The node verifies the peer's credential and, if set, the operator's
`egress.require_labels`. It then opens an authenticated stream (presenting the
caller's Task Biscuit when one was supplied in `X-Mesh-Authentication`) and
forwards the request to `/<type>/<name>/<path>` on the peer, which proxies it
to the backend. Headers pass through, including `Authorization`. Paths that
contain `..` are refused. For an `mcp` service, `<path>` is empty and the
request body is the JSON-RPC message. For `inference`, `<path>` is `v1/models`
or `v1/chat/completions`. For `a2a`, `<path>` is whatever the agent serves,
and `.well-known/agent-card.json` is rewritten for the mesh.

| Header | Effect |
|---|---|
| `X-Mesh-Required-Labels: k=v[,k=v]` | Forward only to a peer whose credential attests every listed pair. Otherwise `403`. Removed before forwarding. Also honoured on `/v1/*`. |

### Talking MCP through the proxy

An MCP session with a remote service, without using the node's own tools:

```bash
SOCK=~/.config/agentmesh/agentmesh.sock
URL=http://localhost/mesh/<peer-id>/mcp/everything

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

Over TCP, add `-H "X-Mesh-Authentication: Bearer $TOKEN"` and use
`http://127.0.0.1:8080` as the base URL.

### Talking A2A through the proxy

An A2A client starts from the agent card. Fetched through the proxy path,
the card comes back regenerated: its interface URL is the proxy path
itself, so a stock client sends `message/send` there without changes:

```bash
curl -s --unix-socket $SOCK \
  http://localhost/mesh/<peer-id>/a2a/triage/.well-known/agent-card.json
```

The official [`a2a` CLI](https://github.com/a2aproject/a2a-cli) (v0.3.0 or
later) is such a client. It speaks TCP only, so the token travels as a
service parameter, set through the environment to keep it off the command
line; `X-Mesh-Required-Labels` goes in the same variable, comma-separated:

```bash
CARD=http://127.0.0.1:8080/mesh/<peer-id>/a2a/triage/.well-known/agent-card.json
export A2ACLI_SVC_PARAM="X-Mesh-Authentication=Bearer $TOKEN"
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
addressed directly, at `/mesh/<peer-id>/inference/<name>/v1/chat/completions`.

## Egress

`/egress/<destination>/<path>` reaches an external HTTP destination that the
control plane assigned to this node (an entry of the
[egress section](../policy/#egress-destinations) of the mesh policy whose
`served_by` selects it). The node is the HTTP origin:

1. It authorizes the request against the caller's Biscuit (or the node's own
   credential for local socket calls), evaluating standing Datalog policy and
   any appended `TaskAuthorizationRule` (`tar_block`) chain against `service`,
   `method`, `path`, `host`, and `port`.
2. It strips the caller's `Authorization`, `Cookie`, `X-Mesh-*`, and
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

`403` is a policy or inspection decision (`Proxy-Status: agentmesh-node; error=http_request_denied`).
`404` is a destination the control plane did not assign to this node
(`error=destination_not_found`). A destination whose broker cannot obtain a
credential answers `502` with `error=proxy_configuration_error`. The same
destination is reachable from another mesh member at
`/mesh/<peer-id>/egress/<destination>/<path>` on that member's node, authorized
on the caller's Biscuit.

### Named TCP tunnels (`CONNECT` and `agentmesh-node forward`)

For destinations with `mode: EGRESS_MODE_TCP` and an allowed `ports` list, the
node accepts HTTP `CONNECT <destination>:<port>` on its local listener and
verifies that the TLS `ClientHello` SNI matches `<destination>` (and does not
use Encrypted Client Hello) before splicing the stream to the remote egress
node. Clients that do not speak `CONNECT` can use `agentmesh-node forward`:

```bash
agentmesh-node forward egress://pg.internal.example:5432 127.0.0.1:15432
```

## Identity evidence

`GET /mesh/identity` returns the node's credential (base64), the control
plane public key it verifies under (SPKI DER), the peer ID, roles, labels
and expiry. `GET /mesh/peer/{peer-id}/evidence` returns the same for a peer
that the node has authenticated. Both refuse plain TCP. They are reachable
only over the Unix socket or over an mTLS-verified connection, because this
material is meant for the node's owner and for auditors, not for agents.

## Debug

`GET /debug/mesh-info`, `GET /debug/connectivity`, `GET /debug/network-info`,
`GET /debug/token-info`, `GET /debug/logs` and `POST /debug/connect-peer`
report and probe the node's view of the mesh for troubleshooting, and answer
even while the mesh is unreachable. `agentmesh-node debug` on the command line
wraps them. Their output is not stable across releases.
