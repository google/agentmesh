---
title: "Exposing mesh services to external callers"
linkTitle: "External ingress"
weight: 4
---

Sometimes an agent, MCP server, or OpenAI-compatible inference endpoint on an
enrolled `agentmesh-node` needs to be reached by an HTTP client that is not on
the mesh: a hosted assistant, a chat bridge, a browser client, or a paired CLI
such as `a2a-serve`.

Agent Mesh handles external HTTP ingress at `agentmesh-router` (and on the
single port of `agentmesh-one`), so `agentmesh-control-plane` never carries
data-plane traffic and the serving laptop or sandbox needs no inbound firewall
ports, subdomains, wildcard DNS, or extra TLS certificates.

Every exposed service is addressed at one deterministic path:

```text
<public-url>/ingress/<peer_id>/<service_type>/<service_name>[/<subpath>]
```

For example:

```text
https://bananas.sam-mesh.dev/ingress/12D3KooW.../a2a/coder
```

## Two-layer opt-in

Nothing on the mesh is reachable from `/ingress/` unless **both** the mesh
administrator and the node owner opt in:

1. **Admin ceiling (`PolicyRole.allowed_ingress`)**: the node's mesh role must
   grant external exposure for that service pattern (`a2a://coder`, `mcp://*`,
   or `*`). Omitting `allowed_auth_modes` permits only the zero-trust default
   (`INGRESS_AUTH_MODE_EDGE`). `INGRESS_AUTH_MODE_PASSTHROUGH` is refused unless
   a role explicitly lists it.
2. **Node service config (`services[].ingress`)**: the node's
   `agentmesh-node.yaml` must include an `ingress:` block on that `a2a`, `mcp`,
   or `inference` service. Services without `ingress:` always return `404` on
   `/ingress/`.

## What the admin writes

In `agentmesh-one` development mode (no `--policy-file`), `mesh:role:node`
grants `INGRESS_AUTH_MODE_EDGE` on `*` out of the box so zero-trust external
ingress works with zero configuration. `INGRESS_AUTH_MODE_PASSTHROUGH` is never
granted by default, even in `agentmesh-one`: pass `--policy-file` or update the
policy via `POST /policies` to enable `passthrough` for a role.

On a production mesh, grant `allowed_ingress` on the serving node's role and
bind external callers to a role whose `allowed_services` and `allowed_targets`
permit calling the service:

```json
{
  "roles": [
    {
      "name": "laptop-agent",
      "allowed_publish": ["a2a://coder", "mcp://git"],
      "allowed_ingress": [
        { "services": ["a2a://coder", "mcp://git"] }
      ]
    },
    {
      "name": "paired-agent",
      "allowed_publish": ["a2a://paired"],
      "allowed_ingress": [
        {
          "services": ["a2a://paired"],
          "allowed_auth_modes": [
            "INGRESS_AUTH_MODE_EDGE",
            "INGRESS_AUTH_MODE_PASSTHROUGH"
          ]
        }
      ]
    },
    {
      "name": "external-caller",
      "allowed_services": ["a2a://coder", "mcp://git"],
      "allowed_targets": ["*"]
    }
  ],
  "bindings": [
    { "role": "laptop-agent",    "members": ["email:alice@example.com"] },
    { "role": "external-caller", "members": ["email:*@example.com"] }
  ]
}
```

## What the node owner writes

Add `ingress:` to any `a2a`, `mcp`, or `inference` entry in `agentmesh-node.yaml`:

```yaml
version: "v1alpha1"
services:
  # Zero-trust default (auth_mode: edge): router + node verify a Delegated
  # Session Biscuit and evaluate Datalog RBAC, TAR attenuation, and allow list.
  - type: a2a
    name: coder
    target_url: "http://127.0.0.1:9001"
    ingress:
      allow:
        - "email:alice@example.com"
        - "group:teammates"

  # Opt-in passthrough: forwards Authorization untouched to a backend that
  # enforces its own application-layer pairing token (requires PASSTHROUGH in
  # the node's PolicyRole.allowed_ingress).
  - type: a2a
    name: paired
    target_url: "http://127.0.0.1:9002"
    ingress:
      auth_mode: passthrough
```

When `agentmesh-node` starts and announces the service, it logs the public URL
from the mesh's router lease and exposes it in `agentmesh-node debug services`:

```text
[Ingress] Published a2a://coder at https://bananas.sam-mesh.dev/ingress/12D3KooW.../a2a/coder (auth_mode=edge)
```

If the node's mesh role does not grant external exposure for that service or
auth mode, `agentmesh-node` logs an error, increments
`agentmesh_node_service_provide_failures_total{scope="ingress"}`, and falls back
to announcing the service internally so mesh peers can still reach it.

## How `edge` and `passthrough` behave

### `auth_mode: edge` (default)

1. Unauthenticated requests (and requests carrying a raw platform JWT) receive
   `401 Unauthorized` with an RFC 9728 header:
   `WWW-Authenticate: Bearer resource_metadata="<public-url>/ingress/.well-known/oauth-protected-resource"`.
2. External callers present `Authorization: Bearer <biscuit>`, where `<biscuit>`
   is a **Delegated Session Biscuit** minted by the control plane's OAuth 2.1
   Authorization Server (`/oauth/authorize` + `/oauth/token`) or RFC 8693 token
   exchange (`POST /oauth/token` or `POST /token/exchange`), optionally
   attenuated with a `TaskAuthorizationRule`. Callers holding an OIDC JWT
   exchange it once at `POST /oauth/token` into a Delegated Session Biscuit so
   `agentmesh-router` stays purely on Ed25519 Biscuit verification with zero
   IdP JWKS network dependencies. `mesh:role:router` Biscuits and unattenuated
   standing node Biscuits (`node(...)` without a `tar_block`) are rejected.
3. The router verifies the Biscuit signature, authority revocation ID, banned
   peer status, `TaskAuthorizationRule` chain (including MCP `tools/call` tool
   names), and `ServiceIngress.allow` locally **before** dialing any provider
   node. Once admitted, both the router and the serving node (defense in depth
   over `/mesh/ingress/1.0.0`) enforce the full intersection of mesh Datalog
   RBAC, `TaskAuthorizationRule`, `ServiceIngress.allow`, and local
   `agentmesh-node.yaml` `attenuation`.
4. The external `Authorization` header is stripped before reaching the local
   backend (replaced only if `target_auth_path` is configured on the node).
5. For `a2a` services, unauthenticated `GET` requests to the service root or
   `/.well-known/agent-card.json` return the backend's A2A `AgentCard` with
   `supportedInterfaces[].url` rewritten to the public `/ingress/...` URL,
   `signatures` cleared, and `securitySchemes` populated with `bearer`
   (`bearerFormat: "Biscuit"`) and `agentmesh_oauth2`.

### `auth_mode: passthrough` (opt-in)

For backends that run their own pairing or token handshake (for example
`a2a-serve` pair tokens), `passthrough` forwards the caller's `Authorization`
header untouched over `/mesh/ingress/1.0.0` while stripping `Cookie` and
`X-Mesh-*` headers and preserving the backend's own `AgentCard`
`securitySchemes`.

Combining `auth_mode: passthrough` with `target_auth_path` or inline credentials
in `target_url` (`http://user:pass@host`) is rejected at config validation and
service registration so node-local static backend credentials can never be
injected on unauthenticated external passthrough routes.

## Operator deployment

### `agentmesh-one` (local, VM, or Cloud Run)

No extra flags are needed. `agentmesh-one` mounts `/ingress/` directly onto its
embedded router on the single HTTP/WebSocket port:

```bash
agentmesh-one --external-url https://my-hub.run.app --data-dir /data
```

### Multi-binary Kubernetes (`agentmesh-router` + `Gateway`)

1. Start `agentmesh-router` with an HTTP ingress listener behind your L7 TLS
   `Gateway`:
   ```text
   --ingress-addr=0.0.0.0:8080
   --ingress-url=https://hub.example.com/ingress
   --public-control-plane=https://hub.example.com
   --allow-insecure-ingress-http
   ```
   (Or terminate TLS directly on the router with `--ingress-tls-cert-path` and
   `--ingress-tls-key-path`.)
2. Route `PathPrefix: /ingress/` on your `HTTPRoute` directly to the
   `agentmesh-router` HTTP ingress `Service` (health check path:
   `/ingress/healthz`), keeping `agentmesh-control-plane` out of the data path.
   Because routers federate their directory and circuit relays, any router pod
   can serve `/ingress/<peer_id>/...` regardless of which router pod holds the
   node's relay reservation.
3. Authenticated `edge` requests are rate-limited per verified Biscuit identity
   at the router. Because routers behind an L7 `Gateway` see the proxy's
   internal source IP on TCP `RemoteAddr`, configure per-client source-IP rate
   limiting at your L7 `Gateway` (for example Cloud Armor on GKE) to protect
   unauthenticated `AgentCard` discovery and `passthrough` routes.
4. With the Helm chart (`charts/agentmesh`), `router.ingressPort` (`8090` by
   default) and `gateway.ingressRoute: true` configure both the router listener
   and the `HTTPRoute` automatically when `gateway.enabled: true`. Set
   `router.ingressUrl` (e.g. `https://hub.example.com/ingress`),
   `router.publicControlPlaneUrl` (e.g. `https://hub.example.com`), and
   `bootstrap.nodeIngress` to advertise the public ingress base URL and seed the
   initial role ceiling.
