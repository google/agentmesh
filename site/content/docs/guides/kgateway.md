---
title: "kgateway with mesh authorization"
linkTitle: "kgateway"
weight: 3
---

You can keep [kgateway](https://kgateway.dev/) as your cluster gateway and
let the mesh decide who gets through. kgateway sends every request to an
`agentmesh-node` over Envoy `ext_authz` and only forwards it if the node
says yes. A route can point at a service in the cluster, or at the node,
which carries the request over the mesh to a service in another network.

The example is in
[`development/examples/kgateway/`](https://github.com/google/agentmesh/tree/main/development/examples/kgateway).
Its `run.sh` creates a kind cluster and checks every step on this page:

```sh
cd development/examples/kgateway
./run.sh
```

This works differently from [agentgateway](../agentgateway/), which
exchanges the caller's token itself. Here the node does the exchange and
answers each check, so the two configurations don't carry over.

## Who does what

- kgateway matches the path and routes the request.
- The node checks the caller's token by exchanging it at the control plane
  (signature, issuer, audience, expiry), then decides against the mesh
  policy.
- For a route into the mesh, the provider on the other side checks again
  before its server sees the request.

## The policy

alice is in `devs`, bob is in `ops`:

```json
"bindings": [
  { "role": "calc-user", "members": ["group:devs"] },
  { "role": "greeter-user", "members": ["group:ops"] }
]
```

`mcp://greeter` is not on the mesh, it's a normal Service. The policy still
applies, because the node decides on the service name, which it takes from
the path (`/mcp/greeter` is `mcp://greeter`).

## The kgateway config

```yaml
apiVersion: gateway.kgateway.dev/v1alpha1
kind: GatewayExtension
metadata:
  name: mesh-authz
  namespace: apps
spec:
  type: ExtAuth
  extAuth:
    grpcService:
      backendRef:
        name: mesh-node-authz
        namespace: mesh
        port: 8080
    headersToForward: ["authorization"]
    failOpen: false
    statusOnError: 503
```

A `TrafficPolicy` attaches it to both routes. A few things to know:

- The node serves gRPC on its API port without TLS, so the Service needs
  `appProtocol: kubernetes.io/h2c`.
- `statusOnError: 503` makes an unreachable node show up differently from a
  denial (default is 403).
- The node lives in another namespace, so you need a `ReferenceGrant`.
- Each route removes `Authorization` with a `RequestHeaderModifier`. That
  runs after `ext_authz`, so the node still sees the token and the backend
  doesn't.

The route into the mesh rewrites the path to the node's mesh API:

```yaml
- type: URLRewrite
  urlRewrite:
    path: { type: ReplaceFullPath, replaceFullPath: /mesh/<provider-peer-id>/mcp/calc }
```

When the node allows a request it adds the caller's credential in
`X-Mesh-Biscuit`, and the node uses that to make the call over the mesh as
the caller.

## Results

| Request | Result |
|---|---|
| alice on `/mcp/calc` | `200` |
| alice on `/mcp/greeter` | `403` |
| bob on `/mcp/greeter` | `200` |
| bob on `/mcp/calc` | `403` |
| no token | `401` |
| token for another client | `403` |
| the node's own API token | `403` |

Then the script scales the node to zero. The greeter is still up and answers
when called directly, but every request through kgateway gets `503`. Once the
node is back, requests go through again.

## Logs

The node logs each check as `Audit Traceability` with
`"protocol": "ext_authz"`. Allowed lines include the caller's email and
role; denied lines only show the node's peer ID, so look up the user in the
control plane's `Border Crossing` line from the same moment. Calls that go
over the mesh show up again in the provider's log.

## For a real deployment

- Use TLS for the control plane and drop `--insecure-control-plane`, and run
  Keycloak properly (see the [Keycloak guide](../keycloak/#what-to-change-for-a-real-deployment)).
- Turn off `--auto-approve-enrollment` and approve nodes yourself
  ([Headless enrollment](../headless-enrollment/#3-approve)).
- Give the node a persistent volume and more than one replica. With
  `failOpen: false`, if the node is down, so is the gateway.
- Only let kgateway reach the node's API port.

To clean up, run `./run.sh down`.
