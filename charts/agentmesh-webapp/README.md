# agentmesh-webapp Helm chart

Deploys Agent Mesh Connect, the web app that puts a browser on an Agent Mesh.
The web app knows no control plane: the person using the page enters one, or
opens a join link that names it. One deployment serves any mesh.

## Install

```bash
helm upgrade --install agentmesh-webapp ./charts/agentmesh-webapp --namespace agentmesh-webapp --create-namespace \
  --set image.repository=ghcr.io/google/agentmesh-webapp --set image.tag=<version>
```

## Expose it

Browsers refuse the page's cryptography on plain `http` to any host but
`localhost`, so other devices must reach it over `https`.

With `gateway.enabled=true` the chart creates a Gateway and an HTTPRoute:

| Value | Default | Meaning |
| --- | --- | --- |
| `gateway.className` | none, required | The GatewayClass, for example `gke-l7-global-external-managed`. |
| `gateway.path` | `""` | The prefix the page is served under, for example `/node`. Empty serves it at `/`. A prefix needs a GatewayClass that supports `URLRewrite`, and helps only when another route shares the hostname. |
| `gateway.hostnames` | `[]` | The hostnames the route answers. |
| `gateway.listeners` | one `http` listener on port 80 | Put an `https` listener here for other devices. |
| `gateway.addresses`, `gateway.annotations` | empty | Passed to the Gateway as given, for example a static IP or a certificate map. |

Without the Gateway, route the `<release>` Service, port `8082`, from an
`https` proxy or Gateway you already run.

## Sign in

If the mesh's control plane has a sign-in provider, that provider must list
the page's address as a redirect URI and allow its origin. Without that, the
page offers only enrollment tokens.
