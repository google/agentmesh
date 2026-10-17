# agentmesh Helm chart

Deploys a self-contained Agent Mesh (control plane, router, console, and an
in-cluster Postgres) for local development, testing, or self-hosting your
own mesh.

> For deployments on GKE/EKS/AKS with externally managed Postgres, DNS and
> OIDC, see the
> [Kubernetes guide](https://google.github.io/agentmesh/docs/guides/kubernetes/).

## Install

```bash
helm upgrade --install agentmesh ./charts/agentmesh --namespace agentmesh --create-namespace \
  --set controlPlane.oidcIssuer=<your OIDC issuer URL>
```

`controlPlane.oidcIssuer` is required: the chart bundles no identity
provider, and the control plane refuses to start without an issuer. Point it
at your own OIDC provider (Google, Okta, a Dex you run, the cluster's own
issuer for ServiceAccount Workload Identity Federation, …). The `kind` dev
environment (`make kind-up`) deploys its own throwaway Dex from
`development/kind/dex.yaml` and wires it in for you.

At the end of `helm install`/`helm upgrade`, the chart prints the exact
`kubectl` command to retrieve your generated secrets (see below) — read the
NOTES output before doing anything else.

## Secrets: `controlPlane.adminToken` and `database.postgres.password`

Both default to `""` in [values.yaml](values.yaml). When left blank, the chart
**auto-generates** a random 32-character secret on first install and stores it
in the `<release>-secrets` Kubernetes Secret; the same value is reused on
`helm upgrade` (it is not rotated on every upgrade). Retrieve the admin token
with:

```bash
kubectl get secret --namespace <namespace> <release>-secrets -o jsonpath='{.data.admin-token}' | base64 -d; echo
```

You can also pin either value explicitly instead of letting the chart
generate one, e.g. for reproducible dev environments or to match an
existing secret:

```bash
helm upgrade --install agentmesh ./charts/agentmesh \
  --set controlPlane.adminToken="$(openssl rand -hex 32)" \
  --set database.postgres.password="$(openssl rand -hex 32)"
```

## `controlPlane.insecureSkipTlsVerify`

Defaults to `false`. Only set this to `true` when `controlPlane.oidcIssuer`
points at an OIDC issuer served with a self-signed or otherwise untrusted
certificate — for example the Kubernetes API server's own issuer
(`https://kubernetes.default.svc.cluster.local`) used for ServiceAccount
Workload Identity Federation in local `kind` clusters, or a local Dex/mock
OIDC instance without a real cert. Leave it `false` for any real-world OIDC
provider (Google, Okta, Dex behind a real TLS certificate, etc.).

## `controlPlane.autoApproveEnrollment`

Defaults to `true` (any node/router presenting a valid identity token is
enrolled immediately, no manual step). Set to `false` if you want an
administrator to approve each enrollment via `/admin/enrollments` before a
node can join — see the
[Headless enrollment guide](https://google.github.io/agentmesh/docs/guides/headless-enrollment/).

## `controlPlane.workloadIssuer` and `controlPlane.workloadSessionTtl`

When `controlPlane.oidcIssuer` includes a workload identity provider alongside a
human identity provider (for example the Kubernetes API server issuer
`https://kubernetes.default.svc.cluster.local`, a SPIRE OIDC Discovery Provider,
or `https://accounts.google.com=.gserviceaccount.com` for Google Cloud service
accounts), list it in `controlPlane.workloadIssuer` so those machine tokens are
accepted at `/register`, `/refresh`, and `/token/exchange` and refused at the
human surfaces (`/user/*`, `/oauth/authorize`). `controlPlane.workloadSessionTtl`
overrides the default `48h` workload session lifetime (which nodes and routers
extend in place on `/refresh` by re-presenting their current workload JWT).

## Gateway API (`gateway.enabled`)

Disabled by default. When enabled the chart creates one `Gateway` fronting
the mesh, with one `HTTPRoute`. `gateway.className` is then **required**,
with no default, because the right GatewayClass is provider-specific
(`cloud-provider-kind` in kind, `gke-l7-global-external-managed` on GKE,
`istio`, `envoy-gateway`, …).

The route exposes only the control plane's enrollment and runtime surface (`/register`,
`/info`, `/keys`, `/routers/lease`, `/policies`, `/egress`, `/revocations`,
`/token/exchange`, `/sts/token`, `/enroll`, `/enroll/status`, `/refresh`,
`/nodes/catalog`, `/.well-known/*`, `/jwks`, `/oauth/authorize`, `/oauth/token`) and the console under `gateway.consolePath`; everything else,
including `/admin` and `/user`, is unrouted. `gateway.adminRoute: true`
additionally routes `/admin` — a dev convenience, leave it off in production.

For the console, the bare prefix (`/console`) is answered with a 302 to
`/console/`, and a `URLRewrite` filter strips the prefix before the request
reaches the console. `URLRewrite` is **Extended** (not core) Gateway API
conformance, so the provider must support it. Set `gateway.consolePath: ""`
to leave the console unrouted.

`listeners`, `hostnames`, `addresses` and `annotations` are passed through to
the Gateway API objects verbatim, so anything the spec allows is expressible.
They default to one plain-HTTP listener on port 80 matching every host, which
suits a local cluster. For example, on GKE:

```yaml
gateway:
  enabled: true
  className: gke-l7-global-external-managed
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    tls:
      certificateRefs:
      - name: agentmesh-tls
    allowedRoutes:
      namespaces:
        from: Same
  hostnames: [mesh.example.com]
  addresses:
  - type: NamedAddress
    value: agentmesh-cp-ip
```

## OIDC login for the console

There is no bundled Dex. Point `controlPlane.oidcIssuer` at your identity
provider and register `https://<control-plane-hostname><consolePath>/auth/callback` as
a redirect URI for the OIDC client the control plane reports.

## Disruption budgets (`*.podDisruptionBudget`)

The control plane and the router each get a `PodDisruptionBudget` with
`maxUnavailable: 1`, so a node drain or autoscaler scale-down evicts one pod
at a time instead of all of them. A budget renders only when its component
runs more than one replica: the default install covers the control plane
(2 replicas) and leaves a single router as it is. Set
`podDisruptionBudget.minAvailable` to use that form instead, or
`podDisruptionBudget.enabled: false` to render none.

## Metrics (`monitoring.*`)

The control plane serves Prometheus metrics on its `http` port and the router
on a dedicated `metrics` containerPort (`router.metricsPort`, default 9090),
which also carries its `/healthz` and `/readyz` probes. Neither endpoint is
authenticated, so the router port is deliberately never a hostPort or a
Service.

Scraping is off by default because both supported resources are CRDs:

- `monitoring.podMonitoring.enabled: true` renders a
  `monitoring.googleapis.com/v1` `PodMonitoring` per component for Google
  Managed Prometheus, which GKE runs out of the box.
- `monitoring.podMonitor.enabled: true` renders a `monitoring.coreos.com/v1`
  `PodMonitor` per component for prometheus-operator; use
  `monitoring.podMonitor.labels` for the selector your Prometheus matches on.

Mesh size and state come from the control plane
(`agentmesh_control_plane_mesh_connected_peers`, `agentmesh_control_plane_routers_active`,
`agentmesh_control_plane_enrolled_nodes{role,state}`); the router adds its live view
(`agentmesh_router_authenticated_peers`, `agentmesh_router_auth_handshakes_total{result}`)
alongside libp2p's own relay and connection metrics.
