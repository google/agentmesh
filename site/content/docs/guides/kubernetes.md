---
title: "Kubernetes"
linkTitle: "Kubernetes"
weight: 4
aliases:
  - /docs/user/kubernetes-deployment/
---

This guide deploys a control plane, a router and a console into a cluster
with the `sam-mesh` Helm chart, then puts services on the mesh with the
`sam-node` chart. The last section lists the settings to change when you
move from a test cluster to one that you keep. The public testnets run this
setup on GKE. Their manifests are in `.github/k8s/` in the repository.

## What gets deployed

| Component | Kind | Notes |
|---|---|---|
| `sam-control-plane` | Deployment (2 replicas) | Stateless. All state is in PostgreSQL. |
| PostgreSQL | StatefulSet | In-cluster by default (`database.postgres.deployInternal`). You can point the chart at your own database instead. |
| `sam-router` | StatefulSet | A PVC holds `router.key`, so the peer ID survives rescheduling. |
| `sam-console` | Deployment | Optional (`console.enabled`). |
| bootstrap Job | Job (post-install hook) | Seeds the mesh policy and mints the router's bootstrap token. |
| Gateway + HTTPRoute | Gateway API | Optional (`gateway.enabled`). Routes the enrollment paths and the console. |

The chart does not include an identity provider, and the control plane needs
one to start. The cluster's own OIDC issuer is a good choice, because every
pod can then enroll with a projected service account token and no secret has
to be distributed.

## 1. Install the mesh

```bash
ISSUER=$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)

helm upgrade --install sam-mesh ./charts/sam-mesh \
  --namespace sam --create-namespace \
  --set controlPlane.oidcIssuer="$ISSUER" \
  --set controlPlane.workloadIssuer="$ISSUER" \
  --set controlPlane.insecureSkipTlsVerify=true \
  --set bootstrap.nodeMembers='{user:system:serviceaccount:sam-nodes:calc-mcp-sam-node}' \
  --set bootstrap.nodeServices='{mcp://calculator,system://sam.catalog}'
```

`controlPlane.workloadIssuer` marks the cluster issuer as a workload identity
provider so service account tokens can enroll, refresh, and exchange credentials
while being refused at `/user/*` and `/oauth/authorize`.
`insecureSkipTlsVerify` is needed when the cluster issuer is served with the
cluster CA, which the control plane does not trust by default. Leave it off
for a public provider. On a managed cluster the issuer is often public (on
GKE: `https://container.googleapis.com/v1/projects/.../clusters/...`) and
does not need the flag.

The three `bootstrap.*` values write the initial policy:

- `nodeMembers`: the identities that may enroll as `sam:role:node`. If
  empty, no node can join until you post a policy.
- `nodeServices`: the services that nodes may call. If empty, nodes can call
  nothing.
- `nodeLabels`: the label patterns that nodes may attest. If empty, nodes
  cannot declare labels.

If you want to bind more roles than the node role, `bootstrap.bindings`
replaces the whole bindings list. Everything the bootstrap job seeds can be
changed later through the console or `POST /policies`. The job runs on
install and on upgrade, but once the database has a policy, the database is
the source of truth.

The chart generates an admin token and a database password and stores them
in the `sam-mesh-secrets` Secret. The release notes print the command to
read them:

```bash
kubectl -n sam get secret sam-mesh-secrets -o jsonpath='{.data.admin-token}' | base64 -d
```

The router enrolls with a bootstrap token that the job writes into
`sam-mesh-router-token`, with `max_usages` equal to `router.replicaCount`.
Set `router.useOidcToken=true` to make it use a projected service account
token instead.

## 2. Expose it

Inside the cluster, the control plane answers at
`http://sam-mesh-control-plane.sam.svc:8080` and the router at
`sam-mesh-router.sam.svc:4501`. That is enough for nodes in the same cluster.

Nodes outside the cluster need two things: the control plane over HTTPS
(nodes refuse to fetch their trust root over plaintext from a remote
address), and the router's libp2p ports. The chart's Gateway handles the
control plane:

```yaml
gateway:
  enabled: true
  className: gke-l7-global-external-managed
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        certificateRefs: [{ name: sam-mesh-tls }]
      allowedRoutes: { namespaces: { from: Same } }
  hostnames: [mesh.example.com]
```

The route exposes only the paths that nodes need (`/info`, `/register`,
`/keys`, `/routers/lease`, `/policies`, `/enroll`, `/enroll/status`,
`/refresh`, `/nodes/catalog`) and the console under `gateway.consolePath`.
`/admin` and `/user` are not routed unless you set `gateway.adminRoute`,
which is meant for development clusters.

For the router, `router.hostPort: 4501` binds TCP and UDP port 4501 on the
Kubernetes node where the router pod runs, and announces that node's IP.
`router.externalAddrs` replaces the announced addresses, for example with a
fixed DNS name:

```yaml
router:
  hostPort: 4501
  externalAddrs: ["/dnsaddr/bootstrap.example.com"]
```

A `/dnsaddr` needs TXT records that resolve to the routers' current
addresses. The testnets run a CronJob
(`.github/k8s/dns-sync-cronjob-template.yaml`) that reads the IPs of the
router pods and updates Cloud DNS. Any mechanism that keeps the records
current works.

## 3. Put a service on the mesh

A service on Kubernetes is a pod with your backend container and a
`sam-node` sidecar, both deployed by the `sam-node` chart. The node enrolls
with the pod's projected service account token, so its identity is
`user:system:serviceaccount:<namespace>:<release>-sam-node`. This is the
identity that the binding in step 1 named.

```yaml
# calc-mcp.values.yaml
controlPlaneUrl: http://sam-mesh-control-plane.sam.svc:8080
config:
  version: v1alpha1
  services:
    - type: mcp
      name: calculator
      description: "Arithmetic tools"
      target_url: http://127.0.0.1:7777/mcp
service:
  name: calc-mcp
  image: ghcr.io/example/calc-mcp:1.0
  ports: [{ containerPort: 7777 }]
```

```bash
helm upgrade --install calc-mcp ./charts/sam-node \
  --namespace sam-nodes --create-namespace -f calc-mcp.values.yaml
```

`config` is the node's `sam-node.yaml`. The pod restarts when it changes.
The sidecar and the backend share the pod's network, so `target_url` is
always `127.0.0.1`. `extraArgs` passes additional `sam-node run` flags. The
chart adds `--insecure-control-plane` for you when the control plane URL is
plain `http` inside the cluster. With a `replicaCount` above one, each
replica enrolls as its own node and offers the same service name.

`development/examples/` in the repository holds working values files for
several backends, and `make kind-up` brings up this whole setup in a local
kind cluster. See [Contributing](../../contributing/#a-local-mesh-in-kind).

## 4. Check it

```bash
kubectl -n sam-nodes logs deploy/calc-mcp -c sam-node | grep -E "Online|PeerID"
```

From a node enrolled anywhere in the mesh:

```bash
mcp-client -url http://127.0.0.1:8080/mcp -token "$TOKEN" \
  -tool discover_remote_services -args '{"type":"mcp","name":"calculator"}'
```

The console shows the same information: enrolled nodes, their reported
services, the router, and the policy. It is at `/console/` behind the
gateway, or you can port-forward `svc/sam-mesh-console`.

## Keeping it

The defaults suit a cluster that you rebuild often. For a cluster that you
keep, review these settings:

- **Database.** Set `database.postgres.deployInternal=false` and give the
  control plane the DSN of a managed PostgreSQL through `--db-dsn-path` or
  the `SAM_DB_DSN` environment variable. The DSN contains a password, so it
  should not be a flag value.
- **Enrollment.** `controlPlane.autoApproveEnrollment` defaults to `true`.
  That is fine when every enrollee holds an OIDC token from an issuer that
  you control. If you hand out bootstrap tokens, consider setting it to
  `false` and approving enrollments in the console.
- **Policy.** Grant nodes only the services they need. Do not bind
  `sam:system:authenticated` to a role with wide grants: on a public
  identity provider it means everyone. The testnets bind it on purpose. A
  private mesh should bind groups or service accounts.
- **Signing keys.** `--key-grace-period` defaults to one hour. A node that is
  down for longer must enroll again. The testnets use 48 hours. Pick a value
  that matches how long your nodes can legitimately be off.
- **Console origin.** When a proxy terminates TLS in front of the console,
  set `console.externalUrl` so that the OIDC redirect URI and the cookie
  `Secure` flag do not depend on forwarded headers.
- **Metrics.** `monitoring.podMonitoring.enabled` (Google Managed
  Prometheus) or `monitoring.podMonitor.enabled` (prometheus-operator)
  scrape the control plane and the router. Both metrics endpoints are
  unauthenticated, so keep them inside the cluster.

The chart's [README](https://github.com/google/sam/blob/main/charts/sam-mesh/README.md)
documents every value. The [control plane](../../reference/control-plane/)
and [router](../../reference/router/) references list the flags the chart
sets.
