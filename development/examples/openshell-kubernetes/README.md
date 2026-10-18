# An OpenShell sandbox on Kubernetes, on the mesh under its own identity

This example is the Kubernetes counterpart of
[`openshell-sandbox`](../openshell-sandbox/), the Docker driver example.
OpenShell runs from its published Helm chart. Every sandbox gets a SPIFFE
identity from SPIRE. The OpenShell supervisor beside each sandbox exchanges
that identity for a mesh credential at the edge `agentmesh-node`. The agent
in the sandbox holds no credential and sees the mesh as one unauthenticated
MCP endpoint. To revoke a sandbox, change the policy.

The example does not modify OpenShell. It installs the chart with one value
(`provider_spiffe_workload_api_socket_path`). The integration is one
provider profile.

```text
sandbox pod (agent, network off)
   │ OpenShell Sandbox Protocol (mTLS, boundary Service)
supervisor pod ── FetchJWTSVID ──▶ SPIRE agent (CSI socket)
   │ POST /oauth/token (client_credentials + jwt-spiffe assertion)
   │ X-Mesh-Authentication: Bearer <Biscuit>
edge agentmesh-node ── /token/exchange ──▶ agentmesh-one (hub, in-cluster or Cloud Run)
   │ mesh stream, caller's Biscuit
office agentmesh-node ──▶ mcp://calc (allowed) / mcp://payroll (refused)
```

## What is different from the Docker example

| | Docker driver | Kubernetes driver |
|---|---|---|
| Supervisor | container on the host network | Pod on the cluster network; the token endpoint and the MCP endpoint are the edge node's Service (`http://edge-node.agentmesh.svc.cluster.local:8080`), which OpenShell accepts as a plaintext in-cluster host |
| Workload identity | SPIRE `docker` attestor, one entry per sandbox keyed on the `openshell.ai/sandbox-name` label | SPIRE Kubernetes stack (SPIFFE hardened charts); one `ClusterSPIFFEID` over supervisor pods using the `openshell.ai/sandbox-id` label, so the subject is `spiffe://openshell.local/openshell/sandbox/<uuid>`, NVIDIA's own template |
| Binding | by name, known before creation | by sandbox id, known after creation (`make sandbox` prints it, `make bind` adds it); or the fleet with `user:spiffe://openshell.local/openshell/sandbox/*` |
| Confinement | workload container with networking off | `agents.x-k8s.io` `Sandbox` + supervisor Pod + three `NetworkPolicy` objects; **the CNI must enforce them** (`make netpol-check` proves it) |
| Operator access | `openshell gateway add http://127.0.0.1:8080` | chart-generated mTLS client bundle over a port-forward |

## Run it

You need `kubectl`, `helm`, `docker`, `kind` (for the local cluster), the
`openshell` CLI (0.1.3 or later), `python3` and `curl`.

```bash
make cluster                     # a kind cluster
make up                          # Agent Sandbox v1.0.7, SPIRE 0.29.0, the mesh (in-cluster hub), OpenShell 0.1.4
make sandbox NAME=demo           # prints spiffe://openshell.local/openshell/sandbox/<id>
make call NAME=demo              # refused: no role binds the identity yet
make bind NAME=demo              # adds the member, pushes the policy
make call NAME=demo              # calc allowed, payroll refused
make netpol-check NAME=demo      # workload pod cannot reach the edge node directly; an unconfined pod can
make rogue                       # second sandbox, unbound, refused
make gemini NAME=demo GCP_PROJECT=<project>   # Gemini on Vertex AI through the mesh; see the guide
make unbind NAME=demo            # the same policy change in reverse; refused within about 3 minutes
```

Expected output of `make call` after `make bind`:

```text
== tools the mesh offers sandbox demo
  12D3KooWM5k2n5zm…  mcp://calc/add           Return a + b.
  12D3KooWM5k2n5zm…  mcp://calc/multiply      Return a * b.
== mcp://calc, allowed for the sandbox role
mcp://calc/add(2, 3) = 5.0
== mcp://payroll, not in the sandbox role
  (no tool of mcp://payroll is visible to this sandbox; calling the office node directly)
mcp://payroll/add(2, 3) -> refused: auth rejected by 12D3KooWM5k2…: biscuit: denied by no matching policies
```

The hub log has one line per credential that the mesh minted:

```text
Border Crossing {"endpoint": "/token/exchange", "decision": "allow",
  "subject": "spiffe://openshell.local/openshell/sandbox/2c399868-…", "roles": ["sandbox"]}
```

## On GKE, with the hub on Cloud Run

The [OpenShell and Substrate guide](../../../site/content/docs/guides/openshell-and-substrate.md)
has the full procedure. A summary:

- Create the node pool for the sandboxes with `--image-type UBUNTU_CONTAINERD`.
  The OpenShell sandbox runtime needs Landlock ABI v3. The
  Container-Optimized OS kernel has no `CONFIG_SECURITY_LANDLOCK`.
- Use Dataplane V2. It enforces `NetworkPolicy`. `make netpol-check` shows
  this.
- GKE assigns ClusterIPs outside RFC 1918. The example renders `allowed_ips`
  in the provider profile from the ClusterIP of the edge Service.
- Expose the SPIRE OIDC discovery provider on a reserved address. Name that
  address as the issuer: `make prereqs OIDC_SERVICE_TYPE=LoadBalancer
  OIDC_LOAD_BALANCER_IP=<ip> JWT_ISSUER=http://<ip>`. Pass the issuer to the
  hub in `--workload-issuer`.
- Set `KUBE_CONTEXT` to the cluster and `HUB` to the URL of the hub. Set
  `CALC_MCP_IMAGE` and `SANDBOX_IMAGE` to images that the cluster can pull.
  Put the join token and the admin token of the hub in `run/join-token` and
  `run/admin-token`.

```bash
export KUBE_CONTEXT=gke_<project>_<zone>_<cluster> HUB=https://<hub>.run.app OPENSHELL_GATEWAY=openshell-gke
make mesh CALC_MCP_IMAGE=<registry>/calc-mcp:v1
make openshell SANDBOX_IMAGE=<registry>/sandbox:v1
make sandbox NAME=demo && make bind NAME=demo && make call NAME=demo
```

`make bind` and `make policy` push the policy to the hub with the admin
token. If the hub mounts the policy from Secret Manager, also add the new
policy as a secret version. Then the next revision starts with it.

## Files

- `spire/values.yaml.tmpl`: SPIFFE hardened chart values; trust domain,
  issuer, the `ClusterSPIFFEID`s for supervisors and the gateway, OIDC provider
  over plain HTTP in-cluster.
- `openshell/values.yaml`: the one OpenShell chart value.
- `openshell/provider-profile.yaml`: the `token_grant` profile.
- `mesh/hub.yaml.tmpl`: in-cluster `agentmesh-one` (only with `HUB=local`).
- `mesh/nodes.yaml.tmpl`: edge node, office node, calculator.
- `policy.json`: the mesh policy; `bind.py` edits its `sandbox` binding.
- `mcp.py`: runs `curl` inside the sandbox through `openshell sandbox exec`.
- `Dockerfile.sandbox`: the sandbox image (Ubuntu + curl); an agent image can
  replace it.
