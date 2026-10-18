# A Substrate actor on the mesh

This example runs the full procedure of the guide at
`site/content/docs/guides/substrate.md` on a kind cluster:

- Agent Substrate, installed from a checkout, with its egress gateway pointed
  at the Agent Mesh credential provider.
- `credential-provider/`, a Substrate `CredentialProvider`. It answers
  `ate-secret://agentmesh/mesh/biscuit` with a mesh credential bound to the
  SPIFFE ID of the calling actor. It asserts that identity to the mesh as a
  workload identity issuer.
- `agentmesh-one`, an edge `agentmesh-node` that the actors reach, and an
  office node that publishes a calculator as `mcp://calc` and
  `mcp://payroll`. All run in namespace `agentmesh`.
- An `EgressPolicy` that lets the actor reach the edge node over plain HTTP.
  The `EgressPolicy` makes the egress gateway inject the credential as
  `X-Mesh-Authentication`.

```bash
make cluster SUBSTRATE_DIR=~/src/substrate   # kind + Substrate (builds images; a few minutes)
make up                                      # the mesh and the provider
make actor NAME=demo                         # a sandbox actor with the egress policy
make call NAME=demo                          # tools, calc allowed, payroll refused
make rogue                                   # an actor the policy does not bind: refused
make gemini NAME=demo GCP_PROJECT=<project>   # Gemini on Vertex AI through the mesh; see the guide
make policy                                  # push the policy after editing manifests/mesh.yaml.tmpl
make down                                    # the actors and the agentmesh namespace
make clean                                   # the kind cluster
```

The provider has its own Go module (`credential-provider/go.mod`) that
depends on the Substrate release it builds against. `go test ./...` in that
directory runs its unit tests without a cluster.

## With the hub elsewhere (Cloud Run)

`HUB=<url>` joins an `agentmesh-one` that runs outside the cluster. The
example then does not deploy the in-cluster hub. The control plane must
fetch the discovery document and the JWKS of the provider. A kind cluster
cannot serve them publicly. Therefore the provider signs with a key that you
keep. You publish the two documents as static files at the location that
`ISSUER` names, a public bucket:

```bash
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out provider-p256.pem
export HUB=https://<hub>.run.app ISSUER=https://storage.googleapis.com/<bucket>/substrate PROVIDER_KEY_PATH=$PWD/provider-p256.pem
make issuer-docs && gcloud storage cp -r run/issuer/.well-known run/issuer/keys gs://<bucket>/substrate/
# hub: --workload-issuer=<other issuers>,$ISSUER (on Cloud Run pass the list with --args="^;^...")
cp <hub join token> run/join-token; cp <hub admin token> run/admin-token
make up && make actor NAME=demo && make call NAME=demo
```

The provider mounts the key from the Secret `credential-provider-signing-key`.
Its discovery document (`--jwks-uri`) names the JWKS in the bucket. To
rotate the key, generate a new key. Publish a JWKS that carries both keys.
Switch the Secret. Then remove the old key from the JWKS.


## On GKE

The Substrate tooling creates the cluster and installs Substrate. This
example adds the mesh to that cluster. `KUBE_CONTEXT` selects the cluster.
`CALC_MCP_IMAGE` names an image that the nodes can pull, because there is no
kind cluster to load an image into:

```bash
# in the Substrate checkout: cp hack/ate-dev-env.sh.example .ate-dev-env.sh, edit, then
source .ate-dev-env.sh && go run ./tools/setup-gcp bootstrap            # cluster, bucket, IAM (~8 min)
kubectl apply -f <this dir>/manifests/namespace.yaml                  # the provider's Service must resolve before the gateway starts
./hack/install-ate.sh --deploy-ate-system --deploy-demo-sandbox \
  --credential-provider='{"name":"agentmesh","address":"credential-provider.agentmesh.svc:50051"}'
# back here
docker build -t <repo>/calc-mcp:latest ../calc-mcp && docker push <repo>/calc-mcp:latest
export KUBE_CONTEXT=gke_<project>_<zone>_<cluster> KO_DOCKER_REPO=<repo> CALC_MCP_IMAGE=<repo>/calc-mcp:latest
export HUB=... ISSUER=... PROVIDER_KEY_PATH=...                      # as in the section above
make up && make actor NAME=demo && make call NAME=demo
```

`atenet-egress` stays at `1/3` until `make up` creates the provider that it
was installed to call. Two Substrate clusters on one hub present the same
actor identities. The trust domain in
`spiffe://substrate-actor.local/actor/<atespace>/<name>` belongs to
Substrate, not to the cluster. Run one cluster per hub, or bind by atespace
names that differ per cluster.
