# A Substrate actor on the mesh

Everything the guide at `site/content/docs/guides/substrate.md` walks through,
on a kind cluster:

- Agent Substrate installed from a checkout, with its egress gateway pointed
  at the Agent Mesh credential provider;
- `credential-provider/`, a Substrate `CredentialProvider` that answers
  `ate-secret://agentmesh/mesh/biscuit` with a mesh credential bound to the
  calling actor's SPIFFE ID, by asserting that identity to the mesh as a
  workload identity issuer;
- `agentmesh-one`, an edge `agentmesh-node` the actors reach, and an office
  node publishing a calculator as `mcp://calc` and `mcp://payroll`, all in
  namespace `agentmesh`;
- an `EgressPolicy` that lets the actor reach the edge node over plain HTTP and
  has the gateway inject the credential as `X-Mesh-Authentication`.

```bash
make cluster SUBSTRATE_DIR=~/src/substrate   # kind + Substrate (builds images; a few minutes)
make up                                      # the mesh and the provider
make actor NAME=demo                         # a sandbox actor with the egress policy
make call NAME=demo                          # tools, calc allowed, payroll refused
make rogue                                   # an actor the policy does not bind: refused
make policy                                  # push the policy after editing manifests/mesh.yaml.tmpl
make down                                    # the actors and the agentmesh namespace
make clean                                   # the kind cluster
```

The provider has its own Go module against the Substrate release it builds
against (`credential-provider/go.mod`); `go test ./...` in that directory runs
its unit tests without a cluster.
