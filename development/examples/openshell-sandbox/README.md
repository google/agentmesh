# An OpenShell sandbox on the mesh

Everything the guide at `site/content/docs/guides/openshell.md` walks through,
as one `docker compose` project and a Makefile:

- a SPIRE server, agent and OIDC discovery provider for the trust domain
  `openshell.local`, attesting OpenShell sandbox supervisors by their Docker
  labels so every sandbox has its own SPIFFE ID;
- `agentmesh-one` trusting that SPIRE issuer, an edge `agentmesh-node` beside
  the sandboxes, and an office `agentmesh-node` publishing a calculator as
  `mcp://calc` and `mcp://payroll`;
- the OpenShell gateway container from the OpenShell release, with the one
  configuration line that projects the SPIRE Workload API into sandbox
  supervisors, and a provider profile whose token grant trades the sandbox's
  JWT-SVID for a mesh credential.

```bash
make up                  # start it all, register the gateway and the provider
make sandbox NAME=demo   # one SPIFFE ID, one sandbox
make call NAME=demo      # tools, calc allowed, payroll refused
make rogue               # a sandbox the policy does not bind: refused
make policy              # push policy.json after you edit it
make down
```

`run/` holds generated tokens and the rendered SPIRE agent configuration and is
not committed. OpenShell keeps its state under `/var/lib/openshell`, where the
SPIRE agent socket also lives.
