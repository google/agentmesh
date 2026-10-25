# kgateway with mesh authorization

kgateway keeps routing; an `agentmesh-node` decides each request over Envoy
gRPC `ext_authz`. Two routes: `/mcp/greeter` goes to a server in the cluster,
`/mcp/calc` goes through the mesh to a server in another namespace. The
guide is `site/content/docs/guides/kgateway.md`.

```sh
./run.sh        # create a kind cluster and run every case
./run.sh down   # delete the cluster and .run/
```

Needs kind, kubectl, helm, docker and make. The agentmesh images are built
from this checkout (the published control plane and router images are amd64
only).

```
== kgateway routes, the node decides
  PASS  alice -> /mcp/calc, through the mesh (calc-user)                   200
  PASS  alice calls add                                                    200 5.0
  PASS  alice -> /mcp/greeter (no greeter-user)                            403
  PASS  bob -> /mcp/greeter, a local backend (greeter-user)                200
  PASS  bob calls hello                                                    200 Hello, bob!
  PASS  bob -> /mcp/calc (no calc-user)                                    403

== Refused by the node's ext_authz
  PASS  no token                                                           401
  PASS  alice, token for client other-app (audience)                       403
  PASS  the node's own API token                                           403

== Fail closed: the node goes away
  PASS  the greeter itself, from inside the cluster                        200
  PASS  bob -> /mcp/greeter, node unreachable                              503
  PASS  alice -> /mcp/calc, node unreachable                               503
  PASS  bob -> /mcp/greeter, node back                                     200
  PASS  alice -> /mcp/calc, node back                                      200
```

For local testing only: plain http, Keycloak `start-dev`, test passwords in
the realm file, and auto-approved enrollment. `.run/` holds the generated
tokens and is not committed.
