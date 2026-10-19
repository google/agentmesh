---
title: "Networking and the node API"
linkTitle: "Networking"
weight: 4
---

This page follows a request from an agent to a service on another node:
how the calling node finds the provider, how the two connect, and what the
agent sees at each end.

## The node's local API

An agent does not speak to the mesh directly. It speaks to the `agentmesh-node` on
its own machine, through one of two listeners:

- **TCP**, `127.0.0.1:8080` by default (`--bind-addr`). Every request must
  carry the node's API token as `X-Mesh-Authentication: Bearer <token>`.
- **A Unix socket**, `<data-dir>/agentmesh.sock` by default (`--socket-path`),
  created with mode `0600`. No token is needed, because only the user who
  owns the socket can open it. `docker.sock` works the same way.

You can turn either listener off by passing an empty value. With
`--bind-addr=`, the node has no listening port and no secret to manage. This
is a good setup when everything that uses the node runs as the same user.

The token travels in `X-Mesh-Authentication` and not in `Authorization`, so
that `Authorization` always means the same thing: the credential for the
service that is being called through the node. On the proxy path that header
is forwarded unchanged. Every other route that needs the token also
accepts it in `Authorization`, for clients that cannot set a custom header.
The node removes the header that carried the token. On `/v1/*`, an
`Authorization` header that is still present is the backend's credential.
The node forwards it as on the proxy path.

An agent mostly uses four parts of the API:

| Path | What it is |
|---|---|
| `/mcp` | An MCP server (Streamable HTTP). Its tools are the mesh operations: list and discover services, find and describe tools, call a tool on a peer. |
| `/v1/models`, `/v1/chat/completions`, `/v1/completions` | An OpenAI-compatible endpoint. `/v1/models` lists every model that a reachable `inference://` provider serves. A completion request is routed to a provider that serves the requested model. |
| `/mesh/<peer-id>/<type>/<name>/<path>` | A reverse proxy to one specific service on one specific node, for every service type. `<type>` is `mcp`, `inference` or `a2a`, and `<path>` is passed through to the backend. This is how a caller reaches an A2A agent: `/mesh/<peer-id>/a2a/<name>/` serves the agent's card, rewritten for the mesh, and its JSON-RPC endpoint. |
| `/mesh/service/discover` | Service discovery over plain HTTP, with the same results as the `discover_remote_services` tool. |

Other routes serve token exchange (`/oauth/token`), revocation
(`/oauth/revoke`), the egress destinations that this node serves
(`/egress/`), and the Envoy `ext_authz` and `ext_proc` integration. The
node also serves identity evidence (`/mesh/identity`) and operator
diagnostics (`/debug/`). The [node API reference](../../reference/node-api/)
lists every route.

## Discovery

The routers keep the mesh's directory, served to members over
`/mesh/directory/1.0.0`. A node announces where it is reached, and a node
that publishes a service announces itself as a provider of that service
name, to a router it holds; the router keeps the records and places each
on the routers closest to its key, which it finds in the Kademlia table
the routers keep among themselves. A node that looks for a service, or
for a peer, asks a router it holds, and the router answers from its own
records and from those closest routers. A node keeps no DHT of its own
and asks only the routers it holds. A node connects to another router only
to reach a peer behind that router, as [Connecting](#connecting) describes.
It re-announces every
reprovide interval of the mesh (`/info`), withdraws a record when it
stops the service or leaves, and a record a provider stopped announcing
without withdrawing it leaves the directory after three intervals.

Before a node advertises a backend, it probes the backend
(`--backend-probe-timeout`, 2 seconds by default). A backend that does not
answer is not advertised, so `discover_remote_services` does not list
services that would fail on the first call.

Discovery results are hints. They tell the caller who claims to provide a
service and, if the provider declared labels, what those labels are. Nothing
is authorized on that basis. The provider's credential is verified when the
connection is made.

Every node also runs the built-in `system://mesh.catalog` service, which
answers the question "what do you host?" for callers whose credential grants
it. `find_remote_tools` uses it to list a peer's tools.

## Connecting

Nodes are libp2p peers. By default a node listens on QUIC (`udp/5001`) and
TCP (`tcp/5002`) and advertises the addresses it has, including private
ones unless you pass `--announce-private=false`. Two nodes that can reach
each other connect directly. When neither can accept an inbound connection,
which is the common case, they use a **relay circuit** through a router.
Hole punching is enabled, so a relayed connection is upgraded to a direct
one when the NATs allow it. A node dials a peer's TCP address before its
QUIC address: the connection to a router carries one stream per peer
relayed over it, and a QUIC connection admits 256 streams while TCP with
yamux has no such limit. The scalability guide's [Connections, streams
and roles](../../guides/scalability/#connections-streams-and-roles) sets
out what each connection carries and what a NAT or firewall sees.

Routers are the fixed points. A node learns their addresses, labels and
load from the control plane's `/info` at enrollment and again on a
schedule, holds two of them with a relay reservation on each, and replaces
one that drops or that sends it away. A router that holds a member answers
a lookup for it from what it sees of the member; any other router answers
from the record the member announced under its own peer ID, so a lookup
for the member learns where it is reached through any router. An SDK
member listens on nothing of its own and is reached through a router it
holds. A call to a peer reached through a
third router goes through that router: the caller runs the credential
handshake there first, since a router relays only between peers it has
verified. The directory, the gossip and the relay are closed to anyone who
is not enrolled: a router serves nothing but the handshake to a peer that
has not passed it.

When a node opens a stream to another node for a service request, the first
message is an authentication frame with the caller's credential and the
service it wants. The receiver verifies the credential, evaluates policy for
that service (see [Authorization](../authorization/)), and answers with its
own credential. Both sides now know who the other is. The caller can check
what it needs to know about the provider, for example its labels, before it
sends any request data.

## What travels where

Every hop between two nodes is encrypted by a libp2p secure channel that
binds the connection to the peer's identity: TLS 1.3, which Go peers and the
Node and Python SDKs use, or Noise, which a browser can speak. Routers and
nodes offer TLS first and accept Noise; two peers that both have TLS land on
it. A relay forwards ciphertext and learns
only that the two peers are talking. The control plane sees enrollments,
refreshes, router leases, policy fetches and catalog reports. It never sees a
request.

Traffic to the control plane is protobuf over HTTPS. Traffic between nodes is
HTTP over libp2p streams for service requests, and protobuf frames for the
authentication handshake, the directory and gossip. Members take the
control plane's events as leaves of the gossip, over floodsub: the routers
deliver every event to them, and run the gossip mesh among themselves.

## Inference routing

`inference://` services are OpenAI-compatible HTTP backends: vLLM, Ollama,
LiteLLM, or a hosted API behind a local proxy. The node's `/v1` endpoint
hides which node serves a model. It keeps a short-lived view of the model
list of every reachable provider. It prefers a local provider when one
serves the model, and otherwise picks among remote providers, ranked by the
labels it knows about and by load. Backends are registered by their root URL
and the node adds the `/v1` prefix. The same backend is therefore reachable
through the `/v1` endpoint and, with `/v1/...` appended, through the proxy
path.

Before any request leaves the node for a provider, the node verifies the
provider's credential and that its role grants serving the service the
request names (`allowed_publish`): the directory says who announced a
name, the credential says who may serve it. A caller can restrict which
providers are acceptable further with
`X-Mesh-Required-Labels: key=value[,key=value]`. The node then confirms
that every listed label is attested in the credential as well before
forwarding. The header is removed before the request leaves the node.
An operator can set a floor that every provider must meet with
`egress.require_labels` in the node configuration.

## Mesh events

The control plane publishes bans and signing-key rotations as signed events.
Routers inject them into a GossipSub topic that every node subscribes to. A
node that receives a ban event drops the banned peer immediately. A node
that receives a rotation event fetches the new key set. Each event is
verified against the control plane's key before a node acts on it or
forwards it.

## Resource limits

Nodes rate-limit authentication attempts per peer and cap the size of every
frame and body they read. Routers cap inbound connections per source address
(`--conns-per-source-ip`, by default a quarter of the connection budget) and
total connections (`--low-watermark`, `--high-watermark`). Members behind a
NAT or a cluster's SNAT share one address, and the handshake, not the
per-address cap, is what keeps strangers out; the cap bounds how much of a
router one address can occupy. `agentmesh-one` sets it to the whole budget for its
embedded router, which sits behind a proxy and sees one address.
