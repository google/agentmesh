---
title: "Scalability"
linkTitle: "Scalability"
weight: 7
---

This guide is for the operator of a mesh that grows past a few hundred
members. It explains what each component spends per member, which setting
bounds what, how to size a deployment for the fleet you expect, how to
place members on routers with labels, and which metrics tell you that a
bound is near. The numbers come from the public testnet: six routers on
2 vCPU held 10,000 members, and every member stayed on the mesh for the
40 minutes the fleet was held; an earlier fleet of 3200 stayed through a
rollout of every router and both control plane replicas.

## What a member costs

A member is one `agentmesh-node` process. It holds a session with two
routers (`--routers`), chosen from those the control plane lists, and a
relay reservation on each. Those two sessions are everything the member
opens to the mesh at rest. Through them it receives the control plane's
events as a leaf of the gossip (floodsub: the routers deliver every
event to it, and it takes no part in the routers' gossip mesh), and it
uses the directory: it announces each service it publishes, and where it
is reached, to a router it holds, and asks a router it holds for
providers and peers. The router keeps the member's records, places each
on the routers closest to its key (three, the mesh's replication,
`agentmesh-control-plane --dht-replication`), and answers each lookup
from its own records and those routers', asked at once. The member keeps
no DHT and connects to no router it does not hold. It re-announces every
5 minutes (the mesh's `--dht-reprovide-interval`) and withdraws a record
when it stops the service or leaves. A member connects to another member only to
call it, through that member's router, where it runs the credential
handshake before asking for the circuit. At rest it uses about 55 MiB of
memory, 300 goroutines and 20 file descriptors, and almost no CPU.

Joining is the expensive moment. The member enrolls at the control plane
(one signed request, one database write, one credential minted), reads the
router list with each router's labels and load, picks its routers and
opens a connection to each, and on each one runs a TLS or Noise handshake,
an identify exchange and the credential handshake, in which the router
verifies the member's credential and the member verifies the router's. A
router pays a few milliseconds of CPU per member that joins, and a fleet
that joins at once pays them all at once.

## Connections, streams and roles

This section is the network model the rest of the guide sizes: what a
connection is, what travels on it, which component opens which, and what
a firewall or NAT between them sees.

### One connection per pair of peers

libp2p keeps one connection between two peers and multiplexes every
protocol over it as streams. A connection is one transport session with
one security handshake:

| Transport | Security | Streams | Who listens on it |
|---|---|---|---|
| TCP | TLS 1.3 or Noise, then yamux | yamux: no per-connection limit; the resource manager's budgets are the only ones | routers (`/tcp/4501` on the testnet), nodes (`/tcp/5002` by default) |
| QUIC v1 (UDP) | TLS 1.3, built in | 256 opened by the far end per connection, fixed in go-libp2p; the 257th waits for one to close, with no error at either end | routers (`/udp/4501/quic-v1`), nodes (`/udp/5001/quic-v1`) |
| WebSocket | TLS 1.3 or Noise, then yamux | as TCP | routers, on the API port, for browsers |
| WebTransport, WebRTC | TLS 1.3 | as QUIC | routers, for browsers |

A stream costs no flow: a NAT or a firewall holds one entry per
connection, whatever runs on it. The entry is kept alive by the
transport's keepalive, every 15 seconds on QUIC and every 30 seconds on
yamux, so a connection that stays open stays reachable through a
middlebox that times idle entries out.

The node dials TCP first. When a peer offers TCP and QUIC, the node dials
the TCP address at once and the QUIC address 250 ms later; once the TCP
socket is connected the dialer holds the other attempts while the
connection upgrades, so QUIC is dialled when the TCP SYN goes unanswered.
A peer that offers no TCP is dialled with no delay. The reason is the
stream limit in the table: the connection a member holds to a router
carries one stream per peer relayed over it, and 256 is a small number
for a service. Hole punching does not use this order; a simultaneous
dial tries every address at once.

### Roles

| Role | What it is for the network | What it opens | What opens to it |
|---|---|---|---|
| Router | The dialable endpoint. Relay for members behind NAT, the directory its members announce to and ask (served from the DHT the routers keep among themselves), the point of admission (credential handshake, relay ACL, bans), the hub GossipSub events pass through, and the record of which members hold a reservation on it. | Connections to the other routers (every pair), for the DHT and GossipSub. | Every member that holds it, the control plane's event publisher. |
| Member (`agentmesh-node`, an SDK) | A client of the routers. It announces where it is reached, looks peers and services up, verifies the peers it talks to and carries the data plane. It keeps no DHT and serves no lookups: the routers it holds answer for it. | K connections to the routers it holds (`--routers`, 2), one to each peer it reaches directly. | Peers that call it: directly when they can, through a router otherwise. |
| Provider | A member that publishes a service: the fan-in point of the mesh. | As a member. | One relayed connection per caller, each a stream on its connection to a router. |
| Control plane | Enrollment, the router catalog, keys, policy and leases, over HTTP. Its event publisher is a member that holds every router. | HTTP only, and the publisher's connections to the routers. | Members and routers, over HTTP. |

### What a connection carries

| Protocol | Between | Streams | Lifetime |
|---|---|---|---|
| `/ipfs/id/1.0.0`, `/ipfs/id/push/1.0.0` | every pair, on connect; push when the peer's addresses change | 1, short | the exchange |
| `/mesh/auth/1.0.0` | member and router on connect and at renewal; caller and provider before a call | 1, short | the handshake |
| `/libp2p/circuit/relay/0.2.0/hop` | member to router | 1 per reservation, renewed; 1 per relayed connection the member opens | the reservation; the relayed connection |
| `/libp2p/circuit/relay/0.2.0/stop` | router to the member a caller reaches | 1 per relayed caller | the relayed connection |
| `/mesh/directory/1.0.0` | member to a router it holds | 1 per request, short | the request |
| `/mesh/kad/1.0.0` | router to router | 1 request stream per router | the connection |
| `/meshsub/1.3.0` | router to router | 1 per direction | the connection; heartbeat every second |
| `/floodsub/1.0.0` | member and router | 1 per direction | the connection |
| `/libp2p/dcutr`, autonat v2 | the two ends of a relayed connection | 1, short | the hole punch |
| `/mesh/mcp/1.0.0`, libp2p-http, `/mesh/goaway/1.0.0`, ping | caller and provider; router and member | 1 per call or session | the call |

The resource manager budgets every protocol a member holds a stream on
for as long as it is connected (gossip, the relay, and MCP on a node) or
opens per request (the directory) from the connection budget, so a router or a provider admits as
many such streams as it admits connections; libp2p's own default for a
protocol it was not told about is a few hundred streams in all, scaled
from host memory. A refused stream is counted in
`agentmesh_router_streams_refused_total{protocol}` and
`agentmesh_node_streams_refused_total{protocol}`.

A stream over TCP also reserves memory. yamux reserves one receive window
(256 KiB) per stream it opens, through the resource manager, and releases
it when the stream closes; the memory is allocated only as data arrives
and waits to be read, so an idle stream holds a reservation and no bytes.
The memory budget therefore follows the stream budget, one window per
stream the budget admits, on the system scope and on the scope of each
peer. libp2p's own default for the system scope is scaled from host
memory and was 1.1 GiB on the testnet's routers, full at 1500 members
over TCP, at which point the relay refused every circuit with
`RESOURCE_LIMIT_EXCEEDED` and no stream counter moved. A refused
reservation is counted in
`agentmesh_router_memory_reservations_refused_total` and
`agentmesh_node_memory_reservations_refused_total`, and the scope that is
full reads from `libp2p_rcmgr_memory{scope}` against
`libp2p_rcmgr_limit{resource="memory",scope}`.

### Hub links and peer links

A member's connection to a router is a hub link. It carries the member's
own streams and one `stop` stream for every peer that reaches the member
through that router, or one `hop` stream for every peer the member
reaches through it. A connection between two members is a peer link; it
carries one session.

A relayed connection is therefore not a connection at the network level.
It is one `hop` stream on the caller's hub link and one `stop` stream on
the provider's hub link, two streams on two connections that exist
already. Nothing new crosses a NAT. What it consumes is stream budget,
on both hub links, and that is where fan-in is bounded:

- the provider's connection to each router: no limit over TCP, 256 over
  QUIC, and the node's relay `stop` budget, which equals its connection
  budget (400) per router;
- the router's `--relay-max-circuits` (1024) for the provider as a
  destination;
- the provider's connection manager: at 400 connections it closes down to
  100, relayed ones included;
- the provider's backend.

Callers that reach a provider through K routers share the provider's
connection budget, so the number of concurrent callers one provider
serves is its connection budget, and a service that more callers reach at
once is published by more providers. The relayed connection is also the
start of a hole punch: a caller and a provider whose NATs allow it move
to a direct peer link, which frees both hub-link streams and holds one
NAT entry at each end.

### What a middlebox sees per member

A member holds K long-lived connections to its routers, kept alive by
the transport, and no other to the mesh: entries that do not churn, K of
them. A member that reaches a peer directly holds one entry per such
peer, at both ends. A relayed connection adds none.

A firewall between a member and the routers needs TCP (and UDP for
QUIC, when the member is allowed to fall back to it) to the routers'
ports outbound; nothing inbound, since every connection to a member
arrives through a hub link it opened. A conntrack table on that path is
sized for the K long-lived entries per member, and a NAT that times idle
UDP entries out in less than the QUIC keepalive (15 s) breaks a QUIC hub
link; TCP first avoids it.

## What bounds the mesh

The table lists each bound, the component that enforces it, its default and
what happens when it is reached. The sections after it explain how to size
them.

| Bound | Where | Default | At the bound |
|---|---|---|---|
| Routers per member | `agentmesh-node --routers` | 2 | A member holds this many routers; one is enough to be on the mesh, the second covers a router restart. |
| Routers per key | `agentmesh-control-plane --dht-replication` | 3 | A record a member announces is kept by the router it announced to and placed on this many routers, the closest to its key, which is what survives routers going down. Published on `/info`, so every router of the mesh runs the same value. |
| Connections per router | `agentmesh-router --high-watermark`, `--low-watermark` | 4000, 15% below (3400) | At the high mark of members the router sends members away, at random, down to the low mark; they attach to another router and stay off this one for five minutes. A mesh of N routers holds about N × 4000 / 2 members. |
| Connections per source address | `agentmesh-router --conns-per-source-ip` | a quarter of the high mark (1000) | The router refuses the next connection from that address. Members behind one NAT or one cluster's egress share an address. |
| Relay reservations per router | `agentmesh-router --relay-max-reservations` | the high mark (4000) | A member that cannot reserve is not reachable through that router. |
| Relayed connections per peer | `agentmesh-router --relay-max-circuits` | 1024 | A service called through the relay holds one circuit per caller; the next caller is refused. |
| Streams per hub link | the transport | TCP: the resource manager's budgets; QUIC: 256 per connection | Every relayed caller is one stream on the provider's connection to the router. The node dials TCP first so the budget is the resource manager's; over QUIC the 257th caller through one router waits until one leaves, and both ends log the connection (see `agentmesh_node_busiest_connection_streams`). |
| Enrollments per second | control plane, fixed | 10 a second, burst 20 | The next enrollment is answered `429` with `Retry-After`; the node retries for up to three minutes. |
| Connections per node | `agentmesh-node`, fixed | 400 high, 100 low | A node called by more peers than this at once closes connections down to 100; past 400 it refuses the next one. |
| Connections per source address at a node | `agentmesh-node`, fixed | a quarter of the high mark (100) | The node refuses the next direct connection from that address, counted in `agentmesh_node_inbound_connections_refused_total`. A service called by a fleet behind one NAT or one cluster's egress sees them all from one address. A caller that arrives through a router is not charged to the router's address: it is bounded by the node's connection budget and per-peer scope, and at the router by the relay's per-peer and per-address budgets. |
| Router lease | `agentmesh-control-plane --lease-duration`, `agentmesh-router --shutdown-lease-ttl` | 15m, 30s | A router that stops without the last lease stays listed for the lease duration. |

The first two rows are the model. The formulas below use these letters:

- F, the members in the fleet.
- N, the routers in the mesh.
- K, the routers a member holds (`--routers`, 2 by default).
- H, a router's high watermark (`--high-watermark`).
- r, the mesh's replication: the routers each record is placed on
  (`--dht-replication` on the control plane, 3 by default).

A fleet of F members on N routers, each member holding K of them, puts
about F × K / N sessions on each router, and that is the figure the
watermarks see: with 10,000 members and K = 2, about 3300 per router on
six routers, 1700 on twelve. Adding a router adds members: the fleet a
mesh holds is N × H / K. A member picks the routers with the most room
when it joins, so a new router fills from the members that join after it
and from those the full routers send away; the members already placed do
not move on their own. When a router stops, its members spread over the
N − 1 others, which is where the headroom in the next section goes.

The directory costs a router no sessions. A member's announcements and
lookups travel on the sessions it already holds, and a router answers a
lookup from its own records and the r routers closest to the key, over
the connections the routers already hold to each other. What the
directory costs is records and requests: a router keeps the records of
its own members and r copies of records whose keys land on it, and asks
r routers per lookup. A key that every member publishes, such as a
service type, lands on the same r routers for all of them; those r
routers hold a record per publisher and answer every lookup of it, and
a lookup of it returns at most 100 providers.

What bounds the total is the router's libp2p connection cap, twice the
high watermark: a router past it refuses the next connection, session or
not. What is left in passing, a call to a peer on this router, two
connections each while members enroll, fits in the gap between the
watermark and the cap.

## Sizing the routers

Start from the fleet you expect, F members on N routers with `--routers`
at its default of 2, and size for the day one router is down:

- `--high-watermark` at least 1.2 × F × K / (N − 1). Each router then
  holds F × K / N sessions in normal running, with room for the members
  of a stopped router, and the connection cap at twice the high mark
  holds what members open in passing. 5000 members on four routers need
  4000; 10,000 members on six routers need 4800, on twelve 2200. The
  testnets deploy with 6000 (`ROUTER_HIGH_WATERMARK` in the deploy
  workflow) on six routers (`ROUTER_REPLICAS`), which holds 10,000
  members with one router out.
- The three knobs, and what each buys. One is a member's own: `--routers`
  (K) is what a router restart costs it; a member with two routers stays
  on the mesh through one, and each one more is a session more per member
  on some router. Two are the mesh's, set on the control plane and read
  by every router from `/info`: `--dht-replication` (r) is what losing
  routers costs the directory, a record on three routers survives two of
  them down at once, and each one more is a copy more of every record;
  `--dht-reprovide-interval` is how soon a provider that stopped without
  unpublishing leaves the directory, three intervals, which is also how
  long routers keep a record, against the announcements a minute the
  routers absorb, providers divided by the interval. None of the three
  adds capacity: routers do, by dividing F × K by N.
- `--low-watermark` at its default, 15% below the high mark. The gap is
  what one shedding moves to the other routers; a smaller gap sheds more
  often, a larger one moves more members at once. A router that sheds is
  one the fleet has outgrown: the members it sends away land on routers
  that are nearly as full, and the fix is a router, not a watermark.
- `--conns-per-source-ip` at the number of members that share one address,
  times two if they may all enroll at once. One cluster behind one egress
  address with 500 nodes needs 1000. The default follows the high mark.
- `--relay-max-reservations` stays at the high mark. `--relay-max-circuits`
  is the number of callers one service may have at once through one router;
  raise it for a service the whole mesh calls.

Memory follows connections: about 190 KiB and six goroutines each, so a
router at 9000 connections uses about 1.7 GiB, with 45,000 to 65,000
goroutines. Part of it stays when the members leave: a router that had
held 10,000 members sat at 720 MiB with 16 connections hours later. Two
libp2p bugs account for most of that, one context per GossipSub peer
ever seen ([go-libp2p-pubsub#735](https://github.com/libp2p/go-libp2p-pubsub/pull/735))
and the addresses and signed records of every peer ever connected
([go-libp2p#3559](https://github.com/libp2p/go-libp2p/pull/3559));
until a release carries the fixes, size a router's memory for the
largest fleet it has held since it started. CPU follows joins
and relayed traffic, and a router needs a core it can use. Under a CPU
limit a router answers handshakes late, members time out and retry, and
the retries cost more than the handshakes did. On Kubernetes set a request
and no limit, as `charts/agentmesh` and the testnet manifests do; the
testnet runs its routers on 2 vCPU without a limit. The router sizes its
libp2p stream limits from the watermarks, so a small VM admits as many
members as its watermarks say; what a small VM cannot do is handshake them
quickly. Its libp2p connection cap is twice the high watermark: between
the two, the connection manager trims and the router sheds, and the cap
refuses only what neither has handled yet. A router that reads
`agentmesh_router_inbound_connections_refused_total{reason="scope_limit"}`
rising has more connections than two watermarks, which a rollout of a
mesh at capacity produces when the stopped router's members land on the
others; the fix is a router or a higher watermark.

The stream budgets follow the watermark per protocol, because a member
holds a stream open to its router for as long as it is connected on each
of gossip and its relay reservation, and opens one per directory request,
and libp2p's default for a protocol it was not told about is a few
hundred streams in all, scaled from host memory. A router that refuses a
member's gossip stream leaves that member without the control plane's
events, and one that refuses its directory stream fails the member's
lookup, which the member retries on its other router; the router counts
the refusal in `agentmesh_router_streams_refused_total{protocol}` and
logs it once a minute per protocol.

Routers connect to one another, every pair, to run the DHT and GossipSub
across the mesh; a router never sheds those connections. That is N × (N − 1)
/ 2 connections for N routers, which is nothing at ten routers and a
question at a hundred; a mesh that large is several meshes.

When you change a router's flags, keep `minReadySeconds` at 90 s or more:
the StatefulSet waits that long between pods so that the members of one
router have settled on the others before the next one stops. A router that
stops announces `--shutdown-lease-ttl` (30 s) in its last lease, so it
stays listed for the time a restart takes and is dropped from `/info` if
it does not come back, and it tells each of its members it is draining
before it closes, so they attach to another router within the second and
leave this one alone for that time.

## Placing members with labels

A router may carry labels, `--label region=eu --label zone=eu-a`, which
the control plane checks against the router role's `allowed_labels` at
enrollment and lists on `/info`. A member picks its routers by them:

- `--router-selector region=eu` holds only routers that carry every pair
  named. A member whose selector no router carries waits, with a warning
  that names the selector and the labels it saw, and is not on the mesh
  until a router that matches exists.
- `--router-prefer zone=eu-a` orders the routers that pass the selector:
  those carrying more of the preferred pairs first, and among equals the
  one with the most room. A member stays on its zone's routers while they
  have capacity and falls to the region's others when they do not.

A selector places a member; it does not isolate it. Discovery and calls
cross the whole mesh: a member on the routers of one region finds a service
on the routers of another and calls it through the service's router, where
it authenticates on the way. What a selector buys is locality for the
relayed traffic, and a sizing you can do per group: the F in the formula
above is the members whose selector lands on a set of routers, and the N
is that set.

One value per key: a router carries `zone=eu-a` or `zone=eu-b`, not both.
A hierarchy is several keys on one router, `region=eu zone=eu-a`, with
members selecting on the broad key and preferring on the narrow one.

## Sizing the join

The control plane admits ten enrollments a second for the whole mesh. A
member it turns away retries after `Retry-After` with jitter for up to
three minutes, so a fleet of up to about 1500 members may start at once and
joins over 150 s. A larger fleet starts in waves of that size, or at a rate
of ten a second. The limiter protects the control plane and is a constant
of the build.

The routers set the other half of the join rate. A fleet of 500 joining at
20 a second was admitted in under a minute by routers on 2 vCPU. Against
the same routers under a 500m CPU limit, more than a third of the members
on one host exited at the handshake timeout. The node retries a router
that did not admit it in time (after 2 s, 4 s and 8 s), so a slow router
costs the fleet time first; it costs members when the retries run out.

The mesh a member joins sets the rest. On the testnet, 1000 members
joining at 5 a second were all ready in 0.4 s at the median and 0.7 s at
the 95th percentile on an empty mesh, and in 3.5 s and 5.5 s on a mesh
already holding 9000, with the 95th percentile reaching 15 s on some of
the steps between; the control plane's 99th percentile went from 25 ms
to 2.5 s over the same steps, and no step lost a member.

A member that enrolls needs its control plane and its routers reachable
from where it runs. Behind a NAT it is reached through a relay, which costs
a reservation on the router and nothing else; a member with a public
address may run `--reachability auto` and be dialled directly once AutoNAT
has confirmed the address, which takes it off the relay. Reachability
decides how a member is reached and nothing else: it keeps no DHT either
way, and serves no lookups.

## Sizing a service

A service is reachable through the node that publishes it, and callers that
cannot dial that node directly reach it through a relay circuit on a router
where it holds a reservation. Each such caller is one stream on the node's
connection to that router (see [Hub links and peer
links](#hub-links-and-peer-links)). Four things bound how many callers one
node serves at once:

- The node's connection manager, 400 connections, relayed ones included.
  A node that many callers reach at once closes connections above that
  down to 100. The node's relay `stop` budget is the same figure per
  router, so a provider that holds two routers can be reached by 400
  callers at once through either.
- The transport of the node's connection to each router: no stream limit
  over TCP, which the node dials first; 256 streams over QUIC.
- `--relay-max-circuits` on the router, 1024 by default.
- The backend behind the node. A `command` backend is one process that
  every caller shares; a URL backend is whatever the server behind it can
  take.

A service that the whole mesh calls is published by several nodes. Callers
discover every provider of a name and pick one, so capacity grows with
providers. A provider that does not answer costs its caller one attempt:
the caller is answered `502 Bad Gateway` and may try another provider. On
the testnet, 1000 members joining over 200 s and each calling a service
published by two nodes as soon as it was ready all completed their first
call, in 1.0 to 1.4 attempts per member, at every size of the mesh up to
10,000; the attempts that failed were callers the two providers had
trimmed at 400 connections, answered 502 and served seconds later. Size
the number of providers to the number of callers you expect in one
moment.

## Running many nodes on one host

A load generator, or a host that runs one node per agent, needs the kernel
limits a few hundred libp2p hosts need. For 500 nodes on one machine:

```text
fs.file-max = 4194304
fs.nr_open = 4194304
kernel.pid_max = 4194304
kernel.threads-max = 2097152
net.core.somaxconn = 4096
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
vm.max_map_count = 1048576
```

with `nofile` at 1048576 and `nproc` unlimited in `limits.conf`. Leave the
ephemeral port range alone; if the nodes serve on fixed ports (metrics, the
API), reserve those with `net.ipv4.ip_local_reserved_ports` so an outgoing
connection is never given one. Every node on the host shares its source
address, so the router's `--conns-per-source-ip` must cover them, twice
while they enroll. Memory is 55 MiB per node; 500 nodes fit in 32 GiB with
room for their backends.

## What to watch

The router and the node serve Prometheus metrics on `--metrics-addr`. The
control plane serves Prometheus metrics on its HTTP listen address,
`--bind-address`. The metrics below are the ones that say a bound is near:

| Metric | Reads as |
|---|---|
| `agentmesh_router_connections{direction="inbound"}` against `agentmesh_router_connection_watermark{level="high"}` | How full a router is. The gap, summed over the routers that are not draining, is the free capacity of the mesh. |
| `agentmesh_router_goaway_sent_total{reason="OVERLOADED"}` | A router at its high mark sent members to the others. Rising on a router that is not draining, the fleet has outgrown its routers. |
| `agentmesh_router_inbound_connections_refused_total` | Members behind one address have hit `--conns-per-source-ip`. |
| `agentmesh_node_inbound_connections_refused_total{reason}` against `agentmesh_node_conns_per_source_ip_limit` | On a provider: direct callers it turned away before the handshake. `per_ip_limit` is a fleet behind one address, `rate_limit` a burst from one address, `scope_limit` more callers at once than the node's connection budget, relayed ones included. The caller sees the connection close before TLS, or `CONNECTION_REFUSED` over QUIC, and nothing more. |
| `agentmesh_node_transit_handshakes_total{router,result}` | On a caller: handshakes with routers it did not hold, run to reach a peer through them. `router="unlisted"` is a router the node's catalog missed, which a member that started during a router rollout produces until its next sync; `result="failed"` rising is a router that refuses the node or is gone while peers still announce circuits through it. |
| `agentmesh_node_peer_lookups_total{result}` | On a caller: directory lookups for a peer it held no address for. `not_found` is a peer the directory does not carry, and the call falls back to circuits through the caller's own routers, which reach the peer only if it holds one of them; `failed` rising is no held router answering (`agentmesh_node_directory_requests_total{result="failed"}` rises with it). |
| `agentmesh_node_provider_reach_total{result}` | On a caller: attempts to reach a provider for its credential before a call; every failure is one 502 at the caller. `relay_refused` is a router that has not admitted the caller or the provider, `dial_timeout` a provider gone or a relay connection at its stream limit (below), `no_address` a provider the directory does not carry. |
| `agentmesh_router_busiest_connection_streams{transport}`, `agentmesh_node_busiest_connection_streams{transport}` | The most streams any one connection carries. Every relayed connection is one stream on the relay's connection to each end, and a QUIC connection admits 256 streams: a provider reached through one router over QUIC has at most 256 callers through it at once, and the 257th waits until one leaves, which it sees as a dial that times out. Both ends log the connection once a minute while it is within a tenth of the limit. A provider that expects more callers than that listens on TCP as well, or holds more routers. |
| `libp2p_relaysvc_reservations_total{type="opened"}` minus `{type="closed"}`, against `agentmesh_router_relay_limit{limit="reservations"}` | Reservations in use against the budget. |
| `libp2p_relaysvc_connection_rejections_total{reason="resource limit exceeded"}` | A service has more callers than `--relay-max-circuits`. |
| `libp2p_rcmgr_blocked_resources` | libp2p refused a connection or stream on a scope. On a router this should stay flat. |
| `agentmesh_router_memory_reservations_refused_total`, `agentmesh_node_memory_reservations_refused_total`, with `libp2p_rcmgr_memory{scope}` against `libp2p_rcmgr_limit{resource="memory",scope}` | The resource manager's memory budget on some scope is full. Over TCP every open stream holds a 256 KiB reservation, so this is the stream budget met from the other side: new streams and relayed connections are refused, with `RESOURCE_LIMIT_EXCEEDED` at the relay and nothing in the stream counters. The scope whose `libp2p_rcmgr_memory` is at its limit names the budget. |
| `agentmesh_router_streams_refused_total{scope,protocol}`, `agentmesh_node_streams_refused_total{scope,protocol}` | The streams behind that gauge, by protocol. `/mesh/directory/1.0.0` or `/floodsub/1.0.0` at the `protocol` scope on a router is members past the stream budget of a protocol: their lookups fail over to their other router, their events stop. `scope="unauthenticated"` is a stream from a peer that never passed the handshake. |
| `agentmesh_router_auth_handshakes_total{result="read_failed"}` | Members that timed out mid-handshake: the router is slow, usually CPU. |
| `agentmesh_router_draining` | The router is stopping. Exclude it from capacity sums. |
| `agentmesh_control_plane_http_requests_total{code="429"}` | Members turned away by the enrollment limiter; they retry. |
| `agentmesh_control_plane_http_request_duration_seconds` | The control plane's own latency; p99 above a second under a join burst means the database is the bound. |
| `agentmesh_node_mesh_connected` | On every node: `0` for five minutes is a member off the mesh. |
| `agentmesh_node_routers{state="attached"}` against `{state="wanted"}` | On every node: fewer attached than wanted for long is a member that cannot find a router with room, or one whose selector too few routers carry. `agentmesh_node_router_candidates{match="selector"}` is how many it could choose from. |
| `agentmesh_router_directory_requests_total{op,result}`, `agentmesh_router_directory_request_seconds{op}` | On every router: the directory requests its members made, by operation (`provide`, `withdraw`, `find_providers`, `find_peer`; `place` is a record or withdrawal another router put here, `lookup` a find another router ran here) and result. `agentmesh_router_directory_lookups_total{result="error"}` rising is a peer router down or slow, whose records lookups miss; the histogram is what a member waits for a lookup. `agentmesh_router_directory_placements_total{result="error"}` rising is a router that does not take the records placed on it. `agentmesh_router_directory_records` is what each router holds. |
| `agentmesh_node_directory_requests_total{op,result}`, `agentmesh_node_directory_request_seconds{op}` | On every node: the same from the member's side. `failed` is a request no held router answered; `empty` a lookup nobody had a record for, which on a fresh mesh is ordinary. |

An autoscaler for the routers has its inputs in the first two rows: scale
out when the free capacity of the mesh is below what one router holds, so
that the stop of any one router still fits, or when a router that is not
draining sends members away. A new router fills from the members that
join after it and from those the full routers shed; it does not pull
members off routers that have room.

## Measuring your own mesh

`agentmesh-bench join` starts N nodes on one host from one bootstrap token
and reports every member's journey from process start to its first call
through the mesh, then holds the fleet resident and samples its readiness.
`tests/scale/member-journey.sh` runs it against a deployment with the
control plane and router metrics read before and after, and
`tests/scale/member-ladder.sh` runs it from several hosts in steps, so each
step lands on a mesh already carrying the ones before. The report says how
many members became ready and how long the p50 and p95 took, which is the
number to compare against the bounds above before a fleet does.
