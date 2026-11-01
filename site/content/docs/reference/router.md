---
title: "agentmesh-router"
linkTitle: "agentmesh-router"
weight: 3
---

`agentmesh-router` is a libp2p peer with a stable identity that new nodes connect
to first. It serves the directory, relays traffic between nodes that cannot reach
each other, and forwards the control plane's signed events. It has no policy
of its own.

```text
agentmesh-router [flags]
```

## Enrollment

A router enrolls like a node, requesting `mesh:role:router`, with one of:

| Flag | Meaning |
|---|---|
| `--jwt-path` | File containing an OIDC token (a projected service account token, for example). |
| `--bootstrap-token-path` | File containing a bootstrap token minted with `"role": "mesh:role:router"`. |
| `--oidc-token`, `--bootstrap-token` | The same tokens as values. Visible in process listings. The file forms are preferred. |
| `--label` | A `key=value` label declared at enrollment, repeatable (`--label region=eu --label zone=eu-west1-b`). The control plane signs it only if `mesh:role:router` allows it in `allowed_labels`, lists it on `/info`, and nodes choose routers by it with `--router-selector` and `--router-prefer`. The same labels, with the same meaning, as a node's; see [labels](../../concepts/authorization/#labels). |

The mesh policy must bind the router's identity to `mesh:role:router`. The
`agentmesh` Helm chart handles this: its bootstrap job binds the router's
service account and mints a bootstrap token with `max_usages` equal to the
replica count.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--control-plane` | `http://127.0.0.1:8080` | Control plane URL. `https://` is required unless the host is loopback. |
| `--insecure-control-plane` | `false` | Accept plaintext `http://` to a non-loopback host, such as an in-cluster Service. |
| `--listen` | `/ip4/0.0.0.0/tcp/5001`, `/ip6/::/tcp/5001` | libp2p listen addresses. Repeatable. Add `/ip4/0.0.0.0/udp/5001/quic-v1` for QUIC. |
| `--external-addr` | none | Addresses to announce instead of the detected ones, such as `/dnsaddr/bootstrap.example.com` or `/ip4/<public-ip>/tcp/5001`. Repeatable. |
| `--keys-path` | `router.key` | The router's private key. It fixes the peer ID across restarts and belongs on persistent storage. |
| `--control-plane-sync-interval` | `5m` | How often the router's one pass over the control plane runs: it renews the lease, re-reads `/info`, `/keys` and `/policies`, and refreshes its own credential when it nears expiry. A mesh event runs a pass at once. Must be well below the control plane's `--lease-duration` and `--key-grace-period`. |
| `--allow-loopback` | `false` | Announce and accept loopback and link-local addresses. For a router and nodes on one host. |
| `--conns-per-source-ip` | a quarter of `--high-watermark` (`1000`) | Inbound connections accepted per source address. One address can hold at most this share of the router's connection budget, so filling a router takes at least four addresses. Members behind a NAT or a cluster's SNAT share one address and each holds one connection per router, two while enrolling. |
| `--low-watermark`, `--high-watermark` | 15% below the high mark (`3400`), `4000` | How many members the router holds: peers that passed the handshake, other routers aside. At the high mark the router sends members away (see below) until it is back at the low mark, so the gap between the two is what one shedding moves; the default moves 15%. The same numbers bound connections: above the high mark the connection manager closes connections, oldest first among those that carry no session, then members; connections to the other routers are never closed. A connection without a session lasts at most `--auth-deadline`; the connection manager leaves a connection alone while it is younger than its grace period, and libp2p's connection cap, at least twice the high mark, is what bounds the total (see the [scalability guide](../../guides/scalability/#what-bounds-the-mesh)). |
| `--relay-limit-duration`, `--relay-limit-data` | `1h`, `0` | Caps on each relayed connection: lifetime, and bytes per direction (`512MiB`, `1GB`). The relay cuts the connection when either is reached. `0` means no limit. |
| `--relay-max-reservations` | `--high-watermark` (`4000`) | Members that may hold a relay reservation on this router at once, which is how many members it can reach on behalf of callers. Per source address the cap is `--conns-per-source-ip`. |
| `--relay-max-circuits` | `1024` | Relayed connections one peer may hold at once through this router, as caller or as destination. A service that many members call at once needs this many open circuits. |
| `--shutdown-lease-ttl` | `30s` | Sent in the router's last lease when it stops: how long it expects to be away, which is how long the control plane keeps listing it. The default covers a pod that restarts in place. A router that is being removed for good can send `1s`. `0` sends nothing and the lease expires on the control plane's schedule. |
| `--auth-deadline` | `1m` | How long an inbound connection may stay open without its peer passing the handshake. A member handshakes the moment it connects, as does the control plane's event publisher, which presents a credential of its own. What is left at the deadline is closed, so a connection without a session costs the router a minute, and the watermarks mean members. `0` keeps every connection. |
| `--metrics-addr` | off | Serve `/metrics`, `/healthz`, `/readyz` and `/debug/peer` without authentication on this address. `/readyz` returns `200` once the router is enrolled and the libp2p host is up. Keep this address separate from the libp2p ports and inside the cluster. |
| `--ingress-addr` | off | Serve external HTTP ingress under `/ingress/` (plus `/ingress/healthz` and `/ingress/.well-known/oauth-protected-resource`) on this address. Non-loopback addresses require TLS (`--ingress-tls-cert-path` / `--ingress-tls-key-path`) or `--allow-insecure-ingress-http` behind a TLS-terminating L7 load balancer. |
| `--ingress-url` | none | Public base URL advertised in the router's lease and rewritten into A2A `AgentCard` and RFC 9728 metadata (for example `https://hub.example.com/ingress`). |
| `--ingress-tls-cert-path`, `--ingress-tls-key-path` | none | TLS certificate and private key for `--ingress-addr`. |
| `--allow-insecure-ingress-http` | `false` | Permit plaintext HTTP on a non-loopback `--ingress-addr` (behind a TLS-terminating L7 proxy) and `http://` in `--ingress-url`. |
| `--public-control-plane` | derived | Optional public control-plane URL advertised in RFC 9728 and A2A OAuth metadata when `--control-plane` is an internal address. |
| `--pprof-addr` | off | Serve Go runtime profiles under `/debug/pprof/` on this address, for attributing memory or goroutines the metrics show as held. Unauthenticated, and a heap profile is a dump of process memory, which holds the router's key: bind it to loopback and reach it with `kubectl port-forward`. |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`. |
| `--log-format` | `text` | `text` or `json`. |

## What it does at run time

1. Fetches `/keys` and enrolls. The credential carries
   `role("mesh:role:router")` and the relay right.
2. Starts the libp2p host, the DHT it shares with the other routers, the
   directory it serves to its members, the relay service and GossipSub.
3. Registers a lease at `POST /routers/lease` with its announced addresses
   and renews it every `--control-plane-sync-interval`, in the same pass
   that re-reads `/keys`, `/info` (the routers to federate with and the ban
   set) and `/policies` (the mesh policy, which decides what a member may
   publish). A `KEY_ROTATION` or `POLICY_UPDATE` event runs the pass at
   once; while the list names a router this one has not authenticated with,
   the federation step alone is retried every 2 seconds. The control plane
   lists the router on `/info` while the lease is live.
4. Runs the mutual credential handshake on every inbound connection and
   refuses peers whose credential does not verify and peers on the ban list.
   Until a peer passes it, the router serves it nothing but the handshake:
   a directory, DHT or gossip stream it opens waits, unread, and is served
   once the peer is authenticated, or reset when the connection closes at
   `--auth-deadline` first. A member's gossip stream opens on connect, a
   moment before its handshake completes, which is why it waits instead of
   being refused outright. The DHT's routing table admits authenticated
   peer routers and nothing else, and the router queries no one else.
5. Serves the directory on `/mesh/directory/1.0.0` to the members it
   holds. A member announces each service it publishes and where it is
   reached; the router keeps the record and places it on the routers
   closest to the key, as many as the mesh's replication (`/info`). A
   record is kept only for a service the member's credential grants serving
   (the role's `allowed_publish`), checked against the credential the
   handshake presented and the mesh policy the router synced, so a grant
   added to a role reaches the directory at the next pass; a record for
   anything else is refused. A record
   lives for the mesh's record TTL after its last announcement,
   and an announcement replaces the addresses of the one before; a member
   that stops a service or leaves withdraws its records, and the router
   withdraws them from the same routers. A member asks for providers of
   a key or for a peer; the router answers from its own records and from
   the routers closest to the key, asked at once. A member keeps no DHT
   and asks only the routers it holds. It connects to another router only
   to reach a peer behind that router.
6. Refreshes its own credential before it expires, like a node, at the
   pass that finds less than 4.8 hours left. The threshold is a fifth of
   the default lifetime and does not follow the control plane's
   `--biscuit-ttl`.
7. Every 5 seconds, compares the members it holds, the peers that passed
   the handshake, with `--high-watermark`. At the mark it picks members at
   random, as many as take it back to `--low-watermark`, and sends each a
   go-away on `/mesh/goaway/1.0.0` with the reason `OVERLOADED` and a
   retry time of 5 minutes. A member that takes the message attaches to
   another router at once and stays off this one for that time; one that
   does not is closed after a 5 second grace, like any other. Connections
   to the other routers are never shed: the DHT runs over them.
8. On `SIGTERM` or `SIGINT`, sends a last lease with `--shutdown-lease-ttl`,
   sends every member a go-away with the reason `DRAINING` and that ttl as
   the retry time, and after the same grace closes its connections. The
   control plane lists the router for that long and no longer, so a router
   that restarts in place is still there when its members redial it, and
   joiners are sent to the routers that remain once the time has passed.
   The operator states the time the router will be down, the way BGP
   graceful shutdown announces a maintenance window.

A router stores nothing except its key. Restarting a router loses no
important state. Nodes reconnect and publish their services again.

## Sizing

The router sizes its libp2p resource limits from `--high-watermark` and
`--conns-per-source-ip`, not from the memory of the machine: the stream
budgets of the system, of identify, of the credential handshake and of the
relay follow the connection budget, so a router on a small VM admits as
many members as its watermarks say. What the machine needs is CPU: every
member that joins costs the router a TLS handshake, an identify exchange and
a credential verification, and a router at its CPU limit answers them late
enough that members time out and retry, which costs more. Give a router at
least one full core and no CPU limit; on Kubernetes, set a request and
leave the limit off. The testnet runs its routers on 2 vCPU without a
limit, and a fleet of 500 members joining at 20 a second is admitted in
under a minute. The [scalability guide](../../guides/scalability/) sizes
the watermarks and the relay budget for a fleet.

## Metrics

The metrics address exposes, next to the Go runtime metrics:

| Metric | Meaning |
|---|---|
| `agentmesh_router_ready` | `1` once the router is enrolled and the host is up. |
| `agentmesh_router_draining` | `1` from the moment the router starts stopping until the process exits. |
| `agentmesh_router_connections{direction}` | Open connections, `inbound` and `outbound`. |
| `agentmesh_router_connection_watermark{level}` | The `low` and `high` watermarks in force. The gap between `inbound` connections and the `high` watermark is the free capacity. |
| `agentmesh_router_conns_per_source_ip_limit` | The per-address cap in force. |
| `agentmesh_router_relay_limit{limit}` | The relay budget in force: `reservations`, `reservations_per_ip` and `circuits_per_peer`. |
| `agentmesh_router_connected_peers`, `agentmesh_router_authenticated_peers`, `agentmesh_router_banned_peers`, `agentmesh_router_revoked_tokens` | Peers in each state and non-expired authority revocation IDs currently enforced by the router. |
| `agentmesh_router_peer_routers{state}` | Other routers this one knows, from the control plane's list or a handshake that proved the router role: `listed`, and `authenticated` for those it currently holds a mutual authentication with. The two differ while a federation pass is pending or a peer router is down. |
| `agentmesh_router_dht_routing_table_size` | Peer routers in the DHT's routing table: the authenticated peer routers, since nothing else enters it. |
| `agentmesh_router_directory_requests_total{op,result}`, `agentmesh_router_directory_request_seconds{op}` | Directory requests served, by operation (`provide`, `withdraw`, `find_providers`, `find_peer`; `place` is a record or withdrawal another router put here, `lookup` a find another router ran here) and result (`ok`, `empty`, `invalid`, `denied` for a record naming a service the member's credential does not grant serving, `error`), with the time each took. |
| `agentmesh_router_directory_records` | Directory records this router holds: its own members' and the copies placed on it. |
| `agentmesh_router_directory_records_expired_total` | Records dropped because their provider stopped announcing them for the mesh's record TTL. |
| `agentmesh_router_directory_placements_total{result}` | Copies of a member's record, or of its withdrawal, this router placed on the routers closest to the key. |
| `agentmesh_router_directory_lookups_total{result}` | Peer routers asked during a lookup; `error` is one that did not answer in time and was left out of the answer. |
| `agentmesh_router_auth_handshakes_total{result}`, `agentmesh_router_lease_renewals_total{result}` | Handshakes and lease renewals by outcome. |
| `agentmesh_router_goaway_sent_total{reason,result}` | Members sent away, by reason (`DRAINING`, `OVERLOADED`) and outcome: `ok` when the member took the message, `unsupported` when it does not speak the protocol and was closed instead, `failed` when the stream broke. A rising `OVERLOADED` count on a router that is not draining is a fleet that has outgrown its routers. |
| `agentmesh_router_unauthenticated_connections_closed_total` | Connections closed at `--auth-deadline` without a handshake. A member handshakes with a router the moment it connects, so a steady rate is members that cannot complete the handshake, and a burst is a scanner. |
| `agentmesh_router_inbound_connections_refused_total{reason}` | Inbound connections the router refused before the handshake, by reason. `per_ip_limit` is the per-address cap. `rate_limit` is the per-address rate limit on new connections. `scope_limit` is libp2p's connection cap. `scope_limit` also counts a connection refused while more than half that cap are still in TLS or Noise setup. `other` is any other refusal. |
| `agentmesh_router_streams_refused_total{scope,protocol}` | Streams refused, by scope and protocol or service. `scope="unauthenticated"` is a stream from a peer that never passed the handshake, reset when its connection closed; a steady rate is a scanner, or a member whose handshake fails. The other scopes are the resource manager's: a count on `/mesh/kad/1.0.0` or a `/meshsub/*` protocol there is members the router keeps out of discovery; see the scalability guide. |
| `agentmesh_router_busiest_connection_streams{transport}` | The most streams any one connection carries. The connection to a service the router relays for holds one stream per relayed caller, and QUIC admits 256 per connection; see the scalability guide. |
| `agentmesh_router_ingress_requests_total{auth_mode,outcome}`, `agentmesh_router_ingress_request_duration_seconds{auth_mode}` | External HTTP ingress requests served under `/ingress/` (`auth_mode` in `edge`, `passthrough`, `metadata`, `unknown`; `outcome` in `allow`, `unauthenticated`, `forbidden`, `not_found`, `rate_limited`, `unavailable`, `bad_gateway`) and their duration. |
| `libp2p_relaysvc_*` | The relay service's own counters: `reservations_total{type}` and `connections_total{type}` (`opened`, `closed`, `renewed`), requests by response status, rejections and bytes relayed. The difference between `opened` and `closed` is the number in use; read it against `agentmesh_router_relay_limit` to see how close the relay is to its budget. |

A fleet is at capacity when `agentmesh_router_connections{direction="inbound"}`
approaches the `high` watermark or open relay reservations approach
`agentmesh_router_relay_limit{limit="reservations"}` on every router that is not
draining; both are the inputs for an autoscaler. `/healthz` and `/readyz`
on the same address are the probes to use in a pod spec.

`GET /debug/peer?peer_id=<id>` on the same address is the router's view of
one peer: its connectedness, whether it is authenticated here and whether it
is a peer router, its open connections, and the addresses the router holds
for it, which are the ones it hands out in a directory answer. It is a diagnostic
for an operator reading why a member cannot reach another, and its shape is
not versioned.
