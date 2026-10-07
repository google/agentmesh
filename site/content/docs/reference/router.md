---
title: "sam-router"
linkTitle: "sam-router"
weight: 3
---

`sam-router` is a libp2p peer with a stable identity that new nodes connect
to first. It hosts the DHT, relays traffic between nodes that cannot reach
each other, and forwards the control plane's signed events. It has no policy
of its own.

```text
sam-router [flags]
```

## Enrollment

A router enrolls like a node, requesting `sam:role:router`, with one of:

| Flag | Meaning |
|---|---|
| `--jwt-path` | File containing an OIDC token (a projected service account token, for example). |
| `--bootstrap-token-path` | File containing a bootstrap token minted with `"role": "sam:role:router"`. |
| `--oidc-token`, `--bootstrap-token` | The same tokens as values. Visible in process listings. The file forms are preferred. |

The mesh policy must bind the router's identity to `sam:role:router`. The
`sam-mesh` Helm chart handles this: its bootstrap job binds the router's
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
| `--keys-sync-interval` | `5m` | How often `/keys` is polled for signing-key rotations. |
| `--lease-renew-interval` | `300s` | How often the lease is renewed. Must be well below the control plane's `--lease-duration`. |
| `--allow-loopback` | `false` | Announce and accept loopback and link-local addresses. For a router and nodes on one host. |
| `--conns-per-source-ip` | `8` (libp2p default) | Inbound connections accepted per source IP. Raise it behind a TLS-terminating proxy or a NAT that puts many peers on one address. |
| `--low-watermark`, `--high-watermark` | `1000`, `4000` | Connection manager limits. Above the high mark, connections are trimmed down to the low mark. |
| `--dht-provider-addr-ttl` | `15m` | How long a service announcement lives after a node last made it. Nodes re-announce every 5 minutes, so a node that is gone drops out of discovery within this time. `0` keeps the default. |
| `--dht-max-record-age` | library default | DHT value record lifetime. |
| `--relay-limit-duration`, `--relay-limit-data` | `1h`, `0` | Caps on each relayed connection: lifetime, and bytes per direction (`512MiB`, `1GB`). The relay cuts the connection when either is reached. `0` means no limit. |
| `--metrics-addr` | off | Serve `/metrics`, `/healthz` and `/readyz` without authentication on this address. `/readyz` returns `200` once the router is enrolled and the libp2p host is up. Keep this address separate from the libp2p ports and inside the cluster. |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`. `LOG_FORMAT=json` selects JSON output. |

## What it does at run time

1. Fetches `/keys` and enrolls. The credential carries
   `role("sam:role:router")` and the relay right.
2. Starts the libp2p host, the DHT in server mode, the relay service and
   GossipSub.
3. Registers a lease at `POST /routers/lease` with its announced addresses
   and renews it every `--lease-renew-interval`. The control plane lists the
   router on `/info` while the lease is live.
4. Runs the mutual credential handshake on every inbound connection and
   refuses peers whose credential does not verify and peers on the ban list.
5. Refreshes its own credential before it expires, like a node.

A router stores nothing except its key. Restarting a router loses no
important state. Nodes reconnect and publish their services again.

## Metrics

The metrics address exposes `sam_router_connected_peers`,
`sam_router_dht_routing_table_size`, `sam_router_auth_handshakes_total` (by
outcome) and `sam_router_lease_renewals_total` (by outcome), next to the Go
runtime metrics. `/healthz` and `/readyz` on the same address are the probes
to use in a pod spec.
