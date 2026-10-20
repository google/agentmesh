---
title: "agentmesh-one"
linkTitle: "agentmesh-one"
aliases:
  - /docs/reference/sam-one/
weight: 4
---

`agentmesh-one` runs a control plane, a router and the web console in one process
on one port. The router's libp2p transport is WebSocket on the same port as
the HTTP API, so a node needs only one `https` URL. The same binary is also
the admin client for a running instance.

```text
agentmesh-one [flags]                              run the mesh
agentmesh-one token create|list|revoke|qr          manage bootstrap tokens on a running instance
agentmesh-one admin ban <peer-id>                  ban a node
```

## Files

Everything lives in `--data-dir` (default `.`): `agentmesh.db` (SQLite), the
router key, `join-token` and `admin-token` when generated, and `bin/` for a
downloaded tunnel connector.

## Server flags

| Flag | Default | Meaning |
|---|---|---|
| `--bind-address` | `0.0.0.0` | Host to bind. |
| `--port` | `0` | TCP port. `0` picks a free one and prints it in the banner. |
| `--external-url` | | Public URL on which nodes reach this instance, for a reverse proxy or a hosted platform. Can also be set with `AGENTMESH_EXTERNAL_URL`. It is the router address members dial and the OIDC issuer the control plane signs with; neither is inferred from request headers. Behind a proxy (Cloud Run, Fly.io, a forwarded Codespaces port) set it, or use `--tunnel`; without it the instance advertises its own listener, logs a warning on the first proxied request and counts them in `agentmesh_one_proxied_requests_without_external_url_total`. |
| `--tunnel` | | Publish the port through a tunnel provider and use the resulting URL as the external URL. Providers: `cloudflare` (a free quick tunnel on `*.trycloudflare.com` by default, no account needed) and `codespaces` (the `https` URL GitHub Codespaces assigns to the forwarded port, read from `CODESPACE_NAME` and `GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN`; nothing is started, and the log reports whether the port answers from the internet). |
| `--tunnel-token-path` | | File containing the tunnel provider authentication token (can also be set with `AGENTMESH_TUNNEL_TOKEN`). Use together with `--tunnel <provider> --external-url https://mesh.example.com` for a permanent custom domain. |
| `--tunnel-install` | `false` | Download the pinned, digest-verified `cloudflared` into `<data-dir>/bin` without asking. Implies acceptance of its license. |
| `--cloudflared-path` | `PATH`, then `<data-dir>/bin` | Explicit connector binary. |
| `--p2p-listen` | none | Extra native libp2p listen addresses, in addition to the WebSocket transport on the main port. |
| `--data-dir` | `.` | See above. On stateless platforms where `router.key` is absent and `AGENTMESH_ADMIN_TOKEN` / `--admin-token-path` is supplied, `router.key` is derived deterministically so the router keeps its PeerID across restarts. |
| `--db-driver` | `sqlite` | `sqlite` or `postgres`. |
| `--db-dsn` | `<data-dir>/agentmesh.db` | Database DSN. |
| `--db-dsn-path` | | File containing the DSN. Overrides `--db-dsn`. Can also be set with `AGENTMESH_DB_DSN`. A PostgreSQL DSN contains a password, so use the file or the variable for PostgreSQL. |
| `--token-path` | | File containing the standing join token. Can also be set with `AGENTMESH_TOKEN`. Generated and saved to the data directory when neither is set. |
| `--no-join-token` | `false` | Run without a standing join token. Devices can then enroll only with minted tokens or OIDC. |
| `--admin-token-path` | | File containing the admin token. Can also be set with `AGENTMESH_ADMIN_TOKEN`. Generated and saved to the data directory when neither is set. |
| `--policy-file` | | Protojson `PolicyConfig` that seeds the mesh policy on first boot. Ignored once the database has a policy. Without it, first boot seeds an open development policy and logs a warning. |
| `--issuer` | | External OIDC issuer(s), comma-separated. Optional. Without an issuer, enrollment works by token only. |
| `--signing-key-path` | | PEM file with operator-owned signing keys (Ed25519 for Biscuits, P-256 for ES256 JWTs; first of each kind signs, later ones verify). Automatic key rotation is off while set; rotate by publishing a new first key and keeping the previous one for the grace period. See the control plane reference. |
| `--workload-issuer` | | Workload OIDC issuer(s), repeatable or comma-separated (`<issuer>` or `<issuer>=<email-suffix>`). Automatically added to `--issuer` and refused at `/user/*` and `/oauth/authorize`. One that does not answer at start-up is resolved in the background and its tokens refused until then (`agentmesh_control_plane_workload_issuer_ready{issuer}`); a `--issuer` that does not answer is fatal. |
| `--oidc-client-id` | first audience | Client ID advertised on `/info`. |
| `--allowed-audiences` | `agentmesh-audience` | Accepted OIDC audiences. |
| `--enroll-qr` | when stdout is a terminal | Print a device-enrollment QR code at startup. Only for `https` URLs. |
| `--enroll-qr-max-usages` | `1` | How many devices the startup QR admits. |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error`. |
| `--log-format` | `text` | `text` or `json`. |

### Embedded component tunables

These flags pass through to the embedded control plane and router. A value
of zero leaves the default of that component unchanged, except where the
row says otherwise.

| Flag | Corresponds to |
|---|---|
| `--control-plane-lease-duration` | `agentmesh-control-plane --lease-duration` |
| `--dht-replication`, `--dht-reprovide-interval` | the same flags of `agentmesh-control-plane`: the mesh's directory parameters, published on `/info`. |
| `--control-plane-key-rotation-interval` | `--key-rotation-interval` |
| `--control-plane-key-grace-period` | `--key-grace-period` |
| `--control-plane-biscuit-ttl` | `--biscuit-ttl` |
| `--control-plane-workload-session-ttl` | `--workload-session-ttl` |
| `--control-plane-node-retention` | `--node-retention` |
| `--control-plane-ephemeral-node-retention` | `--ephemeral-node-retention` |
| `--control-plane-manual-enrollment` | The opposite of `--auto-approve-enrollment`: queue bootstrap enrollments for approval. |
| `--router-control-plane-sync-interval` | `agentmesh-router --control-plane-sync-interval` |
| `--router-low-watermark`, `--router-high-watermark` | `--low-watermark`, `--high-watermark` |
| `--router-conns-per-source-ip` | `--conns-per-source-ip`. `0` follows the high watermark, because peers behind a proxy share source IPs. |
| `--router-relay-limit-duration`, `--router-relay-limit-data` | `--relay-limit-duration`, `--relay-limit-data`. `0` keeps `1h` and no data limit, so set a long duration such as `24h` instead of an unlimited one. |
| `--router-shutdown-lease-ttl` | `--shutdown-lease-ttl`, default `30s`. `0` sends no last lease. |
| `--router-auth-deadline` | `--auth-deadline`, default `1m`. `0` keeps every connection. |
| `--router-allow-loopback` | `--allow-loopback`. Defaults to `true` here, for a laptop. Disable it on a public deployment. |

## The banner

On start, `agentmesh-one` prints the API URL, the console URL, the router's peer
ID, the admin and join tokens, and the `agentmesh-node join` command to use.
Tokens that the operator supplied (through a flag or the environment) are
shown as their source and not as their value, because stdout is often a log.
Tokens that `agentmesh-one` generated are shown in full, because the banner is
where the operator learns them.

## The development policy

With no `--policy-file` and an empty database, first boot seeds three roles,
each with `allowed_services: ["*"]` and `allowed_targets: ["*"]`:
`mesh-admin`, `mesh:role:router`, and `mesh:role:node`, the last one also with
`allowed_labels: ["*"]`. Any enrolled node can then call any service and
declare any label. Replace this policy before sharing the mesh with anyone.

## Admin client

The subcommands talk to a running instance over its HTTP API. Shared flags:

| Flag | Default | Meaning |
|---|---|---|
| `--server` | `http://127.0.0.1:8080` | Base URL of the instance. |
| `--admin-token-path` | | File containing the admin token. Can also be set with `AGENTMESH_ADMIN_TOKEN`, or read from `--data-dir`. |
| `--data-dir` | `.` | Where to find the saved admin token. |

| Command | Flags | Effect |
|---|---|---|
| `token create` | `--role` (`mesh:role:node`), `--ttl-hours` (24), `--max-usages` (1), `--description`, `--autonomous-recovery` | Mint a token. Prints it once on stdout. |
| `token list` | | Tokens with usage count, status (`active`, `exhausted`, `expired`, `revoked`) and expiry. |
| `token revoke <id>` | | Revoke by ID or unambiguous ID prefix. Enrolled devices keep their identity. |
| `token qr` | `--enroll-url`, `--ttl-hours`, `--max-usages`, `--description`, `--autonomous-recovery` | Mint a node token and print `mesh://enroll?server=<url>&token=<token>` as a terminal QR code. The URL must be `https`. |
| `admin ban <peer-id>` | | Ban a node. |

## Platforms

- **A laptop behind NAT**: `--tunnel cloudflare` gives a temporary `https`
  hostname. See [your own mesh](../../getting-started/your-own-mesh/).
- **A GitHub codespace**: `--port 8080 --tunnel codespaces` advertises the
  codespace's forwarded-port URL. The port must be public for devices to
  reach it. See the [Codespaces guide](../../guides/codespaces/).
- **A host with a name**: `--port 8080 --external-url https://mesh.example.com`
  behind a reverse proxy that forwards WebSockets.
- **Cloud Run**: pinned `AGENTMESH_TOKEN` and `AGENTMESH_ADMIN_TOKEN`, one instance, no
  CPU throttling. See the [Cloud Run guide](../../guides/cloud-run/).

`agentmesh-one` is a single process by design. For more than one router, or for a
control plane that scales horizontally, use the separate binaries or the
Helm chart.
