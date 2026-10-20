---
title: "agentmesh-console"
linkTitle: "agentmesh-console"
weight: 8
---

`agentmesh-console` serves the web console, a single-page application that
calls the control plane's admin and user API through this program. It is a
separate program, and a mesh runs without it. `agentmesh-one` embeds it.

```text
agentmesh-console [flags]
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--control-plane` | `http://localhost:8080` | URL of the control plane. The console reads `/info` at start and proxies `/api/*` to this URL. The console does not start when the control plane does not answer. |
| `--admin-token-path` | | File containing the admin token. Can also be set with `AGENTMESH_ADMIN_TOKEN`. The console refuses to start without one. |
| `--bind-addr` | `:8081` | HTTP listen address. |
| `--base-path` | | Path prefix the console is served under, such as `/console`. The console answers under the prefix and at the root, and builds its redirects and cookie path with the prefix. |
| `--external-url` | | Origin that browsers reach the console on, such as `https://console.example`. It sets the OIDC `redirect_uri` and the `Secure` flag of the session cookie. Without it, the console takes both from the `Host` and `X-Forwarded-Proto` headers of each request, which a client controls, and logs a warning at start. |
| `--static-dir` | assets built into the binary | Directory with the frontend files. |
| `--version` | | Print the version and exit. |

## Routes

Every route is also served under `--base-path`.

| Route | Purpose |
|---|---|
| `/api/*` | Proxied to the control plane with the `/api` prefix removed. A request without `Authorization` carries the session cookie's token as the bearer. A request other than `GET`, `HEAD` or `OPTIONS` without `Authorization` is refused with `403` when it comes from another origin. Such a request with an HTML form content type is refused with `415`. |
| `/auth/login`, `/auth/callback`, `/auth/session` | OIDC login with the issuer and client ID that the control plane advertises on `/info`. Not served when the control plane advertises no issuer, or the issuer has no authorization endpoint. |
| `/auth/token` | Exchanges a token pasted into the console, sent as a JSON body `{"token": "..."}`, for the session cookie. |
| `/auth/logout` | Clears the session cookie. |
| `/info` | `{"oidc_enabled": true}` or `false`, for the frontend. |
| any other path | The frontend. An unknown path answers `index.html`. |
