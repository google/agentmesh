---
title: "Identity and enrollment"
linkTitle: "Identity"
weight: 2
---

Every participant in a mesh, node or router, has a key that it generated
itself and a credential that the control plane issued for that key. Callers
that reach the mesh through a node (workloads, users, and sandboxed agents)
exchange their platform JWTs into delegated credentials bound to that node's
channel, and narrow them offline per task. This page follows credentials from
enrollment and exchange to attenuation, outbound federation, renewal, and
revocation.

## Keys and peer IDs

The first thing a node does is generate an Ed25519 key pair and store it in
its data directory (`~/.config/sam-mesh/agent.db` by default). Its **peer
ID**, the `12D3KooW...` string that appears in logs, discovery results and
proxy URLs, is derived from the public key. The key never leaves the machine.
The credential is bound to the key, so a copied credential is useless without
it, and every peer-to-peer connection proves possession of the key as part
of the libp2p handshake.

`sam-node reset --all` deletes the key and gives the node a new peer ID.
`sam-node reset` without `--all` keeps the key and deletes only the
credential.

## Enrollment

Enrollment is a request to the control plane: "here is my public key, here is
who I am, please issue me a credential for role *X* with labels *Y*". There
are three ways to say who you are.

**Interactive OIDC login.** `sam-node join <control-plane-url>` fetches the
control plane's `/info`, learns which identity provider it trusts, and runs an
OpenID Connect login. If a browser is available, it uses the loopback flow.
On a headless machine it uses the device flow (a URL and a code that you enter
on another device), or falls back to pasting a code. `--auth-mode` selects
one of these explicitly. The ID token from the login is sent to
`POST /register` together with the public key and a signature over a fresh
challenge. This is how a person enrolls a laptop.

**Non-interactive OIDC.** A workload that already has an OIDC token does not
need a login. `sam-node run --jwt-path <file>` enrolls with the token in that
file (such as a Kubernetes projected service account token or a SPIRE
JWT-SVID written by `spiffe-helper`). On GCE and Cloud Run,
`sam-node run --cloud-provider gcp` (or `auto`) fetches an identity token
directly from the instance metadata server. `--client-id` and
`--client-secret-path` do the same with an OAuth client-credentials grant.
Routers enroll in the same way with `sam-router --jwt-path`. The control
plane marks workload issuers with `--workload-issuer` (`<issuer>` or
`<issuer>=<email-suffix>`) so workload tokens can enroll, refresh, and
exchange credentials while being refused at human operator endpoints
(`/user/*`, `/oauth/authorize`).

**Bootstrap token.** An operator mints a token with the admin API, the
console, or `sam-one token create`, and copies it to the machine. The node
sends it to `POST /enroll`. Unless the control plane runs with
`--auto-approve-enrollment`, the request waits in a queue until an
administrator approves it, and the node polls `GET /enroll/status` while it
waits. A token has a role, an expiry and a usage count. A single-use token is
spent as soon as one node is approved with it. This is how machines without
an identity of their own enroll, and how `sam-one` enrolls devices by QR
code.

For all three paths, the control plane checks the same things before it
mints a credential:

1. The peer ID matches the submitted public key, and the challenge signature
   verifies under that key. This proves that the requester holds the key it
   is registering.
2. Neither the peer ID nor the identity behind it is banned.
3. The identity resolves, through the bindings in the mesh policy, to the
   role being requested. `sam-node` requests `sam:role:node` and `sam-router`
   requests `sam:role:router`. If the policy binds nobody to `sam:role:node`,
   no node can enroll.
4. Every label the node declared is permitted by the `allowed_labels` of a
   role it holds. A role without `allowed_labels` permits no labels.

The node stores the credential, the control plane's public key, the control
plane URL and the router addresses it received. From then on it is a member
of that mesh only. If you point it at a different control plane later, it
refuses until you reset it, because a credential is only valid for the mesh
that issued it.

## The credential

Inside the mesh, every credential is a [Biscuit](https://www.biscuitsec.org/),
a signed authorization token. Its authority block (Block 0) holds facts
written in Datalog, a small logic language in which a fact looks like
`role("sam:role:node")`. The authority block is signed by the control plane's
Ed25519 key. Any node with the public key can verify it without contacting
anyone.

The control plane mints two kinds of Biscuits:

### 1. Member Biscuit (`POST /register`, `POST /enroll`, `POST /refresh`)

Issued to an enrolled node, router, or native SDK peer. Its authority block
contains:

| Fact | Meaning |
|---|---|
| `node("12D3KooW...")`, `client_peer_id("12D3KooW...")` | The peer ID the token belongs to. Every verifier checks that the connection it arrived on was authenticated as this peer. |
| `expiration(<time>)` | When the token stops being valid. |
| `role("sam:role:node")`, `role("developer")` | The roles the identity resolved to, one fact each. |
| `user("...")`, `email("...")`, `group("...")`, `idp_role("...")` | Claims copied from the OIDC token: subject, verified email, each group, each entry of the issuer's `roles` claim. Absent for bootstrap enrollments. |
| `label("region", "eu")` | One fact per declared and permitted label. |
| `granted_service_*`, `granted_target_*` | What the roles allow, compiled from `allowed_services` and `allowed_targets`. [Authorization](../authorization/) describes them. |

The node does not set any of these facts. Roles come from the bindings in
the mesh policy, not from the identity provider: an issuer's `roles` claim
is stored as `idp_role()`, which grants nothing by itself. Labels are the
ones the node asked for and the policy allowed. Grants come from the policy.

### 2. Delegated Session Biscuit (`POST /token/exchange`, `/oauth/token`)

When a workload or user calls through an enrolled `sam-node` (or an Envoy /
Istio / `agentgateway` proxy integrated with `sam-node`), the node exchanges
the caller's platform JWT (OIDC ID token, Kubernetes projected SA JWT, or
SPIFFE JWT-SVID) at `POST /token/exchange` on the control plane. The control
plane verifies the node's credential and proof-of-possession signature,
validates the caller's `subject_token`, resolves the caller's roles against
the mesh policy, and mints a short-lived Delegated Session Biscuit with zero
database writes:

- `client_peer_id("12D3KooW...")` and `actor_node("12D3KooW...")` bind the
  token to the origin node's transport channel so only that node can present
  it over libp2p, and record the acting node for audit logs and outbound STS.
- **No `node()` fact is minted**, so `node:<peer_id>` bindings on the origin
  node never leak to the delegated caller.
- `user("...")`, `email("...")`, `group("...")`, `idp_role("...")`, and
  `role("...")` reflect the caller's verified identity and resolved roles.

## Task attenuation (`tar_block`) and sealing

Before starting a task or delegating to a sub-agent, any holder (`sam-node`,
an orchestrator via `POST /oauth/token`, or an SDK caller via
`session.attenuate(rule)`) can narrow a Biscuit offline by appending up to 8
blocks.

Each appended block (`block_idx >= 1`) carries zero Datalog rules, zero Datalog
checks, and exactly one fact:

```datalog
tar_block("<base64url-serialized api.TaskAuthorizationRule>")
```

Every verifier decodes the `TaskAuthorizationRule` chain and requires the
request to satisfy both Block 0's standing Datalog policy and every appended
`TaskAuthorizationRule` block (strict intersection across hops). For untrusted
leaf sandboxes, the holder calls `Seal()` (`session.seal()` or `seal=true` on
`POST /oauth/token`), which discards the ephemeral next-block key so no
further blocks can be appended.

## Outbound federation: the control plane as OIDC issuer

External cloud providers do not accept Biscuits, and SAM never forwards a
caller's mesh token to an upstream API. Instead, the control plane acts as a
standard OIDC issuer (`/.well-known/openid-configuration` and `/jwks`, signed
with ES256).

When an egress node serves a destination configured with `oidc_federation` or
`aws_assume_role`, it verifies the caller's Biscuit and `tar_block` chain and
calls `POST /sts/token` on the control plane. The control plane re-verifies
the token and mints a short-lived ES256 border JWT (`sub` = caller principal,
`act.sub` = egress node peer ID, `aud` = destination audience, `sam_roles` =
caller mesh roles, `sam_task` = innermost task name), which the egress node
exchanges at the cloud provider's STS endpoint (such as Google Workload or
Workforce Identity Federation or AWS `AssumeRoleWithWebIdentity`).

## Lifetime and refresh

A Member Biscuit is valid for `--biscuit-ttl`, 24 hours by default (or the
OIDC token's expiry if sooner). Delegated Session Biscuits default to 1 hour
(bounded by the subject JWT's expiry and any `TaskAuthorizationRule.expire_time`).
Nodes and routers check their Member Biscuit every ten minutes, and when less
than a fifth of the lifetime remains they call `POST /refresh` with the
current token and a signature over a fresh challenge. When the member has a
live platform token source (`--jwt-path`, `--cloud-provider`, `--client-id`,
or an SDK `jwtPath` / `jwt` callback), it also sends a fresh platform JWT in
`TokenRefreshRequest.jwt`: the control plane verifies that `iss|sub` matches
the enrolled node record, refreshes the stored claims and session in place,
and re-resolves the identity's roles against the current policy.

Refresh without a fresh platform JWT is bounded by the **session**, which is
a record on the control plane, not a field in the token. A human OIDC session
lasts `--oidc-session-ttl` (90 days by default), and a workload OIDC session
(`--workload-issuer`) lasts `--workload-session-ttl` (48 hours by default). A
bootstrap enrollment has no session expiry. A ban also acts on the session
record.

A node that enrolled interactively with `--offline-access` also keeps an OIDC
refresh token. If its credential expires completely, it uses the refresh
token to obtain a new ID token and re-enrolls under the same peer ID without
any user action.

## Signing keys and rotation

The control plane rotates its Biscuit Ed25519 signing key every
`--key-rotation-interval` (24 hours by default). The previous key stays valid
for `--key-grace-period` (1 hour by default) and is then retired. `GET /keys`
returns the current set of keys, signed by each key in the set. Routers poll
it every `--keys-sync-interval`; nodes fetch it at enrollment and then every
`--control-plane-sync-interval`, together with the ban set, revocation list,
and the mesh policy. A rotation event only brings the next pull forward. Both
accept a new set only if one of its signatures verifies under a key they
already trust. The first key comes from enrollment, and each later key is
vouched for by the key it replaces.

Nobody can verify a credential signed by a retired key, including the
control plane. A node that was offline for a whole grace period therefore
cannot refresh. This is intentional. The grace period is the deadline after
which a machine that went quiet cannot come back unnoticed. How it comes back
depends on how it enrolled:

- An OIDC node with a refresh token re-enrolls on its own.
- A bootstrap node needs an operator to mint a new token and run
  `sam-node join` again (or to restart the router with the new token). The
  node keeps its peer ID. The control plane recognises the approved peer and
  mints a new credential without going through the approval queue.
- A bootstrap node whose record has `autonomous_recovery` set may refresh on
  proof of possession of its key alone. This is off by default, and an
  administrator sets it per token or per node. A node that can always
  recover holds a credential that never expires, and only a ban stops it.

## Revocation

Revocation operates at two levels:

1. **Mesh-wide node, identity, and root-prefix Biscuit revocation:**
   `POST /admin/revoke` with a peer ID (or `sam-one admin ban`, or the console)
   marks the node as banned. Its next refresh is refused and the node daemon
   exits. The control plane publishes banned peer IDs in `/info` and
   `GET /revocations`, together with revoked root Biscuit revocation IDs
   (`RevocationIds()[0]`). Because every offline-attenuated child Biscuit
   shares the root authority block's `RevocationIds()[0]`, revoking the root
   credential invalidates every attenuated task token derived from it across
   the mesh. If the node was enrolled through OIDC, the identity behind it
   (`issuer|subject`) is banned too. `POST /admin/nodes/{peer_id}/unban`
   reverses both bans.
2. **Local task token revocation (`POST /oauth/revoke`):**
   When an orchestrator or sandbox finishes a task before its TTL expires, it
   calls `POST /oauth/revoke` (RFC 7009) on the local `sam-node`, which records
   the leaf token's `RevocationIds()[last]` in its local revocation cache until
   the token's `expire_time`.

A bootstrap token can be revoked before it expires with
`DELETE /admin/bootstrap-tokens/{id}`. The token stays in the list, marked
as revoked, so the record of what it enrolled is kept.

## What a node proves on every connection

The control plane's HTTP API is protected by challenge signatures, because a
peer ID in a request body is otherwise only a claim. On the mesh, the libp2p
secure channel already proves which key is on the other end, so the handshake
between two nodes is simpler. Each side sends its credential. Each side
verifies the other's signature and expiry, checks that the credential's
`node()` fact matches the authenticated peer, and checks the ban and
revocation lists. On per-request streams, the destination node verifies either
the caller's Member Biscuit or a Delegated Session Biscuit whose
`client_peer_id()` matches the authenticated connection peer, and then
evaluates standing Datalog policy and any appended `tar_block` chain.

## See also

- [Headless enrollment](../../guides/headless-enrollment/) for the bootstrap
  token workflow step by step.
- [Agent architecture](../../preview/agent-architecture/) for the two-token
  STS model and task attenuation.
- [Control plane reference](../../reference/control-plane/) for the flags
  and HTTP routes named here.
