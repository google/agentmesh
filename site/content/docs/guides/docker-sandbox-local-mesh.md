---
title: "Docker Sandboxes and a local test mesh"
linkTitle: "Docker Sandboxes journey"
weight: 9
---

This page is the write-up promised in
[#734](https://github.com/google/agentmesh/issues/734) (the Docker Sandboxes
checkbox) and tracked by [#740](https://github.com/google/agentmesh/issues/740).
It documents a real local test mesh, an enrolled publisher, one allowed call,
one refused call, and the diagnostics for both — and then exactly how far the
`agentmesh` kit from
[docker/sbx-kits-contrib#347](https://github.com/docker/sbx-kits-contrib/pull/347)
gets inside a Docker Sandbox, and where the run stops today.

Everything below was run on Windows 11 x64 with Docker Desktop 29.4.1 and the
`sbx` CLI v0.48.0 and v0.49.0-rc3 from
[docker/sbx-releases](https://github.com/docker/sbx-releases), against
`agentmesh-node` v0.1.0. The host-side half is fully reproducible as written.
The sandbox half is blocked in those `sbx` builds; the reproduction, the
registry workarounds that were needed, and the state of the kit build are at
the end. #734 asks for honest reports of what does not work, so the blocked
half is reported in the same detail as the working half.

## Topology

- **The mesh.** `agentmesh-one` on a laptop runs the control plane, a router
  and the console. A Cloudflare quick tunnel gives it an https URL, because
  members on other machines (a sandbox is one) refuse a plaintext control
  plane.
- **The publisher.** `agentmesh-node` beside a small MCP server publishes
  `mcp://notebook-tools` and `mcp://debug-tools`. Both are stdio subprocesses;
  one answers `ping`, the other answers `dbg`.
- **The caller.** A second `agentmesh-node` with no services of its own — the
  role a sandboxed agent would take.
- **The sandbox.** A Docker Sandbox built from the `agentmesh` kit. (See
  [Sandbox status](#docker-sandboxes-status-on-windows); this half stops before
  enrollment in current `sbx` builds.)

The policy below is what makes the journey meaningful: nothing is reachable
until the mesh grants it, and the demo depends on one grant being present and
another being absent.

## The mesh policy, strict from first boot

`agentmesh-one` can seed its policy from a file on first boot. The file used
here grants the catalog to every node (discovery), publish rights for the two
MCP services, and — deliberately — an explicit `allowed_targets`. The explicit
`["*"]` matters; see [finding 1](#what-we-hit-on-the-way).

```json
{
  "roles": [
    {
      "name": "mesh:role:node",
      "allowed_services": ["system://mesh.catalog", "mcp://notebook-tools", "mcp://debug-tools"],
      "allowed_publish": ["mcp://notebook-tools", "mcp://debug-tools"],
      "allowed_targets": ["*"],
      "allowed_labels": ["*"]
    }
  ],
  "bindings": []
}
```

`agentmesh-node` in v0.1.0 enrolls as `mesh:role:node` whatever the token's
own role says, so a bootstrap token for another role is refused at the door
([finding 2](#what-we-hit-on-the-way)); the whole journey therefore uses that
one role, and the boundary between the two services is drawn on the publisher,
in its `agentmesh-node.yaml`:

```yaml
version: "v1alpha1"
labels:
  env: notebook
services:
  - type: mcp
    name: notebook-tools
    description: "Notebook ping tool the sandbox may call"
    command: ["python", "mcp_notebook_server.py", "notebook-tools"]
  - type: mcp
    name: debug-tools
    description: "Notebook debug tool withheld by label"
    command: ["python", "mcp_notebook_server.py", "debug-tools"]
attenuation:
  checks:
    - 'check if label("env", "agent-sbx");'
  policies:
    - 'deny if service("mcp", "debug-tools");'
```

`attenuation.checks` gate every incoming request — including the catalog
fetch that discovery performs ([finding 3](#what-we-hit-on-the-way)). A caller
that has not attested `env=agent-sbx` gets nothing, not even a service list;
a caller that has it reaches `ping` but not `dbg`.

## The journey

1. Start the mesh with the policy and a fixed port, and give it a public URL:

   ```console
   agentmesh-one --data-dir ./one --port 8090 --policy-file ./policy.json \
     --tunnel cloudflare
   ```

   The banner prints the `https://<name>.trycloudflare.com` URL and writes
   the admin and join tokens into `./one`.

2. Mint one single-use token per node. The publisher and the caller each get
   their own, so the spent-once property is exercised twice:

   ```console
   agentmesh-one token create --server http://127.0.0.1:8090 --data-dir ./one \
     --role mesh:role:node --description notebook --max-usages 1 --ttl-hours 24
   ```

   ```
   Token:    mesh-bt-…
   Role:     mesh:role:node
   Expires:  2026-10-19T01:27:59Z
   The plain token is shown only once; store it now.
   ```

3. Enroll and run the publisher; it registers both services on startup:

   ```console
   agentmesh-node run --control-plane http://127.0.0.1:8090 \
     --config ./publisher.yaml \
     --bootstrap-token-path ./publisher.token \
     --data-dir ./publisher --api-token-path ./publisher/api-token
   ```

   ```
   Successfully enrolled via Bootstrap token and joined mesh.
   [ServiceRegistry] Registered and announced SERVICE_TYPE_MCP/notebook-tools
   [ServiceRegistry] Registered and announced SERVICE_TYPE_MCP/debug-tools
   [ServiceRegistry] Successfully registered 2 static services
   Starting MCP server on TCP address 127.0.0.1:8080
   ```

4. Enroll the caller the same way, with `--bind-addr 127.0.0.1:8082` so the
   two local APIs do not collide, and discover the publisher's services:

   ```console
   mcp-client -url http://127.0.0.1:8082/mcp -token-path ./caller/api-token \
     -tool discover_remote_services -args '{"type":"mcp"}'
   ```

   ```json
   [{"peer_id":"12D3KooW…","srv_name":"notebook-tools",
     "srv_description":"Notebook ping tool the sandbox may call"},
    {"peer_id":"12D3KooW…","srv_name":"debug-tools",
     "srv_description":"Notebook debug tool withheld by label"}]
   ```

5. The allowed call — `notebook-tools/ping` over the mesh:

   ```console
   mcp-client -url http://127.0.0.1:8082/mcp -token-path ./caller/api-token \
     -tool call_remote_tool \
     -args '{"peer_id":"12D3KooW…","tool_name":"mcp://notebook-tools/ping","arguments":{"name":"from-caller"}}'
   ```

   ```
   pong-from-caller
   ```

6. The refused call — `debug-tools/dbg`, withheld on the publisher:

   ```console
   mcp-client -url http://127.0.0.1:8082/mcp -token-path ./caller/api-token \
     -tool call_remote_tool \
     -args '{"peer_id":"12D3KooW…","tool_name":"mcp://debug-tools/dbg","arguments":{"kind":"probe"}}'
   ```

   ```
   auth rejected by 12D3KooW…: biscuit: denied by policy
   ```

7. The same call from a node without the `env=agent-sbx` label — refused by
   the publisher's `check`, with the check named to the caller:

   ```
   auth rejected by 12D3KooW…: biscuit: verification failed: failed to verify
   check #2: check if label("env", "agent-sbx")
   ```

## Evidence on the publisher side

`agentmesh-node` audits every authorization decision with the reason. The
three outcomes above appear as:

```json
{"peer_id":"12D3KooWH…","target":"mcp://notebook-tools","decision":"allow","role":"mesh:role:node"}
{"peer_id":"12D3KooWH…","target":"mcp://debug-tools","decision":"deny","reason":"biscuit: denied by policy"}
{"peer_id":"12D3KooWE…","target":"mcp://notebook-tools","decision":"deny","reason":"biscuit: verification failed: failed to verify check #2: check if label(\"env\", \"agent-sbx\")"}
```

Two more diagnostics from the same run, worth keeping as reference:

- A bootstrap token whose role does not match the node's enrollment request
  fails with both sides named:

  ```
  FATAL  Enrollment failed: enrollment failed: requested role "mesh:role:node"
  does not match bootstrap token role "sandbox-agent"
  ```

- A caller that fails the publisher's `check` also fails the **catalog
  fetch** — discovery is not a side channel around authorization:

  ```
  WARN  [Discovery] catalog fetch from 12D3KooW… failed: auth rejected by
  12D3KooW…: biscuit: verification failed: failed to verify check #2:
  check if label("env", "agent-sbx")
  ```

## What we hit on the way

These are behavior differences between the v0.1.0 binaries and the current
documentation; none of them required a code change to work around, but each
cost time to diagnose.

1. **`allowed_targets` must be explicit in v0.1.0.** The
   [policy reference](../reference/policy/) says a role with no
   `allowed_targets` may call any node, and the Datalog vocabulary lists
   `target_unrestricted(true)` as minted "for roles with `allowed_targets:
   ["*"]` or none". With the field absent, v0.1.0 issues credentials without
   that fact, and every inter-node request fails the baseline check
   `check if allow_network_target($fact, $val) or target_unrestricted(true)`.
   Writing `"allowed_targets": ["*"]` restores the documented behavior. This
   is worth an upstream confirmation.

2. **A bootstrap token's role must be `mesh:role:node` for `agentmesh-node`
   v0.1.0.** There is no flag or config key to request another role, so the
   kit's single-use token has to be the default role. (The kit's README is
   consistent with this; the failure mode is quoted above because it is a
   good diagnostic to recognize.)

3. **Local `attenuation.checks` gate discovery too.** A provider-side label
   check applies to the catalog fetch the caller performs during discovery,
   so an unlabelled caller sees an empty service list rather than a listing
   plus a refusal on the call. That is the intended "nothing is reachable by
   default" behavior, but it changes how failures look while debugging.

## Docker Sandboxes: status on Windows

The `agentmesh` kit pairs a sandboxed agent with a mesh node. On this machine:

**What works.**

- The kit **builds** from its v3 source (`agentmesh.yaml`, its Dockerfile and
  the startup hook) with `sbx`, producing a cached artifact
  (`sbx-kit-src:agentmesh-8bdf9ba5b76f`, build time about a minute).
- The sandbox engine **runs**: `sbx run --detach shell` boots a sandbox, and
  `sbx create claude` creates the Claude Code workload standalone; `sbx
  diagnose` reports 13 passed, 0 failed.
- The kit's home on
  [docker/sbx-kits-contrib](https://github.com/docker/sbx-kits-contrib) is the
  **`v3` branch** (the base of #347), not `main`; the OCI artifact
  `docker.io/sbx/agentmesh` is published and current. The `git+…#dir=agentmesh`
  form without a `ref` checks out `main`, where the kit does not exist — pin
  `#ref=v3`.

**What does not work (yet).** Every attempt to compose the built-in `claude`
agent with the mixin — `sbx run claude --kit <kit>`, `sbx create`, `sbx
env run`, `sbx kit add`, and the pinned-reference forms — is refused by the
daemon with:

```
400 Bad Request: kit_artifacts: resolve: the kit set is not coherent:
  - no workload kit in the set; every composition needs exactly one kind: workload base
```

This reproduces identically on `sbx` v0.48.0 and v0.49.0-rc3, with the kit
artifact cached and the composition otherwise healthy. It reads as the
workload half of the kit set not being admitted by the resolver in these
builds; the same error appears for a plain shell sandbox composed with the
mixin, so it is not specific to the Claude kit. Because enrollment happens in
the kit's startup hook, this blocks the sandbox half of this page upstream of
everything documented above.

**Registry pulls needed a workaround on this network.** Tag pulls of
`docker.io/docker/sandbox-kit:3` and `docker.io/sbx/claude:latest` failed
with containerd size-validation errors through the available network path
(`failed size validation: 28566 != 28244`), and the failing pulls could
replace a previously good local copy of the same digest with the truncated
one. Pulling **by digest** succeeded, after which the kit build resolved its
frontend locally. For anyone reproducing on a filtered network: pull
`docker.io/docker/sandbox-kit@sha256:2da64d51eea5598c7439daaad9c62be92956983c61806f1753f708a86cffe11b`
(linux/amd64; the arm64 digest is `sha256:51a9ae9fd93e0a9349621a0f977c1e106facc64958f507e6a8bed168de29c9de`)
first, and give the `sbx` daemon the same upstream proxy the rest of the
machine uses (`sbx settings set proxy`, then `sbx daemon restart`); the
sandbox **egress** policy is separate from that and stays `deny-all` plus the
kit's one control-plane entry.

## What is next

- The moment the composition works in a released `sbx`, the sandbox half of
  this page is mechanical to finish: the kit enrolls with one single-use
  token, carries `labels=env=agent-sbx` through `--kit-args-file`, and the
  same `mcp-client` calls above run from inside the sandbox against its local
  API. Updates will land on
  [#740](https://github.com/google/agentmesh/issues/740).
- The `allowed_targets` difference in [finding 1](#what-we-hit-on-the-way)
  looks like a documentation-versus-code question in v0.1.0 and may want a
  dedicated issue.
