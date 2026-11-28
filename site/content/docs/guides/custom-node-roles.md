---
title: "Granting custom access roles to a node"
linkTitle: "Custom node roles"
weight: 3
aliases:
  - /docs/guides/custom-access-roles/
---

In Agent Mesh, the word "role" is used across two distinct architectural layers:
**component roles** and **access roles**. Confusing the two is a common source
of enrollment and authorization issues.

This guide clarifies the distinction between component roles and access roles,
explains why bootstrap tokens only enroll component identities, and walks
through a step-by-step recipe to enroll a node and grant it a custom access role
via policy bindings.

## Component roles vs. access roles

Agent Mesh enforces a strict two-layer role model:

| Layer | Roles | Purpose | Lifecycle |
|---|---|---|---|
| **Component roles** | `mesh:role:node`, `mesh:role:router` | Identify the infrastructure binary type. A router must hold `mesh:role:router` before the control plane grants it a lease and peers trust it to relay traffic. A node must hold `mesh:role:node` before peers admit it as an enrolled mesh member. | Fixed at enrollment. Baked into the node's Biscuit credential (`role("mesh:role:node")`). Stays fixed for the life of the enrollment so a configuration mistake can never accidentally promote a node into a router. |
| **Access roles** | Custom names such as `caller`, `developer`, `analyst` | Describe what services a node or user may call (`allowed_services`), serve (`allowed_publish`), or expose on ingress (`allowed_ingress`), and which targets they may reach (`allowed_targets`). | Dynamic. Attached through policy bindings (`user:`, `group:`, `email:`, or `node:<peer-id>`). Take effect live via `POST /policies` without re-enrolling or restarting binaries. |

### Why bootstrap tokens enroll component identities only

When an operator runs:

```bash
agentmesh-one token create --role caller   # Do not do this for enrollment!
```

`agentmesh-one` or `POST /admin/bootstrap-tokens` generates a bootstrap token
carrying `role: "caller"`. However, when you pass that token to `agentmesh-node`:

```bash
agentmesh-node join https://mesh.example.com --bootstrap-token-path ./tok
```

The enrollment fails with an error:

```text
enrolled biscuit token lacks required role "mesh:role:node"
```

This is by design: `agentmesh-node` always requests `mesh:role:node`
(`RequiredRole: api.RoleNode`), and the control plane requires the requested role
to match the bootstrap token's role. A bootstrap token is strictly a mechanism to
enroll a component identity (`mesh:role:node` or `mesh:role:router`), not to grant
application-level access roles.

To give a bootstrap-enrolled node a custom access role, you enroll the node with
`mesh:role:node`, get its PeerID, and bind the custom role to `node:<peer-id>`
in the mesh policy.

---

## Step-by-step recipe

### 1. Create a node bootstrap token

Mint a bootstrap token with the component role `mesh:role:node`.

Using `agentmesh-one`:

```bash
agentmesh-one token create --role mesh:role:node --description "worker-node-1" > node-token
```

Or using the control plane admin API with `$AGENTMESH_ADMIN_TOKEN`:

```bash
curl -fsS -X POST https://mesh.example.com/admin/bootstrap-tokens \
  -H "Authorization: Bearer $AGENTMESH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"mesh:role:node","ttl_hours":24,"max_usages":1,"description":"worker-node-1"}' \
  | jq -r .token > node-token
```

(The same action is available in the web console under **Bootstrap Tokens** $\rightarrow$
**+ New Token** by selecting the **Node** role.)

Save the token to a file on the target machine (here `./node-token`). Reading
the token from a file prevents credentials from lingering in shell history or
process tables (`ps`).

### 2. Enroll and start `agentmesh-node`

Enroll the node into a dedicated data directory (`./n1`):

```bash
agentmesh-node join https://mesh.example.com \
  --bootstrap-token-path ./node-token \
  --data-dir ./n1
```

Once joined, start the node:

```bash
agentmesh-node run \
  --control-plane https://mesh.example.com \
  --data-dir ./n1 \
  --bind-addr 127.0.0.1:8080 \
  --api-token-path ./n1/api-token
```

The node stores its cryptographic key and enrolled credential in
`<data-dir>/agent.db`. The bootstrap token file is no longer needed after
enrollment (though keeping `--bootstrap-token-path` configured allows autonomous
re-enrollment if the control plane database is ever recreated).

### 3. Obtain the node's PeerID

Every node has a unique **PeerID** (a string starting with `12D3KooW...`) derived
from its Ed25519 public key. You need this PeerID to bind policies to this
specific node.

You can obtain the PeerID in any of three ways:

1. **From startup logs**: When `agentmesh-node run` starts, it prints:
   ```text
   Agent Mesh Node Online.
   PeerID: 12D3KooWFaBcD1234567890abcdefghijklmnopqrstuv
   Listening on: [/ip4/127.0.0.1/tcp/5002 ...]
   ```

2. **Via the debug CLI**: Using the node's local Unix socket:
   ```bash
   agentmesh-node debug mesh-info --socket-path ./n1/agentmesh.sock
   ```

3. **Via the local HTTP API**: Querying the `/debug/mesh-info` route over TCP
   with the node's API token:
   ```bash
   curl -s -H "Authorization: Bearer $(cat ./n1/api-token)" http://127.0.0.1:8080/debug/mesh-info | jq -r .peer_id
   ```

> [!NOTE]
> `/mesh/identity` answers only over the Unix socket or mTLS (it rejects plain
> TCP to protect credentials from untrusted local clients). For general PeerID
> queries, `/debug/mesh-info` is available over both the Unix socket and
> authenticated TCP.

### 4. Grant the custom access role through policy bindings

Fetch the current mesh policy using `GET /admin/policy` with the admin token:

```bash
curl -fsS https://mesh.example.com/admin/policy \
  -H "Authorization: Bearer $AGENTMESH_ADMIN_TOKEN" > policy.json
```

Add your custom access role under `roles` and bind it to the node's PeerID
under `bindings`. For example, to grant a role named `caller` that allows
invoking `mcp://calculator` and any inference model:

```json
{
  "roles": [
    {
      "name": "mesh:role:node",
      "allowed_services": ["system://mesh.catalog"],
      "allowed_publish": ["*"],
      "allowed_labels": ["*"]
    },
    {
      "name": "caller",
      "allowed_services": ["mcp://calculator", "inference://*"],
      "allowed_targets": ["*"]
    }
  ],
  "bindings": [
    {
      "role": "mesh:role:node",
      "members": ["mesh:system:authenticated"]
    },
    {
      "role": "caller",
      "members": ["node:12D3KooWFaBcD1234567890abcdefghijklmnopqrstuv"]
    }
  ]
}
```

Post the updated policy back to `POST /policies`:

```bash
curl -fsS -X POST https://mesh.example.com/policies \
  -H "Authorization: Bearer $AGENTMESH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @policy.json
```

(You can also make this update in the web console under **Policy** by adding the
role and creating a binding with member `node:<peer-id>`.)

### 5. Policy propagation and credential evaluation

- **No node restart is required.** The node continues running without
  interruption.
- **Propagation timing:** The control plane publishes a policy update event over
  gossip. Nodes pull updated policy rules within the sync jitter window:
  up to `ControlPlaneSyncInterval / 10`. With the default 15-minute sync
  interval (`DefaultControlPlaneSyncInterval`), the jitter is **0 to 90
  seconds** (often taking effect within a few seconds on a quiet mesh).
- **Credential roles vs. policy evaluation:**
  A bootstrap-enrolled node's Biscuit credential will **still list only
  `mesh:role:node`**, even after a credential refresh. Inspecting the
  credential via `/mesh/identity` or reading headers like `X-Mesh-Roles`
  will not display `caller`.

  This is expected: for bootstrap nodes, bound custom access roles are not baked
  into the Biscuit authority block. Instead, the control plane compiles the
  binding into distributed Biscuit Datalog rules:
  ```datalog
  role("caller") <- node("12D3KooWFaBcD1234567890abcdefghijklmnopqrstuv")
  granted_service_set("mcp", ["calculator"]) <- role("caller")
  ```
  When the node sends a request, the verifier's Biscuit authorizer evaluates these
  synced rules against the caller's identity fact `node("<peer-id>")`.

  **Effective permissions come from policy evaluation, not merely the roles
  printed in the credential.** Anyone building a "what can this node do" view
  must read effective grants from the policy bindings, not the roles listed in
  the Biscuit.

### 6. Verify allowed and denied calls

Verify that the node can call permitted services and is denied when attempting
unauthorized calls.

Assume another peer on the mesh (`12D3KooWTargetPeer...`) publishes
`mcp://calculator` as well as an administrative tool `mcp://admin-tools`.

#### Test an allowed call

Using the node's MCP client interface to call `call_remote_tool`:

```bash
curl -s --unix-socket ./n1/agentmesh.sock \
  -X POST http://localhost/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "call_remote_tool",
      "arguments": {
        "peer_id": "12D3KooWTargetPeer...",
        "tool_name": "mcp://calculator/add",
        "arguments": {"a": 2, "b": 3}
      }
    }
  }'
```

The call is authorized under the `caller` role and returns the tool output:

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"5"}]}}
```

You can also test the same call via the direct proxy path:

```bash
curl -s --unix-socket ./n1/agentmesh.sock \
  -X POST "http://localhost/mesh/12D3KooWTargetPeer.../mcp/calculator" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

#### Test a denied call

Attempt to invoke a service not permitted by the `caller` role (such as
`mcp://admin-tools`):

```bash
curl -s --unix-socket ./n1/agentmesh.sock \
  -X POST http://localhost/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "call_remote_tool",
      "arguments": {
        "peer_id": "12D3KooWTargetPeer...",
        "tool_name": "mcp://admin-tools/restart",
        "arguments": {}
      }
    }
  }'
```

The request is rejected during policy evaluation, and `call_remote_tool` returns a
tool error indicating that authorization was denied:

```json
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"call failed: request denied by policy"}],"isError":true}}
```

On the HTTP proxy path, an unauthorized request is rejected with `403 Forbidden`:

```bash
curl -si --unix-socket ./n1/agentmesh.sock \
  -X POST "http://localhost/mesh/12D3KooWTargetPeer.../mcp/admin-tools" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

```http
HTTP/1.1 403 Forbidden
Proxy-Status: agentmesh-node; error=http_request_denied
```

---

## Summary

1. **Bootstrap tokens enroll component identities (`mesh:role:node`)**: Never pass custom access roles to `agentmesh-one token create --role` or `agentmesh-node join`.
2. **Access roles are bound via policy**: Use `node:<peer-id>` in `PolicyConfig.bindings` to grant access roles to specific nodes.
3. **No restarts needed**: Policy changes propagate within the sync jitter window (0–90 seconds by default).
4. **Effective permissions come from policy evaluation**: The node's Biscuit continues to list `mesh:role:node`, but requests are authorized by the synced Datalog rules.
