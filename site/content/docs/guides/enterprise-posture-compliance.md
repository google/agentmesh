---
title: "Enterprise device posture, boundary isolation, and gateway provenance"
linkTitle: "Enterprise posture & compliance"
weight: 4
---

Enterprise security policies often require more than verifying *who* signed in:
a personal phone, a federated partner account, or an untrusted sandbox can
present a valid OIDC token unless the connectivity plane also enforces
**device trust**, **issuer scoping**, **environment isolation**, **task-scoped
execution**, and **tamper-proof attribution**.

Agent Mesh enforces all of these controls end to end using first-class
IdP-verified `claim(key, value)` Biscuit facts, declarative `PolicyConfig`
rules, standard Biscuit Datalog attenuation, and unforgeable PEP provenance
headers—without coupling the core protocol to any single identity provider
(Okta Device Trust, Microsoft Entra Conditional Access, Chrome Enterprise / IAP,
or SPIFFE/Kubernetes).

For a self-contained, zero-Docker walkthrough that runs every control below
locally against real `agentmesh-one` and `agentmesh-node` binaries, see
[`development/examples/device-posture-isolation/`](https://github.com/google/agentmesh/tree/main/development/examples/device-posture-isolation).

---

## 1. First-class IdP-verified `claim(key, value)` facts

Agent Mesh separates **node-declared metadata** from **IdP-verified identity
and posture assertions** at the Biscuit predicate level:

- `label(key, value)` holds metadata declared by an enrolling node in
  `agentmesh-node.yaml` (such as `region: eu-west-1`), bounded by
  `PolicyRole.allowed_labels`.
- `claim(key, value)` holds claims extracted by the control plane from a
  cryptographically verified OIDC JWT at `POST /register`, `POST /refresh`,
  `POST /token/exchange`, and `POST /oauth/token`.

Because `claim()` and `label()` are distinct predicates, an enrolling node can
**never** spoof a device posture or environment claim by declaring a label—even
when its role grants `allowed_labels: ["*"]`—and no control-plane CLI flags are
needed to configure claim mappings. Everything lives in the versioned
`PolicyConfig` document (`POST /policies`):

1. **Automatic collection from `PolicyBinding.claims`:** Any JWT claim path
   matched in a role binding is extracted and minted as a Block 0
   `claim(key, value)` fact on both Member and Delegated Session Biscuits.
2. **Explicit export via `PolicyConfig.attested_claims`:** Additional JWT claim
   paths (such as `amr` or `iss`) can be listed in `attested_claims` so node
   `attenuation` rules, `X-Mesh-Claims` headers, and outbound `/sts/token`
   border JWTs (`mesh_claims`) can inspect them even when no binding matches
   them directly.
3. **Top-level, nested, and multi-valued claims:** Lookup checks exact top-level
   keys first (supporting `"iss"` and URI claim keys such as
   `https://idp.example/trust_tier`) before traversing dot-separated nested JSON
   objects (such as `device.trust_tier`). Strings, booleans, finite numbers,
   and scalar arrays (such as `amr: ["hwk", "mfa"]`, emitted as one `claim()`
   fact per distinct element) are supported; missing or malformed values are
   omitted so deny-by-default policies fail closed.
4. **Bounded Biscuit size:** A policy may reference at most **16** distinct
   claim paths across `PolicyBinding.claims` and `attested_claims` combined
   (`POST /policies` returns `400` above that cap), and each array-valued claim
   emits at most **16** distinct values (claims exceeding 16 elements are
   omitted fail-closed with a warning).
5. **Continuous re-attestation:** When a node refreshes with a fresh JWT
   (`TokenRefreshRequest.jwt`), `claim()` facts are recomputed from the new
   claims; if a device loses high-trust posture, the refreshed Biscuit drops the
   claim immediately. Updating `attested_claims` via `POST /policies` also takes
   effect at each node's next refresh without restarting the control plane.

---

## 2. Structured `PolicyBinding.claims` and multi-issuer `"iss"` scoping

`PolicyBinding.claims` matches a map of `<jwt_claim_path>: <expected_value>`
with logical AND alongside `PolicyBinding.members`. Multiple bindings may target
the same `role` to express OR-of-AND posture profiles.

In multi-issuer meshes (for example, corporate employees plus a federated
partner IdP), `"iss"` is always matchable in `PolicyBinding.claims` so a
partner token with a matching email or claim cannot satisfy a corporate role:

```json
{
  "attested_claims": ["amr"],
  "roles": [
    {
      "name": "mesh:role:node",
      "allowed_labels": ["region=*"]
    },
    {
      "name": "workstation-remote-caller",
      "allowed_services": ["a2a://dev-agent", "mcp://dev-tools"],
      "allowed_targets": ["email:*@corp.example"]
    },
    {
      "name": "sandbox-workload",
      "allowed_services": ["mcp://approved-saas", "egress://bigquery.googleapis.com"],
      "allowed_targets": ["user:spiffe://corp.example/ns/gateway/*"]
    }
  ],
  "bindings": [
    {
      "role": "mesh:role:node",
      "members": ["email:*@corp.example"],
      "claims": {
        "iss": "https://idp.corp.example",
        "device.trust_tier": "high",
        "device.type": "corp_workstation"
      }
    },
    {
      "role": "mesh:role:node",
      "members": ["email:*@corp.example"],
      "claims": {
        "iss": "https://idp.corp.example",
        "device.trust_tier": "high",
        "device.type": "managed_mobile",
        "device.management": "fully_managed"
      }
    },
    {
      "role": "mesh:role:node",
      "members": ["user:spiffe://corp.example/ns/sandboxes/*"],
      "claims": {
        "iss": "https://spiffe.corp.example",
        "workload.env": "sandbox"
      }
    },
    {
      "role": "workstation-remote-caller",
      "members": ["email:*@corp.example"],
      "claims": {
        "iss": "https://idp.corp.example",
        "device.trust_tier": "high",
        "device.type": "corp_workstation"
      }
    },
    {
      "role": "workstation-remote-caller",
      "members": ["email:*@corp.example"],
      "claims": {
        "iss": "https://idp.corp.example",
        "device.trust_tier": "high",
        "device.type": "managed_mobile",
        "device.management": "fully_managed"
      }
    },
    {
      "role": "sandbox-workload",
      "members": ["user:spiffe://corp.example/ns/sandboxes/*"],
      "claims": {
        "iss": "https://spiffe.corp.example",
        "workload.env": "sandbox"
      }
    }
  ]
}
```

`api.BuildPolicyRules` compiles each binding into standard cross-language
Biscuit Datalog rules distributed over `GET /policies`, so Go, TypeScript, and
Python members evaluate the exact same rule:

```datalog
role("workstation-remote-caller") <- email($v), $v.ends_with("@corp.example"), claim("device.trust_tier", "high"), claim("device.type", "corp_workstation"), claim("iss", "https://idp.corp.example")
```

---

## 3. Node-level defense-in-depth (`agentmesh-node.yaml`)

High-trust endpoints (such as developer workstations or gateway PEPs) can
combine standard Biscuit Datalog `rules`, `checks`, and `policies` over
`claim(key, value)` with task-scope guardrails (`require_task_scope`,
`max_task_ttl`). These constraints are enforced uniformly across libp2p
streams (`/libp2p-http`, `/mesh/mcp`), external router ingress
(`/mesh/ingress/1.0.0`), and Envoy `ext_authz` / `ext_proc`:

```yaml
version: "v1alpha1"
attenuation:
  # Hard deny-first isolation policies evaluated before baseline allow policies.
  policies:
    - 'deny if claim("workload.env", "sandbox");'
    - 'deny if claim("device.type", "unmanaged_mobile");'
    - 'deny if claim("device.type", "byod");'
  # Fail-closed posture and hardware-backed MFA checks evaluated on every call.
  checks:
    - 'check if claim("iss", "https://idp.corp.example");'
    - 'check if claim("amr", "hwk");'
    - 'check if claim("device.trust_tier", "high"), claim("device.type", "corp_workstation") or claim("device.trust_tier", "high"), claim("device.type", "managed_mobile"), claim("device.management", "fully_managed");'
  # Refuse blanket standing credentials; require sealed short-lived tar_block rules.
  require_task_scope: true
  max_task_ttl: 15m

services:
  - type: a2a
    name: dev-agent
    description: "Loopback-only local agent service"
    target_url: "http://127.0.0.1:18090"
    ingress:
      auth_mode: edge
      allow:
        - "email:alice@corp.example"
```

| Field | Behavior |
| :--- | :--- |
| `attenuation.checks` | Standard Biscuit Datalog `check if ...` assertions evaluated fail-closed on every request (including `claim()` disjunctions via `or`). |
| `attenuation.policies` | Standard Biscuit Datalog `deny if ...` / `allow if ...` policies evaluated ahead of baseline mesh grants. |
| `attenuation.require_task_scope` | Rejects unattenuated standing credentials (`len(tar_block) == 0`) on non-local inbound mesh, external ingress, and Envoy gateway requests. |
| `attenuation.max_task_ttl` | Caps remaining effective credential lifetime (minimum of Block 0 expiration and appended `tar_block` expirations) and implies `require_task_scope: true`. |

---

## 4. Tamper-proof attribution & gateway provenance

Every Policy Enforcement Point strips caller-supplied `X-Mesh-*` and `X-Peer-Id`
headers—including Envoy `ext_authz` (`headers_to_remove`) and Envoy `ext_proc`
(`remove_headers`)—and stamps verified attributes from the validated Biscuit:

| Header | Description |
| :--- | :--- |
| `X-Mesh-Principal` | Verified caller subject (`email`, `user`, or `node:<peer_id>`). |
| `X-Mesh-Roles` | Comma-separated verified mesh roles. |
| `X-Mesh-Claims` | Canonical sorted `key=value` attested OIDC claims (for example `amr=hwk,amr=mfa,device.trust_tier=high`). |
| `X-Mesh-Labels` | Canonical sorted `key=value` node-declared labels (for example `region=eu-west-1`). |
| `X-Mesh-Actor-Node` | Verified `actor_node` / `client_peer_id` peer that transported the call. |
| `X-Mesh-Origin` | Unforgeable invocation path: `mesh-remote` (libp2p), `mesh-external-ingress` (router edge), or `mesh-gateway` (Envoy `ext_authz`/`ext_proc`). |
| `X-Mesh-Task` / `X-Mesh-Task-Id` | Innermost `TaskAuthorizationRule` metadata / name. |

Downstream agent harnesses and local adapters can read `X-Mesh-Origin`,
`X-Mesh-Principal`, `X-Mesh-Claims`, and `X-Mesh-Task` to distinguish remote or
gateway invocations from interactive local sessions, attach harness-specific
unattended or source-metadata markers, and emit correlated audit trails. When
`EgressDestination.forward_context` is enabled for an operator inspection chain,
`X-Mesh-Claims`, `X-Mesh-Labels`, and `X-Mesh-Actor-Node` are forwarded
alongside `X-Mesh-Principal`, `X-Mesh-Roles`, and `X-Mesh-Task`. Outbound
`POST /sts/token` ES256 border JWTs carry `mesh_claims` (single string for
single-valued claims, JSON array for multi-valued claims such as `amr`) and
`mesh_labels` so downstream cloud IAM / CEL policies can enforce the same
attested posture.
