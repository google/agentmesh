---
title: "Multi-Tier Enterprise Guardrails & Quality Gates"
weight: 25
description: "How Developer, Platform, Central Security, Department Leads, Individual End-Users, and Day-2 Ops each enforce their own layer of guardrails on the same mesh."
---

<video controls playsinline preload="metadata" style="width:100%; border-radius:8px; box-shadow:0 4px 20px rgba(0,0,0,0.4); margin-bottom: 1.5rem;">
  <source src="../../../demo-multi-tier-guardrails.mp4" type="video/mp4">
</video>

When every developer and team starts shipping AI agents, organizations hit a governance paradox:

1. **Agent Developers** want 1-command onboarding from a laptop or Cloud Run without waiting weeks for VPC peering, DNS records, or firewall tickets.
2. **Platform & Networking Engineers** want persistent logical service names (`a2a://support.acme`) that survive replica swaps across environments without static proxy limits.
3. **Central Security (CISO)** wants an organization-wide policy floor, automated quality gates before an agent can serve production (`env=staging` $\rightarrow$ `env=prod`), and zero raw API credentials inside agent containers.
4. **Department Leads & Individual End-Users** want to narrow what an agent can do on *their* infrastructure or on *their* behalf—even when the organization's baseline policy allows it.
5. **Day-2 Operations (SRE)** needs a correlated audit trail across every hop and a 1-command kill-switch (`agentmesh-one admin ban`) if a peer misbehaves.

The runnable example in [`development/examples/multi-tier-guardrails/`](https://github.com/google/agentmesh/tree/main/development/examples/multi-tier-guardrails) walks through all five personas in four acts using **real backends** and zero changes to Agent Mesh's core code:

- **Real Local LLM (`gemma3:1b` via Ollama):** Powers the Support A2A replicas (`support_agent.py`) over an OpenAI-compatible `/v1/chat/completions` endpoint.
- **Real A2A 1.0 SDK (`a2a-sdk`):** Both `support_agent.py` (server) and `a2a_client.py` (client) use the official [`a2a-sdk`](https://pypi.org/project/a2a-sdk/) with SQLite-backed conversation history keyed by `contextId`.
- **Real SQLite MCP Server (`orders_mcp.py`):** Built with the official [`mcp`](https://pypi.org/project/mcp/) Python SDK (`MCPServer`), exposing `get_order_status` (read) and `issue_refund` (write) against a SQLite `orders.db` database.
- **Real External API (`egress://api.github.com`):** Connects to `https://api.github.com` with node-side secret brokering (`secrets/github-ro`).

---

## The 5 Personas in One Mesh

| Persona | What They Control in Agent Mesh | Mechanism Used in This Example |
| :--- | :--- | :--- |
| **1. Agent Developer (Alice)** | Onboarding & iterating on `a2a://support.acme` (`support_agent.py`) | Enrolls `agentmesh-node` in `env=staging` quarantine; zero code changes to promote to `env=prod` |
| **2. Platform / Networking** | Service discovery, outbound floor & replica lifecycle | Input-node `egress.require_labels: {env: prod}`, logical URI `a2a://support.acme`, and `contextId` continuity from Laptop (`v1`) to Cloud Run (`v2`) |
| **3. Central Security (CISO)** | Org-wide baseline RBAC, Quality Gate & Secret Brokering | Control-plane `policy.json` (`allowed_labels`, HTTP method/path rules on `egress://api.github.com`, `credential: github-ro`) |
| **4. Department Lead & End-User** | Local team gate + per-task tool narrowing | Egress-node `attenuation` (`check if label("team", "support");`) + RFC 8693 `/oauth/token` minting a sealed Task Biscuit (`tar_block`) |
| **5. Day-2 Operations (SRE)** | Real-time audit correlation & incident response | Structured `ALLOW`/`DENY` audit stream (`audit.py`) + instant mesh-wide revocation (`agentmesh-one admin ban`) |

---

## Understanding Labels in the Demo: The 3 Control Points

When watching Alice configure `labels:` in `node-v1.yaml` or a caller send `X-Mesh-Required-Labels`, a natural question arises: *"Can a developer or agent just set arbitrary labels to influence security policy?"*

No. In Agent Mesh, labels operate at **three distinct points** with clear separation of authority:

1. **Mesh Enforcement (Control Plane `policy.json` $\rightarrow$ `allowed_labels`):**
   A node's YAML file (`labels:`) is only a **request** at enrollment time. The Control Plane validates every requested label against the role's `allowed_labels` in `policy.json` before cryptographically signing `label("k", "v")` facts into the node's authority Biscuit. If Alice tries to self-assert `env: prod` before passing the Quality Gate, enrollment is rejected (`Label not permitted: label "env=prod" is not permitted by this role's allowed_labels`).
2. **Node Enforcement (Input Node `egress.require_labels` & Egress Node `attenuation.checks`):**
   - **Input Node (`node-caller.yaml`):** The Platform Admin sets `egress.require_labels: { env: prod }` on the caller's node. Even if the calling application sends **no** `X-Mesh-Required-Labels` header, the Input Node blocks calls to staging providers (`403 Forbidden`).
   - **Egress / Provider Node (`node-v1.yaml`):** The Support Department Lead configures a positive inbound Datalog check (`check if label("team", "support");`). Any caller whose Biscuit lacks a Control-Plane-signed `label("team", "support")` fact—whether `team=contractor` or carrying no labels at all—is rejected locally by `node-v1`.
3. **End-User / Agent Intent (`X-Mesh-Required-Labels` HTTP Header):**
   Within the mandatory boundaries enforced by the Mesh and the Nodes, the calling application or agent can pass `X-Mesh-Required-Labels` (for example `replica=v1-laptop` or `replica=v2-cloudrun`) to express **intent** about which specific replica or capability it wants from the mesh. The Input Node **ANDs** the caller's intent with its own `egress.require_labels` floor (`env=prod AND replica=v2-cloudrun`), so the application can narrow selection without ever weakening admin policy.

---

## Run It Yourself

```bash
make build
./development/examples/multi-tier-guardrails/run.sh
```

Pass `--interactive` to step through the four acts one `ENTER` at a time during a live presentation:

```bash
./development/examples/multi-tier-guardrails/run.sh --interactive
```

---

## What Happens in Each Act

### Act 1: Developer Onboarding into Quarantine (`env=staging`) & Quality Gate Promotion
*(Personas: Agent Developer Alice + Central Security / Platform)*

Alice starts her `agentmesh-node` fronting `a2a://support.acme` (`support_agent.py` backed by `gemma3:1b`) and `mcp://orders-db` (`orders_mcp.py` backed by SQLite). Her node config (`node-v1.yaml`) declares `env: staging`, and the initial control-plane policy (`policy.json`) only permits `env=staging`.

Right here, the demo shows both **Mesh Enforcement** and **Input Node Enforcement**:
- If Alice tries to join with `env: prod` in her YAML before passing the Quality Gate, the Control Plane rejects enrollment:
  `Label not permitted: label "env=prod" is not permitted by this role's allowed_labels`
- While Alice's node is in `env=staging`, a plain request through the Input Node (`node-caller.yaml`, which enforces `egress.require_labels: { env: prod }`) is blocked even when the app sends no label headers:
  `HTTP 403 — Required labels not attested by provider`

Next, the automated Quality Gate fetches Alice's Agent Card in `env=staging`, verifies that it conforms to the A2A 1.0 schema and declares the expected skills (`order_lookup`, `refund_triage`), and promotes the policy and node to `env=prod`. Retrying the exact same production request now succeeds with `200 OK` and rewrites `supportedInterfaces[0].url` to point at the caller's local Agent Mesh proxy.

---

### Act 2: Persistent Logical Naming, Zero-Downtime Replica Swap & Agent Intent
*(Persona: Platform / Networking)*

Callers address the agent by its logical mesh name (`a2a://support.acme`), never by an ephemeral IP or Cloud Run URL. On top of the Input Node's mandatory `env=prod` floor, the calling application uses `X-Mesh-Required-Labels` (**End-User / Agent Intent**) to select replicas:

1. **Turn 1 (`contextId=ctx-acme-1042`, `X-Mesh-Required-Labels: replica=v1-laptop`):** The caller uses `a2a_client.py` (official `a2a-sdk`) to ask about Order `#1042`, and `gemma3:1b` on Alice's laptop replica (`[v1-laptop · gemma3:1b]`) replies that Alice's Mechanical Keyboard Pro (`$129.00`) has `SHIPPED`.
2. **Replica Scale-Up:** A second node (`node-v2.yaml`, representing a Cloud Run deployment) joins the mesh advertising `a2a://support.acme` with `env=prod, replica=v2-cloudrun`.
3. **Turn 2 (`contextId=ctx-acme-1042`, `X-Mesh-Required-Labels: replica=v2-cloudrun`):** The caller sends the follow-up question with the same `contextId` to the Cloud Run replica (`[v2-cloudrun · gemma3:1b]`), which loads the conversation history from SQLite and answers seamlessly without dropping context.

---

### Act 3: The 3-Tier Guardrail Hierarchy
*(Personas: Central Security, Department Lead, and Individual End-User)*

Agent Mesh enforces the **strict intersection** of three independent guardrail layers:

```
Effective Permission = (Layer 1: Central Security Block 0 Policy)
                     ∩ (Layer 2: Department Egress-Node Label Check)
                     ∩ (Layer 3: Individual User Per-Task Biscuit tar_block)
```

#### Layer 1 — Central Security (Org Baseline & Secret Broker)
In `policy.json`, Central Security assigns `egress://api.github.com` (`https://api.github.com`) to nodes labelled `site=office` with `credential: "github-ro"`, and restricts callers to `GET /repos/google/agentmesh/pulls*`:

* `GET /repos/google/agentmesh/pulls?state=open&per_page=1` $\rightarrow$ **`200 OK`** (the hosting node injects the read-only GitHub token from `secrets/github-ro`; the caller never holds the credential).
* `POST /repos/google/agentmesh/pulls` $\rightarrow$ **`403 Forbidden`** (blocked by the Block 0 HTTP rule before GitHub ever receives the request).

#### Layer 2 — Department Lead (Egress-Node Positive Label Enforcement)
Central Security's org-wide policy allows `mesh:role:node` to reach `mcp://orders-db`. However, the Support Department Lead adds a local positive label check in `node-v1.yaml`:

```yaml
attenuation:
  checks:
    - 'check if label("team", "support");'
```

When a contractor node enrolled with attested label `team=contractor` attempts to call `mcp://orders-db/get_order_status`, Alice's node rejects the request locally because the caller's Biscuit does not carry a Control-Plane-signed `label("team", "support")` fact:

```text
MCP tool "get_order_status" rejected: biscuit: verification failed: failed to verify check #2: check if label("team", "support")
```

#### Layer 3 — Individual End-User (Per-Task Biscuit `tar_block`)
When a customer asks the agent *"Where is my order #1042?"*, the caller mints a **sealed Task Biscuit** via `POST /oauth/token` (RFC 8693 token exchange) narrowed strictly to `resource=mcp://orders-db` and `scope=tool:get_order_status`:

```bash
curl -s -X POST http://127.0.0.1:19002/oauth/token \
  -H "Authorization: Bearer caller-secret" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "resource=mcp://orders-db" \
  -d "scope=tool:get_order_status" \
  -d "seal=true"
```

Using that narrowed Task Biscuit:
1. Calling `get_order_status(order_id="1042")` against the SQLite MCP server succeeds:
   `Order #1042: status=SHIPPED, item='Mechanical Keyboard Pro', total=$129.00, customer=alice@acme.com`
2. If a prompt injection inside the order notes tricks the agent into calling `issue_refund(order_id="1042", amount_dollars=5000)` using the **same** Task Biscuit, the node's authorizer blocks the tool call mid-flight and leaves the SQLite `refunds` table untouched (`COUNT(*) = 0`):
   ```text
   task authorization denied tool "issue_refund": tar_block[1] ("oauth-task") denied request to mcp://orders-db
   ```

---

### Act 4: Day-2 Operations — Correlated Audit & Instant Kill-Switch
*(Persona: Day-2 Operations / SRE)*

Every `ALLOW` and `DENY` across all three layers is emitted as a structured JSON log event on the hosting node (`audit.py` formats each decision into a single line showing verdict, role, caller PeerID, HTTP method/path or MCP protocol, and target service):

```text
ALLOW mesh:role:node 12D3KooW… GET /.well-known/agent-card.json   a2a://support.acme
ALLOW mesh:role:node 12D3KooW… POST /                             a2a://support.acme
ALLOW mesh:role:node 12D3KooW… GET /repos/google/agentmesh/pulls        egress://api.github.com
DENY  -             12D3KooW… POST /repos/google/agentmesh/pulls       egress://api.github.com
DENY  -             12D3KooW… /mesh/mcp/1.0.0                     mcp://orders-db
ALLOW mesh:role:node 12D3KooW… /mesh/mcp/1.0.0                     mcp://orders-db
```

Finally, if Day-2 Operations detects repeated policy violations from the contractor peer, a single command revokes that peer's identity across the entire mesh:

```bash
./bin/agentmesh-one admin ban <contractor-peer-id> --server $CP_URL --data-dir $WORK_DIR/one
```
