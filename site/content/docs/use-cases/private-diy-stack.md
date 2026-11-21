---
title: "Private DIY Enterprise Stack (On-Prem & Cloud)"
weight: 26
description: "Run a zero-trust AI workforce safely across on-premises infrastructure and cloud by combining self-hosted reasoning (Gemma / DeepSeek), an open-source Agent Harness, and Agent Mesh sidecar networking."
---

<video controls playsinline preload="metadata" style="width:100%; border-radius:8px; box-shadow:0 4px 20px rgba(0,0,0,0.4); margin-bottom: 1.5rem;">
  <source src="../../../demo-private-diy-stack.mp4" type="video/mp4">
</video>

Enterprises adopting AI agents rarely run everything in a single place: sensitive ERP databases and compliance APIs often remain **on-premises**, while agents and elastic GPU reasoning run across **both on-premises servers and Google Cloud** (Cloud Run, GKE, or Compute Engine). Connecting those pieces traditionally forced teams to choose between brittle site-to-site VPNs, opening inbound firewall ports into the data center, or copying raw database credentials into cloud agent containers.

By combining three composable layers, an enterprise can run a **zero-trust AI workforce safely across on-premises infrastructure and cloud** with one cryptographic identity and one Default-Deny policy plane:

| Layer | Role in the Hybrid DIY Stack | Example Technology |
| :--- | :--- | :--- |
| **1. Reasoning (Open-Weights Intelligence)** | Chain-of-thought and tool planning on Cloud Run GPU, GKE, or on-prem GPUs | **Gemma 3** / **DeepSeek-R1** via Ollama or vLLM (`inference://private-llm`) |
| **2. Orchestration (Open Harness)** | ReAct loop, context management, and task execution without hardcoded tool logic or network routes | **Harness²** / custom Python MCP Harness (`agent_harness.py`) |
| **3. Networking & Policy (Agent Mesh)** | Cryptographic Biscuit identities across on-prem and cloud, Default-Deny service routing, secret brokering, and per-task `tar_block` guardrails | **`agentmesh-one`** (control plane + router) & **`agentmesh-node`** sidecars |

The runnable end-to-end implementation lives in [`development/examples/private-diy-stack/`](https://github.com/google/agentmesh/tree/main/development/examples/private-diy-stack).

---

## How Agent Mesh Connects On-Premises and Cloud Safely

```
┌─────────────────────────────────────────┐       ┌──────────────────────────────────────────┐
│  Agent Zone: Cloud Run / Workstation    │       │  Control Plane & Router (agentmesh-one)  │
│  (dept=finance)                         │       │  Issues Biscuit credentials & distributes│
│  ┌───────────────────────────────────┐  │       │  compiled Datalog RBAC policy.json       │
│  │ Self-Hosted Agent Harness         │  │       └────────────────────┬─────────────────────┘
│  │ (Zero DB creds, zero network code)│  │                            │
│  └─────────┬───────────────┬─────────┘  │                            │
│            │ 127.0.0.1     │ 127.0.0.1  │                            ▼
│            │ :19101/mcp    │ :19101/v1  │       ┌──────────────────────────────────────────┐
│            ▼               ▼            │       │  GPU Zone: Cloud / On-Prem GPU Pool      │
│  ┌───────────────────────────────────┐  │ mTLS  │  ┌────────────────────────────────────┐  │
│  │ agentmesh-node (node-agent.yaml)  ├──┼──────►│  │ agentmesh-node (node-inference)    │  │
│  │ Mint sealed task Biscuits (RFC8693│  │ +     │  │ check if label("residency",...)    │  │
│  └─────────────────┬─────────────────┘  │Biscuit│  └─────────────────┬──────────────────┘  │
└────────────────────┼────────────────────┘       │                    │ 127.0.0.1:18892     │
                     │                            │                    ▼                     │
                     │ mTLS + Biscuit             │  ┌────────────────────────────────────┐  │
                     │ (/mesh/mcp/1.0.0)          │  │ Gemma 3 / DeepSeek-R1 (Ollama/vLLM)│  │
                     ▼                            │  └────────────────────────────────────┘  │
┌─────────────────────────────────────────┐       └──────────────────────────────────────────┘
│  On-Prem Vault Zone (zone=vault)        │
│  ┌───────────────────────────────────┐  │
│  │ agentmesh-node (node-tools.yaml)  │  │
│  │ • Publishes mcp://erp-db          │  │
│  │ • Publishes mcp://payroll-vault   │  │
│  │ • Serves egress://compliance...   │  │
│  │ • Enforces tar_block + Datalog    │  │
│  └─────────┬───────────────┬─────────┘  │
│            │               │ Injects    │
│  127.0.0.1 │               │ Vault Key  │
│  :18890    ▼               ▼ :18891     │
│  ┌──────────────────┐ ┌──────────────┐  │
│  │ On-Prem ERP &    │ │ Internal     │  │
│  │ Payroll SQLite   │ │ Compliance   │  │
│  │ MCP Servers      │ │ REST API     │  │
│  └──────────────────┘ └──────────────┘  │
└─────────────────────────────────────────┘
```

### 1. The "Sidecar" Node Architecture

Instead of hardcoding database drivers, API keys, or service IP addresses into your agent code—or opening inbound firewall holes into your on-premises network—Agent Mesh deploys an `agentmesh-node` sidecar next to each workload:

* **For the Agent (`node-agent.yaml` in Cloud Run, GKE, or Workstation):** The sidecar exposes the authorized mesh to your local agent as a loopback **Model Context Protocol (MCP)** server (`http://127.0.0.1:19101/mcp`) and a loopback **OpenAI-compatible inference endpoint** (`http://127.0.0.1:19101/v1`). The agent harness does not know whether a tool or model is running in Google Cloud or in an on-premises vault; it simply queries its local MCP server (`find_remote_tools`, `describe_remote_tool`, `call_remote_tool`) and sends chat completions to `127.0.0.1:19101/v1/chat/completions`.
* **For the Reasoning Engine (`node-inference.yaml` on Cloud GPU or On-Prem GPU):** A sidecar next to the GPU server publishes `inference://private-llm` backed by Ollama or vLLM (`deepseek-r1:1.5b` / `gemma3`) and verifies the caller's Biscuit attributes before serving completions.
* **For the Private Tools (`node-tools.yaml` in the On-Prem Vault):** A sidecar in the on-premises vault zone dials out to the mesh and registers private enterprise databases (`mcp://erp-db`, `mcp://payroll-vault`) and internal REST APIs (`egress://compliance.internal`). Raw API credentials (`secrets/compliance-api-key`) remain on the vault node and are injected at the egress boundary—never transmitted to the cloud or placed inside the agent container.

```yaml
# development/examples/private-diy-stack/node-tools.yaml
version: "v1alpha1"

labels:
  residency: on-prem
  zone: vault
  dept: finance

attenuation:
  checks:
    - 'check if label("residency", "on-prem");'
    - 'check if label("dept", "finance");'

services:
  - type: mcp
    name: erp-db
    description: "Private Enterprise ERP SQLite Database (Invoices, Inventory, Wire Transfers)"
    target_url: "http://127.0.0.1:18890/mcp"
    protocol: "streamable-http"
  - type: mcp
    name: payroll-vault
    description: "Restricted Executive Payroll Database (Default-Deny test target)"
    target_url: "http://127.0.0.1:18890/payroll-mcp"
    protocol: "streamable-http"
```

### 2. Zero Trust Identity & Default-Deny Policy

When you build a private agent network, you cannot let an LLM roam free across the corporate LAN. `agentmesh-control-plane` (`agentmesh-one`) issues short-lived cryptographic **Biscuit** credentials to every node and distributes compiled Datalog RBAC policy across the mesh:

1. **Default-Deny on Service Names:** Nothing is reachable by default. An agent cannot dial an arbitrary IP address; it can only invoke a logical service name (`mcp://erp-db`, `inference://private-llm`, `egress://compliance.internal`) that the control plane's [`policy.json`](https://github.com/google/agentmesh/blob/main/development/examples/private-diy-stack/policy.json) explicitly grants. Even though `mcp://payroll-vault` runs on the exact same vault sidecar as `mcp://erp-db`, calls to `mcp://payroll-vault` are rejected at the Biscuit authorizer (`biscuit: denied by no matching policies`).
2. **HTTP Method & Path Guardrails on Internal APIs:** `policy.json` restricts `egress://compliance.internal` to `GET /v1/vendors/*`. Any attempt by the agent to mutate compliance records via `POST` is rejected with `HTTP 403`.
3. **Data Residency & Department Labels:** Both the control plane and the node-local Datalog policy verify caller attributes (`residency=on-prem`, `dept=finance`). A node enrolled in `dept=external` is cryptographically blocked from calling `mcp://erp-db`.
4. **Per-Task Sealed Biscuits (`tar_block`):** Before executing an untrusted user prompt, the harness calls its local sidecar's RFC 8693 `/oauth/token` endpoint to append and seal a `TaskAuthorizationRule` (`tar_block`) onto its Biscuit, narrowing authority to read-only tools (`lookup_invoice`, `check_inventory`). If a prompt injection tricks the LLM into calling `execute_wire_transfer`, the vault node's Biscuit verifier rejects the call before it ever reaches SQLite.

---

## Running the 4-Act Demo Locally

The example requires zero external Python packages (`stdlib` only) and runs locally in ~12 seconds. If you have a local or Cloud Run Ollama/vLLM server running, pass `USE_LIVE_OLLAMA=1` to route `inference://private-llm` to your live GPU model.

```bash
# Default CLI run (uses built-in deterministic deepseek-r1:1.5b engine)
make -C development/examples/private-diy-stack run

# Launch the interactive browser workbench on http://127.0.0.1:18899
make -C development/examples/private-diy-stack ui

# Or connect to a live Ollama / vLLM instance:
USE_LIVE_OLLAMA=1 OLLAMA_MODEL=deepseek-r1:8b \
  make -C development/examples/private-diy-stack ui
```

### Act 1: Sidecar Enrollment & P2P Service Discovery

`run.sh` starts the private SQLite ERP/Payroll MCP server, the internal Compliance API, the OpenAI-compatible reasoning backend, the `agentmesh-one` control plane, and three `agentmesh-node` sidecars (`node-tools`, `node-inference`, `node-agent`). Over Kademlia DHT and GossipSub, the agent's local sidecar discovers both peers automatically:

```text
--> Enrolling 3 independent agentmesh-node sidecars into the private mesh:
    1. Vault Tool Sidecar      (node-tools.yaml)     -> publishes mcp://erp-db, mcp://payroll-vault & egress://compliance.internal
    2. GPU Reasoning Sidecar   (node-inference.yaml) -> publishes inference://private-llm (deepseek-r1:1.5b)
    3. Agent Harness Sidecar   (node-agent.yaml)     -> exposes 127.0.0.1:19101/mcp and 127.0.0.1:19101/v1 to the local agent

    Discovered via Kademlia DHT / GossipSub from Agent's local sidecar:
      • Vault Tool Node PeerID      : 12D3KooWSKdz7xN3SEyx4coAo8mwRoqceeUNKcTpnCfSX8GkeSaF (mcp://erp-db, egress://compliance.internal)
      • Bare-Metal GPU Node PeerID  : 12D3KooWJnonWvLLU4vn2dRPrAZ59qr4JuQwBXF3CHFgxuANUCuo (inference://private-llm -> deepseek-r1:1.5b)
```

### Act 2: End-to-End Private Agent Execution

`agent_harness.py` connects **only** to `http://127.0.0.1:19101/mcp` and `http://127.0.0.1:19101/v1`. It discovers the remote ERP tools, asks `deepseek-r1:1.5b` (routed over the mesh to `node-inference`) for a tool plan, queries the SQLite ERP database and the internal Compliance API (where `node-tools` injects `secrets/compliance-api-key`), and synthesizes the final audit decision:

```text
--> Running self-hosted agent_harness.py (talks ONLY to 127.0.0.1:19101/mcp and /v1):
    [Harness] Task: "Audit Invoice INV-2026-089 for Acme Robotics, verify SKU-GPU-H200 warehouse stock, and check vendor ACME-01 compliance."
    [Harness] Step 1 -> Asking local MCP server (http://127.0.0.1:19101/mcp) for remote tools on the mesh...
              Discovered 3 tools on Vault Peer 12D3KooWSKdz7xN3…: mcp://erp-db/lookup_invoice, mcp://erp-db/check_inventory, mcp://erp-db/execute_wire_transfer
              Inspected schema for mcp://erp-db/lookup_invoice (required=['invoice_id'])
    [Harness] Step 2 -> Consulting self-hosted reasoning model (deepseek-r1:1.5b) via http://127.0.0.1:19101/v1/chat/completions...
              <think>
              The user wants to audit Invoice INV-2026-089, verify warehouse stock for SKU-GPU-H200, and check vendor ACME-01 compliance. Looking at the local Agent Mesh MCP catalog, I should invoke mcp://erp-db/lookup_invoice and mcp://erp-db/check_inventory, then query egress://compliance.internal/v1/vendors/ACME-01.
              </think>
    [Harness] Step 3 -> Executing tool calls & internal API checks through local sidecar...
              [mcp://erp-db/lookup_invoice]  -> Invoice INV-2026-089: vendor=Acme Robotics GmbH (ACME-01), sku=SKU-GPU-H200, qty=4, amount=$48,500.00, status=PENDING_APPROVAL
              [mcp://erp-db/check_inventory] -> SKU SKU-GPU-H200 (NVIDIA H200 Bare-Metal Server Blade): on_hand=14 units, warehouse=Munich-Vault-B
              [egress://compliance.internal] -> vendor=Acme Robotics GmbH, sanctions=PASSED, iso27001=True (brokered secret verified=True)
    [Harness] Step 4 -> Sending tool observations back to deepseek-r1:1.5b for final synthesis...
              AUDIT DECISION: APPROVED_FOR_RECEIVING — Invoice INV-2026-089 ($48,500.00, 4x SKU-GPU-H200) matches Munich-Vault-B inventory (14 on hand) and vendor ACME-01 is compliance-verified.
```

### Act 3: Zero-Trust Policy Enforcement & Task-Scoped Attenuation

Act 3 proves that an LLM or compromised harness cannot bypass enterprise guardrails:

1. **3a. Unpermitted Service Name (`mcp://payroll-vault`):** Denied by control-plane Datalog policy (`biscuit: denied by no matching policies`).
2. **3b. Unpermitted HTTP Mutation (`POST /v1/vendors/ACME-01`):** Denied with `HTTP 403`.
3. **3c. Cross-Department Call (`dept=external` $\rightarrow$ `mcp://erp-db`):** Denied by the Vault node's local Datalog check (`failed to verify check #3: check if label("dept", "finance")`).
4. **3d. Prompt-Injected Wire Transfer (`execute_wire_transfer`):** Blocked by the sealed `tar_block` on the task Biscuit while `lookup_invoice` continues to succeed:

```text
--> [3d. Per-Task Sealed Biscuit (tar_block) — Blocking Prompt-Injected Wire Transfers]
    Minting a sealed Task Biscuit via RFC 8693 POST /oauth/token narrowed to read-only tools:
      1. Allowed read tool (lookup_invoice)          -> Invoice INV-2026-089: vendor=Acme Robotics GmbH (ACME-01), sku=SKU-GPU-H200, qty=4, amount=$48,500.00, status=PENDING_APPROVAL
      2. Prompt-injected tool (execute_wire_transfer) -> failed to call tool mcp://erp-db/execute_wire_transfer: calling "tools/call": task authorization denied tool "execute_wire_transfer": tar_block[1] ("oauth-task") denied request to mcp://erp-db
      3. SQLite wire_transfers table row count        -> 0 (database untouched!)
```

### Act 4: Correlated Audit Trail & Mesh-Wide Revocation

Every `ALLOW` and `DENY` decision across the GPU and Vault sidecars is emitted as structured JSON (`Audit Traceability`) and summarized by `audit.py`, followed by an immediate mesh-wide ban of the unauthorized external peer via `POST /admin/ban`:

```text
--> Correlated ALLOW / DENY decisions across GPU and Vault Sidecars (audit.py):
    ALLOW mesh:role:node 12D3KooWDTg5… POST /v1/chat/completions          inference://private-llm
    ALLOW mesh:role:node 12D3KooWDTg5… /mesh/mcp/1.0.0                    mcp://erp-db
    ALLOW mesh:role:node 12D3KooWDTg5… GET /v1/vendors/ACME-01            egress://compliance.internal
    DENY  - 12D3KooWDTg5…        /mesh/mcp/1.0.0                    mcp://payroll-vault
    DENY  - 12D3KooWDTg5…        POST /v1/vendors/ACME-01           egress://compliance.internal
    DENY  - 12D3KooWGZN8…        /mesh/mcp/1.0.0                    mcp://erp-db
    DENY  tar_block (oauth-task)     tools/call execute_wire_transfer   mcp://erp-db

--> Revoking unauthorized external node (12D3KooWGZN8uKXSgD2ASM4B7CgbzEQZ6kJUUediHEMVaT7nFsEH) mesh-wide via agentmesh-one admin ban:
    Peer 12D3KooWGZN8uKXSgD2ASM4B7CgbzEQZ6kJUUediHEMVaT7nFsEH banned
```
