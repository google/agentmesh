# Agent Mesh as a Google Cloud Agent Gateway Service Extension (`EXT_PROC_GRPC`)

This example deploys `agentmesh-node` on Google Cloud Run as an Envoy gRPC v3
**Service Extension** (`AuthzExtension` with `wireFormat: EXT_PROC_GRPC` +
`AuthzPolicy` with `policyProfile: CONTENT_AUTHZ`, `action: CUSTOM`) plugged
directly into **Google Cloud Agent Gateway** — keeping Agent Gateway in the L7
data path for TLS inspection, Agent Registry, Model Armor, and Cloud Logging
while Agent Mesh enforces short-lived, cryptographically sealed
**Task Authorization Rules (`tar_block`)** and verified IdP `claim()` facts.

## What This Qualifies With 100% Real Traffic

A single 10-minute sealed Biscuit minted via RFC 8693 `POST /oauth/token`
grants an isolated agent strictly:

1. **Read-only Git Smart HTTP `git clone`** of `github.com/google/agentmesh.git`
   (`GET /google/agentmesh.git/info/refs` + `POST /google/agentmesh.git/git-upload-pack`),
   while blocking `git push` (`POST /git-receive-pack`), unapproved repositories
   (`kubernetes/kubernetes.git`), and raw `HTTP CONNECT` tunnels with HTTP `403`.
2. **Read-only GitHub MCP tools** (`list_issues`, `issue_read`, `search_issues`)
   against live `https://api.github.com` via `ext_proc` JSON-RPC body inspection
   (with **no** custom `X-Mesh-Target-Service` header required — resolved by
   `:authority` + path), stripping spoofed `X-Mesh-*` / `X-Peer-Id` headers and
   blocking all mutating tools (`issue_write`, `create_pull_request`,
   `push_files`, `delete_repository`) with HTTP `403` before reaching the backend.
3. **Fail-closed task scoping:** standing unattenuated Biscuits (no `tar_block`)
   and expired mandates (> 15m `max_task_ttl`) are rejected with HTTP `403`.

## Two Topologies Included

| Topology | Script | Data Path | Best For |
| :--- | :--- | :--- | :--- |
| **A: Managed Agent Gateway (`AGENT_TO_ANYWHERE`)** | [`deploy_managed_agw.sh`](deploy_managed_agw.sh) + [`agent_runtime/deploy_agent.py`](agent_runtime/deploy_agent.py) | Vertex AI Agent Runtime (`AGENT_IDENTITY`) → Managed `AgentGateway` → `AuthzExtension` (`EXT_PROC_GRPC`) → `agentmesh-node` on Cloud Run → live `github.com` & `github-mcp-live` | Exact Google Cloud Agent Gateway product architecture |
| **B: Edge Agent Gateway (External ALB Fallback)** | [`deploy_edge_alb.sh`](deploy_edge_alb.sh) + [`verify_edge_alb.sh`](verify_edge_alb.sh) | Any HTTPS/HTTP client (workstation, CI runner, sandbox) → Regional External ALB (`EXTERNAL_MANAGED`) → `AuthzExtension` (`EXT_PROC_GRPC`) → `agentmesh-node` on Cloud Run → live `github.com` & `github-mcp-live` | Fast end-to-end real `git clone`/`git push` + live MCP verification from any terminal |

## Prerequisites

- A Google Cloud project with billing enabled where you have IAM permissions
  to enable APIs and manage Cloud Run, Service Extensions, and Agent Gateway.
- `gcloud` CLI (`>= 588.0.0`) authenticated with `gcloud auth login` and
  `gcloud auth application-default login`.
- `curl`, `jq`, `git`, and `python3`.

## Quickstart — Topology B (Edge ALB, ~5 minutes)

```bash
export PROJECT_ID="<your-gcp-project-id>"
export REGION="us-central1"

chmod +x deploy_edge_alb.sh verify_edge_alb.sh cleanup.sh
./deploy_edge_alb.sh

# Wait ~60s for AuthzPolicy propagation, then run all 7 live probes (including real git clone):
./verify_edge_alb.sh
```

## Quickstart — Topology A (Managed Agent Gateway + Vertex AI Agent Runtime)

```bash
export PROJECT_ID="<your-gcp-project-id>"
export REGION="us-central1"

chmod +x deploy_managed_agw.sh
./deploy_managed_agw.sh

# Deploy and invoke the Vertex AI Agent Runtime ADK qualification agent:
python3 -m venv /tmp/agw-venv
/tmp/agw-venv/bin/pip install -r agent_runtime/requirements.txt
PROJECT_ID="${PROJECT_ID}" REGION="${REGION}" AGW_NAME="agentmesh-egress-gw" \
  PEP_URL="$(gcloud run services describe agentmesh-agw-pep --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')" \
  MCP_URL="$(gcloud run services describe agentmesh-github-mcp-live --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')" \
  /tmp/agw-venv/bin/python agent_runtime/deploy_agent.py
```

### Production Hardening Notes

- **Lock down `ALLOWED_AUDIENCE` and `ALLOWED_MEMBER`:** The sandbox scripts
  include gcloud's default client ID in `ALLOWED_AUDIENCE` so
  `gcloud auth print-identity-token` works immediately from a developer
  terminal. In production, set `ALLOWED_AUDIENCE` strictly to your dedicated
  workload audience and narrow `ALLOWED_MEMBER` to your agent service account
  or principal prefix.
- **Brokered GitHub credentials:** Mount a Secret Manager read-only GitHub token
  into `agentmesh-agw-pep` and set `MCP_GITHUB_AUTH_PATH=/secrets/github-token`.
  `agentmesh-node` injects `Authorization` via `ext_proc` `HeaderMutation` only
  after Phase 2 JSON-RPC `tools/call` authorization succeeds.
- **Private VPC callout:** For private-only Cloud Run (`--ingress=internal-and-cloud-load-balancing`),
  front `agentmesh-agw-pep` with a Regional Internal ALB, attach a VPC
  `networkAttachment` + `dnsPeeringConfig` to the `AgentGateway`, and point
  `AuthzExtension.service` / `authority` at the private DNS hostname.

## Cleanup

```bash
PROJECT_ID="<your-gcp-project-id>" REGION="us-central1" ./cleanup.sh
```
