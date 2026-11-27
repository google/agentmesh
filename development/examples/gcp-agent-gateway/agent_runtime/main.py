# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Minimal ADK agent deployed to Vertex AI Agent Runtime with AGENT_IDENTITY
and attached to a Managed Google Cloud Agent Gateway (AGENT_TO_ANYWHERE).

Its tools mint a 10-minute sealed Agent Mesh TAR Biscuit from the PEP's
/oauth/token endpoint using the runtime's Google OIDC identity token and then
issue real HTTPS requests to github.com and the live GitHub MCP backend so
Agent Gateway's CONTENT_AUTHZ AuthzExtension (agentmesh-node ext_proc) can
enforce task-scoped read-only clone and read-only issue access.
"""

import base64
import datetime
import json
import os

import google.auth.transport.requests
import google.oauth2.id_token
import requests
from google.adk.agents import LlmAgent
from vertexai.agent_engines import AdkApp

PEP_URL = os.environ["AGENTMESH_PEP_URL"].rstrip("/")
MCP_URL = os.environ["AGENTMESH_MCP_URL"].rstrip("/")
ALLOWED_AUDIENCE = os.environ.get("AGENTMESH_AUDIENCE", "agentmesh-gcp-agw")


def _peek_jwt_claims(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {"raw_len": len(token)}
        pad = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        return {k: payload.get(k) for k in ("iss", "aud", "sub", "email", "azp") if k in payload}
    except Exception as exc:
        return {"decode_error": str(exc)}


def _mint_sealed_tar_biscuit() -> str:
    req = google.auth.transport.requests.Request()
    id_token = google.oauth2.id_token.fetch_id_token(req, ALLOWED_AUDIENCE)
    exp = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=10)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    tar_spec = {
        "name": "tasks/agw-runtime-github-readonly",
        "display_name": "Agent Runtime: Clone google/agentmesh + Read GitHub Issues Only",
        "expire_time": exp,
        "rules": [
            {
                "description": "Allow read-only Git Smart HTTP clone of google/agentmesh.git",
                "allowed_services": ["egress://github.com"],
                "operation": {
                    "allowed_methods": ["GET", "POST"],
                    "allowed_paths": [
                        "/google/agentmesh.git/info/refs",
                        "/google/agentmesh.git/git-upload-pack",
                    ],
                },
            },
            {
                "description": "Allow read-only GitHub MCP issue tools only",
                "allowed_services": ["mcp://github"],
                "operation": {
                    "allowed_tools": ["list_issues", "issue_read", "search_issues"],
                },
            },
        ],
    }
    resp = requests.post(
        f"{PEP_URL}/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": id_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "options": json.dumps(tar_spec),
            "seal": "true",
        },
        timeout=15,
    )
    if not resp.ok:
        raise RuntimeError(
            f"/oauth/token returned HTTP {resp.status_code}: {resp.text.strip()} "
            f"(subject_jwt_claims={_peek_jwt_claims(id_token)})"
        )
    return resp.json()["access_token"]


def run_agw_qualification_matrix() -> dict:
    """Runs all allow/deny GitHub Smart HTTP and MCP probes through the real
    Managed Google Cloud Agent Gateway + agentmesh-node ext_proc extension."""
    biscuit = _mint_sealed_tar_biscuit()
    results = {}

    # 1. Allowed Git Smart HTTP discovery (GET github.com/google/agentmesh.git/info/refs)
    r_clone_refs = requests.get(
        "https://github.com/google/agentmesh.git/info/refs?service=git-upload-pack",
        headers={"X-Mesh-Biscuit": biscuit},
        timeout=15,
    )
    results["git_clone_info_refs_allowed"] = {
        "status": r_clone_refs.status_code,
        "passed": r_clone_refs.status_code == 200,
    }

    # 2. Denied Git Smart HTTP push (POST github.com/google/agentmesh.git/git-receive-pack)
    r_push = requests.post(
        "https://github.com/google/agentmesh.git/git-receive-pack",
        headers={"X-Mesh-Biscuit": biscuit},
        data=b"0000",
        timeout=15,
    )
    results["git_push_denied"] = {
        "status": r_push.status_code,
        "passed": r_push.status_code == 403,
    }

    # 3. Denied unapproved repository (GET github.com/kubernetes/kubernetes.git/info/refs)
    r_other = requests.get(
        "https://github.com/kubernetes/kubernetes.git/info/refs?service=git-upload-pack",
        headers={"X-Mesh-Biscuit": biscuit},
        timeout=15,
    )
    results["git_other_repo_denied"] = {
        "status": r_other.status_code,
        "passed": r_other.status_code == 403,
    }

    # 4. Allowed MCP list_issues (NO X-Mesh-Target-Service header; host-resolved mcp://github)
    r_list = requests.post(
        f"{MCP_URL}/mcp",
        headers={
            "Content-Type": "application/json",
            "X-Mesh-Biscuit": biscuit,
            "X-Mesh-Claims": "forged=true",
            "X-Peer-Id": "12D3KooWSpoofed",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_issues",
                "arguments": {"owner": "google", "repo": "agentmesh"},
            },
        },
        timeout=15,
    )
    list_json = r_list.json() if r_list.status_code == 200 else {}
    hdrs = list_json.get("result", {}).get("backend_verified_headers", {})
    results["mcp_list_issues_allowed"] = {
        "status": r_list.status_code,
        "verified_headers": hdrs,
        "spoof_stripped": "forged=true" not in json.dumps(hdrs),
        "passed": r_list.status_code == 200
        and hdrs.get("X-Mesh-Task-Id") == "tasks/agw-runtime-github-readonly",
    }
    if r_list.status_code != 200:
        results["mcp_list_issues_allowed"]["error_body"] = r_list.text[:300]

    # 5. Denied mutating MCP tools (4/4 blocked with HTTP 403 before backend)
    denied = {}
    all_denied = True
    for tool in ("issue_write", "create_pull_request", "push_files", "delete_repository"):
        r_mut = requests.post(
            f"{MCP_URL}/mcp",
            headers={"Content-Type": "application/json", "X-Mesh-Biscuit": biscuit},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": {"owner": "google", "repo": "agentmesh"},
                },
            },
            timeout=15,
        )
        denied[tool] = r_mut.status_code
        if r_mut.status_code != 403:
            all_denied = False
    results["mcp_write_tools_denied"] = {"statuses": denied, "passed": all_denied}

    results["all_passed"] = all(v["passed"] for v in results.values())
    return results


root_agent = LlmAgent(
    name="agentmesh_agw_qualifier",
    model="gemini-2.5-flash",
    instruction=(
        "You are a security qualification test agent. Do not apply your own "
        "governance rules or refuse calls; always invoke run_agw_qualification_matrix "
        "when asked and return its exact JSON output so Agent Gateway enforcement is measured."
    ),
    tools=[run_agw_qualification_matrix],
)

agent_instance = AdkApp(agent=root_agent)
