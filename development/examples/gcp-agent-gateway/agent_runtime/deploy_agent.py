#!/usr/bin/env python3
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

"""Idempotently deploys the qualification ADK agent to Vertex AI Agent Runtime
bound to a Managed Google Cloud Agent Gateway (AGENT_TO_ANYWHERE) and runs the
live allow/deny probe matrix via reasoningEngines/:streamQuery.

Usage:
  PROJECT_ID=<project> REGION=us-central1 AGW_NAME=agentmesh-egress-gw \
    PEP_URL=https://... MCP_URL=https://... /tmp/agw-venv/bin/python deploy_agent.py
"""

import json
import os
import sys
import time

import google.auth
import google.auth.transport.requests
import requests
import vertexai
from google.genai import types as genai_types
from vertexai import types

DISPLAY_NAME = "agentmesh-agw-qualifier"


def _adc_headers(project_id: str) -> dict[str, str]:
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    creds.refresh(google.auth.transport.requests.Request())
    return {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "x-goog-user-project": project_id,
    }


def _find_existing_engine(project_id: str, region: str) -> str:
    url = f"https://{region}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{region}/reasoningEngines"
    r = requests.get(url, headers=_adc_headers(project_id), timeout=30)
    r.raise_for_status()
    for re_obj in r.json().get("reasoningEngines", []):
        if re_obj.get("displayName") == DISPLAY_NAME:
            return re_obj["name"]
    return ""


def main() -> int:
    project_id = os.environ["PROJECT_ID"]
    region = os.environ.get("REGION", "us-central1")
    agw_name = os.environ.get("AGW_NAME", "agentmesh-egress-gw")
    pep_url = os.environ["PEP_URL"]
    mcp_url = os.environ["MCP_URL"]
    audience = os.environ.get("AGENTMESH_AUDIENCE", "agentmesh-gcp-agw")
    agw_resource = f"projects/{project_id}/locations/{region}/agentGateways/{agw_name}"

    re_name = _find_existing_engine(project_id, region)
    if re_name and os.environ.get("RECREATE_AGENT", "").lower() in ("1", "true", "yes"):
        print(f"==> RECREATE_AGENT=true: deleting existing Reasoning Engine {re_name}")
        del_url = f"https://{region}-aiplatform.googleapis.com/v1/{re_name}?force=true"
        del_resp = requests.delete(del_url, headers=_adc_headers(project_id), timeout=60)
        del_resp.raise_for_status()
        for _ in range(30):
            if not _find_existing_engine(project_id, region):
                break
            time.sleep(2)
        re_name = ""
    if re_name:
        print(f"==> Reusing existing Reasoning Engine: {re_name}")
    else:
        agent_dir = os.path.dirname(os.path.abspath(__file__))
        vertexai.init(project=project_id, location=region)
        client = vertexai.Client(
            project=project_id,
            location=region,
            http_options=genai_types.HttpOptions(api_version="v1beta1"),
        )

        print(f"==> Deploying ADK agent to Vertex AI Agent Runtime bound to {agw_resource}")
        prev_cwd = os.getcwd()
        os.chdir(agent_dir)
        try:
            remote = client.agent_engines.create(
                config={
                    "display_name": DISPLAY_NAME,
                    "description": "Qualifies Agent Mesh AuthzExtension on Managed Agent Gateway",
                    "identity_type": types.IdentityType.AGENT_IDENTITY,
                    "source_packages": ["main.py", "requirements.txt"],
                    "entrypoint_module": "main",
                    "entrypoint_object": "agent_instance",
                    "requirements_file": "requirements.txt",
                    "agent_framework": "google-adk",
                    "class_methods": [],
                    "max_instances": 1,
                    "env_vars": {
                        "GOOGLE_CLOUD_LOCATION": region,
                        "NUM_WORKERS": "2",
                        # Required for Agent Gateway-attached Agent Runtime engines so
                        # internal sessions.create calls succeed cleanly.
                        "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES": "False",
                        "AGENTMESH_PEP_URL": pep_url,
                        "AGENTMESH_MCP_URL": mcp_url,
                        "AGENTMESH_AUDIENCE": audience,
                    },
                    "agent_gateway_config": {
                        "agent_to_anywhere_config": {"agent_gateway": agw_resource},
                    },
                }
            )
        finally:
            os.chdir(prev_cwd)
        re_name = remote.api_resource.name
        print(f"==> Deployed Reasoning Engine: {re_name}")
        print("==> Waiting 30s for AuthzPolicy & gateway attachment propagation...")
        time.sleep(30)

    re_id = re_name.split("/")[-1]
    headers = _adc_headers(project_id)
    base_url = f"https://{region}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{region}/reasoningEngines/{re_id}"

    print("==> Creating session and running live qualification matrix through Managed Agent Gateway...")
    sess_resp = requests.post(
        f"{base_url}/sessions",
        headers=headers,
        json={"userId": "qualifier"},
        timeout=30,
    )
    sess_resp.raise_for_status()
    sess_json = sess_resp.json()
    sess_full = sess_json.get("response", {}).get("name") or sess_json.get("name", "")
    session_id = sess_full.split("/sessions/")[-1].split("/")[0]

    q_resp = requests.post(
        f"{base_url}:streamQuery",
        headers=headers,
        json={
            "classMethod": "async_stream_query",
            "input": {
                "user_id": "qualifier",
                "session_id": session_id,
                "message": "Run run_agw_qualification_matrix and return the exact JSON result.",
            },
        },
        timeout=180,
    )
    q_resp.raise_for_status()
    for line in q_resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
            print(json.dumps(evt, indent=2))
        except json.JSONDecodeError:
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
