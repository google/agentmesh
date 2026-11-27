#!/usr/bin/env bash
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

# Idempotent cleanup for both Topology A (Managed AgentGateway) and
# Topology B (Edge ALB) resources created by this example.
#
# Usage:
#   PROJECT_ID=<your-sandbox-project> REGION=us-central1 ./cleanup.sh

set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID}"
REGION="${REGION:-us-central1}"
AGW_NAME="${AGW_NAME:-agentmesh-egress-gw}"
PEP_SERVICE="${PEP_SERVICE:-agentmesh-agw-pep}"
MCP_SERVICE="${MCP_SERVICE:-agentmesh-github-mcp-live}"
VPC_NAME="${VPC_NAME:-agentmesh-agw-vpc}"
PROXY_SUBNET="${PROXY_SUBNET:-agentmesh-agw-proxy-subnet}"

echo "==> Deleting Managed AgentGateway policies, extension, and gateway (if present)"
gcloud beta network-security authz-policies delete agentmesh-tar-content-authz \
  --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud beta network-security authz-policies delete agentmesh-allow-base \
  --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud beta service-extensions authz-extensions delete agentmesh-tar-ext \
  --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud beta network-services agent-gateways delete "${AGW_NAME}" \
  --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true

echo "==> Deleting Edge ALB AuthzPolicy, AuthzExtension, and LB resources (if present)"
gcloud beta network-security authz-policies delete agentmesh-edge-content-authz \
  --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud beta service-extensions authz-extensions delete agentmesh-edge-ext \
  --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute forwarding-rules delete agentmesh-edge-alb-fr \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute target-http-proxies delete agentmesh-edge-alb-proxy \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute url-maps delete agentmesh-edge-alb-map \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute backend-services delete agentmesh-pep-bs \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute backend-services delete agentmesh-mcp-bs \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute network-endpoint-groups delete agentmesh-pep-neg \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute network-endpoint-groups delete agentmesh-mcp-neg \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute addresses delete agentmesh-edge-alb-ip \
  --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true

echo "==> Deleting Cloud Run services"
gcloud run services delete "${PEP_SERVICE}" --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud run services delete "${MCP_SERVICE}" --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true

echo "==> Deleting VPC subnet and network (best-effort)"
gcloud compute networks subnets delete "${PROXY_SUBNET}" --region="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true
gcloud compute networks delete "${VPC_NAME}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1 || true

echo "Cleanup commands submitted. Delete any deployed Vertex AI Agent Runtime instances separately if created."
