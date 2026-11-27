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

# Idempotent deployment for Topology A:
#   Managed Google Cloud Agent Gateway (AGENT_TO_ANYWHERE) +
#   Service Extensions AuthzExtension (EXT_PROC_GRPC) + AuthzPolicy (CONTENT_AUTHZ) ->
#   agentmesh-node on Cloud Run -> real GitHub + live GitHub MCP backend,
#   verified from a Vertex AI Agent Runtime agent with AGENT_IDENTITY.
#
# Targets a personal or sandbox GCP project with billing enabled.
#
# Usage:
#   PROJECT_ID=<your-sandbox-project> REGION=us-central1 ./deploy_managed_agw.sh

set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID to a GCP project with billing enabled}"
REGION="${REGION:-us-central1}"
AR_REPO="${AR_REPO:-agentmesh-agw}"
AGW_NAME="${AGW_NAME:-agentmesh-egress-gw}"
PEP_SERVICE="${PEP_SERVICE:-agentmesh-agw-pep}"
MCP_SERVICE="${MCP_SERVICE:-agentmesh-github-mcp-live}"
ALLOWED_MEMBER="${ALLOWED_MEMBER:-mesh:system:authenticated}"
ALLOWED_AUDIENCE="${ALLOWED_AUDIENCE:-agentmesh-gcp-agw,32555940559.apps.googleusercontent.com}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
PROJECT_NUM="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
IMAGE_PREFIX="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
PEP_IMAGE="${IMAGE_PREFIX}/${PEP_SERVICE}:latest"
MCP_IMAGE="${IMAGE_PREFIX}/${MCP_SERVICE}:latest"
AGW_RESOURCE="projects/${PROJECT_ID}/locations/${REGION}/agentGateways/${AGW_NAME}"

echo "==> [1/7] Enabling required GCP APIs on ${PROJECT_ID} (${PROJECT_NUM})"
gcloud services enable \
  agentregistry.googleapis.com \
  aiplatform.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  compute.googleapis.com \
  dns.googleapis.com \
  iam.googleapis.com \
  iap.googleapis.com \
  logging.googleapis.com \
  modelarmor.googleapis.com \
  networksecurity.googleapis.com \
  networkservices.googleapis.com \
  run.googleapis.com \
  storage.googleapis.com \
  --project="${PROJECT_ID}"

echo "==> [2/7] Materializing service identities and applying least-privilege IAM"
for svc in aiplatform.googleapis.com networkservices.googleapis.com; do
  gcloud beta services identity create --service="${svc}" --project="${PROJECT_ID}" >/dev/null 2>&1 || true
done

AI_SA="service-${PROJECT_NUM}@gcp-sa-aiplatform.iam.gserviceaccount.com"
AGW_SA="service-${PROJECT_NUM}@gcp-sa-agentgateway.iam.gserviceaccount.com"
COMPUTE_SA="${PROJECT_NUM}-compute@developer.gserviceaccount.com"

# roles/networkservices.viewer is the narrowest predefined role carrying
# networkservices.agentGateways.get needed when Vertex AI Agent Runtime binds to AGW.
for role in roles/networkservices.viewer roles/aiplatform.serviceAgent roles/compute.networkAdmin roles/dns.admin; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${AI_SA}" --role="${role}" --condition=None --quiet >/dev/null
done

for role in roles/agentgateway.serviceAgent roles/aiplatform.user roles/modelarmor.user; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${AGW_SA}" --role="${role}" --condition=None --quiet >/dev/null 2>&1 || true
done

for role in roles/aiplatform.user roles/storage.objectViewer roles/artifactregistry.writer roles/agentregistry.viewer; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${COMPUTE_SA}" --role="${role}" --condition=None --quiet >/dev/null
done

echo "==> [3/7] Building & deploying Cloud Run services (${MCP_SERVICE} and ${PEP_SERVICE})"
gcloud artifacts repositories describe "${AR_REPO}" \
  --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud artifacts repositories create "${AR_REPO}" \
       --repository-format=docker --location="${REGION}" \
       --description="Agent Mesh + Agent Gateway qualification images" \
       --project="${PROJECT_ID}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

if [ "${SKIP_BUILD:-false}" != "true" ]; then
  cat >"${TMP_DIR}/cloudbuild-pep.yaml" <<EOF
steps:
- name: 'gcr.io/cloud-builders/docker'
  env: ['DOCKER_BUILDKIT=1']
  args: ['build', '-f', 'development/examples/gcp-agent-gateway/pep/Dockerfile', '-t', '${PEP_IMAGE}', '.']
images: ['${PEP_IMAGE}']
EOF

  cat >"${TMP_DIR}/cloudbuild-mcp.yaml" <<EOF
steps:
- name: 'gcr.io/cloud-builders/docker'
  env: ['DOCKER_BUILDKIT=1']
  args: ['build', '-f', 'development/examples/gcp-agent-gateway/github-mcp-live/Dockerfile', '-t', '${MCP_IMAGE}', '.']
images: ['${MCP_IMAGE}']
EOF

  (cd "${REPO_ROOT}" && gcloud builds submit --config="${TMP_DIR}/cloudbuild-pep.yaml" --project="${PROJECT_ID}" .)
  (cd "${REPO_ROOT}" && gcloud builds submit --config="${TMP_DIR}/cloudbuild-mcp.yaml" --project="${PROJECT_ID}" .)
else
  echo "    SKIP_BUILD=true: reusing existing images in ${IMAGE_PREFIX}"
fi

gcloud run deploy "${MCP_SERVICE}" \
  --image="${MCP_IMAGE}" \
  --region="${REGION}" \
  --platform=managed \
  --allow-unauthenticated \
  --ingress=all \
  --min-instances=1 \
  --max-instances=2 \
  --project="${PROJECT_ID}"

MCP_URL="$(gcloud run services describe "${MCP_SERVICE}" \
  --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"
MCP_HOST="${MCP_URL#https://}"

# Discover the Google Cloud Agent Identity Workload Identity Pool OIDC issuer
# used by Vertex AI Agent Runtime (identity_type=AGENT_IDENTITY).
if [ -z "${AGENT_IDENTITY_ISSUER:-}" ]; then
  ORG_ID="$(gcloud projects get-ancestors "${PROJECT_ID}" --format='value(id,type)' 2>/dev/null | awk '$2=="organization"{print $1; exit}' || true)"
  if [ -n "${ORG_ID}" ]; then
    AGENT_IDENTITY_ISSUER="https://sts.googleapis.com/v1/organizations/${ORG_ID}/locations/global/workloadIdentityPools/agents.global.org-${ORG_ID}.system.id.goog"
  else
    AGENT_IDENTITY_ISSUER="https://sts.googleapis.com/v1/projects/${PROJECT_NUM}/locations/global/workloadIdentityPools/agents.global.project-${PROJECT_NUM}.system.id.goog"
  fi
fi
echo "    Agent Identity OIDC issuer: ${AGENT_IDENTITY_ISSUER}"

# Configure agentmesh-node with MCP_GITHUB_URL pointing at MCP_URL/mcp so
# unmodified Agent Runtime requests to https://<MCP_HOST>/mcp resolve by :authority
# with zero X-Mesh-Target-Service header.
cat >"${TMP_DIR}/pep-env.yaml" <<EOF
OIDC_ISSUER: "https://accounts.google.com"
WORKLOAD_ISSUER: "https://accounts.google.com,${AGENT_IDENTITY_ISSUER}"
ALLOWED_AUDIENCE: "${ALLOWED_AUDIENCE}"
ALLOWED_MEMBER: "${ALLOWED_MEMBER}"
MCP_GITHUB_URL: "${MCP_URL}/mcp"
EOF

gcloud run deploy "${PEP_SERVICE}" \
  --image="${PEP_IMAGE}" \
  --region="${REGION}" \
  --platform=managed \
  --use-http2 \
  --allow-unauthenticated \
  --ingress=all \
  --min-instances=1 \
  --max-instances=1 \
  --memory=1Gi \
  --cpu=1 \
  --env-vars-file="${TMP_DIR}/pep-env.yaml" \
  --project="${PROJECT_ID}"

PEP_URL="$(gcloud run services describe "${PEP_SERVICE}" \
  --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"
PEP_HOST="${PEP_URL#https://}"

echo "==> [4/7] Creating Managed AgentGateway (${AGW_NAME}, AGENT_TO_ANYWHERE)"
if gcloud beta network-services agent-gateways describe "${AGW_NAME}" \
    --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "    AgentGateway ${AGW_NAME} already exists, skipping import."
else
  cat >"${TMP_DIR}/agent-gateway.yaml" <<EOF
name: ${AGW_NAME}
description: "Agent Mesh Service Extension Qualification Gateway"
protocols:
  - MCP
googleManaged:
  governedAccessPath: AGENT_TO_ANYWHERE
EOF
  gcloud beta network-services agent-gateways import "${AGW_NAME}" \
    --source="${TMP_DIR}/agent-gateway.yaml" \
    --location="${REGION}" \
    --project="${PROJECT_ID}"
fi

echo "==> [5/7] Importing baseline REQUEST_AUTHZ allow policy on AgentGateway"
cat >"${TMP_DIR}/allow-base-policy.yaml" <<EOF
name: agentmesh-allow-base
target:
  resources:
    - "${AGW_RESOURCE}"
httpRules:
  - to:
      operations:
        - paths:
            - prefix: "/"
action: ALLOW
policyProfile: REQUEST_AUTHZ
EOF
gcloud beta network-security authz-policies import agentmesh-allow-base \
  --source="${TMP_DIR}/allow-base-policy.yaml" \
  --location="${REGION}" \
  --project="${PROJECT_ID}"

echo "==> [6/7] Importing AuthzExtension (EXT_PROC_GRPC) pointing to ${PEP_HOST}"
# Omit forwardHeaders so Google Cloud Service Extensions forwards all client
# headers including :authority/:method/:path, Content-Type, Authorization, and
# X-Mesh-Biscuit (setting a partial allowlist drops :authority/Host and breaks
# host-based target resolution).
cat >"${TMP_DIR}/authz-extension.yaml" <<EOF
name: agentmesh-tar-ext
service: ${PEP_HOST}
authority: ${PEP_HOST}
wireFormat: EXT_PROC_GRPC
failOpen: false
timeout: "1.0s"
loadBalancingScheme: LOAD_BALANCING_SCHEME_UNSPECIFIED
EOF
gcloud beta service-extensions authz-extensions import agentmesh-tar-ext \
  --source="${TMP_DIR}/authz-extension.yaml" \
  --location="${REGION}" \
  --project="${PROJECT_ID}"

echo "==> [7/7] Importing CONTENT_AUTHZ AuthzPolicy scoping GitHub & MCP egress to agentmesh-tar-ext"
# Scope the extension to github.com and the MCP backend host so internal
# Vertex AI session/telemetry calls pass untouched.
cat >"${TMP_DIR}/content-authz-policy.yaml" <<EOF
name: agentmesh-tar-content-authz
target:
  loadBalancingScheme: LOAD_BALANCING_SCHEME_UNSPECIFIED
  resources:
    - "${AGW_RESOURCE}"
action: CUSTOM
policyProfile: CONTENT_AUTHZ
httpRules:
  - to:
      operations:
        - hosts:
            - exact: "github.com"
            - exact: "${MCP_HOST}"
          paths:
            - prefix: "/"
customProvider:
  authzExtension:
    resources:
      - "projects/${PROJECT_ID}/locations/${REGION}/authzExtensions/agentmesh-tar-ext"
EOF
gcloud beta network-security authz-policies import agentmesh-tar-content-authz \
  --source="${TMP_DIR}/content-authz-policy.yaml" \
  --location="${REGION}" \
  --project="${PROJECT_ID}"

cat <<SUMMARY

================================================================
  Managed Google Cloud Agent Gateway + Agent Mesh PEP Ready
================================================================
Project:       ${PROJECT_ID} (${PROJECT_NUM})
Region:        ${REGION}
AgentGateway:  ${AGW_RESOURCE}
PEP Service:   ${PEP_URL}
MCP Backend:   ${MCP_URL}

Next: deploy and verify the live Vertex AI Agent Runtime agent:
  python3 -m venv /tmp/agw-venv
  /tmp/agw-venv/bin/pip install -r ${SCRIPT_DIR}/agent_runtime/requirements.txt
  PROJECT_ID=${PROJECT_ID} REGION=${REGION} AGW_NAME=${AGW_NAME} \\
    PEP_URL=${PEP_URL} MCP_URL=${MCP_URL} \\
    /tmp/agw-venv/bin/python ${SCRIPT_DIR}/agent_runtime/deploy_agent.py
================================================================
SUMMARY
