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

# Idempotent deployment for Topology B:
#   Google Cloud External ALB (Edge Agent Gateway) + Service Extensions
#   AuthzExtension (EXT_PROC_GRPC) + AuthzPolicy (CONTENT_AUTHZ) ->
#   agentmesh-node on Cloud Run -> live GitHub Smart HTTP & GitHub MCP backend.
#
# Usage:
#   PROJECT_ID=<your-sandbox-project> REGION=us-central1 ./deploy_edge_alb.sh

set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID to a GCP project with billing enabled}"
REGION="${REGION:-us-central1}"
AR_REPO="${AR_REPO:-agentmesh-agw}"
VPC_NAME="${VPC_NAME:-agentmesh-agw-vpc}"
PROXY_SUBNET="${PROXY_SUBNET:-agentmesh-agw-proxy-subnet}"
PEP_SERVICE="${PEP_SERVICE:-agentmesh-agw-pep}"
MCP_SERVICE="${MCP_SERVICE:-agentmesh-github-mcp-live}"
ALLOWED_MEMBER="${ALLOWED_MEMBER:-mesh:system:authenticated}"
# Include gcloud's default client ID so `gcloud auth print-identity-token` works
# in sandbox verification alongside workload tokens targeting `agentmesh-gcp-agw`.
# In production, restrict ALLOWED_AUDIENCE strictly to your dedicated audience.
ALLOWED_AUDIENCE="${ALLOWED_AUDIENCE:-agentmesh-gcp-agw,32555940559.apps.googleusercontent.com}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
IMAGE_PREFIX="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
PEP_IMAGE="${IMAGE_PREFIX}/${PEP_SERVICE}:latest"
MCP_IMAGE="${IMAGE_PREFIX}/${MCP_SERVICE}:latest"

echo "==> [1/6] Enabling required GCP APIs on ${PROJECT_ID}"
gcloud services enable \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  compute.googleapis.com \
  networksecurity.googleapis.com \
  networkservices.googleapis.com \
  run.googleapis.com \
  --project="${PROJECT_ID}"

echo "==> [2/6] Ensuring Artifact Registry repository ${AR_REPO}"
gcloud artifacts repositories describe "${AR_REPO}" \
  --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud artifacts repositories create "${AR_REPO}" \
       --repository-format=docker --location="${REGION}" \
       --description="Agent Mesh + Agent Gateway qualification images" \
       --project="${PROJECT_ID}"

echo "==> [3/6] Building container images with Cloud Build"
TMP_CB="$(mktemp -d)"
trap 'rm -rf "${TMP_CB}"' EXIT

if [ "${SKIP_BUILD:-false}" != "true" ]; then
  cat >"${TMP_CB}/cloudbuild-pep.yaml" <<EOF
steps:
- name: 'gcr.io/cloud-builders/docker'
  env: ['DOCKER_BUILDKIT=1']
  args: ['build', '-f', 'development/examples/gcp-agent-gateway/pep/Dockerfile', '-t', '${PEP_IMAGE}', '.']
images: ['${PEP_IMAGE}']
EOF

  cat >"${TMP_CB}/cloudbuild-mcp.yaml" <<EOF
steps:
- name: 'gcr.io/cloud-builders/docker'
  env: ['DOCKER_BUILDKIT=1']
  args: ['build', '-f', 'development/examples/gcp-agent-gateway/github-mcp-live/Dockerfile', '-t', '${MCP_IMAGE}', '.']
images: ['${MCP_IMAGE}']
EOF

  (cd "${REPO_ROOT}" && gcloud builds submit --config="${TMP_CB}/cloudbuild-pep.yaml" --project="${PROJECT_ID}" .)
  (cd "${REPO_ROOT}" && gcloud builds submit --config="${TMP_CB}/cloudbuild-mcp.yaml" --project="${PROJECT_ID}" .)
else
  echo "    SKIP_BUILD=true: reusing existing images in ${IMAGE_PREFIX}"
fi

echo "==> [4/6] Deploying Cloud Run services (${MCP_SERVICE} and ${PEP_SERVICE})"
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

# Reserve the Edge ALB static external IP first so we can register it as the
# host-resolved MCP target URL on agentmesh-node (zero X-Mesh-Target-Service needed for /mcp).
gcloud compute networks describe "${VPC_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud compute networks create "${VPC_NAME}" --subnet-mode=auto --project="${PROJECT_ID}"

gcloud compute networks subnets describe "${PROXY_SUBNET}" \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud compute networks subnets create "${PROXY_SUBNET}" \
       --network="${VPC_NAME}" --region="${REGION}" \
       --range=10.12.13.0/24 --purpose=REGIONAL_MANAGED_PROXY --role=ACTIVE \
       --project="${PROJECT_ID}"

gcloud compute addresses describe agentmesh-edge-alb-ip \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud compute addresses create agentmesh-edge-alb-ip \
       --region="${REGION}" --network-tier=STANDARD --project="${PROJECT_ID}"

ALB_IP="$(gcloud compute addresses describe agentmesh-edge-alb-ip \
  --region="${REGION}" --project="${PROJECT_ID}" --format='value(address)')"

cat >"${TMP_CB}/pep-env.yaml" <<EOF
OIDC_ISSUER: "https://accounts.google.com"
WORKLOAD_ISSUER: "https://accounts.google.com"
ALLOWED_AUDIENCE: "${ALLOWED_AUDIENCE}"
ALLOWED_MEMBER: "${ALLOWED_MEMBER}"
MCP_GITHUB_URL: "http://${ALB_IP}/mcp"
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
  --env-vars-file="${TMP_CB}/pep-env.yaml" \
  --project="${PROJECT_ID}"

PEP_URL="$(gcloud run services describe "${PEP_SERVICE}" \
  --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"

echo "==> [5/6] Provisioning Regional External ALB (EXTERNAL_MANAGED)"
gcloud compute network-endpoint-groups describe agentmesh-pep-neg \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud compute network-endpoint-groups create agentmesh-pep-neg \
       --region="${REGION}" --network-endpoint-type=serverless \
       --cloud-run-service="${PEP_SERVICE}" --project="${PROJECT_ID}"

gcloud compute network-endpoint-groups describe agentmesh-mcp-neg \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud compute network-endpoint-groups create agentmesh-mcp-neg \
       --region="${REGION}" --network-endpoint-type=serverless \
       --cloud-run-service="${MCP_SERVICE}" --project="${PROJECT_ID}"

gcloud compute backend-services describe agentmesh-pep-bs \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || {
    gcloud compute backend-services create agentmesh-pep-bs \
      --region="${REGION}" --load-balancing-scheme=EXTERNAL_MANAGED \
      --protocol=HTTP2 --project="${PROJECT_ID}"
    gcloud compute backend-services add-backend agentmesh-pep-bs \
      --region="${REGION}" --network-endpoint-group=agentmesh-pep-neg \
      --network-endpoint-group-region="${REGION}" --project="${PROJECT_ID}"
  }

gcloud compute backend-services describe agentmesh-mcp-bs \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || {
    gcloud compute backend-services create agentmesh-mcp-bs \
      --region="${REGION}" --load-balancing-scheme=EXTERNAL_MANAGED \
      --protocol=HTTP --project="${PROJECT_ID}"
    gcloud compute backend-services add-backend agentmesh-mcp-bs \
      --region="${REGION}" --network-endpoint-group=agentmesh-mcp-neg \
      --network-endpoint-group-region="${REGION}" --project="${PROJECT_ID}"
  }

gcloud compute url-maps describe agentmesh-edge-alb-map \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud compute url-maps create agentmesh-edge-alb-map \
       --region="${REGION}" --default-service=agentmesh-mcp-bs \
       --project="${PROJECT_ID}"

gcloud compute target-http-proxies describe agentmesh-edge-alb-proxy \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud compute target-http-proxies create agentmesh-edge-alb-proxy \
       --region="${REGION}" --url-map=agentmesh-edge-alb-map \
       --project="${PROJECT_ID}"

gcloud compute forwarding-rules describe agentmesh-edge-alb-fr \
  --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 \
  || gcloud compute forwarding-rules create agentmesh-edge-alb-fr \
       --region="${REGION}" --load-balancing-scheme=EXTERNAL_MANAGED \
       --network="${VPC_NAME}" --network-tier=STANDARD \
       --address=agentmesh-edge-alb-ip --target-http-proxy=agentmesh-edge-alb-proxy \
       --target-http-proxy-region="${REGION}" --ports=80 \
       --project="${PROJECT_ID}"

echo "==> [6/6] Importing Service Extensions AuthzExtension (EXT_PROC_GRPC) and AuthzPolicy (CONTENT_AUTHZ)"
PEP_HOST="${PEP_URL#https://}"
# Omit forwardHeaders so all client headers (including :authority, :method,
# :path, Content-Type, Authorization, and X-Mesh-Biscuit) reach ext_proc.
cat >"${TMP_CB}/authz-extension.yaml" <<EOF
name: agentmesh-edge-ext
authority: ${PEP_HOST}
loadBalancingScheme: EXTERNAL_MANAGED
service: https://www.googleapis.com/compute/v1/projects/${PROJECT_ID}/regions/${REGION}/backendServices/agentmesh-pep-bs
wireFormat: EXT_PROC_GRPC
failOpen: false
timeout: "1.0s"
EOF

gcloud beta service-extensions authz-extensions import agentmesh-edge-ext \
  --source="${TMP_CB}/authz-extension.yaml" \
  --location="${REGION}" \
  --project="${PROJECT_ID}"

cat >"${TMP_CB}/authz-policy.yaml" <<EOF
name: agentmesh-edge-content-authz
target:
  loadBalancingScheme: EXTERNAL_MANAGED
  resources:
    - "https://www.googleapis.com/compute/v1/projects/${PROJECT_ID}/regions/${REGION}/forwardingRules/agentmesh-edge-alb-fr"
policyProfile: CONTENT_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - "projects/${PROJECT_ID}/locations/${REGION}/authzExtensions/agentmesh-edge-ext"
httpRules:
  - to:
      operations:
        - paths:
            - prefix: "/mcp"
        - paths:
            - prefix: "/google/"
        - paths:
            - prefix: "/kubernetes/"
EOF

gcloud beta network-security authz-policies import agentmesh-edge-content-authz \
  --source="${TMP_CB}/authz-policy.yaml" \
  --location="${REGION}" \
  --project="${PROJECT_ID}"

cat <<SUMMARY

================================================================
  Edge Agent Gateway (External ALB + EXT_PROC_GRPC) Ready
================================================================
Project:      ${PROJECT_ID}
Region:       ${REGION}
Edge ALB IP:  http://${ALB_IP}
PEP Service:  ${PEP_URL}
MCP Backend:  ${MCP_URL}

Wait ~60s for AuthzPolicy propagation, then run live verification:
  PROJECT_ID=${PROJECT_ID} REGION=${REGION} ./verify_edge_alb.sh
================================================================
SUMMARY
