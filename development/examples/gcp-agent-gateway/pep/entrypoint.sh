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

# Starts a self-contained Agent Mesh control plane + enrolled agentmesh-node
# Service Extension PEP inside one Cloud Run container.
#
# Exposes HTTP/2 (h2c) on 0.0.0.0:${PORT:-8080} for:
#   - /envoy.service.ext_proc.v3.ExternalProcessor/Process (Google Cloud Agent Gateway CONTENT_AUTHZ)
#   - /envoy.service.auth.v3.Authorization/Check           (Envoy gRPC ext_authz)
#   - /ext_authz                                           (Envoy HTTP ext_authz)
#   - /oauth/token                                         (RFC 8693 OIDC -> sealed TAR Biscuit)
#   - /healthz and /readyz

set -euo pipefail

PORT="${PORT:-8080}"
CP_PORT="18082"
DATA_DIR="${DATA_DIR:-/data}"
OIDC_ISSUER="${OIDC_ISSUER:-https://accounts.google.com}"
WORKLOAD_ISSUER="${WORKLOAD_ISSUER:-https://accounts.google.com}"
ALLOWED_AUDIENCE="${ALLOWED_AUDIENCE:-agentmesh-gcp-agw}"
ALLOWED_MEMBER="${ALLOWED_MEMBER:-mesh:system:authenticated}"
MCP_GITHUB_URL="${MCP_GITHUB_URL:-https://api.githubcopilot.com/mcp}"
MCP_GITHUB_AUTH_PATH="${MCP_GITHUB_AUTH_PATH:-}"
EXTRA_EGRESS_HOST="${EXTRA_EGRESS_HOST:-}"

mkdir -p "${DATA_DIR}/one" "${DATA_DIR}/node" "${DATA_DIR}/run"

# Deduplicate every configured OIDC / Workload / Agent Identity issuer so both
# PolicyConfig bindings and node.yaml attenuation checks accept tokens from
# standard Google OIDC as well as Vertex AI Agent Identity pools.
ISSUERS_JSON="$(jq -cn \
  --arg oidc "${OIDC_ISSUER}" \
  --arg workload "${WORKLOAD_ISSUER}" \
  '([$oidc, $workload] | map(split(",")) | flatten | map(split("=")[0] | gsub("^\\s+|\\s+$"; "")) | map(select(length > 0)) | unique)')"
ISSUER_CHECK="$(printf '%s' "${ISSUERS_JSON}" | jq -r 'map("claim(\"iss\", " + tojson + ")") | join(" or ")')"

# Render PolicyConfig from template (fail-closed if any required var is empty).
jq -n \
  --arg member "${ALLOWED_MEMBER}" \
  --argjson issuers "${ISSUERS_JSON}" \
  --arg extra_host "${EXTRA_EGRESS_HOST}" \
  --slurpfile tmpl /etc/agentmesh/policy.json.tmpl \
  '$tmpl[0]
   | .bindings = (
       (.bindings | map(select(.role != "agw-github-agent")))
       + ($issuers | map({"role": "agw-github-agent", "members": [$member], "claims": {"iss": .}}))
     )
   | if $extra_host != "" then .egress += [{"name": $extra_host, "served_by": ["role=agent-gateway-pep"]}] else . end' \
  >"${DATA_DIR}/run/policy.json"

# Render node.yaml from template.
{
  while IFS= read -r line || [ -n "${line}" ]; do
    line="${line//__ISSUER_CHECK__/${ISSUER_CHECK}}"
    line="${line//__MCP_GITHUB_URL__/${MCP_GITHUB_URL}}"
    printf '%s\n' "${line}"
  done </etc/agentmesh/node.yaml.tmpl
  if [ -n "${MCP_GITHUB_AUTH_PATH}" ] && [ -f "${MCP_GITHUB_AUTH_PATH}" ]; then
    printf '    target_auth_path: "%s"\n' "${MCP_GITHUB_AUTH_PATH}"
  fi
} >"${DATA_DIR}/run/node.yaml"

# Generate ephemeral loopback-only admin & sidecar tokens (never passed as CLI flags).
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"${DATA_DIR}/run/admin.token"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"${DATA_DIR}/run/node.token"
chmod 600 "${DATA_DIR}/run/admin.token" "${DATA_DIR}/run/node.token"

cleanup() {
  if [ -n "${ONE_PID:-}" ]; then
    kill "${ONE_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "[entrypoint] Starting agentmesh-one on 127.0.0.1:${CP_PORT} (issuer=${OIDC_ISSUER}, aud=${ALLOWED_AUDIENCE})"
agentmesh-one \
  --bind-address="127.0.0.1" \
  --port="${CP_PORT}" \
  --external-url="http://127.0.0.1:${CP_PORT}" \
  --data-dir="${DATA_DIR}/one" \
  --admin-token-path="${DATA_DIR}/run/admin.token" \
  --issuer="${OIDC_ISSUER}" \
  --workload-issuer="${WORKLOAD_ISSUER}" \
  --allowed-audiences="${ALLOWED_AUDIENCE}" \
  --control-plane-biscuit-ttl=15m \
  --no-join-token \
  --policy-file="${DATA_DIR}/run/policy.json" \
  --router-allow-loopback=true &
ONE_PID=$!

for _ in $(seq 1 80); do
  if ! kill -0 "${ONE_PID}" 2>/dev/null; then
    echo "[entrypoint] ERROR: agentmesh-one exited unexpectedly" >&2
    exit 1
  fi
  if curl --noproxy '*' -sf "http://127.0.0.1:${CP_PORT}/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl --noproxy '*' -sf "http://127.0.0.1:${CP_PORT}/readyz" >/dev/null

# Enroll the PEP node on first start (or reuse persisted identity if mounted).
if [ ! -f "${DATA_DIR}/node/identity.bin" ]; then
  ADMIN_TOKEN="$(cat "${DATA_DIR}/run/admin.token")"
  BT_JSON="$(curl --noproxy '*' -sf -X POST "http://127.0.0.1:${CP_PORT}/admin/bootstrap-tokens" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"role":"mesh:role:node","ttl_hours":1,"max_usages":1,"description":"gcp-agent-gateway-pep"}')"
  printf '%s' "${BT_JSON}" | jq -r '.token' >"${DATA_DIR}/run/node.bootstrap"
  chmod 600 "${DATA_DIR}/run/node.bootstrap"

  echo "[entrypoint] Enrolling agentmesh-node PEP into local control plane"
  agentmesh-node join "http://127.0.0.1:${CP_PORT}" \
    --bootstrap-token-path="${DATA_DIR}/run/node.bootstrap" \
    --config="${DATA_DIR}/run/node.yaml" \
    --data-dir="${DATA_DIR}/node" \
    --allow-loopback
  rm -f "${DATA_DIR}/run/node.bootstrap"
fi

echo "[entrypoint] Starting agentmesh-node Service Extension PEP on 0.0.0.0:${PORT}"
exec agentmesh-node run \
  --bind-addr="0.0.0.0:${PORT}" \
  --socket-path="${DATA_DIR}/node/agentmesh.sock" \
  --api-token-path="${DATA_DIR}/run/node.token" \
  --config="${DATA_DIR}/run/node.yaml" \
  --data-dir="${DATA_DIR}/node" \
  --allow-loopback
