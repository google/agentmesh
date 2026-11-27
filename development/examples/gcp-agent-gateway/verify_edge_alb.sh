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

# Live end-to-end verification against Topology B (Google Cloud External ALB +
# Service Extensions AuthzExtension EXT_PROC_GRPC -> agentmesh-node -> real GitHub).
#
# Usage:
#   PROJECT_ID=<your-sandbox-project> REGION=us-central1 ./verify_edge_alb.sh

set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID}"
REGION="${REGION:-us-central1}"
PEP_SERVICE="${PEP_SERVICE:-agentmesh-agw-pep}"

ALB_IP="$(gcloud compute addresses describe agentmesh-edge-alb-ip \
  --region="${REGION}" --project="${PROJECT_ID}" --format='value(address)')"
PEP_URL="$(gcloud run services describe "${PEP_SERVICE}" \
  --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"

echo "==> Obtaining real Google OIDC ID token"
ID_TOKEN="$(gcloud auth print-identity-token)"

EXP_RFC3339="$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
TAR_JSON="$(cat <<EOF
{
  "name": "tasks/gcp-agw-github-readonly",
  "display_name": "GCP Agent Gateway: Clone google/agentmesh + Read GitHub Issues Only",
  "expire_time": "${EXP_RFC3339}",
  "rules": [
    {
      "description": "Allow read-only Git Smart HTTP clone of google/agentmesh.git only",
      "allowed_services": ["egress://github.com"],
      "operation": {
        "allowed_methods": ["GET", "POST"],
        "allowed_paths": [
          "/google/agentmesh.git/info/refs",
          "/google/agentmesh.git/git-upload-pack"
        ]
      }
    },
    {
      "description": "Allow read-only GitHub MCP issue tools only",
      "allowed_services": ["mcp://github"],
      "operation": {
        "allowed_tools": ["list_issues", "issue_read", "search_issues"]
      }
    }
  ]
}
EOF
)"

echo "==> Exchanging Google OIDC JWT at ${PEP_URL}/oauth/token for sealed 10m TAR Biscuit"
SEALED_RESP="$(curl -sf -X POST "${PEP_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=${ID_TOKEN}" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
  --data-urlencode "options=${TAR_JSON}" \
  --data-urlencode "seal=true")"
SEALED_BISCUIT="$(printf '%s' "${SEALED_RESP}" | jq -r '.access_token')"
test -n "${SEALED_BISCUIT}" && [ "${SEALED_BISCUIT}" != "null" ]

STANDING_RESP="$(curl -sf -X POST "${PEP_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=${ID_TOKEN}" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:id_token")"
STANDING_BISCUIT="$(printf '%s' "${STANDING_RESP}" | jq -r '.access_token')"

TMP_WORK="$(mktemp -d)"
trap 'rm -rf "${TMP_WORK}"' EXIT

PASS=0
FAIL=0
check() {
  local label="$1" ok="$2" detail="$3"
  if [ "${ok}" = "1" ]; then
    printf '  PASS  %-48s %s\n' "${label}" "${detail}"
    PASS=$((PASS + 1))
  else
    printf '  FAIL  %-48s %s\n' "${label}" "${detail}"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "==> Running live probes through real Google Cloud ALB (${ALB_IP}) + EXT_PROC_GRPC"

# 1. Real git clone of github.com/google/agentmesh.git (ALLOW)
if GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
   git -c "http.extraHeader=X-Mesh-Biscuit: ${SEALED_BISCUIT}" \
       -c "http.extraHeader=X-Mesh-Target-Service: egress://github.com" \
       clone --depth=1 "http://${ALB_IP}/google/agentmesh.git" "${TMP_WORK}/agentmesh" >/dev/null 2>&1 \
   && [ -f "${TMP_WORK}/agentmesh/go.mod" ]; then
  HEAD_SHA="$(GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "${TMP_WORK}/agentmesh" log -1 --oneline)"
  check "1. Real git clone google/agentmesh.git" 1 "cloned (${HEAD_SHA})"
else
  check "1. Real git clone google/agentmesh.git" 0 "clone failed"
fi

# 2. Real git push attempt (POST /git-receive-pack -> DENY 403 by ext_proc)
PUSH_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  "http://${ALB_IP}/google/agentmesh.git/git-receive-pack" \
  -H "X-Mesh-Biscuit: ${SEALED_BISCUIT}" \
  -H "X-Mesh-Target-Service: egress://github.com" \
  -d '0000')"
check "2. git push (POST /git-receive-pack) denied" "$([ "${PUSH_STATUS}" = "403" ] && echo 1 || echo 0)" "HTTP ${PUSH_STATUS}"

# 3. Real clone of unapproved repository (DENY 403 by ext_proc)
OTHER_STATUS="$(curl -s -o /dev/null -w '%{http_code}' \
  "http://${ALB_IP}/kubernetes/kubernetes.git/info/refs?service=git-upload-pack" \
  -H "X-Mesh-Biscuit: ${SEALED_BISCUIT}" \
  -H "X-Mesh-Target-Service: egress://github.com")"
check "3. Unapproved repo (kubernetes/kubernetes.git)" "$([ "${OTHER_STATUS}" = "403" ] && echo 1 || echo 0)" "HTTP ${OTHER_STATUS}"

# 4. Real MCP list_issues (NO X-Mesh-Target-Service header; host-resolved mcp://github + spoofed header stripping!)
LIST_BODY="${TMP_WORK}/list.json"
LIST_STATUS="$(curl -s -o "${LIST_BODY}" -w '%{http_code}' -X POST "http://${ALB_IP}/mcp" \
  -H "Content-Type: application/json" \
  -H "X-Mesh-Biscuit: ${SEALED_BISCUIT}" \
  -H "X-Mesh-Claims: forged=true" \
  -H "X-Peer-Id: 12D3KooWSpoofed" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{"owner":"google","repo":"agentmesh"}}}')"
LIST_OK=0
if [ "${LIST_STATUS}" = "200" ] \
   && jq -e '.result.live_github_data | length > 0' "${LIST_BODY}" >/dev/null 2>&1 \
   && jq -e '.result.backend_verified_headers["X-Mesh-Task-Id"] == "tasks/gcp-agw-github-readonly"' "${LIST_BODY}" >/dev/null 2>&1 \
   && ! grep -q "forged=true" "${LIST_BODY}"; then
  LIST_OK=1
fi
check "4. MCP list_issues (real GitHub + spoof strip)" "${LIST_OK}" "HTTP ${LIST_STATUS} principal=$(jq -r '.result.backend_verified_headers["X-Mesh-Principal"] // "none"' "${LIST_BODY}" 2>/dev/null || echo err)"

# 5. Real MCP issue_read #953 (ALLOW)
READ_BODY="${TMP_WORK}/read.json"
READ_STATUS="$(curl -s -o "${READ_BODY}" -w '%{http_code}' -X POST "http://${ALB_IP}/mcp" \
  -H "Content-Type: application/json" \
  -H "X-Mesh-Biscuit: ${SEALED_BISCUIT}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"issue_read","arguments":{"owner":"google","repo":"agentmesh","issue_number":953}}}')"
READ_OK=0
if [ "${READ_STATUS}" = "200" ] && jq -e '.result.live_github_data.number == 953' "${READ_BODY}" >/dev/null 2>&1; then
  READ_OK=1
fi
check "5. MCP issue_read #953 (live GitHub API)" "${READ_OK}" "HTTP ${READ_STATUS}"

# 6. All 4 mutating GitHub MCP tools (DENY 403 by ext_proc before backend)
MUT_OK=1
MUT_SUMMARY=""
for tool in issue_write create_pull_request push_files delete_repository; do
  ST="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://${ALB_IP}/mcp" \
    -H "Content-Type: application/json" \
    -H "X-Mesh-Biscuit: ${SEALED_BISCUIT}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"${tool}\",\"arguments\":{\"owner\":\"google\",\"repo\":\"agentmesh\"}}}")"
  MUT_SUMMARY="${MUT_SUMMARY}${tool}=${ST} "
  if [ "${ST}" != "403" ]; then
    MUT_OK=0
  fi
done
check "6. Mutating MCP tools (4/4 denied by ext_proc)" "${MUT_OK}" "${MUT_SUMMARY}"

# 7. Standing unattenuated Biscuit denied (require_task_scope: true)
STAND_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://${ALB_IP}/mcp" \
  -H "Content-Type: application/json" \
  -H "X-Mesh-Biscuit: ${STANDING_BISCUIT}" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_issues","arguments":{"owner":"google","repo":"agentmesh"}}}')"
check "7. Standing Biscuit (no TAR) denied" "$([ "${STAND_STATUS}" = "403" ] && echo 1 || echo 0)" "HTTP ${STAND_STATUS}"

echo ""
echo "Summary: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
