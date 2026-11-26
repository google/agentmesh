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

# Self-contained, zero-Docker walkthrough of PolicyConfig-driven OIDC claim
# attestation (claim(k, v) including "iss" and multi-valued "amr"), structured
# PolicyBinding.claims, hard sandbox-to-workstation isolation, mandatory task
# scoping, tamper-proof gateway provenance headers, and scoped sandbox egress.
#
# Usage:
#   ./run.sh                 # automated pass/fail run
#   ./run.sh --interactive   # pause between acts for live walkthroughs

set -euo pipefail

# Everything in this example runs strictly on 127.0.0.1; ensure corporate or
# sandbox HTTP proxy variables do not intercept loopback calls.
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
export NO_PROXY="127.0.0.1,localhost"
export no_proxy="127.0.0.1,localhost"

INTERACTIVE=0
if [[ "${1:-}" == "--interactive" ]]; then
  INTERACTIVE=1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENTMESH_ONE="${REPO_ROOT}/bin/agentmesh-one"
AGENTMESH_NODE="${REPO_ROOT}/bin/agentmesh-node"
WORK_DIR="${WORK_DIR:-$(mktemp -d /tmp/agentmesh-posture-demo-XXXXXX)}"
DEMO_SERVER="${WORK_DIR}/demo-server"

IDP_PORT="${IDP_PORT:-18881}"
PARTNER_IDP_PORT="${PARTNER_IDP_PORT:-18884}"
AGENT_PORT="${AGENT_PORT:-18882}"
API_PORT="${API_PORT:-18883}"
CP_PORT="${CP_PORT:-18880}"
WS_API_PORT="${WS_API_PORT:-18890}"
GW_API_PORT="${GW_API_PORT:-18891}"

IDP_URL="http://127.0.0.1:${IDP_PORT}"
PARTNER_IDP_URL="http://127.0.0.1:${PARTNER_IDP_PORT}"
CP_URL="http://127.0.0.1:${CP_PORT}"
WS_API_URL="http://127.0.0.1:${WS_API_PORT}"
GW_API_URL="http://127.0.0.1:${GW_API_PORT}"
API_TOKEN="demo-local-sidecar-token"

PASS_COUNT=0
FAIL_COUNT=0

pause_step() {
  if [[ "${INTERACTIVE}" -eq 1 ]]; then
    echo ""
    read -r -p "  [Press ENTER to continue...] " _
    echo ""
  fi
}

cleanup() {
  for pidfile in "${WORK_DIR}"/*.pid; do
    [[ -f "${pidfile}" ]] && kill "$(cat "${pidfile}")" 2>/dev/null || true
  done
  if [[ "${KEEP_WORK_DIR:-0}" != "1" ]]; then
    rm -rf "${WORK_DIR}"
  fi
}
trap cleanup EXIT

pass() {
  printf "  PASS  %-68s %s\n" "$1" "$2"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  printf "  FAIL  %-68s %s\n" "$1" "$2" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

assert_status() {
  local label="$1" got="$2" want="$3"
  if [[ "${got}" == "${want}" ]]; then
    pass "${label}" "${got}"
  else
    fail "${label}" "got ${got}, want ${want}"
  fi
}

wait_http() {
  local url="$1" label="$2"
  for _ in $(seq 1 60); do
    if curl -sf "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "Timed out waiting for ${label} at ${url}" >&2
  exit 1
}

json_field() {
  python3 -c '
import json, sys
data = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    if isinstance(data, dict):
        data = data.get(key, "")
    else:
        data = ""
        break
print(data if data is not None else "")
' "$1"
}

mint_jwt() {
  local idp_base="$1" profile="$2"
  curl -sf "${idp_base}/mint?profile=${profile}"
}

exchange_biscuit() {
  local sidecar_url="$1" subject_jwt="$2" tar_json="${3:-}"
  local args=(
    -sf -X POST "${sidecar_url}/oauth/token"
    -H "X-Mesh-Authentication: Bearer ${API_TOKEN}"
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
    --data-urlencode "subject_token=${subject_jwt}"
    --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:id_token"
    --data-urlencode "seal=true"
  )
  if [[ -n "${tar_json}" ]]; then
    args+=(--data-urlencode "options=${tar_json}")
  fi
  curl "${args[@]}" | json_field "access_token"
}

if [[ ! -x "${AGENTMESH_ONE}" || ! -x "${AGENTMESH_NODE}" ]]; then
  echo "Building agentmesh-one and agentmesh-node..."
  make -C "${REPO_ROOT}" build >/dev/null
fi
(cd "${REPO_ROOT}" && go build -o "${DEMO_SERVER}" ./development/examples/device-posture-isolation/demo-server)

mkdir -p "${WORK_DIR}/one" "${WORK_DIR}/ws" "${WORK_DIR}/gw" "${WORK_DIR}/spoof" "${WORK_DIR}/partner" "${WORK_DIR}/secrets"
printf '%s\n' "${API_TOKEN}" > "${WORK_DIR}/api-token"
chmod 600 "${WORK_DIR}/api-token"
printf '%s\n' "demo-tools-api-secret" > "${WORK_DIR}/secrets/tools-api"
chmod 600 "${WORK_DIR}/secrets/tools-api"

sed -e "s|127.0.0.1:18881|127.0.0.1:${IDP_PORT}|g" \
    -e "s|127.0.0.1:18883|127.0.0.1:${API_PORT}|g" \
    "${SCRIPT_DIR}/policy.json" > "${WORK_DIR}/policy.json"
sed -e "s|127.0.0.1:18881|127.0.0.1:${IDP_PORT}|g" \
    -e "s|127.0.0.1:18882|127.0.0.1:${AGENT_PORT}|g" \
    "${SCRIPT_DIR}/node-workstation.yaml" > "${WORK_DIR}/node-workstation.yaml"

echo "== Booting zero-trust demo stack (100% loopback, zero claim CLI flags)"
"${DEMO_SERVER}" \
  --idp-addr "127.0.0.1:${IDP_PORT}" \
  --partner-idp-addr "127.0.0.1:${PARTNER_IDP_PORT}" \
  --agent-addr "127.0.0.1:${AGENT_PORT}" \
  --api-addr "127.0.0.1:${API_PORT}" \
  --expected-secret "demo-tools-api-secret" \
  >"${WORK_DIR}/demo-server.log" 2>&1 &
echo $! > "${WORK_DIR}/demo-server.pid"
wait_http "${IDP_URL}/healthz" "primary OIDC IdP"
wait_http "${PARTNER_IDP_URL}/healthz" "partner OIDC IdP"

"${AGENTMESH_ONE}" \
  --bind-address 127.0.0.1 \
  --port "${CP_PORT}" \
  --data-dir "${WORK_DIR}/one" \
  --no-join-token \
  --enroll-qr=false \
  --policy-file "${WORK_DIR}/policy.json" \
  --issuer "${IDP_URL},${PARTNER_IDP_URL}" \
  --workload-issuer "${IDP_URL}=.workloads.corp.example" \
  --allowed-audiences agentmesh-audience \
  --control-plane-biscuit-ttl 15m \
  >"${WORK_DIR}/one.log" 2>&1 &
echo $! > "${WORK_DIR}/one.pid"
wait_http "${CP_URL}/readyz" "agentmesh-one"

mint_jwt "${IDP_URL}" workstation > "${WORK_DIR}/ws.jwt"
mint_jwt "${IDP_URL}" gateway > "${WORK_DIR}/gw.jwt"
chmod 600 "${WORK_DIR}/ws.jwt" "${WORK_DIR}/gw.jwt"

"${AGENTMESH_NODE}" run \
  --control-plane "${CP_URL}" \
  --jwt-path "${WORK_DIR}/ws.jwt" \
  --config "${WORK_DIR}/node-workstation.yaml" \
  --data-dir "${WORK_DIR}/ws" \
  --listen /ip4/127.0.0.1/tcp/0 \
  --bind-addr "127.0.0.1:${WS_API_PORT}" \
  --api-token-path "${WORK_DIR}/api-token" \
  --allow-loopback \
  --discovery-interval 200ms \
  --control-plane-sync-interval 2s \
  >"${WORK_DIR}/ws-node.log" 2>&1 &
echo $! > "${WORK_DIR}/ws-node.pid"

"${AGENTMESH_NODE}" run \
  --control-plane "${CP_URL}" \
  --jwt-path "${WORK_DIR}/gw.jwt" \
  --config "${SCRIPT_DIR}/node-gateway.yaml" \
  --data-dir "${WORK_DIR}/gw" \
  --listen /ip4/127.0.0.1/tcp/0 \
  --bind-addr "127.0.0.1:${GW_API_PORT}" \
  --api-token-path "${WORK_DIR}/api-token" \
  --secrets-dir "${WORK_DIR}/secrets" \
  --allow-loopback \
  --discovery-interval 200ms \
  --control-plane-sync-interval 2s \
  >"${WORK_DIR}/gw-node.log" 2>&1 &
echo $! > "${WORK_DIR}/gw-node.pid"

wait_http "${WS_API_URL}/readyz" "workstation agentmesh-node"
wait_http "${GW_API_URL}/readyz" "egress gateway agentmesh-node"

WS_PEER_ID="$(curl -sf -H "X-Mesh-Authentication: Bearer ${API_TOKEN}" "${WS_API_URL}/debug/mesh-info" | json_field "peer_id")"
GW_PEER_ID="$(curl -sf -H "X-Mesh-Authentication: Bearer ${API_TOKEN}" "${GW_API_URL}/debug/mesh-info" | json_field "peer_id")"
echo "  Control Plane / Router : ${CP_URL}"
echo "  Primary IdP (corp)     : ${IDP_URL}"
echo "  Secondary IdP (partner): ${PARTNER_IDP_URL}"
echo "  Workstation PEP PeerID : ${WS_PEER_ID} (local API ${WS_API_URL})"
echo "  Egress Gateway PeerID  : ${GW_PEER_ID} (local API ${GW_API_URL})"
pause_step

echo ""
echo "== Act 1: Structural Anti-Spoofing & Issuer Pinning (claim() != label())"
mint_jwt "${IDP_URL}" mobile-unmanaged > "${WORK_DIR}/unmanaged.jwt"
mint_jwt "${PARTNER_IDP_URL}" workstation > "${WORK_DIR}/partner-ws.jwt"
chmod 600 "${WORK_DIR}/unmanaged.jwt" "${WORK_DIR}/partner-ws.jwt"

if "${AGENTMESH_NODE}" run \
  --control-plane "${CP_URL}" \
  --jwt-path "${WORK_DIR}/unmanaged.jwt" \
  --config "${SCRIPT_DIR}/node-spoof.yaml" \
  --data-dir "${WORK_DIR}/spoof" \
  --listen /ip4/127.0.0.1/tcp/0 \
  --bind-addr "" \
  --socket-path "" \
  --allow-loopback \
  >"${WORK_DIR}/spoof.log" 2>&1; then
  fail "Unmanaged device declaring spoofed labels refused at /register" "unexpectedly succeeded"
else
  pass "Unmanaged device declaring spoofed labels refused at /register" "403 (label != claim)"
fi

if "${AGENTMESH_NODE}" run \
  --control-plane "${CP_URL}" \
  --jwt-path "${WORK_DIR}/partner-ws.jwt" \
  --config "${WORK_DIR}/node-workstation.yaml" \
  --data-dir "${WORK_DIR}/partner" \
  --listen /ip4/127.0.0.1/tcp/0 \
  --bind-addr "" \
  --socket-path "" \
  --allow-loopback \
  >"${WORK_DIR}/partner.log" 2>&1; then
  fail "Partner IdP asserting workstation posture refused by iss binding" "unexpectedly succeeded"
else
  pass "Partner IdP asserting workstation posture refused by iss binding" "403 (iss mismatch)"
fi
pause_step

EXP_10M="$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
WS_TAR="{\"name\":\"mobile-status-check\",\"expire_time\":\"${EXP_10M}\",\"rules\":[{\"allowed_services\":[\"a2a://dev-agent\"],\"operation\":{\"allowed_methods\":[\"POST\"],\"allowed_paths\":[\"/tasks/*\"]}}]}"
API_TAR="{\"name\":\"sandbox-read-tools\",\"expire_time\":\"${EXP_10M}\",\"rules\":[{\"allowed_services\":[\"egress://api.tools.example\"],\"operation\":{\"allowed_methods\":[\"GET\"],\"allowed_paths\":[\"/v1/*\"]}}]}"

MOBILE_MANAGED_JWT="$(mint_jwt "${IDP_URL}" mobile-managed)"
PARTNER_MOBILE_JWT="$(mint_jwt "${PARTNER_IDP_URL}" mobile-managed)"
MOBILE_WORK_PROFILE_JWT="$(mint_jwt "${IDP_URL}" mobile-work-profile)"
MOBILE_UNMANAGED_JWT="$(mint_jwt "${IDP_URL}" mobile-unmanaged)"
SANDBOX_JWT="$(mint_jwt "${IDP_URL}" sandbox)"

MOBILE_MANAGED_TASK_BISCUIT="$(exchange_biscuit "${WS_API_URL}" "${MOBILE_MANAGED_JWT}" "${WS_TAR}")"
MOBILE_MANAGED_STANDING_BISCUIT="$(exchange_biscuit "${WS_API_URL}" "${MOBILE_MANAGED_JWT}")"
PARTNER_MOBILE_BISCUIT="$(exchange_biscuit "${WS_API_URL}" "${PARTNER_MOBILE_JWT}" "${WS_TAR}")"
MOBILE_WORK_PROFILE_BISCUIT="$(exchange_biscuit "${WS_API_URL}" "${MOBILE_WORK_PROFILE_JWT}" "${WS_TAR}")"
MOBILE_UNMANAGED_BISCUIT="$(exchange_biscuit "${WS_API_URL}" "${MOBILE_UNMANAGED_JWT}" "${WS_TAR}")"
SANDBOX_WS_BISCUIT="$(exchange_biscuit "${GW_API_URL}" "${SANDBOX_JWT}" "${WS_TAR}")"
SANDBOX_API_BISCUIT="$(exchange_biscuit "${GW_API_URL}" "${SANDBOX_JWT}" "${API_TAR}")"

WANT_CLAIMS="amr=hwk,amr=mfa,device.management=fully_managed,device.trust_tier=high,device.type=managed_mobile,iss=${IDP_URL}"

echo ""
echo "== Act 2: Trusted Posture + Multi-Valued amr + Sealed TAR + Provenance"
INGRESS_URL="${CP_URL}/ingress/${WS_PEER_ID}/a2a/dev-agent/tasks/run"
INGRESS_STATUS="000"
for _ in $(seq 1 40); do
  INGRESS_STATUS="$(curl -s -o "${WORK_DIR}/ingress-ok.json" -w "%{http_code}" -X POST "${INGRESS_URL}" \
    -H "Authorization: Bearer ${MOBILE_MANAGED_TASK_BISCUIT}" \
    -H "X-Mesh-Origin: spoofed-local" \
    -H "X-Mesh-Claims: device.trust_tier=forged" \
    -H "X-Mesh-Spoofed: attacker" \
    -d '{"prompt":"summarize build status"}')"
  if [[ "${INGRESS_STATUS}" == "200" ]]; then
    break
  fi
  sleep 0.25
done
assert_status "Fully managed high-trust mobile + hwk + 10m TAR -> /ingress" "${INGRESS_STATUS}" "200"

GOT_ORIGIN="$(json_field "provenance.X-Mesh-Origin" < "${WORK_DIR}/ingress-ok.json")"
GOT_CLAIMS="$(json_field "provenance.X-Mesh-Claims" < "${WORK_DIR}/ingress-ok.json")"
GOT_PRINCIPAL="$(json_field "provenance.X-Mesh-Principal" < "${WORK_DIR}/ingress-ok.json")"
GOT_TASK="$(json_field "provenance.X-Mesh-Task" < "${WORK_DIR}/ingress-ok.json")"
GOT_SPOOFED="$(json_field "provenance.X-Mesh-Spoofed" < "${WORK_DIR}/ingress-ok.json")"

if [[ "${GOT_ORIGIN}" == "mesh-external-ingress" && "${GOT_PRINCIPAL}" == "alice@corp.example" && "${GOT_TASK}" == "mobile-status-check" && -z "${GOT_SPOOFED}" && "${GOT_CLAIMS}" == "${WANT_CLAIMS}" ]]; then
  pass "Spoofed X-Mesh-* stripped; verified X-Mesh-Claims stamped" "origin=${GOT_ORIGIN}"
else
  fail "Spoofed X-Mesh-* stripped; verified X-Mesh-Claims stamped" "origin=${GOT_ORIGIN} claims=${GOT_CLAIMS} spoofed=${GOT_SPOOFED}"
fi

EXT_STATUS="$(curl -s -D "${WORK_DIR}/ext-ok.hdr" -o /dev/null -w "%{http_code}" -X POST "${WS_API_URL}/ext_authz/a2a/dev-agent/tasks/run" \
  -H "Authorization: Bearer ${MOBILE_MANAGED_TASK_BISCUIT}")"
assert_status "Fully managed high-trust mobile + hwk + 10m TAR -> /ext_authz" "${EXT_STATUS}" "200"
if grep -qi "^X-Mesh-Origin: mesh-gateway" "${WORK_DIR}/ext-ok.hdr" && grep -qi "^X-Mesh-Claims: ${WANT_CLAIMS}" "${WORK_DIR}/ext-ok.hdr"; then
  pass "ext_authz stamps X-Mesh-Origin & X-Mesh-Claims" "mesh-gateway"
else
  fail "ext_authz stamps X-Mesh-Origin & X-Mesh-Claims" "missing headers"
fi
pause_step

echo ""
echo "== Act 3: Standing Credentials, Wrong Issuer & Lower-Trust Devices Refused"
S_STANDING="$(curl -s -o /dev/null -w "%{http_code}" -X POST "${INGRESS_URL}" -H "Authorization: Bearer ${MOBILE_MANAGED_STANDING_BISCUIT}" -d '{}')"
S_PARTNER="$(curl -s -o /dev/null -w "%{http_code}" -X POST "${INGRESS_URL}" -H "Authorization: Bearer ${PARTNER_MOBILE_BISCUIT}" -d '{}')"
S_WORKPROF="$(curl -s -o /dev/null -w "%{http_code}" -X POST "${INGRESS_URL}" -H "Authorization: Bearer ${MOBILE_WORK_PROFILE_BISCUIT}" -d '{}')"
S_UNMANAGED="$(curl -s -o /dev/null -w "%{http_code}" -X POST "${INGRESS_URL}" -H "Authorization: Bearer ${MOBILE_UNMANAGED_BISCUIT}" -d '{}')"
assert_status "Standing high-trust token without TAR (require_task_scope)" "${S_STANDING}" "403"
assert_status "Partner issuer asserting posture (blocked by iss claim)" "${S_PARTNER}" "403"
assert_status "Work-profile mobile (denied by PolicyBinding + Datalog)" "${S_WORKPROF}" "403"
assert_status "Unmanaged mobile (denied by PolicyBinding + Datalog)" "${S_UNMANAGED}" "403"
pause_step

echo ""
echo "== Act 4: Hard Sandbox-to-Workstation Isolation Wall"
S_SANDBOX_ING="$(curl -s -o /dev/null -w "%{http_code}" -X POST "${INGRESS_URL}" -H "Authorization: Bearer ${SANDBOX_WS_BISCUIT}" -d '{}')"
S_SANDBOX_EXT="$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WS_API_URL}/ext_authz/a2a/dev-agent/tasks/run" -H "Authorization: Bearer ${SANDBOX_WS_BISCUIT}")"
assert_status "Isolated sandbox (workload.env=sandbox) -> workstation /ingress" "${S_SANDBOX_ING}" "403"
assert_status "Isolated sandbox (workload.env=sandbox) -> workstation /ext_authz" "${S_SANDBOX_EXT}" "403"
pause_step

echo ""
echo "== Act 5: Scoped Sandbox Egress to Approved Tool API via Egress Gateway"
EGRESS_STATUS="000"
for _ in $(seq 1 40); do
  EGRESS_STATUS="$(curl -s -o "${WORK_DIR}/egress-ok.json" -w "%{http_code}" \
    -H "X-Mesh-Authentication: Bearer ${SANDBOX_API_BISCUIT}" \
    -H "X-Mesh-Claims: workload.env=spoofed" \
    "${GW_API_URL}/egress/api.tools.example/v1/projects")"
  if [[ "${EGRESS_STATUS}" == "200" ]]; then
    break
  fi
  sleep 0.25
done
assert_status "Isolated sandbox + 10m TAR -> egress://api.tools.example" "${EGRESS_STATUS}" "200"

CRED_OK="$(json_field "credential_injected" < "${WORK_DIR}/egress-ok.json")"
EG_PRIN="$(json_field "forwarded_context.X-Mesh-Principal" < "${WORK_DIR}/egress-ok.json")"
EG_CLAIMS="$(json_field "forwarded_context.X-Mesh-Claims" < "${WORK_DIR}/egress-ok.json")"
if [[ "${CRED_OK}" == "True" && "${EG_PRIN}" == "bot-alice@bots.workloads.corp.example" && "${EG_CLAIMS}" == "iss=${IDP_URL},workload.env=sandbox" ]]; then
  pass "Gateway injects secret & forwards attested sandbox claims" "principal=${EG_PRIN}"
else
  fail "Gateway injects secret & forwards attested sandbox claims" "cred=${CRED_OK} principal=${EG_PRIN} claims=${EG_CLAIMS}"
fi

EGRESS_DENY="$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "X-Mesh-Authentication: Bearer ${SANDBOX_API_BISCUIT}" \
  "${GW_API_URL}/egress/api.tools.example/v1/projects" -d '{}')"
assert_status "Sandbox POST /v1/projects blocked by GET-only TAR" "${EGRESS_DENY}" "403"

echo ""
echo "================================================================================"
echo "  Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
echo "================================================================================"
if [[ "${FAIL_COUNT}" -ne 0 ]]; then
  exit 1
fi
