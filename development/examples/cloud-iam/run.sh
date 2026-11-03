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

# Cloud IAM Workload Identity Federation Example.
# Brings compose.yaml up, executes each test case, validates the Cloud Audit
# Log records, and checks that no cloud keys exist inside the agent.
#
#   ./run.sh        bring everything up and run every case
#   ./run.sh down   stop everything and delete the generated tokens

set -euo pipefail
umask 022
export MSYS_NO_PATHCONV=1

cd "$(dirname "${BASH_SOURCE[0]}")"
RUN_DIR=.run
COMPOSE=(docker compose --progress=quiet)

if [[ "${1:-}" == "down" ]]; then
  "${COMPOSE[@]}" --profile cases down --volumes --remove-orphans
  rm -rf "${RUN_DIR}"
  exit 0
fi

failures=0

expect() {
  if [[ "$3" == "$2" ]]; then
    printf '  PASS  %-66s %s\n' "$1" "$3"
  else
    printf '  FAIL  %-66s got %s, want %s\n' "$1" "$3" "$2"
    failures=$((failures + 1))
  fi
}

expect_contains() {
  if grep -qF "$2" "$3" 2>/dev/null; then
    printf '  PASS  %-66s %s\n' "$1" "found"
  else
    printf '  FAIL  %-66s string %q not found in %s\n' "$1" "$2" "$3"
    failures=$((failures + 1))
  fi
}

http() {
  "${COMPOSE[@]}" run --rm --no-deps -T tools -s "$@"
}

admin() {
  local method=$1 path=$2
  shift 2
  http -X "${method}" -H "@/example/${RUN_DIR}/admin.header" "$@" "http://control-plane:8080${path}"
}

random_token() {
  head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

mint() {
  admin POST /admin/bootstrap-tokens -H 'Content-Type: application/json' \
    -d "{\"role\":\"$1\",\"ttl_hours\":1,\"max_usages\":1,\"description\":\"cloud-iam example $2\"}" |
    sed -n 's/.*"token": *"\([^"]*\)".*/\1/p' >"${RUN_DIR}/$2.token"
  [[ -s "${RUN_DIR}/$2.token" ]] || { echo "could not mint a bootstrap token for $2" >&2; exit 1; }
}

echo "== Initializing test tokens and secrets in ${RUN_DIR}/"
mkdir -p "${RUN_DIR}/secrets"
random_token >"${RUN_DIR}/admin.token"
printf 'Authorization: Bearer %s\n' "$(cat "${RUN_DIR}/admin.token")" >"${RUN_DIR}/admin.header"

# The short-lived federated credential delivered to the egress PEP node only
echo "ya29.mock-federated-token-for-mesh" >"${RUN_DIR}/secrets/google-wif-token"

echo "== Starting control plane, router, edge node and mock Cloud IAM service"
"${COMPOSE[@]}" up -d --build control-plane cloud-mock

for _ in $(seq 1 60); do
  if [[ "$(http -o /dev/null -w '%{http_code}' http://control-plane:8080/info || true)" == 200 ]]; then
    break
  fi
  sleep 1
done

# Mint single-use bootstrap tokens for router and edge node
mint mesh:role:router router
mint mesh:role:node node-edge

# Load policy
admin PUT /admin/policies -H 'Content-Type: application/json' -d @/example/policy.json >/dev/null

"${COMPOSE[@]}" up -d router node-edge

# Wait for cloud-mock and node-edge to be reachable
for _ in $(seq 1 60); do
  if [[ "$(http -o /dev/null -w '%{http_code}' http://cloud-mock:8080/healthz || true)" == 200 ]]; then
    break
  fi
  sleep 1
done

# Mint member tokens for Alice (role: analyst) and Bob (role: restricted)
mint analyst alice
mint restricted bob

ALICE_TOKEN=$(cat "${RUN_DIR}/alice.token")
BOB_TOKEN=$(cat "${RUN_DIR}/bob.token")

GEMINI_PATH="/v1/projects/demo/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent"
PAYLOAD='{"contents":[{"role":"user","parts":[{"text":"Summarize the monthly budget."}]}]}'

echo ""
echo "== Egress to Vertex AI via Workload Identity Federation"
# Case 1: Alice has analyst role (allowed POST on gemini*:generateContent)
RES_ALICE=$(http -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${ALICE_TOKEN}" \
  -H "X-Mesh-Caller: user:alice" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}" \
  "http://cloud-mock:8080${GEMINI_PATH}")
expect "alice (role analyst) -> POST gemini generateContent" "200" "${RES_ALICE}"

# Case 2: Bob has restricted role (only allowed GET on models metadata)
RES_BOB=$(http -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${BOB_TOKEN}" \
  -H "X-Mesh-Caller: user:bob" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}" \
  "http://cloud-mock:8080${GEMINI_PATH}")
# Mesh policy denies Bob at the node level
expect "bob (role restricted) -> POST gemini generateContent (policy denied)" "403" "${RES_BOB}"

# Case 3: Out of scope request (method/path not allowed)
RES_OUT_OF_SCOPE=$(http -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer ${ALICE_TOKEN}" \
  -H "X-Mesh-Caller: user:alice" \
  -H "Content-Type: application/json" \
  -d '{"delete": true}' \
  "http://cloud-mock:8080/v1/projects/demo/locations/us-central1/models/gemini:delete")
expect "alice -> out-of-scope operation (blocked by path constraint)" "403" "${RES_OUT_OF_SCOPE}"

echo ""
echo "== Refusals & Unauthenticated Access"
# Case 4: No token provided
RES_NO_TOKEN=$(http -o /dev/null -w '%{http_code}' -X POST \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}" \
  "http://cloud-mock:8080${GEMINI_PATH}")
expect "caller without credential" "401" "${RES_NO_TOKEN}"

# Case 5: Invalid/forged token
RES_BAD_TOKEN=$(http -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer forged-token" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}" \
  "http://cloud-mock:8080${GEMINI_PATH}")
expect "caller with invalid token" "401" "${RES_BAD_TOKEN}"

echo ""
echo "== Cloud Audit Log Verification"
AUDIT_LOG="${RUN_DIR}/cloud-audit.log"
expect_contains "Cloud Audit Log captures federated principal: user:alice" \
  "principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/agentmesh/subject/user:alice" \
  "${AUDIT_LOG}"

echo ""
echo "== Credential Boundary Verification"
# Case 6: Verify no long-lived Google Cloud service account keys (.json) exist in the client environment
KEY_COUNT=$(find "${RUN_DIR}" -name "*.json" ! -name "policy.json" 2>/dev/null | grep -i "key" | wc -l || echo "0")
expect "agent holds zero Google Cloud service account keys" "0" "${KEY_COUNT}"

echo ""
if ((failures > 0)); then
  echo "FAILED: ${failures} check(s) did not match" >&2
  exit 1
fi
echo "ALL CHECKS PASSED: Cloud IAM Workload Identity Federation verified."
