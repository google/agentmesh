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

# kgateway with mesh authorization in a kind cluster. Sets everything up and
# runs the cases in README.md.
#
#   ./run.sh        create everything and run every case
#   ./run.sh down   delete the kind cluster and the generated tokens

set -euo pipefail
# Tokens below only end up in secrets.
umask 077

cd "$(dirname "${BASH_SOURCE[0]}")"
PROJECT_ROOT=$(cd ../../.. && pwd)
RUN_DIR=.run
CLUSTER=agentmesh-kgateway
K=(kubectl --context "kind-${CLUSTER}")
GATEWAY_API_VERSION=v1.6.1
KGATEWAY_VERSION=v2.4.7

if [[ "${1:-}" == "down" ]]; then
  kind delete cluster --name "${CLUSTER}"
  rm -rf "${RUN_DIR}"
  exit 0
fi

for bin in kind kubectl helm docker make; do
  command -v "${bin}" >/dev/null 2>&1 || { echo "missing prerequisite: ${bin}" >&2; exit 1; }
done
if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
  echo "kind cluster '${CLUSTER}' already exists; remove it first: ./run.sh down" >&2
  exit 1
fi

failures=0

# expect NAME WANT GOT prints one result line and counts a mismatch.
expect() {
  if [[ "$3" == "$2" ]]; then
    printf '  PASS  %-66s %s\n' "$1" "$3"
  else
    printf '  FAIL  %-66s got %s, want %s\n' "$1" "$3" "$2"
    failures=$((failures + 1))
  fi
}

# http runs curl in the client pod, where the users' tokens are kept.
http() {
  "${K[@]}" -n apps exec client -- curl -s "$@"
}

# admin calls the control plane's admin API.
admin() {
  local method=$1 path=$2
  shift 2
  http -X "${method}" -H @/run/example/admin.header "$@" "http://control-plane.mesh:8080${path}"
}

random_token() {
  head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# mint ROLE NAME writes a single-use bootstrap token for ROLE to .run/NAME.token.
mint() {
  admin POST /admin/bootstrap-tokens -H 'Content-Type: application/json' \
    -d "{\"role\":\"$1\",\"ttl_hours\":1,\"max_usages\":1,\"description\":\"kgateway example $2\"}" |
    sed -n 's/.*"token": *"\([^"]*\)".*/\1/p' >"${RUN_DIR}/$2.token"
  [[ -s "${RUN_DIR}/$2.token" ]] || { echo "could not mint a bootstrap token for $2" >&2; exit 1; }
}

# node_secret NAMESPACE NAME creates the NAME-tokens secret for node NAME.
node_secret() {
  "${K[@]}" -n "$1" create secret generic "$2-tokens" --dry-run=client -o yaml \
    --from-file=bootstrap.token="${RUN_DIR}/$2.token" --from-file=api.token="${RUN_DIR}/$2-api.token" |
    "${K[@]}" apply -f - >/dev/null
  restart "$1" "$2"
}

# restart NAMESPACE DEPLOYMENT: a pod waiting for a missing secret can take
# up to two minutes to retry, a new pod picks it up right away.
restart() {
  "${K[@]}" -n "$1" rollout restart "deploy/$2" >/dev/null
}

# id_token USER CLIENT logs USER in from the client pod and writes the
# Authorization header to /tmp/USER.CLIENT.header there. The password grant
# is only so the script runs unattended.
id_token() {
  # shellcheck disable=SC2016 # expanded by the shell in the pod
  "${K[@]}" -n apps exec client -- sh -c '
    jwt=$(curl -s -d grant_type=password -d "client_id=$2" -d "username=$1" -d "password=$1-test-only" \
      -d scope=openid http://keycloak.mesh:8080/realms/mesh/protocol/openid-connect/token |
      sed -n "s/.*\"id_token\":\"\([^\"]*\)\".*/\1/p")
    [ -n "${jwt}" ] && printf "Authorization: Bearer %s\n" "${jwt}" >"/tmp/$1.$2.header"' \
    sh "$1" "$2" || { echo "no ID token for $1, client $2" >&2; exit 1; }
}

# wait_log NAMESPACE DEPLOYMENT TEXT waits for TEXT in the deployment's logs.
wait_log() {
  for _ in $(seq 1 90); do
    if "${K[@]}" -n "$1" logs "deploy/$2" 2>/dev/null | grep -qF "$3"; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for \"$3\" from $1/$2" >&2
  "${K[@]}" -n "$1" logs --tail 20 "deploy/$2" >&2
  exit 1
}

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"kgateway-example","version":"0"}}}'
GATEWAY=http://apps-gateway.apps:8080
MCP_HEADERS=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')

# initialize URL [HEADER] sends an MCP initialize and prints the status.
initialize() {
  local auth=()
  [[ -z "${2:-}" ]] || auth=(-H "@/tmp/$2.header")
  http -o /dev/null -w '%{http_code}' -X POST ${auth[@]+"${auth[@]}"} "${MCP_HEADERS[@]}" \
    --data "${INIT}" "$1"
}

# call_tool URL HEADER TOOL ARGS calls TOOL in a new MCP session and prints
# the status, plus the result text on success.
call_tool() {
  local auth=(-H "@/tmp/$2.header") id out code
  id=$(http -o /dev/null -D - -X POST "${auth[@]}" "${MCP_HEADERS[@]}" --data "${INIT}" "$1" |
    tr -d '\r' | sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *//p')
  [[ -n "${id}" ]] || { echo "no session"; return; }
  http -o /dev/null -X POST "${auth[@]}" "${MCP_HEADERS[@]}" -H "Mcp-Session-Id: ${id}" \
    --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$1"
  out=$(http -w '\n%{http_code}' -X POST "${auth[@]}" "${MCP_HEADERS[@]}" -H "Mcp-Session-Id: ${id}" \
    --data "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$3\",\"arguments\":$4}}" "$1")
  code=$(tail -n 1 <<<"${out}")
  if [[ "${code}" == 200 ]]; then
    echo "${code} $(sed -n 's/.*"text":"\([^"]*\)".*/\1/p' <<<"${out}" | head -n 1)"
  else
    echo "${code}"
  fi
}

rm -rf "${RUN_DIR}"
mkdir -p "${RUN_DIR}"

echo "== Creating the kind cluster '${CLUSTER}'"
kind create cluster --name "${CLUSTER}" --wait 120s >"${RUN_DIR}/kind.log" 2>&1 || {
  echo "Failed to create kind cluster. Log:" >&2
  cat "${RUN_DIR}/kind.log" >&2
  exit 1
}

echo "== Installing Gateway API ${GATEWAY_API_VERSION} and kgateway ${KGATEWAY_VERSION}"
"${K[@]}" apply --server-side -f \
  "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml" >/dev/null
for chart in kgateway-crds kgateway; do
  helm --kube-context "kind-${CLUSTER}" upgrade -i --create-namespace --namespace kgateway-system \
    --version "${KGATEWAY_VERSION}" --wait "${chart}" "oci://cr.kgateway.dev/kgateway-dev/charts/${chart}" >"${RUN_DIR}/helm-${chart}.log" 2>&1 || {
      echo "Failed to install helm chart ${chart}. Log:" >&2
      cat "${RUN_DIR}/helm-${chart}.log" >&2
      exit 1
    }
done

# The published control plane and router images are amd64 only.
echo "== Building the agentmesh images and the two MCP servers (log: ${RUN_DIR}/build.log)"
{
  make -C "${PROJECT_ROOT}" --no-print-directory docker-build-control-plane docker-build-router docker-build-node
  docker build -t agentmesh-kgateway/calc-mcp:local ../calc-mcp
  docker build -t agentmesh-kgateway/greeter-mcp:local ../greeter-mcp
  kind load docker-image --name "${CLUSTER}" agentmesh-control-plane:local agentmesh-router:local agentmesh-node:local \
    agentmesh-kgateway/calc-mcp:local agentmesh-kgateway/greeter-mcp:local
} >"${RUN_DIR}/build.log" 2>&1 || { tail -n 20 "${RUN_DIR}/build.log" >&2; exit 1; }

echo "== Generating test-only tokens in ${RUN_DIR}/"
random_token >"${RUN_DIR}/admin.token"
printf 'Authorization: Bearer %s\n' "$(cat "${RUN_DIR}/admin.token")" >"${RUN_DIR}/admin.header"
for name in provider mesh-node; do
  random_token >"${RUN_DIR}/${name}-api.token"
done

echo "== Starting Keycloak and the control plane"
# Pods start as their secrets show up.
"${K[@]}" apply -f mesh.yaml -f remote.yaml -f apps.yaml >/dev/null
"${K[@]}" -n mesh create configmap keycloak-realm --from-file=realm-mesh.json >/dev/null
"${K[@]}" -n mesh create secret generic control-plane-admin --from-file=admin.token="${RUN_DIR}/admin.token" >/dev/null
"${K[@]}" -n apps create secret generic client-admin --from-file=admin.header="${RUN_DIR}/admin.header" >/dev/null
"${K[@]}" -n mesh rollout status deploy/keycloak --timeout=300s >/dev/null
# The control plane may restart a few times until Keycloak is up.
"${K[@]}" -n mesh rollout status deploy/control-plane --timeout=300s >/dev/null
"${K[@]}" -n apps wait --for=condition=Ready pod/client --timeout=120s >/dev/null

echo "== Loading the mesh policy (calc-user to group:devs, greeter-user to group:ops)"
expect "load policy.json" 200 "$(admin POST /policies -H 'Content-Type: application/json' \
  --data-binary "$(cat policy.json)" -o /dev/null -w '%{http_code}')"

echo "== Starting the router, the provider of mcp://calc and the node next to kgateway"
mint mesh:role:router router
"${K[@]}" -n mesh create secret generic router-bootstrap --from-file=bootstrap.token="${RUN_DIR}/router.token" >/dev/null
restart mesh router
# Nodes exit if they enroll before the router has a lease.
wait_log mesh router 'Lease advertises'
mint mesh:role:node provider
node_secret remote provider
mint mesh:role:node mesh-node
node_secret mesh mesh-node
wait_log remote provider 'Registered and announced SERVICE_TYPE_MCP/calc'
"${K[@]}" -n mesh rollout status deploy/mesh-node --timeout=180s >/dev/null
"${K[@]}" -n remote rollout status deploy/provider --timeout=180s >/dev/null
PROVIDER=$("${K[@]}" -n remote logs deploy/provider 2>/dev/null | sed -n 's/.*PeerID: \(12D3KooW[1-9A-HJ-NP-Za-km-z]*\).*/\1/p' | head -n 1)
[[ -n "${PROVIDER}" ]] || { echo "could not read the provider's peer ID" >&2; exit 1; }

echo "== Adding the mesh to kgateway: the ext_authz extension, its policy and the routes"
sed "s/__PROVIDER__/${PROVIDER}/g" gateway.yaml | "${K[@]}" apply -f - >/dev/null
"${K[@]}" -n apps wait --for=condition=Programmed gateway/apps-gateway --timeout=180s >/dev/null
"${K[@]}" -n apps rollout status deploy/apps-gateway --timeout=180s >/dev/null
gateway_ready=false
for _ in $(seq 1 60); do
  # A 401 means kgateway asked the node and the node said no.
  if [[ "$(initialize "${GATEWAY}/mcp/greeter" || true)" == 401 ]]; then
    gateway_ready=true
    break
  fi
  sleep 2
done
if [[ "${gateway_ready}" == false ]]; then
  echo "kgateway did not route /mcp/greeter through the node's ext_authz within 120s" >&2
  exit 1
fi

echo "== Tokens from Keycloak, kept in the client pod"
id_token alice agentmesh
id_token bob agentmesh
id_token alice other-app
printf 'Authorization: Bearer %s\n' "$(cat "${RUN_DIR}/mesh-node-api.token")" |
  "${K[@]}" -n apps exec -i client -- sh -c 'cat >/tmp/mesh-node-own.header'

echo
echo "== kgateway routes, the node decides"
expect "alice -> /mcp/calc, through the mesh (calc-user)" 200 "$(initialize "${GATEWAY}/mcp/calc" alice.agentmesh)"
expect "alice calls add" "200 5.0" "$(call_tool "${GATEWAY}/mcp/calc" alice.agentmesh add '{"a":2,"b":3}')"
expect "alice -> /mcp/greeter (no greeter-user)" 403 "$(initialize "${GATEWAY}/mcp/greeter" alice.agentmesh)"
expect "bob -> /mcp/greeter, a local backend (greeter-user)" 200 "$(initialize "${GATEWAY}/mcp/greeter" bob.agentmesh)"
expect "bob calls hello" "200 Hello, bob!" "$(call_tool "${GATEWAY}/mcp/greeter" bob.agentmesh hello '{"name":"bob"}')"
expect "bob -> /mcp/calc (no calc-user)" 403 "$(initialize "${GATEWAY}/mcp/calc" bob.agentmesh)"

echo
echo "== Refused by the node's ext_authz"
expect "no token" 401 "$(initialize "${GATEWAY}/mcp/greeter")"
expect "alice, token for client other-app (audience)" 403 "$(initialize "${GATEWAY}/mcp/greeter" alice.other-app)"
expect "the node's own API token" 403 "$(initialize "${GATEWAY}/mcp/greeter" mesh-node-own)"

# Grab the node's logs now, the pod is deleted below.
node_audit=$("${K[@]}" -n mesh logs deploy/mesh-node | grep -F 'Audit Traceability' | grep -F '"protocol": "ext_authz"' || true)

echo
echo "== Fail closed: the node goes away"
"${K[@]}" -n mesh scale deploy/mesh-node --replicas=0 >/dev/null
"${K[@]}" -n mesh wait --for=delete pod -l app=mesh-node --timeout=120s >/dev/null
expect "the greeter itself, from inside the cluster" 200 "$(initialize http://greeter.apps:7778/mcp)"
expect "bob -> /mcp/greeter, node unreachable" 503 "$(initialize "${GATEWAY}/mcp/greeter" bob.agentmesh)"
expect "alice -> /mcp/calc, node unreachable" 503 "$(initialize "${GATEWAY}/mcp/calc" alice.agentmesh)"
# The node's identity was in an emptyDir, so it needs a new bootstrap token.
mint mesh:role:node mesh-node
node_secret mesh mesh-node
"${K[@]}" -n mesh scale deploy/mesh-node --replicas=1 >/dev/null
"${K[@]}" -n mesh rollout status deploy/mesh-node --timeout=180s >/dev/null
expect "bob -> /mcp/greeter, node back" 200 "$(initialize "${GATEWAY}/mcp/greeter" bob.agentmesh)"
expect "alice -> /mcp/calc, node back" 200 "$(initialize "${GATEWAY}/mcp/calc" alice.agentmesh)"

echo
echo "== Where each decision is logged"
echo "-- node next to kgateway: its ext_authz decisions, with the caller's identity"
grep -F '"decision": "allow"' <<<"${node_audit}" | tail -n 1 | sed 's/^/   /' || true
grep -F '"decision": "deny"' <<<"${node_audit}" | tail -n 1 | sed 's/^/   /' || true
echo "-- control plane: a token it would not exchange"
"${K[@]}" -n mesh logs deploy/control-plane | grep -F 'Border Crossing' | grep -F '"decision": "deny"' |
  tail -n 1 | sed 's/^/   /' || true
echo "-- provider: the call that crossed the mesh, checked again"
"${K[@]}" -n remote logs deploy/provider | grep -F 'Audit Traceability' | tail -n 1 | sed 's/^/   /' || true

echo
if [[ "${failures}" -eq 0 ]]; then
  echo "All cases passed. The cluster is still running; ./run.sh down removes it."
else
  echo "${failures} case(s) failed. The cluster is still running for inspection; ./run.sh down removes it."
  exit 1
fi
