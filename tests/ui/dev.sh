#!/bin/bash
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
#
# Runs the console against a real control plane, seeded with a router and a node
# so the dashboard has something in it, and leaves it up until Ctrl-C. Everything
# is a local process against a throwaway sqlite DB: no docker, no kind, no
# postgres. Static assets are served from the working tree, so editing the HTML,
# CSS or JS only needs a browser refresh.
#
# Usage: make ui-dev   (or tests/ui/dev.sh)

set -o errexit
set -o nounset
set -o pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib/stack.sh"
cd "${REPO_ROOT}"

trap stack_cleanup EXIT INT TERM

for binary in sam-control-plane sam-console sam-router sam-node; do
  if [[ ! -x "${REPO_ROOT}/bin/${binary}" ]]; then
    echo "missing ${REPO_ROOT}/bin/${binary}; run 'make build' first" >&2
    exit 1
  fi
done

stack_start

api() {
  local method="$1" path="$2"
  shift 2
  curl -fsS -X "${method}" \
    -H "Authorization: Bearer ${STACK_ADMIN_TOKEN}" \
    "$@" "${STACK_CP_URL}${path}"
}

echo "Seeding mesh policy..."
api POST /policies -H "Content-Type: application/json" -d '{
  "roles": [
    {"name": "sam-admin", "allowed_services": ["*"], "allowed_targets": ["*"]},
    {"name": "sam:role:router", "allowed_services": ["*"], "allowed_targets": ["*"]},
    {"name": "sam:role:node", "allowed_services": ["mcp://*", "system://sam.catalog"], "allowed_targets": ["*"]}
  ],
  "bindings": [
    {"role": "sam:role:router", "members": ["group:routers"]},
    {"role": "sam:role:node", "members": ["group:users"]},
    {"role": "sam-admin", "members": ["user:root-admin"]}
  ]
}' >/dev/null

# Enrolment is what puts routers and nodes on the dashboard, and a bootstrap
# token is the only way in without an issuer that can actually sign a JWT.
mint_token() {
  local role="$1" description="$2"
  api POST /user/bootstrap-tokens -H "Content-Type: application/json" \
    -d "{\"role\": \"${role}\", \"max_usages\": 1, \"ttl_hours\": 24, \"description\": \"${description}\"}" |
    sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

echo "Enrolling a router..."
ROUTER_TOKEN=$(mint_token "sam:role:router" "ui-dev router")
"${REPO_ROOT}/bin/sam-router" \
  --control-plane "${STACK_CP_URL}" \
  --listen "/ip4/127.0.0.1/tcp/5101" \
  --keys-path "${WORK_DIR}/router.key" \
  --allow-loopback \
  --bootstrap-token "${ROUTER_TOKEN}" \
  >"${WORK_DIR}/router.log" 2>&1 &
PIDS+=($!)

echo "Enrolling a node..."
NODE_TOKEN=$(mint_token "sam:role:node" "ui-dev node")
NODE_DIR="${WORK_DIR}/node"
mkdir -p "${NODE_DIR}"
cat >"${NODE_DIR}/sam-node.yaml" <<'EOF'
version: "v1alpha1"
services: []
EOF
"${REPO_ROOT}/bin/sam-node" join "${STACK_CP_URL}" \
  --bootstrap-token "${NODE_TOKEN}" \
  --data-dir "${NODE_DIR}" \
  --config "${NODE_DIR}/sam-node.yaml" \
  --allow-loopback \
  >"${WORK_DIR}/node-join.log" 2>&1 || echo "  node join failed, see ${WORK_DIR}/node-join.log" >&2

# A couple left over so the Bootstrap Tokens table is not empty.
mint_token "sam:role:node" "spare node token" >/dev/null
mint_token "sam:role:router" "spare router token" >/dev/null

cat <<EOF

  Console   ${STACK_CONSOLE_URL}
  Log in with the admin token:  ${STACK_ADMIN_TOKEN}

  Control plane ${STACK_CP_URL}
  Logs          ${WORK_DIR}

  Static assets are served from internal/console/public, so edits to the HTML,
  CSS or JS just need a browser refresh. Ctrl-C tears everything down.

EOF

wait
