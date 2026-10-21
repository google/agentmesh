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

# Two authorized actors with different grants, and the mesh keeps them apart.
# demo is bound to the `actor` role (mcp://calc); ledger to the `ledger` role
# (mcp://payroll). The check asserts that each reaches only its own tool and
# that the other tool is refused by the serving node, not skipped by the
# client.
#
# `make check` is the turnkey entry point: it pushes the policy, brings both
# actors up and restarts the credential provider so its cache is empty before
# calling this script. To run it on its own, first make sure the
# ledger binding is live and both actors are running and holding a credential
# minted under it:
#
#   make up
#   make actor NAME=demo
#   make actor NAME=ledger      # the worker pool holds two actors; suspend a
#                               # third (make rogue leaves `rogue` suspended)
#   make policy                 # push the ledger binding to the control plane
#   kubectl -n agentmesh rollout restart deployment/credential-provider
#                               # drop the provider cache so the next mint uses
#                               # the policy just pushed (or wait out --cache-ttl)
#   ./check.sh                  # or: make check, which does all of the above
#
# mcp.py exits 0 when the tool answers, 3 when a provider is reached and the
# node refuses the call, and 4 when the mesh offers this actor no provider at
# all. A real isolation deny is 3: the node saw the call and said no.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

ROUTER_PORT="${ROUTER_PORT:-8000}"
ATESPACE="${ATESPACE:-ate-demo-sandbox}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-kind}"
KUBECTL=(kubectl --context "${KUBE_CONTEXT}")

if (exec 3<>"/dev/tcp/127.0.0.1/${ROUTER_PORT}") 2>/dev/null; then
  echo "127.0.0.1:${ROUTER_PORT} is in use; free it or set ROUTER_PORT" >&2; exit 1
fi
"${KUBECTL[@]}" -n ate-system port-forward service/atenet-router "${ROUTER_PORT}:80" >/dev/null 2>&1 &
pf=$!; trap 'kill $pf 2>/dev/null' EXIT INT TERM HUP
# The port-forward is backgrounded and silenced, so a failed start (wrong
# context, namespace, or no permission) would otherwise surface only as
# confusing call errors below. Poll the port until it accepts a connection,
# bounded (5s) and aborting early if the process dies, instead of a fixed sleep.
ready=false
for _ in {1..50}; do
  if (exec 3<>"/dev/tcp/127.0.0.1/${ROUTER_PORT}") 2>/dev/null; then ready=true; break; fi
  kill -0 "$pf" 2>/dev/null || break
  sleep 0.1
done
if [[ "${ready}" != "true" ]]; then
  echo "kubectl port-forward to atenet-router did not start or bind the port" >&2
  exit 1
fi

failures=0
# expect NAME WANT-EXIT ACTOR SERVICE: run one call and check its exit code.
# 0 allowed, 3 refused by the serving node, 4 no provider offered.
expect() {
  local name=$1 want=$2 actor=$3 service=$4 out got
  out=$(ROUTER_PORT="${ROUTER_PORT}" ATESPACE="${ATESPACE}" python3 mcp.py add "${actor}" "${service}" 2 3 2>&1)
  got=$?
  local tail="${out##*$'\n'}"
  if [[ "${got}" == "${want}" ]]; then
    printf '  PASS  %-40s exit %s  %s\n' "${name}" "${got}" "${tail}"
  else
    printf '  FAIL  %-40s got exit %s, want %s  %s\n' "${name}" "${got}" "${want}" "${tail}"
    failures=$((failures + 1))
  fi
}

echo "== each actor reaches its own tool"
expect "demo -> calc (its grant)"       0 demo   calc
expect "ledger -> payroll (its grant)"  0 ledger payroll
echo "== neither can borrow the other's grant (the serving node refuses)"
expect "demo -> payroll (not its grant)"  3 demo   payroll
expect "ledger -> calc (not its grant)"   3 ledger calc

echo
if [[ "${failures}" -eq 0 ]]; then
  echo "OK: the two actors are isolated."
else
  echo "FAIL: ${failures} case(s) did not match."
fi
exit $(( failures > 0 ? 1 : 0 ))
