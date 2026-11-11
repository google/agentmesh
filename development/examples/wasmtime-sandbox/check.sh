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

# Two authorized Wasmtime sandboxes with different grants, and the mesh keeps
# them apart.
# `demo` is bound to the `sandbox` role (mcp://calc, mcp://echo-headers);
# `ledger` to the `ledger` role (mcp://payroll). The check asserts that each
# reaches only its own service and that the other service is refused by the
# serving node (exit 3), while an unbound `rogue` sandbox is also refused.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

if [[ ! -f "run/ports.env" ]]; then
  echo "run/ports.env not found; run 'make up' first (or './run.sh check' for standalone execution)" >&2
  exit 1
fi

failures=0
expect() {
  local label=$1 want=$2 name=$3 service=$4 out got
  out=$(./run.sh call --name "${name}" --service "${service}" --a 2 --b 3 2>&1)
  got=$?
  local tail="${out##*$'\n'}"
  if [[ "${got}" == "${want}" ]]; then
    printf '  PASS  %-42s exit %s  %s\n' "${label}" "${got}" "${tail}"
  else
    printf '  FAIL  %-42s got exit %s, want %s  %s\n' "${label}" "${got}" "${want}" "${tail}"
    failures=$((failures + 1))
  fi
}

echo "== each sandbox reaches its own service"
expect "demo -> calc (its grant)"          0 demo   mcp://calc
expect "ledger -> payroll (its grant)"     0 ledger mcp://payroll
echo "== neither can borrow the other's grant (the serving node refuses)"
expect "demo -> payroll (not its grant)"   3 demo   mcp://payroll
expect "ledger -> calc (not its grant)"    3 ledger mcp://calc
echo "== unbound sandbox is refused"
expect "rogue -> calc (no role binding)"   3 rogue  mcp://calc

echo
if [[ "${failures}" -eq 0 ]]; then
  echo "OK: the Wasmtime sandboxes are isolated."
else
  echo "FAIL: ${failures} case(s) did not match."
fi
exit $(( failures > 0 ? 1 : 0 ))
