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

# Adds one service pattern to what mesh:role:node may call, through the admin API.
#   ./grant.sh                      grants inference://laptop-llm
#   ./grant.sh 'inference://*'      grants every inference service
# The admin token is read from its file and passed to curl in a header file,
# so it never appears in the process list or the shell history.

set -o errexit
set -o nounset
set -o pipefail

PATTERN=${1:-inference://laptop-llm}
URL=${URL:-http://127.0.0.1:9000}
TOKEN_FILE=${TOKEN_FILE:-$HOME/data/admin-token}

fail() { echo "grant: $*" >&2; exit 1; }

[[ -r "$TOKEN_FILE" ]] || fail "admin token not readable at $TOKEN_FILE; is agentmesh-one running?"

umask 077
hdr=$(mktemp)
cur=$(mktemp)
new=$(mktemp)
trap 'rm -f "$hdr" "$cur" "$new"' EXIT

printf 'Authorization: Bearer %s\n' "$(<"$TOKEN_FILE")" > "$hdr"

curl -sS --fail-with-body -H @"$hdr" "$URL/admin/policy" -o "$cur" \
  || fail "could not read the policy from $URL/admin/policy"
jq -e '.roles[] | select(.name == "mesh:role:node")' "$cur" >/dev/null \
  || fail "the policy has no mesh:role:node role"
jq --arg p "$PATTERN" '
  (.roles[] | select(.name == "mesh:role:node") | .allowed_services)
    |= ((. // []) + [$p] | unique)
' "$cur" > "$new"
curl -sS --fail-with-body -H @"$hdr" -H 'Content-Type: application/json' \
  --data-binary @"$new" "$URL/policies" >/dev/null \
  || fail "the control plane refused the new policy"

echo "Granted: mesh:role:node may now call $PATTERN"
jq '.roles[] | select(.name == "mesh:role:node")' "$new"
