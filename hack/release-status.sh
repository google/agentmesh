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

# Prints a Markdown table with, for every project released from this
# repository, its last tag, the commits since that tag under the project's
# paths, and whether the contract the SDKs and the app embed (api/sam.proto,
# api/datalog.go) changed since that tag. Run it before tagging a mesh
# release to see which other tags the release calls for; the release
# workflow writes it to the job summary of a mesh release.
#
#   ./hack/release-status.sh           # measured at HEAD
#   ./hack/release-status.sh v0.2.0    # measured at a tag or commit

set -o errexit
set -o nounset
set -o pipefail

ref="${1:-HEAD}"

# name|tag prefix|paths whose commits count for the project
projects=(
  "mesh|v|cmd internal api go.mod go.sum"
  "sdk/js|sdk/js/v|sdk/js api/sam.proto api/datalog.go"
  "sdk/python|sdk/python/v|sdk/python api/sam.proto api/datalog.go"
  "mobile|mobile/v|mobile internal api go.mod go.sum"
)
contract=(api/sam.proto api/datalog.go)

echo "| Project | Last tag | Commits since | Contract (${contract[*]}) |"
echo "|---|---|---|---|"
for entry in "${projects[@]}"; do
  IFS='|' read -r name prefix paths <<<"${entry}"
  last="$(git describe --tags --abbrev=0 --match "${prefix}*" "${ref}" 2>/dev/null || true)"
  if [[ -z "${last}" ]]; then
    echo "| ${name} | none | all | never released |"
    continue
  fi
  # shellcheck disable=SC2086 # paths is a space-separated list by design
  commits="$(git rev-list --count --no-merges "${last}..${ref}" -- ${paths})"
  moved="$(git rev-list --count --no-merges "${last}..${ref}" -- "${contract[@]}")"
  if [[ "${moved}" -gt 0 ]]; then
    state="changed in ${moved} commit(s)"
  else
    state="unchanged"
  fi
  echo "| ${name} | ${last} | ${commits} | ${state} |"
done
