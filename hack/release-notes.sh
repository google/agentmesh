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

# Prints Markdown release notes for a tag of one project in this repository:
# the commits since the previous tag with the same prefix that touch the
# given paths. The prefix is everything before the version, so `sdk/js/v0.2.0`
# is compared against the latest earlier `sdk/js/v*` tag and `v0.2.0` against
# the latest earlier `v*` tag.
#
#   ./hack/release-notes.sh sdk/js/v0.2.0 sdk/js api/sam.proto

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -lt 2 || ! "$1" =~ ^((.*/)?)v[0-9] ]]; then
  echo "usage: $0 <tag, e.g. sdk/js/v0.2.0> <path>..." >&2
  exit 2
fi
tag="$1"
prefix="${BASH_REMATCH[1]}"
shift

if ! git rev-parse --verify --quiet "${tag}^{commit}" >/dev/null; then
  echo "ERROR: ${tag} is not a tag in this repository" >&2
  exit 1
fi

# Described from the parent so the tag itself is never its own predecessor.
prev="$(git describe --tags --abbrev=0 --match "${prefix}v*" "${tag}^" 2>/dev/null || true)"

range="${tag}"
if [[ -n "${prev}" ]]; then
  range="${prev}..${tag}"
fi

echo "## Changes"
echo
commits="$(git log --no-merges --format='- %s' "${range}" -- "$@")"
if [[ -z "${commits}" ]]; then
  echo "- No changes under: $*"
else
  echo "${commits}"
fi

if [[ -n "${prev}" ]]; then
  repo="${GITHUB_REPOSITORY:-google/sam}"
  echo
  echo "Full changelog: https://github.com/${repo}/compare/${prev}...${tag}"
fi
