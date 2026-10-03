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

# Fails when the protobuf bindings or the baseline Datalog artifact the SDKs
# ship are stale relative to api/, when the example programs embedded in the
# SDK READMEs and the Native SDKs guide differ from the files CI runs, or
# when the JavaScript lockfile resolves packages anywhere but the public
# registry. Regenerates in place, so run it on a clean checkout.

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "${REPO_ROOT}"

GENERATED=(sdk/js/src/gen sdk/python/src/agent_mesh/_proto sdk/python/src/agent_mesh/_gen sdk/testdata)

./hack/gen-sdk-proto.sh

if ! git diff --exit-code -- "${GENERATED[@]}"; then
  echo "ERROR: SDK generated files are not up to date."
  echo "Run ./hack/gen-sdk-proto.sh and commit the result."
  exit 1
fi
echo "SDK generated files are up to date."

go run ./hack/gen-sdk-docs -check sdk site/content/docs
echo "SDK examples embedded in the docs are up to date."

if grep -E '"resolved": "https?://' sdk/js/package-lock.json | grep -qv '"resolved": "https://registry.npmjs.org/'; then
  echo "ERROR: sdk/js/package-lock.json resolves packages outside https://registry.npmjs.org/."
  grep -E '"resolved": "https?://' sdk/js/package-lock.json | grep -v '"resolved": "https://registry.npmjs.org/' | head -3
  echo "Regenerate it with the public registry (sdk/js/.npmrc pins it)."
  exit 1
fi
echo "SDK lockfile resolves against the public registry."
