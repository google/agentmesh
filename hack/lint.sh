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


set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

cd $REPO_ROOT
docker run --rm -v $(pwd):/app -w /app golangci/golangci-lint:v2.14.0 golangci-lint run -v

# golangci-lint has no deadcode linter (removed upstream in v1.49) and its
# replacement, "unused", ignores exported identifiers. This catches exported
# code that is unreachable from every binary and test.
# mobile/ is exported to Android over cgo/FFI and development/examples/ is sample code.
DEADCODE_EXCLUDES='^(mobile/|development/examples/)'
deadcode_report=$(go run golang.org/x/tools/cmd/deadcode@v0.50.0 -test ./... | grep -Ev "${DEADCODE_EXCLUDES}" || true)
if [[ -n "${deadcode_report}" ]]; then
  echo "Dead code detected (unreachable from any binary or test):"
  echo "${deadcode_report}"
  exit 1
fi
