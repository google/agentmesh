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

# Regenerates the protobuf bindings the native SDKs under sdk/ ship for
# api/sam.proto, and the baseline Datalog artifact from api/datalog.go. The
# Go bindings are gen-proto.sh's job. Requires protoc and, for JavaScript,
# an `npm install` in sdk/js (protoc-gen-es).

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "${REPO_ROOT}"

JS_GEN_DIR="sdk/js/src/gen"
PY_GEN_DIR="sdk/python/src/agent_mesh/_proto"
PY_DATALOG_DIR="sdk/python/src/agent_mesh/_gen"
PROTOC_GEN_ES="sdk/js/node_modules/.bin/protoc-gen-es"

if [[ ! -x "${PROTOC_GEN_ES}" ]]; then
  echo "missing ${PROTOC_GEN_ES}: run 'npm install' in sdk/js first" >&2
  exit 1
fi

echo "Generating JavaScript protobuf code..."
mkdir -p "${JS_GEN_DIR}"
protoc -I api \
  --plugin="protoc-gen-es=${PROTOC_GEN_ES}" \
  --es_out="${JS_GEN_DIR}" \
  --es_opt=target=ts \
  api/sam.proto

echo "Generating Python protobuf code..."
mkdir -p "${PY_GEN_DIR}"
protoc -I api \
  --python_out="${PY_GEN_DIR}" \
  --pyi_out="${PY_GEN_DIR}" \
  api/sam.proto
# The relay v2 client speaks go-libp2p's circuit.proto directly; see the
# proto's header for why the SDK carries a copy.
protoc -I sdk/python/proto \
  --python_out="${PY_GEN_DIR}" \
  --pyi_out="${PY_GEN_DIR}" \
  sdk/python/proto/circuit.proto

echo "Generating baseline Datalog artifact and TAR conformance vectors..."
mkdir -p "${PY_DATALOG_DIR}" sdk/testdata
go run ./hack/gen-sdk-datalog "${PY_DATALOG_DIR}/datalog.json" "${JS_GEN_DIR}/datalog.ts" "sdk/testdata/tar_conformance.json"

echo "SDK protobuf generation complete."
