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

# Stamps one version on both native SDKs, so a release publishes
# @agentmesh-p2p/sdk and agentmesh-p2p at the version of its tag. The release
# workflow runs it on the tag; a developer never needs to.
#
#   ./hack/sdk-version.sh 1.2.3

set -o errexit
set -o nounset
set -o pipefail

target="all"
case "${1:-}" in
  --js) target="js"; shift ;;
  --python) target="python"; shift ;;
esac

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: $0 [--js|--python] <semver, e.g. 1.2.3>" >&2
  exit 2
fi
VERSION="$1"

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "${REPO_ROOT}"

if [[ "${target}" == "all" || "${target}" == "js" ]]; then
  # package.json and package-lock.json together; the client identity the SDK
  # presents to MCP peers follows.
  (cd sdk/js && npm version --no-git-tag-version --allow-same-version "${VERSION}" >/dev/null)
  sed -i -E "s/^(export const MCP_CLIENT_INFO = \{ name: \"agent-mesh-sdk\", version: \")[^\"]+(\" \};)$/\1${VERSION}\2/" sdk/js/src/mcp.ts
  # The MCP registry entry and its npm package entry.
  sed -i -E "s/^( +\"version\": \")[^\"]+(\",)$/\1${VERSION}\2/" sdk/js/server.json
fi

if [[ "${target}" == "all" || "${target}" == "python" ]]; then
  sed -i -E "s/^version = \"[^\"]+\"$/version = \"${VERSION}\"/" sdk/python/pyproject.toml
  sed -i -E "s/^__version__ = \"[^\"]+\"$/__version__ = \"${VERSION}\"/" sdk/python/src/agent_mesh/__init__.py
  sed -i -E "s/^(MCP_CLIENT_INFO = mcp_types.Implementation\(name=\"agent-mesh-sdk\", version=\")[^\"]+(\"\))$/\1${VERSION}\2/" sdk/python/src/agent_mesh/mcp_client.py
fi

files=()
if [[ "${target}" == "all" || "${target}" == "js" ]]; then
  files+=(sdk/js/package.json sdk/js/src/mcp.ts sdk/js/server.json)
fi
if [[ "${target}" == "all" || "${target}" == "python" ]]; then
  files+=(sdk/python/pyproject.toml sdk/python/src/agent_mesh/__init__.py sdk/python/src/agent_mesh/mcp_client.py)
fi

for f in "${files[@]}"; do
  if ! grep -q "\"${VERSION}\"" "$f"; then
    echo "ERROR: ${f} does not carry ${VERSION} after stamping" >&2
    exit 1
  fi
done
echo "SDKs stamped as ${VERSION}."
