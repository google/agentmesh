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

# Ensure agentmesh-one and agentmesh-node binaries are available, then run the
# end-to-end Wasmtime sandbox verification suite (`check`) or pass arguments
# through to the Rust host supervisor.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

AGENTMESH_VERSION="${AGENTMESH_VERSION:-v0.2.0}"
VERSION_NO_V="${AGENTMESH_VERSION#v}"
BIN_DIR="$(pwd)/run/bin"

ensure_binaries() {
  if [[ -n "${AGENTMESH_BIN_DIR:-}" ]] && [[ -x "${AGENTMESH_BIN_DIR}/agentmesh-one" || -f "${AGENTMESH_BIN_DIR}/agentmesh-one.exe" ]]; then
    return 0
  fi
  if [[ -x "../../bin/agentmesh-one" && -x "../../bin/agentmesh-node" ]]; then
    export AGENTMESH_BIN_DIR="$(cd ../../bin && pwd)"
    return 0
  fi
  if [[ -x "${BIN_DIR}/agentmesh-one" || -f "${BIN_DIR}/agentmesh-one.exe" ]]; then
    export AGENTMESH_BIN_DIR="${BIN_DIR}"
    return 0
  fi
  if command -v agentmesh-one >/dev/null 2>&1 && command -v agentmesh-node >/dev/null 2>&1; then
    return 0
  fi

  mkdir -p "${BIN_DIR}"
  local uname_s uname_m os arch ext archive sha_cmd
  uname_s="$(uname -s)"
  uname_m="$(uname -m)"

  case "${uname_s}" in
    Linux*)               os="Linux";   ext="tar.gz" ;;
    Darwin*)              os="Darwin";  ext="tar.gz" ;;
    MINGW*|MSYS*|CYGWIN*) os="Windows"; ext="zip" ;;
    *) echo "Unsupported OS: ${uname_s}" >&2; exit 1 ;;
  esac

  case "${uname_m}" in
    x86_64|amd64)  arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "Unsupported architecture: ${uname_m}" >&2; exit 1 ;;
  esac

  archive="agentmesh_${VERSION_NO_V}_${os}_${arch}.${ext}"
  local base_url="https://github.com/google/agentmesh/releases/download/${AGENTMESH_VERSION}"
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' RETURN

  echo "Downloading ${archive} (${AGENTMESH_VERSION})..." >&2
  curl -fsSL "${base_url}/${archive}" -o "${tmp_dir}/${archive}"
  curl -fsSL "${base_url}/checksums.txt" -o "${tmp_dir}/checksums.txt"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${tmp_dir}" && grep " ${archive}\$" checksums.txt | sha256sum -c - >/dev/null)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "${tmp_dir}" && grep " ${archive}\$" checksums.txt | shasum -a 256 -c - >/dev/null)
  fi

  if [[ "${ext}" == "tar.gz" ]]; then
    tar -xzf "${tmp_dir}/${archive}" -C "${BIN_DIR}"
    chmod +x "${BIN_DIR}/agentmesh-one" "${BIN_DIR}/agentmesh-node"
  else
    unzip -q -o "${tmp_dir}/${archive}" -d "${BIN_DIR}"
  fi
  export AGENTMESH_BIN_DIR="${BIN_DIR}"
}

ensure_binaries

if [[ $# -eq 0 ]]; then
  exec cargo run --release --quiet -- check
else
  exec cargo run --release --quiet -- "$@"
fi
