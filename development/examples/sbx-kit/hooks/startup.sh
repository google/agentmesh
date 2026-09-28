#!/bin/sh
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

# Runs on every boot, after every kit's install hooks, so an agent kit that
# seeds its config at install cannot drop the registration. Idempotent.
set -eu
d=$HOME/.sam
mkdir -p "$d" && chmod 700 "$d"
exec 2>>"$d/hooks.log"
echo "$(date -u +%FT%TZ) startup" >&2

if [ ! -s "$d/api-token" ]; then
  (umask 077; head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' > "$d/api-token")
fi
if [ ! -s "$d/token" ]; then
  (umask 077; printf '%s' "$SAM_BOOTSTRAP_TOKEN" > "$d/token")
fi

tok=$(cat "$d/api-token")
url=http://127.0.0.1:8080/mcp
hdr="X-Sam-Authentication: Bearer $tok"
warn() { echo "sam: $1 mcp add failed; add $url by hand" >&2; }
if command -v claude >/dev/null; then
  # --header is variadic: it must come after the name and the url.
  claude mcp remove --scope user sam-mesh >/dev/null 2>&1 || true
  claude mcp add --transport http --scope user sam-mesh "$url" --header "$hdr" >&2 || warn claude
else
  echo "sam: claude not on PATH ($PATH)" >&2
fi
if command -v gemini >/dev/null; then
  gemini mcp add --transport http --scope user sam-mesh "$url" -H "$hdr" >&2 || warn gemini
fi
if command -v codex >/dev/null && ! grep -qs '^\[mcp_servers\.sam-mesh\]' "$HOME/.codex/config.toml"; then
  # codex mcp add has no header flag; the table goes straight into its config.
  mkdir -p "$HOME/.codex"
  printf '\n[mcp_servers.sam-mesh]\nurl = "%s"\nhttp_headers = { "X-Sam-Authentication" = "Bearer %s" }\n' \
    "$url" "$tok" >> "$HOME/.codex/config.toml"
fi

exec sam-node run --daemonize \
  --control-plane "https://$SAM_CONTROL_PLANE" \
  --bootstrap-token-path "$d/token" \
  --api-token-path "$d/api-token" \
  --data-dir "$d" \
  --bind-addr 127.0.0.1:8080
