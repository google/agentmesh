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

# Runs on every boot. The bootstrap token is spent on the first one; later
# boots reuse the identity stored in ~/.sam.
set -eu
d=$HOME/.sam
mkdir -p "$d" && chmod 700 "$d"
if [ ! -s "$d/token" ]; then
  (umask 077; printf '%s' "$SAM_BOOTSTRAP_TOKEN" > "$d/token")
fi
exec sam-node run --daemonize \
  --control-plane "https://$SAM_CONTROL_PLANE" \
  --bootstrap-token-path "$d/token" \
  --api-token-path "$d/api-token" \
  --data-dir "$d" \
  --bind-addr 127.0.0.1:8080
