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

# Records SCRIPT.md for the share-local-model example with VHS and publishes
# it as site/static/demo-share-local-model.mp4.
#
#   ./record.sh                  all ten steps (needs antigravity and opencode)
#   AGENTS=0 ./record.sh         steps 1 to 8, without the agent scenes
#   PUBLISH=0 ./record.sh        record, but leave site/static untouched

set -o errexit
set -o nounset
set -o pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../../.." && pwd)
WORK_DIR=${WORK_DIR:-$HOME/agentmesh-share-local-model}
KIT=$WORK_DIR/kit
DEMO_HOME=$WORK_DIR/home
OUT=$WORK_DIR/out
MODEL=${MODEL:-gemma3:1b}
AGENTS=${AGENTS:-1}
AGENTS_RC=${AGENTS_RC:-}
PUBLISH=${PUBLISH:-1}
API_TOKEN_FILE=${API_TOKEN_FILE:-$WORK_DIR/api-token}
AGENTMESH_BIN=${AGENTMESH_BIN:-$REPO_ROOT/bin}
SESSION=share-local-model

fail() { echo "record: $*" >&2; exit 1; }

for t in vhs ttyd ffmpeg ffprobe tmux jq python3 curl; do
  command -v "$t" >/dev/null || fail "$t is not installed"
done
if [[ "$AGENTMESH_BIN" == "$REPO_ROOT/bin" ]] &&
   [[ ! -x "$AGENTMESH_BIN/agentmesh-one" || ! -x "$AGENTMESH_BIN/agentmesh-node" ]]; then
  make -C "$REPO_ROOT" build
fi
[[ -x "$AGENTMESH_BIN/agentmesh-one" && -x "$AGENTMESH_BIN/agentmesh-node" ]] \
  || fail "agentmesh-one and agentmesh-node not found in $AGENTMESH_BIN"
export PATH="$AGENTMESH_BIN:$PATH"

if pgrep -x agentmesh-one >/dev/null || pgrep -x agentmesh-node >/dev/null; then
  fail "an agentmesh process is already running; stop it before recording"
fi
curl -fsS http://127.0.0.1:11434/api/version >/dev/null \
  || fail "Ollama is not answering on 127.0.0.1:11434"
# Load the model now so the first answer on camera is quick.
curl -fsS http://127.0.0.1:11434/api/generate \
  -d "{\"model\":\"$MODEL\",\"prompt\":\"Reply with OK.\",\"stream\":false,\"keep_alive\":\"30m\"}" >/dev/null \
  || fail "$MODEL did not answer; run: ollama pull $MODEL"

rm -rf "$KIT" "$DEMO_HOME" "$OUT"
mkdir -p "$KIT" "$DEMO_HOME/data" "$OUT"
cp "$HERE"/{demo.tape,layout.sh,ctl.sh,tmux.conf,demo-bashrc,caption.py,captions.txt} "$KIT/"
cp "$HERE"/{mesh-policy.json,node-a.yaml,hello.json,audit.py,grant.sh} "$DEMO_HOME/"
chmod +x "$DEMO_HOME/grant.sh"

if [[ "$AGENTS" == 1 ]]; then
  if [[ -n "$AGENTS_RC" ]]; then
    [[ -r "$AGENTS_RC" ]] || fail "AGENTS_RC=$AGENTS_RC is not readable"
  elif ! command -v antigravity >/dev/null || ! command -v opencode >/dev/null; then
    fail "antigravity and opencode are not on PATH; set AGENTS_RC or AGENTS=0 (see SCRIPT.md)"
  fi
else
  # Without the agent scenes: drop them from the tape and renumber the captions.
  sed -i '/^# >>> agents/,/^# <<< agents/d' "$KIT/demo.tape"
  sed -i 's#^Step \([0-9]*\)/10 #Step \1/8 #' "$KIT/captions.txt"
fi
printf 'AGENTMESH_BIN=%q\nAGENTS_RC=%q\n' "$AGENTMESH_BIN" "$AGENTS_RC" > "$KIT/paths.env"

# Node B's local API token. It persists across takes, because the agents'
# MCP configuration sends it to node B.
if [[ ! -s "$API_TOKEN_FILE" ]]; then
  (umask 077; od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$API_TOKEN_FILE"; echo >> "$API_TOKEN_FILE")
fi
install -m 600 "$API_TOKEN_FILE" "$DEMO_HOME/api-token"
# A fresh admin token for this take, read from a file so the banner and the
# shell history never show it.
(umask 077; od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$DEMO_HOME/data/admin-token"; echo >> "$DEMO_HOME/data/admin-token")
: > "$WORK_DIR/caption.txt"

cleanup() { tmux kill-session -t "$SESSION" 2>/dev/null || true; }
trap cleanup EXIT

(cd "$WORK_DIR" && vhs "$KIT/demo.tape")
cleanup

[[ -s "$OUT/raw.mp4" ]] || fail "vhs wrote no video"
dur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$OUT/raw.mp4")
fade_out=$(awk -v d="$dur" 'BEGIN { printf "%.2f", d - 1.0 }')
ffmpeg -v error -y -i "$OUT/raw.mp4" \
  -vf "fade=t=in:st=0:d=0.8,fade=t=out:st=${fade_out}:d=1.0" \
  -c:v libx264 -crf 18 -preset slow -pix_fmt yuv420p -movflags +faststart \
  "$OUT/demo.mp4"

if [[ "$PUBLISH" == 1 ]]; then
  cp "$OUT/demo.mp4" "$REPO_ROOT/site/static/demo-share-local-model.mp4"
  echo "recorded and published: $REPO_ROOT/site/static/demo-share-local-model.mp4"
else
  echo "recorded: $OUT/demo.mp4"
fi
