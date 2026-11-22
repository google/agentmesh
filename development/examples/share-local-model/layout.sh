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

# Builds the tmux session for the recording and attaches to it. demo.tape runs
# it from the work directory that record.sh prepares.
#
#   +---------------------------+-------------------------------+
#   | control plane             | node B                        |
#   +---------------------------+-------------------------------+
#   | node A                    | operator, then agents on B    |
#   +---------------------------+-------------------------------+
#   | caption (full width, typed at reading speed)              |
#   +-----------------------------------------------------------+
#
# Each shell gets a host label for its prompt (user@node-a:~$) and the demo
# home as its home. Pane ids are stored as @cp @na @nb @op for ctl.sh.

set -o errexit
set -o nounset
set -o pipefail

KIT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORK_DIR=$(dirname "$KIT")
SESSION=share-local-model
COLS=$(tput cols)
ROWS=$(tput lines)
sh_for() { echo "env DEMO_HOME=$WORK_DIR/home DEMO_HOST=$1 bash --rcfile $KIT/demo-bashrc"; }

tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux -f "$KIT/tmux.conf" new-session -d -s "$SESSION" -x "$COLS" -y "$ROWS" "$(sh_for control-plane)"
tmux set -g @ctl "$KIT/ctl.sh"
tmux set -g @captions "$KIT/captions.txt"
tmux set -g @caption_file "$WORK_DIR/caption.txt"

CP=$(tmux display -p -t "$SESSION:0.0" '#{pane_id}')
CAP=$(tmux split-window -d -P -F '#{pane_id}' -v -f -l 5 -t "$CP" \
  "python3 $KIT/caption.py $WORK_DIR/caption.txt $COLS 38")
NB=$(tmux split-window -d -P -F '#{pane_id}' -h -l 52% -t "$CP" "$(sh_for node-b)")
NA=$(tmux split-window -d -P -F '#{pane_id}' -v -l 60% -t "$CP" "$(sh_for node-a)")
OP=$(tmux split-window -d -P -F '#{pane_id}' -v -l 70% -t "$NB" "$(sh_for node-b)")
tmux set -g @cp "$CP"
tmux set -g @na "$NA"
tmux set -g @nb "$NB"
tmux set -g @op "$OP"

tmux select-pane -t "$CP"  -T "control plane · agentmesh-one"
tmux select-pane -t "$NA"  -T "node A · serves a local model (Ollama, gemma3:1b)"
tmux select-pane -t "$NB"  -T "node B · another member of the mesh"
tmux select-pane -t "$OP"  -T "operator, then the agents on node B"
tmux select-pane -t "$CAP" -T ""
tmux select-pane -t "$OP"

exec tmux attach -t "$SESSION"
