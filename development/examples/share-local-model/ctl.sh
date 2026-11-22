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

# Off-camera controls that demo.tape calls through tmux run-shell:
#   ctl.sh go <cp|na|nb|op>   focus a pane (layout.sh stores the pane ids)
#   ctl.sh cap <n>            show line n of captions.txt in the caption pane

set -o errexit
set -o nounset
set -o pipefail

case "${1:-}" in
  go)  tmux select-pane -t "$(tmux show -gv "@${2:?pane name}")" ;;
  cap) sed -n "${2:?caption number}p" "$(tmux show -gv @captions)" > "$(tmux show -gv @caption_file)" ;;
  *)   echo "usage: ctl.sh go <pane> | cap <n>" >&2; exit 2 ;;
esac
