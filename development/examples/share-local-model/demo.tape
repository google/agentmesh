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

# The share-local-model recording, for VHS (https://github.com/charmbracelet/vhs).
# record.sh runs it from the work directory it prepares. Pane focus and
# caption changes are off camera (Hide) through ctl.sh; every Agent Mesh
# command is typed on camera as shown. The scenes are described in SCRIPT.md.

Output "out/raw.mp4"

Require tmux
Require jq
Require python3
Require agentmesh-one
Require agentmesh-node

Set Shell "bash"
Set Width 1920
Set Height 1080
Set FontFamily "DejaVu Sans Mono"
Set FontSize 16
Set Padding 14
Set Framerate 30
Set TypingSpeed 40ms
Set Theme "Dracula"
Set CursorBlink false

# --- setup, off camera ----------------------------------------------------------------
Hide
Type "bash kit/layout.sh"
Enter
Sleep 3s
Show
Sleep 1s

# --- intro --------------------------------------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} cap 1"`
Enter
Show
Sleep 9s

# --- step 1: a locked-down policy ---------------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} cap 2"`
Enter
Show
Sleep 4s
Type "cat mesh-policy.json"
Enter
Sleep 5s

# --- step 2: one command starts the mesh ----------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} go cp; bash #{@ctl} cap 3"`
Enter
Show
Sleep 4s
Type@25ms "agentmesh-one --data-dir ~/data/one --port 9000 --policy-file mesh-policy.json --admin-token-path ~/data/admin-token --no-join-token --enroll-qr=false --log-level warn"
Enter
Wait+Screen@60s /mesh is ready/
Sleep 3s

# --- step 3: one enrollment token per node -------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} go op; bash #{@ctl} cap 4"`
Enter
Show
Sleep 3s
Type "clear"
Enter
Type@25ms "umask 077; for n in node-a node-b; do agentmesh-one token create --server $URL --admin-token-path ~/data/admin-token --description $n | awk '/^Token:/ {print $2}' > ~/data/$n.token; done"
Enter
Sleep 2s
Type "stat -c '%A  %s bytes  %n' data/*.token"
Enter
Wait+Screen@20s /node-b\.token/
Sleep 3s

# --- step 4: node A publishes its model ----------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} go na; bash #{@ctl} cap 5"`
Enter
Show
Sleep 4s
Type "cat node-a.yaml"
Enter
Sleep 3s
Type@25ms "agentmesh-node run --control-plane $URL --bootstrap-token-path ~/data/node-a.token --config node-a.yaml --data-dir ~/data/node-a --bind-addr= --allow-loopback --listen /ip4/127.0.0.1/tcp/0 --control-plane-sync-interval 5s 2>&1 | python3 audit.py"
Enter
Wait+Screen@90s /Node Online/
Sleep 3s

# --- step 5: node B joins ---------------------------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} go nb; bash #{@ctl} cap 6"`
Enter
Show
Sleep 3s
Type@25ms "agentmesh-node run --control-plane $URL --bootstrap-token-path ~/data/node-b.token --data-dir ~/data/node-b --bind-addr 127.0.0.1:8080 --api-token-path api-token --allow-loopback --listen /ip4/127.0.0.1/tcp/0 --control-plane-sync-interval 5s 2>&1 | python3 audit.py"
Enter
Wait+Screen@90s /(?s)Node Online.*Node Online/
Sleep 3s

# --- step 6: refused ----------------------------------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} go op; bash #{@ctl} cap 7"`
Enter
Show
Sleep 3s
Type "clear"
Enter
Type "cat hello.json"
Enter
Sleep 2s
Type@25ms `curl -s --unix-socket ~/data/node-b/agentmesh.sock localhost/v1/chat/completions -d @hello.json | jq -r '.choices[0].message.content // .error.message'`
Sleep 500ms
Enter
Wait+Screen@90s /not served by any provider/
Wait+Screen@30s /DENY/
Sleep 5s

# --- step 7: grant one service by name -------------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} cap 8"`
Enter
Show
Sleep 4s
Type "./grant.sh inference://laptop-llm"
Enter
Wait+Screen@30s /Granted/
Wait+Screen@120s /(?s)Policy updated by the control plane.*Policy updated by the control plane/
Sleep 4s

# --- step 8: the same request is allowed -------------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} cap 9"`
Enter
Show
Sleep 3s
Up 2
Sleep 1s
Enter
Wait+Screen@120s /ALLOW .*chat\/completions/
Wait+Screen@120s /(?m)@node-b:~\$ *$/
Sleep 2s
Screenshot "out/thumbnail.png"
Sleep 3s

# >>> agents (record.sh drops this block when AGENTS=0)
# --- step 9: an AI agent on node B: Antigravity ------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} cap 10"`
Enter
Show
Type "clear"
Enter
Sleep 4s
Type `antigravity -p "Using the agentmesh tools, which AI models are on my mesh and which node serves them? Answer in two short lines of plain text, no markdown."`
Sleep 500ms
Enter
Sleep 3s
Hide
Wait+Screen@300s /(?m)@node-b:~\$ *$/
Show
Sleep 7s

# --- step 10: a second agent: OpenCode ---------------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} cap 11"`
Enter
Show
Type "clear"
Enter
Sleep 4s
Type `opencode run "Using the agentmesh tools, list the services on my mesh and the node that serves each. Two short lines of plain text, no markdown."`
Sleep 500ms
Enter
Sleep 4s
Hide
Wait+Screen@300s /(?m)@node-b:~\$ *$/
Show
Sleep 8s
# <<< agents

# --- close -----------------------------------------------------------------------------------
Hide
Ctrl+B
Type ":"
Type@1ms `run-shell "bash #{@ctl} cap 12"`
Enter
Show
Sleep 7s
