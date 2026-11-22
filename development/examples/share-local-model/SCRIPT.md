# Share a local model: refused, then granted by name

A two-minute recording on one machine. Node A serves a model that runs on
its own loopback. Node B, another member of the mesh, asks for it and is
refused, because nothing is reachable by default. The operator grants that
one service by name, and the same request goes through. Two agents on node B
then find the model through node B's MCP server.

`record.sh` produces it with [VHS](https://github.com/charmbracelet/vhs). The
scenes below are what it types; the captions are in `captions.txt`.

## Before recording

```bash
make build                          # ./bin/agentmesh-one and ./bin/agentmesh-node
ollama pull gemma3:1b               # Ollama listening on 127.0.0.1:11434
```

Tools: `vhs`, `ttyd`, `ffmpeg`, `tmux`, `jq`, `python3`, `curl`, and the
DejaVu Sans Mono font.

Scenes 9 and 10 use two agent CLIs, Antigravity CLI and OpenCode, configured
with node B's MCP server:

- URL: `http://127.0.0.1:8080/mcp`
- Header: `X-Mesh-Authentication: Bearer <token>`, where the token is the
  content of `$WORK_DIR/api-token` (`record.sh` creates it on the first run)

Both commands must work in the recording's shells. If they are not on `PATH`
(for example Windows binaries called from WSL), put wrapper functions in a
file and pass it as `AGENTS_RC`. To record without them, set `AGENTS=0`; the
video then ends after step 8.

## Scenes

The panes: control plane (top left), node A (bottom left), node B (top right)
and the operator, then the agents on node B (bottom right). Every node's log
goes through `audit.py`, which prints one line per authorization decision
(`ALLOW`, `DENY`) and a line when the node loads a changed policy.

### 1. The policy

```bash
cat mesh-policy.json
```

Members hold the role `mesh:role:node`. They may publish `inference://*` but
may call only `system://mesh.catalog`.

### 2. One command starts the mesh

```bash
agentmesh-one --data-dir ~/data/one --port 9000 --policy-file mesh-policy.json \
  --admin-token-path ~/data/admin-token --no-join-token --enroll-qr=false --log-level warn
```

The admin token comes from a file, so the banner does not print it, and there
is no standing join token.

### 3. One enrollment token per node

```bash
umask 077; for n in node-a node-b; do agentmesh-one token create --server $URL \
  --admin-token-path ~/data/admin-token --description $n | awk '/^Token:/ {print $2}' > ~/data/$n.token; done
stat -c '%A  %s bytes  %n' data/*.token
```

### 4. Node A publishes its model

```bash
cat node-a.yaml
agentmesh-node run --control-plane $URL --bootstrap-token-path ~/data/node-a.token \
  --config node-a.yaml --data-dir ~/data/node-a --bind-addr= --allow-loopback \
  --listen /ip4/127.0.0.1/tcp/0 --control-plane-sync-interval 5s 2>&1 | python3 audit.py
```

### 5. Node B joins

```bash
agentmesh-node run --control-plane $URL --bootstrap-token-path ~/data/node-b.token \
  --data-dir ~/data/node-b --bind-addr 127.0.0.1:8080 --api-token-path api-token \
  --allow-loopback --listen /ip4/127.0.0.1/tcp/0 --control-plane-sync-interval 5s 2>&1 | python3 audit.py
```

### 6. Refused

```bash
cat hello.json
curl -s --unix-socket ~/data/node-b/agentmesh.sock localhost/v1/chat/completions \
  -d @hello.json | jq -r '.choices[0].message.content // .error.message'
```

Node B answers that no provider serves the model. Node A's pane shows `DENY`.

### 7. Grant one service by name

```bash
./grant.sh inference://laptop-llm
```

`grant.sh` reads the policy from `GET /admin/policy`, adds the service to
`mesh:role:node` and posts it to `POST /policies`. Both node panes show the
policy update within seconds.

### 8. The same request is allowed

The same `curl`: node A's pane shows `ALLOW` and the model answers.

### 9. An agent: Antigravity CLI

```bash
antigravity -p "Using the agentmesh tools, which AI models are on my mesh and which node serves them? Answer in two short lines of plain text, no markdown."
```

### 10. A second agent: OpenCode

```bash
opencode run "Using the agentmesh tools, list the services on my mesh and the node that serves each. Two short lines of plain text, no markdown."
```

## Notes

- The nodes pull from the control plane every 5 seconds in this demo
  (`--control-plane-sync-interval 5s`; the default is 15 minutes), and a
  policy event brings the pull forward, so the grant lands within seconds.
- The model's answer is different every take.

## Recording

```bash
./record.sh                              # all ten steps
AGENTS=0 ./record.sh                     # steps 1 to 8
AGENTS_RC=~/agents.sh ./record.sh        # agent wrappers from a file
PUBLISH=0 ./record.sh                    # do not copy the video to site/static
AGENTMESH_BIN=/usr/local/bin ./record.sh # installed binaries instead of ./bin
```

The work directory is `$WORK_DIR` (default `~/agentmesh-share-local-model`).
The video is written to `out/demo.mp4` there and, unless `PUBLISH=0`, copied
to `site/static/demo-share-local-model.mp4`; `out/thumbnail.png` is a frame
from step 8.
