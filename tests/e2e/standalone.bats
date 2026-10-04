#!/usr/bin/env bats

# Black-box CUJ for the sam-one all-in-one binary: boot on a random port
# published in the banner, join real sam-nodes through it, drive the admin CLI
# against the live server, and serve a model across the dataplane from an
# inference service declared in node A's configuration to node B's /v1
# endpoint (B -> router -> A). Mirrors docs/getting-started/your-own-mesh.
# In-process coverage lives in tests/integration/standalone_test.go; this file
# only exercises what needs the real binaries.

setup() {
  export SAM_ONE_BINARY="${SAM_ONE_BINARY:-./bin/sam-one}"
  export SAM_NODE_BINARY="${SAM_NODE_BINARY:-./bin/sam-node}"

  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export HOME="$TEST_TMPDIR/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  mkdir -p "$XDG_CONFIG_HOME"

  export SAM_ONE_DATA="$TEST_TMPDIR/sam-one"
}

teardown() {
  for pid in "${BACKEND_PID:-}" "${NODE_A_PID:-}" "${NODE_B_PID:-}" "${SAM_ONE_PID:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  # Give the processes a moment to release the sqlite/bbolt locks.
  wait 2>/dev/null || true
  chmod -R +w "$TEST_TMPDIR" || true
  rm -rf "$TEST_TMPDIR"
}

wait_for_http() {
  local url="$1"
  for _ in $(seq 1 100); do
    curl -sf "$url" > /dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}

wait_for_log() {
  local file="$1" needle="$2"
  for _ in $(seq 1 150); do
    grep -q "$needle" "$file" 2>/dev/null && return 0
    sleep 0.2
  done
  echo "timed out waiting for '$needle' in $file:" >&2
  cat "$file" >&2 || true
  return 1
}

# wait_for_node waits until the node named $1 serves its API on its socket,
# which it does only after it enrolled, a router admitted it, and every
# service in its configuration was registered. A node that exited fails at
# once, with its log.
wait_for_node() {
  local name="$1" pid_var="NODE_${1^^}_PID"
  local sock="$TEST_TMPDIR/node-$name/sam.sock"
  for _ in $(seq 1 150); do
    if ! kill -0 "${!pid_var}" 2>/dev/null; then
      echo "node $name exited before serving its API:" >&2
      cat "$TEST_TMPDIR/node-$name.log" >&2 || true
      return 1
    fi
    curl -sf --unix-socket "$sock" http://localhost/healthz > /dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "node $name did not serve its API in time:" >&2
  cat "$TEST_TMPDIR/node-$name.log" >&2 || true
  return 1
}

# node_peer_id is the peer ID node $1 reports for itself.
node_peer_id() {
  curl -sf --unix-socket "$TEST_TMPDIR/node-$1/sam.sock" http://localhost/debug/mesh-info |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["peer_id"])'
}

# start_node boots a background sam-node joined via the bootstrap token; sets
# NODE_<NAME>_PID for teardown. The sidecar serves only on the Unix socket so
# two nodes on one host never fight over the default TCP bind, and loopback
# addresses must be publishable or peers on one host cannot dial each other.
# Extra arguments are passed through to the node (e.g. --config).
start_node() {
  local name="$1"
  shift
  SAM_API_TOKEN=e2e-secret "$SAM_NODE_BINARY" run \
    --control-plane "$SAM_ONE_URL" \
    --bootstrap-token "$JOIN_TOKEN" \
    --data-dir "$TEST_TMPDIR/node-$name" \
    --bind-addr= \
    --allow-loopback \
    --listen "/ip4/127.0.0.1/tcp/0" "$@" > "$TEST_TMPDIR/node-$name.log" 2>&1 &
  eval "NODE_${name^^}_PID=$!"
}

@test "sam-one boots, nodes join over the single port, and the dataplane carries a service call" {
  "$SAM_ONE_BINARY" --bind-address 127.0.0.1 --port 0 \
    --data-dir "$SAM_ONE_DATA" > "$TEST_TMPDIR/sam-one.log" 2>&1 &
  SAM_ONE_PID=$!

  # The random port is published in the banner, like the generated tokens.
  wait_for_log "$TEST_TMPDIR/sam-one.log" "Join Token:"
  grep -q "Admin Token:  sam_adm_" "$TEST_TMPDIR/sam-one.log"
  SAM_ONE_PORT="$(grep -oE 'API URL:[[:space:]]+http://[^:]+:[0-9]+' "$TEST_TMPDIR/sam-one.log" | grep -oE '[0-9]+$')"
  [[ -n "$SAM_ONE_PORT" ]]
  export SAM_ONE_URL="http://127.0.0.1:${SAM_ONE_PORT}"
  wait_for_http "$SAM_ONE_URL/healthz"

  # The embedded console is served from the same port.
  run curl -sf "$SAM_ONE_URL/console/"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"<html"* ]]

  # Two real nodes join through the single port with the persisted join token.
  JOIN_TOKEN="$(cat "$SAM_ONE_DATA/join-token")"
  [[ "$JOIN_TOKEN" == sam_tok_* ]]

  # An OpenAI-compatible backend on node A's host, declared as an inference
  # service in node A's configuration, as in docs/getting-started/your-own-mesh.
  # Services only exist by declaration at startup, there is no runtime
  # registration endpoint. The same server is also declared as `mcp`: the
  # type is a contract the node verifies, so that one must never be advertised.
  python3 -u "$BATS_TEST_DIRNAME/fixtures/fake_openai.py" \
    > "$TEST_TMPDIR/backend.log" 2>&1 &
  BACKEND_PID=$!
  wait_for_log "$TEST_TMPDIR/backend.log" "listening on port"
  backend_port="$(grep -oE 'port [0-9]+' "$TEST_TMPDIR/backend.log" | grep -oE '[0-9]+')"

  cat > "$TEST_TMPDIR/node-a-services.yaml" <<EOF
version: "v1alpha1"
services:
  - type: inference
    name: laptop-llm
    description: "e2e inference backend"
    target_url: "http://127.0.0.1:${backend_port}"
  - type: mcp
    name: not-an-mcp-server
    description: "a plain HTTP server mislabelled as mcp"
    target_url: "http://127.0.0.1:${backend_port}"
EOF

  start_node a --config "$TEST_TMPDIR/node-a-services.yaml"
  start_node b
  wait_for_node a
  wait_for_node b
  peer_a="$(node_peer_id a)"
  [[ -n "$peer_a" ]]

  sock_a="$TEST_TMPDIR/node-a/sam.sock"
  sock_b="$TEST_TMPDIR/node-b/sam.sock"
  [[ -S "$sock_a" && -S "$sock_b" ]]

  # Node B's OpenAI-compatible endpoint lists the model with A as its owner:
  # the announcement crosses A -> router -> B over the mesh.
  models=""
  for _ in $(seq 1 30); do
    models="$(curl -sf --unix-socket "$sock_b" "http://localhost/v1/models" || true)"
    [[ "$models" == *'"e2e-model"'* ]] && break
    sleep 1
  done
  [[ "$models" == *'"e2e-model"'* ]]
  [[ "$models" == *"$peer_a"* ]]

  # A completion is routed B -> router -> A -> backend, exercising the full
  # dataplane, and comes back as the OpenAI response the backend produced.
  run curl -sf --unix-socket "$sock_b" "http://localhost/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -d '{"model":"e2e-model","messages":[{"role":"user","content":"hi"}]}'
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"hello from the mesh"* ]]

  # STS CUJ: Mint a task-scoped Biscuit on node B narrowed to inference://laptop-llm
  # via RFC 8693 POST /oauth/token and forward it across B -> router -> A.
  task_biscuit="$(curl -sf --unix-socket "$sock_b" "http://localhost/oauth/token" \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    -d 'resource=inference://laptop-llm' |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
  [[ -n "$task_biscuit" ]]

  run curl -sf --unix-socket "$sock_b" "http://localhost/v1/chat/completions" \
    -H "Authorization: Bearer $task_biscuit" \
    -H 'Content-Type: application/json' \
    -d '{"model":"e2e-model","messages":[{"role":"user","content":"hi with task biscuit"}]}'
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"hello from the mesh"* ]]

  # A Task Biscuit narrowed to a different resource (mcp://other) is rejected by node A's verifier.
  wrong_biscuit="$(curl -sf --unix-socket "$sock_b" "http://localhost/oauth/token" \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    -d 'resource=mcp://other' |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
  [[ -n "$wrong_biscuit" ]]

  http_code="$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$sock_b" \
    "http://localhost/v1/chat/completions" \
    -H "Authorization: Bearer $wrong_biscuit" \
    -H 'Content-Type: application/json' \
    -d '{"model":"e2e-model","messages":[{"role":"user","content":"should fail"}]}')"
  [[ "$http_code" -ne 200 ]]

  # Revoking the task Biscuit via RFC 7009 POST /oauth/revoke immediately blocks
  # reuse of that task Biscuit without revoking node B's standing identity.
  run curl -sf --unix-socket "$sock_b" "http://localhost/oauth/revoke" \
    --data-urlencode "token=$task_biscuit"
  [[ "$status" -eq 0 ]]

  revoked_code="$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$sock_b" \
    "http://localhost/v1/chat/completions" \
    -H "Authorization: Bearer $task_biscuit" \
    -H 'Content-Type: application/json' \
    -d '{"model":"e2e-model","messages":[{"role":"user","content":"revoked task"}]}')"
  [[ "$revoked_code" -eq 403 ]]

  # The plain HTTP server never shows up as an MCP provider: node A had
  # registered every configured service before its API came up, so its
  # absence here is a verdict, not a race.
  run curl -sf --unix-socket "$sock_b" \
    "http://localhost/sam/service/discover?type=mcp&name=not-an-mcp-server&timeout=3s"
  [[ "$status" -eq 0 ]]
  [[ "$output" != *"$peer_a"* ]]

  # The admin CLI works against the live server using the persisted admin token.
  run "$SAM_ONE_BINARY" token create --server "$SAM_ONE_URL" \
    --data-dir "$SAM_ONE_DATA" --description "e2e token"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Token:    sam-bt-"* ]]

  run "$SAM_ONE_BINARY" token list --server "$SAM_ONE_URL" --data-dir "$SAM_ONE_DATA"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"e2e token"* ]]
  # The two node enrollments above consumed join token usages.
  join_row="$(echo "$output" | grep "sam-one join token")"
  [[ "$join_row" == *" 2/"* ]]
}
