#!/usr/bin/env bats

# Black-box CUJ for the agentmesh-one all-in-one binary: boot on a random port
# published in the banner, join real agentmesh-nodes through it, drive the admin CLI
# against the live server, and serve a model across the dataplane from an
# inference service declared in node A's configuration to node B's /v1
# endpoint (B -> router -> A). Mirrors docs/getting-started/your-own-mesh.
# In-process coverage lives in tests/integration/standalone_test.go; this file
# only exercises what needs the real binaries.

setup() {
  export AGENTMESH_ONE_BINARY="${AGENTMESH_ONE_BINARY:-./bin/agentmesh-one}"
  export AGENTMESH_NODE_BINARY="${AGENTMESH_NODE_BINARY:-./bin/agentmesh-node}"

  export TEST_TMPDIR
  TEST_TMPDIR="$(mktemp -d)"
  export HOME="$TEST_TMPDIR/home"
  export XDG_CONFIG_HOME="$HOME/.config"
  mkdir -p "$XDG_CONFIG_HOME"

  export AGENTMESH_ONE_DATA="$TEST_TMPDIR/agentmesh-one"
}

teardown() {
  if [[ -n "${ENVOY_CONTAINER:-}" ]]; then
    docker rm -f "$ENVOY_CONTAINER" >/dev/null 2>&1 || true
  fi
  for pid in "${BACKEND_PID:-}" "${NODE_A_PID:-}" "${NODE_B_PID:-}" "${AGENTMESH_ONE_PID:-}"; do
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
  local sock="$TEST_TMPDIR/node-$name/agentmesh.sock"
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
  curl -sf --unix-socket "$TEST_TMPDIR/node-$1/agentmesh.sock" http://localhost/debug/mesh-info |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["peer_id"])'
}

# start_node boots a background agentmesh-node joined via the bootstrap token; sets
# NODE_<NAME>_PID for teardown. The sidecar serves only on the Unix socket so
# two nodes on one host never fight over the default TCP bind, and loopback
# addresses must be publishable or peers on one host cannot dial each other.
# Extra arguments are passed through to the node (e.g. --config).
start_node() {
  local name="$1"
  shift
  AGENTMESH_API_TOKEN=e2e-secret "$AGENTMESH_NODE_BINARY" run \
    --control-plane "$AGENTMESH_ONE_URL" \
    --bootstrap-token "$JOIN_TOKEN" \
    --data-dir "$TEST_TMPDIR/node-$name" \
    --bind-addr= \
    --allow-loopback \
    --listen "/ip4/127.0.0.1/tcp/0" "$@" > "$TEST_TMPDIR/node-$name.log" 2>&1 3>&- &
  eval "NODE_${name^^}_PID=$!"
}

@test "agentmesh-one boots, nodes join over the single port, and the dataplane carries a service call" {
  "$AGENTMESH_ONE_BINARY" --bind-address 127.0.0.1 --port 0 \
    --data-dir "$AGENTMESH_ONE_DATA" > "$TEST_TMPDIR/agentmesh-one.log" 2>&1 3>&- &
  AGENTMESH_ONE_PID=$!

  # The random port is published in the banner, like the generated tokens.
  wait_for_log "$TEST_TMPDIR/agentmesh-one.log" "Join Token:"
  grep -q "Admin Token:  mesh_adm_" "$TEST_TMPDIR/agentmesh-one.log"
  AGENTMESH_ONE_PORT="$(grep -oE 'API URL:[[:space:]]+http://[^:]+:[0-9]+' "$TEST_TMPDIR/agentmesh-one.log" | grep -oE '[0-9]+$')"
  [[ -n "$AGENTMESH_ONE_PORT" ]]
  export AGENTMESH_ONE_URL="http://127.0.0.1:${AGENTMESH_ONE_PORT}"
  wait_for_http "$AGENTMESH_ONE_URL/healthz"

  # The embedded console is served from the same port.
  run curl -sf "$AGENTMESH_ONE_URL/console/"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"<html"* ]]

  # Two real nodes join through the single port with the persisted join token.
  JOIN_TOKEN="$(cat "$AGENTMESH_ONE_DATA/join-token")"
  [[ "$JOIN_TOKEN" == mesh_tok_* ]]

  # An OpenAI-compatible and MCP backend on node A's host, declared in node A's
  # configuration, as in docs/getting-started/your-own-mesh. Services only exist
  # by declaration at startup, there is no runtime registration endpoint. The
  # root URL (/) is also declared as `mcp` (not-an-mcp-server): the type is a
  # contract the node verifies, so that one must never be advertised, while
  # /mcp speaks MCP JSON-RPC and is advertised as mcp://github.
  python3 -u "$BATS_TEST_DIRNAME/fixtures/fake_openai.py" \
    > "$TEST_TMPDIR/backend.log" 2>&1 3>&- &
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
    name: github
    description: "e2e mcp backend"
    target_url: "http://127.0.0.1:${backend_port}/mcp"
  - type: mcp
    name: not-an-mcp-server
    description: "a plain HTTP server mislabelled as mcp"
    target_url: "http://127.0.0.1:${backend_port}"
  - type: a2a
    name: coding-agent
    description: "e2e a2a agent exposed on external ingress"
    target_url: "http://127.0.0.1:${backend_port}/a2a"
    ingress:
      auth_mode: edge
EOF

  start_node a --config "$TEST_TMPDIR/node-a-services.yaml"
  # Start node B with a local TCP sidecar listener (127.0.0.1:0) in addition to
  # its Unix socket so a real Envoy proxy can dial node B over h2c and forward
  # authorized traffic through node B into the mesh.
  start_node b --bind-addr "127.0.0.1:0"
  wait_for_node a
  wait_for_node b
  wait_for_log "$TEST_TMPDIR/node-b.log" "Starting MCP server on TCP address"
  node_b_tcp_port="$(grep -oE 'Starting MCP server on TCP address 127\.0\.0\.1:[0-9]+' "$TEST_TMPDIR/node-b.log" | grep -oE '[0-9]+$')"
  [[ -n "$node_b_tcp_port" ]]

  peer_a="$(node_peer_id a)"
  peer_b="$(node_peer_id b)"
  [[ -n "$peer_a" && -n "$peer_b" ]]

  sock_a="$TEST_TMPDIR/node-a/agentmesh.sock"
  sock_b="$TEST_TMPDIR/node-b/agentmesh.sock"
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

  # External HTTP ingress CUJ on the single agentmesh-one port:
  # 1. Non-exposed internal service (inference://laptop-llm) stays 404 on /ingress/.
  internal_ing_code="$(curl -s -o /dev/null -w '%{http_code}' \
    "$AGENTMESH_ONE_URL/ingress/${peer_a}/inference/laptop-llm/v1/models")"
  [[ "$internal_ing_code" -eq 404 ]]

  # 2. RFC 9728 Protected Resource Metadata and rewritten public A2A AgentCard
  #    are served on /ingress/ without caller credentials.
  run curl -sf "$AGENTMESH_ONE_URL/ingress/.well-known/oauth-protected-resource"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"\"resource\":\"$AGENTMESH_ONE_URL/ingress\""* ]]

  card_json=""
  for _ in $(seq 1 30); do
    card_json="$(curl -sf "$AGENTMESH_ONE_URL/ingress/${peer_a}/a2a/coding-agent/.well-known/agent-card.json" || true)"
    [[ "$card_json" == *"$AGENTMESH_ONE_URL/ingress/${peer_a}/a2a/coding-agent"* ]] && break
    sleep 0.5
  done
  [[ "$card_json" == *"$AGENTMESH_ONE_URL/ingress/${peer_a}/a2a/coding-agent"* ]]
  [[ "$card_json" == *"agentmesh_oauth2"* ]]

  # 3. Unauthenticated POST to edge-protected A2A service returns 401 with RFC 9728 WWW-Authenticate.
  run curl -sS -i -X POST "$AGENTMESH_ONE_URL/ingress/${peer_a}/a2a/coding-agent" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}'
  [[ "$output" == *"401 Unauthorized"* ]]
  [[ "$output" == *"resource_metadata=\"$AGENTMESH_ONE_URL/ingress/.well-known/oauth-protected-resource\""* ]]

  # 4. Authenticated external caller with a task-scoped Session Biscuit reaches
  #    Node A's A2A backend with verified X-Mesh-Ingress=edge attribution.
  a2a_biscuit="$(curl -sf --unix-socket "$sock_b" "http://localhost/oauth/token" \
    -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
    -d 'resource=a2a://coding-agent' |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
  [[ -n "$a2a_biscuit" ]]

  run curl -sf -X POST "$AGENTMESH_ONE_URL/ingress/${peer_a}/a2a/coding-agent" \
    -H "Authorization: Bearer $a2a_biscuit" \
    -H "X-Mesh-Principal: spoofed-admin" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}'
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"a2a ingress=edge"* ]]
  [[ "$output" != *"spoofed-admin"* ]]

  wrong_ing_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    "$AGENTMESH_ONE_URL/ingress/${peer_a}/a2a/coding-agent" \
    -H "Authorization: Bearer $wrong_biscuit" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}')"
  [[ "$wrong_ing_code" -eq 403 ]]

  # Real Envoy proxy CUJ: when Docker is available, place Envoy in front of node B
  # with both ext_authz and ext_proc configured over gRPC h2c, and drive real
  # inference (/v1/chat/completions) and MCP (/mesh/<peer_a>/mcp/github) calls
  # through Envoy -> Node B -> agentmesh-one Router -> Node A -> Backend.
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    envoy_port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

    cat > "$TEST_TMPDIR/envoy.yaml" <<EOF
static_resources:
  listeners:
    - name: listener_0
      address:
        socket_address:
          address: 127.0.0.1
          port_value: ${envoy_port}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: local_service
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: agentmesh_node_b_sidecar
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      transport_api_version: V3
                      grpc_service:
                        envoy_grpc:
                          cluster_name: agentmesh_node_b_h2c
                        timeout: 5s
                  - name: envoy.filters.http.ext_proc
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
                      grpc_service:
                        envoy_grpc:
                          cluster_name: agentmesh_node_b_h2c
                        timeout: 5s
                      allow_mode_override: true
                      message_timeout: 5s
                      processing_mode:
                        request_header_mode: SEND
                        response_header_mode: SKIP
                        request_body_mode: NONE
                        response_body_mode: NONE
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: agentmesh_node_b_h2c
      type: STATIC
      connect_timeout: 2s
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {}
      load_assignment:
        cluster_name: agentmesh_node_b_h2c
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: ${node_b_tcp_port}
    - name: agentmesh_node_b_sidecar
      type: STATIC
      connect_timeout: 2s
      load_assignment:
        cluster_name: agentmesh_node_b_sidecar
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: ${node_b_tcp_port}
EOF

    chmod 0644 "$TEST_TMPDIR/envoy.yaml"
    ENVOY_CONTAINER="sam-e2e-envoy-$$"
    docker run -d --name "$ENVOY_CONTAINER" \
      --network host \
      -v "$TEST_TMPDIR/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
      envoyproxy/envoy:v1.32-latest \
      -c /etc/envoy/envoy.yaml --log-level warning >/dev/null 3>&-

    envoy_ready=0
    for _ in $(seq 1 50); do
      code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${envoy_port}/mesh/${peer_a}/mcp/github" -X POST || true)"
      if [[ "$code" == "401" ]]; then
        envoy_ready=1
        break
      fi
      sleep 0.2
    done
    if [[ "$envoy_ready" -ne 1 ]]; then
      docker logs "$ENVOY_CONTAINER" >&2 || true
      cat "$TEST_TMPDIR/node-b.log" >&2 || true
      return 1
    fi

    # 1. OpenAI inference completion through Envoy -> Node B -> Router -> Node A -> fake_openai.py
    run curl -sS -i "http://127.0.0.1:${envoy_port}/v1/chat/completions" \
      -H "Authorization: Bearer $task_biscuit" \
      -H "X-Mesh-Target-Service: inference://laptop-llm" \
      -H 'Content-Type: application/json' \
      -d '{"model":"e2e-model","messages":[{"role":"user","content":"hi through envoy"}]}'
    if [[ "$status" -ne 0 || "$output" != *"hello from the mesh"* ]]; then
      echo "Envoy /v1/chat/completions failed ($status): $output" >&2
      docker logs "$ENVOY_CONTAINER" >&2 || true
      tail -n 50 "$TEST_TMPDIR/node-b.log" >&2 || true
      return 1
    fi

    # 2. Mint a Task Biscuit narrowed to mcp://github and tool:get_pr.
    mcp_task_biscuit="$(curl -sf --unix-socket "$sock_b" "http://localhost/oauth/token" \
      -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
      -d 'resource=mcp://github' \
      -d 'scope=tool:get_pr' |
      python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
    [[ -n "$mcp_task_biscuit" ]]

    # 2a. Allowed MCP tools/call ("get_pr") traverses Envoy (ext_authz + ext_proc body buffering) ->
    #     Node B (/mesh/<peer_a>/mcp/github) -> Router -> Node A -> MCP backend!
    run curl -sS -i "http://127.0.0.1:${envoy_port}/mesh/${peer_a}/mcp/github" \
      -H "Authorization: Bearer $mcp_task_biscuit" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pr"}}'
    if [[ "$status" -ne 0 || "$output" != *"tool=get_pr peer=${peer_b}"* ]]; then
      echo "Envoy MCP tools/call failed ($status): $output" >&2
      docker logs "$ENVOY_CONTAINER" >&2 || true
      tail -n 50 "$TEST_TMPDIR/node-b.log" >&2 || true
      tail -n 50 "$TEST_TMPDIR/node-a.log" >&2 || true
      return 1
    fi

    # 2b. Disallowed MCP tools/call ("delete_repo") is blocked at Envoy by ext_proc body inspection with 403 Forbidden.
    deny_code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${envoy_port}/mesh/${peer_a}/mcp/github" \
      -H "Authorization: Bearer $mcp_task_biscuit" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo"}}')"
    [[ "$deny_code" -eq 403 ]]
  fi

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

  if [[ -n "${envoy_port:-}" ]]; then
    envoy_revoked_code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${envoy_port}/v1/chat/completions" \
      -H "Authorization: Bearer $task_biscuit" \
      -H "X-Mesh-Target-Service: inference://laptop-llm" \
      -H 'Content-Type: application/json' \
      -d '{"model":"e2e-model","messages":[{"role":"user","content":"revoked task via envoy"}]}')"
    [[ "$envoy_revoked_code" -eq 403 ]]
  fi

  # The plain HTTP server never shows up as an MCP provider: node A had
  # registered every configured service before its API came up, so its
  # absence here is a verdict, not a race.
  run curl -sf --unix-socket "$sock_b" \
    "http://localhost/mesh/service/discover?type=mcp&name=not-an-mcp-server&timeout=3s"
  [[ "$status" -eq 0 ]]
  [[ "$output" != *"$peer_a"* ]]

  # The admin CLI works against the live server using the persisted admin token.
  run "$AGENTMESH_ONE_BINARY" token create --server "$AGENTMESH_ONE_URL" \
    --data-dir "$AGENTMESH_ONE_DATA" --description "e2e token"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"Token:    mesh-bt-"* ]]

  run "$AGENTMESH_ONE_BINARY" token list --server "$AGENTMESH_ONE_URL" --data-dir "$AGENTMESH_ONE_DATA"
  [[ "$status" -eq 0 ]]
  [[ "$output" == *"e2e token"* ]]
  # The two node enrollments above consumed join token usages.
  join_row="$(echo "$output" | grep "agentmesh-one join token")"
  [[ "$join_row" == *" 2/"* ]]
}

