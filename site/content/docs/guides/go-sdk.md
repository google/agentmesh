---
title: "Embedded Go SDK (meshnet)"
linkTitle: "Embedded Go SDK"
weight: 6
---

Package [`github.com/google/agentmesh/sdk/meshnet`](https://github.com/google/agentmesh/tree/main/sdk/meshnet)
embeds an Agent Mesh member directly inside a Go binary—modeled on
[`tailscale.com/tsnet`](https://pkg.go.dev/tailscale.com/tsnet)—with no external
`agentmesh-node` sidecar process and no loopback bearer token.

Use `sdk/meshnet` when you are shipping a single Go binary (an A2A agent, a CLI
such as `a2a-serve`, or an orchestrator) that should enroll, serve A2A over
private P2P and optional external HTTPS ingress, inspect verified callers, call
peer services, delegate attenuated task tokens, or hand local subprocesses a
Unix socket for progressive-discovery MCP and zero-secret `/v1` inference.

| Integration | Best fit | Directory announcement |
| :--- | :--- | :--- |
| **`sdk/meshnet` (Go)** | Single-binary Go agents, CLIs, and orchestrators | Announces `a2a://<name>` (plus optional external HTTP ingress) to the router directory unless `NoAnnounce: true`, and answers `system://mesh.catalog` |
| **[Native SDKs](../native-sdks/) (`sdk/js`, `sdk/python`)** | Node.js, browser, and Python agents | Answers `a2a://<name>` by Peer ID without publishing directory records |
| **`agentmesh-node` sidecar** | Language-agnostic sidecar/gateway wrapping unmodified servers (`mcp://`, `inference://`, `a2a://`), `egress://` `CloudTokenExchanger`, and Envoy / `agentgateway` PEPs | Publishes configured services from `agentmesh-node.yaml` |

Both runnable programs on this page live in
[`sdk/meshnet/examples`](https://github.com/google/agentmesh/tree/main/sdk/meshnet/examples)
and are compiled and linted in CI.

## 1. Start or join a mesh

For local development, run `agentmesh-one` in one terminal:

```bash
agentmesh-one --data-dir ~/agentmesh-one
```

Point your shell at its control plane URL and join-token file (never pass a
secret on a command-line flag where it would appear in `ps` output):

```bash
export AGENTMESH_CONTROL_PLANE_URL=http://127.0.0.1:33775   # API URL printed in the banner
export AGENTMESH_BOOTSTRAP_TOKEN_PATH=~/agentmesh-one/join-token
export AGENTMESH_INSECURE_CONTROL_PLANE=1                   # loopback http:// only; omit for https:// hubs
```

On a shared or production mesh (`https://...`), omit
`AGENTMESH_INSECURE_CONTROL_PLANE` and supply either `BootstrapTokenPath` or a
platform workload JWT via `JWTPath` / `TokenSource` (see
[Headless enrollment](../headless-enrollment/)).

## 2. Serve an A2A agent (Private P2P + Public HTTPS Ingress)

`Server.ListenA2A` registers an A2A service in-process, announces `a2a://<name>`
to the held mesh routers, and returns in-memory `net.Listener`s that work with
any `net/http` handler—including the unmodified official `a2a-go` server
(`github.com/a2aproject/a2a-go/v2/a2asrv`):

<!-- embed: sdk/meshnet/examples/agent/main.go -->
```go
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command agent embeds an Agent Mesh member in-process with sdk/meshnet and
// serves an A2A agent over private P2P (/libp2p-http) and router external HTTP
// ingress (/mesh/ingress/1.0.0), optionally exposing the local MCP and /v1
// inference handlers on a Unix domain socket.
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/sdk/meshnet"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &meshnet.Server{
		StateDir:           cmp.Or(os.Getenv("AGENTMESH_STATE_DIR"), "./state-agent"),
		ControlPlaneURL:    os.Getenv("AGENTMESH_CONTROL_PLANE_URL"),
		BootstrapTokenPath: os.Getenv("AGENTMESH_BOOTSTRAP_TOKEN_PATH"),
		JWTPath:            os.Getenv("AGENTMESH_JWT_PATH"),
		AllowInsecure:      os.Getenv("AGENTMESH_INSECURE_CONTROL_PLANE") == "1",
	}
	status, err := srv.Up(ctx)
	if err != nil {
		log.Fatalf("meshnet.Up: %v", err)
	}
	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("meshnet.Close: %v", err)
		}
	}()

	agentName := cmp.Or(os.Getenv("AGENTMESH_AGENT_NAME"), "coder")
	ep, err := srv.ListenA2A(ctx, meshnet.A2AOptions{
		Name:        agentName,
		Description: "Echo coding agent embedded via sdk/meshnet",
		Public:      true,
		IngressAuth: api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
	})
	if err != nil {
		log.Fatalf("ListenA2A: %v", err)
	}
	defer func() {
		if err := ep.Close(); err != nil {
			log.Printf("Endpoints.Close: %v", err)
		}
	}()

	exec := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			var prompt string
			if ec.Message != nil && len(ec.Message.Parts) > 0 {
				prompt = ec.Message.Parts[0].Text()
			}
			yield(a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("echo: "+prompt)), nil)
		}
	})
	card := &a2a.AgentCard{
		Name:        agentName,
		Description: "Echo coding agent embedded via sdk/meshnet",
		Version:     "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{
			{
				URL:             ep.PrivateURL.String() + "/invoke",
				ProtocolBinding: a2a.TransportProtocolJSONRPC,
				ProtocolVersion: "1.0",
			},
		},
	}

	rpcHandler := a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(exec))
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
	mux.Handle("/invoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if caller, ok := srv.WhoIs(r.RemoteAddr); ok && caller != nil {
			log.Printf("verified caller principal=%s peer=%s task=%s", caller.Principal, caller.PeerID, caller.Task)
		}
		rpcHandler.ServeHTTP(w, r)
	}))

	privHTTP := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	defer func() { _ = privHTTP.Close() }()
	go func() {
		if err := privHTTP.Serve(ep.PrivateListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Printf("private listener: %v", err)
		}
	}()

	if ep.PublicListener != nil {
		pubHTTP := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		defer func() { _ = pubHTTP.Close() }()
		go func() {
			if err := pubHTTP.Serve(ep.PublicListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				log.Printf("public listener: %v", err)
			}
		}()
	}

	if sockPath := os.Getenv("AGENTMESH_SOCKET_PATH"); sockPath != "" {
		_ = os.Remove(sockPath)
		var lc net.ListenConfig
		unixLn, err := lc.Listen(ctx, "unix", sockPath)
		if err != nil {
			log.Fatalf("listen unix %s: %v", sockPath, err)
		}
		defer func() {
			_ = unixLn.Close()
			_ = os.Remove(sockPath)
		}()
		localMux := http.NewServeMux()
		localMux.Handle("/mcp", srv.MCPHandler())
		localMux.Handle("/v1/", srv.InferenceHandler())
		localHTTP := &http.Server{Handler: localMux, ReadHeaderTimeout: 10 * time.Second}
		defer func() { _ = localHTTP.Close() }()
		go func() {
			if err := localHTTP.Serve(unixLn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				log.Printf("unix socket listener: %v", err)
			}
		}()
		fmt.Printf("Local Socket: %s (/mcp, /v1/)\n", sockPath)
	}

	fmt.Printf("Peer ID:      %s\n", status.PeerID)
	fmt.Printf("Private A2A:  %s\n", ep.PrivateURL)
	if ep.PublicURL != nil {
		fmt.Printf("Public A2A:   %s\n", ep.PublicURL)
	}
	<-ctx.Done()
}
```
<!-- /embed -->

Run the agent:

```bash
go run ./sdk/meshnet/examples/agent
```

```text
Peer ID:      12D3KooW...
Private A2A:  http://agentmesh.local/mesh/12D3KooW.../a2a/coder
Public A2A:   http://127.0.0.1:33776/ingress/12D3KooW.../a2a/coder
```

### How `ListenA2A` handles private and public traffic

- **Two listeners, one `http.Handler`:** `ep.PrivateListener` serves
  authenticated mesh peers over `/libp2p-http`. When `Public: true`,
  `ep.PublicListener` serves external HTTPS requests forwarded by enrolled
  routers over `/mesh/ingress/1.0.0`.
- **Automatic `AgentCard` URL rewriting:** `meshnet` relativizes interface URLs
  on `GET /.well-known/agent-card.json` and rewrites `supportedInterfaces` to
  match how each caller reached the agent (`http://agentmesh.local/mesh/<peer_id>/a2a/<name>`
  for mesh peers, `<public-ingress>/<peer_id>/a2a/<name>` for external HTTPS
  callers).
- **Unspoofable caller identity (`Server.WhoIs`):** Inside your HTTP handler,
  `srv.WhoIs(r.RemoteAddr)` returns the cryptographically verified `*CallerInfo`
  (`PeerID`, `Principal`, `Roles`, `Labels`, `Task`) bound to that in-memory
  connection—never trusting spoofable HTTP headers.
- **`EDGE` vs. `PASSTHROUGH` ingress:** `INGRESS_AUTH_MODE_EDGE` (the default)
  verifies Delegated Session Biscuits at both the router and the `meshnet`
  server (`identity.AuthorizeMeshRequest` + `IngressAllow`), while still serving
  `GET /.well-known/agent-card.json` anonymously for A2A discovery.
  `INGRESS_AUTH_MODE_PASSTHROUGH` strips spoofable `X-Mesh-*` headers and
  forwards `Authorization` untouched to your handler when your mesh role
  explicitly grants `PASSTHROUGH` in `PolicyRole.allowed_ingress`; see
  [External ingress](../external-ingress/).
- **Graceful policy-ceiling fallback & `NoAnnounce`:** If `Public: true` is
  requested on a hub whose `PolicyRole.allowed_ingress` denies public exposure
  for that service or auth mode, `ListenA2A` logs a warning, falls back to
  announcing the service privately inside the mesh, and sets `ep.PublicURL` to
  `nil` rather than failing startup. Likewise, setting `NoAnnounce: true` skips
  directory announcements so `ep.PublicURL` is `nil` even when `Public: true`
  (because routers hold no directory route for an unannounced service).

## 3. Discover and call mesh agents with stock `a2a-go`

`Server.Discover` queries the router directory for healthy providers of a
service, and `Server.HTTPClient` returns an `*http.Client` that routes
`http://agentmesh.local/mesh/<peer_id>/<type>/<name>[/<path>]` directly over
authenticated `/libp2p-http` streams:

<!-- embed: sdk/meshnet/examples/call/main.go -->
```go
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command call joins an Agent Mesh in-process with sdk/meshnet, discovers an
// A2A service by name (or dials an explicit mesh URL), and sends a message
// using the unmodified official a2a-go client over srv.HTTPClient().
package main

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2aclient/agentcard"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/sdk/meshnet"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	target := "coder"
	prompt := "hello from meshnet"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	if len(os.Args) > 2 {
		prompt = strings.Join(os.Args[2:], " ")
	}

	srv := &meshnet.Server{
		StateDir:           cmp.Or(os.Getenv("AGENTMESH_STATE_DIR"), "./state-caller"),
		ControlPlaneURL:    os.Getenv("AGENTMESH_CONTROL_PLANE_URL"),
		BootstrapTokenPath: os.Getenv("AGENTMESH_BOOTSTRAP_TOKEN_PATH"),
		JWTPath:            os.Getenv("AGENTMESH_JWT_PATH"),
		AllowInsecure:      os.Getenv("AGENTMESH_INSECURE_CONTROL_PLANE") == "1",
	}
	if _, err := srv.Up(ctx); err != nil {
		log.Fatalf("meshnet.Up: %v", err)
	}
	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("meshnet.Close: %v", err)
		}
	}()

	baseURL := target
	if !strings.HasPrefix(target, "http://") {
		providers, err := srv.Discover(ctx, api.ServiceType_SERVICE_TYPE_A2A, target)
		if err != nil {
			log.Fatalf("Discover(%q): %v", target, err)
		}
		if len(providers) == 0 {
			log.Fatalf("no providers found in mesh directory for a2a://%s", target)
		}
		baseURL = providers[0].GetLocalProxyUrl()
	}

	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	meshHTTP := srv.HTTPClient()
	card, err := agentcard.NewResolver(meshHTTP).Resolve(callCtx, baseURL)
	if err != nil {
		log.Fatalf("Resolve(%q): %v", baseURL, err)
	}
	client, err := a2aclient.NewFromCard(callCtx, card, a2aclient.WithJSONRPCTransport(meshHTTP))
	if err != nil {
		log.Fatalf("NewFromCard: %v", err)
	}
	res, err := client.SendMessage(callCtx, &a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(prompt)),
	})
	if err != nil {
		log.Fatalf("SendMessage: %v", err)
	}

	if msg, ok := res.(*a2a.Message); ok {
		for _, part := range msg.Parts {
			if text := part.Text(); text != "" {
				fmt.Println(text)
			}
		}
		return
	}
	fmt.Printf("%+v\n", res)
}
```
<!-- /embed -->

In a second terminal pointed at the same mesh, call the `coder` agent by name:

```bash
go run ./sdk/meshnet/examples/call coder "review PR #42"
```

```text
echo: review PR #42
```

Before sending a single byte of your request body, `srv.HTTPClient()` verifies
that the remote peer's Biscuit is signed by a trusted control-plane key, has
not been revoked or banned, is authorized by mesh policy to publish
`a2a://coder`, and carries every label required by `srv.EgressRequireLabels`
(and any per-request `X-Mesh-Required-Labels` header). Because `HTTPClient()`
sets no client-wide timeout, A2A Server-Sent Events (`SendStreamingMessage`) and
streaming LLM completions run unbounded while connection and header setup remain
bounded by libp2p stream deadlines.

## 4. Delegate task-scoped credentials (`AttenuateToken`)

When an orchestrator needs to hand a narrower, short-lived credential to a
worker or external sub-agent without giving it standing mesh authority, call
`srv.AttenuateToken` to append a `tar_block` (`api.TaskAuthorizationRule`, 0
Datalog rules, 0 checks) and optionally seal the Biscuit in memory:

```go
rule := &api.TaskAuthorizationRule{
	Name:        "review-pr-42",
	DisplayName: "Call a2a://coder only",
	Rules: []*api.TaskRule{
		{
			AllowedServices: []string{"a2a://coder"},
			Operation:       &api.TaskOperation{AllowedMethods: []string{"POST"}},
		},
	},
}

sealedToken, exp, err := srv.AttenuateToken(rule, 5*time.Minute, true)
```

Every Agent Mesh PEP (`agentmesh-router`, `agentmesh-node`, `sdk/meshnet`,
`sdk/js`, and `sdk/python`) enforces the strict intersection of Block 0 Datalog
RBAC and every appended `TaskAuthorizationRule`. With `seal == true`, the
recipient cannot append further blocks.

## 5. Local MCP and zero-secret `/v1` inference for subprocesses

When your Go process spawns an LLM runtime or CLI subprocess (for example Claude
Code, Gemini CLI, or a sandboxed coding tool), mount `srv.MCPHandler()` and
`srv.InferenceHandler()` on a local Unix domain socket (shown via
`AGENTMESH_SOCKET_PATH` in `examples/agent/main.go`):

- **`srv.MCPServer()` / `srv.MCPHandler()`** exposes the 6 progressive-discovery
  mesh tools (`list_local_services`, `discover_remote_services`,
  `get_mesh_info`, `find_remote_tools`, `describe_remote_tool`,
  `call_remote_tool`) so an agent discovers and invokes remote `mcp://*` tools
  across the mesh without loading hundreds of schemas upfront.
- **`srv.InferenceHandler()`** serves OpenAI-compatible `GET /v1/models`,
  `POST /v1/chat/completions`, and `POST /v1/completions` routed over mesh
  `inference://*` providers with automatic Biscuit injection, streaming SSE
  pass-through, and failover—requiring zero API keys in the subprocess
  environment.

## 6. State directory interoperability (`StateDir`)

`Server.StateDir` persists `identity.key` and `credential.json` with owner-only
permissions (`0700` directory, `0600` files) using the exact protobuf/protojson
layout shared by `agentmesh-node`, `sdk/js`, and `sdk/python`.

An operator can enroll interactively once with `agentmesh-node` and pass the
exported state directory directly to a Go binary built on `sdk/meshnet` (with no
join token needed at runtime):

```bash
agentmesh-node join --hub https://bananas.sam-mesh.dev
agentmesh-node state export ~/.config/my-agent/agentmesh
AGENTMESH_STATE_DIR=~/.config/my-agent/agentmesh go run ./sdk/meshnet/examples/agent
```

Conversely, a state directory populated by `meshnet.Server` (or written with
`meshnet.WriteStateDir` and inspected with `meshnet.ReadStateDir`) can be
imported into `agentmesh-node` with `agentmesh-node state import <dir>` or
opened directly by `sdk/js` and `sdk/python`. When `credential.json` carries an
`oidc_session` (public OIDC clients; no `client_secret` is stored), `meshnet`
persists any rotated `refresh_token` immediately before calling `POST /register`
so one-time refresh tokens survive transient hub failures.

## 7. Lifecycle signals and Prometheus metrics

- **Router admission (`Server.Up`, `Server.Status`):** `Up` returns as soon as
  the first router admits the member while any remaining dials up to
  `Server.Routers` (default `2`) complete in the background, so
  `Status.AttachedRouters` may briefly list one router right after `Up`.
- **Credential-lapse observation (`Done`, `Err`, `OnCredentialLapse`):** Unlike
  the standalone `agentmesh-node` binary, `meshnet.Server` never terminates the
  host process when a credential expires while the control plane or IdP is
  unreachable. Instead, background renewal retries with exponential backoff
  (`2s` up to `5m`), closes `srv.Done()`, sets `srv.Err()` to an error wrapping
  `meshnet.ErrCredentialLapsed`, invokes `srv.OnCredentialLapse` if configured,
  and reports live lapse state via `srv.Status().CredentialLapsed` (which clears
  back to `false` once a retry succeeds).
- **Per-Server Prometheus collectors (`Server.Registerer`):** Pass a
  `prometheus.Registerer` (for example `prometheus.DefaultRegisterer` or a
  custom `*prometheus.Registry`) to export `peer_id`-labeled state gauges and
  refusal/ingress counters (`agentmesh_meshnet_*`). Multiple `Server` instances
  can share one registry without colliding, and `srv.Close()` unregisters all
  collectors for that instance. Leave `Registerer` `nil` to disable metrics.
