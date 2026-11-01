# `sdk/meshnet` — Embedded Go SDK for Agent Mesh

Package `meshnet` (`github.com/google/agentmesh/sdk/meshnet`) embeds an Agent Mesh member directly inside a Go binary—modeled on [`tailscale.com/tsnet`](https://pkg.go.dev/tailscale.com/tsnet)—with zero external `agentmesh-node` sidecar process, zero loopback bearer token, and byte-for-byte state directory compatibility (`identity.key` + `credential.json`) with `agentmesh-node`, `sdk/js`, and `sdk/python`.

For a full walkthrough, see the [Embedded Go SDK guide](../../site/content/docs/guides/go-sdk.md).

## Capabilities

- **Lifecycle & State Compatibility (`Server.Up`, `WriteStateDir`, `ReadStateDir`):** Built directly on `internal/node.AgentMeshNode` so embedded Go applications and `agentmesh-node` share one PEP. Holds an exclusive non-blocking lock (`ErrStateDirLocked`) on `StateDir` while running (or runs purely in memory with zero disk files when `StateDir` is empty), resumes cached credentials from `StateDir` (including public-client `OIDCSession` recovery that persists rotated `refresh_token`s before `POST /register`), enrolls via `BootstrapTokenPath` / `BootstrapToken` / `JWTPath` / `TokenSource`, returns from `Up` as soon as the first router admits the member while remaining dials up to `Routers` finish in the background, refreshes credentials proactively, backs off exponentially (`2s` to `5m`) and signals `Done()` / `Err()` / `OnCredentialLapse` (`ErrCredentialLapsed`, `Status.CredentialLapsed`) if a credential lapses, verifies signed `/keys` sets, and enforces live `/mesh/events/v1` FloodSub revocations and bans.
- **In-Process A2A Serving (`Server.ListenA2A`):** Announces `a2a://<name>` to the router directory (unless `NoAnnounce: true`) and returns in-memory `net.Listener`s (`PrivateListener` over `/libp2p-http` and optional `PublicListener` over `/mesh/ingress/1.0.0` in `EDGE` or `PASSTHROUGH` mode) plus canonical `PrivateURL` and `PublicURL` endpoints (`PublicURL` is `nil` when `NoAnnounce: true`, when no router advertises an `ingress_url`, or when the hub policy ceiling withholds public exposure). Automatically relativizes and rewrites A2A `AgentCard` `supportedInterfaces` URLs per caller.
- **Per-Server Prometheus Metrics (`Server.Registerer`):** Optionally registers `peer_id`-labeled state gauges and refusal/ingress counters (`agentmesh_meshnet_*`) so multiple `Server` instances can share a `prometheus.Registerer` without collision, unregistering all collectors on `Close`.
- **Unspoofable Caller Inspection (`Server.WhoIs`):** Maps `http.Request.RemoteAddr` on `PrivateListener` and `PublicListener` to the cryptographically verified `*CallerInfo` (`PeerID`, `Principal`, `Roles`, `Labels`, `Task`) without trusting HTTP headers. Returns `(nil, false)` for unauthenticated external requests (`INGRESS_AUTH_MODE_PASSTHROUGH` and anonymous `GET /.well-known/agent-card.json` discovery), and sets `PeerID` to `""` for verified external `EDGE` callers without a mesh node identity (such as OIDC users).
- **Outbound Mesh `*http.Client` (`Server.HTTPClient`, `Server.Discover`):** Routes `http://agentmesh.local/mesh/<peer_id>/<type>/<name>[/<rest>]` over authenticated libp2p streams, verifying provider Biscuits, `allowed_publish` Datalog grants, `EgressRequireLabels`, and `X-Mesh-Required-Labels` before sending request bytes.
- **Offline Task-Scoped Attenuation (`Server.AttenuateToken`):** Appends a validated `TaskAuthorizationRule` (`tar_block` fact, 0 Datalog rules, 0 checks) and optionally seals the Biscuit in memory to delegate task-scoped credentials to sub-agents or external workers without their own mesh client.
- **Local Progressive-Discovery MCP Server (`Server.MCPServer`, `Server.MCPHandler`):** Exposes the 6 mesh-operating tools (`list_local_services`, `discover_remote_services`, `get_mesh_info`, `find_remote_tools`, `describe_remote_tool`, `call_remote_tool`) in-process or over Streamable HTTP (for example over a local Unix domain socket).
- **Zero-Secret OpenAI `/v1` Inference (`Server.InferenceHandler`):** Serves `GET /v1/models`, `POST /v1/chat/completions`, and `POST /v1/completions` routed over mesh `inference://*` providers with automatic Biscuit injection and streaming SSE pass-through.

## Examples

### 1. Serve an A2A Agent (`examples/agent`)

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

### 2. Discover & Call Remote Mesh Agents (`examples/call`)

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

### 3. Interoperate with `agentmesh-node` State Directories

An operator can enroll interactively once with `agentmesh-node` and hand the resulting state directory directly to a Go binary embedding `meshnet.Server`:

```bash
agentmesh-node join --hub https://bananas.sam-mesh.dev
agentmesh-node state export ~/.config/my-agent/agentmesh
AGENTMESH_STATE_DIR=~/.config/my-agent/agentmesh go run ./sdk/meshnet/examples/agent
```
