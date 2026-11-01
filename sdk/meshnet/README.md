# `sdk/meshnet` — Embedded Go SDK for Agent Mesh

Package `meshnet` (`github.com/google/agentmesh/sdk/meshnet`) embeds an Agent Mesh member directly inside a Go binary—modeled on [`tailscale.com/tsnet`](https://pkg.go.dev/tailscale.com/tsnet)—with zero external `agentmesh-node` sidecar process, zero loopback bearer token, and byte-for-byte state directory compatibility (`identity.key` + `credential.json`) with `agentmesh-node`, `sdk/js`, and `sdk/python`.

## Capabilities

- **Lifecycle & State Compatibility (`Server.Up`, `WriteStateDir`, `ReadStateDir`):** Resumes cached credentials from `StateDir`, enrolls via `BootstrapTokenPath` / `BootstrapToken` / `JWTPath` / `TokenSource`, refreshes credentials proactively in the background, verifies signed `/keys` sets, and enforces live `/mesh/events/v1` FloodSub revocations and bans.
- **In-Process A2A Serving (`Server.ListenA2A`):** Returns in-memory `net.Listener`s (`PrivateListener` over `/libp2p-http` and optional `PublicListener` over `/mesh/ingress/1.0.0` in `EDGE` or `PASSTHROUGH` mode) plus canonical `PrivateURL` and `PublicURL` endpoints. Automatically relativizes and rewrites A2A `AgentCard` `supportedInterfaces` URLs per caller.
- **Unspoofable Caller Inspection (`Server.WhoIs`):** Maps `http.Request.RemoteAddr` on `PrivateListener` and `PublicListener` to the cryptographically verified `CallerInfo` (`PeerID`, `Principal`, `Roles`, `Labels`, `Task`) without trusting HTTP headers.
- **Outbound Mesh `*http.Client` (`Server.HTTPClient`, `Server.Discover`):** Routes `http://agentmesh.local/mesh/<peer_id>/<type>/<name>[/<rest>]` over authenticated libp2p streams, verifying provider Biscuits, `allowed_publish` Datalog grants, `EgressRequireLabels`, and `X-Mesh-Required-Labels` before sending request bytes.
- **Offline Task-Scoped Attenuation (`Server.AttenuateToken`):** Appends a validated `TaskAuthorizationRule` (`tar_block` fact, 0 Datalog rules, 0 checks) and optionally seals the Biscuit in memory to delegate task-scoped credentials to sub-agents or external workers without their own mesh client.
- **Local Progressive-Discovery MCP Server (`Server.MCPServer`, `Server.MCPHandler`):** Exposes the 6 mesh-operating tools (`list_local_services`, `discover_remote_services`, `get_mesh_info`, `find_remote_tools`, `describe_remote_tool`, `call_remote_tool`) in-process or over Streamable HTTP (e.g. a local Unix domain socket).
- **Zero-Secret OpenAI `/v1` Inference (`Server.InferenceHandler`):** Serves `GET /v1/models`, `POST /v1/chat/completions`, and `POST /v1/completions` routed over mesh `inference://*` providers with automatic Biscuit injection and streaming SSE pass-through.

## Quickstart

### 1. Serve an A2A Agent (Private P2P + Public HTTPS Ingress)

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/sdk/meshnet"
)

func main() {
	ctx := context.Background()

	srv := &meshnet.Server{
		StateDir:           "/var/lib/my-agent/agentmesh",
		ControlPlaneURL:    "https://bananas.sam-mesh.dev",
		BootstrapTokenPath: "/run/secrets/agentmesh-join-token",
	}
	status, err := srv.Up(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()

	ep, err := srv.ListenA2A(ctx, meshnet.A2AOptions{
		Name:         "coder",
		Description:  "Repository coding agent",
		Public:       true,
		IngressAuth:  api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE,
		IngressAllow: []string{"email:alice@example.com"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ep.Close()

	fmt.Printf("Peer ID:     %s\n", status.PeerID)
	fmt.Printf("Private A2A: %s\n", ep.PrivateURL)
	if ep.PublicURL != nil {
		fmt.Printf("Public A2A:  %s\n", ep.PublicURL)
	}

	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, cardHandler)
	mux.Handle("/invoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if caller, ok := srv.WhoIs(r.RemoteAddr); ok {
			log.Printf("verified caller principal=%s peer=%s task=%s", caller.Principal, caller.PeerID, caller.Task)
		}
		rpcHandler.ServeHTTP(w, r)
	}))

	go http.Serve(ep.PrivateListener, mux)
	if ep.PublicListener != nil {
		go http.Serve(ep.PublicListener, mux)
	}
	select {}
}
```

### 2. Discover & Call Remote Mesh Agents with Stock `a2a-go`

```go
providers, err := srv.Discover(ctx, api.ServiceType_SERVICE_TYPE_A2A, "coder")
if err != nil || len(providers) == 0 {
	log.Fatalf("coder not found: %v", err)
}

meshHTTP := srv.HTTPClient()
card, err := agentcard.NewResolver(meshHTTP).Resolve(ctx, providers[0].GetLocalProxyUrl())
if err != nil {
	log.Fatal(err)
}
client, err := a2aclient.NewFromCard(ctx, card, a2aclient.WithJSONRPCTransport(meshHTTP))
```

### 3. Expose Mesh MCP & Zero-Secret OpenAI `/v1` Over a Local Unix Socket

```go
unixLn, err := net.Listen("unix", "/run/agent/mesh.sock")
if err != nil {
	log.Fatal(err)
}
mux := http.NewServeMux()
mux.Handle("/mcp", srv.MCPHandler())
mux.Handle("/v1/", srv.InferenceHandler())
go http.Serve(unixLn, mux)
```

### 4. Interoperate with `agentmesh-node` State Directories

An operator can enroll interactively once with `agentmesh-node` and hand the resulting state directory directly to a Go binary embedding `meshnet.Server`:

```bash
agentmesh-node join --hub https://bananas.sam-mesh.dev
agentmesh-node state export ~/.config/my-agent/agentmesh
```
