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
