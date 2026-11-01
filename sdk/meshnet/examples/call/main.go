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
