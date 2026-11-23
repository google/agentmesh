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

// agentmesh-webapp serves the Agent Mesh Connect web app at /. It knows no
// control plane: the person using the page names one.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/agentmesh/internal/version"
	"github.com/google/agentmesh/internal/webapp"
)

func main() {
	var (
		bindAddr    = flag.String("bind-addr", "127.0.0.1:8082", "Address to serve the web app on. Loopback by default; to reach other devices put it behind https, because browsers refuse the page's cryptography on plain http to any host but localhost")
		showVersion = flag.Bool("version", false, "Print the version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}

	if missing := webapp.MissingBundle(); len(missing) > 0 {
		log.Printf("WARNING: this binary was built without the web app's SDK bundle (make all builds it); the page tells visitors so instead of enrolling them. Missing: %v", missing)
	}

	httpSrv := &http.Server{
		Addr:    *bindAddr,
		Handler: webapp.Handler(),
		// Mitigate Slowloris-style resource exhaustion from slow/malicious clients.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("Agent Mesh web app listening on %s", *bindAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Web app server error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Shutting down the web app server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
}
