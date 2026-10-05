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

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/google/sam/tests/extproc"
	"google.golang.org/grpc"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "listen address (host:port or unix:/path)")
	flag.Parse()

	network := "tcp"
	addr := *listen
	if sock, ok := strings.CutPrefix(addr, "unix:"); ok {
		network = "unix"
		addr = strings.TrimPrefix(sock, "//")
		_ = os.Remove(addr)
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalf("listen %s %s: %v", network, addr, err)
	}

	srv := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(srv, extproc.NewCalloutServer())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		srv.GracefulStop()
	}()

	if network == "unix" {
		fmt.Printf("READY unix:%s\n", addr)
	} else {
		fmt.Printf("READY %s\n", ln.Addr().String())
	}
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
