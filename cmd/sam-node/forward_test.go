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
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseForwardTarget(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "egress://pg.internal.example:5432", want: "pg.internal.example:5432"},
		{in: "pg.internal.example:5432", want: "pg.internal.example:5432"},
		{in: "egress://pg.internal.example", wantErr: true},
		{in: "egress://pg.internal.example:0", wantErr: true},
		{in: "egress://pg.internal.example:99999", wantErr: true},
		{in: "egress://pg.internal.example:5432/extra", wantErr: true},
		{in: "egress://:5432", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseForwardTarget(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseForwardTarget(%q) succeeded with %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseForwardTarget(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseForwardTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRunForwardListener(t *testing.T) {
	var seenHost, seenAuth string
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
			return
		}
		seenHost = r.Host
		seenAuth = r.Header.Get("Proxy-Authorization")
		rc := http.NewResponseController(w)
		conn, _, err := rc.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err == nil && line == "HELLO\n" {
			_, _ = io.WriteString(conn, "WORLD\n")
		}
	}))
	defer proxySrv.Close()
	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- runForwardListener(ctx, "pg.internal.example:5432", "127.0.0.1:0", func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", proxyAddr)
		}, "task-secret", readyCh)
	}()

	var listenAddr string
	select {
	case listenAddr = <-readyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for forward listener")
	}

	conn, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial forward listener: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "HELLO\n"); err != nil {
		t.Fatalf("Write HELLO: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("Read WORLD: %v", err)
	}
	if reply != "WORLD\n" {
		t.Fatalf("got reply %q, want WORLD\\n", reply)
	}
	if seenHost != "pg.internal.example:5432" {
		t.Fatalf("seenHost = %q, want pg.internal.example:5432", seenHost)
	}
	if seenAuth != "Bearer task-secret" {
		t.Fatalf("seenAuth = %q, want Bearer task-secret", seenAuth)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runForwardListener returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for runForwardListener shutdown")
	}
}
