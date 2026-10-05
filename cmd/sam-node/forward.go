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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/sam/internal/node"
	"github.com/spf13/cobra"
)

func newForwardCmd() *cobra.Command {
	var (
		forwardSocketPath   string
		forwardAPIAddr      string
		forwardAPITokenPath string
	)

	cmd := &cobra.Command{
		Use:          "forward egress://<name>:<port> <local-addr>",
		Short:        "Open a local TCP listener bound to a named EGRESS_MODE_TCP destination via CONNECT",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			hostPort, err := parseForwardTarget(args[0])
			if err != nil {
				return err
			}
			localAddr := strings.TrimSpace(args[1])
			if localAddr == "" {
				return fmt.Errorf("local-addr is required")
			}

			token, err := resolveForwardToken(forwardAPITokenPath)
			if err != nil {
				return err
			}

			apiAddr := strings.TrimSpace(forwardAPIAddr)
			if apiAddr == "" {
				apiAddr = strings.TrimSpace(os.Getenv("SAM_API_ADDR"))
			}

			var dialNode func(context.Context) (net.Conn, error)
			if apiAddr != "" {
				dialAddr := strings.TrimPrefix(strings.TrimPrefix(apiAddr, "http://"), "https://")
				dialNode = func(ctx context.Context) (net.Conn, error) {
					return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", dialAddr)
				}
			} else {
				sock := strings.TrimSpace(forwardSocketPath)
				if sock == "" {
					sock = resolveSocketPath(cmd)
				}
				if sock == "" {
					return fmt.Errorf("no Unix socket or --api-addr configured for sam-node forward")
				}
				dialNode = func(ctx context.Context) (net.Conn, error) {
					return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", sock)
				}
			}

			return runForwardListener(cmd.Context(), hostPort, localAddr, dialNode, token, nil)
		},
	}

	cmd.Flags().StringVar(&forwardSocketPath, "socket-path", "", "Unix socket of the running node (defaults to <data-dir>/"+node.DefaultSocketName+")")
	cmd.Flags().StringVar(&forwardAPIAddr, "api-addr", "", "TCP address of the running node sidecar (alternative to --socket-path, or env SAM_API_ADDR)")
	cmd.Flags().StringVar(&forwardAPITokenPath, "api-token-path", "", "Path to file containing Bearer token for sidecar authentication (or env SAM_TASK_TOKEN / SAM_API_TOKEN)")

	return cmd
}

func parseForwardTarget(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "egress://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return "", fmt.Errorf("invalid egress target %q: %w", raw, err)
		}
		if u.Scheme != "egress" {
			return "", fmt.Errorf("unsupported scheme %q (expected egress://<name>:<port>)", u.Scheme)
		}
		if u.Path != "" && u.Path != "/" {
			return "", fmt.Errorf("egress target %q must not include a path", raw)
		}
		trimmed = u.Host
	}
	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid egress target %q (expected egress://<name>:<port>): %w", raw, err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("egress target %q is missing destination name", raw)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid egress target port %q", portStr)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func resolveForwardToken(tokenPath string) (string, error) {
	if strings.TrimSpace(tokenPath) != "" {
		b, err := os.ReadFile(tokenPath) // #nosec G304 -- CLI flag path provided by operator
		if err != nil {
			return "", fmt.Errorf("reading --api-token-path: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if tok := strings.TrimSpace(os.Getenv("SAM_TASK_TOKEN")); tok != "" {
		return tok, nil
	}
	if tok := strings.TrimSpace(os.Getenv("SAM_API_TOKEN")); tok != "" {
		return tok, nil
	}
	return "", nil
}

func runForwardListener(ctx context.Context, targetHostPort, localAddr string, dialNode func(context.Context) (net.Conn, error), token string, readyCh chan<- string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", localAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", localAddr, err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if readyCh != nil {
		readyCh <- ln.Addr().String()
	}
	fmt.Fprintf(os.Stderr, "Forwarding %s -> egress://%s\n", ln.Addr().String(), targetHostPort)

	var wg sync.WaitGroup
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("accepting connection: %w", err)
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			_ = handleForwardConn(ctx, c, targetHostPort, dialNode, token)
		}(clientConn)
	}
	wg.Wait()
	return nil
}

func handleForwardConn(ctx context.Context, clientConn net.Conn, targetHostPort string, dialNode func(context.Context) (net.Conn, error), token string) error {
	defer func() { _ = clientConn.Close() }()

	nodeConn, err := dialNode(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = nodeConn.Close() }()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = clientConn.Close()
			_ = nodeConn.Close()
		case <-done:
		}
	}()

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetHostPort},
		Host:   targetHostPort,
		Header: make(http.Header),
	}
	if token != "" {
		req.Header.Set("Proxy-Authorization", "Bearer "+token)
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if err := req.Write(nodeConn); err != nil {
		return err
	}

	br := bufio.NewReader(nodeConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CONNECT %s rejected with status %s", targetHostPort, resp.Status)
	}

	if buffered := br.Buffered(); buffered > 0 {
		peeked, err := br.Peek(buffered)
		if err != nil {
			return err
		}
		if _, err := clientConn.Write(peeked); err != nil {
			return err
		}
		_, _ = br.Discard(buffered)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(nodeConn, clientConn)
		if tc, ok := nodeConn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, nodeConn)
		if tc, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
	return nil
}
