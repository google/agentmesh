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

package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/audit"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *safeBuffer) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw := strings.TrimSpace(b.buf.String())
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

const testMCPProto = protocol.ID("/test/mcp/audit")

func setupTestMCPService(t *testing.T, ctx context.Context) (*AgentMeshNode, *AgentMeshNode, *safeBuffer, func()) {
	t.Helper()

	var toolCallsCount atomic.Int32
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		srv := mcp.NewServer(&mcp.Implementation{Name: "upstream", Version: "0.0.1"}, nil)
		srv.AddTool(&mcp.Tool{Name: "get_weather", Description: "returns weather", InputSchema: map[string]any{"type": "object"}},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				toolCallsCount.Add(1)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "sunny in SF"}}}, nil
			})
		srv.AddTool(&mcp.Tool{Name: "fail_tool", Description: "returns error result", InputSchema: map[string]any{"type": "object"}},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{
					IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: "tool failed internally"}},
				}, nil
			})
		srv.AddTool(&mcp.Tool{Name: "drop_table", Description: "forbidden tool", InputSchema: map[string]any{"type": "object"}},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "dropped"}}}, nil
			})
		return srv
	}, nil))

	nodeA, cleanupA := startBareNode(t, ctx)
	nodeB, cleanupB := startBareNode(t, ctx)

	buf := &safeBuffer{}
	nodeA.callAuditLogger = audit.New(buf)

	svc := &MCPService{baseService: baseService{
		info:    &api.ServiceInfo{Type: api.ServiceType_SERVICE_TYPE_MCP, Name: "weather"},
		backend: &api.RegisterServiceRequest_TargetUrl{TargetUrl: upstream.URL},
	}}
	if err := svc.Init(ctx); err != nil {
		t.Fatalf("MCPService.Init: %v", err)
	}
	nodeA.services.insertService(svc)

	tar := &api.TaskAuthorizationRule{
		Name: "weather-task",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"mcp://weather"},
			Operation:       &api.TaskOperation{AllowedTools: []string{"get_weather", "fail_tool"}},
		}},
	}

	nodeA.Host.SetStreamHandler(testMCPProto, func(s network.Stream) {
		nodeA.HandleMCPStream(s, RequestContext{
			PeerID:       s.Conn().RemotePeer(),
			Target:       "mcp://weather",
			TaskRules:    []*api.TaskAuthorizationRule{tar},
			CallerLabels: map[string]string{"env": "prod", "team": "data"},
		})
	})

	if err := nodeB.Host.Connect(ctx, peer.AddrInfo{ID: nodeA.Host.ID(), Addrs: nodeA.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	cleanup := func() {
		_ = svc.Teardown()
		cleanupB()
		cleanupA()
		upstream.Close()
	}

	return nodeA, nodeB, buf, cleanup
}

func TestNodeMCPAudit_DisabledByDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, nodeB, _, cleanup := setupTestMCPService(t, ctx)
	defer cleanup()

	// Explicitly disable audit logging on nodeA.
	nodeA.callAuditLogger = nil

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProto)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_weather",
		Arguments: map[string]any{"city": "secret_city_name"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("empty tool content")
	}
}

func TestNodeMCPAudit_InboundSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, nodeB, buf, cleanup := setupTestMCPService(t, ctx)
	defer cleanup()

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProto)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	secretParam := "classified_parameter_value"
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_weather",
		Arguments: map[string]any{"city": secretParam},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("empty tool content")
	}

	lines := buf.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit log record, got %d: %v", len(lines), lines)
	}

	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("failed to parse audit record: %v", err)
	}

	if rec.CallerPeerID != nodeB.Host.ID().String() {
		t.Errorf("CallerPeerID = %q, want %q", rec.CallerPeerID, nodeB.Host.ID().String())
	}
	if rec.ProviderPeerID != nodeA.Host.ID().String() {
		t.Errorf("ProviderPeerID = %q, want %q", rec.ProviderPeerID, nodeA.Host.ID().String())
	}
	if rec.ServiceName != "weather" {
		t.Errorf("ServiceName = %q, want %q", rec.ServiceName, "weather")
	}
	if rec.ToolName != "get_weather" {
		t.Errorf("ToolName = %q, want %q", rec.ToolName, "get_weather")
	}
	if rec.Outcome != audit.OutcomeOK {
		t.Errorf("Outcome = %q, want %q", rec.Outcome, audit.OutcomeOK)
	}
	if rec.CallerLabels["env"] != "prod" || rec.CallerLabels["team"] != "data" {
		t.Errorf("CallerLabels = %v, want env=prod, team=data", rec.CallerLabels)
	}
	if rec.LatencyMS <= 0 {
		t.Errorf("LatencyMS = %v, want > 0", rec.LatencyMS)
	}
	if rec.BytesIn <= 0 {
		t.Errorf("BytesIn = %d, want > 0", rec.BytesIn)
	}
	if rec.BytesOut <= 0 {
		t.Errorf("BytesOut = %d, want > 0", rec.BytesOut)
	}
	if _, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err != nil {
		t.Errorf("invalid RFC3339 timestamp %q: %v", rec.Timestamp, err)
	}

	// Payload and secret exclusion: Ensure argument values or secrets do not appear.
	if strings.Contains(lines[0], secretParam) {
		t.Errorf("audit record leaked secret argument payload %q: %s", secretParam, lines[0])
	}
	if strings.Contains(lines[0], "sunny in SF") {
		t.Errorf("audit record leaked response result payload: %s", lines[0])
	}
}

func TestNodeMCPAudit_InboundTARDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, nodeB, buf, cleanup := setupTestMCPService(t, ctx)
	defer cleanup()

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProto)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	// "drop_table" is not in TAR allowed tools, so it must be denied.
	_, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "drop_table",
		Arguments: map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error calling forbidden tool drop_table")
	}

	lines := buf.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit log record, got %d: %v", len(lines), lines)
	}

	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("failed to parse audit record: %v", err)
	}

	if rec.ToolName != "drop_table" {
		t.Errorf("ToolName = %q, want drop_table", rec.ToolName)
	}
	if rec.Outcome != audit.OutcomeUnauthorized {
		t.Errorf("Outcome = %q, want %q", rec.Outcome, audit.OutcomeUnauthorized)
	}
	if rec.CallerPeerID != nodeB.Host.ID().String() {
		t.Errorf("CallerPeerID = %q, want %q", rec.CallerPeerID, nodeB.Host.ID().String())
	}
}

func TestNodeMCPAudit_InboundToolError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, nodeB, buf, cleanup := setupTestMCPService(t, ctx)
	defer cleanup()

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProto)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "fail_tool",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool returned protocol error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError: true, got %+v", res)
	}

	lines := buf.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit log record, got %d: %v", len(lines), lines)
	}

	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("failed to parse audit record: %v", err)
	}

	if rec.ToolName != "fail_tool" {
		t.Errorf("ToolName = %q, want fail_tool", rec.ToolName)
	}
	if rec.Outcome != audit.OutcomeToolError {
		t.Errorf("Outcome = %q, want %q", rec.Outcome, audit.OutcomeToolError)
	}
}

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func TestNodeMCPAudit_LoggingFailureDoesNotBreakTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA, nodeB, _, cleanup := setupTestMCPService(t, ctx)
	defer cleanup()

	// Replace logger with one that always fails on Write.
	nodeA.callAuditLogger = audit.New(errWriter{})

	s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProto)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	defer func() { _ = s.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, NewStreamTransport(s), nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Tool call must still succeed.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_weather",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool failed despite audit failure tolerance: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("empty content returned")
	}
}

func TestNodeMCPAudit_ConcurrentEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeA, nodeB, buf, cleanup := setupTestMCPService(t, ctx)
	defer cleanup()

	const concurrency = 15
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			s, err := nodeB.Host.NewStream(ctx, nodeA.Host.ID(), testMCPProto)
			if err != nil {
				errCh <- fmt.Errorf("stream %d: %w", idx, err)
				return
			}
			defer func() { _ = s.Close() }()

			client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "0.0.1"}, nil)
			session, err := client.Connect(ctx, NewStreamTransport(s), nil)
			if err != nil {
				errCh <- fmt.Errorf("connect %d: %w", idx, err)
				return
			}
			defer func() { _ = session.Close() }()

			_, err = session.CallTool(ctx, &mcp.CallToolParams{
				Name:      "get_weather",
				Arguments: map[string]any{"i": idx},
			})
			if err != nil {
				errCh <- fmt.Errorf("call %d: %w", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	lines := buf.Lines()
	if len(lines) != concurrency {
		t.Fatalf("expected %d audit records, got %d", concurrency, len(lines))
	}

	for i, line := range lines {
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d invalid json (%s): %v", i, line, err)
		}
		if rec.ToolName != "get_weather" {
			t.Errorf("line %d: ToolName = %q, want get_weather", i, rec.ToolName)
		}
		if rec.Outcome != audit.OutcomeOK {
			t.Errorf("line %d: Outcome = %q, want ok", i, rec.Outcome)
		}
	}
}

func TestNodeMCPAudit_OutboundCallMCPTool_Error(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	nodeA, cleanupA := startBareNode(t, ctx)
	defer cleanupA()

	buf := &safeBuffer{}
	nodeA.callAuditLogger = audit.New(buf)

	// Target a peer with no route / connection, triggering dial failure.
	targetPID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
	_, err := nodeA.CallMCPTool(ctx, targetPID, "mcp://weather/get_forecast", map[string]any{"city": "Tokyo"}, nil)
	if err == nil {
		t.Fatal("expected CallMCPTool to fail for unconnected peer")
	}

	lines := buf.Lines()
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit record, got %d: %v", len(lines), lines)
	}

	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("failed to parse audit record: %v", err)
	}

	if rec.CallerPeerID != nodeA.Host.ID().String() {
		t.Errorf("CallerPeerID = %q, want %q", rec.CallerPeerID, nodeA.Host.ID().String())
	}
	if rec.ProviderPeerID != targetPID.String() {
		t.Errorf("ProviderPeerID = %q, want %q", rec.ProviderPeerID, targetPID.String())
	}
	if rec.ServiceName != "mcp://weather" {
		t.Errorf("ServiceName = %q, want mcp://weather", rec.ServiceName)
	}
	if rec.ToolName != "get_forecast" {
		t.Errorf("ToolName = %q, want get_forecast", rec.ToolName)
	}
	if rec.Outcome != audit.OutcomeCallFailed && rec.Outcome != audit.OutcomeTimeout {
		t.Errorf("Outcome = %q, want call_failed or timeout", rec.Outcome)
	}
	// Verify payload exclusion on outbound call: "Tokyo" must not be in audit record.
	if strings.Contains(lines[0], "Tokyo") {
		t.Errorf("audit record leaked arguments payload: %s", lines[0])
	}
}
