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

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestDisabledByDefault(t *testing.T) {
	var l *Logger
	// Calling Log or Close on a nil logger must not panic and must do nothing.
	l.Log(Record{
		CallerPeerID:   "12D3KooWCaller",
		ProviderPeerID: "12D3KooWProvider",
		ServiceName:    "calculator",
		ToolName:       "add",
		Outcome:        OutcomeOK,
	})
	if err := l.Close(); err != nil {
		t.Fatalf("Close on nil logger returned error: %v", err)
	}

	fromEmpty, err := NewFromFile("")
	if err != nil {
		t.Fatalf("NewFromFile(\"\") returned error: %v", err)
	}
	if fromEmpty != nil {
		t.Fatalf("NewFromFile(\"\") returned non-nil logger: %v", fromEmpty)
	}
}

func TestRecordFormattingAndExclusions(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)

	rec := Record{
		Timestamp:      "2026-11-28T13:00:00Z",
		CallerPeerID:   "12D3KooWCaller1111111111111111111111111111111111111",
		CallerLabels:   map[string]string{"region": "us-east-1", "tier": "gold"},
		ProviderPeerID: "12D3KooWProvider22222222222222222222222222222222222",
		ServiceName:    "code-reviewer",
		ToolName:       "review_pr",
		Outcome:        OutcomeOK,
		LatencyMS:      124.5,
		BytesIn:        512,
		BytesOut:       1024,
	}

	l.Log(rec)

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected newline at end of record, got %q", out)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("failed to parse JSONL output: %v", err)
	}

	// Verify all expected metadata fields are present.
	expectedFields := []string{
		"timestamp",
		"caller_peer_id",
		"caller_labels",
		"provider_peer_id",
		"service_name",
		"tool_name",
		"outcome",
		"latency_ms",
		"bytes_in",
		"bytes_out",
	}
	for _, f := range expectedFields {
		if _, ok := parsed[f]; !ok {
			t.Errorf("missing expected field %q in audit record", f)
		}
	}

	// Verify values
	if parsed["caller_peer_id"] != rec.CallerPeerID {
		t.Errorf("got caller_peer_id %v, want %v", parsed["caller_peer_id"], rec.CallerPeerID)
	}
	if parsed["provider_peer_id"] != rec.ProviderPeerID {
		t.Errorf("got provider_peer_id %v, want %v", parsed["provider_peer_id"], rec.ProviderPeerID)
	}
	if parsed["service_name"] != rec.ServiceName {
		t.Errorf("got service_name %v, want %v", parsed["service_name"], rec.ServiceName)
	}
	if parsed["tool_name"] != rec.ToolName {
		t.Errorf("got tool_name %v, want %v", parsed["tool_name"], rec.ToolName)
	}
	if parsed["outcome"] != OutcomeOK {
		t.Errorf("got outcome %v, want %v", parsed["outcome"], OutcomeOK)
	}
	if parsed["bytes_in"] != float64(512) {
		t.Errorf("got bytes_in %v, want 512", parsed["bytes_in"])
	}
	if parsed["bytes_out"] != float64(1024) {
		t.Errorf("got bytes_out %v, want 1024", parsed["bytes_out"])
	}

	// Verify that forbidden payload content is strictly absent.
	forbiddenKeys := []string{
		"arguments", "args", "params", "prompt", "result", "content",
		"response", "body", "token", "biscuit", "secret", "password", "headers",
	}
	for _, k := range forbiddenKeys {
		if _, ok := parsed[k]; ok {
			t.Errorf("forbidden payload field %q found in audit record", k)
		}
	}
}

func TestConcurrentAuditEvents(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			l.Log(Record{
				CallerPeerID:   "12D3KooWCaller",
				ProviderPeerID: "12D3KooWProvider",
				ServiceName:    "math-service",
				ToolName:       "calculate",
				Outcome:        OutcomeOK,
				LatencyMS:      float64(idx),
				BytesIn:        int64(idx * 10),
				BytesOut:       int64(idx * 20),
			})
		}(i)
	}

	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != concurrency {
		t.Fatalf("expected %d audit lines, got %d", concurrency, len(lines))
	}

	for i, line := range lines {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %d is not valid JSON: %v (content: %q)", i, err, line)
		}
		if r.ToolName != "calculate" || r.ServiceName != "math-service" {
			t.Errorf("line %d has invalid content: %+v", i, r)
		}
	}
}

type errWriter struct{}

func (e *errWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("simulated disk write failure")
}

func TestLoggingFailureDoesNotBreakToolExecution(t *testing.T) {
	l := New(&errWriter{})
	// Logging with a failing writer must not panic or cause an unhandled error.
	l.Log(Record{
		CallerPeerID:   "12D3KooWCaller",
		ProviderPeerID: "12D3KooWProvider",
		ServiceName:    "critical-service",
		ToolName:       "execute",
		Outcome:        OutcomeOK,
	})
}

func TestClassifyJSONRPCError(t *testing.T) {
	cases := []struct {
		code int64
		want string
	}{
		{api.JSONRPCCodeUnauthorized, OutcomeUnauthorized},
		{jsonrpc.CodeInvalidParams, OutcomeInvalidParams},
		{jsonrpc.CodeMethodNotFound, OutcomeNotFound},
		{jsonrpc.CodeInvalidRequest, OutcomeInvalidParams},
		{jsonrpc.CodeParseError, OutcomeInvalidParams},
		{jsonrpc.CodeInternalError, OutcomeBackendError},
		{-99999, OutcomeError},
	}
	for _, tc := range cases {
		got := ClassifyJSONRPCError(tc.code)
		if got != tc.want {
			t.Errorf("ClassifyJSONRPCError(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestNewFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit", "calls.jsonl")

	l, err := NewFromFile(logPath)
	if err != nil {
		t.Fatalf("NewFromFile failed: %v", err)
	}
	defer func() { _ = l.Close() }()

	l.Log(Record{
		CallerPeerID:   "12D3KooW1",
		ProviderPeerID: "12D3KooW2",
		ServiceName:    "echo",
		ToolName:       "ping",
		Outcome:        OutcomeOK,
		LatencyMS:      5.2,
	})

	if err := l.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), `"tool_name":"ping"`) {
		t.Fatalf("expected log to contain ping tool call, got %s", string(data))
	}

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log file: %v", err)
	}
	// Check file permissions are 0600
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected 0600 permissions, got %#o", perm)
	}
}

func TestDefaultTimestamp(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Log(Record{
		CallerPeerID: "12D3KooWCaller",
		ToolName:     "test",
	})
	var r Record
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Timestamp == "" {
		t.Fatal("expected timestamp to be populated automatically when empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Timestamp); err != nil {
		t.Fatalf("timestamp %q is not RFC3339: %v", r.Timestamp, err)
	}
}
