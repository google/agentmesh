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

// Package audit provides optional metadata-only call audit logging for tool
// invocations across mesh nodes and routers.
//
// Payloads, prompts, arguments, results, response bodies, credentials and tokens
// are strictly excluded by design.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/agentmesh/api"
	golog "github.com/ipfs/go-log/v2"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

var logger = golog.Logger("audit")

// Standard outcome classes for call audit records.
// Sensitive details or raw backend error messages must never be placed in outcome.
const (
	OutcomeOK                 = "ok"
	OutcomeUnauthorized       = "unauthorized"
	OutcomeInvalidParams      = "invalid_params"
	OutcomeNotFound           = "not_found"
	OutcomeTimeout            = "timeout"
	OutcomeCancelled          = "cancelled"
	OutcomeRateLimited        = "rate_limited"
	OutcomeToolError          = "tool_error"
	OutcomeBackendError       = "backend_error"
	OutcomeBadGateway         = "bad_gateway"
	OutcomeForbidden          = "forbidden"
	OutcomeCallFailed         = "call_failed"
	OutcomeLabelsNotSatisfied = "labels_not_satisfied"
	OutcomeProviderNotGranted = "provider_not_granted"
	OutcomeError              = "error"
)

// Record is a single structured JSONL tool call audit record.
// Deliberately captures only call metadata. Payloads, arguments, prompts, results,
// response bodies, and credentials are intentionally excluded.
type Record struct {
	Timestamp      string            `json:"timestamp"`
	CallerPeerID   string            `json:"caller_peer_id"`
	CallerLabels   map[string]string `json:"caller_labels,omitempty"`
	ProviderPeerID string            `json:"provider_peer_id"`
	ServiceName    string            `json:"service_name"`
	ToolName       string            `json:"tool_name"`
	Outcome        string            `json:"outcome"`
	LatencyMS      float64           `json:"latency_ms"`
	BytesIn        int64             `json:"bytes_in"`
	BytesOut       int64             `json:"bytes_out"`
}

// Logger writes audit records as atomic JSONL lines to a sink.
type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	closer io.Closer
}

// New creates a Logger writing to w. Nil w returns nil (disabled).
func New(w io.Writer) *Logger {
	if w == nil {
		return nil
	}
	return &Logger{out: w}
}

// NewFromFile opens the given path for appending JSONL records.
// Special path values "stdout" and "-" write to os.Stdout; "stderr" writes to os.Stderr.
// An empty path returns nil (disabled).
func NewFromFile(path string) (*Logger, error) {
	if path == "" {
		return nil, nil
	}
	switch path {
	case "stdout", "-":
		return &Logger{out: os.Stdout}, nil
	case "stderr":
		return &Logger{out: os.Stderr}, nil
	default:
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return nil, fmt.Errorf("create audit log directory %q: %w", dir, err)
			}
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("open audit log file %q: %w", path, err)
		}
		return &Logger{out: f, closer: f}, nil
	}
}

// Log writes an audit record as a single JSONL line.
// Safe for concurrent use. Failures to write are caught and swallowed so they never
// break tool execution.
func (l *Logger) Log(rec Record) {
	if l == nil {
		return
	}
	defer func() {
		_ = recover()
	}()

	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	data, err := json.Marshal(rec)
	if err != nil {
		logger.Debugf("failed to marshal audit record: %v", err)
		return
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.out != nil {
		if _, writeErr := l.out.Write(data); writeErr != nil {
			logger.Debugf("failed to write audit record: %v", writeErr)
		}
	}
}

// Close flushes and closes the underlying file if opened by NewFromFile.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// ClassifyJSONRPCError maps a JSON-RPC error code to a safe, standardized outcome class.
func ClassifyJSONRPCError(code int64) string {
	switch code {
	case api.JSONRPCCodeUnauthorized:
		return OutcomeUnauthorized
	case jsonrpc.CodeInvalidParams:
		return OutcomeInvalidParams
	case jsonrpc.CodeMethodNotFound:
		return OutcomeNotFound
	case jsonrpc.CodeInvalidRequest, jsonrpc.CodeParseError:
		return OutcomeInvalidParams
	case jsonrpc.CodeInternalError:
		return OutcomeBackendError
	default:
		return OutcomeError
	}
}
