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

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DefaultMaxMCPBodyInspectBytes is the default maximum HTTP request body size
// buffered when inspecting an MCP JSON-RPC 2.0 payload for tool-level policy
// evaluation (4 MiB).
const DefaultMaxMCPBodyInspectBytes int64 = 4 << 20

// InspectJSONRPCMCPBody inspects a JSON-RPC 2.0 request body for MCP methods
// and extracts the bare tool name when present, or sets allowStreamInit for
// session handshake, capability discovery, and protocol notification methods
// that precede a tool call.
func InspectJSONRPCMCPBody(body []byte) (mcpTool string, allowStreamInit bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return "", false
	}
	var rpc struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return "", false
	}
	switch rpc.Method {
	case "initialize", "notifications/initialized", "server/discover", "ping",
		"tools/list", "resources/list", "prompts/list", "notifications/cancelled":
		return "", true
	case "tools/call":
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(rpc.Params, &params); err != nil {
			return "", false
		}
		rawTool := strings.TrimSpace(params.Name)
		if rawTool == "" {
			return "", false
		}
		if _, stripped, err := SplitToolName(rawTool); err == nil {
			return stripped, false
		}
		return rawTool, false
	default:
		return "", false
	}
}

// InspectMCPHTTPRequestBody buffers and restores r.Body up to maxBytes
// (defaulting to DefaultMaxMCPBodyInspectBytes when maxBytes <= 0) and extracts
// the MCP tool name and stream initialization flag.
func InspectMCPHTTPRequestBody(r *http.Request, maxBytes int64) (mcpTool string, allowStreamInit bool, err error) {
	if r == nil {
		return "", false, nil
	}
	if strings.EqualFold(r.Method, http.MethodGet) || strings.EqualFold(r.Method, http.MethodDelete) {
		return "", true, nil
	}
	if r.Body == nil || !strings.EqualFold(r.Method, http.MethodPost) {
		return "", false, nil
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxMCPBodyInspectBytes
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return "", false, fmt.Errorf("failed to read MCP request body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if int64(len(bodyBytes)) > maxBytes {
		return "", false, fmt.Errorf("MCP request body exceeds maximum inspection size (%d bytes)", maxBytes)
	}
	tool, allowInit := InspectJSONRPCMCPBody(bodyBytes)
	return tool, allowInit, nil
}
