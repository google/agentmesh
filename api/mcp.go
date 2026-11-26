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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// JSON-RPC error codes AgentMesh itself returns on an MCP stream, as opposed
// to errors from the MCP backend it forwards. JSON-RPC 2.0 reserves -32768 to
// -32000 for the protocol, so these are outside that range.
const (
	// JSONRPCCodeUnauthorized answers a request the caller's credential does not
	// authorize: the caller reached the provider and was identified, but the task
	// in its biscuit does not allow this method or tool. The same request under
	// the same task is denied again.
	JSONRPCCodeUnauthorized = 1001
)

// DefaultMaxMCPBodyInspectBytes is the default maximum HTTP request body size
// buffered when inspecting an MCP JSON-RPC 2.0 payload for tool-level policy
// evaluation (4 MiB).
const DefaultMaxMCPBodyInspectBytes int64 = 4 << 20

// InspectJSONRPCMCPBody inspects a JSON-RPC 2.0 request body for MCP methods
// and extracts the bare tool name when present, or sets allowStreamInit for
// session handshake, capability discovery, and protocol notification methods
// that precede a tool call.
//
// The backend receives the same bytes and reads them with its own parser, so
// the method and the tool read here must be the ones every parser reads. A
// body that is not one JSON object, or that states "method", "params" or the
// tool "name" more than once (uniqueJSONMembers), names no tool and no
// handshake method: a task rule with allowed_tools denies it.
func InspectJSONRPCMCPBody(body []byte) (mcpTool string, allowStreamInit bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return "", false
	}
	members, err := uniqueJSONMembers(body, "method", "params")
	if err != nil {
		return "", false
	}
	var method string
	if err := json.Unmarshal(members["method"], &method); err != nil {
		return "", false
	}
	switch method {
	case "initialize", "notifications/initialized", "server/discover", "ping",
		"tools/list", "resources/list", "prompts/list", "notifications/cancelled":
		return "", true
	case "tools/call":
		name, err := MCPToolCallName(members["params"])
		if err != nil {
			return "", false
		}
		rawTool := strings.TrimSpace(name)
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

// MCPToolCallName returns the tool that the params of an MCP tools/call name.
// It fails when params is not one JSON object with one "name" member that
// holds a non-empty string (uniqueJSONMembers), so the tool an enforcement
// point checks is the tool the backend runs.
func MCPToolCallName(params []byte) (string, error) {
	members, err := uniqueJSONMembers(params, "name")
	if err != nil {
		return "", fmt.Errorf("params: %w", err)
	}
	var name string
	if err := json.Unmarshal(members["name"], &name); err != nil || name == "" {
		return "", errors.New(`params: no "name" member with a non-empty string`)
	}
	return name, nil
}

// uniqueJSONMembers returns the values of the named members of the JSON
// object doc. It fails when doc does not say the same thing to every JSON
// parser: when it is not one valid JSON object and nothing else, when a named
// member occurs more than once, and when a member differs from a name only in
// letter case. A case-insensitive parser, encoding/json among them, reads
// such a member as the named one and keeps the last; most others ignore it.
func uniqueJSONMembers(doc []byte, names ...string) (map[string]json.RawMessage, error) {
	// One value and nothing after it: the decoder below reads the first
	// value of a stream and does not look at what follows it.
	if !json.Valid(doc) {
		return nil, errors.New("not one valid JSON value")
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	members := make(map[string]json.RawMessage, len(names))
	for dec.More() {
		tok, err := dec.Token()
		key, isString := tok.(string)
		if err != nil || !isString {
			return nil, errors.New("not a JSON object")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		for _, name := range names {
			if !strings.EqualFold(key, name) {
				continue
			}
			if key != name {
				return nil, fmt.Errorf("member %q differs from %q only in letter case", key, name)
			}
			if _, seen := members[name]; seen {
				return nil, fmt.Errorf("member %q occurs more than once", name)
			}
			members[name] = value
		}
	}
	return members, nil
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
