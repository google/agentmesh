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
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateTaskAuthorizationRule(t *testing.T) {
	validExp := timestamppb.New(time.Date(2026, 10, 3, 15, 0, 0, 0, time.UTC))

	tests := []struct {
		name    string
		rule    *TaskAuthorizationRule
		wantErr bool
	}{
		{
			name:    "nil rule",
			rule:    nil,
			wantErr: true,
		},
		{
			name: "valid minimal rule",
			rule: &TaskAuthorizationRule{
				Name:        "bq-read",
				DisplayName: "BigQuery Read Task",
				ExpireTime:  validExp,
				Rules: []*TaskRule{
					{
						AllowedServices: []string{"mcp://bigquery", "inference://gemini.*", "egress://*.googleapis.com"},
						Operation: &TaskOperation{
							AllowedTools:       []string{"execute_sql"},
							AllowedMethods:     []string{"GET", "POST"},
							AllowedPaths:       []string{"/v1/projects/*", "/healthz"},
							AllowedPermissions: []string{"bigquery.jobs.create"},
						},
						AllowedResources: []string{"//bigquery.googleapis.com/projects/p1/datasets/d1"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty rules list is structurally valid (fails closed at evaluation)",
			rule: &TaskAuthorizationRule{
				Name: "deny-all",
			},
			wantErr: false,
		},
		{
			name: "name too long",
			rule: &TaskAuthorizationRule{
				Name: strings.Repeat("a", MaxTARNameLength+1),
			},
			wantErr: true,
		},
		{
			name: "too many rules",
			rule: &TaskAuthorizationRule{
				Rules: make([]*TaskRule, MaxRulesPerTAR+1),
			},
			wantErr: true,
		},
		{
			name: "rule with empty allowed_services",
			rule: &TaskAuthorizationRule{
				Rules: []*TaskRule{{}},
			},
			wantErr: true,
		},
		{
			name: "service with path segment rejected",
			rule: &TaskAuthorizationRule{
				Rules: []*TaskRule{{
					AllowedServices: []string{"egress://api.github.com/repos"},
				}},
			},
			wantErr: true,
		},
		{
			name: "service with two wildcards rejected",
			rule: &TaskAuthorizationRule{
				Rules: []*TaskRule{{
					AllowedServices: []string{"mcp://*.example.*"},
				}},
			},
			wantErr: true,
		},
		{
			name: "invalid lowercase HTTP method rejected",
			rule: &TaskAuthorizationRule{
				Rules: []*TaskRule{{
					AllowedServices: []string{"egress://api.github.com"},
					Operation:       &TaskOperation{AllowedMethods: []string{"get"}},
				}},
			},
			wantErr: true,
		},
		{
			name: "invalid HTTP path with dot segment rejected",
			rule: &TaskAuthorizationRule{
				Rules: []*TaskRule{{
					AllowedServices: []string{"egress://api.github.com"},
					Operation:       &TaskOperation{AllowedPaths: []string{"/repos/../secret"}},
				}},
			},
			wantErr: true,
		},
		{
			name: "invalid HTTP path with middle wildcard rejected",
			rule: &TaskAuthorizationRule{
				Rules: []*TaskRule{{
					AllowedServices: []string{"egress://api.github.com"},
					Operation:       &TaskOperation{AllowedPaths: []string{"/repos/*/issues"}},
				}},
			},
			wantErr: true,
		},
		{
			name: "invalid tool name with slash rejected",
			rule: &TaskAuthorizationRule{
				Rules: []*TaskRule{{
					AllowedServices: []string{"mcp://calc"},
					Operation:       &TaskOperation{AllowedTools: []string{"mcp://calc/add"}},
				}},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTaskAuthorizationRule(tc.rule)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateTaskAuthorizationRule() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestEncodeAndDecodeTARBlock(t *testing.T) {
	exp := time.Date(2026, 10, 3, 16, 0, 0, 0, time.UTC)
	orig := &TaskAuthorizationRule{
		Name:        "weather-lookup",
		DisplayName: "Weather Lookup Task",
		ExpireTime:  timestamppb.New(exp),
		Rules: []*TaskRule{
			{
				Description:     "Allow get_weather on weather MCP",
				AllowedServices: []string{"mcp://weather"},
				Operation: &TaskOperation{
					AllowedTools: []string{"get_weather"},
				},
			},
		},
	}

	fact, err := EncodeTARBlockFact(orig)
	if err != nil {
		t.Fatalf("EncodeTARBlockFact() unexpected error: %v", err)
	}
	parsed, err := ParseTARBlockSource(fact.String())
	if err != nil {
		t.Fatalf("ParseTARBlockSource(%q) unexpected error: %v", fact.String(), err)
	}
	if !proto.Equal(orig, parsed) {
		t.Fatalf("round-trip mismatch: got %v, want %v", parsed, orig)
	}

	// Empty rules must be rejected when encoding for attenuation.
	if _, err := EncodeTARBlockFact(&TaskAuthorizationRule{Name: "empty"}); err == nil {
		t.Fatal("expected EncodeTARBlockFact to reject empty rules")
	}

	// Unknown protobuf wire field must be rejected when decoding.
	raw, err := proto.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := protowire.AppendTag(raw, 99, protowire.VarintType)
	withUnknown = protowire.AppendVarint(withUnknown, 1)
	b64Unknown := base64.RawURLEncoding.EncodeToString(withUnknown)
	if _, err := DecodeTARBlockPayload(b64Unknown); err == nil {
		t.Fatal("expected DecodeTARBlockPayload to reject unknown protobuf fields")
	}

	// Padded base64 or non-tar_block source must be rejected.
	if _, err := ParseTARBlockSource(`node("attacker")`); err == nil {
		t.Fatal("expected ParseTARBlockSource to reject non-tar_block predicate")
	}
	if _, err := ParseTARBlockSource(`tar_block("abc=");`); err == nil {
		t.Fatal("expected ParseTARBlockSource to reject padded base64")
	}
}

func TestMatchServicePattern(t *testing.T) {
	tests := []struct {
		pattern string
		reqType string
		reqName string
		want    bool
	}{
		{"*", "mcp", "calculator", true},
		{"*", "egress", "api.github.com", true},
		{"mcp://*", "mcp", "calculator", true},
		{"mcp://*", "inference", "calculator", false},
		{"mcp://calculator", "mcp", "calculator", true},
		{"mcp://calculator", "mcp", "other", false},
		{"egress://*.googleapis.com", "egress", "bigquery.googleapis.com", true},
		{"egress://*.googleapis.com", "egress", "googleapis.com", false},
		{"egress://*.googleapis.com", "egress", "evilgoogleapis.com", false},
		{"inference://gemini.*", "inference", "gemini.pro", true},
		{"inference://gemini.*", "inference", "gemini", false},
		{"inference://gemini.*", "inference", "gemini2.pro", false},
	}

	for _, tc := range tests {
		got := MatchServicePattern(tc.pattern, tc.reqType, tc.reqName)
		if got != tc.want {
			t.Errorf("MatchServicePattern(%q, %q, %q) = %v, want %v", tc.pattern, tc.reqType, tc.reqName, got, tc.want)
		}
	}
}

func TestEvaluateTaskRulesIntersection(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	future := timestamppb.New(now.Add(10 * time.Minute))
	past := timestamppb.New(now.Add(-1 * time.Minute))

	// Hop 1 (Orchestrator): allows mcp://weather (get_weather, get_forecast) and egress://api.github.com (GET, POST /repos/acme/*)
	hop1 := &TaskAuthorizationRule{
		Name:        "orchestrator-scope",
		DisplayName: "Orchestrator Task",
		ExpireTime:  future,
		Rules: []*TaskRule{
			{
				AllowedServices: []string{"mcp://weather"},
				Operation:       &TaskOperation{AllowedTools: []string{"get_weather", "get_forecast"}},
			},
			{
				AllowedServices: []string{"egress://api.github.com"},
				Operation: &TaskOperation{
					AllowedMethods: []string{"GET", "POST"},
					AllowedPaths:   []string{"/repos/acme/*"},
				},
			},
		},
	}

	// Hop 2 (Sub-agent): narrows to mcp://weather (get_weather only) and egress://api.github.com (GET /repos/acme/public/*)
	hop2 := &TaskAuthorizationRule{
		Name:        "subagent-scope",
		DisplayName: "Subagent Task",
		ExpireTime:  future,
		Rules: []*TaskRule{
			{
				AllowedServices: []string{"mcp://weather"},
				Operation:       &TaskOperation{AllowedTools: []string{"get_weather"}},
			},
			{
				AllowedServices: []string{"egress://api.github.com"},
				Operation: &TaskOperation{
					AllowedMethods: []string{"GET"},
					AllowedPaths:   []string{"/repos/acme/public/*"},
				},
			},
		},
	}

	chain := []*TaskAuthorizationRule{hop1, hop2}

	cases := []struct {
		name    string
		req     TaskRequestContext
		wantErr bool
	}{
		{
			name:    "MCP tool in intersection allowed",
			req:     TaskRequestContext{ServiceType: "mcp", ServiceName: "weather", MCPTool: "get_weather"},
			wantErr: false,
		},
		{
			name:    "MCP stream handshake allowed before tools/call",
			req:     TaskRequestContext{ServiceType: "mcp", ServiceName: "weather", AllowMCPStreamInit: true},
			wantErr: false,
		},
		{
			name:    "MCP request without tool name denied when AllowMCPStreamInit is false",
			req:     TaskRequestContext{ServiceType: "mcp", ServiceName: "weather"},
			wantErr: true,
		},
		{
			name:    "MCP tool dropped in hop 2 denied",
			req:     TaskRequestContext{ServiceType: "mcp", ServiceName: "weather", MCPTool: "get_forecast"},
			wantErr: true,
		},
		{
			name:    "HTTP GET under narrowed prefix allowed",
			req:     TaskRequestContext{ServiceType: "egress", ServiceName: "api.github.com", HasHTTP: true, Method: "GET", Path: "/repos/acme/public/readme"},
			wantErr: false,
		},
		{
			name:    "HTTP POST dropped in hop 2 denied",
			req:     TaskRequestContext{ServiceType: "egress", ServiceName: "api.github.com", HasHTTP: true, Method: "POST", Path: "/repos/acme/public/readme"},
			wantErr: true,
		},
		{
			name:    "HTTP path outside hop 2 prefix denied",
			req:     TaskRequestContext{ServiceType: "egress", ServiceName: "api.github.com", HasHTTP: true, Method: "GET", Path: "/repos/acme/private/secret"},
			wantErr: true,
		},
		{
			name:    "CONNECT tunnel on HTTP-narrowed rule denied",
			req:     TaskRequestContext{ServiceType: "egress", ServiceName: "api.github.com", HasHTTP: true, Method: "CONNECT", Path: ""},
			wantErr: true,
		},
		{
			name:    "Non-HTTP request on HTTP-narrowed rule denied",
			req:     TaskRequestContext{ServiceType: "egress", ServiceName: "api.github.com", HasHTTP: false},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EvaluateTaskRules(chain, tc.req, now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("EvaluateTaskRules() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}

	// Expired TAR block must be rejected even if the rule matches.
	expiredChain := []*TaskAuthorizationRule{
		{
			Name:       "expired-hop",
			ExpireTime: past,
			Rules:      []*TaskRule{{AllowedServices: []string{"*"}}},
		},
	}
	if err := EvaluateTaskRules(expiredChain, TaskRequestContext{ServiceType: "mcp", ServiceName: "weather", MCPTool: "get_weather"}, now); err == nil {
		t.Fatal("expected expired TAR block to be rejected")
	}

	// Empty rules TAR block must deny all requests.
	emptyRulesChain := []*TaskAuthorizationRule{{Name: "empty-rules"}}
	if err := EvaluateTaskRules(emptyRulesChain, TaskRequestContext{ServiceType: "mcp", ServiceName: "weather"}, now); err == nil {
		t.Fatal("expected TAR block with empty rules to deny request")
	}
}

func TestEffectiveTARExpiration(t *testing.T) {
	base := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	authExp := base.Add(1 * time.Hour)
	hop1Exp := base.Add(30 * time.Minute)
	hop2Exp := base.Add(15 * time.Minute)

	blocks := []*TaskAuthorizationRule{
		{ExpireTime: timestamppb.New(hop1Exp)},
		{ExpireTime: timestamppb.New(hop2Exp)},
	}
	if got := EffectiveTARExpiration(authExp, blocks); !got.Equal(hop2Exp) {
		t.Fatalf("EffectiveTARExpiration() = %v, want %v", got, hop2Exp)
	}
}
