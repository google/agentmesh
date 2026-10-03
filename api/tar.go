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
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"google.golang.org/protobuf/proto"
)

// Structural bounds for holder-appended TaskAuthorizationRule (tar_block)
// attenuation blocks. Enforced identically by the Go, TypeScript, and Python
// verifiers before evaluating a request.
const (
	// MaxAttenuationBlocks is the maximum number of appended Biscuit blocks
	// (block index 1..MaxAttenuationBlocks) allowed on an inbound token.
	MaxAttenuationBlocks = 8

	// MaxTARBytes is the maximum serialized protobuf byte size of a single
	// TaskAuthorizationRule before base64url encoding.
	MaxTARBytes = 4096

	// MaxRulesPerTAR is the maximum number of TaskRule entries in one
	// TaskAuthorizationRule.
	MaxRulesPerTAR = 16

	// MaxEntriesPerTARList is the maximum number of strings in any repeated
	// field of TaskRule or TaskOperation.
	MaxEntriesPerTARList = 64

	// MaxTARNameLength is the maximum byte length of task_id, name, service
	// patterns, tool names, HTTP paths, and cloud permissions in a TAR.
	MaxTARNameLength = 128

	// MaxTARDescriptionLength is the maximum byte length of human-readable
	// description fields in TaskAuthorizationRule and TaskRule.
	MaxTARDescriptionLength = 256

	// MaxTARResourceLength is the maximum byte length of an allowed_resources
	// entry (e.g. a cloud resource manager path).
	MaxTARResourceLength = 256

	// TARBlockSourcePattern is the exact regular expression that every
	// appended block's Datalog source text must match across Go, TypeScript,
	// and Python verifiers. It permits only a single tar_block("<base64url>")
	// fact with zero rules and zero checks.
	TARBlockSourcePattern = `^tar_block\("([A-Za-z0-9_-]+)"\);?\s*$`
)

var (
	// TARBlockSourceRegex matches the Datalog source of a valid tar_block.
	TARBlockSourceRegex = regexp.MustCompile(TARBlockSourcePattern)
)

// HTTPMethodSyntaxPattern returns the regular expression string used to
// validate HTTP methods in PolicyRole.http and TaskOperation.allowed_methods.
func HTTPMethodSyntaxPattern() string {
	return httpMethodSyntax.String()
}

// ValidateTARServicePattern validates an entry in TaskRule.allowed_services
// using the same dot-anchored service grammar as PolicyRole.allowed_services
// ("*", "<type>://*", "<type>://*.<suffix>", "<type>://<prefix>.*",
// "<type>://<exact>").
func ValidateTARServicePattern(svc string) error {
	if svc == "" {
		return fmt.Errorf("allowed_services entry cannot be empty")
	}
	if len(svc) > MaxTARNameLength {
		return fmt.Errorf("allowed_services entry %q exceeds max length %d", svc, MaxTARNameLength)
	}
	if err := ValidateServiceFormat(svc); err != nil {
		return err
	}
	if svc == "*" {
		return nil
	}
	_, svcName := ParseServiceTarget(svc)
	if strings.Contains(svcName, "/") {
		return fmt.Errorf("invalid service format %q: path segments are not allowed in allowed_services (use allowed_paths)", svc)
	}
	if svcName != "*" && strings.Count(svcName, "*") > 1 {
		return fmt.Errorf("invalid service format %q: at most one wildcard is allowed", svc)
	}
	return nil
}

// ValidateTaskAuthorizationRule validates the structural limits and field
// grammars of a TaskAuthorizationRule. An empty rules list is valid and
// represents a fail-closed rule set that denies all requests.
func ValidateTaskAuthorizationRule(rule *TaskAuthorizationRule) error {
	if rule == nil {
		return fmt.Errorf("task authorization rule is nil")
	}
	if len(rule.GetName()) > MaxTARNameLength {
		return fmt.Errorf("name exceeds max length %d", MaxTARNameLength)
	}
	if len(rule.GetDisplayName()) > MaxTARDescriptionLength {
		return fmt.Errorf("display_name exceeds max length %d", MaxTARDescriptionLength)
	}
	if exp := rule.GetExpireTime(); exp != nil {
		if !exp.IsValid() {
			return fmt.Errorf("expire_time is invalid")
		}
		if exp.AsTime().Unix() <= 0 {
			return fmt.Errorf("expire_time must be after the Unix epoch")
		}
	}
	if len(rule.GetRules()) > MaxRulesPerTAR {
		return fmt.Errorf("rules count %d exceeds max %d", len(rule.GetRules()), MaxRulesPerTAR)
	}
	for i, r := range rule.GetRules() {
		if err := validateTaskRule(i, r); err != nil {
			return err
		}
	}
	return nil
}

func validateTaskRule(idx int, r *TaskRule) error {
	if r == nil {
		return fmt.Errorf("rule[%d] is nil", idx)
	}
	if len(r.GetDescription()) > MaxTARDescriptionLength {
		return fmt.Errorf("rule[%d]: description exceeds max length %d", idx, MaxTARDescriptionLength)
	}
	services := r.GetAllowedServices()
	if len(services) == 0 {
		return fmt.Errorf("rule[%d]: allowed_services must not be empty", idx)
	}
	if len(services) > MaxEntriesPerTARList {
		return fmt.Errorf("rule[%d]: allowed_services count %d exceeds max %d", idx, len(services), MaxEntriesPerTARList)
	}
	for _, svc := range services {
		if err := ValidateTARServicePattern(svc); err != nil {
			return fmt.Errorf("rule[%d]: %w", idx, err)
		}
	}
	if len(r.GetAllowedResources()) > MaxEntriesPerTARList {
		return fmt.Errorf("rule[%d]: allowed_resources count %d exceeds max %d", idx, len(r.GetAllowedResources()), MaxEntriesPerTARList)
	}
	for _, res := range r.GetAllowedResources() {
		if res == "" || len(res) > MaxTARResourceLength {
			return fmt.Errorf("rule[%d]: invalid allowed_resources entry %q", idx, res)
		}
	}
	op := r.GetOperation()
	if op == nil {
		return nil
	}
	if len(op.GetAllowedTools()) > MaxEntriesPerTARList {
		return fmt.Errorf("rule[%d]: allowed_tools count %d exceeds max %d", idx, len(op.GetAllowedTools()), MaxEntriesPerTARList)
	}
	for _, tool := range op.GetAllowedTools() {
		if tool == "" || len(tool) > MaxTARNameLength || strings.ContainsAny(tool, "/?# \t\r\n") {
			return fmt.Errorf("rule[%d]: invalid tool name %q in allowed_tools", idx, tool)
		}
	}
	if len(op.GetAllowedMethods()) > MaxEntriesPerTARList {
		return fmt.Errorf("rule[%d]: allowed_methods count %d exceeds max %d", idx, len(op.GetAllowedMethods()), MaxEntriesPerTARList)
	}
	for _, m := range op.GetAllowedMethods() {
		if !httpMethodSyntax.MatchString(m) {
			return fmt.Errorf("rule[%d]: method %q must be an uppercase HTTP method such as \"GET\"", idx, m)
		}
	}
	if len(op.GetAllowedPaths()) > MaxEntriesPerTARList {
		return fmt.Errorf("rule[%d]: allowed_paths count %d exceeds max %d", idx, len(op.GetAllowedPaths()), MaxEntriesPerTARList)
	}
	for _, p := range op.GetAllowedPaths() {
		if len(p) > MaxTARNameLength {
			return fmt.Errorf("rule[%d]: path %q exceeds max length %d", idx, p, MaxTARNameLength)
		}
		if err := validateHTTPGrantPath(p); err != nil {
			return fmt.Errorf("rule[%d]: %w", idx, err)
		}
	}
	if len(op.GetAllowedPermissions()) > MaxEntriesPerTARList {
		return fmt.Errorf("rule[%d]: allowed_permissions count %d exceeds max %d", idx, len(op.GetAllowedPermissions()), MaxEntriesPerTARList)
	}
	for _, perm := range op.GetAllowedPermissions() {
		if perm == "" || len(perm) > MaxTARNameLength || strings.ContainsAny(perm, " \t\r\n") {
			return fmt.Errorf("rule[%d]: invalid permission %q in allowed_permissions", idx, perm)
		}
	}
	return nil
}

// EncodeTARBlockPayload validates and serializes a TaskAuthorizationRule into
// its canonical unpadded base64url string representation.
func EncodeTARBlockPayload(rule *TaskAuthorizationRule) (string, error) {
	if err := ValidateTaskAuthorizationRule(rule); err != nil {
		return "", err
	}
	if len(rule.GetRules()) == 0 {
		return "", fmt.Errorf("task authorization rule must contain at least one rule when attenuating")
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(rule)
	if err != nil {
		return "", fmt.Errorf("marshal task authorization rule: %w", err)
	}
	if len(raw) == 0 || len(raw) > MaxTARBytes {
		return "", fmt.Errorf("serialized task authorization rule size %d out of range [1, %d]", len(raw), MaxTARBytes)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// EncodeTARBlockFact validates a TaskAuthorizationRule and returns the single
// tar_block("<base64url>") Datalog fact to append in a Biscuit block.
func EncodeTARBlockFact(rule *TaskAuthorizationRule) (biscuit.Fact, error) {
	encoded, err := EncodeTARBlockPayload(rule)
	if err != nil {
		return biscuit.Fact{}, err
	}
	return biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: FactTARBlock,
			IDs:  []biscuit.Term{biscuit.String(encoded)},
		},
	}, nil
}

// DecodeTARBlockPayload decodes an unpadded base64url string into a validated
// TaskAuthorizationRule, rejecting oversized payloads and unknown wire fields.
func DecodeTARBlockPayload(b64 string) (*TaskAuthorizationRule, error) {
	if b64 == "" {
		return nil, fmt.Errorf("empty tar_block payload")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url in tar_block: %w", err)
	}
	if len(raw) == 0 || len(raw) > MaxTARBytes {
		return nil, fmt.Errorf("tar_block protobuf size %d out of range [1, %d]", len(raw), MaxTARBytes)
	}
	var rule TaskAuthorizationRule
	if err := proto.Unmarshal(raw, &rule); err != nil {
		return nil, fmt.Errorf("unmarshal tar_block protobuf: %w", err)
	}
	if len(rule.ProtoReflect().GetUnknown()) > 0 {
		return nil, fmt.Errorf("tar_block protobuf contains unknown fields")
	}
	if err := ValidateTaskAuthorizationRule(&rule); err != nil {
		return nil, fmt.Errorf("invalid tar_block: %w", err)
	}
	return &rule, nil
}

// ParseTARBlockSource validates that a Biscuit block's Datalog source text
// contains solely a single tar_block("<base64url>") fact (with optional
// trailing semicolon and whitespace) and decodes its TaskAuthorizationRule.
func ParseTARBlockSource(blockSource string) (*TaskAuthorizationRule, error) {
	m := TARBlockSourceRegex.FindStringSubmatch(strings.TrimSpace(blockSource))
	if len(m) != 2 {
		return nil, fmt.Errorf("appended block must contain solely a single tar_block(\"<base64url>\") fact")
	}
	return DecodeTARBlockPayload(m[1])
}

// MatchServicePattern reports whether a service pattern from
// TaskRule.allowed_services matches the target (reqType, reqName) using the
// exact same dot-anchored semantics as BuildServiceDatalogFact and
// BaselineSources.Rules:
//   - "*" matches every non-empty (reqType, reqName)
//   - "<type>://*" matches every non-empty reqName of <type>
//   - "<type>://*.<suffix>" matches reqName ending with ".<suffix>"
//   - "<type>://<prefix>.*" matches reqName starting with "<prefix>."
//   - "<type>://<exact>" matches reqName == "<exact>"
func MatchServicePattern(pattern, reqType, reqName string) bool {
	if reqType == "" || reqName == "" || pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	pType, pName := ParseServiceTarget(pattern)
	if pType == "" || pType != reqType || pName == "" {
		return false
	}
	if pName == "*" {
		return true
	}
	if strings.HasPrefix(pName, "*.") && !strings.HasSuffix(pName, ".*") {
		return strings.HasSuffix(reqName, pName[1:])
	}
	if strings.HasSuffix(pName, ".*") && !strings.HasPrefix(pName, "*.") {
		return strings.HasPrefix(reqName, pName[:len(pName)-1])
	}
	return reqName == pName
}

// MatchHTTPPath reports whether a path pattern from TaskOperation.allowed_paths
// ("/exact" or "/prefix/*") matches reqPath using the same semantics as
// BuildHTTPGrantFacts and BaselineSources.HTTPRules.
func MatchHTTPPath(pattern, reqPath string) bool {
	if pattern == "" || reqPath == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(reqPath, strings.TrimSuffix(pattern, "*"))
	}
	return reqPath == pattern
}

// TaskRequestContext carries the wire attributes of a request evaluated
// against a chain of TaskAuthorizationRules.
type TaskRequestContext struct {
	ServiceType string
	ServiceName string

	// HasHTTP is true when the verifier handles the request as HTTP with
	// Method and Path taken from the wire. A CONNECT tunnel carries
	// Method == "CONNECT" and Path == "".
	HasHTTP bool
	Method  string
	Path    string

	// MCPTool is the tool name from params.name on an MCP tools/call request.
	MCPTool string

	// AllowMCPStreamInit permits an MCP session handshake (before tools/call)
	// to satisfy a rule whose only operation restriction is allowed_tools.
	// Every subsequent tools/call on the stream is evaluated with
	// AllowMCPStreamInit false and MCPTool set to params.name.
	AllowMCPStreamInit bool
}

// MatchTaskRule reports whether a single TaskRule permits req.
//
// Fail-closed semantics:
//   - allowed_services must have at least one entry matching (ServiceType, ServiceName).
//   - If operation.allowed_tools is non-empty, ServiceType must be "mcp" and
//     MCPTool must be in allowed_tools (unless AllowMCPStreamInit is true and
//     MCPTool is empty during stream setup).
//   - If operation.allowed_methods or operation.allowed_paths is non-empty,
//     the request must carry HTTP facts (HasHTTP && Method != "" &&
//     Method != "CONNECT" && Path != ""), and every non-empty axis must match.
//   - operation.allowed_permissions and rule.allowed_resources are opaque to
//     the wire PEP and consumed by CloudTokenExchanger at egress.
func MatchTaskRule(rule *TaskRule, req TaskRequestContext) bool {
	if rule == nil {
		return false
	}
	svcMatched := false
	for _, pattern := range rule.GetAllowedServices() {
		if MatchServicePattern(pattern, req.ServiceType, req.ServiceName) {
			svcMatched = true
			break
		}
	}
	if !svcMatched {
		return false
	}

	op := rule.GetOperation()
	if op == nil {
		return true
	}

	if tools := op.GetAllowedTools(); len(tools) > 0 {
		if req.ServiceType != "mcp" {
			return false
		}
		if req.MCPTool == "" {
			if !req.AllowMCPStreamInit {
				return false
			}
		} else if !slices.Contains(tools, req.MCPTool) {
			return false
		}
	}

	methods := op.GetAllowedMethods()
	paths := op.GetAllowedPaths()
	if len(methods) > 0 || len(paths) > 0 {
		if !req.HasHTTP || req.Method == "" || req.Method == "CONNECT" || req.Path == "" {
			return false
		}
		if len(methods) > 0 && !slices.Contains(methods, req.Method) {
			return false
		}
		if len(paths) > 0 {
			pathMatched := false
			for _, p := range paths {
				if MatchHTTPPath(p, req.Path) {
					pathMatched = true
					break
				}
			}
			if !pathMatched {
				return false
			}
		}
	}

	return true
}

// EvaluateTaskRules enforces the intersection of all appended
// TaskAuthorizationRule blocks in a Biscuit token:
//   - For each block, if expire_time is set and now > expire_time, the token
//     is rejected.
//   - For each block, at least one TaskRule in block.rules must match req; if
//     block.rules is empty or no rule matches, the request is denied.
func EvaluateTaskRules(blocks []*TaskAuthorizationRule, req TaskRequestContext, now time.Time) error {
	for i, block := range blocks {
		if block == nil {
			return fmt.Errorf("tar_block[%d] is nil", i+1)
		}
		if exp := block.GetExpireTime(); exp != nil {
			if !exp.IsValid() {
				return fmt.Errorf("tar_block[%d] has invalid expire_time", i+1)
			}
			if now.After(exp.AsTime()) {
				return fmt.Errorf("tar_block[%d] (%q) expired at %s", i+1, block.GetName(), exp.AsTime().UTC().Format(time.RFC3339))
			}
		}
		matched := false
		for _, r := range block.GetRules() {
			if MatchTaskRule(r, req) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("tar_block[%d] (%q) denied request to %s://%s", i+1, block.GetName(), req.ServiceType, req.ServiceName)
		}
	}
	return nil
}

// EffectiveTARExpiration returns the earliest expiration time across the
// authority block's expiration and every appended TaskAuthorizationRule's
// expire_time.
func EffectiveTARExpiration(authorityExp time.Time, blocks []*TaskAuthorizationRule) time.Time {
	effective := authorityExp
	for _, block := range blocks {
		if block == nil || block.GetExpireTime() == nil || !block.GetExpireTime().IsValid() {
			continue
		}
		t := block.GetExpireTime().AsTime()
		if effective.IsZero() || t.Before(effective) {
			effective = t
		}
	}
	return effective
}
