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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

type customError struct {
	message string
}

func (c *customError) Error() string {
	return c.message
}

func TestPolicyDenialClassifier_ServiceSubstring_DatalogEvaluationDenials(t *testing.T) {
	services := []string{
		"db-service",
		"auth-service",
		"payment-service",
		"user-service",
		"customer-service",
		"service-catalog",
		"microservice-alpha",
		"service",
		"my-service-v2",
		"orders-service-api",
		"service_mesh_registry",
	}

	formats := []string{
		"authorization check failed: missing fact: right(#authority, %q, \"execute\")",
		"datalog check failed: missing fact: right(#authority, %q, \"read\")",
		"missing fact: right(#authority, %q, \"write\")",
		"biscuit: verification failed: check 0: check if right(%q)",
		"failed to verify check: right(#authority, %q)",
		"failed to verify block 1: check if permit(%q)",
		"authorizer failure: no fact matches right(%q)",
		"allow_network_target: datalog rule rejected %q",
		"untrusted biscuit token targeting %q",
		"not bound to peer for target service %q",
	}

	for _, svc := range services {
		for i, fmtStr := range formats {
			t.Run(fmt.Sprintf("%s/format_%d", svc, i), func(t *testing.T) {
				msg := fmt.Sprintf(fmtStr, svc)
				err := errors.New(msg)
				reason := classifyPolicyDenialReason(err)
				if reason != api.PolicyDenialReason_DATALOG_EVALUATION_DENIED {
					t.Fatalf("service %q with error %q: expected DATALOG_EVALUATION_DENIED, got %v",
						svc, msg, reason)
				}
			})
		}
	}
}

func TestPolicyDenialClassifier_OperationSubstring_DatalogEvaluationDenials(t *testing.T) {
	operations := []string{
		"method",
		"path",
		"http_method",
		"method_call",
		"get_path",
		"path_eval",
		"method_dispatch",
		"request_path",
		"custom_method_handler",
		"path_traversal_validator",
	}

	formats := []string{
		"authorization check failed: missing fact: operation(#ambient, %q)",
		"datalog check failed: missing fact: method(#authority, %q)",
		"missing fact: action(#ambient, %q)",
		"failed to verify check: path(#ambient, %q)",
		"biscuit: verification failed: check 1: check if authorized_method(%q)",
	}

	for _, op := range operations {
		for i, fmtStr := range formats {
			t.Run(fmt.Sprintf("%s/format_%d", op, i), func(t *testing.T) {
				msg := fmt.Sprintf(fmtStr, op)
				err := errors.New(msg)
				reason := classifyPolicyDenialReason(err)
				if reason != api.PolicyDenialReason_DATALOG_EVALUATION_DENIED {
					t.Fatalf("operation %q with error %q: expected DATALOG_EVALUATION_DENIED, got %v",
						op, msg, reason)
				}
			})
		}
	}
}

func TestPolicyDenialClassifier_SubjectRoleSubstring_DatalogEvaluationDenials(t *testing.T) {
	roles := []string{
		"role",
		"admin-role",
		"role_operator",
		"auditor_role",
		"role_user",
		"super_role",
		"role_service_caller",
		"security_role_admin",
	}

	formats := []string{
		"authorization check failed: missing fact: role(#authority, %q)",
		"datalog check failed: missing fact: subject_role(#authority, %q)",
		"missing fact: caller_role(#ambient, %q)",
		"failed to verify check: has_role(#ambient, %q)",
		"authorizer failure: required fact: role(%q)",
	}

	for _, r := range roles {
		for i, fmtStr := range formats {
			t.Run(fmt.Sprintf("%s/format_%d", r, i), func(t *testing.T) {
				msg := fmt.Sprintf(fmtStr, r)
				err := errors.New(msg)
				reason := classifyPolicyDenialReason(err)
				if reason != api.PolicyDenialReason_DATALOG_EVALUATION_DENIED {
					t.Fatalf("role %q with error %q: expected DATALOG_EVALUATION_DENIED, got %v",
						r, msg, reason)
				}
			})
		}
	}
}

func TestPolicyDenialClassifier_BoundaryConditions(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected api.PolicyDenialReason
	}{
		{
			name:     "nil_error",
			err:      nil,
			expected: api.PolicyDenialReason_POLICY_DENIAL_REASON_UNSPECIFIED,
		},
		{
			name:     "empty_string_error",
			err:      errors.New(""),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "whitespace_only_error",
			err:      errors.New("   \t\n  "),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "arbitrary_unclassified_error",
			err:      errors.New("unexpected internal authorizer error 500"),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "custom_error_struct",
			err:      &customError{message: "datalog evaluation timeout on facts"},
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "custom_error_struct_empty",
			err:      &customError{message: ""},
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPolicyDenialReason(tc.err)
			if got != tc.expected {
				t.Fatalf("classifyPolicyDenialReason(%v) = %v, expected %v", tc.err, got, tc.expected)
			}
		})
	}
}

func TestPolicyDenialClassifier_MultiErrorChains_And_Sentinels(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected api.PolicyDenialReason
	}{
		{
			name:     "sentinel_biscuit_ErrPolicyDenied",
			err:      biscuit.ErrPolicyDenied,
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "wrapped_sentinel_biscuit_ErrPolicyDenied",
			err:      fmt.Errorf("layer3: %w", fmt.Errorf("layer2: %w", fmt.Errorf("layer1: %w", biscuit.ErrPolicyDenied))),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "sentinel_biscuit_ErrNoMatchingPolicy",
			err:      fmt.Errorf("eval failed: %w", biscuit.ErrNoMatchingPolicy),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "sentinel_biscuit_ErrInvalidSignature",
			err:      fmt.Errorf("signature bad: %w", biscuit.ErrInvalidSignature),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "sentinel_datalog_ErrWorldRunLimitTimeout",
			err:      fmt.Errorf("datalog limit: %w", datalog.ErrWorldRunLimitTimeout),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "sentinel_datalog_ErrWorldRunLimitMaxFacts",
			err:      fmt.Errorf("max facts exceeded: %w", datalog.ErrWorldRunLimitMaxFacts),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "sentinel_datalog_ErrWorldRunLimitMaxIterations",
			err:      fmt.Errorf("max iterations exceeded: %w", datalog.ErrWorldRunLimitMaxIterations),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "sentinel_ErrAuthRejected",
			err:      fmt.Errorf("pre-auth: %w", ErrAuthRejected),
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "wrapped_ErrProviderNotGranted",
			err:      fmt.Errorf("layer2: %w", fmt.Errorf("layer1: %w", ErrProviderNotGranted)),
			expected: api.PolicyDenialReason_UNAUTHORIZED_SERVICE,
		},
		{
			name:     "tar_block_precedence_over_datalog",
			err:      errors.New("tar_block[1]: denied due to authorization check failed missing fact"),
			expected: api.PolicyDenialReason_TASK_AUTHORIZATION_RULE_VIOLATION,
		},
		{
			name:     "revocation_precedence_over_datalog",
			err:      errors.New("biscuit token authority is revoked by control plane during datalog check"),
			expected: api.PolicyDenialReason_EXPIRED_CREDENTIAL,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPolicyDenialReason(tc.err)
			if got != tc.expected {
				t.Fatalf("classifyPolicyDenialReason(%v) = %v, expected %v", tc.err, got, tc.expected)
			}
		})
	}
}

func TestPolicyDenialClassifier_EndToEnd_PEP_RejectionSignals(t *testing.T) {
	disp := newChanDispatcher(20)
	n := &AgentMeshNode{
		containmentDispatcher: disp,
	}

	callerPID := peer.ID("12D3KooWTestCallerPeerID")

	services := []struct {
		name     string
		op       string
		errText  string
		expected api.PolicyDenialReason
	}{
		{
			name:     "db-service",
			op:       "query_records",
			errText:  "authorization check failed: missing fact: right(#authority, \"db-service\", \"query_records\")",
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "auth-service",
			op:       "validate_token_method",
			errText:  "datalog check failed: missing fact: right(#authority, \"auth-service\", \"validate_token_method\")",
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "payment-service",
			op:       "process_path_payment",
			errText:  "authorization check failed: missing fact: right(#authority, \"payment-service\", \"process_path_payment\")",
			expected: api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
		},
		{
			name:     "unauthorized-service-explicit",
			op:       "any_op",
			errText:  "unauthorized service: external provider not in manifest",
			expected: api.PolicyDenialReason_UNAUTHORIZED_SERVICE,
		},
		{
			name:     "role-mismatch-explicit",
			op:       "admin_op",
			errText:  "role mismatch: caller has role 'auditor' but requires 'admin'",
			expected: api.PolicyDenialReason_ROLE_MISMATCH,
		},
		{
			name:     "method-not-allowed-explicit",
			op:       "DELETE",
			errText:  "method not allowed: DELETE /api/v1/resource",
			expected: api.PolicyDenialReason_UNAUTHORIZED_PATH_OR_METHOD,
		},
	}

	for _, s := range services {
		t.Run(s.name, func(t *testing.T) {
			req := RequestContext{
				PeerID:   callerPID,
				Target:   s.name,
				Protocol: "/agentmesh/test/1.0.0",
				MCPTool:  s.op,
			}

			n.emitMiddlewarePolicyDenied(req, nil, errors.New(s.errText))

			evt := expectEventTimeout(t, disp, "agentmesh.policy.denied", time.Second)
			if evt == nil {
				t.Fatalf("expected event for %s, got nil", s.name)
			}
			if evt.SpecVersion != "1.0" {
				t.Errorf("expected SpecVersion 1.0, got %s", evt.SpecVersion)
			}
			if evt.EventTime == nil || evt.EventTime.AsTime().IsZero() {
				t.Errorf("expected non-zero EventTime, got %v", evt.EventTime)
			}
			pd := evt.GetPolicyDenied()
			if pd == nil {
				t.Fatalf("expected PolicyDenied payload, got nil")
			}
			if pd.Reason != s.expected {
				t.Fatalf("for service %s: expected reason %v, got %v", s.name, s.expected, pd.Reason)
			}
			if pd.TargetService != s.name {
				t.Errorf("expected TargetService %q, got %q", s.name, pd.TargetService)
			}
			if pd.RequestedOperation != s.op {
				t.Errorf("expected RequestedOperation %q, got %q", s.op, pd.RequestedOperation)
			}
		})
	}
}
