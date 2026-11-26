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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewWebhookHandler_CloudEventsValidation(t *testing.T) {
	handler := NewWebhookHandler(HandlerConfig{
		NoColor: true,
	})

	tests := []struct {
		name         string
		method       string
		headers      map[string]string
		body         string
		wantStatus   int
		wantContains string
	}{
		{
			name:       "reject GET method",
			method:     http.MethodGet,
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "reject missing ce-specversion",
			method: http.MethodPost,
			headers: map[string]string{
				headerCEID:     "123",
				headerCEType:   "agentmesh.policy.denied",
				headerCESource: "agentmesh://node/1",
			},
			wantStatus:   http.StatusBadRequest,
			wantContains: "ce-specversion header must be '1.0'",
		},
		{
			name:   "reject invalid ce-specversion",
			method: http.MethodPost,
			headers: map[string]string{
				headerCESpecVersion: "0.3",
				headerCEID:          "123",
				headerCEType:        "agentmesh.policy.denied",
				headerCESource:      "agentmesh://node/1",
			},
			wantStatus:   http.StatusBadRequest,
			wantContains: "ce-specversion header must be '1.0'",
		},
		{
			name:   "reject missing ce-id",
			method: http.MethodPost,
			headers: map[string]string{
				headerCESpecVersion: "1.0",
				headerCEType:        "agentmesh.policy.denied",
				headerCESource:      "agentmesh://node/1",
			},
			wantStatus:   http.StatusBadRequest,
			wantContains: "ce-id header is required",
		},
		{
			name:   "reject missing ce-type",
			method: http.MethodPost,
			headers: map[string]string{
				headerCESpecVersion: "1.0",
				headerCEID:          "123",
				headerCESource:      "agentmesh://node/1",
			},
			wantStatus:   http.StatusBadRequest,
			wantContains: "ce-type header is required",
		},
		{
			name:   "reject missing ce-source",
			method: http.MethodPost,
			headers: map[string]string{
				headerCESpecVersion: "1.0",
				headerCEID:          "123",
				headerCEType:        "agentmesh.policy.denied",
			},
			wantStatus:   http.StatusBadRequest,
			wantContains: "ce-source header is required",
		},
		{
			name:   "reject invalid JSON payload",
			method: http.MethodPost,
			headers: map[string]string{
				headerCESpecVersion: "1.0",
				headerCEID:          "123",
				headerCEType:        "agentmesh.policy.denied",
				headerCESource:      "agentmesh://node/1",
			},
			body:         "{not-valid-json}",
			wantStatus:   http.StatusBadRequest,
			wantContains: "protojson unmarshal failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/events", bytes.NewBufferString(tc.body))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status code = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantContains != "" && !bytes.Contains(rec.Body.Bytes(), []byte(tc.wantContains)) {
				t.Fatalf("response body %q does not contain %q", rec.Body.String(), tc.wantContains)
			}
		})
	}
}

func TestNewWebhookHandler_HMACVerification(t *testing.T) {
	secret := []byte("test-shared-hmac-secret-key-32b")
	handler := NewWebhookHandler(HandlerConfig{
		HMACSecret: secret,
		NoColor:    true,
	})

	now := timestamppb.Now()
	event := &api.SecuritySignalEvent{
		Id:              "sig-test-1",
		Source:          "urn:agentmesh:node:node-1",
		SpecVersion:     "1.0",
		Type:            "agentmesh.identity.revoked",
		EventTime:       now,
		DataContentType: "application/json",
		Data: &api.SecuritySignalEvent_IdentityRevoked{
			IdentityRevoked: &api.IdentityRevokedSignal{
				PeerId:    "peer-banned",
				Reason:    "malicious activity",
				EventTime: now,
			},
		},
	}
	bodyBytes, err := protojson.Marshal(event)
	if err != nil {
		t.Fatalf("protojson.Marshal failed: %v", err)
	}

	tsMillis := time.Now().UnixMilli()
	tsStr := strconv.FormatInt(tsMillis, 10)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tsStr))
	mac.Write([]byte("."))
	mac.Write(bodyBytes)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	t.Run("missing HMAC headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(bodyBytes))
		req.Header.Set(headerCESpecVersion, "1.0")
		req.Header.Set(headerCEID, event.Id)
		req.Header.Set(headerCEType, event.Type)
		req.Header.Set(headerCESource, event.Source)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("invalid HMAC signature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(bodyBytes))
		req.Header.Set(headerCESpecVersion, "1.0")
		req.Header.Set(headerCEID, event.Id)
		req.Header.Set(headerCEType, event.Type)
		req.Header.Set(headerCESource, event.Source)
		req.Header.Set(headerAgentMeshTimestamp, tsStr)
		req.Header.Set(headerAgentMeshSignature, "sha256=0000000000000000000000000000000000000000000000000000000000000000")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("expired timestamp", func(t *testing.T) {
		expiredTs := strconv.FormatInt(time.Now().Add(-10*time.Minute).UnixMilli(), 10)
		expMac := hmac.New(sha256.New, secret)
		expMac.Write([]byte(expiredTs))
		expMac.Write([]byte("."))
		expMac.Write(bodyBytes)
		expSig := "sha256=" + hex.EncodeToString(expMac.Sum(nil))

		req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(bodyBytes))
		req.Header.Set(headerCESpecVersion, "1.0")
		req.Header.Set(headerCEID, event.Id)
		req.Header.Set(headerCEType, event.Type)
		req.Header.Set(headerCESource, event.Source)
		req.Header.Set(headerAgentMeshTimestamp, expiredTs)
		req.Header.Set(headerAgentMeshSignature, expSig)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for expired timestamp, got %d", rec.Code)
		}
	})

	t.Run("valid HMAC signature accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(bodyBytes))
		req.Header.Set(headerCESpecVersion, "1.0")
		req.Header.Set(headerCEID, event.Id)
		req.Header.Set(headerCEType, event.Type)
		req.Header.Set(headerCESource, event.Source)
		req.Header.Set(headerAgentMeshTimestamp, tsStr)
		req.Header.Set(headerAgentMeshSignature, validSig)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
		}
	})
}

func TestNewWebhookHandler_AllFourSignalTypes(t *testing.T) {
	handler := NewWebhookHandler(HandlerConfig{
		NoColor: true,
	})

	now := timestamppb.Now()

	events := []*api.SecuritySignalEvent{
		{
			Id:          "test-policy-denied",
			Source:      "urn:agentmesh:node:node-1",
			SpecVersion: "1.0",
			Type:        "agentmesh.policy.denied",
			EventTime:   now,
			Data: &api.SecuritySignalEvent_PolicyDenied{
				PolicyDenied: &api.PolicyDeniedSignal{
					Direction:     api.SignalCallerDirection_LOCAL_WORKLOAD,
					Reason:        api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
					Detail:        "denied by biscuit authority block",
					TargetService: "calculator",
					EventTime:     now,
				},
			},
		},
		{
			Id:          "test-transport-refused",
			Source:      "urn:agentmesh:node:node-1",
			SpecVersion: "1.0",
			Type:        "agentmesh.transport.refused",
			EventTime:   now,
			Data: &api.SecuritySignalEvent_TransportRefused{
				TransportRefused: &api.TransportRefusedSignal{
					Reason:         api.TransportRefusalReason_PEER_UNAUTHENTICATED,
					Detail:         "auth deadline exceeded",
					PeerId:         "12D3KooWPeer1",
					CoalescedCount: 3,
					EventTime:      now,
				},
			},
		},
		{
			Id:          "test-identity-revoked",
			Source:      "urn:agentmesh:control-plane:cp-1",
			SpecVersion: "1.0",
			Type:        "agentmesh.identity.revoked",
			EventTime:   now,
			Data: &api.SecuritySignalEvent_IdentityRevoked{
				IdentityRevoked: &api.IdentityRevokedSignal{
					PeerId:    "12D3KooWBannedPeer",
					Reason:    "security breach detected",
					EventTime: now,
				},
			},
		},
		{
			Id:          "test-enrollment-rejected",
			Source:      "urn:agentmesh:control-plane:cp-1",
			SpecVersion: "1.0",
			Type:        "agentmesh.enrollment.rejected",
			EventTime:   now,
			Data: &api.SecuritySignalEvent_EnrollmentRejected{
				EnrollmentRejected: &api.EnrollmentRejectedSignal{
					PeerId:        "12D3KooWRejectedPeer",
					RequestedRole: "router",
					Reason:        api.EnrollmentRejectionReason_REQUESTED_ROLE_UNAUTHORIZED,
					Detail:        "peer not authorized for router role",
					EventTime:     now,
				},
			},
		},
	}

	for _, ev := range events {
		t.Run(ev.Type, func(t *testing.T) {
			body, err := protojson.Marshal(ev)
			if err != nil {
				t.Fatalf("protojson.Marshal failed for %s: %v", ev.Type, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(body))
			req.Header.Set(headerCESpecVersion, "1.0")
			req.Header.Set(headerCEID, ev.Id)
			req.Header.Set(headerCEType, ev.Type)
			req.Header.Set(headerCESource, ev.Source)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("%s: expected 200 OK, got %d (body: %s)", ev.Type, rec.Code, rec.Body.String())
			}

			wantJSON := fmt.Sprintf(`"id":%q`, ev.Id)
			if !bytes.Contains(rec.Body.Bytes(), []byte(wantJSON)) {
				t.Fatalf("%s: expected response to contain %s, got %s", ev.Type, wantJSON, rec.Body.String())
			}
		})
	}
}

func TestAdversarial_WebhookBoundaries(t *testing.T) {
	secret := []byte("boundary-test-secret-32-bytes!!")
	handler := NewWebhookHandler(HandlerConfig{
		HMACSecret: secret,
		NoColor:    true,
	})

	now := timestamppb.Now()
	validEvent := &api.SecuritySignalEvent{
		Id:          "boundary-test-1",
		Source:      "urn:agentmesh:node:node-1",
		SpecVersion: "1.0",
		Type:        "agentmesh.policy.denied",
		EventTime:   now,
		Data: &api.SecuritySignalEvent_PolicyDenied{
			PolicyDenied: &api.PolicyDeniedSignal{
				Direction:     api.SignalCallerDirection_LOCAL_WORKLOAD,
				Reason:        api.PolicyDenialReason_DATALOG_EVALUATION_DENIED,
				TargetService: "vault",
				EventTime:     now,
			},
		},
	}
	validBody, err := protojson.Marshal(validEvent)
	if err != nil {
		t.Fatalf("protojson.Marshal failed: %v", err)
	}

	makeSignedReq := func(method string, tsMillis int64, body []byte) *http.Request {
		tsStr := strconv.FormatInt(tsMillis, 10)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(tsStr))
		mac.Write([]byte("."))
		mac.Write(body)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

		req := httptest.NewRequest(method, "/events", bytes.NewReader(body))
		req.Header.Set(headerCESpecVersion, "1.0")
		req.Header.Set(headerCEID, "boundary-test-1")
		req.Header.Set(headerCEType, "agentmesh.policy.denied")
		req.Header.Set(headerCESource, "urn:agentmesh:node:node-1")
		req.Header.Set(headerAgentMeshTimestamp, tsStr)
		req.Header.Set(headerAgentMeshSignature, sig)
		return req
	}

	t.Run("reject non-POST HTTP methods", func(t *testing.T) {
		methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions}
		for _, m := range methods {
			req := makeSignedReq(m, time.Now().UnixMilli(), validBody)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("method %s: expected 405 Method Not Allowed, got %d", m, rec.Code)
			}
		}
	})

	t.Run("reject payload exceeding 1MB maxBodyBytes", func(t *testing.T) {
		// Create an oversized body (> 1MB) with trailing JSON padding
		oversized := make([]byte, 1024*1024+100)
		copy(oversized, validBody)
		for i := len(validBody); i < len(oversized); i++ {
			oversized[i] = ' '
		}
		req := makeSignedReq(http.MethodPost, time.Now().UnixMilli(), oversized)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("oversized body: expected 413 Payload Too Large, got %d", rec.Code)
		}
	})

	t.Run("reject future timestamp exceeding clock skew", func(t *testing.T) {
		futureTs := time.Now().Add(10 * time.Minute).UnixMilli()
		req := makeSignedReq(http.MethodPost, futureTs, validBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("future timestamp: expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("reject non-numeric timestamp", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(validBody))
		req.Header.Set(headerCESpecVersion, "1.0")
		req.Header.Set(headerCEID, "boundary-test-1")
		req.Header.Set(headerCEType, "agentmesh.policy.denied")
		req.Header.Set(headerCESource, "urn:agentmesh:node:node-1")
		req.Header.Set(headerAgentMeshTimestamp, "not-a-number")
		req.Header.Set(headerAgentMeshSignature, "sha256=abcdef")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("non-numeric timestamp: expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("reject unknown JSON fields (fail closed schema)", func(t *testing.T) {
		injectedJSON := `{"id":"b1","specversion":"1.0","type":"agentmesh.policy.denied","source":"node1","unknown_injected_field":"exploit"}`
		req := makeSignedReq(http.MethodPost, time.Now().UnixMilli(), []byte(injectedJSON))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("unknown field injection: expected 400 Bad Request, got %d", rec.Code)
		}
	})

	t.Run("reject signature missing sha256 prefix", func(t *testing.T) {
		tsMillis := time.Now().UnixMilli()
		tsStr := strconv.FormatInt(tsMillis, 10)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(tsStr))
		mac.Write([]byte("."))
		mac.Write(validBody)
		rawHex := hex.EncodeToString(mac.Sum(nil))

		req := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(validBody))
		req.Header.Set(headerCESpecVersion, "1.0")
		req.Header.Set(headerCEID, "boundary-test-1")
		req.Header.Set(headerCEType, "agentmesh.policy.denied")
		req.Header.Set(headerCESource, "urn:agentmesh:node:node-1")
		req.Header.Set(headerAgentMeshTimestamp, tsStr)
		req.Header.Set(headerAgentMeshSignature, rawHex) // missing sha256= prefix
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("signature missing sha256= prefix: expected 401 Unauthorized, got %d", rec.Code)
		}
	})
}

