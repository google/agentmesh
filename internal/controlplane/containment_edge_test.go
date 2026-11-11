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

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/containment"
	"github.com/google/agentmesh/internal/storage"
	"google.golang.org/protobuf/proto"
)

// TestControlPlaneContainment_EnrollmentRejected_TrulyExpiredBootstrapToken tests
// that a bootstrap token whose expiry has passed triggers an agentmesh.enrollment.rejected
// signal with EXPIRED_BOOTSTRAP_TOKEN and appropriate detail.
func TestControlPlaneContainment_EnrollmentRejected_TrulyExpiredBootstrapToken(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	rawToken := "expired-bootstrap-token-adversarial-test-12345"
	tokenID := fmt.Sprintf("%x", sha256.Sum256([]byte(rawToken)))

	tok := &storage.BootstrapToken{
		ID:          tokenID,
		TokenHash:   tokenID,
		Role:        api.RoleNode,
		MaxUsages:   10,
		UsagesCount: 0,
		Description: "expired test token",
		CreatedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:   time.Now().Add(-30 * time.Minute), // expired in the past
	}
	if err := h.store.SaveBootstrapToken(context.Background(), tok); err != nil {
		t.Fatalf("SaveBootstrapToken: %v", err)
	}

	status, httpCode, errMsg := h.enroll(rawToken)
	if httpCode != http.StatusOK || status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
		t.Fatalf("enroll: expected REJECTED with code 200, got status=%v code=%d msg=%q", status, httpCode, errMsg)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	sig := evt.GetEnrollmentRejected()
	if sig == nil {
		t.Fatal("expected EnrollmentRejected signal, got nil")
	}
	if sig.Reason != api.EnrollmentRejectionReason_EXPIRED_BOOTSTRAP_TOKEN {
		t.Errorf("expected EXPIRED_BOOTSTRAP_TOKEN, got %v", sig.Reason)
	}
	if !strings.Contains(sig.Detail, "Bootstrap token expired") {
		t.Errorf("expected detail to mention 'Bootstrap token expired', got %q", sig.Detail)
	}
}

// TestControlPlaneContainment_EnrollmentRejected_RevokedBootstrapToken tests
// that an explicitly revoked bootstrap token emits agentmesh.enrollment.rejected.
func TestControlPlaneContainment_EnrollmentRejected_RevokedBootstrapToken(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	rawToken := "revoked-bootstrap-token-adversarial-test-67890"
	tokenID := fmt.Sprintf("%x", sha256.Sum256([]byte(rawToken)))

	tok := &storage.BootstrapToken{
		ID:          tokenID,
		TokenHash:   tokenID,
		Role:        api.RoleNode,
		MaxUsages:   10,
		UsagesCount: 0,
		Description: "revoked test token",
		CreatedAt:   time.Now().Add(-1 * time.Hour),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if err := h.store.SaveBootstrapToken(context.Background(), tok); err != nil {
		t.Fatalf("SaveBootstrapToken: %v", err)
	}

	if err := h.store.RevokeBootstrapToken(context.Background(), tokenID); err != nil {
		t.Fatalf("RevokeBootstrapToken: %v", err)
	}

	status, httpCode, errMsg := h.enroll(rawToken)
	if httpCode != http.StatusOK || status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
		t.Fatalf("enroll: expected REJECTED with code 200, got status=%v code=%d msg=%q", status, httpCode, errMsg)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	sig := evt.GetEnrollmentRejected()
	if sig == nil {
		t.Fatal("expected EnrollmentRejected signal, got nil")
	}
	if sig.Reason != api.EnrollmentRejectionReason_EXPIRED_BOOTSTRAP_TOKEN {
		t.Errorf("expected EXPIRED_BOOTSTRAP_TOKEN, got %v", sig.Reason)
	}
	if !strings.Contains(sig.Detail, "Bootstrap token revoked") {
		t.Errorf("expected detail to mention 'Bootstrap token revoked', got %q", sig.Detail)
	}
}

// TestControlPlaneContainment_EnrollmentRejected_MaxUsagesExceeded tests
// that exhausting the allowed usages on a bootstrap token emits agentmesh.enrollment.rejected
// with BOOTSTRAP_TOKEN_USAGE_EXCEEDED.
func TestControlPlaneContainment_EnrollmentRejected_MaxUsagesExceeded(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	rawToken := "single-use-bootstrap-token-11223"
	tokenID := fmt.Sprintf("%x", sha256.Sum256([]byte(rawToken)))

	tok := &storage.BootstrapToken{
		ID:          tokenID,
		TokenHash:   tokenID,
		Role:        api.RoleNode,
		MaxUsages:   1,
		UsagesCount: 1, // already exhausted
		Description: "exhausted token",
		CreatedAt:   time.Now().Add(-1 * time.Hour),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if err := h.store.SaveBootstrapToken(context.Background(), tok); err != nil {
		t.Fatalf("SaveBootstrapToken: %v", err)
	}

	status, httpCode, errMsg := h.enroll(rawToken)
	if httpCode != http.StatusOK || status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
		t.Fatalf("enroll: expected REJECTED with code 200, got status=%v code=%d msg=%q", status, httpCode, errMsg)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	sig := evt.GetEnrollmentRejected()
	if sig == nil {
		t.Fatal("expected EnrollmentRejected signal, got nil")
	}
	if sig.Reason != api.EnrollmentRejectionReason_BOOTSTRAP_TOKEN_USAGE_EXCEEDED {
		t.Errorf("expected BOOTSTRAP_TOKEN_USAGE_EXCEEDED, got %v", sig.Reason)
	}
	if !strings.Contains(sig.Detail, "max usages exceeded") {
		t.Errorf("expected detail to mention 'max usages exceeded', got %q", sig.Detail)
	}
}

// TestControlPlaneContainment_EnrollmentRejected_MalformedProtoRequestBody tests
// that corrupt non-protobuf POST body to /enroll returns 400 Bad Request safely
// without crashing or panicking the server.
func TestControlPlaneContainment_EnrollmentRejected_MalformedProtoRequestBody(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	code, body := h.do(http.MethodPost, "/enroll", "", []byte("malformed-non-protobuf-binary-data"), "application/x-protobuf")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d: %s", code, body)
	}

	// Verify no spurious events leaked
	select {
	case evt := <-disp.events:
		t.Fatalf("unexpected event emitted on malformed proto: %v", evt)
	default:
	}
}

// TestControlPlaneContainment_Refresh_AutonomousRecoveryRefused_And_Granted tests both branches:
// refusal when AutonomousRecovery is disabled vs success when enabled.
func TestControlPlaneContainment_Refresh_AutonomousRecoveryRefused_And_Granted(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	// Branch 1: AutonomousRecovery = false -> Refusal
	priv1, id1 := h.register("node-disabled-recovery")
	rec1, err := h.store.GetNode(context.Background(), id1.String())
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	rec1.AutonomousRecovery = false
	if err := h.store.EnrollNode(context.Background(), rec1); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}

	// Rotate active key past grace period to trigger retired-key fallback
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.RotateKeys(context.Background(), newPriv, newPub, -time.Second); err != nil {
		t.Fatal(err)
	}

	code1, body1 := refreshAs(t, h.baseURL, priv1, rec1.Biscuit, id1.String())
	if code1 != http.StatusUnauthorized {
		t.Fatalf("/refresh: expected 401 Unauthorized, got %d: %s", code1, body1)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	sig := evt.GetEnrollmentRejected()
	if sig == nil {
		t.Fatal("expected EnrollmentRejected signal, got nil")
	}
	if sig.Reason != api.EnrollmentRejectionReason_AUTONOMOUS_RECOVERY_DISABLED {
		t.Errorf("expected AUTONOMOUS_RECOVERY_DISABLED, got %v", sig.Reason)
	}
	if !sig.IsAutonomousRecovery {
		t.Error("expected IsAutonomousRecovery true")
	}
	if !strings.Contains(sig.Detail, "autonomous recovery") {
		t.Errorf("expected detail to mention 'autonomous recovery', got %q", sig.Detail)
	}

	// Branch 2: AutonomousRecovery = true -> Succeeded, NO rejection emitted
	priv2, id2 := h.register("node-enabled-recovery")
	rec2, err := h.store.GetNode(context.Background(), id2.String())
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	rec2.AutonomousRecovery = true
	if err := h.store.EnrollNode(context.Background(), rec2); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}

	// Rotate again past grace period
	newPub2, newPriv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.RotateKeys(context.Background(), newPriv2, newPub2, -time.Second); err != nil {
		t.Fatal(err)
	}

	code2, body2 := refreshAs(t, h.baseURL, priv2, rec2.Biscuit, id2.String())
	if code2 != http.StatusOK {
		t.Fatalf("/refresh: expected 200 OK for enabled autonomous recovery, got %d: %s", code2, body2)
	}

	// Verify NO rejection event was emitted for the successful recovery
	select {
	case e := <-disp.events:
		t.Fatalf("unexpected event for successful autonomous recovery: %v", e)
	default:
	}
}

// TestControlPlaneContainment_Refresh_BannedNode_BothValidAndInvalidChallenge verifies
// that CheckAdmission blocks banned nodes before challenge evaluation, ensuring fail-closed
// emission of agentmesh.identity.revoked with source=TOKEN_REFRESH_REJECTION.
func TestControlPlaneContainment_Refresh_BannedNode_BothValidAndInvalidChallenge(t *testing.T) {
	h := newLifecycleHarness(t)
	priv, id := h.register("banned-refresher")
	rec, err := h.store.GetNode(context.Background(), id.String())
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}

	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	if err := h.store.SetNodeBanned(context.Background(), id.String(), true); err != nil {
		t.Fatalf("SetNodeBanned: %v", err)
	}

	// 1. Refresh with valid challenge
	code, body := refreshAs(t, h.baseURL, priv, rec.Biscuit, id.String())
	if code != http.StatusForbidden {
		t.Fatalf("/refresh: expected 403 Forbidden, got %d: %s", code, body)
	}

	evtRevoked := expectCPEvent(t, disp, "agentmesh.identity.revoked")
	ir := evtRevoked.GetIdentityRevoked()
	if ir.Source != api.RevocationSource_TOKEN_REFRESH_REJECTION {
		t.Errorf("expected source TOKEN_REFRESH_REJECTION, got %v", ir.Source)
	}
	if ir.PeerId != id.String() {
		t.Errorf("expected PeerId %q, got %q", id.String(), ir.PeerId)
	}

	evtRejected := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	er := evtRejected.GetEnrollmentRejected()
	if er.Reason != api.EnrollmentRejectionReason_PEER_PREVIOUSLY_BANNED {
		t.Errorf("expected PEER_PREVIOUSLY_BANNED, got %v", er.Reason)
	}

	// 2. Refresh with forged/invalid challenge signature - CheckAdmission still fires first
	corruptReq := &api.TokenRefreshRequest{
		PeerId:             id.String(),
		ChallengeUnixMs:    time.Now().UnixMilli(),
		ChallengeSignature: []byte("completely-invalid-signature"),
	}
	corruptData, err := proto.Marshal(corruptReq)
	if err != nil {
		t.Fatal(err)
	}
	corruptCode, corruptBody := h.do(http.MethodPost, "/refresh", base64.StdEncoding.EncodeToString(rec.Biscuit), corruptData, "application/x-protobuf")
	if corruptCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden even with invalid challenge signature, got %d: %s", corruptCode, corruptBody)
	}

	evtRevoked2 := expectCPEvent(t, disp, "agentmesh.identity.revoked")
	if evtRevoked2.GetIdentityRevoked().Source != api.RevocationSource_TOKEN_REFRESH_REJECTION {
		t.Errorf("expected TOKEN_REFRESH_REJECTION, got %v", evtRevoked2.GetIdentityRevoked().Source)
	}
	_ = expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
}

// TestControlPlaneContainment_Revocation_AdminAndUserRevoke verifies that both
// POST /admin/revoke and POST /user/revoke emit agentmesh.identity.revoked with
// source=CONTROL_PLANE_ADMIN.
func TestControlPlaneContainment_Revocation_AdminAndUserRevoke(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	// Admin revoke
	_, idAdmin := h.register("admin-victim")
	h.revoke(idAdmin)

	evt1 := expectCPEvent(t, disp, "agentmesh.identity.revoked")
	ir1 := evt1.GetIdentityRevoked()
	if ir1.Source != api.RevocationSource_CONTROL_PLANE_ADMIN {
		t.Errorf("expected CONTROL_PLANE_ADMIN, got %v", ir1.Source)
	}
	if ir1.PeerId != idAdmin.String() {
		t.Errorf("expected PeerId %q, got %q", idAdmin.String(), ir1.PeerId)
	}

	// User revoke
	if err := h.store.SaveUser(context.Background(), &storage.User{
		ID:        "user-victim",
		Email:     "user-victim@example.com",
		Role:      "user",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveUser: %v", err)
	}

	_, idUser := h.register("user-victim")
	userToken := h.mintToken(map[string]interface{}{"sub": "user-victim"})
	code, body := h.do(http.MethodPost, "/user/revoke?id="+idUser.String(), userToken, nil, "")
	if code != http.StatusOK {
		t.Fatalf("/user/revoke: expected 200 OK, got %d: %s", code, body)
	}

	evt2 := expectCPEvent(t, disp, "agentmesh.identity.revoked")
	ir2 := evt2.GetIdentityRevoked()
	if ir2.Source != api.RevocationSource_CONTROL_PLANE_ADMIN {
		t.Errorf("expected CONTROL_PLANE_ADMIN, got %v", ir2.Source)
	}
	if ir2.PeerId != idUser.String() {
		t.Errorf("expected PeerId %q, got %q", idUser.String(), ir2.PeerId)
	}
	if !strings.Contains(ir2.Reason, "Revoked by user") {
		t.Errorf("expected reason to mention 'Revoked by user', got %q", ir2.Reason)
	}
}

// TestControlPlaneContainment_ServerClose_NilDispatcher verifies that Server.Close()
// runs safely when ContainmentDispatcher is nil without panicking or leaking goroutines.
func TestControlPlaneContainment_ServerClose_NilDispatcher(t *testing.T) {
	issuer, _ := startCustomMockOIDC(t)
	srv, store, _ := setupTestServer(t, issuer)
	defer store.Close()

	srv.SetContainmentDispatcher(nil)
	if err := srv.Close(); err != nil {
		t.Fatalf("Server.Close() with nil containment dispatcher failed: %v", err)
	}

	// Calling Close() a second time should be idempotent and not panic
	if err := srv.Close(); err != nil {
		t.Fatalf("second Server.Close() failed: %v", err)
	}
}

// TestControlPlaneContainment_ServerClose_DrainsDispatcher verifies that Server.Close()
// drains pending containment events to an external webhook receiver before shutting down.
func TestControlPlaneContainment_ServerClose_DrainsDispatcher(t *testing.T) {
	var receivedCount atomic.Int32
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookServer.Close()

	disp, err := containment.NewDispatcher(containment.Config{
		Endpoints:     []containment.EndpointConfig{{URL: webhookServer.URL}},
		QueueCapacity: 50,
		Workers:       2,
	})
	if err != nil {
		t.Fatalf("failed to create dispatcher: %v", err)
	}

	issuer, _ := startCustomMockOIDC(t)
	srv, store, _ := setupTestServer(t, issuer, func(o *Options) {
		o.ContainmentDispatcher = disp
	})
	defer store.Close()

	const numEvents = 5
	for i := 0; i < numEvents; i++ {
		srv.emitEnrollmentRejected(
			fmt.Sprintf("peer-drain-%d", i),
			"drain-test",
			api.EnrollmentRejectionReason_EXPIRED_BOOTSTRAP_TOKEN,
			api.RoleNode,
			nil,
			time.Now(),
			false,
		)
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Server.Close() failed: %v", err)
	}

	if got := receivedCount.Load(); got != int32(numEvents) {
		t.Fatalf("expected all %d events to be drained on Close(), got %d", numEvents, got)
	}
}

// TestControlPlaneContainment_ServerClose_DrainTimeoutOnHangingWebhook verifies that
// when an external webhook endpoint hangs, Server.Close() respects the 3-second drain
// deadline rather than hanging indefinitely.
func TestControlPlaneContainment_ServerClose_DrainTimeoutOnHangingWebhook(t *testing.T) {
	handlerDone := make(chan struct{})
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-handlerDone:
		}
	}))
	defer func() {
		close(handlerDone)
		webhookServer.Close()
	}()

	disp, err := containment.NewDispatcher(containment.Config{
		Endpoints: []containment.EndpointConfig{{
			URL:     webhookServer.URL,
			Timeout: 10 * time.Second, // client timeout longer than 3s shutdown drain timeout
		}},
		QueueCapacity: 50,
		Workers:       1,
	})
	if err != nil {
		t.Fatalf("failed to create dispatcher: %v", err)
	}

	issuer, _ := startCustomMockOIDC(t)
	srv, store, _ := setupTestServer(t, issuer, func(o *Options) {
		o.ContainmentDispatcher = disp
	})
	defer store.Close()

	srv.emitEnrollmentRejected(
		"peer-hanging",
		"drain-timeout-test",
		api.EnrollmentRejectionReason_EXPIRED_BOOTSTRAP_TOKEN,
		api.RoleNode,
		nil,
		time.Now(),
		false,
	)

	start := time.Now()
	err = srv.Close()
	elapsed := time.Since(start)

	// drainCtx is 3s; elapsed should be around 3s (2.5s - 6s), NOT 10s or hanging indefinitely
	if elapsed < 2500*time.Millisecond || elapsed > 6*time.Second {
		t.Fatalf("expected drain to timeout around 3s, took %v", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "containment dispatcher close") {
		t.Fatalf("expected containment dispatcher close timeout error, got %v", err)
	}
}
