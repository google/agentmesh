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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"google.golang.org/protobuf/proto"
)

type cpChanDispatcher struct {
	events chan *api.SecuritySignalEvent
}

func newCPChanDispatcher(buf int) *cpChanDispatcher {
	return &cpChanDispatcher{
		events: make(chan *api.SecuritySignalEvent, buf),
	}
}

func (d *cpChanDispatcher) Dispatch(event *api.SecuritySignalEvent) {
	select {
	case d.events <- event:
	default:
	}
}

func (d *cpChanDispatcher) Close(ctx context.Context) error {
	return nil
}

func expectCPEvent(t *testing.T, d *cpChanDispatcher, expectedType string) *api.SecuritySignalEvent {
	t.Helper()
	select {
	case evt := <-d.events:
		if evt.Type != expectedType {
			t.Fatalf("expected event type %q, got %q", expectedType, evt.Type)
		}
		return evt
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event type %q", expectedType)
		return nil
	}
}

func TestControlPlaneContainment_EnrollmentRejected_InvalidBootstrapToken(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	status, httpCode, errMsg := h.enroll("non-existent-bootstrap-token-12345")
	if httpCode != http.StatusOK || status != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
		t.Fatalf("enroll: got status=%v code=%d msg=%q, want REJECTED", status, httpCode, errMsg)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	sig := evt.GetEnrollmentRejected()
	if sig == nil {
		t.Fatal("expected EnrollmentRejected signal, got nil")
	}
	if sig.Reason != api.EnrollmentRejectionReason_EXPIRED_BOOTSTRAP_TOKEN {
		t.Errorf("expected EXPIRED_BOOTSTRAP_TOKEN, got %v", sig.Reason)
	}
	if !strings.Contains(sig.Detail, "Invalid bootstrap token") {
		t.Errorf("expected detail to mention 'Invalid bootstrap token', got %q", sig.Detail)
	}
}

func TestControlPlaneContainment_EnrollmentRejected_BannedNode(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)

	// First register the node cleanly
	priv, id := h.register("banned-alice")

	// Now attach dispatcher and ban the node in store
	h.srv.SetContainmentDispatcher(disp)
	if err := h.store.SetNodeBanned(context.Background(), id.String(), true); err != nil {
		t.Fatalf("SetNodeBanned: %v", err)
	}

	pub, err := crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	ts, sig := registerPoP(t, priv, id.String())
	data, err := proto.Marshal(&api.EnrollRequest{
		Jwt:                h.mintToken(map[string]interface{}{"sub": "banned-alice"}),
		PeerId:             id.String(),
		PublicKey:          pub,
		RequestedRole:      api.RoleNode,
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}

	code, body := h.do(http.MethodPost, "/register", "", data, "application/x-protobuf")
	if code != http.StatusForbidden {
		t.Fatalf("/register: expected 403, got %d: %s", code, body)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	rejectedSig := evt.GetEnrollmentRejected()
	if rejectedSig == nil {
		t.Fatal("expected EnrollmentRejected data, got nil")
	}
	if rejectedSig.Reason != api.EnrollmentRejectionReason_PEER_PREVIOUSLY_BANNED {
		t.Errorf("expected PEER_PREVIOUSLY_BANNED, got %v", rejectedSig.Reason)
	}
	if rejectedSig.PeerId != id.String() {
		t.Errorf("expected PeerId %q, got %q", id.String(), rejectedSig.PeerId)
	}
}

func TestControlPlaneContainment_EnrollmentRejected_RoleUnauthorized(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	priv, id := newTestKey(t)
	pub, err := crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	ts, sig := registerPoP(t, priv, id.String())
	data, err := proto.Marshal(&api.EnrollRequest{
		Jwt:                h.mintToken(map[string]interface{}{"sub": "alice"}),
		PeerId:             id.String(),
		PublicKey:          pub,
		RequestedRole:      "mesh:role:unbound-custom-role",
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}

	code, body := h.do(http.MethodPost, "/register", "", data, "application/x-protobuf")
	if code != http.StatusForbidden {
		t.Fatalf("/register: expected 403, got %d: %s", code, body)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	rejectedSig := evt.GetEnrollmentRejected()
	if rejectedSig == nil {
		t.Fatal("expected EnrollmentRejected data, got nil")
	}
	if rejectedSig.Reason != api.EnrollmentRejectionReason_REQUESTED_ROLE_UNAUTHORIZED {
		t.Errorf("expected REQUESTED_ROLE_UNAUTHORIZED, got %v", rejectedSig.Reason)
	}
	if rejectedSig.RequestedRole != "mesh:role:unbound-custom-role" {
		t.Errorf("expected RequestedRole mesh:role:unbound-custom-role, got %q", rejectedSig.RequestedRole)
	}
}

func TestControlPlaneContainment_EnrollmentRejected_UnattestedLabels(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	priv, id := newTestKey(t)
	pub, err := crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	ts, sig := registerPoP(t, priv, id.String())
	data, err := proto.Marshal(&api.EnrollRequest{
		Jwt:                h.mintToken(map[string]interface{}{"sub": "alice"}),
		PeerId:             id.String(),
		PublicKey:          pub,
		RequestedRole:      api.RoleNode,
		Labels:             map[string]string{"unattested_key": "forbidden_value"},
		ChallengeUnixMs:    ts,
		ChallengeSignature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}

	code, body := h.do(http.MethodPost, "/register", "", data, "application/x-protobuf")
	if code != http.StatusForbidden {
		t.Fatalf("/register: expected 403, got %d: %s", code, body)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	rejectedSig := evt.GetEnrollmentRejected()
	if rejectedSig == nil {
		t.Fatal("expected EnrollmentRejected data, got nil")
	}
	if rejectedSig.Reason != api.EnrollmentRejectionReason_UNATTESTED_LABELS_REJECTED {
		t.Errorf("expected UNATTESTED_LABELS_REJECTED, got %v", rejectedSig.Reason)
	}
	if rejectedSig.SubmittedLabels["unattested_key"] != "forbidden_value" {
		t.Errorf("expected submitted label unattested_key, got %v", rejectedSig.SubmittedLabels)
	}
}

func TestControlPlaneContainment_Refresh_BannedNode(t *testing.T) {
	h := newLifecycleHarness(t)
	priv, id := h.register("bob")
	record, err := h.store.GetNode(context.Background(), id.String())
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}

	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	if err := h.store.SetNodeBanned(context.Background(), id.String(), true); err != nil {
		t.Fatalf("SetNodeBanned: %v", err)
	}

	code, body := refreshAs(t, h.baseURL, priv, record.Biscuit, id.String())
	if code != http.StatusForbidden {
		t.Fatalf("/refresh: expected 403, got %d: %s", code, body)
	}

	// Expect identity.revoked
	evt1 := expectCPEvent(t, disp, "agentmesh.identity.revoked")
	ir := evt1.GetIdentityRevoked()
	if ir.Source != api.RevocationSource_TOKEN_REFRESH_REJECTION {
		t.Errorf("expected TOKEN_REFRESH_REJECTION, got %v", ir.Source)
	}
	if ir.PeerId != id.String() {
		t.Errorf("expected PeerId %q, got %q", id.String(), ir.PeerId)
	}

	// Expect enrollment.rejected
	evt2 := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	er := evt2.GetEnrollmentRejected()
	if er.Reason != api.EnrollmentRejectionReason_PEER_PREVIOUSLY_BANNED {
		t.Errorf("expected PEER_PREVIOUSLY_BANNED, got %v", er.Reason)
	}
}

func TestControlPlaneContainment_Refresh_AutonomousRecoveryDisabled(t *testing.T) {
	h := newLifecycleHarness(t)
	priv, id := h.register("charlie")
	record, err := h.store.GetNode(context.Background(), id.String())
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}

	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	// Disable autonomous recovery
	record.AutonomousRecovery = false
	if err := h.store.EnrollNode(context.Background(), record); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}

	// Retire active key
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.RotateKeys(context.Background(), newPriv, newPub, -time.Second); err != nil {
		t.Fatal(err)
	}

	code, body := refreshAs(t, h.baseURL, priv, record.Biscuit, id.String())
	if code != http.StatusUnauthorized {
		t.Fatalf("/refresh: expected 401, got %d: %s", code, body)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	er := evt.GetEnrollmentRejected()
	if er == nil {
		t.Fatal("expected EnrollmentRejected data, got nil")
	}
	if er.Reason != api.EnrollmentRejectionReason_AUTONOMOUS_RECOVERY_DISABLED {
		t.Errorf("expected AUTONOMOUS_RECOVERY_DISABLED, got %v", er.Reason)
	}
	if !er.IsAutonomousRecovery {
		t.Error("expected IsAutonomousRecovery true")
	}
}

func TestControlPlaneContainment_AdminRevoke(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	_, id := h.register("dave")
	h.revoke(id)

	evt := expectCPEvent(t, disp, "agentmesh.identity.revoked")
	ir := evt.GetIdentityRevoked()
	if ir == nil {
		t.Fatal("expected IdentityRevoked data, got nil")
	}
	if ir.Source != api.RevocationSource_CONTROL_PLANE_ADMIN {
		t.Errorf("expected CONTROL_PLANE_ADMIN, got %v", ir.Source)
	}
	if ir.PeerId != id.String() {
		t.Errorf("expected PeerId %q, got %q", id.String(), ir.PeerId)
	}
}

func TestControlPlaneContainment_AdminEnrollmentReject(t *testing.T) {
	h := newLifecycleHarness(t)
	disp := newCPChanDispatcher(10)
	h.srv.SetContainmentDispatcher(disp)

	h.srv.config.AutoApproveEnrollment = false

	status, out := h.userToken("admin", `{"role":"mesh:role:node"}`)
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("userToken: %d", status)
	}
	token, ok := out["token"].(string)
	if !ok || token == "" {
		t.Fatalf("no token in response: %v", out)
	}

	enrollStatus, httpCode, _ := h.enroll(token)
	if httpCode != http.StatusOK || enrollStatus != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		t.Fatalf("enroll: expected PENDING, got %v (http %d)", enrollStatus, httpCode)
	}

	reqs, err := h.store.ListEnrollmentRequests(context.Background())
	if err != nil || len(reqs) == 0 {
		t.Fatalf("ListEnrollmentRequests: %v (len %d)", err, len(reqs))
	}
	reqID := reqs[0].ID

	rejectCode, rejectBody := h.do(http.MethodPost, "/admin/enrollments/"+reqID+"/reject", "super-secret-admin-token", nil, "")
	if rejectCode != http.StatusOK {
		t.Fatalf("reject: %d %s", rejectCode, rejectBody)
	}

	evt := expectCPEvent(t, disp, "agentmesh.enrollment.rejected")
	er := evt.GetEnrollmentRejected()
	if er == nil {
		t.Fatal("expected EnrollmentRejected data, got nil")
	}
	if er.Reason != api.EnrollmentRejectionReason_REQUESTED_ROLE_UNAUTHORIZED {
		t.Errorf("expected REQUESTED_ROLE_UNAUTHORIZED, got %v", er.Reason)
	}
	if !strings.Contains(er.Detail, "rejected by admin") {
		t.Errorf("expected detail to mention 'rejected by admin', got %q", er.Detail)
	}
}
