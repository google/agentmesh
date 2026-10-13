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
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/storage"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// lifecycleHarness is a control plane with an open node binding, an admin
// token and auto-approve on, plus the request helpers these tests share.
type lifecycleHarness struct {
	t         *testing.T
	srv       *Server
	store     storage.Store
	baseURL   string
	mintToken func(map[string]interface{}) string
	client    *http.Client
}

func newLifecycleHarness(t *testing.T) *lifecycleHarness {
	t.Helper()
	issuer, mintToken := startCustomMockOIDC(t)
	srv, store, baseURL := setupTestServer(t, issuer)
	t.Cleanup(func() {
		_ = srv.Close()
		_ = store.Close()
	})
	srv.config.AdminToken = "super-secret-admin-token"
	srv.config.AutoApproveEnrollment = true
	if err := store.SaveMeshPolicy(context.Background(),
		[]*api.PolicyRole{{Name: api.RoleNode, AllowedServices: []string{"*"}, AllowedTargets: []string{"*"}}},
		[]*api.PolicyBinding{{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}}}); err != nil {
		t.Fatal(err)
	}
	return &lifecycleHarness{t: t, srv: srv, store: store, baseURL: baseURL, mintToken: mintToken, client: &http.Client{Timeout: 5 * time.Second}}
}

// do sends an authenticated request and returns status and body.
func (h *lifecycleHarness) do(method, path, bearer string, body []byte, contentType string) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.baseURL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, respBody
}

// register enrolls an OIDC identity with a fresh key via /register.
func (h *lifecycleHarness) register(sub string) (crypto.PrivKey, peer.ID) {
	h.t.Helper()
	priv, id := newTestKey(h.t)
	pub, err := crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		h.t.Fatal(err)
	}
	ts, sig := registerPoP(h.t, priv, id.String())
	data, err := proto.Marshal(&api.EnrollRequest{
		Jwt: h.mintToken(map[string]interface{}{"sub": sub}), PeerId: id.String(), PublicKey: pub,
		RequestedRole: api.RoleNode, ChallengeUnixMs: ts, ChallengeSignature: sig,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if status, body := h.do(http.MethodPost, "/register", "", data, "application/x-protobuf"); status != http.StatusOK {
		h.t.Fatalf("/register for %s: %d %s", sub, status, body)
	}
	return priv, id
}

// userToken mints a bootstrap token as an OIDC user via /user/bootstrap-tokens.
func (h *lifecycleHarness) userToken(sub string, body string) (int, map[string]any) {
	h.t.Helper()
	status, respBody := h.do(http.MethodPost, "/user/bootstrap-tokens", h.mintToken(map[string]interface{}{"sub": sub}), []byte(body), "application/json")
	var out map[string]any
	_ = json.Unmarshal(respBody, &out)
	return status, out
}

// enroll drives POST /enroll with a fresh key and returns the response status.
func (h *lifecycleHarness) enroll(token string) (api.EnrollmentStatus, int, string) {
	h.t.Helper()
	priv, id := newTestKey(h.t)
	pub, err := crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		h.t.Fatal(err)
	}
	ts, sig := enrollPoP(h.t, priv, id.String())
	data, err := proto.Marshal(&api.BootstrapEnrollRequest{
		BootstrapToken: token, PeerId: id.String(), PublicKey: pub, RequestedRole: api.RoleNode,
		ChallengeUnixMs: ts, ChallengeSignature: sig,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	status, body := h.do(http.MethodPost, "/enroll", "", data, "application/x-protobuf")
	var resp api.BootstrapEnrollResponse
	if status == http.StatusOK {
		if err := proto.Unmarshal(body, &resp); err != nil {
			h.t.Fatal(err)
		}
	}
	return resp.Status, status, resp.ErrorMessage
}

func (h *lifecycleHarness) revoke(id peer.ID) {
	h.t.Helper()
	data, err := proto.Marshal(&api.TokenRevokeRequest{PeerId: id.String()})
	if err != nil {
		h.t.Fatal(err)
	}
	if status, body := h.do(http.MethodPost, "/admin/revoke", "super-secret-admin-token", data, "application/x-protobuf"); status != http.StatusOK {
		h.t.Fatalf("/admin/revoke: %d %s", status, body)
	}
}

// M17: a banned OIDC identity could not /register again, but its still-valid
// ID token passed authenticateUser, so it minted itself a bootstrap token and
// re-enrolled a fresh device. The ban has to hold on every surface the ID
// token can drive, and a token minted before the ban has to stop working.
func TestIdentityBanCoversUserSurfaceAndOwnedTokens(t *testing.T) {
	h := newLifecycleHarness(t)
	ctx := context.Background()
	const sub = "victim-turned-attacker"
	userJWT := h.mintToken(map[string]interface{}{"sub": sub})

	// The identity logs in (user row exists), enrolls a node and mints a
	// bootstrap token while still in good standing.
	if status, body := h.do(http.MethodGet, "/user/status", userJWT, nil, ""); status != http.StatusOK {
		t.Fatalf("/user/status before ban: %d %s", status, body)
	}
	_, nodeID := h.register(sub)
	status, minted := h.userToken(sub, `{"role":"mesh:role:node","max_usages":5}`)
	if status != http.StatusCreated {
		t.Fatalf("token before ban: %d %v", status, minted)
	}
	preBanToken, _ := minted["token"].(string)

	h.revoke(nodeID)
	banned, err := h.store.IsIdentityBanned(ctx, h.srv.config.OIDCIssuer+"|"+sub)
	if err != nil || !banned {
		t.Fatalf("identity not banned after revoke: banned=%v err=%v", banned, err)
	}

	t.Run("user surface refuses the banned identity", func(t *testing.T) {
		for _, tc := range []struct{ method, path string }{
			{http.MethodGet, "/user/status"},
			{http.MethodPost, "/user/bootstrap-tokens"},
			{http.MethodPost, "/user/revoke?id=" + nodeID.String()},
		} {
			status, body := h.do(tc.method, tc.path, userJWT, []byte(`{"role":"mesh:role:node"}`), "application/json")
			if status != http.StatusForbidden {
				t.Errorf("%s %s with a banned identity: got %d (%s), want 403", tc.method, tc.path, status, body)
			}
		}
	})

	t.Run("token minted before the ban enrolls nothing", func(t *testing.T) {
		enrollStatus, httpStatus, msg := h.enroll(preBanToken)
		if httpStatus != http.StatusOK || enrollStatus != api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
			t.Fatalf("enroll with a banned owner's token: http %d, status %v (%s); want REJECTED", httpStatus, enrollStatus, msg)
		}
		if !strings.Contains(msg, "owner is banned") {
			t.Errorf("rejection reason = %q, want the owner ban", msg)
		}
	})

	t.Run("a queued approval is refused too", func(t *testing.T) {
		h.srv.config.AutoApproveEnrollment = false
		t.Cleanup(func() { h.srv.config.AutoApproveEnrollment = true })
		// Another user's token, queued, then that user is banned.
		const other = "queued-then-banned"
		_, otherNode := h.register(other)
		status, minted := h.userToken(other, `{"role":"mesh:role:node","max_usages":1}`)
		if status != http.StatusCreated {
			t.Fatalf("token: %d %v", status, minted)
		}
		otherToken, _ := minted["token"].(string)
		if enrollStatus, httpStatus, msg := h.enroll(otherToken); httpStatus != http.StatusOK || enrollStatus != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
			t.Fatalf("queue: http %d, status %v (%s); want PENDING", httpStatus, enrollStatus, msg)
		}
		h.revoke(otherNode)

		reqs, err := h.store.ListEnrollmentRequests(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var pendingID string
		for _, r := range reqs {
			if r.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
				pendingID = r.ID
			}
		}
		if pendingID == "" {
			t.Fatal("no pending request found")
		}
		status, body := h.do(http.MethodPost, "/admin/enrollments/"+pendingID+"/approve", "super-secret-admin-token", nil, "")
		if status != http.StatusForbidden {
			t.Errorf("approve with a banned owner: got %d (%s), want 403", status, body)
		}
	})

	t.Run("unban lifts both halves", func(t *testing.T) {
		status, body := h.do(http.MethodPost, "/admin/nodes/"+nodeID.String()+"/unban", "super-secret-admin-token", nil, "")
		if status != http.StatusNoContent {
			t.Fatalf("unban: got %d (%s), want 204", status, body)
		}
		if banned, err := h.store.IsIdentityBanned(ctx, h.srv.config.OIDCIssuer+"|"+sub); err != nil || banned {
			t.Errorf("identity still banned after unban: banned=%v err=%v", banned, err)
		}
		if node, err := h.store.GetNode(ctx, nodeID.String()); err != nil || node.Banned {
			t.Errorf("node still banned after unban: err=%v", err)
		}
		if status, body := h.do(http.MethodGet, "/user/status", userJWT, nil, ""); status != http.StatusOK {
			t.Errorf("/user/status after unban: %d %s", status, body)
		}
	})
}

// M3: the usage cap was read-then-increment across two round trips, so
// concurrent enrollments on a 1-use token could all pass the read.
func TestBootstrapTokenUsageCapHoldsUnderConcurrency(t *testing.T) {
	h := newLifecycleHarness(t)
	status, minted := h.userToken("issuer-of-one", `{"role":"mesh:role:node","max_usages":1}`)
	if status != http.StatusCreated {
		t.Fatalf("token: %d %v", status, minted)
	}
	token, _ := minted["token"].(string)

	const attempts = 12
	var wg sync.WaitGroup
	results := make(chan api.EnrollmentStatus, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enrollStatus, httpStatus, _ := h.enroll(token)
			if httpStatus == http.StatusOK {
				results <- enrollStatus
			} else if httpStatus != http.StatusTooManyRequests {
				t.Errorf("unexpected http status %d", httpStatus)
			}
		}()
	}
	wg.Wait()
	close(results)

	approved := 0
	for s := range results {
		if s == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
			approved++
		}
	}
	if approved != 1 {
		t.Errorf("%d enrollments approved on a 1-use token, want exactly 1", approved)
	}
	tok, err := h.store.GetBootstrapToken(context.Background(), minted["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if tok.UsagesCount != 1 {
		t.Errorf("usages_count = %d, want 1", tok.UsagesCount)
	}
}

// M3 (approve arm) and L35: approve re-checks the token and writes the node
// record before the request becomes APPROVED; a second approve or reject of
// the same request is a 409, not a second biscuit.
func TestApproveRechecksTokenAndResolvesOnce(t *testing.T) {
	h := newLifecycleHarness(t)
	h.srv.config.AutoApproveEnrollment = false
	ctx := context.Background()

	queue := func(maxUsages int) (tokenID, requestID string) {
		t.Helper()
		status, minted := h.userToken("queuer", `{"role":"mesh:role:node","max_usages":`+strconv.Itoa(maxUsages)+`}`)
		if status != http.StatusCreated {
			t.Fatalf("token: %d %v", status, minted)
		}
		if enrollStatus, httpStatus, msg := h.enroll(minted["token"].(string)); httpStatus != http.StatusOK || enrollStatus != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
			t.Fatalf("queue: http %d, status %v (%s)", httpStatus, enrollStatus, msg)
		}
		reqs, err := h.store.ListEnrollmentRequests(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range reqs {
			if r.TokenID == minted["id"].(string) && r.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
				return r.TokenID, r.ID
			}
		}
		t.Fatal("pending request not found")
		return "", ""
	}
	approve := func(id string) (int, string) {
		t.Helper()
		status, body := h.do(http.MethodPost, "/admin/enrollments/"+id+"/approve", "super-secret-admin-token", nil, "")
		return status, string(body)
	}

	t.Run("revoked since queued", func(t *testing.T) {
		tokenID, reqID := queue(1)
		if err := h.store.RevokeBootstrapToken(ctx, tokenID); err != nil {
			t.Fatal(err)
		}
		if status, body := approve(reqID); status != http.StatusGone {
			t.Errorf("approve with a revoked token: got %d (%s), want 410", status, body)
		}
		req, err := h.store.GetEnrollmentRequestByID(ctx, reqID)
		if err != nil {
			t.Fatal(err)
		}
		if req.Status != api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING || len(req.BiscuitToken) != 0 {
			t.Errorf("request was resolved despite the revoked token: %+v", req)
		}
	})

	t.Run("second resolution is a conflict", func(t *testing.T) {
		_, reqID := queue(5)
		if status, body := approve(reqID); status != http.StatusOK {
			t.Fatalf("first approve: %d %s", status, body)
		}
		if status, body := approve(reqID); status != http.StatusConflict {
			t.Errorf("second approve: got %d (%s), want 409", status, body)
		}
		if status, body := h.do(http.MethodPost, "/admin/enrollments/"+reqID+"/reject", "super-secret-admin-token", nil, ""); status != http.StatusConflict {
			t.Errorf("reject after approve: got %d (%s), want 409", status, body)
		}
		req, err := h.store.GetEnrollmentRequestByID(ctx, reqID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.GetNode(ctx, req.PeerID); err != nil {
			t.Errorf("approved request has no node record behind it: %v", err)
		}
	})

	t.Run("exhausted since queued", func(t *testing.T) {
		// Two requests queued on a 1-use token: only one approval can land.
		status, minted := h.userToken("queuer", `{"role":"mesh:role:node","max_usages":1}`)
		if status != http.StatusCreated {
			t.Fatalf("token: %d %v", status, minted)
		}
		var ids []string
		for i := 0; i < 2; i++ {
			if _, httpStatus, _ := h.enroll(minted["token"].(string)); httpStatus != http.StatusOK {
				t.Fatalf("queue %d: http %d", i, httpStatus)
			}
		}
		reqs, err := h.store.ListEnrollmentRequests(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range reqs {
			if r.TokenID == minted["id"].(string) {
				ids = append(ids, r.ID)
			}
		}
		if len(ids) != 2 {
			t.Fatalf("queued %d requests, want 2", len(ids))
		}
		if status, body := approve(ids[0]); status != http.StatusOK {
			t.Fatalf("first approve: %d %s", status, body)
		}
		if status, body := approve(ids[1]); status != http.StatusGone {
			t.Errorf("approve past the cap: got %d (%s), want 410", status, body)
		}
	})
}

// L9: a non-admin's token is bounded in lifetime and width.
func TestUserBootstrapTokenCeilings(t *testing.T) {
	h := newLifecycleHarness(t)
	for name, body := range map[string]string{
		"ttl":    `{"role":"mesh:role:node","ttl_hours":` + strconv.Itoa(userTokenMaxTTLHours+1) + `}`,
		"usages": `{"role":"mesh:role:node","max_usages":` + strconv.Itoa(userTokenMaxUsages+1) + `}`,
	} {
		if status, resp := h.userToken("greedy", body); status != http.StatusBadRequest {
			t.Errorf("%s over the ceiling: got %d %v, want 400", name, status, resp)
		}
	}
	if status, resp := h.userToken("modest", `{"role":"mesh:role:node","ttl_hours":`+strconv.Itoa(userTokenMaxTTLHours)+`,"max_usages":`+strconv.Itoa(userTokenMaxUsages)+`}`); status != http.StatusCreated {
		t.Errorf("at the ceiling: got %d %v, want 201", status, resp)
	}
	// Admins are not bounded.
	status, body := h.do(http.MethodPost, "/user/bootstrap-tokens", "super-secret-admin-token",
		[]byte(`{"role":"mesh:role:router","ttl_hours":`+strconv.Itoa(userTokenMaxTTLHours*10)+`,"max_usages":`+strconv.Itoa(userTokenMaxUsages*10)+`}`), "application/json")
	if status != http.StatusCreated {
		t.Errorf("admin over the user ceiling: got %d (%s), want 201", status, body)
	}
}

// L11: /user/status must not hand out live biscuits or key material, and
// mesh-wide state (policy, routers) is admin-only.
func TestUserStatusTrimsCredentialsAndMeshState(t *testing.T) {
	h := newLifecycleHarness(t)
	const sub = "status-user"
	h.register(sub)

	status, body := h.do(http.MethodGet, "/user/status", h.mintToken(map[string]interface{}{"sub": sub}), nil, "")
	if status != http.StatusOK {
		t.Fatalf("/user/status: %d %s", status, body)
	}
	for _, leaked := range []string{`"biscuit"`, `"public_key"`, `"claims_json"`, `"policy"`, `"active_routers"`} {
		if bytes.Contains(body, []byte(leaked)) {
			t.Errorf("non-admin /user/status carries %s", leaked)
		}
	}
	resp := &api.UserStatusResponse{}
	if err := protojson.Unmarshal(body, resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.GetEnrolledNodes()) != 0 {
		// The node was OIDC-enrolled with no owner; a user sees only nodes it
		// owns. What matters is the shape when present, checked as admin.
		t.Errorf("non-owner sees %d nodes", len(resp.GetEnrolledNodes()))
	}

	// protojson omits an empty list, so give the admin view a router to show.
	if err := h.store.UpsertRouterLease(context.Background(), &storage.RouterLease{
		PeerID:      "12D3KooWStatusRouter000000000000000000000000000000",
		Addresses:   []string{"/dns4/router.example/tcp/4501"},
		LastRenewal: time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	status, body = h.do(http.MethodGet, "/user/status", "super-secret-admin-token", nil, "")
	if status != http.StatusOK {
		t.Fatalf("admin /user/status: %d %s", status, body)
	}
	for _, leaked := range []string{`"biscuit"`, `"public_key"`} {
		if bytes.Contains(body, []byte(leaked)) {
			t.Errorf("admin /user/status carries %s", leaked)
		}
	}
	for _, wanted := range []string{`"policy"`, `"active_routers"`, `"claims_json"`, `"peer_id"`} {
		if !bytes.Contains(body, []byte(wanted)) {
			t.Errorf("admin /user/status lacks %s", wanted)
		}
	}
}

// M9: an email the issuer marks unverified resolves no binding and is not
// minted; two issuers sharing a subject do not share a user.
func TestUnverifiedEmailAndIssuerCollision(t *testing.T) {
	h := newLifecycleHarness(t)
	ctx := context.Background()
	if err := h.store.SaveMeshPolicy(ctx,
		[]*api.PolicyRole{{Name: api.RoleNode}, {Name: "by-email", AllowedServices: []string{"*"}}},
		[]*api.PolicyBinding{
			{Role: api.RoleNode, Members: []string{api.SystemAuthenticated}},
			{Role: "by-email", Members: []string{"email:ceo@example.com"}},
		}); err != nil {
		t.Fatal(err)
	}
	cpPriv, cpPub, err := h.store.GetCurrentKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = cpPriv
	_ = cpPub

	mintedRoles := func(claims map[string]interface{}) []string {
		t.Helper()
		priv, id := newTestKey(t)
		pub, err := crypto.MarshalPublicKey(priv.GetPublic())
		if err != nil {
			t.Fatal(err)
		}
		ts, sig := registerPoP(t, priv, id.String())
		claims["sub"] = id.String() // distinct subjects, so only the email can bind
		data, err := proto.Marshal(&api.EnrollRequest{
			Jwt: h.mintToken(claims), PeerId: id.String(), PublicKey: pub,
			RequestedRole: api.RoleNode, ChallengeUnixMs: ts, ChallengeSignature: sig,
		})
		if err != nil {
			t.Fatal(err)
		}
		status, body := h.do(http.MethodPost, "/register", "", data, "application/x-protobuf")
		if status != http.StatusOK {
			t.Fatalf("/register: %d %s", status, body)
		}
		var resp api.EnrollResponse
		if err := proto.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		var roles []string
		for _, r := range []string{api.RoleNode, "by-email"} {
			if authorityHasFact(t, resp.BiscuitToken, api.FactRole+`("`+r+`")`) {
				roles = append(roles, r)
			}
		}
		return roles
	}

	verified := mintedRoles(map[string]interface{}{"email": "ceo@example.com", "email_verified": true})
	if !slices.Contains(verified, "by-email") {
		t.Errorf("verified email did not resolve its binding: roles=%v", verified)
	}
	unverified := mintedRoles(map[string]interface{}{"email": "ceo@example.com", "email_verified": false})
	if slices.Contains(unverified, "by-email") {
		t.Errorf("email the issuer marked unverified resolved a binding: roles=%v", unverified)
	}

	// Issuer collision: a user row from issuer A, then the same sub from
	// issuer B. The second issuer is unknown to the control plane so its
	// token is refused before the user lookup; simulate the collision at the
	// store level, the way a second configured issuer would produce it.
	const sub = "shared-sub"
	if err := h.store.SaveUser(ctx, &storage.User{ID: sub, Issuer: "https://other-idp.example", Email: "x@example.com", Role: "user", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	status, body := h.do(http.MethodGet, "/user/status", h.mintToken(map[string]interface{}{"sub": sub}), nil, "")
	if status != http.StatusUnauthorized {
		t.Errorf("same subject from another issuer: got %d (%s), want 401", status, body)
	}
}

// M2: a mesh with no policy roles used to mint every node an unrestricted
// token. Now it mints the role and nothing else.
func TestNoPolicyMintsNoGrants(t *testing.T) {
	_, cpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, id := newTestKey(t)
	data, err := identity.MintBootstrapBiscuitToken(cpPriv, id, api.RoleNode, time.Now().Add(time.Hour), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, open := range []string{api.FactGrantedServiceAllTypes, api.FactTargetUnrestricted} {
		if authorityHasFact(t, data, open+"(") {
			t.Errorf("token minted under an empty policy carries %s(true)", open)
		}
	}
	if !authorityHasFact(t, data, api.FactRole+`("`+api.RoleNode+`")`) {
		t.Error("token lacks its role fact")
	}
}

// authorityHasFact reports whether the token's authority block prints the
// given Datalog text (Biscuit.Code lists appended blocks only).
func authorityHasFact(t *testing.T, token []byte, text string) bool {
	t.Helper()
	b, err := biscuit.Unmarshal(token)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(b.String(), text)
}
