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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
)

func TestTARNarrowsNeverSelects_OIDCScopes(t *testing.T) {
	policyScopes := []string{
		"https://www.googleapis.com/auth/bigquery.readonly",
		"https://www.googleapis.com/auth/devstorage.read_only",
	}

	// 1. No TAR -> full policy scopes.
	got, err := NarrowOIDCScopes(policyScopes, "bigquery.googleapis.com", nil)
	if err != nil {
		t.Fatalf("NarrowOIDCScopes(nil): %v", err)
	}
	if !slices.Equal(got, policyScopes) {
		t.Fatalf("expected %v, got %v", policyScopes, got)
	}

	// 2. TAR narrows to one scope in policyScopes.
	tar1 := &api.TaskAuthorizationRule{
		Name: "tasks/bq-only",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://bigquery.googleapis.com"},
			Operation: &api.TaskOperation{
				AllowedPermissions: []string{"https://www.googleapis.com/auth/bigquery.readonly"},
			},
		}},
	}
	got, err = NarrowOIDCScopes(policyScopes, "bigquery.googleapis.com", []*api.TaskAuthorizationRule{tar1})
	if err != nil {
		t.Fatalf("NarrowOIDCScopes(tar1): %v", err)
	}
	if !slices.Equal(got, []string{"https://www.googleapis.com/auth/bigquery.readonly"}) {
		t.Fatalf("expected narrowed scope, got %v", got)
	}

	// 3. TAR attempts to select an admin scope not in policyScopes -> fails closed!
	tarEscalate := &api.TaskAuthorizationRule{
		Name: "tasks/escalate-cloud-platform",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://bigquery.googleapis.com"},
			Operation: &api.TaskOperation{
				AllowedPermissions: []string{"https://www.googleapis.com/auth/cloud-platform"},
			},
		}},
	}
	if _, err := NarrowOIDCScopes(policyScopes, "bigquery.googleapis.com", []*api.TaskAuthorizationRule{tarEscalate}); err == nil {
		t.Fatal("expected NarrowOIDCScopes to reject TAR requesting scope outside policyScopes")
	}

	// 4. TAR mixes one allowed scope and one unauthorized scope -> only the policy-allowed scope survives.
	tarMixed := &api.TaskAuthorizationRule{
		Name: "tasks/mixed",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://bigquery.googleapis.com"},
			Operation: &api.TaskOperation{
				AllowedPermissions: []string{
					"https://www.googleapis.com/auth/bigquery.readonly",
					"https://www.googleapis.com/auth/cloud-platform",
				},
			},
		}},
	}
	got, err = NarrowOIDCScopes(policyScopes, "bigquery.googleapis.com", []*api.TaskAuthorizationRule{tarMixed})
	if err != nil {
		t.Fatalf("NarrowOIDCScopes(tarMixed): %v", err)
	}
	if !slices.Equal(got, []string{"https://www.googleapis.com/auth/bigquery.readonly"}) {
		t.Fatalf("expected only policy-allowed scope, got %v", got)
	}

	// 5. Empty policyScopes -> TAR cannot select or inject scopes.
	got, err = NarrowOIDCScopes(nil, "bigquery.googleapis.com", []*api.TaskAuthorizationRule{tar1})
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty scopes when policyScopes is empty, got %v, err=%v", got, err)
	}

	// 6. Blueprint 4 multi-hop TAR carrying Google Cloud IAM permissions
	// (bigquery.googleapis.com/tables.getData) preserves policy OAuth scopes while
	// intersecting fine-grained permissions and resources across hops.
	hop1 := &api.TaskAuthorizationRule{
		Name: "tasks/session-bq-read-sales",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://bigquery.googleapis.com"},
			Operation: &api.TaskOperation{
				AllowedMethods: []string{"GET", "POST"},
				AllowedPaths:   []string{"/bigquery/v2/projects/my-proj/datasets/sales_2026/*"},
				AllowedPermissions: []string{
					"bigquery.googleapis.com/datasets.get",
					"bigquery.googleapis.com/tables.get",
					"bigquery.googleapis.com/tables.getData",
					"bigquery.googleapis.com/jobs.create",
				},
			},
			AllowedResources: []string{"//bigquery.googleapis.com/projects/my-proj/datasets/sales_2026/*"},
		}},
	}
	hop2 := &api.TaskAuthorizationRule{
		Name: "tasks/subagent-q1-only",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://bigquery.googleapis.com"},
			Operation: &api.TaskOperation{
				AllowedMethods:     []string{"GET"},
				AllowedPaths:       []string{"/bigquery/v2/projects/my-proj/datasets/sales_2026/tables/q1/*"},
				AllowedPermissions: []string{"bigquery.googleapis.com/tables.getData"},
			},
			AllowedResources: []string{"//bigquery.googleapis.com/projects/my-proj/datasets/sales_2026/tables/q1"},
		}},
	}
	got, err = NarrowOIDCScopes([]string{"https://www.googleapis.com/auth/bigquery.readonly"}, "bigquery.googleapis.com", []*api.TaskAuthorizationRule{hop1, hop2})
	if err != nil || !slices.Equal(got, []string{"https://www.googleapis.com/auth/bigquery.readonly"}) {
		t.Fatalf("expected bigquery.readonly scope preserved, got %v, err=%v", got, err)
	}
	perms, resources, err := IntersectTaskPermissionsAndResources("bigquery.googleapis.com", []*api.TaskAuthorizationRule{hop1, hop2})
	if err != nil {
		t.Fatalf("IntersectTaskPermissionsAndResources: %v", err)
	}
	if !slices.Equal(perms, []string{"bigquery.googleapis.com/tables.getData"}) {
		t.Fatalf("expected intersected perms [bigquery.googleapis.com/tables.getData], got %v", perms)
	}
	if !slices.Equal(resources, []string{"//bigquery.googleapis.com/projects/my-proj/datasets/sales_2026/tables/q1"}) {
		t.Fatalf("expected intersected resources [../tables/q1], got %v", resources)
	}
}

func TestTARNarrowsNeverSelects_AWSSessionPolicy(t *testing.T) {
	template := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:ListBucket"],
			"Resource": ["arn:aws:s3:::acme-analytics/*"]
		}]
	}`

	// 1. Valid narrowing across two hops.
	hop1 := &api.TaskAuthorizationRule{
		Name: "tasks/s3-read",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://s3.amazonaws.com"},
			Operation: &api.TaskOperation{
				AllowedPermissions: []string{"s3:GetObject", "s3:ListBucket"},
			},
			AllowedResources: []string{"arn:aws:s3:::acme-analytics/2026/*"},
		}},
	}
	hop2 := &api.TaskAuthorizationRule{
		Name: "tasks/s3-q1-only",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://s3.amazonaws.com"},
			Operation: &api.TaskOperation{
				AllowedPermissions: []string{"s3:GetObject"},
			},
			AllowedResources: []string{"arn:aws:s3:::acme-analytics/2026/q1.parquet"},
		}},
	}
	compiled, err := CompileAWSSessionPolicy(template, "s3.amazonaws.com", []*api.TaskAuthorizationRule{hop1, hop2})
	if err != nil {
		t.Fatalf("CompileAWSSessionPolicy: %v", err)
	}
	if !strings.Contains(compiled, `"s3:GetObject"`) || strings.Contains(compiled, `"s3:ListBucket"`) {
		t.Fatalf("expected only s3:GetObject in compiled policy: %s", compiled)
	}
	if !strings.Contains(compiled, `"arn:aws:s3:::acme-analytics/2026/q1.parquet"`) {
		t.Fatalf("expected narrowed resource in compiled policy: %s", compiled)
	}

	// 2. Attempt to escalate Action to s3:DeleteObject (outside template) -> rejected!
	escalateAction := &api.TaskAuthorizationRule{
		Name: "tasks/s3-delete",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://s3.amazonaws.com"},
			Operation: &api.TaskOperation{
				AllowedPermissions: []string{"s3:DeleteObject"},
			},
		}},
	}
	if _, err := CompileAWSSessionPolicy(template, "s3.amazonaws.com", []*api.TaskAuthorizationRule{escalateAction}); err == nil {
		t.Fatal("expected CompileAWSSessionPolicy to reject Action outside template")
	}

	// 3. Attempt to escalate Resource to another bucket (outside template) -> rejected!
	escalateRes := &api.TaskAuthorizationRule{
		Name: "tasks/s3-other-bucket",
		Rules: []*api.TaskRule{{
			AllowedServices:  []string{"egress://s3.amazonaws.com"},
			AllowedResources: []string{"arn:aws:s3:::payroll-secrets/*"},
		}},
	}
	if _, err := CompileAWSSessionPolicy(template, "s3.amazonaws.com", []*api.TaskAuthorizationRule{escalateRes}); err == nil {
		t.Fatal("expected CompileAWSSessionPolicy to reject Resource outside template")
	}
}

func TestOIDCFederationAndAWSExchangers(t *testing.T) {
	var stsCalls atomic.Int32
	var iamCalls atomic.Int32
	mockSTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ":generateAccessToken") {
			iamCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer federated-sts-token" {
				http.Error(w, "unexpected federated token", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken": "impersonated-sa-token",
				"expireTime":  time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			})
			return
		}
		stsCalls.Add(1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("subject_token") != "cp-minted-es256-jwt" {
			http.Error(w, "unexpected subject_token", http.StatusBadRequest)
			return
		}
		if r.FormValue("audience") != "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sam/providers/sam-cp" {
			http.Error(w, "unexpected audience", http.StatusBadRequest)
			return
		}
		if r.FormValue("scope") != "https://www.googleapis.com/auth/bigquery.readonly" {
			http.Error(w, "unexpected scope: "+r.FormValue("scope"), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "federated-sts-token",
			"expires_in":   300,
		})
	}))
	defer mockSTS.Close()

	var mintCalls atomic.Int32
	mintFn := func(_ context.Context, destination, audience string) (string, time.Time, error) {
		mintCalls.Add(1)
		return "cp-minted-es256-jwt", time.Now().Add(5 * time.Minute), nil
	}

	ex := NewOIDCFederationExchanger("bigquery.googleapis.com", &api.OIDCFederation{
		TokenEndpoint: mockSTS.URL + "/v1/token",
		Audience:      "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sam/providers/sam-cp",
		Impersonate:   "bq-reader@my-proj.iam.gserviceaccount.com",
		Scopes: []string{
			"https://www.googleapis.com/auth/bigquery.readonly",
			"https://www.googleapis.com/auth/devstorage.read_only",
		},
	}, mintFn, mockSTS.Client())
	ex.iamCredentialsEndpoint = mockSTS.URL

	tar := &api.TaskAuthorizationRule{
		Name: "tasks/bq-only",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://bigquery.googleapis.com"},
			Operation: &api.TaskOperation{
				AllowedPermissions: []string{"https://www.googleapis.com/auth/bigquery.readonly"},
			},
		}},
	}
	ctx := WithCallerBiscuit(context.Background(), []byte("caller-biscuit-bytes"))
	tok, exp, err := ex.Exchange(ctx, "alice@example.com", []*api.TaskAuthorizationRule{tar})
	if err != nil {
		t.Fatalf("OIDCFederationExchanger.Exchange: %v", err)
	}
	if tok != "impersonated-sa-token" || exp.IsZero() {
		t.Fatalf("unexpected token=%q exp=%v", tok, exp)
	}
	// Second call hits cache!
	tok2, _, err := ex.Exchange(ctx, "alice@example.com", []*api.TaskAuthorizationRule{tar})
	if err != nil || tok2 != "impersonated-sa-token" {
		t.Fatalf("cached Exchange failed: %v", err)
	}
	if mintCalls.Load() != 1 || stsCalls.Load() != 1 || iamCalls.Load() != 1 {
		t.Fatalf("expected 1 mint/sts/iam call with cache hit, got mint=%d sts=%d iam=%d", mintCalls.Load(), stsCalls.Load(), iamCalls.Load())
	}

	// AWS AssumeRoleWithWebIdentity test.
	mockAWS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("Action") != "AssumeRoleWithWebIdentity" || r.FormValue("RoleArn") != "arn:aws:iam::123456789012:role/sam-reader" {
			http.Error(w, "invalid AWS request", http.StatusBadRequest)
			return
		}
		if !strings.Contains(r.FormValue("Policy"), `"s3:GetObject"`) {
			http.Error(w, "missing compiled session policy", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIA123</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>aws-downscoped-session-token</SessionToken><Expiration>` + time.Now().Add(15*time.Minute).UTC().Format(time.RFC3339) + `</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`))
	}))
	defer mockAWS.Close()

	awsEx := NewAWSAssumeRoleExchanger("s3.amazonaws.com", &api.AWSAssumeRole{
		RoleArn: "arn:aws:iam::123456789012:role/sam-reader",
	}, mintFn, mockAWS.Client())
	awsEx.stsEndpoint = mockAWS.URL

	awsTAR := &api.TaskAuthorizationRule{
		Name: "tasks/s3-get",
		Rules: []*api.TaskRule{{
			AllowedServices:  []string{"egress://s3.amazonaws.com"},
			Operation:        &api.TaskOperation{AllowedPermissions: []string{"s3:GetObject"}},
			AllowedResources: []string{"arn:aws:s3:::my-bucket/data.csv"},
		}},
	}
	awsTok, _, err := awsEx.Exchange(ctx, "alice@example.com", []*api.TaskAuthorizationRule{awsTAR})
	if err != nil || awsTok != "aws-downscoped-session-token" {
		t.Fatalf("AWSAssumeRoleExchanger.Exchange: tok=%q err=%v", awsTok, err)
	}
}

func TestEgressServicePreserveHostAndForwardContext(t *testing.T) {
	h := newSTSNodeHarness(t)
	n := h.node
	tar := &api.TaskAuthorizationRule{
		Name: "tasks/inspect-chain",
		Rules: []*api.TaskRule{{
			AllowedServices: []string{"egress://bigquery.googleapis.com"},
		}},
	}
	taskBiscuit, err := identity.AttenuateBiscuit(n.GetIdentity(), tar)
	if err != nil {
		t.Fatal(err)
	}

	var gotHost, gotAuth, gotPrincipal, gotRoles, gotTask string
	operatorChain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotAuth = r.Header.Get("Authorization")
		gotPrincipal = r.Header.Get(api.HeaderSamPrincipal)
		gotRoles = r.Header.Get(api.HeaderSamRoles)
		gotTask = r.Header.Get(api.HeaderSamTask)
		w.WriteHeader(http.StatusOK)
	}))
	defer operatorChain.Close()

	dest := &api.EgressDestination{
		Name:           "bigquery.googleapis.com",
		TargetUrl:      operatorChain.URL,
		ServedBy:       []string{api.RoleNode},
		PreserveHost:   true,
		ForwardContext: true,
	}
	svc, err := newEgressServiceForNode(n, dest, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc.SetExchanger(&StaticSecretExchanger{}) // no-op or custom exchanger
	svc.SetExchanger(exchangerFunc(func(_ context.Context, principal string, rules []*api.TaskAuthorizationRule) (string, time.Time, error) {
		return "brokered-cloud-token-for-" + principal, time.Now().Add(time.Minute), nil
	}))
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/bigquery/v2/projects/p/datasets", nil)
	// Include spoofed headers that must be stripped and replaced by verified Biscuit context.
	req.Header.Set("Authorization", "Bearer caller-secret-must-be-stripped")
	req.Header.Set(api.HeaderSamPrincipal, "spoofed-principal")
	req = req.WithContext(WithCallerBiscuit(req.Context(), taskBiscuit))

	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotHost != "bigquery.googleapis.com" {
		t.Fatalf("expected preserved Host bigquery.googleapis.com, got %q", gotHost)
	}
	if gotAuth != "Bearer brokered-cloud-token-for-alice@example.com" {
		t.Fatalf("expected brokered Authorization, got %q", gotAuth)
	}
	if gotPrincipal != "alice@example.com" {
		t.Fatalf("expected X-Sam-Principal alice@example.com, got %q", gotPrincipal)
	}
	if !strings.Contains(gotRoles, api.RoleNode) {
		t.Fatalf("expected X-Sam-Roles to contain %s, got %q", api.RoleNode, gotRoles)
	}
	if gotTask != "tasks/inspect-chain" {
		t.Fatalf("expected X-Sam-Task tasks/inspect-chain, got %q", gotTask)
	}
}

type exchangerFunc func(ctx context.Context, principal string, rules []*api.TaskAuthorizationRule) (string, time.Time, error)

func (f exchangerFunc) Exchange(ctx context.Context, principal string, rules []*api.TaskAuthorizationRule) (string, time.Time, error) {
	return f(ctx, principal, rules)
}
