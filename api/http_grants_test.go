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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
)

// authorizeHTTP evaluates the baseline policies plus BaselineHTTPRules for a
// token minted with the given facts, against a request on target with the
// given method and path. An empty method leaves the request facts out, as a
// stream that carries no HTTP request does.
func authorizeHTTP(t *testing.T, tokenFacts []biscuit.Fact, target, method, path string) error {
	t.Helper()
	pub, priv := makeKeyPair(t)
	builder := biscuit.NewBuilder(priv)
	for _, f := range tokenFacts {
		if err := builder.AddAuthorityFact(f); err != nil {
			t.Fatalf("AddAuthorityFact: %v", err)
		}
	}
	tok, err := builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	authorizer, err := tok.Authorizer(pub, biscuit.WithWorldOptions(datalog.WithMaxDuration(5*time.Second)))
	if err != nil {
		t.Fatalf("Authorizer: %v", err)
	}
	opType, opName := ParseServiceTarget(target)
	authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: FactService, IDs: []biscuit.Term{biscuit.String(opType), biscuit.String(opName)}}})
	if method != "" {
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: FactMethod, IDs: []biscuit.Term{biscuit.String(method)}}})
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{Name: FactPath, IDs: []biscuit.Term{biscuit.String(path)}}})
	}
	for _, p := range BaselinePolicies {
		authorizer.AddPolicy(p)
	}
	for _, r := range BaselineHTTPRules {
		authorizer.AddRule(r)
	}
	return authorizer.Authorize()
}

func TestHTTPGrantNarrowsServiceGrant(t *testing.T) {
	narrowed := BuildHTTPGrantFacts(&HTTPGrant{
		Service: "egress://api.github.com",
		Methods: []string{"GET", "HEAD"},
		Paths:   []string{"/repos/acme/*", "/user"},
	})

	tests := []struct {
		name        string
		facts       []biscuit.Fact
		target      string
		method      string
		path        string
		expectAllow bool
	}{
		{"allowed method under the prefix", narrowed, "egress://api.github.com", "GET", "/repos/acme/dubbing/pulls", true},
		{"allowed method on the exact path", narrowed, "egress://api.github.com", "HEAD", "/user", true},
		{"method outside the grant", narrowed, "egress://api.github.com", "POST", "/repos/acme/dubbing/pulls", false},
		{"path outside the grant", narrowed, "egress://api.github.com", "GET", "/repos/other/x", false},
		{"the prefix itself is not the exact path", narrowed, "egress://api.github.com", "GET", "/userinfo", false},
		{"another service is not granted at all", narrowed, "egress://api.other.com", "GET", "/user", false},
		// A tunnel is CONNECT with an empty path: neither axis matches.
		{"a tunnel fails closed", narrowed, "egress://api.github.com", "CONNECT", "", false},
		// No method() fact at all: the positive rules derive nothing.
		{"a request without HTTP facts fails closed", narrowed, "egress://api.github.com", "", "", false},
		{
			name:        "methods narrowed, any path",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "mcp://tools", Methods: []string{"GET"}}),
			target:      "mcp://tools",
			method:      "GET",
			path:        "/anything/at/all",
			expectAllow: true,
		},
		{
			name:        "paths narrowed, any method",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "mcp://tools", Paths: []string{"/mcp"}}),
			target:      "mcp://tools",
			method:      "POST",
			path:        "/mcp",
			expectAllow: true,
		},
		{
			name:        "paths narrowed fails closed on a tunnel",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "mcp://tools", Paths: []string{"/mcp"}}),
			target:      "mcp://tools",
			method:      "CONNECT",
			path:        "",
			expectAllow: false,
		},
		{
			name:        "suffix pattern narrowed",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "egress://*.internal.example.com", Methods: []string{"GET"}}),
			target:      "egress://mam.internal.example.com",
			method:      "GET",
			path:        "/v2",
			expectAllow: true,
		},
		{
			name:        "suffix pattern narrowed, wrong method",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "egress://*.internal.example.com", Methods: []string{"GET"}}),
			target:      "egress://mam.internal.example.com",
			method:      "PUT",
			path:        "/v2",
			expectAllow: false,
		},
		{
			name:        "prefix pattern narrowed",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "mcp://calc.*", Paths: []string{"/mcp"}}),
			target:      "mcp://calc.service.internal",
			method:      "POST",
			path:        "/mcp",
			expectAllow: true,
		},
		{
			name:        "type wildcard narrowed",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "egress://*", Methods: []string{"GET"}}),
			target:      "egress://anything.example",
			method:      "GET",
			path:        "/",
			expectAllow: true,
		},
		{
			name:        "type wildcard narrowed does not leak to another type",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "egress://*", Methods: []string{"GET"}}),
			target:      "mcp://anything",
			method:      "GET",
			path:        "/",
			expectAllow: false,
		},
		{
			name:        "global wildcard narrowed",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "*", Methods: []string{"GET"}}),
			target:      "inference://anything",
			method:      "GET",
			path:        "/v1/models",
			expectAllow: true,
		},
		{
			name:        "global wildcard narrowed, wrong method",
			facts:       BuildHTTPGrantFacts(&HTTPGrant{Service: "*", Methods: []string{"GET"}}),
			target:      "inference://anything",
			method:      "POST",
			path:        "/v1/chat/completions",
			expectAllow: false,
		},
		{
			// Union semantics: a plain grant from another role is not narrowed.
			name: "a plain grant alongside a narrowed one is still plain",
			facts: append(slices.Clone(narrowed),
				biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedServiceExact, IDs: []biscuit.Term{biscuit.String("egress"), biscuit.String("api.github.com")}}}),
			target:      "egress://api.github.com",
			method:      "DELETE",
			path:        "/repos/other",
			expectAllow: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizeHTTP(t, tt.facts, tt.target, tt.method, tt.path)
			if tt.expectAllow && err != nil {
				t.Errorf("expected allow, got %v", err)
			}
			if !tt.expectAllow && err == nil {
				t.Error("expected deny, got allow")
			}
		})
	}
}

func TestHTTPGrantKey(t *testing.T) {
	tests := []struct {
		service        string
		wantFact, want string
		wantType       string
	}{
		{"egress://api.github.com", FactHTTPGrantedServiceExact, "api.github.com", "egress"},
		{"egress://*.internal.example.com", FactHTTPGrantedServiceSuffix, ".internal.example.com", "egress"},
		{"mcp://calc.*", FactHTTPGrantedServicePrefix, "calc.", "mcp"},
		{"egress://*", FactHTTPGrantedServiceAll, "*", "egress"},
		{"*", FactHTTPGrantedServiceAllTypes, "*", "*"},
	}
	for _, tt := range tests {
		fact, typ, key := HTTPGrantKey(tt.service)
		if fact != tt.wantFact || typ != tt.wantType || key != tt.want {
			t.Errorf("HTTPGrantKey(%q) = (%s, %s, %s), want (%s, %s, %s)", tt.service, fact, typ, key, tt.wantFact, tt.wantType, tt.want)
		}
	}
}

func TestSplitHTTPGrants(t *testing.T) {
	role := &PolicyRole{
		AllowedServices: []string{"mcp://a", "egress://b", "inference://*"},
		Http:            []*HTTPGrant{{Service: "egress://b", Methods: []string{"GET"}}},
	}
	plain, narrowed := SplitHTTPGrants(role)
	if want := []string{"mcp://a", "inference://*"}; !slices.Equal(plain, want) {
		t.Errorf("plain = %v, want %v", plain, want)
	}
	if len(narrowed) != 1 || narrowed[0].Service != "egress://b" {
		t.Errorf("narrowed = %v, want the egress://b entry", narrowed)
	}
}

func TestBuildPolicyRulesRendersHTTPGrants(t *testing.T) {
	rules, warnings := BuildPolicyRules([]*PolicyRole{{
		Name:            "contractor",
		AllowedServices: []string{"mcp://tools", "egress://mam.internal.example.com"},
		Http:            []*HTTPGrant{{Service: "egress://mam.internal.example.com", Methods: []string{"GET"}, Paths: []string{"/v2/public/*"}}},
	}}, nil)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	texts := PolicyRuleTexts(rules)
	for _, want := range []string{
		`granted_service_set("mcp", ["tools"]) <- role("contractor")`,
		`http_granted_service_exact("egress", "mam.internal.example.com") <- role("contractor")`,
		`granted_method("egress", "mam.internal.example.com", ["GET"]) <- role("contractor")`,
		`granted_path_prefix("egress", "mam.internal.example.com", "/v2/public/") <- role("contractor")`,
	} {
		if !slices.Contains(texts, want) {
			t.Errorf("rules lack %q; got:\n%s", want, strings.Join(texts, "\n"))
		}
	}
	for _, text := range texts {
		if strings.HasPrefix(text, `granted_service_exact("egress"`) || strings.HasPrefix(text, `granted_service_set("egress"`) {
			t.Errorf("narrowed entry rendered as a plain grant: %s", text)
		}
	}
	// The rendered text is what every other implementation parses.
	if _, err := ParseDatalogRules(texts); err != nil {
		t.Fatalf("rendered rules do not parse back: %v", err)
	}
}

func TestValidateHTTPGrant(t *testing.T) {
	allowed := []string{"egress://api.github.com", "mcp://tools"}
	tests := []struct {
		name    string
		grant   *HTTPGrant
		wantErr string
	}{
		{"valid", &HTTPGrant{Service: "egress://api.github.com", Methods: []string{"GET", "HEAD"}, Paths: []string{"/user", "/repos/*"}}, ""},
		{"valid with one axis", &HTTPGrant{Service: "mcp://tools", Paths: []string{"/mcp"}}, ""},
		{"narrows nothing", &HTTPGrant{Service: "mcp://tools"}, "narrows nothing"},
		{"not one of allowed_services", &HTTPGrant{Service: "egress://other.example"}, "does not name one of the role's allowed_services"},
		{"empty service", &HTTPGrant{}, "no service"},
		{"lowercase method", &HTTPGrant{Service: "mcp://tools", Methods: []string{"get"}}, "uppercase HTTP method"},
		{"relative path", &HTTPGrant{Service: "mcp://tools", Paths: []string{"user"}}, `must start with "/"`},
		{"query in path", &HTTPGrant{Service: "mcp://tools", Paths: []string{"/user?x=1"}}, "query"},
		{"wildcard in the middle", &HTTPGrant{Service: "mcp://tools", Paths: []string{"/a/*/b"}}, "only allowed at the end"},
		{"dot segment", &HTTPGrant{Service: "mcp://tools", Paths: []string{"/a/../b"}}, "dot segment"},
		{"encoded dot segment", &HTTPGrant{Service: "mcp://tools", Paths: []string{"/a/%2e%2e/b"}}, "encoded traversal"},
		{"CONNECT method rejected", &HTTPGrant{Service: "egress://api.github.com", Methods: []string{"CONNECT"}}, "not an HTTP request method"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHTTPGrant(tt.grant, allowed)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateHTTPGrantsRejectsDuplicateService(t *testing.T) {
	allowed := []string{"egress://api.github.com", "mcp://tools"}
	dup := []*HTTPGrant{
		{Service: "egress://api.github.com", Methods: []string{"GET"}, Paths: []string{"/repos/*"}},
		{Service: "egress://api.github.com", Methods: []string{"POST"}, Paths: []string{"/issues/*"}},
	}
	if err := ValidateHTTPGrants(dup, allowed); err == nil || !strings.Contains(err.Error(), "duplicate http entry") {
		t.Fatalf("ValidateHTTPGrants(dup) = %v, want duplicate error", err)
	}
}
