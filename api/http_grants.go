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
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/eclipse-biscuit/biscuit-go/v2"
)

// httpMethodSyntax is the token form of an HTTP method, uppercase as the
// registered methods are written. A method is compared byte for byte with
// the request, so the case has to be fixed here.
var httpMethodSyntax = regexp.MustCompile(`^[A-Z][A-Z0-9-]{0,31}$`)

// HTTPGrantKey returns the fact a narrowed grant is minted as and the key its
// method and path facts are keyed by, for one allowed_services entry. The key
// is the term the plain granted_service_* fact would carry, so
// BaselineHTTPRules can derive that fact from it.
func HTTPGrantKey(service string) (factName, svcType, key string) {
	plain := BuildServiceDatalogFact(service)
	svcType, svcName := ParseServiceTarget(service)
	switch plain.Name {
	case FactGrantedServiceAllTypes:
		return FactHTTPGrantedServiceAllTypes, "*", "*"
	case FactGrantedServiceAll:
		return FactHTTPGrantedServiceAll, svcType, "*"
	case FactGrantedServiceSuffix:
		return FactHTTPGrantedServiceSuffix, svcType, svcName[1:]
	case FactGrantedServicePrefix:
		return FactHTTPGrantedServicePrefix, svcType, svcName[:len(svcName)-1]
	default:
		return FactHTTPGrantedServiceExact, svcType, svcName
	}
}

// ValidateHTTPGrant checks one PolicyRole.http entry against the role's
// allowed_services: the entry must narrow a grant the role makes, written the
// same way, and its methods and paths must be well-formed.
func ValidateHTTPGrant(g *HTTPGrant, allowedServices []string) error {
	if g == nil {
		return fmt.Errorf("http entry is nil")
	}
	if g.GetService() == "" {
		return fmt.Errorf("http entry has no service")
	}
	if !slices.Contains(allowedServices, g.GetService()) {
		return fmt.Errorf("http entry %q does not name one of the role's allowed_services", g.GetService())
	}
	if err := ValidateServiceFormat(g.GetService()); err != nil {
		return err
	}
	if len(g.GetMethods()) == 0 && len(g.GetPaths()) == 0 {
		return fmt.Errorf("http entry %q narrows nothing: set methods, paths or both, or remove the entry", g.GetService())
	}
	for _, m := range g.GetMethods() {
		if !httpMethodSyntax.MatchString(m) {
			return fmt.Errorf("http entry %q: method %q must be an uppercase HTTP method such as \"GET\"", g.GetService(), m)
		}
		if m == "CONNECT" {
			return fmt.Errorf("http entry %q: method %q is not an HTTP request method; use EGRESS_MODE_TCP for tunnels", g.GetService(), m)
		}
	}
	for _, p := range g.GetPaths() {
		if err := validateHTTPGrantPath(p); err != nil {
			return fmt.Errorf("http entry %q: %w", g.GetService(), err)
		}
	}
	return nil
}

// ValidateHTTPGrants validates all PolicyRole.http entries for a single role,
// ensuring each entry is valid and no two entries narrow the same service
// (which would otherwise combine their method and path facts across grants).
func ValidateHTTPGrants(grants []*HTTPGrant, allowedServices []string) error {
	seen := make(map[string]bool, len(grants))
	for _, g := range grants {
		if err := ValidateHTTPGrant(g, allowedServices); err != nil {
			return err
		}
		if seen[g.GetService()] {
			return fmt.Errorf("duplicate http entry for service %q; combine methods and paths into a single entry", g.GetService())
		}
		seen[g.GetService()] = true
	}
	return nil
}

// hasEncodedPathTraversal reports whether p contains URL-encoded dot or slash
// sequences (%2e, %2f, %5c, case-insensitive) or ASCII control characters.
func hasEncodedPathTraversal(p string) bool {
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x20 || c == 0x7f || c == '\\' || c == '"' {
			return true
		}
		if c == '%' && i+2 < len(p) {
			hex := strings.ToLower(p[i+1 : i+3])
			if hex == "2e" || hex == "2f" || hex == "5c" || hex == "00" {
				return true
			}
		}
	}
	return false
}

// validateHTTPGrantPath accepts "/exact" or "/prefix/*". The path is matched
// against path($p) as the backend sees it, so it carries no query and no
// dot segment, and a wildcard is only meaningful at the end.
func validateHTTPGrantPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must start with \"/\"", p)
	}
	if strings.ContainsAny(p, "?#") {
		return fmt.Errorf("path %q must not carry a query or a fragment", p)
	}
	if hasEncodedPathTraversal(p) {
		return fmt.Errorf("path %q must not contain encoded traversal sequences or control characters", p)
	}
	trimmed := strings.TrimSuffix(p, "*")
	if strings.Contains(trimmed, "*") {
		return fmt.Errorf("path %q: \"*\" is only allowed at the end, as in \"/v2/*\"", p)
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("path %q must not contain a dot segment", p)
		}
	}
	return nil
}

// BuildHTTPGrantFacts compiles one narrowed grant into the facts minted into
// the holder's credential: the http_granted_service_* fact for the entry,
// then one fact per axis. Methods and exact paths travel as one Set each;
// each prefix is its own fact, because starts_with has no set form.
func BuildHTTPGrantFacts(g *HTTPGrant) []biscuit.Fact {
	factName, svcType, key := HTTPGrantKey(g.GetService())
	keyTerms := []biscuit.Term{biscuit.String(svcType), biscuit.String(key)}

	var facts []biscuit.Fact
	switch factName {
	case FactHTTPGrantedServiceAllTypes:
		facts = append(facts, MarkerFact(factName))
	case FactHTTPGrantedServiceAll:
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{Name: factName, IDs: []biscuit.Term{biscuit.String(svcType)}}})
	default:
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{Name: factName, IDs: keyTerms}})
	}

	if len(g.GetMethods()) == 0 {
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedMethodAny, IDs: keyTerms}})
	} else {
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedMethod,
			IDs:  append(slices.Clone(keyTerms), stringSet(g.GetMethods())),
		}})
	}

	var exact, prefixes []string
	for _, p := range g.GetPaths() {
		if strings.HasSuffix(p, "*") {
			prefixes = append(prefixes, strings.TrimSuffix(p, "*"))
		} else {
			exact = append(exact, p)
		}
	}
	if len(exact) == 0 && len(prefixes) == 0 {
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{Name: FactGrantedPathAny, IDs: keyTerms}})
	}
	if len(exact) > 0 {
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedPathExact,
			IDs:  append(slices.Clone(keyTerms), stringSet(exact)),
		}})
	}
	sort.Strings(prefixes)
	for _, prefix := range prefixes {
		facts = append(facts, biscuit.Fact{Predicate: biscuit.Predicate{
			Name: FactGrantedPathPrefix,
			IDs:  append(slices.Clone(keyTerms), biscuit.String(prefix)),
		}})
	}
	return facts
}

// stringSet builds a sorted, deduplicated Biscuit Set of strings.
func stringSet(values []string) biscuit.Set {
	sorted := slices.Clone(values)
	sort.Strings(sorted)
	sorted = slices.Compact(sorted)
	set := make(biscuit.Set, 0, len(sorted))
	for _, v := range sorted {
		set = append(set, biscuit.String(v))
	}
	return set
}

// SplitHTTPGrants separates a role's allowed_services into the entries minted
// as plain grants and the entries narrowed by PolicyRole.http. A narrowed entry
// is withheld from the plain list: it exists only as its http_granted_service_*
// fact, and the request has to earn the plain fact through BaselineHTTPRules.
func SplitHTTPGrants(role *PolicyRole) (plain []string, narrowed []*HTTPGrant) {
	narrowedByService := make(map[string]bool, len(role.GetHttp()))
	for _, g := range role.GetHttp() {
		if g == nil || g.GetService() == "" {
			continue
		}
		narrowedByService[g.GetService()] = true
		narrowed = append(narrowed, g)
	}
	for _, svc := range role.GetAllowedServices() {
		if !narrowedByService[svc] {
			plain = append(plain, svc)
		}
	}
	return plain, narrowed
}
