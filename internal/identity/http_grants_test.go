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

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
)

// TestMintNarrowedGrant pins what a role with PolicyRole.http mints: the
// narrowed entry appears as its http_granted_service_* fact with its method
// and path facts, and not as a plain grant; the other entries are unchanged.
func TestMintNarrowedGrant(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerID := newTestPeer(t)

	role := &api.PolicyRole{
		Name:            "contractor",
		AllowedServices: []string{"mcp://tools", "egress://mam.internal.example.com"},
		Http: []*api.HTTPGrant{{
			Service: "egress://mam.internal.example.com",
			Methods: []string{"GET"},
			Paths:   []string{"/v2/public/*"},
		}},
	}
	token, err := MintBootstrapBiscuitToken(priv, peerID, "contractor", time.Now().Add(time.Hour), []*api.PolicyRole{role}, nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	b, err := biscuit.Unmarshal(token)
	if err != nil {
		t.Fatal(err)
	}
	code := b.String()

	// Biscuit.String prints Set terms as symbol references, so the set facts
	// are matched on their name and key only.
	for _, want := range []string{
		`granted_service_set("mcp", [`,
		`http_granted_service_exact("egress", "mam.internal.example.com")`,
		`granted_method("egress", "mam.internal.example.com", [`,
		`granted_path_prefix("egress", "mam.internal.example.com", "/v2/public/")`,
	} {
		if !strings.Contains(code, want) {
			t.Errorf("token lacks %s; authority block:\n%s", want, code)
		}
	}
	// The facts line lists them space-separated; a plain egress grant would
	// start a token there, http_granted_service_exact would not.
	for _, tok := range strings.Fields(code) {
		if strings.HasPrefix(tok, `granted_service_exact("egress"`) || strings.HasPrefix(tok, `granted_service_set("egress"`) {
			t.Errorf("narrowed entry minted as a plain grant: %s", tok)
		}
	}
}
