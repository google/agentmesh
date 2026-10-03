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

package storage

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/sam/api"
	"google.golang.org/protobuf/proto"
)

// TestMeshPolicyRoundTripsEveryRoleField stores a role with every repeated
// field populated and reads it back.
//
// role_permissions rows are discriminated by a resource_type string, so a field
// added to PolicyRole without a matching case here is written nowhere and read
// back empty. Nothing fails: the policy saves, the API returns it, and the
// grant silently does not exist. This walks the message with reflection so a
// future field is caught here rather than in production.
func TestMeshPolicyRoundTripsEveryRoleField(t *testing.T) {
	store, err := NewSQLStore("sqlite", filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	want := &api.PolicyRole{
		Name:            "everything",
		AllowedTargets:  []string{"group:backend"},
		AllowedServices: []string{"mcp://tool"},
		CustomDatalog:   []string{`region("emea")`},
		AllowedLabels:   []string{"region=*"},
		Http:            []*api.HTTPGrant{{Service: "mcp://tool", Methods: []string{"GET"}, Paths: []string{"/v1/*"}}},
	}

	if err := store.SaveMeshPolicy(ctx, []*api.PolicyRole{want}, nil); err != nil {
		t.Fatalf("SaveMeshPolicy: %v", err)
	}

	roles, _, err := store.GetMeshPolicy(ctx)
	if err != nil {
		t.Fatalf("GetMeshPolicy: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("got %d roles, want 1", len(roles))
	}
	got := roles[0]

	// Reflection rather than a field list: a new repeated field left out of
	// SaveMeshPolicy comes back empty and is reported here by name.
	wantVal := reflect.ValueOf(want).Elem()
	gotVal := reflect.ValueOf(got).Elem()
	for i := 0; i < wantVal.NumField(); i++ {
		field := wantVal.Type().Field(i)
		if !field.IsExported() || field.Type.Kind() != reflect.Slice {
			continue
		}
		w := wantVal.Field(i).Interface()
		g := gotVal.Field(i).Interface()
		if field.Type.Elem().Implements(reflect.TypeOf((*proto.Message)(nil)).Elem()) {
			// Message slices carry internal state DeepEqual would compare.
			wm, gm := reflect.ValueOf(w), reflect.ValueOf(g)
			if wm.Len() != gm.Len() {
				t.Errorf("field %s did not round trip: saved %d entries, loaded %d", field.Name, wm.Len(), gm.Len())
				continue
			}
			for j := 0; j < wm.Len(); j++ {
				if !proto.Equal(wm.Index(j).Interface().(proto.Message), gm.Index(j).Interface().(proto.Message)) {
					t.Errorf("field %s[%d] did not round trip: saved %v, loaded %v", field.Name, j, wm.Index(j), gm.Index(j))
				}
			}
			continue
		}
		if !reflect.DeepEqual(w, g) {
			t.Errorf("field %s did not round trip: saved %v, loaded %v", field.Name, w, g)
		}
	}
}

// TestSavePolicyDocumentIsAtomic: a document is applied whole or not at all.
// The control plane validates before saving, so the failing row here is one
// validation would have refused; what matters is that the roles written in
// the same call are rolled back with it.
func TestSavePolicyDocumentIsAtomic(t *testing.T) {
	store, err := NewSQLStore("sqlite", filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	first := []*api.PolicyRole{{Name: "first"}}
	egress := []*api.EgressDestination{{Name: "api.github.com", Credential: "gh", ServedBy: []string{"first"}}}
	if err := store.SavePolicyDocument(ctx, first, nil, egress); err != nil {
		t.Fatalf("SavePolicyDocument: %v", err)
	}
	got, err := store.GetEgressDestinations(ctx)
	if err != nil || len(got) != 1 || !proto.Equal(got[0], egress[0]) {
		t.Fatalf("GetEgressDestinations = %v, %v", got, err)
	}

	// Two rows with the same name violate the primary key after the roles
	// were already replaced inside the transaction.
	bad := []*api.EgressDestination{{Name: "dup.example", ServedBy: []string{"second"}}, {Name: "dup.example", ServedBy: []string{"second"}}}
	if err := store.SavePolicyDocument(ctx, []*api.PolicyRole{{Name: "second"}}, nil, bad); err == nil {
		t.Fatal("SavePolicyDocument accepted a duplicate destination")
	}
	roles, _, err := store.GetMeshPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].Name != "first" {
		t.Errorf("roles after a failed document = %v, want the previous document's", roles)
	}
	got, err = store.GetEgressDestinations(ctx)
	if err != nil || len(got) != 1 || got[0].Name != "api.github.com" {
		t.Errorf("egress after a failed document = %v, %v, want the previous document's", got, err)
	}
}
