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
	"path/filepath"
	"testing"

	"github.com/google/agentmesh/internal/node"
	"github.com/spf13/cobra"
)

func TestResolveSocketPath(t *testing.T) {
	originalDataDir, originalSocketPath := dataDirFlag, socketPathFlag
	t.Cleanup(func() { dataDirFlag, socketPathFlag = originalDataDir, originalSocketPath })
	dataDirFlag = t.TempDir()

	newRunCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "run"}
		socketPathFlag = ""
		cmd.Flags().StringVar(&socketPathFlag, "socket-path", "", "")
		return cmd
	}

	t.Run("defaults into the data directory", func(t *testing.T) {
		want := filepath.Join(dataDirFlag, node.DefaultSocketName)
		if got := resolveSocketPath(newRunCmd()); got != want {
			t.Errorf("resolveSocketPath() = %q, want %q", got, want)
		}
	})

	t.Run("honors an explicit path", func(t *testing.T) {
		cmd := newRunCmd()
		if err := cmd.Flags().Set("socket-path", "/tmp/custom.sock"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if got := resolveSocketPath(cmd); got != "/tmp/custom.sock" {
			t.Errorf("resolveSocketPath() = %q, want /tmp/custom.sock", got)
		}
	})

	t.Run("an explicitly empty path disables the socket", func(t *testing.T) {
		cmd := newRunCmd()
		if err := cmd.Flags().Set("socket-path", ""); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if got := resolveSocketPath(cmd); got != "" {
			t.Errorf("resolveSocketPath() = %q, want empty", got)
		}
	})
}

func TestNormalizeControlPlaneURL(t *testing.T) {
	cases := map[string]string{
		"":                                  "",
		"   ":                               "",
		"bananas.sam-mesh.dev":              "https://bananas.sam-mesh.dev",
		"http://localhost:8080":             "http://localhost:8080",
		"https://bananas.sam-mesh.dev/":     "https://bananas.sam-mesh.dev",
		"https://bananas.sam-mesh.dev//":    "https://bananas.sam-mesh.dev",
		"https://bananas.sam-mesh.dev///":   "https://bananas.sam-mesh.dev",
		"  https://bananas.sam-mesh.dev/  ": "https://bananas.sam-mesh.dev",
		"http://127.0.0.1:8080///":          "http://127.0.0.1:8080",
	}
	for in, want := range cases {
		if got := normalizeControlPlaneURL(in); got != want {
			t.Errorf("normalizeControlPlaneURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultControlPlane(t *testing.T) {
	store, err := node.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if got := defaultControlPlane(store, "https://example.com"); got != "https://example.com" {
		t.Errorf("explicit control plane should win: got %q", got)
	}
	if got := defaultControlPlane(store, ""); got != "" {
		t.Errorf("no explicit and no stored URL should resolve to nothing, never a public mesh: got %q", got)
	}

	if err := store.SaveControlPlaneURL("https://stored.example.com"); err != nil {
		t.Fatalf("SaveControlPlaneURL: %v", err)
	}
	if got := defaultControlPlane(store, ""); got != "https://stored.example.com" {
		t.Errorf("no explicit should fall back to the stored URL: got %q", got)
	}
}

func TestIsYesResponse(t *testing.T) {
	tests := map[string]bool{
		"y":       true,
		"Y":       true,
		"yes":     true,
		"YES\n":   true,
		" yes \n": true,
		"n":       false,
		"no":      false,
		"":        false,
		"\n":      false,
		"yep":     false,
	}
	for in, want := range tests {
		if got := isYesResponse(in); got != want {
			t.Errorf("isYesResponse(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDecideJoinAction(t *testing.T) {
	const a, b = "https://a.example.com", "https://b.example.com"

	tests := []struct {
		name                                   string
		identityExists, hasPubKey, interactive bool
		controlPlaneAddr, stored               string
		want                                   joinAction
	}{
		{"no identity, interactive, no urls: needs control plane", false, false, true, "", "", joinNeedsControlPlane},
		{"no identity, interactive, explicit url: proceed", false, false, true, a, "", joinProceed},
		{"no identity, non-interactive: fall back", false, false, false, "", "", joinFallbackNoTTY},
		{"usable identity: skip regardless of terminal", true, true, false, "", a, joinSkip},
		{"usable identity, matching explicit url: skip", true, true, true, a, a, joinSkip},
		{"identity missing pubkey, interactive: proceed (re-join)", true, false, true, "", a, joinProceed},
		{"identity missing pubkey, non-interactive: fall back", true, false, false, "", a, joinFallbackNoTTY},
		{"mismatched, interactive: confirm switch", true, true, true, b, a, joinNeedsConfirmSwitch},
		{"mismatched, non-interactive: fatal", true, true, false, b, a, joinFatalMismatchNoTTY},
		{"explicit equals stored (normalized): not a mismatch", true, true, true, a + "/", a, joinSkip},
		{"no identity, interactive, only stored url: proceed", false, false, true, "", a, joinProceed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideJoinAction(tt.identityExists, tt.hasPubKey, tt.interactive, tt.controlPlaneAddr, tt.stored)
			if got != tt.want {
				t.Errorf("decideJoinAction(%v, %v, %v, %q, %q) = %v, want %v",
					tt.identityExists, tt.hasPubKey, tt.interactive, tt.controlPlaneAddr, tt.stored, got, tt.want)
			}
		})
	}
}
