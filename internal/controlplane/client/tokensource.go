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

package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// TokenSource fetches a fresh platform or OIDC JWT for enrollment, continuous
// attestation at POST /refresh, or fallback re-enrollment.
type TokenSource interface {
	FetchToken(ctx context.Context) (string, error)
}

// FileTokenSource reads a JWT from a file path (e.g. a Kubernetes projected
// ServiceAccount token volume or a SPIRE spiffe-helper JWT-SVID file).
type FileTokenSource struct {
	path string
}

// NewFileTokenSource creates a TokenSource that reads path on every FetchToken call.
func NewFileTokenSource(path string) *FileTokenSource {
	return &FileTokenSource{path: path}
}

// FetchToken reads and trims the JWT from disk.
func (s *FileTokenSource) FetchToken(_ context.Context) (string, error) {
	if strings.TrimSpace(s.path) == "" {
		return "", errors.New("jwt file path is empty")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return "", fmt.Errorf("failed to read JWT file: %w", err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("JWT file %s is empty", s.path)
	}
	return tok, nil
}
