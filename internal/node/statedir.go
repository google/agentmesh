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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/crypto"
	"google.golang.org/protobuf/encoding/protojson"
)

// The state directory is the layout the native SDKs keep a member in, and
// what `agentmesh-node state export` writes and `agentmesh-node state import` reads:
// the private key in the libp2p PrivateKey encoding and the
// api.MemberCredential as protojson with proto field names. Files are
// owner-only; unknown fields in the credential are an error, as on every
// Agent Mesh surface.
const (
	StateDirIdentityFile   = "identity.key"
	StateDirCredentialFile = "credential.json"
)

var stateDirMarshal = protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}

// WriteStateDir writes a member to dir, creating it owner-only.
func WriteStateDir(dir string, privKey []byte, c *api.MemberCredential) error {
	if _, err := crypto.UnmarshalPrivateKey(privKey); err != nil {
		return fmt.Errorf("private key is not a libp2p key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	credential, err := stateDirMarshal.Marshal(c)
	if err != nil {
		return err
	}
	if err := writeOwnerOnly(filepath.Join(dir, StateDirIdentityFile), privKey); err != nil {
		return err
	}
	return writeOwnerOnly(filepath.Join(dir, StateDirCredentialFile), append(credential, '\n'))
}

// ReadStateDir reads a member from dir.
func ReadStateDir(dir string) (privKey []byte, c *api.MemberCredential, err error) {
	privKey, err = os.ReadFile(filepath.Join(dir, StateDirIdentityFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("no identity in %s: %w", dir, err)
		}
		return nil, nil, err
	}
	if _, err := crypto.UnmarshalPrivateKey(privKey); err != nil {
		return nil, nil, fmt.Errorf("%s: not a libp2p private key: %w", filepath.Join(dir, StateDirIdentityFile), err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, StateDirCredentialFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("no credential in %s: %w", dir, err)
		}
		return nil, nil, err
	}
	c = &api.MemberCredential{}
	if err := protojson.Unmarshal(raw, c); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", filepath.Join(dir, StateDirCredentialFile), err)
	}
	return privKey, c, nil
}

func writeOwnerOnly(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
