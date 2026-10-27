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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestValidateControlPlaneTransport(t *testing.T) {
	tests := []struct {
		url      string
		insecure bool
		wantErr  bool
		wantKind error
	}{
		{"https://hub.sam-mesh.dev", false, false, nil},
		{"https://10.0.0.5:8443", false, false, nil},
		{"http://127.0.0.1:8080", false, false, nil},
		{"http://localhost:8080", false, false, nil},
		{"http://[::1]:8080", false, false, nil},
		{"http://[::ffff:127.0.0.1]:8080", false, false, nil},
		// Fail closed on anything that is not literally loopback. "127.1" is
		// loopback to the resolver but not to net.ParseIP; refusing it costs
		// the operator a clearer spelling, accepting a lookalike would cost
		// the trust root.
		{"http://127.1:8080", false, true, ErrInsecureControlPlaneURL},
		{"http://localhost.:8080", false, true, ErrInsecureControlPlaneURL},
		{"http://0.0.0.0:8080", false, true, ErrInsecureControlPlaneURL},
		{"http://agentmesh-control-plane:8080", false, true, ErrInsecureControlPlaneURL},
		{"http://10.0.0.5:8080", false, true, ErrInsecureControlPlaneURL},
		{"http://127.0.0.1.evil.example:8080", false, true, ErrInsecureControlPlaneURL},
		{"http://agentmesh-control-plane:8080", true, false, nil},
		{"https://", false, true, nil},
		{"https://:8443", false, true, nil},
		{"http://", true, true, nil},
		{"ftp://hub.sam-mesh.dev", false, true, nil},
		{"hub.sam-mesh.dev", false, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := ValidateControlPlaneTransport(tt.url, tt.insecure)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateControlPlaneTransport(%q, insecure=%v) = %v, wantErr %v", tt.url, tt.insecure, err, tt.wantErr)
			}
			if tt.wantKind != nil && !errors.Is(err, tt.wantKind) {
				t.Errorf("error %v is not %v", err, tt.wantKind)
			}
		})
	}
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
		"http://127.0.0.1:8080/":            "http://127.0.0.1:8080",
		"http://127.0.0.1:8080///":          "http://127.0.0.1:8080",
		"https://":                          "https://",
		"http://":                           "http://",
	}
	for in, want := range cases {
		if got := NormalizeControlPlaneURL(in); got != want {
			t.Errorf("NormalizeControlPlaneURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// A key set is only as good as the signature a receiver can already check:
// trusting the retiring key must be enough to learn the new one, and a set
// signed by nobody the receiver trusts must not replace anything.
func TestKeysResponseSignatureChain(t *testing.T) {
	oldPub, oldPriv := genKey(t)
	newPub, newPriv := genKey(t)
	now := time.Now()

	signed := func() *KeysResponse {
		resp := &KeysResponse{PublicKeys: [][]byte{oldPub, newPub}}
		if err := SignKeysResponse(resp, []ed25519.PrivateKey{oldPriv, newPriv}, now); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	t.Run("receiver on the retiring key learns the new one", func(t *testing.T) {
		keys, err := VerifyKeysResponse(signed(), []ed25519.PublicKey{oldPub}, now)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if len(keys) != 2 || !keys[1].Equal(newPub) {
			t.Errorf("keys = %d entries, want old and new", len(keys))
		}
	})

	t.Run("receiver on the new key verifies too", func(t *testing.T) {
		if _, err := VerifyKeysResponse(signed(), []ed25519.PublicKey{newPub}, now); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	t.Run("set signed by a stranger is refused", func(t *testing.T) {
		strangerPub, strangerPriv := genKey(t)
		resp := &KeysResponse{PublicKeys: [][]byte{strangerPub}}
		if err := SignKeysResponse(resp, []ed25519.PrivateKey{strangerPriv}, now); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyKeysResponse(resp, []ed25519.PublicKey{oldPub}, now); err == nil {
			t.Fatal("a set signed by an untrusted key must not be accepted")
		}
	})

	t.Run("listing a trusted key without its signature is refused", func(t *testing.T) {
		// The attacker knows the victim trusts oldPub and lists it, but can
		// only sign with their own key.
		attackerPub, attackerPriv := genKey(t)
		resp := &KeysResponse{PublicKeys: [][]byte{oldPub, attackerPub}}
		if err := SignKeysResponse(resp, []ed25519.PrivateKey{attackerPriv, attackerPriv}, now); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyKeysResponse(resp, []ed25519.PublicKey{oldPub}, now); err == nil {
			t.Fatal("a listed-but-not-signing trusted key must not vouch for the set")
		}
	})

	t.Run("tampered set is refused", func(t *testing.T) {
		resp := signed()
		resp.PublicKeys = append(resp.PublicKeys, make([]byte, ed25519.PublicKeySize))
		resp.Signatures = append(resp.Signatures, resp.Signatures[0])
		if _, err := VerifyKeysResponse(resp, []ed25519.PublicKey{oldPub}, now); err == nil {
			t.Fatal("appending a key must break every signature")
		}
	})

	t.Run("replayed set outside the freshness window is refused", func(t *testing.T) {
		if _, err := VerifyKeysResponse(signed(), []ed25519.PublicKey{oldPub}, now.Add(KeysResponseFreshness+time.Minute)); err == nil {
			t.Fatal("a stale set must not be accepted")
		}
	})

	t.Run("nothing trusted verifies nothing", func(t *testing.T) {
		if _, err := VerifyKeysResponse(signed(), nil, now); err == nil {
			t.Fatal("with no trusted key there is nothing to verify against")
		}
	})

	t.Run("unsigned legacy response is refused", func(t *testing.T) {
		resp := &KeysResponse{PublicKeys: [][]byte{oldPub}}
		if _, err := VerifyKeysResponse(resp, []ed25519.PublicKey{oldPub}, now); err == nil {
			t.Fatal("a response without signatures must not be accepted")
		}
	})

	t.Run("malformed public key length is refused", func(t *testing.T) {
		resp := signed()
		resp.PublicKeys = append(resp.PublicKeys, []byte("short"))
		resp.Signatures = append(resp.Signatures, make([]byte, ed25519.SignatureSize))
		if _, err := VerifyKeysResponse(resp, []ed25519.PublicKey{oldPub}, now); err == nil {
			t.Fatal("a response with a malformed key length must not be accepted")
		}
	})
}
