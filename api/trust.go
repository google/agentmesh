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
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrInsecureControlPlaneURL marks a plaintext control-plane URL to a host
// that is not loopback. Whoever answers that URL becomes the trust root
// (/keys, enrollment, router addresses), so without TLS that is whoever sits
// on the path.
var ErrInsecureControlPlaneURL = errors.New("plaintext http:// control plane URL to a non-loopback host")

// NormalizeControlPlaneURL canonicalizes a control plane URL: it trims surrounding
// whitespace, prepends https:// if no scheme is present, strips all trailing slashes,
// and returns an empty string when the input is empty.
func NormalizeControlPlaneURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	for strings.HasSuffix(raw, "/") && !strings.HasSuffix(raw, "://") {
		raw = strings.TrimSuffix(raw, "/")
	}
	return raw
}

// ValidateControlPlaneTransport accepts https://, accepts http:// only to a
// loopback host, and otherwise refuses unless allowInsecure is set by the
// operator (the --insecure-control-plane flag) for a network they trust.
func ValidateControlPlaneTransport(rawURL string, allowInsecure bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid control plane URL %q: %w", rawURL, err)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("control plane URL %q has no host", rawURL)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: %q (use https://, or pass --insecure-control-plane to accept plaintext on a network you trust)", ErrInsecureControlPlaneURL, rawURL)
	default:
		return fmt.Errorf("control plane URL %q must use http:// or https://", rawURL)
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// KeysResponseFreshness bounds how far a signed /keys response's timestamp
// may be from the receiver's clock: a captured response must not be able to
// keep a retired key trusted after its grace period.
const KeysResponseFreshness = 5 * time.Minute

// KeysResponsePayload is the bytes each signature in a KeysResponse covers:
// the key set and the signing time, deterministically encoded, signatures
// cleared.
func KeysResponsePayload(resp *KeysResponse) ([]byte, error) {
	unsigned := &KeysResponse{PublicKeys: resp.PublicKeys, SignTime: resp.SignTime}
	return proto.MarshalOptions{Deterministic: true}.Marshal(unsigned)
}

// SignKeysResponse sets SignTime and one signature per key pair, so a
// receiver that trusts any key still valid on the control plane can verify
// the set. Private keys must be in the same order as resp.PublicKeys.
func SignKeysResponse(resp *KeysResponse, privateKeys []ed25519.PrivateKey, now time.Time) error {
	if len(privateKeys) != len(resp.PublicKeys) {
		return fmt.Errorf("keys response has %d public keys but %d signing keys", len(resp.PublicKeys), len(privateKeys))
	}
	resp.SignTime = timestamppb.New(now)
	payload, err := KeysResponsePayload(resp)
	if err != nil {
		return err
	}
	resp.Signatures = make([][]byte, len(privateKeys))
	for i, priv := range privateKeys {
		resp.Signatures[i] = ed25519.Sign(priv, payload)
	}
	return nil
}

// VerifyKeysResponse returns the key set if it is fresh and at least one
// listed key is already trusted and its signature verifies. A receiver with
// nothing trusted yet cannot verify anything and gets an error: enrollment,
// not /keys, is where the first key comes from.
//
// The guarantee is exactly "a key this receiver already trusts vouches for
// this set". It defends against whoever answers the URL; it cannot defend
// against the holder of a trusted private key, who is the trust root by
// definition and could equally mint biscuits or sign events.
func VerifyKeysResponse(resp *KeysResponse, trusted []ed25519.PublicKey, now time.Time) ([]ed25519.PublicKey, error) {
	if len(trusted) == 0 {
		return nil, errors.New("no trusted control plane key to verify /keys against")
	}
	if len(resp.Signatures) != len(resp.PublicKeys) {
		return nil, fmt.Errorf("keys response carries %d signatures for %d keys", len(resp.Signatures), len(resp.PublicKeys))
	}
	if resp.SignTime == nil || !resp.SignTime.IsValid() || resp.SignTime.AsTime().Unix() <= 0 {
		return nil, errors.New("keys response carries missing or invalid sign_time")
	}
	issued := resp.SignTime.AsTime()
	if now.Sub(issued) > KeysResponseFreshness || issued.Sub(now) > KeysResponseFreshness {
		return nil, fmt.Errorf("keys response sign_time %s is outside the freshness window", issued.UTC().Format(time.RFC3339))
	}
	payload, err := KeysResponsePayload(resp)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	verified := false
	for i, kb := range resp.PublicKeys {
		if len(kb) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keys response public_keys[%d] has invalid length %d", i, len(kb))
		}
		pub := ed25519.PublicKey(kb)
		keys = append(keys, pub)
		if verified {
			continue
		}
		for _, t := range trusted {
			if t.Equal(pub) && ed25519.Verify(pub, payload, resp.Signatures[i]) {
				verified = true
				break
			}
		}
	}
	if !verified {
		return nil, errors.New("keys response is not signed by any trusted control plane key")
	}
	return keys, nil
}
