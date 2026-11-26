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
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// DirectoryProtocolID is the libp2p protocol on which a member asks a
// router it is attached to for the directory: one DirectoryRequest per
// stream, one DirectoryResponse back. Routers place records on each other
// over it as well.
const DirectoryProtocolID protocol.ID = "/mesh/directory/1.0.0"

// DirectoryKeyBytes is the length of a directory key: a sha256 multihash.
const DirectoryKeyBytes = 34

// DirectoryMaxAddrs bounds the addresses one record carries.
const DirectoryMaxAddrs = 32

// DirectoryMaxAddrBytes bounds the text of one address in a record. The
// count includes the "/p2p/<provider>" suffix that the address has in an
// answer. The longest address a libp2p host announces is a circuit relay
// address through a router that has a DNS name of 253 bytes. With both peer
// IDs it is 530 bytes over WebTransport, which has two certhashes, and 660
// bytes over TLS when the address repeats the name as its SNI. 1024 is one
// and a half times the longest. DirectoryMaxAddrs addresses of this length
// are 32 KiB, half of the 64 KiB frame of the directory protocol.
const DirectoryMaxAddrBytes = 1024

// directoryKey is the sha256 multihash of a name: the two-byte multihash
// header (sha2-256, 32 bytes) and the digest. go-libp2p-kad-dht keys
// provider records by this multihash, so a record a member announces here
// is the record a router's DHT holds.
func directoryKey(name string) []byte {
	sum := sha256.Sum256([]byte(name))
	return append([]byte{0x12, 0x20}, sum[:]...)
}

// ServiceKey is the directory key of a service type, or of one named
// service of that type: "mesh:service:<type>" or "mesh:service:<type>:<name>".
func ServiceKey(t ServiceType, name string) ([]byte, error) {
	typeStr, err := ServiceTypeToString(t)
	if err != nil {
		return nil, err
	}
	parts := []string{"mesh:service", typeStr}
	if name != "" {
		parts = append(parts, name)
	}
	return directoryKey(strings.Join(parts, ":")), nil
}

// PeerKey is the directory key under which a member announces where it is
// reached: "mesh:peer:<peer_id>". A find_peer is a lookup of this key.
func PeerKey(p peer.ID) []byte {
	return directoryKey("mesh:peer:" + p.String())
}

// ValidateDirectoryKey rejects anything but a sha256 multihash.
func ValidateDirectoryKey(key []byte) error {
	if len(key) != DirectoryKeyBytes || key[0] != 0x12 || key[1] != 0x20 {
		return fmt.Errorf("directory key must be a sha256 multihash of %d bytes, got %d", DirectoryKeyBytes, len(key))
	}
	return nil
}

// ServiceOfRecord parses the service a record names, "<type>://<name>",
// and reports whether key is one of that service's: by name or by type.
// A record that names no service is the provider's own, under PeerKey.
// This is what a router checks before it keeps a member's record, so that
// a member announces itself, and the services it names, and nothing else.
func ServiceOfRecord(provider peer.ID, key []byte, service string) (ServiceType, string, error) {
	if service == "" {
		if !bytes.Equal(key, PeerKey(provider)) {
			return ServiceType_SERVICE_TYPE_UNSPECIFIED, "", fmt.Errorf("a record naming no service is the provider's own, under its peer key")
		}
		return ServiceType_SERVICE_TYPE_UNSPECIFIED, "", nil
	}
	typeStr, name := ParseServiceTarget(service)
	t, err := ParseServiceType(typeStr)
	if err != nil || t == ServiceType_SERVICE_TYPE_UNSPECIFIED || name == "" || name == "*" {
		return ServiceType_SERVICE_TYPE_UNSPECIFIED, "", fmt.Errorf("service %q must be <type>://<name>", service)
	}
	for _, n := range []string{name, ""} {
		k, err := ServiceKey(t, n)
		if err != nil {
			return ServiceType_SERVICE_TYPE_UNSPECIFIED, "", err
		}
		if bytes.Equal(key, k) {
			return t, name, nil
		}
	}
	return ServiceType_SERVICE_TYPE_UNSPECIFIED, "", fmt.Errorf("key is not %s's, by name or by type", service)
}
