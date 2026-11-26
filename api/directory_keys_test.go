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
	"encoding/hex"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// The keys are the sha256 multihash of a fixed name, so a record a member
// announces in any language lands where the others look it up. The vectors
// here are shared with the SDK tests.
func TestDirectoryKeys(t *testing.T) {
	mcp, err := ServiceKey(ServiceType_SERVICE_TYPE_MCP, "")
	if err != nil {
		t.Fatal(err)
	}
	calc, err := ServiceKey(ServiceType_SERVICE_TYPE_MCP, "calculator")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mcp, calc) {
		t.Fatal("a service type and one of its services share a key")
	}
	for name, key := range map[string][]byte{"mcp": mcp, "mcp:calculator": calc} {
		if err := ValidateDirectoryKey(key); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// sha256("mesh:service:mcp:calculator") behind the multihash header.
	const want = "1220" + "e99b7ec759ced5276520910d75b1f6fe3a5baf5fe46655ac34957139e04a0859"
	if got := hex.EncodeToString(calc); got != want {
		t.Fatalf("calculator key = %s, want %s", got, want)
	}

	if _, err := ServiceKey(ServiceType_SERVICE_TYPE_UNSPECIFIED, "x"); err == nil {
		t.Error("an unspecified service type got a key")
	}

	p, err := peer.Decode("12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectoryKey(PeerKey(p)); err != nil {
		t.Error(err)
	}
	if bytes.Equal(PeerKey(p), mcp) {
		t.Error("a peer key collides with a service key")
	}
	for _, bad := range [][]byte{nil, make([]byte, 33), append([]byte{0x11, 0x20}, make([]byte, 32)...)} {
		if err := ValidateDirectoryKey(bad); err == nil {
			t.Errorf("key %x accepted", bad)
		}
	}
}

// DirectoryMaxAddrBytes holds the longest addresses a libp2p host
// announces: a circuit relay address, with both peer IDs, through a router
// that has a DNS name of the maximum length.
func TestDirectoryMaxAddrBytesHoldsRealAddresses(t *testing.T) {
	const (
		router   = "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB"
		member   = "12D3KooWNT6DHUiBT3881d46esEcB6RzCuN9a74pdK8Gx2jXb8ww"
		certhash = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g"
	)
	label := strings.Repeat("a", 63)
	name := strings.Join([]string{label, label, label, label[:61]}, ".")
	if len(name) != 253 {
		t.Fatalf("the DNS name is %d bytes, want 253", len(name))
	}
	relayed := "/p2p/" + router + "/p2p-circuit/p2p/" + member
	for desc, addr := range map[string]string{
		"TLS and WebSocket":                "/dns4/" + name + "/tcp/65535/tls/ws" + relayed,
		"TLS with an SNI and WebSocket":    "/dns4/" + name + "/tcp/65535/tls/sni/" + name + "/ws" + relayed,
		"WebTransport with two certhashes": "/dns6/" + name + "/udp/65535/quic-v1/webtransport/certhash/" + certhash + "/certhash/" + certhash + relayed,
	} {
		t.Run(desc, func(t *testing.T) {
			ma, err := multiaddr.NewMultiaddr(addr)
			if err != nil {
				t.Fatalf("NewMultiaddr(%s): %v", addr, err)
			}
			if got := len(ma.String()); got > DirectoryMaxAddrBytes {
				t.Errorf("the address is %d bytes, want at most DirectoryMaxAddrBytes = %d", got, DirectoryMaxAddrBytes)
			}
		})
	}
}

// A record is the provider's own, under its peer key, or a service's, by
// name or by type, and the key must be that of the service it names.
func TestServiceOfRecord(t *testing.T) {
	provider := peer.ID("12D3KooWprovider")
	stranger := peer.ID("12D3KooWstranger")
	calc, _ := ServiceKey(ServiceType_SERVICE_TYPE_MCP, "calc")
	mcp, _ := ServiceKey(ServiceType_SERVICE_TYPE_MCP, "")
	for name, tc := range map[string]struct {
		key     []byte
		service string
		wantErr bool
		wantTyp ServiceType
	}{
		"own peer key":                  {key: PeerKey(provider), service: ""},
		"service by name":               {key: calc, service: "mcp://calc", wantTyp: ServiceType_SERVICE_TYPE_MCP},
		"service by type":               {key: mcp, service: "mcp://calc", wantTyp: ServiceType_SERVICE_TYPE_MCP},
		"another peer's key":            {key: PeerKey(stranger), service: "", wantErr: true},
		"service key naming no service": {key: calc, service: "", wantErr: true},
		"peer key naming a service":     {key: PeerKey(provider), service: "mcp://calc", wantErr: true},
		"key of another service":        {key: calc, service: "mcp://weather", wantErr: true},
		"key of another type":           {key: calc, service: "inference://calc", wantErr: true},
		"service without a name":        {key: mcp, service: "mcp://", wantErr: true},
		"service with a wildcard name":  {key: mcp, service: "mcp://*", wantErr: true},
		"service of an unknown type":    {key: calc, service: "ftp://calc", wantErr: true},
		"service that is not a target":  {key: calc, service: "calc", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			typ, svcName, err := ServiceOfRecord(provider, tc.key, tc.service)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ServiceOfRecord(%q) err = %v, wantErr %v", tc.service, err, tc.wantErr)
			}
			if err == nil && tc.service != "" && (typ != tc.wantTyp || svcName != "calc") {
				t.Fatalf("ServiceOfRecord(%q) = %v, %q; want %v, calc", tc.service, typ, svcName, tc.wantTyp)
			}
		})
	}
}
