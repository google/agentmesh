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

package router

import "testing"

// TestIsLoopbackBindHost locks down the host classification that decides, in
// Options.Validate, whether a cleartext ingress bind is allowed without TLS or
// an explicit --allow-insecure-ingress-http opt-in. The security-critical rule
// is that only genuinely loopback hosts qualify: an empty host or an all-
// interfaces wildcard ("0.0.0.0", "::") must NOT be treated as loopback, since
// that is a bind reachable from off-box and so must still demand TLS.
func TestIsLoopbackBindHost(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		// localhost is matched by name, case-insensitively.
		{name: "localhost lowercase", host: "localhost", want: true},
		{name: "localhost uppercase", host: "LOCALHOST", want: true},
		{name: "localhost mixed case", host: "LocalHost", want: true},

		// Surrounding whitespace is trimmed before classification.
		{name: "localhost with surrounding spaces", host: "  localhost  ", want: true},
		{name: "ipv4 loopback with surrounding spaces", host: " 127.0.0.1 ", want: true},

		// The whole 127.0.0.0/8 block is loopback, not just 127.0.0.1.
		{name: "ipv4 loopback canonical", host: "127.0.0.1", want: true},
		{name: "ipv4 loopback non-canonical in 127/8", host: "127.0.0.2", want: true},
		{name: "ipv4 loopback high in 127/8", host: "127.255.255.254", want: true},

		// IPv6 loopback.
		{name: "ipv6 loopback", host: "::1", want: true},

		// All-interfaces wildcards are reachable off-box: never loopback.
		{name: "empty host (bind all interfaces)", host: "", want: false},
		{name: "ipv4 wildcard", host: "0.0.0.0", want: false},
		{name: "ipv6 wildcard", host: "::", want: false},

		// Ordinary routable addresses.
		{name: "private ipv4", host: "192.168.1.1", want: false},
		{name: "public ipv4", host: "8.8.8.8", want: false},
		{name: "public ipv6", host: "2001:4860:4860::8888", want: false},

		// Hostnames other than "localhost" are not resolved; only the literal
		// name and parsed IP literals count, so a would-be loopback alias is
		// treated as non-loopback.
		{name: "localhost subdomain is not localhost", host: "localhost.localdomain", want: false},
		{name: "arbitrary hostname", host: "example.com", want: false},

		// Inputs that are not a bare host: a host:port string or a bracketed
		// IPv6 literal do not parse as an IP and are not "localhost", so they
		// are rejected rather than leniently accepted.
		{name: "host:port is not a bare host", host: "127.0.0.1:8080", want: false},
		{name: "bracketed ipv6 literal", host: "[::1]", want: false},

		// Not an IP and not localhost.
		{name: "garbage", host: "not-an-ip", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLoopbackBindHost(tc.host); got != tc.want {
				t.Errorf("isLoopbackBindHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}
