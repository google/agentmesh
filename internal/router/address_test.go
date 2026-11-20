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

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"google.golang.org/protobuf/proto"
)

// newWebTransportHost listens on QUIC and on WebTransport on the same socket,
// as a router does. It returns the host and its "/webtransport/certhash/..."
// suffix.
func newWebTransportHost(t *testing.T) (host.Host, string) {
	t.Helper()
	h := newLoopbackHost(t, libp2p.DisableRelay(), libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"))
	for _, addr := range h.Network().ListenAddresses() {
		if transport := addr[len(addr)-1].Code(); transport != multiaddr.P_QUIC_V1 {
			continue
		}
		if err := h.Network().Listen(multiaddr.StringCast(addr.String() + "/webtransport")); err != nil {
			t.Fatalf("listen on WebTransport: %v", err)
		}
	}
	for _, addr := range h.Network().ListenAddresses() {
		if _, suffix, found := strings.Cut(addr.String(), "/webtransport"); found {
			return h, "/webtransport" + suffix
		}
	}
	t.Fatalf("no WebTransport listen address in %v", h.Network().ListenAddresses())
	return nil, ""
}

// dnsaddrRecords is the DNS a router sees: the TXT records of the mock, "no
// such host" for a name without one as a real resolver answers, an error for
// every lookup while err is set, no answer at all while silent is set, and a
// count of the lookups.
type dnsaddrRecords struct {
	*madns.MockResolver
	err     error
	silent  bool
	lookups int
}

func (d *dnsaddrRecords) LookupTXT(ctx context.Context, name string) ([]string, error) {
	d.lookups++
	if d.silent {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if d.err != nil {
		return nil, d.err
	}
	if len(d.TXT[name]) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return d.MockResolver.LookupTXT(ctx, name)
}

func (d *dnsaddrRecords) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	d.lookups++
	return d.MockResolver.LookupIPAddr(ctx, name)
}

// useDNSAddrRecords makes the records the DNS of this test.
func useDNSAddrRecords(t *testing.T, txt map[string][]string) *dnsaddrRecords {
	t.Helper()
	records := &dnsaddrRecords{MockResolver: &madns.MockResolver{TXT: txt}}
	resolver, err := madns.NewResolver(madns.WithDefaultResolver(records))
	if err != nil {
		t.Fatal(err)
	}
	defaultResolver := madns.DefaultResolver
	madns.DefaultResolver = resolver
	t.Cleanup(func() { madns.DefaultResolver = defaultResolver })
	return records
}

// advertisedAfter are the addresses the router leases after its external
// addresses, as strings.
func advertisedAfter(r *Router) []string {
	var addrs []string
	for _, addr := range r.advertisedAddrs()[len(r.config.ExternalAddrs):] {
		addrs = append(addrs, addr.String())
	}
	return addrs
}

// With --external-addr, the router leases a WebTransport address for each of
// its external QUIC addresses, given or found in a /dnsaddr under its peer ID.
// It needs no peer to report its address, and leases none it cannot derive.
func TestRouterLeasesWebTransportForItsExternalQUICAddrs(t *testing.T) {
	h, webTransport := newWebTransportHost(t)
	other := newLoopbackHost(t, libp2p.DisableRelay())
	useDNSAddrRecords(t, map[string][]string{
		"_dnsaddr.bootstrap.example": {
			"dnsaddr=/ip4/203.0.113.9/tcp/4501/p2p/" + h.ID().String(),
			"dnsaddr=/ip4/203.0.113.9/udp/4501/quic-v1/p2p/" + h.ID().String(),
			"dnsaddr=/ip6/2001:db8::9/udp/4501/quic-v1/p2p/" + h.ID().String(),
			"dnsaddr=/ip4/203.0.113.10/udp/4501/quic-v1/p2p/" + other.ID().String(),
		},
		"_dnsaddr.nested.example": {"dnsaddr=/dnsaddr/bootstrap.example/p2p/" + h.ID().String()},
	})

	for _, tc := range []struct {
		name     string
		host     host.Host
		external []string
		want     []string
	}{
		{name: "QUIC by IP", host: h, external: []string{"/ip4/203.0.113.9/udp/4501/quic-v1"}, want: []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport}},
		{name: "QUIC by private IP", host: h, external: []string{"/ip4/10.89.0.3/udp/4501/quic-v1"}, want: []string{"/ip4/10.89.0.3/udp/4501/quic-v1" + webTransport}},
		{name: "QUIC by name", host: h, external: []string{"/dns4/router.example/udp/4501/quic-v1"}, want: []string{"/dns4/router.example/udp/4501/quic-v1" + webTransport}},
		{name: "own entry in a dnsaddr", host: h, external: []string{"/dnsaddr/bootstrap.example"}, want: []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport}},
		{name: "same address given and in a dnsaddr", host: h, external: []string{"/dnsaddr/bootstrap.example", "/ip4/203.0.113.9/udp/4501/quic-v1"}, want: []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport}},
		{name: "dnsaddr without a record", host: h, external: []string{"/dnsaddr/unpublished.example"}},
		{name: "dnsaddr record that names another dnsaddr", host: h, external: []string{"/dnsaddr/nested.example"}},
		{name: "TCP only", host: h, external: []string{"/ip4/203.0.113.9/tcp/4501"}},
		{name: "IPv6 address, IPv4 listener", host: h, external: []string{"/ip6/2001:db8::9/udp/4501/quic-v1"}},
		{name: "no WebTransport listener", host: other, external: []string{"/dnsaddr/bootstrap.example", "/ip4/203.0.113.9/udp/4501/quic-v1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Router{Host: tc.host, config: Options{ExternalAddrs: tc.external}}
			r.resolveExternalAddrs(context.Background())
			if got := advertisedAfter(r); !slices.Equal(got, tc.want) {
				t.Errorf("WebTransport addresses for %v: got %v, want %v", tc.external, got, tc.want)
			}
		})
	}
}

// A DNS outage does not withdraw the WebTransport address from the lease: the
// router keeps the addresses of its last successful lookup.
func TestRouterKeepsItsWebTransportAddrWhenTheLookupFails(t *testing.T) {
	h, webTransport := newWebTransportHost(t)
	records := useDNSAddrRecords(t, map[string][]string{
		"_dnsaddr.bootstrap.example": {"dnsaddr=/ip4/203.0.113.9/udp/4501/quic-v1/p2p/" + h.ID().String()},
	})
	r := &Router{Host: h, config: Options{ExternalAddrs: []string{"/dnsaddr/bootstrap.example"}}}
	want := []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport}

	r.resolveExternalAddrs(context.Background())
	if got := advertisedAfter(r); !slices.Equal(got, want) {
		t.Fatalf("WebTransport addresses after the first lookup: got %v, want %v", got, want)
	}

	records.err = errors.New("no DNS server answered")
	for failures := int32(1); failures <= 2; failures++ {
		r.resolveExternalAddrs(context.Background())
		if got := r.externalAddrLookupFailures.Load(); got != failures {
			t.Fatalf("failed lookups in a row: got %d, want %d", got, failures)
		}
		if got := advertisedAfter(r); !slices.Equal(got, want) {
			t.Fatalf("WebTransport addresses after %d failed lookup(s): got %v, want %v", failures, got, want)
		}
	}

	// A router that stops in the middle of a lookup has no DNS failure.
	stopping, stop := context.WithCancel(context.Background())
	stop()
	r.resolveExternalAddrs(stopping)
	if got := r.externalAddrLookupFailures.Load(); got != 2 {
		t.Fatalf("failed lookups after a canceled one: got %d, want 2", got)
	}

	records.err = nil
	records.TXT["_dnsaddr.bootstrap.example"] = []string{"dnsaddr=/ip4/203.0.113.77/udp/4501/quic-v1/p2p/" + h.ID().String()}
	r.resolveExternalAddrs(context.Background())
	if got := r.externalAddrLookupFailures.Load(); got != 0 {
		t.Errorf("failed lookups after DNS answered: got %d, want 0", got)
	}
	want = []string{"/ip4/203.0.113.77/udp/4501/quic-v1" + webTransport}
	if got := advertisedAfter(r); !slices.Equal(got, want) {
		t.Errorf("WebTransport addresses after DNS answered: got %v, want %v", got, want)
	}
}

// A DNS server that does not answer holds a lease back for the lookup limit
// and no longer, and the router keeps the addresses of its last lookup.
func TestRouterGivesUpALookupAfterItsLimit(t *testing.T) {
	h, webTransport := newWebTransportHost(t)
	records := useDNSAddrRecords(t, map[string][]string{
		"_dnsaddr.bootstrap.example": {"dnsaddr=/ip4/203.0.113.9/udp/4501/quic-v1/p2p/" + h.ID().String()},
	})
	r := &Router{Host: h, config: Options{ExternalAddrs: []string{"/dnsaddr/bootstrap.example"}}}
	want := []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport}
	r.resolveExternalAddrs(context.Background())
	if got := advertisedAfter(r); !slices.Equal(got, want) {
		t.Fatalf("WebTransport addresses after the first lookup: got %v, want %v", got, want)
	}

	records.silent = true
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		r.resolveExternalAddrs(context.Background())
		if got := time.Since(start); got != externalAddrLookupTimeout {
			t.Errorf("a lookup with no answer took %s, want %s", got, externalAddrLookupTimeout)
		}
	})
	if got := advertisedAfter(r); !slices.Equal(got, want) {
		t.Errorf("WebTransport addresses after a lookup with no answer: got %v, want %v", got, want)
	}
}

// The lease follows the router's /dnsaddr record: a new address replaces the
// old one at the next lookup, and a removed record withdraws it.
func TestRouterWebTransportAddrFollowsItsDNSAddrRecord(t *testing.T) {
	h, webTransport := newWebTransportHost(t)
	records := useDNSAddrRecords(t, map[string][]string{
		"_dnsaddr.bootstrap.example": {"dnsaddr=/ip4/203.0.113.9/udp/4501/quic-v1/p2p/" + h.ID().String()},
	})
	r := &Router{Host: h, config: Options{ExternalAddrs: []string{"/dnsaddr/bootstrap.example"}}}

	for _, step := range []struct {
		name   string
		record []string
		want   []string
	}{
		{name: "first record", record: records.TXT["_dnsaddr.bootstrap.example"], want: []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport}},
		{name: "the router moved", record: []string{"dnsaddr=/ip4/203.0.113.77/udp/4501/quic-v1/p2p/" + h.ID().String()}, want: []string{"/ip4/203.0.113.77/udp/4501/quic-v1" + webTransport}},
		{name: "record removed", record: nil},
	} {
		records.TXT["_dnsaddr.bootstrap.example"] = step.record
		r.resolveExternalAddrs(context.Background())
		if got := advertisedAfter(r); !slices.Equal(got, step.want) {
			t.Fatalf("%s: WebTransport addresses: got %v, want %v", step.name, got, step.want)
		}
	}
}

// The router looks its /dnsaddr up only for a WebTransport address: one that
// does not listen on WebTransport, or has no /dnsaddr, makes no DNS lookup.
func TestRouterLooksUpOnlyADNSAddrItNeeds(t *testing.T) {
	h, _ := newWebTransportHost(t)
	other := newLoopbackHost(t, libp2p.DisableRelay())
	records := useDNSAddrRecords(t, nil)

	for _, tc := range []struct {
		name     string
		host     host.Host
		external []string
		want     int
	}{
		{name: "no WebTransport listener", host: other, external: []string{"/dnsaddr/bootstrap.example"}, want: 0},
		{name: "no external address", host: h, want: 0},
		{name: "external addresses by IP and by name", host: h, external: []string{"/ip4/203.0.113.9/udp/4501/quic-v1", "/dns4/router.example/udp/4501/quic-v1"}, want: 0},
		{name: "a dnsaddr and a WebTransport listener", host: h, external: []string{"/dnsaddr/bootstrap.example"}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records.lookups = 0
			r := &Router{Host: tc.host, config: Options{ExternalAddrs: tc.external}}
			r.resolveExternalAddrs(context.Background())
			if records.lookups != tc.want {
				t.Errorf("DNS lookups for %v: got %d, want %d", tc.external, records.lookups, tc.want)
			}
		})
	}
}

// Without --external-addr the router leases its host addresses, and those
// include its WebTransport listen address.
func TestRouterWithoutExternalAddrsLeasesItsListenAddrs(t *testing.T) {
	h, webTransport := newWebTransportHost(t)
	r := &Router{Host: h}
	var got, want []string
	for _, addr := range r.advertisedAddrs() {
		got = append(got, addr.String())
	}
	for _, addr := range h.Addrs() {
		want = append(want, addr.String())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("advertisedAddrs: got %v, want the host addresses %v", got, want)
	}
	if !slices.ContainsFunc(got, func(addr string) bool { return strings.HasSuffix(addr, webTransport) }) {
		t.Errorf("advertisedAddrs: got %v, want one that ends in %s", got, webTransport)
	}
}

// An empty address is skipped, among the external addresses and among the
// listen addresses, instead of stopping the router.
func TestWebTransportAddrsSkipAnEmptyAddr(t *testing.T) {
	h, webTransport := newWebTransportHost(t)
	external := []multiaddr.Multiaddr{nil, multiaddr.StringCast("/ip4/203.0.113.9/udp/4501/quic-v1")}
	listen := append([]multiaddr.Multiaddr{nil}, h.Network().ListenAddresses()...)
	var got []string
	for _, ma := range webTransportAddrs(external, listen) {
		got = append(got, ma.String())
	}
	if want := []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport}; !slices.Equal(got, want) {
		t.Errorf("webTransportAddrs with an empty address: got %v, want %v", got, want)
	}
	r := &Router{Host: h}
	// No result to compare: the call must not panic.
	r.warnAddrsWithoutWebTransport(external)
}

// A WebTransport address is an external QUIC address plus the certhashes of
// the router's WebTransport listener, for the IP versions it listens on.
func TestWebTransportAddrsFollowTheListeners(t *testing.T) {
	const webTransport = "/webtransport/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g/certhash/uEiAAq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g"
	listen := []string{"/ip4/0.0.0.0/tcp/4501", "/ip4/0.0.0.0/udp/4501/quic-v1", "/ip4/0.0.0.0/udp/4501/quic-v1" + webTransport}
	byVersion := []string{"/ip4/203.0.113.9/udp/4501/quic-v1", "/ip6/2001:db8::9/udp/4501/quic-v1", "/dns4/router.example/udp/4501/quic-v1", "/dns6/router.example/udp/4501/quic-v1", "/dns/router.example/udp/4501/quic-v1"}
	for _, tc := range []struct {
		name     string
		listen   []string
		external []string
		want     []string
	}{
		{
			name:     "QUIC by IP, not TCP",
			listen:   listen,
			external: []string{"/ip4/203.0.113.9/tcp/4501", "/ip4/203.0.113.9/udp/4501/quic-v1"},
			want:     []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport},
		},
		{
			name:     "IPv4 listener: IPv4 addresses and names",
			listen:   listen,
			external: byVersion,
			want:     []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport, "/dns4/router.example/udp/4501/quic-v1" + webTransport, "/dns/router.example/udp/4501/quic-v1" + webTransport},
		},
		{
			name:     "IPv6 listener: IPv6 addresses and names",
			listen:   []string{"/ip4/0.0.0.0/udp/4501/quic-v1", "/ip6/::/udp/4501/quic-v1", "/ip6/::/udp/4501/quic-v1" + webTransport},
			external: byVersion,
			want:     []string{"/ip6/2001:db8::9/udp/4501/quic-v1" + webTransport, "/dns6/router.example/udp/4501/quic-v1" + webTransport, "/dns/router.example/udp/4501/quic-v1" + webTransport},
		},
		{
			name:     "listeners on both IP versions: every address",
			listen:   append(slices.Clone(listen), "/ip6/::/udp/4501/quic-v1", "/ip6/::/udp/4501/quic-v1"+webTransport),
			external: byVersion,
			want: []string{
				"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport,
				"/ip6/2001:db8::9/udp/4501/quic-v1" + webTransport,
				"/dns4/router.example/udp/4501/quic-v1" + webTransport,
				"/dns6/router.example/udp/4501/quic-v1" + webTransport,
				"/dns/router.example/udp/4501/quic-v1" + webTransport,
			},
		},
		{
			name:     "the same external address twice",
			listen:   listen,
			external: []string{"/ip4/203.0.113.9/udp/4501/quic-v1", "/ip4/203.0.113.9/udp/4501/quic-v1"},
			want:     []string{"/ip4/203.0.113.9/udp/4501/quic-v1" + webTransport},
		},
		{
			name:     "no WebTransport listener",
			listen:   []string{"/ip4/0.0.0.0/tcp/4501", "/ip4/0.0.0.0/udp/4501/quic-v1"},
			external: []string{"/ip4/203.0.113.9/udp/4501/quic-v1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, addr := range webTransportAddrs(parseAddrs(t, tc.external), parseAddrs(t, tc.listen)) {
				got = append(got, addr.String())
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("webTransportAddrs(%v) with listeners %v: got %v, want %v", tc.external, tc.listen, got, tc.want)
			}
		})
	}
}

// A lease renewal looks the /dnsaddr up and sends the WebTransport address to
// the control plane, and a peer that dials that address reaches the router.
func TestRouterRenewLeaseSendsADialableWebTransportAddr(t *testing.T) {
	var mu sync.Mutex
	var leased []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var lease api.RouterLeaseRequest
		if err := proto.Unmarshal(body, &lease); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		leased = lease.Addresses
		mu.Unlock()
		out, err := proto.Marshal(&api.RouterLeaseResponse{Success: true})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(out)
	}))
	t.Cleanup(ts.Close)

	h, webTransport := newWebTransportHost(t)
	var quic string
	for _, addr := range h.Network().ListenAddresses() {
		if transport := addr[len(addr)-1].Code(); transport == multiaddr.P_QUIC_V1 {
			quic = addr.String()
		}
	}
	useDNSAddrRecords(t, map[string][]string{"_dnsaddr.bootstrap.example": {"dnsaddr=" + quic + "/p2p/" + h.ID().String()}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := &Router{
		Host:       h,
		ctx:        ctx,
		cancel:     cancel,
		privKey:    h.Peerstore().PrivKey(h.ID()),
		credential: credential{biscuit: []byte("dummy-biscuit")},
		config:     Options{ControlPlaneURL: ts.URL, HighWaterMark: 4000, ExternalAddrs: []string{"/dnsaddr/bootstrap.example"}},
	}

	r.renewLease()

	mu.Lock()
	got := slices.Clone(leased)
	mu.Unlock()
	want := []string{"/dnsaddr/bootstrap.example/p2p/" + h.ID().String(), quic + webTransport + "/p2p/" + h.ID().String()}
	if !slices.Equal(got, want) {
		t.Fatalf("leased addresses: got %v, want %v", got, want)
	}

	dialer, err := libp2p.New(libp2p.NoListenAddrs, libp2p.DisableRelay())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	info, err := peer.AddrInfoFromString(got[1])
	if err != nil {
		t.Fatalf("parse the leased address %s: %v", got[1], err)
	}
	if err := dialer.Connect(ctx, *info); err != nil {
		t.Fatalf("dial the leased address %s: %v", got[1], err)
	}
}

func parseAddrs(t *testing.T, addrs []string) []multiaddr.Multiaddr {
	t.Helper()
	parsed := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, s := range addrs {
		addr, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		parsed = append(parsed, addr)
	}
	return parsed
}
