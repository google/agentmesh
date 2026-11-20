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
	"net"
	"slices"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
)

// advertisedAddrs are the addresses the router leases to the control plane: the
// --external-addr ones plus their WebTransport addresses, else all host
// addresses. No operator can set a WebTransport address: its certhash changes.
func (r *Router) advertisedAddrs() []multiaddr.Multiaddr {
	if len(r.config.ExternalAddrs) == 0 {
		return r.Host.Addrs()
	}
	addrs := r.externalAddrs()
	external := addrs
	if resolved := r.resolvedExternalAddrs.Load(); resolved != nil {
		external = append(slices.Clone(addrs), *resolved...)
	}
	return append(addrs, webTransportAddrs(external, r.Host.Network().ListenAddresses())...)
}

// externalAddrs are the --external-addr values. Validate refused a malformed
// one at start.
func (r *Router) externalAddrs() []multiaddr.Multiaddr {
	addrs := make([]multiaddr.Multiaddr, 0, len(r.config.ExternalAddrs))
	for _, s := range r.config.ExternalAddrs {
		if ma, err := multiaddr.NewMultiaddr(s); err == nil {
			addrs = append(addrs, ma)
		}
	}
	return addrs
}

// circuitAddrs are advertisedAddrs with /p2p/<router>/p2p-circuit appended:
// where a peer that reserved with this router is reached.
func (r *Router) circuitAddrs() []multiaddr.Multiaddr {
	via := multiaddr.StringCast("/p2p/" + r.Host.ID().String() + "/p2p-circuit")
	advertised := r.advertisedAddrs()
	addrs := make([]multiaddr.Multiaddr, 0, len(advertised))
	for _, a := range advertised {
		addrs = append(addrs, a.Encapsulate(via))
	}
	return addrs
}

// webTransportAddrs are the external QUIC addresses with the router's
// "/webtransport/certhash/..." suffix. An external QUIC address is taken to
// reach the port of the WebTransport listener: nothing here can check that.
func webTransportAddrs(external, listen []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	var addrs []multiaddr.Multiaddr
	for _, addr := range external {
		// No library returns an empty address: the check keeps a bug there from stopping the router.
		if len(addr) == 0 {
			continue
		}
		transport := addr[len(addr)-1].Code()
		if transport != multiaddr.P_QUIC_V1 {
			continue
		}
		// ip4, ip6, dns4, dns6 or dns.
		hostProtocol := addr[0].Code()
		suffix := webTransportSuffix(listen, hostProtocol)
		if suffix == nil {
			continue
		}
		if webTransport := addr.Encapsulate(suffix); !multiaddr.Contains(addrs, webTransport) {
			addrs = append(addrs, webTransport)
		}
	}
	return addrs
}

// webTransportSuffix is the "/webtransport/certhash/..." end of a WebTransport
// listen address on the IP version that an address starting with the host
// protocol reaches, nil without one. All listeners carry the same
// certhashes, since a host has one certificate.
func webTransportSuffix(listen []multiaddr.Multiaddr, hostProtocol int) multiaddr.Multiaddr {
	for _, addr := range listen {
		if len(addr) == 0 {
			continue
		}
		// Cut at /webtransport: the QUIC address before it, and the rest with the certhashes.
		_, suffix := multiaddr.SplitFunc(addr, func(c multiaddr.Component) bool { return c.Code() == multiaddr.P_WEBTRANSPORT })
		ipVersion := addr[0].Code()
		if len(suffix) > 0 && reachesIPVersion(hostProtocol, ipVersion) {
			return suffix
		}
	}
	return nil
}

// reachesIPVersion reports whether an address starting with the host protocol
// reaches a listener on the IP version. A /dns name reaches both.
func reachesIPVersion(hostProtocol, ipVersion int) bool {
	switch hostProtocol {
	case multiaddr.P_IP4, multiaddr.P_DNS4:
		return ipVersion == multiaddr.P_IP4
	case multiaddr.P_IP6, multiaddr.P_DNS6:
		return ipVersion == multiaddr.P_IP6
	}
	return hostProtocol == multiaddr.P_DNS
}

// externalAddrLookupTimeout bounds one /dnsaddr lookup, so a slow DNS server
// cannot hold back the lease.
const externalAddrLookupTimeout = 5 * time.Second

// resolveExternalAddrs finds the router's own addresses in its /dnsaddr
// --external-addr entries, for advertisedAddrs. A failed lookup keeps the
// last result, so a DNS outage does not withdraw a leased address; a record
// that is gone does. A /dnsaddr record that names another /dnsaddr is not
// followed.
func (r *Router) resolveExternalAddrs(ctx context.Context) {
	// P_DNS matches a WebTransport listener on either IP version.
	if len(r.config.ExternalAddrs) == 0 || webTransportSuffix(r.Host.Network().ListenAddresses(), multiaddr.P_DNS) == nil {
		return
	}
	var own []multiaddr.Multiaddr
	lookedUp := false
	for _, ma := range r.externalAddrs() {
		if len(ma) == 0 {
			continue
		}
		if hostProtocol := ma[0].Code(); hostProtocol != multiaddr.P_DNSADDR {
			continue
		}
		lookedUp = true
		lookupCtx, cancel := context.WithTimeout(ctx, externalAddrLookupTimeout)
		resolved, err := madns.DefaultResolver.Resolve(lookupCtx, ma)
		cancel()
		// No record is an answer, not an outage: the entry has no addresses.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			continue
		}
		if ctx.Err() != nil {
			// The router is stopping: not a DNS failure.
			return
		}
		if err != nil {
			// An outage lasts many leases: one warning, then the count at debug.
			if failures := r.externalAddrLookupFailures.Add(1); failures == 1 {
				logger.Warnf("Cannot resolve --external-addr %s, its WebTransport addresses stay as they are: %v", ma, err)
			} else {
				logger.Debugf("Cannot resolve --external-addr %s, %d lookups failed in a row: %v", ma, failures, err)
			}
			return
		}
		for _, addr := range resolved {
			if pi, err := peer.AddrInfoFromP2pAddr(addr); err == nil && pi.ID == r.Host.ID() {
				own = append(own, pi.Addrs...)
			}
		}
	}
	if !lookedUp {
		return
	}
	if failures := r.externalAddrLookupFailures.Swap(0); failures > 0 {
		logger.Infof("--external-addr resolves again after %d failed lookup(s)", failures)
	}
	// A DNS server may rotate its answer: the order is no change.
	slices.SortFunc(own, multiaddr.Multiaddr.Compare)
	last := r.resolvedExternalAddrs.Swap(&own)
	if last == nil || !slices.EqualFunc(*last, own, multiaddr.Multiaddr.Equal) {
		logger.Infof("--external-addr resolves to %d address(es) of this router: %v", len(own), own)
		r.warnAddrsWithoutWebTransport(own)
	}
}

// warnAddrsWithoutWebTransport names the external QUIC addresses that get no
// WebTransport address although the router listens on WebTransport: it does
// not on their IP version.
func (r *Router) warnAddrsWithoutWebTransport(external []multiaddr.Multiaddr) {
	listen := r.Host.Network().ListenAddresses()
	// P_DNS matches a WebTransport listener on either IP version.
	if webTransportSuffix(listen, multiaddr.P_DNS) == nil {
		return
	}
	for _, addr := range external {
		if len(addr) == 0 {
			continue
		}
		transport := addr[len(addr)-1].Code()
		hostProtocol := addr[0].Code()
		if transport == multiaddr.P_QUIC_V1 && webTransportSuffix(listen, hostProtocol) == nil {
			logger.Warnf("No WebTransport address for the external address %s: the router does not listen on WebTransport on its IP version", addr)
		}
	}
}
