# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The libp2p host a member joins the mesh with, configured the way agentmesh-node's
is (internal/node/node.go): TLS for the security protocol, which every peer
offers first, Noise accepted beside it, and yamux the muxer. py-libp2p is
trio-based, so everything here is trio async."""

from __future__ import annotations

import os
import ssl
from datetime import datetime, timedelta, timezone
from typing import Sequence

import multiaddr
import trio
from cryptography import x509
from cryptography.x509.oid import NameOID
from libp2p import new_host
from libp2p.abc import IHost, INetStream
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.crypto.x25519 import create_new_key_pair as create_new_x25519_key_pair
from libp2p.custom_types import TProtocol
from libp2p.network.config import ConnectionConfig
from libp2p.network.swarm import Swarm
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo, info_from_p2p_addr
from libp2p.security.noise.transport import PROTOCOL_ID as NOISE_PROTOCOL_ID
from libp2p.security.noise.transport import Transport as NoiseTransport
from libp2p.security.tls.transport import PROTOCOL_ID as TLS_PROTOCOL_ID
from libp2p.security.tls.transport import IdentityConfig, TLSTransport
from libp2p.stream_muxer.yamux.yamux import PROTOCOL_ID as YAMUX_PROTOCOL_ID
from libp2p.stream_muxer.yamux.yamux import Yamux
from libp2p.transport.websocket.transport import WebsocketTransport
from multiaddr.resolvers import DNSResolver

from .identity import Identity


def _certificate_template() -> x509.CertificateBuilder:
    """The libp2p TLS certificate with nothing but the libp2p extension.
    py-libp2p's default template also adds BasicConstraints and KeyUsage,
    which the spec allows, but js-libp2p (@libp2p/tls) reads the libp2p
    extension from `extensions[0]` and refuses the certificate otherwise."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "libp2p")])
    not_before = datetime.now(timezone.utc) - timedelta(hours=1)
    return (
        x509.CertificateBuilder()
        .serial_number(int.from_bytes(os.urandom(8), "big"))
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=365 * 100))
        .subject_name(name)
        .issuer_name(name)
    )


def create_mesh_host(identity: Identity, listen_addrs: Sequence[str] = ()) -> tuple[IHost, list[multiaddr.Multiaddr]]:
    """Builds the host for `identity`. Run it with `async with host.run(addrs)`.
    listen_addrs are for direct connections, e.g. "/ip4/0.0.0.0/tcp/0" or
    "/ip4/0.0.0.0/tcp/0/ws"; an agent is normally reached through a router's
    relay instead. The host dials TCP and WebSocket: the testnets' routers
    listen on TCP, agentmesh-one's single port is a WebSocket listener."""
    key_pair = create_new_key_pair(identity.seed)
    # No ALPN muxer list: py-libp2p's TLS transport advertises early muxer
    # negotiation but cannot complete it (Python's ssl has no ALPN select
    # callback), and go-libp2p then refuses the mux upgrade. Without it the
    # muxer is negotiated with multistream-select as before.
    tls = TLSTransport(key_pair, identity_config=IdentityConfig(cert_template=_certificate_template()))
    # TLS first, as every Go peer and the JS SDK offer it; Noise accepted, so
    # a member in a browser, which speaks Noise alone, is reached end to end
    # through a relay. Both bind the connection to the peer ID.
    noise = NoiseTransport(key_pair, noise_privkey=create_new_x25519_key_pair().private_key)
    host = new_host(
        key_pair=key_pair,
        sec_opt={TLS_PROTOCOL_ID: tls, NOISE_PROTOCOL_ID: noise},
        muxer_opt={TProtocol(YAMUX_PROTOCOL_ID): Yamux},
        enable_websocket=True,
        # py-libp2p dials wss with certificate verification off unless given
        # a context (libp2p/py-libp2p#1550); the system roots, as go-libp2p
        # and js-libp2p use.
        tls_client_config=ssl.create_default_context(),
        # A member connects to its routers and to the peers it calls or that
        # call it. py-libp2p's AutoConnector would otherwise dial every peer
        # in the peerstore every 30s while under 100 connections, including
        # addresses this host has no transport for and relay addresses it
        # dials as if direct.
        connection_config=ConnectionConfig(min_connections=0, low_watermark=0),
    )
    for transport in host.get_network().transport_manager.get_transports():  # type: ignore[attr-defined]
        if isinstance(transport, WebsocketTransport):
            _dial_websockets_by_name(transport)
    if str(host.get_id()) != identity.peer_id:
        raise RuntimeError(f"libp2p derived peer {host.get_id()} for identity {identity.peer_id}")
    return host, [multiaddr.Multiaddr(a) for a in listen_addrs]


def _dial_websockets_by_name(transport: WebsocketTransport) -> None:
    """py-libp2p resolves a `/dns4/<host>/tcp/443/wss` address to its IP
    before dialing and then names the IP in the TLS SNI and the Host header,
    which a TLS-terminating edge (agentmesh-one behind a tunnel) answers with 403.
    The transport's own dial of an unresolved address keeps the name; the
    dial here goes straight to it, as go-libp2p and js-libp2p do. Fixed
    upstream by libp2p/py-libp2p#1549, not in 0.8; drop this with the
    release that has it."""
    # Bound here so a py-libp2p that renamed it fails at host construction.
    dial_resolved = transport._dial_resolved  # noqa: SLF001

    async def dial(maddr: multiaddr.Multiaddr):  # noqa: ANN202 - py-libp2p's RawConnection
        return await dial_resolved(maddr)

    transport.dial = dial  # type: ignore[method-assign]


# agentmesh-node's swarm dial timeout. py-libp2p has none of its own: a SYN to an
# address nobody answers waits on the kernel, about two minutes, and is then
# retried, and a provider record can name a pod a rollout just replaced. A
# router the control plane lists may be unreachable from where a member runs
# (a public address a network policy drops), and the routers' DHT names it as
# a closer peer to every lookup.
DIAL_TIMEOUT = 15.0

# How long open_stream waits for the close of a connection it gave up on.
HANGUP_GRACE = 1.0


async def dial(host: IHost, info: PeerInfo) -> None:
    """host.connect at the addresses given, bounded by DIAL_TIMEOUT. What the
    host remembers of the peer is dropped first. py-libp2p dials one address
    per transport, the first its peerstore holds, and host.connect only
    appends to that list: a router or provider that came back on another
    address, a pod rescheduled with the same key, would be dialed at the old
    one on every retry, whatever the caller had just resolved. The swarm's
    negative cache is keyed by peer, not by address, and would refuse the new
    address for a minute after the old one failed, so the peer is taken out
    of it as well."""
    host.get_peerstore().clear_addrs(info.peer_id)
    network = host.get_network()
    if isinstance(network, Swarm):
        network.unblock_peer(info.peer_id)
    try:
        with trio.fail_after(DIAL_TIMEOUT):
            await host.connect(info)
    except trio.TooSlowError:
        raise ConnectionError(f"no connection to {info.peer_id} within {DIAL_TIMEOUT:g}s") from None


async def open_stream(host: IHost, peer_id: ID, protocol: TProtocol, timeout: float) -> INetStream:
    """host.new_stream bounded by a timeout. py-libp2p bounds the protocol
    negotiation but not the muxer, and a muxer that cannot open a stream
    would otherwise park the caller forever without a word. A connection
    that stalled so is hung up on: the muxer keeps the backlog slot of a SYN
    it never sent past a cancelled write, and a connection the peer does not
    answer on is no path to it; the next call dials afresh."""
    try:
        with trio.fail_after(timeout):
            return await host.new_stream(peer_id, [protocol])
    except trio.TooSlowError:
        # Closing writes a GO_AWAY on the very connection that stalled; give
        # it a moment, then let the peer time the socket out on its own.
        with trio.CancelScope(shield=True), trio.move_on_after(min(timeout, HANGUP_GRACE)):
            try:
                await host.disconnect(peer_id)
            except Exception:  # noqa: BLE001 - already gone
                pass
        raise ConnectionError(f"no {protocol} stream to {peer_id} within {timeout:g}s") from None


_DNS_PROTOCOLS = frozenset({"dnsaddr", "dns", "dns4", "dns6"})
# The host dials TCP and WebSocket; a resolved address on another transport is noise.
_UNDIALABLE_PROTOCOLS = frozenset({"quic", "quic-v1", "webtransport", "webrtc", "webrtc-direct"})
_WEBSOCKET_PROTOCOLS = frozenset({"ws", "wss"})
_DNS_TIMEOUT = 10.0


async def dial_addrs(addr: multiaddr.Multiaddr) -> list[multiaddr.Multiaddr]:
    """The concrete addresses this host can dial for addr. A control plane
    hands out router addresses as `/dnsaddr/<host>/p2p/<id>`, resolved here
    through the host's `_dnsaddr` TXT records (and `/dns4`, `/dns6`, `/dns`
    through A and AAAA records) the way go-libp2p and js-libp2p do before
    dialing. py-libp2p has no transport for a `/dnsaddr` address; its TCP
    transport resolves `/dns4`, `/dns6` and `/dns` itself, and they are
    resolved here too, so the peerstore holds the concrete addresses. A
    WebSocket address keeps its DNS name: the name is the TLS server name
    and the Host header, which a TLS-terminating edge in front of the router
    (agentmesh-one behind a tunnel) selects the origin by.
    Addresses on transports this host lacks are left out."""
    protocols = [p.name for p in addr.protocols()]
    first = protocols[0] if protocols else ""
    if first == "dnsaddr" or (first in _DNS_PROTOCOLS and not set(protocols) & _WEBSOCKET_PROTOCOLS):
        resolved: list[multiaddr.Multiaddr] = []
        with trio.move_on_after(_DNS_TIMEOUT):
            resolved = list(await DNSResolver().resolve(addr))
        if not resolved:
            raise RuntimeError(f"{addr} resolved to no address")
    else:
        resolved = [addr]
    dialable: list[multiaddr.Multiaddr] = []
    for m in resolved:
        names = {p.name for p in m.protocols()}
        if "tcp" in names and not names & _UNDIALABLE_PROTOCOLS:
            dialable.append(m)
    if not dialable:
        raise RuntimeError(f"{addr} offers no TCP or WebSocket address; this host dials those only")
    return dialable


async def peer_info(addr: multiaddr.Multiaddr) -> PeerInfo:
    """The peer an address names and the concrete addresses to reach it on."""
    addrs = await dial_addrs(addr)
    return PeerInfo(info_from_p2p_addr(addrs[0]).peer_id, addrs)
