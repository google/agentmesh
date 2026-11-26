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

"""Circuit relay v2 as a client of a router: reserve a slot, dial a peer
through the router, accept a peer the router relays to us. Messages are
varint-length-prefixed protobufs (go-libp2p's pbio framing). The module
speaks the protocol directly rather than through py-libp2p's relay client:
a router grants a reservation only after the auth handshake on the same
connection, and the session owns when to reserve, renew and, after a
dropped connection, authenticate and reserve again."""

from __future__ import annotations

import logging
import time
from typing import Callable

import multiaddr
import trio
from libp2p.abc import IHost, INetConn, INetStream
from libp2p.connection_types import ConnectionType
from libp2p.custom_types import TProtocol
from libp2p.network.connection.raw_connection import RawConnection
from libp2p.peer.id import ID
from libp2p.utils.varint import encode_varint_prefixed

from ._proto import circuit_pb2 as circuit
from .auth import read_bounded_varint_prefixed_bytes
from .host import DIAL_TIMEOUT, HANGUP_GRACE, open_stream
from .identity import canonical_peer_id

logger = logging.getLogger("agent_mesh")

HOP_PROTOCOL = TProtocol("/libp2p/circuit/relay/0.2.0/hop")
STOP_PROTOCOL = TProtocol("/libp2p/circuit/relay/0.2.0/stop")

RELAY_MESSAGE_TIMEOUT = 10.0
MAX_RELAY_MESSAGE_BYTES = 64 * 1024


def split_circuit_address(addr: multiaddr.Multiaddr) -> tuple[multiaddr.Multiaddr, ID]:
    """Splits `<relay>/p2p-circuit/p2p/<target>` into the relay address and the target."""
    text = str(addr)
    relay_text, _, tail = text.partition("/p2p-circuit")
    if not _ or not relay_text:
        raise ValueError(f"{addr} is not a /p2p-circuit address")
    target = tail.removeprefix("/p2p/")
    if not target:
        raise ValueError(f"{addr} names no target peer after /p2p-circuit")
    return multiaddr.Multiaddr(relay_text), ID.from_base58(canonical_peer_id(target))


async def reserve_relay(host: IHost, relay_peer_id: ID) -> circuit.Reservation:
    """Asks a connected relay for a reservation and returns it. A router grants
    one only to a peer that passed the auth handshake, so success is also proof
    of admission."""
    stream = await open_stream(host, relay_peer_id, HOP_PROTOCOL, RELAY_MESSAGE_TIMEOUT)
    try:
        with trio.fail_after(RELAY_MESSAGE_TIMEOUT):
            req = circuit.HopMessage(type=circuit.HopMessage.RESERVE)
            await stream.write(encode_varint_prefixed(req.SerializeToString()))
            resp = circuit.HopMessage.FromString(await read_bounded_varint_prefixed_bytes(stream, MAX_RELAY_MESSAGE_BYTES))
    finally:
        await stream.close()
    if resp.type != circuit.HopMessage.STATUS:
        raise RuntimeError(f"relay {relay_peer_id} answered a RESERVE with message type {resp.type}")
    if resp.status != circuit.OK:
        raise RuntimeError(f"relay {relay_peer_id} refused the reservation: {circuit.Status.Name(resp.status)}")
    if resp.reservation.expire <= int(time.time()):
        raise RuntimeError(f"relay {relay_peer_id} granted a reservation that is already expired")
    return resp.reservation


async def dial_through_relay(host: IHost, relay_peer_id: ID, target: ID) -> INetConn:
    """Opens a connection to `target` through a relay we are connected to, and
    registers it with the host so streams can be opened on it. The relay's
    answer and the handshake with the target that follows are each bounded:
    py-libp2p's own limits on that upgrade add up to about a minute when the
    relay accepted the circuit and the far end never speaks, and a relayed
    dial is held to DIAL_TIMEOUT as a direct one is."""
    stream = await open_stream(host, relay_peer_id, HOP_PROTOCOL, RELAY_MESSAGE_TIMEOUT)
    try:
        with trio.fail_after(RELAY_MESSAGE_TIMEOUT):
            req = circuit.HopMessage(type=circuit.HopMessage.CONNECT, peer=circuit.Peer(id=target.to_bytes()))
            await stream.write(encode_varint_prefixed(req.SerializeToString()))
            resp = circuit.HopMessage.FromString(await read_bounded_varint_prefixed_bytes(stream, MAX_RELAY_MESSAGE_BYTES))
        if resp.type != circuit.HopMessage.STATUS or resp.status != circuit.OK:
            raise RuntimeError(
                f"relay {relay_peer_id} refused to connect to {target}: {circuit.Status.Name(resp.status) if resp.status else resp.type}"
            )
    except BaseException:
        await stream.close()
        raise
    # From here the stream is the wire; the usual TLS + yamux upgrade runs on it.
    circuit_addr = multiaddr.Multiaddr(f"/p2p/{relay_peer_id}/p2p-circuit/p2p/{target}")
    raw = RawConnection(stream=stream, initiator=True, connection_type=ConnectionType.RELAYED, addresses=[circuit_addr])
    try:
        with trio.fail_after(DIAL_TIMEOUT):
            return await host.upgrade_outbound_connection(raw, target)
    except BaseException as err:
        # A circuit given up on, timed out, failed or cancelled for another
        # path that won, is reset so the relay drops it too.
        with trio.CancelScope(shield=True), trio.move_on_after(HANGUP_GRACE):
            try:
                await stream.reset()
            except Exception:  # noqa: BLE001 - already gone
                pass
        if isinstance(err, trio.TooSlowError):
            raise ConnectionError(f"no secure connection to {target} through relay {relay_peer_id} within {DIAL_TIMEOUT:g}s") from None
        raise


def stop_stream_handler(host: IHost) -> Callable[[INetStream], object]:
    """Accepts connections a relay forwards to us: answers the STOP request and
    upgrades the stream into an inbound connection the host then serves."""

    async def handle(stream: INetStream) -> None:
        relay_peer_id = stream.muxed_conn.peer_id
        try:
            with trio.fail_after(RELAY_MESSAGE_TIMEOUT):
                msg = circuit.StopMessage.FromString(await read_bounded_varint_prefixed_bytes(stream, MAX_RELAY_MESSAGE_BYTES))
                if msg.type != circuit.StopMessage.CONNECT:
                    await stream.write(
                        encode_varint_prefixed(circuit.StopMessage(type=circuit.StopMessage.STATUS, status=circuit.UNEXPECTED_MESSAGE).SerializeToString())
                    )
                    await stream.close()
                    return
                source = ID(msg.peer.id)
                await stream.write(encode_varint_prefixed(circuit.StopMessage(type=circuit.StopMessage.STATUS, status=circuit.OK).SerializeToString()))
        except (trio.TooSlowError, ValueError) as err:
            logger.warning("relayed connection via %s not accepted: %s", relay_peer_id, err)
            await stream.close()
            return
        circuit_addr = multiaddr.Multiaddr(f"/p2p/{relay_peer_id}/p2p-circuit/p2p/{source}")
        raw = RawConnection(stream=stream, initiator=False, connection_type=ConnectionType.RELAYED, addresses=[circuit_addr])
        try:
            # py-libp2p >=0.8.3 closes any inbound stream when its handler
            # returns unless _keep_open is set (the same hook its own
            # circuit_v2 STOP handler uses). Hand ownership of the stream to
            # the upgraded connection only once upgrade succeeds.
            await host.upgrade_inbound_connection(raw, circuit_addr)
            setattr(stream, "_keep_open", True)
        except Exception as err:  # noqa: BLE001 - the relay's peer failed the upgrade; nothing of ours is affected
            logger.warning("relayed connection from %s via %s failed to upgrade: %s", source, relay_peer_id, err)
            try:
                await stream.close()
            except Exception:  # noqa: BLE001 - already closed by upgrade failure
                pass

    return handle
