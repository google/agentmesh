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

"""What a dial through a relay must do that py-libp2p does not: end at the
SDK's dial timeout when the relay accepted the circuit but the far end never
speaks. py-libp2p's own limits on that upgrade add up to about a minute,
and a caller that walks several relayed paths pays it for each."""

import multiaddr
import pytest
import trio
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.utils.varint import encode_varint_prefixed, read_varint_prefixed_bytes

from agent_mesh import relay as relay_module
from agent_mesh._proto import circuit_pb2 as circuit
from agent_mesh.host import create_mesh_host
from agent_mesh.identity import Identity
from agent_mesh.relay import HOP_PROTOCOL, dial_through_relay, stop_stream_handler

TARGET = ID.from_base58("12D3KooWG1pA6goegCncqwbZLSr8pnjUZ6JMAAe6SmnHTgUNCk88")


def test_a_circuit_the_far_end_never_speaks_on_ends_at_the_dial_timeout(monkeypatch):
    """A relay that answers CONNECT with OK and then forwards nothing, as one
    does while the destination it accepted the circuit for never completes
    its side of the handshake. The dial ends at DIAL_TIMEOUT with a
    ConnectionError, and the relay sees the circuit let go."""
    monkeypatch.setattr(relay_module, "DIAL_TIMEOUT", 0.5, raising=False)
    released = trio.Event()
    released_at = 0.0

    async def accept_and_stall(stream):
        nonlocal released_at
        req = circuit.HopMessage.FromString(await read_varint_prefixed_bytes(stream))
        assert req.type == circuit.HopMessage.CONNECT
        assert ID(req.peer.id) == TARGET
        await stream.write(encode_varint_prefixed(circuit.HopMessage(type=circuit.HopMessage.STATUS, status=circuit.OK).SerializeToString()))
        # Drain the caller's outbound handshake bytes without answering; only
        # the caller's reset/close after DIAL_TIMEOUT ends this loop.
        try:
            while await stream.read(4096):
                pass
        except Exception:  # noqa: BLE001 - the reset is the outcome looked for
            pass
        released_at = trio.current_time()
        released.set()

    async def main():
        relay, relay_listen = create_mesh_host(Identity.generate(), ["/ip4/127.0.0.1/tcp/0"])
        client, _ = create_mesh_host(Identity.generate())
        relay.set_stream_handler(HOP_PROTOCOL, accept_and_stall)
        async with relay.run(listen_addrs=relay_listen), client.run(listen_addrs=[]):
            await client.connect(info_from_p2p_addr(multiaddr.Multiaddr(f"{relay.get_addrs()[0]}")))
            started = trio.current_time()
            with pytest.raises(ConnectionError, match=f"through relay {relay.get_id()} within 0.5s"):
                await dial_through_relay(client, relay.get_id(), TARGET)
            assert 0.5 <= trio.current_time() - started < 3
            with trio.fail_after(3):
                await released.wait()
            assert released_at - started >= 0.5
            assert TARGET not in client.get_connected_peers()

    trio.run(main)


def test_stop_stream_handler_marks_upgraded_stream_keep_open():
    """stop_stream_handler hands the STOP stream off to upgrade_inbound_connection
    and returns. py-libp2p >=0.8.3 closes any inbound stream on handler return
    unless _keep_open is True, so a successful upgrade must mark the stream
    _keep_open while a failed upgrade must leave it unmarked and close it."""

    class _FakeMuxedConn:
        peer_id = ID.from_base58("12D3KooWG1pA6goegCncqwbZLSr8pnjUZ6JMAAe6SmnHTgUNCk88")

    class _FakeStream:
        def __init__(self, incoming: bytes) -> None:
            self.muxed_conn = _FakeMuxedConn()
            self._buf = bytearray(incoming)
            self.written = bytearray()
            self.closed = False

        async def read(self, n: int = -1) -> bytes:
            if not self._buf:
                return b""
            if n < 0 or n >= len(self._buf):
                out = bytes(self._buf)
                self._buf.clear()
                return out
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out

        async def write(self, data: bytes) -> None:
            self.written.extend(data)

        async def close(self) -> None:
            self.closed = True

    class _FakeHost:
        def __init__(self, *, fail_upgrade: bool = False) -> None:
            self.fail_upgrade = fail_upgrade
            self.upgraded: list[tuple[object, object]] = []

        async def upgrade_inbound_connection(self, raw_conn, maddr):
            if self.fail_upgrade:
                raise RuntimeError("boom")
            self.upgraded.append((raw_conn, maddr))
            return object()

    connect_bytes = encode_varint_prefixed(
        circuit.StopMessage(type=circuit.StopMessage.CONNECT, peer=circuit.Peer(id=TARGET.to_bytes())).SerializeToString()
    )

    async def main():
        ok_stream = _FakeStream(connect_bytes)
        ok_host = _FakeHost()
        await stop_stream_handler(ok_host)(ok_stream)
        assert len(ok_host.upgraded) == 1
        assert getattr(ok_stream, "_keep_open", False) is True
        assert ok_stream.closed is False

        fail_stream = _FakeStream(connect_bytes)
        fail_host = _FakeHost(fail_upgrade=True)
        await stop_stream_handler(fail_host)(fail_stream)
        assert fail_host.upgraded == []
        assert getattr(fail_stream, "_keep_open", False) is False
        assert fail_stream.closed is True

    trio.run(main)
