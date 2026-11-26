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
from agent_mesh.relay import HOP_PROTOCOL, dial_through_relay

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
