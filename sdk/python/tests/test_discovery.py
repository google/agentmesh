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

"""The directory client: a request goes to a held router, to the next when
that one fails, and the answer is what the router said."""

import hashlib

import pytest
import trio
import trio.testing
from libp2p.peer.id import ID
from libp2p.utils.varint import encode_varint_prefixed, read_varint_prefixed_bytes

from agent_mesh._proto import agentmesh_pb2 as pb
from agent_mesh import discovery
from agent_mesh.discovery import DIRECTORY_PROTOCOL, _REQUEST_TIMEOUT, DirectoryError, find_peer, find_providers, peer_key, provide, service_key

SELF = ID.from_base58("12D3KooWJoJPhXqLrGAcVsGSzHMzWrmoHCWoTzVSSiT3JfR7RBVo")
ROUTER = ID.from_base58("12D3KooWG1pA6goegCncqwbZLSr8pnjUZ6JMAAe6SmnHTgUNCk88")
ROUTER_B = ID.from_base58("12D3KooWBTdQ3QQZztZFaxQSTzJx5ZSbpgM8zfs43VYzBXAFkdZm")
TARGET = ID.from_base58("12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo")
PROVIDER = ID.from_base58("12D3KooWPZCZBAZRx1TNpPt19sZ7PKcdce8rE7gNGwhzLJtWXU9u")


class _Stream:
    """One directory request answered by a function, as a router would."""

    def __init__(self, answer):
        self._answer = answer
        self._req = b""
        self._resp = b""

    async def write(self, data):
        self._req += data

    async def read(self, n=None):
        if self._req:
            req = pb.DirectoryRequest.FromString(await read_varint_prefixed_bytes(_Bytes(self._req)))
            self._req = b""
            self._resp = encode_varint_prefixed(self._answer(req).SerializeToString())
        n = len(self._resp) if n is None else n
        out, self._resp = self._resp[:n], self._resp[n:]
        return out

    async def close(self):
        pass


class _Bytes:
    def __init__(self, data):
        self._data = data

    async def read(self, n=None):
        n = len(self._data) if n is None else n
        out, self._data = self._data[:n], self._data[n:]
        return out


class _Host:
    """Connected to its routers, each answering with a function; a router
    that is None never answers a stream open."""

    def __init__(self, answers):
        self._answers = answers
        self.asked = []

    def get_id(self):
        return SELF

    async def new_stream(self, peer_id, protocols):
        assert protocols == [DIRECTORY_PROTOCOL]
        self.asked.append(peer_id)
        answer = self._answers[peer_id]
        if answer is None:
            await trio.sleep_forever()
        return _Stream(answer)


def _record(peer_id, *addrs):
    return pb.PeerRecord(peer_id=str(peer_id), addrs=[f"{a}/p2p/{peer_id}" for a in addrs])


def test_directory_closes_an_opened_stream_when_cancelled(monkeypatch):
    closed = []

    async def run():
        with trio.CancelScope() as scope:
            class Stream:
                async def write(self, data):
                    scope.cancel()
                    await trio.lowlevel.checkpoint()

                async def close(self):
                    await trio.lowlevel.checkpoint()
                    closed.append(True)

            async def open_stream(*args):
                return Stream()

            monkeypatch.setattr(discovery, "open_stream", open_stream)
            await discovery.request(None, [ROUTER], pb.DirectoryRequest())
        assert scope.cancelled_caught
        assert closed == [True]

    trio.run(run)


def test_keys_are_the_sha256_multihash_of_the_name():
    """The same bytes api.ServiceKey and api.PeerKey produce, so a record a
    Go member announced is found from Python and the other way round."""
    want = b"\x12\x20" + hashlib.sha256(b"mesh:service:mcp:calculator").digest()
    assert service_key("mcp", "calculator") == want
    assert service_key("mcp") == b"\x12\x20" + hashlib.sha256(b"mesh:service:mcp").digest()
    assert peer_key(TARGET) == b"\x12\x20" + hashlib.sha256(f"mesh:peer:{TARGET}".encode()).digest()
    assert service_key("mcp") != service_key("mcp", "calculator")


def test_find_providers_asks_one_held_router_and_takes_its_answer():
    def knows_provider(req):
        assert req.WhichOneof("request") == "find_providers"
        assert req.find_providers.key == service_key("mcp", "calculator")
        return pb.DirectoryResponse(providers=[_record(PROVIDER, "/ip4/10.0.0.9/tcp/4001"), _record(SELF, "/ip4/10.0.0.1/tcp/1")])

    host = _Host({ROUTER: knows_provider, ROUTER_B: knows_provider})

    async def main():
        found = await find_providers(host, [ROUTER, ROUTER_B], service_key("mcp", "calculator"))
        assert [p.peer_id for p in found] == [str(PROVIDER)], "the member itself is left out"
        assert found[0].addrs == [f"/ip4/10.0.0.9/tcp/4001/p2p/{PROVIDER}"]
        assert host.asked == [ROUTER], "one router answers; the second is not asked"

    trio.run(main)


def test_a_router_that_fails_is_skipped_for_the_next():
    """A router that does not answer costs the request one timeout; a router
    that answers with an error is skipped at once. Only when every held
    router fails does the request fail."""

    def errors(req):
        return pb.DirectoryResponse(error="the directory is not up")

    def answers(req):
        return pb.DirectoryResponse(providers=[_record(PROVIDER, "/ip4/10.0.0.9/tcp/4001")])

    async def main():
        host = _Host({ROUTER: None, ROUTER_B: answers})
        started = trio.current_time()
        found = await find_providers(host, [ROUTER, ROUTER_B], b"\x12\x20" + bytes(32))
        assert [p.peer_id for p in found] == [str(PROVIDER)]
        assert host.asked == [ROUTER, ROUTER_B]
        assert trio.current_time() - started == pytest.approx(_REQUEST_TIMEOUT)

        host = _Host({ROUTER: errors, ROUTER_B: answers})
        assert [p.peer_id for p in await find_providers(host, [ROUTER, ROUTER_B], b"\x12\x20" + bytes(32))] == [str(PROVIDER)]

        host = _Host({ROUTER: errors, ROUTER_B: errors})
        with pytest.raises(DirectoryError, match="no held router answered"):
            await find_providers(host, [ROUTER, ROUTER_B], b"\x12\x20" + bytes(32))

        with pytest.raises(DirectoryError, match="no held router to ask"):
            await find_providers(_Host({}), [], b"\x12\x20" + bytes(32))

    trio.run(main, clock=trio.testing.MockClock(autojump_threshold=0))


def test_find_peer_returns_the_addresses_the_router_knows_or_nothing():
    def knows_target(req):
        assert req.WhichOneof("request") == "find_peer"
        if req.find_peer.peer_id == str(TARGET):
            return pb.DirectoryResponse(peer=_record(TARGET, "/ip4/10.0.0.9/tcp/4001", f"/ip4/10.0.0.2/tcp/4501/p2p/{ROUTER}/p2p-circuit"))
        return pb.DirectoryResponse()

    host = _Host({ROUTER: knows_target})

    async def main():
        addrs = await find_peer(host, [ROUTER], TARGET)
        assert [str(a) for a in addrs] == [
            f"/ip4/10.0.0.9/tcp/4001/p2p/{TARGET}",
            f"/ip4/10.0.0.2/tcp/4501/p2p/{ROUTER}/p2p-circuit/p2p/{TARGET}",
        ]
        assert await find_peer(host, [ROUTER], PROVIDER) == []

    trio.run(main)


def test_provide_announces_this_member_at_its_addresses():
    seen = []

    def takes(req):
        assert req.WhichOneof("request") == "provide"
        seen.append(req.provide)
        return pb.DirectoryResponse()

    host = _Host({ROUTER: takes})

    async def main():
        import multiaddr

        await provide(host, [ROUTER], peer_key(SELF), [multiaddr.Multiaddr("/ip4/10.0.0.1/tcp/1")])
        assert len(seen) == 1
        assert seen[0].key == peer_key(SELF)
        assert list(seen[0].addrs) == ["/ip4/10.0.0.1/tcp/1"]
        assert seen[0].provider == "", "a member names no provider; it announces itself"

    trio.run(main)


def test_read_bounded_varint_prefixed_bytes_rejects_oversized_prefix_before_reading_payload():
    from libp2p.utils.varint import encode_uvarint

    from agent_mesh.auth import read_bounded_varint_prefixed_bytes

    class _BombStream:
        def __init__(self, header: bytes):
            self._header = header
            self.payload_reads = 0

        async def read(self, n=None):
            if self._header:
                out, self._header = self._header[:1], self._header[1:]
                return out
            self.payload_reads += 1
            return b"x" * (n or 1)

    async def main():
        bomb = _BombStream(encode_uvarint(2 * 1024 * 1024 * 1024))
        with pytest.raises(ValueError, match="exceeds"):
            await read_bounded_varint_prefixed_bytes(bomb, 64 * 1024)
        assert bomb.payload_reads == 0

    trio.run(main)


def test_an_empty_answer_is_put_to_the_next_router():
    """A router cut off from the routers closest to the key answers with
    nothing; the next held router is asked before the lookup is empty. An
    announcement is not repeated: one router taking it is enough."""

    def knows_nothing(req):
        return pb.DirectoryResponse()

    def answers(req):
        return pb.DirectoryResponse(providers=[_record(PROVIDER, "/ip4/10.0.0.9/tcp/4001")])

    async def main():
        host = _Host({ROUTER: knows_nothing, ROUTER_B: answers})
        found = await find_providers(host, [ROUTER, ROUTER_B], service_key("mcp", "calculator"))
        assert [p.peer_id for p in found] == [str(PROVIDER)]
        assert host.asked == [ROUTER, ROUTER_B]

        host = _Host({ROUTER: knows_nothing, ROUTER_B: knows_nothing})
        assert await find_providers(host, [ROUTER, ROUTER_B], service_key("mcp", "calculator")) == []
        assert host.asked == [ROUTER, ROUTER_B]

        host = _Host({ROUTER: knows_nothing, ROUTER_B: answers})
        await provide(host, [ROUTER, ROUTER_B], service_key("mcp", "calculator"), [])
        assert host.asked == [ROUTER], "an announcement one router took is not repeated"

    trio.run(main)
