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

from types import SimpleNamespace

import httpx
import pytest
import trio
from trio.testing import MockClock

from agent_mesh import httpx_transport
from agent_mesh.httpx_transport import MeshTransport


def test_mesh_transport_applies_httpx_read_timeout_to_body(monkeypatch):
    closed = []

    class Response:
        status = 200
        headers = {}
        raw_headers = ()

        async def iter_body(self):
            yield b"first"
            await trio.sleep(2)
            yield b"second"

        async def aclose(self):
            closed.append(True)

    async def open_request(*args, **kwargs):
        return Response()

    async def egress_peer(peer, service):
        return peer

    monkeypatch.setattr(httpx_transport, "open_http_request", open_request)
    session = SimpleNamespace(host=None, biscuit=b"fixture", _egress_peer=egress_peer)

    async def run():
        path = "http://mesh/mesh/peer/a2a/example"
        async with httpx.AsyncClient(transport=MeshTransport(session)) as client:
            assert (await client.get(path, timeout=None)).content == b"firstsecond"
            request = httpx.Request("GET", path, extensions={"timeout": None})
            assert (await client.send(request)).content == b"firstsecond"
            with pytest.raises(httpx.ReadTimeout) as caught:
                await client.get(path, timeout=httpx.Timeout(10, read=1))
            assert str(caught.value.request.url) == path
        assert closed == [True, True, True]

    trio.run(run, clock=MockClock(autojump_threshold=0))
