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
import trio

from agent_mesh import libp2p_http
from agent_mesh.httpx_transport import MeshTransport


def test_mesh_transport_keeps_multiple_set_cookie_fields(monkeypatch):
    class Stream:
        async def write(self, data):
            pass

        async def read(self, size):
            return (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Set-Cookie: one=1\r\nSet-Cookie: two=2\r\n\r\nok"
            )

        async def close(self):
            pass

    async def open_stream(*args):
        return Stream()

    async def egress_peer(peer, service):
        return peer

    monkeypatch.setattr(libp2p_http, "open_stream", open_stream)
    session = SimpleNamespace(host=None, biscuit=b"fixture", _egress_peer=egress_peer)

    async def run():
        async with httpx.AsyncClient(transport=MeshTransport(session)) as client:
            response = await client.get("http://mesh/mesh/peer/a2a/example/message")
            assert response.text == "ok"
            assert response.headers.get_list("set-cookie") == ["one=1", "two=2"]
            assert client.cookies.get("one") == "1"
            assert client.cookies.get("two") == "2"

    trio.run(run)
