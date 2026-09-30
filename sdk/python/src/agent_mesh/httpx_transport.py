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

"""The mesh as an httpx transport, so a client built on httpx, such as the
official A2A SDK, reaches a member's service or agent without knowing about
libp2p:

    client = httpx.AsyncClient(transport=MeshTransport(session))
    await client.post("http://mesh/sam/<peer-id>/a2a/agent", json=...)

The URL has the shape sam-node's egress proxy takes, /sam/<peer-id>/<type>/
<name>/<path>. The card of an agent behind a sam-node comes back rewritten to
that shape, as the node's egress proxy serves it, so a stock A2A client
bootstraps from it unchanged. The host is ignored: httpx lowercases it, and a
peer ID is not case-insensitive. Response bodies stream, so `message/stream`
works."""

from __future__ import annotations

from typing import TYPE_CHECKING, AsyncIterator

import httpx

from .libp2p_http import MESH_PATH_PREFIX, StreamedResponse, open_http_request

if TYPE_CHECKING:
    from .session import MeshSession

_REQUEST_TIMEOUT = 60.0


def split_mesh_url(url: httpx.URL) -> tuple[str, str]:
    """(peer ID, request target) of a mesh URL; the target is the
    /<type>/<name>/<path>?<query> the peer's ingress takes."""
    raw = url.raw_path.decode("latin-1")
    path, _, query = raw.partition("?")
    if not path.startswith(MESH_PATH_PREFIX):
        raise httpx.UnsupportedProtocol(f"a mesh URL looks like http://mesh{MESH_PATH_PREFIX}<peer-id>/<type>/<name>/..., got {url}")
    peer_id, _, rest = path[len(MESH_PATH_PREFIX) :].partition("/")
    parts = rest.split("/")
    if not peer_id or len(parts) < 2 or not parts[0] or not parts[1]:
        raise httpx.UnsupportedProtocol(f"a mesh URL names a peer, a service type and a name, got {url}")
    return peer_id, "/" + rest + (f"?{query}" if query else "")


class _BodyStream(httpx.AsyncByteStream):
    def __init__(self, response: StreamedResponse) -> None:
        self._response = response

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._response.iter_body():
            yield chunk

    async def aclose(self) -> None:
        await self._response.aclose()


class MeshTransport(httpx.AsyncBaseTransport):
    """Carries every request of an httpx client to the peer its URL names,
    over /libp2p-http through the session. Runs under trio, as the session
    does."""

    def __init__(self, session: "MeshSession", *, agent: str = "", timeout: float = _REQUEST_TIMEOUT) -> None:
        self._session = session
        self._agent = agent
        self._timeout = timeout

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        peer_text, target = split_mesh_url(request.url)
        peer_id = await self._session._egress_peer(peer_text)  # noqa: SLF001 - the session's verified egress path, not a caller option
        body = await request.aread()
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in request.headers.raw}
        response = await open_http_request(
            self._session.host,
            peer_id,
            self._session.mesh.credential.biscuit,
            request.method,
            target,
            headers=headers,
            body=body,
            agent=self._agent,
            timeout=self._timeout,
        )
        return httpx.Response(response.status, headers=list(response.headers.items()), stream=_BodyStream(response), request=request)


__all__ = ("MESH_PATH_PREFIX", "MeshTransport", "split_mesh_url")
