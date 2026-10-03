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

"""The /libp2p-http protocol (go-libp2p-http): the client that calls inference
and A2A services on the mesh, and the ingress that accepts A2A requests for
this member's own agent, gated by the authorizer the way sam-node gates its
ingress (StartIngressServer in internal/node)."""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from typing import AsyncIterator, Awaitable, Callable, Mapping, Optional, Sequence, Union

import h11
import httpx
import trio
from libp2p.abc import IHost, INetStream
from libp2p.custom_types import TProtocol
from libp2p.network.stream.exceptions import StreamEOF
from libp2p.peer.id import ID

from .auth import AUTH_HANDSHAKE_TIMEOUT
from .authorizer import AuthorizationError, AuthorizeRequest, ProviderAuthorizerOptions, authorize_caller
from .biscuit import VerifiedBiscuit
from .host import open_stream

logger = logging.getLogger("agent_mesh")

# go-libp2p-http's protocol: plain HTTP/1.1 on a stream, one request per stream.
HTTP_PROTOCOL = TProtocol("/libp2p-http")

# Headers of the mesh HTTP datapath (api/network.go).
HEADER_SAM_BISCUIT = "x-sam-biscuit"
HEADER_PEER_ID = "x-peer-id"
HEADER_SAM_NO_TRAILING_SLASH = "x-sam-no-trailing-slash"

# The service name an agent answers under unless it picks another.
DEFAULT_A2A_NAME = "agent"

# The path prefix of a mesh URL, http://mesh/sam/<peer-id>/<type>/<name>/<path>:
# the shape of sam-node's egress proxy and of an agent card rewritten for the
# mesh, by sam-node or by this SDK. The peer ID is in the path, not the host.
MESH_PATH_PREFIX = "/sam/"

# The well-known agent card location (A2A spec / RFC 8615).
AGENT_CARD_PATH = ".well-known/agent-card.json"

_MAX_AGENT_CARD_BYTES = 1 << 20
# The bare service root counts too: a2a-go treats a pathful base URL as the card location.
_AGENT_CARD_TARGET = re.compile(r"^/a2a/([^/?]+)(?:/(?:\.well-known/agent-card\.json)?)?(?:\?.*)?$")
_HTTP_BINDINGS = ("JSONRPC", "HTTP+JSON")

_MAX_INGRESS_BODY_BYTES = 8 * 1024 * 1024
_READ_CHUNK = 64 * 1024
_REQUEST_TIMEOUT = 60.0


@dataclass(frozen=True)
class HTTPRequest:
    """What an in-process HTTP handler receives: the request as it reached
    the agent, path relative to /a2a/<name>."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):  # type: ignore[no-untyped-def]
        return json.loads(self.body)


HTTPHandler = Callable[[HTTPRequest, VerifiedBiscuit], Awaitable[HTTPResponse]]


@dataclass(frozen=True)
class A2AEndpoint:
    """This member's agent as other members reach it: `a2a://<name>`, answered
    by target, the base URL of an A2A server beside this process or a handler
    in it. Authorized requests are forwarded with the biscuit header
    stripped and X-Peer-Id naming the verified caller, as sam-node does. The
    endpoint is not announced anywhere; a caller reaches it by peer ID."""

    target: Union[str, HTTPHandler]
    name: str = DEFAULT_A2A_NAME

    @property
    def service(self) -> str:
        return f"a2a://{self.name}"


@dataclass(frozen=True)
class ProviderOptions:
    authorizer: ProviderAuthorizerOptions
    # Peers the control plane has banned; refused before their token is looked at.
    is_banned: Optional[Callable[[str], bool]] = None
    # Called after a caller is authorized, e.g. for the session's admitted set.
    on_authorized: Optional[Callable[[str, VerifiedBiscuit, str], None]] = None


_DOT_ENCODED = re.compile("%2e", re.IGNORECASE)


def _has_dot_segment(path: str) -> bool:
    # A URL parser reads %2e as a dot too (WHATWG URL, path state), so the
    # check sees what the backend will see.
    return any(_DOT_ENCODED.sub(".", seg) in (".", "..") for seg in path.split("/"))


async def _read_http_request(stream: INetStream, conn: h11.Connection, limit: int) -> tuple[h11.Request, bytes]:
    request: Optional[h11.Request] = None
    body = bytearray()
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            try:
                data = await stream.read(_READ_CHUNK)
            except Exception:  # noqa: BLE001 - EOF or reset: the parser sees end of input
                data = b""
            conn.receive_data(data)
            continue
        if isinstance(event, h11.Request):
            request = event
        elif isinstance(event, h11.Data):
            body.extend(event.data)
            if len(body) > limit:
                raise ValueError(f"body exceeds {limit} bytes")
        elif isinstance(event, h11.EndOfMessage):
            if request is None:
                raise ValueError("end of message before request")
            return request, bytes(body)
        elif isinstance(event, (h11.ConnectionClosed, h11.PAUSED)):
            raise ValueError("connection closed before a request")


async def _write_http_response(stream: INetStream, conn: h11.Connection, status: int, headers: Mapping[str, str], body: bytes) -> None:
    out = [(k.encode(), v.encode()) for k, v in headers.items() if k.lower() not in ("content-length", "transfer-encoding", "connection")]
    out.append((b"content-length", str(len(body)).encode()))
    out.append((b"connection", b"close"))
    data = conn.send(h11.Response(status_code=status, headers=out)) or b""
    data += conn.send(h11.Data(data=body)) or b""
    data += conn.send(h11.EndOfMessage()) or b""
    await stream.write(data)


def http_ingress_handler(endpoint: A2AEndpoint, options: ProviderOptions):  # type: ignore[no-untyped-def]
    """Server side of /libp2p-http, as sam-node's StartIngressServer: the path
    is /<type>/<name>[/<upstream>], the caller's biscuit is X-Sam-Biscuit, and
    the request is authorized for <type>://<name> before anything is forwarded.
    Only the agent's own endpoint is answered; anything else is 404 after
    authorization, so an unauthorized caller learns nothing about it."""

    async def handle(stream: INetStream) -> None:
        peer_id = str(stream.muxed_conn.peer_id)
        conn = h11.Connection(h11.SERVER)

        async def reply(status: int, text: str) -> None:
            await _write_http_response(stream, conn, status, {"content-type": "text/plain; charset=utf-8"}, (text + "\n").encode())

        try:
            try:
                with trio.fail_after(AUTH_HANDSHAKE_TIMEOUT):
                    request, body = await _read_http_request(stream, conn, _MAX_INGRESS_BODY_BYTES)
            except (ValueError, h11.RemoteProtocolError, trio.TooSlowError) as err:
                logger.debug("http ingress from %s: %s", peer_id, err)
                return
            status, headers, out = await _handle_ingress(request, body, peer_id, endpoint, options)
            await _write_http_response(stream, conn, status, headers, out)
        except Exception as err:  # noqa: BLE001 - one caller's failure must not take the handler down
            logger.debug("http ingress from %s failed: %s", peer_id, err)
            try:
                await reply(500, f"ingress error: {err}")
            except Exception:  # noqa: BLE001
                pass
        finally:
            await stream.close()

    return handle


async def _handle_ingress(
    request: h11.Request, body: bytes, peer_id: str, endpoint: A2AEndpoint, options: ProviderOptions
) -> tuple[int, dict[str, str], bytes]:
    def plain(status: int, text: str) -> tuple[int, dict[str, str], bytes]:
        return status, {"content-type": "text/plain; charset=utf-8"}, (text + "\n").encode()

    target = request.target.decode("latin-1")
    raw_path, _, query = target.partition("?")
    # Policy is decided on the /<type>/<name> prefix; a dot segment in what
    # follows could resolve to a sibling path on the backend.
    if _has_dot_segment(raw_path):
        return plain(400, "Invalid path")
    parts = raw_path.lstrip("/").split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return plain(400, "Invalid path")
    service_type, service_name, rest = parts[0], parts[1], parts[2:]
    if service_type not in ("inference", "a2a", "mcp", "egress"):
        return plain(400, "Invalid service type")
    upstream_path = "/".join(rest)

    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in request.headers}
    biscuit_b64 = headers.get(HEADER_SAM_BISCUIT, "")
    if not biscuit_b64:
        return plain(401, "Missing X-Sam-Biscuit header")
    try:
        biscuit = base64.b64decode(biscuit_b64, validate=True)
        if not biscuit:
            raise ValueError("empty")
    except (ValueError, TypeError):
        return plain(400, "Invalid X-Sam-Biscuit encoding")

    target_service = f"{service_type}://{service_name}"
    if options.is_banned is not None and options.is_banned(peer_id):
        return plain(403, "Authorization failed")
    try:
        verified = await trio.to_thread.run_sync(
            authorize_caller,
            AuthorizeRequest(
                biscuit=biscuit,
                peer_id=peer_id,
                target_service=target_service,
                protocol=str(HTTP_PROTOCOL),
                # The path as the backend sees it, decided before authorization
                # so path() is what policy meant, never the routing prefix.
                method=request.method.decode("latin-1"),
                path="/" + upstream_path,
            ),
            options.authorizer,
        )
    except AuthorizationError as err:
        logger.info("http ingress denied %s: %s", peer_id, err)
        return plain(403, "Authorization failed")
    if options.on_authorized:
        options.on_authorized(peer_id, verified, target_service)

    # Under the type the policy was evaluated on.
    if target_service != endpoint.service:
        return plain(404, "Service not found")

    # The biscuit is for policy, not for the backend; X-Peer-Id
    # is set, not added, so an inbound value cannot pose as the verified peer.
    forwarded = {
        k: v
        for k, v in headers.items()
        if k not in (HEADER_SAM_BISCUIT, HEADER_SAM_NO_TRAILING_SLASH, HEADER_PEER_ID, "host", "connection", "transfer-encoding", "content-length")
    }
    forwarded[HEADER_PEER_ID] = peer_id
    if upstream_path == "" and not rest:
        forwarded[HEADER_SAM_NO_TRAILING_SLASH] = "true"
    method = request.method.decode()
    path = "/" + upstream_path + (f"?{query}" if query else "")

    if callable(endpoint.target):
        response = await endpoint.target(HTTPRequest(method=method, path=path, headers=forwarded, body=body), verified)
        return response.status, dict(response.headers), response.body

    async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT, follow_redirects=False) as client:
        upstream = await client.request(method, endpoint.target.rstrip("/") + path, headers=forwarded, content=body or None)
    out_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "connection")}
    return upstream.status_code, out_headers, upstream.content


async def _read_or_eof(stream: INetStream, peer_id: ID) -> bytes:
    """One read for the HTTP parser. The peer closing its side is the end of
    input, which is how a body without a length (server-sent events) ends. A
    reset or any other failure is not: without a length only the stream can
    tell a body that ended from one that was cut."""
    try:
        return await stream.read(_READ_CHUNK)
    except StreamEOF as err:
        # py-libp2p 0.8's yamux drops a reset stream's bookkeeping once its
        # buffer is drained, and a bounded read then reports the end of the
        # stream; the muxed stream itself still knows it was reset.
        if getattr(getattr(stream, "muxed_stream", None), "reset_received", False):
            raise ConnectionError(f"peer {peer_id} broke the stream mid-response: reset") from err
        return b""
    except Exception as err:
        raise ConnectionError(f"peer {peer_id} broke the stream mid-response: {err}") from err


def mesh_http_target(target_service: str, path: str = "") -> str:
    """The request target for a service on a peer: /<type>/<name>/<path>."""
    scheme, sep, name = target_service.partition("://")
    if not sep or scheme not in ("inference", "a2a", "mcp", "egress") or not name:
        raise ValueError(f"service target must look like inference://<name>, got {target_service!r}")
    if not path:
        return f"/{scheme}/{name}"
    return f"/{scheme}/{name}" + (path if path.startswith("/") else "/" + path)


def mesh_url(peer_id: str, target_service: str, path: str = "") -> str:
    """The URL an httpx client on MeshTransport uses for a service on a peer:
    http://mesh/sam/<peer-id>/<type>/<name>/<path>."""
    return "http://mesh" + MESH_PATH_PREFIX + peer_id + mesh_http_target(target_service, path)


def _agent_card_service(method: str, target: str) -> Optional[str]:
    m = _AGENT_CARD_TARGET.match(target)
    return f"a2a://{m.group(1)}" if method == "GET" and m else None


def rewrite_agent_card(card: object, base: str) -> dict:
    """An agent card rebuilt for the mesh, as sam-node's egress proxy serves
    it: HTTP interfaces point at base, gRPC ones go, signatures no longer match.
    Streaming stays as declared, this transport streams. Raises when no interface remains."""
    if not isinstance(card, dict):
        raise ValueError("agent card is not a JSON object")
    interfaces = card.get("supportedInterfaces")
    kept = [
        {**iface, "url": base}
        for iface in (interfaces if isinstance(interfaces, list) else [])
        if isinstance(iface, dict) and str(iface.get("protocolBinding", "")).upper() in _HTTP_BINDINGS
    ]
    if not kept:
        raise ValueError("agent card advertises no supported interface the mesh can carry (JSONRPC or HTTP+JSON); is the agent serving a pre-1.0 A2A card?")
    return {**{k: v for k, v in card.items() if k != "signatures"}, "supportedInterfaces": kept}


class StreamedResponse:
    """A response whose body is still arriving on the stream: status and
    headers are in; `iter_body` yields the body as the peer sends it, which is
    what an SSE stream (A2A `message/stream`) needs. Close it when done."""

    def __init__(self, stream: INetStream, conn: h11.Connection, status: int, headers: dict[str, str], peer_id: ID) -> None:
        self._stream = stream
        self._conn = conn
        self._peer_id = peer_id
        self.status = status
        self.headers = headers

    async def iter_body(self) -> AsyncIterator[bytes]:
        while True:
            event = self._conn.next_event()
            if event is h11.NEED_DATA:
                self._conn.receive_data(await _read_or_eof(self._stream, self._peer_id))
                continue
            if isinstance(event, h11.Data):
                yield bytes(event.data)
            elif isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed, h11.PAUSED)):
                return

    async def read(self, limit: int = _MAX_INGRESS_BODY_BYTES) -> bytes:
        body = bytearray()
        async for chunk in self.iter_body():
            body.extend(chunk)
            if len(body) > limit:
                raise ValueError("response body too large")
        return bytes(body)

    async def aclose(self) -> None:
        await self._stream.close()


class _BufferedResponse(StreamedResponse):
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self._payload = body

    async def iter_body(self) -> AsyncIterator[bytes]:
        yield self._payload

    async def aclose(self) -> None:
        return None


async def open_http_request(
    host: IHost,
    peer_id: ID,
    biscuit: bytes,
    method: str,
    target: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    body: bytes = b"",
    timeout: float = _REQUEST_TIMEOUT,
) -> StreamedResponse:
    """Client side of /libp2p-http, as go-libp2p-http's RoundTripper: one
    stream per request, plain HTTP/1.1 with Host set to the peer ID and the
    biscuit in X-Sam-Biscuit. Returns once the response headers are in; the
    body streams after. The timeout bounds the headers, not the body. An
    agent card is served rewritten for the mesh (rewrite_agent_card), as
    sam-node's egress proxy serves one."""
    service = _agent_card_service(method, target)
    if service is None:
        return await _open_http_request(host, peer_id, biscuit, method, target, headers=headers, body=body, timeout=timeout)
    return await _serve_agent_card(host, peer_id, biscuit, headers, timeout, service)


async def _serve_agent_card(host: IHost, peer_id: ID, biscuit: bytes, headers: Optional[Mapping[str, str]], timeout: float, service: str) -> StreamedResponse:
    """Impersonates the agent's card endpoint as sam-node's egress proxy does:
    holds the client's request, fetches the card itself with identity encoding,
    and answers with it regenerated; the agent's own non-200 is relayed as it is."""
    base = mesh_url(str(peer_id), service)
    identity = {k: v for k, v in (headers or {}).items() if k.lower() != "accept-encoding"}
    try:
        response = await _open_http_request(host, peer_id, biscuit, "GET", mesh_http_target(service, AGENT_CARD_PATH), headers=identity, body=b"", timeout=timeout)
    except Exception as err:  # noqa: BLE001 - answered as sam-node's 502
        return _bad_gateway(f"agent card fetch failed: {err}")
    if response.status != 200:
        return response
    try:
        with trio.fail_after(timeout):
            card = json.loads(await response.read(_MAX_AGENT_CARD_BYTES))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _bad_gateway("agent card is not valid JSON")
    except Exception as err:  # noqa: BLE001 - answered as sam-node's 502
        return _bad_gateway(f"agent card fetch failed: {err}")
    finally:
        await response.aclose()
    try:
        payload = json.dumps(rewrite_agent_card(card, base)).encode()
    except ValueError as err:
        return _bad_gateway(str(err))
    return _BufferedResponse(200, {"content-type": "application/json", "content-length": str(len(payload))}, payload)


def _bad_gateway(reason: str) -> StreamedResponse:
    payload = f"Bad Gateway: {reason}".encode()
    return _BufferedResponse(502, {"content-type": "text/plain", "content-length": str(len(payload))}, payload)


async def _open_http_request(
    host: IHost,
    peer_id: ID,
    biscuit: bytes,
    method: str,
    target: str,
    *,
    headers: Optional[Mapping[str, str]],
    body: bytes,
    timeout: float,
) -> StreamedResponse:
    out = [(k.lower(), v) for k, v in (headers or {}).items() if k.lower() not in ("host", "content-length", HEADER_SAM_BISCUIT, HEADER_PEER_ID)]
    out.append(("host", str(peer_id)))
    out.append((HEADER_SAM_BISCUIT, base64.b64encode(biscuit).decode()))
    out.append(("content-length", str(len(body))))

    conn = h11.Connection(h11.CLIENT)
    stream = await open_stream(host, peer_id, HTTP_PROTOCOL, timeout)
    try:
        with trio.fail_after(timeout):
            data = conn.send(h11.Request(method=method, target=target, headers=out)) or b""
            data += conn.send(h11.Data(data=body)) or b""
            data += conn.send(h11.EndOfMessage()) or b""
            await stream.write(data)
            while True:
                event = conn.next_event()
                if event is h11.NEED_DATA:
                    conn.receive_data(await _read_or_eof(stream, peer_id))
                    continue
                if isinstance(event, h11.Response):
                    resp_headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in event.headers}
                    return StreamedResponse(stream, conn, event.status_code, resp_headers, peer_id)
                if isinstance(event, h11.InformationalResponse):
                    continue
                raise ConnectionError(f"peer {peer_id} closed the stream before answering")
    except BaseException:
        await stream.close()
        raise


async def http_request_over_stream(
    host: IHost,
    peer_id: ID,
    biscuit: bytes,
    target_service: str,
    path: str,
    *,
    method: str = "GET",
    headers: Optional[Mapping[str, str]] = None,
    body: Union[bytes, str, None] = None,
    timeout: float = _REQUEST_TIMEOUT,
) -> HTTPResponse:
    """One request to /<type>/<name>/<path> on a peer, body read whole."""
    payload = body.encode() if isinstance(body, str) else (body or b"")
    with trio.fail_after(timeout):
        response = await open_http_request(host, peer_id, biscuit, method, mesh_http_target(target_service, path), headers=headers, body=payload, timeout=timeout)
        try:
            return HTTPResponse(status=response.status, headers=response.headers, body=await response.read())
        finally:
            await response.aclose()


__all__: Sequence[str] = (
    "AGENT_CARD_PATH",
    "A2AEndpoint",
    "DEFAULT_A2A_NAME",
    "HTTP_PROTOCOL",
    "MESH_PATH_PREFIX",
    "HTTPHandler",
    "HTTPRequest",
    "HTTPResponse",
    "ProviderOptions",
    "StreamedResponse",
    "http_ingress_handler",
    "http_request_over_stream",
    "mesh_http_target",
    "mesh_url",
    "open_http_request",
    "rewrite_agent_card",
)
