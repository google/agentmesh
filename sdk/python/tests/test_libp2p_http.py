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

"""The A2A ingress in one process: this SDK's /libp2p-http handler for one
agent behind a py-libp2p host, called with this SDK's client, the streaming
client and an httpx client on MeshTransport. The real sam-node as a caller is
exercised by tests/integration."""

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import biscuit_auth as ba
import httpx
import multiaddr
import pytest
import trio
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import info_from_p2p_addr

from agent_mesh.authorizer import ProviderAuthorizerOptions
from agent_mesh.controlplane import ROLE_NODE
from agent_mesh.httpx_transport import MeshTransport, split_mesh_url
from agent_mesh.identity import Identity
from agent_mesh.libp2p_http import (
    AGENT_CARD_PATH,
    HTTP_PROTOCOL,
    A2AEndpoint,
    HTTPRequest,
    HTTPResponse,
    ProviderOptions,
    http_ingress_handler,
    http_request_over_stream,
    mesh_http_target,
    open_http_request,
    rewrite_agent_card,
)
from agent_mesh.session import MeshSession

from .test_session import CP, CP_KEY, libp2p_host

# What the control plane renders for a policy granting the node role every
# A2A service on any target, and nothing else.
POLICY_RULES = [
    'granted_service_all("a2a") <- role("sam:role:node")',
    'granted_service_all("sam:system") <- role("sam:role:node")',
    'target_unrestricted(true) <- role("sam:role:node")',
]


def mint(peer_id: str, role: str) -> bytes:
    return ba.BiscuitBuilder(
        "node({p}); client_peer_id({p}); expiration(2035-01-01T00:00:00Z); role({r});", {"p": peer_id, "r": role}
    ).build(CP.private_key).to_bytes()


STOCK_CARD = {
    "name": "echo-agent",
    "version": "1.0.0",
    "capabilities": {"streaming": True, "pushNotifications": False},
    "supportedInterfaces": [
        {"url": "http://127.0.0.1:7777/", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
        {"url": "127.0.0.1:50051", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
    ],
    "signatures": [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "c3RhbGU"}],
    "skills": [],
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
}


class FakeA2AServer(BaseHTTPRequestHandler):
    """Stands in for an A2A server beside the agent: echoes the request and,
    on /stream, answers with three SSE events as message/stream would."""

    seen: list[dict] = []

    def _answer(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        FakeA2AServer.seen.append(
            {
                "method": self.command,
                "path": self.path,
                "peer": self.headers.get("x-peer-id"),
                "body": body.decode(),
                "biscuit": self.headers.get("x-sam-biscuit"),
                "encoding": self.headers.get("accept-encoding"),
            }
        )
        if self.path == f"/{AGENT_CARD_PATH}" and self.headers.get("x-card") == "missing":
            self.send_response(404)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", "7")
            self.end_headers()
            self.wfile.write(b"no card")
            return
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for i in range(3):
                self.wfile.write(f"data: {json.dumps({'event': i})}\n\n".encode())
                self.wfile.flush()
            return
        if self.path == f"/{AGENT_CARD_PATH}":
            grpc_only = self.headers.get("x-card") == "grpc-only"
            interfaces = [i for i in STOCK_CARD["supportedInterfaces"] if not grpc_only or i["protocolBinding"] == "GRPC"]
            payload = json.dumps({**STOCK_CARD, "supportedInterfaces": interfaces}).encode()
        else:
            payload = json.dumps({"path": self.path, "echo": body.decode()}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("x-backend", "fake")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _answer
    do_POST = _answer

    def log_message(self, *_args) -> None:  # noqa: D102 - quiet
        pass


@pytest.fixture(scope="module")
def backend_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeA2AServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


async def start_agent(nursery, target, authorized: list[str]):
    identity = Identity.generate()
    host = libp2p_host(identity)
    biscuit = mint(identity.peer_id, ROLE_NODE)
    options = ProviderOptions(
        authorizer=ProviderAuthorizerOptions(trusted_keys=lambda: [CP_KEY], own_biscuit=lambda: biscuit, policy_rules=lambda: POLICY_RULES),
        on_authorized=lambda peer, _v, service: authorized.append(f"{peer} {service}"),
    )
    host.set_stream_handler(HTTP_PROTOCOL, http_ingress_handler(A2AEndpoint(target=target), options))
    started = trio.Event()
    addr_box = []

    async def run():
        async with host.run(listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]):
            addr_box.append(multiaddr.Multiaddr(f"{host.get_addrs()[0]}"))
            started.set()
            await trio.sleep_forever()

    nursery.start_soon(run)
    await started.wait()
    return host, addr_box[0]


@dataclass
class _Credential:
    biscuit: bytes


@dataclass
class _Mesh:
    credential: _Credential


class FakeSession:
    """What MeshTransport needs of a session: the host, the credential and
    _egress_peer(); the peer is already connected and verified here."""

    def __init__(self, host, biscuit: bytes) -> None:
        self.host = host
        self.mesh = _Mesh(_Credential(biscuit))

    async def _egress_peer(self, peer) -> ID:
        return ID.from_base58(str(peer))


def test_the_agent_is_reachable_by_authorized_callers(backend_url):
    authorized: list[str] = []

    async def main():
        async with trio.open_nursery() as nursery:
            agent, addr = await start_agent(nursery, backend_url, authorized)
            caller_identity = Identity.generate()
            caller = libp2p_host(caller_identity)
            caller_biscuit = mint(caller_identity.peer_id, ROLE_NODE)
            guest_biscuit = mint(caller_identity.peer_id, "sam:role:guest")
            async with caller.run(listen_addrs=[]):
                await caller.connect(info_from_p2p_addr(addr))
                pid = agent.get_id()

                # The agent is forwarded the request with the caller's identity and without its biscuit.
                res = await http_request_over_stream(caller, pid, caller_biscuit, "a2a://agent", "/card?x=1", headers={"x-sam-biscuit": "spoof"})
                assert res.status == 200
                assert res.headers.get("x-backend") == "fake"
                assert res.json() == {"path": "/card?x=1", "echo": ""}
                assert FakeA2AServer.seen[-1]["peer"] == caller_identity.peer_id
                assert FakeA2AServer.seen[-1]["biscuit"] is None
                assert f"{caller_identity.peer_id} a2a://agent" in authorized
                post = await http_request_over_stream(
                    caller, pid, caller_biscuit, "a2a://agent", "/", method="POST", headers={"content-type": "application/json"}, body='{"jsonrpc": "2.0"}'
                )
                assert post.status == 200 and post.json()["echo"] == '{"jsonrpc": "2.0"}'

                # A streamed body arrives event by event.
                streamed = await open_http_request(caller, pid, caller_biscuit, "GET", mesh_http_target("a2a://agent", "/stream"))
                assert streamed.status == 200 and streamed.headers["content-type"] == "text/event-stream"
                events = []
                async for chunk in streamed.iter_body():
                    events.extend(line for line in chunk.decode().split("\n") if line.startswith("data:"))
                await streamed.aclose()
                assert events == ['data: {"event": 0}', 'data: {"event": 1}', 'data: {"event": 2}']

                # An httpx client on the mesh transport, as the A2A SDK's client is.
                session = FakeSession(caller, caller_biscuit)
                url = MeshSession.mesh_url(str(pid), "a2a://agent")
                assert url == f"http://mesh/sam/{pid}/a2a/agent"
                async with httpx.AsyncClient(transport=MeshTransport(session)) as client:  # type: ignore[arg-type]
                    answer = await client.post(url, json={"method": "message/send"}, headers={"x-sam-biscuit": "spoof"})
                    assert answer.status_code == 200 and answer.json()["echo"] == '{"method":"message/send"}'
                    assert FakeA2AServer.seen[-1]["peer"] == caller_identity.peer_id
                    assert FakeA2AServer.seen[-1]["biscuit"] is None
                    async with client.stream("GET", url + "/stream") as answer:
                        lines = [line async for line in answer.aiter_lines() if line.startswith("data:")]
                    assert lines == ['data: {"event": 0}', 'data: {"event": 1}', 'data: {"event": 2}']
                    with pytest.raises(httpx.UnsupportedProtocol):
                        await client.get("http://mesh/not/the/mesh")

                # What the policy does not grant is refused before the agent is reached.
                before = len(FakeA2AServer.seen)
                assert (await http_request_over_stream(caller, pid, guest_biscuit, "a2a://agent", "/card")).status == 403
                assert (await http_request_over_stream(caller, pid, caller_biscuit, "inference://agent", "/")).status == 403
                assert len(FakeA2AServer.seen) == before
                # Granted, but not this agent: 404 after authorization.
                assert (await http_request_over_stream(caller, pid, caller_biscuit, "a2a://other", "/card")).status == 404
                assert (await http_request_over_stream(caller, pid, b"", "a2a://agent", "/card")).status == 401
                assert (await http_request_over_stream(caller, pid, caller_biscuit, "a2a://agent", "/../other/x")).status == 400
                # A URL parser reads %2e as a dot too; the spelling does not get past the check.
                assert (await http_request_over_stream(caller, pid, caller_biscuit, "a2a://agent", "/%2e%2e/other/x")).status == 400
                assert (await http_request_over_stream(caller, pid, caller_biscuit, "a2a://agent", "/.%2E/other/x")).status == 400
            nursery.cancel_scope.cancel()

    async def with_timeout():
        with trio.fail_after(30):
            await main()

    trio.run(with_timeout)


def test_the_card_of_an_agent_behind_a_node_comes_back_rewritten_for_the_mesh(backend_url):
    async def main():
        async with trio.open_nursery() as nursery:
            agent, addr = await start_agent(nursery, backend_url, [])
            caller_identity = Identity.generate()
            caller = libp2p_host(caller_identity)
            caller_biscuit = mint(caller_identity.peer_id, ROLE_NODE)
            async with caller.run(listen_addrs=[]):
                await caller.connect(info_from_p2p_addr(addr))
                pid = agent.get_id()
                base = MeshSession.mesh_url(str(pid), "a2a://agent")
                async with httpx.AsyncClient(transport=MeshTransport(FakeSession(caller, caller_biscuit))) as client:  # type: ignore[arg-type]
                    answer = await client.get(f"{base}/{AGENT_CARD_PATH}")
                    assert answer.status_code == 200 and answer.headers["content-type"] == "application/json"
                    card = answer.json()
                    assert card["supportedInterfaces"] == [{"url": base, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]
                    assert card["capabilities"] == {"streaming": True, "pushNotifications": False}
                    assert "signatures" not in card and card["name"] == "echo-agent" and card["skills"] == []
                    assert FakeA2AServer.seen[-1]["path"] == f"/{AGENT_CARD_PATH}"
                    # The bare service root serves the card too, the way a2a-go resolves a pathful base URL,
                    # and the fetch is the SDK's own: at the well-known path, without the client's accept-encoding.
                    assert (await client.get(base, headers={"accept-encoding": "x-test-only"})).json() == card
                    assert FakeA2AServer.seen[-1]["path"] == f"/{AGENT_CARD_PATH}" and FakeA2AServer.seen[-1]["encoding"] != "x-test-only"
                    missing = await client.get(f"{base}/{AGENT_CARD_PATH}", headers={"x-card": "missing"})
                    assert missing.status_code == 404 and missing.text == "no card"
                    refused = await client.get(f"{base}/{AGENT_CARD_PATH}", headers={"x-card": "grpc-only"})
                    assert refused.status_code == 502 and "no supported interface the mesh can carry" in refused.text
                    assert (await client.get(f"{base}/card")).json() == {"path": "/card", "echo": ""}
                raw = await http_request_over_stream(caller, pid, caller_biscuit, "a2a://agent", f"/{AGENT_CARD_PATH}")
                assert raw.status == 200 and raw.json() == card
            nursery.cancel_scope.cancel()

    async def with_timeout():
        with trio.fail_after(30):
            await main()

    trio.run(with_timeout)


def test_rewrite_agent_card_keeps_only_what_the_mesh_carries():
    with pytest.raises(ValueError, match="not a JSON object"):
        rewrite_agent_card([], "http://mesh/x")
    with pytest.raises(ValueError, match="no supported interface"):
        rewrite_agent_card({"supportedInterfaces": []}, "http://mesh/x")
    assert rewrite_agent_card({"supportedInterfaces": [{"url": "x", "protocolBinding": "http+json"}]}, "http://mesh/x") == {
        "supportedInterfaces": [{"url": "http://mesh/x", "protocolBinding": "http+json"}],
    }


def test_an_in_process_handler_sees_the_verified_caller():
    async def hello(request: HTTPRequest, caller) -> HTTPResponse:
        return HTTPResponse(status=201, body=f"hello {caller.peer_id} {request.method} {request.path}".encode())

    async def main():
        async with trio.open_nursery() as nursery:
            agent, addr = await start_agent(nursery, hello, [])
            caller_identity = Identity.generate()
            caller = libp2p_host(caller_identity)
            async with caller.run(listen_addrs=[]):
                await caller.connect(info_from_p2p_addr(addr))
                res = await http_request_over_stream(caller, agent.get_id(), mint(caller_identity.peer_id, ROLE_NODE), "a2a://agent", "/agent/card")
                assert res.status == 201 and res.text == f"hello {caller_identity.peer_id} GET /agent/card"
            nursery.cancel_scope.cancel()

    async def with_timeout():
        with trio.fail_after(30):
            await main()

    trio.run(with_timeout)


def test_mesh_urls_name_a_peer_and_a_service():
    peer = "12D3KooWJ2Yhy3CKwVPDw7AnkxN5HbZbb65xDoRif54hdXXUzh1U"
    assert split_mesh_url(httpx.URL(f"http://mesh/sam/{peer}/a2a/agent")) == (peer, "/a2a/agent")
    assert split_mesh_url(httpx.URL(f"http://anything:1/sam/{peer}/inference/llm/v1/models?x=1")) == (peer, "/inference/llm/v1/models?x=1")
    for bad in ("http://mesh/a2a/agent", f"http://mesh/sam/{peer}", f"http://mesh/sam/{peer}/a2a", f"http://mesh/sam//a2a/agent"):
        with pytest.raises(httpx.UnsupportedProtocol):
            split_mesh_url(httpx.URL(bad))
    assert mesh_http_target("a2a://agent") == "/a2a/agent"
    assert mesh_http_target("a2a://agent", "card") == "/a2a/agent/card"
    assert mesh_http_target("egress://api.github.com", "/repos/acme/x") == "/egress/api.github.com/repos/acme/x"
    with pytest.raises(ValueError):
        mesh_http_target("ftp://agent", "/")


def test_a_reset_mid_body_is_an_error_and_a_close_is_the_end():
    """A body that arrives without a length (server-sent events) ends when
    the peer closes its side. The same body cut by a reset must not pass for
    one that ended: without a length there is nothing in HTTP to tell them
    apart, only the stream knows."""

    async def truncating(stream) -> None:
        # Same framing as `closing`, reset instead of closed.
        await stream.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\ndata: 1\n\n")
        await stream.reset()

    async def closing(stream) -> None:
        # No length and no chunking: the close is the end of the body.
        await stream.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\ndata: 1\n\ndata: 2\n\n")
        await stream.close()

    async def main():
        async with trio.open_nursery() as nursery:
            server = libp2p_host(Identity.generate())
            handlers = {"/inference/cut": truncating, "/inference/end": closing}

            async def route(stream) -> None:
                request = b""
                while b"\r\n\r\n" not in request:
                    request += await stream.read(1024)
                path = request.split(b" ", 2)[1].decode()
                await handlers[path](stream)

            server.set_stream_handler(HTTP_PROTOCOL, route)
            started = trio.Event()
            addr_box = []

            async def run():
                async with server.run(listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]):
                    addr_box.append(multiaddr.Multiaddr(f"{server.get_addrs()[0]}"))
                    started.set()
                    await trio.sleep_forever()

            nursery.start_soon(run)
            await started.wait()
            caller = libp2p_host(Identity.generate())
            async with caller.run(listen_addrs=[]):
                await caller.connect(info_from_p2p_addr(addr_box[0]))
                pid = server.get_id()
                with trio.fail_after(10):
                    ended = await open_http_request(caller, pid, b"x", "GET", "/inference/end")
                    assert ended.status == 200
                    assert (await ended.read()).decode().count("data:") == 2
                    await ended.aclose()

                    cut = await open_http_request(caller, pid, b"x", "GET", "/inference/cut")
                    assert cut.status == 200
                    with pytest.raises(ConnectionError, match="mid-response"):
                        await cut.read()
                    await cut.aclose()
            nursery.cancel_scope.cancel()

    trio.run(main)
