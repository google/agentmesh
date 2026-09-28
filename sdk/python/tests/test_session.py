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

"""A mesh in one process: a fake control plane behind the transport hook, a
fake router (py-libp2p with the auth handshake and a hop handler) and a peer
that dials the member directly. The real router and control plane are
exercised by tests/integration/sdk_join_test.go."""

import time
import urllib.parse

import biscuit_auth as ba
import httpx
import multiaddr
import pytest
import trio
import trio.testing
from libp2p import new_host
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.custom_types import TProtocol
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.security.tls.transport import PROTOCOL_ID as TLS_PROTOCOL_ID
from libp2p.security.tls.transport import TLSTransport
from libp2p.stream_muxer.yamux.yamux import PROTOCOL_ID as YAMUX_PROTOCOL_ID
from libp2p.stream_muxer.yamux.yamux import Yamux
from libp2p.utils.varint import encode_varint_prefixed, read_varint_prefixed_bytes

from agent_mesh._proto import circuit_pb2 as circuit
from agent_mesh._proto import sam_pb2 as pb
from agent_mesh.auth import AUTH_PROTOCOL, auth_stream_handler, authenticate_with_peer
from agent_mesh.authorizer import ProviderAuthorizerOptions
from agent_mesh.biscuit import ROLE_ROUTER, BiscuitVerificationError
from agent_mesh.controlplane import ROLE_NODE
from agent_mesh.httpx_transport import MeshTransport
from agent_mesh.identity import Identity
from agent_mesh.libp2p_http import HTTP_PROTOCOL, A2AEndpoint, HTTPResponse, ProviderOptions, http_ingress_handler
from agent_mesh.mcp_client import LabelsNotSatisfiedError
from agent_mesh.mesh import AgentMesh
from agent_mesh.relay import HOP_PROTOCOL as RELAY_HOP_PROTOCOL
from agent_mesh.session import MeshSession
from google.protobuf.timestamp_pb2 import Timestamp


def _ts_ms(ms: int) -> Timestamp:
    t = Timestamp()
    t.FromMilliseconds(int(ms))
    return t


def _ts_s(seconds: int) -> Timestamp:
    t = Timestamp()
    t.FromSeconds(int(seconds))
    return t

CP = ba.KeyPair()
CP_KEY = CP.public_key.to_bytes()


def mint(peer_id: str, role: str, expiration: str = "2035-01-01T00:00:00Z", labels: dict[str, str] | None = None) -> bytes:
    code = "node({p}); client_peer_id({p}); expiration(" + expiration + "); role({r});"
    params = {"p": peer_id, "r": role}
    for i, (k, v) in enumerate((labels or {}).items()):
        code += f" label({{k{i}}}, {{v{i}}});"
        params[f"k{i}"] = k
        params[f"v{i}"] = v
    return ba.BiscuitBuilder(code, params).build(CP.private_key).to_bytes()


# What the control plane renders for a policy granting the node role every
# A2A service on any target, and nothing else.
POLICY_RULES = [
    'granted_service_all("a2a") <- role("sam:role:node")',
    'granted_service_all("sam:system") <- role("sam:role:node")',
    'target_unrestricted(true) <- role("sam:role:node")',
]


def fake_control_plane(router_addresses):
    """Approves every enrollment with a biscuit bound to the requesting peer."""

    def transport(method, url, headers, body):
        path = urllib.parse.urlsplit(url).path
        if (method, path) == ("POST", "/enroll"):
            req = pb.BootstrapEnrollRequest.FromString(body)
            return 200, pb.BootstrapEnrollResponse(
                status=pb.ENROLLMENT_STATUS_APPROVED,
                biscuit_token=mint(req.peer_id, ROLE_NODE),
                control_plane_public_key=CP_KEY,
                router_addresses=router_addresses,
                expire_time=_ts_s(int(time.time()) + 3600),
            ).SerializeToString()
        if (method, path) == ("GET", "/keys"):
            # Unsigned: the client keeps the enrollment key when /keys cannot be verified.
            return 200, pb.KeysResponse(public_keys=[CP_KEY], sign_time=_ts_ms(int(time.time() * 1000))).SerializeToString()
        return 404, f"no route for {method} {path}".encode()

    return transport


def libp2p_host(identity: Identity):
    kp = create_new_key_pair(identity.seed)
    return new_host(
        key_pair=kp,
        sec_opt={TLS_PROTOCOL_ID: TLSTransport(kp)},
        muxer_opt={TProtocol(YAMUX_PROTOCOL_ID): Yamux},
    )


def hop_handler(relay_addr: str, grants, ttl: int = 3600, events=None):
    """Answers RESERVE like a go-libp2p relay whose ACL either admits or refuses
    us; `grants` is a bool or a callable of the RESERVE count so far."""
    reserves = 0

    async def handle(stream):
        nonlocal reserves
        req = circuit.HopMessage.FromString(await read_varint_prefixed_bytes(stream))
        assert req.type == circuit.HopMessage.RESERVE
        reserves += 1
        if events is not None:
            events.append(("reserve", str(stream.muxed_conn.peer_id)))
        if grants(reserves) if callable(grants) else grants:
            resp = circuit.HopMessage(
                type=circuit.HopMessage.STATUS,
                status=circuit.OK,
                reservation=circuit.Reservation(expire=int(time.time()) + ttl, addrs=[multiaddr.Multiaddr(relay_addr).to_bytes()]),
            )
        else:
            resp = circuit.HopMessage(type=circuit.HopMessage.STATUS, status=circuit.PERMISSION_DENIED)
        await stream.write(encode_varint_prefixed(resp.SerializeToString()))
        await stream.close()

    return handle


async def start_router(nursery, role=ROLE_ROUTER, trusted=(CP_KEY,), grants=True, ttl=3600, events=None):
    """events, when given, records ("auth", peer) per handshake and ("reserve", peer) per RESERVE."""
    identity = Identity.generate()
    router = libp2p_host(identity)
    router_biscuit = mint(identity.peer_id, role)

    def on_authenticated(peer, _verified):
        if events is not None:
            events.append(("auth", peer))

    router.set_stream_handler(AUTH_PROTOCOL, auth_stream_handler(lambda: router_biscuit, lambda: list(trusted), on_authenticated=on_authenticated))
    started = trio.Event()
    addr_box = []

    async def run():
        async with router.run(listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]):
            addr = f"{router.get_addrs()[0]}"
            router.set_stream_handler(RELAY_HOP_PROTOCOL, hop_handler(addr, grants, ttl, events))
            addr_box.append(addr)
            started.set()
            await trio.sleep_forever()

    nursery.start_soon(run)
    await started.wait()
    return router, addr_box[0]


async def start_provider(nursery, biscuit_for, handshakes: list[str]):
    """A provider answering /sam/auth and /libp2p-http as a member does, with
    whatever credential biscuit_for gives it; the handshakes it answers are
    recorded in handshakes."""
    identity = Identity.generate()
    host = libp2p_host(identity)
    biscuit = biscuit_for(identity.peer_id)
    host.set_stream_handler(AUTH_PROTOCOL, auth_stream_handler(lambda: biscuit, lambda: [CP_KEY], on_authenticated=lambda peer, _v: handshakes.append(peer)))

    async def card(_request, _caller) -> HTTPResponse:
        return HTTPResponse(status=200, body=b'{"ok": true}')

    options = ProviderOptions(authorizer=ProviderAuthorizerOptions(trusted_keys=lambda: [CP_KEY], own_biscuit=lambda: biscuit, policy_rules=lambda: POLICY_RULES))
    host.set_stream_handler(HTTP_PROTOCOL, http_ingress_handler(A2AEndpoint(target=card), options))
    started = trio.Event()
    addr_box = []

    async def run():
        async with host.run(listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]):
            addr_box.append(f"{host.get_addrs()[0]}")
            started.set()
            await trio.sleep_forever()

    nursery.start_soon(run)
    await started.wait()
    return host, addr_box[0]


async def with_timeout(seconds, fn):
    with trio.fail_after(seconds):
        return await fn()


def test_join_authenticates_reserves_and_answers_peers():
    async def main():
        async with trio.open_nursery() as nursery:
            router, router_addr = await start_router(nursery)
            assert "/p2p/12D3Koo" in router_addr

            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([router_addr]))
            async with mesh.join(listen_addrs=["/ip4/127.0.0.1/tcp/0"], refresh_lead=0) as session:
                assert [r.peer_id for r in session.routers] == [str(router.get_id())]
                assert ROLE_ROUTER in session.routers[0].credential.roles
                assert session.relay_addresses == [f"{router_addr}/p2p-circuit/p2p/{mesh.peer_id}"]

                # A peer dials the member and both sides verify each other.
                peer_identity = Identity.generate()
                peer = libp2p_host(peer_identity)
                async with peer.run(listen_addrs=[]):
                    member_addr = multiaddr.Multiaddr(f"{session.host.get_addrs()[0]}")
                    await peer.connect(info_from_p2p_addr(member_addr))
                    frame = pb.AuthFrame(biscuit=mint(peer_identity.peer_id, ROLE_NODE)).SerializeToString()
                    member = await authenticate_with_peer(peer, session.host.get_id(), frame, [CP_KEY])
                    assert member.peer_id == mesh.peer_id
                    assert member.roles == [ROLE_NODE]
                    assert session.authenticated_peers[peer_identity.peer_id].year == 2035

                    # A forged credential gets no answer, only a closed stream.
                    forged = ba.KeyPair()
                    forged_frame = pb.AuthFrame(
                        biscuit=ba.BiscuitBuilder("node({p}); expiration(2035-01-01T00:00:00Z);", {"p": peer_identity.peer_id}).build(forged.private_key).to_bytes()
                    ).SerializeToString()
                    with pytest.raises(Exception):
                        await authenticate_with_peer(peer, session.host.get_id(), forged_frame, [CP_KEY])
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)


def test_join_fails_closed_when_the_router_is_not_a_router():
    async def main():
        async with trio.open_nursery() as nursery:
            _, addr = await start_router(nursery, role=ROLE_NODE)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr]))
            with pytest.raises(RuntimeError, match="lacks expected role 'sam:role:router'"):
                async with mesh.join():
                    pass
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)


def test_join_reports_a_router_that_refuses_the_handshake():
    async def main():
        async with trio.open_nursery() as nursery:
            # Trusts a different control plane, so our credential never verifies.
            _, addr = await start_router(nursery, trusted=(ba.KeyPair().public_key.to_bytes(),))
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr]))
            with pytest.raises(RuntimeError, match="no router admitted this member"):
                async with mesh.join():
                    pass
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)


def test_join_fails_when_the_relay_refuses_the_reservation():
    async def main():
        async with trio.open_nursery() as nursery:
            _, addr = await start_router(nursery, grants=False)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr]))
            with pytest.raises(RuntimeError, match="PERMISSION_DENIED"):
                async with mesh.join():
                    pass
            # Without a reservation the member still joins.
            async with mesh.join(reserve=False) as session:
                assert session.routers[0].reservation is None
                assert session.relay_addresses == []
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)


def test_join_admits_every_router_and_reserves_on_the_first():
    """A peer reserves its relay slot on the first router of its list; a
    caller reaches it only through that router. So the member authenticates
    with every router the control plane named and connect() can try each,
    while one reservation is enough to be reachable."""

    async def main():
        async with trio.open_nursery() as nursery:
            events = []
            router_a, addr_a = await start_router(nursery, events=events)
            router_b, addr_b = await start_router(nursery, events=events)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr_a, addr_b]))
            async with mesh.join(refresh_lead=0) as session:
                assert [r.peer_id for r in session.routers] == [str(router_a.get_id()), str(router_b.get_id())]
                assert [r.reservation is not None for r in session.routers] == [True, False]
                assert session.relay_addresses == [f"{addr_a}/p2p-circuit/p2p/{mesh.peer_id}"]
                assert events.count(("auth", mesh.peer_id)) == 2
                assert events.count(("reserve", mesh.peer_id)) == 1
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)


def test_a_router_nobody_answers_costs_join_one_dial_timeout(monkeypatch):
    """The control plane may list a router this member cannot reach (a
    public address a network policy drops). Every router is dialed at once,
    so join ends at DIAL_TIMEOUT whatever the dark one's position, and the
    reservation still goes to the first *admitted* router of the list."""
    from agent_mesh import session as session_module
    from agent_mesh.host import DIAL_TIMEOUT

    dark = "/ip4/203.0.113.7/tcp/4501/p2p/12D3KooWGvdRCJLYATauVWfsieF2j3a2wXZoEQJUS2MsvRdDtgLM"
    router_a = "/ip4/10.0.0.1/tcp/4501/p2p/12D3KooWG1pA6goegCncqwbZLSr8pnjUZ6JMAAe6SmnHTgUNCk88"
    router_b = "/ip4/10.0.0.2/tcp/4501/p2p/12D3KooWBTdQ3QQZztZFaxQSTzJx5ZSbpgM8zfs43VYzBXAFkdZm"
    reserved = []

    class Host:
        async def connect(self, info):
            if str(info.addrs[0]).startswith("/ip4/203.0.113.7/"):
                await trio.sleep_forever()

    async def authenticated(host, mesh, peer_id):
        return f"credential of {peer_id}"

    async def reserve(host, peer_id):
        reserved.append(str(peer_id))
        return circuit.Reservation()

    monkeypatch.setattr(session_module, "_authenticate_router", authenticated)
    monkeypatch.setattr(session_module, "reserve_relay", reserve)

    async def main():
        started = trio.current_time()
        routers = await session_module._admit(Host(), None, [multiaddr.Multiaddr(a) for a in (dark, router_a, router_b)], reserve=True)
        assert trio.current_time() - started == pytest.approx(DIAL_TIMEOUT)
        assert [r.peer_id[-6:] for r in routers] == ["UNCk88", "AFkdZm"]
        assert [r.reservation is not None for r in routers] == [True, False]
        assert [p[-6:] for p in reserved] == ["UNCk88"]

    trio.run(main, clock=trio.testing.MockClock(autojump_threshold=0))


def test_a_dropped_router_connection_is_reserved_again_before_the_ttl():
    """A router restart takes the reservation with the connection. The member
    notices within the check interval and reserves again, authenticated
    anew, long before the TTL would have had it renew."""

    async def wait_for(predicate):
        while not predicate():
            await trio.sleep(0.1)

    async def main():
        async with trio.open_nursery() as nursery:
            events = []
            router, addr = await start_router(nursery, ttl=3600, events=events)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr]))
            async with mesh.join(refresh_lead=0, reservation_check_interval=0.5) as session:
                member = session.host.get_id()
                assert events == [("auth", mesh.peer_id), ("reserve", mesh.peer_id)]

                await router.disconnect(member)
                await wait_for(lambda: member not in router.get_connected_peers())
                await wait_for(lambda: events.count(("reserve", mesh.peer_id)) >= 2)
                assert events[2:] == [("auth", mesh.peer_id), ("reserve", mesh.peer_id)]
                assert member in router.get_connected_peers()
                assert session.relay_addresses == [f"{addr}/p2p-circuit/p2p/{mesh.peer_id}"]
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 60, main)


def test_join_renews_the_reservation_and_reauthenticates_after_a_disconnect():
    """go-libp2p's relay drops a reservation when its TTL passes and grants one
    only to a peer authenticated on the current connection. The member renews
    ahead of the TTL; once the router has closed the connection, the renewal
    runs the handshake again first."""

    async def wait_for(predicate):
        while not predicate():
            await trio.sleep(0.1)

    async def main():
        async with trio.open_nursery() as nursery:
            events = []
            router, addr = await start_router(nursery, ttl=4, events=events)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr]))
            async with mesh.join(refresh_lead=0, reservation_lead=1) as session:
                member = session.host.get_id()
                assert events == [("auth", mesh.peer_id), ("reserve", mesh.peer_id)]
                first = session.routers[0].reservation.expire

                # Renewed before the TTL, on the same admission.
                await wait_for(lambda: events.count(("reserve", mesh.peer_id)) >= 2)
                assert events.count(("auth", mesh.peer_id)) == 1
                assert session.routers[0].reservation.expire >= first
                assert session.relay_addresses == [f"{addr}/p2p-circuit/p2p/{mesh.peer_id}"]

                # The router drops the connection and with it the admission.
                await router.disconnect(member)
                await wait_for(lambda: member not in router.get_connected_peers())
                reserves = events.count(("reserve", mesh.peer_id))
                await wait_for(lambda: events.count(("reserve", mesh.peer_id)) > reserves)
                assert events.count(("auth", mesh.peer_id)) == 2
                assert events.index(("auth", mesh.peer_id), 2) < len(events) - 1
                assert member in router.get_connected_peers()
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 60, main)


def test_a_refused_renewal_drops_the_connection_and_the_retry_authenticates_again():
    """A router that refuses the renewal, PERMISSION_DENIED when it no longer
    holds the admission, gets a fresh connection and handshake on the retry
    instead of the same RESERVE on the same connection forever."""

    async def wait_for(predicate):
        while not predicate():
            await trio.sleep(0.1)

    async def main():
        async with trio.open_nursery() as nursery:
            events = []
            _, addr = await start_router(nursery, grants=lambda n: n != 2, ttl=4, events=events)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr]))
            async with mesh.join(refresh_lead=0, refresh_retry=0.5, reservation_lead=1) as session:
                first = session.routers[0].reservation.expire
                await wait_for(lambda: events.count(("reserve", mesh.peer_id)) >= 3)
                await wait_for(lambda: session.routers[0].reservation.expire > first)
                auth, reserve = ("auth", mesh.peer_id), ("reserve", mesh.peer_id)
                assert events[:5] == [auth, reserve, reserve, auth, reserve]
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 60, main)


def test_an_egress_floor_stated_at_join_is_held_on_the_http_path():
    """The floor is held on request() and on MeshTransport, and the provider
    is verified as an enrolled member with or without one."""

    async def main():
        async with trio.open_nursery() as nursery:
            _, router_addr = await start_router(nursery)
            handshakes: list[str] = []
            provider, provider_addr = await start_provider(nursery, lambda p: mint(p, ROLE_NODE, labels={"region": "eu"}), handshakes)
            # Enrolled nowhere: a credential no trusted key signed.
            forged = ba.KeyPair()
            _, impostor_addr = await start_provider(
                nursery, lambda p: ba.BiscuitBuilder("node({p}); expiration(2035-01-01T00:00:00Z);", {"p": p}).build(forged.private_key).to_bytes(), handshakes
            )

            def join(**options):
                mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([router_addr]))
                return mesh.join(reserve=False, refresh_lead=0, **options)

            async with join(egress_require_labels={"region": "eu"}) as held, join(egress_require_labels={"region": "eu", "team": "platform"}) as missed, join() as plain:
                card = MeshSession.mesh_url(str(provider.get_id()), "a2a://agent", "/card")
                # Met: one handshake verifies the provider; the verdict is kept for the next calls.
                assert (await held.request(provider_addr, "a2a://agent", "/card")).status == 200
                assert (await held.request(provider_addr, "a2a://agent", "/card")).status == 200
                async with httpx.AsyncClient(transport=MeshTransport(held)) as client:
                    assert (await client.get(card)).status_code == 200
                assert handshakes == [held.peer_id]

                # Missed: every path refuses, and a refusal is not kept: each call asks again.
                with pytest.raises(LabelsNotSatisfiedError):
                    await missed.request(provider_addr, "a2a://agent", "/card")
                async with httpx.AsyncClient(transport=MeshTransport(missed)) as client:
                    with pytest.raises(LabelsNotSatisfiedError):
                        await client.get(card)
                assert handshakes == [held.peer_id, missed.peer_id, missed.peer_id]

                # No floor: no gate, but the provider is verified all the same.
                assert (await plain.request(provider_addr, "a2a://agent", "/card")).status == 200
                with pytest.raises(BiscuitVerificationError):
                    await plain.request(impostor_addr, "a2a://agent", "/card")
                # A banned provider is refused before any handshake.
                plain.banned.add(str(provider.get_id()), int(time.time() * 1000))
                with pytest.raises(PermissionError, match="banned"):
                    await plain.request(provider_addr, "a2a://agent", "/card")
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 60, main)
