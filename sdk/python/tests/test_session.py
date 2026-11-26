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
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.peer.peerstore import PeerStore
from libp2p.security.tls.transport import PROTOCOL_ID as TLS_PROTOCOL_ID
from libp2p.security.tls.transport import TLSTransport
from libp2p.stream_muxer.yamux.yamux import PROTOCOL_ID as YAMUX_PROTOCOL_ID
from libp2p.stream_muxer.yamux.yamux import Yamux
from libp2p.utils.varint import encode_varint_prefixed, read_varint_prefixed_bytes

from agent_mesh._proto import circuit_pb2 as circuit
from agent_mesh._proto import agentmesh_pb2 as pb
from agent_mesh.auth import (
    AUTH_PROTOCOL,
    GOAWAY_MAX_RETRY_AFTER,
    GOAWAY_PROTOCOL,
    ROUTER_SHUN_DURATION,
    auth_stream_handler,
    authenticate_with_peer,
    clamp_go_away_retry_after,
)
from agent_mesh.authorizer import ProviderAuthorizerOptions
from agent_mesh.biscuit import ROLE_ROUTER, BiscuitVerificationError
from agent_mesh.controlplane import ROLE_NODE
from agent_mesh.discovery import DIRECTORY_PROTOCOL, DiscoveredProvider, peer_key
from agent_mesh.httpx_transport import MeshTransport
from agent_mesh.identity import Identity
from agent_mesh.libp2p_http import HTTP_PROTOCOL, A2AEndpoint, HTTPResponse, ProviderOptions, http_ingress_handler
from agent_mesh.mcp_client import LabelsNotSatisfiedError
from agent_mesh.mesh import AgentMesh
from agent_mesh.relay import HOP_PROTOCOL as RELAY_HOP_PROTOCOL
from agent_mesh.session import AdmittedRouter, MeshSession, candidates_from_router_infos, select_routers
from google.protobuf.duration_pb2 import Duration
from google.protobuf.timestamp_pb2 import Timestamp


def _ts_ms(ms: int) -> Timestamp:
    t = Timestamp()
    t.FromMilliseconds(int(ms))
    return t


def _ts_s(seconds: int) -> Timestamp:
    t = Timestamp()
    t.FromSeconds(int(seconds))
    return t

# The control plane's signing key, as an Identity so a test can sign /keys
# with it and as the biscuit key pair that mints credentials.
CP_IDENTITY = Identity.generate()
CP = ba.KeyPair.from_private_key(ba.PrivateKey.from_bytes(CP_IDENTITY.seed, ba.Algorithm.Ed25519))
CP_KEY = CP.public_key.to_bytes()


def mint(peer_id: str, role: str, expiration: str = "2035-01-01T00:00:00Z", labels: dict[str, str] | None = None, signer: ba.KeyPair = CP) -> bytes:
    code = "node({p}); client_peer_id({p}); expiration(" + expiration + "); role({r});"
    if role == ROLE_NODE:
        # The node role of these meshes serves everything.
        code += " granted_publish_all_types(true);"
    params = {"p": peer_id, "r": role}
    for i, (k, v) in enumerate((labels or {}).items()):
        code += f" label({{k{i}}}, {{v{i}}});"
        params[f"k{i}"] = k
        params[f"v{i}"] = v
    return ba.BiscuitBuilder(code, params).build(signer.private_key).to_bytes()


# What the control plane renders for a policy granting the node role every
# A2A service on any target, and nothing else.
POLICY_RULES = [
    'granted_service_all("a2a") <- role("mesh:role:node")',
    'granted_service_all("mesh:system") <- role("mesh:role:node")',
    'target_unrestricted(true) <- role("mesh:role:node")',
]


def fake_control_plane(router_addresses, routers=None):
    """Approves every enrollment with a biscuit bound to the requesting peer.
    /info lists router_addresses and routers as they are at the time of the
    request, so a test that changes the list has the member pull the change."""

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
        if (method, path) == ("GET", "/info"):
            return 200, pb.ControlPlaneInfoResponse(
                router_addresses=list(router_addresses),
                routers=list(routers) if routers is not None else [],
            ).SerializeToString()
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


async def start_router(nursery, role=ROLE_ROUTER, trusted=(CP_KEY,), grants=True, ttl=3600, events=None, identity=None, signer=CP):
    """events, when given, records ("auth", peer) per handshake and ("reserve", peer) per RESERVE."""
    identity = identity or Identity.generate()
    router = libp2p_host(identity)
    router_biscuit = mint(identity.peer_id, role, signer=signer)

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
    """A provider answering /mesh/auth and /libp2p-http as a member does, with
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


def test_a_resumed_member_adopts_a_rotated_key_before_admitting_routers(tmp_path):
    """The control plane rotated its signing key while this member was not
    running: the routers already hold credentials under the new key, and the
    state directory holds only the key the member enrolled under. join pulls
    /keys, signed by the retiring key too, before it authenticates a router."""
    rotated_identity = Identity.generate()
    rotated = ba.KeyPair.from_private_key(ba.PrivateKey.from_bytes(rotated_identity.seed, ba.Algorithm.Ed25519))
    rotated_key = rotated_identity.public_key_raw

    def control_plane_after_rotation():
        def transport(method, url, headers, body):
            path = urllib.parse.urlsplit(url).path
            if (method, path) == ("GET", "/keys"):
                ts = _ts_ms(int(time.time() * 1000))
                payload = pb.KeysResponse(public_keys=[CP_KEY, rotated_key], sign_time=ts).SerializeToString(deterministic=True)
                return 200, pb.KeysResponse(
                    public_keys=[CP_KEY, rotated_key],
                    sign_time=ts,
                    signatures=[CP_IDENTITY.sign(payload), rotated_identity.sign(payload)],
                ).SerializeToString()
            if (method, path) == ("POST", "/refresh"):
                peer_id = pb.TokenRefreshRequest.FromString(body).peer_id
                return 200, pb.TokenRefreshResponse(
                    biscuit_token=mint(peer_id, ROLE_NODE, signer=rotated), expire_time=_ts_s(int(time.time()) + 7200)
                ).SerializeToString()
            return 404, f"no route for {method} {path}".encode()

        return transport

    async def main():
        async with trio.open_nursery() as nursery:
            router, router_addr = await start_router(nursery, trusted=(CP_KEY, rotated_key), signer=rotated)
            # Enrolled before the rotation: the credential on disk trusts one key.
            before = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", state_dir=tmp_path, transport=fake_control_plane([router_addr]))
            assert [bytes(k) for k in before.credential.control_plane_keys] == [CP_KEY]

            # Resumed after it, with the routers now under the new key.
            resumed = AgentMesh.enroll("http://127.0.0.1:1", state_dir=tmp_path, transport=control_plane_after_rotation())
            assert resumed.credential.biscuit == before.credential.biscuit
            async with resumed.join(reserve=False) as session:
                assert [r.peer_id for r in session.routers] == [str(router.get_id())]
            assert {bytes(k) for k in resumed.credential.control_plane_keys} == {CP_KEY, rotated_key}
            assert resumed.credential.biscuit != before.credential.biscuit
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)


def test_join_fails_closed_when_the_router_is_not_a_router():
    async def main():
        async with trio.open_nursery() as nursery:
            _, addr = await start_router(nursery, role=ROLE_NODE)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr]))
            with pytest.raises(RuntimeError, match="lacks expected role 'mesh:role:router'"):
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
    """A member attaches to and reserves a relay slot on up to `routers`
    (default 2) chosen routers."""

    async def main():
        async with trio.open_nursery() as nursery:
            events = []
            router_a, addr_a = await start_router(nursery, events=events)
            router_b, addr_b = await start_router(nursery, events=events)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([addr_a, addr_b]))
            async with mesh.join(refresh_lead=0) as session:
                assert sorted(r.peer_id for r in session.routers) == sorted([str(router_a.get_id()), str(router_b.get_id())])
                assert [r.reservation is not None for r in session.routers] == [True, True]
                assert sorted(session.relay_addresses) == sorted([
                    f"{addr_a}/p2p-circuit/p2p/{mesh.peer_id}",
                    f"{addr_b}/p2p-circuit/p2p/{mesh.peer_id}",
                ])
                assert events.count(("auth", mesh.peer_id)) == 2
                assert events.count(("reserve", mesh.peer_id)) == 2
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)


def test_a_router_nobody_answers_costs_join_one_dial_timeout(monkeypatch):
    """The control plane may list a router this member cannot reach (a
    public address a network policy drops). Routers in the batch are dialed at
    once, so join ends at DIAL_TIMEOUT whatever the dark one's position, and
    reservations go to the admitted routers."""
    from agent_mesh import session as session_module
    from agent_mesh.host import DIAL_TIMEOUT

    dark = "/ip4/203.0.113.7/tcp/4501/p2p/12D3KooWGvdRCJLYATauVWfsieF2j3a2wXZoEQJUS2MsvRdDtgLM"
    router_a = "/ip4/10.0.0.1/tcp/4501/p2p/12D3KooWG1pA6goegCncqwbZLSr8pnjUZ6JMAAe6SmnHTgUNCk88"
    router_b = "/ip4/10.0.0.2/tcp/4501/p2p/12D3KooWBTdQ3QQZztZFaxQSTzJx5ZSbpgM8zfs43VYzBXAFkdZm"
    reserved = []

    class Host:
        def get_peerstore(self):
            return PeerStore()

        def get_network(self):
            return None

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
        assert [r.reservation is not None for r in routers] == [True, True]
        assert [p[-6:] for p in reserved] == ["UNCk88", "AFkdZm"]

    trio.run(main, clock=trio.testing.MockClock(autojump_threshold=0))


def test_connect_dials_the_routers_at_once():
    """A relay whose destination a rollout replaced answers a CONNECT only
    after its own timeout. The routers are dialed at once, so a dead peer
    costs the caller one such wait, not one per router, and the first
    circuit that opens ends the other attempts."""
    router_ids = [
        "12D3KooWG1pA6goegCncqwbZLSr8pnjUZ6JMAAe6SmnHTgUNCk88",
        "12D3KooWGvdRCJLYATauVWfsieF2j3a2wXZoEQJUS2MsvRdDtgLM",
        "12D3KooWBTdQ3QQZztZFaxQSTzJx5ZSbpgM8zfs43VYzBXAFkdZm",
    ]
    target = "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB"
    routers = [AdmittedRouter(peer_id=p, addr=multiaddr.Multiaddr(f"/ip4/10.0.0.{i}/tcp/4501/p2p/{p}"), credential=None) for i, p in enumerate(router_ids, 1)]  # type: ignore[arg-type]

    class Host:
        def get_connected_peers(self):
            return []

    session = MeshSession(mesh=None, host=Host(), routers=routers)  # type: ignore[arg-type]
    dialed: list[str] = []
    ended: list[str] = []

    def relay_of(ma) -> str:
        return str(ma).split("/p2p/")[1].split("/")[0][-6:]

    async def nothing(_target):
        return [], []

    session._routed_addresses = nothing  # type: ignore[method-assign]
    session._unjoined_routers = lambda _target: []  # type: ignore[method-assign]

    async def main():
        # Every relay waits on a destination that is gone.
        async def all_wait(ma):
            dialed.append(relay_of(ma))
            try:
                await trio.sleep(10)
            finally:
                ended.append(relay_of(ma))
            raise RuntimeError("CONNECTION_FAILED")

        session._connect_addr = all_wait  # type: ignore[method-assign]
        started = trio.current_time()
        with pytest.raises(ConnectionError) as err:
            await session.connect(target)
        assert trio.current_time() - started == pytest.approx(10)
        assert sorted(dialed) == sorted(p[-6:] for p in router_ids)
        assert str(err.value).count("CONNECTION_FAILED") == 3

        # One relays for the peer; its circuit ends the others' waits.
        dialed.clear()
        ended.clear()

        async def one_opens(ma):
            dialed.append(relay_of(ma))
            if relay_of(ma) == router_ids[1][-6:]:
                await trio.sleep(1)
                return ID.from_base58(target)
            try:
                await trio.sleep(10)
            finally:
                ended.append(relay_of(ma))
            raise RuntimeError("CONNECTION_FAILED")

        session._connect_addr = one_opens  # type: ignore[method-assign]
        started = trio.current_time()
        assert await session.connect(target) == ID.from_base58(target)
        assert trio.current_time() - started == pytest.approx(1)
        assert sorted(ended) == sorted(p[-6:] for p in (router_ids[0], router_ids[2]))

    trio.run(main, clock=trio.testing.MockClock(autojump_threshold=0))


def test_a_replaced_peer_costs_connect_one_dial_timeout_per_step(monkeypatch):
    """A provider record can name a pod a rollout replaced: its address
    answers nothing, the admitted routers refuse the circuit at once, the DHT
    names the same address again, and the control plane lists routers this
    member has not joined through, one of them dark. The address and the
    routers are dialed at once, the DHT's copy of the address is not dialed
    again, and the routers not joined through are admitted at once: two
    dial timeouts in all, one per step."""
    from agent_mesh import session as session_module
    from agent_mesh.host import DIAL_TIMEOUT

    admitted_id = "12D3KooWG1pA6goegCncqwbZLSr8pnjUZ6JMAAe6SmnHTgUNCk88"
    unjoined = {
        "12D3KooWGvdRCJLYATauVWfsieF2j3a2wXZoEQJUS2MsvRdDtgLM": "/ip4/10.0.0.2/tcp/4501",
        "12D3KooWBTdQ3QQZztZFaxQSTzJx5ZSbpgM8zfs43VYzBXAFkdZm": "/ip4/203.0.113.7/tcp/4501",
    }
    target = "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB"
    dead = "/ip4/10.84.4.137/tcp/5002"

    class Host:
        def get_connected_peers(self):
            return []

    class Credential:
        router_addresses = [f"/ip4/10.0.0.1/tcp/4501/p2p/{admitted_id}"] + [f"{a}/p2p/{p}" for p, a in unjoined.items()]

    class Mesh:
        credential = Credential()

    session = MeshSession(
        mesh=Mesh(),  # type: ignore[arg-type]
        host=Host(),  # type: ignore[arg-type]
        routers=[AdmittedRouter(peer_id=admitted_id, addr=multiaddr.Multiaddr(f"/ip4/10.0.0.1/tcp/4501/p2p/{admitted_id}"), credential=None)],  # type: ignore[arg-type]
    )
    dials: list[list[str]] = []
    admissions: list[tuple[str, float]] = []
    circuits: list[str] = []

    async def dial_nobody_answers(host, info):
        dials.append([str(a) for a in info.addrs])
        await trio.sleep(DIAL_TIMEOUT)
        raise ConnectionError(f"no connection to {info.peer_id} within {DIAL_TIMEOUT:g}s")

    async def refused(ma):
        circuits.append(str(ma))
        raise RuntimeError("relay refused to connect: PERMISSION_DENIED")

    async def dht_names_the_same_address(_target):
        return [multiaddr.Multiaddr(dead)], []

    async def admit_nobody_answers(addr):
        admissions.append((str(addr), trio.current_time()))
        await trio.sleep(DIAL_TIMEOUT)
        raise ConnectionError(f"no connection to {addr} within {DIAL_TIMEOUT:g}s")

    monkeypatch.setattr(session_module, "dial", dial_nobody_answers)
    session._connect_addr = refused  # type: ignore[method-assign]
    session._routed_addresses = dht_names_the_same_address  # type: ignore[method-assign]
    session._admit_router = admit_nobody_answers  # type: ignore[method-assign]

    async def main():
        started = trio.current_time()
        provider = DiscoveredProvider(peer_id=target, addrs=[f"{dead}/p2p/{target}", f"/ip4/10.84.4.137/udp/5001/quic-v1/p2p/{target}"])
        with pytest.raises(ConnectionError) as err:
            await session.connect(provider)
        assert trio.current_time() - started == pytest.approx(2 * DIAL_TIMEOUT)
        # The dead address once, with the admitted router's circuit alongside.
        assert dials == [[dead]]
        assert circuits == [f"/ip4/10.0.0.1/tcp/4501/p2p/{admitted_id}/p2p-circuit/p2p/{target}"]
        # Both routers not joined through, admitted at the same instant.
        assert sorted(a for a, _ in admissions) == sorted(f"{a}/p2p/{p}" for p, a in unjoined.items())
        assert len({t for _, t in admissions}) == 1
        assert str(err.value).count("within 15s") == 3

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


def test_a_router_that_came_back_on_another_address_is_reserved_on_again(monkeypatch):
    """A router pod rescheduled keeps its key and gets a new IP; the name the
    control plane hands out resolves to it. The member's connection went with
    the old pod; the reservation loop dials the router by name again and must
    land on the new address, not on the one the peerstore remembers from the
    old pod, and advertise the relayed address the new pod lists."""
    from multiaddr.resolvers import DNSResolver

    class TXT:
        def __init__(self, strings):
            self.strings = strings

        def __iter__(self):
            for s in self.strings:
                yield type("TXT", (), {"strings": [s.encode()]})()

        def __len__(self):
            return len(self.strings)

    records: dict[str, list[str]] = {}

    class FakeDNS:
        async def resolve(self, name, rdtype):
            return TXT(records.get(str(name).rstrip("."), []))

    monkeypatch.setattr(DNSResolver, "__init__", lambda self: setattr(self, "_resolver", FakeDNS()))

    async def wait_for(predicate):
        while not predicate():
            await trio.sleep(0.1)

    async def main():
        async with trio.open_nursery() as nursery:
            identity = Identity.generate()
            before_events, after_events = [], []
            before, before_addr = await start_router(nursery, events=before_events, identity=identity)
            after, after_addr = await start_router(nursery, events=after_events, identity=identity)
            name = f"/dnsaddr/router.test/p2p/{identity.peer_id}"
            records["_dnsaddr.router.test"] = [f"dnsaddr={before_addr}"]

            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([name]))
            async with mesh.join(refresh_lead=0, refresh_retry=0.5, reservation_check_interval=0.5) as session:
                member = session.host.get_id()
                assert before_events == [("auth", mesh.peer_id), ("reserve", mesh.peer_id)]
                assert session.relay_addresses == [f"{before_addr}/p2p-circuit/p2p/{mesh.peer_id}"]

                # The pod goes: its connection with it, and the name now resolves to the new one.
                records["_dnsaddr.router.test"] = [f"dnsaddr={after_addr}"]
                await before.disconnect(member)
                await wait_for(lambda: member not in before.get_connected_peers())

                reserve = ("reserve", mesh.peer_id)
                await wait_for(lambda: before_events.count(reserve) + after_events.count(reserve) >= 2)
                assert before_events.count(reserve) == 1, "dialed the old pod's address again"
                assert after_events == [("auth", mesh.peer_id), reserve]
                assert member in after.get_connected_peers()
                assert session.relay_addresses == [f"{after_addr}/p2p-circuit/p2p/{mesh.peer_id}"]
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 60, main)


def test_a_router_the_control_plane_lists_elsewhere_is_reserved_on_there():
    """A mesh that hands out literal addresses (agentmesh-one, a kind cluster) has
    no name to re-resolve: a router that came back on another address is
    known only through the control plane's list, refreshed by every pull.
    The reservation loop dials the router at the address that list names
    now and keeps it as the router's address, so the circuits connect()
    opens through it go to the right place too."""

    async def wait_for(predicate):
        while not predicate():
            await trio.sleep(0.1)

    async def main():
        async with trio.open_nursery() as nursery:
            identity = Identity.generate()
            before_events, after_events = [], []
            before, before_addr = await start_router(nursery, events=before_events, identity=identity)
            after, after_addr = await start_router(nursery, events=after_events, identity=identity)
            listed = [before_addr]

            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane(listed))
            async with mesh.join(refresh_lead=0, refresh_retry=0.5, reservation_check_interval=0.5) as session:
                member = session.host.get_id()
                assert [str(r.addr) for r in session.routers] == [before_addr]

                # The control plane lists the router where it is now; the member pulls that.
                listed[:] = [after_addr]
                await session.sync()
                assert list(mesh.credential.router_addresses) == [after_addr]
                await before.disconnect(member)
                await wait_for(lambda: member not in before.get_connected_peers())

                reserve = ("reserve", mesh.peer_id)
                await wait_for(lambda: before_events.count(reserve) + after_events.count(reserve) >= 2)
                assert before_events.count(reserve) == 1, "dialed the address admitted at join again"
                assert after_events == [("auth", mesh.peer_id), reserve]
                assert [str(r.addr) for r in session.routers] == [after_addr]
                assert session.relay_addresses == [f"{after_addr}/p2p-circuit/p2p/{mesh.peer_id}"]
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
            # Enrolled and attesting the floor, but not a node: a router hosts no service.
            _, not_a_node_addr = await start_provider(nursery, lambda p: mint(p, ROLE_ROUTER, labels={"region": "eu"}), handshakes)

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
                # Only nodes host services, as agentmesh-node's checkPeerLabels requires.
                with pytest.raises(BiscuitVerificationError, match="lacks expected role 'mesh:role:node'"):
                    await held.request(not_a_node_addr, "a2a://agent", "/card")
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 60, main)


def test_session_attenuate_and_seal_narrows_outbound_requests():
    """session.attenuate() and session.seal() narrow outbound requests across
    hops and prevent further attenuation of sealed tokens."""

    async def main():
        async with trio.open_nursery() as nursery:
            _, router_addr = await start_router(nursery)
            _, provider_addr = await start_provider(nursery, lambda p: mint(p, ROLE_NODE), [])
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([router_addr]))

            cred_att = mesh.credential.attenuate(
                pb.TaskAuthorizationRule(
                    name="tasks/cred-hop",
                    rules=[
                        pb.TaskRule(
                            allowed_services=["a2a://agent"],
                            operation=pb.TaskOperation(allowed_methods=["GET"], allowed_paths=["/v1/*"]),
                        )
                    ],
                )
            )
            cred_sealed = cred_att.seal()
            with pytest.raises(BiscuitVerificationError):
                cred_sealed.attenuate(pb.TaskAuthorizationRule(name="tasks/after-seal", rules=[pb.TaskRule(allowed_services=["a2a://agent"])]))

            async with mesh.join(reserve=False, refresh_lead=0) as session:
                hop1 = session.attenuate(
                    pb.TaskAuthorizationRule(
                        name="tasks/hop-1",
                        rules=[
                            pb.TaskRule(
                                allowed_services=["a2a://agent"],
                                operation=pb.TaskOperation(allowed_methods=["GET", "POST"], allowed_paths=["/v1/*"]),
                            )
                        ],
                    )
                )
                hop2 = hop1.attenuate(
                    pb.TaskAuthorizationRule(
                        name="tasks/hop-2",
                        rules=[
                            pb.TaskRule(
                                allowed_services=["a2a://agent"],
                                operation=pb.TaskOperation(allowed_methods=["GET"], allowed_paths=["/v1/allowed"]),
                            )
                        ],
                    )
                ).seal()

                assert (await hop2.request(provider_addr, "a2a://agent", "/v1/allowed")).status == 200
                assert (await hop2.request(provider_addr, "a2a://agent", "/v1/denied")).status == 403
                assert (await hop2.request(provider_addr, "a2a://agent", "/v1/allowed", method="POST")).status == 403

                with pytest.raises(BiscuitVerificationError):
                    hop2.attenuate(pb.TaskAuthorizationRule(name="tasks/hop-3", rules=[pb.TaskRule(allowed_services=["a2a://agent"])]))

                # Parent session remains unattenuated.
                assert (await session.request(provider_addr, "a2a://agent", "/v2/anything")).status == 200
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 60, main)


def test_select_routers_filters_orders_and_clamps_retry_after():
    infos = [
        pb.RouterInfo(
            peer_id="12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB",
            addresses=["/ip4/127.0.0.1/tcp/5001/p2p/12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB"],
            labels={"region": "us-west", "zone": "b"},
            connections=80,
            connection_limit=100,
        ),
        pb.RouterInfo(
            peer_id="12D3KooWB4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSC",
            addresses=["/ip4/127.0.0.1/tcp/5002/p2p/12D3KooWB4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSC"],
            labels={"region": "us-west", "zone": "a"},
            connections=90,
            connection_limit=100,
        ),
        pb.RouterInfo(
            peer_id="12D3KooWC4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSD",
            addresses=["/ip4/127.0.0.1/tcp/5003/p2p/12D3KooWC4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSD"],
            labels={"region": "us-west", "zone": "b"},
            connections=10,
            connection_limit=100,
        ),
        pb.RouterInfo(
            peer_id="12D3KooWD4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSE",
            addresses=["/ip4/127.0.0.1/tcp/5004/p2p/12D3KooWD4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSE"],
            labels={"region": "eu-west", "zone": "a"},
            connections=1,
            connection_limit=100,
        ),
    ]
    catalog = candidates_from_router_infos(infos, [])
    assert len(catalog) == 4

    picked = select_routers(
        catalog,
        10,
        selector={"region": "us-west"},
        prefer={"zone": "a"},
        rand=lambda: 0.0,
    )
    assert [c.peer_id for c in picked] == [
        "12D3KooWB4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSC",
        "12D3KooWC4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSD",
        "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB",
    ]

    without_preferred = select_routers(
        catalog,
        10,
        selector={"region": "us-west"},
        prefer={"zone": "a"},
        shunned={"12D3KooWB4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSC": time.time() + 60},
        rand=lambda: 0.0,
    )
    assert [c.peer_id for c in without_preferred] == [
        "12D3KooWC4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSD",
        "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB",
    ]

    fallback = candidates_from_router_infos([], ["/ip4/127.0.0.1/tcp/5001/p2p/12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB"])
    assert len(fallback) == 1
    assert fallback[0].peer_id == "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB"

    # Non-canonical CIDv1 peer_id in RouterInfo is canonicalized at the boundary.
    cidv1 = "bafzaajaiaejcaa5ba677htqqxyoxbxiy45f4bglh4tldbg5fbvpr3xegmqjfkmny"
    cid_candidates = candidates_from_router_infos(
        [pb.RouterInfo(peer_id=cidv1, addresses=["/ip4/127.0.0.1/tcp/5001"])],
        [],
    )
    assert len(cid_candidates) == 1
    assert cid_candidates[0].peer_id == "12D3KooWA4Xop1JaT3MHxwYMkCepYsv4iPVopMXwCz5iHYdBfeSB"

    assert clamp_go_away_retry_after(pb.RouterGoAway()) == ROUTER_SHUN_DURATION
    assert clamp_go_away_retry_after(pb.RouterGoAway(retry_after=Duration(seconds=0))) == ROUTER_SHUN_DURATION
    assert clamp_go_away_retry_after(pb.RouterGoAway(retry_after=Duration(seconds=-5))) == ROUTER_SHUN_DURATION
    assert clamp_go_away_retry_after(pb.RouterGoAway(retry_after=Duration(seconds=600))) == 600.0
    assert clamp_go_away_retry_after(pb.RouterGoAway(retry_after=Duration(seconds=7200))) == GOAWAY_MAX_RETRY_AFTER


def test_join_holds_two_routers_handles_go_away_and_redials_before_failover():
    async def wait_for(predicate):
        while not predicate():
            await trio.sleep(0.05)

    async def main():
        async with trio.open_nursery() as nursery:
            events1, events2, events3 = [], [], []
            r1, addr1 = await start_router(nursery, events=events1)
            r2, addr2 = await start_router(nursery, events=events2)
            r3, addr3 = await start_router(nursery, events=events3)
            pid1, pid2, pid3 = str(r1.get_id()), str(r2.get_id()), str(r3.get_id())

            router_infos = [
                pb.RouterInfo(peer_id=pid3, addresses=[addr3], labels={"region": "us", "tier": "backup"}, connections=90, connection_limit=100),
                pb.RouterInfo(peer_id=pid1, addresses=[addr1], labels={"region": "us", "tier": "primary"}, connections=50, connection_limit=100),
                pb.RouterInfo(peer_id=pid2, addresses=[addr2], labels={"region": "us", "tier": "backup"}, connections=10, connection_limit=100),
            ]
            all_addrs = [addr3, addr1, addr2]
            mesh = AgentMesh.enroll(
                "http://127.0.0.1:1",
                bootstrap_token="sbt",
                transport=fake_control_plane(all_addrs, routers=router_infos),
            )
            async with mesh.join(
                refresh_lead=0,
                routers=2,
                router_selector={"region": "us"},
                router_prefer={"tier": "primary"},
                reservation_check_interval=0.2,
                router_redial_backoffs=(0.05, 0.1),
            ) as session:
                # Only r1 and r2 were authenticated and reserved on at join; r3 is untouched in the catalog.
                assert sorted(r.peer_id for r in session.routers) == sorted([pid1, pid2])
                assert events3 == []
                assert len(session.relay_addresses) == 2
                assert any(a.startswith(addr1) for a in session.relay_addresses)
                assert any(a.startswith(addr2) for a in session.relay_addresses)

                # A go-away from a peer we do not hold (r3) is ignored.
                assert await session.handle_go_away(pid3, pb.RouterGoAway(reason=pb.RouterGoAway.DRAINING), 600.0) is False
                assert session.go_away_received == {}

                # r1 opens a /mesh/goaway/1.0.0 stream over its existing connection to the member.
                stream = await r1.new_stream(session.host.get_id(), [GOAWAY_PROTOCOL])
                msg = pb.RouterGoAway(reason=pb.RouterGoAway.DRAINING, retry_after=Duration(seconds=600))
                await stream.write(encode_varint_prefixed(msg.SerializeToString()))
                await stream.close()

                await wait_for(
                    lambda: sorted(r.peer_id for r in session.routers) == sorted([pid2, pid3])
                    and any(a.startswith(addr3) for a in session.relay_addresses)
                )
                assert session.go_away_received == {"DRAINING": 1}
                assert pid1 in session.shunned_routers
                assert any(a.startswith(addr2) for a in session.relay_addresses)
                assert any(a.startswith(addr3) for a in session.relay_addresses)
                assert not any(a.startswith(addr1) for a in session.relay_addresses)

                # Now make r3 refuse future auth handshakes and drop the connection so redial fails and shuns r3.
                r3.set_stream_handler(
                    AUTH_PROTOCOL,
                    auth_stream_handler(lambda: b"", lambda: [ba.KeyPair().public_key.to_bytes()]),
                )
                await r3.disconnect(session.host.get_id())
                await wait_for(lambda: pid3 in session.shunned_routers)
                assert [r.peer_id for r in session.routers] == [pid2]
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 60, main)



def test_a_member_announces_where_it_is_reached_and_withdraws_it_on_leaving():
    """A member with a relay reservation announces its relayed addresses under
    its peer key to a router it holds, so that a peer on other routers finds
    it by ID; it withdraws the record as it leaves."""
    requests = []

    def directory_handler(stream):
        async def run():
            req = pb.DirectoryRequest.FromString(await read_varint_prefixed_bytes(stream))
            requests.append((req.WhichOneof("request"), req))
            await stream.write(encode_varint_prefixed(pb.DirectoryResponse().SerializeToString()))
            await stream.close()

        return run()

    async def main():
        async with trio.open_nursery() as nursery:
            router, router_addr = await start_router(nursery)
            router.set_stream_handler(DIRECTORY_PROTOCOL, directory_handler)
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=fake_control_plane([router_addr]))
            async with mesh.join(listen_addrs=["/ip4/127.0.0.1/tcp/0"], refresh_lead=0) as session:
                relayed = f"{router_addr}/p2p-circuit/p2p/{mesh.peer_id}"
                assert session.relay_addresses == [relayed]
                assert [op for op, _ in requests] == ["provide"]
                assert requests[0][1].provide.key == peer_key(session.host.get_id())
                assert list(requests[0][1].provide.addrs) == [relayed]
            assert [op for op, _ in requests] == ["provide", "withdraw"]
            assert requests[1][1].withdraw.key == peer_key(session.host.get_id())

            # A member that reserves no relay has no address to announce.
            del requests[:]
            async with mesh.join(reserve=False) as session:
                assert session.relay_addresses == []
            assert requests == []
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)


def test_go_away_replaces_draining_router_immediately_even_when_connection_closes():
    """A GoAway failover must finish on the session nursery even when the
    draining router disconnects immediately (which cancels that connection's
    stream-handler nursery in py-libp2p >=0.8.3) and without waiting for the
    periodic reservation_check_interval poll."""

    async def main():
        async with trio.open_nursery() as nursery:
            r1, addr1 = await start_router(nursery)
            r2, addr2 = await start_router(nursery)
            r3, addr3 = await start_router(nursery)
            pid1, pid2, pid3 = str(r1.get_id()), str(r2.get_id()), str(r3.get_id())

            router_infos = [
                pb.RouterInfo(peer_id=pid3, addresses=[addr3], labels={"tier": "backup"}, connections=90, connection_limit=100),
                pb.RouterInfo(peer_id=pid1, addresses=[addr1], labels={"tier": "primary"}, connections=10, connection_limit=100),
                pb.RouterInfo(peer_id=pid2, addresses=[addr2], labels={"tier": "backup"}, connections=10, connection_limit=100),
            ]
            mesh = AgentMesh.enroll(
                "http://127.0.0.1:1",
                bootstrap_token="sbt",
                transport=fake_control_plane([addr3, addr1, addr2], routers=router_infos),
            )
            async with mesh.join(
                refresh_lead=0,
                routers=2,
                router_prefer={"tier": "primary"},
                reservation_check_interval=30.0,
            ) as session:
                assert sorted(r.peer_id for r in session.routers) == sorted([pid1, pid2])

                stream = await r1.new_stream(session.host.get_id(), [GOAWAY_PROTOCOL])
                msg = pb.RouterGoAway(reason=pb.RouterGoAway.DRAINING, retry_after=Duration(seconds=600))
                await stream.write(encode_varint_prefixed(msg.SerializeToString()))
                await stream.close()
                await r1.disconnect(session.host.get_id())

                with trio.fail_after(5):
                    while sorted(r.peer_id for r in session.routers) != sorted([pid2, pid3]) or len(session.relay_addresses) != 2:
                        await trio.sleep(0.05)
                assert session.go_away_received == {"DRAINING": 1}
                assert pid1 in session.shunned_routers
            nursery.cancel_scope.cancel()

    trio.run(with_timeout, 30, main)
