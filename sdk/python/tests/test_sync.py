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

"""What a joined member keeps in step with the control plane: a fake control
plane behind the transport hook rotates its key and bans a peer; the member
learns both from a pull, refreshes its credential under the new key, and
refuses the banned peer. The real control plane and router are exercised by
tests/integration/sdk_mesh_test.go."""

import base64
import time
import urllib.parse

import biscuit_auth as ba
import multiaddr
import pytest
import trio
from cid import make_cid
from libp2p.peer.peerinfo import info_from_p2p_addr

from agent_mesh import base58
from agent_mesh._proto import agentmesh_pb2 as pb
from agent_mesh.auth import AUTH_PROTOCOL, auth_stream_handler, authenticate_with_peer
from agent_mesh.biscuit import ROLE_ROUTER, verify_peer_biscuit
from agent_mesh.controlplane import ROLE_NODE
from agent_mesh.discovery import DiscoveredProvider
from agent_mesh.identity import Identity
from agent_mesh.mesh import AgentMesh
from agent_mesh.relay import HOP_PROTOCOL as RELAY_HOP_PROTOCOL
from agent_mesh.sync import EVENT_FRESHNESS_MS, BanSet, verify_mesh_event

from .test_session import hop_handler, libp2p_host
from google.protobuf.timestamp_pb2 import Timestamp


def _ts_ms(ms: int) -> Timestamp:
    t = Timestamp()
    t.FromMilliseconds(int(ms))
    return t


def _ts_s(seconds: int) -> Timestamp:
    t = Timestamp()
    t.FromSeconds(int(seconds))
    return t


class SigningKey:
    """One ed25519 key usable both as a biscuit root and for plain signatures."""

    def __init__(self) -> None:
        self.biscuit = ba.KeyPair()
        self.identity = Identity.from_seed(self.biscuit.private_key.to_bytes())

    @property
    def pub(self) -> bytes:
        return self.identity.public_key_raw

    def mint(self, peer_id: str, role: str) -> bytes:
        return ba.BiscuitBuilder("node({p}); expiration(2035-01-01T00:00:00Z); role({r});", {"p": peer_id, "r": role}).build(self.biscuit.private_key).to_bytes()


class FakeControlPlane:
    """A control plane whose key set, ban set and issuing key the test changes."""

    def __init__(self, initial: SigningKey, router_addr: str) -> None:
        self.keys = [initial]
        self.banned: list[str] = []
        self.refreshes = 0
        self.router_addr = router_addr

    @property
    def current(self) -> SigningKey:
        return self.keys[-1]

    def transport(self, method, url, headers, body):  # type: ignore[no-untyped-def]
        path = urllib.parse.urlsplit(url).path
        if (method, path) == ("POST", "/enroll"):
            req = pb.BootstrapEnrollRequest.FromString(body)
            return 200, pb.BootstrapEnrollResponse(
                status=pb.ENROLLMENT_STATUS_APPROVED,
                biscuit_token=self.current.mint(req.peer_id, ROLE_NODE),
                control_plane_public_key=self.current.pub,
                router_addresses=[self.router_addr],
                expire_time=_ts_s(int(time.time()) + 3600),
            ).SerializeToString()
        if (method, path) == ("GET", "/keys"):
            unsigned = pb.KeysResponse(public_keys=[k.pub for k in self.keys], sign_time=_ts_ms(int(time.time() * 1000)))
            payload = unsigned.SerializeToString(deterministic=True)
            return 200, pb.KeysResponse(public_keys=[k.pub for k in self.keys], sign_time=unsigned.sign_time, signatures=[k.identity.sign(payload) for k in self.keys]).SerializeToString()
        if (method, path) == ("GET", "/info"):
            return 200, pb.ControlPlaneInfoResponse(router_addresses=[self.router_addr], banned_peer_ids=self.banned).SerializeToString()
        if (method, path) == ("GET", "/policies"):
            return 200, pb.PolicyConfigGetResponse(datalog_rules=['granted_publish_all_types(true) <- role("mesh:role:node")']).SerializeToString()
        if (method, path) == ("POST", "/refresh"):
            self.refreshes += 1
            presented = base64.b64decode(headers["Authorization"].removeprefix("Bearer "))
            for key in self.keys:
                try:
                    verified = verify_peer_biscuit_any(presented, key.pub)
                except Exception:  # noqa: BLE001 - try the next key
                    continue
                return 200, pb.TokenRefreshResponse(biscuit_token=self.current.mint(verified, ROLE_NODE), expire_time=_ts_s(int(time.time()) + 7200)).SerializeToString()
            return 401, b"unverifiable biscuit"
        return 404, f"no route for {method} {path}".encode()


def verify_peer_biscuit_any(biscuit: bytes, key: bytes) -> str:
    """The peer a biscuit is bound to, if key signed it."""
    token = ba.Biscuit.from_bytes(biscuit, ba.PublicKey.from_bytes(key, ba.Algorithm.Ed25519))
    b = ba.AuthorizerBuilder()
    b.add_policy(ba.Policy("allow if true"))
    return b.build(token).query(ba.Rule("p($p) <- node($p)"))[0].terms[0]


async def start_router(nursery, cp_keys):  # type: ignore[no-untyped-def]
    identity = Identity.generate()
    router = libp2p_host(identity)
    started = trio.Event()
    box = []

    async def run():
        async with router.run(listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]):
            addr = f"{router.get_addrs()[0]}"
            router.set_stream_handler(RELAY_HOP_PROTOCOL, hop_handler(addr, True))
            box.append(addr)
            started.set()
            await trio.sleep_forever()

    nursery.start_soon(run)
    await started.wait()
    cp = FakeControlPlane(cp_keys, box[0])
    router_biscuit = cp.current.mint(identity.peer_id, ROLE_ROUTER)
    router.set_stream_handler(AUTH_PROTOCOL, auth_stream_handler(lambda: router_biscuit, lambda: [k.pub for k in cp.keys]))
    return router, cp


def test_ban_learned_after_the_answer_was_requested_survives_an_answer_that_omits_it():
    bans = BanSet()
    t0 = 1_800_000_000.0
    t1 = t0 + 1
    banned, unbanned = bans.reconcile(["A", "B"], t0)
    assert (sorted(banned), unbanned) == (["A", "B"], [])
    # A gossip event bans C after t1's request went out; t1's answer cannot speak to it.
    assert bans.add("C", int(t1 * 1000) + 500)
    assert bans.reconcile(["A"], t1) == ([], ["B"])
    assert bans.peers() == ["A", "C"]
    assert bans.reconcile(["A"], t1 + 2) == ([], ["C"])
    assert not bans.add("A", 1)


def test_ban_repeated_after_the_answer_was_requested_survives_an_answer_that_omits_it():
    bans = BanSet()
    t0 = 1_800_000_000.0
    t1 = t0 + 1
    assert bans.add("X", int(t0 * 1000))
    # The ban was lifted, which publishes no event, and set again after t1's request went out.
    assert not bans.add("X", int(t1 * 1000) + 500)
    assert bans.reconcile([], t1) == ([], [])
    assert bans.peers() == ["X"]


def test_repeated_ban_with_an_earlier_time_does_not_move_the_ban_time_back():
    bans = BanSet()
    t0 = 1_800_000_000.0
    t1 = t0 + 1
    assert bans.add("X", int(t1 * 1000) + 500)
    assert not bans.add("X", int(t0 * 1000))
    assert bans.reconcile([], t1) == ([], [])
    assert bans.peers() == ["X"]


def test_mesh_event_verifies_only_under_a_trusted_key_and_only_when_fresh():
    key = SigningKey()

    def sign(event: pb.MeshEvent) -> bytes:
        event.ClearField("signature")
        event.signature = key.identity.sign(event.SerializeToString(deterministic=True))
        return event.SerializeToString(deterministic=True)

    now_ms = int(time.time() * 1000)
    target = Identity.generate().peer_id
    banned = sign(pb.MeshEvent(type=pb.MeshEvent.BANNED, peer_id=target, event_time=_ts_ms(now_ms)))
    assert verify_mesh_event(banned, [key.pub], now_ms).peer_id == target
    assert verify_mesh_event(banned, [SigningKey().pub], now_ms) is None
    tampered = bytearray(banned)
    tampered[-1] ^= 1
    assert verify_mesh_event(bytes(tampered), [key.pub], now_ms) is None
    stale = sign(pb.MeshEvent(type=pb.MeshEvent.BANNED, peer_id=target, event_time=_ts_ms(now_ms - EVENT_FRESHNESS_MS - 1)))
    assert verify_mesh_event(stale, [key.pub], now_ms) is None
    assert verify_mesh_event(b"\x01\x02\x03", [key.pub], now_ms) is None

    # The ban set is keyed on the base58 form; an event naming the peer in its
    # CIDv1 form bans the same peer, and one naming no peer bans nobody.
    banned_by_cid = sign(pb.MeshEvent(type=pb.MeshEvent.BANNED, peer_id=cid_form(target), event_time=_ts_ms(now_ms)))
    assert verify_mesh_event(banned_by_cid, [key.pub], now_ms).peer_id == target
    banned_nobody = sign(pb.MeshEvent(type=pb.MeshEvent.BANNED, peer_id="not-a-peer", event_time=_ts_ms(now_ms)))
    assert verify_mesh_event(banned_nobody, [key.pub], now_ms) is None


def cid_form(peer_id: str) -> str:
    """The CIDv1 base32 encoding of a peer ID, as `peer.ToCid(id).String()` prints it."""
    encoded = make_cid(1, "libp2p-key", base58.decode(peer_id)).encode("base32").decode()
    assert encoded != peer_id
    return encoded


def test_pull_learns_a_key_rotation_and_refreshes_the_credential():
    async def main():
        async with trio.open_nursery() as nursery:
            _router, cp = await start_router(nursery, SigningKey())
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=cp.transport)
            async with mesh.join(refresh_lead=0, control_plane_sync_interval=0) as session:
                issuer = cp.current
                assert len(mesh.credential.control_plane_keys) == 1

                # Nothing changed: a pull is a no-op that spends no refresh.
                result = await session.sync()
                assert result.errors == []
                assert not result.keys_changed and not result.refreshed
                assert cp.refreshes == 0

                # The control plane rotates: a new key joins the set and mints from now on.
                cp.keys.append(SigningKey())
                result = await session.sync()
                assert result.errors == []
                assert result.keys_changed and result.refreshed, "credential predating the rotation was not refreshed"
                assert cp.refreshes == 1
                assert len(mesh.credential.control_plane_keys) == 2
                assert not mesh.credential.predates_rotation()
                # The new credential is signed by the new key and no longer by the retiring one.
                assert verify_peer_biscuit(mesh.credential.biscuit, mesh.peer_id, [cp.current.pub]).peer_id == mesh.peer_id
                with pytest.raises(Exception):
                    verify_peer_biscuit(mesh.credential.biscuit, mesh.peer_id, [issuer.pub])

                # The retiring key leaves the set: the member follows without another refresh.
                cp.keys.pop(0)
                result = await session.sync()
                assert result.keys_changed and not result.refreshed
                assert len(mesh.credential.control_plane_keys) == 1
            nursery.cancel_scope.cancel()

    async def with_timeout():
        with trio.fail_after(30):
            await main()

    trio.run(with_timeout)


def test_banned_peer_is_disconnected_and_refused():
    async def main():
        async with trio.open_nursery() as nursery:
            _router, cp = await start_router(nursery, SigningKey())
            mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt", transport=cp.transport)
            async with mesh.join(listen_addrs=["/ip4/127.0.0.1/tcp/0"], refresh_lead=0, control_plane_sync_interval=0) as session:
                peer_identity = Identity.generate()
                peer = libp2p_host(peer_identity)
                frame = pb.AuthFrame(biscuit=cp.current.mint(peer_identity.peer_id, ROLE_NODE)).SerializeToString()
                async with peer.run(listen_addrs=[]):
                    member_addr = multiaddr.Multiaddr(f"{session.host.get_addrs()[0]}")
                    await peer.connect(info_from_p2p_addr(member_addr))
                    await authenticate_with_peer(peer, session.host.get_id(), frame, [cp.current.pub])
                    assert peer_identity.peer_id in session.authenticated_peers

                    # The control plane bans the peer; the next pull evicts it.
                    cp.banned = [peer_identity.peer_id]
                    result = await session.sync()
                    assert result.errors == []
                    assert session.banned.peers() == [peer_identity.peer_id]
                    assert peer_identity.peer_id not in session.authenticated_peers
                    await trio.sleep(0.2)
                    assert peer.get_id() not in session.host.get_connected_peers()

                    # Its token still verifies, and it is still refused at the handshake ...
                    await peer.connect(info_from_p2p_addr(member_addr))
                    with pytest.raises(Exception):
                        await authenticate_with_peer(peer, session.host.get_id(), frame, [cp.current.pub])
                    # ... and outbound, before any dial, however the peer is named.
                    cid = cid_form(peer_identity.peer_id)
                    with pytest.raises(PermissionError, match="banned"):
                        await session.connect(f"{cp.router_addr}/p2p-circuit/p2p/{peer_identity.peer_id}")
                    with pytest.raises(PermissionError, match="banned"):
                        await session.connect(f"{cp.router_addr}/p2p-circuit/p2p/{cid}")
                    with pytest.raises(PermissionError, match="banned"):
                        await session.connect(cid)
                    with pytest.raises(PermissionError, match="banned"):
                        await session.connect(DiscoveredProvider(peer_id=cid))

                    # Lifted by the control plane: the next pull unbans it. A ban
                    # list that names the peer in its CIDv1 form bans the same peer.
                    cp.banned = []
                    await session.sync()
                    assert session.banned.peers() == []
                    cp.banned = [cid, "not-a-peer"]
                    await session.sync()
                    assert session.banned.peers() == [peer_identity.peer_id]
                    cp.banned = []
                    await session.sync()
                    assert session.banned.peers() == []
            nursery.cancel_scope.cancel()

    async def with_timeout():
        with trio.fail_after(30):
            await main()

    trio.run(with_timeout)
