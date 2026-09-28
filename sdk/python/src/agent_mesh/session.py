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

from __future__ import annotations

import logging
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, AsyncIterator, Mapping, Optional, Sequence, Union

import multiaddr
import trio
from libp2p.abc import IHost
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo, info_from_p2p_addr
from libp2p.pubsub.gossipsub import PROTOCOL_ID as GOSSIPSUB_V10
from libp2p.pubsub.gossipsub import PROTOCOL_ID_V11 as GOSSIPSUB_V11
from libp2p.pubsub.gossipsub import PROTOCOL_ID_V12 as GOSSIPSUB_V12
from libp2p.pubsub.gossipsub import GossipSub
from libp2p.pubsub.pubsub import Pubsub
from libp2p.tools.anyio_service import background_trio_service
from mcp import ClientSession

from ._proto import circuit_pb2 as circuit
from ._proto import sam_pb2 as pb
from .auth import AUTH_PROTOCOL, auth_stream_handler, authenticate_with_peer
from .authorizer import ProviderAuthorizerOptions
from .biscuit import ROLE_ROUTER, VerifiedBiscuit, require_role
from .discovery import DiscoveredProvider, find_peer, find_providers, parse_service_target, service_key
from .host import create_mesh_host, dial, dial_addrs, peer_info
from .httpx_transport import MESH_PATH_PREFIX
from .identity import canonical_peer_id
from .libp2p_http import (
    DEFAULT_A2A_NAME,
    HTTP_PROTOCOL,
    A2AEndpoint,
    HTTPHandler,
    HTTPResponse,
    ProviderOptions,
    http_ingress_handler,
    http_request_over_stream,
    mesh_http_target,
)
from .mcp_client import ToolCallResult, ToolInfo, open_mcp_session, require_egress_labels, tool_call_result
from .relay import STOP_PROTOCOL, dial_through_relay, reserve_relay, split_circuit_address, stop_stream_handler
from .sync import GOSSIP_EVENTS_TOPIC, BanSet, verify_mesh_event

if TYPE_CHECKING:
    from .mesh import AgentMesh, ControlPlaneSync

logger = logging.getLogger("agent_mesh")

DEFAULT_REFRESH_LEAD = 60 * 60.0
DEFAULT_REFRESH_RETRY = 30.0
MIN_REFRESH_DELAY = 2.0
# go-libp2p's relay grants a reservation for an hour and drops it on expiry;
# its own clients renew two minutes before that.
RESERVATION_RENEW_LEAD = 2 * 60.0
# The relay also drops the reservation when the connection goes, with a
# router restart or a trimmed connection; this is how long the member is
# unreachable through that router at most before it notices and reserves
# again.
RESERVATION_CHECK_INTERVAL = 30.0
# sam-node's --control-plane-sync-interval default.
DEFAULT_POLICY_SYNC = 15 * 60.0
# sam-node's --control-plane-sync-interval default, and its 2s first pull.
DEFAULT_CONTROL_PLANE_SYNC = 15 * 60.0
FIRST_CONTROL_PLANE_SYNC = 2.0
DEFAULT_CONTROL_PLANE_SYNC_JITTER = 2.0
# How long a provider's positive egress verdict is kept; sam-node's labelGateTTL.
EGRESS_VERDICT_TTL = 5 * 60.0

# How a caller names the peer it wants to reach: a provider `discover` returned,
# a peer id, or a multiaddr. For a provider or a peer id the SDK dials the
# addresses the peer advertised and then the relayed path through every router
# that admitted this member, so the caller never assembles a `/p2p-circuit`
# address. A multiaddr is dialed as given.
Peer = Union[DiscoveredProvider, str, multiaddr.Multiaddr]


def parse_peer_id(text: str) -> ID:
    """The libp2p peer ID for a string in any encoding libp2p accepts."""
    return ID.from_base58(canonical_peer_id(text))


def canonical_peer_ids(ids: Sequence[str]) -> list[str]:
    """Canonicalizes a list from the control plane, dropping entries that are
    not peer IDs: they can match nothing, so they ban nothing."""
    out: list[str] = []
    for text in ids:
        try:
            out.append(canonical_peer_id(text))
        except ValueError:
            continue
    return out


class _MeshsubNoise(logging.Filter):
    """py-libp2p's pubsub opens a meshsub stream to every new peer and the host
    logs an error for each one that does not answer. Peers that leave during
    that exchange and members without pubsub are ordinary on the mesh."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        return not ("Failed to open stream" in message and "/meshsub/" in message)


_MESHSUB_NOISE = _MeshsubNoise()


@dataclass(frozen=True)
class AdmittedRouter:
    peer_id: str
    addr: multiaddr.Multiaddr
    credential: VerifiedBiscuit
    reservation: circuit.Reservation | None = None


@dataclass
class MeshSession:
    """A member that is on the mesh: a libp2p host authenticated with at least
    one router, answering the auth handshake for peers that dial it, and
    keeping its credential fresh for as long as the `join` block is open."""

    mesh: "AgentMesh"
    host: IHost
    routers: list[AdmittedRouter]
    # Peers that passed the inbound auth handshake, with their credential's expiration.
    authenticated_peers: dict[str, datetime] = field(default_factory=dict)
    # Peers the control plane has banned; connections to and from them are refused.
    banned: BanSet = field(default_factory=BanSet)
    # This member's agent, once accept_a2a was called.
    endpoint: Optional[A2AEndpoint] = None
    # sam-node's egress.require_labels for an SDK member: every provider this
    # session calls must attest all of these pairs, on top of a call's
    # required_labels. Held on every call, MCP and HTTP alike; no call waives it.
    egress_require_labels: Optional[Mapping[str, str]] = None
    policy_sync_interval: float = DEFAULT_POLICY_SYNC
    control_plane_sync_interval: float = DEFAULT_CONTROL_PLANE_SYNC
    control_plane_sync_jitter: float = DEFAULT_CONTROL_PLANE_SYNC_JITTER
    reservation_lead: float = RESERVATION_RENEW_LEAD
    reservation_retry: float = DEFAULT_REFRESH_RETRY
    reservation_check_interval: float = RESERVATION_CHECK_INTERVAL
    _nursery: Optional[trio.Nursery] = field(default=None, repr=False)
    _policy_rules: Optional[list[str]] = field(default=None, repr=False)
    _sync_lock: trio.Lock = field(default_factory=trio.Lock, repr=False)
    _sync_trigger: trio.Event = field(default_factory=trio.Event, repr=False)
    # Peers verified as enrolled and holding the floor, until when; misses are never kept.
    _egress_verdicts: dict[str, float] = field(default_factory=dict, repr=False)

    @property
    def peer_id(self) -> str:
        return str(self.host.get_id())

    @staticmethod
    def mesh_url(peer_id: str, target_service: str, path: str = "") -> str:
        """The URL an httpx client on `MeshTransport` uses for a service on a
        peer: http://mesh/sam/<peer-id>/<type>/<name>/<path>, the shape of
        sam-node's egress proxy and of an agent card it rewrote."""
        return "http://mesh" + MESH_PATH_PREFIX + canonical_peer_id(peer_id) + mesh_http_target(target_service, path)

    @property
    def agent_url(self) -> Optional[str]:
        """The mesh URL of this member's own agent, once accept_a2a was called."""
        return self.mesh_url(self.peer_id, self.endpoint.service) if self.endpoint is not None else None

    @property
    def relay_addresses(self) -> list[str]:
        """The `.../p2p-circuit/p2p/<self>` addresses reserved on routers."""
        out = []
        for r in self.routers:
            if r.reservation is None:
                continue
            # A relay lists the addresses it wants advertised; go-libp2p keeps
            # private ones out, so a router on loopback lists none and the
            # address we reached it on is the one that works.
            relay_addrs = [multiaddr.Multiaddr(raw) for raw in r.reservation.addrs] or [r.addr]
            for ma in relay_addrs:
                text = str(ma)
                if f"/p2p/{r.peer_id}" not in text:
                    text = f"{text}/p2p/{r.peer_id}"
                out.append(f"{text}/p2p-circuit/p2p/{self.peer_id}")
        return out

    async def connect(self, peer: Peer) -> ID:
        """Connects to a peer, see `Peer`, and returns its peer ID. A banned
        peer is refused. A peer named by ID that no admitted router relays for
        is looked up in the routers' DHT, and failing that tried through every
        router the control plane lists that this member has not joined
        through; a relay opens a circuit only for a source it authenticated,
        so each such router is admitted first. Which router each side joined
        through does not decide whether they can talk."""
        if isinstance(peer, multiaddr.Multiaddr) or (isinstance(peer, str) and peer.startswith("/")):
            return await self._connect_addr(multiaddr.Multiaddr(str(peer)))
        if isinstance(peer, str):
            target, advertised = parse_peer_id(peer), []
        else:
            target, advertised = parse_peer_id(peer.peer_id), [multiaddr.Multiaddr(a) for a in peer.addrs]
        self._refuse_banned(target)
        if target in self.host.get_connected_peers():
            return target
        failures: list[str] = []
        suffix = f"/p2p/{target}"
        direct: list[multiaddr.Multiaddr] = []
        for a in advertised:
            if "/p2p-circuit" in str(a):
                continue
            try:
                direct.extend(multiaddr.Multiaddr(str(m).removesuffix(suffix)) for m in await dial_addrs(a))
            except Exception as err:  # noqa: BLE001 - an address this host cannot use; the others are tried
                failures.append(f"{a}: {err}")
        if direct:
            try:
                await dial(self.host, PeerInfo(target, direct))
                return target
            except Exception as err:  # noqa: BLE001 - the relayed path is tried next
                failures.append(f"direct {[str(a) for a in direct]}: {err}")
        for r in self.routers:
            try:
                await self._connect_addr(multiaddr.Multiaddr(f"{r.addr}/p2p-circuit{suffix}"))
                return target
            except Exception as err:  # noqa: BLE001 - the next router is tried
                failures.append(f"via router {r.peer_id}: {err}")
        for more in (self._routed_addresses, self._unjoined_router_addresses):
            for ma in await more(target):
                try:
                    await self._connect_addr(ma)
                    return target
                except Exception as err:  # noqa: BLE001 - the next address is tried
                    failures.append(f"{ma}: {err}")
        raise ConnectionError(f"cannot reach {target}:\n  " + "\n  ".join(failures))

    async def _unjoined_router_addresses(self, target: ID) -> list[multiaddr.Multiaddr]:
        """The relayed paths to a peer through the routers the control plane
        lists that this member has not joined through, each admitted first.
        The list is the one the credential carries, refreshed by every
        control plane pull, so a router that came up after join is tried too."""
        out: list[multiaddr.Multiaddr] = []
        for text in self.mesh.credential.router_addresses:
            try:
                addr = multiaddr.Multiaddr(text)
                router = info_from_p2p_addr(addr).peer_id
            except Exception:  # noqa: BLE001 - not a router address
                continue
            if router == target or str(router) in self.banned or any(r.peer_id == str(router) for r in self.routers):
                continue
            try:
                admitted = await self._admit_router(addr)
            except Exception as err:  # noqa: BLE001 - a router that does not admit us is not a path
                logger.debug("router %s did not admit us: %s", router, err)
                continue
            out.append(multiaddr.Multiaddr(f"{admitted.addr}/p2p-circuit/p2p/{target}"))
        return out

    async def _routed_addresses(self, target: ID) -> list[multiaddr.Multiaddr]:
        """The addresses the routers' DHT knows for a peer, relayed ones
        through routers this member has admitted by then: a relay opens a
        circuit only for a source it authenticated, so a router met this way
        is dialed and passed the handshake first, and joins the admitted set."""
        out: list[multiaddr.Multiaddr] = []
        seeds = [ID.from_base58(r.peer_id) for r in self.routers]
        for ma in await find_peer(self.host, target, seeds):
            text = str(ma)
            if "/p2p-circuit" not in text:
                out.append(ma if text.endswith(f"/p2p/{target}") else multiaddr.Multiaddr(f"{text}/p2p/{target}"))
                continue
            relay_addr = multiaddr.Multiaddr(text[: text.index("/p2p-circuit")])
            try:
                relay = info_from_p2p_addr(relay_addr).peer_id
            except Exception:  # noqa: BLE001 - a circuit address naming no relay is useless
                continue
            if str(relay) in self.banned:
                continue
            if not any(r.peer_id == str(relay) for r in self.routers):
                try:
                    await self._admit_router(relay_addr)
                except Exception as err:  # noqa: BLE001 - a relay that is not a router of this mesh is not used
                    logger.debug("router %s named by the DHT did not admit us: %s", relay, err)
                    continue
            out.append(multiaddr.Multiaddr(f"{relay_addr}/p2p-circuit/p2p/{target}"))
        return out

    async def _admit_router(self, addr: multiaddr.Multiaddr) -> AdmittedRouter:
        """Dials a router, runs the handshake and, its role verified, adds it
        to the admitted set."""
        info = await peer_info(addr)
        await dial(self.host, info)
        credential = await _authenticate_router(self.host, self.mesh, info.peer_id)
        router = AdmittedRouter(peer_id=str(info.peer_id), addr=addr, credential=credential)
        if not any(r.peer_id == router.peer_id for r in self.routers):
            self.routers.append(router)
        return router

    async def _connect_addr(self, ma: multiaddr.Multiaddr) -> ID:
        """Dials one multiaddr, through a relay when it says `/p2p-circuit`."""
        if "/p2p-circuit" in str(ma):
            relay_addr, target = split_circuit_address(ma)
            self._refuse_banned(target)
            relay = info_from_p2p_addr(relay_addr)
            if relay.peer_id not in self.host.get_connected_peers():
                await dial(self.host, await peer_info(relay_addr))
            if target not in self.host.get_connected_peers():
                await dial_through_relay(self.host, relay.peer_id, target)
            return target
        info = await peer_info(ma)
        self._refuse_banned(info.peer_id)
        await dial(self.host, info)
        return info.peer_id

    def _refuse_banned(self, peer_id: ID) -> None:
        if str(peer_id) in self.banned:
            raise PermissionError(f"peer {peer_id} is banned by the control plane")

    async def authenticate(self, peer: Peer) -> VerifiedBiscuit:
        """Connects to a peer and runs the mutual auth handshake, returning the
        peer's verified credential."""
        peer_id = await self.connect(peer)
        return await authenticate_with_peer(self.host, peer_id, self.mesh.auth_frame(), self.mesh.credential.control_plane_keys)

    async def discover(self, service: str, name: str | None = None, limit: int = 20) -> list[DiscoveredProvider]:
        """Looks the DHT up for peers offering a service: "mcp://calc", the same
        string call_tool and request take, or a type alone ("mcp") for every
        service of that type, or (type, name). The routers we are connected to
        seed the walk."""
        service_type, service_name = parse_service_target(service) if "://" in service else (service, name)
        if service_type not in ("mcp", "inference", "a2a", "egress"):
            raise ValueError(f"service type must be mcp, inference, a2a or egress, got {service_type!r}")
        seeds = [ID.from_base58(r.peer_id) for r in self.routers]
        return await find_providers(self.host, service_key(service_type, service_name), seeds, limit)

    def open_mcp(
        self,
        peer: Peer,
        target_service: str,
        *,
        required_labels: Optional[Mapping[str, str]] = None,
        agent: str = "",
    ):  # type: ignore[no-untyped-def]
        """Opens an MCP session with a provider for target_service
        ("mcp://<name>", or "" for the provider's own catalog tools):

            async with session.open_mcp(provider, "mcp://calc") as (mcp, verified): ...
        """

        @asynccontextmanager
        async def opened() -> AsyncIterator[tuple[ClientSession, VerifiedBiscuit]]:
            peer_id = await self.connect(peer)
            frame = self.mesh.auth_frame(target_service, agent)
            async with open_mcp_session(
                self.host, peer_id, frame, self.mesh.credential.control_plane_keys, required_labels=required_labels, egress_require_labels=self.egress_require_labels
            ) as opened_session:
                yield opened_session

        return opened()

    async def list_tools(self, peer: Peer, target_service: str, **options: Any) -> list[ToolInfo]:
        """Lists the tools a provider serves for a service."""
        async with self.open_mcp(peer, target_service, **options) as (mcp, _):
            return [ToolInfo(name=t.name, description=t.description) for t in (await mcp.list_tools()).tools]

    async def call_tool(
        self, peer: Peer, target_service: str, tool: str, args: Optional[Mapping[str, Any]] = None, **options: Any
    ) -> ToolCallResult:
        """Calls one tool on a provider's service."""
        async with self.open_mcp(peer, target_service, **options) as (mcp, _):
            result = await mcp.call_tool(tool, dict(args or {}))
            if not hasattr(result, "content"):
                raise RuntimeError(f"tool {tool} answered with {type(result).__name__}, not a result")
            return tool_call_result(result)  # type: ignore[arg-type]

    @property
    def policy_rules(self) -> list[str]:
        """The mesh policy rules this member evaluates for callers, as the
        control plane rendered them (PolicyConfigGetResponse.datalog_rules).
        Empty until accept_a2a() or sync_policy()."""
        return list(self._policy_rules or [])

    async def sync_policy(self) -> None:
        """Re-reads the mesh policy from the control plane."""
        self._policy_rules = await trio.to_thread.run_sync(self.mesh.control_plane.policy_rules, self.mesh.credential.biscuit)

    async def sync(self) -> "ControlPlaneSync":
        """Pulls keys, bans and router addresses from the control plane now, and
        the mesh policy when accepting callers, then applies them: a newly
        banned peer is disconnected and dropped from the admitted set.
        Concurrent calls run one after the other. Errors of individual parts
        are in the result."""
        async with self._sync_lock:
            result = await trio.to_thread.run_sync(self.mesh.sync_control_plane)
            if result.banned_peer_ids is not None:
                newly_banned, _ = self.banned.reconcile(canonical_peer_ids(result.banned_peer_ids), result.fetched_at)
                for peer in newly_banned:
                    await self._evict(peer)
            if self.endpoint is not None:
                try:
                    await self.sync_policy()
                except Exception as err:  # noqa: BLE001 - the last good policy stays in force
                    result.errors.append(f"policy: {err}")
            return result

    def trigger_sync(self) -> None:
        """Asks for a pull soon, after a random delay so a fleet told at once does not pull at once."""
        self._sync_trigger.set()

    async def _evict(self, banned_peer: str) -> None:
        """Drops a banned peer: its admission and its connections."""
        self.authenticated_peers.pop(banned_peer, None)
        try:
            await self.host.disconnect(ID.from_base58(banned_peer))
        except Exception:  # noqa: BLE001 - not connected, or already gone
            pass

    async def _sync_loop(self) -> None:
        """Pulls once shortly after join, then every interval and whenever
        triggered; each periodic wait is stretched by up to a tenth and each
        trigger delayed by up to the jitter, as sam-node's loop does."""
        delay = min(FIRST_CONTROL_PLANE_SYNC, self.control_plane_sync_interval) if self.control_plane_sync_interval > 0 else None
        while True:
            triggered = False
            with trio.move_on_after(delay) if delay is not None else trio.CancelScope():
                await self._sync_trigger.wait()
                triggered = True
            self._sync_trigger = trio.Event()
            if triggered and self.control_plane_sync_jitter > 0:
                await trio.sleep(random.uniform(0, self.control_plane_sync_jitter))  # noqa: S311 - jitter, not security
            try:
                result = await self.sync()
                if result.errors:
                    logger.warning("control plane sync: %s", "; ".join(result.errors))
            except Exception as err:  # noqa: BLE001
                logger.warning("control plane sync failed: %s", err)
            if self.control_plane_sync_interval > 0:
                delay = self.control_plane_sync_interval * random.uniform(1.0, 1.1)  # noqa: S311

    async def _reservation_loop(self) -> None:
        """Renews the relay reservation on each admitted router before the
        relay lets it expire, and again as soon as the connection to that
        router is found gone: the relay drops the reservation with the
        connection, and a member that kept advertising the relayed address
        would have every dial to it fail with NO_RESERVATION. A router that
        dropped the connection forgets the admission with it, so that one is
        dialed and authenticated again before the reservation is asked for."""
        while True:
            reserved = [r for r in self.routers if r.reservation is not None]
            if not reserved:
                return
            due = min(r.reservation.expire for r in reserved) - self.reservation_lead - time.time()  # type: ignore[union-attr]
            await trio.sleep(min(max(MIN_REFRESH_DELAY, due), self.reservation_check_interval))
            failed = False
            for i, r in enumerate(self.routers):
                if r.reservation is None:
                    continue
                expiring = r.reservation.expire - time.time() <= self.reservation_lead + MIN_REFRESH_DELAY
                if not expiring and ID.from_base58(r.peer_id) in self.host.get_connected_peers():
                    continue
                try:
                    self.routers[i] = await _reserve_again(self.host, self.mesh, r)
                except Exception as err:  # noqa: BLE001 - retried; the relay keeps the old reservation until it expires
                    failed = True
                    logger.warning("relay reservation on router %s not renewed, retrying in %.0fs: %s", r.peer_id, self.reservation_retry, err)
            if failed:
                await trio.sleep(self.reservation_retry)

    async def _events_loop(self, pubsub: Pubsub) -> None:
        """The control plane's gossip events, relayed by the routers. The topic
        validator drops anything not signed by a trusted control plane key, so
        a peer whose libp2p key signed the envelope still cannot get an
        unsigned event through."""

        def validate(_peer: ID, message) -> bool:  # type: ignore[no-untyped-def]
            return verify_mesh_event(bytes(message.data), self.mesh.credential.control_plane_keys) is not None

        pubsub.set_topic_validator(GOSSIP_EVENTS_TOPIC, validate, False)
        subscription = await pubsub.subscribe(GOSSIP_EVENTS_TOPIC)
        while True:
            message = await subscription.get()
            event = verify_mesh_event(bytes(message.data), self.mesh.credential.control_plane_keys)
            if event is None:
                continue
            if event.type == pb.MeshEvent.BANNED:
                # Not persisted: a restarted member picks the ban back up from /info.
                if self.banned.add(event.peer_id, event.event_time.ToMilliseconds()):
                    logger.info("peer %s banned by the control plane", event.peer_id)
                    await self._evict(event.peer_id)
            elif event.type == pb.MeshEvent.KEY_ROTATION:
                if len(event.new_public_key) == 32:
                    self.mesh.add_trusted_key(bytes(event.new_public_key))
                self.trigger_sync()
            elif event.type == pb.MeshEvent.POLICY_UPDATE:
                self.trigger_sync()

    async def request(
        self,
        peer: Peer,
        target_service: str,
        path: str,
        *,
        method: str = "GET",
        headers: Optional[Mapping[str, str]] = None,
        body: bytes | str | None = None,
        agent: str = "",
    ) -> HTTPResponse:
        """Calls an inference or A2A service on a provider over /libp2p-http,
        the way sam-node's egress proxy does for /sam/<peer>/<type>/<name>/<path>."""
        peer_id = await self._egress_peer(peer)
        return await http_request_over_stream(
            self.host, peer_id, self.mesh.credential.biscuit, target_service, path, method=method, headers=headers, body=body, agent=agent
        )

    async def _egress_peer(self, peer: Peer) -> ID:
        """The peer an HTTP call goes out to, verified as an enrolled member
        holding the floor before anything is sent (sam-node's VerifyPeerLabels)."""
        peer_id = await self.connect(peer)
        if self._egress_verdicts.get(str(peer_id), 0.0) > time.monotonic():
            return peer_id
        provider = await authenticate_with_peer(self.host, peer_id, self.mesh.auth_frame(), self.mesh.credential.control_plane_keys)
        require_egress_labels(provider, self.egress_require_labels)
        self._egress_verdicts[str(peer_id)] = time.monotonic() + EGRESS_VERDICT_TTL
        return peer_id

    async def accept_a2a(self, target: Union[str, HTTPHandler], *, name: str = DEFAULT_A2A_NAME) -> str:
        """Makes this member's agent reachable: other members call it as
        `a2a://<name>` by peer ID, through a router, and the SDK answers
        /libp2p-http with target, the base URL of an A2A server beside this
        process or a handler in it. Nothing is announced: no DHT record, no
        catalog entry. A tool, a model or a service others should find by
        name is published by a sam-node. Fetches the mesh policy first and
        keeps it current; a policy that cannot be read fails the call, since
        an agent without it could only authorize what callers carry in their
        own tokens. Returns the service target callers use. One agent per
        session."""
        if self.endpoint is not None:
            raise RuntimeError(f"this session already accepts {self.endpoint.service}")
        endpoint = A2AEndpoint(target=target, name=name)
        await self.sync_policy()
        options = ProviderOptions(
            authorizer=ProviderAuthorizerOptions(
                trusted_keys=lambda: self.mesh.credential.control_plane_keys,
                own_biscuit=lambda: self.mesh.credential.biscuit,
                policy_rules=lambda: self._policy_rules or [],
            ),
            on_authorized=lambda peer, verified, _target: self.authenticated_peers.__setitem__(peer, verified.expiration),
            is_banned=lambda peer: peer in self.banned,
        )
        self.host.set_stream_handler(HTTP_PROTOCOL, http_ingress_handler(endpoint, options))
        if self._nursery is not None:
            self._nursery.start_soon(self._policy_loop)
        self.endpoint = endpoint
        return endpoint.service

    async def _policy_loop(self) -> None:
        while True:
            await trio.sleep(self.policy_sync_interval)
            try:
                await self.sync_policy()
            except Exception as err:  # noqa: BLE001 - the last good policy stays in force
                logger.warning("mesh policy sync failed: %s", err)


async def _refresh_loop(mesh: "AgentMesh", lead: float, retry: float) -> None:
    while True:
        due = mesh.credential.expiration - lead - time.time()
        await trio.sleep(max(MIN_REFRESH_DELAY, due))
        try:
            # The control plane client is synchronous; keep the loop free.
            await trio.to_thread.run_sync(mesh.refresh)
        except Exception as err:  # noqa: BLE001 - a failed refresh is retried, the session stays up
            logger.warning("credential refresh failed, retrying in %.0fs: %s", retry, err)
            await trio.sleep(retry)


def _single_cause(group: BaseException) -> BaseException:
    """trio wraps a failure inside `host.run` in one ExceptionGroup per nursery.
    A join that failed for one reason should raise that reason."""
    while isinstance(group, BaseExceptionGroup) and len(group.exceptions) == 1:
        group = group.exceptions[0]
    return group


@asynccontextmanager
async def join_mesh(
    mesh: "AgentMesh",
    *,
    listen_addrs: Sequence[str] = (),
    router_addresses: Optional[Sequence[str]] = None,
    reserve: bool = True,
    refresh_lead: float = DEFAULT_REFRESH_LEAD,
    refresh_retry: float = DEFAULT_REFRESH_RETRY,
    reservation_lead: float = RESERVATION_RENEW_LEAD,
    reservation_check_interval: float = RESERVATION_CHECK_INTERVAL,
    policy_sync_interval: float = DEFAULT_POLICY_SYNC,
    control_plane_sync_interval: float = DEFAULT_CONTROL_PLANE_SYNC,
    control_plane_sync_jitter: float = DEFAULT_CONTROL_PLANE_SYNC_JITTER,
    egress_require_labels: Optional[Mapping[str, str]] = None,
) -> AsyncIterator[MeshSession]:
    """Implements AgentMesh.join(); lives here to keep mesh.py free of libp2p.
    router_addresses names the routers to join through instead of the ones the
    credential lists; a peer behind another router is still reached, see
    MeshSession.connect. egress_require_labels is the floor every provider
    this member calls must attest, see MeshSession."""
    router_addrs = [multiaddr.Multiaddr(a) for a in (mesh.credential.router_addresses if router_addresses is None else router_addresses)]
    if not router_addrs:
        raise RuntimeError("credential lists no router addresses; the control plane had no active router at enrollment" if router_addresses is None else "router_addresses names no router")

    host, listen = create_mesh_host(mesh.identity, listen_addrs)
    authenticated: dict[str, datetime] = {}
    banned = BanSet()
    host.set_stream_handler(
        AUTH_PROTOCOL,
        auth_stream_handler(
            own_biscuit=lambda: mesh.credential.biscuit,
            trusted_keys=lambda: mesh.credential.control_plane_keys,
            on_authenticated=lambda peer, verified: authenticated.__setitem__(peer, verified.expiration),
            is_banned=lambda peer: peer in banned,
        ),
    )
    host.set_stream_handler(STOP_PROTOCOL, stop_stream_handler(host))
    # Built before any connection: Pubsub learns of peers through a notifee it
    # registers here. StrictSign, as every Go component pins it.
    gossipsub = GossipSub(protocols=[GOSSIPSUB_V12, GOSSIPSUB_V11, GOSSIPSUB_V10], degree=6, degree_low=4, degree_high=12)
    pubsub = Pubsub(host, gossipsub, strict_signing=True)
    logging.getLogger("libp2p.host.basic_host").addFilter(_MESHSUB_NOISE)

    try:
        async with host.run(listen_addrs=listen), background_trio_service(pubsub), background_trio_service(gossipsub):
            await pubsub.wait_until_ready()
            admitted = await _admit(host, mesh, router_addrs, reserve)
            async with trio.open_nursery() as nursery:
                nursery.start_soon(_refresh_loop, mesh, refresh_lead, refresh_retry)
                session = MeshSession(
                    mesh=mesh,
                    host=host,
                    routers=admitted,
                    authenticated_peers=authenticated,
                    banned=banned,
                    egress_require_labels=egress_require_labels,
                    policy_sync_interval=policy_sync_interval,
                    control_plane_sync_interval=control_plane_sync_interval,
                    control_plane_sync_jitter=control_plane_sync_jitter,
                    reservation_lead=reservation_lead,
                    reservation_retry=refresh_retry,
                    reservation_check_interval=reservation_check_interval,
                    _nursery=nursery,
                )
                nursery.start_soon(session._events_loop, pubsub)  # noqa: SLF001
                nursery.start_soon(session._sync_loop)  # noqa: SLF001
                nursery.start_soon(session._reservation_loop)  # noqa: SLF001
                try:
                    yield session
                finally:
                    nursery.cancel_scope.cancel()
    except BaseExceptionGroup as group:
        cause = _single_cause(group)
        if cause is group:
            raise
        raise cause from None


async def _admit(host: IHost, mesh: "AgentMesh", router_addrs: list[multiaddr.Multiaddr], reserve: bool) -> list[AdmittedRouter]:
    """Authenticates with every router the control plane named, as the JS SDK
    and sam-node do, and reserves a relay slot on the first that admits us.
    A peer reserves on the first router of its own list, so a caller that
    only knew one router could not reach a peer whose list started
    elsewhere; `connect` tries the relayed path through each of these. The
    routers are dialed at once: one the control plane lists but this member
    cannot reach costs a dial timeout, not one per router behind it."""
    admitted: dict[int, AdmittedRouter] = {}
    failures: list[str] = []

    async def admit(index: int, addr: multiaddr.Multiaddr) -> None:
        try:
            info = await peer_info(addr)
            await dial(host, info)
            credential = await _authenticate_router(host, mesh, info.peer_id)
            admitted[index] = AdmittedRouter(peer_id=str(info.peer_id), addr=addr, credential=credential)
        except Exception as err:  # noqa: BLE001 - every router is tried, the summary names each failure
            failures.append(f"{addr}: {err}")

    async with trio.open_nursery() as nursery:
        for index, addr in enumerate(router_addrs):
            nursery.start_soon(admit, index, addr)
    routers = [admitted[i] for i in sorted(admitted)]
    if not routers:
        raise RuntimeError("no router admitted this member:\n  " + "\n  ".join(failures))
    if reserve:
        for index, router in enumerate(routers):
            try:
                routers[index] = replace(router, reservation=await reserve_relay(host, ID.from_base58(router.peer_id)))
                break
            except Exception as err:  # noqa: BLE001 - the next admitted router is asked
                failures.append(f"{router.addr}: {err}")
        else:
            raise RuntimeError("no router reserved a relay slot for this member:\n  " + "\n  ".join(failures))
    return routers


async def _authenticate_router(host: IHost, mesh: "AgentMesh", peer_id: ID) -> VerifiedBiscuit:
    credential = await authenticate_with_peer(host, peer_id, mesh.auth_frame(), mesh.credential.control_plane_keys)
    # Enforced under the key that verified the token; a relay that
    # is not a router must not become our way onto the mesh.
    require_role(credential, ROLE_ROUTER)
    return credential


async def _reserve_again(host: IHost, mesh: "AgentMesh", router: AdmittedRouter) -> AdmittedRouter:
    peer_id = ID.from_base58(router.peer_id)
    credential = router.credential
    try:
        if peer_id not in host.get_connected_peers():
            await dial(host, await peer_info(router.addr))
            credential = await _authenticate_router(host, mesh, peer_id)
        reservation = await reserve_relay(host, peer_id)
    except Exception:
        # A connection that failed us is not kept: it may be half-open, or up
        # but unauthenticated. The retry then dials and authenticates again.
        try:
            await host.disconnect(peer_id)
        except Exception:  # noqa: BLE001 - already gone
            pass
        raise
    return replace(router, credential=credential, reservation=reservation)
