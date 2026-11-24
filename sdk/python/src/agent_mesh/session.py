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
from typing import TYPE_CHECKING, AbstractSet, Any, AsyncIterator, Awaitable, Callable, Mapping, Optional, Sequence, Union

import multiaddr
import trio
from libp2p.abc import IHost
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo, info_from_p2p_addr
from libp2p.pubsub.floodsub import PROTOCOL_ID as FLOODSUB
from libp2p.pubsub.floodsub import FloodSub
from libp2p.pubsub.pubsub import Pubsub
from libp2p.tools.anyio_service import background_trio_service
from mcp import ClientSession
from mcp.types import PaginatedRequestParams

from ._proto import circuit_pb2 as circuit
from ._proto import agentmesh_pb2 as pb
from .auth import (
    AUTH_PROTOCOL,
    GOAWAY_PROTOCOL,
    ROUTER_SHUN_DURATION,
    auth_stream_handler,
    authenticate_with_peer,
    go_away_reason_name,
    go_away_stream_handler,
)
from .authorizer import ProviderAuthorizerOptions
from .biscuit import ROLE_ROUTER, VerifiedBiscuit, attenuate_biscuit, require_publish, require_role, seal_biscuit
from .controlplane import ROLE_NODE
from .credential import encode_auth_frame
from .discovery import DiscoveredProvider, find_peer, find_providers, parse_service_target, peer_key, provide, service_key, withdraw
from .host import create_mesh_host, dial, dial_addrs, peer_info
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
    mesh_url,
)
from .mcp_client import ToolCallResult, ToolInfo, open_mcp_session, require_egress_labels, tool_call_result
from .relay import STOP_PROTOCOL, dial_through_relay, reserve_relay, split_circuit_address, stop_stream_handler
from .sync import GOSSIP_EVENTS_TOPIC, BanSet, verify_mesh_event

if TYPE_CHECKING:
    from .mesh import AgentMesh, ControlPlaneSync

logger = logging.getLogger("agent_mesh")

# Number of routers a member attaches to and reserves on by default, matching agentmesh-node's defaultRouters.
DEFAULT_ROUTERS = 2
# Backoff delays (seconds) when redialing a held router whose connection dropped before failing over.
ROUTER_REDIAL_BACKOFFS: tuple[float, ...] = (2.0, 4.0, 8.0)

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
# agentmesh-node's --control-plane-sync-interval default.
DEFAULT_POLICY_SYNC = 15 * 60.0
# agentmesh-node's --control-plane-sync-interval default, and its 2s first pull.
DEFAULT_CONTROL_PLANE_SYNC = 15 * 60.0
FIRST_CONTROL_PLANE_SYNC = 2.0
DEFAULT_CONTROL_PLANE_SYNC_JITTER = 2.0
# How often a member announces where it is reached: agentmesh-node's default
# reprovide interval, a third of the mesh's default record TTL.
DEFAULT_ANNOUNCE_INTERVAL = 5 * 60.0
# What leaving the mesh waits for the member's record to be withdrawn.
WITHDRAW_TIMEOUT = 2.0
# How long a provider's positive egress verdict is kept; agentmesh-node's labelGateTTL.
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
    """py-libp2p's pubsub opens a stream to every new peer and the host logs
    an error for each one that does not answer. Peers that leave during that
    exchange and members without pubsub are ordinary on the mesh."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        return not ("Failed to open stream" in message and ("/meshsub/" in message or "/floodsub/" in message))


_MESHSUB_NOISE = _MeshsubNoise()


@dataclass(frozen=True)
class AdmittedRouter:
    peer_id: str
    addr: multiaddr.Multiaddr
    credential: VerifiedBiscuit
    reservation: circuit.Reservation | None = None


@dataclass(frozen=True)
class RouterCandidate:
    """One router candidate from the control plane's /info catalog."""

    peer_id: str
    addresses: list[multiaddr.Multiaddr]
    labels: dict[str, str] = field(default_factory=dict)
    connections: int = 0
    connection_limit: int = 0


def candidates_from_router_infos(
    routers: Sequence[pb.RouterInfo],
    fallback_addresses: Sequence[str],
    router_metadata: Sequence[pb.RouterInfo] = (),
) -> list[RouterCandidate]:
    """Builds router candidates from ControlPlaneInfoResponse.routers, falling
    back to router_addresses when routers is empty (an older control plane).
    When router_metadata is provided alongside explicit fallback_addresses,
    labels and load from router_metadata are attached by peer_id."""
    if routers:
        out: list[RouterCandidate] = []
        for r in routers:
            peer_id: Optional[str] = None
            if r.peer_id:
                try:
                    peer_id = canonical_peer_id(r.peer_id)
                except ValueError:
                    peer_id = None
            addrs: list[multiaddr.Multiaddr] = []
            for raw in r.addresses:
                try:
                    ma = multiaddr.Multiaddr(raw)
                except Exception:  # noqa: BLE001
                    continue
                target: Optional[str] = None
                try:
                    target = str(info_from_p2p_addr(ma).peer_id)
                except Exception:  # noqa: BLE001
                    target = None
                if peer_id is None and target is not None:
                    peer_id = target
                if peer_id is not None and (target is None or target == peer_id):
                    if target is None:
                        ma = multiaddr.Multiaddr(f"{ma}/p2p/{peer_id}")
                    addrs.append(ma)
            if peer_id is None or not addrs:
                continue
            out.append(
                RouterCandidate(
                    peer_id=peer_id,
                    addresses=addrs,
                    labels=dict(r.labels),
                    connections=r.connections,
                    connection_limit=r.connection_limit,
                )
            )
        return out

    meta_by_peer: dict[str, pb.RouterInfo] = {}
    for r in router_metadata:
        if r.peer_id:
            try:
                meta_by_peer[canonical_peer_id(r.peer_id)] = r
            except ValueError:
                continue

    by_id: dict[str, RouterCandidate] = {}
    for raw in fallback_addresses:
        try:
            ma = multiaddr.Multiaddr(raw)
            peer_id = str(info_from_p2p_addr(ma).peer_id)
        except Exception:  # noqa: BLE001
            continue
        existing = by_id.get(peer_id)
        if existing is not None:
            existing.addresses.append(ma)
        else:
            meta = meta_by_peer.get(peer_id)
            by_id[peer_id] = RouterCandidate(
                peer_id=peer_id,
                addresses=[ma],
                labels=dict(meta.labels) if meta is not None else {},
                connections=meta.connections if meta is not None else 0,
                connection_limit=meta.connection_limit if meta is not None else 0,
            )
    return list(by_id.values())


def _matches_labels(router_labels: Mapping[str, str], selector: Optional[Mapping[str, str]]) -> bool:
    if not selector:
        return True
    return all(router_labels.get(k) == v for k, v in selector.items())


def _count_matching_labels(router_labels: Mapping[str, str], prefer: Optional[Mapping[str, str]]) -> int:
    if not prefer:
        return 0
    return sum(1 for k, v in prefer.items() if router_labels.get(k) == v)


def _router_load(candidate: RouterCandidate) -> float:
    if candidate.connection_limit <= 0:
        return 0.5
    load = candidate.connections / candidate.connection_limit
    return min(max(load, 0.0), 1.0)


def select_routers(
    candidates: Sequence[RouterCandidate],
    k: int,
    *,
    selector: Optional[Mapping[str, str]] = None,
    prefer: Optional[Mapping[str, str]] = None,
    attached: Optional[AbstractSet[str]] = None,
    shunned: Optional[Mapping[str, float]] = None,
    now: Optional[float] = None,
    rand: Callable[[], float] = random.random,
) -> list[RouterCandidate]:
    """Picks up to k routers from candidates, mirroring agentmesh-node's selectRouters:
    filters by selector, excludes already-attached and currently-shunned routers,
    and orders by matching prefer labels (descending) then load + jitter (ascending)."""
    if k <= 0:
        return []
    now_ts = time.time() if now is None else now
    scored: list[tuple[int, float, int, RouterCandidate]] = []
    for idx, c in enumerate(candidates):
        if attached is not None and c.peer_id in attached:
            continue
        if shunned is not None and shunned.get(c.peer_id, 0.0) > now_ts:
            continue
        if not _matches_labels(c.labels, selector):
            continue
        prefer_score = _count_matching_labels(c.labels, prefer)
        load = _router_load(c) + rand() * 0.05
        scored.append((-prefer_score, load, idx, c))
    scored.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in scored[:k]]


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
    # Count of /mesh/goaway/1.0.0 frames received from held routers, keyed by reason name (DRAINING, OVERLOADED, REASON_UNSPECIFIED).
    go_away_received: dict[str, int] = field(default_factory=dict)
    # Routers currently shunned (after a go-away or failed redial), mapped to the unix seconds when the shun expires.
    shunned_routers: dict[str, float] = field(default_factory=dict)
    # This member's agent, once accept_a2a was called.
    endpoint: Optional[A2AEndpoint] = None
    # agentmesh-node's egress.require_labels for an SDK member: every provider this
    # session calls must attest all of these pairs, on top of a call's
    # required_labels. Held on every call, MCP and HTTP alike; no call waives it.
    egress_require_labels: Optional[Mapping[str, str]] = None
    reserve: bool = True
    target_routers: int = DEFAULT_ROUTERS
    router_selector: Optional[Mapping[str, str]] = None
    router_prefer: Optional[Mapping[str, str]] = None
    pinned_router_addresses: Optional[list[str]] = None
    router_redial_backoffs: Sequence[float] = ROUTER_REDIAL_BACKOFFS
    policy_sync_interval: float = DEFAULT_POLICY_SYNC
    control_plane_sync_interval: float = DEFAULT_CONTROL_PLANE_SYNC
    control_plane_sync_jitter: float = DEFAULT_CONTROL_PLANE_SYNC_JITTER
    reservation_lead: float = RESERVATION_RENEW_LEAD
    reservation_retry: float = DEFAULT_REFRESH_RETRY
    reservation_check_interval: float = RESERVATION_CHECK_INTERVAL
    announce_interval: float = DEFAULT_ANNOUNCE_INTERVAL
    _held_router_ids: set[str] = field(default_factory=set, repr=False)
    # The addresses of the record last announced under this member's peer key.
    _announced: list[str] = field(default_factory=list, repr=False)
    _relay_lock: trio.Lock = field(default_factory=trio.Lock, repr=False)
    _relay_trigger: trio.Event = field(default_factory=trio.Event, repr=False)
    _nursery: Optional[trio.Nursery] = field(default=None, repr=False)
    _policy_rules: Optional[list[str]] = field(default=None, repr=False)
    _sync_lock: trio.Lock = field(default_factory=trio.Lock, repr=False)
    _sync_trigger: trio.Event = field(default_factory=trio.Event, repr=False)
    # Peers verified as enrolled and holding the floor, until when; misses are never kept.
    _egress_verdicts: dict[str, float] = field(default_factory=dict, repr=False)
    _task_biscuit: Optional[bytes] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self._held_router_ids and self.routers:
            for r in self.routers:
                self._held_router_ids.add(r.peer_id)

    @property
    def peer_id(self) -> str:
        return str(self.host.get_id())

    @property
    def biscuit(self) -> bytes:
        """The Biscuit presented on outbound service calls (task-attenuated when derived via attenuate())."""
        return self._task_biscuit if self._task_biscuit is not None else self.mesh.credential.biscuit

    def is_held_router(self, peer_id: str) -> bool:
        """Whether peer_id is currently in this member's held router set."""
        try:
            canonical = canonical_peer_id(peer_id)
        except ValueError:
            return False
        return canonical in self._held_router_ids

    def _want_routers(self) -> int:
        if self.pinned_router_addresses is not None:
            candidates = candidates_from_router_infos([], self.pinned_router_addresses, getattr(self.mesh, "routers", ()))
            return min(self.target_routers, max(1, len(candidates)))
        return self.target_routers

    def _candidates_for_holding(self) -> list[RouterCandidate]:
        if self.pinned_router_addresses is not None:
            return candidates_from_router_infos([], self.pinned_router_addresses, getattr(self.mesh, "routers", ()))
        return candidates_from_router_infos(getattr(self.mesh, "routers", ()), self.mesh.credential.router_addresses)

    def _shun_router(self, peer_id: str, duration: float = ROUTER_SHUN_DURATION) -> None:
        now = time.time()
        for k, exp in list(self.shunned_routers.items()):
            if exp <= now:
                self.shunned_routers.pop(k, None)
        until = now + (duration if duration > 0 else ROUTER_SHUN_DURATION)
        existing = self.shunned_routers.get(peer_id, 0.0)
        if until > existing:
            self.shunned_routers[peer_id] = until

    async def _detach_router(self, peer_id: str) -> None:
        self._held_router_ids.discard(peer_id)
        self.routers[:] = [r for r in self.routers if r.peer_id != peer_id]
        try:
            await self.host.disconnect(ID.from_base58(peer_id))
        except Exception:  # noqa: BLE001 - not connected, or already gone
            pass

    async def handle_go_away(self, peer_id: str, msg: pb.RouterGoAway, retry_after: float) -> bool:
        """Handles a RouterGoAway message from a router: ignores it if peer_id is
        not in the held set; otherwise records the reason, shuns the router for
        retry_after seconds, drops it from the held set, and tops up from the
        catalog immediately."""
        try:
            canonical = canonical_peer_id(peer_id)
        except ValueError:
            return False
        if canonical not in self._held_router_ids:
            return False
        reason = go_away_reason_name(msg.reason)
        self.go_away_received[reason] = self.go_away_received.get(reason, 0) + 1
        self._shun_router(canonical, retry_after)
        await self._detach_router(canonical)
        await self.top_up_routers()
        self._relay_trigger.set()
        return True

    async def top_up_routers(self) -> list[str]:
        """Attaches and reserves on additional routers from the catalog until this
        session holds _want_routers() routers or no more eligible candidates remain.
        One top-up at a time: the reservation loop and a go-away both call it,
        and two picking the same router at once would hold it twice, or shun
        it while holding it."""
        async with self._relay_lock:
            return await self._top_up_routers()

    async def _top_up_routers(self) -> list[str]:
        failures: list[str] = []
        want = self._want_routers()
        if len(self._held_router_ids) >= want:
            return failures
        candidates = self._candidates_for_holding()
        tried: set[str] = set()
        while len(self._held_router_ids) < want:
            need = want - len(self._held_router_ids)
            exclude = self._held_router_ids | tried | set(self.banned.peers())
            picks = select_routers(
                candidates,
                need,
                selector=self.router_selector,
                prefer=self.router_prefer,
                attached=exclude,
                shunned=self.shunned_routers,
            )
            if not picks:
                break
            tried.update(c.peer_id for c in picks)
            admitted = await _admit_candidates(self.host, self.mesh, picks, self.reserve, failures)
            for router in admitted:
                self._held_router_ids.add(router.peer_id)
                idx = next((i for i, r in enumerate(self.routers) if r.peer_id == router.peer_id), None)
                if idx is not None:
                    self.routers[idx] = router
                else:
                    self.routers.append(router)
            for c in picks:
                if not any(r.peer_id == c.peer_id for r in admitted):
                    self._shun_router(c.peer_id, ROUTER_SHUN_DURATION)
            if not admitted and len(picks) < need:
                break
        return failures

    def attenuate(self, rule: pb.TaskAuthorizationRule) -> "MeshSession":
        """Returns a task-scoped MeshSession view sharing the underlying libp2p host
        whose outbound MCP and HTTP service calls carry a Biscuit attenuated offline
        in memory with rule."""
        next_biscuit = attenuate_biscuit(self.biscuit, rule, self.mesh.credential.control_plane_keys)
        return replace(self, _task_biscuit=next_biscuit)

    def seal(self) -> "MeshSession":
        """Returns a MeshSession view whose outbound Biscuit is sealed so downstream
        holders cannot append any further blocks."""
        sealed = seal_biscuit(self.biscuit, self.mesh.credential.control_plane_keys)
        return replace(self, _task_biscuit=sealed)

    @staticmethod
    def mesh_url(peer_id: str, target_service: str, path: str = "") -> str:
        """The URL an httpx client on `MeshTransport` uses for a service on a
        peer: http://mesh/mesh/<peer-id>/<type>/<name>/<path>, the shape of
        agentmesh-node's egress proxy and of an agent card rewritten for the mesh."""
        return mesh_url(canonical_peer_id(peer_id), target_service, path)

    @property
    def agent_url(self) -> Optional[str]:
        """The mesh URL of this member's own agent, once accept_a2a was called."""
        return self.mesh_url(self.peer_id, self.endpoint.service) if self.endpoint is not None else None

    async def announce(self) -> None:
        """Announces where this member is reached, its relayed addresses on the
        routers it holds, under its peer key, so that a peer attached to other
        routers finds it by ID. Runs after join, when the addresses change and
        every announce_interval; the record outlives its last announcement by
        the mesh's record TTL. A member with no relayed address announces
        nothing: there is nothing to reach it at."""
        if self._task_biscuit is not None:
            return
        addrs = sorted(self.relay_addresses)
        if not addrs:
            return
        await provide(self.host, self._directory_routers(), peer_key(self.host.get_id()), [multiaddr.Multiaddr(a) for a in addrs])
        self._announced = addrs

    async def _announce_loop(self) -> None:
        while True:
            await trio.sleep(self.announce_interval)
            try:
                await self.announce()
            except Exception as err:  # noqa: BLE001 - the next announcement retries
                logger.warning("announcing where this member is reached: %s", err)

    async def _announce_if_moved(self) -> None:
        """Announces again when the relayed addresses changed since the last
        announcement, as after a router was replaced."""
        if self.relay_addresses and sorted(self.relay_addresses) != self._announced:
            try:
                await self.announce()
            except Exception as err:  # noqa: BLE001
                logger.warning("announcing where this member is reached: %s", err)

    async def _withdraw_self(self) -> None:
        """Withdraws this member's record as it leaves; best effort, the record
        expires on its own within the record TTL."""
        if not self._announced or self._task_biscuit is not None:
            return
        with trio.move_on_after(WITHDRAW_TIMEOUT):
            try:
                await withdraw(self.host, self._directory_routers(), peer_key(self.host.get_id()))
            except Exception as err:  # noqa: BLE001
                logger.debug("withdrawing this member's record: %s", err)
        self._announced = []

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
        peer is refused. The peer's own addresses and the relayed path through
        every admitted router are dialed at once. A peer none of them reaches
        is looked up in the routers' DHT and tried through every router the
        control plane lists that this member has not joined through, again at
        once; a relay opens a circuit only for a source it authenticated, so
        each such router is admitted on the way. Which router each side joined
        through does not decide whether they can talk. A peer a rollout
        replaced is still in the routers' tables for a while; its dead
        address answers nothing, and costs the caller one dial timeout per
        step, not one per address or per router."""
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
        circuits = [multiaddr.Multiaddr(f"{r.addr}/p2p-circuit{suffix}") for r in self.routers]
        if await self._connect_through(target, direct, circuits, [], failures):
            return target
        tried = {str(a) for a in direct}
        routed, relays = await self._routed_addresses(target)
        routed = [a for a in routed if str(a) not in tried]
        for addr in self._unjoined_routers(target):
            if not any(str(r) == str(addr) for r in relays):
                relays.append(addr)
        if await self._connect_through(target, routed, [], relays, failures):
            return target
        raise ConnectionError(f"cannot reach {target}:\n  " + "\n  ".join(failures))

    async def _connect_through(
        self, target: ID, direct: list[multiaddr.Multiaddr], circuits: list[multiaddr.Multiaddr], relays: list[multiaddr.Multiaddr], failures: list[str]
    ) -> bool:
        """Dials target every way given at once: its direct addresses as one
        dial, each circuit, and each relay after admitting it. The first that
        reaches target ends the others, and each that failed adds its reason
        to failures."""
        reached = False
        suffix = f"/p2p/{target}"

        async def attempt(what: str, go: Callable[[], Awaitable[object]], nursery: trio.Nursery) -> None:
            nonlocal reached
            try:
                await go()
            except Exception as err:  # noqa: BLE001 - the other attempts go on
                failures.append(f"{what}: {err}")
                return
            reached = True
            nursery.cancel_scope.cancel()

        async def through_relay(addr: multiaddr.Multiaddr) -> None:
            admitted = await self._admit_router(addr)
            await self._connect_addr(multiaddr.Multiaddr(f"{admitted.addr}/p2p-circuit{suffix}"))

        async with trio.open_nursery() as nursery:
            if direct:
                nursery.start_soon(attempt, f"direct {[str(a) for a in direct]}", lambda: dial(self.host, PeerInfo(target, direct)), nursery)
            for ma in circuits:
                nursery.start_soon(attempt, str(ma), lambda ma=ma: self._connect_addr(ma), nursery)
            for addr in relays:
                nursery.start_soon(attempt, f"{addr}/p2p-circuit{suffix}", lambda addr=addr: through_relay(addr), nursery)
        return reached or target in self.host.get_connected_peers()

    def _unjoined_routers(self, target: ID) -> list[multiaddr.Multiaddr]:
        """The routers the control plane lists that this member has not joined
        through. The list is the one the credential carries, refreshed by
        every control plane pull, so a router that came up after join is
        among them."""
        out: list[multiaddr.Multiaddr] = []
        for text in self.mesh.credential.router_addresses:
            try:
                addr = multiaddr.Multiaddr(text)
                router = info_from_p2p_addr(addr).peer_id
            except Exception:  # noqa: BLE001 - not a router address
                continue
            if router == target or str(router) in self.banned or any(r.peer_id == str(router) for r in self.routers):
                continue
            out.append(addr)
        return out

    async def _routed_addresses(self, target: ID) -> tuple[list[multiaddr.Multiaddr], list[multiaddr.Multiaddr]]:
        """What the directory knows for a peer: its direct addresses this
        host can dial, without the peer suffix, and the relays it reserved on
        that are not admitted routers of this member; those the caller tried
        already."""
        direct: list[multiaddr.Multiaddr] = []
        relays: list[multiaddr.Multiaddr] = []
        suffix = f"/p2p/{target}"
        for ma in await find_peer(self.host, self._directory_routers(), target):
            text = str(ma)
            if "/p2p-circuit" not in text:
                try:
                    direct.extend(multiaddr.Multiaddr(str(m).removesuffix(suffix)) for m in await dial_addrs(ma))
                except Exception:  # noqa: BLE001 - an address this host cannot use
                    pass
                continue
            relay_addr = multiaddr.Multiaddr(text[: text.index("/p2p-circuit")])
            try:
                relay = info_from_p2p_addr(relay_addr).peer_id
            except Exception:  # noqa: BLE001 - a circuit address naming no relay is useless
                continue
            if str(relay) in self.banned or any(r.peer_id == str(relay) for r in self.routers) or any(str(r) == str(relay_addr) for r in relays):
                continue
            relays.append(relay_addr)
        return direct, relays

    def _directory_routers(self) -> list[ID]:
        """The routers this member holds and is connected to, which answer its
        directory requests. A request goes over the session the handshake
        opened, never over a dial of its own: a router admits a connection it
        has verified, and the reservation loop is what reconnects."""
        connected = set(self.host.get_connected_peers())
        return [ID.from_base58(r.peer_id) for r in self.routers if ID.from_base58(r.peer_id) in connected]

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
        """Asks the directory for peers offering a service: "mcp://calc", the
        same string call_tool and request take, or a type alone ("mcp") for
        every service of that type, or (type, name). A router this member
        holds answers."""
        service_type, service_name = parse_service_target(service) if "://" in service else (service, name)
        if service_type not in ("mcp", "inference", "a2a", "egress"):
            raise ValueError(f"service type must be mcp, inference, a2a or egress, got {service_type!r}")
        return await find_providers(self.host, self._directory_routers(), service_key(service_type, service_name), limit)

    def open_mcp(
        self,
        peer: Peer,
        target_service: str,
        *,
        required_labels: Optional[Mapping[str, str]] = None,
    ):  # type: ignore[no-untyped-def]
        """Opens an MCP session with a provider for target_service
        ("mcp://<name>", or "" for the provider's own catalog tools):

            async with session.open_mcp(provider, "mcp://calc") as (mcp, verified): ...
        """

        @asynccontextmanager
        async def opened() -> AsyncIterator[tuple[ClientSession, VerifiedBiscuit]]:
            peer_id = await self.connect(peer)
            frame = encode_auth_frame(self.biscuit, target_service)
            async with open_mcp_session(
                self.host,
                peer_id,
                frame,
                self.mesh.credential.control_plane_keys,
                required_labels=required_labels,
                egress_require_labels=self.egress_require_labels,
                policy_rules=self.policy_rules,
            ) as opened_session:
                yield opened_session

        return opened()

    async def list_tools(self, peer: Peer, target_service: str, **options: Any) -> list[ToolInfo]:
        """Lists the tools a provider serves for a service."""
        async with self.open_mcp(peer, target_service, **options) as (mcp, _):
            tools: list[ToolInfo] = []
            cursors: set[str] = set()
            params = None
            while True:
                page = await mcp.list_tools(params=params)
                tools.extend(ToolInfo(name=tool.name, description=tool.description) for tool in page.tools)
                cursor = page.next_cursor
                if cursor is None:
                    return tools
                if cursor in cursors or len(cursors) >= 256:
                    raise RuntimeError("provider returned an unbounded tool catalog")
                cursors.add(cursor)
                params = PaginatedRequestParams(cursor=cursor)

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
        Empty until the first control plane sync, accept_a2a() or sync_policy()."""
        return list(self._policy_rules or [])

    async def sync_policy(self) -> None:
        """Re-reads the mesh policy from the control plane."""
        self._policy_rules = await trio.to_thread.run_sync(self.mesh.control_plane.policy_rules, self.mesh.identity, self.mesh.credential.biscuit)

    async def sync(self) -> "ControlPlaneSync":
        """Pulls keys, bans and router addresses from the control plane now, and
        the mesh policy when accepting callers, then applies them: a newly
        banned peer is disconnected and dropped from the admitted set.
        Concurrent calls run one after the other. Errors of individual parts
        are in the result."""
        async with self._sync_lock:
            result = await trio.to_thread.run_sync(self.mesh.sync_control_plane)
            if result.refreshed:
                await self._readmit_routers()
            if result.banned_peer_ids is not None:
                newly_banned, _ = self.banned.reconcile(canonical_peer_ids(result.banned_peer_ids), result.fetched_at)
                for peer in newly_banned:
                    await self._evict(peer)
            if len(self._held_router_ids) < self._want_routers():
                await self.top_up_routers()
            self._relay_trigger.set()
            # Callers evaluate the policy too: it is what grants a provider the
            # service it serves (require_publish), not only what an A2A
            # endpoint authorizes its callers with.
            try:
                await self.sync_policy()
            except Exception as err:  # noqa: BLE001 - the last good policy stays in force
                result.errors.append(f"policy: {err}")
            return result

    def trigger_sync(self) -> None:
        """Asks for a pull soon, after a random delay so a fleet told at once does not pull at once."""
        self._sync_trigger.set()

    async def refresh(self) -> None:
        """Trades the credential for a fresh one now and shows it to every
        router this member is connected to. A router admits a peer until the
        biscuit it was shown expires, whatever the connection does; a refreshed
        credential it never sees leaves it refusing relay circuits to this
        member once the old one lapses, with every connection still open."""
        # The control plane client is synchronous; keep the loop free.
        await trio.to_thread.run_sync(self.mesh.refresh)
        await self._readmit_routers()

    async def _readmit_routers(self) -> None:
        """Runs the handshake again on the open connection to each admitted
        router; the router records the expiry of the credential it is shown.
        A router without a connection is left to the reservation loop, which
        dials and authenticates it again."""
        connected = self.host.get_connected_peers()
        for i, r in enumerate(self.routers):
            peer_id = ID.from_base58(r.peer_id)
            if peer_id not in connected:
                continue
            try:
                credential = await _authenticate_router(self.host, self.mesh, peer_id)
            except Exception as err:  # noqa: BLE001 - the router keeps the admission it has until the old credential lapses
                logger.warning("router %s did not accept the refreshed credential: %s", r.peer_id, err)
                continue
            self.routers[i] = replace(self.routers[i], credential=credential)

    async def _refresh_loop(self, lead: float, retry: float) -> None:
        while True:
            due = self.mesh.credential.expiration - lead - time.time()
            await trio.sleep(max(MIN_REFRESH_DELAY, due))
            try:
                await self.refresh()
            except Exception as err:  # noqa: BLE001 - a failed refresh is retried, the session stays up
                logger.warning("credential refresh failed, retrying in %.0fs: %s", retry, err)
                await trio.sleep(retry)

    async def _evict(self, banned_peer: str) -> None:
        """Drops a banned peer: its admission and its connections."""
        self.authenticated_peers.pop(banned_peer, None)
        if banned_peer in self._held_router_ids:
            self._held_router_ids.discard(banned_peer)
            self.routers[:] = [r for r in self.routers if r.peer_id != banned_peer]
            self._relay_trigger.set()
        try:
            await self.host.disconnect(ID.from_base58(banned_peer))
        except Exception:  # noqa: BLE001 - not connected, or already gone
            pass

    async def _sync_loop(self) -> None:
        """Pulls once shortly after join, then every interval and whenever
        triggered; each periodic wait is stretched by up to a tenth and each
        trigger delayed by up to the jitter, as agentmesh-node's loop does."""
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
        """Renews the relay reservation on each held router before the relay
        lets it expire, and again as soon as the connection to that router is
        found gone: the relay drops the reservation with the connection, and a
        member that kept advertising the relayed address would have every dial
        to it fail with NO_RESERVATION. When a held router's connection drops,
        it is redialed across router_redial_backoffs first; if it does not come
        back or refuses auth, it is shunned and replaced from the catalog."""
        if not self.reserve and not self._held_router_ids:
            return
        while True:
            reserved = [r for r in self.routers if r.peer_id in self._held_router_ids and r.reservation is not None]
            if not self.reserve and not self._held_router_ids:
                return
            if reserved:
                due = min(r.reservation.expire for r in reserved) - self.reservation_lead - time.time()  # type: ignore[union-attr]
                wait_time = min(max(MIN_REFRESH_DELAY, due), self.reservation_check_interval)
            else:
                wait_time = self.reservation_check_interval
            with trio.move_on_after(wait_time):
                await self._relay_trigger.wait()
            self._relay_trigger = trio.Event()

            failed = False
            held_snapshot = [r for r in self.routers if r.peer_id in self._held_router_ids]
            for r in held_snapshot:
                if r.peer_id not in self._held_router_ids:
                    continue
                connected = ID.from_base58(r.peer_id) in self.host.get_connected_peers()
                expiring = (
                    r.reservation is not None
                    and r.reservation.expire - time.time() <= self.reservation_lead + MIN_REFRESH_DELAY
                )
                missing_res = self.reserve and r.reservation is None
                if connected and not expiring and not missing_res:
                    continue

                if connected:
                    # Renewing an expiring reservation on an still-open connection.
                    try:
                        updated = await _reserve_again(self.host, self.mesh, r, reserve=self.reserve)
                        idx = next((i for i, cur in enumerate(self.routers) if cur.peer_id == r.peer_id), None)
                        if idx is not None:
                            self.routers[idx] = updated
                    except Exception as err:  # noqa: BLE001 - retried; _reserve_again disconnected so next pass redials
                        failed = True
                        logger.warning(
                            "relay reservation on router %s not renewed, retrying in %.0fs: %s",
                            r.peer_id,
                            self.reservation_retry,
                            err,
                        )
                    continue

                # Connection dropped: try immediate reconnect first (covers a router
                # that already restarted or moved to a new address), then redial with
                # router_redial_backoffs before shunning and failing over.
                reconnected = False
                last_err: Optional[Exception] = None
                try:
                    updated = await _reserve_again(self.host, self.mesh, r, reserve=self.reserve)
                    idx = next((i for i, cur in enumerate(self.routers) if cur.peer_id == r.peer_id), None)
                    if idx is not None:
                        self.routers[idx] = updated
                    reconnected = True
                except Exception as err:  # noqa: BLE001
                    last_err = err

                if not reconnected:
                    for backoff in self.router_redial_backoffs:
                        await trio.sleep(backoff)
                        if r.peer_id not in self._held_router_ids:
                            reconnected = True
                            break
                        try:
                            updated = await _reserve_again(self.host, self.mesh, r, reserve=self.reserve)
                            idx = next((i for i, cur in enumerate(self.routers) if cur.peer_id == r.peer_id), None)
                            if idx is not None:
                                self.routers[idx] = updated
                            reconnected = True
                            break
                        except Exception as err:  # noqa: BLE001
                            last_err = err

                if not reconnected and r.peer_id in self._held_router_ids:
                    logger.warning("router %s unreachable after redial, shunning and failing over: %s", r.peer_id, last_err)
                    self._shun_router(r.peer_id, ROUTER_SHUN_DURATION)
                    await self._detach_router(r.peer_id)

            if len(self._held_router_ids) < self._want_routers():
                await self.top_up_routers()
            await self._announce_if_moved()
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
    ) -> HTTPResponse:
        """Calls an inference or A2A service on a provider over /libp2p-http,
        the way agentmesh-node's egress proxy does for /mesh/<peer>/<type>/<name>/<path>."""
        peer_id = await self._egress_peer(peer, target_service)
        return await http_request_over_stream(
            self.host, peer_id, self.biscuit, target_service, path, method=method, headers=headers, body=body
        )

    async def _egress_peer(self, peer: Peer, target_service: str) -> ID:
        """The peer an HTTP call goes out to, verified as an enrolled node
        holding the floor and granted the service before anything is sent
        (agentmesh-node's VerifyProvider)."""
        peer_id = await self.connect(peer)
        verdict = f"{peer_id}|{target_service}"
        if self._egress_verdicts.get(verdict, 0.0) > time.monotonic():
            return peer_id
        provider = await authenticate_with_peer(self.host, peer_id, self.mesh.auth_frame(), self.mesh.credential.control_plane_keys)
        # Only nodes host services; a router's or an admin's credential is a member, not a provider.
        require_role(provider, ROLE_NODE)
        require_publish(provider, target_service, self.policy_rules)
        require_egress_labels(provider, self.egress_require_labels)
        self._egress_verdicts[verdict] = time.monotonic() + EGRESS_VERDICT_TTL
        return peer_id

    async def accept_a2a(self, target: Union[str, HTTPHandler], *, name: str = DEFAULT_A2A_NAME) -> str:
        """Makes this member's agent reachable: other members call it as
        `a2a://<name>` by peer ID, through a router, and the SDK answers
        /libp2p-http with target, the base URL of an A2A server beside this
        process or a handler in it. Nothing is announced: no DHT record, no
        catalog entry. A tool, a model or a service others should find by
        name is published by a agentmesh-node. Fetches the mesh policy first and
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
    routers: int = DEFAULT_ROUTERS,
    router_selector: Optional[Mapping[str, str]] = None,
    router_prefer: Optional[Mapping[str, str]] = None,
    router_redial_backoffs: Sequence[float] = ROUTER_REDIAL_BACKOFFS,
    reserve: bool = True,
    refresh_lead: float = DEFAULT_REFRESH_LEAD,
    refresh_retry: float = DEFAULT_REFRESH_RETRY,
    reservation_lead: float = RESERVATION_RENEW_LEAD,
    reservation_check_interval: float = RESERVATION_CHECK_INTERVAL,
    announce_interval: float = DEFAULT_ANNOUNCE_INTERVAL,
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
    # The pull agentmesh-node makes before it starts: a member resuming from its
    # state directory after a key rotation would otherwise verify the routers,
    # which already hold credentials under the new key, against the keys it
    # persisted, and the sync that would have brought the new key runs only
    # once joined. Best effort; the stored credential serves when the control
    # plane cannot be reached.
    try:
        result = await trio.to_thread.run_sync(mesh.sync_control_plane)
        if result.errors:
            logger.warning("control plane sync before join: %s", "; ".join(result.errors))
    except Exception as err:  # noqa: BLE001 - joining goes on with what the credential holds
        logger.warning("control plane sync before join failed: %s", err)

    pinned_addrs = list(router_addresses) if router_addresses is not None else None
    raw_addrs = pinned_addrs if pinned_addrs is not None else list(mesh.credential.router_addresses)
    for a in raw_addrs:
        multiaddr.Multiaddr(a)
    if pinned_addrs is not None:
        catalog = candidates_from_router_infos([], pinned_addrs, getattr(mesh, "routers", ()))
    else:
        catalog = candidates_from_router_infos(getattr(mesh, "routers", ()), raw_addrs)
    if not catalog:
        raise RuntimeError(
            "credential lists no router addresses; the control plane had no active router at enrollment"
            if router_addresses is None
            else "router_addresses names no router"
        )
    target_count = max(1, routers)
    ordered = select_routers(catalog, len(catalog), selector=router_selector, prefer=router_prefer)
    if not ordered:
        raise RuntimeError("no router admitted this member: no router in catalog matched router_selector")

    host, listen = create_mesh_host(mesh.identity, listen_addrs)
    authenticated: dict[str, datetime] = {}
    banned = BanSet()
    session_ref: list[MeshSession] = []
    host.set_stream_handler(
        AUTH_PROTOCOL,
        auth_stream_handler(
            own_biscuit=lambda: mesh.credential.biscuit,
            trusted_keys=lambda: mesh.credential.control_plane_keys,
            on_authenticated=lambda peer, verified: authenticated.__setitem__(peer, verified.expiration),
            is_banned=lambda peer: peer in banned,
        ),
    )
    host.set_stream_handler(
        GOAWAY_PROTOCOL,
        go_away_stream_handler(
            is_held_router=lambda peer_id: bool(session_ref and session_ref[0].is_held_router(peer_id)),
            on_go_away=lambda peer_id, msg, retry_after: (
                session_ref[0].handle_go_away(peer_id, msg, retry_after) if session_ref else None
            ),
        ),
    )
    host.set_stream_handler(STOP_PROTOCOL, stop_stream_handler(host))
    # Built before any connection: Pubsub learns of peers through a notifee it
    # registers here. StrictSign, as every Go component pins it. A member is
    # a leaf of the gossip: it speaks floodsub, so a router delivers every
    # event to it outright and it takes no part in the routers' gossipsub mesh.
    floodsub = FloodSub(protocols=[FLOODSUB])
    pubsub = Pubsub(host, floodsub, strict_signing=True)
    logging.getLogger("libp2p.host.basic_host").addFilter(_MESHSUB_NOISE)

    try:
        async with host.run(listen_addrs=listen), background_trio_service(pubsub):
            await pubsub.wait_until_ready()
            admitted = await _admit(host, mesh, ordered, reserve, target_count=target_count)
            async with trio.open_nursery() as nursery:
                session = MeshSession(
                    mesh=mesh,
                    host=host,
                    routers=admitted,
                    authenticated_peers=authenticated,
                    banned=banned,
                    egress_require_labels=egress_require_labels,
                    reserve=reserve,
                    target_routers=target_count,
                    router_selector=router_selector,
                    router_prefer=router_prefer,
                    pinned_router_addresses=pinned_addrs,
                    router_redial_backoffs=tuple(router_redial_backoffs),
                    policy_sync_interval=policy_sync_interval,
                    control_plane_sync_interval=control_plane_sync_interval,
                    control_plane_sync_jitter=control_plane_sync_jitter,
                    reservation_lead=reservation_lead,
                    reservation_retry=refresh_retry,
                    reservation_check_interval=reservation_check_interval,
                    announce_interval=announce_interval,
                    _nursery=nursery,
                )
                session_ref.append(session)
                nursery.start_soon(session._refresh_loop, refresh_lead, refresh_retry)  # noqa: SLF001
                nursery.start_soon(session._events_loop, pubsub)  # noqa: SLF001
                nursery.start_soon(session._sync_loop)  # noqa: SLF001
                nursery.start_soon(session._reservation_loop)  # noqa: SLF001
                nursery.start_soon(session._announce_loop)  # noqa: SLF001
                # Best effort: a router that does not take the record is a
                # warning the next announcement retries.
                await session._announce_if_moved()  # noqa: SLF001
                try:
                    yield session
                finally:
                    with trio.CancelScope(shield=True):
                        await session._withdraw_self()  # noqa: SLF001
                    nursery.cancel_scope.cancel()
    except BaseExceptionGroup as group:
        cause = _single_cause(group)
        if cause is group:
            raise
        raise cause from None


async def _admit_candidates(
    host: IHost,
    mesh: "AgentMesh",
    candidates: Sequence[RouterCandidate],
    reserve: bool,
    failures: list[str],
    admitted_any_out: Optional[list[bool]] = None,
) -> list[AdmittedRouter]:
    """Dials and authenticates a batch of router candidates concurrently, and
    reserves a relay slot on each admitted router when reserve is True."""
    admitted: dict[int, AdmittedRouter] = {}

    async def admit_one(index: int, candidate: RouterCandidate) -> None:
        last_err: Optional[Exception] = None
        for addr in candidate.addresses:
            try:
                info = await peer_info(addr)
                await dial(host, info)
                credential = await _authenticate_router(host, mesh, info.peer_id)
                admitted[index] = AdmittedRouter(peer_id=str(info.peer_id), addr=addr, credential=credential)
                return
            except Exception as err:  # noqa: BLE001
                last_err = err
        if last_err is not None:
            failures.append(f"{candidate.addresses[0] if candidate.addresses else candidate.peer_id}: {last_err}")

    async with trio.open_nursery() as nursery:
        for index, candidate in enumerate(candidates):
            nursery.start_soon(admit_one, index, candidate)

    ordered = [admitted[i] for i in sorted(admitted)]
    if ordered and admitted_any_out is not None:
        admitted_any_out.append(True)
    if not reserve:
        return ordered

    reserved: list[AdmittedRouter] = []
    for router in ordered:
        try:
            res = await reserve_relay(host, ID.from_base58(router.peer_id))
            reserved.append(replace(router, reservation=res))
        except Exception as err:  # noqa: BLE001
            failures.append(f"{router.addr}: {err}")
            try:
                await host.disconnect(ID.from_base58(router.peer_id))
            except Exception:  # noqa: BLE001
                pass
    return reserved


async def _admit(
    host: IHost,
    mesh: "AgentMesh",
    candidates_or_addrs: Sequence[Union[multiaddr.Multiaddr, RouterCandidate]],
    reserve: bool,
    target_count: int = DEFAULT_ROUTERS,
) -> list[AdmittedRouter]:
    """Authenticates with up to target_count chosen routers, dialing each batch
    at once so an unreachable router costs one dial timeout rather than one per
    router behind it, and reserves a relay slot on each chosen router."""
    candidates: list[RouterCandidate] = []
    for item in candidates_or_addrs:
        if isinstance(item, RouterCandidate):
            candidates.append(item)
        else:
            try:
                pid = str(info_from_p2p_addr(item).peer_id)
            except Exception:  # noqa: BLE001
                pid = ""
            candidates.append(RouterCandidate(peer_id=pid, addresses=[item]))

    want = max(1, target_count)
    routers: list[AdmittedRouter] = []
    failures: list[str] = []
    admitted_any: list[bool] = []
    cursor = 0
    while len(routers) < want and cursor < len(candidates):
        need = want - len(routers)
        batch = candidates[cursor : cursor + need]
        cursor += len(batch)
        admitted_batch = await _admit_candidates(host, mesh, batch, reserve, failures, admitted_any)
        routers.extend(admitted_batch)

    if not routers:
        if reserve and admitted_any:
            raise RuntimeError("no router reserved a relay slot for this member:\n  " + "\n  ".join(failures))
        raise RuntimeError("no router admitted this member:\n  " + "\n  ".join(failures))
    return routers


async def _authenticate_router(host: IHost, mesh: "AgentMesh", peer_id: ID) -> VerifiedBiscuit:
    credential = await authenticate_with_peer(host, peer_id, mesh.auth_frame(), mesh.credential.control_plane_keys)
    # Enforced under the key that verified the token; a relay that
    # is not a router must not become our way onto the mesh.
    require_role(credential, ROLE_ROUTER)
    return credential


async def _reserve_again(host: IHost, mesh: "AgentMesh", router: AdmittedRouter, *, reserve: bool = True) -> AdmittedRouter:
    """Reserves on a router again, dialed and authenticated first when its
    connection is gone. A router rescheduled keeps its key and comes back on
    another address; the list the control plane hands out, refreshed by
    every pull, names the current one, so the router is dialed at what that
    list says and keeps that as its address. The address admitted at join
    serves only when the list no longer names the router."""
    peer_id = ID.from_base58(router.peer_id)
    credential = router.credential
    addr = router.addr
    try:
        if peer_id not in host.get_connected_peers():
            addr, info = await _current_router_info(mesh, router)
            await dial(host, info)
            credential = await _authenticate_router(host, mesh, peer_id)
        reservation = await reserve_relay(host, peer_id) if reserve else None
    except Exception:
        # A connection that failed us is not kept: it may be half-open, or up
        # but unauthenticated. The retry then dials and authenticates again.
        try:
            await host.disconnect(peer_id)
        except Exception:  # noqa: BLE001 - already gone
            pass
        raise
    return replace(router, addr=addr, credential=credential, reservation=reservation)


async def _current_router_info(mesh: "AgentMesh", router: AdmittedRouter) -> tuple[multiaddr.Multiaddr, PeerInfo]:
    """The router's addresses as the credential lists them now, resolved to
    what this host can dial, and the first of them this host can use as the
    address to keep; the admitted address when the list has none for the
    router."""
    listed: list[multiaddr.Multiaddr] = []
    for r in getattr(mesh, "routers", ()):
        try:
            r_peer_id = canonical_peer_id(r.peer_id)
        except ValueError:
            continue
        if r_peer_id == router.peer_id:
            for raw in r.addresses:
                try:
                    ma = multiaddr.Multiaddr(raw)
                    if f"/p2p/{router.peer_id}" not in str(ma):
                        ma = multiaddr.Multiaddr(f"{ma}/p2p/{router.peer_id}")
                    listed.append(ma)
                except Exception:  # noqa: BLE001
                    continue
    if not listed:
        for text in mesh.credential.router_addresses:
            try:
                ma = multiaddr.Multiaddr(text)
                if str(info_from_p2p_addr(ma).peer_id) == router.peer_id:
                    listed.append(ma)
            except Exception:  # noqa: BLE001 - not a router address
                continue
    kept: Optional[multiaddr.Multiaddr] = None
    dialable: list[multiaddr.Multiaddr] = []
    failures: list[str] = []
    for ma in listed or [router.addr]:
        try:
            dialable.extend(await dial_addrs(ma))
        except Exception as err:  # noqa: BLE001 - an address this host cannot use; the others are tried
            failures.append(f"{ma}: {err}")
            continue
        kept = kept or ma
    if kept is None:
        raise RuntimeError("no address to dial router at:\n  " + "\n  ".join(failures))
    return kept, PeerInfo(ID.from_base58(router.peer_id), dialable)

