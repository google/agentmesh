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

"""The mesh's directory as a member uses it, as agentmesh-node does
(internal/node/directory_client.go): the member keeps no DHT and asks the
routers it holds over /mesh/directory/1.0.0, one DirectoryRequest per
stream, one DirectoryResponse back. A request goes to one held router and
to the next when it fails. The routers run the lookup across their own DHT.
A key is the sha256 multihash of "mesh:service:<type>[:<name>]" for a
service and of "mesh:peer:<peer_id>" for a member."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Iterable, Literal

import multiaddr
import trio
from libp2p.abc import IHost
from libp2p.custom_types import TProtocol
from libp2p.peer.id import ID
from libp2p.utils.varint import encode_varint_prefixed

from ._proto import agentmesh_pb2 as pb
from .auth import read_bounded_varint_prefixed_bytes
from .host import open_stream

logger = logging.getLogger("agent_mesh")

# api.DirectoryProtocolID.
DIRECTORY_PROTOCOL = TProtocol("/mesh/directory/1.0.0")

ServiceType = Literal["mcp", "inference", "a2a", "egress"]

_REQUEST_TIMEOUT = 10.0
MAX_DIRECTORY_MESSAGE_BYTES = 64 * 1024
DEFAULT_LIMIT = 20


@dataclass
class DiscoveredProvider:
    """A peer the directory names as offering a service."""

    peer_id: str
    # Addresses the provider is reached at, each ending in its peer ID; may
    # be empty when the record carried none.
    addrs: list[str] = field(default_factory=list)


class DirectoryError(Exception):
    """No held router answered a directory request."""


def _key(name: str) -> bytes:
    """The sha256 multihash of a name: the two-byte header and the digest."""
    return b"\x12\x20" + hashlib.sha256(name.encode()).digest()


def service_key(service_type: ServiceType, name: str | None = None) -> bytes:
    """The directory key of a service type, or of one named service of that
    type: "mesh:service:<type>" or "mesh:service:<type>:<name>" (api.ServiceKey)."""
    parts = ["mesh:service", service_type] + ([name] if name else [])
    return _key(":".join(parts))


def peer_key(peer_id: ID) -> bytes:
    """The directory key a member announces where it is reached under (api.PeerKey)."""
    return _key(f"mesh:peer:{peer_id}")


def parse_service_target(target: str) -> tuple[str, str]:
    """Splits "mcp://calculator" into ("mcp", "calculator"); "" is the node's own catalog."""
    if target == "":
        return "", ""
    scheme, sep, name = target.partition("://")
    if not sep or scheme not in ("mcp", "inference", "a2a", "egress") or not name:
        raise ValueError(f"service target must look like mcp://<name>, got {target!r}")
    return scheme, name


async def _ask(host: IHost, router: ID, req: pb.DirectoryRequest) -> pb.DirectoryResponse:
    """One request to one router, answered or raised."""
    stream = await open_stream(host, router, DIRECTORY_PROTOCOL, _REQUEST_TIMEOUT)
    try:
        with trio.fail_after(_REQUEST_TIMEOUT):
            await stream.write(encode_varint_prefixed(req.SerializeToString()))
            resp = pb.DirectoryResponse.FromString(await read_bounded_varint_prefixed_bytes(stream, MAX_DIRECTORY_MESSAGE_BYTES))
    finally:
        with trio.move_on_after(1, shield=True):
            try:
                await stream.close()
            except Exception:
                logger.debug("directory: failed to close stream to router %s", router, exc_info=True)
    if resp.error:
        raise DirectoryError(resp.error)
    return resp


async def request(host: IHost, routers: Iterable[ID], req: pb.DirectoryRequest) -> pb.DirectoryResponse:
    """Sends req to the held routers in turn until one answers. A router that
    is restarting costs the request a timeout, not an answer. A lookup one
    router answers with nothing is put to the next as well: a router cut off
    from the routers closest to the key answers from what it can reach."""
    lookup = req.WhichOneof("request") in ("find_providers", "find_peer")
    last: Exception | None = None
    asked = 0
    empty: pb.DirectoryResponse | None = None
    for router in routers:
        asked += 1
        try:
            resp = await _ask(host, router, req)
        except Exception as err:  # noqa: BLE001 - the next router is asked
            last = err
            logger.warning("directory: request through router %s failed: %s", router, err)
            continue
        if lookup and not resp.providers and not resp.HasField("peer"):
            empty = resp
            continue
        return resp
    if empty is not None:
        return empty
    if asked == 0:
        raise DirectoryError("no held router to ask")
    raise DirectoryError(f"no held router answered: {last}")


async def provide(host: IHost, routers: Iterable[ID], key: bytes, addrs: Iterable[multiaddr.Multiaddr]) -> None:
    """Announces this member as a provider of key, reached at addrs, to a
    held router; the router keeps the record and places it on the routers
    closest to the key."""
    req = pb.DirectoryRequest(provide=pb.DirectoryProvide(key=key, addrs=[str(a) for a in addrs]))
    await request(host, routers, req)


async def withdraw(host: IHost, routers: Iterable[ID], key: bytes) -> None:
    """Removes this member's record under key from the held router and from
    the routers it was placed on."""
    await request(host, routers, pb.DirectoryRequest(withdraw=pb.DirectoryWithdraw(key=key)))


async def find_providers(host: IHost, routers: Iterable[ID], key: bytes, limit: int = DEFAULT_LIMIT) -> list[DiscoveredProvider]:
    """Who provides key, up to limit, with their addresses; empty when nobody does."""
    req = pb.DirectoryRequest(find_providers=pb.DirectoryFindProviders(key=key, limit=max(limit, 1)))
    resp = await request(host, routers, req)
    found: dict[str, DiscoveredProvider] = {}
    self_id = str(host.get_id())
    for rec in resp.providers:
        if rec.peer_id == self_id:
            continue
        entry = found.setdefault(rec.peer_id, DiscoveredProvider(peer_id=rec.peer_id))
        for a in rec.addrs:
            if a not in entry.addrs:
                entry.addrs.append(a)
    return list(found.values())[:limit]


async def find_peer(host: IHost, routers: Iterable[ID], target: ID) -> list[multiaddr.Multiaddr]:
    """Where target is reached: its addresses, each ending in its peer ID,
    relayed ones included. Empty when nobody knows the peer."""
    req = pb.DirectoryRequest(find_peer=pb.DirectoryFindPeer(peer_id=str(target)))
    resp = await request(host, routers, req)
    if not resp.HasField("peer") or resp.peer.peer_id != str(target):
        return []
    out: list[multiaddr.Multiaddr] = []
    for a in resp.peer.addrs:
        try:
            out.append(multiaddr.Multiaddr(a))
        except Exception:  # noqa: BLE001 - a malformed address from a router is dropped
            logger.debug("directory: dropping address %r of %s", a, target)
    return out
