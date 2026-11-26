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

"""What a member keeps in step with the control plane while it runs, as
agentmesh-node's controlplane_sync.go: the ban set, reconciled from /info, and the
gossip events that bring the next pull forward."""

from __future__ import annotations

import time
from typing import Optional, Sequence

from ._proto import agentmesh_pb2 as pb
from .identity import canonical_peer_id, verify_ed25519

# The GossipSub topic the control plane publishes mesh events on (api.GossipEvents).
GOSSIP_EVENTS_TOPIC = "/mesh/events/v1"

# How far an event's timestamp may be from now; older or later ones are ignored.
EVENT_FRESHNESS_MS = 5 * 60 * 1000


class BanSet:
    """The peers the control plane has banned, with when each ban was learned
    (unix milliseconds). A ban recorded at or after the instant a /info answer
    was requested is kept when that answer omits it: the answer predates the
    ban and cannot speak to it."""

    def __init__(self) -> None:
        self._banned_at: dict[str, int] = {}

    def __contains__(self, peer_id: str) -> bool:
        return peer_id in self._banned_at

    def __len__(self) -> int:
        return len(self._banned_at)

    def peers(self) -> list[str]:
        return sorted(self._banned_at)

    def add(self, peer_id: str, at_ms: int) -> bool:
        """Records a ban; returns False when the peer was already in the set.
        The set then keeps the later of the stored time and at_ms: a ban time
        never moves back. A second event for a peer can be a new ban, because
        the control plane publishes no event when it lifts one."""
        known = self._banned_at.get(peer_id)
        if known is None or at_ms > known:
            self._banned_at[peer_id] = at_ms
        return known is None

    def reconcile(self, banned_peer_ids: Sequence[str], fetched_at: float) -> tuple[list[str], list[str]]:
        """Makes the set match the control plane's ban set as of fetched_at
        (unix seconds). Returns (newly banned, unbanned)."""
        fetched_at_ms = int(fetched_at * 1000)
        current = set(banned_peer_ids)
        unbanned = [p for p, at in self._banned_at.items() if p not in current and at < fetched_at_ms]
        for p in unbanned:
            del self._banned_at[p]
        banned = [p for p in current if self.add(p, fetched_at_ms)]
        return banned, unbanned


def verify_mesh_event(data: bytes, trusted_keys: Sequence[bytes], now_ms: Optional[int] = None) -> Optional[pb.MeshEvent]:
    """Verifies a MeshEvent as agentmesh-node's verifyEvent does: the signature covers
    the deterministic encoding of the event with the signature cleared, under
    any trusted control plane key. Returns the event, with a banned peer's id in
    canonical form, or None when it does not verify, is not fresh, or bans
    something that is not a peer ID."""
    try:
        event = pb.MeshEvent.FromString(data)
    except Exception:  # noqa: BLE001 - undecodable is unverifiable
        return None
    signature = bytes(event.signature)
    unsigned = pb.MeshEvent()
    unsigned.CopyFrom(event)
    unsigned.ClearField("signature")
    payload = unsigned.SerializeToString(deterministic=True)
    if not any(verify_ed25519(key, payload, signature) for key in trusted_keys):
        return None
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if not event.HasField("event_time") or abs(now_ms - event.event_time.ToMilliseconds()) > EVENT_FRESHNESS_MS:
        return None
    if event.type == pb.MeshEvent.BANNED:
        # Canonicalized after the signature check, which covers the bytes as sent.
        try:
            event.peer_id = canonical_peer_id(event.peer_id)
        except ValueError:
            return None
    return event
