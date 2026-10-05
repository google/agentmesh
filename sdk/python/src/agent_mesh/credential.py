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

import time
from dataclasses import dataclass, field, replace
from typing import Optional

from google.protobuf import json_format
from google.protobuf.timestamp_pb2 import Timestamp

from ._proto import sam_pb2 as pb
from .biscuit import attenuate_biscuit, seal_biscuit


@dataclass(frozen=True)
class MeshCredential:
    """What a member holds after enrolling: its biscuit and what it trusts."""

    control_plane_url: str
    # The biscuit the control plane minted for this identity.
    biscuit: bytes
    # Unix seconds at which the biscuit expires.
    expiration: int
    # Every control plane signing key currently trusted (rotation keeps several valid).
    control_plane_keys: list[bytes] = field(default_factory=list)
    # The trusted set when the biscuit was issued. A key trusted now that was
    # not in this set means a rotation happened since: the biscuit is signed by
    # a retiring key and must be refreshed before that key leaves its grace
    # period (sam-node's identityPredatesRotation).
    issued_under_keys: list[bytes] = field(default_factory=list)
    # Router multiaddrs, `/p2p/<peer id>` suffixed, as handed out at enrollment.
    router_addresses: list[str] = field(default_factory=list)
    # What other implementations persist in the same file and this SDK does
    # not use: when each key was learned (by key bytes) and sam-node's OIDC
    # session. Carried through so a state directory survives a round trip.
    receive_times: dict[bytes, Timestamp] = field(default_factory=dict, compare=False)
    oidc_session: Optional[pb.OIDCSession] = field(default=None, compare=False)

    def attenuate(self, rule: pb.TaskAuthorizationRule) -> "MeshCredential":
        """Returns a new MeshCredential whose biscuit is attenuated offline in memory with rule."""
        attenuated = attenuate_biscuit(self.biscuit, rule, self.control_plane_keys)
        expiration = self.expiration
        if rule.HasField("expire_time"):
            rule_exp = rule.expire_time.ToSeconds()
            if rule_exp < expiration:
                expiration = rule_exp
        return replace(self, biscuit=attenuated, expiration=expiration)

    def seal(self) -> "MeshCredential":
        """Returns a new MeshCredential whose biscuit is sealed against further attenuation."""
        sealed = seal_biscuit(self.biscuit, self.control_plane_keys)
        return replace(self, biscuit=sealed)

    def time_to_live_seconds(self, now: float | None = None) -> int:
        """Seconds of validity left on the biscuit; negative once expired."""
        return self.expiration - int(time.time() if now is None else now)

    def predates_rotation(self) -> bool:
        """Whether a key trusted now was unknown when the credential was issued."""
        issued = {bytes(k) for k in self.issued_under_keys}
        return any(bytes(k) not in issued for k in self.control_plane_keys)

    def to_json(self) -> str:
        """credential.json: the api.MemberCredential message as protojson with
        proto field names, the layout `sam-node state export` writes and every
        SDK reads."""
        message = pb.MemberCredential(
            control_plane_url=self.control_plane_url,
            biscuit=self.biscuit,
            issued_under_keys=[bytes(k) for k in self.issued_under_keys],
            router_addresses=list(self.router_addresses),
        )
        message.expire_time.FromSeconds(self.expiration)
        for k in self.control_plane_keys:
            entry = message.trusted_keys.add(public_key=bytes(k))
            if (received := self.receive_times.get(bytes(k))) is not None:
                entry.receive_time.CopyFrom(received)
        if self.oidc_session is not None:
            message.oidc_session.CopyFrom(self.oidc_session)
        return json_format.MessageToJson(message, preserving_proto_field_name=True, indent=2) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "MeshCredential":
        """Reads credential.json. An unknown field is an error, as on every SAM surface."""
        try:
            message = json_format.Parse(text, pb.MemberCredential())
        except json_format.ParseError as err:
            raise ValueError(f"malformed credential file: {err}") from err
        if not message.control_plane_url or not message.biscuit or not message.HasField("expire_time"):
            raise ValueError("malformed credential file: control_plane_url, biscuit and expire_time are required")
        control_plane_keys = [bytes(k.public_key) for k in message.trusted_keys]
        receive_times: dict[bytes, Timestamp] = {}
        for k in message.trusted_keys:
            if k.HasField("receive_time"):
                received = Timestamp()
                received.CopyFrom(k.receive_time)
                receive_times[bytes(k.public_key)] = received
        oidc_session = None
        if message.HasField("oidc_session"):
            oidc_session = pb.OIDCSession()
            oidc_session.CopyFrom(message.oidc_session)
        return cls(
            control_plane_url=message.control_plane_url,
            biscuit=bytes(message.biscuit),
            expiration=message.expire_time.ToSeconds(),
            control_plane_keys=control_plane_keys,
            # A file that recorded no issuance set: the keys trusted then are the best answer.
            issued_under_keys=[bytes(k) for k in message.issued_under_keys] or list(control_plane_keys),
            router_addresses=list(message.router_addresses),
            receive_times=receive_times,
            oidc_session=oidc_session,
        )


def encode_auth_frame(biscuit: bytes, target_service: str = "") -> bytes:
    """The first frame on every mesh stream (/sam/auth/1.0.0, /sam/mcp/1.0.0):
    the caller's biscuit and the service it wants.
    Framing (varint length prefix) is the transport's job."""
    return pb.AuthFrame(biscuit=biscuit, target_service=target_service).SerializeToString()


def decode_auth_response(data: bytes) -> pb.AuthResponse:
    """The peer's answer to an AuthFrame, carrying its own biscuit on success."""
    return pb.AuthResponse.FromString(data)
