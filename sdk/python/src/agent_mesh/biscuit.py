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

"""Verification of a peer's biscuit, mirroring internal/identity.verifyBiscuit:
signed by a trusted control plane key, authority block + validated tar_block
chain, unexpired, and bound to the peer at the other end of the connection."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

import biscuit_auth as ba
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._proto import sam_pb2
from .tar import _DATALOG, effective_tar_expiration, encode_tar_block_fact, parse_tar_block_source

ROLE_ROUTER = "sam:role:router"

# Datalog evaluation budget, as in internal/identity.AuthorizerOptions.
AUTHORIZER_MAX_FACTS = 1000
AUTHORIZER_MAX_ITERATIONS = 100
AUTHORIZER_MAX_TIME = timedelta(seconds=1)

_EXPIRATION_CHECK = "check if time($t), expiration($e), $t <= $e"


class BiscuitVerificationError(Exception):
    pass


@dataclass(frozen=True)
class VerifiedBiscuit:
    """What a verified peer biscuit says about its holder."""

    # The peer the token is bound to (its node() or actor_node()/client_peer_id() fact).
    peer_id: str
    # When the token lapses; the minimum of authority expiration() and any tar_block expire_time.
    expiration: datetime
    # The trusted key that verified the signature.
    verifying_key: bytes
    roles: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    task_rules: list[sam_pb2.TaskAuthorizationRule] = field(default_factory=list)
    actor_node: Optional[str] = None


def _limits() -> ba.AuthorizerLimits:
    limits = ba.AuthorizerBuilder().limits()
    limits.max_facts = AUTHORIZER_MAX_FACTS
    limits.max_iterations = AUTHORIZER_MAX_ITERATIONS
    limits.max_time = AUTHORIZER_MAX_TIME
    return limits


def _parse_with_trusted_keys(biscuit: bytes, trusted_keys: Sequence[bytes]) -> tuple[ba.Biscuit, bytes]:
    if not trusted_keys:
        raise BiscuitVerificationError("no trusted control plane key to verify against")
    token = None
    verifying_key = b""
    last_err: Exception | None = None
    for key in trusted_keys:
        try:
            token = ba.Biscuit.from_bytes(biscuit, ba.PublicKey.from_bytes(bytes(key), ba.Algorithm.Ed25519))
            verifying_key = bytes(key)
            break
        except Exception as err:  # noqa: BLE001 - biscuit-python raises several types here
            last_err = err
    if token is None:
        raise BiscuitVerificationError(f"biscuit is not signed by a trusted control plane key: {last_err}")
    return token, verifying_key


def _extract_tar_chain(token: ba.Biscuit) -> list[sam_pb2.TaskAuthorizationRule]:
    appended_count = token.block_count() - 1
    max_blocks = _DATALOG["max_attenuation_blocks"]
    if appended_count > max_blocks:
        raise BiscuitVerificationError(f"biscuit carries {appended_count} appended blocks; maximum is {max_blocks}")
    task_rules: list[sam_pb2.TaskAuthorizationRule] = []
    for i in range(1, appended_count + 1):
        try:
            task_rules.append(parse_tar_block_source(token.block_source(i)))
        except Exception as err:  # noqa: BLE001
            raise BiscuitVerificationError(f"biscuit block {i}: {err}") from err
    return task_rules


def verify_peer_biscuit(
    biscuit: bytes,
    expected_peer_id: str,
    trusted_keys: Sequence[bytes],
    now: Optional[datetime] = None,
    *,
    allow_delegated: bool = False,
) -> VerifiedBiscuit:
    """Verifies a biscuit received from expected_peer_id over an authenticated
    connection. Every trusted key is tried, so a token minted under a retiring
    key still verifies during rotation."""
    now = now or datetime.now(timezone.utc)
    token, verifying_key = _parse_with_trusted_keys(biscuit, trusted_keys)
    task_rules = _extract_tar_chain(token)

    builder = ba.AuthorizerBuilder()
    builder.set_limits(_limits())
    builder.add_fact(ba.Fact("time({now})", {"now": now}))
    builder.add_check(ba.Check(_EXPIRATION_CHECK))
    builder.add_policy(ba.Policy("allow if true"))
    authorizer = builder.build(token)
    try:
        authorizer.authorize()
    except Exception as err:  # noqa: BLE001
        raise BiscuitVerificationError(f"biscuit is expired or fails its checks: {err}") from err

    def strings(rule: str) -> list[str]:
        return [f.terms[0] for f in authorizer.query(ba.Rule(rule)) if isinstance(f.terms[0], str)]

    bound_nodes = strings("p($p) <- node($p)")
    actor_nodes = strings("a($a) <- actor_node($a)")
    client_peers = strings("c($c) <- client_peer_id($c)")
    is_bound_node = expected_peer_id in bound_nodes
    is_bound_delegated = allow_delegated and expected_peer_id in actor_nodes and expected_peer_id in client_peers
    if not is_bound_node and not is_bound_delegated:
        raise BiscuitVerificationError(f"biscuit is not bound to peer {expected_peer_id}")

    expirations = [f.terms[0] for f in authorizer.query(ba.Rule("e($e) <- expiration($e)")) if isinstance(f.terms[0], datetime)]
    if not expirations:
        raise BiscuitVerificationError("biscuit carries no expiration fact")
    expiration = effective_tar_expiration(min(expirations), task_rules)
    if now > expiration:
        raise BiscuitVerificationError(f"biscuit is expired at {now.isoformat()} (effective expiration {expiration.isoformat()})")

    labels = {
        f.terms[0]: f.terms[1]
        for f in authorizer.query(ba.Rule("l($k, $v) <- label($k, $v)"))
        if isinstance(f.terms[0], str) and isinstance(f.terms[1], str)
    }

    return VerifiedBiscuit(
        peer_id=expected_peer_id,
        expiration=expiration,
        verifying_key=verifying_key,
        roles=strings("r($r) <- role($r)"),
        labels=labels,
        task_rules=task_rules,
        actor_node=actor_nodes[0] if actor_nodes else None,
    )


def attenuate_biscuit(
    biscuit: bytes,
    rule: sam_pb2.TaskAuthorizationRule,
    trusted_keys: Sequence[bytes],
) -> bytes:
    """Appends a non-authority block carrying a single tar_block("<base64url-proto>")
    fact to an existing Biscuit token in memory without contacting the control plane."""
    token, _ = _parse_with_trusted_keys(biscuit, trusted_keys)
    appended_count = token.block_count() - 1
    max_blocks = _DATALOG["max_attenuation_blocks"]
    if appended_count >= max_blocks:
        raise BiscuitVerificationError(f"biscuit already has {appended_count} appended blocks (maximum {max_blocks})")
    _extract_tar_chain(token)
    fact_str = encode_tar_block_fact(rule)
    bb = ba.BlockBuilder()
    bb.add_fact(ba.Fact(fact_str))
    try:
        return token.append(bb).to_bytes()
    except Exception as err:  # noqa: BLE001
        raise BiscuitVerificationError(f"failed to append tar_block to biscuit: {err}") from err


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    val = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7


def _encode_varint(val: int) -> bytes:
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val)
    return bytes(out)


def _parse_proto_fields(buf: bytes) -> list[tuple[int, int, int | bytes]]:
    pos = 0
    fields: list[tuple[int, int, int | bytes]] = []
    while pos < len(buf):
        tag_wire, pos = _read_varint(buf, pos)
        field_num = tag_wire >> 3
        wire_type = tag_wire & 0x07
        if wire_type == 0:
            val, pos = _read_varint(buf, pos)
            fields.append((field_num, wire_type, val))
        elif wire_type == 2:
            ln, pos = _read_varint(buf, pos)
            if pos + ln > len(buf):
                raise ValueError("truncated length-delimited field")
            fields.append((field_num, wire_type, buf[pos : pos + ln]))
            pos += ln
        else:
            raise ValueError(f"unexpected protobuf wire type {wire_type}")
    return fields


def seal_biscuit(biscuit: bytes, trusted_keys: Sequence[bytes]) -> bytes:
    """Seals a Biscuit token so no further blocks can be appended by downstream holders."""
    token, _ = _parse_with_trusted_keys(biscuit, trusted_keys)
    _extract_tar_chain(token)
    try:
        top_fields = _parse_proto_fields(biscuit)
        last_block_bytes: bytes | None = None
        proof_bytes: bytes | None = None
        out_prefix = bytearray()
        for fnum, wtype, val in top_fields:
            if fnum in (2, 3) and wtype == 2 and isinstance(val, bytes):
                last_block_bytes = val
            if fnum == 4 and wtype == 2 and isinstance(val, bytes):
                proof_bytes = val
            else:
                out_prefix.extend(_encode_varint((fnum << 3) | wtype))
                if wtype == 0 and isinstance(val, int):
                    out_prefix.extend(_encode_varint(val))
                elif isinstance(val, bytes):
                    out_prefix.extend(_encode_varint(len(val)))
                    out_prefix.extend(val)
        if last_block_bytes is None or proof_bytes is None:
            raise ValueError("malformed biscuit container")
        proof_fields = dict((f, v) for f, _, v in _parse_proto_fields(proof_bytes))
        next_secret = proof_fields.get(1)
        if not isinstance(next_secret, bytes) or len(next_secret) != 32:
            raise ValueError("biscuit is already sealed")

        sb_fields = dict((f, v) for f, _, v in _parse_proto_fields(last_block_bytes))
        block_data = sb_fields.get(1)
        next_key_raw = sb_fields.get(2)
        sig_bytes = sb_fields.get(3)
        if not isinstance(block_data, bytes) or not isinstance(next_key_raw, bytes) or not isinstance(sig_bytes, bytes):
            raise ValueError("malformed SignedBlock")
        next_key_fields = dict((f, v) for f, _, v in _parse_proto_fields(next_key_raw))
        alg = int(next_key_fields.get(1, 0))  # type: ignore[arg-type]
        key_bytes = next_key_fields.get(2)
        if not isinstance(key_bytes, bytes):
            raise ValueError("malformed NextKey")
        version = sb_fields.get(5)
        if isinstance(version, int) and version >= 1:
            to_sign = (
                b"\0BLOCK\0"
                + block_data
                + b"\0VERSION\0"
                + struct.pack("<I", version)
                + b"\0ALG\0"
                + struct.pack("<I", alg)
                + b"\0KEY\0"
                + key_bytes
                + b"\0PREVSIG\0"
                + sig_bytes
            )
        else:
            to_sign = block_data + struct.pack("<I", alg) + key_bytes + sig_bytes
        final_sig = Ed25519PrivateKey.from_private_bytes(next_secret).sign(to_sign)
        proof_msg = b"\x12" + _encode_varint(len(final_sig)) + final_sig
        out_prefix.extend(b"\x22" + _encode_varint(len(proof_msg)) + proof_msg)
        sealed = bytes(out_prefix)
        _parse_with_trusted_keys(sealed, trusted_keys)
        return sealed
    except Exception as err:  # noqa: BLE001
        raise BiscuitVerificationError(f"failed to seal biscuit: {err}") from err


def require_role(verified: VerifiedBiscuit, role: str) -> None:
    """Requires role(<role>) on an already verified token, as identity.RequireRole."""
    if role not in verified.roles:
        raise BiscuitVerificationError(f"biscuit lacks expected role {role!r}")

