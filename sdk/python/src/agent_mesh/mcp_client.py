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

"""MCP over a mesh stream, the client side of sam-node's /sam/mcp/1.0.0
(internal/node/gate.go): an AuthFrame naming the service, the provider's
AuthResponse, then JSON-RPC messages each with a varint length prefix."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Mapping, Optional, Sequence

import anyio
import mcp_types
import trio
from libp2p.abc import IHost, INetStream
from libp2p.peer.id import ID
from libp2p.utils.varint import encode_varint_prefixed, read_varint_prefixed_bytes
from mcp import ClientSession
from mcp.shared.message import SessionMessage

from ._proto import sam_pb2 as pb
from .auth import AUTH_HANDSHAKE_TIMEOUT, MAX_AUTH_FRAME_BYTES, MCP_PROTOCOL, AuthRejectedError
from .biscuit import BiscuitVerificationError, VerifiedBiscuit, verify_peer_biscuit
from .host import open_stream

logger = logging.getLogger("agent_mesh")

# go-msgio's default message cap, which sam-node's StreamTransport uses.
MAX_MCP_MESSAGE_BYTES = 8 * 1024 * 1024

MCP_CLIENT_INFO = mcp_types.Implementation(name="agent-mesh-sdk", version="0.1.0")


class LabelsNotSatisfiedError(Exception):
    """The provider's credential lacks what the caller requires (any one pair)
    or what the session's egress floor requires (every pair), as
    checkPeerLabels refuses."""

    def __init__(self, peer_id: str, required: Sequence[str], what: str = "carries none of the required labels"):
        super().__init__(f"peer {peer_id} {what}: {', '.join(required)}")


def require_labels(provider: VerifiedBiscuit, required: Optional[Mapping[str, str]]) -> None:
    """A caller's requirement is satisfied by any one pair, as sam-node's
    api.LabelCheck (`check if label(k1, v1) or label(k2, v2)`): several pairs
    mean "any of these will do". The egress floor (require_egress_labels) is the
    conjunction."""
    if not required:
        return
    if any(provider.labels.get(k) == v for k, v in required.items()):
        return
    raise LabelsNotSatisfiedError(provider.peer_id, [f"{k}={v}" for k, v in required.items()])


def require_egress_labels(provider: VerifiedBiscuit, required: Optional[Mapping[str, str]]) -> None:
    """The egress floor is met only by every one of its pairs, as sam-node's
    api.LabelFloorCheck (`check if label(k1, v1), label(k2, v2)`) for
    egress.require_labels: a floor takes no alternatives. Empty is no floor."""
    if not required or all(provider.labels.get(k) == v for k, v in required.items()):
        return
    raise LabelsNotSatisfiedError(provider.peer_id, [f"{k}={v}" for k, v in required.items()], "does not attest the egress floor")


@dataclass
class ToolInfo:
    """One entry of a provider's tool list."""

    name: str
    description: str | None = None


@dataclass
class ToolCallResult:
    """A tool call's outcome, as MCP reports it."""

    is_error: bool
    # Text content blocks, in order; other block types are left out.
    text: list[str]
    raw: mcp_types.CallToolResult


async def _read_frame(stream: INetStream) -> bytes:
    data = await read_varint_prefixed_bytes(stream)
    if len(data) > MAX_MCP_MESSAGE_BYTES:
        raise ValueError(f"frame of {len(data)} bytes exceeds the {MAX_MCP_MESSAGE_BYTES} byte cap")
    return data


@asynccontextmanager
async def open_mcp_session(
    host: IHost,
    peer_id: ID,
    frame: bytes,
    trusted_keys: Sequence[bytes],
    *,
    required_labels: Optional[Mapping[str, str]] = None,
    egress_require_labels: Optional[Mapping[str, str]] = None,
) -> AsyncIterator[tuple[ClientSession, VerifiedBiscuit]]:
    """Opens /sam/mcp/1.0.0 to a connected provider with `frame`, this member's
    AuthFrame naming the service, verifies the provider and yields an
    initialized MCP ClientSession with the provider's credential; egress_require_labels
    is the session's, not the caller's (require_egress_labels)."""
    stream = await open_stream(host, peer_id, MCP_PROTOCOL, AUTH_HANDSHAKE_TIMEOUT)
    try:
        with trio.fail_after(AUTH_HANDSHAKE_TIMEOUT):
            await stream.write(encode_varint_prefixed(frame))
            data = await read_varint_prefixed_bytes(stream)
        if len(data) > MAX_AUTH_FRAME_BYTES:
            raise AuthRejectedError(str(peer_id), "oversized auth response")
        resp = pb.AuthResponse.FromString(data)
        if not resp.success:
            raise AuthRejectedError(str(peer_id), resp.error or "no reason given")
        try:
            provider = verify_peer_biscuit(resp.biscuit, str(peer_id), trusted_keys)
        except BiscuitVerificationError as err:
            raise AuthRejectedError(str(peer_id), f"provider credential rejected: {err}") from err
        require_labels(provider, required_labels)
        require_egress_labels(provider, egress_require_labels)
    except trio.TooSlowError as err:
        await stream.close()
        raise AuthRejectedError(str(peer_id), "handshake timed out") from err
    except BaseException:
        await stream.close()
        raise

    # The mcp client speaks over a pair of memory streams; two tasks move
    # frames between them and the libp2p stream.
    read_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_stream, write_reader = anyio.create_memory_object_stream[SessionMessage](0)

    async def pump_in() -> None:
        try:
            async with read_writer:
                while True:
                    data = await _read_frame(stream)
                    try:
                        message = mcp_types.jsonrpc_message_adapter.validate_json(data, by_name=False)
                    except ValueError as exc:
                        await read_writer.send(exc)
                        continue
                    await read_writer.send(SessionMessage(message))
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass
        except Exception as err:  # noqa: BLE001 - the stream ended; the session sees the closed read side
            logger.debug("mcp stream from %s ended: %s", peer_id, err)

    async def pump_out() -> None:
        try:
            async with write_reader:
                async for session_message in write_reader:
                    data = session_message.message.model_dump_json(by_alias=True, exclude_unset=True).encode()
                    await stream.write(encode_varint_prefixed(data))
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass

    async with trio.open_nursery() as nursery:
        nursery.start_soon(pump_in)
        nursery.start_soon(pump_out)
        try:
            async with ClientSession(read_stream, write_stream, client_info=MCP_CLIENT_INFO) as session:
                await session.initialize()
                yield session, provider
        finally:
            await stream.close()
            nursery.cancel_scope.cancel()


def tool_call_result(result: mcp_types.CallToolResult) -> ToolCallResult:
    text = [c.text for c in result.content if isinstance(c, mcp_types.TextContent)]
    # mcp_types 2.x names the field is_error; 1.x named it isError.
    is_error = getattr(result, "is_error", None)
    if is_error is None:
        is_error = getattr(result, "isError", False)
    return ToolCallResult(is_error=bool(is_error), text=text, raw=result)
