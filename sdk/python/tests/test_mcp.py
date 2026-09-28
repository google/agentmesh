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

"""A provider in one process: a py-libp2p host that serves /sam/mcp/1.0.0 the
way sam-node does (AuthFrame in, AuthResponse out, then MCP over the stream)
with the official MCP server behind it. The real sam-node is exercised by
tests/integration/sdk_mesh_test.go."""

import json
from pathlib import Path

import anyio
import biscuit_auth as ba
import multiaddr
import mcp_types
import pytest
import trio
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.utils.varint import encode_varint_prefixed, read_varint_prefixed_bytes
from mcp.server.mcpserver import MCPServer
from mcp.shared.message import SessionMessage

from agent_mesh._proto import sam_pb2 as pb
from agent_mesh.auth import MCP_PROTOCOL, AuthRejectedError
from agent_mesh.biscuit import VerifiedBiscuit, verify_peer_biscuit
from agent_mesh.controlplane import ROLE_NODE
from agent_mesh.discovery import parse_service_target, service_key
from agent_mesh.identity import Identity
from agent_mesh.mcp_client import LabelsNotSatisfiedError, open_mcp_session, require_egress_labels, require_labels, tool_call_result

from .test_session import CP, CP_KEY, libp2p_host

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "testdata" / "service_keys.json").read_text())


def mint(peer_id: str, role: str, labels: dict[str, str] | None = None) -> bytes:
    code = "node({p}); expiration(2035-01-01T00:00:00Z); role({r});"
    params = {"p": peer_id, "r": role}
    for i, (k, v) in enumerate((labels or {}).items()):
        code += f" label({{k{i}}}, {{v{i}}});"
        params[f"k{i}"] = k
        params[f"v{i}"] = v
    return ba.BiscuitBuilder(code, params).build(CP.private_key).to_bytes()


def calc_server() -> MCPServer:
    server = MCPServer("calc")

    @server.tool()
    def add(a: int, b: int) -> str:
        return str(a + b)

    return server


def catalog_server() -> MCPServer:
    server = MCPServer("catalog")

    @server.tool()
    def list_local_services() -> str:
        return json.dumps([{"type": "mcp", "name": "calc"}])

    return server


def mcp_stream_handler(provider_biscuit: bytes, served: list[str]):
    """sam-node's WithBiscuitAuth(HandleMCPStream) in miniature."""

    async def handle(stream) -> None:
        peer_id = str(stream.muxed_conn.peer_id)
        frame = pb.AuthFrame.FromString(await read_varint_prefixed_bytes(stream))
        try:
            verify_peer_biscuit(frame.biscuit, peer_id, [CP_KEY])
        except Exception:  # noqa: BLE001 - refused callers get a closed stream
            await stream.close()
            return
        service_type, name = parse_service_target(frame.target_service)
        await stream.write(encode_varint_prefixed(pb.AuthResponse(success=True, biscuit=provider_biscuit).SerializeToString()))
        if service_type != "" and name != "calc":
            # An unknown service closes the stream after the frame, as sam-node does.
            await stream.close()
            return
        served.append(frame.target_service)
        server = catalog_server() if service_type == "" else calc_server()
        low = server._lowlevel_server  # noqa: SLF001 - the only way to run it over custom streams

        read_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
        write_stream, write_reader = anyio.create_memory_object_stream[SessionMessage](0)

        async def pump_in():
            try:
                async with read_writer:
                    while True:
                        data = await read_varint_prefixed_bytes(stream)
                        await read_writer.send(SessionMessage(mcp_types.jsonrpc_message_adapter.validate_json(data, by_name=False)))
            except Exception:  # noqa: BLE001 - the caller went away
                pass

        async def pump_out():
            try:
                async with write_reader:
                    async for message in write_reader:
                        await stream.write(encode_varint_prefixed(message.message.model_dump_json(by_alias=True, exclude_unset=True).encode()))
            except Exception:  # noqa: BLE001
                pass

        async with trio.open_nursery() as nursery:
            nursery.start_soon(pump_in)
            nursery.start_soon(pump_out)
            try:
                await low.run(read_stream, write_stream, low.create_initialization_options())
            except Exception:  # noqa: BLE001 - the session ended with the stream
                pass
            finally:
                await stream.close()
                nursery.cancel_scope.cancel()

    return handle


async def start_provider(nursery, labels=None):
    identity = Identity.generate()
    host = libp2p_host(identity)
    biscuit = mint(identity.peer_id, ROLE_NODE, labels)
    served: list[str] = []
    host.set_stream_handler(MCP_PROTOCOL, mcp_stream_handler(biscuit, served))
    started = trio.Event()
    addr_box = []

    async def run():
        async with host.run(listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]):
            addr_box.append(multiaddr.Multiaddr(f"{host.get_addrs()[0]}"))
            started.set()
            await trio.sleep_forever()

    nursery.start_soon(run)
    await started.wait()
    return host, addr_box[0], served


def frame(biscuit: bytes, target: str) -> bytes:
    return pb.AuthFrame(biscuit=biscuit, target_service=target).SerializeToString()


def test_service_keys_match_internal_node_service():
    for s in FIXTURE["services"]:
        assert service_key(s["type"], s["name"] or None).hex() == s["multihash"], f"{s['type']}:{s['name']}"
    assert parse_service_target("mcp://calc") == ("mcp", "calc")
    assert parse_service_target("egress://api.github.com") == ("egress", "api.github.com")
    assert parse_service_target("") == ("", "")
    with pytest.raises(ValueError, match="must look like"):
        parse_service_target("calc")


def test_tools_over_the_mesh_stream():
    async def main():
        async with trio.open_nursery() as nursery:
            provider, addr, served = await start_provider(nursery, labels={"region": "eu"})
            caller_identity = Identity.generate()
            caller = libp2p_host(caller_identity)
            caller_biscuit = mint(caller_identity.peer_id, ROLE_NODE)
            async with caller.run(listen_addrs=[]):
                await caller.connect(info_from_p2p_addr(addr))
                pid = provider.get_id()

                async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [CP_KEY]) as (mcp, verified):
                    assert verified.peer_id == str(pid)
                    assert verified.labels == {"region": "eu"}
                    assert [t.name for t in (await mcp.list_tools()).tools] == ["add"]
                    result = tool_call_result(await mcp.call_tool("add", {"a": 2, "b": 3}))
                    assert result.text == ["5"] and not result.is_error
                assert served == ["mcp://calc"]

                # The empty target is the provider's own catalog.
                async with open_mcp_session(caller, pid, frame(caller_biscuit, ""), [CP_KEY]) as (mcp, _):
                    result = tool_call_result(await mcp.call_tool("list_local_services", {}))
                    assert "calc" in result.text[0]

                # Required labels are checked on the provider's credential.
                async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [CP_KEY], required_labels={"region": "eu"}):
                    pass
                with pytest.raises(LabelsNotSatisfiedError):
                    async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [CP_KEY], required_labels={"region": "us"}):
                        pass
                # Several pairs are met by any one of them; the provider attests region=eu only.
                async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [CP_KEY], required_labels={"region": "eu", "team": "platform"}):
                    pass

                # The egress floor is met only by every one of its pairs, beside the caller's requirement.
                async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [CP_KEY], egress_require_labels={"region": "eu"}):
                    pass
                with pytest.raises(LabelsNotSatisfiedError, match="does not attest the egress floor: region=eu, team=platform"):
                    async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [CP_KEY], egress_require_labels={"region": "eu", "team": "platform"}):
                        pass
                # Both apply when both are set: neither one's pairs stand in for the other's.
                with pytest.raises(LabelsNotSatisfiedError):
                    async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [CP_KEY], required_labels={"region": "eu"}, egress_require_labels={"team": "platform"}):
                        pass
                with pytest.raises(LabelsNotSatisfiedError):
                    async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [CP_KEY], required_labels={"team": "platform"}, egress_require_labels={"region": "eu"}):
                        pass

                # A provider whose credential the caller does not trust is rejected.
                with pytest.raises(AuthRejectedError):
                    async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://calc"), [ba.KeyPair().public_key.to_bytes()]):
                        pass

                # A caller the provider cannot verify gets no session.
                forged = ba.BiscuitBuilder("node({p}); expiration(2035-01-01T00:00:00Z);", {"p": caller_identity.peer_id}).build(ba.KeyPair().private_key).to_bytes()
                with pytest.raises(Exception):
                    async with open_mcp_session(caller, pid, frame(forged, "mcp://calc"), [CP_KEY]):
                        pass

                # A service the provider does not have ends the session before MCP starts.
                with pytest.raises(Exception):
                    with trio.fail_after(5):
                        async with open_mcp_session(caller, pid, frame(caller_biscuit, "mcp://no-such-service"), [CP_KEY]):
                            pass
            nursery.cancel_scope.cancel()

    async def with_timeout():
        with trio.fail_after(60):
            await main()

    trio.run(with_timeout)


def test_a_requirement_of_several_labels_is_met_by_any_one_of_them():
    """The cases of internal/node/labels_gate_test.go, run through the SDK's
    predicate: a caller naming several pairs means any of these will do, as
    sam-node's checkPeerLabels and api.LabelCheck read it."""
    from datetime import datetime, timezone

    def attesting(labels: dict) -> VerifiedBiscuit:
        return VerifiedBiscuit(peer_id="p", expiration=datetime.now(timezone.utc), verifying_key=CP_KEY, roles=[], labels=labels)

    # exact match
    require_labels(attesting({"region": "us-east-1"}), {"region": "us-east-1"})
    # any-of requirement matches one key
    require_labels(attesting({"region": "na-us", "team": "platform"}), {"region": "eu", "team": "platform"})
    # no built-in hierarchy: coarser requirement fails a finer claim
    with pytest.raises(LabelsNotSatisfiedError):
        require_labels(attesting({"region": "us-east-1"}), {"region": "us"})
    # disjoint labels fail
    with pytest.raises(LabelsNotSatisfiedError):
        require_labels(attesting({"region": "na-us"}), {"region": "eu"})
    # unattested token fails closed, naming every pair the caller asked for
    with pytest.raises(LabelsNotSatisfiedError, match="region=eu, team=platform"):
        require_labels(attesting({}), {"region": "eu", "team": "platform"})
    # an empty requirement is no requirement
    require_labels(attesting({}), {})
    require_labels(attesting({}), None)


def test_the_egress_floor_is_met_only_by_every_one_of_its_pairs():
    """sam-node's api.LabelFloorCheck for egress.require_labels, run through
    the SDK's predicate: a floor takes no alternatives."""
    from datetime import datetime, timezone

    def attesting(labels: dict) -> VerifiedBiscuit:
        return VerifiedBiscuit(peer_id="p", expiration=datetime.now(timezone.utc), verifying_key=CP_KEY, roles=[], labels=labels)

    require_egress_labels(attesting({"region": "eu", "team": "platform"}), {"region": "eu"})
    require_egress_labels(attesting({"region": "eu", "team": "platform"}), {"region": "eu", "team": "platform"})
    # one pair short is a refusal that names the whole floor
    with pytest.raises(LabelsNotSatisfiedError, match="peer p does not attest the egress floor: region=eu, team=platform"):
        require_egress_labels(attesting({"region": "eu"}), {"region": "eu", "team": "platform"})
    with pytest.raises(LabelsNotSatisfiedError):
        require_egress_labels(attesting({"region": "us"}), {"region": "eu"})
    # no floor is no floor
    require_egress_labels(attesting({}), {})
    require_egress_labels(attesting({}), None)
