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

"""Mesh member driven by tests/integration/sdk_mesh_test.go: enrolls, joins
the mesh through a real router, prints one JSON line describing the session,
then takes JSON commands on stdin, one per line, until stdin closes:

  {"cmd": "auth", "addr": "<multiaddr>"}  connect (through a relay when the
                                           address says /p2p-circuit) and run
                                           the auth handshake
  {"cmd": "discover", "type": "mcp", "name": "calc"}
                                           DHT lookup for a service's providers
  {"cmd": "tools", "addr": "<multiaddr>", "service": "mcp://calc",
   "required_labels": {"region": "eu"}}   list a provider's tools; the labels,
                                           if given, must be on its credential
  {"cmd": "call", "addr": "<multiaddr>", "service": "mcp://calc",
   "tool": "add", "args": {...}, "required_labels": {...}}
                                           call one tool
  {"cmd": "accept", "name": "agent", "target": "<url>"}
                                           accept A2A requests for this
                                           member's agent; without target, a
                                           handler in this process answers
  {"cmd": "http", "addr": "<multiaddr>", "service": "a2a://agent",
   "path": "/card", "method": "GET", "body": "..."}
                                           call an HTTP service over the mesh
  {"cmd": "peers"}                          peers that authenticated to us
  {"cmd": "sync"}                           pull keys, bans and routers from
                                           the control plane now
  {"cmd": "banned"}                         peers banned by the control plane
  {"cmd": "quit"}                           leave the mesh and exit

Each command gets one JSON line back. Same environment as conformance.py; the
JavaScript SDK ships the same runner (dist/conformance-join.js).
"""

import base64
import json
import logging
import os
import sys
import traceback

import trio

from .libp2p_http import DEFAULT_A2A_NAME, HTTPRequest, HTTPResponse
from .mesh import AgentMesh
from .session import MeshSession


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def _emit(obj: dict) -> None:
    print(json.dumps(obj), flush=True)


def _labels_from_env(name: str) -> dict[str, str]:
    """Labels from an environment variable written "k=v,k2=v2"; a pair without
    "=" is refused (parseRequiredLabels), so a typo never switches a floor off."""
    out: dict[str, str] = {}
    for pair in os.environ.get(name, "").split(","):
        if not pair.strip():
            continue
        key, sep, value = pair.partition("=")
        if not sep:
            raise SystemExit(f"{name}: invalid label {pair.strip()!r}: expected key=value")
        out[key.strip()] = value.strip()
    return out


def _root_cause(err: BaseException) -> BaseException:
    # trio wraps a failure in one ExceptionGroup per nursery it crossed.
    while isinstance(err, BaseExceptionGroup) and len(err.exceptions) == 1:
        err = err.exceptions[0]
    return err


async def _handle(session: MeshSession, command: dict) -> dict:
    cmd = command.get("cmd")
    try:
        if cmd == "auth":
            verified = await session.authenticate(command["addr"])
            return {
                "cmd": cmd,
                "ok": True,
                "peer_id": verified.peer_id,
                "roles": verified.roles,
                "labels": verified.labels,
                "expiration": int(verified.expiration.timestamp()),
            }
        if cmd == "discover":
            providers = await session.discover(command.get("type", "mcp"), command.get("name"))
            return {"cmd": cmd, "ok": True, "providers": [{"peer_id": p.peer_id, "addrs": p.addrs} for p in providers]}
        if cmd == "tools":
            with trio.fail_after(15):
                tools = await session.list_tools(command["addr"], command.get("service", ""), required_labels=command.get("required_labels"))
            return {"cmd": cmd, "ok": True, "tools": [t.name for t in tools]}
        if cmd == "call":
            with trio.fail_after(15):
                result = await session.call_tool(
                    command["addr"], command.get("service", ""), command["tool"], command.get("args") or {}, required_labels=command.get("required_labels")
                )
            return {"cmd": cmd, "ok": True, "is_error": result.is_error, "text": result.text}
        if cmd == "peers":
            return {"cmd": cmd, "authenticated_peers": sorted(session.authenticated_peers)}
        if cmd == "routers":
            return {"cmd": cmd, "ok": True, "routers": [r.peer_id for r in session.routers], "relay_addresses": session.relay_addresses}
        if cmd == "sync":
            result = await session.sync()
            return {
                "cmd": cmd,
                "ok": not result.errors,
                "error": "; ".join(result.errors),
                "keys_changed": result.keys_changed,
                "refreshed": result.refreshed,
                "trusted_keys": [k.hex() for k in session.mesh.credential.control_plane_keys],
                "biscuit": base64.b64encode(session.mesh.credential.biscuit).decode(),
                "banned": session.banned.peers(),
                "router_addresses": list(session.mesh.credential.router_addresses),
            }
        if cmd == "banned":
            return {"cmd": cmd, "ok": True, "banned": session.banned.peers(), "authenticated_peers": sorted(session.authenticated_peers)}
        if cmd == "accept":
            target = command.get("target")
            if not target:

                async def fake(request: HTTPRequest, caller) -> HTTPResponse:  # type: ignore[no-untyped-def]
                    body = json.dumps({"sdk": "python", "peer": caller.peer_id, "method": request.method, "path": request.path.split("?")[0]})
                    return HTTPResponse(status=200, headers={"content-type": "application/json"}, body=body.encode())

                target = fake
            service = await session.accept_a2a(target, name=command.get("name", DEFAULT_A2A_NAME))
            return {"cmd": cmd, "ok": True, "service": service}
        if cmd == "http":
            with trio.fail_after(15):
                res = await session.request(
                    command["addr"],
                    command.get("service", ""),
                    command.get("path", "/"),
                    method=command.get("method", "GET"),
                    headers=command.get("headers"),
                    body=command.get("body"),
                )
            return {"cmd": cmd, "ok": True, "status": res.status, "headers": res.headers, "body": res.text}
        return {"cmd": cmd, "ok": False, "error": f"unknown command {cmd!r}"}
    except BaseException as err:  # noqa: BLE001 - the driver wants the failure, not a dead runner
        if isinstance(err, (KeyboardInterrupt, SystemExit, trio.Cancelled)):
            raise
        cause = _root_cause(err)
        traceback.print_exception(err, file=sys.stderr)
        return {"cmd": cmd, "ok": False, "error": f"{type(cause).__name__}: {cause}"}


async def main() -> None:
    # stdout carries the protocol lines only; every log goes to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING, force=True)
    control_plane_url = _require_env("SAM_CONTROL_PLANE_URL")
    bootstrap_token_path = _require_env("SAM_BOOTSTRAP_TOKEN_PATH")
    state_dir = _require_env("SAM_SDK_STATE_DIR")
    allow_insecure = os.environ.get("SAM_INSECURE_CONTROL_PLANE") == "1"
    listen = [a for a in os.environ.get("SAM_SDK_LISTEN_ADDRS", "").split(",") if a]
    # Labels this member declares at enrollment; the policy's allowed_labels
    # decide whether the control plane attests them. SAM_SDK_EGRESS_REQUIRE_LABELS
    # is the floor every provider this member calls must attest.
    labels = _labels_from_env("SAM_SDK_LABELS")
    egress_require_labels = _labels_from_env("SAM_SDK_EGRESS_REQUIRE_LABELS")

    mesh = AgentMesh.enroll(
        control_plane_url,
        bootstrap_token_path=bootstrap_token_path,
        state_dir=state_dir,
        allow_insecure=allow_insecure,
        labels=labels or None,
        poll_interval=0.2,
    )
    # The test drives every pull itself; only gossip events bring one forward.
    # SAM_SDK_ROUTERS, peer IDs, joins through those routers only, so the test
    # can put two members on different routers.
    only = {p for p in os.environ.get("SAM_SDK_ROUTERS", "").split(",") if p}
    router_addresses = [a for a in mesh.credential.router_addresses if any(a.endswith(f"/p2p/{p}") for p in only)] if only else None
    async with mesh.join(
        listen_addrs=listen, router_addresses=router_addresses, control_plane_sync_interval=0, control_plane_sync_jitter=0, egress_require_labels=egress_require_labels or None
    ) as session:
        _emit(
            {
                "sdk": "python",
                "peer_id": session.peer_id,
                "routers": [{"peer_id": r.peer_id, "addr": str(r.addr), "roles": r.credential.roles} for r in session.routers],
                "relay_addresses": session.relay_addresses,
                "direct_addresses": [str(a) for a in session.host.get_addrs()],
                "biscuit": base64.b64encode(mesh.credential.biscuit).decode(),
                "trusted_keys": [k.hex() for k in mesh.credential.control_plane_keys],
            }
        )
        while True:
            line = await trio.to_thread.run_sync(sys.stdin.readline)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                command = json.loads(line)
            except json.JSONDecodeError as err:
                _emit({"ok": False, "error": f"not JSON: {err}"})
                continue
            if command.get("cmd") == "quit":
                _emit({"cmd": "quit", "ok": True})
                break
            _emit(await _handle(session, command))


if __name__ == "__main__":
    trio.run(main)
