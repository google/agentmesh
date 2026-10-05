# sam-mesh (Python)

Native Python SDK for joining a SAM agent mesh from inside the agent
process. It replaces the `sam-node` sidecar for agents written in Python:
the agent enrolls with the control plane, joins the mesh through a router,
finds services and calls them, answers A2A requests for the agent itself,
and follows the control plane's keys, bans and policy while it runs. It
publishes no service; a tool or a model others should find by name runs
behind a `sam-node`. Import it as
`agent_mesh`.

Guide: [sam-mesh.dev/docs/guides/native-sdks](https://sam-mesh.dev/docs/guides/native-sdks/),
from an empty machine to two programs on a mesh.
Source: [github.com/google/sam/tree/main/sdk/python](https://github.com/google/sam/tree/main/sdk/python).

## Install

```bash
pip install sam-mesh
```

Python 3.11 or later. The SDK runs on trio (py-libp2p is trio-based); under
asyncio, use it through `anyio` with the trio backend. One dependency,
`fastecdsa`, builds from source against GMP (`libgmp-dev` on Debian).

## Use

Both programs below are in
[`examples/`](https://github.com/google/sam/tree/main/sdk/python/examples)
and run against a real mesh in the repository's tests. They read the mesh
from `SAM_CONTROL_PLANE_URL` and the enrollment token from
`SAM_BOOTSTRAP_TOKEN_PATH`; the guide shows how to get both from `sam-one`
or from the operator of an existing mesh.

Find a service and call it:

<!-- embed: sdk/python/examples/call.py -->
```python
"""Calls something on the mesh: a tool of an MCP service or a path of an
inference or A2A service someone published, found by name, or an agent that
published nothing, reached by its peer ID.

    python call.py mcp://everything echo '{"message": "hi"}'
    python call.py inference://ollama /v1/models
    python call.py 12D3KooW... a2a://agent /card

SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or SAM_JWT_PATH
(a workload identity token your platform issues, such as a Kubernetes
projected service account token), and keeps the identity and credential in
SAM_STATE_DIR; later runs resume from there without it.
"""

import json
import os
import sys

import trio
from agent_mesh import AgentMesh

argv = sys.argv[1:]
# A first argument that is not a service target is the peer ID of an agent.
peer_id = None
if argv and "://" not in argv[0]:
    peer_id, argv = argv[0], argv[1:]
service = argv[0] if len(argv) > 0 else ("a2a://agent" if peer_id else "mcp://everything")
tool_or_path = argv[1] if len(argv) > 1 else ("/card" if peer_id else "echo")
args = json.loads(argv[2]) if len(argv) > 2 else {"message": "hi"}

mesh = AgentMesh.enroll(
    os.environ.get("SAM_CONTROL_PLANE_URL", "https://mesh.example.com"),
    bootstrap_token_path=os.environ.get("SAM_BOOTSTRAP_TOKEN_PATH"),
    jwt_path=os.environ.get("SAM_JWT_PATH"),
    state_dir=os.environ.get("SAM_STATE_DIR", "~/.config/sam-mesh/caller"),
    # A plaintext http:// control plane is otherwise accepted only on loopback.
    allow_insecure=os.environ.get("SAM_INSECURE_CONTROL_PLANE") == "true",
)


async def main() -> None:
    async with mesh.join() as session:
        print(f"on the mesh as {session.peer_id}")

        if peer_id:
            # An agent is not in the discovery table; the SDK finds the path
            # to its peer ID through the routers.
            await session.connect(peer_id)
            provider = peer_id
        else:
            providers = await session.discover(service)
            if not providers:
                raise SystemExit(f"no member of the mesh serves {service}")
            # A provider record can outlive its member; the first that answers is used.
            for provider in providers:
                try:
                    await session.connect(provider)
                    break
                except (ConnectionError, PermissionError) as err:
                    print(f"{provider.peer_id}: {err}", file=sys.stderr)
            else:
                raise SystemExit(f"no provider of {service} is reachable")
        print(f"{service} is served by {peer_id or provider.peer_id}")

        if service.startswith("mcp://"):
            tools = await session.list_tools(provider, service)
            print("tools:", ", ".join(t.name for t in tools))
            result = await session.call_tool(provider, service, tool_or_path, args)
            print("\n".join(result.text))
        else:
            response = await session.request(provider, service, tool_or_path)
            print(response.status, response.text)


trio.run(main)
```
<!-- /embed -->

Be an agent others can call. Nothing is published; a caller reaches the
agent by its peer ID, the one it prints, through a router:

<!-- embed: sdk/python/examples/agent.py -->
```python
"""An agent on the mesh: joins, then answers A2A requests from other members
until stopped. It publishes nothing. There is no service name to look up; a
caller reaches the agent by its peer ID, through a router, as `a2a://agent`.
The mesh policy decides which members may call; the SDK turns the others away
before anything reaches this code.

    python agent.py                        # answered by the handler below
    python agent.py http://127.0.0.1:9999  # forwarded to an A2A server beside it

SAM_CONTROL_PLANE_URL names the mesh. The first run enrolls with the file
SAM_BOOTSTRAP_TOKEN_PATH (a token the mesh operator gave you) or SAM_JWT_PATH
(a workload identity token your platform issues, such as a Kubernetes
projected service account token), and keeps the identity and credential in
SAM_STATE_DIR; later runs resume from there, as the same peer, without it.
"""

import json
import os
import sys

import trio
from agent_mesh import AgentMesh, HTTPRequest, HTTPResponse, VerifiedBiscuit

backend_url = sys.argv[1] if len(sys.argv) > 1 else None

mesh = AgentMesh.enroll(
    os.environ.get("SAM_CONTROL_PLANE_URL", "https://mesh.example.com"),
    bootstrap_token_path=os.environ.get("SAM_BOOTSTRAP_TOKEN_PATH"),
    jwt_path=os.environ.get("SAM_JWT_PATH"),
    state_dir=os.environ.get("SAM_STATE_DIR", "~/.config/sam-mesh/agent"),
    # A plaintext http:// control plane is otherwise accepted only on loopback.
    allow_insecure=os.environ.get("SAM_INSECURE_CONTROL_PLANE") == "true",
)


async def card(request: HTTPRequest, caller: VerifiedBiscuit) -> HTTPResponse:
    """Answers every path with who was asked and who asked; a real agent runs
    an A2A server here, or beside this process at backend_url."""
    body = json.dumps({"name": "agent", "path": request.path, "caller": caller.peer_id})
    return HTTPResponse(status=200, headers={"content-type": "application/json"}, body=body.encode())


async def main() -> None:
    async with mesh.join() as session:
        target = await session.accept_a2a(backend_url or card)
        print(f"accepting {target} as {session.peer_id}", flush=True)
        await trio.sleep_forever()


trio.run(main)
```
<!-- /embed -->

`enroll` reuses the identity and credential saved in `state_dir` when they
are still valid for that control plane, and needs exactly one of
`bootstrap_token_path`, `bootstrap_token`, `jwt_path` or `jwt` (a token string
or a `Callable[[], str]` invoked at enrollment and on every refresh)
otherwise. Read tokens from a file, a callback or the environment; do not put
them on a command line. `labels` are attested at enrollment;
`join(egress_require_labels=)` is the floor every peer the session calls must
attest, all of it, held for the session.

A plaintext `http://` control plane is accepted only on loopback. Pass
`allow_insecure=True` for a network you trust.

## License

Apache-2.0. Issues and contributions at
[github.com/google/sam](https://github.com/google/sam).
