#!/usr/bin/env python3
# Calls the edge node's MCP server from inside an OpenShell sandbox, the way an
# agent would: plain HTTP to host.openshell.internal, no credential in hand.
# The OpenShell supervisor adds the sandbox's mesh credential on the way out.
#
#   mcp.py tools SANDBOX [SERVICE]        tools the mesh offers this sandbox
#   mcp.py add SANDBOX SERVICE A B        call mcp://SERVICE/add through the mesh
import json
import subprocess
import sys

NODE = "http://host.openshell.internal:8090/mcp"


def rpc(sandbox, tool, arguments):
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })
    out = subprocess.run(
        ["openshell", "sandbox", "exec", "--name", sandbox, "--no-tty", "--",
         "curl", "-sS", "--max-time", "60", "-w", "\n%{http_code}", NODE,
         "-H", "Content-Type: application/json",
         "-H", "Accept: application/json, text/event-stream",
         # OpenShell inspects MCP and wants the revision stated, as a real
         # client does after initialize.
         "-H", "MCP-Protocol-Version: 2025-11-25",
         "-d", body],
        check=True, capture_output=True, text=True,
    ).stdout
    out, _, status = out.rpartition("\n")
    # Streamable HTTP answers as JSON or as one SSE message.
    payload = out
    if out.lstrip().startswith("event:") or "\ndata: " in out:
        payload = "".join(line[6:] for line in out.splitlines() if line.startswith("data: "))
    try:
        reply = json.loads(payload)
    except ValueError:
        sys.exit(f"{tool}: HTTP {status}: {out.strip()[:300]}")
    if "error" in reply:
        error = reply["error"]
        sys.exit(f"{tool}: HTTP {status}: {error.get('message', error) if isinstance(error, dict) else error}")
    result = reply["result"]
    text = "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
    if result.get("isError"):
        return None, text
    try:
        return json.loads(text), text
    except ValueError:
        return text, text


def tools(sandbox, service=None):
    args = {"service_name": service} if service else {}
    rows, text = rpc(sandbox, "find_remote_tools", args)
    if rows is None:
        sys.exit(f"find_remote_tools refused: {text}")
    if isinstance(rows, dict):
        rows = rows.get("tools") or rows.get("results") or [rows]
    for row in rows:
        if "error" in row:
            print(f"  {row.get('peer_id', '?')[:16]}…  {row['error']}")
        else:
            print(f"  {row['peer_id'][:16]}…  {row['tool_name']:<24} {row.get('description', '')}")
    return rows


def add(sandbox, service, a, b):
    rows = tools(sandbox, service)
    peers = {r["peer_id"] for r in rows if r.get("tool_name") == f"mcp://{service}/add"}
    if not peers:
        # Discovery already hides what the policy refuses. Ask a peer anyway, so
        # the refusal itself is visible.
        print(f"  (no tool of mcp://{service} is visible to this sandbox; calling the office node directly)")
        peers = {r["peer_id"] for r in rpc(sandbox, "discover_remote_services", {"type": "mcp"})[0] or []}
    if not peers:
        print(f"mcp://{service}/add({a}, {b}) -> refused: the mesh shows this sandbox no MCP provider at all (no role binds its identity)")
        sys.exit(3)
    peer = sorted(peers)[0]
    result, text = rpc(sandbox, "call_remote_tool", {
        "peer_id": peer,
        "tool_name": f"mcp://{service}/add",
        "arguments": {"a": float(a), "b": float(b)},
    })
    if result is None:
        print(f"mcp://{service}/add({a}, {b}) -> refused: {text}")
        sys.exit(3)
    print(f"mcp://{service}/add({a}, {b}) = {text}")


if __name__ == "__main__":
    cmd, *rest = sys.argv[1:] or ["help"]
    if cmd == "tools" and 1 <= len(rest) <= 2:
        tools(*rest)
    elif cmd == "add" and len(rest) == 4:
        add(*rest)
    else:
        sys.exit(__doc__ or "usage: mcp.py tools SANDBOX [SERVICE] | add SANDBOX SERVICE A B")
