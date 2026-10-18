#!/usr/bin/env python3
# Calls the mesh from inside a Substrate actor, the way an agent would: plain
# HTTP to the edge node with a placeholder credential. The Substrate egress
# gateway replaces the placeholder with the actor's mesh credential.
#
# The actor is Substrate's sandbox demo (Alpine, POST /process runs a command
# in the sandbox). This script reaches it through atenet-router on
# 127.0.0.1:${ROUTER_PORT:-8000} with the ate-target-actor header.
#
#   mcp.py tools ACTOR [SERVICE]       tools the mesh offers this actor
#   mcp.py add ACTOR SERVICE A B       call mcp://SERVICE/add through the mesh
import json
import os
import sys
import urllib.error
import urllib.request

ROUTER = "http://127.0.0.1:" + os.environ.get("ROUTER_PORT", "8000")
ATESPACE = os.environ.get("ATESPACE", "ate-demo-sandbox")
# Absolute name: the actor's DNS relay answers REFUSED for the search-domain
# expansions musl tries first under ndots:5, and musl treats that as failure.
NODE = "http://edge-node.agentmesh.svc.cluster.local.:8080/mcp"


def in_actor(actor, command, timeout="60s"):
    body = json.dumps({"command": command, "timeout": timeout}).encode()
    req = urllib.request.Request(ROUTER + "/process", data=body, method="POST", headers={
        "Content-Type": "application/json",
        "ate-target-actor": f"{ATESPACE}/{actor}",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            out = json.load(resp)
    except urllib.error.HTTPError as e:
        sys.exit(f"router answered HTTP {e.code} for actor {ATESPACE}/{actor}: {e.read().decode()[:300]}")
    if out.get("error"):
        sys.exit(f"actor could not run the command: {out['error']} {out.get('stderr', '')}")
    return out["stdout"], out.get("exitCode", 0)


def rpc(actor, tool, arguments):
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    })
    # BusyBox wget speaks HTTP/1.1 well enough for one request; -S puts the
    # status line on stderr, which /process returns separately.
    out, code = in_actor(actor, [
        "wget", "-q", "-O", "-", "-T", "60",
        "--header=Content-Type: application/json",
        "--header=Accept: application/json, text/event-stream",
        "--header=X-Mesh-Authentication: Bearer placeholder",
        f"--post-data={body}", NODE,
    ])
    payload = out
    if out.lstrip().startswith("event:") or "\ndata: " in out:
        payload = "".join(line[6:] for line in out.splitlines() if line.startswith("data: "))
    try:
        reply = json.loads(payload)
    except ValueError:
        sys.exit(f"{tool}: wget exit {code}: {out.strip()[:300] or '(no body; the egress gateway refused the request)'}")
    if "error" in reply:
        error = reply["error"]
        sys.exit(f"{tool}: {error.get('message', error) if isinstance(error, dict) else error}")
    result = reply["result"]
    text = "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
    if result.get("isError"):
        return None, text
    try:
        return json.loads(text), text
    except ValueError:
        return text, text


def tools(actor, service=None):
    rows, text = rpc(actor, "find_remote_tools", {"service_name": service} if service else {})
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


def add(actor, service, a, b):
    rows = tools(actor, service)
    peers = {r["peer_id"] for r in rows if r.get("tool_name") == f"mcp://{service}/add"}
    if not peers:
        print(f"  (no tool of mcp://{service} is visible to this actor; calling the office node directly)")
        peers = {r["peer_id"] for r in rpc(actor, "discover_remote_services", {"type": "mcp"})[0] or []}
    if not peers:
        print(f"mcp://{service}/add({a}, {b}) -> refused: the mesh shows this actor no MCP provider at all (no role binds its identity)")
        sys.exit(3)
    peer = sorted(peers)[0]
    result, text = rpc(actor, "call_remote_tool", {
        "peer_id": peer, "tool_name": f"mcp://{service}/add",
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
        sys.exit("usage: mcp.py tools ACTOR [SERVICE] | add ACTOR SERVICE A B")
