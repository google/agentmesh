#!/usr/bin/env python3
# Calls Gemini on Vertex AI from inside a Substrate actor through the mesh.
# The request goes to the edge node, which forwards it to the office node that
# serves egress://aiplatform.googleapis.com; that node authorizes the method
# and path, mints a federated Google token and injects it. The actor holds no
# Google credential, only the placeholder the egress gateway replaces with its
# mesh credential.
#
#   gemini.py ACTOR OFFICE_PEER PROJECT [REGION] [MODEL] [AGENT_ENGINE_ID]
#
# With an Agent Engine id, a fourth request queries that agent: the same host
# under another granted path.
import json
import os
import sys
import urllib.error
import urllib.request

ROUTER = "http://127.0.0.1:" + os.environ.get("ROUTER_PORT", "8000")
ATESPACE = os.environ.get("ATESPACE", "ate-demo-sandbox")
# Absolute name: see mcp.py.
EDGE = "http://edge-node.agentmesh.svc.cluster.local.:8080"
HEADERS = ["--header=Content-Type: application/json", "--header=X-Mesh-Authentication: ******"]


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
    # A non-zero exit (wget on a 4xx) comes back as an error with the stderr
    # attached; the status line is what the caller wants from it.
    if out.get("error") and "HTTP/" not in out.get("stderr", ""):
        sys.exit(f"actor could not run the command: {out['error']} {out.get('stderr', '')}")
    return out.get("stdout", ""), out.get("stderr", "")


def status_line(stderr):
    # wget -S writes the status line to stderr.
    for line in stderr.splitlines():
        if line.strip().startswith("HTTP/"):
            return line.strip()
    return "(no status line)"


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    actor, peer, project = sys.argv[1:4]
    region = sys.argv[4] if len(sys.argv) > 4 else "us-central1"
    model = sys.argv[5] if len(sys.argv) > 5 else "gemini-2.5-flash"
    engine = sys.argv[6] if len(sys.argv) > 6 else ""
    base = f"{EDGE}/mesh/{peer}/egress/aiplatform.googleapis.com/v1/projects/{project}/locations/{region}"

    print(f"== POST {model}:generateContent, granted to the actor role")
    body = json.dumps({"contents": [{"role": "user", "parts": [{"text": "Answer with one word: what is 2+3?"}]}]})
    out, err = in_actor(actor, ["wget", "-q", "-O", "-", "-T", "60", *HEADERS, f"--post-data={body}",
                                f"{base}/publishers/google/models/{model}:generateContent"])
    try:
        print("  answer:", json.loads(out)["candidates"][0]["content"]["parts"][0]["text"].strip())
    except (ValueError, KeyError, IndexError):
        print("  refused:", (out or err).strip()[:300])

    print("== GET on the model, a method the grant does not list")
    _, err = in_actor(actor, ["wget", "-S", "-q", "-O", "/dev/null", "-T", "30", *HEADERS,
                              f"{base}/publishers/google/models/{model}"])
    print(" ", status_line(err))

    print("== POST to another Vertex AI path, outside the granted paths")
    _, err = in_actor(actor, ["wget", "-S", "-q", "-O", "/dev/null", "-T", "30", *HEADERS, "--post-data={}",
                              f"{base}/endpoints"])
    print(" ", status_line(err))

    if engine:
        print(f"== POST reasoningEngines/{engine}:query, an agent on Agent Engine")
        body = json.dumps({"input": {"a": 40, "b": 2}})
        out, err = in_actor(actor, ["wget", "-q", "-O", "-", "-T", "60", *HEADERS, f"--post-data={body}",
                                    f"{base}/reasoningEngines/{engine}:query"])
        try:
            print("  output:", json.dumps(json.loads(out).get("output")))
        except ValueError:
            print("  refused:", (out or err).strip()[:300])


if __name__ == "__main__":
    main()
