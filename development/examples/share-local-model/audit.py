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

"""Reads an agentmesh-node log on stdin and prints the lines a viewer needs:
what the node serves, one line per authorization decision, and policy updates.

    agentmesh-node run ... 2>&1 | python3 audit.py

Adapted from ../sandboxed-agent/audit.py. Decisions on the internal
system://mesh.catalog lookups are not shown (they are routine allows that
would crowd the pane), and a line is printed when the node loads a changed
policy. On a terminal, ALLOW, DENY and policy updates are colored.
Set AUDIT_RAW=<file> to keep the unfiltered log as well.
"""

import json
import os
import re
import sys
from contextlib import nullcontext

AUDIT = re.compile(r"Audit Traceability\s+(\{.*\})\s*$")
KEEP = re.compile(r"Agent Mesh Node Online|PeerID:|Mesh policy changed|peer banned")
COLOR = {
    "ALLOW": "\033[1;38;2;74;222;128m",   # green
    "DENY": "\033[1;38;2;248;113;113m",   # red
    "POLICY": "\033[1;38;2;250;204;21m",  # yellow
}
RESET = "\033[0m"
# Colors only on a terminal, so a log written to a file stays plain text.
TTY = sys.stdout.isatty()


def paint(kind, text):
    return f"{COLOR[kind]}{text}{RESET}" if TTY else text


def verdict(line):
    m = AUDIT.search(line)
    if m:
        try:
            d = json.loads(m.group(1))
        except json.JSONDecodeError:
            return None
        target = d.get("target", "")
        if target.startswith("system://"):
            return None
        who = f"{d.get('role') or '-'} {d.get('peer_id', '')[:12]}…"
        what = " ".join(x for x in (d.get("method"), d.get("path")) if x) or d.get("protocol", "")
        decision = d.get("decision", "?").upper()
        word = paint(decision, f"{decision:<5}") if decision in COLOR else f"{decision:<5}"
        return f"{word} {who:<28} {what:<26} {target}"
    if "Mesh policy changed" in line:
        return paint("POLICY", "Policy updated by the control plane")
    if "peer banned" in line:
        peer = re.search(r'"peer":\s*"([^"]+)"', line)
        return f"BANNED {peer.group(1) if peer else ''}: the control plane cut this member off"
    if KEEP.search(line):
        # Drop the timestamp and logger columns; keep the message.
        return (line.split("\t")[-1] if "\t" in line else line).strip()
    return None


raw_path = os.environ.get("AUDIT_RAW")
with (open(raw_path, "a") if raw_path else nullcontext()) as raw:
    for raw_line in sys.stdin:
        if raw:
            raw.write(raw_line)
            raw.flush()
        out = verdict(raw_line.rstrip("\n"))
        if out:
            print(out, flush=True)
