#!/usr/bin/env python3
# Adds a sandbox's SPIFFE identity to the sandbox role in policy.json.
#
#   bind.py <member>          e.g. user:spiffe://openshell.local/openshell/sandbox/<id>
#   bind.py --remove <member>
import json
import sys

args = sys.argv[1:]
remove = False
if args and args[0] == "--remove":
    remove = True
    args = args[1:]
if len(args) != 1:
    sys.exit(__doc__)
member = args[0]

with open("policy.json") as f:
    policy = json.load(f)
binding = next((b for b in policy["bindings"] if b["role"] == "sandbox"), None)
if binding is None:
    binding = {"role": "sandbox", "members": []}
    policy["bindings"].append(binding)
if remove:
    binding["members"] = [m for m in binding["members"] if m != member]
    if not binding["members"]:
        policy["bindings"].remove(binding)
    print("unbound", member)
elif member not in binding["members"]:
    binding["members"].append(member)
    print("bound", member)
else:
    print("already bound", member)
with open("policy.json", "w") as f:
    json.dump(policy, f, indent=2)
    f.write("\n")
