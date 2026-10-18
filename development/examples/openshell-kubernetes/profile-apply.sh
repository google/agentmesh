#!/usr/bin/env bash
# Imports the provider profile into the active OpenShell gateway, or updates it
# in place when it already exists (an update must carry the stored
# resource_version).
#
#   profile-apply.sh <profile.yaml>
set -euo pipefail

file=$1
id=$(awk '/^id:/ {print $2; exit}' "$file")
rv=$(openshell profile list -o json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
d = d if isinstance(d, list) else d.get("profiles", [])
print(next((p["resource_version"] for p in d if p.get("id") == sys.argv[1]), 0))' "$id")
if [ "$rv" = 0 ]; then
  openshell profile import -f "$file"
else
  tmp=$(mktemp --suffix=.yaml)
  trap 'rm -f "$tmp"' EXIT
  sed "s/^id: $id\$/id: $id\nresource_version: $rv/" "$file" > "$tmp"
  openshell profile update -f "$tmp" "$id"
fi
