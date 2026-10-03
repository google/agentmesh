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

"""Conformance runner driven by tests/integration/sdk_enroll_test.go: enrolls
against a real control plane, refreshes, reloads from disk and reports what it
holds as JSON on stdout for the Go side to verify. The JavaScript SDK ships the
same runner (dist/conformance.js) with the same environment and output, so one
Go test checks both.

  SAM_CONTROL_PLANE_URL      base URL of the control plane
  SAM_BOOTSTRAP_TOKEN_PATH   file holding a bootstrap token
  SAM_SDK_STATE_DIR          directory for identity and credential
  SAM_INSECURE_CONTROL_PLANE "1" to accept plaintext http:// off loopback
"""

import base64
import json
import os
import sys

from .mesh import AgentMesh


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def main() -> None:
    control_plane_url = _require_env("SAM_CONTROL_PLANE_URL")
    bootstrap_token_path = _require_env("SAM_BOOTSTRAP_TOKEN_PATH")
    state_dir = _require_env("SAM_SDK_STATE_DIR")
    allow_insecure = os.environ.get("SAM_INSECURE_CONTROL_PLANE") == "1"

    mesh = AgentMesh.enroll(
        control_plane_url,
        bootstrap_token_path=bootstrap_token_path,
        state_dir=state_dir,
        allow_insecure=allow_insecure,
        poll_interval=0.2,
    )
    enrolled = mesh.credential

    reloaded = AgentMesh.load(state_dir, allow_insecure=allow_insecure)
    refreshed = reloaded.refresh()

    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    json.dump(
        {
            "sdk": "python",
            "peer_id": mesh.peer_id,
            "public_key": mesh.identity.public_key_raw.hex(),
            "biscuit": b64(enrolled.biscuit),
            "expiration": enrolled.expiration,
            "control_plane_keys": [k.hex() for k in enrolled.control_plane_keys],
            "router_addresses": list(enrolled.router_addresses),
            "reloaded_peer_id": reloaded.peer_id,
            "refreshed_biscuit": b64(refreshed.biscuit),
            "refreshed_expiration": refreshed.expiration,
            "auth_frame": b64(reloaded.auth_frame("mcp://echo")),
        },
        sys.stdout,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
