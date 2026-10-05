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

import base64
import json
import stat
import threading
import time
import urllib.parse
from datetime import datetime, timezone

import pytest

from agent_mesh._proto import sam_pb2 as pb
from agent_mesh.credential import decode_auth_response
from agent_mesh.identity import Identity
from agent_mesh.mesh import AgentMesh, CredentialRetiredError
from google.protobuf.timestamp_pb2 import Timestamp


def _ts_ms(ms: int) -> Timestamp:
    t = Timestamp()
    t.FromMilliseconds(int(ms))
    return t


def _ts_s(seconds: int) -> Timestamp:
    t = Timestamp()
    t.FromSeconds(int(seconds))
    return t

CP_KEY = Identity.generate()


class FakeControlPlane:
    """Approves everything and hands out numbered biscuits. With strict_refresh
    it redeems only the last biscuit it issued, as the real one does, and
    refresh_delay is how long a /refresh takes."""

    def __init__(self, keys_ok=True, strict_refresh=False, refresh_delay=0.0):
        self.issued = 0
        self.keys_ok = keys_ok
        self.strict_refresh = strict_refresh
        self.refresh_delay = refresh_delay
        self.last_biscuit = b""
        self.last_refresh_jwt = ""
        # What /keys serves and signs with; a test rotates by replacing it.
        self.keys = [CP_KEY]
        self._lock = threading.Lock()

    def _issue(self, biscuit):
        self.issued += 1
        self.last_biscuit = biscuit
        return biscuit

    def _signed_keys(self):
        ts = int(time.time() * 1000)
        public = [k.public_key_raw for k in self.keys]
        payload = pb.KeysResponse(public_keys=public, sign_time=_ts_ms(ts)).SerializeToString(deterministic=True)
        return pb.KeysResponse(public_keys=public, sign_time=_ts_ms(ts), signatures=[k.sign(payload) for k in self.keys])

    def transport(self, method, url, headers, body):
        path = urllib.parse.urlsplit(url).path
        if (method, path) == ("POST", "/register"):
            # The biscuit names the JWT that was presented, so a test can see which.
            jwt = pb.EnrollRequest.FromString(body).jwt
            return 200, pb.EnrollResponse(
                biscuit_token=self._issue(f"biscuit-for-{jwt}".encode()),
                control_plane_public_key=self.keys[-1].public_key_raw,
                router_addresses=["/dns4/router.example/tcp/4001/p2p/12D3KooWP8iKhDf3iCMo2H3butNVfdTUtYwYWYQ75jTGnynXPFMp"],
                expire_time=_ts_s(int(time.time()) + 3600),
            ).SerializeToString()
        if (method, path) == ("POST", "/enroll"):
            return 200, pb.BootstrapEnrollResponse(
                status=pb.ENROLLMENT_STATUS_APPROVED,
                biscuit_token=self._issue(f"biscuit-{self.issued + 1}".encode()),
                control_plane_public_key=self.keys[-1].public_key_raw,
                router_addresses=["/dns4/router.example/tcp/4001/p2p/12D3KooWP8iKhDf3iCMo2H3butNVfdTUtYwYWYQ75jTGnynXPFMp"],
                expire_time=_ts_s(int(time.time()) + 3600),
            ).SerializeToString()
        if (method, path) == ("POST", "/refresh"):
            time.sleep(self.refresh_delay)
            refresh_req = pb.TokenRefreshRequest.FromString(body) if body else pb.TokenRefreshRequest()
            with self._lock:
                self.last_refresh_jwt = refresh_req.jwt
                presented = base64.b64decode(headers["Authorization"].removeprefix("Bearer "))
                if self.strict_refresh and presented != self.last_biscuit:
                    return 200, pb.TokenRefreshResponse(error_message="biscuit already redeemed").SerializeToString()
                token_bytes = f"biscuit-for-{refresh_req.jwt}".encode() if refresh_req.jwt else f"biscuit-{self.issued + 1}".encode()
                biscuit = self._issue(token_bytes)
            return 200, pb.TokenRefreshResponse(biscuit_token=biscuit, expire_time=_ts_s(int(time.time()) + 7200)).SerializeToString()
        if (method, path) == ("GET", "/keys"):
            return (200, self._signed_keys().SerializeToString()) if self.keys_ok else (500, b"boom")
        return 404, f"no route for {method} {path}".encode()


def test_enroll_persists_load_resumes_refresh_rotates(tmp_path):
    cp = FakeControlPlane()
    token_path = tmp_path / "bootstrap.token"
    token_path.write_text("sbt_secret\n")
    state = tmp_path / "state"

    mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token_path=token_path, state_dir=state, transport=cp.transport)
    assert mesh.credential.biscuit == b"biscuit-1"
    assert mesh.credential.control_plane_keys == [CP_KEY.public_key_raw]
    assert len(mesh.credential.router_addresses) == 1
    assert mesh.credential.time_to_live_seconds() > 3500

    # Secrets on disk are owner-only.
    for name in ("identity.key", "credential.json"):
        assert stat.S_IMODE((state / name).stat().st_mode) == 0o600, name
    assert stat.S_IMODE(state.stat().st_mode) == 0o700

    resumed = AgentMesh.load(state, transport=cp.transport)
    assert resumed.peer_id == mesh.peer_id
    assert resumed.credential.biscuit == b"biscuit-1"
    assert resumed.control_plane.url == "http://127.0.0.1:1"

    resumed.refresh()
    assert resumed.credential.biscuit == b"biscuit-2"
    on_disk = json.loads((state / "credential.json").read_text())
    assert on_disk["biscuit"] == "YmlzY3VpdC0y"  # base64("biscuit-2")
    # The file is api.MemberCredential as protojson: proto field names, RFC 3339 instants.
    assert sorted(on_disk) == ["biscuit", "control_plane_url", "expire_time", "issued_under_keys", "router_addresses", "trusted_keys"]
    assert on_disk["expire_time"].endswith("Z")

    # Enrolling again from the same directory resumes the saved credential
    # without a token; another control plane or an expiring credential
    # enrolls afresh with the same identity.
    issued_before = cp.issued
    again = AgentMesh.enroll("http://127.0.0.1:1", state_dir=state, transport=cp.transport)
    assert again.peer_id == mesh.peer_id
    assert again.credential.biscuit == b"biscuit-2"
    assert cp.issued == issued_before

    with pytest.raises(ValueError, match="no credential to resume"):
        AgentMesh.enroll("http://127.0.0.2:1", state_dir=state, transport=cp.transport)
    elsewhere = AgentMesh.enroll("http://127.0.0.2:1", bootstrap_token="sbt_secret", state_dir=state, transport=cp.transport)
    assert elsewhere.peer_id == mesh.peer_id
    assert cp.issued == issued_before + 1
    assert elsewhere.credential.control_plane_url == "http://127.0.0.2:1"

    expiring = json.loads((state / "credential.json").read_text())
    expiring["expire_time"] = datetime.fromtimestamp(time.time() + 60, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    (state / "credential.json").write_text(json.dumps(expiring))
    AgentMesh.enroll("http://127.0.0.2:1", bootstrap_token="sbt_secret", state_dir=state, transport=cp.transport)
    assert cp.issued == issued_before + 2


def test_enroll_resumes_only_a_credential_the_control_plane_still_vouches_for(tmp_path):
    """A member off across a rotation comes back with a credential and a trust
    set from before it. Within the grace period the retiring key still signs
    /keys, so the credential is resumed and the new key adopted. Past it, the
    control plane serves only keys the member never saw: the credential is
    dead, and the member enrolls again with the token it has, or says so."""
    cp = FakeControlPlane()
    state = tmp_path / "state"
    mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt_secret", state_dir=state, transport=cp.transport)
    issued = cp.issued

    # Within the grace period: resumed, both keys trusted, and persisted so.
    rotated = Identity.generate()
    cp.keys = [CP_KEY, rotated]
    within = AgentMesh.enroll("http://127.0.0.1:1", state_dir=state, transport=cp.transport)
    assert within.credential.biscuit == mesh.credential.biscuit and cp.issued == issued
    assert {bytes(k) for k in within.credential.control_plane_keys} == {CP_KEY.public_key_raw, rotated.public_key_raw}
    assert len(json.loads((state / "credential.json").read_text())["trusted_keys"]) == 2

    # The control plane cannot be reached: resumed as saved; join tries again.
    cp.keys_ok = False
    assert AgentMesh.enroll("http://127.0.0.1:1", state_dir=state, transport=cp.transport).credential.biscuit == mesh.credential.biscuit
    cp.keys_ok = True

    # Past the grace period, from the state as it was before the rotation.
    (state / "credential.json").write_text(json.dumps({**json.loads((state / "credential.json").read_text()), "trusted_keys": [{"public_key": base64.b64encode(CP_KEY.public_key_raw).decode()}]}))
    cp.keys = [rotated]
    with pytest.raises(CredentialRetiredError, match="key the control plane no longer serves"):
        AgentMesh.enroll("http://127.0.0.1:1", state_dir=state, transport=cp.transport)
    again = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt_secret", state_dir=state, transport=cp.transport)
    assert again.peer_id == mesh.peer_id
    assert again.credential.biscuit != mesh.credential.biscuit and cp.issued == issued + 1
    assert [bytes(k) for k in again.credential.control_plane_keys] == [rotated.public_key_raw]


def test_state_dir_and_token_path_expand_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "bootstrap.token").write_text("sbt_secret\n")
    cp = FakeControlPlane()
    mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token_path="~/bootstrap.token", state_dir="~/state", transport=cp.transport)
    assert (tmp_path / "state" / "credential.json").exists()
    assert AgentMesh.load("~/state", transport=cp.transport).peer_id == mesh.peer_id


def test_enroll_without_state_dir_keeps_enrollment_key_when_keys_fails():
    cp = FakeControlPlane(keys_ok=False)
    mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt_secret", transport=cp.transport)
    assert mesh.credential.control_plane_keys == [CP_KEY.public_key_raw]
    mesh.save()
    mesh.refresh()
    assert mesh.credential.biscuit == b"biscuit-2"


def test_concurrent_refreshes_run_one_after_the_other(tmp_path):
    """A session refreshes the credential from one worker thread and pulls
    from the control plane, which may refresh too, from another. The control
    plane redeems only the last biscuit it issued and both write the same
    state files, so two refreshes at once leave the loser with a spent
    biscuit, or renaming a temp file the winner already renamed."""
    cp = FakeControlPlane(strict_refresh=True, refresh_delay=0.05)
    state = tmp_path / "state"
    mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt_secret", state_dir=state, transport=cp.transport)
    errors = []

    def refresh():
        try:
            mesh.refresh()
        except Exception as err:  # noqa: BLE001 - collected for the assertion
            errors.append(err)

    threads = [threading.Thread(target=refresh) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert mesh.credential.biscuit == b"biscuit-9"
    assert json.loads((state / "credential.json").read_text())["biscuit"] == base64.b64encode(b"biscuit-9").decode()
    assert AgentMesh.load(state, transport=cp.transport).credential.biscuit == b"biscuit-9"


def test_enroll_refuses_ambiguous_credentials():
    cp = FakeControlPlane()
    with pytest.raises(ValueError, match="exactly one of"):
        AgentMesh.enroll("http://127.0.0.1:1", transport=cp.transport)
    with pytest.raises(ValueError, match="exactly one of"):
        AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="a", jwt="b", transport=cp.transport)
    with pytest.raises(ValueError, match="exactly one of"):
        AgentMesh.enroll("http://127.0.0.1:1", jwt="a", jwt_path="/nonexistent", transport=cp.transport)
    assert cp.issued == 0


def test_enroll_reads_a_workload_identity_token_from_jwt_path_and_refresh(tmp_path):
    cp = FakeControlPlane()
    token = tmp_path / "token"
    token.write_text("eyJ.projected.token.1\n")
    mesh = AgentMesh.enroll("http://127.0.0.1:1", jwt_path=token, transport=cp.transport)
    assert mesh.credential.biscuit == b"biscuit-for-eyJ.projected.token.1"

    token.write_text("eyJ.projected.token.2\n")
    mesh.refresh()
    assert cp.last_refresh_jwt == "eyJ.projected.token.2"
    assert mesh.credential.biscuit == b"biscuit-for-eyJ.projected.token.2"

    with pytest.raises(FileNotFoundError):
        AgentMesh.enroll("http://127.0.0.1:1", jwt_path=tmp_path / "missing", transport=cp.transport)


def test_enroll_accepts_callable_jwt_and_invokes_on_refresh():
    cp = FakeControlPlane()
    seq = 0
    should_fail = False

    def fetch_jwt() -> str:
        nonlocal seq
        if should_fail:
            raise RuntimeError("metadata server unavailable")
        seq += 1
        return f"  eyJ.callback.{seq} \n"

    mesh = AgentMesh.enroll("http://127.0.0.1:1", jwt=fetch_jwt, transport=cp.transport)
    assert mesh.credential.biscuit == b"biscuit-for-eyJ.callback.1"

    mesh.refresh()
    assert cp.last_refresh_jwt == "eyJ.callback.2"
    assert mesh.credential.biscuit == b"biscuit-for-eyJ.callback.2"

    should_fail = True
    mesh.refresh()
    assert cp.last_refresh_jwt == ""


def test_load_without_identity_says_enroll_first(tmp_path):
    with pytest.raises(FileNotFoundError, match="no identity"):
        AgentMesh.load(tmp_path)
    (tmp_path / "identity.key").write_bytes(Identity.generate().to_libp2p_private_key())
    with pytest.raises(FileNotFoundError, match="no credential"):
        AgentMesh.load(tmp_path)


def test_auth_frame_is_the_protobuf_with_this_members_biscuit():
    cp = FakeControlPlane()
    mesh = AgentMesh.enroll("http://127.0.0.1:1", bootstrap_token="sbt_secret", transport=cp.transport)
    frame = pb.AuthFrame.FromString(mesh.auth_frame("mcp://calculator"))
    assert frame.biscuit == b"biscuit-1"
    assert frame.target_service == "mcp://calculator"

    resp = decode_auth_response(pb.AuthResponse(success=False, error="denied").SerializeToString())
    assert resp.success is False
    assert resp.error == "denied"
