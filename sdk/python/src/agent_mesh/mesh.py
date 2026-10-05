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

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Mapping, Optional

from ._proto import sam_pb2 as pb
from .controlplane import ROLE_NODE, ControlPlaneClient, Enrollment, KeysNotTrustedError, Transport
from .credential import MeshCredential, encode_auth_frame
from .identity import Identity

_IDENTITY_FILE = "identity.key"
_CREDENTIAL_FILE = "credential.json"
# A saved credential with less validity left than this is not worth resuming; enroll again instead.
_REUSE_MIN_TTL_SECONDS = 5 * 60

JwtSource = Callable[[], str]


class CredentialRetiredError(Exception):
    """The saved credential was issued under a signing key the control plane
    no longer serves, so nothing can verify or refresh it; the member must
    enroll again with a token."""

    def __init__(self, state: Path):
        super().__init__(
            f"the credential in {state} was issued under a key the control plane no longer serves "
            "(the member was off for longer than the key grace period); enroll again with a token"
        )


def _resumable_credential(control_plane: ControlPlaneClient, credential: MeshCredential) -> Optional[MeshCredential]:
    """The saved credential with the control plane's current keys adopted, or
    None when the control plane vouches for none of the keys it trusts. A
    control plane that cannot be reached, or answers in a way that is not a
    verdict on the keys, leaves the credential as it is: the pull before join
    tries again."""
    try:
        keys = control_plane.keys(credential.control_plane_keys)
    except KeysNotTrustedError:
        return None
    except Exception:  # noqa: BLE001 - unreachable, or an answer that is not about the keys
        return credential
    if not keys or {bytes(k) for k in keys} == {bytes(k) for k in credential.control_plane_keys}:
        return credential
    return replace(credential, control_plane_keys=[bytes(k) for k in keys])


@dataclass(frozen=True)
class ControlPlaneSync:
    """What one pull from the control plane changed."""

    # The trusted key set differs from before the pull.
    keys_changed: bool
    # The credential was re-issued because a rotation had happened since.
    refreshed: bool
    # The control plane's ban set, when /info answered.
    banned_peer_ids: Optional[list[str]]
    # When /info was asked (unix seconds); a ban recorded later cannot be in the answer.
    fetched_at: float
    # One entry per part that failed; empty when everything landed.
    errors: list[str] = field(default_factory=list)


class AgentMesh:
    """A member of the mesh: an identity, the credential the control plane
    minted for it, and the client that keeps that credential fresh. join()
    puts it on the mesh over libp2p."""

    def __init__(
        self,
        identity: Identity,
        control_plane: ControlPlaneClient,
        credential: MeshCredential,
        state_dir: Optional[Path],
        jwt_source: Optional[JwtSource] = None,
    ):
        self.identity = identity
        self.control_plane = control_plane
        self._credential = credential
        self._state_dir = state_dir
        self._jwt_source = jwt_source
        # refresh() and sync_control_plane() run in worker threads of the
        # session's loops; the control plane redeems only the last biscuit it
        # issued, and both write the same state files.
        self._lock = threading.RLock()

    @property
    def peer_id(self) -> str:
        return self.identity.peer_id

    @property
    def credential(self) -> MeshCredential:
        return self._credential

    def attenuate(self, rule: pb.TaskAuthorizationRule) -> MeshCredential:
        """Returns a new MeshCredential with a tar_block appended offline in memory."""
        return self._credential.attenuate(rule)

    def seal(self) -> MeshCredential:
        """Returns a new MeshCredential with its biscuit sealed against further attenuation."""
        return self._credential.seal()

    @classmethod
    def enroll(
        cls,
        control_plane_url: str,
        *,
        bootstrap_token: Optional[str] = None,
        bootstrap_token_path: Optional[str | os.PathLike[str]] = None,
        jwt: Optional[str | JwtSource] = None,
        jwt_path: Optional[str | os.PathLike[str]] = None,
        state_dir: Optional[str | os.PathLike[str]] = None,
        identity: Optional[Identity] = None,
        role: str = ROLE_NODE,
        labels: Optional[Mapping[str, str]] = None,
        allow_insecure: bool = False,
        poll_interval: Optional[float] = None,
        cancel: Optional[threading.Event] = None,
        transport: Optional[Transport] = None,
    ) -> "AgentMesh":
        """Enrolls with the control plane and returns a member holding a credential.

        When state_dir already holds an unexpired credential from this control
        plane for the saved identity, that member is returned and no token is
        needed, so a program can call enroll on every start and read the token
        from its environment only on the first. A credential is resumed only
        while the control plane still serves a key the member trusts: one
        issued under a key that retired while the member was off cannot be
        verified or refreshed, so the member enrolls again with the token
        given, or raises CredentialRetiredError without one. Otherwise exactly
        one of bootstrap_token, bootstrap_token_path, jwt or jwt_path must be
        given; a token is better read from a file or a callback than passed as
        a value, and jwt_path or a callable jwt also supplies a fresh workload
        identity token on every refresh. Delete the state directory to enroll
        afresh, for instance with other labels."""
        state = Path(state_dir).expanduser() if state_dir is not None else None
        saved = _load_identity(state)
        identity = identity or saved or Identity.generate()
        control_plane = ControlPlaneClient(control_plane_url, allow_insecure=allow_insecure, transport=transport)
        jwt_source = _resolve_jwt_source(jwt=jwt, jwt_path=jwt_path)
        given = sum(v is not None for v in (bootstrap_token, bootstrap_token_path, jwt, jwt_path))
        if state is not None and saved is not None and saved.peer_id == identity.peer_id:
            credential = _load_credential(state)
            if credential is not None and credential.control_plane_url.rstrip("/") == control_plane.url.rstrip("/") and credential.time_to_live_seconds() > _REUSE_MIN_TTL_SECONDS:
                resumed = _resumable_credential(control_plane, credential)
                if resumed is not None:
                    mesh = cls(identity, control_plane, resumed, state, jwt_source)
                    if resumed is not credential:
                        mesh.save()
                    return mesh
                if given == 0:
                    raise CredentialRetiredError(state)
        if given != 1:
            where = f" (no credential to resume in {state})" if state is not None else ""
            raise ValueError(f"exactly one of bootstrap_token, bootstrap_token_path, jwt or jwt_path is required{where}")

        enrollment: Enrollment
        if jwt is not None or jwt_path is not None:
            token = jwt_source() if jwt_source is not None else str(jwt)
            enrollment = control_plane.register(identity, token, role=role, labels=labels)
        else:
            if bootstrap_token_path is not None:
                bootstrap_token = Path(bootstrap_token_path).expanduser().read_text().strip()
            assert bootstrap_token is not None
            enrollment = control_plane.enroll_bootstrap(
                identity, bootstrap_token, role=role, labels=labels, poll_interval=poll_interval, cancel=cancel
            )

        # Widen trust from the one key the enrollment carries to every key the
        # control plane currently signs with, so peers holding credentials from
        # a retiring key still verify. Best effort, as in sam-node.
        control_plane_keys = [enrollment.control_plane_public_key]
        try:
            control_plane_keys = control_plane.keys(control_plane_keys)
        except Exception:  # noqa: BLE001 - the enrollment key alone still works until the next sync
            pass

        mesh = cls(
            identity,
            control_plane,
            MeshCredential(
                control_plane_url=control_plane.url,
                biscuit=enrollment.biscuit,
                expiration=enrollment.expiration,
                control_plane_keys=control_plane_keys,
                issued_under_keys=list(control_plane_keys),
                router_addresses=list(enrollment.router_addresses),
            ),
            state,
            jwt_source,
        )
        mesh.save()
        return mesh

    @classmethod
    def load(
        cls,
        state_dir: str | os.PathLike[str],
        *,
        identity: Optional[Identity] = None,
        jwt: Optional[JwtSource] = None,
        jwt_path: Optional[str | os.PathLike[str]] = None,
        allow_insecure: bool = False,
        transport: Optional[Transport] = None,
    ) -> "AgentMesh":
        """Resumes a member from a state directory written by an earlier enroll(),
        for a process that must never hold an enrollment token. The control plane
        URL comes from the saved credential."""
        state = Path(state_dir).expanduser()
        identity = identity or _load_identity(state)
        if identity is None:
            raise FileNotFoundError(f"no identity in {state}; enroll first")
        credential = _load_credential(state)
        if credential is None:
            raise FileNotFoundError(f"no credential in {state}; enroll first")
        control_plane = ControlPlaneClient(credential.control_plane_url, allow_insecure=allow_insecure, transport=transport)
        return cls(identity, control_plane, credential, state, _resolve_jwt_source(jwt=jwt, jwt_path=jwt_path))

    def refresh(self) -> MeshCredential:
        """Trades the current biscuit for a fresh one and persists it. The control
        plane redeems only the last biscuit it issued, so a lost refresh result
        means re-enrolling; persisting before returning keeps that rare."""
        with self._lock:
            fresh_jwt: Optional[str] = None
            if self._jwt_source is not None:
                try:
                    token = self._jwt_source()
                    if token:
                        fresh_jwt = token
                except Exception:  # noqa: BLE001 - fall back to session-only refresh if token source is unavailable
                    pass
            result = self.control_plane.refresh(self.identity, self._credential.biscuit, jwt=fresh_jwt)
            control_plane_keys = self._credential.control_plane_keys
            try:
                control_plane_keys = self.control_plane.keys(control_plane_keys)
            except Exception:  # noqa: BLE001 - a failed /keys sync must not cost the new biscuit
                pass
            self._credential = replace(
                self._credential,
                biscuit=result.biscuit,
                expiration=result.expiration,
                control_plane_keys=control_plane_keys,
                issued_under_keys=list(control_plane_keys),
            )
            self.save()
            return self._credential

    def add_trusted_key(self, key: bytes) -> bool:
        """Adopts a signing key announced by a KEY_ROTATION event, so peers whose
        credentials the new key signs verify before the next pull confirms it."""
        with self._lock:
            if any(bytes(k) == bytes(key) for k in self._credential.control_plane_keys):
                return False
            self._credential = replace(self._credential, control_plane_keys=[*self._credential.control_plane_keys, bytes(key)])
            return True

    def sync_control_plane(self) -> ControlPlaneSync:
        """The member's pull from the control plane, as sam-node's SyncControlPlane:
        the signing keys (verified against the set already trusted, so whoever
        answers the URL cannot become the trust root), a credential refresh when
        a rotation happened since it was issued, and /info for the router
        addresses and the ban set. Each part is attempted even when another
        fails; the errors are reported together. Gossip events only bring this
        forward; they are never the only way state arrives."""
        with self._lock:
            return self._sync_control_plane()

    def _sync_control_plane(self) -> ControlPlaneSync:
        errors: list[str] = []
        keys_changed = False
        refreshed = False
        try:
            keys = self.control_plane.keys(self._credential.control_plane_keys)
            if not keys:
                raise ValueError("/keys returned no keys")
            keys_changed = {bytes(k) for k in keys} != {bytes(k) for k in self._credential.control_plane_keys}
            self._credential = replace(self._credential, control_plane_keys=list(keys))
            if self._credential.predates_rotation():
                self.refresh()
                refreshed = True
        except Exception as err:  # noqa: BLE001 - reported, the other parts still run
            errors.append(f"keys: {err}")

        banned_peer_ids: Optional[list[str]] = None
        # Taken before the request: a ban recorded after this instant cannot be
        # in the answer, so its absence must not be read as an unban.
        fetched_at = time.time()
        try:
            info = self.control_plane.info()
            if info.router_addresses:
                self._credential = replace(self._credential, router_addresses=list(info.router_addresses))
            banned_peer_ids = list(info.banned_peer_ids)
        except Exception as err:  # noqa: BLE001
            errors.append(f"info: {err}")
        if keys_changed or banned_peer_ids is not None:
            self.save()
        return ControlPlaneSync(keys_changed=keys_changed, refreshed=refreshed, banned_peer_ids=banned_peer_ids, fetched_at=fetched_at, errors=errors)

    def auth_frame(self, target_service: str = "") -> bytes:
        """The frame that opens every stream to a peer: this member's biscuit plus
        the service it wants (e.g. "mcp://calculator")."""
        return encode_auth_frame(self._credential.biscuit, target_service)

    def join(self, **options):  # type: ignore[no-untyped-def]
        """Joins the mesh: connects to the routers in the credential, passes the
        auth handshake with them, reserves a relay slot and keeps the credential
        and the reservation fresh. An async context manager to use under trio:

            async with mesh.join() as session: ...
        """
        from .session import join_mesh

        return join_mesh(self, **options)

    def save(self) -> None:
        """Writes identity and credential to the state directory, if one is configured."""
        if self._state_dir is None:
            return
        with self._lock:
            self._state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            _write_atomic(self._state_dir / _IDENTITY_FILE, self.identity.to_libp2p_private_key())
            _write_atomic(self._state_dir / _CREDENTIAL_FILE, self._credential.to_json().encode())


def _load_identity(state: Optional[Path]) -> Optional[Identity]:
    if state is None:
        return None
    try:
        return Identity.from_libp2p_private_key((state / _IDENTITY_FILE).read_bytes())
    except FileNotFoundError:
        return None


def _load_credential(state: Path) -> Optional[MeshCredential]:
    try:
        return MeshCredential.from_json((state / _CREDENTIAL_FILE).read_text())
    except FileNotFoundError:
        return None


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _resolve_jwt_source(
    *,
    jwt: Optional[str | JwtSource],
    jwt_path: Optional[str | os.PathLike[str]],
) -> Optional[JwtSource]:
    if jwt_path is not None:
        path = Path(jwt_path).expanduser()
        return lambda: path.read_text(encoding="utf-8").strip()
    if callable(jwt):
        fn = jwt
        return lambda: fn().strip()
    return None

