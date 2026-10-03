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

"""The provider-side authorizer, mirroring internal/node.(*SamNode).Authorize.
Every piece of Datalog it evaluates is text: the baseline generated from
api/datalog.go (_gen/datalog.json) and the mesh policy rules the control
plane renders (GET /policies). Nothing here derives rules from roles."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from typing import Callable, Optional, Sequence

import biscuit_auth as ba

from .biscuit import BiscuitVerificationError, VerifiedBiscuit, _limits, verify_peer_biscuit
from .discovery import parse_service_target
from .tar import TaskRequestContext, evaluate_task_rules

BASELINE_DATALOG: dict = json.loads(resources.files("agent_mesh._gen").joinpath("datalog.json").read_text())


class AuthorizationError(Exception):
    def __init__(self, peer_id: str, reason: str):
        super().__init__(f"caller {peer_id} is not authorized: {reason}")
        self.peer_id = peer_id
        self.reason = reason


@dataclass(frozen=True)
class AuthorizeRequest:
    """What a caller asks for, as sam-node's RequestContext."""

    # The caller's biscuit, as it arrived in the AuthFrame or X-Sam-Biscuit.
    biscuit: bytes
    # The peer at the other end of the authenticated connection.
    peer_id: str
    # "mcp://<name>", or "" for the protocol itself (the provider's own catalog).
    target_service: str
    # The stream protocol; names the service when target_service is "".
    protocol: str
    # The HTTP method and the path as the backend sees it, when the request is
    # HTTP. Both are injected together; a request without them (a stream that
    # carries no HTTP request) does not match a grant narrowed by
    # PolicyRole.http.
    method: Optional[str] = None
    path: str = ""
    # The MCP tool name when evaluating a specific MCP tools/call invocation.
    mcp_tool: str = ""


@dataclass(frozen=True)
class ProviderAuthorizerOptions:
    # Control plane keys, read per request so a rotation takes effect.
    trusted_keys: Callable[[], Sequence[bytes]]
    # This provider's own biscuit; its identity facts are what target grants match.
    own_biscuit: Callable[[], bytes]
    # The mesh policy as PolicyConfigGetResponse.datalog_rules.
    policy_rules: Callable[[], Sequence[str]]
    now: Optional[Callable[[], datetime]] = None


def _token(biscuit: bytes, key: bytes) -> ba.Biscuit:
    return ba.Biscuit.from_bytes(biscuit, ba.PublicKey.from_bytes(bytes(key), ba.Algorithm.Ed25519))


def authorize_caller(req: AuthorizeRequest, options: ProviderAuthorizerOptions) -> VerifiedBiscuit:
    """Authorizes one request from a caller. Returns the caller's verified
    credential when every check holds and a policy allows; raises
    AuthorizationError otherwise. Every trusted key is tried, as
    VerifyBiscuitToken does."""
    now = options.now() if options.now else datetime.now(timezone.utc)
    keys = list(options.trusted_keys())
    if not keys:
        raise AuthorizationError(req.peer_id, "no trusted control plane key")

    # Signature under a trusted key, authority block + tar_block chain, expiry and binding
    # to the connection peer: RequireAuthorityBinding and EnforceExpiration.
    try:
        caller = verify_peer_biscuit(req.biscuit, req.peer_id, keys, now)
    except BiscuitVerificationError as err:
        raise AuthorizationError(req.peer_id, str(err)) from err
    token = _token(req.biscuit, caller.verifying_key)

    b = ba.AuthorizerBuilder()
    b.set_limits(_limits())

    # The action: service(type, name). An empty target is the protocol itself
    # in the system namespace, as sam-node scopes its own catalog.
    if req.target_service == "":
        svc_type, svc_name = BASELINE_DATALOG["system_namespace"], req.protocol
    else:
        try:
            svc_type, svc_name = parse_service_target(req.target_service)
        except ValueError as err:
            raise AuthorizationError(req.peer_id, str(err)) from err
    b.add_fact(ba.Fact(BASELINE_DATALOG["fact_service"] + "({t}, {n})", {"t": svc_type, "n": svc_name}))
    b.add_fact(ba.Fact(BASELINE_DATALOG["fact_connection_peer_id"] + "({p})", {"p": req.peer_id}))
    b.add_fact(ba.Fact(BASELINE_DATALOG["fact_time"] + "({now})", {"now": now}))

    # The request as the wire carried it, never as the caller describes it.
    if req.method is not None:
        b.add_fact(ba.Fact(BASELINE_DATALOG["fact_method"] + "({m})", {"m": req.method}))
        b.add_fact(ba.Fact(BASELINE_DATALOG["fact_path"] + "({p})", {"p": req.path}))

    b.add_check(ba.Check(BASELINE_DATALOG["replay_check"]))
    b.add_check(ba.Check(BASELINE_DATALOG["time_check"]))

    # This provider's identity as target_fact facts, so the caller's target
    # grants have something to match (injectIdentityFacts).
    for f in _identity_target_facts(options.own_biscuit(), keys, now):
        b.add_fact(f)

    b.add_check(ba.Check(BASELINE_DATALOG["target_check"]))
    for p in BASELINE_DATALOG["policies"]:
        b.add_policy(ba.Policy(p))
    for r in BASELINE_DATALOG["rules"]:
        b.add_rule(ba.Rule(r))
    for r in BASELINE_DATALOG["http_rules"]:
        b.add_rule(ba.Rule(r))
    for r in options.policy_rules():
        b.add_rule(ba.Rule(r))

    try:
        b.build(token).authorize()
    except Exception as err:  # noqa: BLE001 - biscuit-python raises several types for a denial
        raise AuthorizationError(req.peer_id, str(err)) from err

    if caller.task_rules:
        try:
            evaluate_task_rules(
                caller.task_rules,
                TaskRequestContext(
                    service_type=svc_type,
                    service_name=svc_name,
                    has_http=req.method is not None,
                    method=req.method or "",
                    path=req.path,
                    mcp_tool=req.mcp_tool,
                    allow_mcp_stream_init=req.method is None and not req.mcp_tool and req.protocol == "/sam/mcp/1.0.0",
                ),
                now,
            )
        except Exception as err:  # noqa: BLE001
            raise AuthorizationError(req.peer_id, str(err)) from err
    return caller


def _identity_target_facts(own_biscuit: bytes, keys: Sequence[bytes], now: datetime) -> list[ba.Fact]:
    """Evaluates this provider's own biscuit and returns its identity as
    target_fact facts, one per target_fact rule of the baseline."""
    if not own_biscuit:
        return []
    verifying_key = None
    last_err: Exception | None = None
    for key in keys:
        try:
            _token(own_biscuit, key)
            verifying_key = key
            break
        except Exception as err:  # noqa: BLE001
            last_err = err
    if verifying_key is None:
        raise BiscuitVerificationError(f"own credential is not signed by a trusted control plane key: {last_err}")
    b = ba.AuthorizerBuilder()
    b.set_limits(_limits())
    b.add_fact(ba.Fact(BASELINE_DATALOG["fact_time"] + "({now})", {"now": now}))
    b.add_check(ba.Check(BASELINE_DATALOG["time_check"]))
    b.add_policy(ba.Policy(BASELINE_DATALOG["allow_if_true"]))
    authorizer = b.build(_token(own_biscuit, verifying_key))
    try:
        authorizer.authorize()
    except Exception as err:  # noqa: BLE001
        raise BiscuitVerificationError(f"own credential does not verify: {err}") from err
    facts: list[ba.Fact] = []
    for r in BASELINE_DATALOG["target_fact_rules"]:
        facts.extend(authorizer.query(ba.Rule(r)))
    return facts
