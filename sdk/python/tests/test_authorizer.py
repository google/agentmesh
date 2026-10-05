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

"""The provider authorizer against tokens minted the way the control plane
mints them and policy rules rendered the way it renders them. The decisions
here are the ones internal/node/middleware_test.go pins."""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import biscuit_auth as ba
import pytest
from google.protobuf.timestamp_pb2 import Timestamp

from agent_mesh._proto import sam_pb2
from agent_mesh.authorizer import BASELINE_DATALOG, AuthorizationError, AuthorizeRequest, ProviderAuthorizerOptions, authorize_caller
from agent_mesh.biscuit import attenuate_biscuit

from .test_session import CP, CP_KEY

OTHER = ba.KeyPair()
PROVIDER = "12D3KooWProvider00000000000000000000000000000000000"
CALLER = "12D3KooWCaller0000000000000000000000000000000000000"

# The role grants the service through the mesh policy rules, exactly as the
# control plane renders them; the token itself carries only the role.
NODE_ROLE_GRANTS = [
    'granted_service_set("mcp", ["calc"]) <- role("sam:role:node")',
    'target_unrestricted(true) <- role("sam:role:node")',
]


def mint(facts: list[str], key: ba.KeyPair = CP, expiration: str = "2035-01-01T00:00:00Z") -> bytes:
    return ba.BiscuitBuilder(f"expiration({expiration}); " + " ".join(f + ";" for f in facts)).build(key.private_key).to_bytes()


def node_token(peer_id: str, extra: list[str] | None = None, key: ba.KeyPair = CP) -> bytes:
    """A token as the control plane mints it for a node bound to peer_id."""
    return mint([f'node("{peer_id}")', f'client_peer_id("{peer_id}")', 'role("sam:role:node")', *(extra or [])], key)


def options(policy_rules: list[str], own_biscuit: bytes | None = None) -> ProviderAuthorizerOptions:
    own = own_biscuit or node_token(PROVIDER, ["granted_service_all_types(true)", "target_unrestricted(true)"])
    return ProviderAuthorizerOptions(trusted_keys=lambda: [CP_KEY], own_biscuit=lambda: own, policy_rules=lambda: policy_rules)


def request(biscuit: bytes, target_service: str = "mcp://calc") -> AuthorizeRequest:
    return AuthorizeRequest(biscuit=biscuit, peer_id=CALLER, target_service=target_service, protocol="/sam/mcp/1.0.0")


def test_role_granted_by_mesh_policy_is_allowed():
    verified = authorize_caller(request(node_token(CALLER)), options(NODE_ROLE_GRANTS))
    assert verified.peer_id == CALLER
    assert verified.roles == ["sam:role:node"]


def test_grants_minted_into_the_token_are_enough():
    token = node_token(CALLER, ['granted_service_exact("mcp", "calc")', "target_unrestricted(true)"])
    authorize_caller(request(token), options([]))


def test_empty_target_is_the_protocol_in_the_system_namespace():
    token = node_token(CALLER, ['granted_service_all("sam:system")', "target_unrestricted(true)"])
    authorize_caller(request(token, ""), options([]))
    with pytest.raises(AuthorizationError):
        authorize_caller(request(token, "mcp://calc"), options([]))


def test_ungranted_service_is_denied():
    with pytest.raises(AuthorizationError):
        authorize_caller(request(node_token(CALLER), "mcp://other"), options(NODE_ROLE_GRANTS))


def test_role_with_no_grants_is_denied():
    guest = mint([f'node("{CALLER}")', f'client_peer_id("{CALLER}")', 'role("sam:role:guest")'])
    with pytest.raises(AuthorizationError):
        authorize_caller(request(guest), options(NODE_ROLE_GRANTS))


def test_token_presented_by_another_peer_is_denied():
    stolen = node_token("12D3KooWVictim000000000000000000000000000000000000", ["granted_service_all_types(true)", "target_unrestricted(true)"])
    with pytest.raises(AuthorizationError):
        authorize_caller(request(stolen), options([]))


def test_client_peer_id_must_match_the_connection_peer():
    token = mint(
        [
            f'node("{CALLER}")',
            'client_peer_id("12D3KooWSomeoneElse000000000000000000000000000000")',
            "granted_service_all_types(true)",
            "target_unrestricted(true)",
        ]
    )
    with pytest.raises(AuthorizationError):
        authorize_caller(request(token), options([]))


def test_expired_token_is_denied():
    token = mint(
        [f'node("{CALLER}")', f'client_peer_id("{CALLER}")', "granted_service_all_types(true)", "target_unrestricted(true)"],
        expiration="2020-01-01T00:00:00Z",
    )
    with pytest.raises(AuthorizationError):
        authorize_caller(request(token), options([]))


def test_untrusted_key_is_denied():
    token = node_token(CALLER, ["granted_service_all_types(true)", "target_unrestricted(true)"], key=OTHER)
    with pytest.raises(AuthorizationError):
        authorize_caller(request(token), options([]))


def test_target_grants_match_the_providers_own_identity():
    provider = node_token(PROVIDER, ['group("backend")'])
    rules = ['granted_service_all_types(true) <- role("sam:role:node")', 'target_restricted(true) <- role("sam:role:node")']
    authorize_caller(request(node_token(CALLER, ['granted_target_set("group", ["backend"])'])), options(rules, provider))
    with pytest.raises(AuthorizationError):
        authorize_caller(request(node_token(CALLER, ['granted_target_set("group", ["frontend"])'])), options(rules, provider))
    with pytest.raises(AuthorizationError):
        authorize_caller(request(node_token(CALLER)), options(rules, provider))


def test_narrowed_grant_follows_the_requests_method_and_path():
    # Rendered as the control plane renders a role with
    # http: [{service: "mcp://calc", methods: ["GET"], paths: ["/v1/*"]}]:
    # the plain grant is withheld, the narrowed facts take its place.
    rules = [
        'http_granted_service_exact("mcp", "calc") <- role("sam:role:node")',
        'granted_method("mcp", "calc", ["GET"]) <- role("sam:role:node")',
        'granted_path_prefix("mcp", "calc", "/v1/") <- role("sam:role:node")',
        'target_unrestricted(true) <- role("sam:role:node")',
    ]

    def http(method: str, path: str) -> AuthorizeRequest:
        return AuthorizeRequest(biscuit=node_token(CALLER), peer_id=CALLER, target_service="mcp://calc", protocol="/libp2p-http", method=method, path=path)

    authorize_caller(http("GET", "/v1/models"), options(rules))
    with pytest.raises(AuthorizationError):
        authorize_caller(http("POST", "/v1/models"), options(rules))
    with pytest.raises(AuthorizationError):
        authorize_caller(http("GET", "/v2/models"), options(rules))
    # A tunnel, and a stream that carries no HTTP request: neither matches.
    with pytest.raises(AuthorizationError):
        authorize_caller(http("CONNECT", ""), options(rules))
    with pytest.raises(AuthorizationError):
        authorize_caller(request(node_token(CALLER)), options(rules))


def test_every_baseline_item_parses_in_biscuit_python():
    for c in (BASELINE_DATALOG["time_check"], BASELINE_DATALOG["replay_check"], BASELINE_DATALOG["target_check"]):
        ba.Check(c)
    for r in BASELINE_DATALOG["rules"] + BASELINE_DATALOG["http_rules"] + BASELINE_DATALOG["target_fact_rules"]:
        ba.Rule(r)
    for p in BASELINE_DATALOG["policies"] + [BASELINE_DATALOG["allow_if_true"]]:
        ba.Policy(p)


_TAR_SUITE = json.loads((Path(__file__).resolve().parents[2] / "testdata" / "tar_conformance.json").read_text())


@pytest.mark.parametrize("vec", _TAR_SUITE["vectors"], ids=lambda v: v["name"])
def test_tar_conformance_vector(vec: dict):
    root_pub = base64.b64decode(_TAR_SUITE["public_key_b64"])
    provider_biscuit = base64.b64decode(_TAR_SUITE["provider_biscuit_b64"])
    biscuit_bytes = base64.b64decode(vec["biscuit_b64"])
    eval_now = datetime.fromisoformat(_TAR_SUITE["evaluation_time"])
    req = AuthorizeRequest(
        biscuit=biscuit_bytes,
        peer_id=_TAR_SUITE["caller_peer_id"],
        target_service=vec["target_service"],
        protocol=vec["protocol"],
        method=vec.get("method"),
        path=vec.get("path", ""),
        mcp_tool=vec.get("mcp_tool", ""),
    )
    opts = ProviderAuthorizerOptions(
        trusted_keys=lambda: [root_pub],
        own_biscuit=lambda: provider_biscuit,
        policy_rules=lambda: _TAR_SUITE["policy_datalog_rules"],
        now=lambda: eval_now,
    )
    if not vec["allow"]:
        with pytest.raises(AuthorizationError):
            authorize_caller(req, opts)
        return
    verified = authorize_caller(req, opts)
    assert verified.peer_id == _TAR_SUITE["caller_peer_id"]
    if "expected_effective_expiration" in vec:
        want_exp = datetime.fromisoformat(vec["expected_effective_expiration"])
        assert verified.expiration == want_exp


def test_attenuate_biscuit_narrows_authority_across_hops():
    root = node_token(CALLER, ["granted_service_all_types(true)", "target_unrestricted(true)"])
    hop1_exp = datetime(2034, 5, 1, 0, 0, 0, tzinfo=timezone.utc)
    hop2_exp = datetime(2034, 2, 1, 0, 0, 0, tzinfo=timezone.utc)

    ts1 = Timestamp()
    ts1.FromDatetime(hop1_exp)
    att1 = attenuate_biscuit(
        root,
        sam_pb2.TaskAuthorizationRule(
            name="hop-1",
            expire_time=ts1,
            rules=[
                sam_pb2.TaskRule(
                    allowed_services=["mcp://calc"],
                    operation=sam_pb2.TaskOperation(allowed_tools=["add", "multiply"]),
                )
            ],
        ),
        [CP_KEY],
    )

    ts2 = Timestamp()
    ts2.FromDatetime(hop2_exp)
    att2 = attenuate_biscuit(
        att1,
        sam_pb2.TaskAuthorizationRule(
            name="hop-2",
            expire_time=ts2,
            rules=[
                sam_pb2.TaskRule(
                    allowed_services=["mcp://calc"],
                    operation=sam_pb2.TaskOperation(allowed_tools=["add"]),
                )
            ],
        ),
        [CP_KEY],
    )

    from agent_mesh.biscuit import BiscuitVerificationError, seal_biscuit

    sealed = seal_biscuit(att2, [CP_KEY])
    verified = authorize_caller(
        AuthorizeRequest(biscuit=sealed, peer_id=CALLER, target_service="mcp://calc", protocol="/sam/mcp/1.0.0", mcp_tool="add"),
        options([]),
    )
    assert verified.expiration == hop2_exp
    assert len(verified.task_rules) == 2

    with pytest.raises(AuthorizationError):
        authorize_caller(
            AuthorizeRequest(biscuit=sealed, peer_id=CALLER, target_service="mcp://calc", protocol="/sam/mcp/1.0.0", mcp_tool="multiply"),
            options([]),
        )

    with pytest.raises(BiscuitVerificationError):
        attenuate_biscuit(
            sealed,
            sam_pb2.TaskAuthorizationRule(name="hop-3", rules=[sam_pb2.TaskRule(allowed_services=["mcp://calc"])]),
            [CP_KEY],
        )

