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

"""Task-Scoped Authorization Rule (TAR) validation, tar_block encoding/decoding,
and multi-hop intersection evaluation, mirroring api/tar.go."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from typing import Callable, Sequence

from ._proto import sam_pb2

_DATALOG: dict = json.loads(resources.files("agent_mesh._gen").joinpath("datalog.json").read_text())

_TAR_BLOCK_SOURCE_RE = re.compile(_DATALOG["tar_block_source_pattern"])
_HTTP_METHOD_RE = re.compile(_DATALOG["http_method_syntax"])
_VALID_SERVICE_TYPES = frozenset({"mcp", "a2a", "inference", "http", "egress"})


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(b64_payload: str) -> bytes:
    if not b64_payload or "=" in b64_payload:
        raise ValueError("invalid unpadded base64url in tar_block")
    padded = b64_payload + "=" * ((4 - len(b64_payload) % 4) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    if _b64url_encode(raw) != b64_payload:
        raise ValueError("non-canonical base64url in tar_block")
    return raw


def validate_service_pattern(s: str) -> None:
    if s == "*":
        return
    scheme, sep, target = s.partition("://")
    if not sep or not scheme:
        raise ValueError(f"invalid service format: {s}")
    if scheme not in _VALID_SERVICE_TYPES:
        raise ValueError(f'invalid service type "{scheme}" in {s}')
    if not target or "/" in target or target.count("*") > 1:
        raise ValueError(f'invalid service target "{target}" in {s}')
    if "*" in target and target != "*":
        valid_suffix = target.startswith("*.") and len(target[2:]) > 0
        valid_prefix = target.endswith(".*") and len(target[:-2]) > 0
        if not valid_suffix and not valid_prefix:
            raise ValueError(f"wildcard in {s!r} must be '*', '*.<suffix>' or '<prefix>.*'")


def validate_http_grant_path(p: str) -> None:
    if not p.startswith("/"):
        raise ValueError(f"path {p!r} must start with '/'")
    if "?" in p or "#" in p:
        raise ValueError(f"path {p!r} must not contain '?' or '#'")
    stars = p.count("*")
    if stars > 1 or (stars == 1 and not p.endswith("*")):
        raise ValueError(f"path {p!r}: '*' is only valid once, at the end")
    for seg in p[1:].split("/"):
        if seg in (".", ".."):
            raise ValueError(f"path {p!r} must not contain '.' or '..' segments")


def _validate_tar_string_list(field_name: str, values: Sequence[str], check_elem: Callable[[str], None]) -> None:
    max_entries = _DATALOG["max_entries_per_tar_list"]
    if len(values) > max_entries:
        raise ValueError(f"TaskRule.{field_name} has {len(values)} entries; maximum is {max_entries}")
    for i, val in enumerate(values):
        try:
            check_elem(val)
        except Exception as err:  # noqa: BLE001
            raise ValueError(f"TaskRule.{field_name}[{i}]: {err}") from err


def validate_task_rule(r: sam_pb2.TaskRule) -> None:
    max_desc = _DATALOG["max_tar_description_length"]
    if len(r.description.encode("utf-8")) > max_desc:
        raise ValueError(f"TaskRule.description exceeds {max_desc} bytes")
    _validate_tar_string_list("allowed_services", r.allowed_services, validate_service_pattern)

    max_res = _DATALOG["max_tar_resource_length"]

    def _check_resource(res: str) -> None:
        if not res:
            raise ValueError("resource must not be empty")
        if len(res.encode("utf-8")) > max_res:
            raise ValueError(f"resource exceeds {max_res} bytes")

    _validate_tar_string_list("allowed_resources", r.allowed_resources, _check_resource)

    if r.HasField("operation"):
        op = r.operation

        def _check_non_empty(label: str) -> Callable[[str], None]:
            def _fn(v: str) -> None:
                if not v:
                    raise ValueError(f"{label} must not be empty")

            return _fn

        def _check_method(m: str) -> None:
            if not _HTTP_METHOD_RE.match(m):
                raise ValueError(f"invalid HTTP method {m!r}")
            if m == "CONNECT":
                raise ValueError("CONNECT is not a grantable HTTP method")

        _validate_tar_string_list("operation.allowed_tools", op.allowed_tools, _check_non_empty("tool name"))
        _validate_tar_string_list("operation.allowed_methods", op.allowed_methods, _check_method)
        _validate_tar_string_list("operation.allowed_paths", op.allowed_paths, validate_http_grant_path)
        _validate_tar_string_list("operation.allowed_permissions", op.allowed_permissions, _check_non_empty("permission"))


def validate_task_authorization_rule(rule: sam_pb2.TaskAuthorizationRule, require_non_empty_rules: bool = True) -> None:
    max_name = _DATALOG["max_tar_name_length"]
    if len(rule.name.encode("utf-8")) > max_name:
        raise ValueError(f"TaskAuthorizationRule.name exceeds {max_name} bytes")
    max_desc = _DATALOG["max_tar_description_length"]
    if len(rule.display_name.encode("utf-8")) > max_desc:
        raise ValueError(f"TaskAuthorizationRule.display_name exceeds {max_desc} bytes")
    if require_non_empty_rules and len(rule.rules) == 0:
        raise ValueError("TaskAuthorizationRule.rules must not be empty")
    max_rules = _DATALOG["max_rules_per_tar"]
    if len(rule.rules) > max_rules:
        raise ValueError(f"TaskAuthorizationRule.rules has {len(rule.rules)} entries; maximum is {max_rules}")
    for i, r in enumerate(rule.rules):
        try:
            validate_task_rule(r)
        except Exception as err:  # noqa: BLE001
            raise ValueError(f"TaskAuthorizationRule.rules[{i}]: {err}") from err
    if rule.HasField("expire_time"):
        seconds = rule.expire_time.seconds
        nanos = rule.expire_time.nanos
        if nanos < 0 or nanos >= 1_000_000_000:
            raise ValueError("TaskAuthorizationRule.expire_time has invalid nanos")
        _ = seconds


def encode_tar_block_payload(rule: sam_pb2.TaskAuthorizationRule) -> str:
    validate_task_authorization_rule(rule, require_non_empty_rules=True)
    raw = rule.SerializeToString(deterministic=True)
    max_bytes = _DATALOG["max_tar_bytes"]
    if len(raw) > max_bytes:
        raise ValueError(f"TaskAuthorizationRule serialized size {len(raw)} exceeds {max_bytes} bytes")
    return _b64url_encode(raw)


def encode_tar_block_fact(rule: sam_pb2.TaskAuthorizationRule) -> str:
    b64 = encode_tar_block_payload(rule)
    return f'{_DATALOG["fact_tar_block"]}("{b64}")'


def decode_tar_block_payload(b64_payload: str) -> sam_pb2.TaskAuthorizationRule:
    raw = _b64url_decode(b64_payload)
    max_bytes = _DATALOG["max_tar_bytes"]
    if len(raw) == 0 or len(raw) > max_bytes:
        raise ValueError(f"tar_block decoded payload size {len(raw)} out of bounds [1, {max_bytes}]")
    rule = sam_pb2.TaskAuthorizationRule()
    try:
        rule.ParseFromString(raw)
    except Exception as err:  # noqa: BLE001
        raise ValueError(f"invalid TaskAuthorizationRule protobuf in tar_block: {err}") from err
    before = rule.SerializeToString(deterministic=True)
    rule.DiscardUnknownFields()
    after = rule.SerializeToString(deterministic=True)
    if before != after:
        raise ValueError("TaskAuthorizationRule in tar_block contains unknown protobuf wire fields")
    validate_task_authorization_rule(rule, require_non_empty_rules=False)
    return rule


def parse_tar_block_source(block_source: str) -> sam_pb2.TaskAuthorizationRule:
    m = _TAR_BLOCK_SOURCE_RE.match(block_source.strip())
    if not m:
        raise ValueError('non-authority block does not match single tar_block("<base64url>") grammar')
    return decode_tar_block_payload(m.group(1))


def _tar_expire_datetime(rule: sam_pb2.TaskAuthorizationRule) -> datetime | None:
    if not rule.HasField("expire_time"):
        return None
    ts = rule.expire_time
    return datetime.fromtimestamp(ts.seconds + ts.nanos / 1e9, tz=timezone.utc)


def effective_tar_expiration(authority_expiration: datetime, rules: Sequence[sam_pb2.TaskAuthorizationRule]) -> datetime:
    effective = authority_expiration
    for r in rules:
        exp = _tar_expire_datetime(r)
        if exp is not None and exp < effective:
            effective = exp
    return effective


@dataclass(frozen=True)
class TaskRequestContext:
    service_type: str
    service_name: str
    has_http: bool = False
    method: str = ""
    path: str = ""
    mcp_tool: str = ""
    allow_mcp_stream_init: bool = False
    resource: str = ""
    permission: str = ""


def match_service_pattern(pattern: str, service_type: str, service_name: str) -> bool:
    if not service_type or not service_name:
        return False
    if pattern == "*":
        return True
    pat_type, sep, pat_target = pattern.partition("://")
    if not sep or pat_type != service_type:
        return False
    if pat_target == "*":
        return True
    if pat_target.startswith("*."):
        return service_name.endswith(pat_target[1:])
    if pat_target.endswith(".*"):
        return service_name.startswith(pat_target[:-1])
    return service_name == pat_target


def match_http_path(pattern: str, req_path: str) -> bool:
    if not req_path:
        return False
    if pattern.endswith("*"):
        return req_path.startswith(pattern[:-1])
    return req_path == pattern


def match_task_rule(rule: sam_pb2.TaskRule, req: TaskRequestContext) -> bool:
    if rule.allowed_services:
        if not any(match_service_pattern(pat, req.service_type, req.service_name) for pat in rule.allowed_services):
            return False
    if rule.allowed_resources:
        if not req.resource or req.resource not in rule.allowed_resources:
            return False
    if rule.HasField("operation"):
        op = rule.operation
        if op.allowed_tools:
            if req.service_type != "mcp":
                return False
            if not req.mcp_tool:
                if not req.allow_mcp_stream_init:
                    return False
            elif req.mcp_tool not in op.allowed_tools:
                return False
        if op.allowed_methods:
            if not req.has_http or not req.method or req.method == "CONNECT":
                return False
            if req.method not in op.allowed_methods:
                return False
        if op.allowed_paths:
            if not req.has_http or not req.path or req.method == "CONNECT":
                return False
            if not any(match_http_path(pat, req.path) for pat in op.allowed_paths):
                return False
        if op.allowed_permissions:
            if not req.permission or req.permission not in op.allowed_permissions:
                return False
    return True


def evaluate_task_rules(
    chain: Sequence[sam_pb2.TaskAuthorizationRule],
    req: TaskRequestContext,
    now: datetime,
) -> None:
    for i, tar in enumerate(chain):
        exp = _tar_expire_datetime(tar)
        if exp is not None and now > exp:
            raise ValueError(f"TaskAuthorizationRule block {i + 1} ({tar.name!r}) is expired")
        if len(tar.rules) == 0:
            raise ValueError(f"TaskAuthorizationRule block {i + 1} ({tar.name!r}) has no rules (fail-closed)")
        if not any(match_task_rule(r, req) for r in tar.rules):
            raise ValueError(f"request denied by TaskAuthorizationRule block {i + 1} ({tar.name!r})")
