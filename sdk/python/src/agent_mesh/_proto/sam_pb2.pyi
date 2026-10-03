from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
ENROLLMENT_STATUS_APPROVED: EnrollmentStatus
ENROLLMENT_STATUS_PENDING: EnrollmentStatus
ENROLLMENT_STATUS_REJECTED: EnrollmentStatus
ENROLLMENT_STATUS_UNSPECIFIED: EnrollmentStatus
SERVICE_TYPE_A2A: ServiceType
SERVICE_TYPE_EGRESS: ServiceType
SERVICE_TYPE_INFERENCE: ServiceType
SERVICE_TYPE_MCP: ServiceType
SERVICE_TYPE_UNSPECIFIED: ServiceType

class AuthFrame(_message.Message):
    __slots__ = ["biscuit", "target_service"]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    TARGET_SERVICE_FIELD_NUMBER: _ClassVar[int]
    biscuit: bytes
    target_service: str
    def __init__(self, biscuit: _Optional[bytes] = ..., target_service: _Optional[str] = ...) -> None: ...

class AuthResponse(_message.Message):
    __slots__ = ["biscuit", "error", "success"]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    biscuit: bytes
    error: str
    success: bool
    def __init__(self, success: bool = ..., error: _Optional[str] = ..., biscuit: _Optional[bytes] = ...) -> None: ...

class BootstrapEnrollRequest(_message.Message):
    __slots__ = ["bootstrap_token", "challenge_signature", "challenge_unix_ms", "labels", "peer_id", "public_key", "requested_role"]
    class LabelsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    BOOTSTRAP_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_ROLE_FIELD_NUMBER: _ClassVar[int]
    bootstrap_token: str
    challenge_signature: bytes
    challenge_unix_ms: int
    labels: _containers.ScalarMap[str, str]
    peer_id: str
    public_key: bytes
    requested_role: str
    def __init__(self, bootstrap_token: _Optional[str] = ..., peer_id: _Optional[str] = ..., public_key: _Optional[bytes] = ..., requested_role: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., challenge_unix_ms: _Optional[int] = ..., challenge_signature: _Optional[bytes] = ...) -> None: ...

class BootstrapEnrollResponse(_message.Message):
    __slots__ = ["biscuit_token", "control_plane_public_key", "error_message", "expire_time", "poll_interval_seconds", "router_addresses", "status"]
    BISCUIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CONTROL_PLANE_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    POLL_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ROUTER_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    biscuit_token: bytes
    control_plane_public_key: bytes
    error_message: str
    expire_time: _timestamp_pb2.Timestamp
    poll_interval_seconds: int
    router_addresses: _containers.RepeatedScalarFieldContainer[str]
    status: EnrollmentStatus
    def __init__(self, status: _Optional[_Union[EnrollmentStatus, str]] = ..., biscuit_token: _Optional[bytes] = ..., poll_interval_seconds: _Optional[int] = ..., error_message: _Optional[str] = ..., control_plane_public_key: _Optional[bytes] = ..., router_addresses: _Optional[_Iterable[str]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CommandBackend(_message.Message):
    __slots__ = ["command", "env"]
    class EnvEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    command: _containers.RepeatedScalarFieldContainer[str]
    env: _containers.ScalarMap[str, str]
    def __init__(self, command: _Optional[_Iterable[str]] = ..., env: _Optional[_Mapping[str, str]] = ...) -> None: ...

class ControlPlaneInfoResponse(_message.Message):
    __slots__ = ["audience", "banned_peer_ids", "client_id", "oidc_issuer", "router_addresses"]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    BANNED_PEER_IDS_FIELD_NUMBER: _ClassVar[int]
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    OIDC_ISSUER_FIELD_NUMBER: _ClassVar[int]
    ROUTER_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    audience: str
    banned_peer_ids: _containers.RepeatedScalarFieldContainer[str]
    client_id: str
    oidc_issuer: str
    router_addresses: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, oidc_issuer: _Optional[str] = ..., client_id: _Optional[str] = ..., audience: _Optional[str] = ..., router_addresses: _Optional[_Iterable[str]] = ..., banned_peer_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class DiscoveredProvider(_message.Message):
    __slots__ = ["local_proxy_url", "peer_id", "srv_description", "srv_name"]
    LOCAL_PROXY_URL_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    SRV_DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SRV_NAME_FIELD_NUMBER: _ClassVar[int]
    local_proxy_url: str
    peer_id: str
    srv_description: str
    srv_name: str
    def __init__(self, peer_id: _Optional[str] = ..., local_proxy_url: _Optional[str] = ..., srv_name: _Optional[str] = ..., srv_description: _Optional[str] = ...) -> None: ...

class EgressAssignmentsRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class EgressAssignmentsResponse(_message.Message):
    __slots__ = ["egress"]
    EGRESS_FIELD_NUMBER: _ClassVar[int]
    egress: _containers.RepeatedCompositeFieldContainer[EgressDestination]
    def __init__(self, egress: _Optional[_Iterable[_Union[EgressDestination, _Mapping]]] = ...) -> None: ...

class EgressDestination(_message.Message):
    __slots__ = ["credential", "name", "served_by", "target_url"]
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SERVED_BY_FIELD_NUMBER: _ClassVar[int]
    TARGET_URL_FIELD_NUMBER: _ClassVar[int]
    credential: str
    name: str
    served_by: _containers.RepeatedScalarFieldContainer[str]
    target_url: str
    def __init__(self, name: _Optional[str] = ..., target_url: _Optional[str] = ..., credential: _Optional[str] = ..., served_by: _Optional[_Iterable[str]] = ...) -> None: ...

class EnrollRequest(_message.Message):
    __slots__ = ["challenge_signature", "challenge_unix_ms", "jwt", "labels", "peer_id", "public_key", "requested_role"]
    class LabelsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    JWT_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_ROLE_FIELD_NUMBER: _ClassVar[int]
    challenge_signature: bytes
    challenge_unix_ms: int
    jwt: str
    labels: _containers.ScalarMap[str, str]
    peer_id: str
    public_key: bytes
    requested_role: str
    def __init__(self, jwt: _Optional[str] = ..., peer_id: _Optional[str] = ..., public_key: _Optional[bytes] = ..., requested_role: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., challenge_unix_ms: _Optional[int] = ..., challenge_signature: _Optional[bytes] = ...) -> None: ...

class EnrollResponse(_message.Message):
    __slots__ = ["biscuit_token", "control_plane_public_key", "error_message", "expire_time", "router_addresses"]
    BISCUIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CONTROL_PLANE_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    ROUTER_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    biscuit_token: bytes
    control_plane_public_key: bytes
    error_message: str
    expire_time: _timestamp_pb2.Timestamp
    router_addresses: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, biscuit_token: _Optional[bytes] = ..., error_message: _Optional[str] = ..., control_plane_public_key: _Optional[bytes] = ..., router_addresses: _Optional[_Iterable[str]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class HTTPGrant(_message.Message):
    __slots__ = ["methods", "paths", "service"]
    METHODS_FIELD_NUMBER: _ClassVar[int]
    PATHS_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    methods: _containers.RepeatedScalarFieldContainer[str]
    paths: _containers.RepeatedScalarFieldContainer[str]
    service: str
    def __init__(self, service: _Optional[str] = ..., methods: _Optional[_Iterable[str]] = ..., paths: _Optional[_Iterable[str]] = ...) -> None: ...

class IdentityEvidenceResponse(_message.Message):
    __slots__ = ["biscuit", "biscuit_expire_time", "check_time", "control_plane_url", "peer_id", "trusted_control_plane_keys"]
    BISCUIT_EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    CHECK_TIME_FIELD_NUMBER: _ClassVar[int]
    CONTROL_PLANE_URL_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    TRUSTED_CONTROL_PLANE_KEYS_FIELD_NUMBER: _ClassVar[int]
    biscuit: bytes
    biscuit_expire_time: _timestamp_pb2.Timestamp
    check_time: _timestamp_pb2.Timestamp
    control_plane_url: str
    peer_id: str
    trusted_control_plane_keys: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, peer_id: _Optional[str] = ..., biscuit: _Optional[bytes] = ..., biscuit_expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., control_plane_url: _Optional[str] = ..., trusted_control_plane_keys: _Optional[_Iterable[bytes]] = ..., check_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class KeysResponse(_message.Message):
    __slots__ = ["public_keys", "sign_time", "signatures"]
    PUBLIC_KEYS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURES_FIELD_NUMBER: _ClassVar[int]
    SIGN_TIME_FIELD_NUMBER: _ClassVar[int]
    public_keys: _containers.RepeatedScalarFieldContainer[bytes]
    sign_time: _timestamp_pb2.Timestamp
    signatures: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, public_keys: _Optional[_Iterable[bytes]] = ..., sign_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., signatures: _Optional[_Iterable[bytes]] = ...) -> None: ...

class MemberCredential(_message.Message):
    __slots__ = ["biscuit", "control_plane_url", "expire_time", "issued_under_keys", "oidc_session", "router_addresses", "trusted_keys"]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    CONTROL_PLANE_URL_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    ISSUED_UNDER_KEYS_FIELD_NUMBER: _ClassVar[int]
    OIDC_SESSION_FIELD_NUMBER: _ClassVar[int]
    ROUTER_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    TRUSTED_KEYS_FIELD_NUMBER: _ClassVar[int]
    biscuit: bytes
    control_plane_url: str
    expire_time: _timestamp_pb2.Timestamp
    issued_under_keys: _containers.RepeatedScalarFieldContainer[bytes]
    oidc_session: OIDCSession
    router_addresses: _containers.RepeatedScalarFieldContainer[str]
    trusted_keys: _containers.RepeatedCompositeFieldContainer[TrustedSigningKey]
    def __init__(self, control_plane_url: _Optional[str] = ..., biscuit: _Optional[bytes] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., trusted_keys: _Optional[_Iterable[_Union[TrustedSigningKey, _Mapping]]] = ..., issued_under_keys: _Optional[_Iterable[bytes]] = ..., router_addresses: _Optional[_Iterable[str]] = ..., oidc_session: _Optional[_Union[OIDCSession, _Mapping]] = ...) -> None: ...

class MeshEvent(_message.Message):
    __slots__ = ["event_time", "new_public_key", "peer_id", "signature", "type"]
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    BANNED: MeshEvent.Type
    EVENT_TIME_FIELD_NUMBER: _ClassVar[int]
    KEY_ROTATION: MeshEvent.Type
    NEW_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_UPDATE: MeshEvent.Type
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    event_time: _timestamp_pb2.Timestamp
    new_public_key: bytes
    peer_id: str
    signature: bytes
    type: MeshEvent.Type
    def __init__(self, type: _Optional[_Union[MeshEvent.Type, str]] = ..., peer_id: _Optional[str] = ..., event_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., new_public_key: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class NodeCatalogReport(_message.Message):
    __slots__ = ["services"]
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    services: _containers.RepeatedCompositeFieldContainer[ServiceInfo]
    def __init__(self, services: _Optional[_Iterable[_Union[ServiceInfo, _Mapping]]] = ...) -> None: ...

class OIDCSession(_message.Message):
    __slots__ = ["audience", "client_id", "issuer", "refresh_token"]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    REFRESH_TOKEN_FIELD_NUMBER: _ClassVar[int]
    audience: str
    client_id: str
    issuer: str
    refresh_token: str
    def __init__(self, issuer: _Optional[str] = ..., client_id: _Optional[str] = ..., audience: _Optional[str] = ..., refresh_token: _Optional[str] = ...) -> None: ...

class PeerEvidenceResponse(_message.Message):
    __slots__ = ["biscuit", "check_time", "expire_time", "labels", "peer_id", "revocation_ids", "roles", "verifying_key"]
    class LabelsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    CHECK_TIME_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_IDS_FIELD_NUMBER: _ClassVar[int]
    ROLES_FIELD_NUMBER: _ClassVar[int]
    VERIFYING_KEY_FIELD_NUMBER: _ClassVar[int]
    biscuit: bytes
    check_time: _timestamp_pb2.Timestamp
    expire_time: _timestamp_pb2.Timestamp
    labels: _containers.ScalarMap[str, str]
    peer_id: str
    revocation_ids: _containers.RepeatedScalarFieldContainer[str]
    roles: _containers.RepeatedScalarFieldContainer[str]
    verifying_key: bytes
    def __init__(self, peer_id: _Optional[str] = ..., biscuit: _Optional[bytes] = ..., verifying_key: _Optional[bytes] = ..., roles: _Optional[_Iterable[str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., revocation_ids: _Optional[_Iterable[str]] = ..., check_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class PolicyBinding(_message.Message):
    __slots__ = ["members", "role"]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    members: _containers.RepeatedScalarFieldContainer[str]
    role: str
    def __init__(self, role: _Optional[str] = ..., members: _Optional[_Iterable[str]] = ...) -> None: ...

class PolicyConfig(_message.Message):
    __slots__ = ["bindings", "egress", "roles"]
    BINDINGS_FIELD_NUMBER: _ClassVar[int]
    EGRESS_FIELD_NUMBER: _ClassVar[int]
    ROLES_FIELD_NUMBER: _ClassVar[int]
    bindings: _containers.RepeatedCompositeFieldContainer[PolicyBinding]
    egress: _containers.RepeatedCompositeFieldContainer[EgressDestination]
    roles: _containers.RepeatedCompositeFieldContainer[PolicyRole]
    def __init__(self, roles: _Optional[_Iterable[_Union[PolicyRole, _Mapping]]] = ..., bindings: _Optional[_Iterable[_Union[PolicyBinding, _Mapping]]] = ..., egress: _Optional[_Iterable[_Union[EgressDestination, _Mapping]]] = ...) -> None: ...

class PolicyConfigGetRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class PolicyConfigGetResponse(_message.Message):
    __slots__ = ["datalog_rules"]
    DATALOG_RULES_FIELD_NUMBER: _ClassVar[int]
    datalog_rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, datalog_rules: _Optional[_Iterable[str]] = ...) -> None: ...

class PolicyConfigUpdateResponse(_message.Message):
    __slots__ = ["error", "success"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    error: str
    success: bool
    def __init__(self, success: bool = ..., error: _Optional[str] = ...) -> None: ...

class PolicyRole(_message.Message):
    __slots__ = ["allowed_labels", "allowed_services", "allowed_targets", "custom_datalog", "http", "name"]
    ALLOWED_LABELS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_SERVICES_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_TARGETS_FIELD_NUMBER: _ClassVar[int]
    CUSTOM_DATALOG_FIELD_NUMBER: _ClassVar[int]
    HTTP_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    allowed_labels: _containers.RepeatedScalarFieldContainer[str]
    allowed_services: _containers.RepeatedScalarFieldContainer[str]
    allowed_targets: _containers.RepeatedScalarFieldContainer[str]
    custom_datalog: _containers.RepeatedScalarFieldContainer[str]
    http: _containers.RepeatedCompositeFieldContainer[HTTPGrant]
    name: str
    def __init__(self, name: _Optional[str] = ..., allowed_targets: _Optional[_Iterable[str]] = ..., allowed_services: _Optional[_Iterable[str]] = ..., custom_datalog: _Optional[_Iterable[str]] = ..., allowed_labels: _Optional[_Iterable[str]] = ..., http: _Optional[_Iterable[_Union[HTTPGrant, _Mapping]]] = ...) -> None: ...

class RegisterServiceRequest(_message.Message):
    __slots__ = ["command", "service", "target_url"]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    TARGET_URL_FIELD_NUMBER: _ClassVar[int]
    command: CommandBackend
    service: ServiceInfo
    target_url: str
    def __init__(self, service: _Optional[_Union[ServiceInfo, _Mapping]] = ..., target_url: _Optional[str] = ..., command: _Optional[_Union[CommandBackend, _Mapping]] = ...) -> None: ...

class RouterLeaseRequest(_message.Message):
    __slots__ = ["addresses", "biscuit", "challenge_signature", "challenge_unix_ms", "connected_peers", "dht_size", "peer_id"]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CONNECTED_PEERS_FIELD_NUMBER: _ClassVar[int]
    DHT_SIZE_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    addresses: _containers.RepeatedScalarFieldContainer[str]
    biscuit: bytes
    challenge_signature: bytes
    challenge_unix_ms: int
    connected_peers: _containers.RepeatedScalarFieldContainer[str]
    dht_size: int
    peer_id: str
    def __init__(self, peer_id: _Optional[str] = ..., addresses: _Optional[_Iterable[str]] = ..., biscuit: _Optional[bytes] = ..., connected_peers: _Optional[_Iterable[str]] = ..., dht_size: _Optional[int] = ..., challenge_unix_ms: _Optional[int] = ..., challenge_signature: _Optional[bytes] = ...) -> None: ...

class RouterLeaseResponse(_message.Message):
    __slots__ = ["error", "expire_time", "success"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    error: str
    expire_time: _timestamp_pb2.Timestamp
    success: bool
    def __init__(self, success: bool = ..., error: _Optional[str] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ServiceAnnounce(_message.Message):
    __slots__ = ["active_requests", "announce_time", "keys", "labels", "latency_ewma_ms", "peer_id", "service_name", "type"]
    class LabelsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ACTIVE_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    ANNOUNCE_TIME_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    LATENCY_EWMA_MS_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    SERVICE_NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    active_requests: int
    announce_time: _timestamp_pb2.Timestamp
    keys: _containers.RepeatedScalarFieldContainer[str]
    labels: _containers.ScalarMap[str, str]
    latency_ewma_ms: float
    peer_id: str
    service_name: str
    type: ServiceType
    def __init__(self, peer_id: _Optional[str] = ..., type: _Optional[_Union[ServiceType, str]] = ..., service_name: _Optional[str] = ..., keys: _Optional[_Iterable[str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., active_requests: _Optional[int] = ..., latency_ewma_ms: _Optional[float] = ..., announce_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ServiceInfo(_message.Message):
    __slots__ = ["description", "name", "type"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    description: str
    name: str
    type: ServiceType
    def __init__(self, type: _Optional[_Union[ServiceType, str]] = ..., name: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class TaskAuthorizationRule(_message.Message):
    __slots__ = ["display_name", "expire_time", "name", "rules"]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    display_name: str
    expire_time: _timestamp_pb2.Timestamp
    name: str
    rules: _containers.RepeatedCompositeFieldContainer[TaskRule]
    def __init__(self, name: _Optional[str] = ..., display_name: _Optional[str] = ..., rules: _Optional[_Iterable[_Union[TaskRule, _Mapping]]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class TaskOperation(_message.Message):
    __slots__ = ["allowed_methods", "allowed_paths", "allowed_permissions", "allowed_tools"]
    ALLOWED_METHODS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_PATHS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_TOOLS_FIELD_NUMBER: _ClassVar[int]
    allowed_methods: _containers.RepeatedScalarFieldContainer[str]
    allowed_paths: _containers.RepeatedScalarFieldContainer[str]
    allowed_permissions: _containers.RepeatedScalarFieldContainer[str]
    allowed_tools: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, allowed_tools: _Optional[_Iterable[str]] = ..., allowed_methods: _Optional[_Iterable[str]] = ..., allowed_paths: _Optional[_Iterable[str]] = ..., allowed_permissions: _Optional[_Iterable[str]] = ...) -> None: ...

class TaskRule(_message.Message):
    __slots__ = ["allowed_resources", "allowed_services", "description", "operation"]
    ALLOWED_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_SERVICES_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    allowed_resources: _containers.RepeatedScalarFieldContainer[str]
    allowed_services: _containers.RepeatedScalarFieldContainer[str]
    description: str
    operation: TaskOperation
    def __init__(self, description: _Optional[str] = ..., allowed_services: _Optional[_Iterable[str]] = ..., operation: _Optional[_Union[TaskOperation, _Mapping]] = ..., allowed_resources: _Optional[_Iterable[str]] = ...) -> None: ...

class TokenRefreshRequest(_message.Message):
    __slots__ = ["challenge_signature", "challenge_unix_ms", "peer_id"]
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    challenge_signature: bytes
    challenge_unix_ms: int
    peer_id: str
    def __init__(self, challenge_signature: _Optional[bytes] = ..., challenge_unix_ms: _Optional[int] = ..., peer_id: _Optional[str] = ...) -> None: ...

class TokenRefreshResponse(_message.Message):
    __slots__ = ["biscuit_token", "error_message", "expire_time"]
    BISCUIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    biscuit_token: bytes
    error_message: str
    expire_time: _timestamp_pb2.Timestamp
    def __init__(self, biscuit_token: _Optional[bytes] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., error_message: _Optional[str] = ...) -> None: ...

class TokenRevokeRequest(_message.Message):
    __slots__ = ["peer_id"]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    def __init__(self, peer_id: _Optional[str] = ...) -> None: ...

class TokenRevokeResponse(_message.Message):
    __slots__ = ["error", "success"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    error: str
    success: bool
    def __init__(self, success: bool = ..., error: _Optional[str] = ...) -> None: ...

class TrustedSigningKey(_message.Message):
    __slots__ = ["public_key", "receive_time"]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    RECEIVE_TIME_FIELD_NUMBER: _ClassVar[int]
    public_key: bytes
    receive_time: _timestamp_pb2.Timestamp
    def __init__(self, public_key: _Optional[bytes] = ..., receive_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EnrollmentStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class ServiceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
