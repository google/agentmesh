from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnrollmentStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENROLLMENT_STATUS_UNSPECIFIED: _ClassVar[EnrollmentStatus]
    ENROLLMENT_STATUS_PENDING: _ClassVar[EnrollmentStatus]
    ENROLLMENT_STATUS_APPROVED: _ClassVar[EnrollmentStatus]
    ENROLLMENT_STATUS_REJECTED: _ClassVar[EnrollmentStatus]

class ServiceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SERVICE_TYPE_UNSPECIFIED: _ClassVar[ServiceType]
    SERVICE_TYPE_MCP: _ClassVar[ServiceType]
    SERVICE_TYPE_INFERENCE: _ClassVar[ServiceType]
    SERVICE_TYPE_A2A: _ClassVar[ServiceType]
    SERVICE_TYPE_EGRESS: _ClassVar[ServiceType]

class IngressAuthMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INGRESS_AUTH_MODE_UNSPECIFIED: _ClassVar[IngressAuthMode]
    INGRESS_AUTH_MODE_EDGE: _ClassVar[IngressAuthMode]
    INGRESS_AUTH_MODE_PASSTHROUGH: _ClassVar[IngressAuthMode]

class EgressMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EGRESS_MODE_HTTP: _ClassVar[EgressMode]
    EGRESS_MODE_TCP: _ClassVar[EgressMode]

class ResponseInspection(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESPONSE_INSPECTION_BUFFERED: _ClassVar[ResponseInspection]
    RESPONSE_INSPECTION_REQUEST_ONLY: _ClassVar[ResponseInspection]

class SignalCallerDirection(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SIGNAL_CALLER_DIRECTION_UNSPECIFIED: _ClassVar[SignalCallerDirection]
    LOCAL_WORKLOAD: _ClassVar[SignalCallerDirection]
    REMOTE_PEER: _ClassVar[SignalCallerDirection]

class PolicyDenialReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POLICY_DENIAL_REASON_UNSPECIFIED: _ClassVar[PolicyDenialReason]
    DATALOG_EVALUATION_DENIED: _ClassVar[PolicyDenialReason]
    TASK_AUTHORIZATION_RULE_VIOLATION: _ClassVar[PolicyDenialReason]
    INSPECTION_FILTER_BLOCKED: _ClassVar[PolicyDenialReason]
    ROLE_MISMATCH: _ClassVar[PolicyDenialReason]
    EXPIRED_CREDENTIAL: _ClassVar[PolicyDenialReason]
    UNAUTHORIZED_SERVICE: _ClassVar[PolicyDenialReason]
    UNAUTHORIZED_PATH_OR_METHOD: _ClassVar[PolicyDenialReason]

class TransportRefusalReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TRANSPORT_REFUSAL_REASON_UNSPECIFIED: _ClassVar[TransportRefusalReason]
    PEER_UNAUTHENTICATED: _ClassVar[TransportRefusalReason]
    NOT_ROUTER_ROLE: _ClassVar[TransportRefusalReason]
    AUTH_DEADLINE_EXCEEDED: _ClassVar[TransportRefusalReason]
    PEER_BANNED: _ClassVar[TransportRefusalReason]
    PROTOCOL_UNAUTHORIZED: _ClassVar[TransportRefusalReason]

class RevocationSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    REVOCATION_SOURCE_UNSPECIFIED: _ClassVar[RevocationSource]
    CONTROL_PLANE_ADMIN: _ClassVar[RevocationSource]
    MESH_EVENT_BANNED_GOSSIP: _ClassVar[RevocationSource]
    LOCAL_CONTROL_PLANE_SYNC: _ClassVar[RevocationSource]
    TOKEN_REFRESH_REJECTION: _ClassVar[RevocationSource]

class EnrollmentRejectionReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENROLLMENT_REJECTION_REASON_UNSPECIFIED: _ClassVar[EnrollmentRejectionReason]
    INVALID_JWT: _ClassVar[EnrollmentRejectionReason]
    EXPIRED_BOOTSTRAP_TOKEN: _ClassVar[EnrollmentRejectionReason]
    BOOTSTRAP_TOKEN_USAGE_EXCEEDED: _ClassVar[EnrollmentRejectionReason]
    UNATTESTED_LABELS_REJECTED: _ClassVar[EnrollmentRejectionReason]
    INVALID_CHALLENGE_SIGNATURE: _ClassVar[EnrollmentRejectionReason]
    REQUESTED_ROLE_UNAUTHORIZED: _ClassVar[EnrollmentRejectionReason]
    PEER_PREVIOUSLY_BANNED: _ClassVar[EnrollmentRejectionReason]
    AUTONOMOUS_RECOVERY_DISABLED: _ClassVar[EnrollmentRejectionReason]
ENROLLMENT_STATUS_UNSPECIFIED: EnrollmentStatus
ENROLLMENT_STATUS_PENDING: EnrollmentStatus
ENROLLMENT_STATUS_APPROVED: EnrollmentStatus
ENROLLMENT_STATUS_REJECTED: EnrollmentStatus
SERVICE_TYPE_UNSPECIFIED: ServiceType
SERVICE_TYPE_MCP: ServiceType
SERVICE_TYPE_INFERENCE: ServiceType
SERVICE_TYPE_A2A: ServiceType
SERVICE_TYPE_EGRESS: ServiceType
INGRESS_AUTH_MODE_UNSPECIFIED: IngressAuthMode
INGRESS_AUTH_MODE_EDGE: IngressAuthMode
INGRESS_AUTH_MODE_PASSTHROUGH: IngressAuthMode
EGRESS_MODE_HTTP: EgressMode
EGRESS_MODE_TCP: EgressMode
RESPONSE_INSPECTION_BUFFERED: ResponseInspection
RESPONSE_INSPECTION_REQUEST_ONLY: ResponseInspection
SIGNAL_CALLER_DIRECTION_UNSPECIFIED: SignalCallerDirection
LOCAL_WORKLOAD: SignalCallerDirection
REMOTE_PEER: SignalCallerDirection
POLICY_DENIAL_REASON_UNSPECIFIED: PolicyDenialReason
DATALOG_EVALUATION_DENIED: PolicyDenialReason
TASK_AUTHORIZATION_RULE_VIOLATION: PolicyDenialReason
INSPECTION_FILTER_BLOCKED: PolicyDenialReason
ROLE_MISMATCH: PolicyDenialReason
EXPIRED_CREDENTIAL: PolicyDenialReason
UNAUTHORIZED_SERVICE: PolicyDenialReason
UNAUTHORIZED_PATH_OR_METHOD: PolicyDenialReason
TRANSPORT_REFUSAL_REASON_UNSPECIFIED: TransportRefusalReason
PEER_UNAUTHENTICATED: TransportRefusalReason
NOT_ROUTER_ROLE: TransportRefusalReason
AUTH_DEADLINE_EXCEEDED: TransportRefusalReason
PEER_BANNED: TransportRefusalReason
PROTOCOL_UNAUTHORIZED: TransportRefusalReason
REVOCATION_SOURCE_UNSPECIFIED: RevocationSource
CONTROL_PLANE_ADMIN: RevocationSource
MESH_EVENT_BANNED_GOSSIP: RevocationSource
LOCAL_CONTROL_PLANE_SYNC: RevocationSource
TOKEN_REFRESH_REJECTION: RevocationSource
ENROLLMENT_REJECTION_REASON_UNSPECIFIED: EnrollmentRejectionReason
INVALID_JWT: EnrollmentRejectionReason
EXPIRED_BOOTSTRAP_TOKEN: EnrollmentRejectionReason
BOOTSTRAP_TOKEN_USAGE_EXCEEDED: EnrollmentRejectionReason
UNATTESTED_LABELS_REJECTED: EnrollmentRejectionReason
INVALID_CHALLENGE_SIGNATURE: EnrollmentRejectionReason
REQUESTED_ROLE_UNAUTHORIZED: EnrollmentRejectionReason
PEER_PREVIOUSLY_BANNED: EnrollmentRejectionReason
AUTONOMOUS_RECOVERY_DISABLED: EnrollmentRejectionReason

class AuthFrame(_message.Message):
    __slots__ = ("biscuit", "target_service")
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    TARGET_SERVICE_FIELD_NUMBER: _ClassVar[int]
    biscuit: bytes
    target_service: str
    def __init__(self, biscuit: _Optional[bytes] = ..., target_service: _Optional[str] = ...) -> None: ...

class AuthResponse(_message.Message):
    __slots__ = ("success", "error", "biscuit")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    success: bool
    error: str
    biscuit: bytes
    def __init__(self, success: bool = ..., error: _Optional[str] = ..., biscuit: _Optional[bytes] = ...) -> None: ...

class RouterGoAway(_message.Message):
    __slots__ = ("reason", "retry_after")
    class Reason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        REASON_UNSPECIFIED: _ClassVar[RouterGoAway.Reason]
        DRAINING: _ClassVar[RouterGoAway.Reason]
        OVERLOADED: _ClassVar[RouterGoAway.Reason]
    REASON_UNSPECIFIED: RouterGoAway.Reason
    DRAINING: RouterGoAway.Reason
    OVERLOADED: RouterGoAway.Reason
    REASON_FIELD_NUMBER: _ClassVar[int]
    RETRY_AFTER_FIELD_NUMBER: _ClassVar[int]
    reason: RouterGoAway.Reason
    retry_after: _duration_pb2.Duration
    def __init__(self, reason: _Optional[_Union[RouterGoAway.Reason, str]] = ..., retry_after: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class MeshEvent(_message.Message):
    __slots__ = ("type", "peer_id", "event_time", "new_public_key", "signature")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        BANNED: _ClassVar[MeshEvent.Type]
        KEY_ROTATION: _ClassVar[MeshEvent.Type]
        POLICY_UPDATE: _ClassVar[MeshEvent.Type]
    BANNED: MeshEvent.Type
    KEY_ROTATION: MeshEvent.Type
    POLICY_UPDATE: MeshEvent.Type
    TYPE_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    EVENT_TIME_FIELD_NUMBER: _ClassVar[int]
    NEW_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    type: MeshEvent.Type
    peer_id: str
    event_time: _timestamp_pb2.Timestamp
    new_public_key: bytes
    signature: bytes
    def __init__(self, type: _Optional[_Union[MeshEvent.Type, str]] = ..., peer_id: _Optional[str] = ..., event_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., new_public_key: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class EnrollRequest(_message.Message):
    __slots__ = ("jwt", "peer_id", "public_key", "requested_role", "labels", "challenge_unix_ms", "challenge_signature")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    JWT_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_ROLE_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    jwt: str
    peer_id: str
    public_key: bytes
    requested_role: str
    labels: _containers.ScalarMap[str, str]
    challenge_unix_ms: int
    challenge_signature: bytes
    def __init__(self, jwt: _Optional[str] = ..., peer_id: _Optional[str] = ..., public_key: _Optional[bytes] = ..., requested_role: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., challenge_unix_ms: _Optional[int] = ..., challenge_signature: _Optional[bytes] = ...) -> None: ...

class EnrollResponse(_message.Message):
    __slots__ = ("biscuit_token", "error_message", "control_plane_public_key", "router_addresses", "expire_time")
    BISCUIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    CONTROL_PLANE_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    ROUTER_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    biscuit_token: bytes
    error_message: str
    control_plane_public_key: bytes
    router_addresses: _containers.RepeatedScalarFieldContainer[str]
    expire_time: _timestamp_pb2.Timestamp
    def __init__(self, biscuit_token: _Optional[bytes] = ..., error_message: _Optional[str] = ..., control_plane_public_key: _Optional[bytes] = ..., router_addresses: _Optional[_Iterable[str]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class BootstrapEnrollRequest(_message.Message):
    __slots__ = ("bootstrap_token", "peer_id", "public_key", "requested_role", "labels", "challenge_unix_ms", "challenge_signature")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    BOOTSTRAP_TOKEN_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_ROLE_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    bootstrap_token: str
    peer_id: str
    public_key: bytes
    requested_role: str
    labels: _containers.ScalarMap[str, str]
    challenge_unix_ms: int
    challenge_signature: bytes
    def __init__(self, bootstrap_token: _Optional[str] = ..., peer_id: _Optional[str] = ..., public_key: _Optional[bytes] = ..., requested_role: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., challenge_unix_ms: _Optional[int] = ..., challenge_signature: _Optional[bytes] = ...) -> None: ...

class BootstrapEnrollResponse(_message.Message):
    __slots__ = ("status", "biscuit_token", "poll_interval_seconds", "error_message", "control_plane_public_key", "router_addresses", "expire_time")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    POLL_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    CONTROL_PLANE_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    ROUTER_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    status: EnrollmentStatus
    biscuit_token: bytes
    poll_interval_seconds: int
    error_message: str
    control_plane_public_key: bytes
    router_addresses: _containers.RepeatedScalarFieldContainer[str]
    expire_time: _timestamp_pb2.Timestamp
    def __init__(self, status: _Optional[_Union[EnrollmentStatus, str]] = ..., biscuit_token: _Optional[bytes] = ..., poll_interval_seconds: _Optional[int] = ..., error_message: _Optional[str] = ..., control_plane_public_key: _Optional[bytes] = ..., router_addresses: _Optional[_Iterable[str]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ServiceIngress(_message.Message):
    __slots__ = ("auth_mode", "allow")
    AUTH_MODE_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    auth_mode: IngressAuthMode
    allow: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, auth_mode: _Optional[_Union[IngressAuthMode, str]] = ..., allow: _Optional[_Iterable[str]] = ...) -> None: ...

class ServiceInfo(_message.Message):
    __slots__ = ("type", "name", "description", "ingress")
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    INGRESS_FIELD_NUMBER: _ClassVar[int]
    type: ServiceType
    name: str
    description: str
    ingress: ServiceIngress
    def __init__(self, type: _Optional[_Union[ServiceType, str]] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., ingress: _Optional[_Union[ServiceIngress, _Mapping]] = ...) -> None: ...

class CommandBackend(_message.Message):
    __slots__ = ("command", "env")
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
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

class RegisterServiceRequest(_message.Message):
    __slots__ = ("service", "target_url", "command")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    TARGET_URL_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    service: ServiceInfo
    target_url: str
    command: CommandBackend
    def __init__(self, service: _Optional[_Union[ServiceInfo, _Mapping]] = ..., target_url: _Optional[str] = ..., command: _Optional[_Union[CommandBackend, _Mapping]] = ...) -> None: ...

class DiscoveredProvider(_message.Message):
    __slots__ = ("peer_id", "local_proxy_url", "srv_name", "srv_description")
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    LOCAL_PROXY_URL_FIELD_NUMBER: _ClassVar[int]
    SRV_NAME_FIELD_NUMBER: _ClassVar[int]
    SRV_DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    local_proxy_url: str
    srv_name: str
    srv_description: str
    def __init__(self, peer_id: _Optional[str] = ..., local_proxy_url: _Optional[str] = ..., srv_name: _Optional[str] = ..., srv_description: _Optional[str] = ...) -> None: ...

class ControlPlaneInfoResponse(_message.Message):
    __slots__ = ("oidc_issuer", "client_id", "audience", "router_addresses", "banned_peer_ids", "routers", "directory")
    OIDC_ISSUER_FIELD_NUMBER: _ClassVar[int]
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    ROUTER_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    BANNED_PEER_IDS_FIELD_NUMBER: _ClassVar[int]
    ROUTERS_FIELD_NUMBER: _ClassVar[int]
    DIRECTORY_FIELD_NUMBER: _ClassVar[int]
    oidc_issuer: str
    client_id: str
    audience: str
    router_addresses: _containers.RepeatedScalarFieldContainer[str]
    banned_peer_ids: _containers.RepeatedScalarFieldContainer[str]
    routers: _containers.RepeatedCompositeFieldContainer[RouterInfo]
    directory: DirectoryParameters
    def __init__(self, oidc_issuer: _Optional[str] = ..., client_id: _Optional[str] = ..., audience: _Optional[str] = ..., router_addresses: _Optional[_Iterable[str]] = ..., banned_peer_ids: _Optional[_Iterable[str]] = ..., routers: _Optional[_Iterable[_Union[RouterInfo, _Mapping]]] = ..., directory: _Optional[_Union[DirectoryParameters, _Mapping]] = ...) -> None: ...

class DirectoryParameters(_message.Message):
    __slots__ = ("replication", "reprovide_interval", "record_ttl")
    REPLICATION_FIELD_NUMBER: _ClassVar[int]
    REPROVIDE_INTERVAL_FIELD_NUMBER: _ClassVar[int]
    RECORD_TTL_FIELD_NUMBER: _ClassVar[int]
    replication: int
    reprovide_interval: _duration_pb2.Duration
    record_ttl: _duration_pb2.Duration
    def __init__(self, replication: _Optional[int] = ..., reprovide_interval: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ..., record_ttl: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class DirectoryRequest(_message.Message):
    __slots__ = ("provide", "find_providers", "find_peer", "withdraw")
    PROVIDE_FIELD_NUMBER: _ClassVar[int]
    FIND_PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    FIND_PEER_FIELD_NUMBER: _ClassVar[int]
    WITHDRAW_FIELD_NUMBER: _ClassVar[int]
    provide: DirectoryProvide
    find_providers: DirectoryFindProviders
    find_peer: DirectoryFindPeer
    withdraw: DirectoryWithdraw
    def __init__(self, provide: _Optional[_Union[DirectoryProvide, _Mapping]] = ..., find_providers: _Optional[_Union[DirectoryFindProviders, _Mapping]] = ..., find_peer: _Optional[_Union[DirectoryFindPeer, _Mapping]] = ..., withdraw: _Optional[_Union[DirectoryWithdraw, _Mapping]] = ...) -> None: ...

class DirectoryProvide(_message.Message):
    __slots__ = ("key", "addrs", "provider", "service", "ingress")
    KEY_FIELD_NUMBER: _ClassVar[int]
    ADDRS_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    INGRESS_FIELD_NUMBER: _ClassVar[int]
    key: bytes
    addrs: _containers.RepeatedScalarFieldContainer[str]
    provider: str
    service: str
    ingress: ServiceIngress
    def __init__(self, key: _Optional[bytes] = ..., addrs: _Optional[_Iterable[str]] = ..., provider: _Optional[str] = ..., service: _Optional[str] = ..., ingress: _Optional[_Union[ServiceIngress, _Mapping]] = ...) -> None: ...

class DirectoryWithdraw(_message.Message):
    __slots__ = ("key", "provider")
    KEY_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    key: bytes
    provider: str
    def __init__(self, key: _Optional[bytes] = ..., provider: _Optional[str] = ...) -> None: ...

class DirectoryFindProviders(_message.Message):
    __slots__ = ("key", "limit")
    KEY_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    key: bytes
    limit: int
    def __init__(self, key: _Optional[bytes] = ..., limit: _Optional[int] = ...) -> None: ...

class DirectoryFindPeer(_message.Message):
    __slots__ = ("peer_id",)
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    def __init__(self, peer_id: _Optional[str] = ...) -> None: ...

class DirectoryResponse(_message.Message):
    __slots__ = ("providers", "peer", "error")
    PROVIDERS_FIELD_NUMBER: _ClassVar[int]
    PEER_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    providers: _containers.RepeatedCompositeFieldContainer[PeerRecord]
    peer: PeerRecord
    error: str
    def __init__(self, providers: _Optional[_Iterable[_Union[PeerRecord, _Mapping]]] = ..., peer: _Optional[_Union[PeerRecord, _Mapping]] = ..., error: _Optional[str] = ...) -> None: ...

class PeerRecord(_message.Message):
    __slots__ = ("peer_id", "addrs", "ingress")
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRS_FIELD_NUMBER: _ClassVar[int]
    INGRESS_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    addrs: _containers.RepeatedScalarFieldContainer[str]
    ingress: ServiceIngress
    def __init__(self, peer_id: _Optional[str] = ..., addrs: _Optional[_Iterable[str]] = ..., ingress: _Optional[_Union[ServiceIngress, _Mapping]] = ...) -> None: ...

class RouterInfo(_message.Message):
    __slots__ = ("peer_id", "addresses", "labels", "connections", "connection_limit", "ingress_url")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_LIMIT_FIELD_NUMBER: _ClassVar[int]
    INGRESS_URL_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    addresses: _containers.RepeatedScalarFieldContainer[str]
    labels: _containers.ScalarMap[str, str]
    connections: int
    connection_limit: int
    ingress_url: str
    def __init__(self, peer_id: _Optional[str] = ..., addresses: _Optional[_Iterable[str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., connections: _Optional[int] = ..., connection_limit: _Optional[int] = ..., ingress_url: _Optional[str] = ...) -> None: ...

class RouterLeaseRequest(_message.Message):
    __slots__ = ("peer_id", "addresses", "biscuit", "connected_peers", "dht_size", "challenge_unix_ms", "challenge_signature", "ttl", "connections", "connection_limit", "ingress_url")
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    CONNECTED_PEERS_FIELD_NUMBER: _ClassVar[int]
    DHT_SIZE_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    TTL_FIELD_NUMBER: _ClassVar[int]
    CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_LIMIT_FIELD_NUMBER: _ClassVar[int]
    INGRESS_URL_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    addresses: _containers.RepeatedScalarFieldContainer[str]
    biscuit: bytes
    connected_peers: _containers.RepeatedScalarFieldContainer[str]
    dht_size: int
    challenge_unix_ms: int
    challenge_signature: bytes
    ttl: _duration_pb2.Duration
    connections: int
    connection_limit: int
    ingress_url: str
    def __init__(self, peer_id: _Optional[str] = ..., addresses: _Optional[_Iterable[str]] = ..., biscuit: _Optional[bytes] = ..., connected_peers: _Optional[_Iterable[str]] = ..., dht_size: _Optional[int] = ..., challenge_unix_ms: _Optional[int] = ..., challenge_signature: _Optional[bytes] = ..., ttl: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ..., connections: _Optional[int] = ..., connection_limit: _Optional[int] = ..., ingress_url: _Optional[str] = ...) -> None: ...

class RouterLeaseResponse(_message.Message):
    __slots__ = ("success", "error", "expire_time")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    success: bool
    error: str
    expire_time: _timestamp_pb2.Timestamp
    def __init__(self, success: bool = ..., error: _Optional[str] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class PolicyRole(_message.Message):
    __slots__ = ("name", "allowed_targets", "allowed_services", "custom_datalog", "allowed_labels", "http", "allowed_publish", "allowed_ingress")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_TARGETS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_SERVICES_FIELD_NUMBER: _ClassVar[int]
    CUSTOM_DATALOG_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_LABELS_FIELD_NUMBER: _ClassVar[int]
    HTTP_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_PUBLISH_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_INGRESS_FIELD_NUMBER: _ClassVar[int]
    name: str
    allowed_targets: _containers.RepeatedScalarFieldContainer[str]
    allowed_services: _containers.RepeatedScalarFieldContainer[str]
    custom_datalog: _containers.RepeatedScalarFieldContainer[str]
    allowed_labels: _containers.RepeatedScalarFieldContainer[str]
    http: _containers.RepeatedCompositeFieldContainer[HTTPGrant]
    allowed_publish: _containers.RepeatedScalarFieldContainer[str]
    allowed_ingress: _containers.RepeatedCompositeFieldContainer[IngressGrant]
    def __init__(self, name: _Optional[str] = ..., allowed_targets: _Optional[_Iterable[str]] = ..., allowed_services: _Optional[_Iterable[str]] = ..., custom_datalog: _Optional[_Iterable[str]] = ..., allowed_labels: _Optional[_Iterable[str]] = ..., http: _Optional[_Iterable[_Union[HTTPGrant, _Mapping]]] = ..., allowed_publish: _Optional[_Iterable[str]] = ..., allowed_ingress: _Optional[_Iterable[_Union[IngressGrant, _Mapping]]] = ...) -> None: ...

class IngressGrant(_message.Message):
    __slots__ = ("services", "allowed_auth_modes")
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_AUTH_MODES_FIELD_NUMBER: _ClassVar[int]
    services: _containers.RepeatedScalarFieldContainer[str]
    allowed_auth_modes: _containers.RepeatedScalarFieldContainer[IngressAuthMode]
    def __init__(self, services: _Optional[_Iterable[str]] = ..., allowed_auth_modes: _Optional[_Iterable[_Union[IngressAuthMode, str]]] = ...) -> None: ...

class HTTPGrant(_message.Message):
    __slots__ = ("service", "methods", "paths")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    METHODS_FIELD_NUMBER: _ClassVar[int]
    PATHS_FIELD_NUMBER: _ClassVar[int]
    service: str
    methods: _containers.RepeatedScalarFieldContainer[str]
    paths: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, service: _Optional[str] = ..., methods: _Optional[_Iterable[str]] = ..., paths: _Optional[_Iterable[str]] = ...) -> None: ...

class EgressDestination(_message.Message):
    __slots__ = ("name", "target_url", "credential", "served_by", "broker", "inspection", "mode", "ports", "preserve_host", "forward_context")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TARGET_URL_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    SERVED_BY_FIELD_NUMBER: _ClassVar[int]
    BROKER_FIELD_NUMBER: _ClassVar[int]
    INSPECTION_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    PORTS_FIELD_NUMBER: _ClassVar[int]
    PRESERVE_HOST_FIELD_NUMBER: _ClassVar[int]
    FORWARD_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    name: str
    target_url: str
    credential: str
    served_by: _containers.RepeatedScalarFieldContainer[str]
    broker: CredentialBroker
    inspection: Inspection
    mode: EgressMode
    ports: _containers.RepeatedScalarFieldContainer[int]
    preserve_host: bool
    forward_context: bool
    def __init__(self, name: _Optional[str] = ..., target_url: _Optional[str] = ..., credential: _Optional[str] = ..., served_by: _Optional[_Iterable[str]] = ..., broker: _Optional[_Union[CredentialBroker, _Mapping]] = ..., inspection: _Optional[_Union[Inspection, _Mapping]] = ..., mode: _Optional[_Union[EgressMode, str]] = ..., ports: _Optional[_Iterable[int]] = ..., preserve_host: bool = ..., forward_context: bool = ...) -> None: ...

class Inspection(_message.Message):
    __slots__ = ("inspectors",)
    INSPECTORS_FIELD_NUMBER: _ClassVar[int]
    inspectors: _containers.RepeatedCompositeFieldContainer[Inspector]
    def __init__(self, inspectors: _Optional[_Iterable[_Union[Inspector, _Mapping]]] = ...) -> None: ...

class Inspector(_message.Message):
    __slots__ = ("model_armor", "ext_proc")
    MODEL_ARMOR_FIELD_NUMBER: _ClassVar[int]
    EXT_PROC_FIELD_NUMBER: _ClassVar[int]
    model_armor: ModelArmor
    ext_proc: ExtProc
    def __init__(self, model_armor: _Optional[_Union[ModelArmor, _Mapping]] = ..., ext_proc: _Optional[_Union[ExtProc, _Mapping]] = ...) -> None: ...

class ModelArmor(_message.Message):
    __slots__ = ("template", "response", "fail_open", "timeout")
    TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    FAIL_OPEN_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    template: str
    response: ResponseInspection
    fail_open: bool
    timeout: _duration_pb2.Duration
    def __init__(self, template: _Optional[str] = ..., response: _Optional[_Union[ResponseInspection, str]] = ..., fail_open: bool = ..., timeout: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class ExtProc(_message.Message):
    __slots__ = ("target", "ca", "client_certificate", "processing_mode", "allow_mode_override", "message_timeout", "failure_mode_allow", "max_buffered_bytes")
    TARGET_FIELD_NUMBER: _ClassVar[int]
    CA_FIELD_NUMBER: _ClassVar[int]
    CLIENT_CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    PROCESSING_MODE_FIELD_NUMBER: _ClassVar[int]
    ALLOW_MODE_OVERRIDE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_MODE_ALLOW_FIELD_NUMBER: _ClassVar[int]
    MAX_BUFFERED_BYTES_FIELD_NUMBER: _ClassVar[int]
    target: str
    ca: str
    client_certificate: str
    processing_mode: ExtProcProcessingMode
    allow_mode_override: bool
    message_timeout: _duration_pb2.Duration
    failure_mode_allow: bool
    max_buffered_bytes: int
    def __init__(self, target: _Optional[str] = ..., ca: _Optional[str] = ..., client_certificate: _Optional[str] = ..., processing_mode: _Optional[_Union[ExtProcProcessingMode, _Mapping]] = ..., allow_mode_override: bool = ..., message_timeout: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ..., failure_mode_allow: bool = ..., max_buffered_bytes: _Optional[int] = ...) -> None: ...

class ExtProcProcessingMode(_message.Message):
    __slots__ = ("request_header_mode", "response_header_mode", "request_body_mode", "response_body_mode", "request_trailer_mode", "response_trailer_mode")
    class HeaderMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        HEADER_MODE_DEFAULT: _ClassVar[ExtProcProcessingMode.HeaderMode]
        SEND: _ClassVar[ExtProcProcessingMode.HeaderMode]
        SKIP: _ClassVar[ExtProcProcessingMode.HeaderMode]
    HEADER_MODE_DEFAULT: ExtProcProcessingMode.HeaderMode
    SEND: ExtProcProcessingMode.HeaderMode
    SKIP: ExtProcProcessingMode.HeaderMode
    class BodyMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NONE: _ClassVar[ExtProcProcessingMode.BodyMode]
        STREAMED: _ClassVar[ExtProcProcessingMode.BodyMode]
        BUFFERED: _ClassVar[ExtProcProcessingMode.BodyMode]
        BUFFERED_PARTIAL: _ClassVar[ExtProcProcessingMode.BodyMode]
        FULL_DUPLEX_STREAMED: _ClassVar[ExtProcProcessingMode.BodyMode]
    NONE: ExtProcProcessingMode.BodyMode
    STREAMED: ExtProcProcessingMode.BodyMode
    BUFFERED: ExtProcProcessingMode.BodyMode
    BUFFERED_PARTIAL: ExtProcProcessingMode.BodyMode
    FULL_DUPLEX_STREAMED: ExtProcProcessingMode.BodyMode
    REQUEST_HEADER_MODE_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_HEADER_MODE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_BODY_MODE_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_BODY_MODE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_TRAILER_MODE_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_TRAILER_MODE_FIELD_NUMBER: _ClassVar[int]
    request_header_mode: ExtProcProcessingMode.HeaderMode
    response_header_mode: ExtProcProcessingMode.HeaderMode
    request_body_mode: ExtProcProcessingMode.BodyMode
    response_body_mode: ExtProcProcessingMode.BodyMode
    request_trailer_mode: ExtProcProcessingMode.HeaderMode
    response_trailer_mode: ExtProcProcessingMode.HeaderMode
    def __init__(self, request_header_mode: _Optional[_Union[ExtProcProcessingMode.HeaderMode, str]] = ..., response_header_mode: _Optional[_Union[ExtProcProcessingMode.HeaderMode, str]] = ..., request_body_mode: _Optional[_Union[ExtProcProcessingMode.BodyMode, str]] = ..., response_body_mode: _Optional[_Union[ExtProcProcessingMode.BodyMode, str]] = ..., request_trailer_mode: _Optional[_Union[ExtProcProcessingMode.HeaderMode, str]] = ..., response_trailer_mode: _Optional[_Union[ExtProcProcessingMode.HeaderMode, str]] = ...) -> None: ...

class CredentialBroker(_message.Message):
    __slots__ = ("static_secret", "oidc_federation", "aws_assume_role", "platform_identity")
    STATIC_SECRET_FIELD_NUMBER: _ClassVar[int]
    OIDC_FEDERATION_FIELD_NUMBER: _ClassVar[int]
    AWS_ASSUME_ROLE_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    static_secret: str
    oidc_federation: OIDCFederation
    aws_assume_role: AWSAssumeRole
    platform_identity: PlatformIdentity
    def __init__(self, static_secret: _Optional[str] = ..., oidc_federation: _Optional[_Union[OIDCFederation, _Mapping]] = ..., aws_assume_role: _Optional[_Union[AWSAssumeRole, _Mapping]] = ..., platform_identity: _Optional[_Union[PlatformIdentity, _Mapping]] = ...) -> None: ...

class OIDCFederation(_message.Message):
    __slots__ = ("token_endpoint", "audience", "impersonate", "scopes")
    TOKEN_ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    IMPERSONATE_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    token_endpoint: str
    audience: str
    impersonate: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, token_endpoint: _Optional[str] = ..., audience: _Optional[str] = ..., impersonate: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ...) -> None: ...

class AWSAssumeRole(_message.Message):
    __slots__ = ("role_arn", "session_policy")
    ROLE_ARN_FIELD_NUMBER: _ClassVar[int]
    SESSION_POLICY_FIELD_NUMBER: _ClassVar[int]
    role_arn: str
    session_policy: str
    def __init__(self, role_arn: _Optional[str] = ..., session_policy: _Optional[str] = ...) -> None: ...

class PlatformIdentity(_message.Message):
    __slots__ = ("scopes",)
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    scopes: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, scopes: _Optional[_Iterable[str]] = ...) -> None: ...

class PolicyBinding(_message.Message):
    __slots__ = ("role", "members")
    ROLE_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    role: str
    members: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, role: _Optional[str] = ..., members: _Optional[_Iterable[str]] = ...) -> None: ...

class PolicyConfig(_message.Message):
    __slots__ = ("roles", "bindings", "egress")
    ROLES_FIELD_NUMBER: _ClassVar[int]
    BINDINGS_FIELD_NUMBER: _ClassVar[int]
    EGRESS_FIELD_NUMBER: _ClassVar[int]
    roles: _containers.RepeatedCompositeFieldContainer[PolicyRole]
    bindings: _containers.RepeatedCompositeFieldContainer[PolicyBinding]
    egress: _containers.RepeatedCompositeFieldContainer[EgressDestination]
    def __init__(self, roles: _Optional[_Iterable[_Union[PolicyRole, _Mapping]]] = ..., bindings: _Optional[_Iterable[_Union[PolicyBinding, _Mapping]]] = ..., egress: _Optional[_Iterable[_Union[EgressDestination, _Mapping]]] = ...) -> None: ...

class PolicyConfigGetRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PolicyConfigGetResponse(_message.Message):
    __slots__ = ("datalog_rules",)
    DATALOG_RULES_FIELD_NUMBER: _ClassVar[int]
    datalog_rules: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, datalog_rules: _Optional[_Iterable[str]] = ...) -> None: ...

class PolicyConfigUpdateResponse(_message.Message):
    __slots__ = ("success", "error")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    success: bool
    error: str
    def __init__(self, success: bool = ..., error: _Optional[str] = ...) -> None: ...

class EgressAssignmentsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EgressAssignmentsResponse(_message.Message):
    __slots__ = ("egress",)
    EGRESS_FIELD_NUMBER: _ClassVar[int]
    egress: _containers.RepeatedCompositeFieldContainer[EgressDestination]
    def __init__(self, egress: _Optional[_Iterable[_Union[EgressDestination, _Mapping]]] = ...) -> None: ...

class KeysResponse(_message.Message):
    __slots__ = ("public_keys", "sign_time", "signatures")
    PUBLIC_KEYS_FIELD_NUMBER: _ClassVar[int]
    SIGN_TIME_FIELD_NUMBER: _ClassVar[int]
    SIGNATURES_FIELD_NUMBER: _ClassVar[int]
    public_keys: _containers.RepeatedScalarFieldContainer[bytes]
    sign_time: _timestamp_pb2.Timestamp
    signatures: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, public_keys: _Optional[_Iterable[bytes]] = ..., sign_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., signatures: _Optional[_Iterable[bytes]] = ...) -> None: ...

class TokenRefreshRequest(_message.Message):
    __slots__ = ("challenge_signature", "challenge_unix_ms", "peer_id", "jwt")
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    JWT_FIELD_NUMBER: _ClassVar[int]
    challenge_signature: bytes
    challenge_unix_ms: int
    peer_id: str
    jwt: str
    def __init__(self, challenge_signature: _Optional[bytes] = ..., challenge_unix_ms: _Optional[int] = ..., peer_id: _Optional[str] = ..., jwt: _Optional[str] = ...) -> None: ...

class TokenRefreshResponse(_message.Message):
    __slots__ = ("biscuit_token", "expire_time", "error_message")
    BISCUIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    biscuit_token: bytes
    expire_time: _timestamp_pb2.Timestamp
    error_message: str
    def __init__(self, biscuit_token: _Optional[bytes] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., error_message: _Optional[str] = ...) -> None: ...

class NodeCatalogReport(_message.Message):
    __slots__ = ("services",)
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    services: _containers.RepeatedCompositeFieldContainer[ServiceInfo]
    def __init__(self, services: _Optional[_Iterable[_Union[ServiceInfo, _Mapping]]] = ...) -> None: ...

class TokenRevokeRequest(_message.Message):
    __slots__ = ("peer_id",)
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    def __init__(self, peer_id: _Optional[str] = ...) -> None: ...

class TokenRevokeResponse(_message.Message):
    __slots__ = ("success", "error")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    success: bool
    error: str
    def __init__(self, success: bool = ..., error: _Optional[str] = ...) -> None: ...

class BootstrapTokenCreateRequest(_message.Message):
    __slots__ = ("role", "owner_id", "ttl_hours", "max_usages", "description", "autonomous_recovery", "ephemeral")
    ROLE_FIELD_NUMBER: _ClassVar[int]
    OWNER_ID_FIELD_NUMBER: _ClassVar[int]
    TTL_HOURS_FIELD_NUMBER: _ClassVar[int]
    MAX_USAGES_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    AUTONOMOUS_RECOVERY_FIELD_NUMBER: _ClassVar[int]
    EPHEMERAL_FIELD_NUMBER: _ClassVar[int]
    role: str
    owner_id: str
    ttl_hours: int
    max_usages: int
    description: str
    autonomous_recovery: bool
    ephemeral: bool
    def __init__(self, role: _Optional[str] = ..., owner_id: _Optional[str] = ..., ttl_hours: _Optional[int] = ..., max_usages: _Optional[int] = ..., description: _Optional[str] = ..., autonomous_recovery: bool = ..., ephemeral: bool = ...) -> None: ...

class BootstrapTokenCreateResponse(_message.Message):
    __slots__ = ("id", "token", "role", "owner_id", "expire_time")
    ID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    OWNER_ID_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    id: str
    token: str
    role: str
    owner_id: str
    expire_time: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., token: _Optional[str] = ..., role: _Optional[str] = ..., owner_id: _Optional[str] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class BootstrapToken(_message.Message):
    __slots__ = ("id", "role", "owner_id", "max_usages", "usages_count", "description", "create_time", "expire_time", "revoke_time", "autonomous_recovery", "ephemeral")
    ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    OWNER_ID_FIELD_NUMBER: _ClassVar[int]
    MAX_USAGES_FIELD_NUMBER: _ClassVar[int]
    USAGES_COUNT_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    CREATE_TIME_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    REVOKE_TIME_FIELD_NUMBER: _ClassVar[int]
    AUTONOMOUS_RECOVERY_FIELD_NUMBER: _ClassVar[int]
    EPHEMERAL_FIELD_NUMBER: _ClassVar[int]
    id: str
    role: str
    owner_id: str
    max_usages: int
    usages_count: int
    description: str
    create_time: _timestamp_pb2.Timestamp
    expire_time: _timestamp_pb2.Timestamp
    revoke_time: _timestamp_pb2.Timestamp
    autonomous_recovery: bool
    ephemeral: bool
    def __init__(self, id: _Optional[str] = ..., role: _Optional[str] = ..., owner_id: _Optional[str] = ..., max_usages: _Optional[int] = ..., usages_count: _Optional[int] = ..., description: _Optional[str] = ..., create_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., revoke_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., autonomous_recovery: bool = ..., ephemeral: bool = ...) -> None: ...

class BootstrapTokenListResponse(_message.Message):
    __slots__ = ("tokens",)
    TOKENS_FIELD_NUMBER: _ClassVar[int]
    tokens: _containers.RepeatedCompositeFieldContainer[BootstrapToken]
    def __init__(self, tokens: _Optional[_Iterable[_Union[BootstrapToken, _Mapping]]] = ...) -> None: ...

class EnrollmentRequest(_message.Message):
    __slots__ = ("id", "peer_id", "token_id", "status", "labels", "create_time", "resolve_time", "resolved_by")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    TOKEN_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    CREATE_TIME_FIELD_NUMBER: _ClassVar[int]
    RESOLVE_TIME_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_BY_FIELD_NUMBER: _ClassVar[int]
    id: str
    peer_id: str
    token_id: str
    status: EnrollmentStatus
    labels: _containers.ScalarMap[str, str]
    create_time: _timestamp_pb2.Timestamp
    resolve_time: _timestamp_pb2.Timestamp
    resolved_by: str
    def __init__(self, id: _Optional[str] = ..., peer_id: _Optional[str] = ..., token_id: _Optional[str] = ..., status: _Optional[_Union[EnrollmentStatus, str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., create_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., resolve_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., resolved_by: _Optional[str] = ...) -> None: ...

class EnrollmentRequestListResponse(_message.Message):
    __slots__ = ("requests",)
    REQUESTS_FIELD_NUMBER: _ClassVar[int]
    requests: _containers.RepeatedCompositeFieldContainer[EnrollmentRequest]
    def __init__(self, requests: _Optional[_Iterable[_Union[EnrollmentRequest, _Mapping]]] = ...) -> None: ...

class User(_message.Message):
    __slots__ = ("id", "issuer", "email", "role", "create_time")
    ID_FIELD_NUMBER: _ClassVar[int]
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    CREATE_TIME_FIELD_NUMBER: _ClassVar[int]
    id: str
    issuer: str
    email: str
    role: str
    create_time: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., issuer: _Optional[str] = ..., email: _Optional[str] = ..., role: _Optional[str] = ..., create_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EnrolledNode(_message.Message):
    __slots__ = ("peer_id", "role", "enrollment_type", "claims_json", "owner_id", "labels", "enroll_time", "expire_time", "banned", "autonomous_recovery", "ephemeral")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    ENROLLMENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    CLAIMS_JSON_FIELD_NUMBER: _ClassVar[int]
    OWNER_ID_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    ENROLL_TIME_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    BANNED_FIELD_NUMBER: _ClassVar[int]
    AUTONOMOUS_RECOVERY_FIELD_NUMBER: _ClassVar[int]
    EPHEMERAL_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    role: str
    enrollment_type: str
    claims_json: str
    owner_id: str
    labels: _containers.ScalarMap[str, str]
    enroll_time: _timestamp_pb2.Timestamp
    expire_time: _timestamp_pb2.Timestamp
    banned: bool
    autonomous_recovery: bool
    ephemeral: bool
    def __init__(self, peer_id: _Optional[str] = ..., role: _Optional[str] = ..., enrollment_type: _Optional[str] = ..., claims_json: _Optional[str] = ..., owner_id: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., enroll_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., banned: bool = ..., autonomous_recovery: bool = ..., ephemeral: bool = ...) -> None: ...

class RouterLease(_message.Message):
    __slots__ = ("peer_id", "addresses", "last_renewal_time", "expire_time", "connected_peers", "dht_size", "ingress_url")
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    LAST_RENEWAL_TIME_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    CONNECTED_PEERS_FIELD_NUMBER: _ClassVar[int]
    DHT_SIZE_FIELD_NUMBER: _ClassVar[int]
    INGRESS_URL_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    addresses: _containers.RepeatedScalarFieldContainer[str]
    last_renewal_time: _timestamp_pb2.Timestamp
    expire_time: _timestamp_pb2.Timestamp
    connected_peers: _containers.RepeatedScalarFieldContainer[str]
    dht_size: int
    ingress_url: str
    def __init__(self, peer_id: _Optional[str] = ..., addresses: _Optional[_Iterable[str]] = ..., last_renewal_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., connected_peers: _Optional[_Iterable[str]] = ..., dht_size: _Optional[int] = ..., ingress_url: _Optional[str] = ...) -> None: ...

class NodeServices(_message.Message):
    __slots__ = ("services", "report_time")
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    REPORT_TIME_FIELD_NUMBER: _ClassVar[int]
    services: _containers.RepeatedCompositeFieldContainer[ServiceInfo]
    report_time: _timestamp_pb2.Timestamp
    def __init__(self, services: _Optional[_Iterable[_Union[ServiceInfo, _Mapping]]] = ..., report_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class AdminStatusResponse(_message.Message):
    __slots__ = ("users", "active_routers", "enrolled_nodes", "enrollment_requests", "bootstrap_tokens", "policy", "node_catalog")
    class NodeCatalogEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: NodeServices
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[NodeServices, _Mapping]] = ...) -> None: ...
    USERS_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_ROUTERS_FIELD_NUMBER: _ClassVar[int]
    ENROLLED_NODES_FIELD_NUMBER: _ClassVar[int]
    ENROLLMENT_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    BOOTSTRAP_TOKENS_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    NODE_CATALOG_FIELD_NUMBER: _ClassVar[int]
    users: _containers.RepeatedCompositeFieldContainer[User]
    active_routers: _containers.RepeatedCompositeFieldContainer[RouterLease]
    enrolled_nodes: _containers.RepeatedCompositeFieldContainer[EnrolledNode]
    enrollment_requests: _containers.RepeatedCompositeFieldContainer[EnrollmentRequest]
    bootstrap_tokens: _containers.RepeatedCompositeFieldContainer[BootstrapToken]
    policy: PolicyConfig
    node_catalog: _containers.MessageMap[str, NodeServices]
    def __init__(self, users: _Optional[_Iterable[_Union[User, _Mapping]]] = ..., active_routers: _Optional[_Iterable[_Union[RouterLease, _Mapping]]] = ..., enrolled_nodes: _Optional[_Iterable[_Union[EnrolledNode, _Mapping]]] = ..., enrollment_requests: _Optional[_Iterable[_Union[EnrollmentRequest, _Mapping]]] = ..., bootstrap_tokens: _Optional[_Iterable[_Union[BootstrapToken, _Mapping]]] = ..., policy: _Optional[_Union[PolicyConfig, _Mapping]] = ..., node_catalog: _Optional[_Mapping[str, NodeServices]] = ...) -> None: ...

class UserStatusResponse(_message.Message):
    __slots__ = ("user", "enrolled_nodes", "bootstrap_tokens", "active_routers", "policy")
    USER_FIELD_NUMBER: _ClassVar[int]
    ENROLLED_NODES_FIELD_NUMBER: _ClassVar[int]
    BOOTSTRAP_TOKENS_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_ROUTERS_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    user: User
    enrolled_nodes: _containers.RepeatedCompositeFieldContainer[EnrolledNode]
    bootstrap_tokens: _containers.RepeatedCompositeFieldContainer[BootstrapToken]
    active_routers: _containers.RepeatedCompositeFieldContainer[RouterLease]
    policy: PolicyConfig
    def __init__(self, user: _Optional[_Union[User, _Mapping]] = ..., enrolled_nodes: _Optional[_Iterable[_Union[EnrolledNode, _Mapping]]] = ..., bootstrap_tokens: _Optional[_Iterable[_Union[BootstrapToken, _Mapping]]] = ..., active_routers: _Optional[_Iterable[_Union[RouterLease, _Mapping]]] = ..., policy: _Optional[_Union[PolicyConfig, _Mapping]] = ...) -> None: ...

class NodeListResponse(_message.Message):
    __slots__ = ("nodes", "next_page_token")
    NODES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    nodes: _containers.RepeatedCompositeFieldContainer[EnrolledNode]
    next_page_token: str
    def __init__(self, nodes: _Optional[_Iterable[_Union[EnrolledNode, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class IdentityEvidenceResponse(_message.Message):
    __slots__ = ("peer_id", "biscuit", "biscuit_expire_time", "control_plane_url", "trusted_control_plane_keys", "check_time")
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    CONTROL_PLANE_URL_FIELD_NUMBER: _ClassVar[int]
    TRUSTED_CONTROL_PLANE_KEYS_FIELD_NUMBER: _ClassVar[int]
    CHECK_TIME_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    biscuit: bytes
    biscuit_expire_time: _timestamp_pb2.Timestamp
    control_plane_url: str
    trusted_control_plane_keys: _containers.RepeatedScalarFieldContainer[bytes]
    check_time: _timestamp_pb2.Timestamp
    def __init__(self, peer_id: _Optional[str] = ..., biscuit: _Optional[bytes] = ..., biscuit_expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., control_plane_url: _Optional[str] = ..., trusted_control_plane_keys: _Optional[_Iterable[bytes]] = ..., check_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class PeerEvidenceResponse(_message.Message):
    __slots__ = ("peer_id", "biscuit", "verifying_key", "roles", "labels", "expire_time", "revocation_ids", "check_time")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    VERIFYING_KEY_FIELD_NUMBER: _ClassVar[int]
    ROLES_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_IDS_FIELD_NUMBER: _ClassVar[int]
    CHECK_TIME_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    biscuit: bytes
    verifying_key: bytes
    roles: _containers.RepeatedScalarFieldContainer[str]
    labels: _containers.ScalarMap[str, str]
    expire_time: _timestamp_pb2.Timestamp
    revocation_ids: _containers.RepeatedScalarFieldContainer[str]
    check_time: _timestamp_pb2.Timestamp
    def __init__(self, peer_id: _Optional[str] = ..., biscuit: _Optional[bytes] = ..., verifying_key: _Optional[bytes] = ..., roles: _Optional[_Iterable[str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., revocation_ids: _Optional[_Iterable[str]] = ..., check_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class MemberCredential(_message.Message):
    __slots__ = ("control_plane_url", "biscuit", "expire_time", "trusted_keys", "issued_under_keys", "router_addresses", "oidc_session")
    CONTROL_PLANE_URL_FIELD_NUMBER: _ClassVar[int]
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    TRUSTED_KEYS_FIELD_NUMBER: _ClassVar[int]
    ISSUED_UNDER_KEYS_FIELD_NUMBER: _ClassVar[int]
    ROUTER_ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    OIDC_SESSION_FIELD_NUMBER: _ClassVar[int]
    control_plane_url: str
    biscuit: bytes
    expire_time: _timestamp_pb2.Timestamp
    trusted_keys: _containers.RepeatedCompositeFieldContainer[TrustedSigningKey]
    issued_under_keys: _containers.RepeatedScalarFieldContainer[bytes]
    router_addresses: _containers.RepeatedScalarFieldContainer[str]
    oidc_session: OIDCSession
    def __init__(self, control_plane_url: _Optional[str] = ..., biscuit: _Optional[bytes] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., trusted_keys: _Optional[_Iterable[_Union[TrustedSigningKey, _Mapping]]] = ..., issued_under_keys: _Optional[_Iterable[bytes]] = ..., router_addresses: _Optional[_Iterable[str]] = ..., oidc_session: _Optional[_Union[OIDCSession, _Mapping]] = ...) -> None: ...

class TrustedSigningKey(_message.Message):
    __slots__ = ("public_key", "receive_time")
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    RECEIVE_TIME_FIELD_NUMBER: _ClassVar[int]
    public_key: bytes
    receive_time: _timestamp_pb2.Timestamp
    def __init__(self, public_key: _Optional[bytes] = ..., receive_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class OIDCSession(_message.Message):
    __slots__ = ("issuer", "client_id", "audience", "refresh_token")
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    REFRESH_TOKEN_FIELD_NUMBER: _ClassVar[int]
    issuer: str
    client_id: str
    audience: str
    refresh_token: str
    def __init__(self, issuer: _Optional[str] = ..., client_id: _Optional[str] = ..., audience: _Optional[str] = ..., refresh_token: _Optional[str] = ...) -> None: ...

class TaskAuthorizationRule(_message.Message):
    __slots__ = ("name", "display_name", "rules", "expire_time")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    name: str
    display_name: str
    rules: _containers.RepeatedCompositeFieldContainer[TaskRule]
    expire_time: _timestamp_pb2.Timestamp
    def __init__(self, name: _Optional[str] = ..., display_name: _Optional[str] = ..., rules: _Optional[_Iterable[_Union[TaskRule, _Mapping]]] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class TaskRule(_message.Message):
    __slots__ = ("description", "allowed_services", "operation", "allowed_resources")
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_SERVICES_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    description: str
    allowed_services: _containers.RepeatedScalarFieldContainer[str]
    operation: TaskOperation
    allowed_resources: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, description: _Optional[str] = ..., allowed_services: _Optional[_Iterable[str]] = ..., operation: _Optional[_Union[TaskOperation, _Mapping]] = ..., allowed_resources: _Optional[_Iterable[str]] = ...) -> None: ...

class TaskOperation(_message.Message):
    __slots__ = ("allowed_tools", "allowed_methods", "allowed_paths", "allowed_permissions")
    ALLOWED_TOOLS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_METHODS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_PATHS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    allowed_tools: _containers.RepeatedScalarFieldContainer[str]
    allowed_methods: _containers.RepeatedScalarFieldContainer[str]
    allowed_paths: _containers.RepeatedScalarFieldContainer[str]
    allowed_permissions: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, allowed_tools: _Optional[_Iterable[str]] = ..., allowed_methods: _Optional[_Iterable[str]] = ..., allowed_paths: _Optional[_Iterable[str]] = ..., allowed_permissions: _Optional[_Iterable[str]] = ...) -> None: ...

class TokenExchangeRequest(_message.Message):
    __slots__ = ("subject_token", "task_rule", "seal", "challenge_unix_ms", "challenge_signature")
    SUBJECT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    TASK_RULE_FIELD_NUMBER: _ClassVar[int]
    SEAL_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    subject_token: str
    task_rule: TaskAuthorizationRule
    seal: bool
    challenge_unix_ms: int
    challenge_signature: bytes
    def __init__(self, subject_token: _Optional[str] = ..., task_rule: _Optional[_Union[TaskAuthorizationRule, _Mapping]] = ..., seal: bool = ..., challenge_unix_ms: _Optional[int] = ..., challenge_signature: _Optional[bytes] = ...) -> None: ...

class TokenExchangeResponse(_message.Message):
    __slots__ = ("biscuit_token", "expire_time", "roles", "subject")
    BISCUIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    ROLES_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    biscuit_token: bytes
    expire_time: _timestamp_pb2.Timestamp
    roles: _containers.RepeatedScalarFieldContainer[str]
    subject: str
    def __init__(self, biscuit_token: _Optional[bytes] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., roles: _Optional[_Iterable[str]] = ..., subject: _Optional[str] = ...) -> None: ...

class STSTokenRequest(_message.Message):
    __slots__ = ("biscuit", "destination", "audience", "challenge_unix_ms", "challenge_signature")
    BISCUIT_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CHALLENGE_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    biscuit: bytes
    destination: str
    audience: str
    challenge_unix_ms: int
    challenge_signature: bytes
    def __init__(self, biscuit: _Optional[bytes] = ..., destination: _Optional[str] = ..., audience: _Optional[str] = ..., challenge_unix_ms: _Optional[int] = ..., challenge_signature: _Optional[bytes] = ...) -> None: ...

class STSTokenResponse(_message.Message):
    __slots__ = ("jwt", "expire_time", "subject", "roles", "task_name")
    JWT_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TIME_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    ROLES_FIELD_NUMBER: _ClassVar[int]
    TASK_NAME_FIELD_NUMBER: _ClassVar[int]
    jwt: str
    expire_time: _timestamp_pb2.Timestamp
    subject: str
    roles: _containers.RepeatedScalarFieldContainer[str]
    task_name: str
    def __init__(self, jwt: _Optional[str] = ..., expire_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., subject: _Optional[str] = ..., roles: _Optional[_Iterable[str]] = ..., task_name: _Optional[str] = ...) -> None: ...

class RevocationsResponse(_message.Message):
    __slots__ = ("revocation_ids", "banned_peer_ids")
    REVOCATION_IDS_FIELD_NUMBER: _ClassVar[int]
    BANNED_PEER_IDS_FIELD_NUMBER: _ClassVar[int]
    revocation_ids: _containers.RepeatedScalarFieldContainer[str]
    banned_peer_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, revocation_ids: _Optional[_Iterable[str]] = ..., banned_peer_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class PolicyDeniedSignal(_message.Message):
    __slots__ = ("direction", "reason", "detail", "target_service", "requested_operation", "requested_resource", "caller_peer_id", "caller_subject", "caller_roles", "caller_labels", "event_time")
    class CallerLabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    TARGET_SERVICE_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_OPERATION_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_RESOURCE_FIELD_NUMBER: _ClassVar[int]
    CALLER_PEER_ID_FIELD_NUMBER: _ClassVar[int]
    CALLER_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    CALLER_ROLES_FIELD_NUMBER: _ClassVar[int]
    CALLER_LABELS_FIELD_NUMBER: _ClassVar[int]
    EVENT_TIME_FIELD_NUMBER: _ClassVar[int]
    direction: SignalCallerDirection
    reason: PolicyDenialReason
    detail: str
    target_service: str
    requested_operation: str
    requested_resource: str
    caller_peer_id: str
    caller_subject: str
    caller_roles: _containers.RepeatedScalarFieldContainer[str]
    caller_labels: _containers.ScalarMap[str, str]
    event_time: _timestamp_pb2.Timestamp
    def __init__(self, direction: _Optional[_Union[SignalCallerDirection, str]] = ..., reason: _Optional[_Union[PolicyDenialReason, str]] = ..., detail: _Optional[str] = ..., target_service: _Optional[str] = ..., requested_operation: _Optional[str] = ..., requested_resource: _Optional[str] = ..., caller_peer_id: _Optional[str] = ..., caller_subject: _Optional[str] = ..., caller_roles: _Optional[_Iterable[str]] = ..., caller_labels: _Optional[_Mapping[str, str]] = ..., event_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class TransportRefusedSignal(_message.Message):
    __slots__ = ("reason", "detail", "peer_id", "remote_multiaddr", "protocol_id", "coalesced_count", "first_seen_time", "event_time")
    REASON_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    REMOTE_MULTIADDR_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_ID_FIELD_NUMBER: _ClassVar[int]
    COALESCED_COUNT_FIELD_NUMBER: _ClassVar[int]
    FIRST_SEEN_TIME_FIELD_NUMBER: _ClassVar[int]
    EVENT_TIME_FIELD_NUMBER: _ClassVar[int]
    reason: TransportRefusalReason
    detail: str
    peer_id: str
    remote_multiaddr: str
    protocol_id: str
    coalesced_count: int
    first_seen_time: _timestamp_pb2.Timestamp
    event_time: _timestamp_pb2.Timestamp
    def __init__(self, reason: _Optional[_Union[TransportRefusalReason, str]] = ..., detail: _Optional[str] = ..., peer_id: _Optional[str] = ..., remote_multiaddr: _Optional[str] = ..., protocol_id: _Optional[str] = ..., coalesced_count: _Optional[int] = ..., first_seen_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., event_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class IdentityRevokedSignal(_message.Message):
    __slots__ = ("peer_id", "source", "reason", "revocation_ids", "issuer_peer_id", "event_time")
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_IDS_FIELD_NUMBER: _ClassVar[int]
    ISSUER_PEER_ID_FIELD_NUMBER: _ClassVar[int]
    EVENT_TIME_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    source: RevocationSource
    reason: str
    revocation_ids: _containers.RepeatedScalarFieldContainer[str]
    issuer_peer_id: str
    event_time: _timestamp_pb2.Timestamp
    def __init__(self, peer_id: _Optional[str] = ..., source: _Optional[_Union[RevocationSource, str]] = ..., reason: _Optional[str] = ..., revocation_ids: _Optional[_Iterable[str]] = ..., issuer_peer_id: _Optional[str] = ..., event_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EnrollmentRejectedSignal(_message.Message):
    __slots__ = ("peer_id", "requested_role", "reason", "detail", "bootstrap_token_id", "remote_address", "submitted_labels", "is_autonomous_recovery", "event_time")
    class SubmittedLabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_ROLE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    BOOTSTRAP_TOKEN_ID_FIELD_NUMBER: _ClassVar[int]
    REMOTE_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SUBMITTED_LABELS_FIELD_NUMBER: _ClassVar[int]
    IS_AUTONOMOUS_RECOVERY_FIELD_NUMBER: _ClassVar[int]
    EVENT_TIME_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    requested_role: str
    reason: EnrollmentRejectionReason
    detail: str
    bootstrap_token_id: str
    remote_address: str
    submitted_labels: _containers.ScalarMap[str, str]
    is_autonomous_recovery: bool
    event_time: _timestamp_pb2.Timestamp
    def __init__(self, peer_id: _Optional[str] = ..., requested_role: _Optional[str] = ..., reason: _Optional[_Union[EnrollmentRejectionReason, str]] = ..., detail: _Optional[str] = ..., bootstrap_token_id: _Optional[str] = ..., remote_address: _Optional[str] = ..., submitted_labels: _Optional[_Mapping[str, str]] = ..., is_autonomous_recovery: bool = ..., event_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class SecuritySignalEvent(_message.Message):
    __slots__ = ("id", "source", "spec_version", "type", "event_time", "data_content_type", "subject", "policy_denied", "transport_refused", "identity_revoked", "enrollment_rejected")
    ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    SPEC_VERSION_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    EVENT_TIME_FIELD_NUMBER: _ClassVar[int]
    DATA_CONTENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    POLICY_DENIED_FIELD_NUMBER: _ClassVar[int]
    TRANSPORT_REFUSED_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_REVOKED_FIELD_NUMBER: _ClassVar[int]
    ENROLLMENT_REJECTED_FIELD_NUMBER: _ClassVar[int]
    id: str
    source: str
    spec_version: str
    type: str
    event_time: _timestamp_pb2.Timestamp
    data_content_type: str
    subject: str
    policy_denied: PolicyDeniedSignal
    transport_refused: TransportRefusedSignal
    identity_revoked: IdentityRevokedSignal
    enrollment_rejected: EnrollmentRejectedSignal
    def __init__(self, id: _Optional[str] = ..., source: _Optional[str] = ..., spec_version: _Optional[str] = ..., type: _Optional[str] = ..., event_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., data_content_type: _Optional[str] = ..., subject: _Optional[str] = ..., policy_denied: _Optional[_Union[PolicyDeniedSignal, _Mapping]] = ..., transport_refused: _Optional[_Union[TransportRefusedSignal, _Mapping]] = ..., identity_revoked: _Optional[_Union[IdentityRevokedSignal, _Mapping]] = ..., enrollment_rejected: _Optional[_Union[EnrollmentRejectedSignal, _Mapping]] = ...) -> None: ...

class WebhookEndpointConfig(_message.Message):
    __slots__ = ("url", "hmac_secret_path", "ca_cert_path", "client_cert_path", "client_key_path", "timeout", "max_retries", "event_types")
    URL_FIELD_NUMBER: _ClassVar[int]
    HMAC_SECRET_PATH_FIELD_NUMBER: _ClassVar[int]
    CA_CERT_PATH_FIELD_NUMBER: _ClassVar[int]
    CLIENT_CERT_PATH_FIELD_NUMBER: _ClassVar[int]
    CLIENT_KEY_PATH_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_FIELD_NUMBER: _ClassVar[int]
    MAX_RETRIES_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPES_FIELD_NUMBER: _ClassVar[int]
    url: str
    hmac_secret_path: str
    ca_cert_path: str
    client_cert_path: str
    client_key_path: str
    timeout: _duration_pb2.Duration
    max_retries: int
    event_types: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, url: _Optional[str] = ..., hmac_secret_path: _Optional[str] = ..., ca_cert_path: _Optional[str] = ..., client_cert_path: _Optional[str] = ..., client_key_path: _Optional[str] = ..., timeout: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ..., max_retries: _Optional[int] = ..., event_types: _Optional[_Iterable[str]] = ...) -> None: ...

class SecuritySignalsConfig(_message.Message):
    __slots__ = ("enabled", "endpoints", "queue_capacity", "coalescing_window")
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    QUEUE_CAPACITY_FIELD_NUMBER: _ClassVar[int]
    COALESCING_WINDOW_FIELD_NUMBER: _ClassVar[int]
    enabled: bool
    endpoints: _containers.RepeatedCompositeFieldContainer[WebhookEndpointConfig]
    queue_capacity: int
    coalescing_window: _duration_pb2.Duration
    def __init__(self, enabled: bool = ..., endpoints: _Optional[_Iterable[_Union[WebhookEndpointConfig, _Mapping]]] = ..., queue_capacity: _Optional[int] = ..., coalescing_window: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ...) -> None: ...
