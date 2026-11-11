---
title: "Containment signals and security webhooks"
linkTitle: "Containment signals"
weight: 10
description: "Technical reference for Agent Mesh out-of-band security containment webhooks and signals."
aliases:
  - /docs/reference/containment/
  - /docs/reference/security-signals/
---

Agent Mesh components (`agentmesh-node` and `agentmesh-control-plane`) provide a generic,
runtime-agnostic security webhook interface. This mechanism emits out-of-band security
state transitions to external sandbox supervisors, container runtimes (such as NVIDIA
OpenShell, gVisor, or Kata), SIEMs, and host containment daemons.

The contract is defined in `api/agentmesh.proto`, serializes over HTTP and Unix domain
sockets using CloudEvents 1.0 binary mode and `protojson`, and supports cryptographic
HMAC-SHA256 signing and mutual TLS.

---

## 1. CloudEvents 1.0 Binary Mode Headers

Dispatched security webhooks use HTTP `POST` requests formatted according to the
[CloudEvents 1.0 Binary Content Mode](https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md#31-binary-content-mode):

| Header | Description | Example |
|---|---|---|
| `ce-specversion` | CloudEvents specification version. Always `1.0`. | `1.0` |
| `ce-id` | Unique UUID v4 identifying the event instance. | `f47ac10b-58cc-4372-a567-0e02b2c3d479` |
| `ce-type` | Fully qualified security signal event type. | `agentmesh.policy.denied` |
| `ce-source` | URI identifying the emitting context. | `agentmesh://containment/dispatcher` or `urn:agentmesh:node:12D3KooW...` |
| `ce-time` | Event generation timestamp formatted as RFC 3339 nano. | `2026-11-10T20:15:30.123456789Z` |
| `ce-subject` | Subject peer ID or caller principal (if known). | `12D3KooW...` or `spiffe://openshell.example/sandbox/42` |
| `Content-Type` | MIME type of the payload. Always `application/json`. | `application/json` |
| `User-Agent` | Client identifier. | `agentmesh-containment/1.0` |
| `X-AgentMesh-Timestamp` | Unix epoch millisecond timestamp used for HMAC signing (optional). | `1762812930123` |
| `X-AgentMesh-Signature` | Hex-encoded HMAC-SHA256 signature (optional). | `sha256=a1b2c3d4...` |

---

## 2. Wire Schema & ProtoJSON Formatting

All wire payloads are defined in `api/agentmesh.proto` under the `SecuritySignalEvent`
envelope and serialized using `protojson.MarshalOptions{UseProtoNames: true}`:
- Field names strictly preserve protobuf snake_case (e.g. `target_service`, `caller_peer_id`).
- Timestamps are encoded as standard RFC 3339 strings matching `google.protobuf.Timestamp`.
- Unknown or unmodeled JSON fields are rejected by receivers.

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "source": "agentmesh://containment/dispatcher",
  "spec_version": "1.0",
  "type": "agentmesh.policy.denied",
  "event_time": "2026-11-10T20:15:30.123456789Z",
  "data_content_type": "application/json",
  "subject": "12D3KooWNodeDemo12345",
  "policy_denied": {
    "direction": "LOCAL_WORKLOAD",
    "reason": "DATALOG_EVALUATION_DENIED",
    "detail": "datalog block 0 denied egress to unauthorized database",
    "target_service": "bigquery",
    "requested_operation": "POST",
    "requested_resource": "//bigquery.googleapis.com/projects/prod-ledger",
    "caller_peer_id": "12D3KooWCallerDemo67890",
    "caller_subject": "spiffe://example.org/ns/prod/sa/analytics-agent",
    "caller_roles": ["agent", "reader"],
    "caller_labels": {
      "env": "production",
      "tier": "restricted"
    },
    "event_time": "2026-11-10T20:15:30.123456789Z"
  }
}
```

---

## 3. The Four Outbound Containment Signals

### 3.1 `agentmesh.policy.denied`

Emitted by `agentmesh-node` whenever an authorization check, Biscuit Datalog policy,
`TaskAuthorizationRule` (`tar_block`) constraint, or content inspection filter
(Model Armor / Envoy `ext_proc`) rejects a request.

#### Fields (`PolicyDeniedSignal`)

| Field | Type | Description |
|---|---|---|
| `direction` | `SignalCallerDirection` | `LOCAL_WORKLOAD` (local sandboxed agent) or `REMOTE_PEER` (incoming mesh request). |
| `reason` | `PolicyDenialReason` | Denial cause: `DATALOG_EVALUATION_DENIED`, `TASK_AUTHORIZATION_RULE_VIOLATION`, `INSPECTION_FILTER_BLOCKED`, `ROLE_MISMATCH`, `EXPIRED_CREDENTIAL`, `UNAUTHORIZED_SERVICE`, `UNAUTHORIZED_PATH_OR_METHOD`. |
| `detail` | `string` | Diagnostic description of why the request was refused. |
| `target_service` | `string` | Requested service URI (e.g. `mcp://github`, `egress://bigquery.googleapis.com`). |
| `requested_operation` | `string` | HTTP method or MCP tool name (e.g. `GET`, `execute_query`). |
| `requested_resource` | `string` | Target resource path or URI pattern. |
| `caller_peer_id` | `string` | Peer ID of the caller if known. |
| `caller_subject` | `string` | Subject claim extracted from the caller's Biscuit or platform JWT. |
| `caller_roles` | `[]string` | Mesh roles held by the caller. |
| `caller_labels` | `map[string]string` | Attested labels present on the caller's credential. |
| `event_time` | `google.protobuf.Timestamp` | Instant when the policy denial occurred. |

### 3.2 `agentmesh.transport.refused`

Emitted by `agentmesh-node` when the libp2p connection gate or stream authorization
gate (`internal/node/auth_gate.go`) rejects an incoming stream or peer connection.
Repetitive refusals from the same peer are coalesced into a single event within a
sliding window.

#### Fields (`TransportRefusedSignal`)

| Field | Type | Description |
|---|---|---|
| `reason` | `TransportRefusalReason` | `PEER_UNAUTHENTICATED`, `NOT_ROUTER_ROLE`, `AUTH_DEADLINE_EXCEEDED`, `PEER_BANNED`, `PROTOCOL_UNAUTHORIZED`. |
| `detail` | `string` | Detailed refusal reason. |
| `peer_id` | `string` | Remote libp2p peer ID string. |
| `remote_multiaddr` | `string` | Remote multiaddress (e.g. `/ip4/198.51.100.42/tcp/4001`). |
| `protocol_id` | `string` | Libp2p protocol ID requested (e.g. `/agentmesh/auth`, `/libp2p-http`). |
| `coalesced_count` | `uint32` | Number of refusal occurrences coalesced in this delivery window ($ \ge 1 $). |
| `first_seen_time` | `google.protobuf.Timestamp` | Timestamp of the first observed rejection in this window. |
| `event_time` | `google.protobuf.Timestamp` | Timestamp of the most recent rejection. |

### 3.3 `agentmesh.identity.revoked`

Emitted when a node or Biscuit credential is explicitly revoked or banned.
`agentmesh-control-plane` emits this signal upon administrative banishment; `agentmesh-node`
emits it upon receiving a signed `MeshEvent.BANNED` gossip broadcast or when `/refresh`
rejects an active session due to an upstream ban.

#### Fields (`IdentityRevokedSignal`)

| Field | Type | Description |
|---|---|---|
| `peer_id` | `string` | Subject peer ID that has been banned or revoked. |
| `source` | `RevocationSource` | `CONTROL_PLANE_ADMIN`, `MESH_EVENT_BANNED_GOSSIP`, `LOCAL_CONTROL_PLANE_SYNC`, `TOKEN_REFRESH_REJECTION`. |
| `reason` | `string` | Administrative or operational explanation for the revocation. |
| `revocation_ids` | `[]string` | Hex-encoded Biscuit authority revocation IDs (`RevocationIds()[0]`). |
| `issuer_peer_id` | `string` | Peer ID of the emitting node or control plane. |
| `event_time` | `google.protobuf.Timestamp` | Instant when the revocation occurred. |

### 3.4 `agentmesh.enrollment.rejected`

Emitted when a node fails bootstrap enrollment (`POST /enroll`) or when autonomous
token recovery is refused during credential refresh (`POST /refresh`).

#### Fields (`EnrollmentRejectedSignal`)

| Field | Type | Description |
|---|---|---|
| `peer_id` | `string` | Peer ID attempting enrollment or recovery. |
| `requested_role` | `string` | Mesh role requested in the enrollment attempt. |
| `reason` | `EnrollmentRejectionReason` | `INVALID_JWT`, `EXPIRED_BOOTSTRAP_TOKEN`, `BOOTSTRAP_TOKEN_USAGE_EXCEEDED`, `UNATTESTED_LABELS_REJECTED`, `INVALID_CHALLENGE_SIGNATURE`, `REQUESTED_ROLE_UNAUTHORIZED`, `PEER_PREVIOUSLY_BANNED`, `AUTONOMOUS_RECOVERY_DISABLED`. |
| `detail` | `string` | Rejection details and validation error. |
| `bootstrap_token_id` | `string` | ID of the bootstrap token used (if applicable). |
| `remote_address` | `string` | Remote network address of the enrollment requester. |
| `submitted_labels` | `map[string]string` | Key/value labels submitted with the enrollment request. |
| `is_autonomous_recovery` | `bool` | `true` if rejection occurred during `/refresh` autonomous re-enrollment. |
| `event_time` | `google.protobuf.Timestamp` | Instant when the rejection occurred. |

---

## 4. Caller Direction Tagging: LOCAL_WORKLOAD vs REMOTE_PEER

The `direction` field on `PolicyDeniedSignal` allows containment runtimes to isolate
the source of an authorization failure:

- **`LOCAL_WORKLOAD`**: Indicates that the violation was attempted by the local agent process
  running on the same host or container and talking to the `agentmesh-node` sidecar listener
  (`http://localhost:8080` or `agentmesh.sock`). This is the primary trigger for host sandbox
  supervisors (OpenShell, gVisor, or host containment daemons) to apply cgroups freezing, revoke Landlock privileges,
  or terminate the local container.
- **`REMOTE_PEER`**: Indicates that the violation arrived over the libp2p network from an
  external mesh member. A `REMOTE_PEER` violation suggests lateral traversal or remote probing,
  warranting peer rate-limiting or mesh-wide eviction rather than host container teardown.

---

## 5. Cryptographic HMAC-SHA256 Signing

To prevent webhook spoofing, endpoints can configure a shared HMAC secret.

### Secret Hygiene Invariant
Per `AGENTS.md`, secrets MUST be loaded from a file path (`hmac_secret_path` or
`--security-webhook-hmac-path`) or provided via the `AGENTMESH_CONTAINMENT_HMAC_SECRET`
environment variable. Raw secret strings in YAML configuration or CLI flags are strictly
forbidden and fail validation at startup.

### Signing Algorithm
When HMAC is enabled, the webhook client attaches two headers:
1. `X-AgentMesh-Timestamp`: String representing the current Unix epoch time in milliseconds.
2. `X-AgentMesh-Signature`: Signature computed as:
   ```text
   signature = "sha256=" + HexEncode(HMAC-SHA256(secret, timestamp + "." + request_body))
   ```

### Verification Example (Go)

```go
func VerifyWebhookSignature(secret []byte, timestamp string, body []byte, signatureHeader string) bool {
    h := hmac.New(sha256.New, secret)
    h.Write([]byte(timestamp))
    h.Write([]byte("."))
    h.Write(body)
    expected := "sha256=" + hex.EncodeToString(h.Sum(nil))
    return hmac.Equal([]byte(signatureHeader), []byte(expected))
}
```

---

## 6. Supported Transports

The webhook dispatcher supports three transport schemes:

1. **Unix Domain Socket (`unix:/path/to.sock`)**:
   Delivers events over a local Unix domain socket using standard HTTP/1.1 framing.
   Zero network exposure; access is controlled via host filesystem DAC permissions.
2. **Mutual TLS (`https://host:port/path`)**:
   Enforces TLS 1.2+. Supports optional `ca_cert_path` for custom PKI bundles and
   `client_cert_path` / `client_key_path` for mTLS client authentication.
3. **Loopback HTTP (`http://127.0.0.1:<port>/path`)**:
   Plaintext HTTP is strictly permitted only for loopback IP addresses (`127.0.0.1`,
   `localhost`, `::1`). Plaintext HTTP to non-loopback destinations is rejected at startup.

---

## 7. Node Configuration

### Command-Line Flags (`agentmesh-node run`)

```bash
agentmesh-node run \
  --security-webhook-url="unix:/var/run/containment.sock" \
  --security-webhook-hmac-path="/etc/agentmesh/webhook-hmac.key" \
  --security-webhook-timeout="500ms" \
  --security-webhook-max-retries=3 \
  --security-webhook-queue-capacity=1024 \
  --security-webhook-coalescing-window="1s"
```

| Flag | Default | Description |
|---|---|---|
| `--security-webhook-url` | `""` | Destination endpoint URL (`unix:...`, `https://...`, `http://127.0.0.1:...`). |
| `--security-webhook-hmac-path` | `""` | File containing shared secret for HMAC-SHA256 signing. |
| `--security-webhook-ca-cert-path` | `""` | Path to CA certificate bundle for HTTPS server verification. |
| `--security-webhook-client-cert-path` | `""` | Path to client TLS certificate for mTLS. |
| `--security-webhook-client-key-path` | `""` | Path to client TLS private key for mTLS. |
| `--security-webhook-timeout` | `500ms` | Per-dispatch timeout for HTTP requests or socket writes. |
| `--security-webhook-max-retries` | `3` | Maximum delivery retry attempts for transient failures. |
| `--security-webhook-events` | `""` | Comma-separated list of event types to dispatch; empty dispatches all. |
| `--security-webhook-queue-capacity` | `1024` | Capacity of the non-blocking ring-buffer dispatch queue. |
| `--security-webhook-coalescing-window` | `1s` | Sliding deduplication window for repetitive signals. |

### YAML Configuration (`agentmesh-node.yaml`)

Under the `security_signals` section in `agentmesh-node.yaml`:

```yaml
version: "v1alpha1"

security_signals:
  enabled: true
  queue_capacity: 1024
  coalescing_window: "1s"
  endpoints:
    - url: "unix:/var/run/containment.sock"
      hmac_secret_path: "/etc/agentmesh/containment-hmac.key"
      timeout: "500ms"
      max_retries: 3
      event_types:
        - "agentmesh.policy.denied"
        - "agentmesh.transport.refused"
    - url: "https://siem.internal:8443/alerts"
      ca_cert_path: "/etc/agentmesh/ca.pem"
      client_cert_path: "/etc/agentmesh/client.crt"
      client_key_path: "/etc/agentmesh/client.key"
      timeout: "1s"
```

---

## 8. Observability & Prometheus Metrics

The dispatcher exports Prometheus counters, gauges, and histograms under the `agentmesh_containment_*` namespace:

| Metric | Type | Labels | Description |
|---|---|---|---|
| `agentmesh_containment_events_queued_total` | Counter | `signal_type` | Total number of security signal events enqueued to the ring buffer. |
| `agentmesh_containment_events_delivered_total` | Counter | `signal_type`, `status_code` | Total number of successfully delivered webhook requests, partitioned by HTTP status code. |
| `agentmesh_containment_events_dropped_total` | Counter | `signal_type`, `reason` | Total number of events dropped due to queue overflow, timeout, or transport failures. |
| `agentmesh_containment_events_coalesced_total` | Counter | `signal_type` | Total number of repetitive events coalesced within sliding windows. |
| `agentmesh_containment_delivery_duration_seconds` | Histogram | `signal_type` | Webhook HTTP delivery duration in seconds. |
| `agentmesh_containment_queue_depth` | Gauge | — | Current depth of the containment webhook ring buffer queue. |
