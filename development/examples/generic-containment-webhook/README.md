# Generic Containment Webhook Blueprint

A runnable, pure Go reference implementation of an out-of-band security containment webhook receiver for [Google Agent Mesh](https://github.com/google/agentmesh) ([Issue #879](https://github.com/google/agentmesh/issues/879)).

This blueprint demonstrates how external supervisors—such as **Kubernetes container controllers**, **OpenShell / gVisor sandbox supervisors**, **host security daemons (e.g., KillSwitch)**, or **enterprise SIEMs**—receive, authenticate, and process real-time security signals emitted by `agentmesh-node` and `agentmesh-control-plane`.

---

## 1. Architecture Overview

Agent Mesh components enforce Zero Trust and task-scoped authorization. When an uncooperative agent, compromised sandbox, or malicious peer attempts an unauthorized action, `agentmesh-node` and `agentmesh-control-plane` emit asynchronous, non-blocking security signals across an out-of-band containment webhook:

```
                      +---------------------------------------+
                      |       google/agentmesh Components     |
                      |                                       |
                      |  +---------------------------------+  |
                      |  | agentmesh-node / control-plane  |  |
                      |  |  - Biscuit / TAR Authorizer     |  |
                      |  |  - Inspection (ModelArmor/Proc) |  |
                      |  |  - libp2p Stream Auth Gate      |  |
                      |  |  - Ban / Revocation Sync        |  |
                      |  |  - /enroll and /refresh Handler |  |
                      |  +----------------+----------------+  |
                      |                   | (rejections)      |
                      |                   v                   |
                      |  +---------------------------------+  |
                      |  | internal/containment Dispatcher |  |
                      |  |  - Bounded Ring Buffer Queue    |  |
                      |  |  - Per-(Signal,Peer) Coalescer  |  |
                      |  |  - Promauto Metrics & Logger    |  |
                      |  |  - HMAC-SHA256 Signer           |  |
                      |  |  - Unix / Loopback HTTP Client  |  |
                      |  +----------------+----------------+  |
                      +-------------------|-------------------+
                                          |
                        CloudEvents 1.0   | (unix:/path.sock OR
                        HMAC Signed       |  http://127.0.0.1:port)
                        ProtoJSON         |
                                          v
                      +---------------------------------------+
                      |      Generic Containment Webhook      |
                      | (development/examples/generic-.../)   |
                      |  - Validates CloudEvents 1.0 headers  |
                      |  - Validates HMAC-SHA256 signatures   |
                      |  - Deserializes protojson event       |
                      |  - Pretty-prints structured alert     |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |     External Containment Actions      |
                      |  * K8s Controller: isolate Pod        |
                      |  * OpenShell: freeze sandbox cgroups  |
                      |  * Host Daemon: terminate process     |
                      |  * SIEM: trigger SOC incident alert   |
                      +---------------------------------------+
```

### Supported Signal Types

The webhook handles the 4 core Agent Mesh security transitions defined in `api/agentmesh.proto`:

| Signal Type | Emitting Component | Trigger Condition |
| :--- | :--- | :--- |
| `agentmesh.policy.denied` | `agentmesh-node` | Biscuit Datalog check failed, Task Authorization Rule (`tar_block`) narrowed access, or Inspection filter blocked request. |
| `agentmesh.transport.refused` | `agentmesh-node` | libp2p auth gate refused unauthenticated peer, invalid router role, or banned peer stream. Coalesced over sliding window. |
| `agentmesh.identity.revoked` | `agentmesh-control-plane` & `agentmesh-node` | Peer banned mesh-wide or Biscuit revocation IDs broadcast via gossip / sync. |
| `agentmesh.enrollment.rejected` | `agentmesh-control-plane` | Token validation failed, bootstrap token expired, or autonomous recovery rejected. |

---

## 2. Quickstart

### Prerequisites

- Go 1.26 or higher
- Cloned `google/agentmesh` repository

### Running the Webhook Receiver

The receiver uses **only the Go standard library** and the existing `api` protobuf bindings in the repository. It introduces **zero new entries** to `go.mod` or `go.sum`.

#### Option A: Local TCP HTTP Mode (Default: Port 8095)

```bash
go run ./development/examples/generic-containment-webhook -port 8095
```

Output:
```
HMAC signature verification disabled (no -hmac-secret-path provided)
Listening for containment signals on HTTP http://127.0.0.1:8095/events
Generic Containment Webhook receiver ready. Press Ctrl+C to exit.
```

#### Option B: Unix Domain Socket Mode (High-Performance Local Isolation)

```bash
go run ./development/examples/generic-containment-webhook \
  -port 0 \
  -socket-path /tmp/agentmesh-containment.sock
```

#### Option C: With HMAC-SHA256 Signature Verification

To enforce cryptographic integrity and anti-tampering between the node and the webhook supervisor, supply a shared secret file:

```bash
# Generate a random 32-byte secret key
openssl rand -hex 32 > /tmp/containment-hmac.key
chmod 600 /tmp/containment-hmac.key

# Start the webhook receiver with HMAC verification
go run ./development/examples/generic-containment-webhook \
  -port 8095 \
  -hmac-secret-path /tmp/containment-hmac.key \
  -verbose
```

### CLI Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-port` | `8095` | Local TCP port for HTTP webhook receiver (`0` to disable TCP). |
| `-socket-path` | `""` | Unix domain socket path for webhook receiver (e.g. `/tmp/containment.sock`). |
| `-hmac-secret-path` | `""` | File containing shared secret for HMAC-SHA256 signature verification. |
| `-verbose` | `false` | Pretty-prints the complete raw ProtoJSON payload in addition to formatted summary. |
| `-no-color` | `false` | Disables ANSI terminal colors (also respects `NO_COLOR=1` environment variable). |

---

## 3. Configuring `agentmesh-node`

To direct `agentmesh-node` to forward containment events to the webhook, pass `--security-webhook-*` flags on startup:

### Connecting via Local HTTP

```bash
./bin/agentmesh-node run \
  --control-plane https://mesh.example.com \
  --security-webhook-url http://127.0.0.1:8095/events \
  --security-webhook-hmac-path /tmp/containment-hmac.key \
  --security-webhook-events agentmesh.policy.denied,agentmesh.identity.revoked \
  --security-webhook-timeout 500ms \
  --security-webhook-max-retries 3 \
  --security-webhook-queue-capacity 1024 \
  --security-webhook-coalescing-window 1s
```

### Connecting via Unix Domain Socket

For tight, container-local or host-local execution, Unix domain sockets avoid TCP port allocation and bypass network stack overhead:

```bash
./bin/agentmesh-node run \
  --control-plane https://mesh.example.com \
  --security-webhook-url unix:///tmp/agentmesh-containment.sock \
  --security-webhook-hmac-path /tmp/containment-hmac.key
```

---

## 4. Testing with `curl` & Sample Events

You can test the webhook receiver directly using `curl`. Each example conforms strictly to the CloudEvents 1.0 specification and `api.SecuritySignalEvent` protojson schema.

### 1. Test `agentmesh.policy.denied` (Authorization Failure)

```bash
curl -X POST http://127.0.0.1:8095/events \
  -H "Content-Type: application/json" \
  -H "ce-specversion: 1.0" \
  -H "ce-id: b9b0d1e2-3f4a-4a5b-8c6d-7e8f9a0b1c2d" \
  -H "ce-type: agentmesh.policy.denied" \
  -H "ce-source: urn:agentmesh:node:12D3KooWNodeDemo12345" \
  -H "ce-time: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  -H "ce-subject: peer-finance-analyzer" \
  -d '{
    "id": "b9b0d1e2-3f4a-4a5b-8c6d-7e8f9a0b1c2d",
    "source": "urn:agentmesh:node:12D3KooWNodeDemo12345",
    "spec_version": "1.0",
    "type": "agentmesh.policy.denied",
    "subject": "peer-finance-analyzer",
    "event_time": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "data_content_type": "application/json",
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
      "event_time": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'"
    }
  }'
```

Receiver Output:
```
================================================================================
[SECURITY SIGNAL RECEIVED] Type: agentmesh.policy.denied (via 127.0.0.1:54321)
--------------------------------------------------------------------------------
  ID:              b9b0d1e2-3f4a-4a5b-8c6d-7e8f9a0b1c2d
  Source:          urn:agentmesh:node:12D3KooWNodeDemo12345
  SpecVersion:     1.0
  Subject:         peer-finance-analyzer
  Event Time:      2026-11-10T23:00:00Z (2ms ago)
--------------------------------------------------------------------------------
  PolicyDeniedSignal:
    Direction:           LOCAL_WORKLOAD
    Reason:              DATALOG_EVALUATION_DENIED
    Detail:              datalog block 0 denied egress to unauthorized database
    Target Service:      bigquery
    Requested Op:        POST
    Requested Res:       //bigquery.googleapis.com/projects/prod-ledger
    Caller Peer ID:      12D3KooWCallerDemo67890
    Caller Subject:      spiffe://example.org/ns/prod/sa/analytics-agent
    Caller Roles:        agent, reader
    Caller Labels:       env=production, tier=restricted
================================================================================
```

### 2. Test `agentmesh.transport.refused` (Connection Gate Refusal)

```bash
curl -X POST http://127.0.0.1:8095/events \
  -H "Content-Type: application/json" \
  -H "ce-specversion: 1.0" \
  -H "ce-id: 3c2a1b0f-8e7d-6c5b-4a3b-2c1d0e9f8a7b" \
  -H "ce-type: agentmesh.transport.refused" \
  -H "ce-source: urn:agentmesh:node:12D3KooWNodeDemo12345" \
  -H "ce-time: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  -d '{
    "id": "3c2a1b0f-8e7d-6c5b-4a3b-2c1d0e9f8a7b",
    "source": "urn:agentmesh:node:12D3KooWNodeDemo12345",
    "spec_version": "1.0",
    "type": "agentmesh.transport.refused",
    "event_time": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "data_content_type": "application/json",
    "transport_refused": {
      "reason": "PEER_UNAUTHENTICATED",
      "detail": "peer handshake deadline exceeded before completing TLS auth",
      "peer_id": "12D3KooWAttacker99999",
      "remote_multiaddr": "/ip4/198.51.100.42/tcp/49152",
      "protocol_id": "/agentmesh/auth/1.0.0",
      "coalesced_count": 5,
      "first_seen_time": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
      "event_time": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'"
    }
  }'
```

### 3. Test `agentmesh.identity.revoked` (Peer Banishment)

```bash
curl -X POST http://127.0.0.1:8095/events \
  -H "Content-Type: application/json" \
  -H "ce-specversion: 1.0" \
  -H "ce-id: fa1a2b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c" \
  -H "ce-type: agentmesh.identity.revoked" \
  -H "ce-source: urn:agentmesh:control-plane:cp-primary-0" \
  -H "ce-time: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  -d '{
    "id": "fa1a2b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
    "source": "urn:agentmesh:control-plane:cp-primary-0",
    "spec_version": "1.0",
    "type": "agentmesh.identity.revoked",
    "event_time": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'",
    "data_content_type": "application/json",
    "identity_revoked": {
      "peer_id": "12D3KooWCompromisedAgent456",
      "source": "CONTROL_PLANE_ADMIN",
      "reason": "Administrative eviction following host sandbox compromise",
      "revocation_ids": ["0a1b2c3d4e5f6a7b8c9d0e1f"],
      "issuer_peer_id": "12D3KooWControlPlaneMaster",
      "event_time": "'$(date -u +'%Y-%m-%dT%H:%M:%SZ')'"
    }
  }'
```

### 4. Test HMAC-SHA256 Authenticated Request

When HMAC verification is enabled on the receiver (`-hmac-secret-path`), every request must supply `X-AgentMesh-Timestamp` (milliseconds since Unix epoch) and `X-AgentMesh-Signature` (`sha256=<hex>` over `timestamp + "." + body`):

```bash
SECRET="my-super-secret-hmac-key-12345"
echo -n "${SECRET}" > /tmp/hmac.key

# Start server in background
go run ./development/examples/generic-containment-webhook \
  -port 8095 \
  -hmac-secret-path /tmp/hmac.key &

# Prepare payload
TS=$(python3 -c 'import time; print(int(time.time() * 1000))')
BODY='{"id":"test-1","source":"test","spec_version":"1.0","type":"agentmesh.identity.revoked","identity_revoked":{"peer_id":"12D3KooWBanned","reason":"compromised"}}'

# Calculate signature: sha256=<hmac_sha256(secret, timestamp + "." + body)>
SIG=$(python3 -c "
import hmac, hashlib
msg = f'${TS}.${BODY}'.encode('utf-8')
key = b'${SECRET}'
print('sha256=' + hmac.new(key, msg, hashlib.sha256).hexdigest())
")

# Send signed request
curl -i -X POST http://127.0.0.1:8095/events \
  -H "Content-Type: application/json" \
  -H "ce-specversion: 1.0" \
  -H "ce-id: test-1" \
  -H "ce-type: agentmesh.identity.revoked" \
  -H "ce-source: test" \
  -H "X-AgentMesh-Timestamp: ${TS}" \
  -H "X-AgentMesh-Signature: ${SIG}" \
  -d "${BODY}"
```

---

## 5. External Consumer Architecture Notes

The generic security signals contract is deliberately runtime-agnostic. Below are architectural blueprints for four common external consumer environments:

### Pattern A: Kubernetes Admission & Container Controllers

In a Kubernetes deployment, `agentmesh-node` runs either as a DaemonSet or as a sidecar container alongside agent workloads. A dedicated **Containment Controller** (or admission webhook) listens for security signals:

1. **Deployment**:
   - The controller exposes an internal HTTPS Service: `https://containment-controller.agentmesh.svc.cluster.local:8443/events` (secured with mTLS or cluster CA; plaintext HTTP to non-loopback destinations is rejected by anti-SSRF policy).
   - Alternatively, it shares a hostPath/emptyDir Unix domain socket (`unix:///run/agentmesh/containment.sock`) or binds to pod-local loopback (`http://127.0.0.1:8095/events`) with the `agentmesh-node` pod.
2. **Action Trigger**:
   - On `agentmesh.identity.revoked` or repeated `agentmesh.policy.denied` signals:
     - The controller translates `caller_subject` (e.g., `spiffe://cluster.local/ns/agent-apps/sa/rag-bot`) to the offending Pod.
     - Adds a label to the Pod: `quarantine: "true"`.
     - Applies a dynamic `NetworkPolicy` blocking all egress from pods with `quarantine: "true"`.
     - Evicts or deletes the compromised Pod via the Kubernetes API:
       ```go
       clientset.CoreV1().Pods(ns).Delete(ctx, podName, metav1.DeleteOptions{})
       ```

### Pattern B: OpenShell & gVisor Sandbox Supervisors

In an OpenShell or gVisor sandbox environment (`development/examples/openshell-sandbox/`), agent workloads run inside unprivileged micro-VMs or virtualized user-space kernels:

1. **Deployment**:
   - The sandbox supervisor mounts a Unix domain socket `/run/agentmesh/containment.sock`.
   - `agentmesh-node` is configured with `--security-webhook-url unix:///run/agentmesh/containment.sock`.
2. **Action Trigger**:
   - On receiving an out-of-band `agentmesh.policy.denied` signal indicating lateral traversal or unauthorized tool access:
     - The supervisor freezes container execution immediately using cgroups v2:
       ```bash
       echo "1" > /sys/fs/cgroup/openshell/sandbox-123/cgroup.freeze
       ```
     - Revokes the sandbox's SPIRE Workload API token, preventing it from obtaining any new mesh credentials.
     - Shuts down the container boundary cleanly.

### Pattern C: Host Security Daemons (e.g., KillSwitch, Falco, Wazuh)

When agents run on enterprise workstations or dedicated servers, a host security daemon monitors both OS system calls and mesh application-layer transitions:

1. **Deployment**:
   - The host daemon creates `/var/run/containment/security.sock` with root/owner permissions.
   - `agentmesh-node` connects to the socket with `--security-webhook-url unix:///var/run/containment/security.sock`.
2. **Action Trigger**:
   - Correlates application-layer denials (`agentmesh.policy.denied`) with host eBPF / auditd system call events (e.g. unexpected socket connect or subprocess spawning).
   - Enforces host-level isolation:
     - Inserts dynamic `nftables` / `iptables` drop rules for the agent process UID.
     - Sends `SIGSTOP` or `SIGKILL` to uncooperative agent processes.
     - Revokes any task Biscuit held by the sandbox via `POST /oauth/revoke` on the local `agentmesh-node` Unix socket.

### Pattern D: Enterprise SIEM & SOC Observability (Splunk, Elastic, Datadog)

For centralized monitoring and compliance auditing:

1. **Deployment**:
   - The webhook receiver runs as an ingestion adapter or serverless function.
2. **Action Trigger**:
   - Enriches the CloudEvents envelope with infrastructure metadata (cloud account, region, host ID).
   - Maps `PolicyDeniedSignal` and `TransportRefusedSignal` fields into standard OpenTelemetry / Elastic Common Schema (ECS) format:
     - `event.category`: `intrusion_detection`
     - `event.action`: `policy_denial`
     - `user.id`: `caller_subject`
   - Emits alerts to PagerDuty or Slack when revocation rates exceed thresholds.

---

## 6. Verification and Testing

To verify this blueprint independently:

1. **Compile and Type-Check**:
   ```bash
   go build -v ./development/examples/generic-containment-webhook/...
   ```

2. **Verify Zero Dependency Additions**:
   ```bash
   git diff go.mod go.sum
   ```
   *Expected output: Empty (no changes to root go.mod or go.sum).*
