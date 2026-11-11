# Cloud IAM: Google Cloud Workload Identity Federation

Demonstrates how an agent outside Google Cloud (e.g. running on a developer's
laptop, in a Docker sandbox, or in an external cluster) securely calls a Google
Cloud API (Vertex AI Gemini) without storing any Google Cloud service account
keys inside the agent container.

## Architecture

```text
[ Agent / Caller ]
        │  POST /mesh/.../publishers/google/models/gemini*:generateContent
        │  (Presents task-scoped mesh credential; holds NO cloud keys)
        ▼
[ Agent Mesh Egress Node ] (PEP at boundary)
        │  1. Verifies mesh role & HTTP method/path policy
        │  2. Obtains short-lived federated token from Google STS (WIF)
        │  3. Injects Authorization: Bearer <federated-token>
        ▼
[ Google Cloud API (Vertex AI) ]
        │  Executes generateContent
        │  Emits Cloud Audit Log:
        │  principal://iam.googleapis.com/.../workloadIdentityPools/agentmesh/subject/<caller>
```

## Running the Example

```sh
./run.sh        # bring up the stack, execute test cases, assert audit logs
./run.sh down   # stop containers and remove generated tokens
```

## Verified Test Cases

The automated verification script asserts the following:

```text
== Egress to Vertex AI via Workload Identity Federation
  PASS  alice (role analyst) -> POST gemini generateContent              200
  PASS  bob (role restricted) -> POST gemini generateContent (policy)    403
  PASS  alice -> out-of-scope operation (blocked by path constraint)     403

== Refusals & Unauthenticated Access
  PASS  caller without credential                                        401
  PASS  caller with invalid token                                        401

== Cloud Audit Log Verification
  PASS  Cloud Audit Log captures federated principal: user:alice         found

== Credential Boundary Verification
  PASS  agent holds zero Google Cloud service account keys               0
```

## Audit Log and Identity Translation

1. **Exact Principal Attribution:** Rather than logging a generic shared service
   account, Cloud Audit Logs record the federated identity of the specific caller:
   `principal://iam.googleapis.com/projects/<PROJECT_NUM>/locations/global/workloadIdentityPools/agentmesh/subject/<caller>`
2. **Boundary Isolation:** Provider-side IAM permissions (e.g. `roles/aiplatform.user`)
   govern cloud access, while fine-grained method and path restrictions (e.g.
   disallowing model deletion or out-of-scope APIs) are enforced by the mesh egress
   policy before requests ever reach the cloud provider.
