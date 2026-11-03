---
title: "Google APIs with a federated credential"
linkTitle: "Google Cloud credentials"
weight: 3
description: "Give mesh members access to Google APIs through an egress node that exchanges the control plane's token at Google STS. No Google credential is stored anywhere."
---

A member of the mesh calls a Google API: Gemini on Vertex AI, an agent on
Agent Engine, BigQuery, or Cloud Storage. This guide puts an `agentmesh-node`
in front of the API as the enforcement point. Workload Identity Federation
supplies the credential.

The node authorizes each request on the caller, the method and the path.
Then the node mints a short-lived token at the control plane, exchanges it
at Google STS, and injects the Google access token. No service account key
exists. The member holds no Google credential.

A runnable local example with an automated verification script and audit-log
checks is available under [development/examples/cloud-iam/](https://github.com/google/agentmesh/tree/main/development/examples/cloud-iam).

How it works:

```text
member     POST /mesh/<serving peer>/egress/aiplatform.googleapis.com/v1/.../gemini-2.5-flash:generateContent
           X-Mesh-Authentication: ****** member's Biscuit>
node       authorizes: role grants egress://aiplatform.googleapis.com, POST, this path
           POST <control plane>/sts/token            -> ES256 JWT: iss=<control plane>, sub=<member>, aud=<WIF provider>
           POST https://sts.googleapis.com/v1/token  -> federated token
           POST iamcredentials ...:generateAccessToken (impersonate) -> access token
           POST https://aiplatform.googleapis.com/v1/.../gemini-2.5-flash:generateContent
           Authorization: ****** token>
```

You need a control plane that Google can reach over HTTPS, at
`/.well-known/openid-configuration` and `/jwks`. You need a node that
serves the destination. You need a Google Cloud project where you can
create a Workload Identity Pool and a service account. The [Cloud Run
guide](/docs/guides/cloud-run/) gives you such a control plane.

## 1. Trust the control plane in Google Cloud

The control plane is an OIDC issuer. Its issuer URL must use `https`.
Behind a TLS-terminating proxy such as Cloud Run, the control plane does
not take the scheme from forwarded headers. Give it the public URL:
`--external-url=https://<hub>.run.app` on `agentmesh-one`, or
`--sts-issuer-url` on `agentmesh-control-plane`. Check the issuer with:

```bash
curl -sS https://<hub>.run.app/.well-known/openid-configuration | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["issuer"], d["jwks_uri"])'
```

Create the pool, the provider and the service account. The allowed
audience of the provider is its own resource name. The control plane puts
that name in `aud`.

```bash
PROJECT=<project>
PN=$(gcloud projects describe $PROJECT --format='value(projectNumber)')
HUB=https://<hub>.run.app
gcloud services enable sts.googleapis.com iamcredentials.googleapis.com aiplatform.googleapis.com --project $PROJECT

gcloud iam workload-identity-pools create agentmesh --project $PROJECT --location global
AUD="//iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/agentmesh/providers/hub-cp"
gcloud iam workload-identity-pools providers create-oidc hub-cp --project $PROJECT --location global \
  --workload-identity-pool agentmesh --issuer-uri "$HUB" --allowed-audiences "$AUD" \
  --attribute-mapping "google.subject=assertion.sub,attribute.actor=assertion.act.sub"

gcloud iam service-accounts create mesh-gemini --project $PROJECT
SA=mesh-gemini@$PROJECT.iam.gserviceaccount.com
gcloud projects add-iam-policy-binding $PROJECT --member serviceAccount:$SA --role roles/aiplatform.user --condition None
gcloud iam service-accounts add-iam-policy-binding $SA --project $PROJECT --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/agentmesh/*"
```

The last binding lets every identity that the control plane authenticates
impersonate the service account. The mesh policy decides which members
reach the destination, and with which methods and paths. To narrow the
binding on the Google side as well, map a claim to an attribute
(`attribute.role=assertion.mesh_roles[0]`). Then bind
`principalSet://.../attribute.role/<role>` instead of `*`.

The `sub` claim in the token is the principal of the member: a SPIFFE ID
for a workload, or `user:<email>` for a person. The `act.sub` claim is the
peer ID of the node that served the request. Google STS maps `sub` to
`google.subject`; the attribute mapping above keeps `act.sub` as
`attribute.actor`.

## 2. Write the policy

The `egress` entry names the destination, the nodes that serve it, and the
federation. The role lists the destination and narrows it to the method
and the path:

```json
{
  "roles": [
    {"name": "mesh:role:node", "allowed_services": ["*"], "allowed_publish": ["*"], "allowed_targets": ["*"], "allowed_labels": ["*"]},
    {"name": "mesh:role:router", "allowed_services": ["*"], "allowed_targets": ["*"]},
    {"name": "sandbox",
     "allowed_services": ["system://mesh.catalog", "egress://aiplatform.googleapis.com"],
     "allowed_targets": ["*"],
     "http": [{"service": "egress://aiplatform.googleapis.com", "methods": ["POST"],
               "paths": ["/v1/projects/<project>/locations/us-central1/publishers/google/models/*"]}]}
  ],
  "bindings": [
    {"role": "sandbox", "members": ["user:spiffe://openshell.local/openshell/sandbox/*"]}
  ],
  "egress": [
    {"name": "aiplatform.googleapis.com",
     "served_by": ["site=office"],
     "broker": {"oidc_federation": {
       "token_endpoint": "https://sts.googleapis.com/v1/token",
       "audience": "//iam.googleapis.com/projects/<project number>/locations/global/workloadIdentityPools/agentmesh/providers/hub-cp",
       "impersonate": "mesh-gemini@<project>.iam.gserviceaccount.com",
       "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}}}
  ]
}
```

- `served_by` selects the nodes by role or label. Each selected node logs
  `[Egress] Serving egress://aiplatform.googleapis.com` when it takes the
  assignment.
- APIs that do not accept the federated principal directly need
  `impersonate`. Vertex AI is one of them.
- `paths` is a prefix match under the destination. The grant above allows
  every publisher model in one region. It allows no other path on the host.
- One hostname can serve more than one product. `aiplatform.googleapis.com`
  serves Gemini (`publishers/google/models/*`) and Agent Engine
  (`reasoningEngines/*`). A role has one `http` entry per service. To grant
  both, put both paths in the `paths` list of that entry.

Push the policy with `POST /policies` and the admin token, or through the
Cloud Run secret. The nodes log the assignment within their sync interval.

## 3. Call the API

Send the request from the node of a member, with the credential of that
member. Address the serving node by peer ID:

```bash
PEER=<peer id of a node that serves the destination>
curl -sS -H "X-Mesh-Authentication: ******" -H "Content-Type: application/json" \
  "http://127.0.0.1:8080/mesh/$PEER/egress/aiplatform.googleapis.com/v1/projects/<project>/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent" \
  -d '{"contents":[{"role":"user","parts":[{"text":"Answer with one word: what is 2+3?"}]}]}'
```

Gemini returns the answer. A `GET` on the same path returns `403` with
`Proxy-Status: agentmesh-node; error=http_request_denied`. A `POST` to
`/v1/projects/<project>/locations/us-central1/endpoints` returns the same
`403`.

The serving node writes one line per decision:

```text
Audit Traceability {"target": "egress://aiplatform.googleapis.com", "method": "POST",
  "path": "/v1/projects/<project>/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
  "host": "aiplatform.googleapis.com", "port": 443, "decision": "allow",
  "user": "spiffe://openshell.local/openshell/sandbox/0e4e35e4-…", "role": "sandbox", "actor_node": "12D3KooW…"}
Audit Traceability {"target": "egress://aiplatform.googleapis.com", "method": "GET", ..., "decision": "deny",
  "reason": "biscuit: denied by no matching policies"}
```

The control plane logs the `/sts/token` request. The Google audit log shows
one `GenerateAccessToken` on the service account for each new token, with
`lifetime: 300s`. That entry names the service account. The identity of
the member is in the audit line of the node.

## 4. From a sandbox

An OpenShell sandbox or a Substrate actor reaches the destination through
its edge node (see [OpenShell or Substrate](/docs/guides/openshell-and-substrate/)).
The enforcement point of the runtime injects the Biscuit of the member. The
edge node forwards the request to the serving node. The allowlist of the
runtime must permit the path `/mesh/**` on the edge node. The examples
permit it. `make gemini NAME=<sandbox> GCP_PROJECT=<project>` in each
example runs the three requests above from inside the sandbox or the actor.

## Limits

- The node caches the Google token per caller credential. An entry is valid
  for at most the lifetime of the token that the node minted at the control
  plane, 5 minutes by default. Then the node performs the exchange again. A
  change of the role of a member takes effect at the next mesh credential of
  that member, as for any destination.
- A `TaskAuthorizationRule` on the Biscuit of the caller narrows `scopes`,
  methods and paths further. It cannot widen them.
- The destination is one hostname. See [Egress
  destinations](/docs/guides/egress-destinations/) for the general limits.
