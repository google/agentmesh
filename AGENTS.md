# SAM Repository AI Agent Guidelines

You are an expert software engineering assistant helping to develop, maintain, and test the **SAM** repository. 

## 1. Architecture & Component Independence
* **Decoupled Architecture:** The `sam-control-plane`, `sam-router` and `sam-node` components are strictly independent. They must not share internal state or tightly couple their logic.
* **API Communication:** All data communication between `sam-control-plane`, `sam-router` and `sam-node` must happen exclusively via the common API defined in `api/sam.proto`.
* **One schema, two encodings:** every request and response on any SAM-defined surface is a message in `api/sam.proto`. The *mesh protocol* — anything a mesh component speaks (node, router, the SDKs under `sdk/`): enrollment, refresh, keys, leases, auth streams, policy sync, token exchange (`/token/exchange`), and outbound border JWT minting (`/sts/token`) — is binary protobuf (`application/x-protobuf`). The *operator plane* — what humans, the web console and admin CLIs call (`/admin/*`, `/users/*`, `POST /policies`) — is protojson of the same messages, with `UseProtoNames` and unknown fields rejected. Never define a wire shape on a SAM-defined surface as a Go struct with `json` tags, an anonymous struct or `map[string]any`, and never serialize an `internal/storage` (or any other internal) type onto either surface. The sole exceptions are external standard protocols for unmodified third-party clients and cloud federation: OAuth 2.1 / RFC 8693 / RFC 7009 / RFC 9728 (`POST /oauth/token`, `POST /oauth/revoke`, `/oauth/authorize`, `/.well-known/*`, `/jwks`), Envoy `ext_authz` / `ext_proc`, MCP JSON-RPC (`/mcp`), OpenAI `/v1/*`, and A2A `/.well-known/agent-card.json`. Clients in `cmd/`, `internal/console` and `sdk/` import `api/` or its generated bindings only.
* **Instants are `google.protobuf.Timestamp`, named `*_time`** (`expire_time`, `sign_time`, `event_time`), never `int64` seconds or milliseconds. `Timestamp` has fixed units, an explicit unset, renders as RFC 3339 in protojson (an `int64` renders as a quoted decimal string), and has a first-class conversion in Go, JavaScript, Python and Dart. A receiver treats an unset instant as invalid, never as the epoch. The one exception is a proof-of-possession value: it is the number that appears in the signed text (`sam:<endpoint>:<peer_id>:<n>`), so it stays an `int64` named `challenge_unix_ms`, the unit in the name. What a member persists between runs is also a message here (`MemberCredential`), so a state directory written by one implementation loads in another.
* **Datalog text is the policy contract:** the control plane renders the mesh policy as Datalog rules (`PolicyConfigGetResponse.datalog_rules`); every member, in any language, adds that text to its authorizer and none derives rules from roles and bindings itself. Datalog must stay in the form every Biscuit implementation parses: a predicate carries at least one term (presence-only facts are `name(true)`, see `api.MarkerFact`).
* **Secrets never travel as flag values:** binaries read credentials from a file (`--*-path`) or the environment, never from a command-line argument that would sit in `ps` output and shell history. Banners and logs name the source of an operator-supplied secret instead of echoing it.
* **Task-Scoped Authorization & Safe Biscuit Attenuation (`tar_block`):** SAM acts as the Authority, Policy Decision Point (PDP), and Task-Scoped Credential Layer (`sts.md`). Never add Datalog rules or checks to non-authority Biscuit blocks (`block_idx >= 1`). Appended blocks must contain 0 rules, 0 checks, and exactly 1 `tar_block("<base64url-proto>")` fact encoding a serialized `api.TaskAuthorizationRule`. Verifiers enforce the intersection of Block 0 Datalog RBAC and every appended `TaskAuthorizationRule` in Go, TypeScript, and Python.
* **Two-Token Model & Complementary Gateway/PEP Integration:** Inside the mesh, credentials are Biscuits; at both borders, credentials are standard JWTs (`sts.md`). Inbound platform credentials (OIDC, K8s SA, SPIFFE JWT-SVID) exchange into delegated Biscuits (`POST /token/exchange`); outbound verified Biscuits mint short-lived ES256 JWTs at the control plane (`POST /sts/token`) that the egress node exchanges at cloud STS endpoints (`CloudTokenExchanger`). `sam-node` integrates with existing gateways (`agentgateway`, Istio, Envoy) via Envoy `ext_authz` / `ext_proc` and RFC 8693 `/oauth/token`, while native SDKs (`sdk/js`, `sdk/python`) attenuate and seal Biscuits in memory.
* **Policy on Names:** egress policy, secret injection and routing decisions are made on the destination *name*, never on an IP. Deny by default.
* **Zero Trust:** Enforce a Zero Trust architecture. Assume no implicit trust between nodes, control planes, routers, or external actors. All data passing through the API must be authenticated, authorized, and validated.
* **Simple UX:** Maintain a very simple User Experience. Configuration, CLI usage, and error messages must be intuitive, minimal, and explicitly clear.

## 2. Dependency Management (Strict Constraint)
* **You are forbidden from suggesting any code that requires a new entry in `go.mod` unless you explicitly ask for my permission first.**
* If a task can be solved using the existing dependencies or the Go standard library, you must choose that path even if it requires more lines of code.

## 3. Testing Best Practices
Enforce strict modularity in testing. The repository uses a defined testing pyramid (Unit, Integration, and E2E via Bats). You must adhere to the following testing philosophy:
* **Optimize for Test Speed:** E2E tests are slow and strictly based on existing Critical User Journeys (CUJs). 
* **Push Coverage Down:** If test coverage for a specific edge case or feature can be added at a lower level (Unit or Integration), it is strictly preferred over E2E for speed. 
* **No Redundancy:** Do not replicate a test in the slower E2E path if it is already sufficiently covered in the Integration path.
* **Test Domains:**
  * **Unit Tests:** Focus on isolated, internal functions.
  * **Integration Tests (`tests/integration/`):** Verify module interactions and API compliance in Go and those are time bounded, no more than 10 seconds per execution.
  * **E2E Tests (`tests/e2e/*.bats`):** Use Bats (Bash Automated Testing System) exclusively for high-level, black-box testing of core CUJs.

## 4. Code Quality & Modularity
* Ensure all new code is highly modular, prioritizing small, single-responsibility functions that are easy to unit test.
* Respect the existing repository structure (`cmd/`, `api/`, `internal/`, `tests/`).

## 5. Validation

* Ensure binaries build using `make`
* Ensure linter passes `make lint`
* Ensure test passes `make test`
* Ensure e2e test passes `make e2e-test`

## 6. Environments
* There are two public testnets available `hub.sam-mesh.dev` that is deployed from the latest released tag and `bananas.sam-mesh.dev` that is deployed from the `main` branch. 
* Their configurations can be found under `.github/k8s`.
* Their deployments are managed under `.github/workflows/deploy.yaml`.
