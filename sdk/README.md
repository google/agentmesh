# Native SDKs

This directory holds the SDKs that let an agent join a SAM mesh from inside
its own process, without a `sam-node` sidecar. Two languages are in scope:

- [`js/`](js/) — `@sam-mesh/sdk`, TypeScript for Node.js, built on
  [js-libp2p](https://github.com/libp2p/js-libp2p).
- [`python/`](python/) — `sam-mesh` (import `agent_mesh`), built on
  [py-libp2p](https://github.com/libp2p/py-libp2p).

The motivation is [issue #480](https://github.com/google/sam/issues/480). The
sidecar works, but it makes every agent deployment manage a second process,
a local port and a token, which does not fit serverless platforms and splits
tracing between the agent and the network layer. An earlier attempt at a
Python package (`sam-mcp-python`) only wrapped the sidecar's HTTP API and was
removed in favour of this work.

Both SDKs speak the mesh protocol directly. There is no SDK-specific
endpoint anywhere in the mesh; a member built with an SDK is, to every other
member and to the control plane, a peer like a `sam-node`.

An SDK member is an agent, not a service provider. It calls what the mesh
offers: MCP tools, inference and A2A services that `sam-node`s publish and
the discovery table names. Inbound, it accepts one thing: A2A requests for
itself, as `a2a://<name>`, reached by peer ID through a router. It publishes
no service, writes no provider record and reports no catalog; a tool, a
model or a named agent that others should find by name runs behind a
`sam-node`. The reasons are in [Agents, not services](#agents-not-services).

## What exists today

Milestones 1 to 5 are implemented and tested in both languages:

| Capability | JS | Python |
| --- | --- | --- |
| ed25519 identity, libp2p key encodings, peer ID | yes | yes |
| Enrollment with a bootstrap token (`POST /enroll`, `GET /enroll/status` polling) | yes | yes |
| Enrollment with an OIDC token (`POST /register`) | yes | yes |
| Credential refresh (`POST /refresh`), also in the background while joined | yes | yes |
| Signed key-set sync (`GET /keys`) | yes | yes |
| Persisted state (identity and credential, owner-only files; IndexedDB in a browser) | yes | yes |
| Biscuit verification of a peer's credential (signature, expiry, peer binding, roles, labels) | yes | yes |
| libp2p host as `sam-node` configures it (TCP and WebSocket, TLS first and Noise, yamux) | yes | yes |
| `/sam/auth/1.0.0`, both sides; join = handshake with a router and check its role | yes | yes |
| Circuit relay v2 reservation on the router; dial and accept through it | yes | yes |
| Service discovery in the mesh DHT (`/sam/kad/1.0.0`) | yes | yes |
| `/sam/mcp/1.0.0` client: list and call a provider's tools, or its catalog | yes | yes |
| Caller-side label requirements on the provider's credential | yes | yes |
| `/libp2p-http` client: call inference and A2A services on the mesh; response bodies stream | yes | yes |
| The mesh as a transport for HTTP clients: `session.fetch()` for fetch-based clients, `MeshTransport` for httpx, so the official A2A SDK's client works unchanged | `fetch` | httpx |
| Provider authorizer: the baseline Datalog and the mesh policy (`GET /policies`), evaluated as `sam-node` does | yes | yes |
| A2A ingress for the agent: `/libp2p-http` for `a2a://<name>`, forwarded to an A2A server beside the process or answered in it; not announced anywhere | yes | yes |
| Control plane pull before join and on `sam-node`'s interval: `/keys` verified against the trusted set, credential refresh after a rotation, `/info` bans and router addresses | yes | yes |
| Gossip events from the control plane (`/sam/mesh/events/v1`, StrictSign): ban enforced at once, key rotation adopted, policy update pulls | yes | yes |
| Banned peers refused: connections dropped and denied, handshakes and requests refused, dials refused | yes | yes |
| Runs in a browser page: WebSocket and Noise to the router, state in IndexedDB, the agent answered by a fetch handler; `sdk/js/examples/browser` against `sam-one`, tested in Chromium | yes | — |
| Published to a registry from the release workflow | npm `@sam-mesh/sdk` | PyPI `sam-mesh` |

A member built this way is on the mesh and uses it in both directions: it
finds a service in the DHT and calls it through the router, verifying the
provider on every call, and it answers A2A requests for its own agent from
a `sam-node` or another SDK member that names it by peer ID, authorizing
every caller with the same Datalog the Go node evaluates. It follows the
control plane while it runs: a ban reaches it as a gossip event within a
second and again with the next pull, and a key rotation makes it refresh
its credential under the new key.

Facts about the libp2p implementations that the SDKs work around, each
pinned by a test:

- py-libp2p's TLS transport advertises early muxer negotiation in ALPN but
  cannot complete it (Python's `ssl` has no ALPN select callback), and
  go-libp2p then refuses the mux upgrade. The Python host sets no ALPN
  muxer list, so the muxer is negotiated with multistream-select
  (`sdk/python/src/agent_mesh/host.py`).
- js-libp2p's `@libp2p/tls` reads the libp2p extension from
  `extensions[0]` of the peer certificate. py-libp2p's default certificate
  puts BasicConstraints and KeyUsage first, so the Python host uses a
  certificate template with only the libp2p extension.
- A router grants a relay reservation only after the auth handshake on
  the same connection, and drops it with the connection. The Python SDK
  carries the relay protocol itself (`sdk/python/src/agent_mesh/relay.py`,
  `sdk/python/proto/circuit.proto`) on top of py-libp2p's raw-connection
  upgrade, so the session decides when to reserve, renew and, after a
  dropped connection, authenticate and reserve again; py-libp2p's own
  `RelayDiscovery` reserves again only after the expiry has passed, when
  the router has already dropped the slot.
- go-libp2p's relay leaves private addresses out of a reservation, so a
  router on loopback (every test) grants a reservation that lists no
  address. js-libp2p falls back to the connection's address; the Python SDK
  does the same.
- js-libp2p reserves a relay slot when it starts listening on
  `<relay>/p2p-circuit`, and a router refuses that before the auth
  handshake. The JS SDK starts the listener after the handshake, through the
  transport manager, which is not on the public `Libp2p` interface
  ([libp2p/js-libp2p#3645](https://github.com/libp2p/js-libp2p/issues/3645)).
- go-libp2p's relay grants a reservation for one hour and drops it when
  that passes, and with the connection it was made on; a member that still
  advertises the relayed address is then unreachable (`NO_RESERVATION`).
  js-libp2p's listener renews on its own, but only on a connection the
  router still holds the admission of, and does not reserve again on a
  static relay after the connection dropped
  ([libp2p/js-libp2p#3601](https://github.com/libp2p/js-libp2p/issues/3601));
  the JS SDK runs the handshake again on every new connection to a router
  and, when the relayed address is gone, authenticates and reserves again
  within thirty seconds. The Python
  SDK renews two minutes before the expiry the router returned, and within
  thirty seconds of the connection to that router going, running the auth
  handshake again first.
- py-libp2p's yamux gives a stream's backlog slot (256 per connection) back
  when the stream closes since 0.8, but not for the `trio.Cancelled` of a
  caller's deadline while the SYN waits on a stalled connection. Every
  stream the SDK opens goes through `open_stream`, which bounds
  `new_stream` with the caller's deadline and hangs up on a connection that
  cannot open a stream in time, so the call fails instead of parking and
  the slots go with the connection.
- py-libp2p's yamux drops a reset stream's bookkeeping once its buffer is
  drained, and a bounded read then reports the end of the stream. The
  Python `/libp2p-http` client reads the muxed stream's reset flag on EOF,
  so a body cut by a reset is an error and not a body that ended.
- py-libp2p's WebSocket transport resolves a `/dns4/<host>/tcp/443/wss`
  address to its IP before dialing and names the IP in the TLS SNI and the
  Host header, which a TLS-terminating edge answers with 403; the Python
  host dials such addresses by name (libp2p/py-libp2p#1549). It also dials
  `wss` with certificate verification off unless given a TLS context
  (libp2p/py-libp2p#1550); the host gives it the system roots.
- py-libp2p's Kademlia client takes a protocol prefix but its provider
  lookups still speak `/ipfs/kad/1.0.0`, so it cannot reach the mesh DHT.
  The Python SDK does a bounded GET_PROVIDERS walk itself on
  `/sam/kad/1.0.0`, seeded by the routers (`agent_mesh/discovery.py`).
  js-libp2p's `@libp2p/kad-dht` takes the protocol and works as is.
- go-libp2p-kad-dht keys provider records by the multihash, not the CID.
  `sdk/testdata/service_keys.json` pins the keys both SDKs derive against
  `internal/node/service.go`.
- go-libp2p-http is plain HTTP/1.1 on a stream, one request per stream,
  with `Host` set to the peer ID. The JS SDK bridges the stream to a Node
  duplex and runs Node's HTTP server and client on it; the Python SDK
  drives `h11` over the stream. Both read the response body as it arrives,
  which an A2A `message/stream` (server-sent events) needs.
- URL parsers lowercase the host (WHATWG `URL`, httpx), and a base58 peer
  ID is case-sensitive. The URL an HTTP client uses for a peer's service
  therefore carries the peer ID in the path,
  `http://mesh/sam/<peer-id>/<type>/<name>/<path>`, the shape of `sam-node`'s
  egress proxy and of an agent card rewritten for the mesh; the host is ignored.
- A member that publishes nothing has announced no address, so nothing in
  the DHT or a router's peerstore names one. `sam-node` dials
  `/p2p/<router>/p2p-circuit` for every router it authenticated with when
  it knows nothing else about a peer, as both SDKs do for a peer named by
  ID (`internal/node/mcp.go`, `preparePeerAddrs`).
- Every Go component runs GossipSub with `StrictSign`. `@libp2p/gossipsub`
  (the libp2p-maintained package; `@chainsafe/libp2p-gossipsub` stops at
  libp2p 2) and py-libp2p's `GossipSub` with `strict_signing=True` both
  exchange messages with `sam-router`. py-libp2p's Pubsub learns of peers
  through a notifee it registers when constructed, so it is built before
  the first connection; it also opens a meshsub stream to every new peer
  and its host logs an error for peers that do not run pubsub, which is
  expected on a mesh with plain peers.
- py-libp2p's connection gate is address-based, not peer-based, so the
  Python SDK enforces a ban by disconnecting the peer and refusing its
  handshakes, requests and dials; js-libp2p's `connectionGater` also denies
  the connection itself, as sam-node's gater does.

## Wire contract

Everything below is what the Go implementation does today, with the source
file that defines it. The SDKs must match it byte for byte; when a Go change
alters one of these, the SDKs change with it.

### Identity

- The identity is an ed25519 key pair. The public key travels in the libp2p
  protobuf encoding `PublicKey{Type: Ed25519, Data: <32 bytes>}`, which is
  the bytes `08 01 12 20` followed by the key. Private keys persist as
  `PrivateKey{Type: Ed25519, Data: <seed || public>}`, bytes `08 01 12 40`
  followed by 64 bytes; this is what `sam-node` writes to its store.
- The peer ID is the identity multihash (`00 24`) of the public key encoding,
  written in base58btc. The control plane refuses an enrollment whose
  `peer_id` is not derived from `public_key`
  (`internal/controlplane/server.go`, `pID.MatchesPublicKey`).

### State directory

What a member keeps between runs is `api.MemberCredential` plus its private
key, and every implementation persists the same two things. The SDKs keep
them in a directory: `identity.key` is the libp2p `PrivateKey` encoding
above; `credential.json` is `MemberCredential` as protojson with proto field
names (`control_plane_url`, `biscuit`, `expire_time` as RFC 3339,
`trusted_keys[].public_key`, `issued_under_keys`, `router_addresses`,
`oidc_session`), written with mode `0600` in a directory of mode `0700`.
An unknown field is an error. `control_plane_url` has no trailing slash.
In a browser the JS SDK keeps the same two records in an IndexedDB
database named after the state location, kept by the browser for the
page's origin.
`sam-node` keeps the same message in `agent.db`, and `sam-node state
export|import <dir>` moves a member between the two
(`internal/node/statedir.go`). `TestNativeSDKExamples` resumes each SDK's
directory with the other SDK and with an imported `sam-node`. Fields an SDK
does not use (`receive_time`, `oidc_session`) are carried through on save,
so a directory survives a round trip through any implementation.

`enroll` resumes the saved credential when it is for this control plane,
has more than five minutes left, and the control plane still serves a key
in `trusted_keys`: `/keys` is pulled and verified against the saved set
before the member is returned, and the keys it names are adopted. A member
off for longer than the key grace period holds a credential no current
key signed and a trusted set no current key is in, so neither verifies;
with a token given, `enroll` enrolls again as the saved identity, and
without one it raises `CredentialRetiredError`. A control plane that cannot
be reached leaves the saved credential in force; the pull before join tries
again. `TestKeyRotationWhileMembersOffline` and
`TestKeyRotationPastGraceWhileMembersOffline` in `tests/integration` run
both cases against real routers and a real control plane.

### Control plane (protobuf over HTTP)

All requests and responses are `application/x-protobuf` bodies of the
messages in `api/sam.proto`. Bodies are capped at 1 MiB on both sides.

| Endpoint | Request | Response | Proof of possession |
| --- | --- | --- | --- |
| `GET /info` | — | `ControlPlaneInfoResponse` | none |
| `POST /enroll` | `BootstrapEnrollRequest` | `BootstrapEnrollResponse` | sign `sam:enroll:<peer_id>:<ts>` |
| `GET /enroll/status?peer_id=` | headers `X-Sam-Challenge-Ts`, `X-Sam-Challenge-Sig` (base64url, unpadded) | `BootstrapEnrollResponse` | sign `sam:enroll-status:<peer_id>:<ts>` |
| `POST /register` | `EnrollRequest` | `EnrollResponse` | sign `sam:register:<peer_id>:<ts>` |
| `POST /refresh` | `TokenRefreshRequest`, header `Authorization: Bearer <base64 biscuit>` | `TokenRefreshResponse` | sign `sam:refresh:<peer_id>:<ts>` |
| `GET /keys` | — | `KeysResponse` | none; see below |
| `GET /policies` | headers `Authorization: Bearer <base64 biscuit>`, `X-Sam-Challenge-Ts`, `X-Sam-Challenge-Sig` | `PolicyConfigGetResponse{datalog_rules}` | sign `sam:policies:<peer_id>:<ts>` |
| `GET /egress` | headers `Authorization: Bearer <base64 biscuit>`, `X-Sam-Challenge-Ts`, `X-Sam-Challenge-Sig` | `EgressAssignmentsResponse` | sign `sam:egress:<peer_id>:<ts>` (`sam-node` only) |
| `GET /revocations` | headers `Authorization: Bearer <base64 biscuit>`, `X-Sam-Challenge-Ts`, `X-Sam-Challenge-Sig` | `RevocationsResponse` | sign `sam:revocations:<peer_id>:<ts>` (`sam-node` only) |
| `POST /nodes/catalog` | `NodeCatalogReport`, headers `Authorization: Bearer <base64 biscuit>`, `X-Sam-Challenge-Ts`, `X-Sam-Challenge-Sig` | `204` | sign `sam:nodes-catalog:<peer_id>:<ts>`; `sam-node` reports what it publishes, while an SDK member publishes nothing and does not call it |

- `<ts>` is the request's `challenge_unix_ms`, unix milliseconds, and must
  be within 5 minutes of the control plane's clock (`challengeMaxAge`). When
  the control plane answers `401` with `"stale or invalid challenge timestamp"`,
  a client reads the response's `Date` header (`Access-Control-Expose-Headers: Date`),
  recomputes `<ts>` from it, and retries once; other `401`s are not retried.
- The endpoints above answer a CORS preflight and mark their responses for
  any origin (`Access-Control-Allow-Origin: *`), so a page on another origin
  can call them. They authenticate by what the request carries, a token in
  the body or a biscuit as a bearer plus the signed challenge, never by a
  cookie. The operator plane (`/admin/*`, `/user/*`) and `/routers/lease` do
  not.
  Challenges are defined in `api/network.go`. It is the one instant on the
  wire that is an `int64`: it is the number in the signed text. Every other
  instant (`expire_time`, `sign_time`, `event_time`, `announce_time`) is a
  `google.protobuf.Timestamp`, and a receiver rejects a message whose
  required instant is unset.
- A bootstrap enrollment answers `PENDING` until an operator approves it,
  unless the control plane runs with auto-approval. The client polls
  `/enroll/status` at the returned `poll_interval_seconds`.
- `/refresh` redeems only the last biscuit the control plane issued for the
  peer. A client must persist the new biscuit before using it; losing it
  means re-enrolling.
- `/keys` signatures cover the deterministic protobuf encoding of
  `KeysResponse{public_keys, sign_time}` with `signatures` cleared, one
  signature per key by that key. The receiver accepts the set when a key it
  already trusts (the enrollment key) vouches for it and `sign_time` is
  within 5 minutes (`api/trust.go`). Rotation keeps several keys valid, so
  a member must trust the whole set to verify peers enrolled under a
  retiring key.
- A plaintext `http://` control plane URL is accepted only for a loopback
  host (`api.ValidateControlPlaneTransport`). The SDKs expose the same
  explicit opt-in (`allowInsecure` / `allow_insecure`).
- Bootstrap tokens are secrets. The SDKs read them from a file or a value the
  caller already holds; the conformance runners take a path in the
  environment. Nothing takes a token as a command-line argument.

### libp2p host (`internal/node/node.go`)

- Transports: `libp2p.DefaultTransports` (TCP, QUIC, WebSocket).
- Security: TLS first, Noise accepted (`libp2p.Security` twice, in that
  order, on `sam-node` and `sam-router`). Both bind the connection to the
  peer ID. The Node and Python SDKs offer the same two in the same order and
  land on TLS with a Go peer and with each other; in a browser the JS SDK
  offers Noise alone, since a page cannot run libp2p's TLS, and a Node or
  Python member reached through a relay meets it on Noise. js-libp2p has
  both; py-libp2p gained TLS in
  [libp2p/py-libp2p#831](https://github.com/libp2p/py-libp2p/pull/831) and
  has passed the libp2p transport interoperability suite against the other
  implementations since
  [libp2p/test-plans#798](https://github.com/libp2p/test-plans/pull/798).
- Muxer: yamux (libp2p default).
- Relay: circuit relay v2, with the routers as static relays; hole punching
  is on. A node behind NAT is reached through a router.
- DHT: Kademlia with protocol prefix `/sam`, mode auto.

### Streams

Three protocols. The first two start with a length-prefixed protobuf frame;
framing is the go-msgio varint style (unsigned varint byte length, then the
bytes), with a 64 KiB cap on the first frame.

- `/sam/auth/1.0.0` (`HandleAuthHandshake`, and the router's equivalent).
  Client sends `AuthFrame{biscuit}`; server verifies the biscuit against the
  control plane keys, checks it is bound to the connection's peer ID and not
  revoked, and answers `AuthResponse{success, biscuit}` with its own
  credential. The client verifies that credential the same way and, for a
  router, requires the router role. This is how a member joins: connect to a
  router, run this handshake, and the router admits it to the relay and
  gossip. Both SDKs answer it too, so a `sam-node` can verify them before
  calling.
- `/sam/mcp/1.0.0` (`WithBiscuitAuth` then `HandleMCPStream`). Client sends
  `AuthFrame{biscuit, target_service: "mcp://<service>", agent}`; server
  authorizes the request with the Biscuit authorizer described below and
  answers `AuthResponse`. The stream then carries MCP JSON-RPC messages, each
  one varint-length-prefixed (`StreamTransport` in `internal/node/gate.go`).
  An empty `target_service` selects the node's own catalog tools. The SDKs
  are clients of this protocol only; they serve no MCP.
- `/libp2p-http` (go-libp2p-http; `StartIngressServer` and the egress proxy
  in `internal/node`). Plain HTTP/1.1 on a stream, one request per stream,
  `Host` set to the peer ID, the caller's biscuit in `X-Sam-Biscuit` and the
  agent it speaks for in `X-Sam-Agent`. The path is
  `/<type>/<name>/<upstream>`; the server authorizes `<type>://<name>` with
  the same authorizer, then forwards `<upstream>` to the service with those
  two headers stripped and `X-Peer-Id` set to the verified caller. The SDKs
  are clients of this for `inference://`, `a2a://` and `egress://` services
  (an egress destination is one a `sam-node` serves for a hostname outside
  the mesh, as the control plane assigned it; the SDK reaches it as any
  other service, `/egress/<hostname>/<path>` on that node), and servers of
  it for their own agent, `a2a://<name>`, only. Bodies are framed by
  `Content-Length` or chunked transfer coding; a response with neither runs
  to the end of the stream. The JS SDK frames these itself
  (`http1.ts`), so the same code runs in a browser.

### Discovery (`internal/node/service.go`)

A provider announces a service as a DHT provider record for
`cidv1(raw, sha256("sam:service:<type>[:<name>]"))`, once for the type and
once for the name (`<type>` is `mcp`, `inference`, `a2a` or `egress`). A consumer
looks up providers for the same CID, dials one and opens `/sam/mcp/1.0.0`.
Gossip topics under `/sam/discovery/v1/...` carry `ServiceAnnounce` for
interest-scoped updates; the DHT is the source of truth. The SDKs look
records up and announce none.

A peer that announced nothing is still reachable by peer ID: every router
relays for the peers it admitted, so a caller dials
`<router>/p2p-circuit/p2p/<peer>` through each router that admitted it.
Both SDKs do this for a bare peer ID, and `sam-node` does it when it knows
no other address for a peer (`preparePeerAddrs` in `internal/node/mcp.go`).
This is how an SDK agent is reached.

### Authorization on the provider side (`internal/node/middleware.go`)

A node that serves a tool evaluates the caller's biscuit with an authorizer
that has, in this order: the biscuit's own authority facts (`node`, `role`,
`label`, `agent`), injected facts `service(<type>, <name>)`,
`connection_peer_id(<peer>)`, `time(<now>)` and optionally `agent(<claim>)`,
the baseline checks, rules and policies from `api/datalog.go`, the
`target_fact` facts derived from the provider's own biscuit, and the mesh
policy rules. Deny by default.

All of that Datalog is text every Biscuit implementation parses, and none
of it is derived in the SDK:

- The baseline (checks, rules, policies, fact names) is generated from
  `api/datalog.go` by `hack/gen-sdk-datalog` into `sdk/js/src/gen/datalog.ts`
  and `sdk/python/src/agent_mesh/_gen/datalog.json`;
  `hack/verify-sdk-generated.sh` fails when they are stale.
- The mesh policy arrives rendered: `GET /policies` answers
  `PolicyConfigGetResponse{datalog_rules}`, one rule per entry, rendered by
  the control plane with `api.BuildPolicyRules`. `sam-node` adds the same
  text; no member compiles roles and bindings itself. An unparseable entry
  rejects the whole response.
- Presence-only facts carry the single term `true`
  (`target_unrestricted(true)`, `granted_service_all_types(true)`,
  `agent_authorized(true)`, …). biscuit-go accepts a predicate with no
  terms; biscuit-rust, and so biscuit-python and biscuit-wasm, do not.
- An unconditional rule is written `head <- true`, which every parser
  accepts as a rule (`role("dev") <- true` for a
  `sam:system:authenticated` binding).

## Agents, not services

An SDK member calls services and accepts A2A requests for its own agent.
It does not publish services: no MCP server, no named inference or A2A
service, no DHT record, no catalog entry. The reasons:

- **The agent is the principal; a service is infrastructure.** A harness
  (LangChain, Claude Code, a browser agent) is an MCP client. The tools it
  should see through the mesh are the ones `sam-node`s publish. Something
  that must be reachable by name, a tool, a model, a named agent, is a
  deployment concern, and the sidecar model exists for it: the `sam-node`
  beside it publishes the service and enforces the policy once, in Go.
- **Publishing is the expensive part.** Being a provider needs a DHT
  provide loop, a catalog report and provider records that go stale on
  every rollout. Accepting requests for the agent itself needs the relay
  reservation, the auth handshake and the authorizer, all of which a member
  needs anyway to be verified by a `sam-node` before it is called.
- **One inbound protocol.** A2A is the protocol for talking to an agent,
  and the A2A SDKs serve one agent card each. One ingress means one
  authorizer path to audit in three languages instead of two ingress
  protocols times a registry of services.
- **The browser.** A browser cannot listen. An agent in a browser is
  reachable through a router's relay and nothing else, which is what
  `accept_a2a` is. The JS SDK runs in a page: it reaches the router over
  WebSocket (`wss` when the router sits behind a TLS-terminating edge, as
  `sam-one --tunnel` puts it), secures the connection with Noise, keeps its
  state in IndexedDB and answers its agent with a fetch handler.

What an SDK agent is on the wire: a peer with a relay reservation on a
router, answering `/sam/auth/1.0.0` and `/libp2p-http` for `a2a://<name>`,
with no DHT record and no catalog entry. To a `sam-node` it is a peer whose
address nobody announced, reached through the router that admitted both,
and whose credential it verifies before forwarding
`/sam/<peer>/a2a/<name>/...`. Routers, the control plane and the Datalog
need no special case.

Two agents that both wrote nothing down still meet: A learns B's peer ID
(an invite, an agent card, a coordinator), dials it through a router, both
present their credentials, and A opens the A2A conversation on that
connection; libp2p's secure channel is end to end, so the router carries
ciphertext.
An agent that must be *found* by name runs behind a `sam-node`. Two agents
that both can only call out (two browsers) meet at a third agent behind a
`sam-node` that both call.

## Plan

Each milestone lands in both languages with its tests before the next one
starts. Where a milestone needs a Go change, the Go change lands first.

### Milestone 1 — identity and enrollment (done)

Described above. Tested by unit tests in each SDK against a fake control
plane and by `tests/integration/sdk_enroll_test.go`, which runs each SDK's
conformance runner against a real control plane in manual-approval mode,
approves the request through `/admin`, and checks the biscuits the SDK
holds against the control plane's records.

### Milestone 2 — join the mesh (done)

- libp2p host per SDK, configured as `sam-node`'s: TCP and WebSocket, TLS,
  yamux, identify, circuit relay v2 client. The testnets' routers listen on
  TCP; `sam-one`'s router is a WebSocket listener on the port that serves
  its API (`/ws`, or `/wss` behind a tunnel), so a member reaches it over
  WebSocket or not at all; `tests/integration/standalone_sdk_test.go` holds
  both SDKs to it. JS: `libp2p`, `@libp2p/tcp`, `@libp2p/websockets`,
  `@libp2p/tls`, `@chainsafe/libp2p-yamux`, `@libp2p/circuit-relay-v2`,
  `@libp2p/identify`. Python: `libp2p>=0.8` (`security.tls`,
  `stream_muxer.yamux`) plus the SDK's own relay client; py-libp2p is
  trio-based, so `join()` is an async context manager.
- Biscuit verification of a peer's credential: signature under any trusted
  control plane key, authority block only, expiry, binding to the
  connection peer ID, roles and labels. JS: `@biscuit-auth/biscuit-wasm`,
  instantiated by hand so no Node flag is needed; Python: `biscuit-python`.
  `sdk/testdata/biscuit_vectors.json` holds tokens minted by
  `internal/identity` (valid, other peer, expired, untrusted key, appended
  block, garbage) and both verifiers agree with the Go one on all of them.
- `/sam/auth/1.0.0` on both sides. Join connects to the routers in the
  credential, runs the handshake, requires the router role under the key
  that verified the token, and reserves a relay slot; the router grants one
  only to an authenticated peer. Inbound handshakes are answered the way
  `HandleAuthHandshake` does: a credential that does not verify gets a
  closed stream and nothing else.
- `session.authenticate(addr)` connects to any peer, directly or through a
  router (`/p2p-circuit`), and runs the handshake; `session.authenticatedPeers`
  is the admitted set. Background refresh is driven by the biscuit's
  expiration, as `StartRenewalLoop` does.
- Tests. Unit: each SDK joins an in-process fake router (its own libp2p
  with the handshake and a relay), and refuses a relay without the router
  role, a router that trusts another control plane, and a refused
  reservation. Integration: `tests/integration/sdk_mesh_test.go` runs one
  mesh with a control plane, a `sam-router`, a `sam-node` and one member per
  SDK, all real, then walks the connectivity matrix: every member on the
  router's lease; each SDK member verifies the `sam-node` and the other SDK
  member on both the direct and the relayed path, and is verified by them;
  the `sam-node` reaches each member through the router; an admitted Go peer
  does the same and sends a forged frame; an address behind the router for
  a peer that is not on the mesh fails. About 7 seconds.

### Milestone 3 — call tools (done)

- Discovery: `session.discover("mcp://calc")`, or `(type, name)`, or a type
  alone, looks the mesh DHT up for the service key
  `internal/node/service.go` derives. JS: `@libp2p/kad-dht` in client mode
  on `/sam/kad/1.0.0`; Python: the SDK's own bounded GET_PROVIDERS walk on
  the same protocol (see the facts above).
- Naming a peer: every call takes a `Peer`, which is a provider `discover`
  returned, a peer id, or a multiaddr. For the first two the SDK dials the
  advertised addresses and `<router>/p2p-circuit/p2p/<peer>` through every
  admitted router, as `preparePeerAddrs` in `internal/node/mcp.go` does; a
  multiaddr is dialed as given.
- `/sam/mcp/1.0.0` client: `session.openMCP(peer, "mcp://<name>")` sends
  the `AuthFrame` naming the service, verifies the provider's credential
  and the caller's required labels (`checkPeerLabels`: every pair must be
  attested, as `api.LabelCheck` joins them with `,`), then runs the
  official MCP client over the varint-framed stream. JS: a `Transport` for
  `@modelcontextprotocol/sdk`; Python: a pair of memory streams pumped to
  and from the libp2p stream for `mcp.ClientSession`. `""` as the target is
  the provider's own catalog (`list_local_services`, `get_mesh_info`).
- Egress floor: `join({ egressRequireLabels })` (`join(egress_require_labels=)`)
  is `sam-node`'s `egress.require_labels` for an SDK member: every provider
  the session calls must attest all of them, on top of a call's required
  labels, on every outbound call however the peer was named, MCP and HTTP
  alike. It is the same rule as the caller's requirement (`api.LabelCheck`),
  checked separately so no call can reach it. Stated once at join and held
  for the session; a call cannot waive or widen it. The three
  implementations agree on it, as they do on the caller's requirement. The
  HTTP path (`request`, `fetch`, `MeshTransport`) verifies the provider with
  or without a floor, through the mutual `/sam/auth/1.0.0` handshake, as
  `sam-node`'s `VerifyPeerLabels` does before its egress proxy sends
  anything; a positive verdict is kept per peer for five minutes
  (`labelGateTTL`); a refusal is not kept. An unmet floor is a
  `LabelsNotSatisfiedError` naming the floor.
- `session.listTools(peer, service)` and `session.callTool(peer, service,
  tool, args)` on top of that.
- Tests. Unit: each SDK calls a tool on an in-process provider that serves
  `/sam/mcp/1.0.0` as `sam-node` does with the official MCP server behind
  it, reads its catalog, and is refused for missing labels, an untrusted
  provider, a forged caller credential and an unknown service. Integration:
  the mesh of `sdk_mesh_test.go` has an MCP backend behind the `sam-node`
  (`calc`, tool `add`); each SDK member discovers it in the DHT, lists and
  calls `add` through the router, reads the node's catalog and is refused a
  service the node does not have. The runners took `discover`, `tools` and
  `call` commands for it.

### Milestone 4 — be an agent (done)

- Datalog as the contract, Go side: the baseline moved into a generated
  artifact both SDKs embed, the control plane renders the mesh policy as
  `datalog_rules`, and `sam-node` consumes that text like any other member.
  See the authorization section above.
- Provider authorizer in each SDK (`authorizer.ts`, `authorizer.py`), built
  from the artifact and `datalog_rules`, evaluated on every inbound
  `/libp2p-http` request in the order `internal/node/middleware.go` uses.
- `/libp2p-http` server for the agent: the path is
  `/<type>/<name>/<upstream>`, the biscuit is `X-Sam-Biscuit`; after
  authorization for `<type>://<name>`, a request for the agent's own
  `a2a://<name>` goes to an A2A server beside the process or a handler in
  it, with the biscuit and agent headers stripped and `X-Peer-Id` set to the
  verified caller; anything else is 404, after authorization, so an
  unauthorized caller learns nothing. JS also takes a Node request
  listener, which is what an Express app with the A2A SDK's handlers is,
  and runs it on the ingress's own `http.Server`.
- `session.accept_a2a(target, name=)` / `session.acceptA2A(spec)` fetches
  the mesh policy, re-reads it on `sam-node`'s sync interval and starts
  answering. It announces nothing. One agent per session.
- `/libp2p-http` client for callers built on HTTP libraries:
  `open_http_request` / `fetchOverStream` return once the headers are in
  and stream the body; `MeshTransport` (httpx) and `session.fetch()`
  (fetch) carry a client's requests to the peer a mesh URL names. The A2A
  SDK's client takes either without changes. The card of an agent behind a
  `sam-node` names the agent's own address; a GET of the well-known card
  path or of the service root is answered the way the node's egress proxy
  answers it: the SDK fetches the card itself, with identity encoding, and
  serves it rewritten (`rewriteAgentCard` / `rewrite_agent_card`): HTTP
  interfaces point at the mesh URL, gRPC ones are dropped, signatures go.
  Streaming stays as the agent declares it, since the transport streams.
- `sam-node`: a peer it knows no address for is dialed through every
  router it authenticated with, so its egress proxy reaches an agent by
  peer ID (`preparePeerAddrs`).
- Examples with the official A2A SDKs (`a2a-agent.ts`, `a2a-call.ts`;
  `a2a_agent.py`, `a2a_call.py`): the A2A SDK's server is the listener
  `acceptA2A` runs (JS) or a uvicorn process `accept_a2a` forwards to
  (Python), its card names the agent by its mesh URL, and the A2A SDK's
  client runs on `session.fetch()` or `MeshTransport`. The A2A SDKs are
  dependencies of the examples only: dev dependencies in `sdk/js`, the
  `examples` extra in `sdk/python`.
- Tests. Unit: each SDK's ingress behind an in-process host, called with
  its own clients: a forwarded A2A server that sees `X-Peer-Id` and never
  the biscuit, an SSE body read event by event, an in-process handler (and
  a Node listener), an httpx client on `MeshTransport`, and refusals for a
  role that grants nothing, an ungranted type, another agent name (404), a
  missing biscuit and a dotted path; plus the authorizer alone against the
  decisions `internal/node/middleware_test.go` pins, and `sam-node`'s
  router fallback. Integration: in the mesh of `sdk_mesh_test.go` each SDK
  member accepts `a2a://agent`; the `sam-node` reaches it by peer ID
  through its egress proxy, the other SDK member does the same with no
  lookup, a lookup for `a2a://agent` finds nothing, the member refuses a
  `/sam/mcp/1.0.0` stream, and a Go peer whose role the policy grants
  nothing gets 403 and is answered once it presents a node-role token.
  About 9 seconds for the whole mesh. `TestNativeSDKA2A` runs the A2A SDK
  agents and calls each from the other language with the A2A SDK's client;
  the answer names the caller's peer, and a `sam-node` fetches the card
  through its egress proxy.

### Milestone 5 — parity and release (done)

- Control plane pull (`session.sync()`, `mesh.syncControlPlane()`), as
  `SyncControlPlane` in `internal/node/controlplane_sync.go`: `/keys`
  verified against the keys already trusted, so whoever answers the URL
  cannot become the trust root; a credential refresh when a key trusted now
  was unknown when the credential was issued (`issuedUnderKeys` in the
  credential file); `/info` for router addresses and the ban set,
  reconciled with the rule that a ban recorded after the request went out
  survives an answer that omits it; the mesh policy while accepting
  callers. Runs
  once shortly after join, then on `sam-node`'s interval with the same
  jitter, and whenever an event triggers it.
- Gossip events on `/sam/mesh/events/v1`: the topic validator rejects
  anything not signed by a trusted control plane key and ignores stale
  events; `BANNED` evicts the peer at once, `KEY_ROTATION` adopts the key
  and triggers a pull, `POLICY_UPDATE` triggers a pull. Bans are not
  persisted; a restarted member reads them from `/info`.
- Ban enforcement: the auth handshake and the A2A ingress refuse a banned
  peer before looking at its token; `connect()` refuses to dial one; its
  connections are dropped when the ban lands.
- Publishing: each SDK has its own release cycle and tags, `sdk/js/v1.2.3`
  for `@sam-mesh/sdk` on npm and `sdk/python/v1.2.3` for `sam-mesh` on
  PyPI, independent of the mesh tags (`v1.2.3`). On such a tag
  `.github/workflows/release.yml` stamps the tag's version on that SDK
  (`hack/sdk-version.sh --js` or `--python`), publishes it through trusted
  publishing and creates a GitHub release for the tag that is not marked
  latest, with notes generated from the commits under the SDK directory and
  `api/sam.proto` since the previous tag of that SDK. A prerelease tag
  (`sdk/js/v0.2.0-rc.1`) publishes under the npm dist-tag `next`, a stable
  tag under `latest`; PyPI needs no tag, `pip` skips prereleases on its own.
  When a publish job fails, re-run it, or run the workflow by hand from the
  Actions tab with the SDK tag as input; it checks out that tag and
  publishes the SDK the tag names. One-time setup by a package owner: on
  npmjs.com, create the
  `sam-mesh` organization, publish `@sam-mesh/sdk` 0.1.0 once by hand
  (`cd sdk/js && npm publish --access public`; the trusted-publisher
  settings live on the package page, which exists only after that), then
  register `google/sam` with workflow `release.yml` under the package's
  Settings, Trusted publishing; on pypi.org, add a pending publisher for
  project `sam-mesh` with the same repository and workflow (environment
  left empty), which reserves the name and lets the first tag create the
  project. No publishing token is stored in the repository.
- Docs: `site/content/docs/guides/native-sdks.md`.
- Tests. Unit: a fake control plane rotates its key and bans a peer; each
  SDK learns both from a pull, refreshes under the new key and only under
  it, drops and refuses the banned peer, and lifts the ban when the control
  plane does; `BanSet` and `verifyMeshEvent` alone. Integration: the mesh
  of `sdk_mesh_test.go` gets the control plane's real event publisher; an
  enrolled Go peer admitted by every member is banned with
  `POST /admin/revoke` and each member learns it from the gossip event
  through the router without pulling, refuses the peer's next handshake,
  and a pull agrees; then the control plane rotates its key and announces
  it, and every member ends up trusting both keys, holding a credential
  that verifies only under the new one, and still authenticating with the
  `sam-node`.

### On the testnets

Both testnets run the example programs, unchanged, as canaries beside the
`sam-node` ones (`.github/k8s/sam-sdk-canary-template.yaml`): two pairs, an
agent written with one SDK and the official A2A SDK (`a2a-agent.ts`,
`a2a_agent.py`) and a caller written with the other in one pod, enrolled
with the pod's projected service account token through `SAM_JWT_PATH`. The
agent accepts `a2a://agent`; the caller reads its peer ID from the line it
prints, through a volume the pod shares, sends it a message with the A2A
SDK's client every five minutes and is Ready while the last answer named
the caller, so the Deployment's availability says whether an agent is still
reachable after hours on the mesh. Two CronJobs cross every implementation
boundary every 15 minutes and once per rollout: the `sam-node` cold-path
probe (`sam-probe-cronjob-template.yaml`) runs an agent per SDK as sidecars
and fetches each one's agent card by peer ID through the egress proxy
(node → SDK), and the SDK cold-path probe
(`sam-sdk-probe-cronjob-template.yaml`) runs each SDK's callers against the
everything canary by name (SDK → node) and the other SDK's agent by peer ID,
the card with the mesh SDK's client and a message with the A2A SDK's
(SDK → SDK). The images (`Dockerfile.sam-sdk-js`, `Dockerfile.sam-sdk-python`)
are built per commit by `deploy.yaml`, so `bananas` runs the SDKs at the
same commit as the Go components they talk to.

### Later

- The connector interface for platforms (issue #480): `Attach`, `Detach`,
  `Refresh`, `Status` and the agent bundle, so a scheduler places SDK
  members the way it places `sam-box` sandboxes.
- Reading the control plane's events also for router address changes, and
  re-dialing a router that replaced another.

### Non-goals

- Rewriting the control plane, router or sandbox components; they stay Go.
- Publishing services from an SDK: an MCP server, a named inference or A2A
  service, a DHT record or a catalog entry. That is `sam-node`'s job; see
  [Agents, not services](#agents-not-services).
- Any SDK-only wire protocol. If an SDK needs something the Go node does not
  speak, the Go node learns it first.

## Working on the SDKs

```bash
# Regenerate protobuf bindings and the Datalog artifact after editing
# api/sam.proto or api/datalog.go
./hack/gen-sdk-proto.sh

# JavaScript
cd sdk/js && npm ci && npm test && npm run build && npm run examples

# Python
python3 -m venv sdk/python/.venv
sdk/python/.venv/bin/pip install -e 'sdk/python[test]'
sdk/python/.venv/bin/pytest sdk/python/tests

# Both against a real control plane, router and sam-node, and the example
# programs the docs embed against the same
go test ./tests/integration -run TestNativeSDK -v

# The JS SDK in a browser page against sam-one, in Chromium (Playwright);
# also run by `make ui-test`
cd sdk/js && node scripts/bundle-browser.mjs examples/browser/app.js build/browser-example
cd tests/ui && npm ci && npx playwright install chromium && npx playwright test browser-sdk
```

`make sdk-test` runs all of the above. The integration tests skip an SDK
whose toolchain is missing, and CI (`.github/workflows/sdk.yml`) installs
both so nothing skips there. The SDK members in the mesh test are the
runners `sdk/js/src/conformance-join.ts` and
`sdk/python/src/agent_mesh/conformance_join.py`: each joins, prints what it
holds, then takes JSON commands on stdin (`auth`, `discover`, `tools`,
`call`, `accept`, `http`, `peers`, `sync`, `banned`, `quit`) so the Go test
can drive both languages through the same script.

The programs the package READMEs and the Native SDKs guide show are
`sdk/js/examples/*.ts` and `sdk/python/examples/*.py`. The Markdown embeds
them between `<!-- embed: <path> -->` and `<!-- /embed -->` markers;
`make sdk-docs` (`go run ./hack/gen-sdk-docs sdk site/content/docs`) copies
the files in, `hack/verify-sdk-generated.sh` fails when a copy is stale, and
`TestNativeSDKExamples` runs the files themselves against a mesh. Edit the
example, regenerate, commit both.

`sdk/js/.npmrc` pins the public registry so `package-lock.json` never
resolves packages through a local mirror; the verify script checks the
lockfile too.

Interoperability facts that the tests pin: `sdk/testdata/identity_vectors.json`
holds key encodings, peer IDs and challenge signatures produced with
go-libp2p, `sdk/testdata/biscuit_vectors.json` holds tokens minted by the
control plane's code, and every SDK reproduces or agrees with them.

The package READMEs (`sdk/js/README.md`, `sdk/python/README.md`) are the
registry pages on npm and PyPI: they hold what a user of the package needs
and nothing about this repository's internals. Everything below is for
contributors.

### Layout

Both SDKs mirror the same Go code, one module per concern; the Go file each
one follows is named so a change on one side can be carried to the others.

| JavaScript (`sdk/js/src/`) | Python (`sdk/python/src/agent_mesh/`) | Mirrors |
| --- | --- | --- |
| `identity.ts` | `identity.py` | ed25519 key pair, libp2p key encodings, peer ID |
| `controlplane.ts` | `controlplane.py` | `/info`, `/keys`, `/enroll`, `/enroll/status`, `/register`, `/refresh`, `/policies`, with the challenges of `api/network.go` |
| `credential.ts` | `credential.py` | what a member holds, `AuthFrame` encoding, `issuedUnderKeys` |
| `mesh.ts` | `mesh.py` | `AgentMesh`: enroll (resumes a credential in the state directory before spending a token, while the control plane still serves a key it trusts), load, refresh, `syncControlPlane` as `SyncControlPlane` in `internal/node/controlplane_sync.go`; state directory (`identity.key`, `credential.json`, the same layout in both languages) |
| `biscuit.ts` | `biscuit.py` | verification of a peer's credential, as `internal/identity.verifyBiscuit` |
| `host.ts` | `host.py` | the libp2p host as `internal/node/node.go` configures it, plus gossipsub and the connection gater |
| `auth.ts` | `auth.py` | `/sam/auth/1.0.0` on both sides, as `HandleAuthHandshake` |
| — | `relay.py` | circuit relay v2 client (py-libp2p's cannot talk to go-libp2p) |
| `session.ts` | `session.py` | `MeshSession`: join, relay reservation, refresh loop, control plane sync loop, gossip events, `acceptA2A()` / `accept_a2a()`, `fetch()` |
| `discovery.ts` | `discovery.py` | service keys and DHT lookups as `internal/node/service.go`; lookups only, no records |
| `mcp.ts` | `mcp_client.py` | MCP over `/sam/mcp/1.0.0`, the client side of `internal/node/gate.go` |
| `authorizer.ts` | `authorizer.py` | the provider authorizer, as `internal/node.(*SamNode).Authorize`, over the generated baseline and `datalog_rules` |
| `libp2p-http.ts` | `libp2p_http.py` | `/libp2p-http` client (streaming) and the A2A ingress for the agent, as go-libp2p-http and `StartIngressServer`; mesh URLs |
| `http1.ts` | — | HTTP/1.1 heads and bodies on a libp2p stream, for `libp2p-http.ts` (Python uses `h11` in `libp2p_http.py`) |
| `libp2p-http-node.ts` | — | the ingress for a Node request listener (an Express app), Node's own HTTP server over the stream |
| `platform/*.ts`, `platform/*.browser.ts` | — | what differs between Node and a browser: transports and security (TCP+WebSocket with TLS then Noise; WebSocket with Noise), state (files; IndexedDB), the biscuit WASM loader, the ingress. `package.json`'s `browser` field maps each to its twin; `scripts/bundle-browser.mjs` bundles for a page and fails if the browser graph reaches a `node:` module |
| — | `httpx_transport.py` | `MeshTransport`, the mesh as an `httpx.AsyncBaseTransport` (JS has `session.fetch()` instead) |
| `sync.ts` | `sync.py` | ban set and mesh event verification, as `reconcileBannedPeers` and `verifyEvent` |
| `conformance.ts`, `conformance-join.ts` | `conformance.py`, `conformance_join.py` | the runners the integration tests drive |
| `../examples/` | `../../examples/` | the programs the docs embed and `TestNativeSDKExamples` runs; `../examples/browser/` is the page `tests/ui/browser-sdk.spec.js` drives |
| `gen/` | `_proto/`, `_gen/` | generated by `hack/gen-sdk-proto.sh` from `api/sam.proto`, `sdk/python/proto/circuit.proto` and `api/datalog.go` |

Unit tests sit beside the code (`*.test.ts`, `tests/test_*.py`) and build a
fake control plane and router in the process; the real ones are exercised
only by `tests/integration`.
