---
title: "Your own mesh"
linkTitle: "Your own mesh"
weight: 2
aliases:
  - /docs/user/device-enrollment/
---

This page gets a mesh of your own running in a few minutes: a control plane,
a router and a web console on your laptop, in one process called `agentmesh-one`.
You then put a member on it, open the console, and see a model that runs on
your machine answer a request from another member. `agentmesh-one` runs the same
code as a Kubernetes deployment, so what you learn here applies there too.

You need the `agentmesh-one` and `agentmesh-node` binaries. The
[install script](../quickstart/#1-install) provides both.

## 1. Start the control plane and obtain its URL

Every Agent Mesh needs a running control plane and router. `agentmesh-one` packages the
control plane, the libp2p WebSocket router, and the web console into a single
binary on one port. When `agentmesh-one` starts—on your machine, in a container, or
on a cloud VM—it brings up the control plane and prints a startup banner
containing its **URL (`API URL`)**, its tokens, and the `agentmesh-node join` command
for nodes to connect to it.

### Ways to run `agentmesh-one` and obtain its URL

| Where your nodes run | How to run `agentmesh-one` | Control plane URL you get |
|---|---|---|
| **Across machines, VMs, or phones** *(Instant HTTPS tunnel)* | `agentmesh-one --data-dir ~/agentmesh-one --tunnel cloudflare --tunnel-install` | Public `https://<name>.trycloudflare.com` URL + terminal QR code |
| **Same machine only** *(Local development)* | `agentmesh-one --data-dir ~/agentmesh-one` | Local `http://127.0.0.1:<port>` URL |
| **Custom domain behind NAT/firewall** | `agentmesh-one --data-dir ~/agentmesh-one --tunnel cloudflare --tunnel-token-path ~/token --external-url https://mesh.example.com` | Permanent `https://mesh.example.com` URL (no inbound firewall ports) |
| **A GitHub codespace, nothing installed** | Open the repository in a codespace and run `make testnet` ([Codespaces](../../guides/codespaces/)) | Public `https://<codespace>-8080.app.github.dev` URL once you make the port public |
| **Always-on Cloud Deployment** *(Cloud Run, SkyPilot)* | See [Cloud Run](../../guides/cloud-run/) (`gcloud run deploy`) or [SkyPilot](../../guides/skypilot/) (`sky launch`) | `https://<svc>.a.run.app` or `https://mesh.example.com` |

For example, starting `agentmesh-one` locally:

```bash
agentmesh-one --data-dir ~/agentmesh-one
```

`--data-dir` holds the database, the router's key and the generated tokens.
Delete it and you get a new mesh. After a moment `agentmesh-one` prints a banner:

```text
══════════════════════════════════════════════════════════════════
Agent Mesh standalone mesh is ready!

API URL:      http://0.0.0.0:33775
Web Console:  http://0.0.0.0:33775/console
Router Peer:  12D3KooWBzUDQCkZhz2rWrYBhpjcCH8VnrRNcwCW6DoF36iADYrY
Admin Token:  mesh_adm_…
Join Token:   mesh_tok_…

To enroll a node:
  agentmesh-node join http://0.0.0.0:33775 --bootstrap-token-path /home/you/agentmesh-one/join-token
══════════════════════════════════════════════════════════════════
```

Two things in the banner matter for the rest of this page:

- The **API URL** is the address of the mesh. `agentmesh-one` picked a free port;
  pass `--port 8080` for a fixed one.
- The **join token** admits new members. It is also written to
  `~/agentmesh-one/join-token`, and the steps below read it from there. The
  **admin token** opens the console and the admin API; it is in
  `~/agentmesh-one/admin-token`.

Keep this terminal open. Everything else happens in a second one, with the
URL from your banner:

```bash
export URL=http://127.0.0.1:33775
```

On first boot `agentmesh-one` seeds an open development policy and logs a warning:
any enrolled member may publish any service and call any service. That is
right for a laptop and wrong for anything shared; [step 5](#5-before-you-share-it)
replaces it.

### Reaching it from other machines

Skip this if everything stays on your laptop. A member on another machine
needs an `https` URL, because the control plane is the member's trust root
and Agent Mesh refuses to fetch it over plaintext from a remote address.

On a laptop behind NAT, the quickest way to an `https` URL is a temporary
tunnel:

```bash
agentmesh-one --data-dir ~/agentmesh-one --tunnel cloudflare
```

This publishes the port on a random `trycloudflare.com` hostname, with no
account needed, and prints that URL in the banner in place of the local one.
If `cloudflared` is not installed, `agentmesh-one` offers to download a pinned,
checksum-verified release into the data directory; `--tunnel-install`
accepts without asking. Set `URL` to the tunnel URL, copy the join token
file to the other machine, and the commands below work there unchanged.

With a real hostname and a reverse proxy in front, pass
`--external-url https://mesh.example.com` instead. The
[Cloud Run guide](../../guides/cloud-run/) shows a hosted variant.

With `--tunnel` or any other `https` URL, `agentmesh-one` also prints a QR code
that enrolls a phone running the Agent Mesh Connect app, which is in
[preview](../../preview/mobile/).

<!-- TODO(screenshot): the banner with a tunnel URL and the QR code. -->

## 2. Put a member on it

A member is anything that holds an identity the control plane issued and
speaks to the mesh through the router: a `agentmesh-node` beside an application, a
program written with a [native SDK](../../guides/native-sdks/), or a phone.
This page uses `agentmesh-node` because it needs no code.

Pull a small model with [Ollama](https://ollama.com) (any OpenAI-compatible
server works in its place) and declare it as an `inference` service. The
`target_url` is the backend's root, without `/v1`; the node adds the prefix:

```bash
ollama pull gemma3:1b

cat > ~/node-a.yaml <<'EOF'
version: "v1alpha1"
services:
  - type: inference
    name: laptop-llm
    description: "Ollama on my laptop"
    target_url: "http://127.0.0.1:11434"
EOF

agentmesh-node run --control-plane $URL \
  --bootstrap-token-path ~/agentmesh-one/join-token \
  --config ~/node-a.yaml \
  --data-dir ~/node-a --bind-addr= --allow-loopback --listen /ip4/127.0.0.1/tcp/0
```

The node enrolls with the join token, connects to the router and prints its
peer ID:

```text
Agent Mesh Node Online.
PeerID: 12D3KooWSCnbUoZ8Jv3EKGv17LqEWtnTMfZ3XYJUg2WTm5Gz2hUK
```

Three of the flags are only needed because you will run a second node on
the same machine in the next step. `--bind-addr=` (an empty value) keeps the
node's local API on its Unix socket so the two nodes do not compete for port
8080, `--allow-loopback` lets them advertise and dial `127.0.0.1`, and
`--listen .../tcp/0` picks a free peer-to-peer port. On separate machines you
would pass none of them.

Ollama is never exposed on the network. It listens on loopback, and the only
way to it from another machine is through this node, which checks the
caller's credential and the mesh policy on every request.

The service `type` is a contract. `inference` is an OpenAI-compatible API,
`mcp` an MCP server, `a2a` an A2A agent, and the node speaks that protocol
to the backend and to nobody else. Before the node advertises an `mcp`
server, the node completes an MCP session with the server. Before the node
advertises an `a2a` agent, the node fetches the agent card. The node does
not advertise a backend that fails its probe. An `inference` backend has no
probe, so the node advertises the service as declared. The node offers the
models that the backend lists on `/v1/models`. The node therefore advertises
a plain web server declared as `inference`.

## 3. See it in the console

Open `http://127.0.0.1:33775/console` (the **Web Console** line of your
banner) and paste the admin token from `~/agentmesh-one/admin-token`. The console
shows the enrolled members, the router, the services each member reports,
the bootstrap tokens with their remaining uses, and the mesh policy, which
you can edit in place.

<!-- TODO(screenshot): the console's nodes view with node A and its laptop-llm service. -->

The same operations are available from the command line. `agentmesh-one` is also
an admin client for a running server. It reads the admin token from the data
directory, from `AGENTMESH_ADMIN_TOKEN` or from `--admin-token-path`, never from a
flag value:

```bash
agentmesh-one token list   --server $URL --data-dir ~/agentmesh-one
agentmesh-one token create --server $URL --data-dir ~/agentmesh-one --description "node c" --max-usages 1
agentmesh-one token revoke <token-id> --server $URL --data-dir ~/agentmesh-one
agentmesh-one admin ban <peer-id>      --server $URL --data-dir ~/agentmesh-one
```

## 4. Call the model from a second member

In a third terminal, start a node with no services of its own:

```bash
export URL=http://127.0.0.1:33775

agentmesh-node run --control-plane $URL \
  --bootstrap-token-path ~/agentmesh-one/join-token \
  --data-dir ~/node-b --bind-addr= --allow-loopback --listen /ip4/127.0.0.1/tcp/0
```

Every node's local API includes an OpenAI-compatible endpoint. `/v1/models`
lists the models that every reachable `inference` provider serves, and a
completion request is routed to a provider of the model it names. Ask node
B:

```bash
SOCK=~/node-b/agentmesh.sock

curl -s --unix-socket $SOCK http://localhost/v1/models

curl -s --unix-socket $SOCK http://localhost/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gemma3:1b","messages":[{"role":"user","content":"Say hello in five words."}]}'
```

The model list shows `gemma3:1b` with node A's peer ID as `owned_by`. Allow
a few seconds after A starts for B to learn about it: members announce their
services in a discovery table the router hosts, and the announcement takes
a moment to arrive.

The request went from B's socket to B, then over an authenticated connection
to A, through A's policy check, to Ollama, and back. Both nodes verified the
other's credential before any data moved. If A and B cannot reach each other
directly, the connection is relayed through the router inside `agentmesh-one`,
which carries ciphertext and learns only that the two are talking.

The socket needs no token: only your user can open it. To point an OpenAI
SDK at the mesh instead, give node B a TCP port with
`--bind-addr 127.0.0.1:8081` and a token as in the
[quick start](../quickstart/#3-run-the-node), then use
`http://127.0.0.1:8081/v1` as `base_url` and the token as `api_key`.

<!-- TODO(video): a short recording of steps 2 to 4 in three terminals. -->

## 5. Before you share it

- **Policy**: replace the open development policy. Write a
  [mesh policy](../../reference/policy/) file and start `agentmesh-one` with
  `--policy-file` on a fresh data directory, or edit the policy in the
  console. Once the database has a policy, the database is the source of
  truth.
- **Enrollment**: run with `--no-join-token` so members can only enroll with
  tokens you mint (`agentmesh-one token create`, single-use by default), or give
  the mesh an identity provider with `--issuer` and let people log in.
- **State**: keep the data directory on durable storage, or point
  `--db-driver postgres --db-dsn ...` at a database.
- **Tokens in logs**: read the admin token from `AGENTMESH_ADMIN_TOKEN` or
  `--admin-token-path` instead of the banner, and pass `--enroll-qr=false`
  in non-interactive environments.

The [agentmesh-one reference](../../reference/agentmesh-one/) lists every flag.

## Where next

- [Native SDKs](../../guides/native-sdks/): make a JavaScript or Python
  program a member, publish a tool from it and call it from another.
- [Exposing services](../../guides/exposing-services/): the three service
  types in detail and what the policy must grant for each. The
  [A2A chat](../../use-cases/chat-a2a/) and
  [Gemini Buddy](../../use-cases/gemini-buddy/) use cases run a complete
  agent behind each of the other two types.
- [Mobile](../../preview/mobile/): a phone as a member.
