---
title: "A2A Chat"
linkTitle: "A2A Chat"
weight: 30
---

Hold a multi-turn conversation with an [A2A](https://a2a-protocol.org/)
(Agent2Agent) agent hosted on a remote mesh node, using a stock, unmodified
`a2a-sdk` client. There is no SAM-specific client code. The mesh regenerates
the agent card, and that is enough for the standard SDK to work as it is.

Source: [`development/examples/chat-a2a/`](https://github.com/google/sam/tree/main/development/examples/chat-a2a).

## The idea

A2A is how agents talk to each other on the mesh. An agent process that
speaks A2A over HTTP is declared on its node as a `type: a2a` service, and
remote peers reach it through the proxy path `/sam/{peer}/a2a/{service}/...`
(see [A2A agents](../../guides/exposing-services/#a2a-agents)).

The problem with proxying A2A directly is the agent card. A2A clients start
from `/.well-known/agent-card.json`, and the card contains the agent's own
interface URLs, which are addresses that are only reachable on the
provider's machine. A stock client would fetch the card through the mesh,
then try to talk to `http://127.0.0.1:7777/` and fail.

So the caller's node stands in for the card endpoint. It holds the client's
request, fetches the card from the agent over the mesh, and serves a
regenerated card whose interface URLs point back at the mesh path that the
client fetched from. Protocol bindings that the mesh cannot carry are
dropped (gRPC needs its own end-to-end connection), and streaming is
advertised as off. The client follows the regenerated card as it would for
any A2A server. Discovery, sending messages and `contextId` round-tripping
all work without changes, while the traffic flows over libp2p between the
nodes.

This example demonstrates both halves:

- **Card regeneration**: the bundled REPL is a plain `a2a-sdk` client. It
  works only because the regenerated card sends it back through the mesh.
- **Conversation continuity**: the agent keeps one Gemini chat session per
  A2A `contextId`. Tell it your name, then ask for it back two turns later.
  The answer shows that the context survived the mesh hop. Each turn is
  still its own short-lived A2A task (`taskId` changes every turn). The
  `contextId` is what persists and groups the turns into one conversation.

## The pieces

- **`chat` service** (`agent.py`): a Gemini-backed A2A agent built on the
  Python `a2a-sdk`. It serves its agent card, answers messages, and holds
  history on the server side, one Gemini chat session per `contextId`. The
  node proxies to it through `target_url`. The agent knows nothing about
  SAM.
- **REPL client** (`chat.py`): a stock `a2a-sdk` client of about forty lines
  that resolves the card through the mesh, then loops `input()` to a message
  send, echoing the `contextId` that the server created on the first reply.

## What you can do with it

- **Bring any A2A agent onto the mesh unchanged.** The example agent is
  plain `a2a-sdk` on purpose. Anything that speaks A2A over HTTP (ADK,
  LangGraph, a hosted agent) plugs in the same way, with one `target_url`
  line in the node configuration.
- **Use any stock A2A client.** `chat.py` is the smallest one. Because of the
  regenerated card, SDKs, CLIs and other agents resolve and call the service
  without knowing that SAM exists.
- **Let the agent own the conversation.** This is the same pattern as
  [Gemini Buddy](../gemini-buddy/), on the standard A2A protocol instead of
  a custom MCP tool. State lives with the agent, keyed by `contextId`, and
  callers only send the next message.

## Try it on kind

The repository ships a [kind](https://kind.sigs.k8s.io/)-based local mesh
that brings the agent up with one command.

### 1. Set a Gemini key for the agent image

`agent.py` calls Gemini, so set your API key on the `ENV GEMINI_API_KEY`
line in `development/examples/chat-a2a/Dockerfile` before building. A free
Google AI Studio key is enough for the demo.

### 2. Bring the mesh up and deploy the agent

```bash
make build            # builds ./bin/sam-node (once)
make kind-up          # control plane + router (no sam-nodes yet)
docker build -t chat-a2a:local development/examples/chat-a2a
kind load docker-image --name sam-kind chat-a2a:local
helm --kube-context kind-sam-kind -n sam-kind install chat-a2a charts/sam-node \
  -f development/kind/sam-node.values.yaml \
  -f development/examples/chat-a2a/values.yaml
```

### 3. Enroll a local caller node

```bash
make kind-local-node  # a local sam-node enrolled in the mesh; leave it running
```

The local node is your entry point. Its API listens on
`http://127.0.0.1:9099` (token `devtoken`), with the MCP tools at `/mcp`.

### 4. Find the provider peer

```bash
./bin/mcp-client -url http://127.0.0.1:9099/mcp -token devtoken \
  -tool discover_remote_services -args '{"type":"a2a","name":"chat"}'
```

Note the peer ID and export it as `PEER`. Discovery is fed by gossip, so
retry for a few seconds after startup if the list comes back empty.

### 5. Watch the card regeneration happen

Fetch the agent card through the mesh with `curl`:

```bash
curl -s -H 'X-Sam-Authentication: Bearer devtoken' \
  "http://127.0.0.1:9099/sam/$PEER/a2a/chat/.well-known/agent-card.json" | jq
```

The interface URLs in the response point back at this
`/sam/{peer}/a2a/chat` path, and not at the agent's own `127.0.0.1:7777`.
`capabilities.streaming` is `false`. That regenerated card is what makes the
example work.

### 6. Chat

Requires [`uv`](https://docs.astral.sh/uv/).

```bash
cd development/examples/chat-a2a
uv run --with-requirements requirements.txt chat.py \
  "http://127.0.0.1:9099/sam/$PEER/a2a/chat"
```

To check the continuity: introduce yourself in one turn, chat about
something else, then ask the agent what your name is. It answers from its
own server-side session. The client never sent the history again, only the
`contextId`.

The official [`a2a` CLI](https://github.com/a2aproject/a2a-cli) is another
stock client. Its reply prints the `contextId` the server created; pass it
back as `--context-id` and the agent continues the same conversation:

```bash
export A2ACLI_SVC_PARAM='X-Sam-Authentication=Bearer devtoken'
CARD="http://127.0.0.1:9099/sam/$PEER/a2a/chat/.well-known/agent-card.json"
a2a send -a "$CARD" "hello, I am Ada"
a2a send -a "$CARD" --context-id <contextId from the first reply> "what is my name?"
```

## Configuration

| var | default | used by |
|-----|---------|---------|
| `GEMINI_API_KEY` | *(placeholder, set in the Dockerfile)* | agent |
| `GEMINI_MODEL` | `models/gemini-3.5-flash-lite` *(set in the Dockerfile)* | agent |

The listen port (`7777`) is a constant at the top of `agent.py`.
