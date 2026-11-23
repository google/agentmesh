---
title: "Agent Mesh Connect (web)"
linkTitle: "Agent Mesh Connect web app"
weight: 4
---

{{% alert title="Preview" color="warning" %}}
The Agent Mesh Connect web app is a page that `agentmesh-webapp` serves. It
puts the browser on a mesh as a member and needs no install. It does not offer
services.
{{% /alert %}}

The web app runs the [JavaScript SDK](../../guides/native-sdks/) in a browser
page. It belongs to no mesh: you enter the address of the mesh's control
plane, or open a join link that carries it. The page enrolls with an enrollment token, or with the account you sign
in with when the mesh has a sign-in provider. It keeps its key and credential
in the browser's storage, and joins the mesh through the router over a secure
WebSocket or WebTransport. A browser enrolled this way is a member like any
other. It has a key, a credential and a peer ID, which the app calls the
**Node ID**.

## Join the mesh from a browser

You need a mesh, `agentmesh-webapp` and a current browser. A browser on
another machine must reach both the mesh and the page over `https`, because a
page served over plain `http` from another machine is not a secure context
and cannot hold a key. On one computer, `http://127.0.0.1` works for both.

1. Start a mesh. For a browser on another machine, give it a public `https`
   address. With `agentmesh-one`, a Cloudflare quick tunnel needs no account:

   ```bash
   agentmesh-one --data-dir ~/agentmesh-one --tunnel cloudflare --tunnel-install
   ```

   Expect: the banner shows the mesh's address on its **API URL** line, and a
   `mesh://enroll?server=…&token=…` code under the QR code.

2. Start the web app:

   ```bash
   agentmesh-webapp
   ```

   Expect: `Agent Mesh web app listening on 127.0.0.1:8082`.

3. For a browser on another machine, put the page behind `https`, for example
   with a second quick tunnel:

   ```bash
   cloudflared tunnel --url http://127.0.0.1:8082
   ```

   Expect: cloudflared prints the page's `https://….trycloudflare.com` address.

4. Open the page's address in the browser.

   Expect: the welcome screen, with **Mesh address** and **Enrollment link,
   code or token**.

5. Paste the `mesh://enroll` code into **Enrollment link, code or token** and
   tap **Join with token**. The code carries the mesh's address and a
   single-use token. Or enter the **API URL** in **Mesh address** and paste
   a token: the banner's **Join Token** admits any number of devices, and
   `agentmesh-one token create --data-dir ~/agentmesh-one --server <API URL>`
   mints a single-use one.

   Expect: a dialog that names the mesh's address. Tap **Join**.

   Expect: the dashboard shows **Node is Running**, the **Node ID** and the
   number of **Routers** that hold a relay slot for the browser.

A link of the form `<page address>#server=<mesh address>&token=<token>` joins
the same way. The values travel after the `#`, which browsers never send to a
server, and the page removes them from the address bar before it does
anything else. A link with `#server=<mesh address>` alone fills in **Mesh
address**, so the mesh's **Sign in** shows at once.

A browser belongs to one mesh at a time. Once it has joined, **Mesh address**
is fixed, and the page refuses a code or link for another mesh. **Reset
device identity** frees it.

Every browser gets its own Node ID. The key lives in the storage of the
browser that enrolled, and browsers do not share it.

## What the screens show

Before the browser enrolls, the app shows only the welcome view: **Mesh
address**, **Sign in** when that mesh has a sign-in provider, the field for
the enrollment link, code or token, and the optional **Labels** the control
plane attests at enrollment.
The tabs appear once the browser has enrolled.

| Tab | What it shows |
| --- | --- |
| **Dashboard** | **Node is Running** or **Node is Stopped**, the mesh's address, **Connected Peers**, **Routers**, the **Node ID**, and **Start** and **Stop**. **Unenroll / Clear Identity** is at the bottom. |
| **Config** | **Device**: the labels this browser enrolled with, whether the browser keeps the storage, and until when the current credential is valid. On a computer, **Local agent** connects an agent on that computer. The version is at the bottom. |

**Routers** counts the routers that hold a relay slot for the browser,
because peers reach it through them.

The node runs only while the page is open. The app remembers whether you left
it running. If you did, it rejoins on its own the next time it opens, with the
same Node ID. If you pressed **Stop**, it waits for **Start**.

Install the app to keep its storage: in Chrome or Edge, use **Install app** in
the menu; in Safari, use **Add to Home Screen** or **Add to Dock**. Safari
deletes a site's storage after seven days without a visit, which deletes the
identity with it. The **Config** tab shows whether the browser has promised
to keep it.

## Coming back after a day or more

The credential lasts 24 hours, and the app renews it while it is open. A
credential that lapsed while the app was closed is renewed when the app
opens.

The mesh also rotates its signing key every 24 hours and keeps the old key
for one more hour. A credential issued under a key that retired cannot be
renewed. So a browser that stayed closed for more than about 25 hours shows
**The mesh no longer accepts this device** and **Rejoin the mesh**. Paste a
new token or code from `agentmesh-one token create`, tap **Join with token**, then
**Join**, or tap **Sign in** again. The browser keeps its Node ID. A banned
device cannot rejoin with its key. **Unenroll / Clear Identity** on that screen resets it, and so does
**Reset device identity** on the welcome screen of a browser that kept its key.

An operator who accepts the risk can mint tokens with `token create
--autonomous-recovery`. Browsers enrolled with such a token keep renewing after
a rotation, and a lost device then keeps renewing until an operator bans it.

## Unenroll and reset the device identity

**Unenroll / Clear Identity** opens a dialog with two choices:

- **Unenroll** deletes the credential and keeps the key. The next enrollment,
  with any token, brings back the same Node ID.
- **Reset device identity** also deletes the key and frees **Mesh address**.
  The next enrollment looks like a device the mesh has never seen, and it can
  be into another mesh.

Both are local. The control plane keeps the node's record until an operator
revokes or bans it in the console.

## Where the identity lives

The key and the credential are in the browser's storage for the page's
address. Clearing the site's data in the browser deletes them. Two
consequences follow, because a Cloudflare quick tunnel gets a new address
every time it starts:

- A new page address is a new site to the browser, so the browser enrolls
  again.
- A new mesh address is another mesh to the page. The browser must **Reset
  device identity**, then enroll again.

For a page and a mesh that browsers stay with, use named tunnels or fixed
addresses.

Only one tab or window of the app runs at a time. A second one shows **Agent
Mesh is open in another tab or window** and offers **Use here**, which takes
over and stops the first.

## Sign in with your account

When the control plane has a sign-in provider, the welcome screen shows
**Sign in with** and the provider's host. The browser then joins with the
account you sign in with, and needs no token. Once **Mesh address** holds the
mesh's address, the app asks that control plane's `/info` for the provider,
and shows the button only if the provider's discovery document answers the
page.

1. Tap **Sign in with** and the provider's host.

   Expect: the provider's sign-in page.

2. Sign in.

   Expect: the app opens again and shows **Node is Running**.

The control plane renews the credential without a new sign-in until the
session ends. The session lasts 90 days, which `agentmesh-control-plane`
changes with `--oidc-session-ttl`. After that, or after a key rotation the
browser missed, the app shows **Rejoin the mesh** and **Sign in** again. The
browser keeps its Node ID.

The operator sets up four things:

- `agentmesh-one` or `agentmesh-control-plane` runs with `--issuer`, the
  provider's issuer URL.
- The provider has a public client for the client ID the control plane
  advertises: `--oidc-client-id`, or else the first of `--allowed-audiences`.
  The client lists the page's address, such as `https://app.example.com/`,
  as a redirect URI.
- The provider allows requests from the page's origin, such as
  `https://app.example.com`, to its discovery and token endpoints. In Dex,
  that is `web.allowedOrigins`.
- The mesh policy binds `mesh:role:node` to the people who may join, or to
  `mesh:system:authenticated` for everyone the provider signs in.

## Use the node from an agent on your computer

On a computer, the app can offer the node to an MCP agent that runs on the same
computer, such as Claude Code or Cursor. The agent gets the five tools
`agentmesh-node` serves on `/mcp`: `get_mesh_info`, `discover_remote_services`,
`find_remote_tools`, `describe_remote_tool` and `call_remote_tool`. Its calls
use this node's identity and the mesh policy. A device whose only pointer is a
touch screen, such as a phone, does not show this option.

The agent reaches the page through a local relay, a program that runs beside
the agent and needs Node.js 22. The web app serves the relay as one
JavaScript file at `sdk/agentmesh-relay.mjs` under the page's address. It is built on the
[WebMCP local relay](https://docs.mcp-b.ai/packages/webmcp-local-relay). You
save it once, so starting the agent runs that copy and downloads nothing.
The agent pairs with the page once, and the page then runs only calls that the
paired agent signed.

1. Open the app on the computer, open the **Config** tab and press
   **Connect a local agent**.

   Expect: the card shows a prompt for your agent, with a pairing token and
   the time it expires.

2. Copy the prompt and paste it into your agent. The prompt works with any
   MCP agent. It asks the agent to:
   1. save the relay as `~/.local/share/agentmesh/webapp-relay/relay.mjs`,
      with a `node -e` command that works on any system;
   2. add the relay as a local MCP server named `agentmesh-webapp`;
   3. call `pair_agent` with the token, then `get_mesh_info`.

   The agent asks you once to approve the first two steps, then works
   without asking again. An agent that cannot change its configuration tells
   you what to add.

3. If the agent loads MCP servers only when it starts, restart it when it
   asks. With Claude Code, quit it and run `claude --continue` to come back
   to the same conversation, then ask it to go on.

   Expect: the card lists the agent by name, the agent shows a `peer_id`
   equal to the app's **Node ID**, and the Dashboard shows **Local agent …
   connected** with the agent's last call.

The token works once. If nobody uses it within 10 minutes, the page replaces
it and the prompt changes. An agent that uses an old token gets **The
pairing token is wrong, expired or already used**. Copy the prompt again.

To add the relay by hand, open **Add the relay by hand** on the card. It shows
the download command and the server in the `mcpServers` form that most agents'
configuration files take. Write `~` as your home folder's full path, because
an agent starts the server without a shell. With Claude Code, run the download
command from the card, then:

```bash
claude mcp add agentmesh-webapp -- node ~/.local/share/agentmesh/webapp-relay/relay.mjs --widget-origin https://app.example.com --agent-name "Claude Code"
```

Then paste the prompt, so the agent pairs.

If the agent's calls fail with **wrong signature** after the mesh is updated,
run the download command again and restart the agent's MCP server.

One relay serves one page on a computer. Open the app in one browser at a
time while an agent is connected, and use one mesh at a time.

Keep the app open with the node running while the agent uses the tools. If
the agent restarts, the open page finds the new relay within a few seconds.

The relay keeps the key it shares with the page in
`~/.config/agentmesh/webapp-relay/<page address>/<agent name>.json`, which only
your user can read. The page keeps the same key in the browser's storage. A
restarted agent or a reloaded page stays paired. To pair a second agent, press
**Pair another agent**. **Forget** next to an agent deletes its key in the
page, and that agent must pair again.

The **Local agent** card lists the last calls, which agent made each one and
what it aimed at, such as
`Claude Code: call_remote_tool mcp://calc/add on 12D3KooW…xYz`.

The relay listens on `127.0.0.1`, and the page connects to it. `--widget-origin`
makes the relay accept only this app. A program under your own user account can
read the relay's key file and the node's key in the browser's storage, the same
as with `agentmesh-node`'s API token. A program under another user account
cannot call the tools without the key. If it takes the relay's port before your
agent does, it can still read the tool list, and read and change the results of
your calls.
Chrome may ask whether the page can reach devices on your local network; allow
it for this app. **Disconnect local agent** withdraws the tools.

## Requirements

- An `https` address for the page and for the mesh. On one computer,
  `http://127.0.0.1` works for both, which is handy for development.
- A current Chrome, Edge, Firefox or Safari.

## Build and deploy the app

The app's own files are in `internal/webapp/public` and are embedded in
`agentmesh-webapp`. `make all` builds the SDK bundle they import from
`sdk/js`, which needs Node.js 22, and then the binaries:

```bash
make all
```

The container image builds it too. `make build` builds the binaries only.
`agentmesh-webapp` still runs: it logs a warning, and the page tells whoever
opens it that the app is missing.

`agentmesh-webapp` serves the page at `/` and knows no mesh. One deployment
serves any mesh. Its image is `ghcr.io/google/agentmesh-webapp`, and the
`agentmesh-webapp` Helm chart deploys it, with an optional Gateway.

| Flag | Default | Meaning |
|---|---|---|
| `--bind-addr` | `127.0.0.1:8082` | HTTP listen address. Set `:8082` in a container. |
| `--version` | | Print the version and exit. |

The page loads its files relative to its own address, so a proxy can serve it
under a prefix, such as `/node/`, if it strips the prefix before
`agentmesh-webapp`. Serve it over `https` for devices other than the one it
runs on.
