---
title: "Getting started"
linkTitle: "Getting started"
weight: 1
---

Every Agent Mesh has a **control plane**, one or more **routers** and the
**members** (`agentmesh-node` or native SDK programs). The control plane
enrolls members and distributes policy. The routers keep the directory of
members and their services. A router relays traffic between two members
that cannot connect directly. The members enroll with the control plane and
connect to the routers.

To connect an agent or machine to a mesh, you need **a running control plane
and its URL** (`https://...`).

## How to get a control plane and its URL

Pick the option that matches what you want to do:

| Control plane option | How to run it and obtain its URL | Architecture & Ingress | Best for |
|---|---|---|---|
| **1. Shared Public Testnet** | Already running — use **`https://bananas.sam-mesh.dev`** | Hosted shared control plane and router | Trying `agentmesh-node` and calling your first remote tool or model in 60 seconds ([Quick start](quickstart/)). |
| **2. Local Control Plane (`agentmesh-one`)** | Run `agentmesh-one --data-dir ~/agentmesh-one --tunnel cloudflare --tunnel-install` and copy `API URL:` from the startup banner | Single binary (control plane + router + console) with SQLite and an HTTPS tunnel | Running your own private mesh from a workstation or VM in seconds ([Your own mesh](your-own-mesh/)). |
| **3. Codespace Control Plane (`agentmesh-one`)** | Open the repository in a [GitHub codespace](../guides/codespaces/), run `make testnet`, make port 8080 public | `agentmesh-one` in a container on your GitHub account, published on `https://<codespace>-8080.app.github.dev` | A control plane of your own with nothing installed and no cloud account, for as long as the codespace runs ([Codespaces](../guides/codespaces/)). |
| **4. Cloud Control Plane (`agentmesh-one`)** | **[Cloud Run](../guides/cloud-run/)**: `gcloud run deploy agentmesh-one --image ghcr.io/google/agentmesh-one:latest ...`<br>**[SkyPilot](../guides/skypilot/)**: `sky launch -c agentmesh-hub deploy/skypilot/agentmesh-one.yaml` | Always-on `agentmesh-one` with managed TLS/WSS ingress + PostgreSQL or persistent disk *(can also run on cloud free tiers for testing)* | Operating a dedicated production control plane in your own cloud account ([Cloud Run](../guides/cloud-run/) · [SkyPilot](../guides/skypilot/)). |

---

## Walkthroughs

1. **[Quick start](quickstart/)**: Join the public `bananas.sam-mesh.dev`
   testnet, discover remote MCP tools and inference models, and give your AI
   agent the Agent Mesh skill.
2. **[Your own mesh](your-own-mesh/)**: Start `agentmesh-one` in one command, grab
   the Control Plane URL from the startup banner, publish a local Ollama model,
   and call it from another node.
