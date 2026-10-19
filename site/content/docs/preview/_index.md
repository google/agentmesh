---
title: "Preview"
linkTitle: "Preview"
weight: 6
---

Features that work end to end and are tested in CI, but whose interfaces,
flags or file formats may still change between releases. You can use them
today. Expect to adjust your configuration when you upgrade, and report what
you find.

- [Sandboxed agents](sandboxed-agents/): run an agent inside a sandbox that
  has no network interface and holds no credentials. A boundary process
  outside the sandbox decides which names the agent may reach.
- [Agent architecture](agent-architecture/): the design behind the
  sandbox: why the boundary uses named HTTP tunnels, how an agent gets an
  identity, and how an agent serves.
- [Agent Mesh Connect](mobile/): the Android and iOS app that turns a phone into a
  node.

Everything outside this section (the node, the routers, the control plane,
identity, policy and the deployment guides) is the stable core.
