---
title: "Control and data boundaries"
linkTitle: "Boundaries"
weight: 5
---

When you run your own control plane, you decide everything about the mesh.
On the public testnets, someone else decides who joins and what the policy
says. This page lists the decisions that become yours in a dedicated
deployment and the mechanism that enforces each of them.

## What you control in a dedicated deployment

- **Membership.** Enrollment goes through your identity provider or through
  bootstrap tokens that you mint. The bindings in the control plane decide
  which identities receive which roles. An identity without a binding cannot
  enroll a node.
- **The signing key.** The control plane generates its Ed25519 signing keys
  and stores them in its database. Every credential in the mesh is signed by
  one of these keys, and nobody outside the deployment can mint or extend a
  credential. The keys rotate on the schedule you set.
- **The policy.** What each role may call, on which nodes and with which
  labels, is stored in your database. It can only be changed with your admin
  token or through your console.
- **Revocation.** A ban takes effect on the next credential refresh (within
  the credential TTL, 24 hours by default) and, through the mesh event
  channel, immediately on every connected node.
- **Where the software runs.** Agent Mesh is Apache-2.0, sends no telemetry, and
  does not depend on any hosted service. The control plane, routers and
  nodes run wherever you put them: a laptop, a private cluster, an
  air-gapped network.

The public testnets give you none of this. They are useful for trying the
software. Do not put anything there that you would not publish.

## Where data goes

The control plane is not on the data path. A request from an agent goes from
its node to the provider's node over an encrypted libp2p stream. The stream
is relayed through a router only when the two nodes cannot connect directly,
and the relay sees only ciphertext. No part of a request, its arguments or
its result is recorded centrally.

Routers are on the path, so place them with care. If the nodes in a region
use a router in that region, relayed traffic between them stays in the
region.

## Keeping data inside a boundary

Labels are how a deployment expresses facts such as "this node is in the EU"
or "this node handles HIPAA data". A node declares its labels, the control
plane attests only the labels that the node's role permits, and the labels
become signed facts in the node's credential. Three mechanisms can then hold
a boundary:

- **A provider refuses callers from outside the boundary.**
  `check if label("jurisdiction", "eu")` in the provider node's
  `attenuation.checks` rejects any caller whose credential lacks that fact,
  regardless of what the mesh policy granted.
- **A caller refuses providers outside the boundary.** With
  `X-Mesh-Required-Labels` on a request, the calling node verifies the
  provider's credential before it sends anything. A provider that cannot
  show every label named is skipped.
- **An operator sets a floor for a whole node.** `egress.require_labels` in
  the node configuration applies to every outbound request from that node.
  Callers cannot lower it.

All three mechanisms act on signed facts, not on discovery data, and all
three fail closed. A provider whose credential cannot be fetched or verified
is treated as if it did not have the label.

## The host has the final say

The node that publishes a service decides who calls it. The mesh policy
grants access. The node's `attenuation` block can add checks that the caller
must also satisfy, and `deny` rules that override a grant. This is
intentional. The central policy states what the operator of the mesh
intends. The operator of the machine that holds the data can always refuse.

## Evidence

Two endpoints on the node's local API expose what the node knows, for audit
or automation. They are reachable only over the node's Unix socket or over
mTLS.

- `GET /mesh/identity` returns the node's own credential, the control plane
  public key it was verified against, and its roles, labels and expiry.
- `GET /mesh/peer/{peer-id}/evidence` returns the same information for a peer
  that the node has authenticated.

Both results can be verified offline with the control plane's public key.

## Why credentials expire

A credential lasts 24 hours by default and is renewed in the background.
Short lifetimes make revocation work without a central check on every
request. A stolen credential is useful for at most its remaining lifetime. A
banned node cannot renew. Under automatic rotation, the control plane
retires each signing key one grace period after the next rotation. A node
that was offline past the retirement of the key that signed its credential
has to come back through enrollment. So the node cannot reappear without
notice. The one exception is a node that an administrator opted in to
autonomous recovery. The lifetime, the session length, the rotation
interval and the grace period are all control plane flags that the operator
sets.

## See also

- [Identity](../identity/) for enrollment, refresh, rotation and revocation.
- [Authorization](../authorization/) for labels and local rules in detail.
- [Kubernetes](../../guides/kubernetes/) and [your own mesh](../../getting-started/your-own-mesh/)
  for deploying a control plane.
