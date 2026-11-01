// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"time"

	"github.com/google/agentmesh/api"
	cpclient "github.com/google/agentmesh/internal/controlplane/client"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// maxControlPlaneBodyBytes caps every response body read from the control
// plane or an IdP: a misbehaving or impersonated server must not be able to
// make the node buffer arbitrary amounts of memory. Bodies that carry a
// message go through cpclient.ReadBody, which turns an oversized answer into
// an error rather than a truncated message.
const maxControlPlaneBodyBytes = cpclient.MaxBodyBytes

// controlPlaneClient speaks the pull endpoints of controlPlaneURL through the
// node's transport policy.
func controlPlaneClient(controlPlaneURL string) *cpclient.Client {
	return cpclient.New(controlPlaneURL, controlPlaneHTTPClient(10*time.Second))
}

// controlPlane returns a control plane client configured with this node's
// peer ID and private key so authenticated requests carry a signed challenge.
func (n *AgentMeshNode) controlPlane(controlPlaneURL string) *cpclient.Client {
	if n == nil {
		return controlPlaneClient(controlPlaneURL)
	}
	c := cpclient.New(controlPlaneURL, n.cpHTTPClient(10*time.Second))
	priv := n.config.PrivKey
	if priv == nil && n.Store != nil {
		if kb, err := n.Store.LoadKey(); err == nil {
			if len(kb) > 0 {
				priv, _ = crypto.UnmarshalPrivateKey(kb)
			} else {
				priv, _ = LoadOrGenerateKey(n.Store)
			}
		}
	}
	if priv != nil {
		pid, err := n.localPeerID()
		if err != nil || pid == "" {
			pid, _ = peer.IDFromPrivateKey(priv)
		}
		if pid != "" {
			c.WithIdentity(pid.String(), priv)
		}
	}
	return c
}

func (n *AgentMeshNode) fetchControlPlaneInfo(ctx context.Context, controlPlaneURL string) (*api.ControlPlaneInfoResponse, error) {
	return n.controlPlane(controlPlaneURL).FetchInfo(ctx)
}

// fetchControlPlaneKeys retrieves the full set of currently valid control
// plane public keys from /keys, the same catch-up path routers use.
// Enrollment only hands out the newest key, so this is how a node learns
// keys still in their rotation grace period, or rotations it missed while
// offline. The set is accepted only if signed by a key in trusted.
func (n *AgentMeshNode) fetchControlPlaneKeys(ctx context.Context, controlPlaneURL string, trusted []ed25519.PublicKey) ([]ed25519.PublicKey, error) {
	return n.controlPlane(controlPlaneURL).FetchKeys(ctx, trusted)
}

// FetchControlPlaneInfo retrieves the latest configuration from the control plane's /info endpoint.
func FetchControlPlaneInfo(ctx context.Context, controlPlaneURL string) (*api.ControlPlaneInfoResponse, error) {
	return controlPlaneClient(controlPlaneURL).FetchInfo(ctx)
}

// mergeTrustedKeys replaces the stored trust set with the authoritative set
// from /keys, preserving ReceivedAt for keys already known so local grace
// pruning keeps working across syncs.
func mergeTrustedKeys(existing []TrustedKey, fetched []ed25519.PublicKey, now time.Time) []TrustedKey {
	merged := make([]TrustedKey, 0, len(fetched))
	for _, key := range fetched {
		tk := TrustedKey{Key: key, ReceivedAt: now}
		for _, old := range existing {
			if bytes.Equal(old.Key, key) {
				tk.ReceivedAt = old.ReceivedAt
				break
			}
		}
		merged = append(merged, tk)
	}
	return merged
}

func publicKeysOf(keys []TrustedKey) []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, 0, len(keys))
	for _, tk := range keys {
		out = append(out, tk.Key)
	}
	return out
}

// ReportNodeCatalog self-reports this node's locally registered services to
// the control plane's /nodes/catalog endpoint, so an admin can see mesh-wide
// service topology (see catalog.go's HandleNodeCatalog for why this exists
// instead of the control plane discovering it via DHT/P2P itself).
func ReportNodeCatalog(ctx context.Context, controlPlaneURL string, biscuitToken []byte, services []*api.ServiceInfo) error {
	return controlPlaneClient(controlPlaneURL).ReportCatalog(ctx, biscuitToken, services)
}
