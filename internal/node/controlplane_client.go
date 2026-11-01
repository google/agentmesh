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
	"net/http"
	"sync/atomic"
	"time"

	cpclient "github.com/google/agentmesh/internal/controlplane/client"
)

// allowInsecureControlPlane is process-wide because the control-plane URL
// reaches the node from several places (flag, store, mobile FFI) and every
// request to it must be held to the same transport policy.
var allowInsecureControlPlane atomic.Bool

// SetAllowInsecureControlPlane records the operator's --insecure-control-plane
// choice: plaintext http:// to a non-loopback control plane is then accepted.
func SetAllowInsecureControlPlane(allow bool) {
	allowInsecureControlPlane.Store(allow)
}

// controlPlaneHTTPClient is the client for every request the node makes to
// its control plane; the plaintext policy is re-checked on every hop.
func controlPlaneHTTPClient(timeout time.Duration) *http.Client {
	return cpclient.NewHTTPClient(timeout, allowInsecureControlPlane.Load, "agentmesh-node")
}

// cpHTTPClient returns an HTTP client honoring either the process-wide
// --insecure-control-plane setting or this node's Options.AllowInsecureControlPlane.
func (n *AgentMeshNode) cpHTTPClient(timeout time.Duration) *http.Client {
	return cpclient.NewHTTPClient(timeout, func() bool {
		return allowInsecureControlPlane.Load() || (n != nil && n.config.AllowInsecureControlPlane)
	}, "agentmesh-node")
}
