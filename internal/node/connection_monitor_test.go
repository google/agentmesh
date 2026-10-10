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
	"context"
	"errors"
	"testing"

	"github.com/google/agentmesh/api"
	"github.com/multiformats/go-multiaddr"
)

type mockRouterConnectionManager struct {
	connected          bool
	meshConfigErr      error
	storedAddrs        []string
	controlPlaneURLErr error
	controlPlaneURL    string
	discoverErr        error
	discoverResp       *api.ControlPlaneInfoResponse
	connectP2PErr      error
	connectHTTPErr     error
	saveConfigErr      error

	// connectCalls counts calls to ConnectAndAuthWithRouter so it can return
	// connectP2PErr for the first (P2P, stored-address) attempt and
	// connectHTTPErr for the second (HTTP fallback, discovered-address)
	// attempt. A static "which attempt is this" flag can't tell the two
	// calls apart, since it's fixed for the whole test case before either
	// call happens - that let the P2P attempt silently return the HTTP
	// result and skip exercising the real P2P failure path.
	connectCalls int
}

func (m *mockRouterConnectionManager) IsConnected() bool {
	return m.connected
}

func (m *mockRouterConnectionManager) LoadMeshConfig() ([]byte, []string, error) {
	return nil, m.storedAddrs, m.meshConfigErr
}

func (m *mockRouterConnectionManager) ConnectAndAuthWithRouter(ctx context.Context, addr multiaddr.Multiaddr) error {
	m.connectCalls++
	if m.connectCalls == 1 {
		return m.connectP2PErr
	}
	return m.connectHTTPErr
}

func (m *mockRouterConnectionManager) LoadControlPlaneURL() (string, error) {
	return m.controlPlaneURL, m.controlPlaneURLErr
}

func (m *mockRouterConnectionManager) DiscoverControlPlaneInfo(ctx context.Context, url string) (*api.ControlPlaneInfoResponse, error) {
	return m.discoverResp, m.discoverErr
}

func (m *mockRouterConnectionManager) SaveMeshConfig(pubKey []byte, addrs []string) error {
	return m.saveConfigErr
}

func (m *mockRouterConnectionManager) UpdateRelays(addrs []multiaddr.Multiaddr) {}

func TestCheckRouterConnection(t *testing.T) {
	cases := []struct {
		name       string
		mgr        *mockRouterConnectionManager
		wantStable bool
		wantReconn bool
	}{
		{
			name: "already connected",
			mgr: &mockRouterConnectionManager{
				connected: true,
			},
			wantStable: true,
			wantReconn: false,
		},
		{
			name: "disconnected, reconnects via P2P",
			mgr: &mockRouterConnectionManager{
				connected:     false,
				storedAddrs:   []string{"/ip4/127.0.0.1/tcp/4001"},
				connectP2PErr: nil,
			},
			wantStable: false,
			wantReconn: true,
		},
		{
			name: "disconnected, P2P fails, reconnects via HTTP",
			mgr: &mockRouterConnectionManager{
				connected:       false,
				storedAddrs:     []string{"/ip4/127.0.0.1/tcp/4001"},
				connectP2PErr:   errors.New("p2p failed"),
				controlPlaneURL: "https://cp.example.com",
				discoverResp: &api.ControlPlaneInfoResponse{
					RouterAddresses: []string{"/ip4/127.0.0.1/tcp/4002"},
				},
				connectHTTPErr: nil,
			},
			wantStable: false,
			wantReconn: true,
		},
		{
			name: "disconnected, all fail",
			mgr: &mockRouterConnectionManager{
				connected:       false,
				storedAddrs:     []string{"/ip4/127.0.0.1/tcp/4001"},
				connectP2PErr:   errors.New("p2p failed"),
				controlPlaneURL: "https://cp.example.com",
				discoverResp: &api.ControlPlaneInfoResponse{
					RouterAddresses: []string{"/ip4/127.0.0.1/tcp/4002"},
				},
				connectHTTPErr: errors.New("http fallback connect failed"),
			},
			wantStable: false,
			wantReconn: false,
		},
		{
			name: "disconnected, HTTP discovery fails",
			mgr: &mockRouterConnectionManager{
				connected:       false,
				storedAddrs:     []string{"/ip4/127.0.0.1/tcp/4001"},
				connectP2PErr:   errors.New("p2p failed"),
				controlPlaneURL: "https://cp.example.com",
				discoverErr:     errors.New("discovery failed"),
			},
			wantStable: false,
			wantReconn: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stable, reconnected := checkRouterConnection(context.Background(), tc.mgr)
			if stable != tc.wantStable {
				t.Errorf("expected stable %v, got %v", tc.wantStable, stable)
			}
			if reconnected != tc.wantReconn {
				t.Errorf("expected reconnected %v, got %v", tc.wantReconn, reconnected)
			}
		})
	}
}
