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
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/agentmesh/internal/logging"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Bound the diagnostic dials so a dead peer yields an error instead of a
// request that hangs for as long as the caller's patience.
const (
	connectivityPingTimeout = 15 * time.Second
	connectPeerTimeout      = 30 * time.Second
)

// newDebugHandler serves the operator diagnostics under /debug. These were MCP
// tools once; they moved here so agents never see them in their tool list (#318).
func newDebugHandler(n *AgentMeshNode) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/mesh-info", func(w http.ResponseWriter, r *http.Request) {
		info, err := n.meshInfo()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeDebugJSON(w, info)
	})
	mux.HandleFunc("GET /debug/connectivity", func(w http.ResponseWriter, r *http.Request) {
		writeDebugJSON(w, n.connectivityStats(r.Context(), r.URL.Query().Get("peer_id")))
	})
	mux.HandleFunc("GET /debug/network-info", func(w http.ResponseWriter, r *http.Request) {
		writeDebugJSON(w, n.networkInfo())
	})
	mux.HandleFunc("GET /debug/peer-addrs", func(w http.ResponseWriter, r *http.Request) {
		pid, err := peer.Decode(r.URL.Query().Get("peer_id"))
		if err != nil {
			http.Error(w, "invalid peer id", http.StatusBadRequest)
			return
		}
		resp, err := n.peerAddrs(r.Context(), pid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeDebugJSON(w, resp)
	})
	mux.HandleFunc("GET /debug/token-info", func(w http.ResponseWriter, r *http.Request) {
		writeDebugJSON(w, n.tokenInfo())
	})
	mux.HandleFunc("GET /debug/logs", func(w http.ResponseWriter, r *http.Request) {
		writeDebugJSON(w, logsResponse{Logs: logging.RecentLogs()})
	})
	mux.HandleFunc("POST /debug/connect-peer", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PeerAddr string `json:"peer_addr"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if req.PeerAddr == "" {
			http.Error(w, "peer_addr is required", http.StatusBadRequest)
			return
		}
		if err := n.connectPeer(r.Context(), req.PeerAddr); err != nil {
			http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusInternalServerError)
			return
		}
		writeDebugJSON(w, map[string]string{"status": "connected"})
	})

	// One guard for every handler: refuse loudly on a half-built node instead
	// of panicking mid-request or fabricating zero-value diagnostics.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := n.debugReady(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// debugReady reports whether the components the /debug handlers touch exist.
func (n *AgentMeshNode) debugReady() error {
	switch {
	case n == nil:
		return fmt.Errorf("node not initialized")
	case n.Host == nil:
		return fmt.Errorf("libp2p host not initialized")
	case n.Directory == nil:
		return fmt.Errorf("the directory is not up")
	case n.Store == nil:
		return fmt.Errorf("node store not initialized")
	}
	return nil
}

func writeDebugJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Errorf("Failed to encode response: %v", err)
	}
}

// The types below are the /debug payloads. They are unexported on purpose:
// these endpoints are unversioned operator diagnostics, not part of the
// api/agentmesh.proto mesh contract.

type meshInfoResponse struct {
	PeerID          string   `json:"peer_id"`
	ConnectedPeers  []string `json:"connected_peers"`
	AttachedRouters []string `json:"attached_routers"`
	RouterPeerID    string   `json:"router_peer_id"`
	IngressURLs     []string `json:"ingress_urls,omitempty"`
	LocalAPISocket  string   `json:"local_api_socket,omitempty"`
}

type connectivityResponse struct {
	ConnectedPeers  int    `json:"connected_peers"`
	TotalKnownPeers int    `json:"total_known_peers"`
	PingLatencyMS   *int64 `json:"ping_latency_ms,omitempty"`
	PingError       *bool  `json:"ping_error,omitempty"`
	PingErrorMsg    string `json:"ping_error_msg,omitempty"`
	RouterLatencyMS *int64 `json:"router_latency_ms,omitempty"`
	RouterError     *bool  `json:"router_error,omitempty"`
	RouterErrorMsg  string `json:"router_error_msg,omitempty"`
}

type tokenInfoResponse struct {
	HasToken         bool     `json:"has_token"`
	ExpiresInSeconds *float64 `json:"expires_in_seconds,omitempty"`
	IsExpired        *bool    `json:"is_expired,omitempty"`
}

type networkInfoResponse struct {
	ListenAddresses    []string `json:"listen_addresses"`
	AnnouncedAddresses []string `json:"announced_addresses"`
	// DirectoryAddresses is what the directory holds for this node: the
	// addresses of the record it last announced, which follow
	// AnnouncedAddresses at the next announcement pass.
	DirectoryAddresses []string `json:"directory_addresses"`
}

// recordAnnouncer is a directory that remembers the record it last
// announced.
type recordAnnouncer interface {
	Announced() []multiaddr.Multiaddr
}

// peerAddrsResponse is what the DHT says about a peer: the addresses it
// published, before this node decides which to dial.
type peerAddrsResponse struct {
	PeerID    string   `json:"peer_id"`
	Addresses []string `json:"addresses"`
}

type logsResponse struct {
	Logs []string `json:"logs"`
}

// meshInfo backs both the get_mesh_info MCP tool and GET /debug/mesh-info.
// The MCP path skips the /debug boundary guard, so it re-checks here.
func (n *AgentMeshNode) meshInfo() (*meshInfoResponse, error) {
	if err := n.debugReady(); err != nil {
		return nil, err
	}

	peers := n.Host.Network().Peers()
	// Pre-sized so zero peers serializes as [] rather than null.
	connectedPeers := make([]string, 0, len(peers))
	for _, p := range peers {
		connectedPeers = append(connectedPeers, p.String())
	}
	// Routers the node holds as relays, a subset of the connected peers: a
	// DHT query connects the node to other routers without attaching to them.
	attached := n.attachedRouters()
	attachedRouters := make([]string, 0, len(attached))
	for _, p := range attached {
		attachedRouters = append(attachedRouters, p.String())
	}
	slices.Sort(attachedRouters)

	return &meshInfoResponse{
		PeerID:          n.Host.ID().String(),
		ConnectedPeers:  connectedPeers,
		AttachedRouters: attachedRouters,
		RouterPeerID:    n.RouterPeerID.String(),
		IngressURLs:     n.routerIngressURLs(),
		LocalAPISocket:  n.BoundSocketPath,
	}, nil
}

// peerAddrs backs GET /debug/peer-addrs: the addresses the DHT holds for a
// peer, looked up and not dialed, so an operator can see what a call would
// have to work with without making one.
func (n *AgentMeshNode) peerAddrs(ctx context.Context, pid peer.ID) (*peerAddrsResponse, error) {
	if err := n.debugReady(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
	defer cancel()
	info, err := n.Directory.FindPeer(ctx, pid)
	if err != nil {
		return nil, fmt.Errorf("find %s: %w", pid, err)
	}
	resp := &peerAddrsResponse{PeerID: pid.String(), Addresses: make([]string, 0, len(info.Addrs))}
	for _, a := range info.Addrs {
		resp.Addresses = append(resp.Addresses, a.String())
	}
	slices.Sort(resp.Addresses)
	return resp, nil
}

// connectivityStats backs GET /debug/connectivity: with a peer ID it pings that
// peer, otherwise it pings the Agent Mesh router.
func (n *AgentMeshNode) connectivityStats(ctx context.Context, peerIDStr string) connectivityResponse {
	ctx, cancel := context.WithTimeout(ctx, connectivityPingTimeout)
	defer cancel()

	stats := connectivityResponse{
		ConnectedPeers:  len(n.Host.Network().Peers()),
		TotalKnownPeers: len(n.Host.Peerstore().Peers()),
	}

	if peerIDStr != "" {
		pid, err := peer.Decode(peerIDStr)
		if err == nil {
			n.preparePeerAddrs(ctx, pid)
			start := time.Now()
			err := n.Host.Connect(ctx, peer.AddrInfo{ID: pid})
			latency := time.Since(start).Milliseconds()
			failed := err != nil
			stats.PingLatencyMS = &latency
			stats.PingError = &failed
			if err != nil {
				stats.PingErrorMsg = err.Error()
			}
		} else {
			failed := true
			stats.PingError = &failed
			stats.PingErrorMsg = "invalid peer id"
		}
	} else if n.RouterPeerID != "" {
		start := time.Now()
		err := n.Host.Connect(ctx, peer.AddrInfo{ID: n.RouterPeerID})
		latency := time.Since(start).Milliseconds()
		failed := err != nil
		stats.RouterLatencyMS = &latency
		stats.RouterError = &failed
		if err != nil {
			stats.RouterErrorMsg = err.Error()
		}
	}

	return stats
}

// tokenInfo backs GET /debug/token-info.
func (n *AgentMeshNode) tokenInfo() tokenInfoResponse {
	var info tokenInfoResponse
	token, err := n.Store.LoadIdentity()
	if err == nil && len(token) > 0 {
		info.HasToken = true
		exp, err := n.Store.LoadIdentityExpiration()
		if err == nil {
			expiresIn := time.Until(time.Unix(exp, 0)).Seconds()
			expired := time.Now().Unix() > exp
			info.ExpiresInSeconds = &expiresIn
			info.IsExpired = &expired
		}
	}
	return info
}

// networkInfo backs GET /debug/network-info.
func (n *AgentMeshNode) networkInfo() networkInfoResponse {
	listenAddrs := []string{}
	for _, a := range n.Host.Network().ListenAddresses() {
		listenAddrs = append(listenAddrs, a.String())
	}

	announcedAddrs := []string{}
	for _, a := range n.Host.Addrs() {
		announcedAddrs = append(announcedAddrs, a.String())
	}

	directoryAddrs := []string{}
	if d, ok := n.Directory.(recordAnnouncer); ok {
		for _, a := range d.Announced() {
			directoryAddrs = append(directoryAddrs, a.String())
		}
	}

	return networkInfoResponse{
		ListenAddresses:    listenAddrs,
		AnnouncedAddresses: announcedAddrs,
		DirectoryAddresses: directoryAddrs,
	}
}

// connectPeer backs POST /debug/connect-peer.
func (n *AgentMeshNode) connectPeer(ctx context.Context, peerAddr string) error {
	ctx, cancel := context.WithTimeout(ctx, connectPeerTimeout)
	defer cancel()

	ma, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		return err
	}
	addrInfo, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return err
	}
	if n.revokedPeers != nil && n.revokedPeers.Contains(addrInfo.ID.String()) {
		return fmt.Errorf("failed to dial: failed to dial %s: gater disallows connection to peer", addrInfo.ID)
	}
	conns := n.Host.Network().ConnsToPeer(addrInfo.ID)
	connectedness := n.Host.Network().Connectedness(addrInfo.ID)
	logger.Debugf("[connect-peer] Target peer %s, connectedness: %v, active conns: %d", addrInfo.ID, connectedness, len(conns))

	err = n.Host.Connect(ctx, *addrInfo)
	logger.Debugf("[connect-peer] Host.Connect returned error: %v", err)
	return err
}
