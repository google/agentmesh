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

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/google/sam/api"
)

var _ connmgr.ConnectionGater = (*nodeConnGate)(nil)

// nodeConnGate enforces swarm-level AuthN policies
type nodeConnGate struct {
	node *SamNode
}

// InterceptPeerDial controls who we are allowed to call (Outbound)
func (g *nodeConnGate) InterceptPeerDial(p peer.ID) (allow bool) {
	logger.Debugf("[Gater] InterceptPeerDial for %s", p)
	if g.node.revokedPeers != nil && g.node.revokedPeers.Contains(p.String()) {
		logger.Warnf("[Gater] InterceptPeerDial denying %s: in revoked cache", p)
		return false
	}
	logger.Debugf("[Gater] InterceptPeerDial allowing %s", p)
	return true
}

// InterceptAddrDial ensures we only dial specific approved networks
func (g *nodeConnGate) InterceptAddrDial(p peer.ID, m multiaddr.Multiaddr) (allow bool) {
	return true
}

// InterceptAccept controls who can call us (Inbound)
func (g *nodeConnGate) InterceptAccept(n network.ConnMultiaddrs) (allow bool) {
	return true // Connection allowed, but InterceptSecured will verify the PeerID
}

// InterceptSecured is called after TLS handshake. This is our Layer 2 Check.
func (g *nodeConnGate) InterceptSecured(dir network.Direction, p peer.ID, n network.ConnMultiaddrs) (allow bool) {
	logger.Debugf("[Gater] InterceptSecured for %s (dir: %v)", p, dir)
	if g.node.revokedPeers != nil && g.node.revokedPeers.Contains(p.String()) {
		logger.Warnf("[Gater] InterceptSecured denying %s: in revoked cache", p)
		return false
	}
	logger.Debugf("[Gater] InterceptSecured allowing %s", p)
	return true
}

// HandleMCPStream is the libp2p stream handler for the MCP protocol.
// It routes the authenticated stream to the appropriate backend service,
// or serves the internal MCP catalog if the TargetService is empty/catalog.
func (n *SamNode) HandleMCPStream(s network.Stream, reqCtx RequestContext) {
	// If the TargetService is for a registered local backend, dumb-pipe proxy to it.
	target := reqCtx.Target
	targetType, targetName := api.ParseServiceTarget(target)
	if target != "" && targetName != api.CatalogTarget {
		if n.services == nil {
			logger.Errorf("[MCP] Service registry is not initialized")
			_ = s.Reset()
			return
		}
		// The policy passed on the type the caller named; this stream only
		// carries MCP, so anything else is a type-confusion attempt.
		if t, err := api.ParseServiceType(targetType); err == nil && t == api.ServiceType_SERVICE_TYPE_MCP {
			if svc, ok := n.services.GetTyped(t, targetName); ok {
				if mcpSvc, isMcp := svc.(*MCPService); isMcp {
					mcpSvc.HandleStreamPassThrough(s, reqCtx)
					return
				}
			}
		}
		logger.Warnf("[MCP] Client requested unknown target service %q, closing stream", truncateForLog(target))
		_ = s.Reset()
		return
	}

	// Target is catalog/internal tools. We spin up an MCP server for these local mesh tools.
	defer func() {
		if err := s.Close(); err != nil {
			logger.Debugf("[MCP] Failed to close MCP stream: %v", err)
		}
	}()

	transport := NewStreamTransport(s)
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sam-node-catalog",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_local_services",
		Description: "List services registered on the local node. Optionally filter by type.",
	}, n.handleListLocalServices)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_mesh_info",
		Description: "Get information about the mesh network",
	}, n.handleGetMeshInfoRemote)

	ctx := context.Background()
	if err := server.Run(ctx, transport); err != nil {
		logger.Errorf("[MCP] Catalog server error on stream from %s: %v", s.Conn().RemotePeer(), err)
	}
}
func (g *nodeConnGate) InterceptUpgraded(n network.Conn) (allow bool, cc control.DisconnectReason) {
	return true, 0
}

// StreamTransport implements the mcp.Transport interface for a libp2p stream.
type StreamTransport struct {
	s network.Stream
	r msgio.ReadCloser
	w msgio.WriteCloser
}

// NewStreamTransport creates a new StreamTransport for the given stream.
func NewStreamTransport(s network.Stream) *StreamTransport {
	return &StreamTransport{
		s: s,
		r: msgio.NewVarintReader(s),
		w: msgio.NewVarintWriter(s),
	}
}

// Send sends a message over the stream.
func (t *StreamTransport) Send(data []byte) error {
	return t.w.WriteMsg(data)
}

// Read reads a message from the stream.
func (t *StreamTransport) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := t.r.ReadMsg()
	if err != nil {
		return nil, err
	}
	defer t.r.ReleaseMsg(msg)

	return jsonrpc.DecodeMessage(msg)
}

// Close closes the stream.
func (t *StreamTransport) Close() error {
	return t.s.Close()
}

// Connect satisfies the mcp.Transport interface. For a stream, it's already connected.
func (t *StreamTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	return t, nil
}

// SessionID satisfies the mcp.Connection interface.
func (t *StreamTransport) SessionID() string {
	return t.s.Conn().RemotePeer().String()
}

// Write writes a message to the stream.
func (t *StreamTransport) Write(ctx context.Context, msg jsonrpc.Message) error {
	data, err := jsonrpc.EncodeMessage(msg)
	if err != nil {
		return err
	}
	return t.w.WriteMsg(data)
}
