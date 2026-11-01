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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-msgio"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

// meshInstructions tells connecting clients how the Agent Mesh is composed and how
// to discover and call remote tools/services. Sent at initialize time.
const meshInstructions = `This MCP server connects this node to an Agent Mesh: a network of remote agents that host their own services (e.g., MCP servers or inference services) and tools.

The mesh allows you to discover these remote services, list their tools, and call them.
To use these remote services and their tools, the client can use the following flow:
  1. find_remote_tools — discover what tools exist across the mesh (returns peer_id + namespaced tool_name + description). Optionally narrow by service_name or peer_id.
  2. describe_remote_tool — fetch a specific tool's input_schema before calling it. Always do this so you know the argument shape.
  3. call_remote_tool — invoke it. Pass peer_id, the namespaced tool_name (scheme://service/tool, e.g. 'mcp://code-reviewer/review_pr'), and arguments as a JSON object whose keys match the input_schema.

Other useful tools: discover_remote_services browses services by type (e.g. 'MCP' or 'Inference'), get_mesh_info reports connected peers and mesh state, list_local_services shows what this node hosts.

Node diagnostics (logs, connectivity, network/token info, connecting to a peer by address) are NOT MCP tools. When asked to diagnose this node, run 'agentmesh-node debug --help' in a shell to discover the available diagnostics, then invoke the matching subcommand. They talk to the node over its Unix socket, so no token is involved.

Tools on remote services are identified via the format 'scheme://service-name/tool-name' (where 'scheme://service-name' represents the well-known local address of the service, and 'tool-name' is the individual tool to execute on it. Tool names themselves can contain any characters).

Inference services ('inference://...') are NOT called via call_remote_tool — they are plain OpenAI-compatible HTTP endpoints. Use discover_remote_services with type 'inference' to get each one's local_proxy_url, then send a normal HTTP request (e.g. POST <local_proxy_url>/chat/completions) directly to that URL.

A2A agents ('a2a://...') are NOT called via call_remote_tool either: discover them with type 'a2a', then point a stock A2A client, e.g. the official a2a CLI (github.com/a2aproject/a2a-cli), at <local_proxy_url>/.well-known/agent-card.json over TCP with the same 'X-Mesh-Authentication' header (for that CLI: A2ACLI_SVC_PARAM="X-Mesh-Authentication=Bearer <token>"). Check for the CLI with 'a2a version'. If it is missing, propose installing it to the user before trying anything else, and do not hand-write A2A JSON-RPC requests: method names differ between A2A versions, so guessed calls fail.

To authenticate such an HTTP request to this node, try these in order:
  1. If get_mesh_info reports a local_api_socket, send the request over that Unix socket and skip authentication entirely: it serves this same HTTP API, and only the user who owns the socket can connect to it, so no token is involved and no secret lands in a command line. e.g. 'curl --unix-socket <local_api_socket> <local_proxy_url>/chat/completions'.
  2. Otherwise use the TCP endpoint with header 'X-Mesh-Authentication: Bearer <node API token>'. Do not read your MCP client configuration files to recover that token: they hold every other server's headers too, and reading them puts all of those secrets into the transcript. A daemonized node writes its token to ~/.config/agentmesh/api-token; have curl read the file itself (e.g. -H @<(printf 'X-Mesh-Authentication: Bearer %s' "$(cat ~/.config/agentmesh/api-token)")) so the value never lands in an argument. If the node was started with --api-token-path or AGENTMESH_API_TOKEN, ask the user where the token lives.

Never print that token or echo it into the transcript. 'Authorization: Bearer <upstream-credential>' is a different thing: send it only when the destination service requires its own credential — it passes straight through untouched and is never used to authenticate to this node.`

// NewMCPServer creates a new MCP server instance with all tools registered.
func NewMCPServer(node *AgentMeshNode) *mcp.Server {
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "agentmesh-node-mcp",
		Version: "0.1.0",
	}, &mcp.ServerOptions{Instructions: meshInstructions})

	// Add list_local_services tool
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "list_local_services",
		Description: "List services registered on the local node. Optionally filter by type.",
	}, node.handleListLocalServices)

	// Add discover_remote_services tool
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "discover_remote_services",
		Description: "Discover remote services in the mesh. Provide only `type` to browse every reachable service of that type (returns name + description for each); add `name` to target a specific service. For `type: inference`, each result's `local_proxy_url` is called directly over HTTP (NOT via call_remote_tool) — the response includes a usage hint with the exact headers required. For `type: a2a`, `local_proxy_url` is the agent's base URL for any stock A2A client.",
	}, node.handleDiscoverRemoteServices)

	// Add the get_mesh_info tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_mesh_info",
		Description: "Get information about the mesh network",
	}, node.handleGetMeshInfo)

	// Add the call_remote_tool tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "call_remote_tool",
		Description: "Call an MCP tool on a remote agent",
	}, node.handleCallRemoteTool)

	// Add the find_remote_tools tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "find_remote_tools",
		Description: "Discover MCP tools available on hosted services across the mesh. Returns name + description per tool, plus the provider's declared labels (e.g. region) when known. Optionally narrow by peer_id, service_name, or tool_name (exact tool name; fastest — served from mesh announcements when available). intent is reserved for future ranking and is accepted-but-ignored.",
	}, node.handleFindRemoteTools)

	// Add the describe_remote_tool tool.
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "describe_remote_tool",
		Description: "Return the description, input schema, and output schema for a specific aggregated tool on a specific peer. peer_id and tool_name are both required; tool_name must be a namespaced 'scheme://service/tool' name as returned by find_remote_tools.",
	}, node.handleDescribeRemoteTool)

	return mcpServer
}

// NewUnauthenticatedMCPServer creates a minimal MCP server that instructs the client on how to authenticate.
func NewUnauthenticatedMCPServer(controlPlaneURL string) *mcp.Server {
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "agentmesh-node-mcp-unauth",
		Version: "0.1.0",
	}, &mcp.ServerOptions{Instructions: "This node is unauthenticated. Use the get_login_instructions tool or help_user_login prompt."})

	joinCmd := "agentmesh-node join"
	if controlPlaneURL != "" {
		joinCmd += " " + controlPlaneURL
	}

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_login_instructions",
		Description: "Get instructions on how to authenticate this node so it can join the Agent Mesh.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, params map[string]any) (*mcp.CallToolResult, any, error) {
		msg := fmt.Sprintf("The node is unauthenticated. Please open a regular terminal and run:\n\n  %s\n\nOnce complete, restart this MCP client.", joinCmd)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: msg},
			},
		}, nil, nil
	})

	mcpServer.AddPrompt(&mcp.Prompt{
		Name:        "help_user_login",
		Description: "Provides the user with login instructions when the node is unauthenticated.",
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: "Instructions for joining the Agent Mesh.",
			Messages: []*mcp.PromptMessage{
				{
					Role: "user",
					Content: &mcp.TextContent{
						Text: fmt.Sprintf("Please open a terminal and run:\n\n`%s`\n\nAfter you finish, please restart this MCP connection.", joinCmd),
					},
				},
			},
		}, nil
	})

	return mcpServer
}

// MCP 2026-07-28 removed sessions, and the SDK serves it over HTTP only in
// stateless mode; a stateful server also refuses legacy clients that already
// send the new per-request _meta version tag.
var streamableOptions = &mcp.StreamableHTTPOptions{Stateless: true}

// NewUnauthenticatedMCPHandler creates an HTTP handler for the unauthenticated MCP server.
func NewUnauthenticatedMCPHandler(controlPlaneURL string) http.Handler {
	mcpServer := NewUnauthenticatedMCPServer(controlPlaneURL)

	streamableHandler := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		return mcpServer
	}, streamableOptions)

	mux := http.NewServeMux()
	mux.Handle("/mcp", streamableHandler)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debugf("Unauth MCP Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		mux.ServeHTTP(w, r)
	})
}

// NewMCPHandler creates a new HTTP handler for the MCP server using the official SDK.
func NewMCPHandler(node *AgentMeshNode) http.Handler {
	mcpServer := NewMCPServer(node)

	streamableHandler := mcp.NewStreamableHTTPHandler(func(request *http.Request) *mcp.Server {
		return mcpServer
	}, streamableOptions)

	mux := http.NewServeMux()
	mux.Handle("/mcp", streamableHandler)

	// Wrap in logging middleware to debug incoming requests
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debugf("MCP Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		mux.ServeHTTP(w, r)
	})

	return wrappedHandler
}

// CallMCPTool opens a stream to a remote peer, performs the handshake, and calls a tool.
// requiredLabels, when non-empty, fail-closed verifies the peer's control-plane-attested
// labels (see checkPeerLabels) before the tool is invoked; nil means no caller
// requirement, though the operator's egress floor, if configured, is still enforced.
func (n *AgentMeshNode) CallMCPTool(ctx context.Context, targetPeer peer.ID, toolName string, params any, requiredLabels map[string]string) (*mcp.CallToolResult, error) {
	var res *mcp.CallToolResult
	var err error
	maxRetries := 3
	backoff := 1 * time.Second

	// Attempt to filter private IPs and resolve direct IPs for relay nodes.
	n.preparePeerAddrs(ctx, targetPeer)

	for i := 0; i < maxRetries; i++ {
		res, err = n.callMCPToolOnce(ctx, targetPeer, toolName, params, requiredLabels)
		if err == nil {
			return res, nil
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context deadline exceeded") {
			logger.Warnf("[MCP] Tool call failed with timeout or cancellation, not retrying: %v", err)
			return nil, err
		}
		// A denial is an answer, not a failure to reach anyone. Retrying it
		// just delays the same reply and knocks on the remote peer three times
		// for one call. That holds for the remote peer refusing the caller
		// and for the caller refusing a provider not granted the service.
		if errors.Is(err, ErrAuthRejected) || errors.Is(err, ErrProviderNotGranted) {
			logger.Warnf("[MCP] Tool call denied, not retrying: %v", err)
			return nil, err
		}
		// An authorizer that stopped at its facts or iterations limit stops
		// there again on a retry; only its time limit depends on load.
		if stopped, transient := authorizerLimit(err); stopped && !transient {
			logger.Warnf("[MCP] Tool call stopped at an authorizer limit, not retrying: %v", err)
			return nil, err
		}
		logger.Warnf("[MCP] Tool call failed, retrying in %v: %v", backoff, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("context canceled during retry: %w", ctx.Err())
		case <-timer.C:
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, err)
}

// ErrAuthRejected marks a service-level authorization denial from a remote peer,
// as opposed to a transport/connectivity failure. Callers use errors.Is to tell
// "you're not allowed" apart from "the service is unreachable" so that discovery
// (find_remote_tools) can hide forbidden services instead of leaking their names.
var ErrAuthRejected = errors.New("auth rejected")

func (n *AgentMeshNode) ConnectMCPSession(ctx context.Context, targetPeer peer.ID, targetService string, requiredLabels map[string]string) (*mcp.ClientSession, func(), error) {
	// Open stream
	logger.Debugf("Dialing %s for MCP...\n", targetPeer)
	// For discovery, we want a fast failure, but for tool calls, we can wait a bit. We'll use the context's deadline,
	// but bound it to 15s max for the dial itself to prevent hanging.
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	dialCtx = network.WithAllowLimitedConn(dialCtx, "mcp")
	defer cancel()

	s, err := n.Host.NewStream(dialCtx, targetPeer, api.MCPProtocolID)
	if err != nil {
		// If dial failed completely, mark private IP failed so we skip it next time
		if putErr := n.Host.Peerstore().Put(targetPeer, PeerstoreKeyPrivateIPFailed, true); putErr != nil {
			logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", putErr)
		}
		return nil, nil, fmt.Errorf("failed to open stream to %s: %w", targetPeer, err)
	}

	if remoteAddr := s.Conn().RemoteMultiaddr(); remoteAddr != nil {
		parts := multiaddr.Split(remoteAddr)
		isCircuit := len(parts) >= 2 && parts[len(parts)-1].Protocol().Code == multiaddr.P_CIRCUIT

		var putVal bool
		if isCircuit || !isPrivateIP(remoteAddr) {
			putVal = true
		} else {
			putVal = false
		}
		if putErr := n.Host.Peerstore().Put(targetPeer, PeerstoreKeyPrivateIPFailed, putVal); putErr != nil {
			logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", putErr)
		}
	}
	logger.Debugf("Opened stream to %s for MCP\n", targetPeer)

	cleanup := func() {
		if err := s.Close(); err != nil {
			logger.Debugf("[MCP] Failed to close stream: %v", err)
		}
	}

	// Load caller's task biscuit from ctx when present, falling back to this node's biscuit
	biscuitBytes := n.GetRequestIdentity(ctx)
	if len(biscuitBytes) == 0 && n.Store != nil {
		var loadErr error
		biscuitBytes, loadErr = n.Store.LoadIdentity()
		if loadErr != nil {
			cleanup()
			return nil, nil, fmt.Errorf("failed to load identity biscuit: %w", loadErr)
		}
	}
	if len(biscuitBytes) == 0 {
		cleanup()
		return nil, nil, fmt.Errorf("failed to load identity biscuit: empty credential")
	}

	// Marshal AuthFrame
	authFrame := api.AuthFrame{
		Biscuit:       biscuitBytes,
		TargetService: targetService,
	}
	authBytes, _ := proto.Marshal(&authFrame)

	// Handshake should be fast; set a hard deadline to prevent hanging
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))

	// Write AuthFrame
	logger.Debugf("Writing auth frame to %s...\n", targetPeer)
	writer := msgio.NewVarintWriter(s)
	if err := writer.WriteMsg(authBytes); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to write auth frame to %s: %w", targetPeer, err)
	}

	// Read ACK
	logger.Debugf("Reading auth response from %s...\n", targetPeer)
	reader := msgio.NewVarintReaderSize(s, 1024*64)
	msg, err := reader.ReadMsg()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to read auth response from %s: %w", targetPeer, err)
	}
	defer reader.ReleaseMsg(msg)

	// Clear deadline so the MCP SDK can use the stream normally without timing out
	_ = s.SetDeadline(time.Time{})

	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("invalid auth response from %s: %w", targetPeer, err)
	}

	if !resp.Success {
		cleanup()
		return nil, nil, fmt.Errorf("%w by %s: %s", ErrAuthRejected, targetPeer, resp.Error)
	}

	// The provider's biscuit is verified unconditionally: signature, expiry,
	// binding to targetPeer and, for a named service, the grant to serve it.
	// The directory names whoever announced the service; only this says the
	// peer is enrolled and may serve it. Caller-required labels and the
	// operator's egress floor are additional checks on the same token. An
	// empty target is the peer's own catalog, which names no service.
	if err := n.checkProvider(resp.Biscuit, targetPeer, requiredLabels, targetService); err != nil {
		cleanup()
		return nil, nil, err
	}

	// Handoff to SDK using custom transport
	transport := NewStreamTransport(s)
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "agentmesh-node-mcp-client", Version: "0.1.0"}, nil)

	session, err := mcpClient.Connect(ctx, transport, nil)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to connect client: %w", err)
	}

	fullCleanup := func() {
		_ = session.Close()
		cleanup()
	}

	return session, fullCleanup, nil
}

func (n *AgentMeshNode) callMCPToolOnce(ctx context.Context, targetPeer peer.ID, toolName string, params any, requiredLabels map[string]string) (*mcp.CallToolResult, error) {
	targetService, originalToolName, err := api.SplitToolName(toolName)
	if err != nil {
		return nil, err
	}

	session, cleanup, err := n.ConnectMCPSession(ctx, targetPeer, targetService, requiredLabels)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// We don't need to marshall the params, the SDK takes care of it
	// Passing pre-marshaled []byte triggers encoding/json's base64 which gets rejected
	callParams := &mcp.CallToolParams{
		Name:      originalToolName,
		Arguments: params,
	}

	res, err := session.CallTool(ctx, callParams)
	if err != nil {
		return nil, fmt.Errorf("failed to call tool %s: %w", toolName, err)
	}

	return res, nil
}

// fetchRemoteServiceCatalog calls the remote peer's list_local_services
// MCP tool with the type filter and returns the parsed catalog.
func (n *AgentMeshNode) fetchRemoteServiceCatalog(ctx context.Context, peerID peer.ID, typeStr string) ([]*api.ServiceInfo, error) {
	n.preparePeerAddrs(ctx, peerID)

	session, cleanup, err := n.ConnectMCPSession(ctx, peerID, "system://"+api.CatalogTarget, nil)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	callParams := &mcp.CallToolParams{
		Name:      "list_local_services",
		Arguments: map[string]string{"type": typeStr},
	}

	res, err := session.CallTool(ctx, callParams)
	if err != nil {
		return nil, fmt.Errorf("failed to call tool list_local_services: %w", err)
	}

	if res == nil || len(res.Content) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return nil, fmt.Errorf("unexpected content type: %T", res.Content[0])
	}
	var services []*api.ServiceInfo
	if err := json.Unmarshal([]byte(text.Text), &services); err != nil {
		logger.Warnf("[Discovery] catalog unmarshal failed; raw text from %s: %q", peerID, truncateForLog(text.Text))
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return services, nil
}

// preparePeerAddrs scans the target peer's addresses, filters out unroutable private IPs,
// and ensures relay circuits are available. This prevents dial backoff errors when the
// relay is behind a load-balanced DNS address or when pods advertise internal IPs.
func (n *AgentMeshNode) preparePeerAddrs(ctx context.Context, targetPeer peer.ID) {
	if n.Host == nil || n.Directory == nil {
		logger.Debugf("[Discovery] Host or directory is nil")
		return
	}
	logger.Debugf("[Discovery] connectedness for %s: %s (conns: %d)", targetPeer, n.Host.Network().Connectedness(targetPeer), len(n.Host.Network().ConnsToPeer(targetPeer)))

	// If we are currently connected to the peer, examine active connections to see if any are direct private IPs.
	cond := n.Host.Network().Connectedness(targetPeer)
	if cond == network.Connected || cond == network.Limited {
		conns := n.Host.Network().ConnsToPeer(targetPeer)
		hasDirectPrivateIP := false
		for _, c := range conns {
			remoteAddr := c.RemoteMultiaddr()
			if isPrivateIP(remoteAddr) && !hasCircuit(remoteAddr) {
				hasDirectPrivateIP = true
				break
			}
		}
		if !hasDirectPrivateIP {
			if err := n.Host.Peerstore().Put(targetPeer, PeerstoreKeyPrivateIPFailed, true); err != nil {
				logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", err)
			}
			logger.Debugf("[Discovery] Peer %s is connected via relay, marking private IP as failed", targetPeer)
		} else {
			if err := n.Host.Peerstore().Put(targetPeer, PeerstoreKeyPrivateIPFailed, false); err != nil {
				logger.Errorf("[Discovery] Failed to put peerstore private IP failed key: %v", err)
			}
		}
	}

	changed := false
	addrs := n.Host.Peerstore().Addrs(targetPeer)
	if len(addrs) == 0 {
		logger.Debugf("[Discovery] No addresses in peerstore for %s, asking the directory", targetPeer)
		findCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
		addrInfo, err := n.Directory.FindPeer(findCtx, targetPeer)
		cancel()
		addrs = addrInfo.Addrs
		switch {
		case len(addrs) > 0:
			changed = true
			peerLookupsTotal.WithLabelValues(lookupFound).Inc()
		case err != nil && !errors.Is(err, routing.ErrNotFound):
			peerLookupsTotal.WithLabelValues(lookupFailed).Inc()
			logger.Warnf("[Discovery] Directory lookup for %s failed: %v", targetPeer, err)
		default:
			peerLookupsTotal.WithLabelValues(lookupNotFound).Inc()
			logger.Infof("[Discovery] The directory knows no address for %s; trying circuits through this node's routers", targetPeer)
		}
	}
	logger.Debugf("[Discovery] preparePeerAddrs for %s: found %d addrs in peerstore: %v", targetPeer, len(addrs), addrs)

	var validAddrs []multiaddr.Multiaddr
	seen := make(map[string]struct{})

	addUnique := func(ma multiaddr.Multiaddr) bool {
		str := ma.String()
		if _, ok := seen[str]; !ok {
			seen[str] = struct{}{}
			validAddrs = append(validAddrs, ma)
			return true
		}
		return false
	}

	for _, ma := range addrs {
		parts := multiaddr.Split(ma)

		// If it's a circuit relay, we always keep the generic /p2p-circuit form.
		// We'll reconstruct it below. But we must also check if the address itself is routable.
		isCircuit := len(parts) >= 2 && parts[len(parts)-1].Protocol().Code == multiaddr.P_CIRCUIT

		if !isCircuit {
			// Regular address (not a circuit relay). Filter private IPs if loopback isn't allowed,
			// and we know from a previous dial that private IPs are unreachable for this peer.
			if isPrivateIP(ma) && !n.AllowLoopback {
				val, err := n.Host.Peerstore().Get(targetPeer, PeerstoreKeyPrivateIPFailed)
				if failed, ok := val.(bool); err == nil && ok && failed {
					changed = true
					logger.Debugf("[Discovery] Skipping private IP %s for %s due to previous failure", ma, targetPeer)
					continue
				}
			}
			addUnique(ma)
			continue
		}

		// Keep the advertised circuit address
		addUnique(ma)

		// Also synthesize a generic /p2p-circuit using the relay's peer ID.
		p2pPart := parts[len(parts)-2]
		if p2pPart.Protocol().Code != multiaddr.P_P2P {
			continue
		}

		relayID, err := peer.Decode(p2pPart.Value())
		if err != nil {
			continue
		}

		if len(n.Host.Peerstore().Addrs(relayID)) == 0 {
			logger.Debugf("[Discovery] No addresses for relay %s, asking the directory", relayID)
			findCtx, cancel := context.WithTimeout(ctx, dhtLookupTimeout)
			addrInfo, err := n.Directory.FindPeer(findCtx, relayID)
			cancel()
			if err != nil {
				logger.Debugf("[Discovery] Relay %s not found in the directory: %v", relayID, err)
			} else {
				rememberAddrs(n.Host.Peerstore(), addrInfo)
			}
		}

		circuitAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s/p2p-circuit", relayID.String()))
		if err == nil {
			if addUnique(circuitAddr) {
				changed = true
			}
		}
	}

	// A peer that announced no circuit is still reachable through the
	// routers that admitted both of us: an SDK agent publishes no address at
	// all, and a node's direct addresses may be on a network this one cannot
	// reach. Every router relays for the peers it authenticated, so each is
	// a path worth trying; libp2p dials direct addresses first and these after.
	if !slices.ContainsFunc(validAddrs, func(ma multiaddr.Multiaddr) bool { return circuitRelay(ma) != "" }) {
		for _, router := range n.authenticatedRouterIDs() {
			circuitAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s/p2p-circuit", router.String()))
			if err == nil && addUnique(circuitAddr) {
				changed = true
			}
		}
	}

	if kept := n.selectTransit(ctx, validAddrs); len(kept) != len(validAddrs) {
		validAddrs = kept
		changed = true
	}

	if changed && len(validAddrs) > 0 {
		// Clear existing addresses to prevent libp2p from hanging on dead private IPs
		n.Host.Peerstore().ClearAddrs(targetPeer)
		n.Host.Peerstore().AddAddrs(targetPeer, validAddrs, peerstore.TempAddrTTL)
		logger.Debugf("[Discovery] Replaced addrs for %s with %d routable/circuit addrs", targetPeer, len(validAddrs))
		// The lookup dialled the peer before any transit handshake, and a
		// router refuses a circuit to a caller it has not admitted; the swarm
		// put that address in dial backoff, which the handshake has outdated.
		if sw, ok := n.Host.Network().(*swarm.Swarm); ok {
			sw.Backoff().Clear(targetPeer)
		}
	}
}

// circuitRelay is the relay a circuit address goes through, or "" for any
// other address.
func circuitRelay(ma multiaddr.Multiaddr) peer.ID {
	parts := multiaddr.Split(ma)
	if len(parts) < 2 || parts[len(parts)-1].Protocol().Code != multiaddr.P_CIRCUIT || parts[len(parts)-2].Protocol().Code != multiaddr.P_P2P {
		return ""
	}
	relayID, err := peer.Decode(parts[len(parts)-2].Value())
	if err != nil {
		return ""
	}
	return relayID
}

// relayTransportAddr is the relay's own address carried in a circuit
// address, the components before /p2p/<relay>/p2p-circuit, or nil for a
// bare circuit or any other address.
func relayTransportAddr(ma multiaddr.Multiaddr) multiaddr.Multiaddr {
	if circuitRelay(ma) == "" {
		return nil
	}
	parts := multiaddr.Split(ma)
	if len(parts) < 3 {
		return nil
	}
	return multiaddr.Multiaddr(slices.Clone(parts[:len(parts)-2]))
}

// transitCatalogRefreshInterval bounds how often a relay the catalog does
// not list makes the node re-read /info.
const transitCatalogRefreshInterval = 10 * time.Second

// selectTransit decides which of a peer's circuit addresses to dial and
// makes sure the node is admitted at the router behind them. A router
// relays only between peers it has admitted, and a node keeps sessions
// with a few routers, so the peer's routers are often not among them. One
// transit router is enough: a router the node already holds when the peer
// is on it too, which costs the mesh nothing; otherwise the peer's router
// with the most room, which the node runs the handshake with, as it does
// at start, before the circuit is asked for. Circuits through the peer's
// other routers are dropped: each would be a handshake and a session
// there, and a service the whole mesh calls would hold every caller at
// every one of its routers.
//
// A relay the catalog does not list is first looked for in a fresh /info:
// the catalog is read at start, a router that was restarting then was not
// in it, and a member that started during a rollout would otherwise never
// transit that router until the next sync. A relay still unlisted after
// that is handshaken with all the same, after the listed routers: a router
// whose lease the control plane does not carry admits the node like any
// other, and a relay that is not a router (a node with --enable-relay)
// admits what it has handshaken with on its own terms and is kept whatever
// the handshake said. Direct addresses always pass.
func (n *AgentMeshNode) selectTransit(ctx context.Context, addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	var relays []peer.ID
	relayAddrs := map[peer.ID][]multiaddr.Multiaddr{}
	for _, ma := range addrs {
		relay := circuitRelay(ma)
		if relay == "" {
			continue
		}
		if _, seen := relayAddrs[relay]; !seen {
			relays = append(relays, relay)
		}
		if via := relayTransportAddr(ma); via != nil {
			relayAddrs[relay] = append(relayAddrs[relay], via)
		} else if _, seen := relayAddrs[relay]; !seen {
			relayAddrs[relay] = nil
		}
	}
	if len(relays) == 0 {
		return addrs
	}

	routers := map[peer.ID]routerCandidate{}
	for _, c := range n.routerCandidates() {
		routers[c.ID] = c
	}
	var unlisted []peer.ID
	for _, r := range relays {
		if _, isRouter := routers[r]; !isRouter {
			unlisted = append(unlisted, r)
		}
	}
	if len(unlisted) > 0 && n.refreshCatalogForTransit(ctx) {
		routers = map[peer.ID]routerCandidate{}
		for _, c := range n.routerCandidates() {
			routers[c.ID] = c
		}
		unlisted = unlisted[:0]
		for _, r := range relays {
			if _, isRouter := routers[r]; !isRouter {
				unlisted = append(unlisted, r)
			}
		}
	}
	var viaRouters []peer.ID
	for _, r := range relays {
		if _, isRouter := routers[r]; isRouter {
			viaRouters = append(viaRouters, r)
		}
	}

	usable := map[peer.ID]bool{}
	for _, r := range relays {
		if n.isAuthenticatedAndConnected(r) {
			usable[r] = true
		}
	}
	if len(usable) == 0 {
		sort.SliceStable(viaRouters, func(i, j int) bool {
			return routers[viaRouters[i]].loadRatio() < routers[viaRouters[j]].loadRatio()
		})
		biscuitBytes, err := n.loadIdentityForAuth()
		if err != nil {
			logger.Debugf("[AuthN] Cannot authenticate to a transit router: %v", err)
			return addrs
		}
		for _, r := range append(viaRouters, unlisted...) {
			_, listed := routers[r]
			kind := transitListed
			if !listed {
				kind = transitUnlisted
				logger.Infof("[AuthN] Relay %s is not a router the control plane lists; handshaking with it for the circuit", r)
			}
			router := peer.AddrInfo{ID: r, Addrs: append(n.Host.Peerstore().Addrs(r), relayAddrs[r]...)}
			if err := n.authRouter(ctx, router, biscuitBytes); err != nil {
				transitHandshakesTotal.WithLabelValues(kind, "failed").Inc()
				logger.Warnf("[AuthN] Transit router %s did not admit this node: %v", r, err)
				continue
			}
			transitHandshakesTotal.WithLabelValues(kind, "ok").Inc()
			logger.Debugf("[AuthN] Authenticated to transit router %s", r)
			usable[r] = true
			break
		}
		if len(usable) == 0 {
			return addrs
		}
	}

	kept := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, ma := range addrs {
		relay := circuitRelay(ma)
		if _, isRouter := routers[relay]; relay != "" && isRouter && !usable[relay] {
			continue
		}
		kept = append(kept, ma)
	}
	return kept
}

// refreshCatalogForTransit re-reads the routers from the control plane for
// a relay the catalog does not list, at most once per
// transitCatalogRefreshInterval. It reports whether the catalog was re-read.
func (n *AgentMeshNode) refreshCatalogForTransit(ctx context.Context) bool {
	n.mu.Lock()
	due := time.Since(n.transitCatalogRefreshedAt) >= transitCatalogRefreshInterval
	if due {
		n.transitCatalogRefreshedAt = time.Now()
	}
	n.mu.Unlock()
	if !due {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := n.refreshRouterCatalog(ctx); err != nil {
		logger.Debugf("[AuthN] Routers not re-read from the control plane for a transit relay: %v", err)
		return false
	}
	return true
}
