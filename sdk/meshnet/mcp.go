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

package meshnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

const meshMCPInstructions = `This MCP server connects this agent to an Agent Mesh: a zero-trust peer-to-peer network of remote agents, MCP tool servers, and OpenAI-compatible inference providers.

To discover and call remote MCP tools efficiently without loading every schema upfront:
  1. find_remote_tools — discover what tools exist across the mesh (returns peer_id + namespaced tool_name + description). Optionally narrow by service_name, peer_id, or tool_name.
  2. describe_remote_tool — fetch a specific tool's input_schema before calling it so you know the exact argument shape.
  3. call_remote_tool — invoke it. Pass peer_id, the namespaced tool_name ('mcp://<service>/<tool>'), and arguments as a JSON object matching input_schema.

Other tools:
  - discover_remote_services — browse reachable services by type ('mcp', 'inference', or 'a2a').
  - list_local_services — list A2A services hosted by this embedded meshnet.Server.
  - get_mesh_info — inspect this member's PeerID, attached routers, and credential expiration.

Inference ('inference://...') and A2A ('a2a://...') services are HTTP endpoints, NOT MCP tools: invoke inference via the host's OpenAI-compatible /v1 endpoint (Server.InferenceHandler) and A2A agents via Server.HTTPClient using each provider's local_proxy_url.`

var (
	errAuthRejected   = errors.New("auth rejected")
	streamableMCPOpts = &mcp.StreamableHTTPOptions{Stateless: true}
)

type streamTransport struct {
	st network.Stream
	r  msgio.ReadCloser
	w  msgio.WriteCloser
}

func newStreamTransport(st network.Stream) *streamTransport {
	return &streamTransport{
		st: st,
		r:  msgio.NewVarintReader(st),
		w:  msgio.NewVarintWriter(st),
	}
}

func (t *streamTransport) Connect(_ context.Context) (mcp.Connection, error) {
	return t, nil
}

func (t *streamTransport) SessionID() string {
	return t.st.Conn().RemotePeer().String()
}

func (t *streamTransport) Read(_ context.Context) (jsonrpc.Message, error) {
	msg, err := t.r.ReadMsg()
	if err != nil {
		return nil, err
	}
	defer t.r.ReleaseMsg(msg)
	return jsonrpc.DecodeMessage(msg)
}

func (t *streamTransport) Write(_ context.Context, msg jsonrpc.Message) error {
	data, err := jsonrpc.EncodeMessage(msg)
	if err != nil {
		return err
	}
	return t.w.WriteMsg(data)
}

func (t *streamTransport) Close() error {
	return t.st.Close()
}

// MCPServer returns an in-process *mcp.Server exposing the 6 mesh-operating
// tools (find_remote_tools, describe_remote_tool, call_remote_tool,
// discover_remote_services, list_local_services, and get_mesh_info) for local
// coding agents, sandboxes, or Go agent frameworks (ADK, Genkit).
func (s *Server) MCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "agentmesh-meshnet-mcp",
		Version: "0.1.0",
	}, &mcp.ServerOptions{Instructions: meshMCPInstructions})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_local_services",
		Description: "List services registered on this embedded meshnet.Server. Optionally filter by type.",
	}, s.handleListLocalServices)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "discover_remote_services",
		Description: "Discover remote services in the mesh. Provide only `type` ('mcp', 'inference', or 'a2a') to browse all services of that type, or add `name` for a specific service.",
	}, s.handleDiscoverRemoteServices)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_mesh_info",
		Description: "Get information about this meshnet member and its mesh connectivity.",
	}, s.handleGetMeshInfoLocal)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "call_remote_tool",
		Description: "Call an MCP tool on a remote mesh peer.",
	}, s.handleCallRemoteTool)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "find_remote_tools",
		Description: "Discover MCP tools hosted across the mesh (returns peer_id, namespaced tool_name, and description without full schemas).",
	}, s.handleFindRemoteTools)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "describe_remote_tool",
		Description: "Return the description, input_schema, and output_schema for a specific namespaced 'mcp://<service>/<tool>' tool on a remote peer.",
	}, s.handleDescribeRemoteTool)

	return srv
}

// MCPHandler returns a stateless StreamableHTTP http.Handler serving
// Server.MCPServer() (accepting requests at "/mcp" or "/", so callers can
// mount it directly or behind http.StripPrefix).
func (s *Server) MCPHandler() http.Handler {
	mcpSrv := s.MCPServer()
	streamable := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpSrv
	}, streamableMCPOpts)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/mcp", "/mcp/":
			streamable.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *Server) handleMCPStream(st network.Stream) {
	defer func() { _ = st.Close() }()
	remotePeer := st.Conn().RemotePeer()

	if s.rateLimiter != nil && !s.rateLimiter.Allow(remotePeer.String()) {
		s.log().Warn("MCP stream rate limit exceeded", "peer_id", remotePeer.String())
		_ = st.Reset()
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(authHandshakeTimeout))

	reader := msgio.NewVarintReaderSize(st, 64*1024)
	msg, err := reader.ReadMsg()
	if err != nil {
		s.log().Debug("failed reading MCP auth frame", "peer_id", remotePeer.String(), "error", err)
		return
	}
	defer reader.ReleaseMsg(msg)

	var authFrame api.AuthFrame
	if err := proto.Unmarshal(msg, &authFrame); err != nil {
		s.log().Warn("invalid protobuf in MCP auth frame", "peer_id", remotePeer.String())
		return
	}

	writer := msgio.NewVarintWriter(st)
	if _, err := s.authorizeInbound(authFrame.GetBiscuit(), remotePeer, authFrame.GetTargetService(), string(api.MCPProtocolID), nil); err != nil {
		respBytes, _ := proto.Marshal(&api.AuthResponse{Success: false, Error: err.Error()})
		_ = writer.WriteMsg(respBytes)
		return
	}

	respBytes, err := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: s.currentBiscuit()})
	if err != nil {
		return
	}
	if err := writer.WriteMsg(respBytes); err != nil {
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	target := authFrame.GetTargetService()
	_, targetName := api.ParseServiceTarget(target)
	if target != "" && targetName != api.CatalogTarget {
		s.log().Warn("closing MCP stream for unknown local service", "peer_id", remotePeer.String(), "target", target)
		_ = st.Reset()
		return
	}

	catalogSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "agentmesh-node-catalog",
		Version: "0.1.0",
	}, nil)
	mcp.AddTool(catalogSrv, &mcp.Tool{
		Name:        "list_local_services",
		Description: "List services registered on the local node. Optionally filter by type.",
	}, s.handleListLocalServices)
	mcp.AddTool(catalogSrv, &mcp.Tool{
		Name:        "get_mesh_info",
		Description: "Get information about the mesh network",
	}, s.handleGetMeshInfoRemote)

	if err := catalogSrv.Run(context.Background(), newStreamTransport(st)); err != nil {
		s.log().Debug("catalog MCP session ended", "peer_id", remotePeer.String(), "error", err)
	}
}

type listLocalServicesParams struct {
	Type string `json:"type,omitempty" jsonschema:"Optional service type filter (mcp, inference, a2a). Empty means all types."`
}

func (s *Server) handleListLocalServices(_ context.Context, _ *mcp.CallToolRequest, params listLocalServicesParams) (*mcp.CallToolResult, any, error) {
	typeFilter := api.ServiceType_SERVICE_TYPE_UNSPECIFIED
	if params.Type != "" {
		parsed, err := api.ParseServiceType(params.Type)
		if err != nil {
			return nil, nil, err
		}
		typeFilter = parsed
	}
	services := s.listLocalServiceInfos(typeFilter)
	data, err := json.Marshal(services)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

type discoverRemoteServicesParams struct {
	Type   string `json:"type" jsonschema:"Required. One of: mcp, inference, a2a."`
	Name   string `json:"name,omitempty" jsonschema:"Optional service name. Omit to list all services of the given type."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Optional limit for pagination. Defaults to 20."`
	Offset int    `json:"offset,omitempty" jsonschema:"Optional offset for pagination. Defaults to 0."`
}

func (s *Server) handleDiscoverRemoteServices(ctx context.Context, _ *mcp.CallToolRequest, params discoverRemoteServicesParams) (*mcp.CallToolResult, any, error) {
	svcType, err := api.ParseServiceType(params.Type)
	if err != nil || svcType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return nil, nil, fmt.Errorf("invalid or unspecified service type: %s", params.Type)
	}
	providers, err := s.Discover(ctx, svcType, params.Name)
	if err != nil {
		return nil, nil, err
	}
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := max(params.Offset, 0)
	if offset >= len(providers) {
		providers = []*api.DiscoveredProvider{}
	} else {
		end := offset + limit
		if end > len(providers) || end < offset {
			end = len(providers)
		}
		providers = providers[offset:end]
	}
	data, err := json.Marshal(providers)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

type getMeshInfoParams struct{}

func (s *Server) handleGetMeshInfoLocal(_ context.Context, _ *mcp.CallToolRequest, _ getMeshInfoParams) (*mcp.CallToolResult, any, error) {
	st := s.Status()
	payload := struct {
		PeerID          string   `json:"peer_id"`
		ControlPlaneURL string   `json:"control_plane_url"`
		AttachedRouters []string `json:"attached_routers"`
		IngressURLs     []string `json:"ingress_urls,omitempty"`
		ExpireTime      string   `json:"expire_time,omitempty"`
	}{
		PeerID:          st.PeerID,
		ControlPlaneURL: st.ControlPlaneURL,
		AttachedRouters: st.AttachedRouters,
		IngressURLs:     st.IngressURLs,
	}
	if !st.ExpireTime.IsZero() {
		payload.ExpireTime = st.ExpireTime.UTC().Format(time.RFC3339)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func (s *Server) handleGetMeshInfoRemote(_ context.Context, _ *mcp.CallToolRequest, _ getMeshInfoParams) (*mcp.CallToolResult, any, error) {
	data, err := json.Marshal(struct {
		PeerID string `json:"peer_id"`
	}{PeerID: s.peerID.String()})
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

type callRemoteToolParams struct {
	PeerID         string         `json:"peer_id" jsonschema:"The Peer ID of the target agent."`
	ToolName       string         `json:"tool_name" jsonschema:"Namespaced tool name ('mcp://<service>/<tool>')."`
	Arguments      map[string]any `json:"arguments,omitempty" jsonschema:"Tool arguments as a JSON object matching input_schema."`
	RequiredLabels string         `json:"required_labels,omitempty" jsonschema:"Optional comma-separated key=value pairs attested on the provider's Biscuit."`
}

func (s *Server) handleCallRemoteTool(ctx context.Context, _ *mcp.CallToolRequest, params callRemoteToolParams) (*mcp.CallToolResult, any, error) {
	targetPeer, err := peer.Decode(params.PeerID)
	if err != nil {
		return nil, nil, err
	}
	required, err := parseRequiredLabels(params.RequiredLabels)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid required_labels: %w", err)
	}
	res, err := s.callMCPTool(ctx, targetPeer, params.ToolName, params.Arguments, required)
	if err != nil {
		return nil, nil, err
	}
	return res, nil, nil
}

type findRemoteToolsParams struct {
	Intent      string `json:"intent,omitempty" jsonschema:"Optional natural-language intent (reserved for future ranking)."`
	PeerID      string `json:"peer_id,omitempty" jsonschema:"Restrict the search to a single peer. Empty searches the whole mesh."`
	ServiceName string `json:"service_name,omitempty" jsonschema:"Restrict results to tools on this MCP service (e.g. 'code-reviewer')."`
	ToolName    string `json:"tool_name,omitempty" jsonschema:"Exact bare tool name to locate across the mesh."`
}

type remoteToolRow struct {
	PeerID      string            `json:"peer_id"`
	ToolName    string            `json:"tool_name,omitempty"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Error       string            `json:"error,omitempty"`
}

func (s *Server) handleFindRemoteTools(ctx context.Context, _ *mcp.CallToolRequest, params findRemoteToolsParams) (*mcp.CallToolResult, any, error) {
	if s.host == nil {
		return nil, nil, errors.New("meshnet: Server is not running")
	}
	selfID := s.peerID.String()
	if params.PeerID != "" && params.PeerID == selfID {
		return nil, nil, fmt.Errorf("peer_id %q is this member; find_remote_tools searches remote peers", params.PeerID)
	}
	serviceFilter, err := normalizeMCPServiceFilter(params.ServiceName)
	if err != nil {
		return nil, nil, err
	}

	var rows []remoteToolRow
	if params.PeerID != "" {
		pid, err := peer.Decode(params.PeerID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid peer_id %q: %w", params.PeerID, err)
		}
		rows, err = s.fetchRemoteToolCatalogue(ctx, pid, serviceFilter)
		if err != nil {
			return nil, nil, err
		}
	} else {
		providers, err := s.Discover(ctx, api.ServiceType_SERVICE_TYPE_MCP, "")
		if err != nil {
			return nil, nil, fmt.Errorf("discover MCP providers: %w", err)
		}
		seen := map[string]bool{}
		var peerIDs []peer.ID
		for _, p := range providers {
			if p.GetPeerId() == selfID || seen[p.GetPeerId()] {
				continue
			}
			seen[p.GetPeerId()] = true
			if pid, err := peer.Decode(p.GetPeerId()); err == nil {
				peerIDs = append(peerIDs, pid)
			}
		}
		rows = s.fanOutFetchTools(ctx, peerIDs, serviceFilter)
	}

	if params.ToolName != "" {
		var filtered []remoteToolRow
		for _, row := range rows {
			if row.Error == "" && row.ToolName[strings.LastIndex(row.ToolName, "/")+1:] == params.ToolName {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	if rows == nil {
		rows = []remoteToolRow{}
	}
	data, err := json.Marshal(rows)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func normalizeMCPServiceFilter(name string) (string, error) {
	switch {
	case name == "":
		return "", nil
	case !strings.Contains(name, "://"):
		return api.MCPServicePrefix + name, nil
	case strings.HasPrefix(name, api.MCPServicePrefix):
		return name, nil
	default:
		return "", fmt.Errorf("service_name %q: find_remote_tools searches MCP services only", name)
	}
}

type describeRemoteToolParams struct {
	PeerID   string `json:"peer_id" jsonschema:"Peer ID of the node hosting the MCP service. Required."`
	ToolName string `json:"tool_name" jsonschema:"Namespaced tool name as returned by find_remote_tools ('mcp://<service>/<tool>'). Required."`
}

type remoteToolDescription struct {
	PeerID       string `json:"peer_id,omitempty"`
	ToolName     string `json:"tool_name"`
	Description  string `json:"description"`
	InputSchema  any    `json:"input_schema,omitempty"`
	OutputSchema any    `json:"output_schema,omitempty"`
}

func (s *Server) handleDescribeRemoteTool(ctx context.Context, _ *mcp.CallToolRequest, params describeRemoteToolParams) (*mcp.CallToolResult, any, error) {
	if params.PeerID == "" {
		return nil, nil, errors.New("peer_id is required")
	}
	if params.ToolName == "" {
		return nil, nil, errors.New("tool_name is required")
	}
	pid, err := peer.Decode(params.PeerID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid peer_id: %w", err)
	}
	desc, err := s.fetchRemoteToolDescription(ctx, pid, params.ToolName)
	if err != nil {
		return nil, nil, err
	}
	data, err := json.Marshal(desc)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func (s *Server) connectMCPSession(ctx context.Context, targetPeer peer.ID, targetService string, requiredLabels map[string]string) (*mcp.ClientSession, func(), error) {
	if s.host == nil {
		return nil, nil, errors.New("meshnet: Server is not running")
	}
	biscuitBytes := s.currentBiscuit()
	if len(biscuitBytes) == 0 {
		return nil, nil, errors.New("meshnet: missing local member credential")
	}

	dialCtx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "mcp"), 15*time.Second)
	defer cancel()

	st, err := s.host.NewStream(dialCtx, targetPeer, api.MCPProtocolID)
	if err != nil {
		_ = s.host.Peerstore().Put(targetPeer, peerstoreKeyPrivateIPFailed, true)
		return nil, nil, fmt.Errorf("open MCP stream to %s: %w", targetPeer, err)
	}

	if remoteAddr := st.Conn().RemoteMultiaddr(); remoteAddr != nil {
		parts := multiaddr.Split(remoteAddr)
		isCircuit := len(parts) >= 2 && parts[len(parts)-1].Protocol().Code == multiaddr.P_CIRCUIT
		_ = s.host.Peerstore().Put(targetPeer, peerstoreKeyPrivateIPFailed, isCircuit || !isPrivateIP(remoteAddr))
	}

	cleanup := func() { _ = st.Close() }

	authBytes, err := proto.Marshal(&api.AuthFrame{
		Biscuit:       biscuitBytes,
		TargetService: targetService,
	})
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	_ = st.SetDeadline(time.Now().Add(authHandshakeTimeout))
	if err := msgio.NewVarintWriter(st).WriteMsg(authBytes); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("write MCP auth frame to %s: %w", targetPeer, err)
	}
	reader := msgio.NewVarintReaderSize(st, 64*1024)
	msg, err := reader.ReadMsg()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("read MCP auth response from %s: %w", targetPeer, err)
	}
	defer reader.ReleaseMsg(msg)
	_ = st.SetDeadline(time.Time{})

	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("decode MCP auth response from %s: %w", targetPeer, err)
	}
	if !resp.GetSuccess() {
		cleanup()
		return nil, nil, fmt.Errorf("%w by %s: %s", errAuthRejected, targetPeer, resp.GetError())
	}

	if err := s.checkProvider(resp.GetBiscuit(), targetPeer, requiredLabels, targetService); err != nil {
		cleanup()
		return nil, nil, err
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "agentmesh-meshnet-mcp-client", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, newStreamTransport(st), nil)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("connect MCP client: %w", err)
	}
	return session, func() {
		_ = session.Close()
		cleanup()
	}, nil
}

func (s *Server) callMCPTool(ctx context.Context, targetPeer peer.ID, toolName string, args any, requiredLabels map[string]string) (*mcp.CallToolResult, error) {
	targetService, bareTool, err := api.SplitToolName(toolName)
	if err != nil {
		return nil, err
	}
	s.preparePeerAddrs(ctx, targetPeer)

	backoff := time.Second
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		session, cleanup, err := s.connectMCPSession(ctx, targetPeer, targetService, requiredLabels)
		if err == nil {
			res, callErr := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      bareTool,
				Arguments: args,
			})
			cleanup()
			if callErr == nil {
				return res, nil
			}
			err = fmt.Errorf("call tool %s: %w", toolName, callErr)
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, errAuthRejected) || errors.Is(err, errProviderNotGranted) {
			return nil, err
		}
		if attempt == 2 {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("failed after 3 attempts: %w", lastErr)
}

func (s *Server) fetchRemoteServiceCatalog(ctx context.Context, peerID peer.ID, typeStr string) ([]*api.ServiceInfo, error) {
	s.preparePeerAddrs(ctx, peerID)
	session, cleanup, err := s.connectMCPSession(ctx, peerID, "system://"+api.CatalogTarget, nil)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_local_services",
		Arguments: map[string]string{"type": typeStr},
	})
	if err != nil {
		return nil, fmt.Errorf("call list_local_services: %w", err)
	}
	if res == nil || len(res.Content) == 0 {
		return nil, errors.New("empty catalog response")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return nil, fmt.Errorf("unexpected catalog content %T", res.Content[0])
	}
	var services []*api.ServiceInfo
	if err := json.Unmarshal([]byte(text.Text), &services); err != nil {
		return nil, fmt.Errorf("unmarshal catalog: %w", err)
	}
	return services, nil
}

func (s *Server) fetchRemoteToolCatalogue(ctx context.Context, targetPeer peer.ID, serviceFilter string) ([]remoteToolRow, error) {
	services, err := s.fetchRemoteServiceCatalog(ctx, targetPeer, "MCP")
	if err != nil {
		return nil, fmt.Errorf("fetch remote service catalog: %w", err)
	}
	var rows []remoteToolRow
	for _, svc := range services {
		if svc == nil || svc.GetType() != api.ServiceType_SERVICE_TYPE_MCP {
			continue
		}
		connectService := svc.GetName()
		if !strings.Contains(connectService, "://") && !strings.Contains(connectService, ":") {
			connectService = api.MCPServicePrefix + connectService
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rows = append(rows, s.fetchToolsForRemoteService(ctx, targetPeer, connectService, svc.GetName(), serviceFilter)...)
	}
	return rows, nil
}

func (s *Server) fetchToolsForRemoteService(ctx context.Context, targetPeer peer.ID, connectService, rawName, serviceFilter string) []remoteToolRow {
	s.preparePeerAddrs(ctx, targetPeer)
	session, cleanup, err := s.connectMCPSession(ctx, targetPeer, connectService, nil)
	if err != nil {
		if errors.Is(err, errAuthRejected) {
			return nil
		}
		if serviceFilter == "" || connectService == serviceFilter {
			return []remoteToolRow{{
				PeerID:   targetPeer.String(),
				ToolName: connectService,
				Error:    fmt.Sprintf("failed to connect: %v", err),
			}}
		}
		return nil
	}
	defer cleanup()

	listRes, err := session.ListTools(ctx, nil)
	if err != nil {
		if serviceFilter == "" || connectService == serviceFilter {
			return []remoteToolRow{{
				PeerID:   targetPeer.String(),
				ToolName: rawName,
				Error:    fmt.Sprintf("failed to list tools: %v", err),
			}}
		}
		return nil
	}
	if listRes == nil {
		return nil
	}
	var rows []remoteToolRow
	for _, t := range listRes.Tools {
		if t == nil {
			continue
		}
		fullName := connectService + "/" + t.Name
		if serviceFilter != "" && !strings.HasPrefix(fullName, serviceFilter+"/") {
			continue
		}
		rows = append(rows, remoteToolRow{
			PeerID:      targetPeer.String(),
			ToolName:    fullName,
			Description: t.Description,
		})
	}
	return rows
}

func (s *Server) fanOutFetchTools(ctx context.Context, peers []peer.ID, serviceFilter string) []remoteToolRow {
	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)
	var (
		mu   sync.Mutex
		rows []remoteToolRow
		wg   sync.WaitGroup
	)
	for _, pid := range peers {
		wg.Add(1)
		go func(p peer.ID) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			peerRows, err := s.fetchRemoteToolCatalogue(peerCtx, p, serviceFilter)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				rows = append(rows, remoteToolRow{
					PeerID: p.String(),
					Error:  fmt.Sprintf("failed to fetch tool catalogue: %v", err),
				})
				return
			}
			rows = append(rows, peerRows...)
		}(pid)
	}
	wg.Wait()
	return rows
}

func (s *Server) fetchRemoteToolDescription(ctx context.Context, pid peer.ID, toolName string) (*remoteToolDescription, error) {
	serviceName, actualToolName, err := api.SplitToolName(toolName)
	if err != nil {
		return nil, err
	}
	if serviceName == "system://"+api.CatalogTarget {
		return nil, errors.New("cannot describe system catalog tools via describe_remote_tool")
	}
	s.preparePeerAddrs(ctx, pid)

	session, cleanup, err := s.connectMCPSession(ctx, pid, serviceName, nil)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	listRes, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	if listRes == nil {
		return nil, errors.New("list tools response was nil")
	}
	for _, tool := range listRes.Tools {
		if tool != nil && tool.Name == actualToolName {
			return &remoteToolDescription{
				PeerID:       pid.String(),
				ToolName:     toolName,
				Description:  tool.Description,
				InputSchema:  tool.InputSchema,
				OutputSchema: tool.OutputSchema,
			}, nil
		}
	}
	return nil, errors.New("tool not found on peer")
}
