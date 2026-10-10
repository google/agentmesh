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
	"strings"
	"sync"
	"time"

	"github.com/google/agentmesh/api"
	samdiscovery "github.com/google/agentmesh/internal/node/discovery"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ListLocalServicesParams defines the parameters for the list_local_services tool.
type ListLocalServicesParams struct {
	Type string `json:"type,omitempty" jsonschema:"Optional service type filter (mcp, inference, a2a). Empty means all types."`
}

// handleListLocalServices implements the list_local_services tool.
func (n *AgentMeshNode) handleListLocalServices(ctx context.Context, req *mcp.CallToolRequest, params ListLocalServicesParams) (*mcp.CallToolResult, any, error) {
	typeFilter := api.ServiceType_SERVICE_TYPE_UNSPECIFIED
	if params.Type != "" {
		parsed, err := api.ParseServiceType(params.Type)
		if err != nil {
			return nil, nil, err
		}
		typeFilter = parsed
	}
	services := n.ListLocalServices(typeFilter)
	logger.Infof("[ListLocalServices] Filter: %v, Returning %d services", typeFilter, len(services))
	respData, err := json.Marshal(services)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(respData)},
		},
	}, nil, nil
}

// inferenceInvocationHint tells the calling agent how to call an inference://
// service's local_proxy_url directly over HTTP. Inference services are plain
// OpenAI-compatible endpoints, never invoked via call_remote_tool.
const inferenceInvocationHint = `To call an inference service, send a normal HTTP request (e.g. POST <local_proxy_url>/chat/completions) directly to its "local_proxy_url" — do NOT use call_remote_tool. Required headers:
  - "X-Mesh-Authentication: Bearer <your local node API token>" authenticates you to this node; it is never forwarded off-node.
  - "Authorization: Bearer <upstream-credential>" is OPTIONAL and only needed if the destination service itself requires its own credential (e.g. a provider API key); it passes straight through untouched and plays no part in authenticating to this node.`

// DiscoverRemoteServicesParams defines the parameters for the discover_remote_services tool.
type DiscoverRemoteServicesParams struct {
	Type   string `json:"type" jsonschema:"Required. One of: mcp, inference, a2a."`
	Name   string `json:"name,omitempty" jsonschema:"Optional service name. Omit to list all services of the given type."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Optional limit for pagination. Defaults to 20."`
	Offset int    `json:"offset,omitempty" jsonschema:"Optional offset for pagination. Defaults to 0."`
}

// handleDiscoverRemoteServices implements the discover_remote_services tool.
func (n *AgentMeshNode) handleDiscoverRemoteServices(ctx context.Context, req *mcp.CallToolRequest, params DiscoverRemoteServicesParams) (*mcp.CallToolResult, any, error) {
	serviceType, err := api.ParseServiceType(params.Type)
	if err != nil || serviceType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return nil, nil, fmt.Errorf("invalid or unspecified service type: %s", params.Type)
	}
	providers, err := n.DiscoverRemoteServices(ctx, serviceType, params.Name)
	if err != nil {
		return nil, nil, err
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	if offset >= len(providers) {
		providers = []*api.DiscoveredProvider{}
	} else {
		end := offset + limit
		if end > len(providers) || end < offset {
			end = len(providers)
		}
		providers = providers[offset:end]
	}

	respData, err := json.Marshal(providers)
	if err != nil {
		return nil, nil, err
	}
	content := []mcp.Content{&mcp.TextContent{Text: string(respData)}}
	if serviceType == api.ServiceType_SERVICE_TYPE_INFERENCE && len(providers) > 0 {
		content = append(content, &mcp.TextContent{Text: inferenceInvocationHint})
	}
	return &mcp.CallToolResult{
		Content: content,
	}, nil, nil
}

// GetMeshInfoParams defines the parameters for the get_mesh_info tool.
type GetMeshInfoParams struct{}

// handleGetMeshInfo implements the get_mesh_info tool.
func (n *AgentMeshNode) handleGetMeshInfo(ctx context.Context, req *mcp.CallToolRequest, params GetMeshInfoParams) (*mcp.CallToolResult, any, error) {
	resData, err := n.meshInfo()
	if err != nil {
		return nil, nil, err
	}
	responseBytes, err := json.Marshal(resData)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(responseBytes)},
		},
	}, nil, nil
}

// handleGetMeshInfoRemote is get_mesh_info as served to other peers over the
// catalog stream: the local socket path, the router and the connected-peer
// list are this node's business, not a remote caller's.
func (n *AgentMeshNode) handleGetMeshInfoRemote(ctx context.Context, req *mcp.CallToolRequest, params GetMeshInfoParams) (*mcp.CallToolResult, any, error) {
	full, err := n.meshInfo()
	if err != nil {
		return nil, nil, err
	}
	responseBytes, err := json.Marshal(struct {
		PeerID  string `json:"peer_id"`
		DHTSize int    `json:"dht_size"`
	}{PeerID: full.PeerID, DHTSize: full.DHTSize})
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(responseBytes)}},
	}, nil, nil
}

// CallRemoteToolParams defines the parameters for the call_remote_tool tool.
//
// Arguments is a JSON object whose shape matches the target server's
// input_schema (use describe_remote_tool to fetch it). Earlier revisions
// took a stringified JSON blob here; that footgun is gone.
type CallRemoteToolParams struct {
	PeerID         string         `json:"peer_id" jsonschema:"The Peer ID of the target agent"`
	ToolName       string         `json:"tool_name" jsonschema:"The name of the server to call"`
	Arguments      map[string]any `json:"arguments,omitempty" jsonschema:"Server arguments as a JSON object whose keys match the target server's input_schema. Call describe_remote_tool first to learn the schema."`
	RequiredLabels string         `json:"required_labels,omitempty" jsonschema:"Comma-separated key=value pairs (e.g. 'region=us-east-1,team=platform'). Fails closed: the call is rejected unless the peer attests every one of them. Empty means no requirement."`
}

// handleCallRemoteTool implements the call_remote_tool tool.
func (n *AgentMeshNode) handleCallRemoteTool(ctx context.Context, req *mcp.CallToolRequest, params CallRemoteToolParams) (*mcp.CallToolResult, any, error) {
	logger.Infof("[MCP] call_remote_tool called for peer %s, tool %s", params.PeerID, params.ToolName)
	targetPeer, err := peer.Decode(params.PeerID)
	if err != nil {
		return nil, nil, err
	}
	requiredLabels, err := parseRequiredLabels(params.RequiredLabels)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid required_labels: %w", err)
	}
	res, err := n.CallMCPTool(ctx, targetPeer, params.ToolName, params.Arguments, requiredLabels)
	if err != nil {
		return nil, nil, err
	}
	return res, nil, nil
}

// FindRemoteToolsParams defines the parameters for the
// find_remote_tools tool.
type FindRemoteToolsParams struct {
	Intent      string `json:"intent,omitempty" jsonschema:"Natural-language description of what the caller is looking for. Reserved for future semantic ranking; currently accepted but ignored."`
	PeerID      string `json:"peer_id,omitempty" jsonschema:"Restrict the search to a single peer. Empty means search the whole mesh."`
	ServiceName string `json:"service_name,omitempty" jsonschema:"Restrict results to tools whose name starts with this service prefix (e.g. 'code-reviewer'). Empty means no service filter."`
	ToolName    string `json:"tool_name,omitempty" jsonschema:"Exact (non-namespaced) tool name to locate across the mesh, e.g. 'review_pr'. Served from gossip announcements when fresh; falls back to a mesh-wide fetch. Empty means list all tools."`
}

// remoteToolRow is one entry in the find_remote_tools response.
type remoteToolRow struct {
	PeerID      string `json:"peer_id"`
	ToolName    string `json:"tool_name,omitempty"`
	Description string `json:"description,omitempty"`
	// Labels are the provider's operator-declared labels, when known from
	// gossip (e.g. "region"). A routing hint, not an enforced attribute.
	Labels map[string]string `json:"labels,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// handleFindRemoteTools implements the find_remote_tools tool.
//
// Scope:
//   - If params.PeerID is set, only that peer is queried.
//   - Otherwise the candidate list is obtained via DiscoverRemoteServices.
//
// Filtering:
//   - If params.ServiceName is set, only tools from that service are returned.
//     Bare ("everything") and namespaced ("mcp://everything") forms are equivalent.
//   - params.Intent is accepted and logged at debug level, but does not
//     filter or rank results in this implementation (placeholder for
//     future semantic search).
func (n *AgentMeshNode) handleFindRemoteTools(ctx context.Context, req *mcp.CallToolRequest, params FindRemoteToolsParams) (*mcp.CallToolResult, any, error) {
	if params.Intent != "" {
		logger.Debugf("[find_remote_tools] intent (ignored): %q", params.Intent)
	}

	selfID := n.Host.ID().String()
	if params.PeerID != "" && params.PeerID == selfID {
		return nil, nil, fmt.Errorf("peer_id %q is this node; cross-mesh discovery cannot target self", params.PeerID)
	}

	serviceFilter, err := normalizeServiceFilter(params.ServiceName)
	if err != nil {
		return nil, nil, err
	}

	var rows []remoteToolRow

	// Exact-name lookup: gossip fast path, avoiding the catalog fan-out
	// when interested announcements are already flowing.
	if params.ToolName != "" && params.PeerID == "" && n.Discovery != nil {
		n.Discovery.Ensure(api.ServiceType_SERVICE_TYPE_MCP, params.ToolName)
		if provs := n.Discovery.Providers(api.ServiceType_SERVICE_TYPE_MCP, params.ToolName); len(provs) > 0 {
			candidates := gossipToolRows(provs, params.ToolName, serviceFilter)
			rows = n.verifyGossipToolRows(ctx, candidates)
			if len(rows) > 0 {
				return marshalToolRows(rows)
			}
		}
	}

	if params.PeerID != "" {
		pid, err := peer.Decode(params.PeerID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid peer_id %q: %w", params.PeerID, err)
		}
		peerRows, err := n.fetchRemoteToolCatalogue(ctx, pid, serviceFilter)
		if err != nil {
			return nil, nil, err
		}
		rows = peerRows
	} else {
		providers, err := n.DiscoverRemoteServices(ctx, api.ServiceType_SERVICE_TYPE_MCP, "")
		if err != nil {
			return nil, nil, fmt.Errorf("discover providers: %w", err)
		}
		seen := map[string]bool{}
		var peerIDs []peer.ID
		for _, p := range providers {
			if p.PeerId == selfID || seen[p.PeerId] {
				continue
			}
			seen[p.PeerId] = true
			pid, err := peer.Decode(p.PeerId)
			if err != nil {
				continue
			}
			peerIDs = append(peerIDs, pid)
		}

		rows = n.fanOutFetch(ctx, peerIDs, serviceFilter)
	}

	if params.ToolName != "" {
		rows = filterRowsByToolName(rows, params.ToolName)
	}
	n.annotateToolLabels(rows)
	return marshalToolRows(rows)
}

// marshalToolRows renders the find_remote_tools response.
func marshalToolRows(rows []remoteToolRow) (*mcp.CallToolResult, any, error) {
	if rows == nil {
		rows = []remoteToolRow{}
	}
	respData, err := json.Marshal(rows)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(respData)}},
	}, nil, nil
}

// normalizeServiceFilter canonicalises the service_name filter.
//
// This tool only ever searches MCP services, so the scheme is redundant and a
// bare "everything" is accepted alongside "mcp://everything". Any other scheme
// is an error rather than a filter that matches nothing: an empty result is
// already the honest answer for a service the mesh does not have, so it cannot
// also mean the caller misspelled one.
func normalizeServiceFilter(name string) (string, error) {
	switch {
	case name == "":
		return "", nil
	case !strings.Contains(name, "://"):
		return api.MCPServicePrefix + name, nil
	case strings.HasPrefix(name, api.MCPServicePrefix):
		return name, nil
	default:
		return "", fmt.Errorf("service_name %q: find_remote_tools searches MCP services only; pass a bare name such as \"everything\" or an %s name", name, api.MCPServicePrefix)
	}
}

// gossipToolRows builds result rows from gossip-observed providers of a tool.
// serviceNameFilter must already be canonical; see normalizeServiceFilter.
func gossipToolRows(provs []samdiscovery.Provider, toolName, serviceNameFilter string) []remoteToolRow {
	var rows []remoteToolRow
	for _, p := range provs {
		name := p.Service
		if !strings.Contains(name, "://") {
			name = api.MCPServicePrefix + name
		}
		if serviceNameFilter != "" && name != serviceNameFilter {
			continue
		}
		rows = append(rows, remoteToolRow{
			PeerID:   p.PeerID,
			ToolName: name + "/" + toolName,
			Labels:   p.Labels,
		})
	}
	return rows
}

// verifyGossipToolRows treats unsolicited announcements as routing hints, not
// authorization evidence. Each candidate is confirmed through the existing
// authenticated MCP session and exact tools/list response before it is exposed.
func (n *AgentMeshNode) verifyGossipToolRows(ctx context.Context, candidates []remoteToolRow) []remoteToolRow {
	return verifyGossipToolRowsWithFetcher(ctx, candidates, n.fetchRemoteToolDescription)
}

const (
	gossipVerificationMaxConcurrent = 8
	gossipVerificationTimeout       = 5 * time.Second
)

func verifyGossipToolRowsWithFetcher(
	ctx context.Context,
	candidates []remoteToolRow,
	fetchDescription func(context.Context, peer.ID, string) (*remoteToolDescription, error),
) []remoteToolRow {
	if len(candidates) == 0 {
		return nil
	}

	type verificationResult struct {
		row remoteToolRow
		ok  bool
	}
	results := make([]verificationResult, len(candidates))
	jobs := make(chan int)
	workerCount := len(candidates)
	if workerCount > gossipVerificationMaxConcurrent {
		workerCount = gossipVerificationMaxConcurrent
	}

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					candidate := candidates[index]
					pid, err := peer.Decode(candidate.PeerID)
					if err != nil {
						logger.Debugf("[find_remote_tools] invalid gossip peer %q skipped: %v", candidate.PeerID, err)
						continue
					}
					requestCtx, cancel := context.WithTimeout(ctx, gossipVerificationTimeout)
					description, err := fetchDescription(requestCtx, pid, candidate.ToolName)
					cancel()
					if err != nil {
						logger.Debugf("[find_remote_tools] unverified gossip candidate %s on %s skipped: %v", candidate.ToolName, pid, err)
						continue
					}
					results[index] = verificationResult{
						ok: true,
						row: remoteToolRow{
							PeerID:      description.PeerID,
							ToolName:    description.ToolName,
							Description: description.Description,
							Labels:      candidate.Labels,
						},
					}
				}
			}
		}()
	}

sendCandidates:
	for index := range candidates {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break sendCandidates
		}
	}
	close(jobs)
	wg.Wait()

	rows := make([]remoteToolRow, 0, len(results))
	for _, result := range results {
		if result.ok {
			rows = append(rows, result.row)
		}
	}
	return rows
}

// filterRowsByToolName keeps rows whose namespaced tool name ends in the
// bare tool name; error rows (no tool listing) are dropped from targeted
// lookups.
func filterRowsByToolName(rows []remoteToolRow, toolName string) []remoteToolRow {
	var out []remoteToolRow
	for _, row := range rows {
		if row.Error != "" {
			continue
		}
		if row.ToolName[strings.LastIndex(row.ToolName, "/")+1:] == toolName {
			out = append(out, row)
		}
	}
	return out
}

// annotateToolLabels fills in the operator-declared labels for peers the
// gossip view knows, when not already known from a fresher source.
func (n *AgentMeshNode) annotateToolLabels(rows []remoteToolRow) {
	if n.Discovery == nil {
		return
	}
	for i := range rows {
		if len(rows[i].Labels) != 0 {
			continue
		}
		if labels := n.Discovery.PeerLabels(rows[i].PeerID); labels != nil {
			rows[i].Labels = labels
		}
	}
}

// fetchRemoteToolCatalogue gets the remote node's service catalogue,
// then opens a separate libp2p stream to each MCP service to fetch its tools.
// serviceNameFilter must already be canonical; see normalizeServiceFilter.
func (n *AgentMeshNode) fetchRemoteToolCatalogue(ctx context.Context, targetPeer peer.ID, serviceNameFilter string) ([]remoteToolRow, error) {
	services, err := n.fetchRemoteServiceCatalog(ctx, targetPeer, "MCP")
	if err != nil {
		return nil, fmt.Errorf("fetch remote service catalog: %w", err)
	}

	var rows []remoteToolRow

	for _, svc := range services {
		if svc == nil || svc.Type != api.ServiceType_SERVICE_TYPE_MCP {
			continue
		}

		targetService := svc.Name
		connectService := targetService
		if !strings.Contains(connectService, "://") && !strings.Contains(connectService, ":") {
			connectService = api.MCPServicePrefix + connectService
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		rows = append(rows, n.fetchToolsForRemoteService(ctx, targetPeer, connectService, targetService, serviceNameFilter)...)
	}

	return rows, nil
}

// fetchToolsForRemoteService opens one MCP session to a single remote service,
// lists its tools, and returns the matching rows. Per-service failures are
// encoded as error rows (or omitted for AuthRejected); the session is always
// closed when the function returns.
func (n *AgentMeshNode) fetchToolsForRemoteService(
	ctx context.Context,
	targetPeer peer.ID,
	connectService, targetService, serviceNameFilter string,
) []remoteToolRow {
	n.preparePeerAddrs(ctx, targetPeer)
	session, cleanup, err := n.ConnectMCPSession(ctx, targetPeer, connectService, nil)
	if err != nil {
		if errors.Is(err, ErrAuthRejected) {
			// Not authorized for this service: omit it entirely rather than
			// leaking its existence ("what you see is what you can do", #176).
			logger.Debugf("Hiding unauthorized service %s from discovery: %v", targetService, err)
			return nil
		}
		logger.Debugf("Failed to connect MCP session for service %s: %v", targetService, err)
		if serviceNameFilter == "" || connectService == serviceNameFilter {
			return []remoteToolRow{{
				PeerID:   targetPeer.String(),
				ToolName: connectService,
				Error:    fmt.Sprintf("failed to connect: %v", err),
			}}
		}
		return nil
	}
	defer cleanup()

	tools, err := listAllTools(ctx, session)
	if err != nil {
		if serviceNameFilter == "" || connectService == serviceNameFilter {
			return []remoteToolRow{{
				PeerID:   targetPeer.String(),
				ToolName: targetService,
				Error:    fmt.Sprintf("failed to list tools: %v", err),
			}}
		}
		return nil
	}
	var rows []remoteToolRow
	for _, t := range tools {
		if t == nil {
			continue
		}
		t.Name = connectService + "/" + t.Name
		if serviceNameFilter != "" && !strings.HasPrefix(t.Name, serviceNameFilter+"/") {
			continue
		}
		rows = append(rows, remoteToolRow{
			PeerID:      targetPeer.String(),
			ToolName:    t.Name,
			Description: t.Description,
		})
	}
	return rows
}

// fanOutFetch queries each peer's tool catalogue concurrently with a
// small cap and returns the filtered rows. Per-peer failures are
// logged at debug level and skipped — best-effort mesh-wide fetch.
func (n *AgentMeshNode) fanOutFetch(ctx context.Context, peers []peer.ID, serviceName string) []remoteToolRow {
	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)

	var (
		mu   sync.Mutex
		rows []remoteToolRow
	)

	var wg sync.WaitGroup
	for _, pid := range peers {
		pid := pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			peerRows, err := n.fetchRemoteToolCatalogue(peerCtx, pid, serviceName)
			if err != nil {
				logger.Debugf("[find_remote_tools] peer %s skipped: %v", pid, err)
				mu.Lock()
				rows = append(rows, remoteToolRow{
					PeerID: pid.String(),
					Error:  fmt.Sprintf("failed to fetch tool catalogue: %v", err),
				})
				mu.Unlock()
				return
			}

			mu.Lock()
			rows = append(rows, peerRows...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	return rows
}

// remoteToolDescription is the JSON payload describe_local_tool emits on the
// peer side and describe_remote_tool re-emits on the caller side. The
// caller-side handler fills PeerID; the peer-side handler leaves it empty.
//
// InputSchema and OutputSchema mirror mcp.Tool's typing (`any`): the SDK
// surfaces them as map[string]any on the client side, and we re-marshal
// them verbatim without imposing a typed-schema constraint.
type remoteToolDescription struct {
	PeerID       string `json:"peer_id,omitempty"`
	ToolName     string `json:"tool_name"`
	Description  string `json:"description"`
	InputSchema  any    `json:"input_schema,omitempty"`
	OutputSchema any    `json:"output_schema,omitempty"`
}

// DescribeRemoteToolParams defines parameters for the describe_remote_tool
// sidecar tool.
type DescribeRemoteToolParams struct {
	PeerID   string `json:"peer_id" jsonschema:"Peer ID of the node hosting the server. Required."`
	ToolName string `json:"tool_name" jsonschema:"Namespaced server name as returned by find_remote_tools (e.g. 'mcp://code-reviewer/review_pr'). Required."`
}

func (n *AgentMeshNode) fetchRemoteToolDescription(ctx context.Context, pid peer.ID, toolName string) (*remoteToolDescription, error) {
	serviceName, actualToolName, err := api.SplitToolName(toolName)
	if err != nil {
		return nil, err
	}
	if serviceName == "system://"+api.CatalogTarget {
		return nil, fmt.Errorf("cannot describe system catalog tools via describe_remote_tool")
	}
	n.preparePeerAddrs(ctx, pid)

	session, cleanup, err := n.ConnectMCPSession(ctx, pid, serviceName, nil)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	tools, err := listAllTools(ctx, session)
	if err != nil {
		return nil, err
	}

	for _, tool := range tools {
		if tool == nil {
			continue
		}
		if tool.Name == actualToolName {
			return &remoteToolDescription{
				PeerID:       pid.String(),
				ToolName:     toolName,
				Description:  tool.Description,
				InputSchema:  tool.InputSchema,
				OutputSchema: tool.OutputSchema,
			}, nil
		}
	}

	return nil, fmt.Errorf("tool not found on peer")
}

// handleDescribeRemoteTool implements the describe_remote_tool client-facing tool.
func (n *AgentMeshNode) handleDescribeRemoteTool(ctx context.Context, req *mcp.CallToolRequest, params DescribeRemoteToolParams) (*mcp.CallToolResult, any, error) {
	if params.PeerID == "" {
		return nil, nil, fmt.Errorf("peer_id is required")
	}
	if params.ToolName == "" {
		return nil, nil, fmt.Errorf("tool_name is required")
	}

	pid, err := peer.Decode(params.PeerID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid peer_id: %w", err)
	}

	payload, err := n.fetchRemoteToolDescription(ctx, pid, params.ToolName)
	if err != nil {
		return nil, nil, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}
