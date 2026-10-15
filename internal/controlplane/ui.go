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

package controlplane

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/storage"
)

// Page bounds for GET /user/nodes, so one request is one bounded query.
const (
	defaultNodesPageSize = 50
	maxNodesPageSize     = 200
)

// statusNodeStates are the nodes GET /admin/status and GET /user/status list on
// every console refresh. Expired rows stay for the retention period, so
// GET /user/nodes pages them instead and the lists stay the size of the live mesh.
var statusNodeStates = []storage.NodeState{storage.NodeAdmitted, storage.NodeBanned}

// HandleAdminStatus HTTP GET `/admin/status`: the whole mesh as the console
// shows it, protojson of AdminStatusResponse.
func (s *Server) HandleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	now := time.Now()

	routers, err := s.store.GetActiveRouters(ctx)
	if err != nil {
		logger.Errorf("Failed to get active routers: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	nodes, err := s.store.ListNodes(ctx, storage.NodeFilter{States: statusNodeStates, Now: now})
	if err != nil {
		logger.Errorf("Failed to list nodes: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	reqs, err := s.store.ListEnrollmentRequests(ctx)
	if err != nil {
		logger.Errorf("Failed to list enrollment requests: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	tokens, err := s.store.ListBootstrapTokens(ctx)
	if err != nil {
		logger.Errorf("Failed to list bootstrap tokens: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	users, err := s.store.ListUsers(ctx)
	if err != nil {
		logger.Errorf("Failed to list users: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	policy, err := s.loadPolicyConfig(ctx)
	if err != nil {
		logger.Errorf("Failed to list policy: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	enrolled := make([]*api.EnrolledNode, 0, len(nodes))
	for i := range nodes {
		enrolled = append(enrolled, enrolledNodeView(&nodes[i], true))
	}

	writeProtoJSON(w, &api.AdminStatusResponse{
		Users:              userViews(users),
		ActiveRouters:      routerLeaseViews(routers),
		EnrolledNodes:      enrolled,
		EnrollmentRequests: enrollmentRequestViews(reqs),
		BootstrapTokens:    bootstrapTokenViews(tokens),
		Policy:             policy,
		NodeCatalog:        s.catalogViewFor(nodes, now),
	})
}

// HandleListNodes HTTP GET `/user/nodes`: one page of the nodes the caller
// may see, protojson of NodeListResponse. An administrator sees every owner's
// nodes and may pick one with owner_id; a user sees only its own.
func (s *Server) HandleListNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}

	query := r.URL.Query()
	pageSize, err := parseNodesPageSize(query.Get("page_size"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	after, err := decodeNodesPageToken(query.Get("page_token"))
	if err != nil {
		http.Error(w, "Invalid page_token", http.StatusBadRequest)
		return
	}
	states, err := parseNodeStates(query["state"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	isAdmin := user.Role == "admin"
	owner := &user.ID
	if isAdmin {
		owner = nil
	}
	if query.Has("owner_id") {
		id := query.Get("owner_id")
		if !isAdmin && id != user.ID {
			http.Error(w, "Only an administrator may list another owner's nodes", http.StatusForbidden)
			return
		}
		owner = &id
	}

	// One row past the page tells whether a next page exists.
	nodes, err := s.store.ListNodes(r.Context(), storage.NodeFilter{
		States:  states,
		Now:     time.Now(),
		OwnerID: owner,
		Role:    query.Get("role"),
		After:   after,
		Limit:   pageSize + 1,
	})
	if err != nil {
		logger.Errorf("Failed to list nodes: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	resp := &api.NodeListResponse{}
	if len(nodes) > pageSize {
		nodes = nodes[:pageSize]
		last := nodes[pageSize-1]
		resp.NextPageToken = encodeNodesPageToken(storage.NodeCursor{EnrolledAt: last.EnrolledAt, PeerID: last.PeerID})
	}
	for i := range nodes {
		resp.Nodes = append(resp.Nodes, enrolledNodeView(&nodes[i], isAdmin))
	}
	writeProtoJSON(w, resp)
}

func parseNodesPageSize(raw string) (int, error) {
	if raw == "" {
		return defaultNodesPageSize, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, errors.New("page_size must be a positive integer")
	}
	return min(n, maxNodesPageSize), nil
}

// parseNodeStates reads the repeatable state parameter; none means every state.
func parseNodeStates(raw []string) ([]storage.NodeState, error) {
	states := make([]storage.NodeState, 0, len(raw))
	for _, value := range raw {
		state := storage.NodeState(value)
		switch state {
		case storage.NodeAdmitted, storage.NodeExpired, storage.NodeBanned:
			if !slices.Contains(states, state) {
				states = append(states, state)
			}
		default:
			return nil, fmt.Errorf("state must be admitted, expired or banned, not %q", value)
		}
	}
	return states, nil
}

// The token is opaque to clients: base64url of "<enrollment unix ms>:<peer ID>",
// the sort key of the last row served.
func encodeNodesPageToken(c storage.NodeCursor) string {
	key := strconv.FormatInt(c.EnrolledAt.UnixMilli(), 10) + ":" + c.PeerID
	return base64.RawURLEncoding.EncodeToString([]byte(key))
}

// decodeNodesPageToken returns nil for an empty token, the first page.
func decodeNodesPageToken(token string) (*storage.NodeCursor, error) {
	if token == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	ms, peerID, ok := strings.Cut(string(raw), ":")
	if !ok || peerID == "" {
		return nil, errors.New("page token lacks a peer ID")
	}
	at, err := strconv.ParseInt(ms, 10, 64)
	if err != nil {
		return nil, err
	}
	return &storage.NodeCursor{EnrolledAt: time.UnixMilli(at), PeerID: peerID}, nil
}
