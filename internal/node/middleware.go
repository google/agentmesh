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
	"crypto/ed25519"
	"errors"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
)

// RequestContext carries the security metadata for a specific stream request
type RequestContext struct {
	PeerID   peer.ID
	User     string
	Group    string
	Protocol string
	Target   string

	// HTTP is set when the node handles the request as HTTP: the method as
	// received and the path as the backend sees it. Injected as method() and
	// path() facts, taken from the wire and never from the caller's token. A
	// tunnel the node opens without terminating HTTP carries Method "CONNECT"
	// and an empty Path. Nil on a stream that carries no HTTP request.
	HTTP *HTTPRequestFacts

	// Egress is set on a request for an egress destination: the hostname and
	// port the node connects to, injected as host() and port() facts.
	Egress *EgressFacts

	// Local marks a request this node makes for one of its own clients over the
	// local API, for a destination it serves itself. The caller is then this
	// node, evaluated on its own credential, and the target check is satisfied
	// because a node is always allowed to reach itself. Never set from the wire.
	Local bool

	// MCPTool is set when evaluating a specific MCP tools/call invocation.
	MCPTool string

	// AllowMCPStreamInit is set when an MCP request is a session handshake or
	// discovery method (initialize, ping, tools/list).
	AllowMCPStreamInit bool

	// TaskRules holds the verified TaskAuthorizationRule chain extracted from
	// the caller's Biscuit during stream authentication so downstream stream
	// handlers (such as MCP pass-through) can enforce tool-level constraints.
	TaskRules []*api.TaskAuthorizationRule
}

// HTTPRequestFacts is what an HTTP request contributes to policy.
type HTTPRequestFacts struct {
	Method string
	Path   string
}

// EgressFacts is the destination of an egress request.
type EgressFacts struct {
	Host string
	Port int
}

// recoverStreamHandler isolates a panic while processing untrusted peer bytes
// to the single stream, resetting it instead of crashing the whole node.
func recoverStreamHandler(name string, next network.StreamHandler) network.StreamHandler {
	return func(s network.Stream) {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("[%s] panic recovered from peer %s: %v\n%s", name, s.Conn().RemotePeer(), r, debug.Stack())
				_ = s.Reset()
			}
		}()
		next(s)
	}
}

// trackingStream wraps a network.Stream to count bytes read and written.
type trackingStream struct {
	network.Stream
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
}

func (t *trackingStream) Read(p []byte) (n int, err error) {
	n, err = t.Stream.Read(p)
	t.bytesRead.Add(int64(n))
	return n, err
}
func (t *trackingStream) Write(p []byte) (n int, err error) {
	n, err = t.Stream.Write(p)
	t.bytesWritten.Add(int64(n))
	return n, err
}

// WithBiscuitAuth enforces a Protobuf handshake on a stream before calling the next handler.
func (n *AgentMeshNode) WithBiscuitAuth(next func(network.Stream, RequestContext)) network.StreamHandler {
	return func(s network.Stream) {
		ts := &trackingStream{Stream: s}
		remotePeer := s.Conn().RemotePeer()
		var reqCtx RequestContext

		defer func() {
			target := reqCtx.Target
			if target == "" {
				target = "unauthenticated_or_failed"
			}
			logger.Infow("Stream Accounting",
				"peer_id", remotePeer.String(),
				"target", truncateForLog(target),
				"protocol", reqCtx.Protocol,
				"bytes_read", ts.bytesRead.Load(),
				"bytes_written", ts.bytesWritten.Load(),
			)
			if err := ts.Close(); err != nil {
				logger.Debugf("[Auth] Failed to close stream: %v", err)
			}
		}()

		if !n.rateLimiter.Allow(remotePeer.String()) {
			logger.Warnf("[Auth] Rate limit exceeded for %s, dropping connection", remotePeer)
			_ = ts.Reset()
			return
		}

		// The peer is not authorized yet: it gets the handshake budget to
		// produce its frame, not an open-ended hold on this goroutine.
		if err := ts.SetReadDeadline(time.Now().Add(authHandshakeTimeout)); err != nil {
			logger.Debugf("[Auth] Failed to set auth frame deadline for %s: %v", remotePeer, err)
		}

		// Read AuthFrame
		reader := msgio.NewVarintReaderSize(ts, 1024*64)
		msg, err := reader.ReadMsg()
		if err != nil {
			logger.Errorf("[Auth] Failed to read auth frame from %s: %v", remotePeer, err)
			return
		}
		defer reader.ReleaseMsg(msg)

		var authFrame api.AuthFrame
		if err := proto.Unmarshal(msg, &authFrame); err != nil {
			logger.Warnf("[Auth] Invalid auth frame from %s", remotePeer)
			return
		}

		reqCtx = RequestContext{
			PeerID:   remotePeer,
			User:     "", // Not used in Authorize
			Protocol: string(ts.Protocol()),
			Target:   authFrame.TargetService,
		}

		writer := msgio.NewVarintWriter(ts)

		taskRules, err := n.verifyBiscuitTokenWithRules(authFrame.Biscuit, reqCtx)
		if err != nil {
			logger.Warnf("[Auth] AuthZ Denied %s: %v", remotePeer, err)
			resp := &api.AuthResponse{Success: false, Error: err.Error()}
			respBytes, _ := proto.Marshal(resp)
			_ = writer.WriteMsg(respBytes)
			return
		}
		reqCtx.TaskRules = taskRules

		// Valid. Mutual auth: return our control-plane-minted identity so the
		// caller can verify this node's attested facts (e.g. region) before
		// sending request data.
		resp := &api.AuthResponse{Success: true, Biscuit: n.GetIdentity()}
		respBytes, _ := proto.Marshal(resp)
		if err := writer.WriteMsg(respBytes); err != nil {
			logger.Errorf("[Auth] Failed to write ACK to %s: %v", remotePeer, err)
			return
		}

		// Authorized: the session itself is long-lived, so the pre-auth
		// deadline comes off.
		if err := ts.SetReadDeadline(time.Time{}); err != nil {
			logger.Debugf("[Auth] Failed to clear auth frame deadline for %s: %v", remotePeer, err)
		}

		next(ts, reqCtx)
	}
}

// VerifyBiscuitToken checks revocation, cache, and evaluates the token against trusted keys and local policies.
func (n *AgentMeshNode) VerifyBiscuitToken(biscuitBytes []byte, reqCtx RequestContext) error {
	_, err := n.verifyBiscuitTokenWithRules(biscuitBytes, reqCtx)
	return err
}

func (n *AgentMeshNode) verifyBiscuitTokenWithRules(biscuitBytes []byte, reqCtx RequestContext) ([]*api.TaskAuthorizationRule, error) {
	remotePeer := reqCtx.PeerID

	// Check revocation cache
	if n.revokedPeers != nil {
		if _, isRevoked := n.revokedPeers.Get(remotePeer.String()); isRevoked {
			logger.Warnf("[Auth] Peer %s is revoked", remotePeer)
			return nil, fmt.Errorf("peer is revoked")
		}
	}

	n.keysMu.RLock()
	keys := n.trustedKeys
	n.keysMu.RUnlock()

	var authorized bool
	var taskRules []*api.TaskAuthorizationRule
	var lastErr error
	for _, pubKey := range keys {
		logger.Infof("[Auth] Trying key: %x", pubKey.Key)
		if rules, err := n.authorizeWithRules(biscuitBytes, reqCtx, pubKey.Key); err == nil {
			authorized = true
			taskRules = rules
			break
		} else {
			lastErr = err
			if !errors.Is(err, biscuit.ErrInvalidSignature) {
				break
			}
		}
	}

	if !authorized {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("authorization failed")
	}

	return taskRules, nil
}

func (n *AgentMeshNode) Authorize(rawToken []byte, req RequestContext, pubKey ed25519.PublicKey) error {
	_, err := n.authorizeWithRules(rawToken, req, pubKey)
	return err
}

func (n *AgentMeshNode) authorizeWithRules(rawToken []byte, req RequestContext, pubKey ed25519.PublicKey) ([]*api.TaskAuthorizationRule, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(pubKey))
	}
	b, taskRules, err := identity.UnmarshalInbound(rawToken)
	if err != nil {
		return nil, fmt.Errorf("invalid biscuit: %w", err)
	}
	if n.IsBiscuitRevoked(b) {
		logger.Infow("Audit Traceability", append(req.auditFields(), "decision", "deny", "reason", "biscuit is revoked")...)
		return nil, fmt.Errorf("biscuit is revoked")
	}

	authorizer, err := b.Authorizer(pubKey, identity.AuthorizerOptions(n.BiscuitTimeout)...)
	if err != nil {
		return nil, err
	}

	if err := identity.RequireAuthorityRequestBinding(b, req.PeerID); err != nil {
		return nil, err
	}

	// The request as every enforcement point describes it: the service it
	// names, or the connection protocol in the system namespace when it
	// names none; the HTTP line and egress destination when present; and
	// the connection peer, which binds client_peer_id to this stream.
	meshReq := identity.MeshRequest{
		ConnectionPeer:     req.PeerID,
		Unrestricted:       req.Local,
		MCPTool:            req.MCPTool,
		AllowMCPStreamInit: req.AllowMCPStreamInit || (req.HTTP == nil && req.MCPTool == "" && req.Protocol == string(api.MCPProtocolID)),
	}
	if req.Target == "" {
		meshReq.ServiceType = api.SystemNamespace
		meshReq.ServiceName = req.Protocol
	} else {
		meshReq.ServiceType, meshReq.ServiceName = api.ParseServiceTarget(req.Target)
	}
	if req.HTTP != nil {
		meshReq.HasHTTP = true
		meshReq.Method = req.HTTP.Method
		meshReq.Path = req.HTTP.Path
	}
	if req.Egress != nil {
		meshReq.HasEgress = true
		meshReq.EgressHost = req.Egress.Host
		meshReq.EgressPort = int64(req.Egress.Port)
	}

	pol, err := n.meshPolicy()
	if err != nil {
		return nil, err
	}
	if err := identity.AuthorizeMeshRequest(authorizer, meshReq, pol); err != nil {
		logger.Infow("Audit Traceability", append(req.auditFields(), "decision", "deny", "reason", err.Error())...)
		logger.Debugf("Authorizer failure: %v, token: %s", err, b.String())
		logger.Debugf("Authorizer state: %s", authorizer.PrintWorld())
		return nil, err
	}

	if len(taskRules) > 0 {
		if err := api.EvaluateTaskRules(taskRules, meshReq.TaskRequest(), time.Now()); err != nil {
			logger.Infow("Audit Traceability", append(req.auditFields(), "decision", "deny", "reason", err.Error())...)
			return nil, err
		}
	}

	var userStr, emailStr, roleStr, actorNodeStr string

	if facts, _ := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_user", IDs: []biscuit.Term{biscuit.Variable("u")}},
		Body: []biscuit.Predicate{{Name: api.FactUser, IDs: []biscuit.Term{biscuit.Variable("u")}}},
	}); len(facts) > 0 && len(facts[0].IDs) > 0 {
		if s, ok := facts[0].IDs[0].(biscuit.String); ok {
			userStr = string(s)
		}
	}

	if facts, _ := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_email", IDs: []biscuit.Term{biscuit.Variable("e")}},
		Body: []biscuit.Predicate{{Name: api.FactEmail, IDs: []biscuit.Term{biscuit.Variable("e")}}},
	}); len(facts) > 0 && len(facts[0].IDs) > 0 {
		if s, ok := facts[0].IDs[0].(biscuit.String); ok {
			emailStr = string(s)
		}
	}

	if facts, _ := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_role", IDs: []biscuit.Term{biscuit.Variable("r")}},
		Body: []biscuit.Predicate{{Name: api.FactRole, IDs: []biscuit.Term{biscuit.Variable("r")}}},
	}); len(facts) > 0 && len(facts[0].IDs) > 0 {
		if s, ok := facts[0].IDs[0].(biscuit.String); ok {
			roleStr = string(s)
		}
	}

	if facts, _ := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_actor_node", IDs: []biscuit.Term{biscuit.Variable("a")}},
		Body: []biscuit.Predicate{{Name: api.FactActorNode, IDs: []biscuit.Term{biscuit.Variable("a")}}},
	}); len(facts) > 0 && len(facts[0].IDs) > 0 {
		if s, ok := facts[0].IDs[0].(biscuit.String); ok {
			actorNodeStr = string(s)
		}
	}

	auditFields := append(req.auditFields(),
		"decision", "allow",
		"user", userStr,
		"email", emailStr,
		"role", roleStr,
	)
	if actorNodeStr != "" {
		if n.revokedPeers != nil {
			if actorPID, pErr := peer.Decode(actorNodeStr); pErr == nil {
				if _, isRevoked := n.revokedPeers.Get(actorPID.String()); isRevoked {
					logger.Infow("Audit Traceability", append(req.auditFields(), "decision", "deny", "reason", "actor_node is revoked")...)
					return nil, fmt.Errorf("actor_node %s is revoked", actorPID.String())
				}
			}
		}
		auditFields = append(auditFields, "actor_node", actorNodeStr)
	}
	if len(taskRules) > 0 {
		auditFields = append(auditFields, "task", taskRules[len(taskRules)-1].GetName())
	}
	logger.Infow("Audit Traceability", auditFields...)

	return taskRules, nil
}

// auditFields is what every authorization decision logs about the request:
// who asked, for what, and the request facts policy saw. One line per
// decision, allow or deny, is the audit trail of the PEP.
func (req RequestContext) auditFields() []any {
	fields := []any{
		"peer_id", req.PeerID.String(),
		"target", req.Target,
		"protocol", req.Protocol,
	}
	if req.HTTP != nil {
		fields = append(fields, "method", req.HTTP.Method, "path", req.HTTP.Path)
	}
	if req.Egress != nil {
		fields = append(fields, "host", req.Egress.Host, "port", req.Egress.Port)
	}
	if req.MCPTool != "" {
		fields = append(fields, "mcp_tool", req.MCPTool)
	}
	return fields
}

// meshPolicy is what this node adds to every authorization it performs,
// on whichever path the request arrived: the target facts of its own
// credential, its local attenuation from agentmesh-node.yaml, and the mesh
// policy rules it last synced. Both the in-mesh verifier
// (verifyBiscuitTokenWithRules) and the external ingress handler build their
// authorizer from this one value, so neither can drift from the other.
func (n *AgentMeshNode) meshPolicy() (identity.MeshPolicy, error) {
	targetFacts, err := n.ownTargetFacts()
	if err != nil {
		return identity.MeshPolicy{}, err
	}
	n.MeshPolicyMu.RLock()
	meshRules := n.MeshPolicyRules
	n.MeshPolicyMu.RUnlock()

	pol := identity.MeshPolicy{TargetFacts: targetFacts, MeshRules: meshRules}
	if n.nodeConfig != nil {
		pol.LocalPolicies = n.nodeConfig.Policies
		pol.LocalChecks = n.nodeConfig.Checks
		pol.LocalRules = n.nodeConfig.Rules
	}
	return pol, nil
}

// ownTargetFacts queries this node's own credential for the target_fact()
// facts a caller's target grants are matched against. A node without an
// identity yet contributes none: BaselineTargetCheck then admits only a
// caller whose grant is unrestricted.
func (n *AgentMeshNode) ownTargetFacts() ([]biscuit.Fact, error) {
	ourIdentity := n.GetIdentity()
	if len(ourIdentity) == 0 {
		logger.Debugf("[Auth] Node identity is missing, no target facts to match against")
		return nil, nil
	}
	ourB, err := biscuit.Unmarshal(ourIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal node identity: %w", err)
	}
	facts, err := identity.TargetFactsFromBiscuit(ourB, n.trustedPublicKeys(), n.BiscuitTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to inject target facts: %w", err)
	}
	return facts, nil
}
