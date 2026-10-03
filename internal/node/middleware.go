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
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/google/sam/api"
	"github.com/google/sam/internal/identity"
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
func (n *SamNode) WithBiscuitAuth(next func(network.Stream, RequestContext)) network.StreamHandler {
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
func (n *SamNode) VerifyBiscuitToken(biscuitBytes []byte, reqCtx RequestContext) error {
	_, err := n.verifyBiscuitTokenWithRules(biscuitBytes, reqCtx)
	return err
}

func (n *SamNode) verifyBiscuitTokenWithRules(biscuitBytes []byte, reqCtx RequestContext) ([]*api.TaskAuthorizationRule, error) {
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

func (n *SamNode) Authorize(rawToken []byte, req RequestContext, pubKey ed25519.PublicKey) error {
	_, err := n.authorizeWithRules(rawToken, req, pubKey)
	return err
}

func (n *SamNode) authorizeWithRules(rawToken []byte, req RequestContext, pubKey ed25519.PublicKey) ([]*api.TaskAuthorizationRule, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(pubKey))
	}
	b, taskRules, err := identity.UnmarshalInbound(rawToken)
	if err != nil {
		return nil, fmt.Errorf("invalid biscuit: %w", err)
	}

	authorizer, err := b.Authorizer(pubKey, identity.AuthorizerOptions(n.BiscuitTimeout)...)
	if err != nil {
		return nil, err
	}

	if err := identity.RequireAuthorityBinding(b, req.PeerID); err != nil {
		return nil, err
	}

	// Inject the current action context (Standard Vocabulary)
	var opType, opName string
	if req.Target == "" {
		// When no explicit target is requested, the operation is scoped to the connection protocol itself,
		// which resides in the "system" namespace.
		opType = api.SystemNamespace
		opName = req.Protocol
	} else {
		opType, opName = api.ParseServiceTarget(req.Target)
	}
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactService,
			IDs:  []biscuit.Term{biscuit.String(opType), biscuit.String(opName)},
		},
	})

	// Inject connection_peer_id fact for replay defense
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactConnectionPeerID,
			IDs:  []biscuit.Term{biscuit.String(req.PeerID.String())},
		},
	})

	// Enforce client_peer_id matches connection_peer_id
	authorizer.AddCheck(api.BaselineReplayCheck)

	// The request as the wire carried it. Present only when there is an HTTP
	// request, so a grant narrowed to methods and paths (PolicyRole.http) has
	// nothing to match on a bare stream and fails closed.
	if req.HTTP != nil {
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactMethod,
			IDs:  []biscuit.Term{biscuit.String(req.HTTP.Method)},
		}})
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactPath,
			IDs:  []biscuit.Term{biscuit.String(req.HTTP.Path)},
		}})
	}
	if req.Egress != nil {
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactHost,
			IDs:  []biscuit.Term{biscuit.String(req.Egress.Host)},
		}})
		authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactPort,
			IDs:  []biscuit.Term{biscuit.Integer(req.Egress.Port)},
		}})
	}
	if req.Local {
		authorizer.AddFact(api.MarkerFact(api.FactTargetUnrestricted))
	}

	identity.EnforceExpiration(authorizer)

	// Inject facts from our own identity token to support target matching
	if err := n.injectIdentityFacts(authorizer, pubKey); err != nil {
		return nil, fmt.Errorf("failed to inject target facts: %w", err)
	}

	if n.nodeConfig != nil {
		for _, p := range n.nodeConfig.Policies {
			authorizer.AddPolicy(p)
		}
		for _, c := range n.nodeConfig.Checks {
			authorizer.AddCheck(c)
		}
		for _, r := range n.nodeConfig.Rules {
			authorizer.AddRule(r)
		}
	}

	// Apply Baseline Policies and Rules
	authorizer.AddCheck(api.BaselineTargetCheck)
	for _, p := range api.BaselinePolicies {
		authorizer.AddPolicy(p)
	}
	for _, r := range api.BaselineRules {
		authorizer.AddRule(r)
	}
	for _, r := range api.BaselineHTTPRules {
		authorizer.AddRule(r)
	}

	// Apply Dynamic Mesh Policy Rules
	n.MeshPolicyMu.RLock()
	meshRules := n.MeshPolicyRules
	n.MeshPolicyMu.RUnlock()

	for _, r := range meshRules {
		authorizer.AddRule(r)
	}

	err = authorizer.Authorize()
	if err != nil {
		logger.Infow("Audit Traceability", append(req.auditFields(), "decision", "deny", "reason", err.Error())...)
		logger.Debugf("Authorizer failure: %v, token: %s", err, b.String())
		logger.Debugf("Authorizer state: %s", authorizer.PrintWorld())
		return nil, err
	}

	if len(taskRules) > 0 {
		taskReq := api.TaskRequestContext{
			ServiceType:        opType,
			ServiceName:        opName,
			MCPTool:            req.MCPTool,
			AllowMCPStreamInit: req.HTTP == nil && req.MCPTool == "" && req.Protocol == string(api.MCPProtocolID),
		}
		if req.HTTP != nil {
			taskReq.HasHTTP = true
			taskReq.Method = req.HTTP.Method
			taskReq.Path = req.HTTP.Path
		}
		if err := api.EvaluateTaskRules(taskRules, taskReq, time.Now()); err != nil {
			logger.Infow("Audit Traceability", append(req.auditFields(), "decision", "deny", "reason", err.Error())...)
			return nil, err
		}
	}

	var userStr, emailStr, roleStr string

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

	auditFields := append(req.auditFields(),
		"decision", "allow",
		"user", userStr,
		"email", emailStr,
		"role", roleStr,
	)
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

func (n *SamNode) injectIdentityFacts(authorizer biscuit.Authorizer, pubKey ed25519.PublicKey) error {
	ourIdentity := n.GetIdentity()
	if ourIdentity == nil {
		logger.Debugf("[Auth] Node identity is missing, skipping target fact injection")
		return nil
	}

	ourB, err := biscuit.Unmarshal(ourIdentity)
	if err != nil {
		return fmt.Errorf("failed to unmarshal node identity: %w", err)
	}

	n.keysMu.RLock()
	keys := make([]TrustedKey, len(n.trustedKeys))
	copy(keys, n.trustedKeys)
	n.keysMu.RUnlock()

	authOpts := identity.AuthorizerOptions(n.BiscuitTimeout)

	var auth biscuit.Authorizer
	var authErr error
	for _, tk := range keys {
		if a, err := ourB.Authorizer(tk.Key, authOpts...); err == nil {
			auth = a
			break
		} else {
			authErr = err
		}
	}

	if auth == nil {
		return fmt.Errorf("failed to create authorizer for node identity (signature verification mismatch): %w", authErr)
	}

	// We must Authorize() to evaluate the token's facts into the world
	auth.AddPolicy(api.AllowIfTruePolicy)
	if err := auth.Authorize(); err != nil {
		return fmt.Errorf("failed to validate node identity token (e.g. expired): %w", err)
	}

	for _, rule := range api.TargetFactRules {
		if factSet, err := auth.Query(rule); err == nil {
			for _, fact := range factSet {
				authorizer.AddFact(fact)
			}
		}
	}
	return nil
}
