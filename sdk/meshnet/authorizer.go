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
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	labelGateCacheSize   = 1024
	labelGateTTL         = 5 * time.Minute
	labelGateDialTimeout = 10 * time.Second
)

var (
	errProviderUnreachable = errors.New("provider unreachable")
	errProviderNotGranted  = errors.New("provider not granted the service")
)

type httpRequestFacts struct {
	method string
	path   string
}

func (s *Server) policyRules() []biscuit.Rule {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.meshPolicyRules
}

// meshPolicy builds the shared identity.MeshPolicy used by both in-mesh stream
// authorization and external router HTTP ingress, keeping every PEP on the
// single identity.AuthorizeMeshRequest assembly.
func (s *Server) meshPolicy() (identity.MeshPolicy, error) {
	var targetFacts []biscuit.Fact
	if ourIdentity := s.currentBiscuit(); len(ourIdentity) > 0 {
		ourB, err := biscuit.Unmarshal(ourIdentity)
		if err != nil {
			return identity.MeshPolicy{}, fmt.Errorf("unmarshal local identity: %w", err)
		}
		tf, err := identity.TargetFactsFromBiscuit(ourB, s.trustedPublicKeys(), s.biscuitTimeout())
		if err != nil {
			return identity.MeshPolicy{}, fmt.Errorf("extract local target facts: %w", err)
		}
		targetFacts = tf
	}
	return identity.MeshPolicy{
		TargetFacts: targetFacts,
		MeshRules:   s.policyRules(),
	}, nil
}

func (s *Server) authorizeInbound(rawToken []byte, remotePeer peer.ID, target, protocol string, httpFacts *httpRequestFacts) (*CallerInfo, error) {
	if s.isPeerBanned(remotePeer) {
		s.log().Warn("refusing inbound request from banned peer", "peer_id", remotePeer.String(), "target", target)
		return nil, errors.New("peer is banned")
	}
	keys := s.trustedPublicKeys()
	if len(keys) == 0 {
		return nil, errors.New("no trusted control plane keys loaded")
	}

	var lastErr error
	for _, pubKey := range keys {
		info, err := s.authorizeInboundWithKey(rawToken, remotePeer, target, protocol, httpFacts, pubKey)
		if err == nil {
			return info, nil
		}
		lastErr = err
		if !errors.Is(err, biscuit.ErrInvalidSignature) {
			break
		}
	}
	return nil, lastErr
}

func (s *Server) authorizeInboundWithKey(rawToken []byte, remotePeer peer.ID, target, protocol string, httpFacts *httpRequestFacts, pubKey ed25519.PublicKey) (*CallerInfo, error) {
	b, taskRules, err := identity.UnmarshalInbound(rawToken)
	if err != nil {
		return nil, fmt.Errorf("invalid biscuit: %w", err)
	}
	if s.isBiscuitRevoked(b) {
		s.log().Info("inbound authorization denied", "peer_id", remotePeer.String(), "target", target, "reason", "biscuit is revoked")
		return nil, errors.New("biscuit is revoked")
	}
	if err := identity.RequireAuthorityRequestBinding(b, remotePeer); err != nil {
		return nil, err
	}

	authorizer, err := b.Authorizer(pubKey, identity.AuthorizerOptions(s.biscuitTimeout())...)
	if err != nil {
		return nil, err
	}

	var opType, opName string
	if target == "" {
		opType = api.SystemNamespace
		opName = protocol
	} else {
		opType, opName = api.ParseServiceTarget(target)
	}
	meshReq := identity.MeshRequest{
		ServiceType:        opType,
		ServiceName:        opName,
		ConnectionPeer:     remotePeer,
		AllowMCPStreamInit: httpFacts == nil && protocol == string(api.MCPProtocolID),
	}
	if httpFacts != nil {
		meshReq.HasHTTP = true
		meshReq.Method = httpFacts.method
		meshReq.Path = httpFacts.path
	}

	pol, err := s.meshPolicy()
	if err != nil {
		return nil, err
	}
	if err := identity.AuthorizeMeshRequest(authorizer, meshReq, pol); err != nil {
		s.log().Info("inbound authorization denied", "peer_id", remotePeer.String(), "target", target, "protocol", protocol, "reason", err.Error())
		return nil, err
	}

	if len(taskRules) > 0 {
		if err := api.EvaluateTaskRules(taskRules, meshReq.TaskRequest(), time.Now()); err != nil {
			s.log().Info("inbound task rule denied", "peer_id", remotePeer.String(), "target", target, "reason", err.Error())
			return nil, err
		}
	}

	actorNode := queryFirstString(authorizer, api.FactActorNode)
	if actorNode != "" {
		if actorPID, pErr := peer.Decode(actorNode); pErr == nil && s.isPeerBanned(actorPID) {
			s.log().Info("inbound authorization denied", "peer_id", remotePeer.String(), "target", target, "reason", "actor_node is banned")
			return nil, fmt.Errorf("actor_node %s is banned", actorPID.String())
		}
	}

	email := queryFirstString(authorizer, api.FactEmail)
	user := queryFirstString(authorizer, api.FactUser)
	nodeFact := queryFirstString(authorizer, api.FactNode)
	clientPeer := queryFirstString(authorizer, api.FactClientPeerID)
	roles := queryAllStrings(authorizer, api.FactRole)
	labels := queryLabels(authorizer)

	principal := email
	switch {
	case principal != "":
	case user != "":
		principal = user
	case nodeFact != "":
		principal = "node:" + nodeFact
	case clientPeer != "":
		principal = "peer:" + clientPeer
	default:
		principal = "node:" + remotePeer.String()
	}

	var taskName string
	if len(taskRules) > 0 {
		taskName = taskRules[len(taskRules)-1].GetName()
	}

	s.log().Info("inbound authorization allowed",
		"peer_id", remotePeer.String(),
		"principal", principal,
		"roles", roles,
		"task", taskName,
		"target", target,
		"protocol", protocol,
	)

	return &CallerInfo{
		PeerID:    remotePeer.String(),
		Principal: principal,
		Roles:     roles,
		Labels:    labels,
		Task:      taskName,
	}, nil
}

func queryAllStrings(authorizer biscuit.Authorizer, factName string) []string {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q", IDs: []biscuit.Term{biscuit.Variable("v")}},
		Body: []biscuit.Predicate{{Name: factName, IDs: []biscuit.Term{biscuit.Variable("v")}}},
	})
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range facts {
		if len(f.IDs) == 1 {
			if str, ok := f.IDs[0].(biscuit.String); ok {
				out = append(out, string(str))
			}
		}
	}
	sort.Strings(out)
	return out
}

func queryFirstString(authorizer biscuit.Authorizer, factName string) string {
	vals := queryAllStrings(authorizer, factName)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func queryLabels(authorizer biscuit.Authorizer) map[string]string {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q_lbl", IDs: []biscuit.Term{biscuit.Variable("k"), biscuit.Variable("v")}},
		Body: []biscuit.Predicate{{Name: api.FactLabel, IDs: []biscuit.Term{biscuit.Variable("k"), biscuit.Variable("v")}}},
	})
	if err != nil || len(facts) == 0 {
		return nil
	}
	out := make(map[string]string, len(facts))
	for _, f := range facts {
		if len(f.IDs) == 2 {
			k, okK := f.IDs[0].(biscuit.String)
			v, okV := f.IDs[1].(biscuit.String)
			if okK && okV {
				out[string(k)] = string(v)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Server) verifyLocalBiscuit(rawToken []byte) (*identity.VerifiedBiscuitClaims, error) {
	claims, err := identity.InspectVerifiedBiscuit(rawToken, s.trustedPublicKeys(), s.biscuitTimeout())
	if err != nil {
		return nil, err
	}
	if s.isBiscuitRevoked(claims.Biscuit) {
		return nil, errors.New("biscuit is revoked")
	}
	if claims.NodePeerID != "" {
		if pid, pErr := peer.Decode(claims.NodePeerID); pErr == nil && s.isPeerBanned(pid) {
			return nil, fmt.Errorf("peer %s is banned", pid)
		}
	}
	if claims.ActorNodePeerID != "" {
		if pid, pErr := peer.Decode(claims.ActorNodePeerID); pErr == nil && s.isPeerBanned(pid) {
			return nil, fmt.Errorf("actor_node %s is banned", pid)
		}
	}
	return claims, nil
}

// parseRequiredLabels splits X-Mesh-Required-Labels ("k1=v1,k2=v2") into a
// validated map, rejecting malformed entries fail-closed.
func parseRequiredLabels(h string) (map[string]string, error) {
	if strings.TrimSpace(h) == "" {
		return nil, nil
	}
	var out map[string]string
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("invalid label %q: expected key=value", part)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if err := api.ValidateLabelKey(k); err != nil {
			return nil, err
		}
		if err := api.ValidateLabelValue(v); err != nil {
			return nil, err
		}
		if out == nil {
			out = make(map[string]string)
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("duplicate label key %q", k)
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid required labels %q: expected at least one key=value pair", h)
	}
	return out, nil
}

func labelGateStatus(err error, denied string) (string, int) {
	if errors.Is(err, errProviderUnreachable) {
		return "Bad Gateway: destination did not answer", http.StatusBadGateway
	}
	return denied, http.StatusForbidden
}

func labelGateKey(peerID peer.ID, required, floor map[string]string, service string) string {
	render := func(sb *strings.Builder, m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteByte('|')
			sb.WriteString(k)
			sb.WriteByte('=')
			sb.WriteString(m[k])
		}
	}
	var sb strings.Builder
	sb.WriteString(peerID.String())
	render(&sb, required)
	sb.WriteString("#floor")
	render(&sb, floor)
	sb.WriteString("=svc=")
	sb.WriteString(service)
	return sb.String()
}

func (s *Server) verifyProvider(ctx context.Context, peerID peer.ID, required map[string]string, service string) error {
	key := labelGateKey(peerID, required, s.EgressRequireLabels, service)
	if s.peerLabelGate != nil {
		if until, ok := s.peerLabelGate.Get(key); ok && time.Now().Before(until) {
			return nil
		}
	}

	providerBiscuit, err := s.fetchPeerBiscuit(ctx, peerID)
	if err != nil {
		return fmt.Errorf("provider %s unreachable: %w: %w", peerID, errProviderUnreachable, err)
	}
	if err := s.checkProvider(providerBiscuit, peerID, required, service); err != nil {
		return err
	}
	if s.peerLabelGate != nil {
		s.peerLabelGate.Add(key, time.Now().Add(labelGateTTL))
	}
	return nil
}

func (s *Server) checkProvider(providerBiscuit []byte, peerID peer.ID, required map[string]string, service string) error {
	if len(providerBiscuit) == 0 {
		return fmt.Errorf("provider %s returned no identity biscuit", peerID)
	}
	trusted := s.trustedPublicKeys()
	if len(trusted) == 0 {
		return errors.New("no trusted control plane keys loaded")
	}
	b, key, err := identity.VerifyBiscuitAndGetKey(providerBiscuit, peerID, trusted, s.biscuitTimeout())
	if err != nil {
		return fmt.Errorf("provider %s biscuit verification failed: %w", peerID, err)
	}
	if err := identity.RequireRole(b, key, api.RoleNode, s.biscuitTimeout()); err != nil {
		return fmt.Errorf("provider %s is not enrolled as a node: %w", peerID, err)
	}

	authorizer, err := b.Authorizer(key, identity.AuthorizerOptions(s.biscuitTimeout())...)
	if err != nil {
		return fmt.Errorf("provider %s authorizer failed: %w", peerID, err)
	}
	if len(required) > 0 {
		check, err := api.LabelCheck(required)
		if err != nil {
			return err
		}
		authorizer.AddCheck(check)
	}
	if len(s.EgressRequireLabels) > 0 {
		check, err := api.LabelCheck(s.EgressRequireLabels)
		if err != nil {
			return err
		}
		authorizer.AddCheck(check)
	}
	authorizer.AddPolicy(api.AllowIfTruePolicy)
	if err := authorizer.Authorize(); err != nil {
		return fmt.Errorf("provider %s does not attest required labels: %w", peerID, err)
	}

	if service != "" && service != "system://"+api.CatalogTarget {
		svcType, svcName := api.ParseServiceTarget(service)
		if svcType == "" || svcName == "" {
			return fmt.Errorf("service %q must be <type>://<name>", service)
		}
		if err := identity.RequirePublish(b, key, svcType, svcName, s.policyRules(), s.biscuitTimeout()); err != nil {
			return fmt.Errorf("%w: %w", errProviderNotGranted, err)
		}
	}
	return nil
}

func (s *Server) fetchPeerBiscuit(ctx context.Context, peerID peer.ID) ([]byte, error) {
	ourBiscuit := s.currentBiscuit()
	if len(ourBiscuit) == 0 {
		return nil, errors.New("missing local member biscuit")
	}
	s.preparePeerAddrs(ctx, peerID)
	dialCtx, cancel := context.WithTimeout(network.WithAllowLimitedConn(ctx, "label-gate"), labelGateDialTimeout)
	defer cancel()

	st, err := s.host.NewStream(dialCtx, peerID, api.AuthProtocolID)
	if err != nil {
		return nil, fmt.Errorf("open auth stream: %w", err)
	}
	defer func() { _ = st.Close() }()
	_ = st.SetDeadline(time.Now().Add(labelGateDialTimeout))

	if st.Conn().RemotePeer() != peerID {
		return nil, fmt.Errorf("authenticated connection peer %s does not match requested peer %s", st.Conn().RemotePeer(), peerID)
	}
	authBytes, err := proto.Marshal(&api.AuthFrame{Biscuit: ourBiscuit})
	if err != nil {
		return nil, err
	}
	if err := msgio.NewVarintWriter(st).WriteMsg(authBytes); err != nil {
		return nil, fmt.Errorf("write auth frame: %w", err)
	}
	reader := msgio.NewVarintReaderSize(st, 64*1024)
	msg, err := reader.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("read auth response: %w", err)
	}
	defer reader.ReleaseMsg(msg)

	var resp api.AuthResponse
	if err := proto.Unmarshal(msg, &resp); err != nil {
		return nil, fmt.Errorf("invalid auth response: %w", err)
	}
	if !resp.GetSuccess() {
		return nil, fmt.Errorf("auth rejected: %s", resp.GetError())
	}
	return resp.GetBiscuit(), nil
}

// AttenuateToken appends a validated TaskAuthorizationRule (`tar_block` fact,
// 0 rules, 0 checks) to the member's current Biscuit in memory without a
// control-plane round trip, optionally sealing it so downstream holders cannot
// append further blocks. Use it to delegate a task-scoped credential to a
// sub-agent or an external worker without its own mesh identity; callers
// already running a Server call peers directly through Server.HTTPClient().
func (s *Server) AttenuateToken(rule *api.TaskAuthorizationRule, ttl time.Duration, seal bool) (string, time.Time, error) {
	if rule == nil {
		return "", time.Time{}, errors.New("meshnet: TaskAuthorizationRule is required")
	}
	raw := s.currentBiscuit()
	if len(raw) == 0 {
		return "", time.Time{}, errors.New("meshnet: no member credential loaded (call Up first)")
	}

	cloned := proto.Clone(rule).(*api.TaskAuthorizationRule)
	now := time.Now()
	exp := s.credentialExpireTime()
	if exp.IsZero() {
		exp = now.Add(api.BiscuitTokenTTL)
	}
	if ttl > 0 {
		if candidate := now.Add(ttl); candidate.Before(exp) {
			exp = candidate
		}
	}
	if cloned.GetExpireTime() != nil {
		if ruleExp := cloned.GetExpireTime().AsTime(); ruleExp.Before(exp) {
			exp = ruleExp
		}
	}
	if !now.Before(exp) {
		return "", time.Time{}, errors.New("meshnet: attenuated token expiration is in the past")
	}
	cloned.ExpireTime = timestamppb.New(exp)

	out, err := identity.AttenuateBiscuit(raw, cloned)
	if err != nil {
		return "", time.Time{}, err
	}
	if seal {
		out, err = identity.SealBiscuit(out)
		if err != nil {
			return "", time.Time{}, err
		}
	}
	return base64.RawURLEncoding.EncodeToString(out), exp, nil
}
