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
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type trustedKeySnapshot struct {
	Key     ed25519.PublicKey
	SPKIDER []byte
}

func snapshotControlPlaneKey(key ed25519.PublicKey) (trustedKeySnapshot, error) {
	if len(key) != ed25519.PublicKeySize {
		return trustedKeySnapshot{}, fmt.Errorf("invalid Ed25519 key size %d", len(key))
	}
	keyCopy := append(ed25519.PublicKey(nil), key...)
	der, err := x509.MarshalPKIXPublicKey(keyCopy)
	if err != nil {
		return trustedKeySnapshot{}, fmt.Errorf("marshal Ed25519 SPKI: %w", err)
	}
	return trustedKeySnapshot{
		Key:     keyCopy,
		SPKIDER: der,
	}, nil
}

func (n *AgentMeshNode) trustedKeySnapshot() ([]trustedKeySnapshot, error) {
	n.keysMu.RLock()
	trusted := append([]TrustedKey(nil), n.trustedKeys...)
	n.keysMu.RUnlock()

	snapshots := make([]trustedKeySnapshot, 0, len(trusted))
	for _, candidate := range trusted {
		snapshot, err := snapshotControlPlaneKey(candidate.Key)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return bytes.Compare(snapshots[i].SPKIDER, snapshots[j].SPKIDER) < 0
	})
	return snapshots, nil
}

func keysFromSnapshot(snapshots []trustedKeySnapshot) []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(snapshots))
	for _, snapshot := range snapshots {
		keys = append(keys, snapshot.Key)
	}
	return keys
}

func findSelectedKey(snapshots []trustedKeySnapshot, selected ed25519.PublicKey) (trustedKeySnapshot, bool) {
	for _, snapshot := range snapshots {
		if snapshot.Key.Equal(selected) {
			return snapshot, true
		}
	}
	return trustedKeySnapshot{}, false
}

func (n *AgentMeshNode) stillTrustsKey(selected trustedKeySnapshot) bool {
	n.keysMu.RLock()
	defer n.keysMu.RUnlock()
	for _, candidate := range n.trustedKeys {
		if candidate.Key.Equal(selected.Key) {
			return true
		}
	}
	return false
}

func requireIdentityEvidenceTransport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fromLocalSocket(r) && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
			writeEvidenceError(w, http.StatusForbidden, "Strong transport required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeEvidenceProtoJSON(w http.ResponseWriter, status int, value proto.Message) {
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(value)
	if err != nil {
		logger.Errorf("[IdentityEvidence] Failed to encode response: %v", err)
		writeEvidenceError(w, http.StatusInternalServerError, "Failed to encode response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		logger.Errorf("[IdentityEvidence] Failed to write response: %v", err)
	}
}

func writeEvidenceError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, status)
}

func handleIdentityEvidenceNotFound(w http.ResponseWriter, _ *http.Request) {
	writeEvidenceError(w, http.StatusNotFound, "Not found")
}

func handleIdentityEvidence(n *AgentMeshNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeEvidenceError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if n == nil || n.Host == nil {
		writeEvidenceError(w, http.StatusServiceUnavailable, "Node is unavailable")
		return
	}
	if n.peerIsRevoked(n.Host.ID()) {
		writeEvidenceError(w, http.StatusForbidden, "Local identity is revoked")
		return
	}
	response, err := n.buildIdentityEvidence(time.Now().UTC())
	if err != nil {
		logger.Warnf("[IdentityEvidence] Local identity unavailable: %v", err)
		writeEvidenceError(w, http.StatusServiceUnavailable, "Identity evidence unavailable")
		return
	}
	writeEvidenceProtoJSON(w, http.StatusOK, response)
}

func handlePeerEvidence(n *AgentMeshNode, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeEvidenceError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if n == nil || n.Host == nil {
		writeEvidenceError(w, http.StatusServiceUnavailable, "Node is unavailable")
		return
	}
	const prefix = "/mesh/peer/"
	remainder := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(remainder, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "evidence" {
		writeEvidenceError(w, http.StatusNotFound, "Not found")
		return
	}
	requestedPeer, err := peer.Decode(parts[0])
	if err != nil || requestedPeer.String() != parts[0] {
		writeEvidenceError(w, http.StatusBadRequest, "Invalid peer ID")
		return
	}
	if n.peerIsRevoked(requestedPeer) {
		writeEvidenceError(w, http.StatusForbidden, "Peer is revoked")
		return
	}

	observation, err := n.fetchPeerBiscuitEvidence(r.Context(), requestedPeer)
	if err != nil {
		logger.Warnf("[IdentityEvidence] Peer evidence fetch failed for %s: %v", requestedPeer, err)
		writeEvidenceError(w, http.StatusBadGateway, "Failed to fetch peer evidence")
		return
	}
	response, err := n.buildPeerEvidence(requestedPeer, observation, time.Now().UTC())
	if err != nil {
		logger.Warnf("[IdentityEvidence] Peer evidence verification failed for %s: %v", requestedPeer, err)
		writeEvidenceError(w, http.StatusUnprocessableEntity, "Peer evidence is unverifiable")
		return
	}
	writeEvidenceProtoJSON(w, http.StatusOK, response)
}

func trustedControlPlaneKeysUnavailable(err error, snapshots []trustedKeySnapshot) error {
	if err != nil {
		return fmt.Errorf("trusted control-plane keys unavailable: %w", err)
	}
	if len(snapshots) == 0 {
		return fmt.Errorf("trusted control-plane keys unavailable")
	}
	return nil
}

func (n *AgentMeshNode) buildIdentityEvidence(checkedAt time.Time) (*api.IdentityEvidenceResponse, error) {
	if n == nil || n.Host == nil || n.Store == nil {
		return nil, fmt.Errorf("node identity store is unavailable")
	}
	biscuitBytes := n.GetIdentity()
	if len(biscuitBytes) == 0 {
		return nil, fmt.Errorf("node is not enrolled")
	}
	snapshots, err := n.trustedKeySnapshot()
	if unavailable := trustedControlPlaneKeysUnavailable(err, snapshots); unavailable != nil {
		return nil, unavailable
	}
	b, selectedKey, err := identity.VerifyBiscuitAndGetKey(biscuitBytes, n.Host.ID(), keysFromSnapshot(snapshots), n.BiscuitTimeout)
	if err != nil {
		return nil, err
	}
	selected, ok := findSelectedKey(snapshots, selectedKey)
	if !ok {
		return nil, fmt.Errorf("selected verification key is not in the trusted snapshot")
	}
	claims, err := extractBiscuitClaims(b, selectedKey, n.BiscuitTimeout, checkedAt)
	if err != nil {
		return nil, err
	}
	if claims.PeerID != n.Host.ID().String() || n.peerIsRevoked(n.Host.ID()) || !n.stillTrustsKey(selected) {
		return nil, fmt.Errorf("local peer binding, revocation, or trust state changed during verification")
	}
	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil {
		return nil, fmt.Errorf("control-plane URL unavailable: %w", err)
	}
	keyEvidence := make([][]byte, 0, len(snapshots))
	for _, snapshot := range snapshots {
		keyEvidence = append(keyEvidence, append([]byte(nil), snapshot.SPKIDER...))
	}
	return &api.IdentityEvidenceResponse{
		PeerId:                  n.Host.ID().String(),
		Biscuit:                 append([]byte(nil), biscuitBytes...),
		BiscuitExpireTime:       timestamppb.New(claims.Expiration),
		ControlPlaneUrl:         controlPlaneURL,
		TrustedControlPlaneKeys: keyEvidence,
		CheckTime:               timestamppb.New(checkedAt),
	}, nil
}

func (n *AgentMeshNode) buildPeerEvidence(requested peer.ID, observation peerBiscuitObservation, checkedAt time.Time) (*api.PeerEvidenceResponse, error) {
	if requested == "" || observation.ConnectionPeer == "" || requested != observation.ConnectionPeer {
		return nil, fmt.Errorf("requested and connection PeerIDs differ")
	}
	snapshots, err := n.trustedKeySnapshot()
	if unavailable := trustedControlPlaneKeysUnavailable(err, snapshots); unavailable != nil {
		return nil, unavailable
	}
	b, selectedKey, err := identity.VerifyBiscuitAndGetKey(observation.Biscuit, observation.ConnectionPeer, keysFromSnapshot(snapshots), n.BiscuitTimeout)
	if err != nil {
		return nil, err
	}
	selected, ok := findSelectedKey(snapshots, selectedKey)
	if !ok {
		return nil, fmt.Errorf("selected verification key is not in the trusted snapshot")
	}
	claims, err := extractBiscuitClaims(b, selectedKey, n.BiscuitTimeout, checkedAt)
	if err != nil {
		return nil, err
	}
	if claims.PeerID != requested.String() || n.peerIsRevoked(requested) || !n.stillTrustsKey(selected) {
		return nil, fmt.Errorf("peer binding, revocation, or trust state changed during verification")
	}

	revocationIDs := make([]string, 0, len(b.RevocationIds()))
	for _, id := range b.RevocationIds() {
		revocationIDs = append(revocationIDs, hex.EncodeToString(id))
	}
	return &api.PeerEvidenceResponse{
		PeerId:        requested.String(),
		Biscuit:       append([]byte(nil), observation.Biscuit...),
		VerifyingKey:  append([]byte(nil), selected.SPKIDER...),
		Roles:         append([]string(nil), claims.Roles...),
		Labels:        claims.Labels,
		ExpireTime:    timestamppb.New(claims.Expiration),
		RevocationIds: revocationIDs,
		CheckTime:     timestamppb.New(checkedAt),
	}, nil
}

// peerIsRevoked reports whether the peer is in the revocation cache, which is
// reconciled against the control plane's ban set by every SyncControlPlane
// and updated by MeshEvent_BANNED.
func (n *AgentMeshNode) peerIsRevoked(peerID peer.ID) bool {
	return n.revokedPeers != nil && n.revokedPeers.Contains(peerID.String())
}

type biscuitClaims struct {
	PeerID     string
	Roles      []string
	Labels     map[string]string
	Expiration time.Time
}

func extractBiscuitClaims(b *biscuit.Biscuit, key ed25519.PublicKey, timeout time.Duration, checkedAt time.Time) (biscuitClaims, error) {
	authorizer, err := b.Authorizer(key, identity.AuthorizerOptions(timeout)...)
	if err != nil {
		return biscuitClaims{}, err
	}
	authorizer.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactTime,
		IDs:  []biscuit.Term{biscuit.Date(checkedAt)},
	}})
	authorizer.AddCheck(api.ControlPlaneStaticTimeCheck)
	authorizer.AddPolicy(api.AllowIfTruePolicy)
	if err := authorizer.Authorize(); err != nil {
		return biscuitClaims{}, err
	}

	peerIDs, err := queryStringFacts(authorizer, api.FactNode)
	if err != nil || len(peerIDs) != 1 {
		return biscuitClaims{}, fmt.Errorf("expected exactly one node fact")
	}
	roles, err := queryStringFacts(authorizer, api.FactRole)
	if err != nil {
		return biscuitClaims{}, err
	}
	labels, err := queryLabelFacts(authorizer)
	if err != nil {
		return biscuitClaims{}, err
	}
	expiration, err := queryExpiration(authorizer)
	if err != nil {
		return biscuitClaims{}, err
	}
	sort.Strings(roles)
	return biscuitClaims{PeerID: peerIDs[0], Roles: roles, Labels: labels, Expiration: expiration.UTC()}, nil
}

func queryStringFacts(authorizer biscuit.Authorizer, factName string) ([]string, error) {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q", IDs: []biscuit.Term{biscuit.Variable("v")}},
		Body: []biscuit.Predicate{{Name: factName, IDs: []biscuit.Term{biscuit.Variable("v")}}},
	})
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(facts))
	for _, fact := range facts {
		if len(fact.IDs) != 1 {
			return nil, fmt.Errorf("unexpected %s fact shape", factName)
		}
		value, ok := fact.IDs[0].(biscuit.String)
		if !ok {
			return nil, fmt.Errorf("unexpected %s fact type", factName)
		}
		values = append(values, string(value))
	}
	return values, nil
}

func queryLabelFacts(authorizer biscuit.Authorizer) (map[string]string, error) {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q", IDs: []biscuit.Term{biscuit.Variable("k"), biscuit.Variable("v")}},
		Body: []biscuit.Predicate{{Name: api.FactLabel, IDs: []biscuit.Term{biscuit.Variable("k"), biscuit.Variable("v")}}},
	})
	if err != nil {
		return nil, err
	}
	labels := make(map[string]string, len(facts))
	for _, fact := range facts {
		if len(fact.IDs) != 2 {
			return nil, fmt.Errorf("unexpected label fact shape")
		}
		key, keyOK := fact.IDs[0].(biscuit.String)
		value, valueOK := fact.IDs[1].(biscuit.String)
		if !keyOK || !valueOK {
			return nil, fmt.Errorf("unexpected label fact type")
		}
		if previous, exists := labels[string(key)]; exists && previous != string(value) {
			return nil, fmt.Errorf("conflicting attested label %q", key)
		}
		labels[string(key)] = string(value)
	}
	return labels, nil
}

func queryExpiration(authorizer biscuit.Authorizer) (time.Time, error) {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "q", IDs: []biscuit.Term{biscuit.Variable("t")}},
		Body: []biscuit.Predicate{{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Variable("t")}}},
	})
	if err != nil {
		return time.Time{}, err
	}
	if len(facts) != 1 || len(facts[0].IDs) != 1 {
		return time.Time{}, fmt.Errorf("expected exactly one expiration fact")
	}
	expiration, ok := facts[0].IDs[0].(biscuit.Date)
	if !ok {
		return time.Time{}, fmt.Errorf("unexpected expiration fact type")
	}
	return time.Time(expiration), nil
}
