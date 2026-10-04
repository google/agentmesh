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
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand"
	"time"

	cpclient "github.com/google/sam/internal/controlplane/client"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// The node reads three things from the control plane while it runs: the
// signing keys it verifies every credential against (/keys), the ban set and
// router addresses (/info), and the mesh policy (/policies). They are pulled
// together, by one loop, on one interval. Gossip events are notifications
// that bring the next pull forward; they are never the only way state
// arrives, because a once-published event with no replay is missed by any
// node that was down, partitioned, or simply enrolled later.

// SyncControlPlane is the node's single pull from the control plane. Each
// part is attempted even when another fails, so a policy outage does not
// stop a key rotation from landing; the errors are reported together. Called
// once before Start, so the node dials the routers the control plane knows
// now and enforces the bans it holds now, and then by the sync loop.
func (n *SamNode) SyncControlPlane(ctx context.Context) error {
	if n.Store == nil {
		return errors.New("node has no store")
	}
	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil || controlPlaneURL == "" {
		return errors.New("control plane URL not found in store")
	}
	var errs []error
	if err := n.syncTrustedKeys(ctx, controlPlaneURL); err != nil {
		errs = append(errs, fmt.Errorf("keys: %w", err))
	} else if n.identityPredatesRotation() {
		if err := n.RefreshEnrollment(ctx); err != nil {
			errs = append(errs, fmt.Errorf("refresh enrollment after key rotation: %w", err))
		}
	}
	if err := n.syncMeshInfo(ctx, controlPlaneURL); err != nil {
		errs = append(errs, fmt.Errorf("info: %w", err))
	}
	if err := n.syncMeshPolicy(ctx); err != nil {
		errs = append(errs, fmt.Errorf("policy: %w", err))
	}
	if err := n.syncEgressAssignments(ctx, controlPlaneURL); err != nil {
		errs = append(errs, fmt.Errorf("egress: %w", err))
	}
	if err := n.syncRevocations(ctx, controlPlaneURL); err != nil {
		errs = append(errs, fmt.Errorf("revocations: %w", err))
	}
	return errors.Join(errs...)
}

func (n *SamNode) syncRevocations(ctx context.Context, controlPlaneURL string) error {
	token := n.GetIdentity()
	if len(token) == 0 {
		return nil
	}
	fetchedAt := time.Now()
	resp, err := controlPlaneClient(controlPlaneURL).FetchRevocations(ctx, token)
	if errors.Is(err, cpclient.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	expiry := fetchedAt.Add(24 * time.Hour)
	for _, revID := range resp.GetRevocationIds() {
		n.RevokeBiscuitID(revID, expiry)
	}
	if len(resp.GetBannedPeerIds()) > 0 {
		n.reconcileBannedPeers(resp.GetBannedPeerIds(), fetchedAt)
	}
	return nil
}

// syncTrustedKeys replaces the trust set with the control plane's current
// /keys answer and persists it. Enrollment hands out only the newest key, so
// this is how a node learns the key still in its rotation grace period (which
// routers and peers may still be signed by) and any successor it did not hear
// about. Verification against the keys already trusted keeps whoever answers
// the URL from becoming the trust root; an empty answer is a failure so the
// set is never wiped.
func (n *SamNode) syncTrustedKeys(ctx context.Context, controlPlaneURL string) error {
	n.keysMu.RLock()
	existing := append([]TrustedKey(nil), n.trustedKeys...)
	n.keysMu.RUnlock()
	if len(existing) == 0 {
		return errors.New("no trusted control plane keys to verify /keys against")
	}
	keys, err := FetchControlPlaneKeys(ctx, controlPlaneURL, publicKeysOf(existing))
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("/keys returned no keys")
	}
	merged := mergeTrustedKeys(existing, keys, time.Now())
	n.keysMu.Lock()
	n.trustedKeys = merged
	snapshot := append([]TrustedKey(nil), merged...)
	n.keysMu.Unlock()
	n.persistTrustedKeys(snapshot)
	logger.Debugf("Synced %d valid control plane keys", len(merged))
	return nil
}

// identityPredatesRotation reports whether a trusted key exists that was not
// known when the stored identity was issued: the identity is then signed by
// a retiring key and must be refreshed before that key leaves its grace
// period. Both sides of the comparison are persisted, so the answer is the
// same after a restart. An identity from a build that recorded no set is
// checked against the stored mesh-config key, the one enrollment handed out
// with it. Nothing enrolled means nothing to refresh.
func (n *SamNode) identityPredatesRotation() bool {
	if n.Store == nil || len(n.GetIdentity()) == 0 {
		return false
	}
	issuance, err := n.Store.LoadIdentityKeySet()
	if err != nil {
		logger.Warnf("Could not load the identity's key set: %v", err)
		return false
	}
	if len(issuance) == 0 {
		enrollmentKey, _, err := n.Store.LoadMeshConfig()
		if err != nil || len(enrollmentKey) != ed25519.PublicKeySize {
			return false
		}
		issuance = []ed25519.PublicKey{ed25519.PublicKey(enrollmentKey)}
	}
	n.keysMu.RLock()
	defer n.keysMu.RUnlock()
	for _, tk := range n.trustedKeys {
		if !containsPublicKey(issuance, tk.Key) {
			return true
		}
	}
	return false
}

func containsPublicKey(keys []ed25519.PublicKey, key ed25519.PublicKey) bool {
	for _, candidate := range keys {
		if candidate.Equal(key) {
			return true
		}
	}
	return false
}

// recordIdentityKeySet pins the trusted set to the identity just adopted.
func (n *SamNode) recordIdentityKeySet() {
	if n.Store == nil {
		return
	}
	n.keysMu.RLock()
	keys := publicKeysOf(n.trustedKeys)
	n.keysMu.RUnlock()
	if err := n.Store.SaveIdentityKeySet(keys); err != nil {
		logger.Errorf("Failed to persist the identity's key set: %v", err)
	}
}

// syncMeshInfo reads /info. The router addresses are persisted for the next
// start and, until the host exists, adopted as the static relays Start will
// dial; once it is running they only matter to the next start. The ban set
// is reconciled against the revocation cache, which is how a running node
// learns a ban or an unban it got no event for.
func (n *SamNode) syncMeshInfo(ctx context.Context, controlPlaneURL string) error {
	// Taken before the request: a ban recorded after this instant cannot be
	// in the answer, so its absence must not be read as an unban.
	fetchedAt := time.Now()
	info, err := FetchControlPlaneInfo(ctx, controlPlaneURL)
	if err != nil {
		return err
	}
	if len(info.RouterAddresses) > 0 {
		pubKey, _, loadErr := n.Store.LoadMeshConfig()
		switch {
		case loadErr != nil:
			logger.Warnf("Failed to load mesh config; not persisting router addresses: %v", loadErr)
		case len(pubKey) > 0:
			if saveErr := n.Store.SaveMeshConfig(pubKey, info.RouterAddresses); saveErr != nil {
				logger.Warnf("Failed to persist router addresses: %v", saveErr)
			}
		}
		if n.Host == nil {
			if addrs := parseMultiaddrs(info.RouterAddresses); len(addrs) > 0 {
				n.config.RouterAddrs = addrs
			}
		}
	}
	n.reconcileBannedPeers(info.GetBannedPeerIds(), fetchedAt)
	return nil
}

// parseMultiaddrs keeps the addresses that parse and logs the rest.
func parseMultiaddrs(addrs []string) []multiaddr.Multiaddr {
	out := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, s := range addrs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			logger.Warnf("Ignoring router address %q from the control plane: %v", s, err)
			continue
		}
		out = append(out, ma)
	}
	return out
}

// reconcileBannedPeers makes the revocation cache match the control plane's
// ban set as of fetchedAt. Bans recorded at or after fetchedAt are kept even
// when absent from the answer: the answer predates them and cannot speak to
// them (see the router's reconcileBannedPeers for the same rule).
func (n *SamNode) reconcileBannedPeers(peerIDs []string, fetchedAt time.Time) {
	if n.revokedPeers == nil {
		return
	}
	banned := make(map[string]peer.ID, len(peerIDs))
	for _, id := range peerIDs {
		p, err := peer.Decode(id)
		if err != nil {
			logger.Warnf("Ignoring undecodable banned peer ID %q from the control plane: %v", id, err)
			continue
		}
		banned[p.String()] = p
	}
	fetchedAtMs := fetchedAt.UnixMilli()
	for _, key := range n.revokedPeers.Keys() {
		if _, still := banned[key]; still {
			continue
		}
		if bannedAt, ok := n.revokedPeers.Peek(key); ok && bannedAt >= fetchedAtMs {
			continue
		}
		logger.Infof("Peer %s is no longer banned by the control plane; lifting the local ban", key)
		n.revokedPeers.Remove(key)
	}
	for key, p := range banned {
		if n.revokedPeers.Contains(key) {
			continue
		}
		logger.Infow("peer banned by the control plane", "event", meshEventBanned, "peer", key)
		n.banPeer(p, fetchedAtMs)
	}
}

// banPeer records the ban and evicts the peer: the cache entry is what the
// gater and the auth path consult, and dropping the admission is what stops
// the relay ACL from honouring a session that was already established.
func (n *SamNode) banPeer(p peer.ID, bannedAtMs int64) {
	if n.revokedPeers != nil {
		n.revokedPeers.Add(p.String(), bannedAtMs)
	}
	n.authPeers.Delete(p)
	if n.Host != nil {
		_ = n.Host.Network().ClosePeer(p)
	}
}

// triggerControlPlaneSync asks the sync loop to run soon, after a random
// delay of up to the configured jitter so a fleet told at once does not hit
// the control plane at once. A pending request is not duplicated.
func (n *SamNode) triggerControlPlaneSync() {
	select {
	case n.controlPlaneSyncTrigger <- struct{}{}:
	default:
	}
}

// startControlPlaneSyncLoop pulls once shortly after start, then every
// interval and whenever triggered. Each periodic wait is stretched by up to a
// tenth of the interval and each trigger delayed by up to the configured
// jitter, so a fleet started or notified together does not pull together.
// Failures are logged at Warn once and at Debug while they persist, with an
// Info on recovery.
func (n *SamNode) startControlPlaneSyncLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 || n.Store == nil {
		return
	}
	go func() {
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		failures := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case <-n.controlPlaneSyncTrigger:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				if jitter := n.config.ControlPlaneSyncJitter; jitter > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(rand.Int63n(int64(jitter)))):
					}
				}
			}
			timer.Reset(interval + time.Duration(rand.Int63n(int64(interval/10)+1)))

			err := n.SyncControlPlane(ctx)
			switch {
			case err != nil && failures == 0:
				logger.Warnf("Control plane sync failed: %v", err)
			case err != nil:
				logger.Debugf("Control plane sync still failing (%d consecutive): %v", failures+1, err)
			case failures > 0:
				logger.Infof("Control plane sync recovered after %d failures", failures)
			}
			if err != nil {
				failures++
			} else {
				failures = 0
			}
		}
	}()
}
