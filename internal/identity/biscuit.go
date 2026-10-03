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

package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/peer"
)

// DefaultAuthorizerTimeout bounds Datalog evaluation when no timeout is configured.
// biscuit-go defaults to 2ms of wall-clock time, of which a single authorization of
// a realistic token already spends ~0.14ms (~1.1ms under -race), so ordinary
// scheduling noise turns into a spurious denial.
const DefaultAuthorizerTimeout = 1 * time.Second

// Datalog world limits, biscuit-go's defaults made explicit. They bound the
// number of derived facts and fixpoint iterations, but neither preempts a
// single rule: one self-join over a few hundred facts runs to completion
// whatever these say, and on timeout biscuit-go's worker goroutine keeps
// computing. The only bound on attacker-authored rules is therefore that SAM
// never evaluates any: see UnmarshalInbound.
const (
	maxDatalogFacts      = 1000
	maxDatalogIterations = 100
)

// AuthorizerOptions returns the authorizer options enforcing a Datalog evaluation
// budget. A non-positive timeout falls back to DefaultAuthorizerTimeout.
func AuthorizerOptions(timeout time.Duration) []biscuit.AuthorizerOption {
	if timeout <= 0 {
		timeout = DefaultAuthorizerTimeout
	}
	return []biscuit.AuthorizerOption{biscuit.WithWorldOptions(
		datalog.WithMaxDuration(timeout),
		datalog.WithMaxFacts(maxDatalogFacts),
		datalog.WithMaxIterations(maxDatalogIterations),
	)}
}

// ErrAppendedBlocks is returned for a token that carries attenuation blocks.
var ErrAppendedBlocks = errors.New("biscuit carries appended blocks; SAM tokens are authority-block only")

// UnmarshalInbound parses a token received from a peer or a client and
// refuses one with appended blocks.
//
// Appending needs no root key, so appended blocks are the one place a token
// holder can put Datalog of their own. SAM reads nothing from them: facts
// there are invisible to the authorizer and RequireAuthorityBinding ignores
// them. What they can still do is cost CPU: a block with a self-join rule
// over a few hundred facts pins a core for the whole evaluation budget on
// every verifier that evaluates it, and leaks the worker goroutine (see the
// limits above). The control plane never mints such blocks, so a token that
// has any is not one SAM issued in its current form.
func UnmarshalInbound(biscuitData []byte) (*biscuit.Biscuit, error) {
	b, err := biscuit.Unmarshal(biscuitData)
	if err != nil {
		return nil, fmt.Errorf("malformed biscuit: %w", err)
	}
	if n := b.BlockCount(); n > 0 {
		return nil, fmt.Errorf("%w (%d)", ErrAppendedBlocks, n)
	}
	return b, nil
}

// EnforceExpiration injects the current time and the expiration check into an
// authorizer. Every path that admits a biscuit must call this: expiry is a
// Datalog check over a time fact, so an authorizer built without the fact
// silently accepts expired tokens (see #296). A token carrying no expiration()
// fact fails the check, so this is fail-closed.
func EnforceExpiration(authorizer biscuit.Authorizer) {
	authorizer.AddFact(biscuit.Fact{
		Predicate: biscuit.Predicate{
			Name: api.FactTime,
			IDs:  []biscuit.Term{biscuit.Date(time.Now())},
		},
	})
	authorizer.AddCheck(api.ControlPlaneStaticTimeCheck)
}

// authorityBlockID is the block index biscuit-go reports for a fact carried by
// the root-signed authority block. Every other index is an appended attenuation
// block, which any token holder can create without the root key.
const authorityBlockID = 0

// RequireAuthorityBinding checks that the token is bound to expectedPeer by an
// api.FactNode fact in the authority block.
//
// The block matters. biscuit-go's GetBlockID searches appended attenuation
// blocks too, and appending needs no root key, so a holder of anyone's token can
// append node(<their own peer id>) offline and satisfy a binding that only tests
// the error. Those facts are invisible to the Datalog authorizer (see
// TestAttenuationBlockFactsAreInvisibleToTheAuthorizer), so this lookup is the
// only place the distinction has to be made by hand.
func RequireAuthorityBinding(b *biscuit.Biscuit, expectedPeer peer.ID) error {
	boundFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(expectedPeer.String())},
	}}
	blockID, err := b.GetBlockID(boundFact)
	if err != nil {
		return fmt.Errorf("token is not bound to peer %s: %w", expectedPeer, err)
	}
	if blockID != authorityBlockID {
		return fmt.Errorf("token is not bound to peer %s: %s fact comes from appended block %d, not the authority block", expectedPeer, api.FactNode, blockID)
	}
	return nil
}

// expirationOf reports the expiration() fact of an already-authorized token.
func expirationOf(authorizer biscuit.Authorizer) (time.Time, error) {
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_exp", IDs: []biscuit.Term{biscuit.Variable("e")}},
		Body: []biscuit.Predicate{{Name: api.FactExpiration, IDs: []biscuit.Term{biscuit.Variable("e")}}},
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("expiration query failed: %w", err)
	}

	// A token may carry several; the earliest is the one that binds.
	var earliest time.Time
	for _, fact := range facts {
		if len(fact.IDs) != 1 {
			continue
		}
		date, ok := fact.IDs[0].(biscuit.Date)
		if !ok {
			continue
		}
		if t := time.Time(date); earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return time.Time{}, fmt.Errorf("no %s fact in token", api.FactExpiration)
	}
	return earliest, nil
}

// MintBiscuitToken generates a signed Biscuit token for a peer with policy rules based on JWT claims.
// labels are control-plane-attested key=value claims (canonical, pre-validated); empty means no claims.
func MintBiscuitToken(signingKey ed25519.PrivateKey, claims jwt.MapClaims, token *oidc.IDToken, remotePeer peer.ID, biscuitExpiry time.Time, roles []string, policyRoles []*api.PolicyRole, labels map[string]string) ([]byte, []string, error) {
	if claims == nil {
		return nil, nil, fmt.Errorf("claims cannot be nil")
	}

	biscuitBytes, err := mintBiscuit(signingKey, remotePeer, roles, biscuitExpiry, claims, policyRoles, labels)
	if err != nil {
		return nil, nil, err
	}
	return biscuitBytes, roles, nil
}

func mintBiscuit(signingKey ed25519.PrivateKey, remotePeer peer.ID, roles []string, expiration time.Time, claims jwt.MapClaims, policyRoles []*api.PolicyRole, labels map[string]string) ([]byte, error) {
	builder := biscuit.NewBuilder(signingKey)
	addedFacts := make(map[string]bool)
	addFact := func(fact biscuit.Fact) error {
		factStr := fact.String()
		if addedFacts[factStr] {
			return nil
		}
		if err := builder.AddAuthorityFact(fact); err != nil {
			return err
		}
		addedFacts[factStr] = true
		return nil
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactExpiration,
		IDs:  []biscuit.Term{biscuit.Date(expiration)},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add expiration fact: %w", err)
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactNode,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add node fact: %w", err)
	}

	if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: api.FactClientPeerID,
		IDs:  []biscuit.Term{biscuit.String(remotePeer.String())},
	}}); err != nil {
		return nil, fmt.Errorf("failed to add client_peer_id fact: %w", err)
	}

	// One signed fact per declared label so a requirement is a single exact
	// match (see api.FactLabel).
	for _, fact := range api.LabelFacts(labels) {
		if err := addFact(fact); err != nil {
			return nil, fmt.Errorf("failed to add label fact: %w", err)
		}
	}

	if claims != nil {
		if err := translateClaimsToFacts(addFact, claims); err != nil {
			return nil, err
		}
	}

	rolesMap := make(map[string]*api.PolicyRole)
	for _, pr := range policyRoles {
		if pr != nil {
			rolesMap[pr.Name] = pr
		}
	}

	sort.Strings(roles)
	var errs []error
	// Collected across every matched role and merged into Set facts once below: a token's
	// authorization is the union of its resolved roles' grants, so exact entries don't need to
	// stay siloed per role, and merging keeps fact counts flat regardless of how many roles match.
	var allServices []string
	var allTargets []string
	// Narrowed grants (PolicyRole.http) are minted per entry: they are keyed
	// by the entry they narrow, so there is nothing to merge across roles.
	var allHTTP []*api.HTTPGrant
	for _, role := range roles {
		if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
			Name: api.FactRole,
			IDs:  []biscuit.Term{biscuit.String(role)},
		}}); err != nil {
			errs = append(errs, fmt.Errorf("failed to add role fact for %s: %w", role, err))
			continue
		}

		if role == api.RoleRouter {
			if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: api.FactRight,
				IDs:  []biscuit.Term{biscuit.String(api.RightRelay)},
			}}); err != nil {
				errs = append(errs, fmt.Errorf("failed to add relay right: %w", err))
			}
			if err := addFact(api.MarkerFact(api.FactTargetUnrestricted)); err != nil {
				errs = append(errs, fmt.Errorf("failed to add target unrestricted: %w", err))
			}
			continue
		}

		if pr, ok := rolesMap[role]; ok {
			plainServices, narrowed := api.SplitHTTPGrants(pr)
			allServices = append(allServices, plainServices...)
			allHTTP = append(allHTTP, narrowed...)
			allTargets = append(allTargets, pr.AllowedTargets...)

			for _, customEntry := range pr.CustomDatalog {
				trimmed := strings.TrimRight(strings.TrimSpace(customEntry), ";")
				if trimmed == "" {
					continue
				}
				fact, err := parser.FromStringFact(trimmed)
				if err != nil {
					// custom_datalog holds facts and rules alike. A rule is
					// node-side material, distributed to nodes and applied by
					// their authorizer, and cannot be an authority fact — so
					// skip it here rather than fail the token and lock every
					// node resolving to this role out of enroll and refresh.
					if _, ruleErr := parser.FromStringRule(trimmed); ruleErr == nil {
						continue
					}
					errs = append(errs, fmt.Errorf("failed to parse custom Datalog entry %q for role %s as a fact or a rule: %w", customEntry, role, err))
				} else if err := addFact(fact); err != nil {
					errs = append(errs, fmt.Errorf("failed to add custom Datalog fact %q for role %s: %w", customEntry, role, err))
				}
			}
		}
	}

	for _, fact := range api.BuildServiceDatalogFacts(allServices) {
		if err := addFact(fact); err != nil {
			errs = append(errs, fmt.Errorf("failed to add service fact: %w", err))
		}
	}
	for _, g := range allHTTP {
		for _, fact := range api.BuildHTTPGrantFacts(g) {
			if err := addFact(fact); err != nil {
				errs = append(errs, fmt.Errorf("failed to add http grant fact: %w", err))
			}
		}
	}
	for _, fact := range api.BuildTargetDatalogFacts(allTargets) {
		if err := addFact(fact); err != nil {
			errs = append(errs, fmt.Errorf("failed to add target fact: %w", err))
		}
	}

	// No policy means no grants. A mesh with no roles defined used to mint
	// every non-router an unrestricted token; a fresh control plane, or one
	// whose policy was wiped, was the most permissive configuration there
	// is. Deny by default: the operator posts a policy, then nodes can talk.

	if len(errs) > 0 {
		return nil, fmt.Errorf("biscuit policy validation failed: %w", errors.Join(errs...))
	}

	t, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build biscuit: %w", err)
	}

	bBytes, err := t.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize biscuit: %w", err)
	}

	return bBytes, nil
}

// VerifyBiscuit verifies the validity of a Biscuit token.
// It ensures that:
// 1. The token is cryptographically signed by one of the trustedPublicKeys.
// 2. The token is not expired.
// 3. The token is securely bound to the expected remotePeer.
func VerifyBiscuit(biscuitData []byte, expectedPeer peer.ID, trustedPublicKeys []ed25519.PublicKey, timeout time.Duration) (*biscuit.Biscuit, error) {
	b, _, _, err := verifyBiscuit(biscuitData, expectedPeer, trustedPublicKeys, timeout)
	return b, err
}

// VerifyBiscuitAndGetKey is VerifyBiscuit that also reports which trusted key
// verified the token, for callers that go on to evaluate it under that key.
func VerifyBiscuitAndGetKey(biscuitData []byte, expectedPeer peer.ID, trustedPublicKeys []ed25519.PublicKey, timeout time.Duration) (*biscuit.Biscuit, ed25519.PublicKey, error) {
	b, key, _, err := verifyBiscuit(biscuitData, expectedPeer, trustedPublicKeys, timeout)
	return b, key, err
}

// VerifyBiscuitAndGetExpiry is VerifyBiscuit that also reports when the token
// lapses, for callers that cache the admission and must drop it on time.
func VerifyBiscuitAndGetExpiry(biscuitData []byte, expectedPeer peer.ID, trustedPublicKeys []ed25519.PublicKey, timeout time.Duration) (time.Time, error) {
	_, _, expiry, err := verifyBiscuit(biscuitData, expectedPeer, trustedPublicKeys, timeout)
	return expiry, err
}

func verifyBiscuit(biscuitData []byte, expectedPeer peer.ID, trustedPublicKeys []ed25519.PublicKey, timeout time.Duration) (*biscuit.Biscuit, ed25519.PublicKey, time.Time, error) {
	b, err := UnmarshalInbound(biscuitData)
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	authOpts := AuthorizerOptions(timeout)

	var lastErr error
	var authorizer biscuit.Authorizer
	var verifyingKey ed25519.PublicKey
	for _, pubKey := range trustedPublicKeys {
		candidate, err := b.Authorizer(pubKey, authOpts...)
		if err != nil {
			lastErr = err
			continue
		}

		EnforceExpiration(candidate)
		candidate.AddPolicy(api.AllowIfTruePolicy)

		if err := candidate.Authorize(); err == nil {
			authorizer = candidate
			verifyingKey = pubKey
			break
		} else {
			lastErr = err
		}
	}

	if authorizer == nil {
		return nil, nil, time.Time{}, fmt.Errorf("no valid key found for verification: %v", lastErr)
	}

	if err := RequireAuthorityBinding(b, expectedPeer); err != nil {
		return nil, nil, time.Time{}, err
	}

	// EnforceExpiration already passed, so the fact is there; a failure here is
	// a query error, and fails closed rather than caching an admission forever.
	expiry, err := expirationOf(authorizer)
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	return b, verifyingKey, expiry, nil
}

func translateClaimsToFacts(addFact func(biscuit.Fact) error, claims map[string]any) error {
	claimMap := api.OIDCClaimToFact()
	keys := make([]string, 0, len(claimMap))
	for k := range claimMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, claimKey := range keys {
		factName := claimMap[claimKey]
		val, ok := claims[claimKey]
		if !ok || val == nil {
			continue
		}
		// Every claim is treated as a list; a scalar is a list of one. Special
		// casing which facts are multi-valued would mean a claim added to the
		// map but not to that list is silently dropped at mint time.
		seen := make(map[string]bool)
		for _, item := range toStringSlice(val) {
			if seen[item] {
				continue
			}
			seen[item] = true
			if err := addFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: factName,
				IDs:  []biscuit.Term{biscuit.String(item)},
			}}); err != nil {
				return fmt.Errorf("failed to add %s fact: %w", factName, err)
			}
		}
	}
	return nil
}

func toStringSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []string:
		return v
	case []any:
		var res []string
		for _, item := range v {
			if str, ok := item.(string); ok && str != "" {
				res = append(res, str)
			}
		}
		return res
	}
	return nil
}

// MintBootstrapBiscuitToken generates a signed Biscuit token for a peer using a bootstrap role.
// labels are control-plane-attested key=value claims (canonical, pre-validated); empty means no claims.
func MintBootstrapBiscuitToken(signingKey ed25519.PrivateKey, remotePeer peer.ID, role string, expiration time.Time, policyRoles []*api.PolicyRole, labels map[string]string) ([]byte, error) {
	return mintBiscuit(signingKey, remotePeer, []string{role}, expiration, nil, policyRoles, labels)
}

// VerifyExpiredAndExtractPeerID checks that the biscuit is signed by one of the
// trusted keys and returns the peer ID, deliberately WITHOUT enforcing expiry.
// Only the refresh flow may use it: a node refreshes precisely because its token
// lapsed, so it has nothing unexpired to present. Callers must bound the request
// some other way (the refresh handler gates on the session record and a signed
// challenge). Everywhere else, use VerifyAndExtractPeerID.
func VerifyExpiredAndExtractPeerID(trustedPublicKeys []ed25519.PublicKey, biscuitData []byte, timeout time.Duration) (peer.ID, error) {
	return extractPeerID(trustedPublicKeys, biscuitData, timeout, false)
}

// VerifyAndExtractPeerID checks that the biscuit is signed by one of the trusted
// keys and is unexpired, and returns the peer ID.
func VerifyAndExtractPeerID(trustedPublicKeys []ed25519.PublicKey, biscuitData []byte, timeout time.Duration) (peer.ID, error) {
	return extractPeerID(trustedPublicKeys, biscuitData, timeout, true)
}

func extractPeerID(trustedPublicKeys []ed25519.PublicKey, biscuitData []byte, timeout time.Duration, enforceExpiry bool) (peer.ID, error) {
	b, err := UnmarshalInbound(biscuitData)
	if err != nil {
		return "", err
	}

	authOpts := AuthorizerOptions(timeout)

	var authorizer biscuit.Authorizer
	var verified bool
	var lastErr error

	for _, pubKey := range trustedPublicKeys {
		auth, err := b.Authorizer(pubKey, authOpts...)
		if err != nil {
			lastErr = err
			continue
		}
		if enforceExpiry {
			EnforceExpiration(auth)
		}
		// No policy is added, so a token that passes every check still reports
		// ErrNoMatchingPolicy; that is success here. A failed check reports the
		// check error instead, so expiry still rejects.
		if err := auth.Authorize(); err == nil || errors.Is(err, biscuit.ErrNoMatchingPolicy) {
			authorizer = auth
			verified = true
			break
		} else {
			lastErr = err
		}
	}

	if !verified {
		return "", fmt.Errorf("signature verification failed: %v", lastErr)
	}

	// Extract the peer ID using Datalog query
	facts, err := authorizer.Query(biscuit.Rule{
		Head: biscuit.Predicate{Name: "get_peer", IDs: []biscuit.Term{biscuit.Variable("p")}},
		Body: []biscuit.Predicate{{Name: api.FactNode, IDs: []biscuit.Term{biscuit.Variable("p")}}},
	})
	if err != nil {
		return "", fmt.Errorf("query failed: %w", err)
	}

	if len(facts) == 0 {
		return "", fmt.Errorf("no %s fact found in biscuit. Authorizer state: %s", api.FactNode, authorizer.PrintWorld())
	}

	// Extract value from fact
	pred := facts[0].Predicate
	if len(pred.IDs) != 1 {
		return "", fmt.Errorf("unexpected fact structure")
	}

	strVal, ok := pred.IDs[0].(biscuit.String)
	if !ok {
		return "", fmt.Errorf("node fact value is not a string")
	}

	pID, err := peer.Decode(string(strVal))
	if err != nil {
		return "", fmt.Errorf("invalid peer ID in biscuit: %w", err)
	}

	return pID, nil
}

// VerifyBiscuitRole checks that the biscuit is signed by the control plane's public key
// and contains the specified role fact. It deliberately does NOT enforce expiry: its
// callers either hold a token the control plane minted moments ago, or are deciding
// whether an identity loaded from disk is worth starting with, where a lapsed token
// should trigger a refresh rather than refuse to boot. Do not use it to admit a token
// received from a peer.
func VerifyBiscuitRole(biscuitData []byte, controlPlanePubKey ed25519.PublicKey, expectedRole string, timeout time.Duration) error {
	b, err := UnmarshalInbound(biscuitData)
	if err != nil {
		return err
	}
	return RequireRole(b, controlPlanePubKey, expectedRole, timeout)
}

// RequireRole checks that the token carries role(expectedRole) under the given
// key. It checks nothing else: a token received from a peer must already have
// passed VerifyBiscuitAndGetKey, which is where expiry and the peer binding are
// enforced, and key must be the key that verified it.
func RequireRole(b *biscuit.Biscuit, key ed25519.PublicKey, expectedRole string, timeout time.Duration) error {
	authorizer, err := b.Authorizer(key, AuthorizerOptions(timeout)...)
	if err != nil {
		return fmt.Errorf("failed to create authorizer: %w", err)
	}

	authorizer.AddCheck(biscuit.Check{Queries: []biscuit.Rule{
		{
			Body: []biscuit.Predicate{
				{Name: api.FactRole, IDs: []biscuit.Term{biscuit.String(expectedRole)}},
			},
		},
	}})
	authorizer.AddPolicy(api.AllowIfTruePolicy)

	if err := authorizer.Authorize(); err != nil {
		return fmt.Errorf("biscuit lacks expected role %q: %w", expectedRole, err)
	}
	return nil
}
