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

package storage

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/google/agentmesh/api"
)

var (
	ErrNotFound = errors.New("not found")

	// ErrNodeBanned and ErrNodeSessionExpired are the two ways an enrolled node
	// stops being servable. See EnrolledNode.CheckAdmission.
	ErrNodeBanned         = errors.New("node is banned")
	ErrNodeSessionExpired = errors.New("node session expired")

	// ErrBootstrapTokenUnusable is returned by ConsumeBootstrapTokenUsage when
	// the token is expired, revoked or has no usages left. One error for the
	// three so a caller cannot tell them apart after the fact and race one.
	ErrBootstrapTokenUnusable = errors.New("bootstrap token is expired, revoked or exhausted")

	// ErrEnrollmentAlreadyResolved is returned by ResolveEnrollmentRequest
	// when the request is no longer pending: someone else approved or
	// rejected it first.
	ErrEnrollmentAlreadyResolved = errors.New("enrollment request is already resolved")
)

// KeyPair holds cryptographic key information.
type KeyPair struct {
	Private    ed25519.PrivateKey
	Public     ed25519.PublicKey
	Expiration time.Time
}

// OIDCKeyPair holds an ES256 (P-256) key pair for outbound OIDC/STS JWT signing.
type OIDCKeyPair struct {
	Kid        string
	PrivateKey []byte
	PublicKey  []byte
	Expiration time.Time
}

// RouterLease represents a router registered with the control plane.
type RouterLease struct {
	PeerID         string
	Addresses      []string
	LastRenewal    time.Time
	ExpiresAt      time.Time
	ConnectedPeers []string
	DHTSize        int
	// The router's load as of this lease: open inbound connections and the
	// number it accepts. Listed on /info for members to choose routers by.
	Connections     int
	ConnectionLimit int
}

// User represents a human identity in the mesh.
type User struct {
	// ID is the OIDC subject. Issuer is the OIDC issuer it came from: the
	// pair is what an identity ban is keyed on (see SetIdentityBanned), and
	// two issuers may hand out the same subject to different people.
	ID        string
	Issuer    string
	Email     string
	Role      string
	CreatedAt time.Time
}

// IdentityKey is the "issuer|subject" form identity bans are keyed on.
func (u *User) IdentityKey() string {
	return u.Issuer + "|" + u.ID
}

// EnrolledNode represents a node enrolled in the mesh.
type EnrolledNode struct {
	PeerID         string
	PublicKey      []byte
	Biscuit        []byte
	Role           string
	EnrollmentType string
	ClaimsJSON     string
	OwnerID        string
	// Labels are the attested key=value claims minted into the node's
	// biscuit; kept on the record so token refreshes re-mint them unchanged.
	Labels     map[string]string
	EnrolledAt time.Time
	ExpiresAt  time.Time
	Banned     bool
	// AutonomousRecovery lets /refresh re-issue this node's biscuit after the
	// key that signed it has been retired, on proof of possession alone. Off
	// by default: without it a bootstrap node offline past the key grace
	// period needs an operator to mint a new token, which is what stops a
	// forgotten or stolen machine from rejoining on its own. Only ever set
	// server-side, from the token that enrolled the node or by an admin.
	AutonomousRecovery bool
}

// NodeState is what CheckAdmission says of a node at some instant. "admitted"
// is not liveness: a node that enrolled once and went away stays admitted
// until its session expires.
type NodeState string

const (
	NodeAdmitted NodeState = "admitted"
	NodeExpired  NodeState = "expired"
	NodeBanned   NodeState = "banned"
)

// NodeFilter selects what ListNodes returns; the zero value is every node.
type NodeFilter struct {
	// States keeps the nodes in any of these states at Now, time.Now() if zero.
	States []NodeState
	Now    time.Time
	// OwnerID nil means every owner; any other value, even "", keeps only
	// that owner's nodes.
	OwnerID *string
	Role    string
	// After resumes from the last row of the previous page. Limit 0 is no limit.
	After *NodeCursor
	Limit int
}

// NodeCursor is the sort key of the last row of a ListNodes page.
type NodeCursor struct {
	EnrolledAt time.Time
	PeerID     string
}

// NodeCount is how many nodes of one role are in one state.
type NodeCount struct {
	Role  string
	State NodeState
	Count int
}

// CheckAdmission reports whether the control plane may still serve this node.
// Enrollment is bounded by two independent conditions, an explicit ban and the
// end of the OIDC session, and every path that acts on an enrolled node has to
// apply both: checking only Banned lets a node whose session lapsed keep
// reading mesh state until someone bans it by hand.
func (n *EnrolledNode) CheckAdmission(now time.Time) error {
	if n.Banned {
		return ErrNodeBanned
	}
	if !n.ExpiresAt.IsZero() && now.After(n.ExpiresAt) {
		return ErrNodeSessionExpired
	}
	return nil
}

// BootstrapToken represents a pre-shared token for node enrollment.
type BootstrapToken struct {
	ID          string
	TokenHash   string
	Role        string
	OwnerID     string
	MaxUsages   int
	UsagesCount int
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	// RevokedAt is set by RevokeBootstrapToken - a soft revoke, distinct from
	// natural expiry, since enrollment_requests.token_id has a foreign key
	// into this table and a hard delete would break that trail. Nil means
	// never revoked.
	RevokedAt *time.Time
	// AutonomousRecovery is copied onto every node this token enrolls; see
	// EnrolledNode.AutonomousRecovery.
	AutonomousRecovery bool
}

// IsRevoked reports whether the token has been explicitly revoked, as
// opposed to merely expired or usage-exhausted.
func (t *BootstrapToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// EnrollmentRequest represents a pending or resolved node registration request (CSR).
type EnrollmentRequest struct {
	ID        string
	PeerID    string
	PublicKey []byte
	TokenID   string
	Status    api.EnrollmentStatus
	// Labels are the operator-declared key=value claims, surfaced to the
	// approving admin; approval attests them into the minted biscuit.
	Labels       map[string]string
	BiscuitToken []byte
	CreatedAt    time.Time
	ResolvedAt   *time.Time
	ResolvedBy   string
}

// Store defines the persistent operations for the Agent Mesh control plane.
type Store interface {
	// Ping checks the health of the underlying database connection.
	Ping(ctx context.Context) error

	// GetCurrentKey retrieves the active key pair for biscuit signing.
	GetCurrentKey(ctx context.Context) (ed25519.PrivateKey, ed25519.PublicKey, error)

	// GetAllValidKeys retrieves the active key pair and any non-expired historical key pairs.
	GetAllValidKeys(ctx context.Context) ([]KeyPair, error)

	// GetAllValidPublicKeys is GetAllValidKeys for verifiers: the same key
	// set without the private halves.
	GetAllValidPublicKeys(ctx context.Context) ([]ed25519.PublicKey, error)

	// RotateKeys rotates the current key to a new key pair and sets the expiration of the old key.
	RotateKeys(ctx context.Context, newPriv ed25519.PrivateKey, newPub ed25519.PublicKey, gracePeriod time.Duration) error

	// ClaimKeyRotation atomically claims the next scheduled key-rotation
	// window, so multiple control-plane replicas sharing one database rotate
	// keys exactly once per interval instead of racing independently. It
	// returns true if the caller won the claim (advancing the deadline by
	// interval), false if another replica already claimed this window.
	ClaimKeyRotation(ctx context.Context, now time.Time, interval time.Duration) (bool, error)

	// ReleaseKeyRotationClaim reverts a claim won via ClaimKeyRotation with
	// the same now/interval back to its pre-claim deadline, so the window
	// can be retried without waiting a full interval. Callers use this when
	// the rotation that followed a successful claim failed.
	ReleaseKeyRotationClaim(ctx context.Context, now time.Time, interval time.Duration) error

	// SaveInitialKey sets the initial key pair if no keys exist yet.
	SaveInitialKey(ctx context.Context, priv ed25519.PrivateKey, pub ed25519.PublicKey) error

	// SaveUser creates or updates a User.
	SaveUser(ctx context.Context, user *User) error

	// GetUser retrieves a User by ID.
	GetUser(ctx context.Context, id string) (*User, error)

	// ListUsers retrieves all registered users.
	ListUsers(ctx context.Context) ([]User, error)

	// EnrollNode registers or updates a node enrollment.
	EnrollNode(ctx context.Context, node *EnrolledNode) error

	// GetNode retrieves node enrollment details.
	GetNode(ctx context.Context, peerID string) (*EnrolledNode, error)

	// SetNodeBanned updates the banned status of a node. ErrNotFound if no
	// node has that peer ID.
	SetNodeBanned(ctx context.Context, peerID string, banned bool) error

	// IsNodeBanned checks if a node is currently banned.
	IsNodeBanned(ctx context.Context, peerID string) (bool, error)

	// SetNodeAutonomousRecovery toggles EnrolledNode.AutonomousRecovery.
	// Returns ErrNotFound if no such node is enrolled.
	SetNodeAutonomousRecovery(ctx context.Context, peerID string, enabled bool) error

	// SetIdentityBanned bans or unbans an enrolled OIDC identity, keyed as
	// "issuer|subject". A node ban is keyed on a self-generated peer id, so
	// this is what makes a ban survive keypair regeneration.
	SetIdentityBanned(ctx context.Context, identity string, banned bool) error

	// SetNodeAndIdentityBanned is SetNodeBanned and SetIdentityBanned in one
	// transaction, so a failure cannot leave the device banned while its
	// identity may still enroll a new one, or the other way round. An empty
	// identity bans the node alone.
	SetNodeAndIdentityBanned(ctx context.Context, peerID, identity string, banned bool) error

	// IsIdentityBanned checks if an identity is currently banned.
	IsIdentityBanned(ctx context.Context, identity string) (bool, error)

	// ListBannedPeerIDs returns the peer IDs of every currently banned node.
	// Callers publish this as the complete ban set (see
	// ControlPlaneInfoResponse.banned_peer_ids), so it must be the whole list
	// rather than a page of it.
	ListBannedPeerIDs(ctx context.Context) ([]string, error)

	// UpsertRouterLease updates or creates a lease for a agentmesh-router.
	UpsertRouterLease(ctx context.Context, lease *RouterLease) error

	// GetActiveRouters retrieves all routers whose leases are still valid.
	GetActiveRouters(ctx context.Context) ([]RouterLease, error)

	// SaveMeshPolicy persists the mesh configurations.
	SaveMeshPolicy(ctx context.Context, roles []*api.PolicyRole, bindings []*api.PolicyBinding) error

	// GetMeshPolicy loads the mesh configurations.
	GetMeshPolicy(ctx context.Context) ([]*api.PolicyRole, []*api.PolicyBinding, error)

	// SaveEgressDestinations replaces the egress section of the mesh policy
	// (PolicyConfig.egress).
	SaveEgressDestinations(ctx context.Context, egress []*api.EgressDestination) error

	// GetEgressDestinations loads the egress section of the mesh policy.
	GetEgressDestinations(ctx context.Context) ([]*api.EgressDestination, error)

	// SavePolicyDocument replaces roles, bindings and egress destinations in
	// one transaction: a policy post is applied whole or not at all.
	SavePolicyDocument(ctx context.Context, roles []*api.PolicyRole, bindings []*api.PolicyBinding, egress []*api.EgressDestination) error

	// SaveBootstrapToken persists a new bootstrap token.
	SaveBootstrapToken(ctx context.Context, token *BootstrapToken) error

	// GetBootstrapToken retrieves a bootstrap token by its ID (sha256 hash).
	GetBootstrapToken(ctx context.Context, id string) (*BootstrapToken, error)

	// ConsumeBootstrapTokenUsage spends one usage of a token, atomically
	// with the check that a usage is left and that the token is neither
	// expired (as of now) nor revoked. ErrBootstrapTokenUnusable when it is
	// not: a read-then-increment would let concurrent enrollments overshoot
	// max_usages.
	ConsumeBootstrapTokenUsage(ctx context.Context, id string, now time.Time) error

	// RevokeBootstrapToken soft-revokes a token by setting its RevokedAt, so
	// HandleEnroll refuses it even though it may still be within its TTL and
	// usage count. Idempotent: revoking an already-revoked or unknown token
	// is not an error - callers that need to distinguish "unknown" first
	// look the token up with GetBootstrapToken.
	RevokeBootstrapToken(ctx context.Context, id string) error

	// CreateEnrollmentRequest saves a new pending enrollment request.
	CreateEnrollmentRequest(ctx context.Context, req *EnrollmentRequest) error

	// GetEnrollmentRequest retrieves an enrollment request by PeerID.
	GetEnrollmentRequest(ctx context.Context, peerID string) (*EnrollmentRequest, error)

	// GetEnrollmentRequestByID retrieves an enrollment request by ID.
	GetEnrollmentRequestByID(ctx context.Context, id string) (*EnrollmentRequest, error)

	// ListEnrollmentRequests retrieves all enrollment requests.
	ListEnrollmentRequests(ctx context.Context) ([]EnrollmentRequest, error)

	// UpdateEnrollmentRequest updates status, resolved details, and stored Biscuit of a request.
	UpdateEnrollmentRequest(ctx context.Context, id string, status api.EnrollmentStatus, biscuit []byte, resolvedBy string) error

	// ResolveEnrollmentRequest is UpdateEnrollmentRequest for a request that
	// must still be pending: two admins acting on the same request cannot
	// both succeed. ErrEnrollmentAlreadyResolved if it was not pending.
	ResolveEnrollmentRequest(ctx context.Context, id string, status api.EnrollmentStatus, biscuit []byte, resolvedBy string) error

	// ListNodes retrieves the enrolled nodes the filter selects, newest
	// enrollment first. Peer ID breaks ties, so pages neither skip nor repeat a row.
	ListNodes(ctx context.Context, filter NodeFilter) ([]EnrolledNode, error)

	// CountNodes counts every enrolled node by role and by its state at now.
	CountNodes(ctx context.Context, now time.Time) ([]NodeCount, error)

	// DeleteExpiredNodes removes enrolled nodes whose session expired before
	// the given time and that are not banned, returning how many went. A
	// lapsed session already refuses every refresh, so the row only records
	// that the node once existed; a ban, by contrast, is the row, and must
	// outlive the session it was placed on. Nodes with no session bound
	// (zero ExpiresAt) are never removed.
	DeleteExpiredNodes(ctx context.Context, before time.Time) (int64, error)

	// ListBootstrapTokens retrieves all bootstrap tokens.
	ListBootstrapTokens(ctx context.Context) ([]BootstrapToken, error)

	// GetCurrentOIDCKey retrieves the active ES256 key pair for OIDC/STS JWT signing.
	GetCurrentOIDCKey(ctx context.Context) (*OIDCKeyPair, error)

	// GetAllValidOIDCKeys retrieves the active ES256 key pair and any non-expired historical key pairs.
	GetAllValidOIDCKeys(ctx context.Context) ([]OIDCKeyPair, error)

	// SaveInitialOIDCKey saves the initial ES256 key pair if no OIDC keys exist yet.
	SaveInitialOIDCKey(ctx context.Context, kid string, priv, pub []byte) error

	// RotateOIDCKeys rotates the current ES256 key to a new key pair and sets the expiration of the old key.
	RotateOIDCKeys(ctx context.Context, kid string, newPriv, newPub []byte, gracePeriod time.Duration) error

	// SaveRevokedBiscuit persists a Biscuit revocation ID until its expiration time.
	SaveRevokedBiscuit(ctx context.Context, revocationID string, expiresAt time.Time) error

	// ListRevokedBiscuits returns all unexpired Biscuit revocation IDs as of now and prunes expired rows.
	ListRevokedBiscuits(ctx context.Context, now time.Time) (map[string]time.Time, error)

	// IsBiscuitRevoked checks if the given base64url-encoded revocation ID is currently revoked.
	IsBiscuitRevoked(ctx context.Context, revocationID string, now time.Time) (bool, error)

	// Close closes the underlying database connection.
	Close() error
}
