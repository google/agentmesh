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
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/node"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// State directory filenames, matching sdk/js, sdk/python, and
// `agentmesh-node state export|import`.
const (
	StateDirIdentityFile   = node.StateDirIdentityFile
	StateDirCredentialFile = node.StateDirCredentialFile
)

const minResumeLifetime = 5 * time.Minute

// ErrCredentialRetired indicates that the persisted credential's control-plane
// signing key was rotated past its grace period while this member was offline,
// and no join token or TokenSource was supplied to re-enroll.
var ErrCredentialRetired = errors.New("meshnet: saved credential signing key retired; provide a join token to re-enroll")

// WriteStateDir writes a member's libp2p private key and MemberCredential to
// dir with owner-only permissions (0700 directory, 0600 files).
func WriteStateDir(dir string, privKey []byte, c *api.MemberCredential) error {
	return node.WriteStateDir(dir, privKey, c)
}

// ReadStateDir loads a member's libp2p private key and MemberCredential from
// dir, rejecting unknown fields in credential.json.
//
// When MemberCredential.oidc_session is populated (for example from an
// interactive `agentmesh-node join` export), Server uses it to recover expired
// credentials for public OIDC clients (no client_secret is stored in
// MemberCredential) and persists any rotated refresh_token immediately before
// calling POST /register so one-time refresh tokens survive transient failures.
func ReadStateDir(dir string) ([]byte, *api.MemberCredential, error) {
	return node.ReadStateDir(dir)
}

type tokenSourceAdapter struct {
	fn      func(ctx context.Context) (string, error)
	jwtPath string
}

func (a *tokenSourceAdapter) FetchToken(ctx context.Context) (string, error) {
	if a.fn != nil {
		tok, err := a.fn(ctx)
		if err != nil {
			return "", err
		}
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return "", errors.New("meshnet: TokenSource returned an empty token")
		}
		return tok, nil
	}
	if a.jwtPath != "" {
		raw, err := os.ReadFile(a.jwtPath)
		if err != nil {
			return "", fmt.Errorf("meshnet: read JWTPath: %w", err)
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return "", errors.New("meshnet: JWTPath file is empty")
		}
		return tok, nil
	}
	return "", errors.New("meshnet: no platform JWT source configured")
}

func (s *Server) tokenSource() node.TokenSource {
	jwtPath := strings.TrimSpace(s.JWTPath)
	if s.TokenSource == nil && jwtPath == "" {
		return nil
	}
	return &tokenSourceAdapter{
		fn:      s.TokenSource,
		jwtPath: jwtPath,
	}
}

func normalizeControlPlaneURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	return strings.TrimSuffix(raw, "/")
}

type joinSecretKind int

const (
	joinSecretNone joinSecretKind = iota
	joinSecretJWT
	joinSecretBootstrap
)

func (s *Server) resolveJoinSecret(ctx context.Context) (joinSecretKind, string, error) {
	if ts := s.tokenSource(); ts != nil {
		tok, err := ts.FetchToken(ctx)
		if err != nil {
			return joinSecretNone, "", err
		}
		return joinSecretJWT, tok, nil
	}
	if p := strings.TrimSpace(s.BootstrapTokenPath); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return joinSecretNone, "", fmt.Errorf("meshnet: read BootstrapTokenPath: %w", err)
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return joinSecretNone, "", errors.New("meshnet: BootstrapTokenPath file is empty")
		}
		return joinSecretBootstrap, tok, nil
	}
	if tok := strings.TrimSpace(s.BootstrapToken); tok != "" {
		return joinSecretBootstrap, tok, nil
	}
	return joinSecretNone, "", nil
}

func (s *Server) newAgentMeshNode(store *node.Store, privKey crypto.PrivKey) (*node.AgentMeshNode, error) {
	listenAddrs := s.ListenAddrs
	if len(listenAddrs) == 0 {
		listenAddrs = []string{
			"/ip4/0.0.0.0/udp/0/quic-v1",
			"/ip4/0.0.0.0/tcp/0",
			"/ip6/::/udp/0/quic-v1",
			"/ip6/::/tcp/0",
		}
	}
	n, err := node.NewAgentMeshNode(node.Options{
		PrivKey:                   privKey,
		Store:                     store,
		ListenAddrs:               listenAddrs,
		AllowLoopback:             s.AllowInsecure,
		EnableRelay:               false,
		RequiredRole:              api.RoleNode,
		Routers:                   s.Routers,
		RouterSelector:            maps.Clone(s.RouterSelector),
		RouterPrefer:              maps.Clone(s.RouterPrefer),
		BootstrapTokenPath:        strings.TrimSpace(s.BootstrapTokenPath),
		BootstrapToken:            strings.TrimSpace(s.BootstrapToken),
		TokenSource:               s.tokenSource(),
		AllowInsecureControlPlane: s.AllowInsecure,
		DisableFatalExit:          true,
		Registerer:                s.Registerer,
		BiscuitTimeout:            s.biscuitTimeout,
		RenewalInitialBackoff:     s.renewalInitialBackoff,
		RenewalMaxBackoff:         s.renewalMaxBackoff,
		OnCredentialLapse:         s.handleCredentialLapse,
		OnCredentialRenewed:       s.handleCredentialRenewed,
		NodeConfig: &node.NodeConfigComplete{
			Labels:              maps.Clone(s.Labels),
			EgressRequireLabels: maps.Clone(s.EgressRequireLabels),
		},
	})
	if err != nil {
		return nil, err
	}
	n.BoundHTTPAddr = "agentmesh.local"
	return n, nil
}

func (s *Server) openStore() (*node.Store, error) {
	dir := strings.TrimSpace(s.StateDir)
	if dir == "" {
		return node.NewMemoryStore(), nil
	}
	return node.NewStateDirStore(dir)
}

func (s *Server) ensureCredential(ctx context.Context) (retErr error) {
	store, err := s.openStore()
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = store.Close()
			s.store = nil
			s.node = nil
		}
	}()

	privKey, err := node.LoadOrGenerateKey(store)
	if err != nil {
		return err
	}
	peerID, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("derive peer ID: %w", err)
	}
	s.privKey = privKey
	s.peerID = peerID
	s.store = store

	cred, err := store.Credential()
	if err != nil {
		return err
	}

	explicitCP := normalizeControlPlaneURL(s.ControlPlaneURL)
	storedCP := ""
	if cred != nil {
		storedCP = normalizeControlPlaneURL(cred.GetControlPlaneUrl())
	}

	switch {
	case explicitCP != "":
		s.cpURL = explicitCP
	case storedCP != "":
		s.cpURL = storedCP
	default:
		return errors.New("meshnet: ControlPlaneURL is required when no saved credential exists")
	}

	if err := api.ValidateControlPlaneTransport(s.cpURL, s.AllowInsecure); err != nil {
		return err
	}

	// Switching control planes keeps identity.key (PeerID) while replacing the
	// mesh credential; refuse cleanly before touching disk if no join token was
	// supplied for the new mesh.
	var switchKind joinSecretKind
	var switchTok string
	if cred != nil && len(cred.GetBiscuit()) > 0 && storedCP != "" && storedCP != s.cpURL {
		switchKind, switchTok, err = s.resolveJoinSecret(ctx)
		if err != nil {
			return err
		}
		if switchKind == joinSecretNone {
			return fmt.Errorf("meshnet: saved credential belongs to %s, not %s; provide a join token to switch meshes", storedCP, s.cpURL)
		}
		if err := store.SetCredential(&api.MemberCredential{ControlPlaneUrl: s.cpURL}); err != nil {
			return err
		}
		cred = &api.MemberCredential{ControlPlaneUrl: s.cpURL}
	} else if storedCP == "" && cred != nil && len(cred.GetBiscuit()) > 0 {
		if err := store.SaveControlPlaneURL(s.cpURL); err != nil {
			return err
		}
	}

	n, err := s.newAgentMeshNode(store, privKey)
	if err != nil {
		return err
	}
	s.node = n

	if switchKind != joinSecretNone {
		return s.enrollWithSecret(ctx, switchKind, switchTok)
	}

	if cred != nil && len(cred.GetBiscuit()) > 0 {
		keysErr := n.SyncTrustedKeys(ctx, s.cpURL)
		roleOK := n.VerifyOwnBiscuit(cred.GetBiscuit()) == nil
		remaining := time.Until(s.credentialExpireTime())

		if keysErr == nil && roleOK && remaining > minResumeLifetime && !n.IdentityPredatesRotation() {
			s.log().Info("resumed mesh credential from state directory",
				"peer_id", s.peerID.String(),
				"control_plane", s.cpURL,
				"expires_in", remaining.Round(time.Second),
			)
			return nil
		}

		refreshErr := n.RefreshEnrollment(ctx)
		if refreshErr == nil {
			s.log().Info("refreshed mesh credential on startup", "peer_id", s.peerID.String())
			return nil
		}

		// Try OIDC refresh_token recovery if stored in credential.json.
		// ReEnrollWithRefreshToken persists any rotated refresh_token immediately
		// before calling POST /register so one-time refresh tokens are never lost.
		if cred.GetOidcSession().GetRefreshToken() != "" {
			if oidcErr := n.ReEnrollWithRefreshToken(ctx); oidcErr == nil {
				s.log().Info("re-enrolled via saved OIDC session", "peer_id", s.peerID.String())
				return nil
			} else {
				s.log().Warn("re-enrollment via saved OIDC session failed on startup",
					"peer_id", s.peerID.String(),
					"error", oidcErr,
				)
			}
		}

		// Try operator-supplied join token / TokenSource re-enrollment.
		kind, tok, tokErr := s.resolveJoinSecret(ctx)
		if tokErr != nil {
			return tokErr
		}
		if kind != joinSecretNone {
			return s.enrollWithSecret(ctx, kind, tok)
		}

		// If the control plane was unreachable (not a retired key error) and the
		// saved token still verifies locally with time remaining, proceed with
		// cached state so transient hub outages do not break restarts.
		if keysErr != nil && roleOK && remaining > 0 && !isRetiredVerificationError(keysErr) {
			s.log().Warn("control plane unreachable at startup; continuing with cached credential",
				"peer_id", s.peerID.String(),
				"error", keysErr,
				"expires_in", remaining.Round(time.Second),
			)
			return nil
		}
		return fmt.Errorf("%w: refresh failed (%v)", ErrCredentialRetired, refreshErr)
	}

	kind, tok, err := s.resolveJoinSecret(ctx)
	if err != nil {
		return err
	}
	if kind == joinSecretNone {
		return errors.New("meshnet: no saved credential and no join token configured (set TokenSource, JWTPath, BootstrapTokenPath, or BootstrapToken)")
	}
	return s.enrollWithSecret(ctx, kind, tok)
}

func (s *Server) enrollWithSecret(ctx context.Context, kind joinSecretKind, secret string) error {
	switch kind {
	case joinSecretJWT:
		_, err := s.node.EnrollJWTCredential(ctx, s.cpURL, secret)
		return err
	case joinSecretBootstrap:
		_, err := s.node.EnrollBootstrapCredential(ctx, s.cpURL, secret, false)
		return err
	default:
		return errors.New("meshnet: unknown join secret kind")
	}
}

func isRetiredVerificationError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "/keys response rejected")
}

// Refresh proactively exchanges the Server's current Biscuit for a fresh one at
// POST /refresh (attaching a fresh platform JWT when TokenSource or JWTPath is
// configured), verifies the returned credential, persists it to StateDir, and
// re-authenticates attached router sessions.
func (s *Server) Refresh(ctx context.Context) error {
	if s.node == nil {
		return errors.New("meshnet: Server is not running (call Up first)")
	}
	return s.node.RefreshEnrollment(ctx)
}

func (s *Server) credentialExpireTime() time.Time {
	if s.store == nil {
		return time.Time{}
	}
	expUnix, err := s.store.LoadIdentityExpiration()
	if err != nil || expUnix <= 0 {
		return time.Time{}
	}
	return time.Unix(expUnix, 0)
}
