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
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/node"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/encoding/protojson"
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
	if c == nil {
		c = &api.MemberCredential{}
	}
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

func parseRouterMultiaddrs(rawAddrs []string) []multiaddr.Multiaddr {
	var out []multiaddr.Multiaddr
	for _, raw := range rawAddrs {
		if ma, err := multiaddr.NewMultiaddr(raw); err == nil {
			out = append(out, ma)
		}
	}
	return out
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
	var routerAddrs []multiaddr.Multiaddr
	if store != nil {
		if _, stored, err := store.LoadMeshConfig(); err == nil && len(stored) > 0 {
			routerAddrs = parseRouterMultiaddrs(stored)
		}
	}
	n, err := node.NewAgentMeshNode(node.Options{
		PrivKey:                   privKey,
		Store:                     store,
		ListenAddrs:               listenAddrs,
		RouterAddrs:               routerAddrs,
		AllowLoopback:             s.AllowInsecure,
		EnableRelay:               false,
		RequiredRole:              api.RoleNode,
		Routers:                   s.Routers,
		RouterSelector:            maps.Clone(s.RouterSelector),
		RouterPrefer:              maps.Clone(s.RouterPrefer),
		BootstrapTokenPath:        strings.TrimSpace(s.BootstrapTokenPath),
		TokenSource:               s.tokenSource(),
		AllowInsecureControlPlane: s.AllowInsecure,
		DisableFatalExit:          true,
		OnStreamRefused:           s.onStreamRefused,
		BiscuitTimeout:            s.biscuitTimeout,
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
	tmpDir, err := os.MkdirTemp("", "meshnet-store-*")
	if err != nil {
		return nil, fmt.Errorf("create store workspace: %w", err)
	}
	store, err := node.NewStore(tmpDir)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	cleanupOnErr := func(e error) (*node.Store, error) {
		_ = store.Close()
		_ = os.RemoveAll(tmpDir)
		return nil, e
	}

	dir := strings.TrimSpace(s.StateDir)
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return cleanupOnErr(fmt.Errorf("create state directory %s: %w", dir, err))
		}
		keyPath := filepath.Join(dir, StateDirIdentityFile)
		if rawKey, rErr := os.ReadFile(keyPath); rErr == nil {
			if _, uErr := crypto.UnmarshalPrivateKey(rawKey); uErr != nil {
				return cleanupOnErr(fmt.Errorf("%s: not a libp2p private key: %w", keyPath, uErr))
			}
			if sErr := store.SaveKey(rawKey); sErr != nil {
				return cleanupOnErr(sErr)
			}
		} else if !errors.Is(rErr, os.ErrNotExist) {
			return cleanupOnErr(rErr)
		}

		credPath := filepath.Join(dir, StateDirCredentialFile)
		if rawCred, rErr := os.ReadFile(credPath); rErr == nil {
			cred := &api.MemberCredential{}
			if uErr := protojson.Unmarshal(rawCred, cred); uErr != nil {
				return cleanupOnErr(fmt.Errorf("%s: %w", credPath, uErr))
			}
			if sErr := store.SetCredential(cred); sErr != nil {
				return cleanupOnErr(sErr)
			}
		} else if !errors.Is(rErr, os.ErrNotExist) {
			return cleanupOnErr(rErr)
		}

		var persistMu sync.Mutex
		store.SetOnChange(func() error {
			persistMu.Lock()
			defer persistMu.Unlock()
			kb, lErr := store.LoadKey()
			if lErr != nil {
				return lErr
			}
			if len(kb) == 0 {
				return nil
			}
			c, cErr := store.Credential()
			if cErr != nil {
				return cErr
			}
			return WriteStateDir(dir, kb, c)
		})
	}

	s.storeTmpDir = tmpDir
	return store, nil
}

func (s *Server) verifyOwnBiscuit(raw []byte) bool {
	if s.node == nil || len(raw) == 0 {
		return false
	}
	claims, err := s.node.VerifyLocalBiscuit(raw)
	if err != nil || claims == nil {
		return false
	}
	if err := identity.RequireAuthorityBinding(claims.Biscuit, s.peerID); err != nil {
		return false
	}
	return slices.Contains(claims.Roles, api.RoleNode)
}

func (s *Server) identityPredatesRotation() bool {
	if s.store == nil || s.node == nil || len(s.node.GetIdentity()) == 0 {
		return false
	}
	issuance, err := s.store.LoadIdentityKeySet()
	if err != nil {
		return false
	}
	if len(issuance) == 0 {
		enrollmentKey, _, mErr := s.store.LoadMeshConfig()
		if mErr != nil || len(enrollmentKey) != ed25519.PublicKeySize {
			return false
		}
		issuance = []ed25519.PublicKey{ed25519.PublicKey(enrollmentKey)}
	}
	trusted, err := s.store.LoadTrustedKeys()
	if err != nil {
		return false
	}
	for _, tk := range trusted {
		if !slices.ContainsFunc(issuance, func(k ed25519.PublicKey) bool { return k.Equal(tk.Key) }) {
			return true
		}
	}
	return false
}

func (s *Server) ensureCredential(ctx context.Context) (retErr error) {
	store, err := s.openStore()
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = store.Close()
			s.cleanupStoreTmpDir()
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

	finalize := func() error {
		rebuilt, rErr := s.newAgentMeshNode(store, privKey)
		if rErr != nil {
			return rErr
		}
		s.node = rebuilt
		return nil
	}

	if switchKind != joinSecretNone {
		if err := s.enrollWithSecret(ctx, switchKind, switchTok); err != nil {
			return err
		}
		return finalize()
	}

	if cred != nil && len(cred.GetBiscuit()) > 0 {
		keysErr := n.SyncTrustedKeys(ctx, s.cpURL)
		roleOK := s.verifyOwnBiscuit(cred.GetBiscuit())
		remaining := time.Until(s.credentialExpireTime())

		if keysErr == nil && roleOK && remaining > minResumeLifetime && !s.identityPredatesRotation() {
			s.log().Info("resumed mesh credential from state directory",
				"peer_id", s.peerID.String(),
				"control_plane", s.cpURL,
				"expires_in", remaining.Round(time.Second),
			)
			return finalize()
		}

		refreshErr := n.RefreshEnrollment(ctx)
		if refreshErr == nil {
			s.log().Info("refreshed mesh credential on startup", "peer_id", s.peerID.String())
			return finalize()
		}

		// Try OIDC refresh_token recovery if stored in credential.json.
		// ReEnrollWithRefreshToken persists any rotated refresh_token immediately
		// before calling POST /register so one-time refresh tokens are never lost.
		if cred.GetOidcSession().GetRefreshToken() != "" {
			if oidcErr := n.ReEnrollWithRefreshToken(ctx); oidcErr == nil {
				s.log().Info("re-enrolled via saved OIDC session", "peer_id", s.peerID.String())
				return finalize()
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
			if err := s.enrollWithSecret(ctx, kind, tok); err != nil {
				return err
			}
			return finalize()
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
			return finalize()
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
	if err := s.enrollWithSecret(ctx, kind, tok); err != nil {
		return err
	}
	return finalize()
}

func (s *Server) enrollWithSecret(ctx context.Context, kind joinSecretKind, secret string) error {
	switch kind {
	case joinSecretJWT:
		return s.node.Enroll(ctx, s.cpURL, secret)
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

func (s *Server) startRenewalLoop(ctx context.Context) {
	initBackoff := s.renewalInitialBackoff
	if initBackoff <= 0 {
		initBackoff = 2 * time.Second
	}
	maxBackoff := s.renewalMaxBackoff
	if maxBackoff < initBackoff {
		maxBackoff = max(5*time.Minute, initBackoff)
	}
	go func() {
		var failureBackoff time.Duration
		for {
			renewAfter := node.DefaultRenewalFallback
			if expTime := s.credentialExpireTime(); !expTime.IsZero() {
				duration := time.Until(expTime)
				switch {
				case duration > node.RenewalThreshold:
					renewAfter = duration - node.RenewalBuffer
					if failureBackoff > renewAfter {
						renewAfter = min(failureBackoff, duration/2)
					}
				case duration > 0:
					renewAfter = max(duration/2, initBackoff)
					if failureBackoff > renewAfter {
						renewAfter = min(failureBackoff, max(duration/2, initBackoff))
					}
				case failureBackoff > 0:
					renewAfter = failureBackoff
				default:
					renewAfter = min(time.Second, initBackoff)
				}
			} else if failureBackoff > 0 {
				renewAfter = failureBackoff
			}

			timer := time.NewTimer(renewAfter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				refreshErr := s.node.RefreshEnrollment(ctx)
				if refreshErr == nil {
					failureBackoff = 0
					s.handleCredentialRenewed()
					continue
				}

				renewErr := s.fallbackReEnroll(ctx)
				if renewErr == nil {
					failureBackoff = 0
					s.handleCredentialRenewed()
					continue
				}

				if failureBackoff == 0 {
					failureBackoff = initBackoff
				} else {
					failureBackoff = min(failureBackoff*2, maxBackoff)
				}
				s.log().Warn("credential renewal failed; scheduled backoff retry",
					"peer_id", s.peerID.String(),
					"next_backoff", failureBackoff,
					"refresh_error", refreshErr,
					"reenroll_error", renewErr,
				)

				if exp := s.credentialExpireTime(); !exp.IsZero() && !time.Now().Before(exp) {
					s.handleCredentialLapse(errors.Join(refreshErr, renewErr))
				}
			}
		}
	}()
}

func (s *Server) fallbackReEnroll(ctx context.Context) error {
	var errs []error
	if ts := s.tokenSource(); ts != nil {
		newJWT, fetchErr := ts.FetchToken(ctx)
		if fetchErr != nil {
			errs = append(errs, fetchErr)
		} else if enrollErr := s.node.Enroll(ctx, s.cpURL, newJWT); enrollErr == nil {
			return nil
		} else {
			errs = append(errs, enrollErr)
		}
	}
	if s.store != nil {
		if rt, _ := s.store.LoadRefreshToken(); rt != "" {
			if oidcErr := s.node.ReEnrollWithRefreshToken(ctx); oidcErr == nil {
				return nil
			} else {
				errs = append(errs, oidcErr)
			}
		}
	}
	var bootToken string
	if p := strings.TrimSpace(s.BootstrapTokenPath); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("read BootstrapTokenPath: %w", err))
		} else {
			bootToken = strings.TrimSpace(string(raw))
		}
	} else {
		bootToken = strings.TrimSpace(s.BootstrapToken)
	}
	if bootToken != "" {
		if _, bErr := s.node.EnrollBootstrapCredential(ctx, s.cpURL, bootToken, true); bErr == nil {
			return nil
		} else {
			errs = append(errs, bErr)
		}
	}
	if len(errs) == 0 {
		return errors.New("no token source configured for renewal")
	}
	return errors.Join(errs...)
}

// Refresh proactively exchanges the Server's current Biscuit for a fresh one at
// POST /refresh (attaching a fresh platform JWT when TokenSource or JWTPath is
// configured), verifies the returned credential, persists it to StateDir, and
// re-authenticates attached router sessions.
func (s *Server) Refresh(ctx context.Context) error {
	if s.node == nil {
		return errors.New("meshnet: Server is not running (call Up first)")
	}
	err := s.node.RefreshEnrollment(ctx)
	if err == nil {
		s.credentialLapsed.Store(false)
	}
	return err
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
