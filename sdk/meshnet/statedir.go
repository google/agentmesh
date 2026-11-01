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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	cpclient "github.com/google/agentmesh/internal/controlplane/client"
	"github.com/google/agentmesh/internal/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// State directory filenames, matching sdk/js, sdk/python, and
// `agentmesh-node state export|import`.
const (
	StateDirIdentityFile   = "identity.key"
	StateDirCredentialFile = "credential.json"
)

const (
	minResumeLifetime      = 5 * time.Minute
	renewalThreshold       = 10 * time.Minute
	renewalBuffer          = 5 * time.Minute
	defaultRenewalFallback = 5 * time.Minute
	controlPlaneTimeout    = 30 * time.Second
	defaultPollInterval    = 2 * time.Second
)

// ErrCredentialRetired indicates that the persisted credential's control-plane
// signing key was rotated past its grace period while this member was offline,
// and no join token or TokenSource was supplied to re-enroll.
var ErrCredentialRetired = errors.New("meshnet: saved credential signing key retired; provide a join token to re-enroll")

var stateDirMarshal = protojson.MarshalOptions{UseProtoNames: true, Multiline: true, Indent: "  "}

type trustedKey struct {
	key        ed25519.PublicKey
	receivedAt time.Time
}

// WriteStateDir writes a member's libp2p private key and MemberCredential to
// dir with owner-only permissions (0700 directory, 0600 files).
func WriteStateDir(dir string, privKey []byte, c *api.MemberCredential) error {
	if _, err := crypto.UnmarshalPrivateKey(privKey); err != nil {
		return fmt.Errorf("private key is not a libp2p key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	credential, err := stateDirMarshal.Marshal(c)
	if err != nil {
		return err
	}
	if err := writeOwnerOnly(filepath.Join(dir, StateDirIdentityFile), privKey); err != nil {
		return err
	}
	return writeOwnerOnly(filepath.Join(dir, StateDirCredentialFile), append(credential, '\n'))
}

// ReadStateDir loads a member's libp2p private key and MemberCredential from
// dir, rejecting unknown fields in credential.json.
func ReadStateDir(dir string) ([]byte, *api.MemberCredential, error) {
	privKey, err := os.ReadFile(filepath.Join(dir, StateDirIdentityFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("no identity in %s: %w", dir, err)
		}
		return nil, nil, err
	}
	if _, err := crypto.UnmarshalPrivateKey(privKey); err != nil {
		return nil, nil, fmt.Errorf("%s: not a libp2p private key: %w", filepath.Join(dir, StateDirIdentityFile), err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, StateDirCredentialFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("no credential in %s: %w", dir, err)
		}
		return nil, nil, err
	}
	c := &api.MemberCredential{}
	if err := protojson.Unmarshal(raw, c); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", filepath.Join(dir, StateDirCredentialFile), err)
	}
	return privKey, c, nil
}

func writeOwnerOnly(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

func (s *Server) cpHTTPClient(timeout time.Duration) *http.Client {
	return cpclient.NewHTTPClient(timeout, func() bool { return s.AllowInsecure }, "agentmesh-meshnet")
}

func (s *Server) cpClient() *cpclient.Client {
	c := cpclient.New(s.cpURL, s.cpHTTPClient(controlPlaneTimeout))
	if s.privKey != nil && s.peerID != "" {
		c = c.WithIdentity(s.peerID.String(), s.privKey)
	}
	return c
}

func (s *Server) loadOrCreateIdentity() (*api.MemberCredential, error) {
	if s.StateDir != "" {
		keyPath := filepath.Join(s.StateDir, StateDirIdentityFile)
		keyBytes, err := os.ReadFile(keyPath)
		if err == nil {
			priv, uErr := crypto.UnmarshalPrivateKey(keyBytes)
			if uErr != nil {
				return nil, fmt.Errorf("%s: not a libp2p private key: %w", keyPath, uErr)
			}
			pid, pErr := peer.IDFromPrivateKey(priv)
			if pErr != nil {
				return nil, fmt.Errorf("derive peer ID: %w", pErr)
			}
			s.privKey = priv
			s.privKeyBytes = keyBytes
			s.peerID = pid

			credPath := filepath.Join(s.StateDir, StateDirCredentialFile)
			rawCred, cErr := os.ReadFile(credPath)
			if cErr != nil {
				if errors.Is(cErr, os.ErrNotExist) {
					return nil, nil
				}
				return nil, cErr
			}
			cred := &api.MemberCredential{}
			if err := protojson.Unmarshal(rawCred, cred); err != nil {
				return nil, fmt.Errorf("%s: %w", credPath, err)
			}
			return cred, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 identity: %w", err)
	}
	raw, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("derive peer ID: %w", err)
	}
	s.privKey = priv
	s.privKeyBytes = raw
	s.peerID = pid
	if s.StateDir != "" {
		if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
			return nil, err
		}
		if err := writeOwnerOnly(filepath.Join(s.StateDir, StateDirIdentityFile), raw); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (s *Server) ensureCredential(ctx context.Context) error {
	cred, err := s.loadOrCreateIdentity()
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

	if cred != nil && len(cred.GetBiscuit()) > 0 && (storedCP == "" || storedCP == s.cpURL) {
		s.adoptLoadedCredential(cred)

		keysErr := s.syncTrustedKeys(ctx)
		roleOK := s.verifySavedRole() == nil
		remaining := time.Until(s.credentialExpireTime())

		if keysErr == nil && roleOK && remaining > minResumeLifetime && !s.identityPredatesRotation() {
			s.log().Info("resumed mesh credential from state directory",
				"peer_id", s.peerID.String(),
				"control_plane", s.cpURL,
				"expires_in", remaining.Round(time.Second),
			)
			return nil
		}

		refreshErr := s.Refresh(ctx)
		if refreshErr == nil {
			s.log().Info("refreshed mesh credential on startup", "peer_id", s.peerID.String())
			return nil
		}

		// Try OIDC refresh_token recovery if stored in credential.json.
		if jwtStr, oidcErr := s.renewFromOIDCSession(ctx); oidcErr == nil && jwtStr != "" {
			if regErr := s.enrollJWT(ctx, jwtStr); regErr == nil {
				s.log().Info("re-enrolled via saved OIDC session", "peer_id", s.peerID.String())
				return nil
			}
		}

		// Try operator-supplied join token / TokenSource re-enrollment.
		kind, tok, tokErr := s.resolveJoinSecret(ctx)
		if tokErr != nil {
			return tokErr
		}
		if kind != joinSecretNone {
			return s.enrollWithSecret(ctx, kind, tok, false)
		}

		// If the control plane was unreachable (not a retired key error) and the
		// saved token still verifies locally with time remaining, proceed with
		// cached state so transient hub outages do not break restarts.
		if keysErr != nil && roleOK && remaining > 0 && !isRetiredVerificationError(keysErr) {
			s.log().Warn("control plane unreachable at startup; continuing with cached credential",
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
		if cred != nil && storedCP != "" && storedCP != s.cpURL {
			return fmt.Errorf("meshnet: saved credential belongs to %s, not %s; provide a join token to switch meshes", storedCP, s.cpURL)
		}
		return errors.New("meshnet: no saved credential and no join token configured (set TokenSource, JWTPath, BootstrapTokenPath, or BootstrapToken)")
	}
	return s.enrollWithSecret(ctx, kind, tok, false)
}

func isRetiredVerificationError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "/keys response rejected")
}

func (s *Server) adoptLoadedCredential(c *api.MemberCredential) {
	now := time.Now()
	var tks []trustedKey
	for _, k := range c.GetTrustedKeys() {
		if len(k.GetPublicKey()) != ed25519.PublicKeySize {
			continue
		}
		recv := now
		if k.GetReceiveTime() != nil {
			recv = k.GetReceiveTime().AsTime()
		}
		tks = append(tks, trustedKey{
			key:        ed25519.PublicKey(slices.Clone(k.GetPublicKey())),
			receivedAt: recv,
		})
	}
	var issued []ed25519.PublicKey
	for _, raw := range c.GetIssuedUnderKeys() {
		if len(raw) == ed25519.PublicKeySize {
			issued = append(issued, ed25519.PublicKey(slices.Clone(raw)))
		}
	}

	s.keysMu.Lock()
	s.trustedKeys = tks
	s.issuedUnderKeys = issued
	s.keysMu.Unlock()

	s.credMu.Lock()
	s.biscuit = slices.Clone(c.GetBiscuit())
	if c.GetExpireTime() != nil {
		s.expireTime = c.GetExpireTime().AsTime()
	} else {
		s.expireTime = time.Time{}
	}
	s.storedRouterAddrs = slices.Clone(c.GetRouterAddresses())
	if c.GetOidcSession() != nil {
		s.oidcSession = proto.Clone(c.GetOidcSession()).(*api.OIDCSession)
	}
	s.credMu.Unlock()
}

func (s *Server) persistState() error {
	if s.StateDir == "" {
		return nil
	}
	s.keysMu.RLock()
	protoKeys := make([]*api.TrustedSigningKey, 0, len(s.trustedKeys))
	for _, tk := range s.trustedKeys {
		protoKeys = append(protoKeys, &api.TrustedSigningKey{
			PublicKey:   slices.Clone(tk.key),
			ReceiveTime: timestamppb.New(tk.receivedAt),
		})
	}
	issued := make([][]byte, 0, len(s.issuedUnderKeys))
	for _, k := range s.issuedUnderKeys {
		issued = append(issued, slices.Clone(k))
	}
	s.keysMu.RUnlock()

	s.credMu.RLock()
	biscuitCopy := slices.Clone(s.biscuit)
	exp := s.expireTime
	routerAddrs := slices.Clone(s.storedRouterAddrs)
	var oidcCopy *api.OIDCSession
	if s.oidcSession != nil {
		oidcCopy = proto.Clone(s.oidcSession).(*api.OIDCSession)
	}
	s.credMu.RUnlock()

	var expProto *timestamppb.Timestamp
	if !exp.IsZero() {
		expProto = timestamppb.New(exp)
	}
	cred := &api.MemberCredential{
		ControlPlaneUrl: s.cpURL,
		Biscuit:         biscuitCopy,
		ExpireTime:      expProto,
		TrustedKeys:     protoKeys,
		IssuedUnderKeys: issued,
		RouterAddresses: routerAddrs,
		OidcSession:     oidcCopy,
	}
	return WriteStateDir(s.StateDir, s.privKeyBytes, cred)
}

type joinSecretKind int

const (
	joinSecretNone joinSecretKind = iota
	joinSecretJWT
	joinSecretBootstrap
)

func (s *Server) resolveJoinSecret(ctx context.Context) (joinSecretKind, string, error) {
	if s.TokenSource != nil {
		tok, err := s.TokenSource(ctx)
		if err != nil {
			return joinSecretNone, "", fmt.Errorf("TokenSource: %w", err)
		}
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return joinSecretNone, "", errors.New("TokenSource returned an empty token")
		}
		return joinSecretJWT, tok, nil
	}
	if s.JWTPath != "" {
		raw, err := os.ReadFile(s.JWTPath)
		if err != nil {
			return joinSecretNone, "", fmt.Errorf("read JWTPath %s: %w", s.JWTPath, err)
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return joinSecretNone, "", fmt.Errorf("JWTPath %s is empty", s.JWTPath)
		}
		return joinSecretJWT, tok, nil
	}
	if s.BootstrapTokenPath != "" {
		raw, err := os.ReadFile(s.BootstrapTokenPath)
		if err != nil {
			return joinSecretNone, "", fmt.Errorf("read BootstrapTokenPath %s: %w", s.BootstrapTokenPath, err)
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return joinSecretNone, "", fmt.Errorf("BootstrapTokenPath %s is empty", s.BootstrapTokenPath)
		}
		return joinSecretBootstrap, tok, nil
	}
	if tok := strings.TrimSpace(s.BootstrapToken); tok != "" {
		return joinSecretBootstrap, tok, nil
	}
	return joinSecretNone, "", nil
}

func (s *Server) enrollWithSecret(ctx context.Context, kind joinSecretKind, tok string, trustedOnly bool) error {
	switch kind {
	case joinSecretJWT:
		return s.enrollJWT(ctx, tok)
	case joinSecretBootstrap:
		return s.enrollBootstrap(ctx, tok, trustedOnly)
	default:
		return errors.New("no enrollment secret")
	}
}

func (s *Server) enrollJWT(ctx context.Context, jwtStr string) error {
	pubBytes, err := crypto.MarshalPublicKey(s.privKey.GetPublic())
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	client := s.cpHTTPClient(controlPlaneTimeout)
	regURL := s.cpURL + "/register"

	resp, err := cpclient.DoWithChallengeRetry(ctx, client, time.Now, cpclient.DefaultEnrollBackoff, func(ts int64) (*http.Request, error) {
		sig, err := s.privKey.Sign(api.RegisterChallenge(s.peerID.String(), ts))
		if err != nil {
			return nil, fmt.Errorf("sign register challenge: %w", err)
		}
		req := &api.EnrollRequest{
			Jwt:                jwtStr,
			PeerId:             s.peerID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleNode,
			Labels:             s.Labels,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		}
		data, err := proto.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, regURL, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		return httpReq, nil
	})
	if err != nil {
		return fmt.Errorf("POST /register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := cpclient.ReadBody(resp.Body)
		return fmt.Errorf("POST /register failed (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	respData, err := cpclient.ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("read /register response: %w", err)
	}
	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(respData, &enrollResp); err != nil {
		return fmt.Errorf("decode /register response: %w", err)
	}
	if enrollResp.GetErrorMessage() != "" {
		return fmt.Errorf("enrollment failed: %s", enrollResp.GetErrorMessage())
	}
	return s.adoptEnrollment(ctx, enrollResp.GetBiscuitToken(), enrollResp.GetControlPlanePublicKey(), enrollResp.GetExpireTime(), enrollResp.GetRouterAddresses(), false)
}

func (s *Server) enrollBootstrap(ctx context.Context, bootstrapToken string, trustedOnly bool) error {
	pubBytes, err := crypto.MarshalPublicKey(s.privKey.GetPublic())
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	client := s.cpHTTPClient(controlPlaneTimeout)
	enrollURL := s.cpURL + "/enroll"

	resp, err := cpclient.DoWithChallengeRetry(ctx, client, time.Now, cpclient.DefaultEnrollBackoff, func(ts int64) (*http.Request, error) {
		sig, err := s.privKey.Sign(api.EnrollChallenge(s.peerID.String(), ts))
		if err != nil {
			return nil, fmt.Errorf("sign enroll challenge: %w", err)
		}
		req := &api.BootstrapEnrollRequest{
			BootstrapToken:     bootstrapToken,
			PeerId:             s.peerID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      api.RoleNode,
			Labels:             s.Labels,
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		}
		data, err := proto.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		return httpReq, nil
	})
	if err != nil {
		return fmt.Errorf("POST /enroll: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := cpclient.ReadBody(resp.Body)
		return fmt.Errorf("POST /enroll failed (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	respData, err := cpclient.ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("read /enroll response: %w", err)
	}
	enrollResp := &api.BootstrapEnrollResponse{}
	if err := proto.Unmarshal(respData, enrollResp); err != nil {
		return fmt.Errorf("decode /enroll response: %w", err)
	}
	if enrollResp.GetErrorMessage() != "" {
		return fmt.Errorf("enrollment failed: %s", enrollResp.GetErrorMessage())
	}

	if enrollResp.GetStatus() == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		s.log().Info("bootstrap enrollment pending administrator approval; polling status", "peer_id", s.peerID.String())
		approved, err := s.pollBootstrapStatus(ctx, client, enrollResp.GetPollIntervalSeconds())
		if err != nil {
			return err
		}
		enrollResp = approved
	}
	if enrollResp.GetStatus() == api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
		return errors.New("bootstrap enrollment was rejected by administrator")
	}

	return s.adoptEnrollment(ctx, enrollResp.GetBiscuitToken(), enrollResp.GetControlPlanePublicKey(), enrollResp.GetExpireTime(), enrollResp.GetRouterAddresses(), trustedOnly)
}

func (s *Server) pollBootstrapStatus(ctx context.Context, client *http.Client, pollSec int32) (*api.BootstrapEnrollResponse, error) {
	u, err := url.Parse(s.cpURL)
	if err != nil {
		return nil, fmt.Errorf("parse control plane URL: %w", err)
	}
	u = u.JoinPath("enroll", "status")
	q := u.Query()
	q.Set("peer_id", s.peerID.String())
	u.RawQuery = q.Encode()
	statusURL := u.String()

	interval := defaultPollInterval
	if pollSec > 0 {
		interval = time.Duration(pollSec) * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			hResp, err := cpclient.DoWithChallenge(client, time.Now, func(ts int64) (*http.Request, error) {
				hReq, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
				if err != nil {
					return nil, err
				}
				if err := cpclient.SetChallengeHeaders(hReq, s.privKey, api.EnrollStatusChallenge(s.peerID.String(), ts), ts); err != nil {
					return nil, err
				}
				return hReq, nil
			})
			if err != nil {
				s.log().Warn("enrollment status check failed", "error", err)
				continue
			}
			if hResp.StatusCode != http.StatusOK {
				body, _ := cpclient.ReadBody(hResp.Body)
				_ = hResp.Body.Close()
				s.log().Warn("enrollment status returned non-OK", "status", hResp.Status, "body", strings.TrimSpace(string(body)))
				continue
			}
			data, err := cpclient.ReadBody(hResp.Body)
			_ = hResp.Body.Close()
			if err != nil {
				s.log().Warn("enrollment status read failed", "error", err)
				continue
			}
			statusResp := &api.BootstrapEnrollResponse{}
			if err := proto.Unmarshal(data, statusResp); err != nil {
				s.log().Warn("enrollment status decode failed", "error", err)
				continue
			}
			if statusResp.GetErrorMessage() != "" {
				return nil, fmt.Errorf("enrollment failed: %s", statusResp.GetErrorMessage())
			}
			switch statusResp.GetStatus() {
			case api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED:
				return statusResp, nil
			case api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED:
				return nil, errors.New("bootstrap enrollment was rejected by administrator")
			}
		}
	}
}

func (s *Server) adoptEnrollment(ctx context.Context, biscuitToken, cpPubKey []byte, exp *timestamppb.Timestamp, routerAddrs []string, trustedOnly bool) error {
	if len(biscuitToken) == 0 {
		return errors.New("enrollment returned an empty biscuit token")
	}
	if len(cpPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("enrollment returned invalid control plane public key size %d", len(cpPubKey))
	}
	if exp == nil {
		return errors.New("enrollment response missing expire_time")
	}

	if trustedOnly {
		if !s.isTrustedKey(cpPubKey) {
			sum := sha256.Sum256(cpPubKey)
			return fmt.Errorf("re-enrollment answer names untrusted control plane key %s", hex.EncodeToString(sum[:8]))
		}
		if err := s.verifyOwnBiscuit(biscuitToken); err != nil {
			return fmt.Errorf("re-enrollment biscuit failed verification: %w", err)
		}
	} else {
		if _, _, err := identity.VerifyBiscuitAndGetKey(biscuitToken, s.peerID, []ed25519.PublicKey{ed25519.PublicKey(cpPubKey)}, s.biscuitTimeout()); err != nil {
			return fmt.Errorf("enrolled biscuit verification failed: %w", err)
		}
		if err := identity.VerifyBiscuitRole(biscuitToken, ed25519.PublicKey(cpPubKey), api.RoleNode, s.biscuitTimeout()); err != nil {
			return fmt.Errorf("enrolled biscuit lacks role %q: %w", api.RoleNode, err)
		}
	}

	s.addTrustedKey(ed25519.PublicKey(slices.Clone(cpPubKey)))
	if err := s.syncTrustedKeys(ctx); err != nil {
		s.log().Warn("could not fetch full /keys set after enrollment; continuing with enrollment key", "error", err)
	}

	s.keysMu.Lock()
	s.issuedUnderKeys = s.publicKeysLocked()
	s.keysMu.Unlock()

	s.credMu.Lock()
	s.biscuit = slices.Clone(biscuitToken)
	s.expireTime = exp.AsTime()
	if len(routerAddrs) > 0 {
		s.storedRouterAddrs = slices.Clone(routerAddrs)
	}
	s.credMu.Unlock()

	if err := s.persistState(); err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	s.readmitRouters(ctx)
	return nil
}

// Refresh exchanges the member's current Biscuit for a freshly minted one at
// POST /refresh, persists the updated state directory, and presents the new
// credential on every live router session.
func (s *Server) Refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	currentBiscuit := s.currentBiscuit()
	if len(currentBiscuit) == 0 {
		return errors.New("meshnet: no current biscuit to refresh")
	}

	var freshJWT string
	if s.TokenSource != nil {
		if tok, err := s.TokenSource(ctx); err != nil {
			s.log().Warn("TokenSource failed during refresh; attempting session-backed refresh", "error", err)
		} else {
			freshJWT = strings.TrimSpace(tok)
		}
	} else if s.JWTPath != "" {
		if raw, err := os.ReadFile(s.JWTPath); err == nil {
			freshJWT = strings.TrimSpace(string(raw))
		}
	}

	client := s.cpHTTPClient(controlPlaneTimeout)
	refreshURL := s.cpURL + "/refresh"
	b64Biscuit := base64.StdEncoding.EncodeToString(currentBiscuit)

	resp, err := cpclient.DoWithChallenge(client, time.Now, func(ts int64) (*http.Request, error) {
		sig, err := s.privKey.Sign(api.RefreshChallenge(s.peerID.String(), ts))
		if err != nil {
			return nil, fmt.Errorf("sign refresh challenge: %w", err)
		}
		req := &api.TokenRefreshRequest{
			ChallengeSignature: sig,
			ChallengeUnixMs:    ts,
			PeerId:             s.peerID.String(),
			Jwt:                freshJWT,
		}
		reqData, err := proto.Marshal(req)
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshURL, bytes.NewReader(reqData))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		httpReq.Header.Set("Authorization", "Bearer "+b64Biscuit)
		return httpReq, nil
	})
	if err != nil {
		return fmt.Errorf("POST /refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := cpclient.ReadBody(resp.Body)
		return fmt.Errorf("POST /refresh failed (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	respData, err := cpclient.ReadBody(resp.Body)
	if err != nil {
		return fmt.Errorf("read /refresh response: %w", err)
	}
	var refreshResp api.TokenRefreshResponse
	if err := proto.Unmarshal(respData, &refreshResp); err != nil {
		return fmt.Errorf("decode /refresh response: %w", err)
	}
	if refreshResp.GetErrorMessage() != "" {
		return fmt.Errorf("refresh error: %s", refreshResp.GetErrorMessage())
	}
	if refreshResp.GetExpireTime() == nil {
		return errors.New("refresh response missing expire_time")
	}
	if err := s.verifyOwnBiscuit(refreshResp.GetBiscuitToken()); err != nil {
		return fmt.Errorf("refreshed biscuit rejected: %w", err)
	}

	s.keysMu.Lock()
	s.issuedUnderKeys = s.publicKeysLocked()
	s.keysMu.Unlock()

	s.credMu.Lock()
	s.biscuit = slices.Clone(refreshResp.GetBiscuitToken())
	s.expireTime = refreshResp.GetExpireTime().AsTime()
	s.credMu.Unlock()

	if err := s.persistState(); err != nil {
		return fmt.Errorf("persist refreshed state: %w", err)
	}
	s.readmitRouters(ctx)
	return nil
}

func (s *Server) renewFromOIDCSession(ctx context.Context) (string, error) {
	s.credMu.RLock()
	sess := s.oidcSession
	s.credMu.RUnlock()
	if sess == nil || sess.GetIssuer() == "" || sess.GetClientId() == "" || sess.GetRefreshToken() == "" {
		return "", errors.New("no OIDC refresh session")
	}

	issuer := strings.TrimSuffix(sess.GetIssuer(), "/")
	if err := api.ValidateControlPlaneTransport(issuer, s.AllowInsecure); err != nil {
		return "", err
	}
	httpClient := s.cpHTTPClient(15 * time.Second)
	discReq, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	discResp, err := httpClient.Do(discReq)
	if err != nil {
		return "", err
	}
	defer func() { _ = discResp.Body.Close() }()
	if discResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned %s", discResp.Status)
	}
	var doc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(discResp.Body, 1<<20)).Decode(&doc); err != nil || doc.TokenEndpoint == "" {
		return "", fmt.Errorf("invalid OIDC discovery document: %w", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {sess.GetClientId()},
		"refresh_token": {sess.GetRefreshToken()},
	}
	tokReq, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokResp, err := httpClient.Do(tokReq)
	if err != nil {
		return "", err
	}
	defer func() { _ = tokResp.Body.Close() }()
	if tokResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC token refresh returned %s", tokResp.Status)
	}
	var tokOut struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(tokResp.Body, 1<<20)).Decode(&tokOut); err != nil {
		return "", err
	}
	if tokOut.RefreshToken != "" {
		s.credMu.Lock()
		if s.oidcSession != nil {
			s.oidcSession.RefreshToken = tokOut.RefreshToken
		}
		s.credMu.Unlock()
	}
	if tokOut.IDToken != "" {
		return tokOut.IDToken, nil
	}
	if tokOut.AccessToken != "" {
		return tokOut.AccessToken, nil
	}
	return "", errors.New("OIDC token response contained neither id_token nor access_token")
}

func (s *Server) startRenewalLoop(ctx context.Context) {
	go func() {
		for {
			renewAfter := defaultRenewalFallback
			if exp := s.credentialExpireTime(); !exp.IsZero() {
				d := time.Until(exp)
				switch {
				case d > renewalThreshold:
					renewAfter = d - renewalBuffer
				case d > 0:
					renewAfter = max(d/2, 2*time.Second)
				default:
					renewAfter = 2 * time.Second
				}
			}

			timer := time.NewTimer(renewAfter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if err := s.Refresh(ctx); err == nil {
				s.log().Info("renewed mesh credential", "peer_id", s.peerID.String(), "expire_time", s.credentialExpireTime())
				continue
			} else {
				s.log().Warn("proactive biscuit refresh failed; attempting token re-enrollment", "error", err)
			}

			if jwtStr, err := s.renewFromOIDCSession(ctx); err == nil && jwtStr != "" {
				if regErr := s.enrollJWT(ctx, jwtStr); regErr == nil {
					s.log().Info("renewed mesh credential via OIDC session", "peer_id", s.peerID.String())
					continue
				}
			}
			kind, tok, err := s.resolveJoinSecret(ctx)
			if err == nil && kind == joinSecretJWT {
				if regErr := s.enrollJWT(ctx, tok); regErr == nil {
					s.log().Info("renewed mesh credential via JWT source", "peer_id", s.peerID.String())
					continue
				} else {
					s.log().Error("JWT re-enrollment failed", "error", regErr)
				}
			}
		}
	}()
}

func (s *Server) verifyOwnBiscuit(token []byte) error {
	if len(token) == 0 {
		return errors.New("empty biscuit token")
	}
	trusted := s.trustedPublicKeys()
	if len(trusted) == 0 {
		return errors.New("no trusted control plane keys loaded")
	}
	_, key, err := identity.VerifyBiscuitAndGetKey(token, s.peerID, trusted, s.biscuitTimeout())
	if err != nil {
		return err
	}
	return identity.VerifyBiscuitRole(token, key, api.RoleNode, s.biscuitTimeout())
}

func (s *Server) verifySavedRole() error {
	tok := s.currentBiscuit()
	if len(tok) == 0 {
		return errors.New("empty biscuit")
	}
	trusted := s.trustedPublicKeys()
	if len(trusted) == 0 {
		return errors.New("no trusted keys")
	}
	var lastErr error
	for _, k := range trusted {
		if err := identity.VerifyBiscuitRole(tok, k, api.RoleNode, s.biscuitTimeout()); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

func (s *Server) currentBiscuit() []byte {
	s.credMu.RLock()
	defer s.credMu.RUnlock()
	return slices.Clone(s.biscuit)
}

func (s *Server) credentialExpireTime() time.Time {
	s.credMu.RLock()
	defer s.credMu.RUnlock()
	return s.expireTime
}

func (s *Server) trustedPublicKeys() []ed25519.PublicKey {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return s.publicKeysLocked()
}

func (s *Server) publicKeysLocked() []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, 0, len(s.trustedKeys))
	for _, tk := range s.trustedKeys {
		out = append(out, tk.key)
	}
	return out
}

func (s *Server) isTrustedKey(pub []byte) bool {
	for _, k := range s.trustedPublicKeys() {
		if k.Equal(ed25519.PublicKey(pub)) {
			return true
		}
	}
	return false
}

func (s *Server) addTrustedKey(key ed25519.PublicKey) {
	s.keysMu.Lock()
	for _, tk := range s.trustedKeys {
		if bytes.Equal(tk.key, key) {
			s.keysMu.Unlock()
			return
		}
	}
	s.trustedKeys = append(s.trustedKeys, trustedKey{key: slices.Clone(key), receivedAt: time.Now()})
	s.keysMu.Unlock()
	if err := s.persistState(); err != nil {
		s.log().Warn("failed to persist updated trusted keys", "error", err)
	}
}
