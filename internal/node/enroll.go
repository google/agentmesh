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
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/agentmesh/api"
	cpclient "github.com/google/agentmesh/internal/controlplane/client"
	"github.com/google/agentmesh/internal/identity"
	golog "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var logger = golog.Logger("agentmesh-node")

// expireUnix is the unix seconds of a control plane's expire_time for the
// store; an unset one is 0, an already-expired credential, so the node
// refreshes at once instead of trusting a token of unknown lifetime.
func expireUnix(t *timestamppb.Timestamp) int64 {
	if t == nil {
		return 0
	}
	return t.AsTime().Unix()
}

// LoadOrGenerateKey retrieves the persistent libp2p private key from s or
// generates and saves a new Ed25519 identity without terminating the process
// on error.
func LoadOrGenerateKey(s *Store) (crypto.PrivKey, error) {
	kb, err := s.LoadKey()
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	if len(kb) > 0 {
		priv, unmarshalErr := crypto.UnmarshalPrivateKey(kb)
		if unmarshalErr != nil {
			return nil, fmt.Errorf("corrupt key in store: %w", unmarshalErr)
		}
		return priv, nil
	}
	logger.Info("[Store] Generating new Peer Identity...")
	priv, _, genErr := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if genErr != nil {
		return nil, fmt.Errorf("generate key: %w", genErr)
	}
	raw, marshalErr := crypto.MarshalPrivateKey(priv)
	if marshalErr != nil {
		return nil, fmt.Errorf("marshal private key: %w", marshalErr)
	}
	if saveErr := s.SaveKey(raw); saveErr != nil {
		return nil, fmt.Errorf("save key: %w", saveErr)
	}
	return priv, nil
}

// GetOrGenerateKey retrieves a persistent private key or creates one if it's the first run
func GetOrGenerateKey(s *Store) crypto.PrivKey {
	priv, err := LoadOrGenerateKey(s)
	if err != nil {
		logger.Fatalf("Failed to load or generate key: %v", err)
	}
	return priv
}

func (n *AgentMeshNode) Enroll(ctx context.Context, controlPlaneURL string, jwt string) error {
	peerID, err := n.localPeerID()
	if err != nil {
		return err
	}
	enrollResp, err := n.enrollHTTP(ctx, controlPlaneURL, jwt, peerID, n.config.PrivKey)
	if err != nil {
		return err
	}
	if n.Store != nil {
		if saveErr := n.Store.SaveControlPlaneURL(controlPlaneURL); saveErr != nil {
			logger.Warnf("Failed to save control plane URL: %v", saveErr)
		}
	}
	if n.Host == nil {
		return nil
	}

	// Routers already holding a session are shown the new credential;
	// connectToRouters skips them, as their sessions are live.
	n.readmitRouters(ctx)
	if len(enrollResp.RouterAddresses) == 0 && n.IsConnected() {
		return nil
	}
	return n.connectToRouters(ctx, controlPlaneURL, enrollResp.RouterAddresses)
}

// EnrollBootstrapCredential obtains and persists a member credential via
// POST /enroll (polling /enroll/status if pending) without attaching to routers.
func (n *AgentMeshNode) EnrollBootstrapCredential(ctx context.Context, controlPlaneURL, bootstrapToken string, trustedOnly bool) (*api.BootstrapEnrollResponse, error) {
	if n.config.PrivKey == nil && n.Store != nil {
		priv, err := LoadOrGenerateKey(n.Store)
		if err != nil {
			return nil, err
		}
		n.config.PrivKey = priv
	}
	resp, err := n.enrollBootstrapCredential(ctx, controlPlaneURL, bootstrapToken, trustedOnly)
	if err != nil {
		return nil, err
	}
	if n.Store != nil {
		if err := n.Store.SaveControlPlaneURL(controlPlaneURL); err != nil {
			return nil, fmt.Errorf("save control plane URL: %w", err)
		}
	}
	if n.Host != nil {
		n.readmitRouters(ctx)
	}
	return resp, nil
}

// adoptEnrolledKeys widens the trust set from the single key an enrollment
// response carries to every key the control plane currently signs with.
// The router handshake that follows verifies the router's own biscuit, and
// right after a rotation that is still signed by the retiring key; with only
// the newest key loaded the node would refuse every router. Best effort: a
// control plane too old to serve /keys still enrolls with one key.
func (n *AgentMeshNode) adoptEnrolledKeys(ctx context.Context, controlPlaneURL string, newest []byte) {
	n.addTrustedKey(ed25519.PublicKey(newest))
	if err := n.syncTrustedKeys(ctx, controlPlaneURL); err != nil {
		logger.Warnf("Could not fetch the control plane's full key set after enrollment (continuing with the enrollment key only): %v", err)
	}
	n.recordIdentityKeySet()
}

// enrollHTTP performs the HTTP half of enrollment for an explicit peer
// identity, so it can run before the libp2p host exists (startup recovery).
// privKey signs the proof-of-possession challenge; peerID must be its own.
func (n *AgentMeshNode) enrollHTTP(ctx context.Context, controlPlaneURL, jwt string, peerID peer.ID, privKey crypto.PrivKey) (*api.EnrollResponse, error) {
	pubBytes, err := crypto.MarshalPublicKey(privKey.GetPublic())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		return nil, fmt.Errorf("control plane address must be an HTTP or HTTPS URL for enrollment: %s", controlPlaneURL)
	}
	url := controlPlaneURL + "/register"
	logger.Infof("Enrolling via HTTP at %s", url)

	client := n.cpHTTPClient(30 * time.Second)
	resp, err := cpclient.DoWithChallengeRetry(ctx, client, time.Now, cpclient.DefaultEnrollBackoff, func(ts int64) (*http.Request, error) {
		sig, err := privKey.Sign(api.RegisterChallenge(peerID.String(), ts))
		if err != nil {
			return nil, fmt.Errorf("failed to sign registration challenge: %w", err)
		}
		req := &api.EnrollRequest{
			Jwt:                jwt,
			PeerId:             peerID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      n.config.RequiredRole,
			Labels:             n.labels(),
			ChallengeUnixMs:    ts,
			ChallengeSignature: sig,
		}
		data, err := proto.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal enroll request: %v", err)
		}
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %v", err)
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		return httpReq, nil
	})
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("failed to close response body: %v", err)
		}
	}()

	enrollResp, err := n.processEnrollResponse(resp)
	if err != nil {
		return nil, err
	}
	n.adoptEnrolledKeys(ctx, controlPlaneURL, enrollResp.ControlPlanePublicKey)
	return enrollResp, nil
}

// ReEnrollWithRefreshToken re-enrolls over HTTP with a JWT from the stored
// refresh token, keeping the PeerID. Must not touch n.Host: startup recovery
// runs it before the host exists, and the mobile app on a never-started node.
func (n *AgentMeshNode) ReEnrollWithRefreshToken(ctx context.Context) error {
	controlPlaneURL, err := n.Store.LoadControlPlaneURL()
	if err != nil || controlPlaneURL == "" {
		return fmt.Errorf("no control plane URL in store")
	}
	jwt, err := n.renewWithRefreshToken(ctx, "")
	if err != nil {
		return err
	}
	privKey, err := LoadOrGenerateKey(n.Store)
	if err != nil {
		return err
	}
	peerID, err := peer.IDFromPublicKey(privKey.GetPublic())
	if err != nil {
		return fmt.Errorf("failed to derive peer ID from stored key: %w", err)
	}
	_, err = n.enrollHTTP(ctx, controlPlaneURL, jwt, peerID, privKey)
	return err
}

func (n *AgentMeshNode) processEnrollResponse(resp *http.Response) (*api.EnrollResponse, error) {
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxControlPlaneBodyBytes))
		return nil, fmt.Errorf("enrollment failed with status %s: %s", resp.Status, string(body))
	}

	respData, err := cpclient.ReadBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("enrollment response: %w", err)
	}

	var enrollResp api.EnrollResponse
	if err := proto.Unmarshal(respData, &enrollResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if enrollResp.ErrorMessage != "" {
		return nil, fmt.Errorf("enrollment failed: %s", enrollResp.ErrorMessage)
	}
	if len(enrollResp.BiscuitToken) == 0 {
		return nil, fmt.Errorf("received empty biscuit token")
	}
	if len(enrollResp.ControlPlanePublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("received invalid control plane public key size: %d bytes (expected %d)", len(enrollResp.ControlPlanePublicKey), ed25519.PublicKeySize)
	}

	if n.config.RequiredRole != "" {
		if err := identity.VerifyBiscuitRole(enrollResp.BiscuitToken, ed25519.PublicKey(enrollResp.ControlPlanePublicKey), n.config.RequiredRole, n.BiscuitTimeout); err != nil {
			return nil, fmt.Errorf("enrolled biscuit token lacks required role %q: %w", n.config.RequiredRole, err)
		}
	}

	if err := n.Store.SaveIdentity(enrollResp.BiscuitToken); err != nil {
		return nil, fmt.Errorf("failed to save identity: %v", err)
	}
	n.SetIdentityCache(enrollResp.BiscuitToken)

	if err := n.Store.SaveIdentityExpiration(expireUnix(enrollResp.ExpireTime)); err != nil {
		return nil, fmt.Errorf("failed to save identity expiration: %v", err)
	}
	if err := n.Store.SaveMeshConfig(enrollResp.ControlPlanePublicKey, enrollResp.RouterAddresses); err != nil {
		return nil, fmt.Errorf("failed to save mesh config: %v", err)
	}

	return &enrollResp, nil
}

func (n *AgentMeshNode) connectToRouters(ctx context.Context, controlPlaneURL string, addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("failed to connect and authenticate after HTTP enrollment: control plane returned no router addresses")
	}
	if err := n.joinRouters(ctx, controlPlaneURL, addrs); err != nil {
		return fmt.Errorf("failed to connect and authenticate with any router after HTTP enrollment: %w", err)
	}
	logger.Info("Successfully enrolled via HTTP and stored identity and mesh config.")
	return nil
}

// joinRouters is the handshake that follows an enrollment: the node attaches
// through the same admission as at Start, so the routers are chosen and
// retried the same way. The enrollment answer lists addresses alone, so the
// catalog is read from /info first, where the routers carry the labels a
// selector matches; the answer is the fallback when /info cannot be read.
func (n *AgentMeshNode) joinRouters(ctx context.Context, controlPlaneURL string, addrs []string) error {
	var cands []routerCandidate
	if info, err := n.fetchControlPlaneInfo(ctx, controlPlaneURL); err == nil {
		cands = candidatesFromInfo(ctx, info)
	} else {
		logger.Debugf("Routers not read from /info after enrollment, using the enrollment answer: %v", err)
	}
	if len(cands) == 0 {
		cands = candidatesFromAddrs(ctx, parseMultiaddrs(addrs))
	}
	if len(cands) == 0 {
		return fmt.Errorf("no router peer behind %v", addrs)
	}
	n.setRouterCatalog(cands)
	_, err := n.admitByRouters(ctx)
	return err
}

// EnrollBootstrap enrolls the node with the control plane using a pre-shared bootstrap token.
// If the enrollment status is PENDING, it polls the status endpoint until approved or rejected.
func (n *AgentMeshNode) EnrollBootstrap(ctx context.Context, controlPlaneURL string, bootstrapToken string) error {
	enrollResp, err := n.enrollBootstrapCredential(ctx, controlPlaneURL, bootstrapToken, false)
	if err != nil {
		return err
	}

	// Connect and Auth to router after enrollment to join the mesh
	if len(enrollResp.RouterAddresses) == 0 {
		return fmt.Errorf("failed to connect and authenticate after bootstrap enrollment: control plane returned no router addresses")
	}
	if err := n.joinRouters(ctx, controlPlaneURL, enrollResp.RouterAddresses); err != nil {
		return fmt.Errorf("failed to connect/auth with router after bootstrap enrollment: %w", err)
	}

	logger.Info("Successfully enrolled via Bootstrap token and joined mesh.")
	return nil
}

// enrollBootstrapCredential is the HTTP half of EnrollBootstrap: it obtains
// a credential with the bootstrap token and persists it with the mesh
// configuration, without attaching to routers. With trustedOnly, for a node
// that already has a trust root and only needs the control plane to know it
// again (the control plane lost its store), the answer must verify under a
// key the node already trusts; without it, first enrollment, the key in
// the answer is trusted on first use.
func (n *AgentMeshNode) enrollBootstrapCredential(ctx context.Context, controlPlaneURL string, bootstrapToken string, trustedOnly bool) (*api.BootstrapEnrollResponse, error) {
	// The identity is the node key; the host, when there is one, carries
	// the same key.
	if n.config.PrivKey == nil {
		return nil, errors.New("node has no private key")
	}
	pubKey := n.config.PrivKey.GetPublic()
	peerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive peer ID: %w", err)
	}
	pubBytes, err := crypto.MarshalPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	if !strings.HasPrefix(controlPlaneURL, "http://") && !strings.HasPrefix(controlPlaneURL, "https://") {
		return nil, fmt.Errorf("control plane address must be an HTTP or HTTPS URL for enrollment: %s", controlPlaneURL)
	}
	enrollURL := controlPlaneURL + "/enroll"
	logger.Infof("Enrolling via Bootstrap token at %s", enrollURL)

	client := n.cpHTTPClient(30 * time.Second)
	resp, err := cpclient.DoWithChallengeRetry(ctx, client, time.Now, cpclient.DefaultEnrollBackoff, func(enrollTS int64) (*http.Request, error) {
		enrollSig, err := n.config.PrivKey.Sign(api.EnrollChallenge(peerID.String(), enrollTS))
		if err != nil {
			return nil, fmt.Errorf("failed to sign enrollment challenge: %w", err)
		}
		req := &api.BootstrapEnrollRequest{
			BootstrapToken:     bootstrapToken,
			PeerId:             peerID.String(),
			PublicKey:          pubBytes,
			RequestedRole:      n.config.RequiredRole,
			Labels:             n.labels(),
			ChallengeUnixMs:    enrollTS,
			ChallengeSignature: enrollSig,
		}
		data, err := proto.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal bootstrap enroll request: %w", err)
		}
		httpReq, err := http.NewRequestWithContext(ctx, "POST", enrollURL, bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/x-protobuf")
		return httpReq, nil
	})
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxControlPlaneBodyBytes))
		return nil, fmt.Errorf("enrollment failed with status %s: %s", resp.Status, string(body))
	}

	respData, err := cpclient.ReadBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("bootstrap enrollment response: %w", err)
	}

	enrollResp := &api.BootstrapEnrollResponse{}
	if err := proto.Unmarshal(respData, enrollResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if enrollResp.ErrorMessage != "" {
		return nil, fmt.Errorf("enrollment failed: %s", enrollResp.ErrorMessage)
	}

	if enrollResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_PENDING {
		logger.Infof("Enrollment is pending approval. Polling status...")

		u, err := url.Parse(controlPlaneURL)
		if err != nil {
			return nil, fmt.Errorf("invalid control plane URL: %w", err)
		}
		u = u.JoinPath("enroll", "status")
		q := u.Query()
		q.Set("peer_id", peerID.String())
		u.RawQuery = q.Encode()
		statusURL := u.String()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

	pollLoop:
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
				// Prove possession of the enrollment key on every poll; the
				// control plane returns the biscuit only to the enrollee.
				hResp, err := cpclient.DoWithChallenge(client, time.Now, func(ts int64) (*http.Request, error) {
					hReq, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
					if err != nil {
						return nil, fmt.Errorf("failed to create status request: %w", err)
					}
					if err := cpclient.SetChallengeHeaders(hReq, n.config.PrivKey, api.EnrollStatusChallenge(peerID.String(), ts), ts); err != nil {
						return nil, fmt.Errorf("failed to sign enrollment status challenge: %w", err)
					}
					return hReq, nil
				})
				if err != nil {
					logger.Warnf("Failed to check enrollment status: %v", err)
					continue
				}

				if hResp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(io.LimitReader(hResp.Body, maxControlPlaneBodyBytes))
					_ = hResp.Body.Close()
					logger.Warnf("Status check returned status %s: %s", hResp.Status, string(body))
					continue
				}

				hRespData, err := cpclient.ReadBody(hResp.Body)
				_ = hResp.Body.Close()
				if err != nil {
					logger.Warnf("Enrollment status response: %v", err)
					continue
				}

				statusResp := &api.BootstrapEnrollResponse{}
				if err := proto.Unmarshal(hRespData, statusResp); err != nil {
					logger.Warnf("Failed to unmarshal status response: %v", err)
					continue
				}

				if statusResp.ErrorMessage != "" {
					return nil, fmt.Errorf("enrollment failed: %s", statusResp.ErrorMessage)
				}

				if statusResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_APPROVED {
					enrollResp = statusResp
					break pollLoop
				} else if statusResp.Status == api.EnrollmentStatus_ENROLLMENT_STATUS_REJECTED {
					return nil, fmt.Errorf("enrollment was rejected by administrator")
				}
			}
		}
	}

	if len(enrollResp.BiscuitToken) == 0 {
		return nil, fmt.Errorf("received empty biscuit token from enrollment response")
	}

	if len(enrollResp.ControlPlanePublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("received invalid control plane public key size: %d bytes", len(enrollResp.ControlPlanePublicKey))
	}

	if trustedOnly {
		// This node already has a trust root. Whoever answered may name any
		// key in the response; only a credential that verifies under a key
		// this node trusts, for this node, with the required role, replaces
		// the one it holds, and a response naming another key is refused:
		// a party able to answer the control plane URL would otherwise
		// swap the trust root and the router list with a single 401.
		if !n.isTrustedKey(enrollResp.ControlPlanePublicKey) {
			return nil, fmt.Errorf("re-enrollment answer names a control plane key this node does not trust (%s); refusing to replace the trust root", keyFingerprintHex(enrollResp.ControlPlanePublicKey))
		}
		if err := n.verifyOwnBiscuit(enrollResp.BiscuitToken); err != nil {
			return nil, fmt.Errorf("re-enrollment credential does not verify under a trusted control plane key: %w", err)
		}
	} else if err := identity.VerifyBiscuitRole(enrollResp.BiscuitToken, ed25519.PublicKey(enrollResp.ControlPlanePublicKey), n.config.RequiredRole, n.BiscuitTimeout); err != nil {
		return nil, fmt.Errorf("enrolled biscuit token lacks required role %q: %w", n.config.RequiredRole, err)
	}

	if err := n.Store.SaveIdentity(enrollResp.BiscuitToken); err != nil {
		return nil, fmt.Errorf("failed to save identity: %v", err)
	}
	n.SetIdentityCache(enrollResp.BiscuitToken)

	if err := n.Store.SaveIdentityExpiration(expireUnix(enrollResp.ExpireTime)); err != nil {
		return nil, fmt.Errorf("failed to save identity expiration: %v", err)
	}

	if err := n.Store.SaveMeshConfig(enrollResp.ControlPlanePublicKey, enrollResp.RouterAddresses); err != nil {
		return nil, fmt.Errorf("failed to save mesh config: %v", err)
	}

	n.adoptEnrolledKeys(ctx, controlPlaneURL, enrollResp.ControlPlanePublicKey)
	return enrollResp, nil
}

// isTrustedKey reports whether pub is one of the control plane keys this
// node trusts now.
func (n *AgentMeshNode) isTrustedKey(pub []byte) bool {
	for _, k := range n.getTrustedPublicKeys() {
		if k.Equal(ed25519.PublicKey(pub)) {
			return true
		}
	}
	return false
}

// keyFingerprintHex identifies a public key in a message the way the
// control plane and routers do in theirs.
func keyFingerprintHex(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
