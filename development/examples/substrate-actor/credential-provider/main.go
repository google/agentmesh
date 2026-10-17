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

// Command credential-provider is an Agent Substrate credential provider that
// gives every actor its own Agent Mesh credential.
//
// Substrate's egress gateway calls FetchSecret with the URI named in the
// actor's EgressPolicy and the actor's SPIFFE ID, which the gateway verified
// from the actor's client certificate. For ate-secret://agentmesh/mesh/biscuit
// this provider signs a short-lived assertion that names that SPIFFE ID as the
// subject, exchanges it at an agentmesh-node token endpoint (RFC 8693), and
// returns the Biscuit the mesh minted. The control plane trusts this provider
// as a workload identity issuer and binds roles to the actor's SPIFFE ID, so
// the mesh policy, not the provider, decides what each actor may call.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agent-substrate/substrate/pkg/proto/credproviderpb"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	// Substrate credential URIs are ate-secret://<provider-class>/<provider-name>/<tail>.
	credentialTail    = "biscuit"
	assertionLifetime = 10 * time.Minute
	expirySkew        = 30 * time.Second
)

var (
	listenAddr       = flag.String("listen-address", ":50051", "gRPC listen address for the Substrate CredentialProvider service")
	httpAddr         = flag.String("http-address", ":8080", "HTTP listen address for OIDC discovery, the JWKS and health")
	serverBundle     = flag.String("server-cred-bundle", "", "PEM private key and certificate chain this provider serves TLS with (required)")
	clientCAFile     = flag.String("client-ca-file", "", "CA bundle the egress gateway's client certificate must chain to (required)")
	injectorIdentity = flag.String("injector-identity", "spiffe://cluster.local/ns/ate-system/sa/atenet-egress", "URI SAN the egress gateway's client certificate must carry")
	providerName     = flag.String("provider-name", "agentmesh", "provider class of the ate-secret:// URIs this provider serves")
	instanceName     = flag.String("instance-name", "mesh", "provider name segment of the ate-secret:// URIs this provider serves")
	actorTrustDomain = flag.String("actor-trust-domain", "substrate-actor.local", "SPIFFE trust domain of actor identities")
	nodeURL          = flag.String("node-url", "", "agentmesh-node API whose /oauth/token mints the credential (required)")
	issuer           = flag.String("issuer", "", "iss of the assertions this provider signs; the control plane fetches <issuer>/.well-known/openid-configuration (required)")
	audience         = flag.String("audience", "agentmesh", "aud of the assertions; one of the control plane's --allowed-audiences")
	cacheTTL         = flag.Duration("cache-ttl", time.Minute, "longest a minted credential is reused; also how long a mesh policy change takes to reach an actor")
)

func main() {
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if err := run(context.Background()); err != nil {
		logger.Error("exiting", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	for name, value := range map[string]string{
		"--server-cred-bundle": *serverBundle, "--client-ca-file": *clientCAFile,
		"--node-url": *nodeURL, "--issuer": *issuer,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	signer, err := newSigner(*issuer, *audience)
	if err != nil {
		return err
	}
	provider := &provider{
		name:        *providerName,
		instance:    *instanceName,
		trustDomain: *actorTrustDomain,
		signer:      signer,
		node:        strings.TrimRight(*nodeURL, "/"),
		cacheTTL:    *cacheTTL,
		http:        &http.Client{Timeout: 15 * time.Second},
		cache:       map[string]*cached{},
	}

	creds, err := serverCredentials(*serverBundle, *clientCAFile, *injectorIdentity)
	if err != nil {
		return err
	}
	grpcSrv := grpc.NewServer(grpc.Creds(creds))
	credproviderpb.RegisterCredentialProviderServer(grpcSrv, provider)
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listenAddr, err)
	}

	httpSrv := &http.Server{Addr: *httpAddr, Handler: signer.handler(), ReadHeaderTimeout: 5 * time.Second}
	errs := make(chan error, 2)
	go func() { errs <- grpcSrv.Serve(lis) }()
	go func() { errs <- httpSrv.ListenAndServe() }()
	slog.Info("serving", slog.String("grpc", *listenAddr), slog.String("http", *httpAddr),
		slog.String("issuer", *issuer), slog.String("node", provider.node), slog.String("uri", provider.uri()))

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	grpcSrv.GracefulStop()
	return httpSrv.Shutdown(shutdownCtx)
}

// provider answers FetchSecret for one URI with a per-actor mesh credential.
type provider struct {
	credproviderpb.UnimplementedCredentialProviderServer
	name        string
	instance    string
	trustDomain string
	signer      *signer
	node        string
	cacheTTL    time.Duration
	http        *http.Client

	mu    sync.Mutex
	cache map[string]*cached
}

type cached struct {
	mu      sync.Mutex
	token   []byte
	expires time.Time
}

type actorRef struct{ atespace, name string }

// FetchSecret returns the Biscuit for the actor the gateway attested. The URI
// must be ate-secret://<provider-name>/<instance-name>/biscuit; anything else
// is not served.
func (p *provider) FetchSecret(ctx context.Context, req *credproviderpb.FetchSecretRequest) (*credproviderpb.FetchSecretResponse, error) {
	if err := p.checkURI(req.GetUri()); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	actor, err := p.parseActor(req.GetActorSpiffeId())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	token, err := p.credential(ctx, req.GetActorSpiffeId(), actor)
	if err != nil {
		return nil, err
	}
	return &credproviderpb.FetchSecretResponse{OpaqueBytes: token}, nil
}

func (p *provider) uri() string {
	return "ate-secret://" + p.name + "/" + p.instance + "/" + credentialTail
}

func (p *provider) checkURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("credential URI: %w", err)
	}
	if u.Scheme != "ate-secret" || u.Host != p.name || u.Path != "/"+p.instance+"/"+credentialTail || u.RawQuery != "" {
		return fmt.Errorf("credential URI %q is not %s", raw, p.uri())
	}
	return nil
}

// parseActor accepts spiffe://<trust-domain>/actor/<atespace>/<name>, the ID
// Substrate's gateway derives from the actor's certificate.
func (p *provider) parseActor(id string) (actorRef, error) {
	u, err := url.Parse(id)
	if err != nil {
		return actorRef{}, fmt.Errorf("actor SPIFFE ID: %w", err)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if u.Scheme != "spiffe" || u.Host != p.trustDomain || len(parts) != 3 || parts[0] != "actor" || parts[1] == "" || parts[2] == "" {
		return actorRef{}, fmt.Errorf("actor SPIFFE ID %q is not spiffe://%s/actor/<atespace>/<name>", id, p.trustDomain)
	}
	return actorRef{atespace: parts[1], name: parts[2]}, nil
}

// credential returns the cached Biscuit for subject, minting one when the
// cache has none or the entry has aged out. Concurrent requests for one actor
// share a single mint.
func (p *provider) credential(ctx context.Context, subject string, actor actorRef) ([]byte, error) {
	p.mu.Lock()
	entry, ok := p.cache[subject]
	if !ok {
		entry = &cached{}
		p.cache[subject] = entry
	}
	p.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.token != nil && time.Now().Before(entry.expires) {
		return entry.token, nil
	}
	token, lifetime, err := p.mint(ctx, subject, actor)
	if err != nil {
		return nil, err
	}
	reuse := min(lifetime-expirySkew, p.cacheTTL)
	if reuse <= 0 {
		return token, nil
	}
	entry.token, entry.expires = token, time.Now().Add(reuse)
	return token, nil
}

// mint signs an assertion for subject and exchanges it at the node token
// endpoint. The control plane verifies the assertion against this provider's
// JWKS and resolves the subject's roles from the mesh policy.
func (p *provider) mint(ctx context.Context, subject string, actor actorRef) ([]byte, time.Duration, error) {
	assertion, err := p.signer.assertion(subject, map[string]string{"atespace": actor.atespace, "actorName": actor.name})
	if err != nil {
		return nil, 0, status.Errorf(codes.Internal, "signing assertion: %v", err)
	}
	form := url.Values{
		"grant_type":         {grantTypeTokenExchange},
		"subject_token":      {assertion},
		"subject_token_type": {tokenTypeJWT},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.node+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, status.Errorf(codes.Internal, "token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, 0, status.Errorf(codes.Unavailable, "agentmesh-node token endpoint: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, status.Errorf(codes.Unavailable, "reading token response: %v", err)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, 0, status.Errorf(codes.Unavailable, "token response is not JSON (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		slog.Warn("mesh refused the actor", slog.String("actor", subject), slog.Int("status", resp.StatusCode),
			slog.String("error", out.Error), slog.String("description", out.Description))
		return nil, 0, status.Errorf(codes.PermissionDenied, "mesh refused %s: %s %s", subject, out.Error, out.Description)
	}
	slog.Info("minted mesh credential", slog.String("actor", subject), slog.Int64("expires_in", out.ExpiresIn))
	return []byte(out.AccessToken), time.Duration(out.ExpiresIn) * time.Second, nil
}

// signer holds the ES256 key the provider asserts actor identities with and
// publishes it the way an OIDC issuer does.
type signer struct {
	issuer, audience string
	kid              string
	key              *ecdsa.PrivateKey
	jwks, discovery  []byte
}

func newSigner(issuer, audience string) (*signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	s := &signer{issuer: issuer, audience: audience, kid: base64.RawURLEncoding.EncodeToString(sum[:]), key: key}
	coord := func(b []byte) string {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(padded)
	}
	s.jwks, _ = json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": s.kid,
		"x": coord(key.PublicKey.X.Bytes()), "y": coord(key.PublicKey.Y.Bytes()),
	}}})
	s.discovery, _ = json.Marshal(map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/keys",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"claims_supported":                      []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "ate.dev"},
	})
	return s, nil
}

func (s *signer) assertion(subject string, actor map[string]string) (string, error) {
	now := time.Now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":     s.issuer,
		"sub":     subject,
		"aud":     []string{s.audience},
		"iat":     now.Unix(),
		"nbf":     now.Add(-time.Minute).Unix(),
		"exp":     now.Add(assertionLifetime).Unix(),
		"jti":     hex.EncodeToString(jti),
		"ate.dev": actor,
	})
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}

func (s *signer) handler() http.Handler {
	mux := http.NewServeMux()
	serve := func(body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(body)
		}
	}
	mux.Handle("GET /.well-known/openid-configuration", serve(s.discovery))
	mux.Handle("GET /keys", serve(s.jwks))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

// serverCredentials builds the mutual TLS the gateway expects from a provider:
// the pod's servicedns certificate on the server side, and on the client side
// a certificate that chains to the pod-identity CA and carries the egress
// gateway's SPIFFE ID. Both files rotate, so they are read on every handshake.
func serverCredentials(bundlePath, caPath, expectedSAN string) (credentials.TransportCredentials, error) {
	if _, err := loadBundle(bundlePath); err != nil {
		return nil, err
	}
	if _, err := loadPool(caPath); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool, err := loadPool(caPath)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion: tls.VersionTLS13,
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  pool,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return loadBundle(bundlePath)
				},
				VerifyConnection: func(state tls.ConnectionState) error {
					if len(state.PeerCertificates) == 0 {
						return errors.New("client certificate is required")
					}
					for _, u := range state.PeerCertificates[0].URIs {
						if u.String() == expectedSAN {
							return nil
						}
					}
					return fmt.Errorf("client certificate URI SANs %v do not include %q", state.PeerCertificates[0].URIs, expectedSAN)
				},
			}, nil
		},
	}
	return credentials.NewTLS(cfg), nil
}

// loadBundle reads a Kubernetes pod certificate credential bundle: a PEM
// private key followed by the certificate chain.
func loadBundle(path string) (*tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("credential bundle: %w", err)
	}
	var cert tls.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			cert.Certificate = append(cert.Certificate, block.Bytes)
		case strings.HasSuffix(block.Type, "PRIVATE KEY") && cert.PrivateKey == nil:
			key, err := parsePrivateKey(block)
			if err != nil {
				return nil, fmt.Errorf("credential bundle %s: %w", path, err)
			}
			cert.PrivateKey = key
		}
	}
	if cert.PrivateKey == nil || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("credential bundle %s has no key and certificate", path)
	}
	return &cert, nil
}

func parsePrivateKey(block *pem.Block) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("client CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("client CA bundle %s holds no certificates", path)
	}
	return pool, nil
}
