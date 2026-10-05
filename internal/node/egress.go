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
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/sam/api"
	cpclient "github.com/google/sam/internal/controlplane/client"
	"google.golang.org/protobuf/proto"
)

// DefaultSecretsDir is where a node looks for the credentials the control
// plane names in egress destinations when --secrets-dir is not given.
const DefaultSecretsDir = "/etc/sam/secrets"

// Proxy-Status error types (RFC 9209) the node answers with when it, and not
// the destination, refuses a request. A client can then tell a policy denial
// from a 403 the destination sent.
const (
	proxyStatusDenied              = "http_request_denied"
	proxyStatusDestinationNotFound = "destination_not_found"
	proxyStatusConfigurationError  = "proxy_configuration_error"
)

// refuse answers a request the node refuses itself, naming the reason in
// Proxy-Status so the client can tell it from the destination's own answer.
func refuse(w http.ResponseWriter, status int, text, errorType string) {
	w.Header().Set("Proxy-Status", "sam-node; error="+errorType)
	http.Error(w, text, status)
}

// EgressService serves egress://<name>: this node is the HTTP origin for one
// destination outside the mesh. The destination, where to forward, and which
// credential to present are the control plane's decision (an
// EgressDestination that selected this node); the node holds no policy of
// its own about it. Every request reaches the handler only after Authorize
// ran with the caller's credential and the method, path, host and port facts.
type EgressService struct {
	node              *SamNode
	destination       *api.EgressDestination
	info              *api.ServiceInfo
	target            *url.URL
	secretsDir        string
	exchanger         CloudTokenExchanger
	isStaticSecret    bool
	modelArmorBaseURL string
	modelArmorClient  *http.Client
	handler           http.Handler
}

type egressCallerContext struct {
	principal string
	roles     []string
	actorNode string
	task      string
	rules     []*api.TaskAuthorizationRule
}

type egressContextKey struct{}

// newEgressService builds the service for one assignment. The target URL was
// validated by the control plane; it is parsed again here because this node
// dials it.
func newEgressService(d *api.EgressDestination, secretsDir string) (*EgressService, error) {
	return newEgressServiceForNode(nil, d, secretsDir)
}

func newEgressServiceForNode(node *SamNode, d *api.EgressDestination, secretsDir string) (*EgressService, error) {
	if err := api.ValidateEgressName(d.GetName()); err != nil {
		return nil, err
	}
	target, err := url.Parse(api.EgressTargetURL(d))
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("egress %s: invalid target_url", d.GetName())
	}
	if target.User != nil {
		return nil, fmt.Errorf("egress %s: target_url must not carry a credential", d.GetName())
	}
	if cred := api.EgressStaticSecret(d); cred != "" && (filepath.Base(cred) != cred || cred == "." || cred == "..") {
		return nil, fmt.Errorf("egress %s: credential %q must be a file name", d.GetName(), cred)
	}
	cloned := proto.Clone(d).(*api.EgressDestination)
	s := &EgressService{
		node:        node,
		destination: cloned,
		info: &api.ServiceInfo{
			Type:        api.ServiceType_SERVICE_TYPE_EGRESS,
			Name:        d.GetName(),
			Description: "egress to " + target.Scheme + "://" + target.Host,
		},
		target:     target,
		secretsDir: secretsDir,
	}
	s.initExchanger()
	return s, nil
}

func (s *EgressService) initExchanger() {
	if secretName := api.EgressStaticSecret(s.destination); secretName != "" {
		s.exchanger = NewStaticSecretExchanger(s.secretsDir, secretName)
		s.isStaticSecret = true
		return
	}
	if b := s.destination.GetBroker(); b != nil {
		switch kind := b.GetKind().(type) {
		case *api.CredentialBroker_OidcFederation:
			if kind.OidcFederation != nil {
				s.exchanger = NewOIDCFederationExchanger(s.destination.GetName(), kind.OidcFederation, s.mintBorderJWT, nil)
			}
		case *api.CredentialBroker_AwsAssumeRole:
			if kind.AwsAssumeRole != nil {
				s.exchanger = NewAWSAssumeRoleExchanger(s.destination.GetName(), kind.AwsAssumeRole, s.mintBorderJWT, nil)
			}
		case *api.CredentialBroker_PlatformIdentity:
			if kind.PlatformIdentity != nil {
				s.exchanger = NewPlatformIdentityExchanger(s.destination.GetName(), kind.PlatformIdentity, nil)
			}
		}
	}
}

func (s *EgressService) mintBorderJWT(ctx context.Context, destination, audience string) (string, time.Time, error) {
	if s.node == nil {
		return "", time.Time{}, errors.New("egress service has no node attached for STS minting")
	}
	biscuitBytes := CallerBiscuitFromContext(ctx)
	if len(biscuitBytes) == 0 {
		biscuitBytes = s.node.GetIdentity()
	}
	resp, err := s.node.MintBorderJWT(ctx, biscuitBytes, destination, audience)
	if err != nil {
		return "", time.Time{}, err
	}
	var exp time.Time
	if resp.GetExpireTime().IsValid() {
		exp = resp.GetExpireTime().AsTime()
	}
	return resp.GetJwt(), exp, nil
}

func (s *EgressService) Info() *api.ServiceInfo { return s.info }
func (s *EgressService) Handler() http.Handler  { return s.handler }
func (s *EgressService) Teardown() error        { return nil }

// SetExchanger overrides the CloudTokenExchanger on s (used by tests and custom brokers).
func (s *EgressService) SetExchanger(ex CloudTokenExchanger) {
	s.exchanger = ex
	s.isStaticSecret = false
}

// Init builds the reverse proxy and confirms the named credential is
// readable, so a destination whose credential the platform did not deliver is
// refused here, visibly, instead of answering 502 to every request.
func (s *EgressService) Init(ctx context.Context) error {
	if api.EgressStaticSecret(s.destination) != "" {
		if _, err := s.credential(); err != nil {
			return err
		}
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(s.target)
			if s.destination.GetPreserveHost() {
				pr.Out.Host = s.destination.GetName()
			} else {
				pr.Out.Host = s.target.Host
			}
			// What the caller sent authenticated it to the node, and what the
			// node knows about the caller is for policy; none of it is for the
			// destination, which sees the node's own credential only.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
			for name := range pr.Out.Header {
				if strings.HasPrefix(name, "X-Sam-") || strings.HasPrefix(name, "X-Forwarded-") || name == api.HeaderPeerID {
					pr.Out.Header.Del(name)
				}
			}
			if auth, ok := pr.In.Context().Value(egressAuthKey{}).(string); ok && auth != "" {
				pr.Out.Header.Set("Authorization", auth)
			}
			if s.destination.GetForwardContext() {
				if ec, ok := pr.In.Context().Value(egressContextKey{}).(egressCallerContext); ok {
					if ec.principal != "" {
						pr.Out.Header.Set(api.HeaderSamPrincipal, ec.principal)
					}
					if len(ec.roles) > 0 {
						pr.Out.Header.Set(api.HeaderSamRoles, strings.Join(ec.roles, ","))
					}
					if ec.task != "" {
						pr.Out.Header.Set(api.HeaderSamTask, ec.task)
					}
				}
			}
		},
	}
	s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect || strings.EqualFold(r.Header.Get("Upgrade"), HeaderSamTunnelUpgrade) {
			reqPort := s.port()
			if pStr := r.Header.Get(HeaderSamEgressPort); pStr != "" {
				if p, err := strconv.Atoi(pStr); err == nil {
					reqPort = p
				}
			}
			s.ServeTunnel(r.Context(), w, r, reqPort)
			return
		}
		if s.destination.GetMode() == api.EgressMode_EGRESS_MODE_TCP {
			recordEgressDecision(s.info.Name, egressOutcomeDeny)
			refuse(w, http.StatusForbidden, "egress destination is configured for TCP tunnel mode only", proxyStatusDenied)
			return
		}
		s.serveInspectedEgress(w, r, proxy)
	})
	return nil
}

type egressAuthKey struct{}

func (s *EgressService) extractCallerContext(ctx context.Context) egressCallerContext {
	var ec egressCallerContext
	if s.node != nil {
		if pid, err := s.node.localPeerID(); err == nil {
			ec.actorNode = pid.String()
		}
	}
	rawBiscuit := CallerBiscuitFromContext(ctx)
	if len(rawBiscuit) == 0 && s.node != nil {
		rawBiscuit = s.node.GetIdentity()
	}
	if len(rawBiscuit) == 0 {
		return ec
	}
	if s.node != nil {
		if claims, err := s.node.VerifyLocalBiscuit(rawBiscuit); err == nil {
			ec.principal = claims.Principal()
			ec.roles = claims.Roles
			if claims.ActorNodePeerID != "" {
				ec.actorNode = claims.ActorNodePeerID
			}
			ec.task = claims.InnermostTaskName()
			ec.rules = claims.TaskRules
			return ec
		}
	}
	return ec
}

func (s *EgressService) resolveAuthorization(ctx context.Context) (string, egressCallerContext, error) {
	ec := s.extractCallerContext(ctx)
	if s.exchanger == nil {
		return "", ec, nil
	}
	tok, _, err := s.exchanger.Exchange(ctx, ec.principal, ec.rules)
	if err != nil {
		return "", ec, err
	}
	if tok == "" {
		return "", ec, nil
	}
	if s.isStaticSecret {
		if user, pass, ok := strings.Cut(tok, ":"); ok {
			return authorizationFor(user, pass), ec, nil
		}
	}
	return authorizationFor("", tok), ec, nil
}

// credential reads the named file under the secrets directory and renders it
// as an Authorization value: "TOKEN" as Bearer, "user:pass" as Basic, the
// forms target_auth_path accepts.
func (s *EgressService) credential() (string, error) {
	name := api.EgressStaticSecret(s.destination)
	data, err := os.ReadFile(filepath.Join(s.secretsDir, name))
	if err != nil {
		return "", fmt.Errorf("credential %q: %w (put the file in %s)", name, errors.Unwrap(err), s.secretsDir)
	}
	cred := strings.TrimSpace(string(data))
	if cred == "" {
		return "", fmt.Errorf("credential %q is empty", name)
	}
	if user, pass, ok := strings.Cut(cred, ":"); ok {
		return authorizationFor(user, pass), nil
	}
	return authorizationFor("", cred), nil
}

// port is the destination port: explicit in the target URL, or the scheme's.
func (s *EgressService) port() int {
	if p := s.target.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if s.target.Scheme == "http" {
		return 80
	}
	return 443
}

// sameAssignment reports whether the service already serves d as written.
func (s *EgressService) sameAssignment(d *api.EgressDestination) bool {
	return proto.Equal(s.destination, d)
}

// egressFactsFor is the host and port an egress request will be sent to,
// for the authorizer; nil for a service of another type.
func egressFactsFor(svc Service) *EgressFacts {
	es, ok := svc.(*EgressService)
	if !ok {
		return nil
	}
	return &EgressFacts{Host: es.info.Name, Port: es.port()}
}

// syncEgressAssignments makes the registry's egress services match what the
// control plane assigned to this node: new and changed destinations are
// registered, withdrawn ones unregistered. One assignment that cannot be
// served (a credential the platform did not deliver) is reported and the
// rest are still applied.
func (n *SamNode) syncEgressAssignments(ctx context.Context, controlPlaneURL string) error {
	token := n.GetIdentity()
	if len(token) == 0 {
		return errors.New("node has no identity token to fetch egress assignments")
	}
	resp, err := controlPlaneClient(controlPlaneURL).FetchEgress(ctx, token)
	if errors.Is(err, cpclient.ErrNotFound) {
		// A control plane predating egress destinations assigns none; the
		// node keeps whatever it serves and does not report an error.
		logger.Debugf("[Egress] control plane %s has no /egress endpoint; no destinations assigned", controlPlaneURL)
		return nil
	}
	if err != nil {
		return err
	}
	return n.applyEgressAssignments(ctx, resp.GetEgress())
}

func (n *SamNode) applyEgressAssignments(ctx context.Context, assigned []*api.EgressDestination) error {
	if n.services == nil {
		// Before Start there is no registry to reconcile against; Start
		// applies what arrived last.
		n.pendingEgressMu.Lock()
		n.pendingEgress = assigned
		n.pendingEgressMu.Unlock()
		return nil
	}
	var errs []error
	var registered, withdrawn, unchanged int
	wanted := make(map[string]bool, len(assigned))
	for _, d := range assigned {
		if d == nil {
			continue
		}
		wanted[d.GetName()] = true
		if existing, ok := n.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, d.GetName()); ok {
			if es, ok := existing.(*EgressService); ok && es.sameAssignment(d) {
				unchanged++
				continue
			}
		}
		svc, err := newEgressServiceForNode(n, d, n.config.SecretsDir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := n.services.Register(ctx, svc); err != nil {
			errs = append(errs, fmt.Errorf("egress %s: %w", d.GetName(), err))
			continue
		}
		registered++
		logger.Infof("[Egress] Serving egress://%s -> %s (assigned by the control plane)", d.GetName(), api.EgressTargetURL(d))
	}
	for _, info := range n.services.List(api.ServiceType_SERVICE_TYPE_EGRESS) {
		if !wanted[info.GetName()] {
			if err := n.services.Unregister(ctx, info.GetName()); err != nil {
				errs = append(errs, err)
			} else {
				withdrawn++
				logger.Infof("[Egress] Withdrawn egress://%s (no longer assigned)", info.GetName())
			}
		}
	}
	// One line per sync that changed something or failed, so "why is my
	// destination not served" has an answer in the log; a quiet sync is debug.
	summary := fmt.Sprintf("[Egress] Assignments: %d assigned, %d registered, %d unchanged, %d withdrawn, %d refused", len(assigned), registered, unchanged, withdrawn, len(errs))
	if registered+withdrawn+len(errs) > 0 {
		logger.Infof("%s", summary)
	} else {
		logger.Debugf("%s", summary)
	}
	recordEgressAssignment("registered", registered)
	recordEgressAssignment("withdrawn", withdrawn)
	recordEgressAssignment("refused", len(errs))
	return errors.Join(errs...)
}

// applyPendingEgress registers the assignments that arrived before the
// registry existed. Called by Start once it does.
func (n *SamNode) applyPendingEgress(ctx context.Context) {
	n.pendingEgressMu.Lock()
	pending := n.pendingEgress
	n.pendingEgress = nil
	n.pendingEgressMu.Unlock()
	if len(pending) == 0 {
		return
	}
	if err := n.applyEgressAssignments(ctx, pending); err != nil {
		logger.Warnf("[Egress] applying assignments received before start: %v", err)
	}
}

// handleLocalEgress serves /egress/{host}/{path} on the local API: a client
// of this node asks for a destination this node serves. The caller is this
// node, so its own credential is evaluated, with the request's method and
// path and the destination's host and port, as on the mesh datapath. The
// client's Authorization was for the node and does not travel further.
func handleLocalEgress(node *SamNode, w http.ResponseWriter, r *http.Request) {
	if hasDotSegment(r.URL.Path) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	host, upstreamPath, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/egress/"), "/")
	host = api.NormalizeMeshHost(host)
	if host == "" {
		http.Error(w, "Usage: /egress/<destination>/<path>", http.StatusBadRequest)
		return
	}
	svc, ok := node.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, host)
	if !ok || svc.Handler() == nil {
		recordEgressDecision(host, egressOutcomeNotAssigned)
		refuse(w, http.StatusNotFound, fmt.Sprintf("no egress destination %q is assigned to this node", host), proxyStatusDestinationNotFound)
		return
	}
	identity := node.GetRequestIdentity(r.Context())
	if len(identity) == 0 {
		http.Error(w, "node has no credential yet", http.StatusServiceUnavailable)
		return
	}
	target := api.EgressServicePrefix + host
	reqCtx := RequestContext{
		PeerID:   node.Host.ID(),
		Protocol: "local-api",
		Target:   target,
		HTTP:     &HTTPRequestFacts{Method: r.Method, Path: "/" + upstreamPath},
		Egress:   egressFactsFor(svc),
		Local:    true,
	}
	if err := node.VerifyBiscuitToken(identity, reqCtx); err != nil {
		recordEgressDecision(host, egressOutcomeDeny)
		refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusDenied)
		return
	}
	recordEgressDecision(host, egressOutcomeAllow)
	r.Header.Del(api.HeaderSamBiscuit)
	r.Header.Set(api.HeaderPeerID, node.Host.ID().String())
	r.URL.Path = "/" + upstreamPath
	r.URL.RawPath = ""
	svc.Handler().ServeHTTP(w, r.WithContext(WithCallerBiscuit(r.Context(), identity)))
}
