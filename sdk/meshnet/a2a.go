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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/node"
	"github.com/libp2p/go-libp2p/core/peer"
)

// A2AOptions configures an in-process A2A service registered on a Server.
type A2AOptions struct {
	// Name is the service name published under a2a://<Name>. Required.
	Name string
	// Description is advertised in system://mesh.catalog discovery responses.
	Description string
	// Public exposes the service on external router HTTP ingress
	// (/ingress/<peer_id>/a2a/<Name>) in addition to private mesh P2P.
	Public bool
	// IngressAuth selects edge Biscuit verification (default) or passthrough
	// when Public is true.
	IngressAuth api.IngressAuthMode
	// IngressAllow optionally restricts which attested principals ("email:*",
	// "user:*", "group:*", "idp_role:*", "node:*") may invoke the service in
	// INGRESS_AUTH_MODE_EDGE.
	IngressAllow []string
	// NoAnnounce skips directory announcements while still serving streams from
	// peers that dial this PeerID directly. Because no router holds a directory
	// route for an unannounced service, Endpoints.PublicURL is always nil when
	// NoAnnounce is true (even if Public is also set).
	NoAnnounce bool
}

// Endpoints holds the in-memory listeners and canonical URLs for an A2A service
// registered via Server.ListenA2A.
type Endpoints struct {
	// PrivateListener delivers HTTP requests from authenticated mesh peers over
	// /libp2p-http. Always non-nil.
	PrivateListener net.Listener
	// PrivateURL is http://agentmesh.local/mesh/<peer_id>/a2a/<name>.
	PrivateURL *url.URL
	// PublicListener delivers external HTTP requests forwarded by enrolled
	// routers over /mesh/ingress/1.0.0. Non-nil iff A2AOptions.Public is true.
	PublicListener net.Listener
	// PublicURL is <router_ingress_url>/<peer_id>/a2a/<name> when Public is
	// true, NoAnnounce is false, the hub's policy ceiling admitted the ingress
	// announcement, and at least one router in the catalog advertises an
	// ingress_url; nil otherwise.
	PublicURL *url.URL
	// Close unregisters the service, withdraws its directory keys, and closes
	// PrivateListener and PublicListener.
	Close func() error
}

type meshnetAddr string

func (a meshnetAddr) Network() string { return "meshnet" }
func (a meshnetAddr) String() string  { return string(a) }

type inprocListener struct {
	addr   meshnetAddr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newInprocListener(label string) *inprocListener {
	return &inprocListener{
		addr:   meshnetAddr(label),
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (l *inprocListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case c := <-l.conns:
		return c, nil
	}
}

func (l *inprocListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *inprocListener) Addr() net.Addr { return l.addr }

func (l *inprocListener) enqueue(ctx context.Context, c net.Conn) error {
	select {
	case <-l.closed:
		_ = c.Close()
		return net.ErrClosed
	case <-ctx.Done():
		_ = c.Close()
		return ctx.Err()
	case l.conns <- c:
		return nil
	}
}

type trackedConn struct {
	net.Conn
	local   net.Addr
	remote  net.Addr
	onClose func()
	once    sync.Once
}

func (c *trackedConn) LocalAddr() net.Addr  { return c.local }
func (c *trackedConn) RemoteAddr() net.Addr { return c.remote }

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

type meshnetA2AService struct {
	s             *Server
	name          string
	description   string
	noAnnounce    bool
	ingress       *api.ServiceIngress
	privateLn     *inprocListener
	publicLn      *inprocListener
	privateURL    *url.URL
	ingressActive atomic.Bool
}

var (
	_ node.Service              = (*meshnetA2AService)(nil)
	_ node.UnannouncedService   = (*meshnetA2AService)(nil)
	_ node.IngressStateObserver = (*meshnetA2AService)(nil)
	_ node.ExternalIngressGate  = (*meshnetA2AService)(nil)
)

func (svc *meshnetA2AService) Info() *api.ServiceInfo {
	var ing *api.ServiceIngress
	if svc.ingress != nil {
		ing = &api.ServiceIngress{
			AuthMode: svc.ingress.GetAuthMode(),
			Allow:    slices.Clone(svc.ingress.GetAllow()),
		}
	}
	return &api.ServiceInfo{
		Type:        api.ServiceType_SERVICE_TYPE_A2A,
		Name:        svc.name,
		Description: svc.description,
		Ingress:     ing,
	}
}

func (svc *meshnetA2AService) Init(context.Context) error { return nil }

func (svc *meshnetA2AService) NoAnnounce() bool { return svc.noAnnounce }

func (svc *meshnetA2AService) SetIngressActive(active bool) {
	svc.ingressActive.Store(active)
}

func (svc *meshnetA2AService) ExternalIngressAllowed() bool {
	if svc.publicLn == nil {
		return false
	}
	if svc.noAnnounce {
		return true
	}
	return svc.ingressActive.Load()
}

func (svc *meshnetA2AService) Teardown() error {
	_ = svc.privateLn.Close()
	if svc.publicLn != nil {
		_ = svc.publicLn.Close()
	}
	return nil
}

func (svc *meshnetA2AService) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, externalIngress := svc.s.callerInfoFromRequest(r)
		targetLn := svc.privateLn
		if externalIngress {
			if !svc.ExternalIngressAllowed() {
				http.Error(w, "Service not found", http.StatusNotFound)
				return
			}
			targetLn = svc.publicLn
		}
		roots := svc.s.candidateCardRoots(svc.name)
		svc.s.deliverHTTP(w, r, targetLn, caller, svc.s.relativizeAgentCardMultiRoot(svc.name, roots))
	})
}

// WhoIs returns the cryptographically verified mesh identity of the caller
// behind an active HTTP request served on PrivateListener or PublicListener,
// keyed by http.Request.RemoteAddr. Because connections are in-memory net.Pipe
// pairs tracked in Server's active table, WhoIs cannot be spoofed by HTTP
// headers.
func (s *Server) WhoIs(remoteAddr string) (*CallerInfo, bool) {
	v, ok := s.activeConns.Load(remoteAddr)
	if !ok {
		return nil, false
	}
	info, ok := v.(*CallerInfo)
	if !ok || info == nil {
		return nil, false
	}
	return &CallerInfo{
		PeerID:    info.PeerID,
		Principal: info.Principal,
		Roles:     slices.Clone(info.Roles),
		Labels:    maps.Clone(info.Labels),
		Task:      info.Task,
	}, true
}

// ListenA2A registers an in-process A2A service on the running Server, announces
// it to the mesh directory (unless NoAnnounce is true), and returns the
// in-memory listeners and canonical URLs to pass to http.Server.Serve.
func (s *Server) ListenA2A(ctx context.Context, opts A2AOptions) (*Endpoints, error) {
	if !s.isRunning() || s.node.Services() == nil {
		return nil, errors.New("meshnet: Server is not running (call Up first)")
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return nil, errors.New("meshnet: A2AOptions.Name is required")
	}
	if err := api.ValidateServiceFormat(api.ServiceTypeStringA2A + "://" + name); err != nil {
		return nil, fmt.Errorf("meshnet: invalid A2A service name %q: %w", name, err)
	}
	if s.node.IsServiceRegistered(name) {
		return nil, fmt.Errorf("meshnet: A2A service %q is already registered", name)
	}

	var ing *api.ServiceIngress
	if opts.Public {
		mode := opts.IngressAuth
		if mode == api.IngressAuthMode_INGRESS_AUTH_MODE_UNSPECIFIED {
			mode = api.IngressAuthMode_INGRESS_AUTH_MODE_EDGE
		}
		allow := make([]string, len(opts.IngressAllow))
		for i, raw := range opts.IngressAllow {
			if prefix, val, ok := strings.Cut(raw, ":"); ok && prefix == api.FactNode {
				if id, err := peer.Decode(val); err == nil {
					allow[i] = api.FactNode + ":" + id.String()
					continue
				}
			}
			allow[i] = raw
		}
		ing = &api.ServiceIngress{
			AuthMode: mode,
			Allow:    allow,
		}
		if err := api.ValidateServiceIngress(api.ServiceType_SERVICE_TYPE_A2A, ing); err != nil {
			return nil, fmt.Errorf("meshnet: service %q: %w", name, err)
		}
	}

	privURL, err := url.Parse(fmt.Sprintf("http://agentmesh.local/mesh/%s/%s/%s", s.peerID.String(), api.ServiceTypeStringA2A, name))
	if err != nil {
		return nil, err
	}

	privLn := newInprocListener("meshnet:private:a2a:" + name)
	var pubLn *inprocListener
	if opts.Public {
		pubLn = newInprocListener("meshnet:public:a2a:" + name)
	}

	svc := &meshnetA2AService{
		s:           s,
		name:        name,
		description: opts.Description,
		noAnnounce:  opts.NoAnnounce,
		ingress:     ing,
		privateLn:   privLn,
		publicLn:    pubLn,
		privateURL:  privURL,
	}

	if err := s.node.Services().Register(ctx, svc); err != nil {
		_ = svc.Teardown()
		return nil, fmt.Errorf("meshnet: register A2A service %q: %w", name, err)
	}

	// Announce this member's peer record immediately alongside its service keys
	// so peers discovering the new service can resolve its addresses without
	// waiting for the initial reprovide delay.
	if !opts.NoAnnounce && s.node.Directory != nil {
		peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := s.node.Directory.Provide(peerCtx, api.PeerKey(s.peerID), ""); err != nil && ctx.Err() == nil {
			s.log().Debug("peer directory announcement skipped or failed during ListenA2A",
				"peer_id", s.peerID.String(),
				"service", name,
				"error", err,
			)
		}
		cancel()
	}

	var pubURL *url.URL
	if opts.Public && !opts.NoAnnounce && svc.ingressActive.Load() {
		pubURL = s.computePublicURL(name)
	}

	var pubNetLn net.Listener
	if pubLn != nil {
		pubNetLn = pubLn
	}

	var closeOnce sync.Once
	closeFn := func() error {
		closeOnce.Do(func() {
			uCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if uErr := s.node.UnregisterService(uCtx, name); uErr != nil {
				s.log().Warn("failed unregistering A2A service", "service", name, "error", uErr)
			}
			_ = svc.Teardown()
		})
		return nil
	}

	return &Endpoints{
		PrivateListener: privLn,
		PrivateURL:      privURL,
		PublicListener:  pubNetLn,
		PublicURL:       pubURL,
		Close:           closeFn,
	}, nil
}

func (s *Server) computePublicURL(name string) *url.URL {
	if s.node == nil {
		return nil
	}
	base := s.node.PreferredRouterIngressURL()
	if base == "" {
		return nil
	}
	raw := fmt.Sprintf("%s/%s/%s/%s", base, s.peerID.String(), api.ServiceTypeStringA2A, name)
	u, err := url.Parse(raw)
	if err != nil {
		s.log().Warn("failed parsing router ingress URL", "service", name, "raw_url", raw, "error", err)
		return nil
	}
	return u
}

func (s *Server) candidateCardRoots(serviceName string) []string {
	roots := []string{"/mesh/" + s.peerID.String() + "/" + api.ServiceTypeStringA2A + "/" + serviceName}
	if pubURL := s.computePublicURL(serviceName); pubURL != nil {
		if p := strings.TrimSuffix(pubURL.EscapedPath(), "/"); p != "" && !slices.Contains(roots, p) {
			roots = append(roots, p)
		}
	}
	if s.node != nil {
		for _, base := range s.node.RouterIngressURLs() {
			u, err := url.Parse(base)
			if err != nil {
				s.log().Debug("ignoring invalid router ingress base URL when computing card roots", "base_url", base, "error", err)
				continue
			}
			p := strings.TrimSuffix(u.EscapedPath(), "/") + "/" + s.peerID.String() + "/" + api.ServiceTypeStringA2A + "/" + serviceName
			if !slices.Contains(roots, p) {
				roots = append(roots, p)
			}
		}
	}
	slices.SortStableFunc(roots, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	roots = append(roots, "")
	return roots
}

func (s *Server) deliverHTTP(
	w http.ResponseWriter,
	r *http.Request,
	ln *inprocListener,
	caller *CallerInfo,
	modifyResp func(*http.Response) error,
) {
	if ln == nil {
		http.Error(w, "Service listener unavailable", http.StatusNotFound)
		return
	}

	seq := s.nextConnSeq.Add(1)
	remoteKey := fmt.Sprintf("meshnet:%s#%d", caller.PeerID, seq)
	s.activeConns.Store(remoteKey, caller)

	clientSide, serverSide := net.Pipe()
	serverConn := &trackedConn{
		Conn:   serverSide,
		local:  ln.Addr(),
		remote: meshnetAddr(remoteKey),
		onClose: func() {
			s.activeConns.Delete(remoteKey)
		},
	}

	var dialOnce sync.Once
	dialUsed := false
	tr := &http.Transport{
		DisableKeepAlives:  true,
		DisableCompression: true,
		DialContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
			var conn net.Conn
			var err error
			dialOnce.Do(func() {
				dialUsed = true
				if eErr := ln.enqueue(dCtx, serverConn); eErr != nil {
					_ = clientSide.Close()
					s.activeConns.Delete(remoteKey)
					err = eErr
					return
				}
				conn = clientSide
			})
			if err != nil {
				return nil, err
			}
			if conn == nil {
				return nil, errors.New("in-process connection already consumed")
			}
			return conn, nil
		},
	}
	defer func() {
		tr.CloseIdleConnections()
		if !dialUsed {
			_ = clientSide.Close()
			_ = serverConn.Close()
			s.activeConns.Delete(remoteKey)
		}
	}()

	targetURL, _ := url.Parse("http://meshnet.internal")
	proxy := &httputil.ReverseProxy{
		Transport:      tr,
		FlushInterval:  -1,
		ModifyResponse: modifyResp,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del(api.HeaderMeshNoTrailingSlash)
		},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
			if errors.Is(err, net.ErrClosed) {
				http.Error(rw, "Service listener closed", http.StatusServiceUnavailable)
				return
			}
			http.Error(rw, fmt.Sprintf("Bad Gateway: %v", err), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) callerInfoFromRequest(r *http.Request) (*CallerInfo, bool) {
	externalIngress := r.Header.Get(api.HeaderMeshIngress) != ""
	caller := &CallerInfo{
		PeerID: r.Header.Get(api.HeaderPeerID),
	}
	if raw := node.CallerBiscuitFromContext(r.Context()); len(raw) > 0 && s.node != nil {
		if claims, err := s.node.VerifyLocalBiscuit(raw); err == nil && claims != nil {
			caller.Principal = claims.Principal()
			caller.Roles = slices.Clone(claims.Roles)
			caller.Labels = maps.Clone(claims.Labels)
			caller.Task = claims.InnermostTaskName()
			if externalIngress {
				if actor := cmp.Or(claims.ActorNodePeerID, claims.NodePeerID); actor != "" {
					if id, pErr := peer.Decode(actor); pErr == nil {
						caller.PeerID = id.String()
					} else {
						caller.PeerID = actor
					}
				}
			}
		}
	}
	if caller.Principal == "" {
		caller.Principal = r.Header.Get(api.HeaderMeshPrincipal)
	}
	if caller.Task == "" {
		caller.Task = r.Header.Get(api.HeaderMeshTask)
	}
	return caller, externalIngress
}

const (
	a2aAgentCardEscapedPath = "/.well-known/agent-card.json"
	maxAgentCardBytes       = 1 << 20
)

func (s *Server) relativizeAgentCardMultiRoot(service string, candidateRoots []string) func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.Request == nil || resp.Request.Method != http.MethodGet ||
			resp.Request.URL.EscapedPath() != a2aAgentCardEscapedPath ||
			resp.StatusCode != http.StatusOK {
			return nil
		}
		if enc := resp.Header.Get("Content-Encoding"); enc != "" {
			s.log().Warn("A2A agent card is compressed; relaying interface URLs unchanged", "service", service, "encoding", enc)
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentCardBytes+1))
		if err != nil {
			return fmt.Errorf("read agent card of %q: %w", service, err)
		}
		if len(raw) > maxAgentCardBytes {
			s.log().Warn("A2A agent card exceeds size limit; relaying interface URLs unchanged", "service", service, "max_bytes", maxAgentCardBytes)
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(raw), resp.Body), resp.Body}
			return nil
		}
		_ = resp.Body.Close()
		out, err := relativizeCardJSON(raw, candidateRoots)
		if err != nil {
			s.log().Warn("A2A agent card relayed with interface URLs unchanged", "service", service, "error", err)
			out = raw
		}
		resp.Body = io.NopCloser(bytes.NewReader(out))
		resp.ContentLength = int64(len(out))
		resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
		return nil
	}
}

func relativizeCardJSON(raw []byte, roots []string) ([]byte, error) {
	var card map[string]json.RawMessage
	if err := json.Unmarshal(raw, &card); err != nil {
		return nil, fmt.Errorf("card is not a JSON object: %w", err)
	}
	ifacesRaw, ok := card["supportedInterfaces"]
	if !ok {
		return raw, nil
	}
	var ifaces []map[string]json.RawMessage
	if err := json.Unmarshal(ifacesRaw, &ifaces); err != nil {
		return nil, fmt.Errorf("supportedInterfaces is not a list of objects: %w", err)
	}
	for _, iface := range ifaces {
		var u, binding string
		if iface == nil || json.Unmarshal(iface["url"], &u) != nil || json.Unmarshal(iface["protocolBinding"], &binding) != nil ||
			!isHTTPBinding(a2a.TransportProtocol(binding)) {
			continue
		}
		for _, root := range roots {
			rel, matched := relativeToRoot(u, root)
			if !matched {
				continue
			}
			enc, err := json.Marshal(rel)
			if err != nil {
				return nil, err
			}
			iface["url"] = enc
			break
		}
	}
	enc, err := json.Marshal(ifaces)
	if err != nil {
		return nil, err
	}
	card["supportedInterfaces"] = enc
	return json.Marshal(card)
}

func relativeToRoot(raw, root string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" {
		return "", false
	}
	p := u.EscapedPath()
	var rest string
	switch {
	case p == root || p == root+"/":
	case strings.HasPrefix(p, root+"/"):
		rest = strings.TrimPrefix(p, root+"/")
	default:
		return "", false
	}
	if api.HasDotSegment(rest) {
		return "", false
	}
	if u.RawQuery != "" {
		rest += "?" + u.RawQuery
	}
	return rest, true
}

func isHTTPBinding(binding a2a.TransportProtocol) bool {
	switch strings.ToUpper(string(binding)) {
	case string(a2a.TransportProtocolJSONRPC), string(a2a.TransportProtocolHTTPJSON):
		return true
	}
	return false
}
