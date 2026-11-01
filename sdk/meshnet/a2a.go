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
	"encoding/base64"
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
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	gostream "github.com/libp2p/go-libp2p-gostream"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	a2aAgentCardPath  = ".well-known/agent-card.json"
	maxAgentCardBytes = 1 << 20
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
	// peers that dial this PeerID directly.
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
	// true, the hub's policy ceiling admitted the ingress announcement, and at
	// least one router in the catalog advertises an ingress_url; nil otherwise.
	PublicURL *url.URL
	// Close unregisters the service, withdraws its directory keys, and closes
	// PrivateListener and PublicListener.
	Close func() error
}

type a2aEntry struct {
	name        string
	description string
	noAnnounce  bool
	ingress     *api.ServiceIngress
	privateLn   *inprocListener
	publicLn    *inprocListener
	privateURL  *url.URL

	mu           sync.RWMutex
	publicActive bool
	publicURL    *url.URL
}

func (e *a2aEntry) setPublicState(active bool, pubURL *url.URL) {
	e.mu.Lock()
	e.publicActive = active
	e.publicURL = pubURL
	e.mu.Unlock()
}

func (e *a2aEntry) getPublicState() (bool, *url.URL) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.publicActive, e.publicURL
}

func (e *a2aEntry) serviceInfo() *api.ServiceInfo {
	active, _ := e.getPublicState()
	var ing *api.ServiceIngress
	if active && e.ingress != nil {
		ing = &api.ServiceIngress{
			AuthMode: e.ingress.GetAuthMode(),
			Allow:    slices.Clone(e.ingress.GetAllow()),
		}
	}
	return &api.ServiceInfo{
		Type:        api.ServiceType_SERVICE_TYPE_A2A,
		Name:        e.name,
		Description: e.description,
		Ingress:     ing,
	}
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
	if s.host == nil || s.dir == nil {
		return nil, errors.New("meshnet: Server is not running (call Up first)")
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return nil, errors.New("meshnet: A2AOptions.Name is required")
	}
	if err := api.ValidateServiceFormat(api.ServiceTypeStringA2A + "://" + name); err != nil {
		return nil, fmt.Errorf("meshnet: invalid A2A service name %q: %w", name, err)
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

	privURL, err := url.Parse(s.localMeshURL(s.peerID, api.ServiceTypeStringA2A, name))
	if err != nil {
		return nil, err
	}

	privLn := newInprocListener("meshnet:private:a2a:" + name)
	var pubLn *inprocListener
	if opts.Public {
		pubLn = newInprocListener("meshnet:public:a2a:" + name)
	}

	entry := &a2aEntry{
		name:         name,
		description:  opts.Description,
		noAnnounce:   opts.NoAnnounce,
		ingress:      ing,
		privateLn:    privLn,
		publicLn:     pubLn,
		privateURL:   privURL,
		publicActive: opts.Public,
	}

	s.a2aMu.Lock()
	if _, exists := s.a2aServices[name]; exists {
		s.a2aMu.Unlock()
		return nil, fmt.Errorf("meshnet: A2A service %q is already registered", name)
	}
	s.a2aServices[name] = entry
	s.a2aMu.Unlock()

	if !opts.NoAnnounce {
		s.announceA2AEntry(ctx, entry)
		peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = s.dir.provide(peerCtx, api.PeerKey(s.peerID), "")
		cancel()
	} else if opts.Public {
		entry.setPublicState(true, s.computePublicURL(name))
	}

	_, pubURL := entry.getPublicState()
	var pubNetLn net.Listener
	if pubLn != nil {
		pubNetLn = pubLn
	}

	var closeOnce sync.Once
	closeFn := func() error {
		closeOnce.Do(func() {
			s.unregisterA2A(name, entry)
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
	urls := s.routerIngressURLs()
	if len(urls) == 0 {
		return nil
	}
	raw := fmt.Sprintf("%s/%s/%s/%s", urls[0], s.peerID.String(), api.ServiceTypeStringA2A, name)
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return u
}

func (s *Server) announceA2AEntry(ctx context.Context, entry *a2aEntry) {
	target := api.ServiceTypeStringA2A + "://" + entry.name
	nameKey, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, entry.name)
	if err != nil {
		return
	}
	typeKey, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, "")
	if err != nil {
		return
	}

	if entry.ingress != nil {
		ingCtx, ingCancel := context.WithTimeout(ctx, 5*time.Second)
		err := s.dir.provideWithIngress(ingCtx, nameKey, target, entry.ingress)
		ingCancel()
		if err == nil {
			pubURL := s.computePublicURL(entry.name)
			entry.setPublicState(true, pubURL)
			if pubURL != nil {
				s.log().Info("announced public A2A ingress endpoint", "service", target, "public_url", pubURL.String())
			}
		} else {
			entry.setPublicState(false, nil)
			if ctx.Err() == nil {
				s.log().Warn("external ingress announcement refused; falling back to internal-only announcement",
					"service", target,
					"error", err,
				)
			}
			fbCtx, fbCancel := context.WithTimeout(ctx, 5*time.Second)
			if fbErr := s.dir.provide(fbCtx, nameKey, target); fbErr != nil && ctx.Err() == nil {
				s.log().Warn("internal fallback announcement failed", "service", target, "error", fbErr)
			}
			fbCancel()
		}
	} else {
		nameCtx, nameCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := s.dir.provide(nameCtx, nameKey, target); err != nil && ctx.Err() == nil {
			s.log().Warn("A2A service name announcement failed", "service", target, "error", err)
		}
		nameCancel()
	}

	typeCtx, typeCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := s.dir.provide(typeCtx, typeKey, target); err != nil && ctx.Err() == nil {
		s.log().Warn("A2A service type announcement failed", "service", target, "error", err)
	}
	typeCancel()
}

func (s *Server) unregisterA2A(name string, entry *a2aEntry) {
	s.a2aMu.Lock()
	cur, ok := s.a2aServices[name]
	if ok && cur == entry {
		delete(s.a2aServices, name)
	}
	stillHasA2A := len(s.a2aServices) > 0
	s.a2aMu.Unlock()

	_ = entry.privateLn.Close()
	if entry.publicLn != nil {
		_ = entry.publicLn.Close()
	}

	if ok && cur == entry && !entry.noAnnounce && s.dir != nil {
		wCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if nameKey, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, name); err == nil {
			_ = s.dir.withdraw(wCtx, nameKey)
		}
		if !stillHasA2A {
			if typeKey, err := api.ServiceKey(api.ServiceType_SERVICE_TYPE_A2A, ""); err == nil {
				_ = s.dir.withdraw(wCtx, typeKey)
			}
		}
	}
}

func (s *Server) getA2AEntry(name string) (*a2aEntry, bool) {
	s.a2aMu.RLock()
	defer s.a2aMu.RUnlock()
	e, ok := s.a2aServices[name]
	return e, ok
}

func (s *Server) listA2AEntries() []*a2aEntry {
	s.a2aMu.RLock()
	defer s.a2aMu.RUnlock()
	out := make([]*a2aEntry, 0, len(s.a2aServices))
	for _, e := range s.a2aServices {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b *a2aEntry) int { return cmp.Compare(a.name, b.name) })
	return out
}

func (s *Server) listLocalServiceInfos(typeFilter api.ServiceType) []*api.ServiceInfo {
	if typeFilter != api.ServiceType_SERVICE_TYPE_UNSPECIFIED && typeFilter != api.ServiceType_SERVICE_TYPE_A2A {
		return []*api.ServiceInfo{}
	}
	entries := s.listA2AEntries()
	out := make([]*api.ServiceInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.serviceInfo())
	}
	return out
}

func (s *Server) deliverHTTP(w http.ResponseWriter, r *http.Request, ln *inprocListener, caller *CallerInfo, modifyResp func(*http.Response) error) {
	id := s.nextConnSeq.Add(1)
	remoteAddr := fmt.Sprintf("meshnet-conn-%d", id)
	if caller != nil {
		s.activeConns.Store(remoteAddr, caller)
	}

	clientSide, serverSide := net.Pipe()
	serverConn := &trackedConn{
		Conn:   serverSide,
		local:  ln.Addr(),
		remote: meshnetAddr(remoteAddr),
		onClose: func() {
			s.activeConns.Delete(remoteAddr)
		},
	}
	clientConn := &trackedConn{
		Conn:   clientSide,
		local:  meshnetAddr(remoteAddr),
		remote: ln.Addr(),
		onClose: func() {
			s.activeConns.Delete(remoteAddr)
		},
	}

	var dialOnce sync.Once
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var conn net.Conn
			var err error
			dialOnce.Do(func() {
				if qErr := ln.enqueue(ctx, serverConn); qErr != nil {
					_ = clientConn.Close()
					err = qErr
					return
				}
				conn = clientConn
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
	defer transport.CloseIdleConnections()

	proxy := &httputil.ReverseProxy{
		FlushInterval: -1,
		Transport:     transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			noTrailingSlash := pr.In.Header.Get(api.HeaderMeshNoTrailingSlash) == "true"
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			if pr.Out.URL.Host == "" {
				pr.Out.URL.Host = "agentmesh.local"
			}
			pr.Out.Host = pr.Out.URL.Host
			pr.Out.Header.Del(api.HeaderMeshNoTrailingSlash)
			if noTrailingSlash && pr.Out.URL.Path == "/" {
				pr.Out.URL.Path = "/"
			}
		},
		ModifyResponse: modifyResp,
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, pErr error) {
			s.activeConns.Delete(remoteAddr)
			_ = clientConn.Close()
			_ = serverConn.Close()
			s.log().Warn("local A2A handler delivery failed", "error", pErr)
			http.Error(rw, "Bad Gateway", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) startHTTPServers(ctx context.Context) error {
	privListener, err := gostream.Listen(s.host, "/libp2p-http")
	if err != nil {
		return fmt.Errorf("listen /libp2p-http: %w", err)
	}
	privServer := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler:           s.privateHTTPHandler(),
	}

	gatedRouter := &routerHost{meshHost{Host: s.host, s: s}}
	pubListener, err := gostream.Listen(gatedRouter, api.IngressProtocolID)
	if err != nil {
		_ = privListener.Close()
		return fmt.Errorf("listen %s: %w", api.IngressProtocolID, err)
	}
	pubServer := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler:           s.externalIngressHandler(),
	}

	go func() {
		if sErr := privServer.Serve(privListener); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			s.log().Error("private /libp2p-http server error", "error", sErr)
		}
	}()
	go func() {
		if sErr := pubServer.Serve(pubListener); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			s.log().Error("external ingress server error", "error", sErr)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = privServer.Close()
		_ = privListener.Close()
		_ = pubServer.Close()
		_ = pubListener.Close()
	}()
	return nil
}

func (s *Server) privateHTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if api.HasDotSegment(path) {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		svcTypeStr := strings.ToLower(parts[0])
		svcName := parts[1]
		upstreamPath := ""
		if len(parts) > 2 {
			upstreamPath = parts[2]
		}
		svcType, err := api.ParseServiceType(svcTypeStr)
		if err != nil || svcType == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
			http.Error(w, "Invalid service type", http.StatusBadRequest)
			return
		}

		biscuitB64 := r.Header.Get(api.HeaderMeshBiscuit)
		if biscuitB64 == "" {
			http.Error(w, "Missing X-Mesh-Biscuit header", http.StatusUnauthorized)
			return
		}
		biscuitBytes, err := base64.StdEncoding.DecodeString(biscuitB64)
		if err != nil {
			biscuitBytes, err = identity.DecodeBase64Biscuit(biscuitB64)
			if err != nil {
				http.Error(w, "Invalid X-Mesh-Biscuit encoding", http.StatusBadRequest)
				return
			}
		}

		remotePeer, err := peer.Decode(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Invalid remote peer", http.StatusBadRequest)
			return
		}
		if s.rateLimiter != nil && !s.rateLimiter.Allow(remotePeer.String()) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		target := svcTypeStr + "://" + svcName
		backendPath := "/" + upstreamPath
		// Authorize BEFORE checking whether svcName is registered so an
		// unauthorized peer learns nothing about hosted service names.
		caller, err := s.authorizeInbound(biscuitBytes, remotePeer, target, "/libp2p-http", &httpRequestFacts{
			method: r.Method,
			path:   backendPath,
		})
		if err != nil {
			http.Error(w, "Authorization failed", http.StatusForbidden)
			return
		}

		if svcType != api.ServiceType_SERVICE_TYPE_A2A {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		entry, ok := s.getA2AEntry(svcName)
		if !ok {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}

		for h := range r.Header {
			lower := strings.ToLower(h)
			if lower == "cookie" || strings.HasPrefix(lower, "x-mesh-") {
				delete(r.Header, h)
			}
		}
		r.Header.Set(api.HeaderPeerID, remotePeer.String())
		if caller.Principal != "" {
			r.Header.Set(api.HeaderMeshPrincipal, caller.Principal)
		}
		if len(caller.Roles) > 0 {
			r.Header.Set(api.HeaderMeshRoles, strings.Join(caller.Roles, ","))
		}
		if caller.Task != "" {
			r.Header.Set(api.HeaderMeshTask, caller.Task)
		}

		rewriteInboundRequestPath(r, parts, upstreamPath)
		roots := s.candidateCardRoots(entry)
		s.deliverHTTP(w, r, entry.privateLn, caller, relativizeAgentCardResponse(entry.name, roots))
	})
}

func (s *Server) externalIngressHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if api.HasDotSegment(path) {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		svcTypeStr := strings.ToLower(parts[0])
		svcName := parts[1]
		upstreamPath := ""
		if len(parts) > 2 {
			upstreamPath = parts[2]
		}
		svcType, err := api.ParseServiceType(svcTypeStr)
		if err != nil {
			http.Error(w, "Invalid service type", http.StatusBadRequest)
			return
		}
		if !api.IsInboundServiceType(svcType) {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}

		remotePeer, err := peer.Decode(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Invalid remote peer", http.StatusBadRequest)
			return
		}
		if s.isPeerBanned(remotePeer) {
			http.Error(w, "Peer is revoked", http.StatusForbidden)
			return
		}
		if s.externalIngressLimiter != nil && !s.externalIngressLimiter.Allow(remotePeer.String()) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		routerBiscuitHeader := r.Header.Get(api.HeaderMeshBiscuit)
		if routerBiscuitHeader == "" {
			http.Error(w, "Missing X-Mesh-Biscuit header", http.StatusUnauthorized)
			return
		}
		routerBiscuitBytes, err := identity.DecodeBase64Biscuit(routerBiscuitHeader)
		if err != nil {
			http.Error(w, "Invalid X-Mesh-Biscuit encoding", http.StatusBadRequest)
			return
		}
		routerClaims, err := s.verifyLocalBiscuit(routerBiscuitBytes)
		if err != nil {
			s.log().Warn("router biscuit verification failed on external ingress", "router_peer_id", remotePeer.String(), "error", err)
			http.Error(w, "Router authentication failed", http.StatusForbidden)
			return
		}
		if err := identity.RequireAuthorityBinding(routerClaims.Biscuit, remotePeer); err != nil {
			s.log().Warn("router biscuit binding mismatch on external ingress", "router_peer_id", remotePeer.String(), "error", err)
			http.Error(w, "Router authentication failed", http.StatusForbidden)
			return
		}
		if !slices.Contains(routerClaims.Roles, api.RoleRouter) {
			s.log().Warn("non-router peer attempted external ingress", "peer_id", remotePeer.String())
			http.Error(w, "Forbidden: only enrolled routers may forward external ingress", http.StatusForbidden)
			return
		}

		if svcType != api.ServiceType_SERVICE_TYPE_A2A {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		entry, ok := s.getA2AEntry(svcName)
		if !ok || entry.ingress == nil || entry.publicLn == nil {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		if active, _ := entry.getPublicState(); !active {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}

		effectiveMode := api.EffectiveIngressAuthMode(entry.ingress)
		modeStr, err := api.IngressAuthModeToString(effectiveMode)
		if err != nil {
			http.Error(w, "Unsupported service ingress auth mode", http.StatusForbidden)
			return
		}
		if wireMode := strings.TrimSpace(r.Header.Get(api.HeaderMeshIngress)); wireMode != "" && wireMode != modeStr {
			http.Error(w, "Ingress auth mode mismatch", http.StatusForbidden)
			return
		}

		target := svcTypeStr + "://" + svcName
		backendPath := "/" + upstreamPath
		roots := s.candidateCardRoots(entry)

		if effectiveMode == api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH {
			api.SanitizeExternalIngressHeaders(r.Header, false)
			r.Header.Set(api.HeaderPeerID, remotePeer.String())
			r.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringPassthrough)
			s.log().Info("external ingress border crossing",
				"mode", api.IngressAuthModeStringPassthrough,
				"router_peer_id", remotePeer.String(),
				"target", target,
				"method", r.Method,
				"path", backendPath,
			)
			caller := &CallerInfo{
				PeerID:    remotePeer.String(),
				Principal: "passthrough",
			}
			rewriteInboundRequestPath(r, parts, upstreamPath)
			s.deliverHTTP(w, r, entry.publicLn, caller, relativizeAgentCardResponse(entry.name, roots))
			return
		}

		callerBiscuitHeader := strings.TrimSpace(r.Header.Get(api.HeaderMeshIngressCallerBiscuit))
		if r.Method == http.MethodGet && upstreamPath == a2aAgentCardPath && callerBiscuitHeader == "" {
			api.SanitizeExternalIngressHeaders(r.Header, true)
			r.Header.Set(api.HeaderPeerID, remotePeer.String())
			r.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringEdge)
			s.log().Info("external ingress border crossing",
				"mode", api.IngressAuthModeStringEdge,
				"router_peer_id", remotePeer.String(),
				"principal", "anonymous:agent-card",
				"target", target,
				"method", r.Method,
				"path", backendPath,
			)
			caller := &CallerInfo{
				PeerID:    remotePeer.String(),
				Principal: "anonymous:agent-card",
			}
			rewriteInboundRequestPath(r, parts, upstreamPath)
			s.deliverHTTP(w, r, entry.publicLn, caller, relativizeAgentCardResponse(entry.name, roots))
			return
		}

		if callerBiscuitHeader == "" {
			http.Error(w, "Missing caller credentials on edge ingress request", http.StatusUnauthorized)
			return
		}
		callerBiscuitBytes, err := identity.DecodeBase64Biscuit(callerBiscuitHeader)
		if err != nil {
			http.Error(w, "Invalid caller biscuit encoding", http.StatusBadRequest)
			return
		}
		verifiedCaller, err := s.verifyLocalBiscuit(callerBiscuitBytes)
		if err != nil {
			s.log().Warn("external ingress caller verification failed", "router_peer_id", remotePeer.String(), "target", target, "error", err)
			http.Error(w, "Authorization failed", http.StatusForbidden)
			return
		}

		evalParams, err := s.buildExternalIngressEvalParams(svcTypeStr, svcName, r.Method, backendPath, entry.ingress.GetAllow())
		if err != nil {
			s.log().Warn("failed building external ingress evaluation params", "target", target, "error", err)
			http.Error(w, "Authorization failed", http.StatusForbidden)
			return
		}
		callerRes, err := identity.AuthorizeIngressDelegatedBiscuit(verifiedCaller, evalParams)
		if err != nil {
			s.log().Warn("external ingress authorization denied", "router_peer_id", remotePeer.String(), "target", target, "error", err)
			http.Error(w, "Authorization failed", http.StatusForbidden)
			return
		}

		api.SanitizeExternalIngressHeaders(r.Header, true)
		r.Header.Set(api.HeaderPeerID, remotePeer.String())
		r.Header.Set(api.HeaderMeshIngress, api.IngressAuthModeStringEdge)
		if callerRes.Principal != "" {
			r.Header.Set(api.HeaderMeshPrincipal, callerRes.Principal)
		}
		if len(callerRes.Roles) > 0 {
			r.Header.Set(api.HeaderMeshRoles, strings.Join(callerRes.Roles, ","))
		}
		if callerRes.TaskName != "" {
			r.Header.Set(api.HeaderMeshTask, callerRes.TaskName)
		}

		s.log().Info("external ingress border crossing",
			"mode", api.IngressAuthModeStringEdge,
			"router_peer_id", remotePeer.String(),
			"principal", callerRes.Principal,
			"roles", callerRes.Roles,
			"task", callerRes.TaskName,
			"target", target,
			"method", r.Method,
			"path", backendPath,
		)

		caller := &CallerInfo{
			PeerID:    callerRes.ActorNodeID,
			Principal: callerRes.Principal,
			Roles:     slices.Clone(callerRes.Roles),
			Task:      callerRes.TaskName,
		}
		if caller.PeerID == "" {
			caller.PeerID = remotePeer.String()
		}
		rewriteInboundRequestPath(r, parts, upstreamPath)
		s.deliverHTTP(w, r, entry.publicLn, caller, relativizeAgentCardResponse(entry.name, roots))
	})
}

func (s *Server) buildExternalIngressEvalParams(serviceType, serviceName, method, path string, allow []string) (identity.IngressEvalParams, error) {
	pol, err := s.meshPolicy()
	if err != nil {
		return identity.IngressEvalParams{}, err
	}
	return identity.IngressEvalParams{
		ServiceType:     serviceType,
		ServiceName:     serviceName,
		Method:          method,
		Path:            path,
		TargetFacts:     pol.TargetFacts,
		MeshPolicyRules: pol.MeshRules,
		Allow:           allow,
		Timeout:         s.biscuitTimeout(),
	}, nil
}

func rewriteInboundRequestPath(r *http.Request, parts []string, upstreamPath string) {
	if upstreamPath == "" {
		r.URL.Path = "/"
		if len(parts) == 2 {
			r.Header.Set(api.HeaderMeshNoTrailingSlash, "true")
		}
	} else {
		r.URL.Path = "/" + upstreamPath
	}
	r.URL.RawPath = ""
}

func (s *Server) candidateCardRoots(entry *a2aEntry) []string {
	roots := []string{"/mesh/" + s.peerID.String() + "/" + api.ServiceTypeStringA2A + "/" + entry.name}
	if _, pubURL := entry.getPublicState(); pubURL != nil {
		if p := strings.TrimSuffix(pubURL.EscapedPath(), "/"); p != "" && !slices.Contains(roots, p) {
			roots = append(roots, p)
		}
	}
	for _, base := range s.routerIngressURLs() {
		if u, err := url.Parse(base); err == nil {
			p := strings.TrimSuffix(u.EscapedPath(), "/") + "/" + s.peerID.String() + "/" + api.ServiceTypeStringA2A + "/" + entry.name
			if !slices.Contains(roots, p) {
				roots = append(roots, p)
			}
		}
	}
	slices.SortStableFunc(roots, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	roots = append(roots, "")
	return roots
}

func relativizeAgentCardResponse(service string, roots []string) func(*http.Response) error {
	cardPath := "/" + a2aAgentCardPath
	return func(resp *http.Response) error {
		if resp.Request == nil || resp.Request.Method != http.MethodGet || resp.Request.URL.EscapedPath() != cardPath ||
			resp.StatusCode != http.StatusOK {
			return nil
		}
		if resp.Header.Get("Content-Encoding") != "" {
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentCardBytes+1))
		if err != nil {
			return fmt.Errorf("read agent card of %q: %w", service, err)
		}
		if len(raw) > maxAgentCardBytes {
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(raw), resp.Body), resp.Body}
			return nil
		}
		_ = resp.Body.Close()
		out, err := relativizeAgentCardMultiRoot(raw, roots)
		if err != nil {
			out = raw
		}
		resp.Body = io.NopCloser(bytes.NewReader(out))
		resp.ContentLength = int64(len(out))
		resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
		return nil
	}
}

func relativizeAgentCardMultiRoot(raw []byte, roots []string) ([]byte, error) {
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
			!a2aBindingOverHTTP(a2a.TransportProtocol(binding)) {
			continue
		}
		for _, root := range roots {
			if rel, ok := relativeToRoot(u, root); ok {
				enc, err := json.Marshal(rel)
				if err != nil {
					return nil, err
				}
				iface["url"] = enc
				break
			}
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
	case root == "" && (p == "" || p == "/"):
	case root == "" && strings.HasPrefix(p, "/"):
		rest = strings.TrimPrefix(p, "/")
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

func a2aBindingOverHTTP(binding a2a.TransportProtocol) bool {
	switch strings.ToUpper(string(binding)) {
	case string(a2a.TransportProtocolJSONRPC), string(a2a.TransportProtocolHTTPJSON):
		return true
	}
	return false
}
