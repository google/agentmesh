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
	"runtime/debug"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/identity"
	"github.com/google/agentmesh/internal/p2plimits"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-msgio"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"
)

const (
	streamScopeUnauthenticated = "unauthenticated"
	streamScopeNotRouter       = "not_router"

	authWait             = time.Minute
	authPollInterval     = 100 * time.Millisecond
	authHandshakeTimeout = 10 * time.Second
	goAwayMaxRetryAfter  = time.Hour
	defaultShunDuration  = 5 * time.Minute

	connLowWaterMark  = 96
	connHighWaterMark = 128
	peerStreamCap     = 256
)

var errNotAuthenticated = errors.New("peer did not authenticate")

var _ connmgr.ConnectionGater = (*connGate)(nil)

type connGate struct {
	s *Server
}

func (g *connGate) InterceptPeerDial(p peer.ID) bool {
	if g.s.isPeerBanned(p) {
		g.s.log().Warn("refusing outbound dial to banned peer", "peer_id", p.String())
		return false
	}
	return true
}

func (g *connGate) InterceptAddrDial(_ peer.ID, _ multiaddr.Multiaddr) bool {
	return true
}

func (g *connGate) InterceptAccept(_ network.ConnMultiaddrs) bool {
	return true
}

func (g *connGate) InterceptSecured(dir network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	if g.s.isPeerBanned(p) {
		g.s.log().Warn("refusing secured connection with banned peer", "peer_id", p.String(), "direction", dir.String())
		return false
	}
	return true
}

func (g *connGate) InterceptUpgraded(_ network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

type meshHost struct {
	host.Host
	s *Server
}

func (h *meshHost) SetStreamHandler(pid protocol.ID, handler network.StreamHandler) {
	h.Host.SetStreamHandler(pid, h.s.requireAuthenticated(handler))
}

func (h *meshHost) SetStreamHandlerMatch(pid protocol.ID, match func(protocol.ID) bool, handler network.StreamHandler) {
	h.Host.SetStreamHandlerMatch(pid, match, h.s.requireAuthenticated(handler))
}

func (h *meshHost) NewStream(ctx context.Context, p peer.ID, pids ...protocol.ID) (network.Stream, error) {
	if err := h.s.ensurePeerAuthenticated(ctx, p); err != nil {
		return nil, err
	}
	return h.Host.NewStream(ctx, p, pids...)
}

type routerHost struct {
	meshHost
}

func (h *routerHost) SetStreamHandler(pid protocol.ID, handler network.StreamHandler) {
	h.Host.SetStreamHandler(pid, h.s.requireRouter(handler))
}

func (h *routerHost) SetStreamHandlerMatch(pid protocol.ID, match func(protocol.ID) bool, handler network.StreamHandler) {
	h.Host.SetStreamHandlerMatch(pid, match, h.s.requireRouter(handler))
}

func (s *Server) isPeerAuthenticated(p peer.ID) bool {
	return s.isAuthenticatedAndConnected(p) || s.isAdmitted(p)
}

func (s *Server) isAuthenticatedRouter(p peer.ID) bool {
	return s.isAuthenticatedAndConnected(p) || s.isAdmittedRouter(p)
}

func (s *Server) isAdmitted(p peer.ID) bool {
	return admissionHolds(&s.authPeers, p)
}

func (s *Server) isAdmittedRouter(p peer.ID) bool {
	return admissionHolds(&s.authRouters, p)
}

func (s *Server) admitPeer(p peer.ID, expiry time.Time, router bool) {
	s.authPeers.Store(p, expiry)
	if router {
		s.authRouters.Store(p, expiry)
	} else {
		s.authRouters.Delete(p)
	}
}

func (s *Server) forgetAdmission(p peer.ID) {
	s.authPeers.Delete(p)
	s.authRouters.Delete(p)
}

func admissionHolds(m interface {
	Load(any) (any, bool)
	Delete(any)
}, p peer.ID) bool {
	v, ok := m.Load(p)
	if !ok {
		return false
	}
	expiry, ok := v.(time.Time)
	if !ok || !time.Now().Before(expiry) {
		m.Delete(p)
		return false
	}
	return true
}

func (s *Server) ensurePeerAuthenticated(ctx context.Context, p peer.ID) error {
	if s.isPeerAuthenticated(p) {
		return nil
	}
	if !s.isCatalogRouter(p) || s.isAttached(p) {
		return fmt.Errorf("%s: %w", p, errNotAuthenticated)
	}
	biscuitBytes := s.currentBiscuit()
	if len(biscuitBytes) == 0 {
		return errors.New("missing member credential")
	}
	return s.authRouter(ctx, peer.AddrInfo{ID: p}, biscuitBytes)
}

func (s *Server) requireAuthenticated(next network.StreamHandler) network.StreamHandler {
	return func(st network.Stream) {
		p := st.Conn().RemotePeer()
		if err := s.awaitPeerAuthenticated(context.Background(), p); err != nil {
			s.incRefusedStream(streamScopeUnauthenticated, st.Protocol())
			s.log().Debug("refusing unauthenticated stream", "protocol", string(st.Protocol()), "peer_id", p.String(), "error", err)
			_ = st.Reset()
			return
		}
		next(st)
	}
}

func (s *Server) requireRouter(next network.StreamHandler) network.StreamHandler {
	return s.requireAuthenticated(func(st network.Stream) {
		p := st.Conn().RemotePeer()
		if !s.isAuthenticatedRouter(p) {
			s.incRefusedStream(streamScopeNotRouter, st.Protocol())
			s.log().Warn("refusing router-only stream from non-router peer", "protocol", string(st.Protocol()), "peer_id", p.String())
			_ = st.Reset()
			return
		}
		next(st)
	})
}

func (s *Server) awaitPeerAuthenticated(ctx context.Context, p peer.ID) error {
	if s.isPeerAuthenticated(p) {
		return nil
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, authWait)
	defer cancel()
	tick := time.NewTicker(authPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			if parent.Err() != nil {
				return parent.Err()
			}
			return errNotAuthenticated
		case <-tick.C:
		}
		if s.isPeerAuthenticated(p) {
			return nil
		}
		if s.host.Network().Connectedness(p) != network.Connected {
			return errNotAuthenticated
		}
	}
}

func (s *Server) incRefusedStream(scope string, protoID protocol.ID) {
	key := scope + "|" + string(protoID)
	s.refusedMu.Lock()
	s.refusedStreams[key]++
	s.refusedMu.Unlock()
}

func (s *Server) refusedStreamCount(scope string, protoID protocol.ID) uint64 {
	key := scope + "|" + string(protoID)
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	return s.refusedStreams[key]
}

func (s *Server) recoverStream(name string, next network.StreamHandler) network.StreamHandler {
	return func(st network.Stream) {
		defer func() {
			if r := recover(); r != nil {
				s.log().Error("recovered panic in stream handler",
					"handler", name,
					"peer_id", st.Conn().RemotePeer().String(),
					"panic", fmt.Sprint(r),
					"stack", string(debug.Stack()),
				)
				_ = st.Reset()
			}
		}()
		next(st)
	}
}

func (s *Server) handleAuthHandshake(st network.Stream) {
	defer func() { _ = st.Close() }()
	remotePeer := st.Conn().RemotePeer()

	if s.isPeerBanned(remotePeer) {
		s.log().Warn("refusing auth handshake from banned peer", "peer_id", remotePeer.String())
		_ = st.Reset()
		return
	}
	if s.handshakeLimiter != nil && !s.handshakeLimiter.Allow(remotePeer.String()) {
		s.log().Warn("handshake rate limit exceeded", "peer_id", remotePeer.String())
		_ = st.Reset()
		return
	}
	_ = st.SetDeadline(time.Now().Add(authHandshakeTimeout))

	reader := msgio.NewVarintReaderSize(st, 64*1024)
	msg, err := reader.ReadMsg()
	if err != nil {
		s.log().Debug("failed reading auth frame", "peer_id", remotePeer.String(), "error", err)
		return
	}
	defer reader.ReleaseMsg(msg)

	var exchange api.AuthFrame
	if err := proto.Unmarshal(msg, &exchange); err != nil {
		s.log().Warn("invalid protobuf in auth handshake", "peer_id", remotePeer.String())
		return
	}

	b, verifyingKey, expiry, err := identity.VerifyBiscuitAdmission(exchange.GetBiscuit(), remotePeer, s.trustedPublicKeys(), s.biscuitTimeout())
	if err != nil {
		s.log().Warn("auth handshake rejected", "peer_id", remotePeer.String(), "error", err)
		return
	}
	if s.isBiscuitRevoked(b) {
		s.log().Warn("auth handshake rejected: biscuit is revoked", "peer_id", remotePeer.String())
		return
	}

	isRouter := identity.RequireRole(b, verifyingKey, api.RoleRouter, s.biscuitTimeout()) == nil
	s.admitPeer(remotePeer, expiry, isRouter)
	s.log().Info("admitted mesh peer", "peer_id", remotePeer.String(), "is_router", isRouter)

	respBytes, err := proto.Marshal(&api.AuthResponse{Success: true, Biscuit: s.currentBiscuit()})
	if err != nil {
		return
	}
	if err := msgio.NewVarintWriter(st).WriteMsg(respBytes); err != nil {
		s.log().Debug("failed writing auth handshake ACK", "peer_id", remotePeer.String(), "error", err)
	}
}

func (s *Server) handleGoAway(ctx context.Context, st network.Stream) {
	defer func() { _ = st.Close() }()
	router := st.Conn().RemotePeer()
	if !s.isAttached(router) {
		_ = st.Reset()
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg, err := msgio.NewVarintReaderSize(st, 1024).ReadMsg()
	if err != nil {
		_ = st.Reset()
		return
	}
	var goAway api.RouterGoAway
	if err := proto.Unmarshal(msg, &goAway); err != nil {
		_ = st.Reset()
		return
	}
	retryAfter := goAway.GetRetryAfter().AsDuration()
	if retryAfter <= 0 {
		retryAfter = defaultShunDuration
	}
	retryAfter = min(retryAfter, goAwayMaxRetryAfter)
	s.log().Info("router sent go-away; failing over",
		"router_peer_id", router.String(),
		"reason", goAway.GetReason().String(),
		"retry_after", retryAfter,
	)
	s.shun(router, retryAfter)
	s.detach(router)
	s.mu.Lock()
	delete(s.authenticatedRouters, router)
	s.mu.Unlock()
	go s.topUpRouters(ctx)
}

func (s *Server) newResourceManager() (network.ResourceManager, error) {
	total := connHighWaterMark * peerStreamCap
	cfg := rcmgr.PartialLimitConfig{
		System: rcmgr.ResourceLimits{
			Streams:         rcmgr.LimitVal(2 * total),
			StreamsInbound:  rcmgr.LimitVal(total),
			StreamsOutbound: rcmgr.LimitVal(total),
			Conns:           rcmgr.LimitVal(2 * connHighWaterMark),
			ConnsInbound:    rcmgr.LimitVal(connHighWaterMark),
			ConnsOutbound:   rcmgr.LimitVal(2 * connHighWaterMark),
			FD:              rcmgr.LimitVal(2 * connHighWaterMark),
			Memory:          rcmgr.LimitVal64(int64(2*total) * p2plimits.StreamWindow),
		},
		PeerDefault: p2plimits.Streams(peerStreamCap),
	}.Build(rcmgr.DefaultLimits.AutoScale())

	// Unregistered per-Server counter so multiple embedded meshnet.Server
	// instances never collide on prometheus.DefaultRegisterer.
	refusedCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentmesh_meshnet_connections_refused_total",
		Help: "Inbound libp2p connections refused by the resource manager.",
	}, []string{"reason"})

	perIP := p2plimits.DefaultConnsPerSourceIP(connHighWaterMark)
	return p2plimits.New(cfg, perIP, refusedCounter, func(format string, args ...any) {
		s.log().Warn(fmt.Sprintf(format, args...))
	})
}
