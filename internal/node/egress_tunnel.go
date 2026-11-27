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
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/google/agentmesh/internal/tlsinspect"
	gostream "github.com/libp2p/go-libp2p-gostream"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// HeaderMeshEgressPort carries the requested TCP destination port when a
	// CONNECT tunnel is forwarded across /libp2p-http.
	HeaderMeshEgressPort = "X-Mesh-Egress-Port"
	// HeaderMeshTunnelUpgrade marks an HTTP/1.1 request over /libp2p-http as a
	// raw TCP CONNECT tunnel.
	HeaderMeshTunnelUpgrade = "mesh-tcp-tunnel"

	clientHelloReadTimeout = 5 * time.Second
)

func (s *EgressService) isAllowedTCPPort(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	ports := s.destination.GetPorts()
	if len(ports) == 0 {
		return false
	}
	return slices.Contains(ports, uint32(port))
}

func (s *EgressService) resolveTCPTargetAddr(reqPort int) string {
	if s.destination.GetTargetUrl() != "" && s.target != nil {
		if p := s.target.Port(); p != "" {
			return s.target.Host
		}
		return net.JoinHostPort(s.target.Hostname(), strconv.Itoa(reqPort))
	}
	return net.JoinHostPort(s.destination.GetName(), strconv.Itoa(reqPort))
}

func (s *EgressService) allowsLocalTarget() bool {
	if s.destination.GetTargetUrl() == "" || s.target == nil {
		return false
	}
	h := strings.TrimSpace(s.target.Hostname())
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		unmapped := ip.Unmap()
		return unmapped.IsLoopback() || unmapped.IsPrivate()
	}
	return false
}

func isForbiddenEgressAddr(addr netip.Addr, allowLocal bool) bool {
	ip := addr.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if !allowLocal {
		if ip.IsLoopback() || ip.IsPrivate() || !ip.IsGlobalUnicast() {
			return true
		}
		if ip.Is4() {
			b := ip.As4()
			// RFC 1122 "This" network (0.0.0.0/8)
			if b[0] == 0 {
				return true
			}
			// RFC 6598 Carrier-Grade NAT (100.64.0.0/10)
			if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
				return true
			}
			// RFC 6890 IETF Protocol Assignments (192.0.0.0/24) & TEST-NET-1 (192.0.2.0/24)
			if b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2) {
				return true
			}
			// RFC 2544 Benchmarking (198.18.0.0/15)
			if b[0] == 198 && (b[1] == 18 || b[1] == 19) {
				return true
			}
			// RFC 5737 TEST-NET-2 (198.51.100.0/24) & TEST-NET-3 (203.0.113.0/24)
			if (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113) {
				return true
			}
			// RFC 1112 Reserved for Future Use / Class E (240.0.0.0/4)
			if b[0] >= 240 {
				return true
			}
		} else if ip.Is6() {
			b := ip.As16()
			// RFC 6052 Well-Known Prefix NAT64 (64:ff9b::/96)
			if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b &&
				b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
				b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 {
				return true
			}
			// RFC 3849 Documentation (2001:db8::/32)
			if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 {
				return true
			}
			// RFC 3056 6to4 (2002::/16) — check embedded IPv4
			if b[0] == 0x20 && b[1] == 0x02 {
				v4 := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
				if isForbiddenEgressAddr(v4, false) {
					return true
				}
			}
		}
	}
	return false
}

func dialSafeEgressTCP(ctx context.Context, addr string, allowLocal bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if parsed, pErr := netip.ParseAddr(host); pErr == nil {
		ips = []netip.Addr{parsed}
	} else {
		resolved, rErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if rErr != nil {
			return nil, rErr
		}
		ips = resolved
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses resolved for %s", host)
	}
	var allowed []netip.Addr
	for _, ip := range ips {
		if !isForbiddenEgressAddr(ip, allowLocal) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("egress dial to %s refused: resolved IP is in a forbidden range", host)
	}
	var d net.Dialer
	var lastErr error
	for _, ip := range allowed {
		conn, dErr := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
		if dErr == nil {
			return conn, nil
		}
		lastErr = dErr
	}
	return nil, lastErr
}

// ServeTunnel handles a named TCP CONNECT tunnel on an EGRESS_MODE_TCP
// EgressService. It enforces the ports allow-list before hijacking, reads the
// client's TLS ClientHello and verifies that SNI matches destination.Name (and
// that ECH is absent) before dialing upstream, and audits bytes in each
// direction and duration.
func (s *EgressService) ServeTunnel(ctx context.Context, w http.ResponseWriter, r *http.Request, reqPort int) {
	callerCtx := s.extractCallerContext(ctx)
	if s.destination.GetMode() != api.EgressMode_EGRESS_MODE_TCP {
		recordEgressDecision(s.info.Name, egressOutcomeDeny)
		refuse(w, http.StatusForbidden, fmt.Sprintf("egress destination %q is HTTP-only; TCP tunnels are not permitted", s.info.Name), proxyStatusDenied)
		return
	}
	if !s.isAllowedTCPPort(reqPort) {
		recordEgressDecision(s.info.Name, egressOutcomeDeny)
		logger.Warnw("Egress TCP Tunnel Verdict",
			"destination", s.info.Name,
			"port", reqPort,
			"mesh_task", callerCtx.task,
			"verdict", "deny_port",
		)
		refuse(w, http.StatusForbidden, fmt.Sprintf("egress destination %q does not allow TCP port %d", s.info.Name, reqPort), proxyStatusDenied)
		return
	}

	rc := http.NewResponseController(w)
	clientConn, clientBuf, err := rc.Hijack()
	if err != nil {
		http.Error(w, "TCP tunnel hijacking not supported", http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	var reader io.Reader = clientConn
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		buffered, _ := clientBuf.Peek(clientBuf.Reader.Buffered())
		_, _ = clientBuf.Discard(len(buffered))
		reader = io.MultiReader(bytes.NewReader(buffered), clientConn)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(clientHelloReadTimeout))
	rawHello, sni, err := tlsinspect.VerifyClientHello(reader, s.destination.GetName())
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		recordEgressDecision(s.info.Name, egressOutcomeDeny)
		logger.Warnw("Egress TCP Tunnel Verdict",
			"destination", s.info.Name,
			"port", reqPort,
			"sni", sni,
			"mesh_task", callerCtx.task,
			"verdict", "deny_sni",
			"error", err.Error(),
		)
		return
	}

	targetAddr := s.resolveTCPTargetAddr(reqPort)
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	upstreamConn, err := dialSafeEgressTCP(dialCtx, targetAddr, s.allowsLocalTarget())
	cancel()
	if err != nil {
		logger.Warnw("Egress TCP Tunnel Verdict",
			"destination", s.info.Name,
			"port", reqPort,
			"sni", sni,
			"mesh_task", callerCtx.task,
			"verdict", "dial_error",
			"error", err.Error(),
		)
		return
	}
	defer func() { _ = upstreamConn.Close() }()

	start := time.Now()
	if _, err := upstreamConn.Write(rawHello); err != nil {
		return
	}

	var txBytes, rxBytes int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstreamConn, reader)
		txBytes = int64(len(rawHello)) + n
		if cw, ok := upstreamConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = upstreamConn.Close()
		}
	}()
	go func() {
		defer wg.Done()
		rxBytes, _ = io.Copy(clientConn, upstreamConn)
		if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = clientConn.Close()
		}
	}()
	wg.Wait()

	logger.Infow("Egress TCP Tunnel Verdict",
		"destination", s.info.Name,
		"port", reqPort,
		"sni", sni,
		"mesh_task", callerCtx.task,
		"verdict", "allow",
		"bytes_tx", txBytes,
		"bytes_rx", rxBytes,
		"duration", time.Since(start).String(),
	)
}

// withConnectTunnel intercepts HTTP CONNECT requests at the sidecar server,
// authenticates the caller via withCallerOrTokenAuth, and either serves the
// tunnel locally (when this node serves egress://<host>) or forwards it across
// the mesh to a serving egress node.
func withConnectTunnel(node *AgentMeshNode, token string, next http.Handler) http.Handler {
	authedConnect := withCallerOrTokenAuth(node, token, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleConnectTunnel(node, w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			next.ServeHTTP(w, r)
			return
		}
		if proxyAuth := r.Header.Get("Proxy-Authorization"); proxyAuth != "" && r.Header.Get(api.HeaderMeshAuthentication) == "" {
			r.Header.Set(api.HeaderMeshAuthentication, proxyAuth)
		}
		r.Header.Del("Proxy-Authorization")
		authedConnect.ServeHTTP(w, r)
	})
}

func parseConnectHostPort(r *http.Request) (string, int, error) {
	rawHost := r.Host
	if rawHost == "" {
		rawHost = r.URL.Host
	}
	host, portStr, err := net.SplitHostPort(rawHost)
	if err != nil {
		return "", 0, fmt.Errorf("CONNECT target %q must be host:port", rawHost)
	}
	host = api.NormalizeMeshHost(host)
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	if err := api.ValidateEgressName(host); err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func handleConnectTunnel(node *AgentMeshNode, w http.ResponseWriter, r *http.Request) {
	host, port, err := parseConnectHostPort(r)
	if err != nil {
		refuse(w, http.StatusBadRequest, err.Error(), proxyStatusDenied)
		return
	}
	requiredLabels, err := parseRequiredLabels(r.Header.Get(api.HeaderMeshRequiredLabels))
	if err != nil {
		refuse(w, http.StatusBadRequest, fmt.Sprintf("Invalid %s header: %v", api.HeaderMeshRequiredLabels, err), proxyStatusDenied)
		return
	}
	r.Header.Del(api.HeaderMeshRequiredLabels)

	if node == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	identity := node.GetRequestIdentity(r.Context())
	if len(identity) == 0 {
		http.Error(w, "node has no credential yet", http.StatusServiceUnavailable)
		return
	}

	// 1. If this node serves egress://<host> locally and satisfies any caller
	// label requirement and the operator's egress floor, authorize and serve directly.
	var localLabelFailed bool
	if node.services != nil {
		if svc, ok := node.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, host); ok {
			es, ok := svc.(*EgressService)
			if !ok {
				refuse(w, http.StatusNotFound, "invalid egress service", proxyStatusDestinationNotFound)
				return
			}
			if outsideLabels(requiredLabels, node.labels(), true) || outsideLabels(node.egressFloor(), node.labels(), true) {
				localLabelFailed = true
			} else {
				var localPID peer.ID
				if pid, pErr := node.localPeerID(); pErr == nil {
					localPID = pid
				}
				reqCtx := RequestContext{
					PeerID:   localPID,
					Protocol: "local-api",
					Target:   api.EgressServicePrefix + host,
					HTTP:     &HTTPRequestFacts{Method: http.MethodConnect, Path: ""},
					Egress:   &EgressFacts{Host: host, Port: port},
					Local:    true,
				}
				if err := node.VerifyBiscuitToken(identity, reqCtx); err != nil {
					recordEgressDecision(host, egressOutcomeDeny)
					refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusDenied)
					return
				}
				recordEgressDecision(host, egressOutcomeAllow)
				es.ServeTunnel(WithCallerBiscuit(r.Context(), identity), w, r, port)
				return
			}
		}
	}

	// 2. Otherwise discover a remote provider in the mesh, verify its labels, and forward the tunnel over /libp2p-http.
	if node.Host == nil {
		if localLabelFailed {
			recordEgressDecision(host, egressOutcomeDeny)
			refuse(w, http.StatusForbidden, "Required labels not attested by provider", proxyStatusDenied)
			return
		}
		refuse(w, http.StatusNotFound, fmt.Sprintf("no egress destination %q is assigned to this node", host), proxyStatusDestinationNotFound)
		return
	}
	providers, err := node.DiscoverRemoteServices(r.Context(), api.ServiceType_SERVICE_TYPE_EGRESS, host)
	if err != nil || len(providers) == 0 {
		if localLabelFailed {
			recordEgressDecision(host, egressOutcomeDeny)
			refuse(w, http.StatusForbidden, "Required labels not attested by provider", proxyStatusDenied)
			return
		}
		refuse(w, http.StatusNotFound, fmt.Sprintf("no provider found for egress://%s", host), proxyStatusDestinationNotFound)
		return
	}
	// A provider that was heard from and refused is a verdict; one that
	// never answered is not, and when every provider is in that state the
	// caller is told so rather than told it was denied.
	var denied bool
	for _, p := range providers {
		targetPeer, decErr := peer.Decode(p.GetPeerId())
		if decErr != nil {
			continue
		}
		if err := node.VerifyProvider(r.Context(), targetPeer, requiredLabels, api.ServiceTypeStringEgress+"://"+host); err != nil {
			logger.Warnf("[Egress] CONNECT label gate refused egress to %s: %v", targetPeer, err)
			denied = denied || !errors.Is(err, ErrProviderUnreachable)
			continue
		}
		forwardConnectTunnelToPeer(node, w, r, targetPeer, host, port, identity)
		return
	}
	if !denied {
		refuse(w, http.StatusBadGateway, "Bad Gateway: no provider answered", proxyStatusDestinationUnreachable)
		return
	}
	recordEgressDecision(host, egressOutcomeDeny)
	refuse(w, http.StatusForbidden, "Required labels not attested by provider", proxyStatusDenied)
}

func forwardConnectTunnelToPeer(node *AgentMeshNode, w http.ResponseWriter, r *http.Request, targetPeer peer.ID, host string, port int, biscuitBytes []byte) {
	dialCtx, cancel := context.WithTimeout(allowLimitedEgressConn(r.Context()), 10*time.Second)
	node.prepareEgressPeer(dialCtx, targetPeer.String())
	meshConn, err := gostream.Dial(dialCtx, node.Host, targetPeer, "/libp2p-http")
	cancel()
	if err != nil {
		logger.Warnf("[Egress] CONNECT dial to peer %s for %s:%d failed: %v", targetPeer, host, port, err)
		refuse(w, http.StatusBadGateway, fmt.Sprintf("failed to dial egress peer: %v", err), proxyStatusConfigurationError)
		return
	}
	defer func() { _ = meshConn.Close() }()

	reqLine := fmt.Sprintf("GET /egress/%s HTTP/1.1\r\nHost: %s:%d\r\nConnection: Upgrade\r\nUpgrade: %s\r\n%s: %d\r\n%s: %s\r\n\r\n",
		host,
		host,
		port,
		HeaderMeshTunnelUpgrade,
		HeaderMeshEgressPort,
		port,
		api.HeaderMeshBiscuit,
		base64.StdEncoding.EncodeToString(biscuitBytes),
	)
	if _, err := io.WriteString(meshConn, reqLine); err != nil {
		logger.Warnf("[Egress] CONNECT send to peer %s for %s:%d failed: %v", targetPeer, host, port, err)
		refuse(w, http.StatusBadGateway, "failed to send tunnel request to egress peer", proxyStatusConfigurationError)
		return
	}

	meshBuf := bufio.NewReader(meshConn)
	resp, err := http.ReadResponse(meshBuf, r)
	if err != nil {
		logger.Warnf("[Egress] CONNECT read response from peer %s for %s:%d failed: %v", targetPeer, host, port, err)
		refuse(w, http.StatusBadGateway, "failed to read tunnel response from egress peer", proxyStatusConfigurationError)
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if ps := resp.Header.Get("Proxy-Status"); ps != "" {
			w.Header().Set("Proxy-Status", ps)
		}
		http.Error(w, strings.TrimSpace(string(body)), resp.StatusCode)
		return
	}

	rc := http.NewResponseController(w)
	clientConn, clientBuf, err := rc.Hijack()
	if err != nil {
		http.Error(w, "TCP tunnel hijacking not supported", http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	var clientReader io.Reader = clientConn
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		buffered, _ := clientBuf.Peek(clientBuf.Reader.Buffered())
		_, _ = clientBuf.Discard(len(buffered))
		clientReader = io.MultiReader(bytes.NewReader(buffered), clientConn)
	}

	var meshReader io.Reader = meshConn
	if meshBuf.Buffered() > 0 {
		buffered, _ := meshBuf.Peek(meshBuf.Buffered())
		_, _ = meshBuf.Discard(len(buffered))
		meshReader = io.MultiReader(bytes.NewReader(buffered), meshConn)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(meshConn, clientReader)
		_ = meshConn.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, meshReader)
		_ = clientConn.Close()
	}()
	wg.Wait()
}
