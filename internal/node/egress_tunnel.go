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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/sam/api"
	gostream "github.com/libp2p/go-libp2p-gostream"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// HeaderSamEgressPort carries the requested TCP destination port when a
	// CONNECT tunnel is forwarded across /libp2p-http.
	HeaderSamEgressPort = "X-Sam-Egress-Port"
	// HeaderSamTunnelUpgrade marks an HTTP/1.1 request over /libp2p-http as a
	// raw TCP CONNECT tunnel.
	HeaderSamTunnelUpgrade = "sam-tcp-tunnel"

	tlsRecordTypeHandshake      = 0x16
	tlsHandshakeTypeClientHello = 0x01
	tlsExtServerName            = 0x0000
	tlsExtEncryptedClientHello  = 0xfe0d
	maxTLSRecordBytes           = 16384
	clientHelloReadTimeout      = 5 * time.Second
)

// readAndVerifyTLSClientHello reads a single TLS record from r, verifies that
// it is an unencrypted TLS ClientHello whose SNI matches expectedHost and that
// Encrypted Client Hello (ECH, 0xfe0d) is not present, and returns the exact
// raw record bytes so the caller can replay them to the upstream server before
// splicing.
func readAndVerifyTLSClientHello(r io.Reader, expectedHost string) ([]byte, string, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, "", fmt.Errorf("failed to read TLS record header: %w", err)
	}
	if hdr[0] != tlsRecordTypeHandshake {
		return nil, "", fmt.Errorf("expected TLS Handshake record (0x16), got 0x%02x", hdr[0])
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen <= 0 || recLen > maxTLSRecordBytes {
		return nil, "", fmt.Errorf("invalid TLS record length %d", recLen)
	}
	payload := make([]byte, recLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, "", fmt.Errorf("failed to read TLS Handshake record body: %w", err)
	}

	rawRecord := make([]byte, 5+recLen)
	copy(rawRecord[:5], hdr[:])
	copy(rawRecord[5:], payload)

	sni, hasECH, err := parseClientHelloSNIAndECH(payload)
	if err != nil {
		return rawRecord, "", err
	}
	if hasECH {
		return rawRecord, sni, errors.New("TLS ClientHello contains Encrypted Client Hello (ECH), which is forbidden on named TCP tunnels")
	}
	if sni == "" {
		return rawRecord, "", errors.New("TLS ClientHello is missing SNI server_name extension")
	}
	normSNI := api.NormalizeMeshHost(sni)
	normExpected := api.NormalizeMeshHost(expectedHost)
	if normSNI != normExpected {
		return rawRecord, sni, fmt.Errorf("TLS ClientHello SNI %q does not match destination %q", sni, expectedHost)
	}
	return rawRecord, normSNI, nil
}

func parseClientHelloSNIAndECH(b []byte) (sni string, hasECH bool, err error) {
	if len(b) < 4 {
		return "", false, errors.New("truncated TLS handshake message")
	}
	if b[0] != tlsHandshakeTypeClientHello {
		return "", false, fmt.Errorf("expected TLS ClientHello (0x01), got 0x%02x", b[0])
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if len(b) < hsLen {
		return "", false, errors.New("TLS ClientHello record shorter than handshake length")
	}
	b = b[:hsLen]

	// legacy_version (2) + random (32)
	if len(b) < 34 {
		return "", false, errors.New("truncated TLS ClientHello fixed header")
	}
	b = b[34:]

	// legacy_session_id (1-byte length)
	if len(b) < 1 {
		return "", false, errors.New("truncated TLS ClientHello session_id")
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen {
		return "", false, errors.New("truncated TLS ClientHello session_id bytes")
	}
	b = b[sidLen:]

	// cipher_suites (2-byte length)
	if len(b) < 2 {
		return "", false, errors.New("truncated TLS ClientHello cipher_suites")
	}
	csLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if csLen == 0 || csLen%2 != 0 || len(b) < csLen {
		return "", false, errors.New("invalid TLS ClientHello cipher_suites length")
	}
	b = b[csLen:]

	// legacy_compression_methods (1-byte length)
	if len(b) < 1 {
		return "", false, errors.New("truncated TLS ClientHello compression_methods")
	}
	compLen := int(b[0])
	b = b[1:]
	if compLen == 0 || len(b) < compLen {
		return "", false, errors.New("invalid TLS ClientHello compression_methods length")
	}
	b = b[compLen:]

	if len(b) == 0 {
		// No extensions present -> no SNI.
		return "", false, nil
	}
	if len(b) < 2 {
		return "", false, errors.New("truncated TLS ClientHello extensions length")
	}
	extTotalLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < extTotalLen {
		return "", false, errors.New("truncated TLS ClientHello extensions block")
	}
	b = b[:extTotalLen]

	for len(b) >= 4 {
		extType := binary.BigEndian.Uint16(b[:2])
		extLen := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]
		if len(b) < extLen {
			return "", false, errors.New("truncated TLS extension data")
		}
		extData := b[:extLen]
		b = b[extLen:]

		switch extType {
		case tlsExtEncryptedClientHello:
			hasECH = true
		case tlsExtServerName:
			parsed, err := parseServerNameExtension(extData)
			if err != nil {
				return "", false, err
			}
			sni = parsed
		}
	}
	if len(b) != 0 {
		return "", false, errors.New("trailing bytes in TLS ClientHello extensions")
	}
	return sni, hasECH, nil
}

func parseServerNameExtension(b []byte) (string, error) {
	if len(b) < 2 {
		return "", errors.New("truncated server_name extension")
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < listLen {
		return "", errors.New("truncated server_name list")
	}
	b = b[:listLen]
	var hostName string
	for len(b) >= 3 {
		nameType := b[0]
		nameLen := int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if len(b) < nameLen || nameLen == 0 {
			return "", errors.New("invalid server_name entry length")
		}
		val := string(b[:nameLen])
		b = b[nameLen:]
		if nameType == 0x00 {
			hostName = val
		}
	}
	return hostName, nil
}

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
			"sam_task", callerCtx.task,
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
	rawHello, sni, err := readAndVerifyTLSClientHello(reader, s.destination.GetName())
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		recordEgressDecision(s.info.Name, egressOutcomeDeny)
		logger.Warnw("Egress TCP Tunnel Verdict",
			"destination", s.info.Name,
			"port", reqPort,
			"sni", sni,
			"sam_task", callerCtx.task,
			"verdict", "deny_sni",
			"error", err.Error(),
		)
		return
	}

	targetAddr := s.resolveTCPTargetAddr(reqPort)
	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	upstreamConn, err := d.DialContext(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		logger.Warnw("Egress TCP Tunnel Verdict",
			"destination", s.info.Name,
			"port", reqPort,
			"sni", sni,
			"sam_task", callerCtx.task,
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
		"sam_task", callerCtx.task,
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
func withConnectTunnel(node *SamNode, token string, next http.Handler) http.Handler {
	authedConnect := withCallerOrTokenAuth(node, token, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleConnectTunnel(node, w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			next.ServeHTTP(w, r)
			return
		}
		if proxyAuth := r.Header.Get("Proxy-Authorization"); proxyAuth != "" && r.Header.Get(api.HeaderSamAuthentication) == "" {
			r.Header.Set(api.HeaderSamAuthentication, proxyAuth)
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

func handleConnectTunnel(node *SamNode, w http.ResponseWriter, r *http.Request) {
	host, port, err := parseConnectHostPort(r)
	if err != nil {
		refuse(w, http.StatusBadRequest, err.Error(), proxyStatusDenied)
		return
	}
	if node == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	identity := node.GetRequestIdentity(r.Context())
	if len(identity) == 0 {
		http.Error(w, "node has no credential yet", http.StatusServiceUnavailable)
		return
	}

	// 1. If this node serves egress://<host> locally, authorize and serve directly.
	if node.services != nil {
		if svc, ok := node.services.GetTyped(api.ServiceType_SERVICE_TYPE_EGRESS, host); ok {
			es, ok := svc.(*EgressService)
			if !ok {
				refuse(w, http.StatusNotFound, "invalid egress service", proxyStatusDestinationNotFound)
				return
			}
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

	// 2. Otherwise discover a remote provider in the mesh and forward the tunnel over /libp2p-http.
	if node.Host == nil {
		refuse(w, http.StatusNotFound, fmt.Sprintf("no egress destination %q is assigned to this node", host), proxyStatusDestinationNotFound)
		return
	}
	providers, err := node.DiscoverRemoteServices(r.Context(), api.ServiceType_SERVICE_TYPE_EGRESS, host)
	if err != nil || len(providers) == 0 {
		refuse(w, http.StatusNotFound, fmt.Sprintf("no provider found for egress://%s", host), proxyStatusDestinationNotFound)
		return
	}
	targetPeer, err := peer.Decode(providers[0].GetPeerId())
	if err != nil {
		refuse(w, http.StatusBadGateway, "invalid provider peer ID", proxyStatusConfigurationError)
		return
	}
	forwardConnectTunnelToPeer(node, w, r, targetPeer, host, port, identity)
}

func forwardConnectTunnelToPeer(node *SamNode, w http.ResponseWriter, r *http.Request, targetPeer peer.ID, host string, port int, biscuitBytes []byte) {
	dialCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	meshConn, err := gostream.Dial(dialCtx, node.Host, targetPeer, "/libp2p-http")
	cancel()
	if err != nil {
		refuse(w, http.StatusBadGateway, fmt.Sprintf("failed to dial egress peer: %v", err), proxyStatusConfigurationError)
		return
	}
	defer func() { _ = meshConn.Close() }()

	reqLine := fmt.Sprintf("GET /egress/%s HTTP/1.1\r\nHost: %s:%d\r\nConnection: Upgrade\r\nUpgrade: %s\r\n%s: %d\r\n%s: %s\r\n\r\n",
		host,
		host,
		port,
		HeaderSamTunnelUpgrade,
		HeaderSamEgressPort,
		port,
		api.HeaderSamBiscuit,
		base64.StdEncoding.EncodeToString(biscuitBytes),
	)
	if _, err := io.WriteString(meshConn, reqLine); err != nil {
		refuse(w, http.StatusBadGateway, "failed to send tunnel request to egress peer", proxyStatusConfigurationError)
		return
	}

	meshBuf := bufio.NewReader(meshConn)
	resp, err := http.ReadResponse(meshBuf, r)
	if err != nil {
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
