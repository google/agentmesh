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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/agentmesh/api"
	"github.com/libp2p/go-libp2p"
	gostream "github.com/libp2p/go-libp2p-gostream"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/multiformats/go-multiaddr"
)

func startTestTLSServer(t *testing.T, dnsName string, upstreamHits *atomic.Int32) (string, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			upstreamHits.Add(1)
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if line == "PING\n" {
					_, _ = io.WriteString(conn, "PONG\n")
				}
			}(c)
		}
	}()

	return ln.Addr().String(), pool
}

func TestEgressTCPTunnelEndToEnd(t *testing.T) {
	var upstreamHits atomic.Int32
	tlsAddr, rootPool := startTestTLSServer(t, "pg.internal.example", &upstreamHits)

	svc, err := newEgressService(&api.EgressDestination{
		Name:      "pg.internal.example",
		Mode:      api.EgressMode_EGRESS_MODE_TCP,
		Ports:     []uint32{5432},
		TargetUrl: "https://" + tlsAddr,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("newEgressService: %v", err)
	}

	t.Run("disallowed port is rejected before hijacking or dialing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodConnect, "http://pg.internal.example:6379", nil)
		rec := httptest.NewRecorder()
		svc.ServeTunnel(context.Background(), rec, req, 6379)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got status %d, want 403", rec.Code)
		}
		if upstreamHits.Load() != 0 {
			t.Fatalf("upstream should not have been dialed on disallowed port")
		}
	})

	t.Run("HTTP-mode destination rejects TCP tunnel", func(t *testing.T) {
		httpSvc, err := newEgressService(&api.EgressDestination{
			Name:      "api.internal.example",
			Mode:      api.EgressMode_EGRESS_MODE_HTTP,
			TargetUrl: "https://" + tlsAddr,
		}, t.TempDir())
		if err != nil {
			t.Fatalf("newEgressService: %v", err)
		}
		req := httptest.NewRequest(http.MethodConnect, "http://api.internal.example:443", nil)
		rec := httptest.NewRecorder()
		httpSvc.ServeTunnel(context.Background(), rec, req, 443)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got status %d, want 403", rec.Code)
		}
	})

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusMethodNotAllowed)
			return
		}
		svc.ServeTunnel(r.Context(), w, r, 5432)
	}))
	defer proxySrv.Close()
	proxyHostPort := strings.TrimPrefix(proxySrv.URL, "http://")

	dialTunnel := func(t *testing.T) net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", proxyHostPort, 5*time.Second)
		if err != nil {
			t.Fatalf("Dial proxy: %v", err)
		}
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: "pg.internal.example:5432"},
			Host:   "pg.internal.example:5432",
			Header: make(http.Header),
		}
		if err := req.Write(conn); err != nil {
			_ = conn.Close()
			t.Fatalf("Write CONNECT: %v", err)
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			_ = conn.Close()
			t.Fatalf("ReadResponse: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			t.Fatalf("CONNECT status = %d", resp.StatusCode)
		}
		return conn
	}

	t.Run("mismatched SNI is refused before dialing upstream", func(t *testing.T) {
		before := upstreamHits.Load()
		conn := dialTunnel(t)
		defer func() { _ = conn.Close() }()

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: "wrong.internal.example",
			RootCAs:    rootPool,
		})
		if err := tlsConn.Handshake(); err == nil {
			t.Fatalf("expected TLS handshake with mismatched SNI to fail")
		}
		if upstreamHits.Load() != before {
			t.Fatalf("upstream should not have been dialed when SNI mismatches")
		}
	})

	t.Run("matching SNI splices TLS stream end-to-end", func(t *testing.T) {
		conn := dialTunnel(t)
		defer func() { _ = conn.Close() }()

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: "pg.internal.example",
			RootCAs:    rootPool,
		})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("TLS handshake failed: %v", err)
		}
		if _, err := io.WriteString(tlsConn, "PING\n"); err != nil {
			t.Fatalf("Write PING: %v", err)
		}
		reply, err := bufio.NewReader(tlsConn).ReadString('\n')
		if err != nil {
			t.Fatalf("Read PONG: %v", err)
		}
		if reply != "PONG\n" {
			t.Fatalf("got reply %q, want PONG\\n", reply)
		}
	})
}

func TestIsForbiddenEgressAddrRanges(t *testing.T) {
	forbidden := []string{
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"0.1.2.3",
		"192.0.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"240.0.0.1",
		"::1",
		"fe80::1",
		"64:ff9b::a9fe:a9fe",
		"2001:db8::1",
		"2002:7f00:0001::1",
	}
	for _, s := range forbidden {
		ip := netip.MustParseAddr(s)
		if !isForbiddenEgressAddr(ip, false) {
			t.Errorf("expected %s to be forbidden when allowLocal=false", s)
		}
	}
	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"2606:4700:4700::1111",
	}
	for _, s := range allowed {
		ip := netip.MustParseAddr(s)
		if isForbiddenEgressAddr(ip, false) {
			t.Errorf("expected %s to be allowed when allowLocal=false", s)
		}
	}
}

func TestHandleConnectTunnelRequiredLabels(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://pg.internal.example:5432", nil)
	req.Host = "pg.internal.example:5432"
	req.Header.Set(api.HeaderMeshRequiredLabels, ",,")
	handleConnectTunnel(nil, rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed X-Mesh-Required-Labels on CONNECT: got %d, want 400", rec.Code)
	}
}

func TestForwardConnectTunnelOverLimitedRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	relayHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.DisableRelay())
	if err != nil {
		t.Fatalf("relay host: %v", err)
	}
	t.Cleanup(func() { _ = relayHost.Close() })
	if _, err := relay.New(relayHost); err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	relayInfo := peer.AddrInfo{ID: relayHost.ID(), Addrs: relayHost.Addrs()}

	// Provider and consumer connect exclusively via the circuit relay (Limited conn),
	// mirroring NAT / Cloud Run deployments with no direct peer-to-peer route.
	providerHost, err := libp2p.New(libp2p.NoListenAddrs, libp2p.EnableRelay())
	if err != nil {
		t.Fatalf("provider host: %v", err)
	}
	t.Cleanup(func() { _ = providerHost.Close() })
	if err := providerHost.Connect(ctx, relayInfo); err != nil {
		t.Fatalf("provider connect relay: %v", err)
	}
	if _, err := client.Reserve(ctx, providerHost, relayInfo); err != nil {
		t.Fatalf("provider reserve relay: %v", err)
	}

	consumerHost, err := libp2p.New(libp2p.NoListenAddrs, libp2p.EnableRelay())
	if err != nil {
		t.Fatalf("consumer host: %v", err)
	}
	t.Cleanup(func() { _ = consumerHost.Close() })
	if err := consumerHost.Connect(ctx, relayInfo); err != nil {
		t.Fatalf("consumer connect relay: %v", err)
	}
	circuitMA, err := multiaddr.NewMultiaddr("/p2p/" + relayHost.ID().String() + "/p2p-circuit")
	if err != nil {
		t.Fatalf("circuit multiaddr: %v", err)
	}
	if err := consumerHost.Connect(ctx, peer.AddrInfo{
		ID:    providerHost.ID(),
		Addrs: []multiaddr.Multiaddr{relayHost.Addrs()[0].Encapsulate(circuitMA)},
	}); err != nil {
		t.Fatalf("consumer connect provider via relay: %v", err)
	}
	if got := consumerHost.Network().Connectedness(providerHost.ID()); got != network.Limited {
		t.Fatalf("connectedness = %v, want Limited (relayed)", got)
	}

	var upstreamHits atomic.Int32
	tlsAddr, rootPool := startTestTLSServer(t, "pg.internal.example", &upstreamHits)
	tcpSvc, err := newEgressService(&api.EgressDestination{
		Name:      "pg.internal.example",
		Mode:      api.EgressMode_EGRESS_MODE_TCP,
		Ports:     []uint32{5432},
		TargetUrl: "https://" + tlsAddr,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("newEgressService: %v", err)
	}

	meshLn, err := gostream.Listen(providerHost, "/libp2p-http")
	if err != nil {
		t.Fatalf("gostream.Listen: %v", err)
	}
	t.Cleanup(func() { _ = meshLn.Close() })

	providerSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/egress/github.com" {
				refuse(w, http.StatusForbidden, "Authorization failed", proxyStatusDenied)
				return
			}
			if r.URL.Path == "/egress/pg.internal.example" && strings.EqualFold(r.Header.Get("Upgrade"), HeaderMeshTunnelUpgrade) {
				tcpSvc.ServeTunnel(r.Context(), w, r, 5432)
				return
			}
			http.NotFound(w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = providerSrv.Serve(meshLn) }()
	t.Cleanup(func() { _ = providerSrv.Close() })

	consumerNode := &AgentMeshNode{Host: consumerHost}

	t.Run("relayed policy denial returns 403 with Proxy-Status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodConnect, "http://github.com:443", nil)
		req.Host = "github.com:443"
		forwardConnectTunnelToPeer(consumerNode, rec, req, providerHost.ID(), "github.com", 443, []byte("test-biscuit"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got status %d (%q), want 403", rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		if ps := rec.Header().Get("Proxy-Status"); !strings.Contains(ps, "agentmesh-node; error=http_request_denied") {
			t.Fatalf("Proxy-Status = %q, want agentmesh-node; error=http_request_denied", ps)
		}
	})

	t.Run("relayed allowed TCP tunnel splices TLS end-to-end", func(t *testing.T) {
		proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			forwardConnectTunnelToPeer(consumerNode, w, r, providerHost.ID(), "pg.internal.example", 5432, []byte("test-biscuit"))
		}))
		defer proxySrv.Close()

		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(proxySrv.URL, "http://"), 5*time.Second)
		if err != nil {
			t.Fatalf("Dial proxy: %v", err)
		}
		defer func() { _ = conn.Close() }()

		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: "pg.internal.example:5432"},
			Host:   "pg.internal.example:5432",
			Header: make(http.Header),
		}
		if err := req.Write(conn); err != nil {
			t.Fatalf("Write CONNECT: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
		}

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: "pg.internal.example",
			RootCAs:    rootPool,
		})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("TLS handshake over relayed tunnel failed: %v", err)
		}
		if _, err := io.WriteString(tlsConn, "PING\n"); err != nil {
			t.Fatalf("Write PING: %v", err)
		}
		reply, err := bufio.NewReader(tlsConn).ReadString('\n')
		if err != nil {
			t.Fatalf("Read PONG: %v", err)
		}
		if reply != "PONG\n" {
			t.Fatalf("got reply %q, want PONG\\n", reply)
		}
	})
}
