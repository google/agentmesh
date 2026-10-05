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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/sam/api"
)

func buildTestTLSClientHelloRecord(sni string, includeECH bool) []byte {
	var exts bytes.Buffer
	if sni != "" {
		hostBytes := []byte(sni)
		// server_name extension (0x0000)
		var snList bytes.Buffer
		snList.WriteByte(0x00) // host_name type
		_ = binary.Write(&snList, binary.BigEndian, uint16(len(hostBytes)))
		snList.Write(hostBytes)

		var snExt bytes.Buffer
		_ = binary.Write(&snExt, binary.BigEndian, uint16(snList.Len()))
		snExt.Write(snList.Bytes())

		_ = binary.Write(&exts, binary.BigEndian, uint16(tlsExtServerName))
		_ = binary.Write(&exts, binary.BigEndian, uint16(snExt.Len()))
		exts.Write(snExt.Bytes())
	}
	if includeECH {
		echPayload := []byte{0x01, 0x02, 0x03, 0x04}
		_ = binary.Write(&exts, binary.BigEndian, uint16(tlsExtEncryptedClientHello))
		_ = binary.Write(&exts, binary.BigEndian, uint16(len(echPayload)))
		exts.Write(echPayload)
	}

	var body bytes.Buffer
	// legacy_version TLS 1.2 (0x0303)
	body.Write([]byte{0x03, 0x03})
	// random (32 bytes)
	body.Write(make([]byte, 32))
	// session_id length (0)
	body.WriteByte(0x00)
	// cipher_suites length (2) + TLS_AES_128_GCM_SHA256 (0x1301)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})
	// compression_methods length (1) + null (0x00)
	body.Write([]byte{0x01, 0x00})
	if exts.Len() > 0 {
		_ = binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
		body.Write(exts.Bytes())
	}

	var hs bytes.Buffer
	hs.WriteByte(tlsHandshakeTypeClientHello)
	hsLen := body.Len()
	hs.Write([]byte{byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)})
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(tlsRecordTypeHandshake)
	rec.Write([]byte{0x03, 0x01})
	_ = binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func TestReadAndVerifyTLSClientHello(t *testing.T) {
	t.Run("matching SNI succeeds and preserves raw record", func(t *testing.T) {
		raw := buildTestTLSClientHelloRecord("pg.internal.example", false)
		gotRaw, gotSNI, err := readAndVerifyTLSClientHello(bytes.NewReader(raw), "pg.internal.example")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotSNI != "pg.internal.example" {
			t.Fatalf("got SNI %q, want pg.internal.example", gotSNI)
		}
		if !bytes.Equal(gotRaw, raw) {
			t.Fatalf("returned raw record does not match input bytes")
		}
	})

	t.Run("mismatched SNI is rejected", func(t *testing.T) {
		raw := buildTestTLSClientHelloRecord("evil.internal.example", false)
		_, _, err := readAndVerifyTLSClientHello(bytes.NewReader(raw), "pg.internal.example")
		if err == nil || !strings.Contains(err.Error(), "does not match destination") {
			t.Fatalf("expected SNI mismatch error, got %v", err)
		}
	})

	t.Run("missing SNI is rejected", func(t *testing.T) {
		raw := buildTestTLSClientHelloRecord("", false)
		_, _, err := readAndVerifyTLSClientHello(bytes.NewReader(raw), "pg.internal.example")
		if err == nil || !strings.Contains(err.Error(), "missing SNI") {
			t.Fatalf("expected missing SNI error, got %v", err)
		}
	})

	t.Run("Encrypted Client Hello (ECH 0xfe0d) is rejected", func(t *testing.T) {
		raw := buildTestTLSClientHelloRecord("pg.internal.example", true)
		_, _, err := readAndVerifyTLSClientHello(bytes.NewReader(raw), "pg.internal.example")
		if err == nil || !strings.Contains(err.Error(), "Encrypted Client Hello") {
			t.Fatalf("expected ECH error, got %v", err)
		}
	})

	t.Run("non-TLS traffic is rejected", func(t *testing.T) {
		_, _, err := readAndVerifyTLSClientHello(strings.NewReader("GET / HTTP/1.1\r\n\r\n"), "pg.internal.example")
		if err == nil || !strings.Contains(err.Error(), "expected TLS Handshake record") {
			t.Fatalf("expected non-TLS record error, got %v", err)
		}
	})
}

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
