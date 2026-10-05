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

package extproc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const methodPath = "/envoy.service.ext_proc.v3.ExternalProcessor/Process"

func writeFrame(w io.Writer, msg proto.Message) error {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	_, err = w.Write(frame)
	return err
}

func readFrame(r io.Reader, msg proto.Message) error {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return proto.Unmarshal(payload, msg)
}

func TestStdlibHTTP2AgainstGRPCGoCallout_TransportsAndPhases(t *testing.T) {
	t.Run("unix_socket_and_4_phase_mutation", func(t *testing.T) {
		sockPath := filepath.Join(t.TempDir(), "callout.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("listen unix: %v", err)
		}
		callout := NewCalloutServer()
		srv := grpc.NewServer()
		extprocv3.RegisterExternalProcessorServer(srv, callout)
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(srv.Stop)

		var protocols http.Protocols
		protocols.SetUnencryptedHTTP2(true)
		tr := &http.Transport{
			ForceAttemptHTTP2: true,
			Protocols:         &protocols,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		}
		client := &http.Client{Transport: tr}
		runFullCalloutRoundTrip(t, client, "http://localhost"+methodPath, callout)
	})

	t.Run("tls_alpn_h2_and_trailers_only_rejection", func(t *testing.T) {
		serverCert, rootPool := generateSelfSignedCert(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		callout := NewCalloutServer()
		srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2"},
		})))
		extprocv3.RegisterExternalProcessorServer(srv, callout)
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(srv.Stop)

		var protocols http.Protocols
		protocols.SetHTTP2(true)
		tr := &http.Transport{
			ForceAttemptHTTP2: true,
			Protocols:         &protocols,
			TLSClientConfig: &tls.Config{
				RootCAs:    rootPool,
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2"},
			},
		}
		client := &http.Client{Transport: tr}
		endpoint := "https://" + ln.Addr().String() + methodPath

		// 1. Verify full 4-phase round trip over TLS ALPN h2.
		runFullCalloutRoundTrip(t, client, endpoint, callout)

		// 2. Verify trailers-only gRPC rejection (codes.PermissionDenied = 7).
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, pr)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/grpc+proto")
		req.Header.Set("TE", "trailers")

		go func() {
			_ = writeFrame(pw, &extprocv3.ProcessingRequest{
				Request: &extprocv3.ProcessingRequest_RequestHeaders{
					RequestHeaders: &extprocv3.HttpHeaders{
						EndOfStream: true,
						Headers: &corev3.HeaderMap{
							Headers: []*corev3.HeaderValue{
								{Key: ":method", Value: "POST"},
								{Key: ":path", Value: "/trailers-only-error"},
							},
						},
					},
				},
			})
			_ = pw.Close()
		}()

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("client.Do: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var dummy extprocv3.ProcessingResponse
		_ = readFrame(resp.Body, &dummy)
		grpcStatus := resp.Header.Get("Grpc-Status")
		if grpcStatus == "" {
			grpcStatus = resp.Trailer.Get("Grpc-Status")
		}
		if grpcStatus != "7" {
			t.Fatalf("expected Grpc-Status 7 (PermissionDenied), got %q (hdr=%v trailer=%v)", grpcStatus, resp.Header, resp.Trailer)
		}
	})
}

func runFullCalloutRoundTrip(t *testing.T, client *http.Client, endpoint string, callout *CalloutServer) {
	t.Helper()
	pr, pw := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, pr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Grpc-Timeout", "2000m")

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		r, e := client.Do(req)
		if e != nil {
			errCh <- e
			return
		}
		respCh <- r
	}()

	samStruct, err := structpb.NewStruct(map[string]any{
		"destination": "vertex.googleapis.com",
		"principal":   "user:alice@example.com",
		"roles":       []any{"developer"},
		"actor_node":  "12D3KooWTest",
		"task":        "task-conformance-1",
	})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}

	// 1. Send RequestHeaders
	if err := writeFrame(pw, &extprocv3.ProcessingRequest{
		Attributes: map[string]*structpb.Struct{"sam": samStruct},
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{
				EndOfStream: false,
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{
						{Key: ":method", Value: "POST"},
						{Key: ":path", Value: "/v1/models/gemini:generateContent"},
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("writeFrame RequestHeaders: %v", err)
	}

	var httpResp *http.Response
	select {
	case httpResp = <-respCh:
	case e := <-errCh:
		t.Fatalf("client.Do: %v", e)
	}
	defer func() { _ = httpResp.Body.Close() }()

	var r1 extprocv3.ProcessingResponse
	if err := readFrame(httpResp.Body, &r1); err != nil {
		t.Fatalf("readFrame RequestHeaders: %v", err)
	}
	if r1.GetModeOverride().GetRequestBodyMode() != extprocv3http.ProcessingMode_BUFFERED {
		t.Fatalf("expected ModeOverride BUFFERED, got %+v", r1.GetModeOverride())
	}
	if got := callout.LastSamAttributes()["destination"].GetStringValue(); got != "vertex.googleapis.com" {
		t.Fatalf("callout saw destination=%q, want vertex.googleapis.com", got)
	}
	if !callout.LastStreamHadDeadline() {
		t.Fatalf("expected callout server stream context to have a deadline from Grpc-Timeout")
	}

	// 2. Send RequestBody
	if err := writeFrame(pw, &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{
				Body:        []byte("prompt with PII_SSN inside"),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("writeFrame RequestBody: %v", err)
	}
	var r2 extprocv3.ProcessingResponse
	if err := readFrame(httpResp.Body, &r2); err != nil {
		t.Fatalf("readFrame RequestBody: %v", err)
	}
	gotBody := string(r2.GetRequestBody().GetResponse().GetBodyMutation().GetBody())
	if gotBody != "prompt with [REDACTED_SSN] inside" {
		t.Fatalf("mutated request body = %q", gotBody)
	}

	// 3. Send ResponseHeaders
	if err := writeFrame(pw, &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{
				EndOfStream: false,
				Headers: &corev3.HeaderMap{
					Headers: []*corev3.HeaderValue{{Key: ":status", Value: "200"}},
				},
			},
		},
	}); err != nil {
		t.Fatalf("writeFrame ResponseHeaders: %v", err)
	}
	var r3 extprocv3.ProcessingResponse
	if err := readFrame(httpResp.Body, &r3); err != nil {
		t.Fatalf("readFrame ResponseHeaders: %v", err)
	}

	// 4. Send ResponseBody
	if err := writeFrame(pw, &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{
				Body:        []byte("completion RAW_OUTPUT"),
				EndOfStream: true,
			},
		},
	}); err != nil {
		t.Fatalf("writeFrame ResponseBody: %v", err)
	}
	_ = pw.Close()

	var r4 extprocv3.ProcessingResponse
	if err := readFrame(httpResp.Body, &r4); err != nil {
		t.Fatalf("readFrame ResponseBody: %v", err)
	}
	gotRespBody := string(r4.GetResponseBody().GetResponse().GetBodyMutation().GetBody())
	if gotRespBody != "completion SANITIZED_OUTPUT" {
		t.Fatalf("mutated response body = %q", gotRespBody)
	}

	// Verify immediate_response on a second stream.
	pr2, pw2 := io.Pipe()
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, pr2)
	req2.Header.Set("Content-Type", "application/grpc+proto")
	req2.Header.Set("TE", "trailers")
	go func() {
		_ = writeFrame(pw2, &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &extprocv3.HttpHeaders{
					EndOfStream: true,
					Headers: &corev3.HeaderMap{
						Headers: []*corev3.HeaderValue{
							{Key: ":method", Value: "POST"},
							{Key: ":path", Value: "/immediate-deny"},
						},
					},
				},
			},
		})
		_ = pw2.Close()
	}()
	httpResp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("client.Do 2: %v", err)
	}
	defer func() { _ = httpResp2.Body.Close() }()
	var rDeny extprocv3.ProcessingResponse
	if err := readFrame(httpResp2.Body, &rDeny); err != nil {
		t.Fatalf("readFrame deny: %v", err)
	}
	if rDeny.GetImmediateResponse().GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected Forbidden ImmediateResponse, got %+v", rDeny)
	}
}

func generateSelfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
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
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, pool
}

func ExampleCalloutServer() {
	fmt.Println(methodPath)
	// Output: /envoy.service.ext_proc.v3.ExternalProcessor/Process
}
