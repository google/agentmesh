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

// Command generic-containment-webhook is a runnable reference receiver for
// Google Agent Mesh out-of-band security containment signals.
//
// It demonstrates how external supervisors (Kubernetes admission/container
// controllers, OpenShell sandbox supervisors, host security daemons, or SIEMs)
// consume, authenticate, and process CloudEvents 1.0 security signals emitted
// by agentmesh-node and agentmesh-control-plane.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/agentmesh/api"
	"google.golang.org/protobuf/encoding/protojson"
)

// CloudEvents 1.0 and Agent Mesh header constants.
const (
	headerCESpecVersion      = "ce-specversion"
	headerCEID               = "ce-id"
	headerCEType             = "ce-type"
	headerCESource           = "ce-source"
	headerCETime             = "ce-time"
	headerCESubject          = "ce-subject"
	headerContentType        = "Content-Type"
	headerAgentMeshTimestamp = "X-AgentMesh-Timestamp"
	headerAgentMeshSignature = "X-AgentMesh-Signature"

	maxBodyBytes     = 1 << 20 // 1 MB limit
	maxClockSkew     = 5 * time.Minute
	defaultPort      = 8095
	defaultSocketURL = ""
)

// ANSI color escape codes.
const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiRed     = "\033[31m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiBlue    = "\033[34m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
	ansiGray    = "\033[90m"
)

// HandlerConfig configures the security webhook HTTP handler.
type HandlerConfig struct {
	HMACSecret []byte
	Verbose    bool
	NoColor    bool
}

// NewWebhookHandler constructs an http.Handler that authenticates CloudEvents 1.0
// headers, verifies HMAC-SHA256 signatures, deserializes api.SecuritySignalEvent,
// and pretty-prints the containment signal.
func NewWebhookHandler(cfg HandlerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed: only POST is supported for webhook events", http.StatusMethodNotAllowed)
			return
		}

		// 1. Validate CloudEvents 1.0 specification headers
		specVersion := r.Header.Get(headerCESpecVersion)
		if specVersion != "1.0" {
			http.Error(w, fmt.Sprintf("Bad Request: %s header must be '1.0' (got %q)", headerCESpecVersion, specVersion), http.StatusBadRequest)
			return
		}

		ceID := r.Header.Get(headerCEID)
		if ceID == "" {
			http.Error(w, fmt.Sprintf("Bad Request: %s header is required", headerCEID), http.StatusBadRequest)
			return
		}

		ceType := r.Header.Get(headerCEType)
		if ceType == "" {
			http.Error(w, fmt.Sprintf("Bad Request: %s header is required", headerCEType), http.StatusBadRequest)
			return
		}

		ceSource := r.Header.Get(headerCESource)
		if ceSource == "" {
			http.Error(w, fmt.Sprintf("Bad Request: %s header is required", headerCESource), http.StatusBadRequest)
			return
		}

		// 2. Read request body safely
		defer func() { _ = r.Body.Close() }()
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		if err != nil {
			http.Error(w, "Bad Request: unable to read request body", http.StatusBadRequest)
			return
		}
		if len(bodyBytes) > maxBodyBytes {
			http.Error(w, "Payload Too Large: request body exceeds 1MB limit", http.StatusRequestEntityTooLarge)
			return
		}

		// 3. Verify HMAC-SHA256 signature if secret is configured
		if len(cfg.HMACSecret) > 0 {
			tsStr := r.Header.Get(headerAgentMeshTimestamp)
			sigHeader := r.Header.Get(headerAgentMeshSignature)

			if tsStr == "" || sigHeader == "" {
				http.Error(w, "Unauthorized: missing X-AgentMesh-Timestamp or X-AgentMesh-Signature header", http.StatusUnauthorized)
				return
			}

			// Verify timestamp freshness
			tsMillis, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				http.Error(w, "Unauthorized: invalid X-AgentMesh-Timestamp header", http.StatusUnauthorized)
				return
			}
			eventTime := time.UnixMilli(tsMillis)
			skew := time.Since(eventTime).Abs()
			if skew > maxClockSkew {
				http.Error(w, fmt.Sprintf("Unauthorized: timestamp skew too large (%v > %v)", skew, maxClockSkew), http.StatusUnauthorized)
				return
			}

			// Compute HMAC-SHA256: secret over timestamp + "." + body
			mac := hmac.New(sha256.New, cfg.HMACSecret)
			mac.Write([]byte(tsStr))
			mac.Write([]byte("."))
			mac.Write(bodyBytes)
			expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

			if subtle.ConstantTimeCompare([]byte(sigHeader), []byte(expectedSig)) != 1 {
				http.Error(w, "Unauthorized: HMAC signature verification failed", http.StatusUnauthorized)
				return
			}
		}

		// 4. Deserialize protojson body into api.SecuritySignalEvent
		event := &api.SecuritySignalEvent{}
		unmarshalOpts := protojson.UnmarshalOptions{
			DiscardUnknown: false,
		}
		if err := unmarshalOpts.Unmarshal(bodyBytes, event); err != nil {
			http.Error(w, fmt.Sprintf("Bad Request: protojson unmarshal failed: %v", err), http.StatusBadRequest)
			return
		}

		// 5. Format and pretty-print signal to stdout
		printSecurityEvent(event, r, cfg)

		// 6. Return 200 OK acknowledgment
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"acknowledged","id":%q,"type":%q}`+"\n", event.GetId(), event.GetType())
	})
}

func printSecurityEvent(event *api.SecuritySignalEvent, r *http.Request, cfg HandlerConfig) {
	c := colorizer{!cfg.NoColor}

	bannerColor := ansiBlue
	switch event.GetType() {
	case "agentmesh.policy.denied":
		bannerColor = ansiRed
	case "agentmesh.transport.refused":
		bannerColor = ansiYellow
	case "agentmesh.identity.revoked":
		bannerColor = ansiMagenta
	case "agentmesh.enrollment.rejected":
		bannerColor = ansiCyan
	}

	border := strings.Repeat("=", 80)
	divider := strings.Repeat("-", 80)

	fmt.Println()
	fmt.Println(c.color(bannerColor+ansiBold, border))
	fmt.Printf("%s %s%s%s\n",
		c.color(bannerColor+ansiBold, "[SECURITY SIGNAL RECEIVED]"),
		c.color(ansiBold, "Type: "),
		c.color(bannerColor+ansiBold, event.GetType()),
		c.color(ansiGray, fmt.Sprintf(" (via %s)", r.RemoteAddr)),
	)
	fmt.Println(c.color(ansiGray, divider))

	// Envelope Fields
	fmt.Printf("  %-16s %s\n", c.color(ansiBold, "ID:"), event.GetId())
	fmt.Printf("  %-16s %s\n", c.color(ansiBold, "Source:"), event.GetSource())
	fmt.Printf("  %-16s %s\n", c.color(ansiBold, "SpecVersion:"), event.GetSpecVersion())
	if event.GetSubject() != "" {
		fmt.Printf("  %-16s %s\n", c.color(ansiBold, "Subject:"), event.GetSubject())
	}
	if event.GetEventTime() != nil {
		t := event.GetEventTime().AsTime()
		fmt.Printf("  %-16s %s (%s)\n", c.color(ansiBold, "Event Time:"), t.Format(time.RFC3339Nano), time.Since(t).Round(time.Millisecond).String()+" ago")
	}

	// Typed Data Oneof Payload
	fmt.Println(c.color(ansiGray, divider))
	switch d := event.GetData().(type) {
	case *api.SecuritySignalEvent_PolicyDenied:
		p := d.PolicyDenied
		fmt.Printf("  %s:\n", c.color(ansiRed+ansiBold, "PolicyDeniedSignal"))
		fmt.Printf("    %-20s %s\n", "Direction:", p.GetDirection().String())
		fmt.Printf("    %-20s %s\n", "Reason:", c.color(ansiRed, p.GetReason().String()))
		fmt.Printf("    %-20s %s\n", "Detail:", p.GetDetail())
		fmt.Printf("    %-20s %s\n", "Target Service:", c.color(ansiBold, p.GetTargetService()))
		if p.GetRequestedOperation() != "" {
			fmt.Printf("    %-20s %s\n", "Requested Op:", p.GetRequestedOperation())
		}
		if p.GetRequestedResource() != "" {
			fmt.Printf("    %-20s %s\n", "Requested Res:", p.GetRequestedResource())
		}
		if p.GetCallerPeerId() != "" {
			fmt.Printf("    %-20s %s\n", "Caller Peer ID:", p.GetCallerPeerId())
		}
		if p.GetCallerSubject() != "" {
			fmt.Printf("    %-20s %s\n", "Caller Subject:", p.GetCallerSubject())
		}
		if len(p.GetCallerRoles()) > 0 {
			fmt.Printf("    %-20s %s\n", "Caller Roles:", strings.Join(p.GetCallerRoles(), ", "))
		}
		if len(p.GetCallerLabels()) > 0 {
			labels := make([]string, 0, len(p.GetCallerLabels()))
			for k, v := range p.GetCallerLabels() {
				labels = append(labels, fmt.Sprintf("%s=%s", k, v))
			}
			fmt.Printf("    %-20s %s\n", "Caller Labels:", strings.Join(labels, ", "))
		}

	case *api.SecuritySignalEvent_TransportRefused:
		t := d.TransportRefused
		fmt.Printf("  %s:\n", c.color(ansiYellow+ansiBold, "TransportRefusedSignal"))
		fmt.Printf("    %-20s %s\n", "Reason:", c.color(ansiYellow, t.GetReason().String()))
		fmt.Printf("    %-20s %s\n", "Detail:", t.GetDetail())
		fmt.Printf("    %-20s %s\n", "Peer ID:", t.GetPeerId())
		fmt.Printf("    %-20s %s\n", "Remote Multiaddr:", t.GetRemoteMultiaddr())
		fmt.Printf("    %-20s %s\n", "Protocol ID:", t.GetProtocolId())
		if t.GetCoalescedCount() > 1 {
			fmt.Printf("    %-20s %s\n", "Coalesced Count:", c.color(ansiBold, strconv.FormatUint(uint64(t.GetCoalescedCount()), 10)))
		}

	case *api.SecuritySignalEvent_IdentityRevoked:
		i := d.IdentityRevoked
		fmt.Printf("  %s:\n", c.color(ansiMagenta+ansiBold, "IdentityRevokedSignal"))
		fmt.Printf("    %-20s %s\n", "Peer ID:", c.color(ansiMagenta+ansiBold, i.GetPeerId()))
		fmt.Printf("    %-20s %s\n", "Source:", i.GetSource().String())
		fmt.Printf("    %-20s %s\n", "Reason:", i.GetReason())
		if len(i.GetRevocationIds()) > 0 {
			fmt.Printf("    %-20s %s\n", "Revocation IDs:", strings.Join(i.GetRevocationIds(), ", "))
		}
		if i.GetIssuerPeerId() != "" {
			fmt.Printf("    %-20s %s\n", "Issuer Peer ID:", i.GetIssuerPeerId())
		}

	case *api.SecuritySignalEvent_EnrollmentRejected:
		e := d.EnrollmentRejected
		fmt.Printf("  %s:\n", c.color(ansiCyan+ansiBold, "EnrollmentRejectedSignal"))
		fmt.Printf("    %-20s %s\n", "Peer ID:", e.GetPeerId())
		fmt.Printf("    %-20s %s\n", "Requested Role:", e.GetRequestedRole())
		fmt.Printf("    %-20s %s\n", "Reason:", c.color(ansiCyan, e.GetReason().String()))
		fmt.Printf("    %-20s %s\n", "Detail:", e.GetDetail())
		if e.GetBootstrapTokenId() != "" {
			fmt.Printf("    %-20s %s\n", "Token ID:", e.GetBootstrapTokenId())
		}
		if e.GetRemoteAddress() != "" {
			fmt.Printf("    %-20s %s\n", "Remote Address:", e.GetRemoteAddress())
		}
		if e.GetIsAutonomousRecovery() {
			fmt.Printf("    %-20s %s\n", "Autonomous Recov:", "true")
		}

	default:
		fmt.Printf("  %s\n", c.color(ansiGray, "No payload or unrecognized data type"))
	}

	// Verbose Dump
	if cfg.Verbose {
		fmt.Println(c.color(ansiGray, divider))
		fmt.Println(c.color(ansiBold, "Raw ProtoJSON Payload:"))
		m := protojson.MarshalOptions{Multiline: true, Indent: "  "}
		if jsonDump, err := m.Marshal(event); err == nil {
			fmt.Println(string(jsonDump))
		}
	}

	fmt.Println(c.color(bannerColor+ansiBold, border))
	fmt.Println()
}

type colorizer struct {
	enabled bool
}

func (c colorizer) color(code, text string) string {
	if !c.enabled {
		return text
	}
	return code + text + ansiReset
}

func main() {
	portFlag := flag.Int("port", defaultPort, "Local TCP port for HTTP webhook receiver (0 to disable TCP)")
	socketPathFlag := flag.String("socket-path", defaultSocketURL, "Unix domain socket path for webhook receiver (e.g. /tmp/containment.sock)")
	hmacSecretPathFlag := flag.String("hmac-secret-path", "", "Path to file containing shared secret for HMAC-SHA256 signature verification")
	verboseFlag := flag.Bool("verbose", false, "Print raw protojson event body in addition to formatted summary")
	noColorFlag := flag.Bool("no-color", false, "Disable ANSI color formatting in console output")
	flag.Parse()

	// Detect if NO_COLOR environment variable is set
	if os.Getenv("NO_COLOR") != "" {
		*noColorFlag = true
	}

	if *portFlag <= 0 && *socketPathFlag == "" {
		log.Fatalf("Fatal: at least one of -port (>0) or -socket-path must be specified")
	}

	var hmacSecret []byte
	if *hmacSecretPathFlag != "" {
		secretBytes, err := os.ReadFile(*hmacSecretPathFlag)
		if err != nil {
			log.Fatalf("Fatal: reading HMAC secret file %q: %v", *hmacSecretPathFlag, err)
		}
		hmacSecret = bytes.TrimSpace(secretBytes)
		log.Printf("HMAC-SHA256 verification enabled (secret loaded from %s, length: %d bytes)", *hmacSecretPathFlag, len(hmacSecret))
	} else {
		log.Printf("HMAC signature verification disabled (no -hmac-secret-path provided)")
	}

	handler := NewWebhookHandler(HandlerConfig{
		HMACSecret: hmacSecret,
		Verbose:    *verboseFlag,
		NoColor:    *noColorFlag,
	})

	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.Handle("/events", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	// Start TCP listener if configured
	if *portFlag > 0 {
		tcpAddr := fmt.Sprintf("127.0.0.1:%d", *portFlag)
		tcpServer := &http.Server{
			Addr:              tcpAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("Listening for containment signals on HTTP http://%s/events", tcpAddr)
			if err := tcpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP listener error: %v", err)
			}
		}()

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer shutdownCancel()
			_ = tcpServer.Shutdown(shutdownCtx)
		}()
	}

	// Start Unix domain socket listener if configured
	if *socketPathFlag != "" {
		sockPath := *socketPathFlag
		_ = os.Remove(sockPath) // Clean up stale socket file if it exists

		unixListener, err := net.Listen("unix", sockPath)
		if err != nil {
			log.Fatalf("Fatal: creating Unix domain socket listener at %s: %v", sockPath, err)
		}
		defer func() { _ = os.Remove(sockPath) }()

		unixServer := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("Listening for containment signals on Unix socket unix:%s", sockPath)
			if err := unixServer.Serve(unixListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("Unix socket listener error: %v", err)
			}
		}()

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer shutdownCancel()
			_ = unixServer.Shutdown(shutdownCtx)
		}()
	}

	log.Printf("Generic Containment Webhook receiver ready. Press Ctrl+C to exit.")
	<-ctx.Done()
	log.Printf("Shutting down containment webhook receiver...")
	wg.Wait()
	log.Printf("Receiver gracefully terminated.")
}
