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

package tunnel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// stubCloudflared writes a shell script that mimics cloudflared's banner on
// stderr and then runs until killed, like the real connector.
func stubCloudflared(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloudflared")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// resolved is a LookupHost for tests whose fake hostnames exist nowhere.
func resolved(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil }

// fakeAuthoritative starts a UDP nameserver that answers NXDOMAIN for the
// first misses queries and an A record afterwards, like the zone's own
// server watching a record get created. It returns its address and the
// query counter.
func fakeAuthoritative(t *testing.T, misses int32) (string, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var n atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			sz, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if err := q.Unpack(buf[:sz]); err != nil || len(q.Questions) != 1 {
				continue
			}
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RCode: dnsmessage.RCodeNameError},
				Questions: q.Questions,
			}
			// Go asks A and AAAA in parallel; only A queries advance the
			// record's existence, AAAA just mirrors the current state.
			exists := n.Load() > misses
			if q.Questions[0].Type == dnsmessage.TypeA {
				exists = n.Add(1) > misses
			}
			if exists {
				resp.RCode = dnsmessage.RCodeSuccess
				if q.Questions[0].Type == dnsmessage.TypeA {
					resp.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
						Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
					}}
				}
			}
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String(), &n
}

func TestCloudflareOpenParsesQuickTunnelURL(t *testing.T) {
	bin := stubCloudflared(t, `
[ "$1" = tunnel ] && [ "$2" = --url ] || { echo "bad args: $*" >&2; exit 2; }
echo "$3" > "$(dirname "$0")/target"
echo "INF Requesting new quick Tunnel on trycloudflare.com..." >&2
echo 'ERR Request failed error="Post \"https://api.trycloudflare.com/tunnel\": context deadline exceeded" retrying' >&2
echo "INF +------------------------------------------------------------+" >&2
echo "INF |  Your quick Tunnel has been created! Visit it at:          |" >&2
echo "INF |  https://brave-otter-quick-1234.trycloudflare.com           |" >&2
echo "INF +------------------------------------------------------------+" >&2
trap 'exit 0' TERM
while :; do sleep 1; done
`)
	p := &Cloudflare{Binary: bin, Timeout: 5 * time.Second, LookupHost: resolved}
	tun, err := p.Open(context.Background(), "http://127.0.0.1:18080")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got, want := tun.URL(), "https://brave-otter-quick-1234.trycloudflare.com"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	target, err := os.ReadFile(filepath.Join(filepath.Dir(bin), "target"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(target)) != "http://127.0.0.1:18080" {
		t.Fatalf("connector got target %q", target)
	}
	select {
	case <-tun.Done():
		t.Fatal("tunnel reported done while the connector is running")
	default:
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-tun.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed after Close")
	}
	if err := tun.Err(); err != nil {
		t.Fatalf("Err after Close = %v, want nil", err)
	}
}

func TestCloudflareOpenNamedTunnel(t *testing.T) {
	bin := stubCloudflared(t, `
[ "$1" = tunnel ] && [ "$2" = --no-autoupdate ] && [ "$3" = run ] && [ "$4" = --url ] || { echo "bad args: $*" >&2; exit 2; }
[ "$TUNNEL_TOKEN" = "cf_secret_tok" ] || { echo "missing env TUNNEL_TOKEN" >&2; exit 3; }
echo "INF Registered tunnel connection connIndex=0" >&2
trap 'exit 0' TERM
while :; do sleep 1; done
`)
	p := &Cloudflare{
		Binary:      bin,
		Timeout:     5 * time.Second,
		Token:       "cf_secret_tok",
		ExternalURL: "https://mesh.example.com/",
	}
	tun, err := p.Open(context.Background(), "http://127.0.0.1:18080")
	if err != nil {
		t.Fatalf("Open named tunnel: %v", err)
	}
	defer func() { _ = tun.Close() }()

	if got, want := tun.URL(), "https://mesh.example.com"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

func TestCloudflareOpenReportsEarlyExit(t *testing.T) {
	bin := stubCloudflared(t, `echo "ERR failed to request quick tunnel" >&2; exit 1`)
	p := &Cloudflare{Binary: bin, Timeout: 5 * time.Second}
	if _, err := p.Open(context.Background(), "http://127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "exited before publishing") {
		t.Fatalf("Open error = %v, want early-exit error", err)
	}
}

// A connector that stops on its own reports why even when its exit status
// is 0: only Close leaves Err nil, and the caller logs the outage only when
// Err is set.
func TestCloudflareReportsUnrequestedCleanExit(t *testing.T) {
	bin := stubCloudflared(t, `echo "INF starting" >&2; exit 0`)
	_, err := (&Cloudflare{Binary: bin, Timeout: 5 * time.Second}).Open(context.Background(), "http://127.0.0.1:1")
	if err == nil || strings.Contains(err.Error(), "%!") {
		t.Errorf("Open error = %v, want an early-exit error with a reason", err)
	}

	gate := filepath.Join(t.TempDir(), "exit")
	bin = stubCloudflared(t, `echo "INF |  https://installed-quick-1234.trycloudflare.com  |" >&2
while [ ! -e "`+gate+`" ]; do sleep 0.01; done
exit 0
`)
	tun, err := (&Cloudflare{Binary: bin, Timeout: 5 * time.Second, LookupHost: resolved}).Open(context.Background(), "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tun.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Done not closed after the connector exited")
	}
	if tun.Err() == nil {
		t.Fatal("Err = nil after the connector exited without Close, want an error")
	}
}

func TestCloudflareOpenTimesOutWithoutURL(t *testing.T) {
	bin := stubCloudflared(t, `trap 'exit 0' TERM; while :; do sleep 1; done`)
	p := &Cloudflare{Binary: bin, Timeout: 200 * time.Millisecond}
	if _, err := p.Open(context.Background(), "http://127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "did not publish") {
		t.Fatalf("Open error = %v, want timeout error", err)
	}
}

// Open must not hand back a URL nobody can resolve yet: the phone that scans
// the QR code in the next second would be told the host does not exist.
func TestCloudflareOpenWaitsForHostnameToBePublished(t *testing.T) {
	bin := stubCloudflared(t, idleConnector)
	var lookups atomic.Int32
	p := &Cloudflare{Binary: bin, Timeout: 5 * time.Second, LookupHost: func(_ context.Context, host string) ([]string, error) {
		if host != "installed-quick-1234.trycloudflare.com" {
			t.Errorf("lookup of %q, want the tunnel hostname", host)
		}
		if lookups.Add(1) <= 2 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []string{"192.0.2.1"}, nil
	}}
	start := time.Now()
	tun, err := p.Open(context.Background(), "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = tun.Close()
	if n := lookups.Load(); n != 3 {
		t.Fatalf("lookups = %d, want 3 (two NXDOMAIN, then an answer)", n)
	}
	if waited := time.Since(start); waited < time.Second {
		t.Fatalf("Open returned after %s, before the name was published", waited)
	}
}

// A name that never shows up delays Open by at most Timeout; the tunnel is
// still returned because DNS, not the tunnel, is what is lagging.
func TestCloudflareOpenGivesUpOnDNSAtDeadline(t *testing.T) {
	bin := stubCloudflared(t, idleConnector)
	p := &Cloudflare{Binary: bin, Timeout: time.Second, LookupHost: func(_ context.Context, host string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}}
	start := time.Now()
	tun, err := p.Open(context.Background(), "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = tun.Close()
	if waited := time.Since(start); waited < time.Second || waited > 4*time.Second {
		t.Fatalf("Open took %s, want about the 1s timeout", waited)
	}
	if tun.URL() != "https://installed-quick-1234.trycloudflare.com" {
		t.Fatalf("URL = %q", tun.URL())
	}
}

// lookupAt asks only the given server, so a recursive resolver in between
// never sees (and never caches) a query for a name that does not exist yet.
func TestLookupAtAsksOnlyTheGivenServer(t *testing.T) {
	server, queries := fakeAuthoritative(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := lookupAt(ctx, server, "fresh-quick-1234.trycloudflare.com")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("first lookup err = %v, want IsNotFound", err)
	}
	addrs, err := lookupAt(ctx, server, "fresh-quick-1234.trycloudflare.com")
	if err != nil || len(addrs) != 1 || addrs[0] != "192.0.2.1" {
		t.Fatalf("second lookup = %v, %v; want [192.0.2.1]", addrs, err)
	}
	if n := queries.Load(); n < 2 {
		t.Fatalf("fake server saw %d queries, want the lookups to reach it", n)
	}
}

func TestCloudflareOpenMissingBinary(t *testing.T) {
	p := &Cloudflare{Binary: filepath.Join(t.TempDir(), "missing")}
	if _, err := p.Open(context.Background(), "http://127.0.0.1:1"); err == nil || !errors.Is(err, ErrCloudflaredUnavailable) {
		t.Fatalf("Open error = %v, want ErrCloudflaredUnavailable", err)
	}
}

// fakeRelease serves one asset for this platform and swaps the pinned
// digests to match it, restoring the table when the test ends. The asset is
// a shell script (raw or tarred, like the real linux/macOS assets), so a
// successful install can also be executed.
func fakeRelease(t *testing.T, script string, tarball bool) (baseURL string, hits *int32) {
	t.Helper()
	orig, ok := pinnedAsset()
	if !ok {
		t.Skipf("no pinned asset for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	body := []byte("#!/bin/sh\n" + script)
	binSum := sha256.Sum256(body)
	asset := body
	if tarball {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: "cloudflared", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
		_ = tw.Close()
		_ = gz.Close()
		asset = buf.Bytes()
	}
	assetSum := sha256.Sum256(asset)
	key := runtime.GOOS + "/" + runtime.GOARCH
	cloudflaredAssets[key] = releaseAsset{
		Name:         orig.Name,
		AssetSHA256:  hex.EncodeToString(assetSum[:]),
		BinarySHA256: hex.EncodeToString(binSum[:]),
		Tarball:      tarball,
	}
	t.Cleanup(func() { cloudflaredAssets[key] = orig })

	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		if r.URL.Path != "/"+CloudflaredVersion+"/"+orig.Name {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(asset)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/", &count
}

// idleConnector is the script body of a fake cloudflared that publishes a
// URL and waits to be terminated.
const idleConnector = `echo "INF |  https://installed-quick-1234.trycloudflare.com  |" >&2
trap 'exit 0' TERM
while :; do sleep 1; done
`

func TestCloudflareDownloadsPinnedReleaseWithConsent(t *testing.T) {
	for _, tarball := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "tarball"}[tarball], func(t *testing.T) {
			base, hits := fakeRelease(t, idleConnector, tarball)
			dir := filepath.Join(t.TempDir(), "bin")
			var asked []string
			p := &Cloudflare{
				InstallDir: dir,
				ReleaseURL: base,
				Timeout:    5 * time.Second,
				LookupHost: resolved,
				Consent: func(version, url string) bool {
					asked = append(asked, version+" "+url)
					return true
				},
			}
			t.Setenv("PATH", t.TempDir()) // no system cloudflared

			tun, err := p.Open(context.Background(), "http://127.0.0.1:1")
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			_ = tun.Close()
			if len(asked) != 1 || !strings.Contains(asked[0], CloudflaredVersion) || !strings.Contains(asked[0], base) {
				t.Fatalf("consent asked = %v", asked)
			}
			if tun.URL() != "https://installed-quick-1234.trycloudflare.com" {
				t.Fatalf("URL = %q", tun.URL())
			}
			installed := installedCloudflared(dir)
			if fi, err := os.Stat(installed); err != nil || fi.Mode().Perm()&0o111 == 0 {
				t.Fatalf("installed binary missing or not executable: %v %v", fi, err)
			}
			if leftovers, _ := filepath.Glob(filepath.Join(dir, ".cloudflared-*")); len(leftovers) != 0 {
				t.Fatalf("temp files left behind: %v", leftovers)
			}

			// Second run: the verified cache is reused, nothing is asked or fetched.
			tun, err = p.Open(context.Background(), "http://127.0.0.1:1")
			if err != nil {
				t.Fatalf("second Open: %v", err)
			}
			_ = tun.Close()
			if len(asked) != 1 || atomic.LoadInt32(hits) != 1 {
				t.Fatalf("cache not used: consent asked %d times, release fetched %d times", len(asked), *hits)
			}
		})
	}
}

func TestCloudflareRefusesDownloadWithoutConsent(t *testing.T) {
	base, hits := fakeRelease(t, idleConnector, false)
	t.Setenv("PATH", t.TempDir())
	p := &Cloudflare{InstallDir: filepath.Join(t.TempDir(), "bin"), ReleaseURL: base}
	_, err := p.Open(context.Background(), "http://127.0.0.1:1")
	if !errors.Is(err, ErrCloudflaredUnavailable) {
		t.Fatalf("nil Consent: err = %v, want ErrCloudflaredUnavailable", err)
	}
	p.Consent = func(string, string) bool { return false }
	_, err = p.Open(context.Background(), "http://127.0.0.1:1")
	if !errors.Is(err, ErrCloudflaredUnavailable) || atomic.LoadInt32(hits) != 0 {
		t.Fatalf("declined Consent: err = %v, fetches = %d", err, *hits)
	}
}

func TestCloudflareRejectsTamperedDownloadAndCache(t *testing.T) {
	base, _ := fakeRelease(t, idleConnector, false)
	t.Setenv("PATH", t.TempDir())
	dir := filepath.Join(t.TempDir(), "bin")
	p := &Cloudflare{InstallDir: dir, ReleaseURL: base, Timeout: 5 * time.Second, LookupHost: resolved, Consent: func(string, string) bool { return true }}

	// A cached file with the right name but the wrong content is never run;
	// it is replaced by a verified download.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installedCloudflared(dir), []byte("#!/bin/sh\necho pwned >&2; exit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tun, err := p.Open(context.Background(), "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("Open with tampered cache: %v", err)
	}
	_ = tun.Close()
	if asset, _ := pinnedAsset(); !verifyBinary(installedCloudflared(dir), asset.BinarySHA256) {
		t.Fatal("tampered cache was not replaced by the verified build")
	}

	// A download whose bytes do not match the pin is discarded.
	key := runtime.GOOS + "/" + runtime.GOARCH
	bad := cloudflaredAssets[key]
	bad.AssetSHA256 = strings.Repeat("0", 64)
	cloudflaredAssets[key] = bad
	_ = os.Remove(installedCloudflared(dir))
	if _, err := p.Open(context.Background(), "http://127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("Open with mismatching asset digest: err = %v", err)
	}
	if _, err := os.Stat(installedCloudflared(dir)); !os.IsNotExist(err) {
		t.Fatal("mismatching download was installed")
	}
}

func TestLookup(t *testing.T) {
	p, err := Lookup(" Cloudflare ")
	if err != nil || p.Name() != "cloudflare" {
		t.Fatalf("Lookup = %v, %v", p, err)
	}
	if _, err := Lookup("ngrok"); err == nil || !strings.Contains(err.Error(), "available: cloudflare") {
		t.Fatalf("Lookup unknown = %v", err)
	}
}

// ExternalURL names the hostname of a named tunnel; without a Token the
// connector runs a quick tunnel, and the URL published is the one it was
// assigned, not ExternalURL.
func TestCloudflareQuickTunnelIgnoresExternalURL(t *testing.T) {
	bin := stubCloudflared(t, `echo "INF |  https://quick-ext-1234.trycloudflare.com  |" >&2
echo "INF Registered tunnel connection connIndex=0 location=ams01 protocol=quic" >&2
trap 'exit 0' TERM
while :; do sleep 1; done
`)
	p := &Cloudflare{Binary: bin, Timeout: 5 * time.Second, LookupHost: resolved, ExternalURL: "https://mesh.example.com"}
	tun, err := p.Open(context.Background(), "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	if got, want := tun.URL(), "https://quick-ext-1234.trycloudflare.com"; got != want {
		t.Fatalf("URL = %q, want the assigned quick-tunnel URL %q", got, want)
	}
}

// A named tunnel needs a hostname: an ExternalURL that trims to nothing is
// refused before cloudflared is started.
func TestCloudflareNamedTunnelRefusesAnEmptyExternalURL(t *testing.T) {
	for _, externalURL := range []string{"", "  ", "/", " // "} {
		p := &Cloudflare{Binary: filepath.Join(t.TempDir(), "never-started"), Token: "token", ExternalURL: externalURL}
		_, err := p.Open(context.Background(), "http://127.0.0.1:1")
		if err == nil || !strings.Contains(err.Error(), "requires ExternalURL") {
			t.Errorf("Open with ExternalURL %q: err = %v, want the ExternalURL refusal", externalURL, err)
		}
	}
}
