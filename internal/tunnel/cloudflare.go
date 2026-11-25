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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	golog "github.com/ipfs/go-log/v2"
)

var logger = golog.Logger("tunnel")

// Cloudflare opens a TryCloudflare quick tunnel: `cloudflared tunnel --url
// <target>` publishes the target on a random https://*.trycloudflare.com
// subdomain with no account or login. Quick tunnels are a development
// convenience with no SLA; cloudflared prints the assigned URL on its log
// output, which is the only thing this provider parses.
//
// The connector binary is resolved in order: Binary if set, `cloudflared` on
// PATH, a previously installed copy under InstallDir whose digest still
// matches the pin, and finally a fresh download of the pinned release, which
// happens only if Consent agrees. A cached copy that fails verification is
// never run.
type Cloudflare struct {
	// Binary is an explicit cloudflared executable; when set, nothing else
	// is tried.
	Binary string
	// Timeout bounds how long Open waits for the URL and then for its
	// hostname to be published in DNS; defaults to 30s.
	Timeout time.Duration
	// InstallDir is where a downloaded cloudflared is kept (agentmesh-one uses
	// <data-dir>/bin). Empty disables both the cache and downloads.
	InstallDir string
	// Consent is asked before downloading; installing cloudflared means
	// accepting Cloudflare's license, so this must be an explicit choice.
	// Nil never downloads.
	Consent func(version, url string) bool
	// ReleaseURL overrides the GitHub release download prefix (mirrors,
	// tests). The pinned digests still apply.
	ReleaseURL string
	// HTTPClient performs the download; nil uses a 10 minute timeout.
	HTTPClient *http.Client
	// LookupHost asks whether the assigned hostname exists yet; nil asks
	// the zone's authoritative nameserver (see authoritativeLookup). Tests
	// stub it.
	LookupHost func(ctx context.Context, host string) ([]string, error)
	// Token is an optional named tunnel token (from --tunnel-token-path
	// or AGENTMESH_TUNNEL_TOKEN). When set, Open runs
	// `cloudflared tunnel --no-autoupdate run --url <target>` with
	// TUNNEL_TOKEN in the child environment instead of a random
	// trycloudflare.com quick tunnel, and publishes ExternalURL.
	Token string
	// ExternalURL is the public https:// hostname routed to the named
	// tunnel when Token is set.
	ExternalURL string
}

// quickTunnelURL matches the assigned hostname in cloudflared's banner. The
// same pattern also matches cloudflared's own API endpoint, which shows up
// in retry logs before the banner; assignedQuickTunnelURL filters it out.
var quickTunnelURL = regexp.MustCompile(`https://([a-z0-9-]+)\.trycloudflare\.com`)

// assignedQuickTunnelURL returns the quick-tunnel URL in line, or "" when
// the line has none or only names api.trycloudflare.com.
func assignedQuickTunnelURL(line string) string {
	for _, m := range quickTunnelURL.FindAllStringSubmatch(line, -1) {
		if m[1] != "api" {
			return m[0]
		}
	}
	return ""
}

// Name implements Provider.
func (c *Cloudflare) Name() string { return "cloudflare" }

// Open implements Provider.
func (c *Cloudflare) Open(ctx context.Context, target string) (Tunnel, error) {
	namedURL := strings.TrimRight(strings.TrimSpace(c.ExternalURL), "/")
	if c.Token != "" && namedURL == "" {
		return nil, fmt.Errorf("cloudflare named tunnel requires ExternalURL (--external-url)")
	}
	binary, err := c.resolveBinary(ctx)
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)

	// The process outlives Open: its lifetime is the tunnel's, ended by Close.
	procCtx, cancel := context.WithCancel(context.Background())
	var cmd *exec.Cmd
	if c.Token != "" {
		cmd = exec.CommandContext(procCtx, binary, "tunnel", "--no-autoupdate", "run", "--url", target)
		cmd.Env = append(os.Environ(), "TUNNEL_TOKEN="+c.Token)
	} else {
		cmd = exec.CommandContext(procCtx, binary, "tunnel", "--url", target, "--no-autoupdate")
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start cloudflared: %w", err)
	}
	t := &process{cancel: cancel, done: make(chan struct{})}
	if c.Token != "" {
		t.namedURL = namedURL
	}
	urlCh := make(chan string, 1)
	go t.scan(pr, urlCh)
	go func() {
		err := cmd.Wait()
		_ = pw.Close()
		t.finish(err)
	}()

	select {
	case u := <-urlCh:
		t.url = u
		if c.Token == "" {
			c.awaitPublished(ctx, u, deadline)
		}
		return t, nil
	case <-t.done:
		return nil, fmt.Errorf("cloudflared exited before publishing a URL: %w", t.Err())
	case <-time.After(timeout):
		_ = t.Close()
		return nil, fmt.Errorf("cloudflared did not publish a URL within %s", timeout)
	case <-ctx.Done():
		_ = t.Close()
		return nil, ctx.Err()
	}
}

// awaitPublished blocks until the tunnel hostname exists in DNS, the deadline
// passes or ctx ends. A quick-tunnel record appears a few seconds after
// cloudflared prints the URL, and a device that asks before then is told the
// host does not exist, so the URL must not be announced earlier. Missing the
// deadline is not an error: the tunnel works once DNS catches up.
func (c *Cloudflare) awaitPublished(ctx context.Context, rawURL string, deadline time.Time) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	lookup := c.LookupHost
	if lookup == nil {
		lookup = authoritativeLookup
	}
	for {
		lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := lookup(lctx, u.Hostname())
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			logger.Warnf("%s is not published in DNS yet; devices may need a moment before they can reach it", u.Hostname())
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// authoritativeLookup resolves host at its zone's own nameserver, bypassing
// every cache in between. Asking a recursive resolver before the record
// exists makes it cache the NXDOMAIN (the zone's SOA allows 30 minutes) and
// strands every device behind that resolver, including a agentmesh-node on this
// very machine; the authoritative server has no cache to poison.
func authoritativeLookup(ctx context.Context, host string) ([]string, error) {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid host: %s", host)
	}
	zone := strings.Join(parts[len(parts)-2:], ".")
	nss, err := net.DefaultResolver.LookupNS(ctx, zone)
	if err != nil {
		return nil, err
	}
	if len(nss) == 0 || nss[0] == nil {
		return nil, fmt.Errorf("no nameservers for %s", zone)
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, nss[0].Host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no address for nameserver %s", nss[0].Host)
	}
	return lookupAt(ctx, net.JoinHostPort(addrs[0], "53"), host)
}

// lookupAt resolves host by asking only the nameserver at server.
func lookupAt(ctx context.Context, server, host string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
	// The trailing dot makes the name absolute so no search domain is tried.
	return r.LookupHost(ctx, host+".")
}

// resolveBinary picks the cloudflared to run; see the type doc for the order.
func (c *Cloudflare) resolveBinary(ctx context.Context) (string, error) {
	if c.Binary != "" {
		path, err := exec.LookPath(c.Binary)
		if err != nil {
			return "", fmt.Errorf("%w at %q: %v", ErrCloudflaredUnavailable, c.Binary, err)
		}
		return path, nil
	}
	if path, err := exec.LookPath("cloudflared"); err == nil {
		return path, nil
	}
	if c.InstallDir == "" {
		return "", fmt.Errorf("%w on PATH (install it from %s)", ErrCloudflaredUnavailable, CloudflaredLicenseURL)
	}
	asset, ok := pinnedAsset()
	if !ok {
		return "", fmt.Errorf("%w on PATH and no pinned build for %s/%s (install it from %s)", ErrCloudflaredUnavailable, runtime.GOOS, runtime.GOARCH, CloudflaredLicenseURL)
	}
	cached := installedCloudflared(c.InstallDir)
	if verifyBinary(cached, asset.BinarySHA256) {
		return cached, nil
	}
	if _, err := os.Stat(cached); err == nil {
		logger.Warnf("Ignoring %s: digest does not match the pinned cloudflared %s", cached, CloudflaredVersion)
	}
	base := c.ReleaseURL
	if base == "" {
		base = DefaultCloudflaredReleaseURL
	}
	url := base + CloudflaredVersion + "/" + asset.Name
	if c.Consent == nil || !c.Consent(CloudflaredVersion, url) {
		return "", fmt.Errorf("%w on PATH and download not authorized (install it from %s, or allow agentmesh-one to download the pinned release)", ErrCloudflaredUnavailable, CloudflaredLicenseURL)
	}
	client := c.HTTPClient
	if client == nil {
		client = defaultDownloadClient()
	}
	return downloadCloudflared(ctx, client, base, c.InstallDir)
}

// process is a Tunnel backed by a child connector process.
type process struct {
	url      string
	namedURL string
	cancel   context.CancelFunc
	done     chan struct{}

	mu     sync.Mutex
	closed bool
	err    error
}

func (p *process) URL() string           { return p.url }
func (p *process) Done() <-chan struct{} { return p.done }

func (p *process) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *process) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.cancel()
	<-p.done
	return nil
}

// finish records the exit and releases Done; an exit caused by Close is
// not an error, any other exit is, even with status 0.
func (p *process) finish(err error) {
	p.mu.Lock()
	if !p.closed {
		if err == nil {
			err = errors.New("exit status 0")
		}
		p.err = err
	}
	p.mu.Unlock()
	close(p.done)
}

// scan drains the connector's output for its lifetime (a full pipe would
// stall the child) and reports the first quick-tunnel URL (or named-tunnel
// edge registration) it sees.
func (p *process) scan(r io.Reader, urlCh chan<- string) {
	sc := bufio.NewScanner(r)
	found := false
	for sc.Scan() {
		line := sc.Text()
		logger.Debugf("cloudflared: %s", line)
		if !found {
			if p.namedURL != "" {
				if strings.Contains(line, "Registered tunnel connection") {
					found = true
					urlCh <- p.namedURL
				}
			} else if m := assignedQuickTunnelURL(line); m != "" {
				found = true
				urlCh <- m
			}
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		logger.Debugf("cloudflared output closed: %v", err)
		_, _ = io.Copy(io.Discard, r)
	}
}
