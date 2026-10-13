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

// Package logging configures go-log the same way in every binary.
package logging

import (
	"container/ring"
	"net/url"
	"strings"
	"sync"

	golog "github.com/ipfs/go-log/v2"
	"go.uber.org/zap"
)

var logger = golog.Logger("logging")

const (
	ringBufferScheme = "ringbuffer"
	logBufferLines   = 500
	// maxLogLineBytes bounds each retained line so the ring's memory is
	// bounded too (logBufferLines * maxLogLineBytes), whatever a remote peer
	// manages to get logged.
	maxLogLineBytes = 4 << 10
)

var (
	ringBufferOnce sync.Once
	ringBuffer     *ringBufferSink
)

// Options selects how a binary logs. Zero values keep the defaults: info
// level, text format and no in-memory ring buffer.
type Options struct {
	Level      string // log level: debug, info, warn or error (default: info)
	Format     string // output format: text or json (default: text)
	RingBuffer bool   // also retain the most recent lines in memory (see RecentLogs)
}

// Setup applies opts process-wide.
func Setup(opts Options) {
	lvl := golog.LevelInfo
	var levelErr error
	if opts.Level != "" {
		lvl, levelErr = golog.LevelFromString(opts.Level)
		if levelErr != nil {
			lvl = golog.LevelInfo
		}
	}

	cfg := golog.GetConfig()
	cfg.Level = lvl
	if opts.RingBuffer {
		ringBufferOnce.Do(func() {
			ringBuffer = newRingBufferSink(logBufferLines)
			_ = zap.RegisterSink(ringBufferScheme, func(*url.URL) (zap.Sink, error) {
				return ringBuffer, nil
			})
		})
		cfg.URL = ringBufferScheme + "://"
	} else {
		cfg.URL = ""
	}
	badFormat := false
	switch opts.Format {
	case "json":
		cfg.Format = golog.JSONOutput
	case "", "text":
		cfg.Format = golog.PlaintextOutput
	default:
		badFormat = true
		cfg.Format = golog.PlaintextOutput
	}
	golog.SetupLogging(cfg)

	// go-log starts at error level, so warnings only show after SetAllLoggers.
	if levelErr != nil {
		logger.Warnf("invalid log level %q, using info", opts.Level)
	}
	if badFormat {
		logger.Warnf("invalid log format %q, want text or json; using text", opts.Format)
	}
	// go-libp2p-kad-dht logs routine small-mesh conditions (empty routing
	// table, no closer peers) at INFO/ERROR, the latter through a malformed
	// zap call inside the library. Only an explicit debug level keeps them.
	if lvl > golog.LevelDebug {
		_ = golog.SetLogLevel("dht", "fatal")
		_ = golog.SetLogLevel("dht/RtRefreshManager", "fatal")
	}
}

// RecentLogs returns the most recent log lines captured when Options.RingBuffer
// was enabled in Setup.
func RecentLogs() []string {
	if ringBuffer == nil {
		return []string{}
	}
	return ringBuffer.lines()
}

type ringBufferSink struct {
	mu     sync.Mutex
	buffer *ring.Ring
}

func newRingBufferSink(lines int) *ringBufferSink {
	return &ringBufferSink{buffer: ring.New(lines)}
}

func (s *ringBufferSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// zap writes complete log lines per Write call.
	line := strings.TrimSuffix(string(p), "\n")
	if len(line) > maxLogLineBytes {
		line = line[:maxLogLineBytes] + "…[truncated]"
	}
	s.buffer.Value = line
	s.buffer = s.buffer.Next()
	return len(p), nil
}

func (s *ringBufferSink) Sync() error  { return nil }
func (s *ringBufferSink) Close() error { return nil }

func (s *ringBufferSink) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	logs := []string{}
	s.buffer.Do(func(p any) {
		if p != nil {
			logs = append(logs, p.(string))
		}
	})
	return logs
}
