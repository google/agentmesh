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
	"os"

	golog "github.com/ipfs/go-log/v2"
)

var logger = golog.Logger("logging")

// Options selects how a binary logs. Zero values keep the defaults: info
// level, the LOG_FORMAT env var (else text) and no extra sink.
type Options struct {
	Level   string // log level: debug, info, warn or error
	Format  string // output format: text or json; empty falls back to $LOG_FORMAT, else text
	SinkURL string // extra go-log sink, e.g. the node's ring buffer
}

// Setup applies opts process-wide. go-log reads its GOLOG_* env at package
// init, before main runs, so the config is re-applied here through
// SetupLogging.
func Setup(opts Options) {
	lvl, levelErr := golog.LevelFromString(opts.Level)
	if levelErr != nil {
		lvl = golog.LevelInfo
	}
	format := opts.Format
	badFormat := format != "" && format != "text" && format != "json"
	if format == "" || badFormat {
		format = os.Getenv("LOG_FORMAT")
	}

	cfg := golog.GetConfig()
	if opts.SinkURL != "" {
		cfg.URL = opts.SinkURL
	}
	switch format {
	case "json":
		cfg.Format = golog.JSONOutput
	case "text":
		cfg.Format = golog.PlaintextOutput
	}
	golog.SetupLogging(cfg)
	golog.SetAllLoggers(lvl)

	// go-log starts at error level, so warnings only show after SetAllLoggers.
	if levelErr != nil {
		logger.Warnf("invalid log level %q, using info", opts.Level)
	}
	if badFormat {
		logger.Warnf("invalid log format %q, want text or json; using LOG_FORMAT", opts.Format)
	}
	// go-libp2p-kad-dht logs routine small-mesh conditions (empty routing
	// table, no closer peers) at INFO/ERROR, the latter through a malformed
	// zap call inside the library. Only an explicit debug level keeps them.
	if lvl > golog.LevelDebug {
		_ = golog.SetLogLevel("dht", "fatal")
		_ = golog.SetLogLevel("dht/RtRefreshManager", "fatal")
	}
}
