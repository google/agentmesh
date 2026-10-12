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

// Setup applies the sink URL, the LOG_FORMAT=json bridge and the log level.
// go-log reads GOLOG_LOG_FMT at package init, before main runs, so the
// config has to be re-applied here through SetupLogging.
func Setup(level, sinkURL string) {
	cfg := golog.GetConfig()
	if sinkURL != "" {
		cfg.URL = sinkURL
	}
	if os.Getenv("LOG_FORMAT") == "json" {
		cfg.Format = golog.JSONOutput
	}
	golog.SetupLogging(cfg)

	lvl := golog.LevelInfo
	var levelErr error
	if level != "" {
		if parsed, err := golog.LevelFromString(level); err == nil {
			lvl = parsed
		} else {
			levelErr = err
		}
	}
	golog.SetAllLoggers(lvl)
	// Warn after SetAllLoggers, which sets this logger to a level that lets
	// the warning through.
	if levelErr != nil {
		logger.Warnf("invalid log level %q, falling back to info", level)
	}
	// go-libp2p-kad-dht logs routine small-mesh conditions (empty routing
	// table, no closer peers) at INFO/ERROR, the latter through a malformed
	// zap call inside the library. Only an explicit debug level keeps them.
	if lvl > golog.LevelDebug {
		_ = golog.SetLogLevel("dht", "fatal")
		_ = golog.SetLogLevel("dht/RtRefreshManager", "fatal")
	}
}
