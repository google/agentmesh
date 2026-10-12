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

package logging

import (
	"testing"

	golog "github.com/ipfs/go-log/v2"
	"go.uber.org/zap/zapcore"
)

func TestSetupFormatBridge(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	Setup("info", "")
	if got := golog.GetConfig().Format; got != golog.JSONOutput {
		t.Fatalf("format = %v, want %v (JSONOutput)", got, golog.JSONOutput)
	}
}

func TestSetupLevels(t *testing.T) {
	dht := golog.Logger("dht")
	app := golog.Logger("logging-test-app")

	Setup("info", "")
	if !app.Desugar().Core().Enabled(zapcore.InfoLevel) {
		t.Error("info level not applied to ordinary loggers")
	}
	if dht.Desugar().Core().Enabled(zapcore.ErrorLevel) {
		t.Error("dht logger not suppressed at info level")
	}

	Setup("debug", "")
	if !dht.Desugar().Core().Enabled(zapcore.ErrorLevel) {
		t.Error("explicit debug level must keep dht logs")
	}
}

func TestSetupInvalidLevelFallsBackToInfo(t *testing.T) {
	app := golog.Logger("logging-test-fallback")
	Setup("degub", "")
	if !app.Desugar().Core().Enabled(zapcore.InfoLevel) {
		t.Error("invalid level must fall back to info, got stricter")
	}
	if app.Desugar().Core().Enabled(zapcore.DebugLevel) {
		t.Error("invalid level must fall back to info, got debug")
	}
}
