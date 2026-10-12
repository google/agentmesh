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

func TestSetupFormat(t *testing.T) {
	cases := []struct {
		name string
		env  string
		flag string
		want golog.LogFormat
	}{
		{"env selects json", "json", "", golog.JSONOutput},
		{"env selects text", "text", "", golog.PlaintextOutput},
		{"flag wins over env", "json", "text", golog.PlaintextOutput},
		{"flag selects json", "", "json", golog.JSONOutput},
		{"invalid flag falls back to env", "json", "bogus", golog.JSONOutput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LOG_FORMAT", tc.env)
			Setup(Options{Format: tc.flag})
			if got := golog.GetConfig().Format; got != tc.want {
				t.Errorf("format = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSetupInvalidFormatKeepsCurrent(t *testing.T) {
	t.Setenv("LOG_FORMAT", "")
	Setup(Options{Format: "text"})
	Setup(Options{Format: "bogus"})
	if got := golog.GetConfig().Format; got != golog.PlaintextOutput {
		t.Errorf("format = %v, want %v (PlaintextOutput): an invalid value must keep the current format", got, golog.PlaintextOutput)
	}
}

func TestSetupLevels(t *testing.T) {
	dht := golog.Logger("dht")
	app := golog.Logger("logging-test-app")

	Setup(Options{Level: "info"})
	if got := app.Desugar().Core().Enabled(zapcore.InfoLevel); !got {
		t.Errorf("app Enabled(Info) = %v, want true after Setup(info)", got)
	}
	if got := dht.Desugar().Core().Enabled(zapcore.ErrorLevel); got {
		t.Errorf("dht Enabled(Error) = %v, want false (suppressed) at info level", got)
	}

	Setup(Options{Level: "debug"})
	if got := dht.Desugar().Core().Enabled(zapcore.ErrorLevel); !got {
		t.Errorf("dht Enabled(Error) = %v, want true at explicit debug level", got)
	}
}

func TestSetupInvalidLevelFallsBackToInfo(t *testing.T) {
	app := golog.Logger("logging-test-fallback")
	Setup(Options{Level: "degub"})
	if got := app.Desugar().Core().Enabled(zapcore.InfoLevel); !got {
		t.Errorf("app Enabled(Info) = %v, want true: invalid level must fall back to info", got)
	}
	if got := app.Desugar().Core().Enabled(zapcore.DebugLevel); got {
		t.Errorf("app Enabled(Debug) = %v, want false: invalid level must fall back to info, not debug", got)
	}
}
