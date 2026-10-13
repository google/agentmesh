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
	"strings"
	"testing"

	golog "github.com/ipfs/go-log/v2"
	"go.uber.org/zap/zapcore"
)

func TestSetupFormat(t *testing.T) {
	cases := []struct {
		name string
		flag string
		want golog.LogFormat
	}{
		{"json", "json", golog.JSONOutput},
		{"empty defaults to text", "", golog.PlaintextOutput},
		{"json again", "json", golog.JSONOutput},
		{"invalid falls back to text", "bogus", golog.PlaintextOutput},
		{"explicit text", "text", golog.PlaintextOutput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			Setup(Options{Format: tc.flag})
			if got := golog.GetConfig().Format; got != tc.want {
				t.Errorf("format = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSetupLevels(t *testing.T) {
	dht := golog.Logger("dht")
	app := golog.Logger("logging-test-app")

	Setup(Options{Level: "info"})
	if got := app.Desugar().Core().Enabled(zapcore.InfoLevel); !got {
		t.Errorf("app Enabled(Info) = %v, want true after Setup(info)", got)
	}
	// A logger created after Setup must also inherit the configured level.
	late := golog.Logger("logging-test-late")
	if got := late.Desugar().Core().Enabled(zapcore.InfoLevel); !got {
		t.Errorf("late logger Enabled(Info) = %v, want true after Setup(info)", got)
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

func TestSetupRingBuffer(t *testing.T) {
	Setup(Options{Level: "info", RingBuffer: true})
	golog.Logger("logging-test-ring").Infof("hello ring buffer")
	lines := RecentLogs()
	found := false
	for _, line := range lines {
		if strings.Contains(line, "hello ring buffer") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("RecentLogs() = %v, want line containing %q", lines, "hello ring buffer")
	}
}

// The ring keeps whole lines; without a per-line cap a remote peer that gets
// an 8 MiB string logged pins it in memory for 500 rounds.
func TestRingBufferSinkCapsLineBytes(t *testing.T) {
	sink := newRingBufferSink(4)
	huge := strings.Repeat("A", 3*maxLogLineBytes) + "\n"
	if _, err := sink.Write([]byte(huge)); err != nil {
		t.Fatal(err)
	}
	_, _ = sink.Write([]byte("short\n"))

	lines := sink.lines()
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	if got := len(lines[0]); got > maxLogLineBytes+len("…[truncated]") {
		t.Errorf("stored line is %d bytes, want <= %d", got, maxLogLineBytes+len("…[truncated]"))
	}
	if !strings.HasSuffix(lines[0], "[truncated]") {
		t.Errorf("truncated line should be marked, got suffix %q", lines[0][len(lines[0])-16:])
	}
	if lines[1] != "short" {
		t.Errorf("second line = %q, want %q", lines[1], "short")
	}
}
