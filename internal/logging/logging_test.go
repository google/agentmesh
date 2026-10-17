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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

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
	ringLine(t, "hello ring buffer")
}

// captureStderr points os.Stderr at a file for the rest of the test, so a
// Setup that opens the "stderr" sink writes there.
func captureStderr(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = f
	t.Cleanup(func() {
		os.Stderr = orig
		_ = f.Close()
	})
	return f
}

// ringLine waits for the ring buffer to hold a line containing want: the
// lines reach it through a pipe, so they land just after the log call returns.
func ringLine(t *testing.T, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, line := range RecentLogs() {
			if strings.Contains(line, want) {
				return line
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("RecentLogs() = %v, want a line containing %q", RecentLogs(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The ring buffer is what tools read through /debug/logs, so it holds JSON
// whatever --log-format says; the format only shapes what humans read on stderr.
func TestRingBufferIsJSONWhateverTheFormat(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			stderr := captureStderr(t)
			Setup(Options{Level: "info", Format: format, RingBuffer: true})
			msg := fmt.Sprintf("ring-json-%s-%d", format, time.Now().UnixNano())
			golog.Logger("logging-test-sinks").Infof("%s", msg)

			var entry struct {
				Level  string `json:"level"`
				Logger string `json:"logger"`
				Msg    string `json:"msg"`
			}
			line := ringLine(t, msg)
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("ring line %q is not JSON: %v", line, err)
			}
			if entry.Msg != msg || entry.Level != "info" || entry.Logger != "logging-test-sinks" {
				t.Errorf("ring entry = %+v, want msg %q, level info, logger logging-test-sinks", entry, msg)
			}

			out, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			stderrLine := strings.TrimSpace(string(out))
			if !strings.Contains(stderrLine, msg) {
				t.Fatalf("stderr = %q, want a line containing %q", stderrLine, msg)
			}
			if gotJSON := json.Valid([]byte(stderrLine)); gotJSON != (format == "json") {
				t.Errorf("stderr line %q is JSON = %v, want %v for --log-format=%s", stderrLine, gotJSON, format == "json", format)
			}
		})
	}
}

// A second Setup must not add a second ring sink, or every line would be
// retained twice.
func TestSetupRingBufferTwiceKeepsOneCopy(t *testing.T) {
	Setup(Options{Level: "info", RingBuffer: true})
	Setup(Options{Level: "info", RingBuffer: true})
	id := time.Now().UnixNano()
	msg := fmt.Sprintf("only once please %d", id)
	log := golog.Logger("logging-test-twice")
	log.Infof("%s", msg)
	// Lines reach the ring in order, so once the later line is there, every
	// copy of the earlier one is too.
	log.Infof("after %d", id)
	ringLine(t, fmt.Sprintf("after %d", id))

	n := 0
	for _, line := range RecentLogs() {
		if strings.Contains(line, msg) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("ring holds %d copies of %q, want 1", n, msg)
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
