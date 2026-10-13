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

package node

import (
	"strings"
	"testing"
)

func TestTruncateForLog(t *testing.T) {
	if got := truncateForLog("small"); got != "small" {
		t.Errorf("short strings must pass through, got %q", got)
	}
	long := strings.Repeat("x", maxRemoteLogBytes+1000)
	got := truncateForLog(long)
	if !strings.HasPrefix(got, long[:maxRemoteLogBytes]) || !strings.HasSuffix(got, "(+1000 bytes)") {
		t.Errorf("unexpected truncation: %q", got[len(got)-40:])
	}
	if len(got) > maxRemoteLogBytes+32 {
		t.Errorf("truncated string is %d bytes", len(got))
	}
}
