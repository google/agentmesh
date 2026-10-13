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

import "fmt"

// maxRemoteLogBytes is how much of a remote-controlled string a log
// message may carry; see truncateForLog.
const maxRemoteLogBytes = 256

// truncateForLog bounds a string that a remote peer chose (a request path, a
// tool result, a target name) before it reaches the logs.
func truncateForLog(s string) string {
	if len(s) <= maxRemoteLogBytes {
		return s
	}
	return fmt.Sprintf("%s…(+%d bytes)", s[:maxRemoteLogBytes], len(s)-maxRemoteLogBytes)
}
