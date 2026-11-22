# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Caption pane for the recording: shows the text in a file, typed at reading
speed, and redraws whenever the file changes.

    python3 caption.py <caption-file> <columns> <characters-per-second>

Adapted from the caption pane in ../multi-tier-guardrails/record.sh. A
caption that starts with "Step n/m · " draws that label in an accent color.
"""

import sys
import textwrap
import time

path, cols, cps = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
sys.stdout.write("\033[?25l")  # no cursor in the caption pane
last = None
while True:
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
    except FileNotFoundError:
        text = ""
    if text != last:
        last = text
        time.sleep(0.4)  # let the recording show the pane before typing starts
        sys.stdout.write("\033[2J\033[H\n")
        label, sep, body = text.partition(" · ")
        if not (sep and label.startswith("Step ")):
            label, body = "", text
        width = cols - 6 - (len(label) + 3 if label else 0)
        first = True
        for line in textwrap.wrap(body, width)[:3]:
            sys.stdout.write("   ")
            if first and label:
                sys.stdout.write(f"\033[1;38;2;34;211;238m{label}\033[0m\033[38;2;148;163;184m · \033[0m")
            first = False
            sys.stdout.write("\033[1m")
            for ch in line:
                sys.stdout.write(ch)
                sys.stdout.flush()
                time.sleep(1 / cps)
            sys.stdout.write("\033[0m\n")
        sys.stdout.flush()
    time.sleep(0.1)
