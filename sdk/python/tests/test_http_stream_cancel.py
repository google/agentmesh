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

import pytest
import trio

from agent_mesh import libp2p_http


@pytest.mark.parametrize("cancel", [False, True])
def test_http_request_closes_stream_on_failure(monkeypatch, cancel):
    closed = []

    class Stream:
        async def write(self, data):
            await trio.lowlevel.checkpoint()
            raise OSError("write failed")

        async def close(self):
            await trio.lowlevel.checkpoint()
            closed.append(True)

    async def open_stream(*args):
        return Stream()

    monkeypatch.setattr(libp2p_http, "open_stream", open_stream)

    async def request():
        await libp2p_http.open_http_request(None, "peer", b"fixture", "GET", "/a2a/example/message")

    async def run():
        if cancel:
            with trio.CancelScope() as scope:
                scope.cancel()
                await request()
            assert scope.cancelled_caught
        else:
            with pytest.raises(OSError, match="write failed"):
                await request()
        assert closed == [True]

    trio.run(run)
