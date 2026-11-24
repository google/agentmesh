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

from contextlib import asynccontextmanager
from types import SimpleNamespace

import trio

from agent_mesh.session import MeshSession


def test_sdk_lists_all_remote_tool_pages():
    async def run():
        for next_cursor in (None, "next"):
            calls = []
            closed = []

            class Client:
                async def list_tools(self, *, params=None):
                    cursor = None if params is None else params.cursor
                    calls.append(cursor)
                    if cursor is None:
                        return SimpleNamespace(
                            tools=[SimpleNamespace(name="first", description=None)],
                            next_cursor=next_cursor,
                        )
                    return SimpleNamespace(
                        tools=[SimpleNamespace(name="second", description="Second tool")],
                        next_cursor=None,
                    )

            @asynccontextmanager
            async def open_mcp(peer, service):
                try:
                    yield Client(), None
                finally:
                    closed.append(True)

            session = SimpleNamespace(open_mcp=open_mcp)
            tools = await MeshSession.list_tools(session, "peer", "mcp://catalog")
            assert closed == [True]
            expected = ["first"] if next_cursor is None else ["first", "second"]
            assert [tool.name for tool in tools] == expected
            assert calls == ([None] if next_cursor is None else [None, "next"])

    trio.run(run)
