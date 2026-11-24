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

from agent_mesh.discovery import find_providers


def test_directory_checks_provider_limit_before_contacting_routers():
    async def run():
        assert await find_providers(None, [], b"", limit=0) == []
        with pytest.raises(ValueError, match="limit"):
            await find_providers(None, [], b"", limit=-1)

    trio.run(run)
