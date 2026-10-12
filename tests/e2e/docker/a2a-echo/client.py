"""One-shot stock a2a-sdk client for the e2e CUJ: resolve, verify, send, print.

Exits non-zero if the regenerated card is not mesh-usable or no reply arrives.
"""
import asyncio
import os
import sys
import uuid

import httpx
from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.helpers import get_message_text
from a2a.types import Message, Part, Role, SendMessageRequest


async def main(url: str, text: str) -> None:
    token = os.environ.get("AGENTMESH_API_TOKEN", "secret-token")
    headers = {"X-Mesh-Authentication": f"Bearer {token}"}
    labels = os.environ.get("AGENTMESH_REQUIRED_LABELS")
    if labels:
        headers["X-Mesh-Required-Labels"] = labels
    async with httpx.AsyncClient(timeout=60, headers=headers) as http:
        card = await A2ACardResolver(http, url).get_agent_card()
        bindings = [i.protocol_binding for i in card.supported_interfaces]
        assert "GRPC" not in bindings, f"gRPC interface not dropped: {bindings}"
        assert all(i.url == url for i in card.supported_interfaces), \
            f"interface URLs not regenerated to {url}: {card.supported_interfaces}"
        assert card.capabilities.streaming, "streaming not kept as the agent declares it"
        client = await create_client(card, client_config=ClientConfig(httpx_client=http))
        message = Message(
            role=Role.ROLE_USER,
            message_id=str(uuid.uuid4()),
            parts=[Part(text=text)],
        )
        async for event in client.send_message(SendMessageRequest(message=message)):
            if event.HasField("message"):
                print(f"agent> {get_message_text(event.message)}")
                return
        sys.exit("no message reply received")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: client.py <mesh-a2a-base-url> <text>")
    asyncio.run(main(sys.argv[1], sys.argv[2]))
