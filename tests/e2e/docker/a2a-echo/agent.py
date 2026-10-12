"""Stock a2a-sdk echo agent for the e2e mesh CUJ: deterministic, no external APIs.

The card deliberately advertises a gRPC interface and streaming so the test
can verify the mesh regenerates the card (drops gRPC, keeps streaming) and
that the stock client's streamed message/send crosses the mesh.
"""
import uuid

import uvicorn
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
)
from starlette.applications import Starlette

PORT = 7777


class EchoExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        await event_queue.enqueue_event(
            Message(
                role=Role.ROLE_AGENT,
                message_id=str(uuid.uuid4()),
                parts=[Part(text=f"echo: {context.get_user_input()}")],
                context_id=context.context_id,
                task_id=context.task_id,
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass


agent_card = AgentCard(
    name="echo",
    description="Deterministic echo agent for the a2a e2e CUJ",
    version="0.1.0",
    capabilities=AgentCapabilities(streaming=True),
    default_input_modes=["text"],
    default_output_modes=["text"],
    skills=[
        AgentSkill(
            id="echo",
            name="echo",
            description="Echoes the input back",
            tags=["echo"],
        )
    ],
    supported_interfaces=[
        AgentInterface(
            protocol_binding="JSONRPC",
            protocol_version="1.0",
            url=f"http://127.0.0.1:{PORT}/",
        ),
        # Unreachable through the mesh; the regenerated card must drop it.
        AgentInterface(
            protocol_binding="GRPC",
            protocol_version="1.0",
            url="127.0.0.1:50051",
        ),
    ],
)

handler = DefaultRequestHandler(
    agent_executor=EchoExecutor(),
    task_store=InMemoryTaskStore(),
    agent_card=agent_card,
)
# JSON-RPC at "/": the mesh card regeneration drops URL subpaths, so clients land on the root.
app = Starlette(
    routes=[
        *create_jsonrpc_routes(request_handler=handler, rpc_url="/"),
        *create_agent_card_routes(agent_card=agent_card),
    ]
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
