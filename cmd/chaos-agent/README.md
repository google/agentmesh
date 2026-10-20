# Agent Mesh Chaos Agent

This directory contains a complete, production-grade Python AI Agent built with **LangChain** and the **MCP Python SDK**.

This provides a realistic workload for the Agent Mesh scale testing experiment. Rather than a synthetic benchmark or a hardcoded Go loop, this is a true autonomous agent capable of reasoning, exploring tools, and adversarial "Chaos Monkey" testing.

## How it works

1. It connects to the `agentmesh-node` MCP endpoint via Streamable HTTP (or `agentmesh-box` proxy in the microVM).
2. It dynamically converts all discovered MCP tools into LangChain `Tool` objects with JSON schemas.
3. It initializes a LangChain `create_agent` tool-calling agent using the Agent Mesh's OpenAI-compatible inference endpoint (`/v1/chat/completions`).
4. It is given an adversarial prompt to explore all tools, fuzz them with extreme inputs, and find bugs.
5. The LangChain framework automatically handles the multi-turn reasoning and tool-calling loop until the agent achieves its goal or hits the max iteration limit.

## Running Locally

First, ensure you have Python installed, then install the dependencies:

```bash
pip install -r requirements.txt
```

Run the agent against a local `agentmesh-node`:

```bash
python agent.py --auth "Bearer <your-agentmesh-node-token>"
```

### Customizing the Chaos

You can pass a custom prompt to instruct the agent to test specific behaviors:

```bash
python agent.py \
  --prompt "Focus exclusively on the 'get_mesh_info' tool. Call it 5 times in rapid succession to test rate limiting." \
  --auth "Bearer <token>"
```
