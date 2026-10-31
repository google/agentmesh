#!/usr/bin/env python3
# A minimal OpenAI-compatible backend for e2e tests: one model, one canned
# completion. Standard library only, so it runs wherever python3 does.
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "e2e-model"


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/v1/models":
            self._json(200, {"object": "list", "data": [{"id": MODEL, "object": "model", "owned_by": "e2e"}]})
            return
        if self.path == "/a2a/.well-known/agent-card.json":
            port = self.server.server_address[1]
            self._json(200, {
                "name": "coding-agent",
                "description": "e2e laptop A2A agent",
                "version": "1.0.0",
                "supportedInterfaces": [{
                    "url": f"http://127.0.0.1:{port}/a2a",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0",
                }],
                "capabilities": {"streaming": False},
                "defaultInputModes": ["text/plain"],
                "defaultOutputModes": ["text/plain"],
                "skills": [{"id": "code", "name": "Code", "description": "Coding harness"}],
            })
            return
        self._json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            req = {}
        if self.path == "/v1/chat/completions" and req.get("model") == MODEL:
            self._json(200, {
                "id": "cmpl-e2e", "object": "chat.completion", "model": MODEL,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "hello from the mesh"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 4, "total_tokens": 5},
            })
            return
        if self.path == "/mcp" or self.path.startswith("/mcp/"):
            method = req.get("method", "")
            req_id = req.get("id", 1)
            if method == "initialize":
                self._json(200, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "github", "version": "1.0"},
                    },
                })
                return
            if method == "notifications/initialized":
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if method == "tools/list":
                self._json(200, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {"name": "get_pr", "description": "Get pull request"},
                            {"name": "delete_repo", "description": "Delete repository"},
                        ]
                    },
                })
                return
            if method == "tools/call":
                peer_id = self.headers.get("X-Peer-Id", "")
                tool_name = (req.get("params") or {}).get("name", "")
                self._json(200, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": f"tool={tool_name} peer={peer_id}",
                        }]
                    },
                })
                return
        if self.path == "/a2a" or self.path == "/a2a/":
            ingress_mode = self.headers.get("X-Mesh-Ingress", "")
            principal = self.headers.get("X-Mesh-Principal", "")
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id", 1),
                "result": {
                    "message": {
                        "messageId": "msg-e2e-1",
                        "role": "ROLE_AGENT",
                        "parts": [{"text": f"a2a ingress={ingress_mode} principal={principal}"}],
                    }
                },
            })
            return
        self._json(404, {"error": {"message": "unknown model", "code": "model_not_found"}})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(f"listening on port {server.server_address[1]}", flush=True)
    server.serve_forever()

