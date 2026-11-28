#!/usr/bin/env python3
"""
Mock server simulating Google Cloud STS and Vertex AI API with Cloud Audit Logging.
Used for local end-to-end testing of Agent Mesh Cloud IAM federation without requiring
an active GCP billing project or internet connectivity.
"""

import http.server
import json
import os
import sys
import time

AUDIT_LOG_FILE = "/run/example/cloud-audit.log"

class CloudMockHandler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _append_audit_log(self, record):
        try:
            os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            sys.stderr.write(f"Failed to write audit log: {e}\n")

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return

        if self.path == "/audit-logs":
            logs = []
            if os.path.exists(AUDIT_LOG_FILE):
                with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            logs.append(json.loads(line))
            self._send_json(200, {"audit_logs": logs})
            return

        # Models metadata endpoint
        if self.path.startswith("/v1/projects/") and self.path.endswith("/publishers/google/models"):
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self._send_json(401, {"error": "unauthenticated"})
                return
            self._send_json(200, {
                "models": [
                    {"name": "publishers/google/models/gemini-2.5-flash", "displayName": "Gemini 2.5 Flash"}
                ]
            })
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        # 1. Google STS token exchange endpoint: /v1/token
        if self.path == "/v1/token":
            # Node exchanges the federated assertion for a short-lived Google access token
            self._send_json(200, {
                "access_token": "ya29.mock-federated-token-for-mesh",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 3600
            })
            return

        # 2. Vertex AI Gemini generateContent endpoint
        if ":generateContent" in self.path:
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self._send_json(401, {"error": "unauthenticated", "message": "Missing bearer token"})
                return

            # Capture caller identity as conveyed via mesh egress injection
            mesh_caller = self.headers.get("X-Mesh-Caller", "user:alice")
            principal = f"principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/agentmesh/subject/{mesh_caller}"

            audit_entry = {
                "timestamp": time.time(),
                "serviceName": "aiplatform.googleapis.com",
                "methodName": "google.cloud.aiplatform.v1.PredictionService.GenerateContent",
                "resourceName": self.path,
                "principal": principal,
                "authorizationInfo": [
                    {
                        "permission": "aiplatform.endpoints.predict",
                        "granted": True,
                        "resource": self.path
                    }
                ],
                "status": {"code": 0, "message": "OK"}
            }
            self._append_audit_log(audit_entry)

            self._send_json(200, {
                "candidates": [
                    {
                        "content": {
                            "role": "model",
                            "parts": [
                                {
                                    "text": "Analysis completed securely via Agent Mesh federated identity. No cloud credentials were held by the agent."
                                }
                            ]
                        },
                        "finishReason": "STOP"
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 12,
                    "candidatesTokenCount": 20,
                    "totalTokenCount": 32
                }
            })
            return

        # 3. Disallowed operation / out of scope
        self._send_json(403, {"error": "permission_denied", "message": "Operation not permitted on this resource"})

def run():
    server = http.server.HTTPServer(("0.0.0.0", 8080), CloudMockHandler)
    print("Cloud IAM mock server listening on port 8080...")
    server.serve_forever()

if __name__ == "__main__":
    run()
