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

# Build context must be the repository root:
#   docker build -f development/examples/gcp-agent-gateway/pep/Dockerfile .

FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -buildvcs=false -o /out/agentmesh-one ./cmd/agentmesh-one && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -buildvcs=false -o /out/agentmesh-node ./cmd/agentmesh-node

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -u 65532 -r -s /usr/sbin/nologin nonroot && \
    mkdir -p /data /etc/agentmesh && \
    chown -R 65532:65532 /data /etc/agentmesh

COPY --from=builder /out/agentmesh-one /usr/local/bin/agentmesh-one
COPY --from=builder /out/agentmesh-node /usr/local/bin/agentmesh-node
COPY development/examples/gcp-agent-gateway/pep/policy.json.tmpl /etc/agentmesh/policy.json.tmpl
COPY development/examples/gcp-agent-gateway/pep/node.yaml.tmpl /etc/agentmesh/node.yaml.tmpl
COPY development/examples/gcp-agent-gateway/pep/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER nonroot
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
