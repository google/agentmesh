# A sandbox image holds the harness and the init that gives it a route.
# No credentials, and no proxy configuration: the agent is unmodified and does
# not know it is confined.
FROM golang:1.27.1@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS init
WORKDIR /src
COPY cmd/nano-init/go.mod cmd/nano-init/go.sum ./
RUN go mod download
COPY cmd/nano-init/ ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /nano-init .

FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

# Nothing else is needed. nano-init carries its own TCP stack and speaks
# netlink directly, so this image has no tun2proxy, no socat and no iproute2 —
# which is the difference between a sandbox that is the agent and one that is
# the agent plus a toolbox.
COPY --from=init /nano-init /usr/local/bin/nano-init

WORKDIR /app
COPY development/examples/agent-harness/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY development/examples/agent-harness/agent.py .

# Building the tun needs NET_ADMIN, so this stays root. The isolation that
# matters is the sandbox around the container, not the uid inside it; a microVM
# makes the same trade with its own kernel.
ENTRYPOINT ["nano-init", "run", "/run/agent.sock", "python", "agent.py"]
