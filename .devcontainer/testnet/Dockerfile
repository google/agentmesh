# A mesh without a toolchain: the released agentmesh-one and agentmesh-node binaries are
# copied out of the published images. AGENTMESH_CHANNEL selects `stable` (the last
# release tag, what hub.sam-mesh.dev runs) or `latest` (main, what
# bananas.sam-mesh.dev runs).
ARG AGENTMESH_CHANNEL=stable
FROM ghcr.io/google/agentmesh-one:${AGENTMESH_CHANNEL} AS agentmesh-one
FROM ghcr.io/google/agentmesh-node:${AGENTMESH_CHANNEL} AS agentmesh-node

FROM mcr.microsoft.com/devcontainers/base:bookworm@sha256:99f5250dd2d5f8b11046d5662dd94c1e3c1dae56b560c7caad5ceb7edf349046
COPY --from=agentmesh-one /agentmesh-one /usr/local/bin/agentmesh-one
COPY --from=agentmesh-node /agentmesh-node /usr/local/bin/agentmesh-node
