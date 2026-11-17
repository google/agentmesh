# A mesh without a toolchain: the released agentmesh-one and agentmesh-node binaries are
# copied out of the published images. AGENTMESH_CHANNEL selects `stable` (the last
# release tag, what hub.sam-mesh.dev runs) or `latest` (main, what
# bananas.sam-mesh.dev runs).
ARG AGENTMESH_CHANNEL=stable
FROM ghcr.io/google/agentmesh-one:${AGENTMESH_CHANNEL} AS agentmesh-one
FROM ghcr.io/google/agentmesh-node:${AGENTMESH_CHANNEL} AS agentmesh-node

FROM mcr.microsoft.com/devcontainers/base:bookworm@sha256:85a349062e4ccc4755304f1264183e604391697608765e72765340b7cb7e2438
COPY --from=agentmesh-one /agentmesh-one /usr/local/bin/agentmesh-one
COPY --from=agentmesh-node /agentmesh-node /usr/local/bin/agentmesh-node
