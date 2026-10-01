ARG SAM_VERSION=v0.1.0-rc.8
FROM ghcr.io/google/sam-node:${SAM_VERSION} AS sam

FROM scratch
COPY --from=sam /sam-node /usr/local/bin/sam-node
COPY --chmod=0755 hooks/ /usr/local/lib/sam/
