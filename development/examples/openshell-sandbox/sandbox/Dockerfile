# The sandbox image: Ubuntu with curl and python3 for the walkthrough, built
# the way OpenShell's bring-your-own-container example does it. An agent image
# (Claude Code, Codex, Gemini CLI, ...) takes the same place.
FROM nvcr.io/nvidia/base/ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl iproute2 nftables python3 \
    && rm -rf /var/lib/apt/lists/* \
    && if getent passwd ubuntu >/dev/null; then userdel ubuntu; fi \
    && if getent group ubuntu >/dev/null; then groupdel ubuntu; fi \
    && groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid sandbox --create-home --shell /bin/bash sandbox \
    && install -d -o sandbox -g sandbox /sandbox

WORKDIR /sandbox
USER sandbox:sandbox
