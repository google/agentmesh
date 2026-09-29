FROM node:26-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1

# The buddy: Google's Gemini CLI.
RUN npm install -g --ignore-scripts --no-audit --no-fund @google/gemini-cli@0.60.0

WORKDIR /srv
COPY package.json package-lock.json buddy_server.mjs ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# Dev-only: replace <API_KEY> with a Google AI Studio free-tier key before `make kind`.
# Keep the edit local so it is never committed:
#   git update-index --skip-worktree development/examples/gemini-buddy-mcp/Dockerfile
ENV GEMINI_API_KEY=<API_KEY>
ENV GEMINI_CLI_TRUST_WORKSPACE=true

EXPOSE 7780
CMD ["node", "buddy_server.mjs"]
