FROM node:26-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1

WORKDIR /srv
COPY package.json package-lock.json server.mjs lease-token.mjs ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

EXPOSE 7780
CMD ["node", "server.mjs"]
