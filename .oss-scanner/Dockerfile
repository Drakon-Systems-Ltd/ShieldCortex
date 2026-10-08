# OSS Scanner build image (https://red.anthropic.com/oss-scanner).
# Built with network access; everything after runs offline.
FROM node:22-bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 build-essential git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives at /src
# Run as the unprivileged node user: several tests assert file-permission behaviour that root bypasses.
COPY --chown=node:node . /src
WORKDIR /src
USER node

# Native deps (better-sqlite3 etc.) compile here while network is available.
RUN npm ci && npm run build:ts

# Cheap smoke test so we know the image works; never abort the build on failures.
RUN (npm test -- --ci --silent 2>&1 | grep -E '^(FAIL|Tests:|Test Suites:)') || echo "WARNING: jest reported failures"
