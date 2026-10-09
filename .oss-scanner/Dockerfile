# OSS Scanner build image (https://red.anthropic.com/oss-scanner).
# Built with network access; everything after runs offline, so every dependency
# the scanner might exercise is installed and built here.
FROM node:22-bookworm
ENV DEBIAN_FRONTEND=noninteractive NEXT_TELEMETRY_DISABLED=1 CI=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 build-essential git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives at /src
# Run as the unprivileged node user: several tests assert file-permission behaviour that root bypasses.
COPY --chown=node:node . /src
WORKDIR /src
USER node

# Root project: native deps (better-sqlite3 etc.) compile here while network is available.
RUN npm ci --no-audit --no-fund && npm run build:ts

# The dashboard has its own lockfile, dependencies, Next build and Jest runner;
# the root Jest config excludes it, so it is installed and built separately.
RUN cd dashboard && npm ci --no-audit --no-fund && npm run build

# Smoke tests. Non-gating by design (a red suite must not hide the image from the
# scanner), but the real exit status and full logs are kept under .oss-scanner/
# so a reader can tell "tests passed" from "tests ran". No pipelines here: a
# pipeline reports the last command's status, which previously let a failing
# suite exit 0 behind grep.
RUN npm test -- --ci --silent > .oss-scanner/jest-root.log 2>&1; rc=$?; \
    grep -E '^(FAIL|Tests:|Test Suites:)' .oss-scanner/jest-root.log; \
    echo "root jest exit=$rc" | tee .oss-scanner/jest-root.exit; \
    [ "$rc" -eq 0 ] || echo "WARNING: root jest failed (exit $rc), see .oss-scanner/jest-root.log"
RUN cd dashboard && npx jest --ci > ../.oss-scanner/jest-dashboard.log 2>&1; rc=$?; \
    grep -E '^(FAIL|Tests:|Test Suites:)' ../.oss-scanner/jest-dashboard.log; \
    echo "dashboard jest exit=$rc" | tee ../.oss-scanner/jest-dashboard.exit; \
    [ "$rc" -eq 0 ] || echo "WARNING: dashboard jest failed (exit $rc), see .oss-scanner/jest-dashboard.log"
