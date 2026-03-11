# OpenClaw Quickstart

Use ShieldCortex with OpenClaw when you want session capture, realtime defence scanning, and a second memory layer you can review.

## Install

```bash
npm install -g shieldcortex
shieldcortex quickstart openclaw
```

This installs:

- the OpenClaw lifecycle hook
- the realtime scanning plugin

## Verify

```bash
shieldcortex openclaw status
shieldcortex dashboard
```

In the dashboard, use:

- `Capture` for OpenClaw session evidence
- `Recall` to inspect what would rank
- `Review` to discard noisy auto-extracted memories

## Recommended default

Keep OpenClaw auto-memory in complement mode unless you explicitly want dual storage:

```bash
shieldcortex config --openclaw-auto-memory false
```

This keeps ShieldCortex focused on durable decisions, fixes, patterns, and preferences rather than transient chat noise.

