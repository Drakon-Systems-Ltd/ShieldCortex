# OpenClaw Quickstart

Use ShieldCortex with OpenClaw when you want session capture, realtime defence scanning, and a second memory layer you can review.

If this is a fresh machine with no paid licence, ShieldCortex will also start a 14-day Pro trial automatically on first run. That trial covers Pro-gated local features. Cloud sync for this OpenClaw box still requires Team or higher.

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

## If OpenClaw runs on a remote server

If your OpenClaw box should appear in ShieldCortex Cloud as an online device, also connect the machine itself:

```bash
shieldcortex license activate <team-key>
shieldcortex config --cloud-api-key <cloud-api-key>
shieldcortex config --cloud-enable
shieldcortex service install --headless
```

See [cloud-servers.md](cloud-servers.md) for the full server checklist.

## Recommended default

Keep OpenClaw auto-memory in complement mode unless you explicitly want dual storage:

```bash
shieldcortex config --openclaw-auto-memory false
```

This keeps ShieldCortex focused on durable decisions, fixes, patterns, and preferences rather than transient chat noise.
