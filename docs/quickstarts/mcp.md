# MCP Agent Quickstart

Use ShieldCortex when you want an MCP-compatible memory and security layer that works across agents, not just one editor.

Every local feature is free — no trial, no licence key. Full cloud sync and shared cloud workflows are Enterprise (sales@drakonsystems.com); the cloud free tier (audit metadata, 500 scans/month) just needs your email.

## Install

```bash
npm install -g shieldcortex
shieldcortex setup
```

`setup` shows the hosts it detects (Claude Code, OpenClaw, Hermes, Codex, Cursor / VS Code) and asks before wiring each one. To skip the table and install for one host, name it: `shieldcortex setup codex`, `shieldcortex setup copilot` (VS Code / Cursor) or `shieldcortex setup claude`. The older `shieldcortex install` is the Claude Code install (the same as `setup claude`), not the wizard.

## Verify

```bash
shieldcortex doctor
shieldcortex status
```

## If the agent runs on a server

For headless Linux hosts or always-on cloud boxes, connect the machine to ShieldCortex Cloud with the persistent worker:

```bash
shieldcortex license activate <enterprise-key>
shieldcortex config --cloud-api-key <cloud-api-key>
shieldcortex config --cloud-enable
shieldcortex service install --headless
```

See [cloud-servers.md](cloud-servers.md) for the full verification flow.

## What you get

- durable local memory
- semantic recall
- recall explanations
- review queue
- memory poisoning defence
- optional cloud replica sync for team visibility

## Best workflow

After install, open:

```bash
shieldcortex dashboard
```

Start with `Recall` and `Review`, not the graph. That gives you the fastest path to trustworthy agent memory.
