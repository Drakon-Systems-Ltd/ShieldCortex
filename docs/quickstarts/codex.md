# ShieldCortex for Codex

Use ShieldCortex as an MCP memory and security layer for Codex CLI and the Codex VS Code extension.

Every local feature is free — no trial, no licence key. Optional cloud memory sync and shared cloud workflows are Enterprise (sales@drakonsystems.com); the cloud free tier (audit metadata, 500 scans/month) just needs your email.

## Install

```bash
npm install -g shieldcortex
shieldcortex codex install
```

This writes the ShieldCortex MCP server into:

```text
~/.codex/config.toml
```

Codex CLI and the Codex VS Code extension share that config on the same machine, so one install covers both.

## Verify

```bash
shieldcortex codex status
codex mcp list
```

You should see a ShieldCortex MCP entry named `shieldcortex-memory`.

## What you get

- durable memory via `remember` / `recall`
- recall explanations and review flows in the local dashboard
- prompt and tool-output scanning before bad memory lands
- optional cloud sync, replay, and team review

## Remove

```bash
shieldcortex codex uninstall
```
