# OpenClaw Integration

ShieldCortex integrates with [OpenClaw](https://openclaw.dev) in complement mode by default:
- Real-time defence scanning is on
- Context recall at session start is on
- Automatic memory writes are opt-in (off by default)

This lets OpenClaw keep its native memory behavior while ShieldCortex adds security, auditability, and lower-noise memory extraction when enabled.

## Install

```bash
npm install -g shieldcortex
npx shieldcortex openclaw install
openclaw gateway restart
```

Check status:

```bash
npx shieldcortex openclaw status
```

## What gets installed

`shieldcortex openclaw install` installs both components:

1. `cortex-memory` hook
- Path: `~/.openclaw/hooks/internal/cortex-memory/` (or `~/.openclaw/hooks/cortex-memory/` on some installs)
- Handles session bootstrap context injection + explicit keyword saves

2. `shieldcortex-realtime` plugin
- Path: `~/.openclaw/extensions/shieldcortex-realtime/`
- Hooks into `llm_input` and `llm_output`

## Default behavior (safe complement mode)

Enabled by default:
- `agent:bootstrap`: inject relevant prior context (`CORTEX_MEMORY.md`)
- Keyword triggers: saves when user explicitly says phrases like `remember this:`
- `llm_input` scanning: real-time threat detection + audit logging

Disabled by default:
- Auto-extract on `/new`, `/stop`, `/clear`, `/exit`
- `llm_output` auto-memory extraction

This avoids duplicate/noisy writes for users who already rely on OpenClaw memory or another primary memory store.

## Enable optional auto-memory

CLI:

```bash
npx shieldcortex config --openclaw-auto-memory true
```

Disable:

```bash
npx shieldcortex config --openclaw-auto-memory false
```

Dashboard:
- Start dashboard with `npx shieldcortex --dashboard`
- Open `Shield Overview -> OpenClaw Memory`
- Toggle auto-memory and dedupe settings

Config file (`~/.shieldcortex/config.json`):

```json
{
  "openclawAutoMemory": true,
  "openclawAutoMemoryDedupe": true,
  "openclawAutoMemoryNoveltyThreshold": 0.88,
  "openclawAutoMemoryMaxRecent": 300
}
```

Tuning bounds:
- `openclawAutoMemoryNoveltyThreshold`: `0.6` to `0.99`
- `openclawAutoMemoryMaxRecent`: `50` to `1000`

## Security and audit

All memory writes routed through ShieldCortex are scanned by the defence pipeline and recorded in audit logs. Threat detections from the real-time plugin can also sync to cloud when configured.

Optional cloud config example:

```json
{
  "cloudApiKey": "sc_...",
  "cloudBaseUrl": "https://api.shieldcortex.ai",
  "cloudEnabled": true
}
```

## Shared database

Memories are stored in `~/.shieldcortex/memories.db` and shared across ShieldCortex integrations (including Claude Code + OpenClaw when both use ShieldCortex memory tools).

## Troubleshooting

OpenClaw not detected:

```bash
which openclaw
```

Hook/plugin not active after install:
1. Run `npx shieldcortex openclaw status`
2. Restart OpenClaw gateway
3. Reinstall with `npx shieldcortex openclaw install`

Auto-memory not saving:
1. Confirm `openclawAutoMemory` is enabled
2. Check `~/.shieldcortex/config.json` for expected values
3. Check plugin/hook logs for `shieldcortex` or `cortex-memory` messages

## Uninstall

```bash
npx shieldcortex openclaw uninstall
```

## Related

- [README](../README.md)
- [OpenClaw plugin README](../plugins/openclaw/README.md)
- [Architecture](../ARCHITECTURE.md)
