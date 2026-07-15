# OpenClaw Integration

ShieldCortex integrates with [OpenClaw](https://openclaw.dev) in complement mode by default:
- Real-time defence scanning is on
- The before-tool-call Action Guard is on (catastrophic operations blocked; dangerous operations enforced by default)
- Automatic memory writes are opt-in (off by default)

Context recall at session start is handled by OpenClaw's native Memory Search —
ShieldCortex stopped injecting bootstrap context in v2026.2.26 (it duplicated
what OpenClaw already recalls and ate context window).

This lets OpenClaw keep its native memory behavior while ShieldCortex adds security, auditability, and lower-noise memory extraction when enabled.

## Install

### Native OpenClaw install (preferred)

```bash
openclaw skills install shieldcortex
openclaw plugins install @drakon-systems/shieldcortex-realtime
openclaw gateway restart
```

This uses OpenClaw's native npm hook-pack and plugin-pack install flow. The
hook comes from `shieldcortex`; the real-time plugin comes from the standalone
`@drakon-systems/shieldcortex-realtime` package.

### ShieldCortex wrapper (compatibility path)

```bash
npm install -g shieldcortex
shieldcortex openclaw install
openclaw gateway restart
```

The wrapper also migrates older hook installs out of
`~/.openclaw/hooks/internal/cortex-memory` and removes duplicate legacy copies.

If the wrapper install fails with `permission denied`, use one of these:

```bash
sudo "$(command -v shieldcortex)" openclaw install
```

Or fix ownership so future installs work without `sudo`:

```bash
sudo chown -R "$USER":"$USER" ~/.openclaw ~/.claude
shieldcortex openclaw install
```

Check status:

```bash
shieldcortex openclaw status
```

## What gets installed

The native OpenClaw commands above install both components separately. Existing
wrapper-based installs can keep using `shieldcortex openclaw install`. The
wrapper also installs both components:

1. `cortex-memory` hook
- Path: `~/.openclaw/hooks/cortex-memory/`
- Handles lifecycle wiring on `agent:bootstrap` (security-warning handoff — no
  system-prompt injection since v2026.2.26) + explicit keyword saves

2. `shieldcortex-realtime` plugin
- Native `openclaw plugins install` puts it in OpenClaw's managed npm project
  tree (`~/.openclaw/npm/projects/…/node_modules/@drakon-systems/shieldcortex-realtime`,
  registered in `plugins/installs.json`); the wrapper's compatibility path
  copies it to `~/.openclaw/extensions/shieldcortex-realtime/`
- Hooks into `llm_input`, `llm_output`, `before_tool_call`, and `session_end`

## Default behavior (safe complement mode)

Enabled by default:
- Keyword triggers: saves when user explicitly says phrases like `remember this:`
- `llm_input` scanning: real-time threat detection + audit logging
- `before_tool_call` Action Guard: catastrophic operations blocked, dangerous operations enforced (see the [plugin README](../plugins/openclaw/README.md) for `actionGuard` opt-down and allowlisting)
- `agent:bootstrap` lifecycle wiring: security-warning file handoff only — no context injection (removed v2026.2.26; OpenClaw's native Memory Search recalls context at session start)

Disabled by default:
- Auto-extract on `/new`, `/stop`, `/clear`, `/exit`
- `llm_output` auto-memory extraction

This avoids duplicate/noisy writes for users who already rely on OpenClaw memory or another primary memory store.

## Enable optional auto-memory

CLI:

```bash
shieldcortex config --openclaw-auto-memory true
```

Disable:

```bash
shieldcortex config --openclaw-auto-memory false
```

Dashboard:
- Start dashboard with `shieldcortex --dashboard`
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
1. Run `shieldcortex openclaw status`
2. Restart OpenClaw gateway
3. Reinstall with `openclaw skills install shieldcortex` and `openclaw plugins install @drakon-systems/shieldcortex-realtime`
4. If `status` shows a legacy `internal/cortex-memory` path, rerun `shieldcortex openclaw install` once to migrate and clean up duplicates

Permission denied during install:
1. Check where the binary lives with `command -v shieldcortex`
2. Run `sudo "$(command -v shieldcortex)" openclaw install`
3. Or fix directory ownership with `sudo chown -R "$USER":"$USER" ~/.openclaw ~/.claude`

Auto-memory not saving:
1. Confirm `openclawAutoMemory` is enabled
2. Check `~/.shieldcortex/config.json` for expected values
3. Check plugin/hook logs for `shieldcortex` or `cortex-memory` messages

## Uninstall

```bash
shieldcortex openclaw uninstall
```

## Related

- [README](../README.md)
- [OpenClaw plugin README](../plugins/openclaw/README.md)
- [Architecture](../ARCHITECTURE.md)
