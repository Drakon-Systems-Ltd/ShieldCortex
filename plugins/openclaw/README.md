# ShieldCortex Real-time Scanner — OpenClaw Plugin

Real-time defence scanning and memory extraction for OpenClaw v2026.2.15+.

## What it does

| Hook | Action |
|------|--------|
| `llm_input` | Scans prompts + history through ShieldCortex defence pipeline. Logs threats, writes audit log, optionally syncs to cloud. **Fire-and-forget.** |
| `llm_output` | Extracts decisions, fixes, learnings from assistant responses via pattern matching + salience scoring. Saves to ShieldCortex memory via mcporter. **Fire-and-forget.** |

## Installation

### Automatic (recommended)

```bash
npm install -g shieldcortex
npx shieldcortex openclaw install
openclaw gateway restart
```

The plugin is copied to `~/.openclaw/extensions/shieldcortex-realtime/` where OpenClaw discovers it automatically.

### Manual

If you need to install manually, copy the compiled plugin files:

```bash
mkdir -p ~/.openclaw/extensions/shieldcortex-realtime
cp node_modules/shieldcortex/plugins/openclaw/dist/* ~/.openclaw/extensions/shieldcortex-realtime/
openclaw gateway restart
```

Find the package root with `npm root -g` (global) or `npm root` (local).

## Requirements

- OpenClaw v2026.2.15+ (needs `llm_input`/`llm_output` plugin hooks)
- ShieldCortex installed globally (`npm i -g shieldcortex`) or at `~/ShieldCortex/`
- `mcporter` available via npx (for memory saves)

## Cloud Sync (optional)

Add your API key to `~/.shieldcortex/config.json`:

```json
{
  "cloudApiKey": "sc_...",
  "cloudEndpoint": "https://api.shieldcortex.ai"
}
```

Threat detections will POST to the cloud endpoint. Fails silently if not configured.

## Audit Logs

Written to `~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl` — one JSON object per line.
