# ShieldCortex Real-time Scanner — OpenClaw Plugin

Real-time defence scanning and memory extraction for OpenClaw v2026.2.15+.

## What it does

| Hook | Action |
|------|--------|
| `llm_input` | Scans prompts + history through ShieldCortex defence pipeline. Logs threats, writes audit log, optionally syncs to cloud. **Fire-and-forget.** |
| `llm_output` | Memory extraction from assistant responses (enabled by default). Saves to ShieldCortex memory via mcporter with novelty/dedupe filtering to reduce noise. Disable with `shieldcortex config --openclaw-auto-memory false`. **Fire-and-forget.** |

## Installation

### Automatic (recommended)

```bash
npm install -g shieldcortex
shieldcortex openclaw install
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

## Auto-Memory

Auto-memory extraction is on by default. ShieldCortex complements your existing memory system with built-in deduplication to avoid noise.

Disable it:

```bash
shieldcortex config --openclaw-auto-memory false
```

Re-enable it:

```bash
shieldcortex config --openclaw-auto-memory true
```

Or set directly in `~/.shieldcortex/config.json`:

```json
{
  "openclawAutoMemory": true
}
```

Novelty filtering is enabled by default when auto-memory is on. Optional tuning keys:

```json
{
  "openclawAutoMemoryDedupe": true,
  "openclawAutoMemoryNoveltyThreshold": 0.88,
  "openclawAutoMemoryMaxRecent": 300
}
```

You can also manage these settings from the local dashboard in `Shield Overview -> OpenClaw Memory`.

## Cloud Sync (optional)

Add your API key to `~/.shieldcortex/config.json`:

```json
{
  "cloudApiKey": "sc_...",
  "cloudBaseUrl": "https://api.shieldcortex.ai"
}
```

Threat detections will POST to the cloud endpoint. Fails silently if not configured.

## Audit Logs

Written to `~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl` — one JSON object per line.
