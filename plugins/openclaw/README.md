# @drakon-systems/shieldcortex-realtime

OpenClaw plugin for ShieldCortex real-time defence scanning and optional memory extraction.

## Compatibility

- **Node.js** — ≥ 18 required
- **OpenClaw** — ≥ 2026.3.22 required, **≥ 2026.4.23 recommended** — 2026.4.23 added host-package linking for plugins that declare `openclaw` as a peer dependency ([#70462](https://github.com/openclaw/openclaw/pull/70462)), which lets any future `openclaw/plugin-sdk/*` imports resolve without a duplicate runtime bundle
- **ShieldCortex** — ≥ 4.11.1 required

OpenClaw is declared as an **optional** peer dependency, so installs on older OpenClaw keep working but miss the linking benefit.

### Packaging note for OpenClaw discovery

Only the dedicated `@drakon-systems/shieldcortex-realtime` plugin declares OpenClaw plugin metadata (`openclaw.extensions` + a root `openclaw.plugin.json`). The main `shieldcortex` package keeps an `openclaw.hooks` entry — needed for the documented `openclaw hooks install` flow — but **as of v4.20.0 it no longer declares `openclaw.extensions`** so OpenClaw's npm discovery cannot mistake the bare main package for a plugin.

Why this matters. The realtime plugin's `peerDependencies.shieldcortex` causes OpenClaw to install the main package alongside in its own npm tree (`~/.openclaw/npm/node_modules/shieldcortex`). With the old contract (pre-v4.20.0) OpenClaw scanned that bare copy, found `openclaw.extensions`, registered it as a duplicate of this plugin, and emitted `duplicate plugin id detected; global plugin will be overridden by global plugin`. Functionally it dedupes — the right `dist/index.js` always wins — but the warning was noise. Removing `openclaw.extensions` from the main package makes the bare copy invisible to discovery; the warning goes away and the dedicated plugin remains the only registration target.

The defensive root `openclaw.plugin.json` is kept for one release on the main package as a shim against OpenClaw versions that might still consult it; it can be removed in a follow-up once that's confirmed clear. History: the v4.18.2 incident (Jarvis, 2026-05-16) was `plugin manifest not found` because the package declared `openclaw.extensions` *without* a root manifest. v4.18.3 added the manifest; v4.20.0 removes the declaration that required it in the first place.

### Known limitations under OpenClaw 2026.4.23

- **Forked subagent context is host-owned.** OpenClaw 2026.4.23 added `ContextEngine.prepareSubagentSpawn({ contextMode: "isolated" | "fork" })` on the plugin-sdk's `ContextEngine` interface, but the spawn itself is initiated by the host runtime — plugins can only react to the lifecycle, not call `sessions_spawn` directly. Work that would benefit from an isolated scratch transcript (e.g. batch scans) therefore still runs inline in the parent session. If upstream exposes a plugin-callable spawn API, scan offloading will be revisited.
- **No public `systemPromptAddition` seam in plugin-sdk.** Hook metadata (`{ name, description }`) is typed and stable, but the SDK does not expose a structured hook for contributing to the effective system prompt. SC's bootstrap injection was disabled in v2026.2.26 for this reason (it was using private internals), and OpenClaw's native Memory Search now handles context recall at session start.

## What it does

| Hook | Action |
|------|--------|
| `llm_input` | Scans prompts and history through the ShieldCortex defence pipeline. Threats are logged to audit and can forward to ShieldCortex Cloud. |
| `llm_output` | Extracts high-signal memories from assistant replies and writes them into ShieldCortex with novelty filtering and dedupe. |
| `before_tool_call` | Runs the Action Guard before tools execute. Catastrophic shell/file/network/git actions are blocked; dangerous actions warn by default or request approval when enforcement is enabled. |

The plugin is intentionally fire-and-forget: it should not stall the OpenClaw turn loop if ShieldCortex is unavailable.

## Installation

### 1. Install ShieldCortex

This plugin resolves the main `shieldcortex` package at runtime, so the CLI must also be installed somewhere the machine can reach.

```bash
npm install -g shieldcortex
```

If `shieldcortex` is not on `PATH`, set `binaryPath` in the plugin config.

### 2. Install the plugin

```bash
openclaw plugins install @drakon-systems/shieldcortex-realtime
```

If you also want the companion session hook, install it from the main package:

```bash
openclaw skills install shieldcortex
```

Restart OpenClaw after installing:

```bash
openclaw gateway restart
```

### Local development

From the monorepo root, you can link the working plugin directory directly:

```bash
openclaw plugins install --link /path/to/ShieldCortex/plugins/openclaw
```

## Configuration

The plugin reads config from `plugins.entries.shieldcortex-realtime.config` in your OpenClaw config and merges it over `~/.shieldcortex/config.json`.

Example:

```json
{
  "plugins": {
    "entries": {
      "shieldcortex-realtime": {
        "enabled": true,
        "hooks": {
          "allowConversationAccess": true
        },
        "config": {
          "binaryPath": "/usr/local/bin/shieldcortex",
          "openclawAutoMemory": true,
          "openclawAutoMemoryDedupe": true,
          "openclawAutoMemoryNoveltyThreshold": 0.88,
          "openclawAutoMemoryMaxRecent": 300
        }
      }
    }
  }
}
```

Supported plugin config keys:

- `binaryPath`: absolute path to the `shieldcortex` binary
- `cloudApiKey`: optional ShieldCortex Cloud API key for realtime threat forwarding
- `cloudBaseUrl`: optional API base URL override
- `openclawAutoMemory`: enable or disable output memory extraction
- `openclawAutoMemoryDedupe`: enable or disable duplicate suppression
- `openclawAutoMemoryNoveltyThreshold`: dedupe similarity threshold, `0.6` to `0.99`
- `openclawAutoMemoryMaxRecent`: dedupe cache size, `50` to `1000`

## Auto-memory

Auto-memory extraction is enabled when `openclawAutoMemory` is `true`. It complements your existing memory setup with deduplication to avoid noisy repeats.

You can manage the same settings through ShieldCortex itself:

```bash
shieldcortex config --openclaw-auto-memory true
shieldcortex config --openclaw-auto-memory false
```

Or by editing `~/.shieldcortex/config.json`:

```json
{
  "openclawAutoMemory": true,
  "openclawAutoMemoryDedupe": true,
  "openclawAutoMemoryNoveltyThreshold": 0.88,
  "openclawAutoMemoryMaxRecent": 300
}
```

## Cloud forwarding

Threat forwarding is optional. Configure it in ShieldCortex:

```json
{
  "cloudApiKey": "sc_...",
  "cloudBaseUrl": "https://api.shieldcortex.ai"
}
```

Or in the plugin entry config if you want plugin-specific overrides.

## Audit logs

Realtime events are written to:

```text
~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl
```

Each line is a JSON object with input-scan, threat, and output-memory activity.
