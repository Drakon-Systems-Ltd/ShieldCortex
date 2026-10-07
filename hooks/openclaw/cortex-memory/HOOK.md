---
name: cortex-memory
description: "Persistent brain-like memory via ShieldCortex — recalls past knowledge, with optional auto-save"
homepage: https://github.com/Drakon-Systems-Ltd/ShieldCortex
metadata:
  { "openclaw": { "emoji": "🧠", "events": ["command:new", "command:stop", "agent:bootstrap"], "requires": { "bins": ["npx"] }, "install": [{ "id": "community", "kind": "community", "label": "ShieldCortex" }] } }
---

# Cortex Memory Hook

Integrates [ShieldCortex](https://github.com/Drakon-Systems-Ltd/ShieldCortex) persistent memory. Recalls past knowledge at session start, and can optionally auto-save important session context.

## What It Does

### On `/new` (Session End)
When `openclawAutoMemory` is enabled:
1. Reads the ending session transcript
2. Pattern-matches for decisions, bug fixes, learnings, architecture changes, and preferences
3. Saves up to 5 high-salience memories to ShieldCortex via mcporter
4. Skips exact and near-duplicate memories using novelty filtering

### On `/stop` (Session End)
When `openclawAutoMemory` is enabled:
1. Reads the current session transcript
2. Pattern-matches for important content (same patterns as `/new`)
3. Saves memories with a `session-stop` tag for tracking
4. Skips exact and near-duplicate memories using novelty filtering

Core OpenClaw 2026.9.6 does not show the hook's "Saved N memories" note for `/stop`: the stop command sends its own reply and does not read the hook's `event.messages`.

`/clear` and `/exit` are not core OpenClaw 2026.9.6 hook events, and they are not in this hook's `events` list, so this hook does not capture on them.

### On Session Start (Agent Bootstrap)
Unbounded `CORTEX_MEMORY.md` dump remains **disabled** (v2026.2.26 ~40× context blow-up class).

**Memory SOTA B:** when `memory.inject.nativeContract` is set to `sc_only` or `disable_native_inject`, bootstrap may push a **single budgeted** `SHIELDCORTEX_INJECT_PACK.md` (hard ceilings; hash-ring; fact-only). Without that contract the hook does **not** reclaim the native memory bus.

The hook still fires on `agent:bootstrap` for lifecycle wiring (threat scan warnings, optional inject pack, self-heal). It must never reintroduce unbounded memory dumps.

### Keyword Triggers (dormant, not registered)

The handler has a keyword-trigger path, but it is **not registered** on core OpenClaw 2026.9.6 with this manifest, and it is not enabled by default. The `events` list above subscribes only `command:new`, `command:stop` and `agent:bootstrap`. OpenClaw never sends this hook a `message` event, and no other command action reaches the handler's command fallback. Saying one of these phrases does **not** save anything through this hook. The per-message proactive recall in the same `message` branch is dormant for the same reason; this hook does not recall memory on each message.

Phrases the dormant code recognises:

| Trigger Phrase | Category | Importance |
|---------------|----------|------------|
| **"remember this"** | note | critical |
| **"don't forget"** | note | critical |
| **"this is important"** | note | critical |
| **"make a note"** | note | critical |
| **"for the record"** | note | critical |
| **"note to self"** | note | critical |
| **"important:"** | note | critical |
| **"crucial:"** | note | critical |
| **"key point:"** | note | high |
| **"lesson learned"** | learning | high |
| **"i learned"** | learning | normal |
| **"TIL:"** | learning | normal |
| **"today i learned"** | learning | normal |
| **"never again"** | error | critical |
| **"root cause was"** | error | high |
| **"the fix was"** | error | high |
| **"always do"** | preference | high |
| **"never do"** | preference | high |
| **"i prefer"** | preference | normal |
| **"we should always"** | preference | high |
| **"we decided"** | architecture | high |
| **"decision made"** | architecture | high |
| **"going with"** | architecture | normal |

If that path were registered, it would save the text after the phrase as the memory content.

## Defence Audit Guarantees

Every byte that lands in `memories` from the auto-extract path passes the
6-layer defence pipeline first. The hook write path is no longer the
bypass it once was:

- **ALLOW** → row inserted into `memories`; a corresponding row appears in
  `defence_audit` with `source_type = 'hook'` and the hook's identifier
  (`session-end-hook` / `pre-compact-hook` / `stop-hook`).
- **QUARANTINE** → row inserted into `quarantine` (not `memories`), linked
  to the audit row via `audit_id`. Visible in the dashboard for review.
- **BLOCK** → dropped. The audit row written by the pipeline carries the
  block reason; nothing reaches `memories`.
- **Pipeline error** → dropped + a synthetic audit row with reason
  `pipeline_error: <msg>`. Never silently lose data.

Built-in firewall rules covering instruction injection, hidden
instruction, imperative tool-call directives ("call X tool now"), command
injection, and credential leaks (AWS / JWT / private keys) are seeded
into `firewall_rules` on first run with `built_in = 1`. They are
always evaluated (user-added custom rules are free too, behind a dormant
feature gate) and excluded from the user-facing 25-rule cap.

The chunker also rejects malformed candidates *before* they reach the
write path: imperative tool-calls, bare-imperative starts ("commit
secrets" with the negation dropped), email-body bleed, and path-label
fragments. Auto-extracted memories are now capped at salience 0.6
(reserved 1.0 for LLM-rated future paths).

To audit an existing database for malformed rows accumulated before this
fix:

```bash
shieldcortex memories purge --malformed --dry-run    # preview
shieldcortex memories purge --malformed --execute    # delete (writes a backup first)
```

## Auto-Memory

Auto-memory extraction runs only when `openclawAutoMemory` is `true` in `~/.shieldcortex/config.json`. When the key is not set, or the file is missing, it is off. A fresh global, non-CI `npm install -g shieldcortex` on a machine with no config file writes one with `openclawAutoMemory: true` (and `proactiveRecall: true`) when that write succeeds. Local and CI installs, and installs run with `--ignore-scripts`, do not write it. An existing config file is never changed, so an upgrade keeps whatever it already says. When on, it captures decisions, fixes, and learnings, with deduplication.

The config file does not install this hook. It runs only once the hook is installed in OpenClaw and not disabled there: `shieldcortex openclaw install`, or `shieldcortex setup`, which asks before wiring.

Disable auto-save with CLI:

```bash
npx shieldcortex config --openclaw-auto-memory false
```

Re-enable it:

```bash
npx shieldcortex config --openclaw-auto-memory true
```

Or set directly in config:

```json
{
  "openclawAutoMemory": true
}
```

in `~/.shieldcortex/config.json`.

## Requirements

- **npx** must be available (Node.js installed)
- ShieldCortex installs automatically on first use via `npx -y shieldcortex`
- mcporter must be available for MCP tool calls

## Database

Memories stored in `~/.shieldcortex/memories.db` (SQLite). Shared with Claude Code sessions — memories created here are available everywhere.

## Install

```bash
openclaw skills install shieldcortex
```

Optional companion real-time plugin:

```bash
openclaw plugins install @drakon-systems/shieldcortex-realtime
```

## Uninstall

```bash
shieldcortex openclaw uninstall
```

Or disable without removing:

```json
{
  "hooks": {
    "internal": {
      "entries": {
        "cortex-memory": { "enabled": false }
      }
    }
  }
}
```
