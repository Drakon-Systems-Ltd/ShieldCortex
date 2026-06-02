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

### On `/stop`, `/clear`, `/exit` (Session End)
When `openclawAutoMemory` is enabled:
1. Captures the current session transcript before it ends
2. Pattern-matches for important content (same patterns as `/new`)
3. Saves memories with a `session-stop` tag for tracking
4. **Ensures work is saved** even when explicitly ending a session
5. Skips exact and near-duplicate memories using novelty filtering

### On Session Start (Agent Bootstrap)
Bootstrap context injection was **disabled in v2026.2.26**. OpenClaw's native Memory Search now handles context recall at session start, so the hook no longer pushes memories into the system prompt (which was producing ~40× duplication of CORTEX_MEMORY.md and eating most of the context window).

The hook still fires on `agent:bootstrap` for lifecycle wiring (warning-bootstrap-file handoff, etc.) but contributes nothing to the system prompt. This keeps `extraSystemPromptHash` stable across turns and prevents the session-binding reset loop documented in `src/setup/claude-md.ts`.

### Keyword Triggers

Say any of these phrases to trigger an instant save to Cortex memory:

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

Content after the trigger phrase is extracted and saved as the memory content.

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
evaluated on every tier (the Pro `custom_firewall_rules` gate applies
only to user-added rules) and excluded from the user-facing 25-rule cap.

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

Auto-memory extraction is enabled by default. ShieldCortex complements your existing memory system by capturing decisions, fixes, and learnings with built-in deduplication to avoid noise.

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
