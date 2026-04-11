---
name: cortex-memory
description: "Persistent brain-like memory via ShieldCortex — recalls past knowledge, with optional auto-save"
homepage: https://github.com/Drakon-Systems-Ltd/ShieldCortex
metadata:
  {
    "openclaw":
      {
        "emoji": "🧠",
        "events": ["command:new", "command:stop", "agent:bootstrap", "command"],
        "requires": { "anyBins": ["npx"] },
        "install": [{ "id": "community", "kind": "community", "label": "ShieldCortex" }],
      },
  }
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
1. Calls Cortex `get_context` to retrieve relevant memories
2. Injects them into the agent's bootstrap context
3. Agent starts with knowledge of past sessions

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
