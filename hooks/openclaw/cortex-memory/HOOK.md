---
name: cortex-memory
description: "Persistent brain-like memory via ShieldCortex — auto-saves session context and recalls past knowledge"
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

Integrates [ShieldCortex](https://github.com/Drakon-Systems-Ltd/ShieldCortex) persistent memory. Automatically saves important session context and recalls past knowledge at session start.

## What It Does

### On `/new` (Session End)
1. Reads the ending session transcript
2. Pattern-matches for decisions, bug fixes, learnings, architecture changes, and preferences
3. Saves up to 5 high-salience memories to ShieldCortex via mcporter

### On `/stop`, `/clear`, `/exit` (Session End)
1. Captures the current session transcript before it ends
2. Pattern-matches for important content (same patterns as `/new`)
3. Saves memories with a `session-stop` tag for tracking
4. **Ensures work is saved** even when explicitly ending a session

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

## Requirements

- **npx** must be available (Node.js installed)
- ShieldCortex installs automatically on first use via `npx -y shieldcortex`
- mcporter must be available for MCP tool calls

## Database

Memories stored in `~/.shieldcortex/memories.db` (SQLite). Shared with Claude Code sessions — memories created here are available everywhere.

## Install

```bash
npx shieldcortex openclaw install
```

## Uninstall

```bash
npx shieldcortex openclaw uninstall
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
