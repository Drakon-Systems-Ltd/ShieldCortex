---
name: cortex-memory
description: "Persistent brain-like memory via Claude Cortex — auto-saves session context and recalls past knowledge"
homepage: https://github.com/mkdelta221/claude-cortex
metadata:
  {
    "clawdbot":
      {
        "emoji": "🧠",
        "events": ["command:new", "agent:bootstrap", "command"],
        "requires": { "anyBins": ["npx"] },
        "install": [{ "id": "community", "kind": "community", "label": "Claude Cortex" }],
      },
  }
---

# Cortex Memory Hook

Integrates [Claude Cortex](https://github.com/mkdelta221/claude-cortex) persistent memory. Automatically saves important session context and recalls past knowledge at session start.

## What It Does

### On `/new` (Session End)
1. Reads the ending session transcript
2. Pattern-matches for decisions, bug fixes, learnings, architecture changes, and preferences
3. Saves up to 5 high-salience memories to Claude Cortex via mcporter

### On Session Start (Agent Bootstrap)
1. Calls Cortex `get_context` to retrieve relevant memories
2. Injects them into the agent's bootstrap context
3. Agent starts with knowledge of past sessions

### Keyword Triggers
- Say **"remember this"** or **"don't forget"** followed by content
- Auto-saves to Cortex with critical importance

## Requirements

- **npx** must be available (Node.js installed)
- Claude Cortex installs automatically on first use via `npx -y claude-cortex`
- mcporter must be available for MCP tool calls

## Database

Memories stored in `~/.claude-cortex/memories.db` (SQLite). Shared with Claude Code sessions — memories created here are available everywhere.

## Install

```bash
npx claude-cortex clawdbot install
```

## Uninstall

```bash
npx claude-cortex clawdbot uninstall
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
