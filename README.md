# ShieldCortex 🧠

**Brain-like memory system for Claude Code** — Solves context compaction and memory persistence.

Claude Code forgets everything when context compacts or sessions end. Cortex fixes that with automatic memory extraction, temporal decay, and consolidation — like a human brain.

## Quick Start

```bash
# Step 1: Install
npm install -g shieldcortex

# Step 2: Configure hooks + Claude Code (REQUIRED — this makes memory automatic)
npx shieldcortex setup

# Step 3: Restart Claude Code and approve the MCP server when prompted
```

**That's it.** Cortex now automatically:
- 📥 **Loads context** when a session starts
- 🧠 **Saves important content** before compaction (decisions, fixes, learnings)
- 💾 **Extracts knowledge** when a session ends

You don't need to manually "remember" anything. The hooks handle it.

> **Verify your install:** Run `npx shieldcortex doctor` to check everything is configured correctly.

## How It Works

### Automatic Memory (via Hooks)

When you run `npx shieldcortex setup`, three hooks are installed:

| Hook | Fires When | What It Does |
|------|-----------|--------------|
| **SessionStart** | Session begins | Loads project context from memory |
| **PreCompact** | Before context compaction | Extracts important content before it's lost |
| **SessionEnd** | Session exits | Saves decisions, fixes, and learnings |

**What gets auto-extracted:**
- Decisions: "decided to...", "going with...", "chose..."
- Error fixes: "fixed by...", "the solution was...", "root cause..."
- Learnings: "learned that...", "discovered...", "turns out..."
- Architecture: "the architecture uses...", "design pattern..."
- Preferences: "always...", "never...", "prefer to..."

### Brain-Like Memory Model

Cortex doesn't just store text — it thinks like a brain:

- **Short-term memory** — Session-level, high detail, decays fast
- **Long-term memory** — Cross-session, consolidated, persists
- **Episodic memory** — Specific events and successful patterns
- **Salience detection** — Automatically scores what's worth keeping
- **Temporal decay** — Memories fade but reinforce through access
- **Consolidation** — Worthy short-term memories promote to long-term

### Salience Detection

Not everything is worth remembering. The system scores content automatically:

| Factor | Weight | Example |
|--------|--------|---------|
| Explicit request | 1.0 | "Remember this" |
| Architecture decision | 0.9 | "We're using microservices" |
| Error resolution | 0.8 | "Fixed by updating X" |
| Code pattern | 0.7 | "Use this approach for auth" |
| User preference | 0.7 | "Always use strict mode" |

### Temporal Decay

Like human memory, unused memories fade:

```
score = base_salience × (0.995 ^ hours_since_access)
```

Each access boosts the score by 1.2×. Frequently accessed short-term memories consolidate into long-term storage.

## Tools

Cortex provides these MCP tools to Claude Code:

| Tool | Description |
|------|-------------|
| `remember` | Manually store a memory (optional — hooks do this automatically) |
| `recall` | Search memories by query, category, or tags |
| `forget` | Delete memories (with safety confirmations) |
| `get_context` | Get relevant project context — key after compaction |
| `start_session` / `end_session` | Session lifecycle management |
| `consolidate` | Manually trigger memory consolidation |
| `memory_stats` | View memory statistics |
| `export_memories` / `import_memories` | Backup and restore |

### MCP Resources

| Resource | Description |
|----------|-------------|
| `memory://context` | Current memory context summary |
| `memory://important` | High-priority memories |
| `memory://recent` | Recently accessed memories |

## Dashboard

Cortex includes a visual dashboard with a knowledge graph, memory cards, insights, and a 3D brain view.

```bash
# Start the dashboard
npx shieldcortex --dashboard
```

- **Dashboard**: http://localhost:3030
- **API**: http://localhost:3001

### Auto-start on login

```bash
npx shieldcortex service install    # Enable
npx shieldcortex service uninstall  # Disable
npx shieldcortex service status     # Check
```

Works on **macOS** (launchd), **Linux** (systemd), and **Windows** (Startup folder).

### Dashboard Views

- **Graph** — 2D knowledge graph with zoom-responsive labels and animated links
- **Memories** — Browseable card grid with sort, filter, and bulk actions
- **Insights** — Activity heatmap, knowledge coverage, memory quality analysis
- **Brain** — 3D neural network visualization

### Memory Colors

| Color | Category |
|-------|----------|
| Blue | Architecture |
| Purple | Pattern |
| Green | Preference |
| Red | Error |
| Yellow | Learning |
| Cyan | Context |

## CLI Reference

```bash
npx shieldcortex setup              # Configure Claude Code + hooks + Clawdbot
npx shieldcortex setup --with-stop-hook  # Also install real-time Stop hook
npx shieldcortex doctor             # Check installation health
npx shieldcortex --dashboard        # Start dashboard + API
npx shieldcortex --version          # Show version
npx shieldcortex hook pre-compact   # Run hook manually
npx shieldcortex hook session-start
npx shieldcortex hook session-end
npx shieldcortex hook stop
npx shieldcortex service install    # Auto-start dashboard on login
npx shieldcortex graph backfill     # Extract entities from existing memories
npx shieldcortex clawdbot install   # Install Clawdbot/Moltbot hook
npx shieldcortex clawdbot status    # Check Clawdbot hook status
```

## Advanced Configuration

<details>
<summary>Alternative install methods</summary>

### Use with npx (no global install)

Create `.mcp.json` in your project directory:

```json
{
  "mcpServers": {
    "memory": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "shieldcortex"]
    }
  }
}
```

For global config, create `~/.claude/.mcp.json` with the same content.

### Install from source

```bash
git clone https://github.com/mkdelta221/shieldcortex.git
cd shieldcortex
npm install
npm run build
```

</details>

<details>
<summary>Manual hook configuration</summary>

If you prefer to configure hooks manually instead of using `npx shieldcortex setup`, add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreCompact": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "npx -y shieldcortex hook pre-compact",
            "timeout": 10
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "npx -y shieldcortex hook session-start",
            "timeout": 5
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "npx -y shieldcortex hook session-end",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

</details>

<details>
<summary>Custom database location</summary>

Default: `~/.shieldcortex/memories.db`

```bash
npx shieldcortex --db /path/to/custom.db
```

Or in MCP config:
```json
{
  "mcpServers": {
    "memory": {
      "command": "node",
      "args": ["/path/to/dist/index.js", "--db", "/path/to/custom.db"]
    }
  }
}
```

</details>

<details>
<summary>Environment variables</summary>

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | API server port |
| `CORTEX_CORS_ORIGINS` | `localhost:3030,localhost:3000` | Comma-separated allowed CORS origins |
| `CORTEX_GRAPH_EXTRACTION` | `pattern` | Entity extraction mode (currently only `pattern`) |

</details>

<details>
<summary>Tuning parameters</summary>

In `src/memory/types.ts`:

```typescript
export const DEFAULT_CONFIG = {
  decayRate: 0.995,              // Per-hour decay factor
  reinforcementFactor: 1.2,      // Access boost
  salienceThreshold: 0.3,        // Min score to keep
  consolidationThreshold: 0.6,   // Min for STM→LTM
  maxShortTermMemories: 100,
  maxLongTermMemories: 1000,
  autoConsolidateHours: 4,
};
```

</details>

## Clawdbot / Moltbot Integration

Cortex works with [Clawdbot](https://github.com/clawdbot/clawdbot) and [Moltbot](https://github.com/moltbot/moltbot) via [mcporter](https://mcpmarket.com/tools/skills/mcporter).

```bash
# Automatic (recommended)
npx shieldcortex clawdbot install
# Or: npx shieldcortex setup (auto-detects Clawdbot/Moltbot)
```

The **cortex-memory** hook provides:
- **Auto-save on `/new`** — Extracts decisions, fixes, learnings from ending sessions
- **Context injection on bootstrap** — Agent starts with past session knowledge
- **Keyword triggers** — Say "remember this" or "don't forget" to save explicitly

### Manual mcporter usage

```bash
npx mcporter call --stdio "npx -y shieldcortex" remember title:"API uses JWT" content:"Auth uses JWT with 15-min expiry"
npx mcporter call --stdio "npx -y shieldcortex" recall query:"authentication"
npx mcporter call --stdio "npx -y shieldcortex" get_context
```

Memories are shared between Claude Code and Clawdbot — same SQLite database.

## Knowledge Graph

ShieldCortex automatically extracts entities (tools, languages, files, concepts, people) and relationships from your memories, building a knowledge graph you can query.

### MCP Tools

| Tool | Description |
|------|-------------|
| `graph_query` | Traverse from an entity — returns connected entities up to N hops |
| `graph_entities` | List known entities, filter by type |
| `graph_explain` | Find paths between two entities with source memories |

### Backfill Existing Memories

```bash
npx shieldcortex graph backfill
```

Extracts entities and relationships from all existing memories. Safe to run multiple times.

### API Endpoints

```
GET /api/graph/entities              — List entities (filterable by type)
GET /api/graph/entities/:id/triples  — Triples for an entity
GET /api/graph/triples               — All triples (with pagination)
GET /api/graph/search?q=auth         — Search entities by name
GET /api/graph/paths?from=X&to=Y     — Shortest path between entities
```

## How This Differs

| Feature | ShieldCortex | Other MCP Memory Tools |
|---------|---------------|------------------------|
| Automatic extraction | ✅ Hooks save context for you | ❌ Manual only |
| Salience detection | ✅ Auto-detects importance | ❌ Everything is equal |
| Temporal decay | ✅ Memories fade naturally | ❌ Static storage |
| Consolidation | ✅ STM → LTM promotion | ❌ Flat storage |
| Context injection | ✅ Auto-loads on session start | ❌ Manual recall |
| Knowledge graph | ✅ Visual dashboard | ❌ Usually missing |

## Troubleshooting

**Cortex isn't remembering anything automatically**
→ Did you run `npx shieldcortex setup`? This installs the hooks that make memory automatic. Run `npx shieldcortex doctor` to verify.

**Dashboard doesn't load**
→ Run `npx shieldcortex doctor` to check status. The dashboard requires a one-time build — if it fails, try `cd $(npm root -g)/shieldcortex/dashboard && npm install && npm run build`.

**Memories show 0 in the dashboard**
→ Memories are created during compaction and session events. Use Claude Code for a while — memories build up naturally over time. You can also manually save with the `remember` tool.

**"No cortex entry found in .mcp.json"**
→ Create `.mcp.json` in your project root (see Advanced Configuration) or run `npx shieldcortex setup` to configure automatically.

## Support

If you find this project useful, consider supporting its development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cyborgninja)

## License

MIT
