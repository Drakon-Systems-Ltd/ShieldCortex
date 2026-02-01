# ShieldCortex

[![npm version](https://img.shields.io/npm/v/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![npm downloads](https://img.shields.io/npm/dm/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**The security layer for any AI agent's memory.** Like Cloudflare, but for everything your AI remembers — regardless of platform.

Researchers have [demonstrated persistent memory attacks](https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/) on AI agents. Attackers can poison what your agent remembers — injecting instructions, stealing credentials, or assembling attacks across days of fragmented memories. **ShieldCortex stops that.**

### Supported Agents

ShieldCortex is agent-agnostic middleware. It works with:

- **[Claude Code](https://claude.ai)** — Native MCP server + hooks (`npx shieldcortex setup`)
- **[OpenClaw / Moltbook](https://openclaw.dev)** — Native hook support (`npx shieldcortex clawdbot install`)
- **[LangChain JS](https://js.langchain.com)** — `ShieldCortexMemory` adapter (`import { ShieldCortexMemory } from 'shieldcortex/integrations/langchain'`)
- **Python frameworks (CrewAI, AutoGPT, etc.)** — Via REST API (`POST /api/v1/scan`)
- **Any MCP-compatible agent** — Via `@langchain/mcp-adapters` or direct MCP protocol
- **Any agent with a memory backend** — REST API for scanning, quarantine, and audit

If your agent stores memories, ShieldCortex can protect them.

---

## Is Your AI Agent Compromised?

Find out in 30 seconds:

```bash
npx shieldcortex setup
```

Then ask your AI agent: **"Scan my memories for threats"**

ShieldCortex will scan every stored memory and report:
- Hidden instructions disguised as normal content
- Credential harvesting attempts
- Encoded payloads (base64, unicode tricks, hex)
- Fragmented attack patterns spread across multiple memories
- Privilege escalation attempts

**No threats found?** Great — now you're protected going forward too.

---

## What It Does

ShieldCortex is a defence pipeline that sits between AI agents and their memory:

```
Agent → ShieldCortex → Any Memory Backend
         ↓
    Scan → Score → Classify → Audit
```

Every memory write is scanned. Every memory read is filtered. Everything is logged.

### Defence Layers

| Layer | What It Catches | Tier |
|-------|----------------|------|
| **Memory Firewall** | Prompt injection, hidden instructions, encoding tricks, command injection | Free |
| **Audit Logger** | Full forensic trail of every memory operation | Free |
| **Trust Scorer** | Filters memories by source reliability (user=1.0, web=0.3, agent=0.1) | Free |
| **Sensitivity Classifier** | Detects passwords, API keys, PII — auto-redacts on recall | Pro |
| **Fragmentation Detector** | Catches multi-step assembly attacks spread across days | Pro |

### Attack Vectors Blocked

1. **Direct injection** — `[SYSTEM: ignore previous instructions]` hidden in memory content
2. **Credential harvesting** — Memories that try to exfiltrate API keys or passwords
3. **Encoding tricks** — Base64/hex/unicode payloads that bypass text filters
4. **Slow-burn assembly** — Attack fragments planted over days that combine into a full exploit
5. **Privilege escalation** — Memories referencing system commands, file paths, or admin URLs

---

## Quick Start

### Fresh Install

```bash
# Install
npm install -g shieldcortex

# Auto-detect your agent and configure (works with Claude Code, OpenClaw, and more)
npx shieldcortex setup

# Restart your agent and approve the MCP server
```

### Migrating from Claude Cortex

```bash
# Non-destructive — copies your database, updates settings
npx shieldcortex migrate

# Restart your agent
```

Your existing memories are preserved. The original database stays intact at `~/.claude-cortex/` for rollback.

### Verify Installation

```bash
npx shieldcortex doctor
```

---

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

### Brain-Like Memory Model

ShieldCortex doesn't just store text — it thinks like a brain:

- **Short-term → Long-term** promotion based on access frequency
- **Salience detection** — auto-scores what's worth keeping
- **Temporal decay** — unused memories fade, accessed memories strengthen
- **Knowledge graph** — entities and relationships extracted automatically

### Defence Pipeline

Every `addMemory()` call runs through the defence pipeline:

1. **Trust scoring** — source gets a trust score (user=1.0 down to agent=0.1)
2. **Firewall scan** — content checked for injection, encoding, privilege escalation
3. **Sensitivity classification** — detects secrets, PII, credentials
4. **Fragmentation analysis** — cross-references with recent memories for assembly patterns
5. **Audit logging** — full record regardless of outcome
6. **Decision** — ALLOW, QUARANTINE, or BLOCK

On recall, memories are filtered by trust score and sensitivity level. RESTRICTED content is redacted.

---

## MCP Tools

| Tool | Description |
|------|-------------|
| `remember` | Store a memory (optional — hooks do this automatically) |
| `recall` | Search memories by query, category, or tags |
| `forget` | Delete memories |
| `get_context` | Get relevant project context |
| `memory_stats` | View memory statistics |
| `scan_memories` | Scan existing memories for threats |
| `audit_query` | Query the defence audit trail |
| `quarantine_review` | Review quarantined memories |
| `defence_stats` | Threat counts, trust distribution |
| `graph_query` | Traverse the knowledge graph |
| `graph_entities` | List known entities |
| `graph_explain` | Find paths between entities |

---

## Dashboard

```bash
npx shieldcortex --dashboard
```

- **Dashboard**: http://localhost:3030
- **API**: http://localhost:3001

Views: Knowledge Graph, Memory Browser, Insights, 3D Brain Visualization.

### Auto-start on login

```bash
npx shieldcortex service install    # Enable
npx shieldcortex service uninstall  # Disable
npx shieldcortex service status     # Check
```

Works on macOS (launchd), Linux (systemd), and Windows.

---

## CLI Reference

```bash
npx shieldcortex setup              # Auto-detect agent + configure hooks
npx shieldcortex migrate            # Migrate from Claude Cortex
npx shieldcortex doctor             # Check installation health
npx shieldcortex --dashboard        # Start dashboard + API
npx shieldcortex --version          # Show version
npx shieldcortex service install    # Auto-start on login
npx shieldcortex graph backfill     # Extract entities from existing memories
npx shieldcortex clawdbot install   # Install OpenClaw hook
npx shieldcortex uninstall          # Full uninstall
```

---

## Pricing

| | Free (npm) | Pro (coming soon) |
|---|---|---|
| Memory Firewall | Yes | Yes |
| Audit Logger | Yes | Yes |
| Trust Scorer | Yes | Yes |
| Retroactive Scanner | Yes | Yes |
| Sensitivity Classifier | — | Yes |
| Fragmentation Detector | — | Yes |
| Cloud API | — | Yes |
| Dashboard & Alerts | — | Yes |
| Compliance Exports | — | Yes |

Free tier is fully functional for individual developers. Pro adds enterprise defence layers and a hosted cloud API.

---

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

### Install from source

```bash
git clone https://github.com/Drakon-Systems-Ltd/ShieldCortex.git
cd ShieldCortex
npm install
npm run build
```

</details>

<details>
<summary>Custom database location</summary>

Default: `~/.shieldcortex/memories.db`

```bash
npx shieldcortex --db /path/to/custom.db
```

</details>

<details>
<summary>Environment variables</summary>

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | API server port |
| `CORTEX_CORS_ORIGINS` | `localhost:3030,localhost:3000` | Allowed CORS origins |

</details>

---

## LangChain Integration

```javascript
import { ShieldCortexMemory, ShieldCortexGuard } from 'shieldcortex/integrations/langchain';

// As a LangChain memory backend (scans before storing)
const memory = new ShieldCortexMemory({ mode: 'balanced' });
const vars = await memory.loadMemoryVariables({ input: 'deployment config' });
await memory.saveContext({ input: 'hello' }, { output: 'hi' });

// As standalone middleware (scan without storing)
const guard = new ShieldCortexGuard();
const result = guard.scan('some content to check');
if (!result.allowed) {
  console.warn('Blocked:', result.firewall.reason);
}
```

## REST API (Any Agent)

Start the API server, then scan content from any language or framework:

```bash
npm run dev:api   # Starts on http://localhost:3001
```

```bash
# Scan content
curl -X POST http://localhost:3001/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"content": "memory to scan", "title": "test"}'

# Batch scan
curl -X POST http://localhost:3001/api/v1/scan/batch \
  -H 'Content-Type: application/json' \
  -d '{"items": [{"content": "item 1"}, {"content": "item 2"}]}'

# Query audit logs
curl http://localhost:3001/api/v1/audit?firewallResult=BLOCK

# List quarantined items
curl http://localhost:3001/api/v1/quarantine

# Approve/reject quarantined items
curl -X POST http://localhost:3001/api/v1/quarantine/1/approve
curl -X POST http://localhost:3001/api/v1/quarantine/1/reject
```

All defence layers run automatically — firewall, trust scoring, sensitivity classification, and audit logging.

---

## OpenClaw / Clawdbot Integration

```bash
npx shieldcortex clawdbot install
```

The **cortex-memory** hook provides auto-save on `/new`, context injection on bootstrap, and keyword triggers ("remember this").

---

## License

MIT

**Built by [Drakon Systems](https://github.com/Drakon-Systems-Ltd)**
