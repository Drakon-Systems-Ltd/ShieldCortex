# ShieldCortex

[![npm version](https://img.shields.io/npm/v/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![npm downloads](https://img.shields.io/npm/dm/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue)](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)

## Complete Memory & Security for AI Agents

**ShieldCortex gives your AI agent persistent memory AND protects it from attack. One package. Full solution.**

Most AI agents are stateless — they forget everything between sessions. ShieldCortex fixes that with production-grade persistent memory. But memory creates risk: researchers have [demonstrated memory poisoning attacks](https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/) that hijack AI behaviour. **ShieldCortex is the only solution that solves both problems.**

```
┌─────────────────────────────────────────────────────────────┐
│                      ShieldCortex                           │
├─────────────────────────────┬───────────────────────────────┤
│     MEMORY SYSTEM           │     SECURITY LAYER            │
├─────────────────────────────┼───────────────────────────────┤
│ • Persistent storage        │ • Memory firewall             │
│ • Semantic search           │ • Prompt injection detection  │
│ • Project scoping           │ • Credential protection       │
│ • Importance ranking        │ • Sub-agent access control    │
│ • Auto-cleanup & decay      │ • Full audit trail            │
│ • Category organisation     │ • Threat quarantine           │
└─────────────────────────────┴───────────────────────────────┘
```

**Stop choosing between memory and security. Get both.**

---

## What You Get

### Memory System (Production-Ready)
- **Persistent storage** — SQLite-backed, survives restarts
- **Semantic search** — Find memories by meaning, not just keywords
- **Project scoping** — Isolate memories per project/context
- **Importance levels** — Critical, high, normal, low with auto-decay
- **Categories** — Architecture, decisions, preferences, context, learnings
- **Auto-cleanup** — Configurable retention, importance-based expiry
- **Full MCP support** — Works with any MCP-compatible agent

### Security Layer (5 Defence Layers)
| Layer | What It Does | Tier |
|-------|-------------|------|
| **Memory Firewall** | Blocks prompt injection, encoding tricks, hidden instructions | Free |
| **Audit Logger** | Full forensic trail of every memory operation | Free |
| **Trust Scorer** | Scores memories by source reliability | Free |
| **Sub-Agent Security** | Access control, rate limiting, auto-quarantine | Free |
| **Sensitivity Classifier** | Detects & redacts passwords, API keys, PII | Pro |
| **Fragmentation Detector** | Catches slow-burn assembly attacks | Pro |

### Attack Vectors Blocked
- **Direct injection** — `[SYSTEM: ignore previous]` hidden in content
- **Credential harvesting** — Attempts to exfiltrate secrets
- **Encoding tricks** — Base64/hex/unicode payloads
- **Slow-burn assembly** — Attack fragments planted over days
- **Privilege escalation** — System command references

---

## Quick Start

```bash
# Install globally
npm install -g shieldcortex

# Auto-configure for your agent (Claude Code, OpenClaw, LangChain, etc.)
npx shieldcortex setup

# That's it. Your agent now has persistent memory + security.
```

**Already using Claude Cortex?** Migrate in one command:
```bash
npx shieldcortex migrate
```

**Verify installation:**
```bash
npx shieldcortex doctor
```

---

## Supported Agents

ShieldCortex is agent-agnostic middleware:

| Agent | Integration |
|-------|-------------|
| **[Claude Code](https://claude.ai)** | `npx shieldcortex setup` — Native MCP server |
| **[OpenClaw / Moltbot](https://openclaw.dev)** | `npx shieldcortex openclaw install` — Native hooks |
| **[LangChain JS](https://js.langchain.com)** | `import { ShieldCortexMemory } from 'shieldcortex/integrations/langchain'` |
| **Python (CrewAI, AutoGPT)** | REST API — `POST /api/v1/scan` |
| **Any MCP agent** | Via MCP protocol or `@langchain/mcp-adapters` |

If your agent stores memories, ShieldCortex can power and protect them.

---

## Requirements

| Requirement | Version |
|-------------|---------|
| **Node.js** | >= 18.0.0 |
| **Platform** | macOS, Linux, or Windows |
| **Storage** | ~50MB for SQLite database |

No external dependencies. No Docker required. Just `npm install` and go.

---

## Is Your AI Agent Already Compromised?

Find out in 30 seconds:

```bash
npx shieldcortex setup
```

Then ask your agent: **"Scan my memories for threats"**

ShieldCortex will scan every stored memory and report:
- Hidden instructions disguised as normal content
- Credential harvesting attempts
- Encoded payloads (base64, unicode, hex)
- Fragmented attack patterns spread across memories
- Privilege escalation attempts

**No threats found?** Great — now you're protected going forward.

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

---

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

---

## OpenClaw Integration

```bash
npx shieldcortex openclaw install
```

The **cortex-memory** hook provides:
- Auto-save on `/new` command
- Context injection on bootstrap
- Keyword triggers ("remember this...")

---

## Dashboard

```bash
npx shieldcortex --dashboard
```

- **Dashboard**: http://localhost:3030
- **API**: http://localhost:3001

Views: Shield (defence overview), Audit Log, Quarantine, Memories, 3D Brain, Knowledge Graph.

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
npx shieldcortex openclaw install   # Install OpenClaw hook
npx shieldcortex uninstall          # Full uninstall (requires confirmation)
npx shieldcortex uninstall --confirm # Non-interactive uninstall
```

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

## Why ShieldCortex?

| Feature | Claude Cortex | Mem0 | Zep | **ShieldCortex** |
|---------|---------------|------|-----|------------------|
| Persistent Memory | Yes | Yes | Yes | Yes |
| Semantic Search | Yes | Yes | Yes | Yes |
| Prompt Injection Detection | No | No | No | **Yes** |
| Memory Firewall | No | No | No | **Yes** |
| Sub-Agent Access Control | No | No | No | **Yes** |
| Audit Trail | No | No | Partial | **Yes** |
| Credential Protection | No | No | No | **Yes** |
| MCP Native | Yes | No | No | **Yes** |
| Self-Hosted | Yes | No | Partial | **Yes** |
| Open Source | Yes | Partial | Partial | **Yes** |

**ShieldCortex is the only memory system built for adversarial conditions.**

---

## Pricing

| Tier | What You Get | Price |
|------|--------------|-------|
| **Free** | Full memory system + core security (firewall, audit, trust scoring) | Free |
| **Pro** | + Sensitivity classifier, fragmentation detector, web dashboard | Coming soon |

Free tier is fully functional for individual developers.

---

## Links

- **Website:** [shieldcortex.ai](https://shieldcortex.ai)
- **npm:** [npmjs.com/package/shieldcortex](https://www.npmjs.com/package/shieldcortex)
- **GitHub:** [github.com/Drakon-Systems-Ltd/ShieldCortex](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
- **Architecture:** [ARCHITECTURE.md](ARCHITECTURE.md)

---

## License

MIT

**Built by [Drakon Systems](https://github.com/Drakon-Systems-Ltd)**
