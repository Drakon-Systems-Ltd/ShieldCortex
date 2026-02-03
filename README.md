# ShieldCortex

[![npm version](https://img.shields.io/npm/v/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![npm downloads](https://img.shields.io/npm/dm/shieldcortex.svg)](https://www.npmjs.com/package/shieldcortex)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue)](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)

## 🧠 + 🛡️ Complete Memory & Security for AI Agents

**ShieldCortex gives your AI agent persistent memory AND protects it from attack. One package. Full solution.**

Most AI agents are stateless — they forget everything between sessions. ShieldCortex fixes that with production-grade persistent memory. But memory creates risk: researchers have [demonstrated memory poisoning attacks](https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/) that hijack AI behaviour. **ShieldCortex is the only solution that solves both problems.**

```
┌─────────────────────────────────────────────────────────────┐
│                      ShieldCortex                           │
├─────────────────────────────┬───────────────────────────────┤
│     🧠 MEMORY SYSTEM        │     🛡️ SECURITY LAYER        │
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

### 🧠 Memory System (Production-Ready)
- **Persistent storage** — SQLite-backed, survives restarts
- **Semantic search** — Find memories by meaning, not just keywords
- **Project scoping** — Isolate memories per project/context
- **Importance levels** — Critical, high, normal, low with auto-decay
- **Categories** — Architecture, decisions, preferences, context, learnings
- **Auto-cleanup** — Configurable retention, importance-based expiry
- **Full MCP support** — Works with any MCP-compatible agent

### 🛡️ Security Layer (5 Defence Layers)
| Layer | What It Does | Tier |
|-------|-------------|------|
| **Memory Firewall** | Blocks prompt injection, encoding tricks, hidden instructions | Free |
| **Audit Logger** | Full forensic trail of every memory operation | Free |
| **Trust Scorer** | Scores memories by source reliability | Free |
| **Sub-Agent Security** | Access control, rate limiting, auto-quarantine | Free |
| **Sensitivity Classifier** | Detects & redacts passwords, API keys, PII | Pro |
| **Fragmentation Detector** | Catches slow-burn assembly attacks | Pro |

### 🎯 Attack Vectors Blocked
- **Direct injection** — `[SYSTEM: ignore previous]` hidden in content
- **Credential harvesting** — Attempts to exfiltrate secrets
- **Encoding tricks** — Base64/hex/unicode payloads
- **Slow-burn assembly** — Attack fragments planted over days
- **Privilege escalation** — System command references

---

## Quick Start (30 Seconds)

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

---

## Supported Agents

ShieldCortex is agent-agnostic middleware:

| Agent | Integration |
|-------|-------------|
| **[Claude Code](https://claude.ai)** | `npx shieldcortex setup` — Native MCP server |
| **[OpenClaw](https://openclaw.ai)** | `npx shieldcortex clawdbot install` — Native hooks |
| **[LangChain JS](https://js.langchain.com)** | `import { ShieldCortexMemory } from 'shieldcortex/integrations/langchain'` |
| **Python (CrewAI, AutoGPT)** | REST API — `POST /api/v1/scan` |
| **Any MCP agent** | Via MCP protocol or `@langchain/mcp-adapters` |

If your agent stores memories, ShieldCortex can power and protect them.

---

## Requirements

| Requirement | Version |
|-------------|---------|
| **Node.js** | ≥ 18.0.0 |
| **Platform** | macOS, Linux, or Windows |
| **Storage** | ~50MB for SQLite database |

ShieldCortex runs anywhere Node.js runs. No external dependencies. No Docker required. Just `npm install` and go.

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

## How It Works

```
┌──────────┐     ┌──────────────────────────────────┐     ┌─────────────┐
│          │     │          ShieldCortex            │     │             │
│  Agent   │────▶│  Scan → Score → Store → Index   │────▶│  SQLite DB  │
│          │     │  Filter → Audit → Protect        │     │             │
└──────────┘     └──────────────────────────────────┘     └─────────────┘
     │                          │
     │    ┌─────────────────────┴─────────────────────┐
     │    │              On Every Write:              │
     │    │  ✓ Scan for injection patterns           │
     │    │  ✓ Detect credential exposure            │
     │    │  ✓ Check encoding tricks                 │
     │    │  ✓ Score trust level                     │
     │    │  ✓ Log to audit trail                    │
     │    └───────────────────────────────────────────┘
     │
     │    ┌─────────────────────────────────────────────┐
     └───▶│              On Every Read:                │
          │  ✓ Filter by trust threshold              │
          │  ✓ Semantic search & ranking              │
          │  ✓ Redact sensitive content               │
          │  ✓ Log access to audit trail              │
          └─────────────────────────────────────────────┘
```

---

## Configuration

```json
{
  "memory": {
    "database": "~/.shieldcortex/memory.db",
    "maxMemories": 10000,
    "defaultImportance": "normal",
    "decayEnabled": true,
    "decayHalfLifeDays": 30
  },
  "security": {
    "enableFirewall": true,
    "enableAudit": true,
    "trustThreshold": 0.5,
    "quarantineOnThreat": true
  },
  "search": {
    "semanticEnabled": true,
    "maxResults": 20
  }
}
```

---

## CLI Commands

```bash
# Setup & Migration
shieldcortex setup              # Auto-configure for your agent
shieldcortex migrate            # Migrate from Claude Cortex

# Memory Operations
shieldcortex remember "fact"    # Store a memory
shieldcortex recall "query"     # Search memories
shieldcortex forget <id>        # Delete a memory
shieldcortex list               # List recent memories

# Security Operations
shieldcortex scan               # Scan all memories for threats
shieldcortex audit              # View audit log
shieldcortex quarantine list    # View quarantined memories
shieldcortex trust <id> <score> # Manually set trust score

# Dashboard
shieldcortex dashboard          # Open web dashboard (Pro)
```

---

## Why ShieldCortex?

| Feature | Claude Cortex | Mem0 | Zep | **ShieldCortex** |
|---------|---------------|------|-----|------------------|
| Persistent Memory | ✅ | ✅ | ✅ | ✅ |
| Semantic Search | ✅ | ✅ | ✅ | ✅ |
| Prompt Injection Detection | ❌ | ❌ | ❌ | ✅ |
| Memory Firewall | ❌ | ❌ | ❌ | ✅ |
| Sub-Agent Access Control | ❌ | ❌ | ❌ | ✅ |
| Audit Trail | ❌ | ❌ | ⚠️ | ✅ |
| Credential Protection | ❌ | ❌ | ❌ | ✅ |
| MCP Native | ✅ | ❌ | ❌ | ✅ |
| Self-Hosted | ✅ | ❌ | ⚠️ | ✅ |
| Open Source | ✅ | ⚠️ | ⚠️ | ✅ |

**ShieldCortex is the only memory system built for adversarial conditions.**

---

## Pricing

| Tier | What You Get | Price |
|------|--------------|-------|
| **Free** | Full memory system + core security (firewall, audit, trust scoring) | £0 |
| **Pro** | + Sensitivity classifier, fragmentation detector, web dashboard | £29/mo |
| **Team** | + Multi-agent coordination, shared memory pools, team audit | £99/mo |
| **Enterprise** | + SSO, SLA, dedicated support, custom integrations | Contact us |

[Get Started Free](https://shieldcortex.ai) • [View Pricing](https://shieldcortex.ai/pricing)

---

## Links

- 🌐 **Website:** [shieldcortex.ai](https://shieldcortex.ai)
- 📦 **npm:** [npmjs.com/package/shieldcortex](https://www.npmjs.com/package/shieldcortex)
- 🐙 **GitHub:** [github.com/Drakon-Systems-Ltd/ShieldCortex](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
- 📖 **Docs:** [docs.shieldcortex.ai](https://docs.shieldcortex.ai)
- 🏢 **By:** [Drakon Systems](https://drakonsystems.com)

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT © [Drakon Systems Ltd](https://drakonsystems.com)

---

<p align="center">
  <strong>Give your AI agent a brain that fights back.</strong><br>
  <a href="https://shieldcortex.ai">shieldcortex.ai</a>
</p>
