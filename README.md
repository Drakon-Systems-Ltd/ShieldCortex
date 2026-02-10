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

### NEW: ShieldCortex Cloud

See every threat across every project in one team dashboard. The local package now syncs audit data to [ShieldCortex Cloud](https://shieldcortex.ai) — sign up directly from the built-in dashboard, no CLI commands needed.

```
Local Agent                    ShieldCortex Cloud
┌──────────────┐               ┌──────────────────────┐
│  npm package │──audit sync──▶│  Team dashboard      │
│  (free,      │               │  Audit log + stats   │
│   unlimited) │               │  Team invites        │
│              │               │  Usage analytics     │
└──────────────┘               └──────────────────────┘
```

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

### Security Layer (6 Defence Layers)
| Layer | What It Does | Tier |
|-------|-------------|------|
| **Memory Firewall** | Blocks prompt injection, encoding tricks, hidden instructions | Free |
| **Audit Logger** | Full forensic trail of every memory operation | Free |
| **Trust Scorer** | Scores memories by source reliability | Free |
| **Sub-Agent Security** | Access control, rate limiting, auto-quarantine | Free |
| **Sensitivity Classifier** | Detects & redacts passwords, API keys, PII | Free |
| **Fragmentation Detector** | Catches slow-burn assembly attacks | Free |
| **Credential Leak Detector** | Blocks API keys, tokens, private keys, connection strings from persisting in memory | Free |

### Skill Scanner (Agent Instruction Files)

AI agents are configured by instruction files (`SKILL.md`, `CLAUDE.md`, `.cursorrules`, etc.) — and attackers are hiding prompt injections inside them. ShieldCortex scans all of them:

| Format | File |
|--------|------|
| Claude Code Skills | `SKILL.md` |
| Claude Code Config | `CLAUDE.md` |
| OpenClaw Hooks | `HOOK.md`, `handler.js` |
| Cursor | `.cursorrules` |
| Windsurf | `.windsurfrules` |
| Cline | `.clinerules` |
| GitHub Copilot | `copilot-instructions.md` |
| Aider | `.aider.conf.yml` |
| Continue | `.continue/config.json` |

```bash
# Scan all instruction files on your machine
npx shieldcortex scan-skills

# Scan a specific file
npx shieldcortex scan-skill ~/.claude/plugins/cache/.../SKILL.md
```

The dashboard Skills tab shows results with severity badges, expandable threat details, and actions:
- **Trust** — Mark known-safe skills so they're not flagged on future scans (free, local)
- **Remove** — Delete dangerous skill files from disk (cloud-connected, premium)

### NEW: Credential Leak Detection (v2.7.0)

Agents sometimes accidentally persist secrets in memory — API keys pasted in chat, connection strings from debug output, private keys from config files. ShieldCortex now automatically detects and blocks these before they're stored.

| Category | Providers / Patterns | Severity |
|----------|---------------------|----------|
| **API Keys** | OpenAI, Anthropic, AWS, GitHub, Stripe, Twilio, SendGrid, Slack, Google, npm | Critical |
| **Auth Tokens** | JWT, Bearer headers, Basic auth | High |
| **Private Keys** | RSA, EC, SSH, PKCS8 PEM blocks | Critical |
| **Connection Strings** | PostgreSQL, MySQL, MongoDB, Redis (with passwords) | Critical |
| **Env Secrets** | PASSWORD=, SECRET=, TOKEN=, API_KEY= assignments | High |
| **High-Entropy Strings** | Shannon entropy > 4.5 on 20+ char tokens | Medium |

```typescript
import { scanForCredentials, redactCredentials } from 'shieldcortex/defence';

// Standalone scan
const result = scanForCredentials('My key is sk-abc123...');
// → { leaked: true, findings: [{ type: 'api_key', provider: 'openai', severity: 'critical', action: 'blocked' }] }

// Redact secrets from content
const safe = redactCredentials('postgres://admin:pass@db.host/mydb');
// → "[REDACTED-connection_string-postgres]"
```

Runs automatically in the defence pipeline — no configuration needed. Critical and high-severity findings are blocked by default.

### Attack Vectors Blocked
- **Direct injection** — `[SYSTEM: ignore previous]` hidden in content
- **Credential harvesting** — Attempts to exfiltrate secrets
- **Credential persistence** — API keys, tokens, and passwords accidentally stored in memory
- **Encoding tricks** — Base64/hex/unicode payloads
- **Slow-burn assembly** — Attack fragments planted over days
- **Privilege escalation** — System command references
- **Skill file poisoning** — Hidden instructions in agent configuration files

### 🤖 Multi-Agent Security

Running multiple agents or sub-agents? ShieldCortex prevents rogue agents from accessing sensitive data:

| Feature | What It Does |
|---------|--------------|
| **Hierarchical Trust Decay** | Sub-agents get lower trust: `user-spawned` (0.9) → `>task-1` (0.63) → `>subtask-2` (0.44) |
| **Origin-Based Scoring** | Different trust by source: user (0.9), cron (0.5), agent-spawned (0.3), web (0.2) |
| **Credential Isolation** | RESTRICTED memories blocked below trust 0.7 — sub-agents can't access secrets |
| **Depth Circuit Breaker** | Agents beyond depth 5 get trust = 0 (blocked entirely) |
| **Auto-Quarantine** | Low-trust writes go to quarantine for human review |
| **Environment Detection** | Auto-detects sub-agents from `CLAUDE_CODE_ENTRYPOINT` — zero config |

```
Trust ≥0.7  → Read all, write direct, delete own
Trust 0.5–0.7 → Read own + non-restricted, quarantine writes
Trust <0.5  → Read own only, quarantine only, no delete
```

**Result:** A sub-agent spawning another sub-agent that tries to read your API keys? **Blocked.**

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

## OpenClaw Setup

**Three commands. That's it.** Works on macOS, Linux (including headless servers), and Windows.

```bash
# 1. Install globally
npm install -g shieldcortex

# 2. Install the OpenClaw hook
sudo npx shieldcortex openclaw install

# 3. Connect to Cloud (get your API key from the Cloud dashboard)
npx shieldcortex config --cloud-api-key <your-key> --cloud-enable
```

Every memory your OpenClaw agent saves now passes through the 6-layer defence pipeline, and audit data syncs to your team's Cloud dashboard automatically.

### Onboarding Team Members

Adding someone to your team? Give them an API key and these three commands:

```bash
npm install -g shieldcortex
sudo npx shieldcortex openclaw install
npx shieldcortex config --cloud-api-key <team-api-key> --cloud-enable
```

No signup, no browser, no account creation needed. The API key ties their scans to your team. Their device appears in your Cloud dashboard automatically once scans start flowing.

> **Headless servers?** No problem — ShieldCortex runs entirely via CLI. No GUI or browser required.

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

**One command. Persistent memory for every OpenClaw session.**

```bash
sudo npx shieldcortex openclaw install
```

This installs the **cortex-memory** hook directly into OpenClaw's bundled hooks directory. No configuration needed.

### What It Does

```
Session Start                During Session              Session End (/new)
     │                            │                            │
     ▼                            ▼                            ▼
┌─────────────┐           ┌─────────────┐           ┌─────────────┐
│ Inject past │           │ "remember   │           │ Auto-extract│
│ context     │           │  this: ..." │           │ decisions,  │
│ into agent  │           │  → save     │           │ fixes, etc. │
└─────────────┘           └─────────────┘           └─────────────┘
```

| Feature | What Happens |
|---------|--------------|
| **Context Injection** | On session start, relevant past memories are injected into the agent's bootstrap context |
| **Keyword Triggers** | Say "remember this:" or "don't forget:" followed by content to save it with critical importance |
| **Auto-Extraction** | On `/new`, the hook extracts architecture decisions, bug fixes, and learnings from the ending session |
| **Security** | All content passes through the 6-layer defence pipeline before storage |

### Shared Memory

The database (`~/.shieldcortex/memories.db`) is shared with Claude Code. Memories created in OpenClaw appear instantly in Claude Code sessions, and vice versa.

### Commands

```bash
sudo npx shieldcortex openclaw install    # Install hook
sudo npx shieldcortex openclaw uninstall  # Remove hook
npx shieldcortex openclaw status          # Check status
```

[Full documentation](docs/openclaw-integration.md)

---

## Dashboard

```bash
npx shieldcortex --dashboard
```

- **Dashboard**: http://localhost:3030
- **API**: http://localhost:3001

Views: Shield (defence overview), Audit Log, Quarantine, Memories, 3D Brain, Knowledge Graph, Skills Scanner.

### Cloud Sync

Connect your local dashboard to ShieldCortex Cloud and see threats from all your projects in one place. The dashboard includes a guided setup — just enter your email and click the magic link.

```bash
# Or configure via CLI
npx shieldcortex config --cloud-api-key <key> --cloud-enable
```

Once connected, every local scan automatically syncs audit metadata (not content) to your Cloud dashboard.

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
npx shieldcortex install            # Alias for setup
npx shieldcortex migrate            # Migrate from Claude Cortex
npx shieldcortex doctor             # Check installation health
npx shieldcortex scan-skills         # Scan all agent instruction files
npx shieldcortex scan-skill <file>  # Scan a specific instruction file
npx shieldcortex --dashboard        # Start dashboard + API
npx shieldcortex --version          # Show version
npx shieldcortex service install    # Auto-start on login
npx shieldcortex graph backfill     # Extract entities from existing memories
npx shieldcortex openclaw install   # Install OpenClaw hook
npx shieldcortex copilot install    # Configure MCP for VS Code + Cursor
npx shieldcortex scan "text"        # Quick content scan (credential + threat detection)
npx shieldcortex config --cloud-api-key <key>  # Set Cloud API key
npx shieldcortex config --cloud-enable  # Enable cloud sync
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
| Cloud Team Dashboard | No | Yes | Yes | **Yes** |
| MCP Native | Yes | No | No | **Yes** |
| Self-Hosted | Yes | No | Partial | **Yes** |
| Open Source | Yes | Partial | Partial | **Yes** |

**ShieldCortex is the only memory system built for adversarial conditions.**

---

## Pricing

| Tier | What You Get | Price |
|------|--------------|-------|
| **Free** | npm package (unlimited local scans) + Cloud (500 scans/month, 1 member, 7-day audit retention) | Free |
| **Pro** | 10K cloud scans/month, team invites, 90-day retention | £29/mo |
| **Team** | 100K cloud scans/month, unlimited members, 1-year retention | £99/mo |
| **Enterprise** | Self-hosted, SLA, custom rules, dedicated support | [Contact us](https://shieldcortex.ai/pricing) |

The npm package is free and unlimited for local use. Cloud tiers add team visibility, longer retention, and higher scan limits. See [shieldcortex.ai/pricing](https://shieldcortex.ai/pricing) for details.

---

## Links

- **Website:** [shieldcortex.ai](https://shieldcortex.ai)
- **Cloud Dashboard:** [api.shieldcortex.ai](https://api.shieldcortex.ai)
- **npm:** [npmjs.com/package/shieldcortex](https://www.npmjs.com/package/shieldcortex)
- **GitHub:** [github.com/Drakon-Systems-Ltd/ShieldCortex](https://github.com/Drakon-Systems-Ltd/ShieldCortex)
- **Docs:** [shieldcortex.ai/docs](https://shieldcortex.ai/docs)
- **Architecture:** [ARCHITECTURE.md](ARCHITECTURE.md)

---

## License

MIT

**Built by [Drakon Systems](https://github.com/Drakon-Systems-Ltd)**
