# ShieldCortex — Competitive Analysis

*Last updated: Feb 1, 2026*

## The AI Memory Landscape

The AI agent memory market is exploding. Agents need persistent memory to be useful, but the solutions are fragmented and — critically — **none of them address security**.

---

## Key Players

### 1. Supermemory (supermemory.ai)
**What:** Cloud-hosted Memory API for AI apps
**Founded by:** Dhravya Shah
**Traction:** 10,000+ developers, 70+ YC companies, 30+ enterprises
**Pricing:** Free tier → Pro (paid) → Enterprise

**Architecture:**
- Cloud SaaS — your data is sent to their servers
- Knowledge graph with 3 relationship types (Updates, Extends, Derives)
- Auto-forgetting: temporal memories expire, contradictions resolve
- Handles any content type (PDFs, videos, web pages, text, images)
- RAG-as-a-service built in
- User profiles (static facts + dynamic episodic context)
- Processing pipeline: Queue → Extract → Chunk → Embed → Index → Done

**Integrations:**
- MCP server (Claude Code, Cursor, etc.)
- OpenClaw/Moltbot plugin (claude-supermemory)
- Browser extension (Chrome/Edge)
- Raycast extension
- Connectors: Notion, Google Drive, OneDrive

**Strengths:**
- Most polished product in the space
- YC-backed with real enterprise traction
- Sophisticated graph relationships (updates/extends/derives)
- Broad integration ecosystem
- Handles multimedia content

**Weaknesses:**
- ❌ **Cloud-only** — user data leaves their machine and sits on Supermemory's servers
- ❌ **No security layer** — no scanning, no trust scoring, no injection detection
- ❌ **Paid** — requires Pro plan for meaningful use
- ❌ **Privacy risk** — AI agent memories (potentially containing credentials, personal data, business secrets) stored on third-party cloud
- ❌ **No audit trail** for security/compliance

---

### 2. ShieldCortex (github.com/mkdelta221/shieldcortex)
**What:** Open-source brain-like memory system for Claude Code
**Founded by:** Michael Kyriacou (Drakon Systems) — **this is our foundation**
**Traction:** Open-source, growing community
**Pricing:** Free forever

**Architecture:**
- 100% local (SQLite with FTS5, runs on your machine)
- Brain-inspired memory tiers: STM → LTM → Episodic
- Salience scoring (importance-based retention)
- Natural decay (memories fade if not reinforced)
- Knowledge graph with entity extraction and relationships
- Hook-based auto-capture (PreCompact, SessionStart, SessionEnd, Stop)

**Integrations:**
- Claude Code (native hooks)
- OpenClaw/Moltbot (clawdbot hook)
- MCP server
- Dashboard with visualization

**Strengths:**
- ✅ **100% local** — data never leaves your machine
- ✅ **Free and open-source** — no API costs
- ✅ **Brain-inspired architecture** — more biologically accurate than graph-only approaches
- ✅ **Automatic** — hooks handle everything, no manual memory management
- ✅ **Foundation for ShieldCortex** — battle-tested memory engine

**Weaknesses:**
- 🟡 Focused primarily on Claude Code / dev workflows
- 🟡 Less sophisticated graph relationships than Supermemory
- 🟡 No multimedia content handling
- 🟡 Smaller integration ecosystem

---

### 3. Mem0 (mem0.ai)
**What:** Memory layer for AI applications
**Positioning:** "Memory for AI agents and assistants"

**Notable:** Another cloud memory provider, similar space to Supermemory. Same security gaps apply.

---

### 4. Letta / MemGPT
**What:** Stateful LLM framework with memory management
**Positioning:** Agent framework with built-in memory

**Notable:** More of a full agent framework than a standalone memory solution. Memory is a feature, not the product.

---

## Head-to-Head: Supermemory vs ShieldCortex

| Dimension | Supermemory | ShieldCortex |
|-----------|-------------|---------------|
| **Privacy** | ❌ Cloud (data on their servers) | ✅ 100% local |
| **Security** | ❌ None | ❌ None (until ShieldCortex) |
| **Features** | ✅ More polished, multimedia | 🟡 Dev/code focused |
| **Graph** | ✅ Sophisticated relationships | 🟡 Basic entity extraction |
| **Auto-forget** | ✅ Temporal + contradiction | ✅ Decay-based |
| **Cost** | ❌ Paid API | ✅ Free |
| **Integration breadth** | ✅ Broad ecosystem | 🟡 Claude Code focused |
| **Self-hosting** | 🟡 Enterprise only | ✅ Always local |
| **Brain-like architecture** | 🟡 Graph-focused | ✅ STM/LTM/Episodic tiers |
| **Content types** | ✅ PDF, video, images, web | 🟡 Text/code primarily |

---

## Where ShieldCortex Fits

**Nobody is doing memory security.** Every player above — Supermemory, Cortex, Mem0, Letta — stores and retrieves memories with **zero protection** against:

1. Prompt injection via memory
2. Memory poisoning (gradual corruption)
3. Cross-session data leakage
4. Memory exfiltration
5. Fragmented payload assembly (Palo Alto's Jan 2026 warning)

### ShieldCortex's Position

```
┌─────────────────────────────────────────┐
│            ANY AI AGENT                 │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│          SHIELDCORTEX                   │
│   Scan → Classify → Trust-Score        │
│   Firewall → Detect → Audit            │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│        ANY MEMORY BACKEND               │
│  Supermemory │ Cortex │ Mem0 │ Custom   │
└─────────────────────────────────────────┘
```

**We don't compete with memory providers. We protect them.**

### The Cloudflare Analogy

Cloudflare doesn't host your website — it sits in front of any web server and protects it. ShieldCortex doesn't store your memories — it sits in front of any memory system and secures it.

### The Privacy Angle

Cloud memory providers like Supermemory create an additional attack surface — your AI agent's entire brain (potentially containing credentials, personal data, business secrets, code) is stored on someone else's infrastructure.

ShieldCortex addresses this two ways:
1. **Local memory users** (Cortex, etc.) → Scan and protect before storage
2. **Cloud memory users** (Supermemory, etc.) → Scan and sanitise before data leaves your machine

**Marketing hook:** "Why are you sending your AI's brain to someone else's cloud? And if you must — at least scan it first."

---

## Market Timing

- **Jan 31, 2026:** Palo Alto Networks publishes warning about persistent memory attacks on AI agents
- **Jan 2026:** Moltbook hits 30,000+ AI agents, zero memory security
- **Jan 2026:** Supermemory has 10,000+ devs sending AI memories to the cloud
- **Feb 2026:** ShieldCortex launches — first mover in AI memory security

The window is NOW. Every week that passes, someone else could build this.

---

## Competitive Moat

1. **First mover** — No direct competitor in AI memory security
2. **Open-source core** — Community adoption creates lock-in through familiarity
3. **Universal compatibility** — Works with any memory backend, not tied to one ecosystem
4. **Research credibility** — Built by people who identified and documented the attack vectors
5. **ShieldCortex foundation** — Battle-tested memory engine underneath the security layer
