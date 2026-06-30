# ShieldCortex — Architecture

## Overview

ShieldCortex is a security layer and brain-like memory system for AI agents. It protects **three surfaces**: what the agent *stores* (the memory-write defence pipeline below), what it *does* (the Iron Dome Action Guard, which gates tool calls at runtime), and what it *sees* (the Environment Firewall, which scrubs fetched/tool content before it becomes authority). It runs in two agent runtimes — **OpenClaw** (an in-process plugin on the `before_tool_call` bus) and **Hermes** (a `pre_tool_call` plugin via the local REST API) — both advisory-first and fail-open.

```
Agent → ShieldCortex → Memory Store (SQLite)
         ↓
    Tier 1 (sync, 1-5ms):
    Trust → Firewall → Sensitivity → Fragmentation → Credential → Audit
         ↓ (if QUARANTINE + verify enabled)
    Tier 2 (async, 500-2000ms):
    Cloud LLM Verification → verdict → optional QUARANTINE→BLOCK upgrade
```

## Memory Model

### Short-Term Memory (STM)
- **Scope**: Current coding session
- **Decay**: Fast (hours)
- **Limit**: 100 memories max

### Long-Term Memory (LTM)
- **Scope**: Cross-session, persistent
- **Content**: Architecture decisions, code patterns, user preferences
- **Decay**: Slow (weeks/months), reinforced by access
- **Limit**: 1,000 memories max

### Episodic Memory
- **Scope**: Specific events/outcomes
- **Content**: "When I tried X, Y happened", successful solutions
- **Decay**: Based on utility

## Salience Detection

| Factor | Weight | Description |
|--------|--------|-------------|
| Explicit request | 1.0 | User says "remember this" |
| Architecture decision | 0.9 | System design choices |
| Error resolution | 0.8 | Debugging breakthroughs |
| Code pattern | 0.7 | Reusable implementation patterns |
| User preference | 0.7 | Coding style, tool preferences |
| Repeated mention | 0.6 | Topics that come up multiple times |
| File location | 0.5 | Where important code lives |
| Temporary context | 0.2 | Current debugging state |

Base salience: 0.25. Deletion threshold: 0.2.

## Temporal Decay & Reinforcement

- **Decay**: `score = base_score * (0.995 ^ hours_since_access)`
- **Reinforcement**: Each access boosts score by 1.2x
- **Consolidation**: High-access STM → LTM (runs every 4 hours)

## Defence Pipeline

Every `addMemory()` call runs through a tiered defence pipeline:

### 1. Trust Scorer (`src/defence/trust/`)
Scores the source of the memory write:

| Source | Trust Score |
|--------|------------|
| user | 1.0 |
| cli | 0.9 |
| hook | 0.8 |
| api | 0.7 |
| agent | 0.5 |
| web | 0.3 |
| unknown | 0.1 |

Low trust (< 0.5) escalates detections to BLOCK in balanced mode.

### 2. Memory Firewall (`src/defence/firewall/`)

Four detection modules run in parallel:

- **Instruction Detector** — prompt injection, fake system prompts, hidden instructions, social engineering, delimiter attacks, frontmatter injection
- **Privilege Detector** — credential references, system commands, destructive filesystem ops, network exfiltration, external URLs
- **Encoding Detector** — base64, hex (including plain continuous hex), URL encoding, zero-width chars, RTL override, Unicode homoglyphs
- **Anomaly Scorer** — entropy analysis, length anomalies, repetition patterns

**Modes:**
- `strict` — any detection → BLOCK
- `balanced` — context-aware: instruction injection → QUARANTINE (low trust → BLOCK), encoding decoded and re-scanned, zero-width/RTL always quarantined
- `permissive` — allow all, populate indicators only

### 3. Sensitivity Classifier (`src/defence/sensitivity/`)

Classifies content as PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED. Detects passwords, API keys, PII, credentials. RESTRICTED content is blocked. CONFIDENTIAL is redacted on recall.

### 4. Fragmentation Detector (`src/defence/fragmentation/`)

Cross-references new memories with recent ones to catch multi-step assembly attacks:
- Entity extraction from content
- Temporal analysis of related memories
- Assembly pattern detection (fragments that combine into exploits)

### 5. Audit Logger (`src/defence/audit/`)

Full forensic trail of every memory operation: source, trust score, firewall result, sensitivity level, anomaly score, threat indicators, blocked patterns, duration.

### 6. Credential Leak Detection (`src/defence/credential-leak/`)

Scans content for 25+ credential patterns across 11 providers (AWS, GitHub, Stripe, etc.). Entropy analysis catches generic secrets. Blocked credentials upgrade the firewall result to BLOCK.

### Tier 2: LLM Verification (`src/cloud/verify.ts`)

Optional async layer for content that Tier 1 flags as QUARANTINE. Submits content to `/v1/verify` for cloud-based LLM analysis (Claude 3.5 Haiku).

- **Fail-OPEN** — if the LLM is unavailable or times out, the Tier 1 verdict stands unchanged
- **Advisory mode** (default): fire-and-forget HTTP request, returns `{ status: 'pending' }` immediately
- **Enforce mode**: awaits the LLM verdict; upgrades QUARANTINE → BLOCK if verdict is THREAT with confidence >= 0.7
- Credentials are redacted before sending to the LLM
- Configurable timeout (default 5000ms, range 1000-30000ms)
- Gated by: cloud enabled + API key set + verify enabled + firewall result matches triggers

**Config** (`~/.shieldcortex/config.json`):
```json
{
  "verifyEnabled": true,
  "verifyMode": "advisory",
  "verifyTriggers": ["QUARANTINE"],
  "verifyTimeoutMs": 5000
}
```

**API**: `runDefencePipelineWithVerify()` wraps the sync pipeline and adds optional verification. Returns `DefencePipelineResultWithVerify` which extends the standard result with a `verification` field.

## Runtime Defence

The memory-write pipeline above protects what the agent **stores**. Two further layers run at tool-execution time to protect what the agent **does** and **sees**.

### Iron Dome — Action Guard (`src/defence/iron-dome/`)

Gates what the agent *does*. `evaluateToolCall(toolName, args)` classifies each tool call into a family (exec / write / delete / network / git / read / memory) and scans the **execution surface** — the shell command, the target path, and the egress URL — against catastrophic, dangerous, and sensitive patterns:

- **Catastrophic** (recursive root deletes, fork bombs, `mkfs`, `dd` to a raw disk, `curl | sh`, secret exfiltration) → **hard block**, and this can never fail open regardless of config.
- **Dangerous** (plain deletes, `sudo`, force-push, service stops, external egress) → `require_approval`.
- **Benign** → allowed silently; the guard never nags on routine work (`ls`, `git status`, `npm test`).

The guard scans only the *execution surface*, never content the agent *produces* — a message body or file contents that merely quote a command is data, not an action (v4.44.0). Within a shell command, tokens that are only printed (`echo`) or commented are treated as inert, without trusting quote-stripping (which would be a bypass). Advisory by default; every block is audited to `~/.shieldcortex/audit/`.

### Environment Firewall (`src/defence/`)

Protects what the agent *sees*. Runs the firewall over fetched web pages and tool output **before** that content reaches the model, auto-catching hidden/prompt injection that would otherwise become authority (v4.43.0).

### Runtime integrations

| Runtime | Hook | Package |
|---------|------|---------|
| OpenClaw | `before_tool_call` (typed-hook bus) + `llm_input` / `llm_output` | `@drakon-systems/shieldcortex-realtime` (npm) |
| Hermes | `pre_tool_call` → REST `POST /api/v1/scan` | `plugins/hermes/shieldcortex/` (repo) |

Both integrations are **advisory-first** and **fail-open**: an unreachable or erroring guard never wedges the agent.

## Knowledge Graph (`src/graph/`)

Entities and relationships automatically extracted from memories:
- Pattern-based entity extraction (files, tools, languages, concepts, people, services)
- Entity resolution with fuzzy matching
- Subject-predicate-object triples
- Graph traversal and path finding

## Database Schema

SQLite with FTS5 full-text search. Location: `~/.shieldcortex/memories.db`

```sql
CREATE TABLE memories (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL,           -- 'short_term', 'long_term', 'episodic'
  category TEXT,                -- 'architecture', 'pattern', 'preference', etc.
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  project TEXT,
  tags TEXT,                    -- JSON array
  salience REAL DEFAULT 0.5,
  access_count INTEGER DEFAULT 0,
  last_accessed TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  decayed_score REAL,
  metadata TEXT,                -- JSON
  trust_score REAL,
  sensitivity_level TEXT,
  source TEXT                   -- JSON { type, identifier }
);

CREATE VIRTUAL TABLE memories_fts USING fts5(
  title, content, tags,
  content='memories',
  content_rowid='id'
);
```

## File Structure

```
shieldcortex/
├── src/
│   ├── index.ts                    # MCP server entry point
│   ├── server.ts                   # MCP server setup, tool definitions
│   ├── database/
│   │   └── init.ts                 # SQLite setup, schema, transactions
│   ├── memory/
│   │   ├── types.ts                # Memory type definitions
│   │   ├── store.ts                # Core CRUD operations, links
│   │   ├── salience.ts             # Salience scoring
│   │   ├── decay.ts                # Temporal decay logic
│   │   ├── consolidate.ts          # STM → LTM consolidation
│   │   ├── similarity.ts           # Semantic similarity
│   │   ├── activation.ts           # Spreading activation
│   │   └── contradiction.ts        # Contradiction detection
│   ├── cloud/
│   │   ├── config.ts               # Cloud + verify config (~/.shieldcortex/config.json)
│   │   ├── cli.ts                  # CLI flag handlers (cloud + verify)
│   │   ├── sync.ts                 # Fire-and-forget audit sync
│   │   └── verify.ts               # LLM verification HTTP client (Tier 2)
│   ├── defence/
│   │   ├── pipeline.ts             # Orchestrates all layers (sync + async verify)
│   │   ├── types.ts                # Defence type definitions
│   │   ├── firewall/
│   │   │   ├── index.ts            # Firewall orchestrator
│   │   │   ├── instruction-detector.ts
│   │   │   ├── privilege-detector.ts
│   │   │   ├── encoding-detector.ts
│   │   │   └── anomaly-scorer.ts
│   │   ├── trust/
│   │   │   ├── source-scorer.ts    # Trust hierarchy
│   │   │   └── recall-filter.ts    # Filter by trust on recall
│   │   ├── sensitivity/
│   │   │   ├── classifier.ts       # PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED
│   │   │   ├── patterns.ts         # Detection patterns
│   │   │   └── redaction.ts        # Auto-redact secrets
│   │   ├── fragmentation/
│   │   │   ├── entity-extractor.ts
│   │   │   ├── temporal-analyzer.ts
│   │   │   └── assembly-detector.ts
│   │   ├── credential-leak/
│   │   │   └── index.ts            # 25+ credential patterns, entropy analysis
│   │   ├── audit/
│   │   │   ├── logger.ts           # Write audit entries
│   │   │   └── queries.ts          # Query audit trail
│   │   └── scanner/
│   │       └── scan-existing.ts    # Retroactive memory scanner
│   ├── integrations/
│   │   ├── langchain.ts            # ShieldCortexMemory + ShieldCortexGuard
│   │   └── index.ts
│   ├── graph/
│   │   ├── extract.ts              # Entity/triple extraction
│   │   ├── resolve.ts              # Entity resolution
│   │   └── backfill.ts             # Backfill existing memories
│   ├── api/
│   │   └── visualization-server.ts # REST API + WebSocket + defence endpoints
│   ├── tools/
│   │   ├── remember.ts
│   │   ├── recall.ts
│   │   ├── forget.ts
│   │   ├── context.ts
│   │   └── graph.ts
│   ├── context/
│   │   └── project-context.ts      # Project auto-detection
│   ├── service/
│   │   ├── install.ts              # Cross-platform service installer
│   │   └── templates.ts            # launchd/systemd/Windows templates
│   ├── setup/
│   │   ├── migrate.ts              # Claude Cortex → ShieldCortex migration
│   │   ├── settings-hooks.ts       # Auto-configure hooks
│   │   └── doctor.ts               # Installation health check
│   ├── worker/
│   │   └── brain-worker.ts         # Background processing
│   └── embeddings/
│       └── generator.ts            # Text embeddings
├── scripts/
│   ├── session-start-hook.mjs      # Auto-recall context
│   ├── pre-compact-hook.mjs        # Auto-extract before compaction
│   ├── session-end-hook.mjs        # Auto-extract on exit
│   └── stop-hook.mjs               # Check last response (opt-in)
├── hooks/
│   └── openclaw/cortex-memory/     # OpenClaw hook
├── dashboard/                      # Next.js 3D brain visualization
├── package.json
├── tsconfig.json
└── README.md
```

## Anti-Bloat Safeguards

- Max 100 STM, 1,000 LTM memories
- 10KB content limit per memory
- 100MB database hard limit
- Auto-consolidation every 4 hours
- Auto-vacuum after deletions
- Decay scores persisted every 5 minutes
