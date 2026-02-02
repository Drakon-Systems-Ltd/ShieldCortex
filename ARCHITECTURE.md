# ShieldCortex — Architecture

## Overview

ShieldCortex is a security layer and brain-like memory system for AI agents. It combines persistent memory (STM/LTM/episodic) with a 5-layer defence pipeline that scans every memory write for threats.

```
Agent → ShieldCortex → Memory Store (SQLite)
         ↓
    Trust → Firewall → Sensitivity → Fragmentation → Audit
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

Every `addMemory()` call runs through 5 layers:

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
│   ├── defence/
│   │   ├── pipeline.ts             # Orchestrates all 5 layers
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
