# ShieldCortex — Architecture

## Overview

ShieldCortex is a security layer and brain-like memory system for AI agents. It protects **three surfaces**: what the agent *stores* (the memory-write defence pipeline below), what it *does* (the Iron Dome Action Guard, which gates tool calls at runtime), and what it *sees* (the Environment Firewall, which scrubs fetched/tool content before it becomes authority). It runs in two agent runtimes — **OpenClaw** (an in-process plugin on the `before_tool_call` bus) and **Hermes** (a `pre_tool_call` plugin via the local REST API) — both advisory-first, and fail-open at the transport so a down guard never wedges the agent.

```
Agent → ShieldCortex → Memory Store (SQLite)
         ↓
    Tier 1 (sync, 1-5ms):
    Sanitise → Trust → Firewall → Sensitivity → Fragmentation → Credential
         ↓
    decision → Audit → dashboard event → cloud sync (fire-and-forget)
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

### 1. Input Sanitisation (`src/defence/input-sanitisation/`)

Runs first, before any analysis. Strips control characters and null bytes so that
no later layer is fed a string the detectors and the storage layer would read
differently. The categories it stripped are passed on to the firewall, so a
sanitised-away payload still counts as a signal rather than vanishing silently.

### 2. Trust Scorer (`src/defence/trust/`)
Scores the source of the memory write:

| Source type | Trust Score |
|--------|------------|
| user | 1.0 |
| cli | 0.9 |
| hook | 0.8 |
| api | 0.7 |
| file | 0.6 |
| tool_response | 0.5 |
| agent | 0.5 (delegates to the hierarchy scorer) |
| email | 0.4 |
| web | 0.3 |
| *unrecognised type* | 0.0 |

Exact `type:identifier` keys override the type score:

| Key | Trust Score | Why |
|--------|------------|---|
| `user:direct` | 1.0 | |
| `user:approved` | 0.9 | Approved by the operator, not authored by them |
| `file:import` | 0.4 | Pinned **below** the 0.5–0.7 auto-quarantine band so a benign backup restore succeeds, while imported rows stay scanned and low-trust until reviewed |

Low trust (< 0.5) escalates detections to BLOCK in balanced mode. Note `tool_response`
and `agent` both sit at 0.5 — the top of the auto-quarantine band — so agent writes and
tool output are quarantined for review rather than trusted.

### 3. Memory Firewall (`src/defence/firewall/`)

Seven detection modules run over the sanitised content, all dispatched from
`analyzeFirewall()`:

- **Instruction Detector** — prompt injection, fake system prompts, hidden instructions, social engineering, delimiter attacks, frontmatter injection
- **Privilege Detector** — credential references, system commands, destructive filesystem ops, network exfiltration, external URLs
- **Encoding Detector** — base64, hex (including plain continuous hex), URL encoding, zero-width chars, RTL override, Unicode homoglyphs
- **Markdown-Image Detector** — image and link syntax used to exfiltrate content to an attacker-controlled URL on render
- **Credential-Exfil Detector** — content that pairs a secret with an egress path
- **Anomaly Scorer** — entropy analysis, length anomalies, repetition patterns
- **Skill-Threat Detector** (`../skill-scanner/patterns.js`) — skill/hook-format threat patterns, applied at memory-**write** time and not only on file scans

`confusables.ts` is **not** a detector — it is a shared utility (`foldConfusables`,
`hasConfusables`) imported *by* the instruction and encoding detectors, so a
homoglyph-smuggled keyword is caught by the detector it was trying to evade. Don't
list it as an eighth module.

When the encoding detector decodes an embedded payload, the decoded snippet is
re-scanned through the instruction, privilege, skill-threat, anomaly, and
credential-leak checks — so obfuscation buys an attacker nothing.

**Modes:**
- `strict` — any detection → BLOCK
- `balanced` — context-aware: instruction injection → QUARANTINE (low trust → BLOCK), encoding decoded and re-scanned, zero-width/RTL always quarantined
- `permissive` — allow all, populate indicators only

### 4. Sensitivity Classifier (`src/defence/sensitivity/`)

Classifies content as PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED. Detects passwords, API keys, PII, credentials. RESTRICTED content is blocked. CONFIDENTIAL is redacted on recall.

### 5. Fragmentation Detector (`src/defence/fragmentation/`)

Cross-references new memories with recent ones to catch multi-step assembly attacks. Skipped when the firewall has already blocked:
- Entity extraction from content
- Temporal analysis of related memories
- Assembly pattern detection (fragments that combine into exploits)

### 6. Credential Leak Detection (`src/defence/credential-leak/`)

Scans content for **49 credential patterns across 25 providers** (AWS, GitHub, Stripe, OpenAI, Anthropic, Azure, Google, HashiCorp, MongoDB, Postgres, Redis, SSH/RSA/EC private keys, and more — see `credential-leak/patterns.ts`). Entropy analysis catches generic secrets that match no known pattern. Blocked credentials upgrade the firewall result to BLOCK.

> Counts drift as providers are added. Regenerate rather than trusting this line:
> `grep -oE "provider:\s*'[^']+'" src/defence/credential-leak/patterns.ts | sort -u | wc -l`

### 7. Audit Logger (`src/defence/audit/`)

Runs *after* the decision, not as a gate on it. Full forensic trail of every memory operation: source, trust score, firewall result, sensitivity level, anomaly score, threat indicators, blocked patterns, duration. A BLOCK or QUARANTINE additionally emits a dashboard event and a fire-and-forget cloud sync — neither can delay or change the verdict.

### Semantic Analysis (`src/defence/semantic/`) — async path only

Not one of the six synchronous layers. On `runDefencePipelineWithVerify()` and during deep skill scans, content is embedded and compared by cosine similarity against a curated corpus of attack phrasings, catching paraphrased injections the regexes miss. Escalation is additive — a clear match raises the verdict to at least QUARANTINE and never downgrades a BLOCK. Threshold is tunable via `SEMANTIC_SIMILARITY_THRESHOLD`. When no embedding model is installed the layer is a silent no-op and every other layer still runs.

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

Both integrations are **advisory-first** and **fail-open at the transport**: an unreachable or erroring guard never wedges the agent. That is a statement about the *plumbing*, not about every verdict — when the guard does run, the catastrophic action class hard-blocks and cannot be configured open (see Iron Dome above). Everything below that class is advisory by default.

## Knowledge Graph (`src/graph/`)

Entities and relationships automatically extracted from memories:
- Pattern-based entity extraction (files, tools, languages, concepts, people, services)
- Entity resolution with fuzzy matching
- Subject-predicate-object triples
- Graph traversal and path finding

This is a **recall aid** (one of three signals fused by the RRF ranker), not a
security surface. It is built from attacker-influenceable memory content, so it
carries no trust weight. Not to be confused with the Threat Graph below.

## Threat Graph (`src/threat-graph/`)

A **security event graph** — the subsystem that makes ShieldCortex *learn*.
Where the Knowledge Graph indexes memory content, the Threat Graph is a
deterministic projection of the **defence audit ledgers** (`defence_audit` +
the OpenClaw gateway's realtime JSONL) into `threat_nodes` / `threat_edges`.
Full design: [`docs/design/2026-08-11-threat-graph.md`](docs/design/2026-08-11-threat-graph.md).

**Core principle:** the ledgers are truth; the graph is a derived view,
rebuildable byte-for-byte (up to surrogate ids) from the ledger at any time
via `shieldcortex threat-graph rebuild`. Nothing in the graph is authoritative
on its own, so there is no separate "graph tampering" surface to defend — graph
integrity reduces to audit integrity plus projector determinism.

**The projector** (`projector.ts`) runs on the brain-worker light tick (both
profiles) under a single-writer lease, in atomic claim-and-advance batches. It
two-tiers volume: aggregate counters/edges for the bulk of scans, event nodes
only for *notable* rows (BLOCK / QUARANTINE / high-anomaly). A
`PROJECTOR_VERSION` bump forces a from-zero rebuild on upgrade.

Three learning loops sit on top, in dependency order:

1. **Per-source risk** (`risk.ts`, Loop 1) — a decayed severity sum per source
   (BLOCK 1.0 / QUARANTINE 0.5 / high-anomaly ALLOW 0.1; `pipeline_error`
   rows weight 0 so a wedged install can't inflate itself). The raw exponent
   sum lives in node `attrs` (ledger-derived, deterministic); the decayed
   output lives in `source_risk` (wall-clock, recomputed by an idle sweep so
   risk heals on schedule). **Accrual is gated on attestation** — an attacker
   writing under a victim's name (which resolves *unattested*) can never enter
   the risk sum the enforcement path consumes. Accrual is rate-capped so no
   identity saturates risk in a burst.
2. **Advisory trust modifier** (`risk.ts` + `defence/pipeline.ts`, Loop 2) —
   the one hot-path touch: an O(1), guarded, fail-to-zero read of `source_risk`
   after trust scoring. Subtracts `min(risk × 0.3, 0.3)` from trust
   (additive-tightening — never raises trust). **Default mode is `advisory`**:
   computed and recorded on the audit row, *not applied*. `enforce` applies it,
   and only for attested identities. Operators can dispute a poisoned score
   with `shieldcortex threat-graph reset-source`.
3. **Operator allowances** (`decision.ts` + `allowance.ts`, Loop 3) — the
   system learns from *your review decisions*. Each individual quarantine
   approve/reject lands a structured decision row; the projector derives
   `source —allows→ pattern` allowances from 3 qualifying approvals (distinct
   days, distinct content, individually reviewed — bulk never counts).
   Optional **auto-release** (`threatGraph.autoRelease`, default **off**)
   admits a would-be-quarantined item only when *every* detection is an active
   allowance and the title+content exactly matches an approved exemplar; it
   never releases a BLOCK, is per-source per-day capped, and **fails closed**.

**Invariants** (why this can *learn* without becoming *trainable*): the ledger
is truth; every automatic effect is additive-tightening; operators are the only
loosening force and they loosen narrowly and expiringly; the hot path reads
only O(1) precomputed values and can never be harmed by a graph fault; node
identity is class-typed (only system vocabulary is trusted); everything is
bounded (caps, decay half-life, retention).

**Honest state:** every learning effect ships **advisory or off** by default.
The false-positive rate is unmeasured (#182), and the design requires an
advisory soak before any deployment moves the trust modifier to `enforce`.
Run on a fleet's own audit history, the top "risks" are the fleet's own trusted
infrastructure processing security content — which is exactly why advisory is
the default. Local-only: no threat-graph data is synced to the cloud.

Surfaces: `threat_graph` MCP tool (`sources` / `source` / `events` /
`allowances` views, row+byte capped) · `shieldcortex threat-graph
rebuild|status|reset-source` · a `doctor` freshness check.

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
│   ├── index.ts                    # CLI entry + command dispatch; re-exports lib.ts
│   ├── lib.ts                      # Public programmatic API → `shieldcortex/lib`
│   ├── scan-only.ts                # Light sync scan, no DB/ML → `shieldcortex/scan`
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
│   │   ├── disposition.ts          # Verdict resolution
│   │   ├── input-sanitisation/     # Layer 1 — strip control chars / null bytes
│   │   ├── firewall/
│   │   │   ├── index.ts            # Firewall orchestrator
│   │   │   ├── instruction-detector.ts
│   │   │   ├── privilege-detector.ts
│   │   │   ├── encoding-detector.ts
│   │   │   ├── confusables.ts
│   │   │   ├── markdown-image-detector.ts
│   │   │   ├── credential-exfil-detector.ts
│   │   │   └── anomaly-scorer.ts
│   │   ├── trust/
│   │   │   ├── source-scorer.ts    # Trust hierarchy
│   │   │   ├── agent-scorer.ts     # Sub-agent hierarchy (0.7× decay per level)
│   │   │   ├── access-control.ts   # Read/write/delete ACL engine
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
│   │   ├── semantic/               # Async deep-scan embedding layer
│   │   ├── iron-dome/              # Action Guard — gates what the agent does
│   │   ├── overseer/               # Approval-path guard (advisory)
│   │   ├── skill-scanner/          # Scan installed agent skills/hooks
│   │   ├── custom-patterns/        # User-defined injection patterns (DB-backed)
│   │   ├── custom-rules/           # User-defined firewall rules (DB-backed)
│   │   ├── quarantine/             # Quarantine store + 7-day auto-expire
│   │   ├── judge/                  # Optional LLM judge
│   │   ├── explainer/              # Human-readable verdict explanations
│   │   ├── hidden-web-injection.ts # Hidden-content detection for fetched pages
│   │   ├── tool-response-scanner.ts# Scan tool output before it becomes context
│   │   ├── tool-response-enforce.ts# Enforce/redact mode for the above
│   │   ├── audit/
│   │   │   ├── logger.ts           # Write audit entries
│   │   │   └── queries.ts          # Query audit trail
│   │   └── scanner/
│   │       └── scan-existing.ts    # Retroactive memory scanner
│   ├── integrations/
│   │   ├── langchain.ts            # ShieldCortexMemory + ShieldCortexGuard
│   │   ├── openclaw.ts             # OpenClaw integration surface
│   │   ├── universal.ts            # Framework-agnostic wrapper
│   │   └── index.ts
│   ├── environment/                # Environment Firewall → `shieldcortex/environment`
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
├── plugins/
│   ├── openclaw/                   # @drakon-systems/shieldcortex-realtime
│   └── hermes/shieldcortex/        # Hermes pre_tool_call plugin
├── skills/shieldcortex/            # Canonical SKILL.md (ClawHub source)
├── dashboard/                      # Next.js — CIC terminal, graph, audit, shield, dome, cloud
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
