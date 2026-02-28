# ShieldCortex — Persistent Memory & Security for AI Agents

Give your AI agent a brain that persists between sessions — and protect it from memory poisoning attacks.

## Description

ShieldCortex is a complete memory system with built-in security. It gives AI agents persistent, intelligent memory with semantic search, knowledge graphs, decay-based forgetting, and contradiction detection. Every memory write passes through a 6-layer defence pipeline that blocks prompt injection, credential leaks, and poisoning attacks. Iron Dome adds behavioural protection with action gates, security profiles, and full audit trails.

**Use when:**
- You want your agent to remember things between sessions (decisions, preferences, architecture, context)
- You need semantic search across past memories (not just keyword matching)
- You want automatic memory consolidation, decay, and cleanup
- You want knowledge graph extraction from memories (entities, relationships)
- You need to protect memory from prompt injection or poisoning attacks
- You want credential leak detection in memory writes (25+ patterns, 11 providers)
- You want to audit what's been stored in and retrieved from memory
- You want to scan agent instruction files (SKILL.md, .cursorrules, CLAUDE.md) for hidden threats
- You want behavioural protection with Iron Dome (action gates, security profiles)
- You want to guard any memory backend with the defence pipeline (Universal Memory Bridge)

**Do NOT use when:**
- You only need simple key-value storage (use a config file)
- You want ephemeral session-only context (use the agent's built-in context window)
- You need a vector database for RAG pipelines (ShieldCortex is agent memory, not document retrieval)

## Prerequisites

- Node.js >= 18
- npm or pnpm (or pip for Python)

## Install

```bash
npm install -g shieldcortex
```

Python SDK:

```bash
pip install shieldcortex
```

For OpenClaw integration (installs the cortex-memory hook):

```bash
shieldcortex openclaw install
```

For Claude Code / VS Code / Cursor MCP integration:

```bash
shieldcortex install
```

## Quick Start

### As an OpenClaw hook (automatic)

After `shieldcortex openclaw install`, the hook activates on next restart:

- **Injects** relevant past memories on session start
- **"remember this: ..."** keyword trigger saves memories inline
- **Auto-memory** (opt-in) — extracts important context on session end with smart deduplication

Enable auto-memory:
```bash
npx shieldcortex config --openclaw-auto-memory
```

### CLI Commands

```bash
# Check status
shieldcortex status

# Scan content for threats
shieldcortex scan "some text to check"

# Full security audit of your agent environment
shieldcortex audit

# Scan all installed skills/instruction files for hidden threats
shieldcortex scan-skills

# Scan a single skill file
shieldcortex scan-skill ./path/to/SKILL.md

# Build knowledge graph from existing memories
shieldcortex graph backfill

# Start the visual dashboard
shieldcortex --dashboard
```

### As a Library (programmatic)

```javascript
import {
  addMemory,
  getMemoryById,
  runDefencePipeline,
  scanSkill,
  extractFromMemory,
  consolidate,
  initDatabase
} from 'shieldcortex';

// Initialize
initDatabase('/path/to/memories.db');

// Add a memory (automatically passes through defence pipeline)
addMemory({
  title: 'API uses OAuth2',
  content: 'The payment API requires OAuth2 bearer tokens, not API keys',
  category: 'architecture',
  importance: 'high',
  project: 'my-project'
});

// Scan content before processing
const result = runDefencePipeline(untrustedContent, 'Email Import', {
  type: 'external',
  identifier: 'email-scanner'
});

if (result.allowed) {
  // Safe to process
}

// Extract knowledge graph entities
const { entities, triples } = extractFromMemory(
  'Database Migration',
  'We switched from MySQL to PostgreSQL for the auth service',
  'architecture'
);
// entities: [{name: 'MySQL', type: 'service'}, {name: 'PostgreSQL', type: 'service'}, ...]
// triples: [{subject: 'auth service', predicate: 'uses', object: 'PostgreSQL'}, ...]
```

## Memory System Features

| Feature | Description |
|---------|-------------|
| **Persistent Storage** | SQLite-backed, survives restarts and compaction |
| **Semantic Search** | Find memories by meaning, not just keywords |
| **Project Scoping** | Isolate memories per project/workspace |
| **Importance Levels** | Critical, high, normal, low with auto-decay |
| **Categories** | Architecture, decisions, preferences, context, learnings, errors |
| **Decay & Forgetting** | Old, unaccessed memories fade — like a real brain |
| **Consolidation** | Automatic merging of similar/duplicate memories |
| **Contradiction Detection** | Flags when new memories conflict with existing ones |
| **Knowledge Graph** | Extracts entities and relationships from memories |
| **Activation Scoring** | Recently accessed memories get retrieval priority |
| **Salience Scoring** | Important memories surface first in search |

## Security Features

| Layer | Protection |
|-------|-----------|
| **Input Sanitisation** | Strip control characters, null bytes, dangerous formatting |
| **Pattern Detection** | Regex matching for known injection patterns |
| **Semantic Analysis** | Embedding similarity to attack corpus |
| **Structural Validation** | JSON/format integrity checks |
| **Behavioural Scoring** | Anomaly detection over time |
| **Credential Leak Detection** | Blocks API keys, tokens, private keys (25+ patterns, 11 providers) |
| **Trust Scoring** | Source-based reliability scoring for memory writes |
| **Audit Trail** | Full forensic log of every memory operation |
| **Skill Scanner** | Detect prompt injection in SKILL.md, .cursorrules, CLAUDE.md |

### Iron Dome

Behavioural security layer that controls what agents can do:

- **Security Profiles** — `school`, `enterprise`, `personal`, `paranoid` — each with tailored action gates and trust levels
- **Action Gates** — gate dangerous actions (send_email, delete_file, api_call) requiring approval before execution
- **Injection Scanning** — scan any text for prompt injection patterns with severity and category
- **Full Audit Trail** — every action check is logged for forensic review

### Universal Memory Bridge

Guard any memory backend with the defence pipeline — not just ShieldCortex's built-in storage:

```javascript
import { ShieldCortexGuardedMemoryBridge, MarkdownMemoryBackend } from 'shieldcortex';

const bridge = new ShieldCortexGuardedMemoryBridge({
  backend: new MarkdownMemoryBackend('~/.my-memories/'),
});
```

Built-in backends: `MarkdownMemoryBackend`, `OpenClawMarkdownBackend`. Implement the backend interface for custom storage.

## ShieldCortex Cloud (Optional)

Sync audit data to a team dashboard for cross-project visibility:

```bash
shieldcortex config set-api-key <your-key>
```

Free local package is unlimited. Cloud adds team dashboards, audit aggregation, and alerts.

## Links

- **npm:** https://www.npmjs.com/package/shieldcortex
- **PyPI:** https://pypi.org/project/shieldcortex
- **GitHub:** https://github.com/Drakon-Systems-Ltd/ShieldCortex
- **Website:** https://shieldcortex.ai
- **Docs:** https://shieldcortex.ai/docs
