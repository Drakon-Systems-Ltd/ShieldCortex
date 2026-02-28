---
name: shieldcortex
description: Persistent memory system with security for AI agents. Remembers decisions, preferences, architecture, and context across sessions with knowledge graphs, decay, contradiction detection, and a 6-layer defence pipeline with Iron Dome behavioural protection. Use when asked to "remember this", "what do we know about", "recall context", "scan for threats", "run security audit", "check memory stats", or when starting a new session and needing prior context.
license: MIT
metadata:
  author: Drakon Systems
  version: 2.17.0
  mcp-server: shieldcortex
  category: memory-and-security
  tags: [memory, security, knowledge-graph, mcp, iron-dome]
---

# ShieldCortex — Persistent Memory & Security for AI Agents

Give your agent a brain that persists between sessions and protect it from memory poisoning attacks.

## When to Use This Skill

- You want to remember things between sessions (decisions, preferences, architecture, context)
- You need to recall relevant past context at the start of a session
- You want knowledge graph extraction from memories (entities, relationships)
- You need to protect memory from prompt injection or poisoning attacks
- You want credential leak detection in memory writes
- You want to audit what has been stored in and retrieved from memory
- You want to scan instruction files (SKILL.md, .cursorrules, CLAUDE.md) for threats

## Setup

Install the npm package globally, then configure the MCP server:

```bash
npm install -g shieldcortex
shieldcortex install
```

Python SDK also available:

```bash
pip install shieldcortex
```

## Core Workflow

### Session Start

At the start of every session, retrieve prior context:

1. Call `start_session` to begin a new session and get relevant memories
2. Or call `get_context` with a query describing the current task

### Remembering

Call `remember` immediately when any of these happen:

- **Architecture decisions** — "We're using PostgreSQL for the database"
- **Bug fixes** — capture root cause and solution
- **User preferences** — "Always use TypeScript strict mode"
- **Completed features** — what was built and why
- **Error resolutions** — what broke and how it was fixed
- **Project context** — tech stack, key patterns, file structure

Parameters:
- `title` (required): Short summary
- `content` (required): Detailed information
- `category`: architecture, pattern, preference, error, context, learning, todo, note
- `importance`: low, normal, high, critical
- `project`: Scope to a specific project (auto-detected if omitted)
- `tags`: Array of tags for categorisation

### Recalling

Call `recall` to search for past memories:

- `mode: "search"` — query-based semantic search (default)
- `mode: "recent"` — most recent memories
- `mode: "important"` — highest-salience memories

Filter by `category`, `tags`, `project`, or `type` (short_term, long_term, episodic).

### Forgetting

Call `forget` to remove outdated or incorrect memories:

- Delete by `id` for a specific memory
- Delete by `query` to match content
- Always use `dryRun: true` first to preview what will be deleted
- Use `confirm: true` for bulk deletions

### Session End

Call `end_session` with a summary to trigger memory consolidation. This promotes short-term memories to long-term and runs decay on old, unaccessed memories.

## Knowledge Graph

ShieldCortex automatically extracts entities and relationships from memories.

- `graph_query` — traverse from an entity, returns connected entities up to N hops
- `graph_entities` — list known entities, filter by type (person, tool, concept, file, language, service, pattern)
- `graph_explain` — find the path connecting two entities

Use the knowledge graph to understand relationships between concepts, technologies, and decisions across the project.

## Memory Intelligence

- `consolidate` — merge duplicate/similar memories, run decay. Use `dryRun: true` to preview
- `detect_contradictions` — find conflicting memories (e.g., "use Redis" vs "don't use Redis")
- `get_related` — find memories connected to a specific memory ID
- `link_memories` — create explicit relationships (references, extends, contradicts, related)
- `memory_stats` — view total counts, category breakdown, decay stats

## Security & Defence

Every memory write passes through a 6-layer defence pipeline:

1. Input Sanitisation — strips control characters and null bytes
2. Pattern Detection — regex matching for known injection patterns
3. Semantic Analysis — embedding similarity to attack corpus
4. Structural Validation — JSON/format integrity checks
5. Behavioural Scoring — anomaly detection over time
6. Credential Leak Detection — blocks API keys, tokens, private keys (25+ patterns, 11 providers)

### Iron Dome

Behavioural security layer that controls what agents can do, not just what they remember:

- `iron_dome_activate` — activate with a profile: `school`, `enterprise`, `personal`, or `paranoid`
- `iron_dome_status` — check active profile, trusted channels, and approval rules
- `iron_dome_check` — gate an action (e.g., send_email, delete_file) before execution
- `iron_dome_scan` — scan text for prompt injection patterns

Profiles control action gates (what actions require approval), channel trust (which instruction sources are trusted), and approval rules.

### Security Tools

- `audit_query` — query the forensic audit log of all memory operations
- `defence_stats` — view defence system statistics (blocks, allows, quarantines)
- `quarantine_review` — review and manage quarantined memories (list, approve, reject)
- `scan_memories` — scan existing memories for signs of poisoning
- `scan_skill` — scan an instruction file for hidden threats (SKILL.md, .cursorrules, CLAUDE.md, etc.)

## Universal Memory Bridge

ShieldCortex can act as a security layer for any memory backend — not just its own. Use `ShieldCortexGuardedMemoryBridge` to wrap any memory system with the full defence pipeline:

```javascript
import { ShieldCortexGuardedMemoryBridge, MarkdownMemoryBackend } from 'shieldcortex';

const bridge = new ShieldCortexGuardedMemoryBridge({
  backend: new MarkdownMemoryBackend('~/.my-memories/'),
});

// All writes pass through the 6-layer defence pipeline
await bridge.write({ title: 'Decision', content: 'Use PostgreSQL' });
```

Built-in backends: `MarkdownMemoryBackend`, `OpenClawMarkdownBackend`. Implement the backend interface for custom storage.

## Project Scoping

- `set_project` — switch active project context
- `get_project` — show current project scope
- Use `project: "*"` for global/cross-project memories

## Best Practices

1. **Remember immediately** — call `remember` right after a decision is made or a bug is fixed, not at the end of the session
2. **Use categories** — architecture, pattern, preference, error, context, learning
3. **Set importance** — mark critical decisions as `importance: "critical"` so they resist decay
4. **Recall at session start** — always call `get_context` or `start_session` first
5. **End sessions properly** — call `end_session` with a summary to trigger consolidation
6. **Review contradictions** — periodically run `detect_contradictions` to catch conflicting information
7. **Scope by project** — memories are automatically scoped to the current project directory

## Troubleshooting

**Memory not found in recall:**
- Try `mode: "search"` with different query phrasing
- Check `set_project` — you may be searching the wrong project scope
- Use `includeDecayed: true` to find memories that have faded

**Memory blocked by firewall:**
- The defence pipeline detected a potential threat (injection, credential leak)
- Check `audit_query` for the specific block reason
- Review with `quarantine_review` if it was a false positive
- Avoid including literal API keys or tokens in memory content

**Consolidation removing memories:**
- Run `consolidate` with `dryRun: true` first to preview
- Mark important memories as `importance: "critical"` to prevent decay
- Access memories regularly — `recall` boosts activation and prevents decay

## OpenClaw Auto-Memory

When using the OpenClaw hook, auto-memory extraction is off by default. Enable it to automatically extract memories from session output:

```bash
npx shieldcortex config --openclaw-auto-memory
```

When enabled, the system deduplicates against recent memories to avoid storing duplicates. Configure with:

- `openclawAutoMemory` — enable/disable (default: false)
- `openclawAutoMemoryDedupe` — deduplicate against existing memories (default: true)
- `openclawAutoMemoryNoveltyThreshold` — similarity threshold for deduplication (default: 0.88)
- `openclawAutoMemoryMaxRecent` — number of recent memories to check (default: 300)

## Links

- npm: https://www.npmjs.com/package/shieldcortex
- PyPI: https://pypi.org/project/shieldcortex
- GitHub: https://github.com/Drakon-Systems-Ltd/ShieldCortex
- Website: https://shieldcortex.ai
