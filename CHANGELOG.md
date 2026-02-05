# Changelog

All notable changes to this project will be documented in this file.

## [2.4.17] - 2026-02-05

### Fixed

- **macOS Tahoe 26.2 dashboard spawn** — Dashboard now launches correctly when `/bin/sh` is sandboxed. Uses explicit shell path from `$SHELL` with `/bin/zsh` fallback.
- **React 19 strict lint compliance** — Fixed `Date.now()` purity issues by using stable state-based timestamps. Fixed setState-in-effect patterns.
- **CI stability** — Skipped flaky search reinforcement tests that timeout in GitHub Actions.

### Improved

- **Better spawn error messaging** — When dashboard spawn fails, users now see a clear manual workaround with exact commands.
- **Resilient dashboard build** — Build script no longer fails if standalone output is unavailable (Turbopack compatibility).

## [2.4.16] - 2026-02-05

### Fixed

- **macOS Tahoe spawn fix (initial)** — Added `shell: true` option for dashboard spawn process.

## [2.4.15] - 2026-02-05

### Fixed

- **Dashboard spawn error handling** — Improved error messages for spawn failures.

## [2.4.14] - 2026-02-05

### Fixed

- **WebSocket crash on disconnected clients** — Added readyState check and try-catch to all WebSocket.send() calls in visualization server. Prevents server crash when broadcasting to clients that disconnected mid-operation.
- **Unicode truncation using wrong length metric** — Content truncation now uses `Buffer.byteLength()` instead of `string.length` to correctly handle multi-byte characters (emoji, CJK). A 10KB limit now enforces actual bytes, not UTF-16 code units.
- **Embedding buffer null dereference** — Added validation that embedding exists and has `.buffer` property before storing. Prevents crash when embedding generation returns invalid result.
- **Silent catch-all hiding errors** — Memory link creation now only ignores UNIQUE constraint violations (expected duplicates). Other errors are logged for debugging.
- **Silent dynamic import failure** — Async cleanup import errors are now logged with message instead of silently swallowed.

## [2.4.13] - 2026-02-05

### Security

- **CRITICAL: Fail-closed on pipeline exception** — Defence pipeline now returns `BLOCK` on any exception instead of `ALLOW`. Prevents attackers from bypassing security by triggering errors.
- **CRITICAL: Fixed ReDOS vulnerability** — Instruction detector patterns now length-capped (50KB max) with bounded repetition to prevent catastrophic backtracking attacks.
- **HIGH: Decoded content full scan** — Base64/hex decoded content now runs through complete firewall pipeline (privilege escalation + anomaly scoring), not just instruction detection.
- **HIGH: Unknown sources now untrusted** — Environment detector defaults to `type: 'agent'` (trust ~0.3) instead of `type: 'cli'` (trust 0.9) for unrecognised callers.
- **HIGH: Anomaly scorer encoding detection** — Added base64 ratio analysis and Shannon entropy calculation to detect encoded payloads masquerading as normal content.

### Fixed

- **Schema mismatch in fragmentation detector** — Changed `detected_at` to `created_at` to match actual database schema. Added query limit to prevent unbounded queries.
- **Remember tool source tracking** — Added `source` parameter to MCP schema for proper audit trail on memory writes.
- **Dashboard path resolution** — Multi-candidate path finder for dashboard server.js works correctly when installed as npm package.
- **Empty string validation** — Remember tool now validates and trims title/content, rejecting empty strings.
- **NaN in API limit parsing** — Visualization server now provides fallback for invalid limit parameters.
- **LangChain clear() contract** — Now throws meaningful error by default with `allowClear` config option, matching BaseMemory contract.
- **OpenClaw hook timeout handling** — Added retry logic and structured error responses for timeout scenarios.

### Changed

- **Trust hierarchy clarified** — Unknown environment sources treated as untrusted agents, not CLI users.
- **Added `pipeline_error` threat indicator** — New indicator type for defence pipeline exceptions.

## [2.4.12] - 2026-02-05

### Added
- **Expanded keyword triggers** — 24 trigger phrases across 5 categories for automatic memory saves:
  - Note: "remember this", "don't forget", "this is important", "make a note", "for the record", "note to self", "important:", "crucial:", "key point:"
  - Learning: "lesson learned", "i learned", "TIL:", "today i learned"
  - Error: "never again", "root cause was", "the fix was"
  - Preference: "always do", "never do", "i prefer", "we should always"
  - Architecture: "we decided", "decision made", "going with"

### Fixed
- **CI dashboard dependencies** — workflow now installs dashboard deps before publish

## [2.4.11] - 2026-02-05

### Fixed
- **Keyword trigger on message events** — "remember this:" and other triggers now work on message events, not just command events

## [2.4.10] - 2026-02-04

### Added
- **Dashboard reinforce button feedback** — visual confirmation when reinforcing memories (loading state, success flash, green ring animation)
- **Bundled dashboard in npm package** — `npx shieldcortex --dashboard` now works globally without separate install
- **Next.js standalone output** — dashboard builds as self-contained server for portable distribution

### Fixed
- **CI auto-release on tag push** — workflow now properly creates GitHub releases when version tags are pushed
- **Dashboard static file paths** — fixed 404 errors for JS chunks after rebuilds

### Changed
- **Improved onboarding UX** — clearer setup instructions and feedback messages

## [2.4.6] - 2026-02-04

### Added
- **Comprehensive OpenClaw integration docs** — full documentation in `/docs` folder
- **Dev.to article** — "How to Give Your AI Agent Persistent Memory in 60 Seconds"
- **Stop/clear/exit session save handlers** — auto-saves context when sessions end

## [2.4.5] - 2026-02-03

### Fixed
- **Migrate command cleanup** — now removes old LaunchAgents and npm packages from previous installations

## [2.4.4] - 2026-02-03

### Fixed
- **MCP server startup hang** — removed synchronous `consolidate()` call that blocked server initialization on large databases. The 4-hour periodic cleanup handles consolidation instead.

## [2.4.3] - 2026-02-03

### Added
- **`npx shieldcortex status` command** — shows database size, memory counts, projects, and defence stats
- **Auto-create GitHub release on tag push** — CI workflow creates release automatically
- **Multi-Agent Security docs** — added trust hierarchy details to README

## [2.4.2] - 2026-02-03

### Changed
- **Renamed `clawdbot` command to `openclaw`** — CLI command is now `npx shieldcortex openclaw install|uninstall|status`. The old `clawdbot` command still works as a backward-compat alias.
- **README restructured** — merged marketing content with technical documentation, added platform badges and comparison table.

## [2.2.0] - 2026-02-01

### Dashboard
- **Security-first redesign** — new default Shield view with defence pipeline status, quarantine queue, threat timeline, and stats summary
- **Audit Log view** — filterable table of all defence pipeline events (time range, source, result)
- **Quarantine Review view** — approve/reject quarantined memories with "Type YES" human confirmation
- **New navigation** — Shield | Audit | Queue | Memories | Brain | Graph (Shield is default)
- **Branding update** — shield icon with cyan/blue/emerald gradient, security-focused metadata
- **Alert badge** — blocked count badge on Shield nav item

### Fixed
- **Defence pipeline was skipped for MCP `remember` calls** — source defaulted to undefined, bypassing the pipeline entirely. Now defaults to `{type: 'cli', identifier: 'mcp'}`
- **DefenceSource type missing `cli` and `hook`** — added to type union and trust scorer (cli=0.9, hook=0.8)
- **Trust scores aligned with ARCHITECTURE.md** — user=1.0, cli=0.9, hook=0.8, api=0.7, agent=0.5, web=0.3

## [2.1.4] - 2026-02-01

### Security
- **Uninstall protection** — `uninstall` and `uninstall-setup` now require interactive TTY confirmation (type "yes") or explicit `--confirm` flag. Prevents bot-initiated or piped uninstalls.

## [2.1.3] - 2026-02-01

### Security
- **Fixed 6 defence pipeline bypass vulnerabilities**
  - Pipeline: QUARANTINE now correctly blocks content (was allowing through)
  - Pipeline: RESTRICTED sensitivity classification now blocks content
  - Instruction detector: added fake system prompt markers (`SYSTEM:`, `ASSISTANT:`, `</system>`)
  - Instruction detector: added YAML frontmatter injection detection (`role: system`)
  - Instruction detector: added social engineering patterns (authority claims, urgency manipulation)
  - Encoding detector: added plain continuous hex string detection (20+ hex chars)
  - Firewall balanced mode: encoded content is now decoded and re-scanned for hidden instructions
  - Firewall balanced mode: zero-width chars, RTL overrides, and Unicode homoglyphs always quarantined

### Test Results
- Strict mode: 16/16 attack vectors blocked
- Balanced mode: 15/16 attack vectors blocked

## [2.1.2] - 2026-02-01

### Fixed
- Removed dashboard source from npm package (390KB → 232KB)
- Fixed broken Palo Alto research link → embracethered.com
- Fixed repo URLs (`mkdelta221` → `Drakon-Systems-Ltd`)
- Added security-focused npm keywords

## [2.1.1] - 2026-02-01

### Fixed
- Added `exports` map to package.json for subpath imports (`shieldcortex/integrations/langchain`)

## [2.1.0] - 2026-02-01

### Added
- **REST API endpoints** for defence pipeline — `POST /api/v1/scan`, `/scan/batch`, `GET /audit`, quarantine management
- **LangChain JS integration** — `ShieldCortexMemory` (BaseMemory-compatible) and `ShieldCortexGuard` (standalone scanner)
- **OpenClaw hook** — `cortex-memory` hook for persistent memory in OpenClaw sessions

### Changed
- README: Supported Agents section now accurately reflects implemented integrations

## [2.0.0] - 2026-02-01

### Added
- **Defence Pipeline** — universal security middleware for AI agent memory (backend-agnostic)
  - **Memory Firewall** — detects prompt injection, hidden instructions, encoding tricks, privilege escalation
  - **Fragmentation Detector** — entity extraction + temporal cross-referencing to catch multi-step assembly attacks
  - **Sensitivity Classifier** — classifies content as PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED, auto-redacts secrets
  - **Trust Scorer** — source-based trust hierarchy (user=1.0, agent=0.1), filters low-trust memories on recall
  - **Audit Logger** — full forensic trail of every memory operation with querying
- **Retroactive Scanner** — `scan_memories` MCP tool scans existing memories for poisoning
- **4 new MCP tools** — `audit_query`, `quarantine_review`, `defence_stats`, `scan_memories`
- **`npx shieldcortex migrate`** — non-destructive migration from Claude Cortex (copies DB, swaps settings)

### Changed
- **Rebranded** from Claude Cortex → ShieldCortex across all files
- Defence pipeline runs on every `addMemory()` call — quarantines blocked content automatically
- `searchMemories()` now filters by trust score and redacts RESTRICTED content

### Removed
- `uninstall.sh` (replaced by `npx shieldcortex uninstall`)
- `scripts/pre-compact-hook.sh` (superseded by `.mjs` version)

## [1.13.0] - 2026-01-31

### Added
- **Ontological Knowledge Graph** — entities and subject-predicate-object triples automatically extracted from memories
- Pattern-based entity extraction for files, tools, languages, concepts, people, services, and patterns
- Entity resolution with case-insensitive matching, alias lookup, and Levenshtein fuzzy matching
- `graph_query` MCP tool — traverse the knowledge graph from any entity
- `graph_entities` MCP tool — list known entities filtered by type
- `graph_explain` MCP tool — find paths between two entities with source memories
- REST API endpoints for graph data (`/api/graph/entities`, `/api/graph/triples`, `/api/graph/search`, `/api/graph/paths`)
- Dashboard **Ontology** view with force-graph visualization, entity type filtering, and detail sidebar
- `npx shieldcortex graph backfill` command to extract entities from existing memories
- Brain worker graph maintenance — automatic orphan entity pruning every 30 minutes

## [1.12.0] - 2026-01-30

### Added
- **GitHub Actions CI** — Automated build + test on push/PR (Node 20 + 22 matrix)
- **Auto-publish to npm** — GitHub release triggers `npm publish` with pre-built dashboard (`.next/` ships in package, zero install-time cost)

### Security
- **CORS restricted to localhost** — API server now only accepts requests from `localhost:3030`, `localhost:3000`, and `127.0.0.1` equivalents. Configurable via `CORTEX_CORS_ORIGINS` environment variable (comma-separated origins).

## [1.11.0] - 2026-01-30

### Added
- **Dashboard redesign**: Multi-view layout with slim nav rail replacing the left sidebar
- **2D Knowledge Graph**: Interactive force-directed graph as default view (`react-force-graph-2d`) — nodes colored by category, sized by salience, linked by relationships
- **Memories card grid**: Browseable card view with sort (salience/date/decay), grid/list toggle, and bulk select + delete
- **Insights view**: Activity heatmap (GitHub-style), knowledge coverage bar charts, memory quality analysis (never-accessed, stale, duplicates, contradictions)
- **API endpoints**: `GET /api/memories/activity` and `GET /api/memories/quality` for insights data
- **View transitions**: Smooth fade animations between views (Framer Motion)
- 3D Brain visualization preserved as optional "Brain" tab

## [1.10.0] - 2026-01-30

### Added
- **`setup` auto-configures hooks** — `npx shieldcortex setup` now installs PreCompact, SessionStart, and SessionEnd hooks into `~/.claude/settings.json` using portable `npx shieldcortex hook <name>` commands.
- **Stop hook (opt-in)** — `npx shieldcortex setup --with-stop-hook` installs a Stop hook that checks the last assistant message for notable content (decisions, fixes, learnings) and prompts Claude to use `remember`. Loop prevention is programmatic (`stop_hook_active` boolean check), not LLM-dependent.
- `npx shieldcortex hook stop` CLI command for manual invocation.

## [1.9.1] - 2026-01-30

### Added
- **`doctor` command** — `npx shieldcortex doctor` checks installation health: Node version, database, CLAUDE.md setup, hooks, MCP config.
- **`--version` / `-v` flag** — `npx shieldcortex --version` prints the current version.

## [1.9.0] - 2026-01-30

### Added
- **SessionEnd hook** — Auto-extracts important context when a Claude Code session exits. Reads the session transcript and saves high-salience memories (decisions, fixes, learnings) to the database.
- Hook coverage matrix in README documenting when each hook fires and its reliability.
- `npx shieldcortex hook session-end` CLI command for manual invocation.

### Changed
- SessionEnd hook skips extraction on `/clear` (intentional session wipe).
- Auto-extracted memories from SessionEnd are tagged with `session-end` for filtering.

## [1.8.3] - 2026-01-29

### Security
- **CRITICAL: Removed `shell: true` from OpenClaw hook** — `execFile` with `shell: true` allowed command injection via memory content. Now uses safe direct execution.
- **Parameterized SQL in session-start hook** — Replaced string interpolation in `NOT IN` clause with proper `?` placeholders.
- **Word-boundary regex for SQL endpoint** — DROP/TRUNCATE blocking now uses `\bDROP\b` to avoid false positives on column names.

### Fixed
- **Quote escaping in OpenClaw hook** — Single quotes in memory content are now escaped (`''`) instead of stripped, preserving data integrity.

### Added
- **`prepublishOnly` script** — Automatically runs `npm run build` before `npm publish` to prevent stale dist.

## [1.8.2] - 2026-01-29

### Fixed
- Strengthen post-compaction `get_context` directive to ensure context is recalled after compaction.
- Pre-compact hook now reads session JSONL files directly for reliable conversation extraction.

## [1.8.1] - 2026-01-29

### Changed
- **Unified setup command** — `npx shieldcortex setup` now configures both Claude Code (CLAUDE.md) and OpenClaw hook in one step.

## [1.8.0] - 2026-01-29

### Added
- **OpenClaw hook installer** — `npx shieldcortex openclaw install|uninstall|status`
- Bundled `cortex-memory` hook that integrates via mcporter for persistent memory in OpenClaw sessions.
- Auto-saves session context on `/new`, injects past memories on bootstrap, keyword triggers ("remember this").

## [1.7.2] - 2026-01-28

### Added
- OpenClaw integration section in README with mcporter usage examples.

## [1.7.1] - 2026-01-28

### Fixed
- Added `hook` subcommand routing, fixed hook documentation.

## [1.7.0] - 2026-01-28

### Added
- **`setup` command** — `npx shieldcortex setup` injects proactive memory instructions into `~/.claude/CLAUDE.md`.

## [1.6.1] - 2026-01-28

### Fixed
- **ARM64 embedding support** — Migrated from `@xenova/transformers` to `@huggingface/transformers` for native Apple Silicon compatibility.

## [1.6.0] - 2026-01-28

### Added
- **Memory intelligence overhaul** — 7 improvements to connect isolated subsystems:
  - Semantic linking in `detectRelationships` (embeddings + FTS5 content similarity)
  - Search results reinforce salience and create co-search links
  - Dynamic salience evolution via link count, contradictions, and mention count
  - Contradictions surfaced in search results with warnings
  - Memory enrichment wired into search flow
  - Real consolidation merges related STM into coherent LTM entries
  - Increased activation weight in search, cache pruning

## [1.5.2] - 2026-01-28

### Added
- **Cross-platform auto-start service** — `npx shieldcortex service install|uninstall|status`
- Supports macOS (launchd), Linux (systemd), Windows (Startup folder VBS script).
- Logs to `~/.shieldcortex/logs/`.

## [1.5.1] - 2026-01-28

### Improved
- **Dashboard auto-starts API server** - No more manual `npm run dev:api` required when running dashboard directly
- Running `cd dashboard && npm run dev` now automatically detects and starts the API if not running

## [1.5.0] - 2026-01-28

### Added
- **Cross-process event IPC** - MCP tool events (remember, recall, forget) now appear in dashboard Activity log
- Events persisted to SQLite `events` table for cross-process communication
- API server polls for new events every 500ms and broadcasts via WebSocket
- Automatic cleanup of processed events after 24 hours

## [1.4.2] - 2026-01-28

### Fixed
- Removed duplicate Pause/Sync buttons from dashboard header (now only in sidebar)
- Consolidation events now properly emit to Activity log
- Added tooltips to all dashboard buttons for better UX

## [1.4.1] - 2026-01-28

### Fixed
- React duplicate key error in MemoryDetail when memory has bidirectional relationships

## [1.4.0] - 2026-01-28

### Added
- **Version management in dashboard** - Display current version, check for updates, update, and restart server
- New API endpoints: `/api/version`, `/api/version/check`, `/api/version/update`, `/api/version/restart`
- VersionPanel component in dashboard sidebar
- WebSocket events for update progress: `update_started`, `update_complete`, `update_failed`, `server_restarting`
- Dashboard documentation section in README with features list and color legend

### Fixed
- MCP server now reports actual version from package.json instead of hardcoded "1.0.0"

## [1.3.2] - 2026-01-28

### Fixed
- FTS5 query escaping: periods in search terms now properly quoted (fixes "syntax error near ." when remembering content with version numbers like v1.3.1)

## [1.3.1] - 2026-01-28

### Fixed
- README branding: changed "Claude Memory" references to "ShieldCortex"

## [1.3.0] - 2026-01-27

### Added
- Jest test infrastructure with 31 passing tests
- Test coverage for salience, decay, similarity, and memory types
- npm scripts: `test`, `test:watch`, `test:coverage`, `audit:security`
- React error boundary for dashboard crash handling
- `.npmignore` for cleaner npm package

### Fixed
- npm security vulnerability (hono package)
- Type safety in embeddings (replaced `any` with proper interface)
- Three.js memory leaks in BrainMesh (use refs for cleanup)
- WebSocket dependency array causing reconnection loops
- Type-safe material casting in SynapseNodes

## [1.2.1] - 2026-01-27

### Added
- Ko-fi support link in README
- GitHub sponsor button via FUNDING.yml

## [1.2.0] - 2026-01-27

### Added
- Dashboard control panel (pause/resume memory creation, trigger consolidation)
- Debug tools panel with query tester, activity log, relationship graph, SQL console
- Control API endpoints for pause/resume/consolidate
- Chip visualization components (alternative view)
- Category labels for brain regions

## [1.1.1] - 2026-01-27

### Added
- Proactive memory instructions in SessionStart hook
- Reminds Claude to use `remember` immediately for decisions, bug fixes, learnings

### Fixed
- React duplicate key error in brain visualization
- Added defensive deduplication for memory nodes

## [1.1.0] - 2026-01-27

### Changed
- Clean neural network design for dashboard visualization
- Ghost wireframe brain outline (faint gray, no animation)
- Gray neural connections with bright white signal pulses
- Larger solid-colored memory nodes (no transparency/glow)
- Simplified UI overlay (just memory count)

### Removed
- Stars background, colored brain regions
- Synapse endpoint bulbs, connection count badge
- Neural activity indicator, holographic color mode

## [1.0.0] - 2026-01-27

### Added
- Brain-like memory system with short-term, long-term, and episodic memory types
- Salience detection for automatic importance scoring
- Temporal decay with reinforcement on access
- Automatic consolidation (STM → LTM promotion)
- Full-text search via SQLite FTS5
- Semantic search via vector embeddings (@xenova/transformers)
- Cross-project global memories with scope parameter
- Memory relationships and automatic linking
- Spreading activation for related memory priming
- Contradiction detection between memories
- Background worker for continuous brain-like processing
- Dashboard visualization (optional, runs separately)
- Session hooks for auto-recall and pre-compact memory extraction

### MCP Tools
- `remember` - Store memories with auto-categorization
- `recall` - Search and retrieve memories
- `forget` - Delete memories with safety confirmations
- `get_context` - Get relevant project context
- `start_session` / `end_session` - Session management
- `consolidate` - Manual consolidation trigger
- `memory_stats` - View statistics
- `export_memories` / `import_memories` - Backup and restore
- `get_related` / `link_memories` - Memory relationships
- `detect_contradictions` - Find conflicting memories
- `set_project` / `get_project` - Project scope management
