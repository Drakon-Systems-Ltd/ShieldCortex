# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **Local memory replica sync** — local memories can now be backfilled to ShieldCortex Cloud with `shieldcortex cloud sync --full`, using stable external IDs and the shared cloud retry queue

## [3.0.4] - 2026-03-08

### Changed

- Refactored the visualization API server into focused route modules for memories, recall, graph, incidents, admin, and system endpoints
- Extracted memory search/ranking helpers out of the main store to reduce coupling in the memory core
- Unified the OpenClaw hook and plugin around a shared runtime helper for config loading and Cortex command execution
- Pruned dashboard standalone publish output further to reduce npm package size
- Jest runs now use a valid localStorage backing file and suppress only the ESM experimental warning instead of leaking runtime noise

### Fixed

- Full `npm test` output is now clean of the previous localStorage-path and VM Modules warning spam
- Quarantine tests no longer emit expected maintenance logs during normal test runs

## [3.0.1] - 2026-03-08

### Fixed

- **CI Jest wrapper compatibility** — removed the direct `--localstorage-file` Node flag from `scripts/run-jest.mjs`, which failed on GitHub Actions Node 20

## [3.0.0] - 2026-03-08

### Added

- **Trust Console dashboard home** — new default dashboard landing view with urgent actions, memory health, coverage, and free/pro workflow cards
- **Recall explanations API** — `GET /api/recall/explain` returns score breakdowns and ranking reasons without mutating recall state
- **Incident replay API** — `GET /api/v1/incidents/replay` reconstructs a best-effort timeline from defence audit, quarantine, and retained events
- **CLI quickstart** — `shieldcortex quickstart` detects the fastest install/setup path for Claude Code, OpenClaw, Copilot, or security-only usage
- **Targeted regression coverage** for read-only recall explanations and incident replay query behavior

### Changed

- Query embeddings are now cached in-process to reduce repeated recall latency
- Recall fallback reuses existing search results instead of duplicating FTS work
- Test runner now uses a controlled wrapper script for more stable local and CI execution
- Brain worker timers are cleaned up more defensively on shutdown

### Fixed

- Read-only explanation queries no longer reinforce memories, create co-search links, or enrich content as a side effect
- Jest test runs no longer emit the prior localstorage-path warning and avoid the previous lingering timer/process cleanup issue

## [2.20.0] - 2026-03-07

### Added

- **Ego-centric knowledge graph** — Graph tab rebuilt with focus-on-one-entity navigation. Click any neighbour to re-centre. New `/api/graph/entities/:id/neighbourhood` endpoint
- **Memory Timeline** — New Timeline tab showing memories chronologically, grouped by day, with category/type filters and search
- **Memory Health Score** — Circular progress widget on Shield tab (freshness, graph coverage, consistency, consolidation). New `/api/health-score` endpoint
- **Embedding-based recall** — Vector similarity fallback using `all-MiniLM-L6-v2` when FTS5 returns fewer than 3 results. Embedding cache in SQLite
- **NavRail sparklines** — 7-day trend micro-charts on Shield and Memories nav items
- **Keyboard shortcuts** — Press `?` for help. `g+s` Shield, `g+m` Memories, `g+t` Timeline, `/` search, `Escape` close panels
- **Memory inline editing** — Edit title, content, category, tags in-place from the detail panel
- **`shieldcortex doctor`** — 9-point installation health checker (database, schema, hooks, processes, disk, locks, embeddings)
- **Webhooks** — POST notifications on memory events with HMAC-SHA256 signing. Configure in `~/.shieldcortex/config.json`
- **Memory expiry rules** — Auto-delete memories by category/type/tag/age. Protects critical memories. Configure in config.json
- **Content-aware consolidation** — Deduplicates near-identical memories, creates summary memories for topic clusters
- **Corrupt database recovery** — Auto-detects corruption, backs up, attempts recovery, creates fresh DB as last resort
- **Incremental graph extraction** — Tracks extraction version per memory, skips already-processed ones. `--force` to re-extract

### Changed

- Graph triple extraction captures dotted names (`Next.js`, `Node.js`)
- Co-occurrence triples generated for entities in the same memory
- Graph API triples limit raised from 500 to 10,000
- `PATCH /api/memories/:id` now validates input fields

## [2.18.0] - 2026-02-28

### Added

- **License key system** — Ed25519-signed offline licence verification (`shieldcortex license activate/status/deactivate`)
- **Feature gating** — `requireFeature()` / `isFeatureEnabled()` for Pro and Team tier features
- **8 gated features** — custom injection patterns, custom Iron Dome policies, custom firewall rules, audit export, skill scanner deep, cloud sync, team management, shared patterns
- **Online validation** — periodic 24h check against SaaS API for revocation detection

### Changed

- Cloud sync, heartbeat, and pattern/policy sync now respect licence tier (Team+ only)
- Iron Dome cloud policy overrides gated behind Pro licence (built-in profiles remain free)

## [2.17.1] - 2026-02-28

### Added

- **Hook check in `shieldcortex status`** — warns when Claude Code hooks are not configured, with instructions to run `shieldcortex install`
- **Post-uninstall guidance** — `shieldcortex uninstall` now shows how to remove the npm package and clear npx cache

### Changed

- **README rewrite** — security-first positioning, dashboard screenshots, Iron Dome and Universal Memory Bridge sections, comparison table
- **ClawHub skills** — updated both SKILL.md files to v2.17.0 with Iron Dome, Universal Memory Bridge, Python SDK, and auto-memory config

## [2.16.0] - 2026-02-25

### Added

- **Iron Dome Cloud Sync** — Custom injection patterns and central policies defined in the ShieldCortex cloud dashboard are now synced to all connected devices automatically
  - `setExternalPatterns()` — Register cloud-synced regex patterns for injection scanning alongside the 23 built-in patterns
  - `getExternalPatternCount()` — Returns the count of active cloud patterns
  - `getEffectiveIronDomeConfig()` — Returns merged config: cloud policy overrides + base profile + local enabled flag
  - `refreshCloudIronDome()` — Fetches patterns + policy from cloud (10s timeout, disk cache fallback)
  - `applyCachedCloudPatterns()` — Loads cached patterns from disk on startup
  - Cloud patterns and policy are persisted to `~/.shieldcortex/config.json` with HMAC integrity
  - Brain worker refreshes cloud Iron Dome data every 5 minutes (light tick)
  - Invalid cloud regex patterns are silently skipped; valid ones scan alongside built-in patterns
  - `InjectionDetection.category` widened from `InjectionCategory` to `InjectionCategory | string` to support custom categories

## [2.15.2] - 2026-02-23
- **Fix:** Confirmation protocol CLI now works when Iron Dome config predates the feature (graceful fallback to defaults)
- **Fix:** `classifyAction` handles missing `confirmationProtocol` in legacy configs

## [2.15.1] - 2026-02-23
- **User-configurable confirmation tiers** — Users can now move actions between RED/AMBER/GREEN tiers, add custom actions, and remove overrides via CLI or config
- **CLI commands:** `iron-dome confirmation list|move|add|remove` for managing tiers
- **Config merging** — User overrides merge with profile defaults (user wins on conflicts)

## [2.15.0] - 2026-02-23

### Added

- **Iron Dome — Destructive Action Confirmation Protocol** — 3-tier classification system (RED/AMBER/GREEN) that gates destructive actions before they execute. RED actions (rm, delete, drop, force_push, etc.) always require explicit user confirmation. AMBER actions are announced before proceeding. GREEN actions execute silently. Unknown actions default to AMBER as a safe fallback. Matching is case-insensitive with partial (contains) matching so `rm -rf /tmp` correctly matches the `rm` rule.

  - `classifyAction(action, config)` — Returns tier, description, and reversibility for any action
  - `requiresConfirmation(action, config)` — Quick check: is this a RED-tier action?
  - `requiresAnnouncement(action, config)` — Quick check: is this RED or AMBER?
  - RED classifications are audit-logged via `logIronDomeAudit`
  - Each profile (school/enterprise/personal/paranoid) has its own tier lists with profile-specific additions (e.g. school adds `export_pupil_data`, enterprise adds `transfer_funds`, paranoid promotes most actions to RED)

- **New config field:** `confirmationProtocol: { red: string[], amber: string[], green: string[] }` on `IronDomeConfig`

- **New types:** `ConfirmationTier`, `ConfirmationResult`, `IronDomeConfirmationProtocol`

## [2.14.0] - 2026-02-22

### Added

- **Iron Dome — Behaviour Protection Layer** — New defence module that protects agent *actions* from compromise, complementing the existing 6-layer memory defence pipeline. While the pipeline guards what goes INTO memory, Iron Dome guards what comes OUT as behaviour.

  - **Prompt injection scanner** — 40+ detection patterns across 8 categories (fake system messages, authority claims, urgency/secrecy, credential extraction, instruction injection, encoding tricks, role manipulation, context escape). Returns severity (low/medium/high/critical) and risk level.
  - **Instruction gateway** — Validates that instructions come from trusted channels (terminal, CLI, Slack, etc.) before allowing execution.
  - **Action gate** — Controls what actions agents can take: auto-approve (read, search), requires-approval (send email, delete file, purchase), or blocked (sub-agent restricted operations).
  - **PII guard** — Prevents output of protected personal data categories. Two rule types: `neverOutput` (completely blocked) and `aggregatesOnly` (only totals/averages permitted).
  - **Kill switch** — Emergency stop on configurable trigger phrase (default: "full stop").
  - **Sub-agent restrictions** — Blocks dangerous operations from spawned sub-agents and optionally sanitises context passed to them.

- **4 pre-built profiles:**
  - `school` — GDPR strict: pupil names, DOB, medical info, SEN status locked; attendance and grades aggregates-only
  - `enterprise` — Financial protection: credit cards, bank accounts, salary locked; revenue and expenses aggregates-only
  - `personal` — Lighter touch: passwords and financial data locked, more actions auto-approved
  - `paranoid` — Terminal-only trust, nearly everything requires approval

- **Iron Dome CLI:**
  - `shieldcortex iron-dome activate [--profile school|enterprise|personal|paranoid]`
  - `shieldcortex iron-dome status`
  - `shieldcortex iron-dome deactivate`
  - `shieldcortex iron-dome scan --text "..." | --file <path>`
  - `shieldcortex iron-dome audit [--tail] [--search <term>]`

- **4 new MCP tools:** `iron_dome_status`, `iron_dome_scan`, `iron_dome_check`, `iron_dome_activate`

- **New library exports:** `activateIronDome`, `deactivateIronDome`, `getIronDomeStatus`, `scanForInjection`, `isChannelTrusted`, `isActionAllowed`, `checkPII`, `handleKillPhrase`, `IRON_DOME_PROFILES`, `DEFAULT_IRON_DOME_CONFIG` plus 8 type exports

## [2.13.3] - 2026-02-22

### Fixed

- **Quarantine cloud sync reliability** — `syncQuarantineToCloud` now logs failures and enqueues failed uploads for retry instead of silently dropping errors.
- **Retry queue endpoint coverage** — `sync_queue` retries now support both `/v1/audit/ingest` and `/v1/quarantine/ingest` payloads (with backward compatibility for legacy queued audit payloads).
- **Embedding worker path resolution** — source-mode/dev/test runs now resolve the embedding worker more safely, reducing repeated worker startup failures when only `dist` worker artifacts exist.
- **Async memory lifecycle noise** — async embedding persistence and cleanup paths now degrade more cleanly around DB teardown/uninitialized states.

## [2.13.2] - 2026-02-21

### Fixed

- **Quarantine cloud sync gap** — `syncQuarantineToCloud` now fires for all QUARANTINE paths: pipeline-native results (pipeline.ts step 9) and post-pipeline sub-agent trust overrides (store.ts). Previously only memory writes synced quarantine content to cloud.

## [2.13.0] - 2026-02-21

### Added

- **LLM Verification (Tier 2)** — Optional cloud-based LLM verification layer for content flagged by the regex firewall. Adds `runDefencePipelineWithVerify()` async wrapper that submits QUARANTINE'd content to `/v1/verify` for deeper analysis. Two modes:
  - **Advisory** (default): fire-and-forget, non-blocking
  - **Enforce**: awaits LLM verdict, upgrades QUARANTINE → BLOCK on high-confidence threats
- **Verify CLI** — `npx shieldcortex config --verify-enable|--verify-disable|--verify-mode|--verify-timeout` for managing LLM verification settings
- New exports: `submitVerification`, `pollVerification`, `getVerifyConfig`, `setVerifyConfig`
- New types: `VerifyResult`, `VerifyThreat`, `DefencePipelineResultWithVerify`, `VerifyConfig`

### Fixed

- **Fragmentation false BLOCK in SaaS context** — `getRecentEntities()` and `storeExtractedEntities()` now gracefully handle missing SQLite database (try/catch with empty fallback), preventing fail-closed BLOCK decisions when the npm package is used as a library without `initDatabase()`
- **Visualization server bound to 0.0.0.0** — Dashboard server now defaults to `127.0.0.1` (localhost only). Override with `SHIELDCORTEX_HOST` env var if LAN access is needed

## [2.12.6] - 2026-02-18

### Fixed

- **Plugin database init** — OpenClaw real-time plugin now calls `initDatabase()` before loading the defence pipeline, so audit logging works correctly outside the MCP server context
- **OpenClaw install diagnostics** — `isOpenClawInstalled()` check prevents spuriously creating `~/.openclaw/` on non-OpenClaw systems; better error output when install fails

## [2.12.5] - 2026-02-18

### Fixed

- **OpenClaw hook crash on bootstrap injection** — `bootstrapFiles.push()` was missing the `path` property required by OpenClaw's `buildInjectedWorkspaceFiles`. All three injection sites (CORTEX_MEMORY.md, SHIELDCORTEX_WARNINGS.md, SHIELDCORTEX_HOOK_MIGRATED.md) now include `path` derived from the workspace directory, fixing `TypeError: Cannot read properties of undefined (reading 'replace')` on every gateway-routed agent run.

## [2.12.2] - 2026-02-16

### Added

- **Version debug diagnostics** — `shieldcortex --version --debug` now shows the resolved entry point, package.json path, and argv[1] to help diagnose stale version issues. `shieldcortex doctor` also reports version resolution paths.

## [2.12.1] - 2026-02-16

### Fixed

- **Suppress "Database not initialized" error spam** — When ShieldCortex is used as a library (e.g. OpenClaw extension), `logAudit()` now silently skips if the database hasn't been initialized, instead of `console.error()`ing on every pipeline call. Defence scanning still works; only the SQLite audit trail is skipped.

## [2.12.0] - 2026-02-16

### Fixed

- **OpenClaw plugin now properly discoverable** — The installer copies the real-time scanning plugin to `~/.openclaw/extensions/shieldcortex-realtime/` where OpenClaw discovers it via its global extensions directory. Previously registered via `plugins.entries` in `openclaw.json` which caused config validation errors.

### Changed

- `openclaw install` installs both the cortex-memory hook and the real-time plugin
- `openclaw uninstall` removes both the hook and the plugin from the extensions directory
- `openclaw status` reports plugin installation status and path

## [2.11.1] - 2026-02-16

### Added

- **Auto-register real-time plugin** — `openclaw install` now automatically registers the real-time scanning plugin in `~/.openclaw/openclaw.json`. No manual config editing needed.
  - `openclaw uninstall` removes the plugin entry
  - `openclaw status` reports plugin registration status and validates the source path
  - Safely creates `openclaw.json` if it doesn't exist, preserves existing config

## [2.11.0] - 2026-02-16

### Added

- **Real-time scanning plugin for OpenClaw** — New `plugins/openclaw/` module hooks into OpenClaw v2026.2.15+ `llm_input` and `llm_output` events for continuous protection:
  - **`llm_input` defence scanning** — Every prompt and user message is scanned through the 6-layer defence pipeline before the model processes it. Threats are logged to `~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl` and optionally synced to ShieldCortex Cloud.
  - **`llm_output` memory extraction** — Assistant responses are pattern-matched in real-time for architecture decisions, error fixes, learnings, and preferences. Up to 3 high-salience memories auto-saved per turn — no more waiting for compaction.
  - **Smart filtering** — Internal OpenClaw content (boot checks, heartbeats, system events) is automatically skipped to eliminate false positives.
  - **Cloud sync** — When `cloudApiKey` is configured, threat detections are POSTed to `api.shieldcortex.ai` for team dashboards.
  - **Fire-and-forget** — All scanning is non-blocking. Zero latency impact on LLM calls.

### Changed

- **Plugin included in npm package** — `plugins/` directory now ships with `npm install`, including compiled JS ready to load.

## [2.10.10] - 2026-02-13

### Fixed

- **Keepalive corrupts JSON-RPC stream** — The `$/ping` keepalive wrote directly to `process.stdout`, racing with the MCP SDK's `StdioServerTransport`. When both wrote simultaneously, the interleaved output corrupted the JSON-RPC stream, causing tool calls to hang indefinitely. Now routed through `server.server.notification()` so all writes are serialised by the SDK transport. ([#6](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/6))

## [2.10.8] - 2026-02-15

### Fixed

- **Embedding model hang on first `remember` call** — The ONNX model load (`Xenova/all-MiniLM-L6-v2`) could block the event loop indefinitely on first invocation, causing Claude Code to consider the MCP connection dead. Added a 30-second timeout on model loading and a 10-second timeout on individual inference calls. Loading state is properly reset on timeout so retries work cleanly (no stale rejected promises). ([#5](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/5))

### Added

- **Model preload on server start** — `preloadModel()` is now called immediately after `server.connect()`, fire-and-forget. The model warms up in the background during session setup, so by the first tool call it's usually ready. Respects `SHIELDCORTEX_SKIP_EMBEDDINGS=1`.

## [2.10.7] - 2026-02-15

### Added

- **OpenClaw hook self-check and self-heal** — The cortex-memory hook now detects on first bootstrap if it's running from an unexpected or legacy path. It auto-copies itself to the correct `~/.openclaw/hooks/internal/cortex-memory/` location and cleans up stale `.clawdbot` directories. One-shot per process (no loops or memory leaks), fails silently on any error. Injects an informational notice into bootstrap context when a migration occurs.

## [2.10.6] - 2026-02-15

### Added

- **`doctor` checks OpenClaw hook paths** — `npx shieldcortex doctor` now verifies the cortex-memory hook is installed in the correct `~/.openclaw/hooks/` directory (including `internal/` subdirectory). Detects legacy `.clawdbot/hooks/` installs and recommends `npx shieldcortex migrate`.
- **`migrate` handles OpenClaw hook paths** — New step 4/6 copies hooks from `~/.clawdbot/hooks/` to `~/.openclaw/hooks/` and cleans up legacy directories. Handles `.clawdbot` → `.openclaw` symlinks gracefully (skips migration when symlinked).

## [2.10.5] - 2026-02-13

### Changed

- Maintenance release.

## [2.10.4] - 2026-02-13

### Added

- **MCP tool annotations** — All 24 MCP tools now include `title`, `readOnlyHint`, `destructiveHint`, and `idempotentHint` annotations per the MCP specification. Required for Anthropic Connectors Directory listing. 15 tools marked read-only, 8 write, 1 destructive (`forget`).

## [2.10.3] - 2026-02-13

### Added

- **Stale npx cache warning** — CLI now detects when `npx` is running a cached older version and prints a warning suggesting the globally installed binary instead.

### Changed

- **Docs use `shieldcortex` instead of `npx shieldcortex`** — README, SKILL.md, and CLI help updated to use the globally installed binary directly, avoiding npx cache staleness issues.

## [2.10.2] - 2026-02-13

### Added

- **Cloud heartbeat** — BrainWorker now sends a heartbeat to ShieldCortex Cloud every 5 minutes, keeping devices marked "Online" in the dashboard even when idle (no scans triggering cloud sync).

## [2.10.1] - 2026-02-13

### Fixed

- **CLI guard fails with npm global bin symlink** — When installed globally (`npm install -g shieldcortex`) and invoked as a bare command (e.g. `"command": "shieldcortex"` in MCP config), the `isCLI` guard failed because `process.argv[1]` was the symlink path, not the resolved target. Added `fs.realpathSync()` to resolve symlinks and `path.basename()` fallback. Fixes [#2](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/2).

## [2.10.0] - 2026-02-13

### Fixed

- **CRITICAL: `import('shieldcortex')` no longer crashes** — Previously, importing the package as a library triggered the MCP server, consumed stdin, spawned background workers, and eventually got SIGKILL'd by the OS. The `main()` CLI entrypoint now only runs when the file is executed directly (via `npx shieldcortex` or `node dist/index.js`), not when imported.

- **Library exports now work** — `import { runDefencePipeline, addMemory, scanSkill } from 'shieldcortex'` now returns 70 named exports covering defence, memory, knowledge graph, skill scanning, and audit. Previously returned empty object `{}`.

### Added

- **New `src/lib.ts` library entry point** — Clean, side-effect-free module exporting all public APIs. Available via `import ... from 'shieldcortex'` (default) or `import ... from 'shieldcortex/lib'` (explicit).

- **Exported APIs include:**
  - Defence: `runDefencePipeline`, `analyzeFirewall`, `scanForCredentials`, `classifySensitivity`, `redactContent`
  - Memory: `addMemory`, `getMemoryById`, `updateMemory`, `deleteMemory`, `accessMemory`
  - Memory Intelligence: `calculateDecayedScore`, `processDecay`, `calculateSalience`, `consolidate`, `detectContradictions`, `activateMemory`
  - Knowledge Graph: `extractFromMemory`, `processExtractionResult`, `backfillGraph`
  - Skill Scanner: `scanSkill`, `scanSkillContent`, `discoverSkillFiles`
  - Audit: `scanMemories`, `scanMcpConfigs`, `scanEnvFiles`, `scanRulesFiles`
  - Version: `version`

## [2.9.0] - 2026-02-12

### Added

- **`npx shieldcortex audit` — comprehensive security scanner** — New command scans an AI agent's entire environment and produces a colour-coded security report with A-F grading. Four scanners run in sequence:
  - **Memory Scanner** — Scans `~/.claude/`, Cursor, and Windsurf memory files for planted instructions, poisoned memories, and credential leaks using the full defence pipeline.
  - **MCP Config Scanner** — Checks MCP server configs across 9 locations for known-vulnerable servers (e.g. `mcp-remote` CVE-2025-6514), dangerous flags (`--dangerously-skip-permissions`, `--yolo`), and suspicious URLs.
  - **Environment Scanner** — Discovers `.env` files reachable by AI agents, runs credential leak detection, and flags files not protected by `.gitignore`.
  - **Rules File Scanner** — Detects Unicode-hidden backdoors (the "Rules File Backdoor" attack pattern, CVE-2025-54135/54136) and prompt injection in `.cursorrules`, `.windsurfrules`, `.clinerules`, `CLAUDE.md`, and GitHub Copilot instructions.

- **Three output modes** — `--json` for programmatic consumption, `--markdown` for GitHub PR comments and CI summaries, and default terminal mode with ASCII art shield header and ANSI colour-coded findings.

- **CI mode** — `npx shieldcortex audit --ci` exits with code 1 if critical or high findings exist, suitable for CI/CD pipelines.

- **GitHub Action** — `action.yml` composite action enables `shieldcortex/scan@v1` in GitHub workflows. Scans PRs for agent config security issues and posts results to the GitHub Step Summary.

## [2.8.4] - 2026-02-12

### Fixed

- **OpenClaw hook installs to wrong directory** — On servers with both `~/.claude/` and `~/.openclaw/`, the installer preferred `~/.claude/hooks/` but OpenClaw reads from `~/.openclaw/hooks/`. Now installs to ALL detected hook directories and prefers `~/.openclaw/` for the `openclaw` subcommand.

## [2.8.3] - 2026-02-12

### Fixed

- **Dashboard auth breaks on page refresh** — The session token handshake endpoint was one-time-only, so refreshing the dashboard page lost the cached token and all mutations (mode changes, quarantine actions, etc.) silently failed with 401. Token endpoint now serves the same per-session token on every request.

## [2.8.2] - 2026-02-11

### Fixed

- **OpenClaw hook self-scanning** — The cortex-memory hook scanner now skips itself and the `internal` hooks directory to avoid false-positive "potentially unsafe" warnings in logs.

## [2.8.1] - 2026-02-11

### Fixed

- **MCP process leak** — ShieldCortex processes no longer linger after mcporter disconnects. Added stdin EOF detection and a 60-second idle timeout as safety net. Each orphaned process used 200-275MB RAM; on constrained servers this caused OOM.

## [2.8.0] - 2026-02-10

### Added

- **Per-session API auth** — The local API server now generates a per-session token on startup and requires it for all mutating requests (POST/DELETE/PATCH). The dashboard claims the token via a one-time handshake endpoint that locks after the first request, preventing rogue processes from hijacking the API.
- **Config file integrity (HMAC)** — `config.json` is signed with HMAC-SHA256 on every write and verified on every read. If tampering is detected, ShieldCortex falls back to strict mode (fail-closed) and shows a red warning banner in the dashboard.
- **Config tamper warning** — The Defence Pipeline card in the dashboard displays an alert when config integrity verification fails.

### Security

- **Scan endpoint lockdown** — `POST /api/v1/scan` and `/api/v1/scan/batch` no longer accept a `config` body parameter. Attempts to override the defence config via the HTTP API are ignored and logged as `config_override_attempt` in the audit trail.
- **Unauthenticated API closed** — All mutating endpoints now return 401 without a valid session token. GET endpoints remain open (read-only).
- **Dashboard auth-aware fetch** — All dashboard mutation hooks use `authFetch()` to transparently include the session token.

## [2.7.1] - 2026-02-10

### Added

- **Persistent firewall mode** — Users can now set the defence mode (strict/balanced/permissive) via CLI (`npx shieldcortex config --mode strict`), and the setting persists in `~/.shieldcortex/config.json`. The pipeline reads the persisted mode as default instead of always using `balanced`.
- **Dashboard mode selector** — Interactive dropdown in the Defence Pipeline card to switch firewall mode from the local dashboard. Colour-coded: strict (red), balanced (cyan), permissive (green).
- **Defence config API** — `GET/POST /api/defence/config` endpoints for reading and setting the firewall mode programmatically.
- **`--cloud-status` now shows defence mode** — The config status output includes the current firewall mode.

## [2.7.0] - 2026-02-10

### Added

- **Credential Leak Detection (Layer 6)** — New defence layer that detects API keys, tokens, private keys, connection strings, and environment secrets accidentally persisted in AI agent memory. Supports 25+ credential patterns across 11 providers (OpenAI, Anthropic, AWS, GitHub, Stripe, Google, Twilio, SendGrid, Slack, Mailgun, npm). Shannon entropy analysis catches high-entropy secrets that don't match known patterns.
- **`scanForCredentials(content)`** — Standalone function for credential scanning outside the pipeline.
- **`redactCredentials(content)`** — Replaces detected credentials with `[REDACTED-{type}-{provider}]` placeholders.
- **CLI `scan` output** — Now shows credential findings with provider, type, severity, and confidence.

### Changed

- Defence pipeline upgraded from 5 to 6 layers — credential scan runs after fragmentation analysis, before the final decision.
- `DefencePipelineResult` now includes optional `credentialScan` field when credentials are detected.
- Critical and high severity credentials trigger `BLOCK`; medium triggers warnings; low is logged.

## [2.6.4] - 2026-02-10

### Fixed

- **OpenClaw hook installer path bug** — `shieldcortex openclaw install` was creating hooks at `~/.claude/hooks/internal/cortex-memory/` instead of `~/.claude/hooks/cortex-memory/`. Removed erroneous `internal/` path segment for both Claude Code and legacy OpenClaw paths.
- **Hook handler file extension** — Fixed handler file reference from `handler.js` to `handler.ts` to match the actual source file.

## [2.6.3] - 2026-02-10

### Added

- **`shieldcortex copilot install`** — New command to configure the ShieldCortex MCP server for VS Code (GitHub Copilot) and Cursor. Supports install, uninstall, and status subcommands. Detects VS Code, VS Code Insiders, and Cursor automatically.

### Fixed

- **OpenClaw hook installer detection bug** — `shieldcortex openclaw install` failed with "OpenClaw is not installed" on machines with Claude Code but without the legacy OpenClaw binary. Now detects Claude Code via `~/.claude/` directory and the `claude` binary.

## [2.6.2] - 2026-02-09

### Fixed

- **Brain activity feed always empty** — The activity feed at the bottom of the Brain tab never showed events because WebSocket events weren't wired into the UI store. Events (creates, updates, deletes, consolidation, decay) now stream into the feed in real-time.

## [2.6.1] - 2026-02-09

### Fixed

- **Dashboard startup crash on Node 22** — Removed fragile `require.resolve('shieldcortex/package.json')` self-reference that threw `ERR_PACKAGE_PATH_NOT_EXPORTED` on some Node 22 installs. Dashboard path is now resolved entirely via `__dirname`.

## [2.6.0] - 2026-02-09

### Added

- **Cloud sync retry queue** — Failed cloud sync requests are now queued in local SQLite and retried with exponential backoff (30s, 60s, 120s). After 3 failures, entries are marked as permanently failed. The BrainWorker processes up to 10 queued items every 5 minutes and purges entries older than 7 days.
- **Cloud sync status indicator** — The local dashboard now shows a sync status dot in the Defence Overview: green (OK), amber (pending retries), red (failed items), or grey (disabled). Polls every 10 seconds.
- **`lastSyncAt` tracking** — Successful cloud syncs now write a timestamp to `~/.shieldcortex/config.json`, displayed in the dashboard as "last sync N ago".

### Fixed

- **Graceful EADDRINUSE handling** — The API server now prints a clear error message with fix instructions when port 3001 is already in use, instead of crashing with an unhandled error.

## [2.5.3] - 2026-02-08

### Added

- **Content-based format auto-detection** — When scanning skill content without a file path (cloud dashboard, API), the parser now infers the format from content patterns (frontmatter, JSON, JS exports, YAML keys). Improves scan accuracy for pasted content.

### Fixed

- **Skill scanner "unknown" format on cloud** — Pasted content with YAML frontmatter is now correctly identified as skill-md/hook-md instead of falling through as "unknown".

## [2.5.2] - 2026-02-08

### Fixed

- **OpenClaw hook timeout on ARM64/slow systems** — The cortex-memory hook now detects globally-installed shieldcortex and uses the direct binary path instead of `npx -y shieldcortex`, which took 10+ seconds for package resolution. Resolution order: `binaryPath` in `~/.shieldcortex/config.json` > global install via `which` > fallback to `npx`. Users must re-run `sudo npx shieldcortex openclaw install` to update the hook.

## [2.5.1] - 2026-02-08

### Added

- **`npx shieldcortex scan "text"` CLI command** — Lightweight content scanner that runs the full defence pipeline (firewall + trust + sensitivity) without starting the MCP server or loading ONNX models. Works immediately on ARM64 Linux.
- **`SHIELDCORTEX_SKIP_EMBEDDINGS=1` env var** — Disables ONNX model loading for environments where it hangs (ARM64 Linux). MCP server still works, just without semantic search.
- **Platform reporting** — Cloud sync now sends `platform` field (e.g. `linux/arm64`, `darwin/arm64`) with every audit entry, populating the Devices page.

### Fixed

- **HuggingFace cache permission error on global install** — Model cache now uses `~/.cache/shieldcortex/models/` instead of the library default (which falls inside root-owned `node_modules/` on global installs).

## [2.5.0] - 2026-02-07

### Added

- **Device identity** — Each machine now generates a stable UUID on first run, stored in `~/.shieldcortex/config.json`. Sent with every cloud sync payload for per-device tracking.
- **Quarantine cloud sync** — When the local firewall quarantines content, it now syncs the full content to ShieldCortex Cloud so the Quarantine Review page populates. Fire-and-forget, same as audit sync.
- **Device name** — OS hostname is captured and sent alongside the device UUID for human-friendly identification.

### Changed

- **Cloud sync payload** — Now includes `device_id` (UUID) and `device_name` (hostname) fields in every audit ingest request.

## [2.4.26] - 2026-02-07

### Added

- **Skill Scanner: Trust & Remove actions** — Scan results now show trust/untrust buttons (shield icon) and a cloud-gated remove button (trash icon) for dangerous skill files.
- **Trusted skills** — Mark known-safe skills as trusted so they show a "TRUSTED" badge instead of threat warnings on future scans. Stored locally in `~/.shieldcortex/config.json`.
- **Cloud-gated skill removal** — One-click delete of dangerous skill files from disk, gated behind cloud connection as a premium upsell. Path validation prevents arbitrary file deletion (only known skill directories allowed).
- **Skill name display** — Scanner results now show the parsed skill name (e.g. "brainstorming", "test-driven-development") as the primary label instead of just "SKILL.md", with the shortened file path as a subtitle.
- **Cloud upsell banner** — Non-cloud users clicking remove see a dismissible banner prompting them to connect to ShieldCortex Cloud.
- **Contradictions click-through** — Clicking the "Contradictions" count in the Brain tab top stats bar now opens the right sidebar inspector with the first contradicting memory.
- **3 new local API endpoints** — `POST /api/skills/trust`, `DELETE /api/skills/trust`, `DELETE /api/skills/file` for managing trusted skills and removing dangerous files.

### Fixed

- **Brain tab right sidebar not reopening** — Closing the MemoryInspector sidebar now correctly toggles both the selected memory and the sidebar visibility state. Previously, closing the sidebar cleared the memory but didn't toggle the sidebar flag, making it impossible to reopen.

## [2.4.25] - 2026-02-07

### Fixed

- **Skill file discovery** — `discoverSkillFiles()` now recursively scans `~/.claude/plugins/cache/` up to 6 levels deep. Previously only scanned one level, missing all Claude Code marketplace skills which are nested 6 levels deep.

## [2.4.24] - 2026-02-07

### Added

- **Skill Scanner** — Framework-agnostic scanner for AI agent instruction files. Detects prompt injection, data exfiltration, tool abuse, and stealth instructions in SKILL.md, CLAUDE.md, .cursorrules, .windsurfrules, .clinerules, copilot-instructions.md, .aider.conf.yml, and .continue/config.json.
- **Skill Scanner CLI** — `npx shieldcortex scan-skill <file>` and `npx shieldcortex scan-skills` commands for scanning individual files or discovering all instruction files.
- **Skill Scanner Dashboard** — New "Skills" tab in the local dashboard with Scan All button, expandable file results, severity badges, and paste-to-scan area.
- **SkillScannerCard** — Summary card on Shield overview showing scan results at a glance.
- **`POST /api/skills/scan-all` endpoint** — Local API endpoint for batch discovery and scanning of all installed skill files.
- **`discoverSkillFiles()` function** — Reusable file discovery extracted from CLI for use by both CLI and API.
- **Session start hook** — Quick check for suspicious instruction files (.cursorrules, .windsurfrules, etc.) on every session start.

## [2.4.21] - 2026-02-07

### Changed

- **README** — Added Cloud dashboard section, cloud sync documentation, updated pricing tiers (Free/Pro/Team/Enterprise), added cloud CLI commands, updated comparison table.

### Fixed

- **Dashboard TypeScript build** — Fixed Lucide `Cloud` icon `title` prop not accepted by TypeScript types. Wrapped icon in a `<div>` with the title attribute.
- **Dashboard ESLint** — Fixed unescaped apostrophe in CloudUpsellCard (`We'll` → `We&apos;ll`) triggering `react/no-unescaped-entities` rule.

## [2.4.20] - 2026-02-07

### Added

- **Cloud sync UI** — CloudUpsellCard on Shield overview prompts local users to connect to ShieldCortex Cloud. Enter email, verify via magic link, and auto-configure cloud sync without leaving the dashboard.
- **Cloud status indicator** — Cloud icon in the dashboard header shows connection state (green when syncing, grey when disconnected).
- **Cloud config API** — `GET /api/cloud/config` and `POST /api/cloud/config` endpoints on the local API server for reading and updating cloud sync settings.
- **useCloudStatus hook** — React Query hook for polling cloud configuration state with 30-second refresh.

## [2.4.19] - 2026-02-05

### Security

- **Owner spoofing prevention** — Null-source memories no longer default to `user:direct`. Uses non-spoofable `__system:unattributed` sentinel so agents cannot claim ownership of unattributed memories.

### Fixed

- **JSON.parse crash in rowToMemory** — Corrupted JSON in `tags` or `metadata` columns no longer crashes all search/get operations. Uses safe parse with fallback.
- **INSERT + defence UPDATE now atomic** — Memory creation and trust score assignment wrapped in a single transaction. Prevents untrusted memories from getting default trust_score=1.0 on crash.
- **WebSocket error handler closes connection** — Error handler now explicitly closes the socket to prevent stale connections accumulating.
- **Broadcast removes failed clients** — Failed WebSocket send now removes client from tracking set and closes connection, preventing error spam.
- **Fragmentation store errors now logged** — Empty catch block replaced with warning log so broken fragmentation storage is visible.
- **MCP signal handlers registered before connect** — Graceful shutdown handlers set up before `server.connect()` so cleanup runs even if connection fails.

## [2.4.18] - 2026-02-05

### Fixed

- **Dashboard crash on startup (ERR_PACKAGE_PATH_NOT_EXPORTED)** — Added `./package.json` to package exports map. Wrapped `require.resolve` call in try-catch so dashboard path resolution can't crash during array construction.

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
