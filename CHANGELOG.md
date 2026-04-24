# Changelog

All notable changes to this project will be documented in this file.

## v4.12.0 — 24 April 2026

**ShieldCortex ↔ OpenClaw compatibility pass (Phase 1 + 2).** Three themes:

1. **Deep uninstall closes the "partial cleanup" gap.** `shieldcortex uninstall --deep` scans 15 known residue locations across `~/.openclaw/openclaw.json`, `~/.openclaw/workspace/.clawhub/lock.json`, and stale hook/extension directories, then surgically removes any ShieldCortex references while preserving sibling keys. Best-effort restarts the OpenClaw gateway so the purge takes effect. Driven by the 2026-04-23/24 fleet incident where five hosts needed hand-scripted `jq` surgery to purge orphan entries left by prior version bumps and manual cleanups.

2. **Doctor gains an OpenClaw residue check.** `shieldcortex doctor` now reports dirty-location count and points at `uninstall --deep` as the fix. Skipped cleanly on non-OpenClaw hosts.

3. **Plugin declares `openclaw` as an optional peer dependency.** Unlocks OpenClaw 2026.4.23's [#70462](https://github.com/openclaw/openclaw/pull/70462) host-package linking for plugins that declare the peer, so future `openclaw/plugin-sdk/*` imports resolve without duplicating the runtime bundle. Manifest also carries an `engines` block hinting at `>=2026.4.23` as recommended.

### What's new

- **`shieldcortex uninstall --deep [--no-gateway-restart]`** — `src/setup/deep-clean.ts`. Declarative scan spec per residue location (`delete-config-key` / `filter-config-array` / `delete-directory`), so adding a new residue path is a single-item append. Exposes `scanForResidue()`, `cleanResidue()`, and `runDeepClean()` for programmatic use.
- **`shieldcortex doctor`** — new `OpenClaw residue` check in `src/cli/doctor.ts`.
- **Plugin manifest** — `plugins/openclaw/package.json` + `plugins/openclaw/openclaw.plugin.json` add `openclaw >=2026.3.22` (optional peer) and `engines.openclaw >=2026.4.23` recommended.
- **Plugin README** — new Compatibility matrix + Known limitations section documenting the 2026.4.23 gaps (plugins can't call `sessions_spawn` directly, no public `systemPromptAddition` seam).
- **Hook docs corrected** — `hooks/openclaw/cortex-memory/HOOK.md` no longer claims bootstrap context injection happens. Injection was actually disabled in v2026.2.26 (native OpenClaw Memory Search handles recall); docs were stale for ~2 months.

### Tests

- 8 new tests in `src/__tests__/deep-clean.test.ts` (baseline / full detection / surgical removal / idempotency / dryRun / orphan entries / malformed JSON / structured return)
- 7 new tests in `src/__tests__/plugin-manifest.test.ts` lock in peer-dep shape, engines block, activation hooks, and plugin-version/root-version invariants
- 4 new tests in `src/__tests__/hook-hash-stability.test.ts` assert the CLAUDE.md INSTRUCTIONS template contains no runtime-dependent interpolations (no `Date.now`, `randomUUID`, `Math.random`, etc.), and that HOOK.md matches the actual handler behaviour

### Why it matters

The existing `uninstallPlugin()` only cleaned config entries when the extension directory still existed on disk. In the field we kept seeing orphan config entries produce "plugin references without files" warnings and load-time errors after every partial update. Deep-clean scans independently of disk state.

The hash-stability tests guard a silent failure mode: if anyone introduces dynamic content into the CLAUDE.md block (timestamps, UUIDs, env reads), every SC install flips `extraSystemPromptHash` and every claude-cli session resets mid-flight with `reason=system-prompt`. Same shape as the v4.11.1 `npx -y` MCP hash thrash, different source.

## v4.11.1 — 22 April 2026

**Fleet-critical fix: MCP registration no longer uses `npx -y` as the command** — it now resolves and pins the installed `shieldcortex` binary path (falls back to `npx -y` only when no global install exists). This closes a silent session-wipe loop that was hitting every production OpenClaw install.

### The bug

Claude Code and OpenClaw both hash the effective MCP server configuration to decide whether the active CLI session needs resetting. The ShieldCortex installer was writing `{command: "npx", args: ["-y", "shieldcortex"]}` — but `npx -y` resolves dynamically on every invocation (global cache vs on-demand, version-drift between resolutions, fresh npm publish), and every shift in what it resolves to flipped the MCP config hash. A flipped hash triggers `cli session reset reason=mcp`, which starts a fresh CLI session and throws away all prior conversation context.

Observed on TARS (Oracle ARM, systemd-managed `openclaw-gateway`) on 2026-04-22: `cli session reset reason=mcp` fired 14 times in one day, roughly every 30 minutes. Symptom surfaced as "Fresh session here — no prior context loaded" mid-conversation in Telegram DMs, plus confabulated responses ("Yeah, I restarted the worker" — nothing had been restarted) when the model tried to fill the context gap. Completely silent from the user's perspective until you compared timestamps.

### Fix

- **`src/setup/claude-md.ts::setupGlobalMcp`** now calls a new `resolveMcpCommand()` helper that shells out to `which shieldcortex` (or `where` on Windows) to find the installed binary, and writes that absolute path into `~/.claude.json`. If no binary resolves, falls back to the previous `npx -y` behaviour (which still works for `npx shieldcortex setup` one-shot users who have nothing installed globally).
- **Existing `npx -y` registrations are auto-upgraded** — the installer was previously short-circuiting with "already configured" when it saw any shieldcortex entry. Now it detects the stale form and rewrites it to the stable binary path, logging the reason. Re-running `shieldcortex setup` (or `shieldcortex quickstart`) on any v4.11.0-or-earlier install migrates the config.
- **Three regression tests** in `src/__tests__/mcp-registration.test.ts` lock in: binary path preferred over `npx`; TARS-scenario stale `npx -y` registration is auto-upgraded; idempotent when already on the stable form.

### Also

- **Plugin `@drakon-systems/shieldcortex-realtime@4.11.0` was never on npm** — the CI `Publish to npm` workflow only published the main `shieldcortex` package and the ClawHub skill; the plugin had been manually published historically, which silently drifted every release. Fixed in `.github/workflows/publish.yml` with a new `Publish plugin to npm` step that verifies plugin version matches main and then publishes `plugins/openclaw/` on tag push. Manually published `@drakon-systems/shieldcortex-realtime@4.11.0` to unblock; v4.11.1 onward is CI-published.

### Manual migration for existing installs

If you're already on v4.11.0 and hitting the session-reset loop, either:

```bash
# One-command fix (works on v4.11.1+; re-runs the MCP setup with the new resolver)
shieldcortex setup

# Or manually, for any version:
WHICH=$(which shieldcortex)
jq --arg p "$WHICH" '.mcpServers.memory = {type:"stdio", command:$p, args:[]}' ~/.claude.json > /tmp/c.json && mv /tmp/c.json ~/.claude.json
# Restart your OpenClaw gateway / Claude Code session.
```

## v4.11.0 — 22 April 2026

> **Default behaviour changes — please read.** This is the first release in the 4.10.x line that flips user-visible defaults. Every previous behaviour is still available; it's just opt-in now. To restore the pre-v4.11.0 defaults in one command: `shieldcortex config --restore-4.10-defaults`.

**Why this exists.** Fleet evidence showed the per-turn memory-injection side of the product was net-negative on fast agent loops — three production agents (Tars, Friday, Jarvis) ran measurably better with ShieldCortex removed. The defence pipeline (scan, X-Ray, Iron Dome, Environment Firewall, credential leak detection, interceptor) stays on: it earns its cost. The memory-injection-into-prompt side (prompt recall, SessionStart preamble, PreCompact auto-extract at old thresholds) pays per-turn tax that only breaks even on deep interactive sessions, not agent workloads. See `docs/audits/2026-04-22-hooks-and-defaults-audit.md` for the full analysis.

### Default changes

- **Proactive memory recall on prompt submit is now OFF** — was ON. Opt in with `shieldcortex config --proactive-recall true`. Used to add 200–500ms of synchronous latency and 100–400 tokens of recall context to every user message, which on a 100-turn fleet loop was 20–50s of cumulative drag plus 20–80k tokens of mostly noisy context. Applies to the Claude Code `UserPromptSubmit` hook and the OpenClaw `cortex-memory` `message` event.
- **Tool-call interceptor no longer prompts for approval on critical/high severity writes** — `severityActions.critical` default changed from `require_approval` to `log`; `high` changed from `require_approval` to `warn`. The defence pipeline still runs, and `failurePolicy` still denies on critical/high failure, so the *defensive block* is preserved. What goes away is the 1–5 second sync pause and human approval prompt on every legitimate memory write. Opt back in with `shieldcortex config --restore-4.10-defaults` or explicit plugin config.
- **SessionStart preamble is now OFF by default** — was `minimal`. The preamble was a prescriptive "ALWAYS use `remember`…" instruction block that repeated every fresh session. The memory list itself is the signal; the drumbeat is noise. Opt in with `"sessionStart": { "preamble": "minimal" }` or `"full"` in `~/.shieldcortex/config.json`.
- **SessionStart memory cap reduced 15 → 5** — each memory is 100–400 tokens, so 15 of them was 500–2000 tokens of boot-time context pollution. Five high-salience items is enough to orient a returning session without eating the window. (This is a constant; not reversible via config. Pin `shieldcortex@4.10.7` if you need the old cap.)
- **PreCompact extraction thresholds raised +0.1 across the board** — architecture 0.28 → 0.38, error 0.30 → 0.40, and so on. Previous thresholds produced ~5% signal and flooded the memory store with noise, which then hurt recall precision downstream. Prefer missing a marginal memory to saving a noisy one.
- **PreCompact `MAX_AUTO_MEMORIES` dropped 5 → 2** — same reason.
- **PreCompact stdout reminder text removed** — the 200-token "## IMPORTANT: Proactive Memory Use…" block that printed after every compaction was pure context spam. The memories themselves remain the signal.

### New

- **`shieldcortex config --restore-4.10-defaults`** — one-command migration helper. Writes explicit overrides for every flipped default to `~/.shieldcortex/config.json`. The MAX_CONTEXT_MEMORIES constant change is not reversible via config and is called out at the end of the helper's output.
- **One-time notice on `shieldcortex update`** — when a user updates from <4.11.0, the CLI prints a summary of the default changes and the restore command.
- **Regression-guard test** in `src/defence/__tests__/interceptor.test.ts` — locks in the new `DEFAULT_CONFIG.severityActions` map so the flip can't silently regress.

### What stays on

- Defence pipeline at every `runDefencePipeline()` call site (scan, firewall, at memory write time).
- Iron Dome behavioural action gates.
- Environment Firewall (`env scan`).
- X-Ray supply-chain scanner (`xray`).
- Credential leak detection (25+ patterns, 11 providers).
- OpenClaw `llm_input` async fire-and-forget scan — ~50ms, doesn't block the model, clear defensive value.
- Tool-call interceptor itself — just with the approval gate relaxed.
- SessionStart hook for fresh `source=startup` only (it already stopped re-pasting on `resume`/`compact`/`clear` in v4.10.5).
- PreCompact extraction — just with tightened thresholds.
- CLAUDE.md block as rewritten in v4.10.7.

### Breaking?

Technically yes. Users who explicitly relied on `proactiveRecall: true` behaviour, the require-approval prompts on memory writes, or the preamble block will see different behaviour. The restore helper is a one-command undo. No code moved; only defaults flipped.

## v4.10.7 — 22 April 2026

**Closes the #27 loose end** — the static ghost-tool block injected into `~/.claude/CLAUDE.md` at install time has been rewritten. Previously it told the model to unconditionally call `remember` / `recall` / `get_context` / `forget` — tools that are not exposed in OpenClaw-only installs where the ShieldCortex MCP server isn't wired. The model would follow the instruction, the call would fail silently, and the user would see apparent amnesia.

- **Block now describes automatic capture first** (PreCompact / UserPromptSubmit / SessionStart hooks), with manual tool calls framed as optional and conditional on the tools actually appearing in the session's tool surface.
- **Explicit anti-nag line**: "Do not nag yourself to call tools that do not appear — it produces silent failures and user-visible amnesia".
- **Installer now self-updates stale blocks** — `setupClaudeMd()` detects the marker plus a content-signature substring, and rewrites the whole block if the signature is missing. Previously idempotent-skip left the stale block in place forever on existing installs.
- Two new tests in `src/__tests__/claude-md-refresh.test.ts` lock in the refresh behaviour.

## v4.10.6 — 22 April 2026

**Ship the shared helper Tars added in v4.10.5** — fixes silent fleet-wide amnesia.

- **`scripts/lib/project-key.mjs` was missing from the npm tarball** — v4.10.5 introduced the shared helper to unify project-key derivation across `session-start-hook.mjs` and `prompt-recall-hook.mjs`, but `package.json` `files` only listed the individual `scripts/*.mjs` files by name. The `scripts/lib` directory was excluded from published packages, so every install of 4.10.5 had both hooks crashing on startup with `ERR_MODULE_NOT_FOUND` and exit code 0 (silent failure).
- **Impact on OpenClaw fleets** — Claude Code fires `UserPromptSubmit → prompt-recall` on every user turn. With the hook broken, no prior-turn context was injected, so Opus 4.7 (which refuses to confabulate the way 4.6 did) replied "I don't have context for what you're replying to — this looks like the start of our conversation" to every Telegram message. Surfaced on the Jarvis / Edith / Tars fleet right after the Opus 4.7 switch; masked the packaging bug as a model-behaviour complaint.
- **Fix** — added `scripts/lib` to the `files` array in `package.json` so the whole directory ships with the npm tarball. Verified by `npm pack --dry-run` listing `scripts/lib/project-key.mjs`.

## v4.10.5 — 22 April 2026

**Session-start hook fixes** — stops the v4.10.4 "amnesia every resume" complaint.

- **`SessionStart` hook no longer re-pastes its banner on `resume` / `compact` / `clear`** — Claude Code fires this hook on every context reboot, not just first-run. The banner was landing back in the model's context after every compaction and long conversations felt like a fresh session every message. The hook now inspects `hookData.source` and exits silently for the three non-startup sources, logging the skip to stderr only.
- **Proactive-memory preamble is now `minimal` by default** — the 13-line "ALWAYS use `remember`" block was burning ~400 tokens on every startup and, worse, naming MCP tools that aren't exposed in every install (OpenClaw-only users see read-only `memory_search`/`memory_get` and fail silently when they try to call `remember`). Default is now a one-line hint; the original block is still available with `"sessionStart": { "preamble": "full" }` in `~/.shieldcortex/config.json`, or can be fully silenced with `"preamble": "off"`.
- **Project-key derivation prefers git `origin` over cwd basename** — sessions running under sibling repos that share a remote now resolve to the same project key, so memories stored from one aren't siloed from the other. Resolution order: `SHIELDCORTEX_PROJECT_KEY` env → `config.projectKey` → `config.projectAliases[basename]` → git origin (`owner-repo`) → cwd basename (legacy fallback).
- **Shared `scripts/lib/project-key.mjs` helper** — session-start and prompt-recall hooks now agree on the project key for a given cwd; previously each ran separate basename-only logic.
- **Regression tests** added for source gating, preamble suppression, and project-key derivation.

## v4.10.4 — 21 April 2026

**Bundled bug fixes + security** — cleans up the remaining issues from the 2026-04-20 shipping audit.

- **All 12 npm audit vulnerabilities cleared** — `npm audit fix` resolved protobufjs (CRITICAL, arbitrary code execution via @huggingface/transformers), tar (CRITICAL, path traversal), picomatch + path-to-regexp (HIGH, ReDoS), qs (moderate, DoS). No breaking changes required. Resolves [#25](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/25).
- **Fresh-clone `npm run build` no longer fails with `next: not found`** — added `bootstrap:dashboard` gate that runs `npm ci` inside `dashboard/` if `node_modules` is missing. Idempotent and sub-second on subsequent builds. Resolves [#22](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/22).
- **`doctor` and `install` now share one canonical hook list** — both previously hardcoded different lists including SessionEnd (which was removed from defaults because it crashes OpenClaw agents). Now both import `REQUIRED_HOOK_NAMES` from `settings-hooks.ts`. Includes a regression-guard test. Resolves [#23](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/23).
- **Permission-denied hook skip message now says which framework is affected** — instead of a bare "Skipped /home/ubuntu/.claude/hooks/cortex-memory (permission denied)", the message now explains whether it's the Claude Code path (informational, OpenClaw unaffected) or the OpenClaw path (blocking — fix immediately) with the exact chown command. Resolves [#26](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/26).

## v4.10.3 — 21 April 2026

**OpenClaw status detection fix** — resolves [#20](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/20). `shieldcortex openclaw status` now reports the plugin as installed after a successful `openclaw plugins install @drakon-systems/shieldcortex-realtime`, instead of claiming "not installed".

- **Canonical marker switched from `index.js` to `openclaw.plugin.json`** — the published plugin tarball ships raw TypeScript (`index.ts`, OpenClaw transpiles at runtime). The old disk check only looked for `index.js`, so it returned false immediately after a successful native install and status reported "not installed" despite config + files being present
- **Disk state and config state now surfaced separately** — status output distinguishes "installed on disk but not in openclaw.json" from "referenced in config but no files on disk", so drift is visible instead of flattened to "not installed"
- **Trust check also accepts `index.ts`** in the `plugins.allow` entry path, for the same reason
- **Entry file name (`index.js` vs `index.ts`) printed** in status output so operators can see which form the install took

## v4.10.2 — 21 April 2026

**Library API fix** — `addMemory()` and other programmatic insert paths now work against fresh installs. Resolves [#19](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/19).

- **`schema.sql` is now copied to `dist/database/`** during build — was being silently dropped from the published npm tarball, forcing fresh installs onto the inline-fallback schema
- **Inline-fallback schema synced with `schema.sql`** — the fallback was missing seven columns (`status`, `pinned`, `reviewed_at`, `reviewed_by`, `source_kind`, `capture_method`, `cloud_excluded`), causing `addMemory()` to fail with `table memories has no column named status` on any fresh database created after the inline-fallback path was hit
- Now there are two layers: the file-based `schema.sql` is the canonical source, and the inline fallback is kept in sync as defence-in-depth for bundlers that strip non-JS assets

## v4.10.1 — 20 April 2026

**Upgrade-path fix** — `shieldcortex update` now always reconciles the OpenClaw plugin and skill, even when the main npm package is already on the latest version.

- **Short-circuit removed** — the `if (latest === currentVersion) return` guard was skipping plugin + skill reconciliation once main was current, so v4.9 → v4.10 upgraders stayed stuck on v4.9 of the plugin
- **Plugin reconciliation always runs** — rm-rf of the extension dir + fresh `openclaw plugins install` on every `shieldcortex update`, not only when main is out of date
- **Skill reconciliation always runs** — `openclaw skills install shieldcortex --force` every time, regardless of main version state
- **"Restart gateway" hint only shown when main actually changed** — less confusing when only plugin/skill drifted

No behaviour change for fresh installs. Only matters if you were previously on v4.9.x and already upgraded main to v4.10.0 with a stale plugin/skill.

## v4.10.0 — 20 April 2026

**Environment Firewall (Phase 1)** — new third defence layer that scores hostile environments before they influence the agent.

- **New CLI**: `shieldcortex env scan <url>` — fetches a URL, scores provenance, detects hidden instructions, runs injection patterns against visible + hidden content, returns a taint label (`trusted` / `untrusted` / `suspicious` / `hostile`) and exit code (0 / 1 / 2)
- **Provenance scoring** — TLS check, redirect chain, domain allowlist, suspicious TLD detection, Punycode / IP-host / embedded-credential penalties
- **Hidden instruction detection** — `display:none`, `visibility:hidden`, zero font-size, off-screen positioning, same-colour text, ARIA-hidden, HTML comments, inline scripts, Unicode bidi overrides, zero-width characters, meta refreshes
- **Taint derivation** — hostile if hidden content contains injection patterns; suspicious if layout-hidden regions are substantial; trusted only for allowlisted TLS domains with no injection hits
- **Library export**: `import { scanUrl } from 'shieldcortex/environment'`
- Extends the strategic model: *memory firewall* (what the agent stores) + *Iron Dome* (what the agent does) + *Environment Firewall* (what the agent sees)

## v4.9.1 — 16 April 2026

**Cloud audit log alignment** — closes silent data loss between npm package and SaaS audit ingest.

- **`blocked_patterns` now synced** — was generated by the firewall but never sent to cloud; the SaaS schema and DB column have been waiting for this data
- **`fragmentation_score` now synced** — fragmentation analysis results are now visible in the cloud audit trail
- SaaS `/v1/audit/ingest` schema updated to validate and persist both fields (silently dropped before)

## v4.9.0 — 16 April 2026

**Defence pipeline hardening** — wired skill scanner threat patterns into the write-time pipeline.

- **Skill threat detection at write-time** — `tool_injection`, `scope_escalation`, `data_exfiltration`, `persistence`, `supply_chain`, `agent_manipulation`, `stealth_instruction` patterns now block memory writes, not just skill file scans
- **Decoded content re-scan expanded** — credential detection and skill threat scanning now run on base64/hex-decoded payloads
- **Path traversal protection** on `/api/skills/scan` endpoint with allowlist of permitted directories

## v4.7.0 — 8 April 2026

**Proactive Recall** — AI agents now automatically recall relevant memories before responding to every message. No more repeated mistakes.

- **`UserPromptSubmit` hook** — queries memory via FTS5 + category boost on every user prompt (<100ms)
- **Automatic context injection** — relevant memories injected into the conversation before the model responds
- **Smart filtering** — skips trivial prompts ("yes", "do it", confirmations), max 5 memories per recall
- **Category boost** — error-related prompts automatically surface error memories, deploy prompts surface architecture memories
- **OpenClaw integration** — proactive recall also works in the cortex-memory hook for non-Claude agents
- **Configurable** — `npx shieldcortex config --proactive-recall false` to disable
- Access counts reinforced on recalled memories (strengthens frequently-needed knowledge)

## v4.7.7 — 11 April 2026

- **Plugin scanner compatibility** — removed `child_process` import from OpenClaw plugin; runtime resolution now uses filesystem-only lookups instead of spawning `which`/`npm` processes. Removes `process.env` access (replaced with config file read). Fixes OpenClaw's "dangerous code patterns detected" block on `openclaw plugins install`.

## v4.7.6 — 11 April 2026

- **`shieldcortex update`** — new CLI command to self-update via `npm install -g shieldcortex@latest`. Shows current vs available version, skips if already up to date.

## v4.7.5 — 11 April 2026

- **CI publish race condition fixed** — publish workflow now polls for CI checks to complete (up to 5 minutes, 15s intervals) instead of failing instantly when checks haven't started yet. No more manual `gh run rerun` after every release.

## v4.7.4 — 10 April 2026

- **Hook commands use global binary** — all hook registrations now use `shieldcortex hook ...` directly instead of `npx shieldcortex hook ...` which hits stale npx cache.

## v4.7.3 — 10 April 2026

- **Floating-point precision fix** — fragmentation score of 0.30000000000000004 was blocking at threshold 0.3 due to IEEE 754 rounding. Now uses integer math at 3 decimal places.

## v4.6.8 — 8 April 2026

- Cloud sync banner: "Clear failed" button now appears directly in the warning banner when dead-letter failures exist

## v4.6.7 — 7 April 2026

**Database resilience + cloud sync fixes**

- **DB staleness detection** — `getDatabase()` checks file inode; auto-reconnects if the live file was replaced during recovery
- **Startup cleanup** — removes `.corrupt.*` and `.recovery-failed.*` backup files older than 7 days
- **Cloud sync banner** — no longer says "healthy" when there are dead-letter failures; honest messaging
- **Clear Failed fix** — `reconcileSyncQueue` DELETE now handles legacy payloads without `$.kind` field via COALESCE fallback
- **Plugin hardening** — `before_tool_call` hook catches unexpected errors gracefully (intentional blocks still propagate)
- Plugin manifest version aligned

## v4.6.6 — 6 April 2026

**Dashboard navigation + data alignment**

- **Stat card data alignment** — quality API duplicate count now filters archived/suppressed/reviewed memories, matching the review queue
- **Clickable stat cards** — Memory Base → Memories, Healthy → Review, Queue → Quarantine, Blocked → Audit
- **Clickable hygiene numbers** — duplicates/stale/never-used numbers navigate to the right review queue section
- **Review focus wiring** — clicking from Overview navigates to Review and auto-scrolls to the right section (duplicates, contradictions)
- **QualityPanel navigation** — every item is clickable; "Review all N" links for sections with 5+ items

## [4.6.5] - 2026-04-06

### Fixed
- **Plugin version drift** — installer now patches the manifest version to match the main package version during extensions copy, so the registered version is always correct. Plugin manifests also aligned to current release.

## [4.6.4] - 2026-04-06

### Fixed
- **Plugin install missing files** — extensions copy now includes `interceptor.js` and `intercept-ingest.js` alongside `index.js`. Also writes `package.json` with `"type": "module"` to prevent Node ESM reparsing warnings.

## [4.6.3] - 2026-04-06

### Fixed
- **OpenClaw plugin not found on custom npm paths** — installer now only skips extensions copy when npm global is in a path OpenClaw auto-discovers (`/usr/lib`, `/usr/local/lib`, `/opt/homebrew/lib`). Custom paths like `~/.npm-global` correctly fall back to the extensions copy.

## [4.6.2] - 2026-04-06

### Fixed
- **OpenClaw duplicate plugin warning** — installer now detects global npm install and skips the `~/.openclaw/extensions/` copy that caused "duplicate plugin id" warnings. Cleans up stale extensions copies automatically.

## [4.6.1] - 2026-04-06

### Fixed
- **OpenClaw plugin stack overflow** — `import('shieldcortex/defence')` caught and handled gracefully instead of crashing with "Maximum call stack size exceeded"
- **Plugin registering 200+ times** — guard prevents `register()` from running more than once per process
- **Plugin version showing v0.0.0** — now reads version from `openclaw.plugin.json` manifest when `package.json` isn't available at the installed path

## [4.6.0] - 2026-04-06

### Added
- **Constellation graph**: Full knowledge graph with 2-level cluster/detail view — all entities visible as coloured nebula clusters, click to bloom into individual nodes
- **Review queue**: Card-based review flow with Keep/Suppress/Archive actions, slide animations, progress tracking, and accurate total counts
- **Cloud sync diagnostics**: Clear failed items button, manual refresh, save feedback toast
- **Graph search limit**: `/api/graph/search` now respects `limit` query parameter

### Changed
- Cloud sync polling reduced from 10s to 30s for better battery life
- Button component defaults to `type="button"` preventing accidental form submissions
- GlassCard now supports keyboard activation (Enter/Space) when clickable

### Fixed
- **Review Keep button**: Now correctly sets `reviewed_at` timestamp and removes item from queue
- **Review queue counts**: Summary uses COUNT queries for true totals instead of capped page sizes
- **X-Ray false positives**: Polyglot detection now checks file header only (not entire buffer), obfuscation only flags code files, system paths excluded from scanning
- **Graph fit-to-view**: Now calls `zoomToFit()` via ref instead of no-op state toggle
- **OverviewView crash**: Null-safe property chains for `contradictions`, `duplicates`, `stale`, `neverAccessed`
- **Auth token race**: Token deduplication no longer nulls promise prematurely
- **WebSocket reconnect**: Invalidates cached auth token on auth failure close codes
- **Audit export**: `revokeObjectURL` deferred to prevent download race condition
- **Decay tick leak**: Interval now assigned to variable and cleared on shutdown
- **API 404s**: Unmatched `/api/*` routes return JSON instead of HTML
- **Bulk quarantine validation**: Array element types now validated as integers

### Removed
- Dead code: `Topbar.tsx`, `RouteScaffold.tsx` components

## [4.5.0] - 2026-04-03

### Added
- **Finding lifecycle**: X-Ray findings now have persistent status (new, reviewed, ignored, resolved, quarantined)
- **Finding actions**: Review, ignore, resolve (with notes), quarantine file, delete — all from the dashboard
- **Real-time alerts**: Watch detections broadcast via WebSocket with toast notifications in dashboard
- **Findings tab**: New tab in X-Ray with status filters, stats summary, and action buttons on every finding
- **File quarantine**: Move suspicious files to `~/.shieldcortex/quarantine/files/` directly from the dashboard
- **Findings store**: Persistent JSON store with deduplication, 30-day auto-cleanup, and 500 finding cap
- **API endpoints**: `GET/PATCH/DELETE /api/xray/findings/:id`, `POST /api/xray/findings/:id/quarantine`, `GET /api/xray/findings/stats`
- **IPC for watch detections**: Atomic JSONL-based event file with 512KB cap for cross-process communication
- **Toast notifications**: `sonner` integration for dark-themed toast alerts

### Changed
- Dashboard redesigned with OpenClaw-inspired dark theme (coral/cyan accents, glassmorphic cards)
- Navigation simplified from 18 routes to 5 tabbed sections
- All sub-components restyled with `--sc-*` CSS variable system
- Mobile responsive sidebar with hamburger menu
- Error boundaries added for dashboard routes
- Skeleton loaders replace text loading states
- Watch mode ignore list expanded (.next, .cache, .turbo, __pycache__, .venv)

## [Unreleased]

## [3.4.29] - 2026-03-22

### Fixed

- **Trial-aware dashboard status** — `/api/license/status` now reports the effective trial tier and active trial metadata, so the dashboard stops showing trial users as free or unlicensed while Pro features are unlocked
- **Safe MCP first-run startup** — explicit `--mode mcp` no longer emits the Pro trial welcome banner, and database startup/recovery diagnostics were moved off stdout so MCP transports stay clean
- **Isolated trial test coverage** — the new trial and feature-gating suites now run against a temp ShieldCortex config directory instead of renaming or deleting a developer's real `~/.shieldcortex` files

## [3.4.28] - 2026-03-22

### Fixed

- **OpenClaw provenance persistence** — OpenClaw hook/plugin memories now preserve `sourceType` and `sourceIdentifier` in stored metadata so ShieldCortex can keep real capture provenance instead of flattening them into generic manual rows
- **OpenClaw source inference** — the local memory store now recognises `session-end`, `session-stop`, `keyword-trigger`, and realtime plugin tags as OpenClaw evidence when deriving source and capture method
- **Legacy OpenClaw backfill** — startup migrations now repair older OpenClaw auto-extracted rows that were previously left as `user:direct`, so local/cloud capture views can recover them without requiring users to recreate the memories
- **Local capture legacy session grouping** — the local Capture API now derives stable fallback session ids for older OpenClaw rows that never stored an explicit `sessionId`

## [3.4.27] - 2026-03-21

### Fixed

- **macOS service status accuracy** — `shieldcortex service status` now inspects the active LaunchAgent correctly, so a running dashboard/worker no longer shows up as `Running: no`

## [3.4.26] - 2026-03-21

### Added

- **Editable Iron Dome kill phrase** — operators can now update the local Iron Dome emergency kill phrase directly from the dashboard instead of being stuck with the default phrase

### Fixed

- **Iron Dome config mutation path** — added a dedicated local API route and dashboard mutation flow for updating editable Iron Dome configuration fields without resetting the active profile

## [3.4.25] - 2026-03-21

### Fixed

- **Review queue dashboard lint** — `ReviewQueueView` now uses stable section IDs instead of brittle ref mutation, which fixes the React/TypeScript lint failures on the dashboard build and keeps focused review sections scrollable without callback-ref churn

## [3.4.24] - 2026-03-21

### Fixed

- **Claude Code multi-session startup** — the startup lock is now advisory when another live ShieldCortex process already owns the managed database, so concurrent Claude Code MCP sessions can keep using the same WAL-backed store instead of failing on second startup
- **Safer multi-process shutdown** — close-time WAL checkpointing now uses `PASSIVE` instead of `TRUNCATE`, which avoids demanding exclusive access when more than one installed ShieldCortex process is attached to the database
- **Reliability regression coverage** — added direct route-level tests for cloud config mutations and review actions, startup recovery tests for recent healthy backup restore and stale/live lock handling, and stabilized the OpenClaw installer suite so installer trust behavior stays covered

## [3.4.23] - 2026-03-19

### Fixed

- **OpenClaw installer output clarity** — `shieldcortex openclaw install` now explicitly says whether the realtime plugin was installed through native OpenClaw package records, native linked records, or the trusted local fallback path
- **Status clarity for plugin trust** — `shieldcortex openclaw status` now tells operators when a copied local plugin is trusted via `plugins.allow`, instead of only saying “installed”

## [3.4.22] - 2026-03-19

### Fixed

- **OpenClaw installer provenance** — `shieldcortex openclaw install` now prefers native OpenClaw plugin installation when available, instead of only copying a local plugin into `~/.openclaw/extensions`
- **Fallback install trust pinning** — when the installer must fall back to a copied local plugin, it now automatically pins the copied `shieldcortex-realtime` path into `plugins.allow` so OpenClaw stops warning that the plugin is untracked local code
- Added regression coverage for the fallback installer path so copied realtime plugins remain trusted by default

## [3.4.21] - 2026-03-18

### Fixed

- **Recall cleanup** — the Recall workspace now keeps the ranked recall set primary, moves expected-memory selection and likely misses into secondary disclosure, and makes the current run clearer at a glance
- **Audit cleanup** — the Audit page now starts with result counts and operator controls instead of only a raw event table, while export is moved behind explicit disclosure
- **Brain workflow cleanup** — the Brain page no longer reserves space for an empty inspector, keeps the category rail hidden until requested, and moves the dense metric strip behind a secondary disclosure

## [3.4.20] - 2026-03-18

### Fixed

- **Shield action flow cleanup** — the local Shield page now exposes direct operator actions for quarantine, audit, cloud, and brain views from the section headers instead of making operators infer the next move from dense cards
- **Cloud control clarity cleanup** — project selection now stays tucked behind an explicit chooser when scope is include/exclude, and the controls foreground the current policy summary instead of showing every project selector all the time
- **Graph interaction cleanup** — local Graph reduces left-rail noise by collapsing jump lists, keeps Read clearly primary, and treats the visual graph modes as secondary exploratory tools

## [3.4.19] - 2026-03-18

### Fixed

- **Graph page cleanup** — local Graph now keeps `Read` as the obvious primary path, moves `Map` and `Bloom` behind an explicit visual explorer, and reduces first-paint clutter with a simpler evidence-oriented sidebar
- **Cloud density cleanup** — local Cloud now treats memory/graph replication as the main signal and moves audit/quarantine transport history into the advanced section where it belongs
- **Shield density cleanup** — local Shield no longer expands advanced review controls by default, so the first screen stays focused on decisions and system status instead of specialist tools

## [3.4.18] - 2026-03-18

### Fixed

- **Shield page product cleanup** — the local Shield workspace now separates immediate review work, system status, policy tuning, and advanced controls into clearer sections instead of presenting every defence card at the same priority
- **Cloud page product cleanup** — local Cloud diagnostics now foreground replication health and policy, while transport-level debug signals are moved into a secondary advanced section so the page reads operationally instead of like a raw dump
- **Brain page product cleanup** — the Brain workspace now starts from a calmer shell with recent activity collapsed by default and a clearer focus/pressure summary before the full visual workspace

## [3.4.17] - 2026-03-17

### Fixed

- **Recall stays inside the workflow now** — ranked results can be inspected in an in-page side panel instead of forcing operators into the generic Memories screen, so comparing ranks, misses, and contradictions no longer breaks context
- **Workflow audit pass on remaining local pages** — Overview urgent actions, Quarantine, Audit, Shield, and Cloud config/sync controls were checked for dead placeholder actions; the remaining obvious generic-jump path was removed from Recall
## [3.4.16] - 2026-03-17

### Fixed

- **Capture workflow now matches Review semantics** — OpenClaw session records no longer show a fake `State` box, action labels now reflect real review transitions like restore/archive/discard, and the selected memory panel stays in sync after capture-originated review actions
- **Workflow audit cleanup** — the remaining high-traffic dashboard workflow pages now use dynamic review-signal chips instead of placeholder-looking state labels, reducing the number of surfaces that implied actions had not actually taken effect

## [3.4.15] - 2026-03-17

### Fixed

- **Review queue actions now line up with actual memory state** — review mutations now update the visible queue immediately, selected review items stay in sync after pin/suppress/archive/canonicalize, and rescoping a memory now really persists `scope` instead of silently doing nothing
- **Resolved items stop leaking back into review** — the backend review queue, contradiction detector, and duplicate detector now exclude archived/suppressed memories, so resolved contradiction and duplicate cards stop pretending they still need action
- **Review cards no longer fake a hardcoded `State active` box** — the queue now shows dynamic review signals such as pinned/canonical/cloud-excluded/reviewed/global, plus clearer “next move” messaging on each card

## [3.4.14] - 2026-03-17

### Fixed

- **Startup safety hardening** — ShieldCortex now takes an exclusive startup lock on the managed database, refuses to let `npx` caches or project-checkout builds touch the real `~/.shieldcortex/memories.db` by default, and logs the runtime path plus WAL/SHM state at startup for easier forensics
- **Healthy backup restore preference** — when recovery is needed, ShieldCortex now prefers the latest healthy rotated backup over creating a fresh empty database, and it auto-heals the specific “empty live DB beside a recent healthy backup” state that caused repeated apparent memory loss

## [3.4.13] - 2026-03-17

### Fixed

- **Dashboard review actions no longer leak Iron Dome internals** — clicking keep/suppress/archive/merge in the local dashboard now satisfies the AMBER “announcement” requirement automatically, instead of throwing the internal message `Action requires announcement before execution` back at operators
- Added regression coverage so dashboard-originated AMBER actions pass, while non-dashboard channels still require an explicit acknowledgement signal when `enforceAmber` is enabled

## [3.4.12] - 2026-03-17

### Fixed

- **Review workflow actionability** — review actions now surface real success/error feedback instead of behaving like dead controls, and the Review queue no longer throws operators out to the generic memories page when they inspect an item
- **Inline review inspection** — selected review items now stay visible in an in-page side panel beside contradictions, duplicates, and cleanup sections so operators can click through the queue without losing context

## [3.4.11] - 2026-03-17

### Fixed

- **Startup integrity fallback hardening** — before rotating a “corrupt” memory database into backup and creating a fresh empty store, ShieldCortex now reopens the on-disk DB through a fresh read-only connection and only performs destructive recovery if that second integrity check also fails

## [3.4.10] - 2026-03-17

### Fixed

- **Capture detail panel flow** — selected captured memories now stay in an in-page side panel beside the captured record list on desktop, so operators can click through records and keep the chosen memory visible without being sent back to the top of the page

## [3.4.9] - 2026-03-17

### Fixed

- **Quarantine approval now actually restores memories** — approving quarantined items from the dashboard now promotes them into the memory store instead of only flipping review status, and the relevant memory/review/capture views refresh immediately
- **Dashboard trust-channel hardening** — Iron Dome now treats the local dashboard as trusted at the gateway even if a persisted config is malformed, and it self-heals stored configs that omit `dashboard`
- **Cloud config mutation validation** — local cloud settings now reject invalid payloads earlier, surface real API error messages in the dashboard, and refuse enabling cloud sync without a valid API key and base URL
- **Dashboard shell/layout hardening** — the remaining detached global memory drawer path was removed, audit/quarantine views stay in page flow, and embedded memory detail panels no longer fight the page scroll model

## [3.4.8] - 2026-03-16

### Fixed

- **Review workflow routing** — Home `Urgent actions` now opens the relevant review section directly instead of dumping operators into a contextless page
- **Contradiction resolution UX** — the Review Queue now lets operators compare contradictory memories side by side, inspect both, pin, suppress, and resolve a contradiction by keeping one and suppressing the other
- **Capture workspace layout** — selected captured memories now render in page flow instead of a detached sticky side panel, so the session view and captured record list behave like one scrollable workspace

## [3.4.7] - 2026-03-16

### Fixed

- **Iron Dome dashboard self-lockout** — persisted Iron Dome configs now always normalize `dashboard` back into `trustedChannels`, so an old or malformed local policy cannot block the local dashboard from managing its own config
- Added regression coverage for persisted Iron Dome configs that omit `dashboard`, ensuring both stored status and effective policy repair the channel automatically on load
- Existing installs recover cleanly on the next config load/save instead of continuing to emit false `dashboard is not in trusted channels list` gateway blocks
## [3.4.6] - 2026-03-16

### Fixed

- **Cloud diagnostics now report real replication health** — the local Cloud page no longer treats stale `audit` or `quarantine` retry history as if memory/cloud replication is currently broken
- Status banners and summary cards now prioritise `memory` and `graph` replication failures, while auxiliary sync history remains visible as debugging context instead of a false “cloud sync failed” state

## [3.4.5] - 2026-03-16

### Fixed

- **FTS recovery on startup** — ShieldCortex now attempts an in-place `memories_fts` rebuild when the database integrity failure is limited to the full-text index, instead of incorrectly treating the whole memory store as lost and recreating an empty DB
- Added regression coverage for FTS-only corruption detection and recovery so startup preserves memory rows during searchable-index repair
- **Capture page layout** — the local Capture workflow now uses normal page flow and an in-page sticky detail panel instead of a detached drawer plus nested scroll regions
- Workflow pages now avoid trapping content inside competing scroll containers, which makes `Capture` and `Memories` materially more usable with large memory sets

## [3.4.4] - 2026-03-14

### Changed

- Iron Dome now treats the authenticated local dashboard as a trusted channel in built-in profiles instead of blocking dashboard mutations at the gateway by default
- Dashboard REST mutation routes now enforce Iron Dome action gates and announcement/confirmation tiers for config changes, SQL writes, quarantine review, and memory management actions

### Docs

- README and CLI help now explain that dashboard actions are trusted but still gated by Iron Dome confirmation policy

## [3.4.1] - 2026-03-12

### Added

- **Interactive quickstart detection** — `shieldcortex quickstart` now offers to install into detected Claude Code, OpenClaw, Copilot/Cursor, and Codex environments when run in an interactive terminal

### Changed

- Added `shieldcortex quickstart --yes` / `--install-detected` for non-interactive all-detected setup
- Kept npm install non-destructive: integrations are still only configured after explicit confirmation or an explicit quickstart flag

## [3.4.0] - 2026-03-12

### Added

- **Duplicate merge workflow** — Review Queue now surfaces duplicate memory candidates with a recommended survivor and one-click merge actions
- **Memory merge API** — added a dedicated merge route so the dashboard can merge duplicate memories intentionally instead of relying only on background dedupe

### Changed

- Duplicate detection is now exposed as a first-class review signal, not just a background consolidation behavior
- Merge actions preserve unique content, combine tags, keep the stronger survivor, and refresh graph/cloud sync state for the merged memory

## [3.3.1] - 2026-03-12

### Fixed

- **Codex installer dedupe** — repeat `shieldcortex codex install` runs now replace the existing Codex MCP block cleanly instead of risking duplicate `[mcp_servers.shieldcortex-memory]` sections in `~/.codex/config.toml`
- Codex MCP block matching now handles shared config files more robustly, including CRLF-safe section matching
## [3.3.0] - 2026-03-12

### Added

- **Codex integration** — added `shieldcortex codex install|uninstall|status` so ShieldCortex can register itself directly into Codex MCP config
- **Codex quickstart** — added dedicated Codex setup docs covering Codex CLI and the Codex VS Code extension from one shared config file

### Changed

- `shieldcortex quickstart` now detects Codex and recommends the Codex MCP install path when `~/.codex` is present
- Trust/source inference now recognises Codex CLI and Codex VS Code environments for better provenance and security scoring
- MCP config auditing now scans Codex MCP configuration from `~/.codex/config.toml`
- README and npm metadata now treat Codex as a first-class supported integration

## [3.2.3] - 2026-03-11

### Docs

- Added a dedicated cloud-server quickstart for always-on Linux boxes and remote hosts
- Clarified the exact server-to-cloud onboarding flow in the README:
  - activate Team licence
  - set cloud API key
  - enable cloud sync
  - install the headless worker service
- Updated MCP and OpenClaw quickstarts to point server users to the cloud-server guide

### Changed

- Public docs now explain that ShieldCortex Cloud `Online` means a recent ShieldCortex heartbeat, not just machine uptime

## [3.2.2] - 2026-03-11

### Added

- **Headless worker mode** — `shieldcortex --mode worker` now runs a persistent background worker for cloud heartbeats, retry processing, and graph maintenance without requiring the local dashboard
- **Server-first service install** — `shieldcortex service install --headless` now gives always-on Linux boxes a better default path for staying online in ShieldCortex Cloud

### Changed

- Linux service install now defaults to headless worker mode when no display session is present, which fits cloud/server hosts better than dashboard auto-start
- Service status now reports the installed mode so it is clearer whether a device is running dashboard, API, or worker service

### Fixed

- Headless ShieldCortex services now stay alive correctly even though the brain-worker timers are intentionally `unref()`'d
- The cloud Devices page is clearer about what “online” means: recent ShieldCortex heartbeat, not just machine uptime

## [3.2.1] - 2026-03-11

### Changed

- Tightened the public package positioning around one clearer wedge: trustworthy AI agent memory with inspectable recall and built-in security
- Reworked `shieldcortex quickstart` copy to guide users by job-to-be-done and ecosystem path instead of just listing install commands
- Added dedicated quickstart docs for Claude Code, OpenClaw, LangChain JS, and MCP agents to reduce time-to-value from the README and npm page

### Docs

- README now leads with adoption-focused messaging: remember the right things, inspect recall, and stop poisoned memory from spreading
- Added ecosystem-specific quickstarts under `docs/quickstarts/` for Claude Code, OpenClaw, LangChain JS, and generic MCP setups

## [3.2.0] - 2026-03-10

### Added

- **Recall Workspace** — a new local dashboard workflow for testing recall queries, inspecting why memories ranked, comparing expected memories, and spotting likely misses before they become trust issues
- **Review Queue** — a new local review workflow for stale, never-used, contradictory, low-trust, noisy auto-extracted, and projectless memories with direct suppress/archive/pin/canonicalize actions
- **Capture workflow** — the local Memories area now behaves like an operator-facing capture surface, combining stored memories, source trust, and OpenClaw activity instead of just a generic card grid
- **OpenClaw Session View** — recent OpenClaw sessions now open into a full local session inspector with event trail, security signals, linked memories, and direct keep/discard review actions
- **Memory provenance metadata** — memories now track status, pinned state, review timestamps, source kind, capture method, trust score, and cloud exclusion intent

### Changed

- Local dashboard information architecture now foregrounds `Recall`, `Review`, and `Capture` workflows instead of treating the graph as the main way to understand memory
- Memory detail panels now surface provenance, review state, and sync intent alongside the existing content and relationship detail
- OpenClaw hook/plugin writes now pass flatter source and session attribution into the remember pipeline so stored memories can be traced back to their origin more reliably
- Cloud memory and graph sync now respect per-memory cloud exclusion state coming from the new review workflow
- Recall explanation responses now include stronger eligibility context and contradiction-aware ranking feedback

### Fixed

- Normal recall now excludes archived and suppressed memories by default so review actions actually change what the agent can retrieve
- OpenClaw session capture reporting no longer inflates saved counts by double-counting stored memories and audit log totals
- The new capture workflow is safer against partial or older session payloads because the dashboard hook and API now share a richer typed session shape

## [3.1.0] - 2026-03-10

### Added

- **Readable graph modes** — the dashboard graph now supports `Read`, `Map`, and `Bloom` views so users can switch between relationship statements, a cleaner canvas map, and an organic branch layout
- **Local cloud diagnostics** — new Cloud dashboard view shows queue pressure, sync lag, licence gating, device identity, and current sync policy in one place
- **Cloud sync controls** — local devices can now choose all/include/exclude project scope, `full` vs `metadata` sync mode, and sensitive-memory exclusion before data is replicated
- **Local-to-cloud graph replication** — full sync now includes entities, triples, and memory-entity links alongside replicated memories

### Changed

- Full graph sync is now authoritative per memory slice and prunes stale replicated graph slices during cloud backfill
- Dashboard graph exploration is more navigable, with readable relationship outlines and less cluttered focus-on-one-entity layouts

### Fixed

- Graph slices are now replaced on memory updates, cleared on delete, and cleaned during forced backfill so stale entities and triples do not linger locally
- Cloud diagnostics no longer crash when older or partial API responses omit nested sync-control fields

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
